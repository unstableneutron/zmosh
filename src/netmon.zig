const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

const log = std.log.scoped(.netmon);

const c = @cImport({
    @cInclude("ifaddrs.h");
    @cInclude("net/if.h");
    @cInclude("netinet/in.h");
    @cInclude("sys/socket.h");
});

const LinuxNlmsghdr = extern struct {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
};

const LinuxSockaddrNl = extern struct {
    nl_family: u16,
    nl_pad: u16 = 0,
    nl_pid: u32 = 0,
    nl_groups: u32 = 0,
};

const linux_af_netlink = 16;
const linux_netlink_route = 0;
const linux_rtmgrp_link = 0x1;
const linux_rtmgrp_ipv4_ifaddr = 0x10;
const linux_rtmgrp_ipv4_route = 0x40;
const linux_rtmgrp_ipv6_ifaddr = 0x100;
const linux_rtmgrp_ipv6_route = 0x400;

pub const default_poll_interval_ns: i64 = std.time.ns_per_s;

pub const PollingChangeDetector = struct {
    last_hash: u64,
    interval_ns: i64 = default_poll_interval_ns,
    next_check_ns: i64,

    pub fn init(now: i64, initial_hash: u64) PollingChangeDetector {
        return .{
            .last_hash = initial_hash,
            .next_check_ns = now + default_poll_interval_ns,
        };
    }

    pub fn isDue(self: *const PollingChangeDetector, now: i64) bool {
        return now >= self.next_check_ns;
    }

    pub fn pollTimeoutMs(self: *const PollingChangeDetector, now: i64) i32 {
        if (self.isDue(now)) return 0;

        const remaining_ns = self.next_check_ns - now;
        const remaining_ms = @divFloor(remaining_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms);
        return @intCast(@min(remaining_ms, @as(i64, std.math.maxInt(i32))));
    }

    pub fn observe(self: *PollingChangeDetector, now: i64, snapshot_hash: u64) bool {
        if (!self.isDue(now)) return false;
        self.next_check_ns = now + self.interval_ns;
        if (snapshot_hash == self.last_hash) return false;
        self.last_hash = snapshot_hash;
        return true;
    }

    pub fn reset(self: *PollingChangeDetector, now: i64, snapshot_hash: u64) void {
        self.last_hash = snapshot_hash;
        self.next_check_ns = now + self.interval_ns;
    }
};

pub const NetworkMonitor = struct {
    alloc: std.mem.Allocator,
    detector: PollingChangeDetector,
    linux_fd: ?i32,

    pub fn init(alloc: std.mem.Allocator) NetworkMonitor {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        const initial_hash = readSnapshotHash(alloc) catch |err| blk: {
            log.warn("failed to read initial interface snapshot: {s}", .{@errorName(err)});
            break :blk 0;
        };

        var monitor = NetworkMonitor{
            .alloc = alloc,
            .detector = PollingChangeDetector.init(now, initial_hash),
            .linux_fd = null,
        };

        if (builtin.os.tag == .linux) {
            monitor.linux_fd = initLinuxRouteFd() catch |err| blk: {
                log.warn("failed to start netlink route monitor, falling back to polling: {s}", .{@errorName(err)});
                break :blk null;
            };
        }

        return monitor;
    }

    pub fn deinit(self: *NetworkMonitor) void {
        if (self.linux_fd) |fd| {
            posix.close(fd);
            self.linux_fd = null;
        }
    }

    pub fn pollFd(self: *const NetworkMonitor) ?i32 {
        return self.linux_fd;
    }

    pub fn pollTimeoutMs(self: *const NetworkMonitor, now: i64) i32 {
        return self.detector.pollTimeoutMs(now);
    }

    pub fn poll(self: *NetworkMonitor, now: i64, revents: i16) bool {
        var changed = false;

        if (self.linux_fd != null and revents != 0) {
            const linux_changed = self.handleLinuxEvents(revents) catch |err| blk: {
                log.warn("linux netlink monitor failed, disabling realtime notifications: {s}", .{@errorName(err)});
                self.disableLinuxFd();
                break :blk true;
            };
            if (linux_changed) {
                changed = true;
                self.refreshBaseline(now);
            }
        }

        if (self.detector.isDue(now)) {
            const snapshot_hash = readSnapshotHash(self.alloc) catch |err| blk: {
                log.warn("failed to poll interface snapshot: {s}", .{@errorName(err)});
                self.detector.next_check_ns = now + self.detector.interval_ns;
                break :blk null;
            };
            if (snapshot_hash) |hash| {
                if (self.detector.observe(now, hash)) changed = true;
            }
        }

        return changed;
    }

    fn refreshBaseline(self: *NetworkMonitor, now: i64) void {
        const snapshot_hash = readSnapshotHash(self.alloc) catch |err| {
            log.warn("failed to refresh interface snapshot baseline: {s}", .{@errorName(err)});
            self.detector.next_check_ns = now + self.detector.interval_ns;
            return;
        };
        self.detector.reset(now, snapshot_hash);
    }

    fn disableLinuxFd(self: *NetworkMonitor) void {
        if (self.linux_fd) |fd| {
            posix.close(fd);
            self.linux_fd = null;
        }
    }

    fn handleLinuxEvents(self: *NetworkMonitor, revents: i16) !bool {
        const fd = self.linux_fd orelse return false;

        if (revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
            return error.NetlinkUnavailable;
        }

        var changed = revents & posix.POLL.HUP != 0;
        if (revents & posix.POLL.IN == 0) return changed;

        while (true) {
            var buf: [8192]u8 = undefined;
            const n = posix.read(fd, &buf) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };
            if (n == 0) {
                changed = true;
                break;
            }
            changed = parseLinuxNetlinkBuffer(buf[0..n]) or changed;
        }

        return changed;
    }
};

pub fn linuxNetlinkMessageSignalsChange(msg_type: u16) bool {
    return switch (msg_type) {
        4, // NLMSG_OVERRUN
        16, 17, // RTM_{NEW,DEL}LINK
        20, 21, // RTM_{NEW,DEL}ADDR
        24, 25, // RTM_{NEW,DEL}ROUTE
        => true,
        else => false,
    };
}

fn parseLinuxNetlinkBuffer(buf: []const u8) bool {
    var offset: usize = 0;
    var changed = false;

    while (offset + @sizeOf(LinuxNlmsghdr) <= buf.len) {
        const hdr = std.mem.bytesToValue(LinuxNlmsghdr, buf[offset .. offset + @sizeOf(LinuxNlmsghdr)]);
        const msg_len: usize = @intCast(hdr.nlmsg_len);
        if (msg_len < @sizeOf(LinuxNlmsghdr) or offset + msg_len > buf.len) return true;

        if (linuxNetlinkMessageSignalsChange(@intCast(hdr.nlmsg_type))) {
            changed = true;
        }

        offset += std.mem.alignForward(usize, msg_len, 4);
    }

    return changed;
}

fn initLinuxRouteFd() !i32 {
    if (builtin.os.tag != .linux) return error.Unsupported;

    const fd = try posix.socket(linux_af_netlink, posix.SOCK.RAW | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC, linux_netlink_route);
    errdefer posix.close(fd);

    var addr = std.mem.zeroes(LinuxSockaddrNl);
    addr.nl_family = linux_af_netlink;
    addr.nl_groups = linux_rtmgrp_link |
        linux_rtmgrp_ipv4_ifaddr |
        linux_rtmgrp_ipv6_ifaddr |
        linux_rtmgrp_ipv4_route |
        linux_rtmgrp_ipv6_route;

    try posix.bind(fd, @ptrCast(&addr), @sizeOf(LinuxSockaddrNl));
    return fd;
}

fn readSnapshotHash(alloc: std.mem.Allocator) !u64 {
    var ifap: ?*c.struct_ifaddrs = null;
    if (c.getifaddrs(&ifap) != 0) return error.GetIfAddrsFailed;
    defer c.freeifaddrs(ifap);

    var entry_hashes = try std.ArrayList(u64).initCapacity(alloc, 16);
    defer entry_hashes.deinit(alloc);

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        const if_name = if (ifa.ifa_name != null) std.mem.span(ifa.ifa_name) else continue;
        if (if_name.len == 0) continue;
        if ((ifa.ifa_flags & c.IFF_LOOPBACK) != 0) continue;

        const family: u16 = if (ifa.ifa_addr != null) ifa.ifa_addr.*.sa_family else 0;
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(if_name);
        hasher.update(std.mem.asBytes(&ifa.ifa_flags));
        hasher.update(std.mem.asBytes(&family));

        if (ifa.ifa_addr != null) {
            switch (family) {
                posix.AF.INET => {
                    const in_ptr: *const c.struct_sockaddr_in = @ptrCast(@alignCast(ifa.ifa_addr));
                    const ip: [4]u8 = @bitCast(in_ptr.sin_addr.s_addr);
                    hasher.update(&ip);
                },
                posix.AF.INET6 => {
                    const in6_ptr: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(ifa.ifa_addr));
                    const ip: [16]u8 = @as(*const [16]u8, @ptrCast(&in6_ptr.sin6_addr)).*;
                    hasher.update(&ip);
                    hasher.update(std.mem.asBytes(&in6_ptr.sin6_scope_id));
                },
                else => {},
            }
        }

        try entry_hashes.append(alloc, hasher.final());
    }

    std.sort.heap(u64, entry_hashes.items, {}, comptime std.sort.asc(u64));

    var hasher = std.hash.Wyhash.init(0);
    hasher.update(std.mem.asBytes(&entry_hashes.items.len));
    for (entry_hashes.items) |entry| {
        hasher.update(std.mem.asBytes(&entry));
    }
    return hasher.final();
}

test "polling detector waits for the next interval and tracks baseline changes" {
    var detector = PollingChangeDetector.init(0, 11);

    try std.testing.expect(!detector.observe(0, 99));
    try std.testing.expect(detector.pollTimeoutMs(0) > 0);

    const at_interval = default_poll_interval_ns;
    try std.testing.expect(detector.observe(at_interval, 11) == false);
    try std.testing.expect(detector.observe(2 * default_poll_interval_ns, 12));
    try std.testing.expectEqual(@as(u64, 12), detector.last_hash);
}

test "polling detector reset restores the baseline and delay" {
    var detector = PollingChangeDetector.init(5 * std.time.ns_per_s, 1);
    detector.reset(9 * std.time.ns_per_s, 44);

    try std.testing.expectEqual(@as(u64, 44), detector.last_hash);
    try std.testing.expect(detector.pollTimeoutMs(9 * std.time.ns_per_s) > 0);
    try std.testing.expect(!detector.observe(9 * std.time.ns_per_s, 55));
}

test "linux netlink route and address notifications count as path changes" {
    try std.testing.expect(linuxNetlinkMessageSignalsChange(16));
    try std.testing.expect(linuxNetlinkMessageSignalsChange(17));
    try std.testing.expect(linuxNetlinkMessageSignalsChange(20));
    try std.testing.expect(linuxNetlinkMessageSignalsChange(21));
    try std.testing.expect(linuxNetlinkMessageSignalsChange(24));
    try std.testing.expect(linuxNetlinkMessageSignalsChange(25));
    try std.testing.expect(linuxNetlinkMessageSignalsChange(4));
    try std.testing.expect(!linuxNetlinkMessageSignalsChange(3));
}
