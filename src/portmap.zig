const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");
const nat = @import("nat.zig");
const udp = @import("udp.zig");

const bsd_c = if (builtin.os.tag == .macos or builtin.os.tag == .freebsd)
    @cImport({
        @cInclude("sys/types.h");
        @cInclude("sys/sysctl.h");
        @cInclude("net/route.h");
        @cInclude("netinet/in.h");
    })
else
    struct {};

pub const nat_pmp_port: u16 = 5351;
pub const default_lifetime_seconds: u32 = 7200;
const retry_schedule_ms = [_]u32{ 100, 250, 500 };

pub const Opcode = enum(u8) {
    public_address = 0,
    map_udp = 1,
};

pub const ResultCode = enum(u16) {
    success = 0,
    unsupported_version = 1,
    not_authorized = 2,
    network_failure = 3,
    out_of_resources = 4,
    unsupported_opcode = 5,
    unknown = 0xffff,

    fn fromInt(value: u16) ResultCode {
        return std.meta.intToEnum(ResultCode, value) catch .unknown;
    }
};

pub const PublicAddressResponse = struct {
    result_code: ResultCode,
    epoch_seconds: u32,
    public_ip: [4]u8,
};

pub const MapUdpResponse = struct {
    result_code: ResultCode,
    epoch_seconds: u32,
    internal_port: u16,
    external_port: u16,
    lifetime_seconds: u32,
};

pub const Response = union(enum) {
    public_address: PublicAddressResponse,
    map_udp: MapUdpResponse,
};

pub const MappingState = struct {
    public_ip: ?[4]u8 = null,
    external_port: ?u16 = null,
    lifetime_seconds: u32 = 0,
    refresh_at_ns: i64 = 0,
    expires_at_ns: i64 = 0,

    pub fn currentCandidate(self: *const MappingState) ?nat.Candidate {
        const ip = self.public_ip orelse return null;
        const port = self.external_port orelse return null;
        if (self.lifetime_seconds == 0) return null;
        return .{
            .ctype = .host,
            .addr = std.net.Address.initIp4(ip, port),
            .source = "nat-pmp",
        };
    }

    pub fn applyPublicAddress(self: *MappingState, public_ip: [4]u8) bool {
        const before = self.currentCandidate();
        self.public_ip = public_ip;
        const after = self.currentCandidate();
        return candidateChanged(before, after);
    }

    pub fn applyMapping(self: *MappingState, response: MapUdpResponse, now_ns: i64) bool {
        const before = self.currentCandidate();

        if (response.result_code != .success or response.lifetime_seconds == 0) {
            self.external_port = null;
            self.lifetime_seconds = 0;
            self.refresh_at_ns = 0;
            self.expires_at_ns = 0;
        } else {
            self.external_port = response.external_port;
            self.lifetime_seconds = response.lifetime_seconds;
            const refresh_seconds = @max(@as(u32, 1), response.lifetime_seconds / 2);
            self.refresh_at_ns = now_ns + @as(i64, refresh_seconds) * std.time.ns_per_s;
            self.expires_at_ns = now_ns + @as(i64, response.lifetime_seconds) * std.time.ns_per_s;
        }

        const after = self.currentCandidate();
        return candidateChanged(before, after);
    }

    pub fn maybeExpire(self: *MappingState, now_ns: i64) bool {
        if (self.expires_at_ns == 0 or now_ns < self.expires_at_ns) return false;

        const before = self.currentCandidate();
        self.external_port = null;
        self.lifetime_seconds = 0;
        self.refresh_at_ns = 0;
        self.expires_at_ns = 0;
        const after = self.currentCandidate();
        return candidateChanged(before, after);
    }
};

const RequestState = struct {
    awaiting: bool = false,
    retry_idx: usize = 0,
    next_retry_ns: i64 = 0,

    fn start(self: *RequestState, now_ns: i64) void {
        self.awaiting = true;
        self.retry_idx = 0;
        self.next_retry_ns = now_ns + @as(i64, retry_schedule_ms[0]) * std.time.ns_per_ms;
    }

    fn markDone(self: *RequestState) void {
        self.awaiting = false;
        self.retry_idx = 0;
        self.next_retry_ns = 0;
    }
};

pub const Client = struct {
    sock: udp.UdpSocket,
    gateway: std.net.Address,
    internal_port: u16,
    requested_lifetime_seconds: u32 = default_lifetime_seconds,
    state: MappingState = .{},
    public_request: RequestState = .{},
    map_request: RequestState = .{},
    request_cycle_active: bool = false,

    pub fn bootstrap(alloc: std.mem.Allocator, internal_port: u16) !?Client {
        const gateway = try discoverGateway(alloc) orelse return null;

        var sock = try udp.UdpSocket.bindEphemeral(posix.AF.INET);
        errdefer sock.close();

        var client = Client{
            .sock = sock,
            .gateway = gateway,
            .internal_port = internal_port,
        };
        errdefer client.deinit();

        const now: i64 = @intCast(std.time.nanoTimestamp());
        try client.beginRequestCycle(now);

        const deadline = now + 750 * std.time.ns_per_ms;
        while (@as(i64, @intCast(std.time.nanoTimestamp())) < deadline) {
            const loop_now: i64 = @intCast(std.time.nanoTimestamp());
            _ = try client.service(loop_now);
            if (client.currentCandidate() != null) return client;
            if (!client.hasPendingWork()) break;

            const delay_ms = client.pollDelayMs(loop_now) orelse break;
            var poll_fds = [_]posix.pollfd{.{ .fd = client.sock.getFd(), .events = posix.POLL.IN, .revents = 0 }};
            _ = posix.poll(&poll_fds, @intCast(@max(@as(i64, 1), delay_ms))) catch |err| {
                if (err == error.Interrupted) continue;
                break;
            };
            if (poll_fds[0].revents & posix.POLL.IN != 0) {
                _ = try client.handleReadable(@intCast(std.time.nanoTimestamp()));
                if (client.currentCandidate() != null) return client;
            }
        }

        return null;
    }

    pub fn deinit(self: *Client) void {
        self.sock.close();
    }

    pub fn currentCandidate(self: *const Client) ?nat.Candidate {
        return self.state.currentCandidate();
    }

    pub fn wantsPoll(self: *const Client) bool {
        return self.public_request.awaiting or self.map_request.awaiting;
    }

    pub fn pollDelayMs(self: *const Client, now_ns: i64) ?i64 {
        var delay_ns: ?i64 = null;

        if (self.public_request.awaiting) {
            const delta = @max(@as(i64, 0), self.public_request.next_retry_ns - now_ns);
            delay_ns = if (delay_ns) |existing| @min(existing, delta) else delta;
        }
        if (self.map_request.awaiting) {
            const delta = @max(@as(i64, 0), self.map_request.next_retry_ns - now_ns);
            delay_ns = if (delay_ns) |existing| @min(existing, delta) else delta;
        }
        if (!self.request_cycle_active and self.state.refresh_at_ns != 0) {
            const delta = @max(@as(i64, 0), self.state.refresh_at_ns - now_ns);
            delay_ns = if (delay_ns) |existing| @min(existing, delta) else delta;
        }
        if (self.state.expires_at_ns != 0) {
            const delta = @max(@as(i64, 0), self.state.expires_at_ns - now_ns);
            delay_ns = if (delay_ns) |existing| @min(existing, delta) else delta;
        }

        return if (delay_ns) |value| @divFloor(value, std.time.ns_per_ms) else null;
    }

    pub fn service(self: *Client, now_ns: i64) !bool {
        const changed = self.state.maybeExpire(now_ns);

        if (!self.request_cycle_active and self.state.refresh_at_ns != 0 and now_ns >= self.state.refresh_at_ns) {
            try self.beginRequestCycle(now_ns);
        }

        try self.maybeRetryPublic(now_ns);
        try self.maybeRetryMap(now_ns);

        return changed;
    }

    pub fn handleReadable(self: *Client, now_ns: i64) !bool {
        var changed = false;
        while (true) {
            var recv_buf: [128]u8 = undefined;
            const packet = try self.sock.recvRaw(&recv_buf) orelse break;
            if (!isGatewayPacket(self.gateway, packet.from)) continue;

            const response = parseResponse(packet.data) catch continue;
            switch (response) {
                .public_address => |public| {
                    self.public_request.markDone();
                    if (public.result_code == .success) {
                        changed = self.state.applyPublicAddress(public.public_ip) or changed;
                    }
                },
                .map_udp => |mapping| {
                    self.map_request.markDone();
                    if (mapping.result_code == .success) {
                        self.request_cycle_active = false;
                    }
                    changed = self.state.applyMapping(mapping, now_ns) or changed;
                },
            }
        }
        return changed;
    }

    fn beginRequestCycle(self: *Client, now_ns: i64) !void {
        self.request_cycle_active = true;

        self.public_request.start(now_ns);
        self.sendPublicAddressRequest() catch |err| {
            if (err == error.WouldBlock) {
                self.public_request.next_retry_ns = now_ns + 50 * std.time.ns_per_ms;
            } else {
                return err;
            }
        };

        self.map_request.start(now_ns);
        self.sendMapRequest() catch |err| {
            if (err == error.WouldBlock) {
                self.map_request.next_retry_ns = now_ns + 50 * std.time.ns_per_ms;
            } else {
                return err;
            }
        };
    }

    fn maybeRetryPublic(self: *Client, now_ns: i64) !void {
        if (!self.public_request.awaiting or now_ns < self.public_request.next_retry_ns) return;
        if (self.public_request.retry_idx >= retry_schedule_ms.len) {
            self.public_request.markDone();
            return;
        }

        self.sendPublicAddressRequest() catch |err| {
            if (err == error.WouldBlock) {
                self.public_request.next_retry_ns = now_ns + 50 * std.time.ns_per_ms;
                return;
            }
            return err;
        };
        const interval_ms = retry_schedule_ms[self.public_request.retry_idx];
        self.public_request.retry_idx += 1;
        self.public_request.next_retry_ns = now_ns + @as(i64, interval_ms) * std.time.ns_per_ms;
    }

    fn maybeRetryMap(self: *Client, now_ns: i64) !void {
        if (!self.map_request.awaiting or now_ns < self.map_request.next_retry_ns) return;
        if (self.map_request.retry_idx >= retry_schedule_ms.len) {
            self.map_request.markDone();
            return;
        }

        self.sendMapRequest() catch |err| {
            if (err == error.WouldBlock) {
                self.map_request.next_retry_ns = now_ns + 50 * std.time.ns_per_ms;
                return;
            }
            return err;
        };
        const interval_ms = retry_schedule_ms[self.map_request.retry_idx];
        self.map_request.retry_idx += 1;
        self.map_request.next_retry_ns = now_ns + @as(i64, interval_ms) * std.time.ns_per_ms;
    }

    fn hasPendingWork(self: *const Client) bool {
        return self.wantsPoll() or self.currentCandidate() != null or (!self.request_cycle_active and self.state.refresh_at_ns != 0);
    }

    fn sendPublicAddressRequest(self: *Client) !void {
        var buf: [2]u8 = undefined;
        try self.sock.sendTo(encodePublicAddressRequest(&buf), self.gateway);
    }

    fn sendMapRequest(self: *Client) !void {
        var buf: [12]u8 = undefined;
        try self.sock.sendTo(encodeMapUdpRequest(self.internal_port, self.internal_port, self.requested_lifetime_seconds, &buf), self.gateway);
    }
};

pub fn encodePublicAddressRequest(buf: *[2]u8) []const u8 {
    buf[0] = 0;
    buf[1] = @intFromEnum(Opcode.public_address);
    return buf;
}

pub fn encodeMapUdpRequest(internal_port: u16, requested_external_port: u16, lifetime_seconds: u32, buf: *[12]u8) []const u8 {
    buf[0] = 0;
    buf[1] = @intFromEnum(Opcode.map_udp);
    std.mem.writeInt(u16, buf[2..4], 0, .big);
    std.mem.writeInt(u16, buf[4..6], internal_port, .big);
    std.mem.writeInt(u16, buf[6..8], requested_external_port, .big);
    std.mem.writeInt(u32, buf[8..12], lifetime_seconds, .big);
    return buf;
}

pub fn parseResponse(data: []const u8) !Response {
    if (data.len < 8) return error.InvalidNatPmpResponse;
    if (data[0] != 0) return error.InvalidNatPmpResponse;
    if ((data[1] & 0x80) == 0) return error.InvalidNatPmpResponse;

    const opcode = data[1] & 0x7f;
    const result_code = ResultCode.fromInt(std.mem.readInt(u16, data[2..4], .big));
    const epoch_seconds = std.mem.readInt(u32, data[4..8], .big);

    switch (opcode) {
        @intFromEnum(Opcode.public_address) => {
            if (data.len != 12) return error.InvalidNatPmpResponse;
            return .{ .public_address = .{
                .result_code = result_code,
                .epoch_seconds = epoch_seconds,
                .public_ip = data[8..12].*,
            } };
        },
        @intFromEnum(Opcode.map_udp) => {
            if (data.len != 16) return error.InvalidNatPmpResponse;
            return .{ .map_udp = .{
                .result_code = result_code,
                .epoch_seconds = epoch_seconds,
                .internal_port = std.mem.readInt(u16, data[8..10], .big),
                .external_port = std.mem.readInt(u16, data[10..12], .big),
                .lifetime_seconds = std.mem.readInt(u32, data[12..16], .big),
            } };
        },
        else => return error.InvalidNatPmpResponse,
    }
}

pub fn discoverGateway(alloc: std.mem.Allocator) !?std.net.Address {
    if (posix.getenv("ZMX_NAT_PMP_GATEWAY")) |raw| {
        return try resolveGatewayOverride(alloc, raw);
    }

    return switch (builtin.os.tag) {
        .linux => try discoverGatewayLinux(alloc),
        .macos, .freebsd => try discoverGatewayBsd(alloc),
        else => null,
    };
}

fn resolveGatewayOverride(alloc: std.mem.Allocator, raw: []const u8) !?std.net.Address {
    const hp = nat.parseHostPort(raw, nat_pmp_port) catch return null;
    const list = std.net.getAddressList(alloc, hp.host, hp.port) catch return null;
    defer list.deinit();

    for (list.addrs) |addr| {
        if (addr.any.family == posix.AF.INET) return addr;
    }
    return null;
}

fn discoverGatewayLinux(alloc: std.mem.Allocator) !?std.net.Address {
    const file = std.fs.openFileAbsolute("/proc/net/route", .{}) catch return null;
    defer file.close();

    const contents = try file.readToEndAlloc(alloc, 64 * 1024);
    defer alloc.free(contents);

    var lines = std.mem.splitScalar(u8, contents, '\n');
    _ = lines.next();
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;

        var fields = std.mem.tokenizeAny(u8, trimmed, " \t");
        _ = fields.next() orelse continue;
        const destination = fields.next() orelse continue;
        const gateway = fields.next() orelse continue;
        const flags = fields.next() orelse continue;

        const destination_value = std.fmt.parseUnsigned(u32, destination, 16) catch continue;
        if (destination_value != 0) continue;

        const flags_value = std.fmt.parseUnsigned(u32, flags, 16) catch continue;
        if ((flags_value & 0x2) == 0) continue;

        const gateway_value = std.fmt.parseUnsigned(u32, gateway, 16) catch continue;
        if (gateway_value == 0) continue;

        const ip = [4]u8{
            @truncate(gateway_value),
            @truncate(gateway_value >> 8),
            @truncate(gateway_value >> 16),
            @truncate(gateway_value >> 24),
        };
        return std.net.Address.initIp4(ip, nat_pmp_port);
    }

    return null;
}

fn discoverGatewayBsd(alloc: std.mem.Allocator) !?std.net.Address {
    if (!(builtin.os.tag == .macos or builtin.os.tag == .freebsd)) return null;

    var mib = [_]c_int{
        bsd_c.CTL_NET,
        bsd_c.PF_ROUTE,
        0,
        bsd_c.AF_INET,
        bsd_c.NET_RT_FLAGS,
        bsd_c.RTF_GATEWAY,
    };
    var needed: usize = 0;
    if (bsd_c.sysctl(&mib, mib.len, null, &needed, null, 0) != 0 or needed == 0) return null;

    const buffer = try alloc.alloc(u8, needed);
    defer alloc.free(buffer);

    if (bsd_c.sysctl(&mib, mib.len, buffer.ptr, &needed, null, 0) != 0) return null;

    var offset: usize = 0;
    while (offset + @sizeOf(bsd_c.struct_rt_msghdr) <= needed) {
        const rtm: *const bsd_c.struct_rt_msghdr = @ptrCast(@alignCast(buffer.ptr + offset));
        if (rtm.rtm_msglen == 0 or offset + rtm.rtm_msglen > needed) break;

        var cursor = offset + @sizeOf(bsd_c.struct_rt_msghdr);
        const message_end = offset + rtm.rtm_msglen;
        var dst: ?*const bsd_c.struct_sockaddr = null;
        var gateway: ?*const bsd_c.struct_sockaddr = null;
        var mask: ?*const bsd_c.struct_sockaddr = null;

        var addr_idx: usize = 0;
        while (addr_idx < bsd_c.RTAX_MAX and cursor + @sizeOf(bsd_c.struct_sockaddr) <= message_end) : (addr_idx += 1) {
            const bit = @as(i32, 1) << @intCast(addr_idx);
            if ((rtm.rtm_addrs & bit) == 0) continue;

            const sa: *const bsd_c.struct_sockaddr = @ptrCast(@alignCast(buffer.ptr + cursor));
            switch (addr_idx) {
                bsd_c.RTAX_DST => dst = sa,
                bsd_c.RTAX_GATEWAY => gateway = sa,
                bsd_c.RTAX_NETMASK => mask = sa,
                else => {},
            }
            cursor += sockaddrStorageLen(sa);
        }

        if (isDefaultRoute(dst, mask) and gateway != null and gateway.?.sa_family == bsd_c.AF_INET) {
            const in: *const bsd_c.struct_sockaddr_in = @ptrCast(@alignCast(gateway.?));
            const addr_u32 = std.mem.bigToNative(u32, in.sin_addr.s_addr);
            const ip = [4]u8{
                @truncate(addr_u32 >> 24),
                @truncate(addr_u32 >> 16),
                @truncate(addr_u32 >> 8),
                @truncate(addr_u32),
            };
            return std.net.Address.initIp4(ip, nat_pmp_port);
        }

        offset += rtm.rtm_msglen;
    }

    return null;
}

fn sockaddrStorageLen(sa: *const bsd_c.struct_sockaddr) usize {
    const raw_len: usize = if (sa.sa_len == 0) @sizeOf(bsd_c.struct_sockaddr) else sa.sa_len;
    return std.mem.alignForward(usize, raw_len, @sizeOf(usize));
}

fn isDefaultRoute(dst: ?*const bsd_c.struct_sockaddr, mask: ?*const bsd_c.struct_sockaddr) bool {
    const dst_sa = dst orelse return false;
    if (dst_sa.sa_family != bsd_c.AF_INET) return false;

    const dst_in: *const bsd_c.struct_sockaddr_in = @ptrCast(@alignCast(dst_sa));
    if (dst_in.sin_addr.s_addr != 0) return false;

    if (mask) |mask_sa| {
        if (mask_sa.sa_family != bsd_c.AF_INET) return false;
        const mask_in: *const bsd_c.struct_sockaddr_in = @ptrCast(@alignCast(mask_sa));
        return mask_in.sin_addr.s_addr == 0;
    }

    return true;
}

fn isGatewayPacket(expected_gateway: std.net.Address, from: std.net.Address) bool {
    if (from.any.family != posix.AF.INET) return false;
    return nat.isAddressEqual(expected_gateway, from);
}

fn candidateChanged(before: ?nat.Candidate, after: ?nat.Candidate) bool {
    if (before == null and after == null) return false;
    if (before == null or after == null) return true;
    return !nat.isAddressEqual(before.?.addr, after.?.addr) or before.?.ctype != after.?.ctype;
}

test "nat-pmp request encoding" {
    var public_buf: [2]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0, 0 }, encodePublicAddressRequest(&public_buf));

    var map_buf: [12]u8 = undefined;
    const request = encodeMapUdpRequest(60000, 60000, 7200, &map_buf);
    try std.testing.expectEqual(@as(usize, 12), request.len);
    try std.testing.expectEqual(@as(u8, 0), request[0]);
    try std.testing.expectEqual(@as(u8, 1), request[1]);
    try std.testing.expectEqual(@as(u16, 60000), std.mem.readInt(u16, request[4..6], .big));
    try std.testing.expectEqual(@as(u16, 60000), std.mem.readInt(u16, request[6..8], .big));
    try std.testing.expectEqual(@as(u32, 7200), std.mem.readInt(u32, request[8..12], .big));
}

test "nat-pmp response decoding" {
    var public_response = [_]u8{0} ** 12;
    public_response[1] = 0x80;
    std.mem.writeInt(u16, public_response[2..4], 0, .big);
    std.mem.writeInt(u32, public_response[4..8], 7, .big);
    public_response[8..12].* = .{ 203, 0, 113, 7 };

    const decoded_public = try parseResponse(&public_response);
    switch (decoded_public) {
        .public_address => |resp| {
            try std.testing.expect(resp.result_code == .success);
            try std.testing.expectEqual(@as(u32, 7), resp.epoch_seconds);
            try std.testing.expectEqualSlices(u8, &[_]u8{ 203, 0, 113, 7 }, &resp.public_ip);
        },
        else => try std.testing.expect(false),
    }

    var map_response = [_]u8{0} ** 16;
    map_response[1] = 0x81;
    std.mem.writeInt(u16, map_response[2..4], 0, .big);
    std.mem.writeInt(u32, map_response[4..8], 11, .big);
    std.mem.writeInt(u16, map_response[8..10], 60000, .big);
    std.mem.writeInt(u16, map_response[10..12], 45678, .big);
    std.mem.writeInt(u32, map_response[12..16], 3600, .big);

    const decoded_map = try parseResponse(&map_response);
    switch (decoded_map) {
        .map_udp => |resp| {
            try std.testing.expect(resp.result_code == .success);
            try std.testing.expectEqual(@as(u16, 60000), resp.internal_port);
            try std.testing.expectEqual(@as(u16, 45678), resp.external_port);
            try std.testing.expectEqual(@as(u32, 3600), resp.lifetime_seconds);
        },
        else => try std.testing.expect(false),
    }
}

test "mapping state schedules refresh and expires" {
    var state = MappingState{};

    try std.testing.expect(!state.applyPublicAddress(.{ 198, 51, 100, 20 }));
    try std.testing.expect(state.currentCandidate() == null);

    const changed = state.applyMapping(.{
        .result_code = .success,
        .epoch_seconds = 0,
        .internal_port = 60000,
        .external_port = 45678,
        .lifetime_seconds = 120,
    }, 1_000);
    try std.testing.expect(changed);

    const candidate = state.currentCandidate().?;
    try std.testing.expectEqual(@as(u16, 45678), candidate.addr.getPort());
    try std.testing.expectEqual(@as(i64, 1_000 + 60 * std.time.ns_per_s), state.refresh_at_ns);
    try std.testing.expectEqual(@as(i64, 1_000 + 120 * std.time.ns_per_s), state.expires_at_ns);

    try std.testing.expect(!state.maybeExpire(1_000 + 119 * std.time.ns_per_s));
    try std.testing.expect(state.maybeExpire(1_000 + 120 * std.time.ns_per_s));
    try std.testing.expect(state.currentCandidate() == null);
}
