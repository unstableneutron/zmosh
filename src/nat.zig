const std = @import("std");
const posix = std.posix;
const udp = @import("udp.zig");

const c = @cImport({
    @cInclude("ifaddrs.h");
    @cInclude("net/if.h");
    @cInclude("netinet/in.h");
    @cInclude("sys/socket.h");
});

pub const stun_magic_cookie: u32 = 0x2112A442;
pub const default_stun_servers = [_][]const u8{
    "stun.cloudflare.com:3478",
    "stun.l.google.com:19302",
};
const retry_schedule_ms = [_]u32{ 500, 1000, 2000 };

pub const max_candidates: usize = 8;

pub const CandidateType = enum {
    host,
    srflx,
};

pub const Candidate = struct {
    ctype: CandidateType,
    addr: std.net.Address,
    source: []const u8,
};

pub const CandidateWire = struct {
    ctype: CandidateType,
    endpoint: []const u8,
    source: []const u8,
};

pub const Connect2Payload = struct {
    v: u8 = 2,
    key: []const u8,
    port: u16,
    candidates: []CandidateWire,
    ssh_fallback: bool = true,
};

pub const Candidates2Payload = struct {
    candidates: []CandidateWire,
};

pub const TimingStats = struct {
    samples: usize = 0,
    min_ns: ?i64 = null,
    max_ns: ?i64 = null,
    total_ns: i128 = 0,

    pub fn observe(self: *TimingStats, duration_ns: i64) void {
        if (duration_ns <= 0) return;
        self.samples += 1;
        self.total_ns += duration_ns;
        self.min_ns = if (self.min_ns) |existing| @min(existing, duration_ns) else duration_ns;
        self.max_ns = if (self.max_ns) |existing| @max(existing, duration_ns) else duration_ns;
    }

    pub fn averageNs(self: *const TimingStats) ?i64 {
        if (self.samples == 0) return null;
        return @as(i64, @intCast(@divFloor(self.total_ns, @as(i128, @intCast(self.samples)))));
    }

    pub fn conservativeNs(self: *const TimingStats) ?i64 {
        return self.max_ns orelse self.averageNs();
    }
};

pub const SrflxGatherResult = struct {
    candidates: std.ArrayList(Candidate),
    responsive_servers: usize = 0,
    rtt_stats: TimingStats = .{},

    pub fn deinit(self: *SrflxGatherResult, alloc: std.mem.Allocator) void {
        self.candidates.deinit(alloc);
    }
};

pub fn encodeCandidatesPayloadJson(alloc: std.mem.Allocator, candidates: []const Candidate) ![]u8 {
    var wire_list = try std.ArrayList(CandidateWire).initCapacity(alloc, candidates.len);
    defer wire_list.deinit(alloc);
    var owned_endpoints = try std.ArrayList([]u8).initCapacity(alloc, candidates.len);
    defer {
        for (owned_endpoints.items) |ep| alloc.free(ep);
        owned_endpoints.deinit(alloc);
    }

    for (candidates) |candidate| {
        const endpoint = try endpointForAddressAlloc(alloc, candidate.addr);
        try owned_endpoints.append(alloc, endpoint);
        try wire_list.append(alloc, .{
            .ctype = candidate.ctype,
            .endpoint = endpoint,
            .source = candidate.source,
        });
    }

    const payload = Candidates2Payload{ .candidates = wire_list.items };
    var builder: std.Io.Writer.Allocating = .init(alloc);
    errdefer builder.deinit();
    try builder.writer.print("{f}", .{std.json.fmt(payload, .{})});
    return builder.toOwnedSlice();
}

pub fn parseCandidatesPayloadJson(alloc: std.mem.Allocator, json_payload: []const u8) !std.ArrayList(Candidate) {
    var parsed = try std.json.parseFromSlice(Candidates2Payload, alloc, json_payload, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var out = try std.ArrayList(Candidate).initCapacity(alloc, parsed.value.candidates.len);
    errdefer out.deinit(alloc);
    for (parsed.value.candidates) |wire| {
        const candidate = try wireToCandidate(wire);
        if (!isCandidateAddressUsable(candidate.addr)) continue;
        try out.append(alloc, candidate);
    }
    return out;
}

pub fn endpointForAddressAlloc(alloc: std.mem.Allocator, addr: std.net.Address) ![]u8 {
    return std.fmt.allocPrint(alloc, "{f}", .{addr});
}

pub const HostPort = struct {
    host: []const u8,
    port: u16,
};

pub fn parseHostPort(spec: []const u8, default_port: u16) !HostPort {
    if (spec.len == 0) return error.InvalidHostPort;

    if (spec[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, spec, ']') orelse return error.InvalidHostPort;
        const host = spec[1..close_idx];
        if (host.len == 0) return error.InvalidHostPort;

        if (close_idx + 1 == spec.len) {
            return .{ .host = host, .port = default_port };
        }

        if (close_idx + 2 > spec.len or spec[close_idx + 1] != ':') return error.InvalidHostPort;
        const port = std.fmt.parseInt(u16, spec[close_idx + 2 ..], 10) catch return error.InvalidHostPort;
        return .{ .host = host, .port = port };
    }

    const colon_idx_opt = std.mem.lastIndexOfScalar(u8, spec, ':');
    if (colon_idx_opt == null) {
        return .{ .host = spec, .port = default_port };
    }

    const colon_idx = colon_idx_opt.?;
    const host = spec[0..colon_idx];
    if (host.len == 0) return error.InvalidHostPort;
    const port = std.fmt.parseInt(u16, spec[colon_idx + 1 ..], 10) catch return error.InvalidHostPort;
    return .{ .host = host, .port = port };
}

pub fn resolveStunServers(
    alloc: std.mem.Allocator,
    socket_family: u16,
    server_specs: []const []const u8,
) !std.ArrayList(std.net.Address) {
    const specs = if (server_specs.len > 0) server_specs else default_stun_servers[0..];

    var out = try std.ArrayList(std.net.Address).initCapacity(alloc, specs.len);
    errdefer out.deinit(alloc);

    for (specs) |spec| {
        const hp = parseHostPort(spec, 3478) catch continue;
        const list = std.net.getAddressList(alloc, hp.host, hp.port) catch continue;
        defer list.deinit();

        for (list.addrs) |addr| {
            if (!shouldUseCandidate(socket_family, addr)) continue;

            var exists = false;
            for (out.items) |existing| {
                if (isAddressEqual(existing, addr)) {
                    exists = true;
                    break;
                }
            }
            if (!exists) try out.append(alloc, addr);
        }
    }

    return out;
}

pub fn parseEndpoint(endpoint: []const u8) !std.net.Address {
    if (endpoint.len == 0) return error.InvalidEndpoint;

    if (endpoint[0] == '[') {
        const close_idx = std.mem.indexOfScalar(u8, endpoint, ']') orelse return error.InvalidEndpoint;
        if (close_idx + 2 >= endpoint.len or endpoint[close_idx + 1] != ':') return error.InvalidEndpoint;

        const host = endpoint[1..close_idx];
        const port = std.fmt.parseInt(u16, endpoint[close_idx + 2 ..], 10) catch return error.InvalidEndpoint;
        return std.net.Address.parseIp(host, port) catch return error.InvalidEndpoint;
    }

    const colon_idx = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return error.InvalidEndpoint;
    const host = endpoint[0..colon_idx];
    const port = std.fmt.parseInt(u16, endpoint[colon_idx + 1 ..], 10) catch return error.InvalidEndpoint;
    return std.net.Address.parseIp(host, port) catch return error.InvalidEndpoint;
}

pub fn wireToCandidate(wire: CandidateWire) !Candidate {
    return .{
        .ctype = wire.ctype,
        .addr = try parseEndpoint(wire.endpoint),
        .source = if (wire.ctype == .srflx) "srflx" else "host",
    };
}

pub fn isAddressEqual(a: std.net.Address, b: std.net.Address) bool {
    if (a.any.family != b.any.family) return false;
    if (a.getPort() != b.getPort()) return false;

    switch (a.any.family) {
        posix.AF.INET => return a.in.sa.addr == b.in.sa.addr,
        posix.AF.INET6 => return std.mem.eql(u8, &a.in6.sa.addr, &b.in6.sa.addr),
        else => return false,
    }
}

pub fn isStunPacket(server_addr: std.net.Address, from: std.net.Address, data: []const u8) bool {
    if (!isAddressEqual(server_addr, from)) return false;
    if (data.len < 20) return false;
    const cookie = std.mem.readInt(u32, data[4..][0..4], .big);
    return cookie == stun_magic_cookie;
}

pub const StunState = struct {
    txn_id: [12]u8,
    server_addr: std.net.Address,
    sent_ns: i64 = 0,
    retries: u8 = 0,
    result: ?Candidate = null,
    last_rtt_ns: ?i64 = null,

    waiting_response: bool = false,
    next_retry_ns: i64 = 0,

    pub fn init(server_addr: std.net.Address) StunState {
        var txn_id: [12]u8 = undefined;
        std.crypto.random.bytes(&txn_id);
        return .{
            .txn_id = txn_id,
            .server_addr = server_addr,
        };
    }

    pub fn sendRequest(self: *StunState, sock: *udp.UdpSocket) !void {
        var req: [20]u8 = undefined;
        std.mem.writeInt(u16, req[0..2], 0x0001, .big);
        std.mem.writeInt(u16, req[2..4], 0, .big);
        std.mem.writeInt(u32, req[4..8], stun_magic_cookie, .big);
        req[8..20].* = self.txn_id;
        try sock.sendTo(&req, self.server_addr);

        const now: i64 = @intCast(std.time.nanoTimestamp());
        self.sent_ns = now;
        self.waiting_response = true;
        self.next_retry_ns = now + @as(i64, retry_schedule_ms[0]) * std.time.ns_per_ms;
    }

    pub fn maybeRetry(self: *StunState, sock: *udp.UdpSocket, now_ns: i64) !void {
        if (!self.waiting_response or self.result != null) return;
        if (self.retries >= retry_schedule_ms.len) {
            self.waiting_response = false;
            return;
        }
        if (now_ns < self.next_retry_ns) return;

        var req: [20]u8 = undefined;
        std.mem.writeInt(u16, req[0..2], 0x0001, .big);
        std.mem.writeInt(u16, req[2..4], 0, .big);
        std.mem.writeInt(u32, req[4..8], stun_magic_cookie, .big);
        req[8..20].* = self.txn_id;
        sock.sendTo(&req, self.server_addr) catch |err| {
            if (err == error.WouldBlock) {
                self.next_retry_ns = now_ns + 50 * std.time.ns_per_ms;
                return;
            }
            return err;
        };

        self.retries += 1;

        self.sent_ns = now_ns;
        if (self.retries < retry_schedule_ms.len) {
            self.next_retry_ns = now_ns + @as(i64, retry_schedule_ms[self.retries]) * std.time.ns_per_ms;
        } else {
            self.next_retry_ns = now_ns;
        }
    }

    pub fn handleResponse(self: *StunState, data: []const u8) !?Candidate {
        if (data.len < 20) return error.InvalidStunResponse;

        const msg_type = std.mem.readInt(u16, data[0..][0..2], .big);
        if (msg_type != 0x0101) return null;

        const msg_len = std.mem.readInt(u16, data[2..][0..2], .big);
        if (data.len < 20 + msg_len) return error.InvalidStunResponse;

        const cookie = std.mem.readInt(u32, data[4..][0..4], .big);
        if (cookie != stun_magic_cookie) return error.InvalidStunResponse;
        if (!std.mem.eql(u8, data[8..20], &self.txn_id)) return null;

        var offset: usize = 20;
        const end = 20 + msg_len;
        while (offset + 4 <= end) {
            const attr_type = std.mem.readInt(u16, data[offset..][0..2], .big);
            const attr_len = std.mem.readInt(u16, data[offset + 2 ..][0..2], .big);
            offset += 4;
            if (offset + attr_len > end) return error.InvalidStunResponse;

            const value = data[offset .. offset + attr_len];
            if (attr_type == 0x0020) {
                const candidate = try parseXorMappedAddress(value, self.txn_id);
                self.result = candidate;
                self.last_rtt_ns = @as(i64, @intCast(std.time.nanoTimestamp())) - self.sent_ns;
                self.waiting_response = false;
                return candidate;
            }

            offset += align4(attr_len);
        }

        return null;
    }
};

fn align4(len: usize) usize {
    return (len + 3) & ~@as(usize, 3);
}

fn parseXorMappedAddress(value: []const u8, txn_id: [12]u8) !Candidate {
    if (value.len < 4) return error.InvalidStunResponse;
    const family = value[1];
    const x_port = std.mem.readInt(u16, value[2..][0..2], .big);
    const port = x_port ^ @as(u16, @truncate(stun_magic_cookie >> 16));

    if (family == 0x01) {
        if (value.len < 8) return error.InvalidStunResponse;
        const x_addr = std.mem.readInt(u32, value[4..][0..4], .big);
        const addr_u32 = x_addr ^ stun_magic_cookie;
        var ip: [4]u8 = undefined;
        std.mem.writeInt(u32, &ip, addr_u32, .big);
        return .{
            .ctype = .srflx,
            .addr = std.net.Address.initIp4(ip, port),
            .source = "stun",
        };
    }

    if (family == 0x02) {
        if (value.len < 20) return error.InvalidStunResponse;

        const cookie_bytes = std.mem.asBytes(&std.mem.nativeToBig(u32, stun_magic_cookie));
        var xor_key: [16]u8 = undefined;
        @memcpy(xor_key[0..4], cookie_bytes);
        @memcpy(xor_key[4..16], &txn_id);

        var ip: [16]u8 = undefined;
        for (0..16) |i| ip[i] = value[4 + i] ^ xor_key[i];

        return .{
            .ctype = .srflx,
            .addr = std.net.Address.initIp6(ip, port, 0, 0),
            .source = "stun",
        };
    }

    return error.InvalidStunResponse;
}

pub fn shouldUseCandidate(socket_family: u16, addr: std.net.Address) bool {
    if (socket_family == posix.AF.INET and addr.any.family != posix.AF.INET) return false;
    if (socket_family == posix.AF.INET6 and addr.any.family != posix.AF.INET and addr.any.family != posix.AF.INET6) return false;
    return addr.any.family == posix.AF.INET or addr.any.family == posix.AF.INET6;
}

fn shouldIgnoreInterface(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "docker") or
        std.mem.startsWith(u8, name, "br-") or
        std.mem.startsWith(u8, name, "veth") or
        std.mem.startsWith(u8, name, "utun") or
        std.mem.startsWith(u8, name, "bridge");
}

fn isIp4CandidateUsable(ip: [4]u8) bool {
    if (ip[0] == 0) return false;
    if (ip[0] == 127) return false;
    if (ip[0] == 169 and ip[1] == 254) return false;
    if (ip[0] >= 224 and ip[0] <= 239) return false;
    return true;
}

fn isIp4Privateish(ip: [4]u8) bool {
    if (ip[0] == 10) return true;
    if (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) return true;
    if (ip[0] == 192 and ip[1] == 168) return true;
    if (ip[0] == 100 and ip[1] >= 64 and ip[1] <= 127) return true;
    return false;
}

fn isIp6Loopback(ip: [16]u8) bool {
    return std.mem.eql(u8, ip[0..15], &([_]u8{0} ** 15)) and ip[15] == 1;
}

fn isIp6AllZero(ip: [16]u8) bool {
    return std.mem.eql(u8, &ip, &([_]u8{0} ** 16));
}

fn isIp6UniqueLocal(ip: [16]u8) bool {
    return (ip[0] & 0xfe) == 0xfc;
}

fn isIp6CandidateUsable(ip: [16]u8) bool {
    if (isIp6AllZero(ip) or isIp6Loopback(ip)) return false;
    if (ip[0] == 0xff) return false;
    if (ip[0] == 0xfe and (ip[1] & 0xc0) == 0x80) return false;
    return true;
}

pub fn isCandidateAddressUsable(addr: std.net.Address) bool {
    return switch (addr.any.family) {
        posix.AF.INET => blk: {
            const addr_u32 = std.mem.bigToNative(u32, addr.in.sa.addr);
            const ip = [4]u8{
                @truncate(addr_u32 >> 24),
                @truncate(addr_u32 >> 16),
                @truncate(addr_u32 >> 8),
                @truncate(addr_u32),
            };
            break :blk isIp4CandidateUsable(ip);
        },
        posix.AF.INET6 => isIp6CandidateUsable(addr.in6.sa.addr),
        else => false,
    };
}

pub fn appendUniqueCandidate(list: *std.ArrayList(Candidate), alloc: std.mem.Allocator, candidate: Candidate) !void {
    for (list.items) |existing| {
        if (isAddressEqual(existing.addr, candidate.addr)) return;
    }
    try list.append(alloc, candidate);
}

pub fn gatherHostCandidates(
    alloc: std.mem.Allocator,
    local_port: u16,
    socket_family: u16,
    max_candidates_limit: usize,
) !std.ArrayList(Candidate) {
    var out = try std.ArrayList(Candidate).initCapacity(alloc, 8);

    var ifap: ?*c.struct_ifaddrs = null;
    if (c.getifaddrs(&ifap) != 0) return out;
    defer c.freeifaddrs(ifap);

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        if (ifa.ifa_addr == null) continue;
        if ((ifa.ifa_flags & c.IFF_UP) == 0) continue;
        if ((ifa.ifa_flags & c.IFF_LOOPBACK) != 0) continue;

        const if_name = std.mem.span(ifa.ifa_name);
        if (shouldIgnoreInterface(if_name)) continue;

        const fam: u16 = ifa.ifa_addr.*.sa_family;
        if (fam == posix.AF.INET) {
            if (!shouldUseCandidate(socket_family, std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0))) continue;

            const in_ptr: *const c.struct_sockaddr_in = @ptrCast(@alignCast(ifa.ifa_addr));
            const addr_u32 = std.mem.bigToNative(u32, in_ptr.sin_addr.s_addr);
            const ip = [4]u8{
                @truncate(addr_u32 >> 24),
                @truncate(addr_u32 >> 16),
                @truncate(addr_u32 >> 8),
                @truncate(addr_u32),
            };
            if (!isIp4CandidateUsable(ip)) continue;

            try appendUniqueCandidate(&out, alloc, .{
                .ctype = .host,
                .addr = std.net.Address.initIp4(ip, local_port),
                .source = "ifaddr",
            });
        } else if (fam == posix.AF.INET6) {
            if (socket_family == posix.AF.INET) continue;

            const in6_ptr: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(ifa.ifa_addr));
            const ip: [16]u8 = @as(*const [16]u8, @ptrCast(&in6_ptr.sin6_addr)).*;
            if (!isIp6CandidateUsable(ip)) continue;

            try appendUniqueCandidate(&out, alloc, .{
                .ctype = .host,
                .addr = std.net.Address.initIp6(ip, local_port, 0, 0),
                .source = "ifaddr",
            });
        }
    }

    sortAndTruncateCandidates(&out, max_candidates_limit);
    return out;
}

fn candidatePriority(candidate: Candidate) u8 {
    return switch (candidate.ctype) {
        .host => switch (candidate.addr.any.family) {
            posix.AF.INET6 => if (isIp6UniqueLocal(candidate.addr.in6.sa.addr)) 4 else 0,
            posix.AF.INET => blk: {
                const addr_u32 = std.mem.bigToNative(u32, candidate.addr.in.sa.addr);
                const ip = [4]u8{
                    @truncate(addr_u32 >> 24),
                    @truncate(addr_u32 >> 16),
                    @truncate(addr_u32 >> 8),
                    @truncate(addr_u32),
                };
                break :blk if (isIp4Privateish(ip)) 5 else 1;
            },
            else => 7,
        },
        .srflx => switch (candidate.addr.any.family) {
            posix.AF.INET6 => 2,
            posix.AF.INET => 3,
            else => 6,
        },
    };
}

pub fn sortCandidatesByPriority(candidates: []Candidate) void {
    var i: usize = 1;
    while (i < candidates.len) : (i += 1) {
        const key = candidates[i];
        const key_priority = candidatePriority(key);
        var j = i;
        while (j > 0) {
            if (candidatePriority(candidates[j - 1]) <= key_priority) break;
            candidates[j] = candidates[j - 1];
            j -= 1;
        }
        candidates[j] = key;
    }
}

pub fn sortAndTruncateCandidates(candidates: *std.ArrayList(Candidate), max_candidates_limit: usize) void {
    sortCandidatesByPriority(candidates.items);
    if (candidates.items.len > max_candidates_limit) {
        candidates.items.len = max_candidates_limit;
    }
}

pub fn replaceCandidateSet(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(Candidate),
    socket_family: u16,
    candidates: []const Candidate,
    max_candidates_limit: usize,
) !void {
    out.clearRetainingCapacity();
    for (candidates) |candidate| {
        if (!shouldUseCandidate(socket_family, candidate.addr)) continue;
        if (!isCandidateAddressUsable(candidate.addr)) continue;
        try appendUniqueCandidate(out, alloc, candidate);
    }
    sortAndTruncateCandidates(out, max_candidates_limit);
}

pub fn adaptiveProbeTimeoutMs(base_timeout_ms: u32, probe: ProbeState, observed_rtt_ns: ?i64) u32 {
    const clamped_base = std.math.clamp(base_timeout_ms, @as(u32, 500), @as(u32, 30_000));
    if (probe.candidates.len == 0) return clamped_base;

    const warmup_rounds: u8 = @min(probe.attempts_per_candidate, 2);
    const send_window_ms = @as(i64, @intCast(probe.candidates.len)) *
        @as(i64, warmup_rounds) *
        @as(i64, probe.interval_ms);
    const settle_ms: i64 = if (observed_rtt_ns) |ns|
        std.math.clamp(@max(@as(i64, 1), @divFloor(ns + std.time.ns_per_ms - 1, std.time.ns_per_ms)) * 3, @as(i64, 150), @as(i64, 4000))
    else
        250;
    const adaptive_ms = @max(@as(i64, clamped_base), send_window_ms + settle_ms);
    return @as(u32, @intCast(std.math.clamp(adaptive_ms, @as(i64, 500), @as(i64, 30_000))));
}

pub const ProbeState = struct {
    candidates: []Candidate,
    attempts_per_candidate: u8 = 5,
    interval_ms: u32 = 200,
    selected: ?std.net.Address = null,

    current_round: u8 = 0,
    next_idx: usize = 0,

    pub fn nextProbeAddr(self: *ProbeState) ?std.net.Address {
        if (self.selected != null) return null;
        if (self.candidates.len == 0) return null;
        if (self.current_round >= self.attempts_per_candidate) return null;

        const addr = self.candidates[self.next_idx].addr;
        self.next_idx += 1;
        if (self.next_idx >= self.candidates.len) {
            self.next_idx = 0;
            self.current_round += 1;
        }
        return addr;
    }

    pub fn reset(self: *ProbeState, candidates: []Candidate) void {
        self.candidates = candidates;
        self.selected = null;
        self.current_round = 0;
        self.next_idx = 0;
    }

    pub fn onAuthenticatedRecv(self: *ProbeState, from: std.net.Address) void {
        if (self.selected == null) self.selected = from;
    }

    pub fn isComplete(self: *const ProbeState) bool {
        return self.selected != null or self.candidates.len == 0 or self.current_round >= self.attempts_per_candidate;
    }
};

pub const CandidateReprobe = struct {
    candidates: std.ArrayList(Candidate) = .empty,
    probe: ProbeState = .{ .candidates = &[_]Candidate{} },
    next_probe_ns: i64 = 0,
    persistent: bool = false,

    pub fn deinit(self: *CandidateReprobe, alloc: std.mem.Allocator) void {
        self.candidates.deinit(alloc);
    }

    pub fn clear(self: *CandidateReprobe) void {
        self.candidates.clearRetainingCapacity();
        self.probe.reset(self.candidates.items);
        self.next_probe_ns = 0;
        self.persistent = false;
    }

    pub fn start(
        self: *CandidateReprobe,
        alloc: std.mem.Allocator,
        socket_family: u16,
        refreshed_candidates: []const Candidate,
        now: i64,
    ) !bool {
        return self.startWithMode(alloc, socket_family, refreshed_candidates, now, false);
    }

    pub fn startPersistent(
        self: *CandidateReprobe,
        alloc: std.mem.Allocator,
        socket_family: u16,
        refreshed_candidates: []const Candidate,
        now: i64,
    ) !bool {
        return self.startWithMode(alloc, socket_family, refreshed_candidates, now, true);
    }

    fn startWithMode(
        self: *CandidateReprobe,
        alloc: std.mem.Allocator,
        socket_family: u16,
        refreshed_candidates: []const Candidate,
        now: i64,
        persistent: bool,
    ) !bool {
        try replaceCandidateSet(alloc, &self.candidates, socket_family, refreshed_candidates, max_candidates);
        self.probe.reset(self.candidates.items);
        self.next_probe_ns = now;
        self.persistent = persistent;
        return self.candidates.items.len > 0;
    }

    pub fn isActive(self: *const CandidateReprobe) bool {
        if (self.candidates.items.len == 0) return false;
        if (self.probe.selected != null) return false;
        return self.persistent or !self.probe.isComplete();
    }

    pub fn maybeNextProbeAddr(self: *CandidateReprobe, now: i64) ?std.net.Address {
        if (!self.isActive()) return null;
        if (now < self.next_probe_ns) return null;

        var addr = self.probe.nextProbeAddr();
        if (addr == null and self.persistent) {
            self.probe.reset(self.candidates.items);
            addr = self.probe.nextProbeAddr();
        }

        const next_addr = addr orelse return null;
        self.next_probe_ns = now + @as(i64, self.probe.interval_ms) * std.time.ns_per_ms;
        return next_addr;
    }

    pub fn pollDelayMs(self: *const CandidateReprobe, now: i64) ?i64 {
        if (!self.isActive()) return null;
        return @divFloor(@max(@as(i64, 0), self.next_probe_ns - now), std.time.ns_per_ms);
    }

    pub fn onAuthenticatedRecv(self: *CandidateReprobe, from: std.net.Address) bool {
        return self.onAuthenticatedRecvMode(from, false);
    }

    pub fn onAuthenticatedRecvPeerReflexive(self: *CandidateReprobe, from: std.net.Address) bool {
        return self.onAuthenticatedRecvMode(from, true);
    }

    fn onAuthenticatedRecvMode(self: *CandidateReprobe, from: std.net.Address, allow_peer_reflexive: bool) bool {
        if (!self.isActive()) return false;

        if (!allow_peer_reflexive) {
            for (self.candidates.items) |candidate| {
                if (isAddressEqual(candidate.addr, from)) break;
            } else {
                return false;
            }
        }

        const selected_before = self.probe.selected;
        self.probe.onAuthenticatedRecv(from);
        return selected_before == null and self.probe.selected != null;
    }
};

pub fn gatherServerReflexiveCandidates(
    alloc: std.mem.Allocator,
    sock: *udp.UdpSocket,
    stun_servers: []const std.net.Address,
    max_candidates_limit: usize,
) !SrflxGatherResult {
    var result = SrflxGatherResult{
        .candidates = try std.ArrayList(Candidate).initCapacity(alloc, stun_servers.len),
    };
    errdefer result.candidates.deinit(alloc);

    if (stun_servers.len == 0) return result;

    var states = try alloc.alloc(StunState, stun_servers.len);
    defer alloc.free(states);

    for (stun_servers, 0..) |server_addr, idx| {
        states[idx] = StunState.init(server_addr);
        states[idx].sendRequest(sock) catch {};
    }

    const deadline = @as(i64, @intCast(std.time.nanoTimestamp())) + 4 * std.time.ns_per_s;
    while (true) {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        if (now >= deadline) break;

        var pending = false;
        var next_retry_ns = deadline;
        for (states) |*state| {
            if (!state.waiting_response or state.result != null) continue;
            pending = true;
            next_retry_ns = @min(next_retry_ns, state.next_retry_ns);
        }
        if (!pending) break;

        const timeout_ns = @min(deadline - now, @max(@as(i64, 0), next_retry_ns - now));
        const timeout_ms: i32 = @intCast(@max(@as(i64, 1), @divFloor(timeout_ns + std.time.ns_per_ms - 1, std.time.ns_per_ms)));
        var poll_fds = [_]posix.pollfd{.{ .fd = sock.getFd(), .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&poll_fds, timeout_ms) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        if (poll_fds[0].revents & posix.POLL.IN != 0) {
            while (true) {
                var recv_buf: [1500]u8 = undefined;
                const raw = sock.recvRaw(&recv_buf) catch break;
                const packet = raw orelse break;

                for (states) |*state| {
                    if (!isStunPacket(state.server_addr, packet.from, packet.data)) continue;
                    const had_result = state.result != null;
                    const parsed = state.handleResponse(packet.data) catch break;
                    if (!had_result and parsed != null) {
                        result.responsive_servers += 1;
                        if (state.last_rtt_ns) |rtt_ns| result.rtt_stats.observe(rtt_ns);
                        try appendUniqueCandidate(&result.candidates, alloc, parsed.?);
                    }
                    break;
                }
            }
        }

        const retry_now: i64 = @intCast(std.time.nanoTimestamp());
        for (states) |*state| {
            state.maybeRetry(sock, retry_now) catch {};
        }
    }

    sortAndTruncateCandidates(&result.candidates, max_candidates_limit);
    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseEndpoint ipv4 and ipv6" {
    const v4 = try parseEndpoint("127.0.0.1:60000");
    try std.testing.expect(v4.any.family == posix.AF.INET);
    try std.testing.expect(v4.getPort() == 60000);

    const v6 = try parseEndpoint("[2001:db8::1]:60001");
    try std.testing.expect(v6.any.family == posix.AF.INET6);
    try std.testing.expect(v6.getPort() == 60001);
}

test "parseHostPort supports defaults and bracketed ipv6" {
    const a = try parseHostPort("stun.cloudflare.com", 3478);
    try std.testing.expectEqualStrings("stun.cloudflare.com", a.host);
    try std.testing.expect(a.port == 3478);

    const b = try parseHostPort("stun.example.com:5349", 3478);
    try std.testing.expectEqualStrings("stun.example.com", b.host);
    try std.testing.expect(b.port == 5349);

    const hp_v6 = try parseHostPort("[2001:db8::1]:9999", 3478);
    try std.testing.expectEqualStrings("2001:db8::1", hp_v6.host);
    try std.testing.expect(hp_v6.port == 9999);
}

test "isStunPacket validates source and cookie" {
    const server = std.net.Address.initIp4(.{ 1, 2, 3, 4 }, 3478);
    const same = std.net.Address.initIp4(.{ 1, 2, 3, 4 }, 3478);
    const other = std.net.Address.initIp4(.{ 5, 6, 7, 8 }, 3478);

    var pkt: [20]u8 = [_]u8{0} ** 20;
    std.mem.writeInt(u32, pkt[4..8], stun_magic_cookie, .big);

    try std.testing.expect(isStunPacket(server, same, &pkt));
    try std.testing.expect(!isStunPacket(server, other, &pkt));
    pkt[7] ^= 0x01;
    try std.testing.expect(!isStunPacket(server, same, &pkt));
}

test "stun parse xor-mapped-address ipv4" {
    const server = std.net.Address.initIp4(.{ 8, 8, 8, 8 }, 3478);
    var state = StunState.init(server);
    state.txn_id = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    // Build Binding Success with XOR-MAPPED-ADDRESS for 203.0.113.7:54321.
    var msg: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u16, msg[0..2], 0x0101, .big);
    std.mem.writeInt(u16, msg[2..4], 12, .big);
    std.mem.writeInt(u32, msg[4..8], stun_magic_cookie, .big);
    msg[8..20].* = state.txn_id;
    std.mem.writeInt(u16, msg[20..22], 0x0020, .big);
    std.mem.writeInt(u16, msg[22..24], 8, .big);
    msg[24] = 0;
    msg[25] = 0x01;

    const port: u16 = 54321;
    const x_port = port ^ @as(u16, @truncate(stun_magic_cookie >> 16));
    std.mem.writeInt(u16, msg[26..28], x_port, .big);

    const ip = [4]u8{ 203, 0, 113, 7 };
    const ip_u32 = std.mem.readInt(u32, &ip, .big);
    std.mem.writeInt(u32, msg[28..32], ip_u32 ^ stun_magic_cookie, .big);

    const candidate = (try state.handleResponse(&msg)).?;
    try std.testing.expect(candidate.ctype == .srflx);
    try std.testing.expect(candidate.addr.any.family == posix.AF.INET);
    try std.testing.expect(candidate.addr.getPort() == port);
}

test "probe state progresses and locks on auth recv" {
    var candidates = [_]Candidate{
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 10, 0, 0, 10 }, 60000), .source = "host" },
        .{ .ctype = .srflx, .addr = std.net.Address.initIp4(.{ 198, 51, 100, 20 }, 61000), .source = "srflx" },
    };

    var state = ProbeState{
        .candidates = &candidates,
        .attempts_per_candidate = 2,
    };

    const first = state.nextProbeAddr().?;
    const second = state.nextProbeAddr().?;
    try std.testing.expect(!isAddressEqual(first, second));

    state.onAuthenticatedRecv(std.net.Address.initIp4(.{ 198, 51, 100, 20 }, 61000));
    try std.testing.expect(state.isComplete());
    try std.testing.expect(state.nextProbeAddr() == null);
}

test "candidate payload json round trip" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const candidates = [_]Candidate{
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 203, 0, 113, 10 }, 60000), .source = "ifaddr" },
        .{ .ctype = .srflx, .addr = std.net.Address.initIp4(.{ 198, 51, 100, 7 }, 60001), .source = "stun" },
    };

    const json_payload = try encodeCandidatesPayloadJson(alloc, &candidates);
    defer alloc.free(json_payload);

    var parsed = try parseCandidatesPayloadJson(alloc, json_payload);
    defer parsed.deinit(alloc);

    try std.testing.expectEqual(@as(usize, 2), parsed.items.len);
    try std.testing.expect(parsed.items[0].ctype == .host);
    try std.testing.expectEqual(@as(u16, 60000), parsed.items[0].addr.getPort());
    try std.testing.expect(parsed.items[1].ctype == .srflx);
    try std.testing.expectEqual(@as(u16, 60001), parsed.items[1].addr.getPort());
}

test "probe state reset swaps candidates and clears progress" {
    var first_candidates = [_]Candidate{
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 10, 0, 0, 10 }, 60000), .source = "host" },
        .{ .ctype = .srflx, .addr = std.net.Address.initIp4(.{ 198, 51, 100, 20 }, 61000), .source = "srflx" },
    };
    var second_candidates = [_]Candidate{
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 203, 0, 113, 10 }, 62000), .source = "host" },
    };

    var state = ProbeState{
        .candidates = &first_candidates,
        .attempts_per_candidate = 2,
    };

    _ = state.nextProbeAddr().?;
    state.onAuthenticatedRecv(first_candidates[1].addr);
    try std.testing.expect(state.isComplete());

    state.reset(&second_candidates);
    try std.testing.expect(!state.isComplete());
    try std.testing.expect(state.selected == null);
    const next = state.nextProbeAddr().?;
    try std.testing.expect(isAddressEqual(next, second_candidates[0].addr));
}

test "candidate sorting keeps globally useful paths ahead of local hosts" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var candidates = try std.ArrayList(Candidate).initCapacity(alloc, 5);
    defer candidates.deinit(alloc);
    try candidates.append(alloc, .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 10, 0, 0, 10 }, 60000), .source = "private-v4" });
    try candidates.append(alloc, .{ .ctype = .host, .addr = std.net.Address.initIp6(.{ 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 60000, 0, 0), .source = "ula-v6" });
    try candidates.append(alloc, .{ .ctype = .srflx, .addr = std.net.Address.initIp4(.{ 198, 51, 100, 20 }, 60001), .source = "stun-v4" });
    try candidates.append(alloc, .{ .ctype = .host, .addr = std.net.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, 60002, 0, 0), .source = "global-v6" });
    try candidates.append(alloc, .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 203, 0, 113, 10 }, 60003), .source = "global-v4" });

    sortAndTruncateCandidates(&candidates, 3);

    try std.testing.expectEqual(@as(usize, 3), candidates.items.len);
    try std.testing.expect(candidates.items[0].ctype == .host);
    try std.testing.expect(candidates.items[0].addr.any.family == posix.AF.INET6);
    try std.testing.expect(candidates.items[1].ctype == .host);
    try std.testing.expect(candidates.items[1].addr.any.family == posix.AF.INET);
    try std.testing.expect(candidates.items[2].ctype == .srflx);
}

test "adaptive probe timeout grows for slow observed RTT" {
    var candidates = [_]Candidate{
        .{ .ctype = .srflx, .addr = std.net.Address.initIp4(.{ 198, 51, 100, 20 }, 60001), .source = "stun" },
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 203, 0, 113, 10 }, 60002), .source = "host" },
    };

    const probe = ProbeState{ .candidates = &candidates };
    try std.testing.expectEqual(@as(u32, 3000), adaptiveProbeTimeoutMs(3000, probe, 50 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(u32, 3500), adaptiveProbeTimeoutMs(1000, probe, 900 * std.time.ns_per_ms));
}
