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

fn isIp6Loopback(ip: [16]u8) bool {
    return std.mem.eql(u8, ip[0..15], &([_]u8{0} ** 15)) and ip[15] == 1;
}

fn isIp6AllZero(ip: [16]u8) bool {
    return std.mem.eql(u8, &ip, &([_]u8{0} ** 16));
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

pub fn gatherHostCandidates(
    alloc: std.mem.Allocator,
    local_port: u16,
    socket_family: u16,
    max_candidates: usize,
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

            try out.append(alloc, .{
                .ctype = .host,
                .addr = std.net.Address.initIp4(ip, local_port),
                .source = "ifaddr",
            });
        } else if (fam == posix.AF.INET6) {
            if (socket_family == posix.AF.INET) continue;

            const in6_ptr: *const c.struct_sockaddr_in6 = @ptrCast(@alignCast(ifa.ifa_addr));
            const ip: [16]u8 = @as(*const [16]u8, @ptrCast(&in6_ptr.sin6_addr)).*;
            if (!isIp6CandidateUsable(ip)) continue;

            try out.append(alloc, .{
                .ctype = .host,
                .addr = std.net.Address.initIp6(ip, local_port, 0, 0),
                .source = "ifaddr",
            });
        }

        if (out.items.len >= max_candidates) break;
    }

    return out;
}

fn candidatePriority(candidate: Candidate) u8 {
    if (candidate.addr.any.family == posix.AF.INET6 and candidate.ctype == .host and isIp6CandidateUsable(candidate.addr.in6.sa.addr)) return 0;
    if (candidate.ctype == .srflx) return 1;
    return 2;
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
