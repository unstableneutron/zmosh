const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const nat = @import("nat.zig");
const netmon = @import("netmon.zig");
const builtin = @import("builtin");

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_stdout_buf = 4 * 1024 * 1024;
const max_bootstrap_line = 4096;
const default_probe_timeout_ms: u32 = 3000;
const network_change_heartbeat_burst: u8 = 3;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const initial_resync_backoff_ns = 250 * std.time.ns_per_ms;
const detach_drain_ns = 2 * std.time.ns_per_s;
const session_end_grace_ns = 2 * std.time.ns_per_s;
const ssh_fallback_after_disconnected_ns = 10 * std.time.ns_per_s;
const udp_switch_request_retry_ns = 500 * std.time.ns_per_ms;
const udp_switch_request_timeout_ns = 2 * std.time.ns_per_s;
const use_ack_timeout_ms: i32 = 2000;
const max_standby_buffer = 8 * 1024;
const initial_ssh_snapshot_id: u32 = 0x8000_0000;
const max_ssh_snapshot_restarts: u8 = 2;

const c = switch (builtin.os.tag) {
    .macos => @cImport({
        @cInclude("sys/ioctl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
    .freebsd => @cImport({
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
    else => @cImport({
        @cInclude("sys/ioctl.h");
        @cInclude("termios.h");
        @cInclude("unistd.h");
    }),
};

const log = std.log.scoped(.remote);

pub const SshBootstrap = struct {
    stdin_fd: i32,
    stdout_fd: i32,
};

pub const NatTraversalMode = enum {
    auto,
    off,
};

pub const RemoteAttachOptions = struct {
    nat_traversal: NatTraversalMode = .auto,
    stun_servers: []const []const u8 = &.{},
    probe_timeout_ms: u32 = default_probe_timeout_ms,
    connect_debug: bool = false,
};

pub const RemoteSession = struct {
    host: []const u8,
    port: u16,
    key: crypto.Key,
    server_candidates: std.ArrayList(nat.Candidate),
    ssh: ?SshBootstrap,
    ssh_pid: ?posix.pid_t,

    pub fn deinit(self: *RemoteSession, alloc: std.mem.Allocator) void {
        self.server_candidates.deinit(alloc);
        if (self.ssh) |pipes| {
            posix.close(pipes.stdin_fd);
            posix.close(pipes.stdout_fd);
        }
        if (self.ssh_pid) |pid| {
            _ = posix.waitpid(pid, posix.W.NOHANG);
        }
        self.ssh = null;
        self.ssh_pid = null;
    }
};

pub const RemoteTransport = union(enum) {
    udp: struct {
        sock: *udp_mod.UdpSocket,
        peer: *udp_mod.Peer,
    },
    ssh: struct {
        read_fd: i32,
        write_fd: i32,
        read_buf: ipc.SocketBuffer,
        write_buf: std.ArrayList(u8),
    },

    pub fn deinit(self: *RemoteTransport, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .udp => {},
            .ssh => |*s| {
                if (s.read_fd == s.write_fd) {
                    posix.close(s.read_fd);
                } else {
                    posix.close(s.read_fd);
                    posix.close(s.write_fd);
                }
                s.read_buf.deinit();
                s.write_buf.deinit(alloc);
            },
        }
    }
};

const StandbySsh = struct {
    read_fd: i32,
    write_fd: i32,
    control: union(enum) {
        line: std.ArrayList(u8),
        framed: ipc.SocketBuffer,
    },

    fn initLine(alloc: std.mem.Allocator, pipes: SshBootstrap) !StandbySsh {
        return .{
            .read_fd = pipes.stdout_fd,
            .write_fd = pipes.stdin_fd,
            .control = .{ .line = try std.ArrayList(u8).initCapacity(alloc, 128) },
        };
    }

    fn deinit(self: *StandbySsh, alloc: std.mem.Allocator, close_fds: bool) void {
        if (close_fds) {
            if (self.read_fd == self.write_fd) {
                posix.close(self.read_fd);
            } else {
                posix.close(self.read_fd);
                posix.close(self.write_fd);
            }
        }
        switch (self.control) {
            .line => |*buffer| buffer.deinit(alloc),
            .framed => |*read_buf| read_buf.deinit(),
        }
    }
};

const Connect2Json = struct {
    v: u8,
    key: []const u8,
    port: u16 = 0,
    candidates: []nat.CandidateWire,
    ssh_fallback: bool = false,
};

const Candidates2Json = struct {
    candidates: []nat.CandidateWire,
};

/// Parse a ZMX_CONNECT line: "ZMX_CONNECT udp <port> <base64_key>\n"
pub fn parseConnectLine(line: []const u8) !struct { port: u16, key: crypto.Key } {
    const trimmed = std.mem.trimRight(u8, line, "\r\n");
    var it = std.mem.splitScalar(u8, trimmed, ' ');

    const prefix = it.next() orelse return error.InvalidConnectLine;
    if (!std.mem.eql(u8, prefix, "ZMX_CONNECT")) return error.InvalidConnectLine;

    const proto = it.next() orelse return error.InvalidConnectLine;
    if (!std.mem.eql(u8, proto, "udp")) return error.UnsupportedProtocol;

    const port_str = it.next() orelse return error.InvalidConnectLine;
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidPort;

    const key_str = it.next() orelse return error.InvalidConnectLine;
    const key = crypto.keyFromBase64(key_str) catch return error.InvalidKey;

    return .{ .port = port, .key = key };
}

fn parseConnect2Line(
    alloc: std.mem.Allocator,
    line: []const u8,
) !struct { key: crypto.Key, port: u16, candidates: std.ArrayList(nat.Candidate) } {
    const trimmed = std.mem.trimRight(u8, line, "\r\n");
    if (!std.mem.startsWith(u8, trimmed, "ZMX_CONNECT2 ")) return error.InvalidConnectLine;

    const json_payload = trimmed["ZMX_CONNECT2 ".len..];
    var parsed = try std.json.parseFromSlice(Connect2Json, alloc, json_payload, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    if (parsed.value.v != 2) return error.UnsupportedBootstrapVersion;
    const key = crypto.keyFromBase64(parsed.value.key) catch return error.InvalidKey;

    var candidates = try std.ArrayList(nat.Candidate).initCapacity(alloc, parsed.value.candidates.len);
    errdefer candidates.deinit(alloc);

    for (parsed.value.candidates) |wire| {
        const candidate = try nat.wireToCandidate(wire);
        if (!nat.isCandidateAddressUsable(candidate.addr)) continue;
        try candidates.append(alloc, candidate);
    }

    return .{ .key = key, .port = parsed.value.port, .candidates = candidates };
}

fn isValidSessionName(session: []const u8) bool {
    if (session.len == 0) return false;
    for (session) |ch| {
        if (std.ascii.isAlphanumeric(ch)) continue;
        if (ch == '.' or ch == '_' or ch == '-') continue;
        return false;
    }
    return true;
}

fn shellQuoteAlloc(alloc: std.mem.Allocator, raw: []const u8) ![]u8 {
    var quoted = try std.ArrayList(u8).initCapacity(alloc, raw.len + 2);
    errdefer quoted.deinit(alloc);

    try quoted.append(alloc, '\'');
    for (raw) |ch| {
        if (ch == '\'') {
            try quoted.appendSlice(alloc, "'\\''");
        } else {
            try quoted.append(alloc, ch);
        }
    }
    try quoted.append(alloc, '\'');
    return quoted.toOwnedSlice(alloc);
}

fn setNonBlocking(fd: i32) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.SOCK.NONBLOCK);
}

fn clampProbeTimeoutMs(ms: u32) u32 {
    return std.math.clamp(ms, @as(u32, 500), @as(u32, 30_000));
}

fn connectDebug(enabled: bool, comptime fmt: []const u8, args: anytype) void {
    if (!enabled) return;
    std.debug.print("zmx debug: " ++ fmt ++ "\n", args);
}

fn durationNsToMsForLog(ns: ?i64) i64 {
    return if (ns) |value| @max(@as(i64, 1), @divFloor(value, std.time.ns_per_ms)) else -1;
}

fn countCandidatesByType(candidates: []const nat.Candidate, ctype: nat.CandidateType) usize {
    var count: usize = 0;
    for (candidates) |candidate| {
        if (candidate.ctype == ctype) count += 1;
    }
    return count;
}

fn writeAllFd(fd: i32, bytes: []const u8) !void {
    const deadline_ns: i64 = @as(i64, @intCast(std.time.nanoTimestamp())) + 2 * std.time.ns_per_s;
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(fd, bytes[off..]) catch |err| {
            if (err == error.WouldBlock) {
                if (@as(i64, @intCast(std.time.nanoTimestamp())) >= deadline_ns) return error.WriteTimeout;
                var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                _ = posix.poll(&fds, 200) catch |poll_err| {
                    if (poll_err == error.Interrupted) continue;
                    return poll_err;
                };
                continue;
            }
            return err;
        };
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

fn sendUse(fd: i32, mode: []const u8) !void {
    var line_buf: [32]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buf, "ZMX_USE {s}\n", .{mode});
    try writeAllFd(fd, line);
}

fn sendCandidates(fd: i32, alloc: std.mem.Allocator, candidates: []const nat.Candidate) !void {
    const json_payload = try nat.encodeCandidatesPayloadJson(alloc, candidates);
    defer alloc.free(json_payload);

    var line = try std.ArrayList(u8).initCapacity(alloc, "ZMX_CANDIDATES2 \n".len + json_payload.len);
    defer line.deinit(alloc);
    try line.appendSlice(alloc, "ZMX_CANDIDATES2 ");
    try line.appendSlice(alloc, json_payload);
    try line.append(alloc, '\n');
    try writeAllFd(fd, line.items);
}

fn appendUniqueCandidate(list: *std.ArrayList(nat.Candidate), alloc: std.mem.Allocator, candidate: nat.Candidate, max_candidates: usize) !void {
    _ = max_candidates;
    try nat.appendUniqueCandidate(list, alloc, candidate);
}

fn parseCandidatesLine(alloc: std.mem.Allocator, line: []const u8) !std.ArrayList(nat.Candidate) {
    if (!std.mem.startsWith(u8, line, "ZMX_CANDIDATES2 ")) return error.InvalidControlMessage;
    return nat.parseCandidatesPayloadJson(alloc, line["ZMX_CANDIDATES2 ".len..]);
}

fn sendFramedMessage(fd: i32, alloc: std.mem.Allocator, tag: ipc.Tag, payload: []const u8) !void {
    var msg = try std.ArrayList(u8).initCapacity(alloc, @sizeOf(ipc.Header) + payload.len);
    defer msg.deinit(alloc);
    try ipc.appendMessage(alloc, &msg, tag, payload);
    try writeAllFd(fd, msg.items);
}

fn sendFramedCandidates(fd: i32, alloc: std.mem.Allocator, candidates: []const nat.Candidate) !void {
    const json_payload = try nat.encodeCandidatesPayloadJson(alloc, candidates);
    defer alloc.free(json_payload);
    try sendFramedMessage(fd, alloc, .CandidateRefresh, json_payload);
}

fn replaceCandidateSet(
    alloc: std.mem.Allocator,
    out: *std.ArrayList(nat.Candidate),
    socket_capability: udp_mod.SocketCapability,
    candidates: []const nat.Candidate,
) !void {
    try nat.replaceCandidateSet(alloc, out, socket_capability, candidates, nat.max_candidates);
}

const CandidateReprobe = nat.CandidateReprobe;

const AsyncSrflxRefresh = struct {
    stun_servers: std.ArrayList(std.net.Address),
    mappings: std.ArrayList(?std.net.Address),
    states: std.ArrayList(nat.StunState),

    const DatagramEvent = enum {
        ignored,
        handled,
        changed,
    };

    fn init(
        alloc: std.mem.Allocator,
        socket_capability: udp_mod.SocketCapability,
        stun_server_specs: []const []const u8,
    ) !AsyncSrflxRefresh {
        var stun_servers = try nat.resolveStunServers(alloc, socket_capability, stun_server_specs);
        errdefer stun_servers.deinit(alloc);

        var mappings = try std.ArrayList(?std.net.Address).initCapacity(alloc, stun_servers.items.len);
        errdefer mappings.deinit(alloc);
        try mappings.resize(alloc, stun_servers.items.len);
        for (mappings.items) |*slot| slot.* = null;

        return .{
            .stun_servers = stun_servers,
            .mappings = mappings,
            .states = try std.ArrayList(nat.StunState).initCapacity(alloc, stun_servers.items.len),
        };
    }

    fn deinit(self: *AsyncSrflxRefresh, alloc: std.mem.Allocator) void {
        self.stun_servers.deinit(alloc);
        self.mappings.deinit(alloc);
        self.states.deinit(alloc);
    }

    fn start(self: *AsyncSrflxRefresh, alloc: std.mem.Allocator, sock: *udp_mod.UdpSocket) !bool {
        self.states.clearRetainingCapacity();
        if (self.mappings.items.len != self.stun_servers.items.len) {
            try self.mappings.resize(alloc, self.stun_servers.items.len);
        }
        for (self.mappings.items) |*slot| slot.* = null;

        for (self.stun_servers.items, 0..) |server_addr, idx| {
            var state = nat.StunState.init(server_addr, idx);
            state.sendRequest(sock) catch {};
            try self.states.append(alloc, state);
        }

        return self.states.items.len > 0;
    }

    fn maybeRetry(self: *AsyncSrflxRefresh, sock: *udp_mod.UdpSocket, now: i64) !void {
        for (self.states.items) |*state| {
            state.maybeRetry(sock, now) catch |err| {
                if (err == error.WouldBlock) continue;
                return err;
            };
        }
    }

    fn pollDelayMs(self: *const AsyncSrflxRefresh, now: i64) ?i64 {
        var next_retry_ns: ?i64 = null;
        for (self.states.items) |state| {
            if (!state.waiting_response or state.result != null) continue;
            next_retry_ns = if (next_retry_ns) |existing| @min(existing, state.next_retry_ns) else state.next_retry_ns;
        }
        const retry_ns = next_retry_ns orelse return null;
        return @divFloor(@max(@as(i64, 0), retry_ns - now), std.time.ns_per_ms);
    }

    fn handleDatagram(self: *AsyncSrflxRefresh, from: std.net.Address, data: []const u8) DatagramEvent {
        for (self.states.items) |*state| {
            if (!state.waiting_response or state.result != null) continue;
            if (!nat.isStunPacket(state.server_addr, from, data)) continue;

            const parsed = state.handleResponse(data) catch return .handled;
            if (parsed) |candidate| {
                const existing = self.mappings.items[state.server_idx];
                if (existing == null or !nat.isAddressEqual(existing.?, candidate.addr)) {
                    self.mappings.items[state.server_idx] = candidate.addr;
                    return .changed;
                }
            }
            return .handled;
        }
        return .ignored;
    }

    fn buildCandidateSet(
        self: *const AsyncSrflxRefresh,
        alloc: std.mem.Allocator,
        bound_port: u16,
        socket_capability: udp_mod.SocketCapability,
    ) !std.ArrayList(nat.Candidate) {
        var candidates = try nat.gatherHostCandidates(alloc, bound_port, socket_capability, nat.max_candidates);
        errdefer candidates.deinit(alloc);

        for (self.mappings.items) |maybe_addr| {
            const addr = maybe_addr orelse continue;
            try appendUniqueCandidate(&candidates, alloc, .{
                .ctype = .srflx,
                .addr = addr,
                .source = "stun",
            }, nat.max_candidates);
        }

        nat.sortAndTruncateCandidates(&candidates, nat.max_candidates);
        return candidates;
    }
};

fn handleUdpStandbyControlMessages(
    alloc: std.mem.Allocator,
    standby_buffer: *std.ArrayList(u8),
    server_candidates: *std.ArrayList(nat.Candidate),
    socket_capability: udp_mod.SocketCapability,
    reprobe: *CandidateReprobe,
    peer: *udp_mod.Peer,
    now: i64,
    connect_debug: bool,
) !void {
    while (true) {
        const nl_idx = std.mem.indexOfScalar(u8, standby_buffer.items, '\n') orelse break;
        const line = std.mem.trimRight(u8, standby_buffer.items[0..nl_idx], "\r\n");

        if (std.mem.startsWith(u8, line, "ZMX_CANDIDATES2 ")) {
            var candidates = parseCandidatesLine(alloc, line) catch |err| {
                connectDebug(connect_debug, "ignoring invalid standby candidate refresh: {s}", .{@errorName(err)});
                try standby_buffer.replaceRange(alloc, 0, nl_idx + 1, &[_]u8{});
                continue;
            };
            defer candidates.deinit(alloc);

            try replaceCandidateSet(alloc, server_candidates, socket_capability, candidates.items);
            if (try reprobe.start(alloc, socket_capability, server_candidates.items, now)) {
                peer.enterRecoveryMode(now);
                connectDebug(connect_debug, "received refreshed server candidates over standby SSH ({d})", .{reprobe.candidates.items.len});
            } else {
                connectDebug(connect_debug, "received standby candidate refresh with no usable addresses", .{});
            }
        } else {
            connectDebug(connect_debug, "ignoring standby control line during UDP: {s}", .{line});
        }

        try standby_buffer.replaceRange(alloc, 0, nl_idx + 1, &[_]u8{});
    }
}

fn resolveHostAddress(alloc: std.mem.Allocator, host: []const u8, port: u16) !std.net.Address {
    return std.net.Address.resolveIp(host, port) catch blk: {
        const list = try std.net.getAddressList(alloc, host, port);
        defer list.deinit();
        if (list.addrs.len == 0) return error.HostNotFound;
        break :blk list.addrs[0];
    };
}

fn gatherLocalCandidates(
    alloc: std.mem.Allocator,
    sock: *udp_mod.UdpSocket,
    socket_capability: udp_mod.SocketCapability,
    stun_servers: []const []const u8,
    stun_rtt_stats: *nat.TimingStats,
    responsive_stun_servers: *usize,
) !std.ArrayList(nat.Candidate) {
    var candidates = try nat.gatherHostCandidates(alloc, sock.bound_port, socket_capability, nat.max_candidates);
    errdefer candidates.deinit(alloc);

    var stun_addrs = try nat.resolveStunServers(alloc, socket_capability, stun_servers);
    defer stun_addrs.deinit(alloc);

    var srflx = try nat.gatherServerReflexiveCandidates(alloc, sock, stun_addrs.items, nat.max_candidates);
    defer srflx.deinit(alloc);

    stun_rtt_stats.* = srflx.rtt_stats;
    responsive_stun_servers.* = srflx.responsive_servers;

    for (srflx.candidates.items) |candidate| {
        try appendUniqueCandidate(&candidates, alloc, candidate, nat.max_candidates);
    }

    nat.sortAndTruncateCandidates(&candidates, nat.max_candidates);
    return candidates;
}

fn sendProbeHeartbeatTo(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    target: std.net.Address,
    reliable_recv: *const transport.RecvState,
) !void {
    var pkt_buf: [1200]u8 = undefined;
    const pkt = try transport.buildUnreliable(
        .heartbeat,
        0,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
        "",
        &pkt_buf,
    );

    var enc_buf: [9000]u8 = undefined;
    const datagram = try crypto.encodeDatagram(
        peer.key,
        peer.direction,
        peer.send_seq,
        pkt,
        &enc_buf,
    );

    try sock.sendTo(datagram, target);

    const now: i64 = @intCast(std.time.nanoTimestamp());
    peer.last_send_time_any = now;
    peer.send_seq += 1;
}

const ProbeDecision = enum {
    udp,
    ssh,
};

fn probeAndSelectTransport(
    alloc: std.mem.Allocator,
    session: *RemoteSession,
    options: RemoteAttachOptions,
    fallback_addr: std.net.Address,
    udp_sock: *udp_mod.UdpSocket,
    peer: *udp_mod.Peer,
    reliable_recv: *const transport.RecvState,
) !ProbeDecision {
    if (session.ssh == null) {
        peer.addr = fallback_addr;
        return .udp;
    }

    const pipes = session.ssh.?;

    var local_stun_rtt_stats: nat.TimingStats = .{};
    var responsive_stun_servers: usize = 0;
    var local_candidates = try gatherLocalCandidates(
        alloc,
        udp_sock,
        udp_sock.capability,
        options.stun_servers,
        &local_stun_rtt_stats,
        &responsive_stun_servers,
    );
    defer local_candidates.deinit(alloc);

    connectDebug(options.connect_debug, "local candidates host={d} srflx={d} responsive_stun={d} stun_rtt_ms(min/max)={d}/{d}", .{
        countCandidatesByType(local_candidates.items, .host),
        countCandidatesByType(local_candidates.items, .srflx),
        responsive_stun_servers,
        durationNsToMsForLog(local_stun_rtt_stats.min_ns),
        durationNsToMsForLog(local_stun_rtt_stats.max_ns),
    });

    try sendCandidates(pipes.stdin_fd, alloc, local_candidates.items);

    var remote_candidates = try std.ArrayList(nat.Candidate).initCapacity(alloc, session.server_candidates.items.len + 1);
    defer remote_candidates.deinit(alloc);

    for (session.server_candidates.items) |candidate| {
        if (!nat.shouldUseCandidate(udp_sock.capability, candidate.addr)) continue;
        if (!nat.isCandidateAddressUsable(candidate.addr)) continue;
        try appendUniqueCandidate(&remote_candidates, alloc, candidate, nat.max_candidates);
    }
    try appendUniqueCandidate(&remote_candidates, alloc, .{
        .ctype = .host,
        .addr = fallback_addr,
        .source = "ssh_host",
    }, nat.max_candidates);

    nat.sortAndTruncateCandidates(&remote_candidates, nat.max_candidates);
    if (remote_candidates.items.len == 0) {
        connectDebug(options.connect_debug, "no usable remote UDP candidates; staying on SSH", .{});
        return .ssh;
    }

    var probe = nat.ProbeState{ .candidates = remote_candidates.items };
    var next_probe_ns: i64 = @intCast(std.time.nanoTimestamp());
    const observed_rtt_ns = local_stun_rtt_stats.conservativeNs();
    const adaptive_probe_timeout_ms = nat.adaptiveProbeTimeoutMs(clampProbeTimeoutMs(options.probe_timeout_ms), probe, observed_rtt_ns);
    const probe_timeout_ns = @as(i64, adaptive_probe_timeout_ms) * std.time.ns_per_ms;
    const deadline = next_probe_ns + probe_timeout_ns;
    const probe_start_ns = next_probe_ns;
    var sent_attempts: usize = 0;
    var authenticated_packets: usize = 0;

    connectDebug(options.connect_debug, "probing remote candidates={d} timeout_ms={d} observed_stun_rtt_ms={d}", .{
        remote_candidates.items.len,
        adaptive_probe_timeout_ms,
        durationNsToMsForLog(observed_rtt_ns),
    });

    while (@as(i64, @intCast(std.time.nanoTimestamp())) < deadline and !probe.isComplete()) {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        if (now >= next_probe_ns) {
            if (probe.nextProbeAddr()) |addr| {
                sent_attempts += 1;
                sendProbeHeartbeatTo(peer, udp_sock, addr, reliable_recv) catch |err| {
                    if (err != error.WouldBlock) return err;
                };
            }
            next_probe_ns = now + @as(i64, probe.interval_ms) * std.time.ns_per_ms;
        }

        const timeout_ns = @min(deadline - now, @max(@as(i64, 0), next_probe_ns - now));
        const timeout_ms: i32 = @intCast(@max(@as(i64, 0), @divFloor(timeout_ns, std.time.ns_per_ms)));
        var poll_fds = [_]posix.pollfd{.{ .fd = udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&poll_fds, timeout_ms) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        if (poll_fds[0].revents & posix.POLL.IN != 0) {
            while (true) {
                var raw_buf: [9000]u8 = undefined;
                const raw = try udp_sock.recvRaw(&raw_buf) orelse break;

                var decrypt_buf: [9000]u8 = undefined;
                const prev_addr = peer.addr;
                const decoded = try peer.decodeAndUpdate(raw.data, raw.from, &decrypt_buf);
                peer.addr = prev_addr;
                if (decoded == null) continue;
                authenticated_packets += 1;
                probe.onAuthenticatedRecv(raw.from);
            }
        }
    }

    const elapsed_ms = @divFloor(@as(i64, @intCast(std.time.nanoTimestamp())) - probe_start_ns, std.time.ns_per_ms);
    if (probe.selected) |selected| {
        connectDebug(options.connect_debug, "UDP probe selected={f} attempts={d} auth={d} elapsed_ms={d}", .{ selected, sent_attempts, authenticated_packets, elapsed_ms });
        peer.addr = selected;
        return .udp;
    }

    connectDebug(options.connect_debug, "UDP probe fell back to SSH attempts={d} auth={d} elapsed_ms={d}", .{ sent_attempts, authenticated_packets, elapsed_ms });
    return .ssh;
}

/// Bootstrap a remote session via SSH: ssh <host> zmosh serve <session>
/// Prepends common user bin dirs to PATH since SSH non-interactive sessions
/// often have a minimal PATH that excludes ~/.local/bin, ~/bin, etc.
pub fn connectRemote(alloc: std.mem.Allocator, host: []const u8, session: []const u8, options: RemoteAttachOptions) !RemoteSession {
    if (!isValidSessionName(session)) return error.InvalidSessionName;

    const probe_timeout_ms = clampProbeTimeoutMs(options.probe_timeout_ms);
    const term = posix.getenv("TERM") orelse "xterm-256color";
    const colorterm = posix.getenv("COLORTERM");
    const term_q = try shellQuoteAlloc(alloc, term);
    defer alloc.free(term_q);
    const session_q = try shellQuoteAlloc(alloc, session);
    defer alloc.free(session_q);

    const stun_servers_joined = if (options.stun_servers.len > 0)
        try std.mem.join(alloc, ",", options.stun_servers)
    else
        null;
    defer if (stun_servers_joined) |joined| alloc.free(joined);

    const stun_servers_q = if (stun_servers_joined) |joined|
        try shellQuoteAlloc(alloc, joined)
    else
        null;
    defer if (stun_servers_q) |quoted| alloc.free(quoted);

    const bootstrap_env = if (options.nat_traversal == .auto) "ZMX_BOOTSTRAP=2 " else "ZMX_BOOTSTRAP=0 ";
    const debug_env = if (options.connect_debug) "ZMX_CONNECT_DEBUG=1 " else "";
    const probe_env = if (options.nat_traversal == .auto and probe_timeout_ms != default_probe_timeout_ms)
        try std.fmt.allocPrint(alloc, "ZMX_PROBE_TIMEOUT_MS={d} ", .{probe_timeout_ms})
    else
        null;
    defer if (probe_env) |v| alloc.free(v);

    const stun_env = if (options.nat_traversal == .auto and stun_servers_q != null)
        try std.fmt.allocPrint(alloc, "ZMX_STUN_SERVERS={s} ", .{stun_servers_q.?})
    else
        null;
    defer if (stun_env) |v| alloc.free(v);

    const probe_env_s = probe_env orelse "";
    const stun_env_s = stun_env orelse "";

    const remote_cmd = if (colorterm) |ct| blk: {
        const ct_q = try shellQuoteAlloc(alloc, ct);
        defer alloc.free(ct_q);
        break :blk try std.fmt.allocPrint(
            alloc,
            "{s}{s}{s}{s}TERM={s} COLORTERM={s} PATH=\"$PATH:/opt/homebrew/bin:$HOME/bin:$HOME/.local/bin\" zmosh serve {s}",
            .{ bootstrap_env, debug_env, probe_env_s, stun_env_s, term_q, ct_q, session_q },
        );
    } else try std.fmt.allocPrint(
        alloc,
        "{s}{s}{s}{s}TERM={s} PATH=\"$PATH:/opt/homebrew/bin:$HOME/bin:$HOME/.local/bin\" zmosh serve {s}",
        .{ bootstrap_env, debug_env, probe_env_s, stun_env_s, term_q, session_q },
    );
    defer alloc.free(remote_cmd);

    connectDebug(options.connect_debug, "bootstrap mode={s} probe_timeout_ms={d} stun_servers={d}", .{
        if (options.nat_traversal == .auto) "auto" else "off",
        probe_timeout_ms,
        options.stun_servers.len,
    });

    const argv = [_][]const u8{ "ssh", host, "--", remote_cmd };
    var child = std.process.Child.init(&argv, alloc);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Inherit;
    try child.spawn();

    const stdout = child.stdout.?;
    const child_pid: posix.pid_t = child.id;
    var buf: [max_bootstrap_line]u8 = undefined;
    var total: usize = 0;
    var have_newline = false;
    while (total < buf.len) {
        const n = stdout.read(buf[total..]) catch return error.SshReadFailed;
        if (n == 0) break;
        total += n;
        if (std.mem.indexOfScalar(u8, buf[0..total], '\n') != null) {
            have_newline = true;
            break;
        }
    }

    if (total == 0) {
        _ = child.wait() catch {};
        return error.SshNoOutput;
    }
    if (!have_newline and total == buf.len) return error.BootstrapLineTooLarge;

    const line_end = std.mem.indexOfScalar(u8, buf[0..total], '\n') orelse total;
    const line = buf[0..line_end];
    connectDebug(options.connect_debug, "bootstrap line={s}", .{line});

    if (std.mem.startsWith(u8, line, "ZMX_CONNECT2 ")) {
        const parsed = parseConnect2Line(alloc, line) catch |err| {
            _ = child.wait() catch {};
            return err;
        };

        const stdin_fd = child.stdin.?.handle;
        const stdout_fd = child.stdout.?.handle;
        try setNonBlocking(stdin_fd);
        try setNonBlocking(stdout_fd);

        const port = if (parsed.port != 0)
            parsed.port
        else if (parsed.candidates.items.len > 0)
            parsed.candidates.items[0].addr.getPort()
        else
            60000;

        return .{
            .host = host,
            .port = port,
            .key = parsed.key,
            .server_candidates = parsed.candidates,
            .ssh = .{ .stdin_fd = stdin_fd, .stdout_fd = stdout_fd },
            .ssh_pid = child_pid,
        };
    }

    const parsed = parseConnectLine(line) catch |err| {
        _ = child.wait() catch {};
        return err;
    };

    if (child.stdin) |f| f.close();
    if (child.stdout) |f| f.close();

    return .{
        .host = host,
        .port = parsed.port,
        .key = parsed.key,
        .server_candidates = .empty,
        .ssh = null,
        .ssh_pid = child_pid,
    };
}

var sigwinch_received: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn handleSigwinch(_: i32, _: *const posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    sigwinch_received.store(true, .release);
}

fn setupSigwinchHandler() void {
    const act: posix.Sigaction = .{
        .handler = .{ .sigaction = handleSigwinch },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.SIGINFO,
    };
    posix.sigaction(posix.SIG.WINCH, &act, null);
}

fn getTerminalSize() ipc.Resize {
    var ws: c.struct_winsize = undefined;
    if (c.ioctl(posix.STDOUT_FILENO, c.TIOCGWINSZ, &ws) == 0 and ws.ws_row > 0 and ws.ws_col > 0) {
        return .{ .rows = ws.ws_row, .cols = ws.ws_col };
    }
    return .{ .rows = 24, .cols = 80 };
}

/// Detects Kitty keyboard protocol escape sequence for Ctrl+\
fn isKittyCtrlBackslash(buf: []const u8) bool {
    return std.mem.indexOf(u8, buf, "\x1b[92;5u") != null or
        std.mem.indexOf(u8, buf, "\x1b[92;5:1u") != null;
}

fn sendHeartbeat(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_recv: *const transport.RecvState,
    last_ack_send_ns: *i64,
    ack_dirty: *bool,
    now: i64,
) !void {
    var pkt_buf: [1200]u8 = undefined;
    const pkt = try transport.buildUnreliable(
        .heartbeat,
        0,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
        "",
        &pkt_buf,
    );
    try peer.send(sock, pkt);
    last_ack_send_ns.* = now;
    ack_dirty.* = false;
}

fn sendReliablePayload(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    channel: transport.Channel,
    payload: []const u8,
    now: i64,
) !void {
    const packet = try reliable_send.buildAndTrack(
        channel,
        payload,
        reliable_recv.ack(),
        reliable_recv.ackBits(),
        now,
    );
    peer.send(sock, packet) catch |err| {
        if (err == error.NoPeerAddress or err == error.WouldBlock) return;
        return err;
    };
}

fn sendIpcReliable(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    tag: ipc.Tag,
    payload: []const u8,
    now: i64,
) !void {
    if (payload.len <= max_ipc_payload) {
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
        try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .reliable_ipc, ipc_bytes, now);
        return;
    }

    var off: usize = 0;
    while (off < payload.len) {
        const end = @min(off + max_ipc_payload, payload.len);
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
        try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .reliable_ipc, ipc_bytes, now);
        off = end;
    }
}

fn requestResync(
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
    reliable_recv: *const transport.RecvState,
    last_resync_request_ns: *i64,
    resync_backoff_ns: *i64,
    resync_pending: *bool,
    now: i64,
) !void {
    if ((now - last_resync_request_ns.*) < resync_backoff_ns.*) return;

    var ctrl_buf: [8]u8 = undefined;
    const payload = transport.buildControl(.resync_request, &ctrl_buf);
    try sendReliablePayload(peer, sock, reliable_send, reliable_recv, .control, payload, now);
    last_resync_request_ns.* = now;
    resync_backoff_ns.* = @min(resync_backoff_ns.* * 2, std.time.ns_per_s);
    resync_pending.* = true;
}

fn appendSshIpc(write_buf: *std.ArrayList(u8), alloc: std.mem.Allocator, tag: ipc.Tag, payload: []const u8) !void {
    try ipc.appendMessage(alloc, write_buf, tag, payload);
}

fn queueUdpSwitchRequest(write_buf: *std.ArrayList(u8), alloc: std.mem.Allocator, pending_udp_switch: *PendingUdpSwitch, now: i64) !void {
    var req_buf: [8]u8 = undefined;
    try appendSshIpc(write_buf, alloc, .TransportSwitchRequest, ipc.encodeTransportSwitchRequest(&req_buf, .udp));
    pending_udp_switch.arm(now);
}

fn flushWriteBuffer(fd: i32, write_buf: *std.ArrayList(u8), alloc: std.mem.Allocator) !void {
    if (write_buf.items.len == 0) return;
    const written = posix.write(fd, write_buf.items) catch |err| {
        if (err == error.WouldBlock) return;
        return err;
    };
    if (written > 0) {
        try write_buf.replaceRange(alloc, 0, written, &[_]u8{});
    }
}

fn drainUdpReliableSend(
    alloc: std.mem.Allocator,
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_send: *transport.ReliableSend,
) !void {
    if (!reliable_send.hasPending()) return;

    const deadline_ns = @as(i64, @intCast(std.time.nanoTimestamp())) + detach_drain_ns;
    while (reliable_send.hasPending()) {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        if (now >= deadline_ns) break;

        var retransmits = try reliable_send.collectRetransmits(alloc, now, peer.rto_us());
        defer retransmits.deinit(alloc);
        for (retransmits.items) |pkt| {
            peer.send(sock, pkt) catch |err| {
                if (err != error.NoPeerAddress and err != error.WouldBlock) return err;
            };
        }

        const remaining_ms = @max(@as(i64, 1), @divFloor(deadline_ns - now, std.time.ns_per_ms));
        const rto_ms = @max(@as(i64, 1), @divFloor(peer.rto_us(), 1000));
        const poll_timeout: i32 = @intCast(@min(remaining_ms, rto_ms));
        var poll_fds = [_]posix.pollfd{.{ .fd = sock.getFd(), .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&poll_fds, poll_timeout) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        if (poll_fds[0].revents & posix.POLL.IN == 0) continue;
        while (true) {
            var decrypt_buf: [9000]u8 = undefined;
            const recv_result = try peer.recv(sock, &decrypt_buf);
            const result = recv_result orelse break;

            const packet = transport.parsePacket(result.data) catch continue;
            if (reliable_send.ack(packet.ack, packet.ack_bits)) |rtt_us| {
                peer.reportRtt(rtt_us);
            }
        }
    }
}

fn closeSshBootstrap(pipes: SshBootstrap) void {
    if (pipes.stdin_fd == pipes.stdout_fd) {
        posix.close(pipes.stdin_fd);
    } else {
        posix.close(pipes.stdin_fd);
        posix.close(pipes.stdout_fd);
    }
}

fn shouldSwitchToStandbySsh(now: i64, disconnected_since_ns: ?i64, standby_ssh: ?StandbySsh) bool {
    if (standby_ssh == null) return false;
    const since = disconnected_since_ns orelse return false;
    return (now - since) >= ssh_fallback_after_disconnected_ns;
}

fn shouldBufferSshOutput(active_snapshot_id: ?u32, awaiting_ssh_snapshot: bool) bool {
    return active_snapshot_id != null or awaiting_ssh_snapshot;
}

const PendingUdpSwitch = struct {
    active: bool = false,
    started_at_ns: i64 = 0,
    last_request_ns: i64 = 0,

    fn arm(self: *PendingUdpSwitch, now: i64) void {
        if (!self.active) self.started_at_ns = now;
        self.active = true;
        self.last_request_ns = now;
    }

    fn clear(self: *PendingUdpSwitch) void {
        self.* = .{};
    }

    fn shouldRetry(self: *const PendingUdpSwitch, now: i64) bool {
        return self.active and !self.timedOut(now) and (now - self.last_request_ns) >= udp_switch_request_retry_ns;
    }

    fn timedOut(self: *const PendingUdpSwitch, now: i64) bool {
        return self.active and (now - self.started_at_ns) >= udp_switch_request_timeout_ns;
    }
};

fn reserveSshSnapshotId(next_ssh_snapshot_id: *u32, awaiting_ssh_snapshot: *bool, expected_ssh_snapshot_id: *?u32) u32 {
    const snapshot_id = next_ssh_snapshot_id.*;
    next_ssh_snapshot_id.* +%= 1;
    awaiting_ssh_snapshot.* = true;
    expected_ssh_snapshot_id.* = snapshot_id;
    return snapshot_id;
}

fn restartSshBaseline(
    alloc: std.mem.Allocator,
    write_buf: *std.ArrayList(u8),
    next_ssh_snapshot_id: *u32,
    awaiting_ssh_snapshot: *bool,
    expected_ssh_snapshot_id: *?u32,
    active_snapshot_id: *?u32,
    stdout_buf: *std.ArrayList(u8),
    deferred_output_buf: *std.ArrayList(u8),
    ssh_snapshot_restarts: *u8,
) !void {
    if (ssh_snapshot_restarts.* >= max_ssh_snapshot_restarts) return error.SshSnapshotRestartLimit;
    ssh_snapshot_restarts.* += 1;

    stdout_buf.clearRetainingCapacity();
    deferred_output_buf.clearRetainingCapacity();
    active_snapshot_id.* = null;

    const snapshot_id = reserveSshSnapshotId(next_ssh_snapshot_id, awaiting_ssh_snapshot, expected_ssh_snapshot_id);
    const size = getTerminalSize();
    const init = ipc.Init{ .rows = size.rows, .cols = size.cols, .snapshot_id = snapshot_id };
    try appendSshIpc(write_buf, alloc, .Init, std.mem.asBytes(&init));
}

fn buildSshReplayPayload(alloc: std.mem.Allocator, channel: transport.Channel, payload: []const u8) !?[]u8 {
    switch (channel) {
        .control => {
            const ctrl = transport.parseControl(payload) catch return try alloc.dupe(u8, payload);
            if (ctrl == .resync_request) return null;
            return try alloc.dupe(u8, payload);
        },
        .reliable_ipc => {
            var filtered = try std.ArrayList(u8).initCapacity(alloc, payload.len);
            errdefer filtered.deinit(alloc);

            var offset: usize = 0;
            while (offset < payload.len) {
                const remaining = payload[offset..];
                const msg_len = ipc.expectedLength(remaining) orelse return try alloc.dupe(u8, payload);
                if (remaining.len < msg_len) return try alloc.dupe(u8, payload);

                const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
                if (hdr.tag != .Init) {
                    try filtered.appendSlice(alloc, remaining[0..msg_len]);
                }
                offset += msg_len;
            }

            if (filtered.items.len == 0) return null;
            return try filtered.toOwnedSlice(alloc);
        },
        else => return try alloc.dupe(u8, payload),
    }
}

fn handleSshMessage(
    alloc: std.mem.Allocator,
    write_buf: *std.ArrayList(u8),
    msg: anytype,
    reliable_inbox: *transport.ReliableInbox,
    reliable_recv: *transport.RecvState,
    stdout_buf: *std.ArrayList(u8),
    deferred_output_buf: *std.ArrayList(u8),
    active_snapshot_id: *?u32,
    awaiting_ssh_snapshot: *bool,
    expected_ssh_snapshot_id: *?u32,
    next_ssh_snapshot_id: *u32,
    ssh_snapshot_restarts: *u8,
    session_ended: *bool,
    session_end_deadline_ns: *?i64,
    now: i64,
) !void {
    if (msg.header.tag == .ReliableReplay) {
        const replay = ipc.parseReliableReplay(msg.payload) catch return;
        const channel = std.meta.intToEnum(transport.Channel, replay.channel) catch return;
        if (!reliable_inbox.accepts(replay.seq)) return;
        if (reliable_recv.onReliable(replay.seq) != .accept) return;
        try reliable_inbox.push(replay.seq, channel, replay.payload);
        while (reliable_inbox.popReady()) |delivery| {
            defer delivery.deinit(alloc);

            switch (delivery.channel) {
                .control => {
                    const ctrl = transport.parseControl(delivery.payload) catch continue;
                    _ = ctrl;
                },
                .reliable_ipc => {
                    var offset: usize = 0;
                    while (offset < delivery.payload.len) {
                        const remaining = delivery.payload[offset..];
                        const msg_len = ipc.expectedLength(remaining) orelse break;
                        if (remaining.len < msg_len) break;

                        const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
                        const payload = remaining[@sizeOf(ipc.Header)..msg_len];

                        if (hdr.tag == .Output and payload.len > 0) {
                            const target_buf = if (shouldBufferSshOutput(active_snapshot_id.*, awaiting_ssh_snapshot.*)) deferred_output_buf else stdout_buf;
                            if (target_buf.items.len + payload.len > max_stdout_buf) {
                                try restartSshBaseline(alloc, write_buf, next_ssh_snapshot_id, awaiting_ssh_snapshot, expected_ssh_snapshot_id, active_snapshot_id, stdout_buf, deferred_output_buf, ssh_snapshot_restarts);
                            } else {
                                try target_buf.appendSlice(alloc, payload);
                            }
                        } else if (hdr.tag == .Snapshot and payload.len >= @sizeOf(ipc.Snapshot)) {
                            const snapshot = std.mem.bytesToValue(ipc.Snapshot, payload[0..@sizeOf(ipc.Snapshot)]);
                            const snapshot_bytes = payload[@sizeOf(ipc.Snapshot)..];

                            if (awaiting_ssh_snapshot.*) {
                                const expected = expected_ssh_snapshot_id.* orelse {
                                    offset += msg_len;
                                    continue;
                                };
                                if (snapshot.id != expected) {
                                    offset += msg_len;
                                    continue;
                                }
                            }

                            if (active_snapshot_id.*) |current| {
                                if (snapshot.id < current) {
                                    offset += msg_len;
                                    continue;
                                }
                                if (snapshot.id > current) {
                                    stdout_buf.clearRetainingCapacity();
                                    deferred_output_buf.clearRetainingCapacity();
                                    active_snapshot_id.* = snapshot.id;
                                }
                            } else {
                                stdout_buf.clearRetainingCapacity();
                                deferred_output_buf.clearRetainingCapacity();
                                active_snapshot_id.* = snapshot.id;
                            }

                            if (stdout_buf.items.len + snapshot_bytes.len > max_stdout_buf) {
                                try restartSshBaseline(alloc, write_buf, next_ssh_snapshot_id, awaiting_ssh_snapshot, expected_ssh_snapshot_id, active_snapshot_id, stdout_buf, deferred_output_buf, ssh_snapshot_restarts);
                            } else {
                                try stdout_buf.appendSlice(alloc, snapshot_bytes);
                                if (snapshot.isFinal()) {
                                    active_snapshot_id.* = null;
                                    awaiting_ssh_snapshot.* = false;
                                    expected_ssh_snapshot_id.* = null;
                                    ssh_snapshot_restarts.* = 0;
                                    if (stdout_buf.items.len + deferred_output_buf.items.len > max_stdout_buf) {
                                        try restartSshBaseline(alloc, write_buf, next_ssh_snapshot_id, awaiting_ssh_snapshot, expected_ssh_snapshot_id, active_snapshot_id, stdout_buf, deferred_output_buf, ssh_snapshot_restarts);
                                    } else {
                                        try stdout_buf.appendSlice(alloc, deferred_output_buf.items);
                                        deferred_output_buf.clearRetainingCapacity();
                                    }
                                }
                            }
                        } else if (hdr.tag == .SessionEnd) {
                            session_ended.* = true;
                            session_end_deadline_ns.* = session_end_deadline_ns.* orelse now + session_end_grace_ns;
                        }

                        offset += msg_len;
                    }
                },
                else => unreachable,
            }
        }
        return;
    }

    if (msg.header.tag == .Output and msg.payload.len > 0) {
        const target_buf = if (shouldBufferSshOutput(active_snapshot_id.*, awaiting_ssh_snapshot.*)) deferred_output_buf else stdout_buf;
        if (target_buf.items.len + msg.payload.len > max_stdout_buf) {
            try restartSshBaseline(alloc, write_buf, next_ssh_snapshot_id, awaiting_ssh_snapshot, expected_ssh_snapshot_id, active_snapshot_id, stdout_buf, deferred_output_buf, ssh_snapshot_restarts);
        } else {
            try target_buf.appendSlice(alloc, msg.payload);
        }
    } else if (msg.header.tag == .Snapshot and msg.payload.len >= @sizeOf(ipc.Snapshot)) {
        const snapshot = std.mem.bytesToValue(ipc.Snapshot, msg.payload[0..@sizeOf(ipc.Snapshot)]);
        const snapshot_bytes = msg.payload[@sizeOf(ipc.Snapshot)..];

        if (awaiting_ssh_snapshot.*) {
            const expected = expected_ssh_snapshot_id.* orelse return;
            if (snapshot.id != expected) return;
        }

        if (active_snapshot_id.*) |current| {
            if (snapshot.id < current) return;
            if (snapshot.id > current) {
                stdout_buf.clearRetainingCapacity();
                deferred_output_buf.clearRetainingCapacity();
                active_snapshot_id.* = snapshot.id;
            }
        } else {
            stdout_buf.clearRetainingCapacity();
            deferred_output_buf.clearRetainingCapacity();
            active_snapshot_id.* = snapshot.id;
        }

        if (stdout_buf.items.len + snapshot_bytes.len > max_stdout_buf) {
            try restartSshBaseline(alloc, write_buf, next_ssh_snapshot_id, awaiting_ssh_snapshot, expected_ssh_snapshot_id, active_snapshot_id, stdout_buf, deferred_output_buf, ssh_snapshot_restarts);
        } else {
            try stdout_buf.appendSlice(alloc, snapshot_bytes);
            if (snapshot.isFinal()) {
                active_snapshot_id.* = null;
                awaiting_ssh_snapshot.* = false;
                expected_ssh_snapshot_id.* = null;
                ssh_snapshot_restarts.* = 0;
                if (stdout_buf.items.len + deferred_output_buf.items.len > max_stdout_buf) {
                    try restartSshBaseline(alloc, write_buf, next_ssh_snapshot_id, awaiting_ssh_snapshot, expected_ssh_snapshot_id, active_snapshot_id, stdout_buf, deferred_output_buf, ssh_snapshot_restarts);
                } else {
                    try stdout_buf.appendSlice(alloc, deferred_output_buf.items);
                    deferred_output_buf.clearRetainingCapacity();
                }
            }
        }
    } else if (msg.header.tag == .SessionEnd) {
        session_ended.* = true;
        session_end_deadline_ns.* = session_end_deadline_ns.* orelse now + session_end_grace_ns;
    }
}

fn waitForUseAck(fd: i32, alloc: std.mem.Allocator, mode: []const u8, buffered: *std.ArrayList(u8)) !void {
    var expected_buf: [32]u8 = undefined;
    const expected = try std.fmt.bufPrint(&expected_buf, "ZMX_USE_OK {s}", .{mode});

    const deadline_ms = @as(i64, @intCast(std.time.milliTimestamp())) + use_ack_timeout_ms;
    while (true) {
        if (std.mem.indexOfScalar(u8, buffered.items, '\n')) |nl_idx| {
            const line = std.mem.trimRight(u8, buffered.items[0..nl_idx], "\r\n");
            if (std.mem.eql(u8, line, expected)) {
                try buffered.replaceRange(alloc, 0, nl_idx + 1, &[_]u8{});
                return;
            }
            try buffered.replaceRange(alloc, 0, nl_idx + 1, &[_]u8{});
            continue;
        }

        const now_ms = @as(i64, @intCast(std.time.milliTimestamp()));
        if (now_ms >= deadline_ms) return error.UseAckTimeout;

        const wait_ms = @min(@as(i64, 200), deadline_ms - now_ms);
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&fds, @intCast(@max(@as(i64, 1), wait_ms))) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        if (fds[0].revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
            return error.UnexpectedEof;
        }
        if (fds[0].revents & posix.POLL.HUP != 0 and fds[0].revents & posix.POLL.IN == 0) {
            return error.UnexpectedEof;
        }
        if (fds[0].revents & posix.POLL.IN == 0) continue;

        var tmp: [256]u8 = undefined;
        const n = posix.read(fd, &tmp) catch |err| {
            if (err == error.WouldBlock) continue;
            return err;
        };
        if (n == 0) return error.UnexpectedEof;
        if (buffered.items.len + n > max_standby_buffer) return error.ControlMessageTooLarge;
        try buffered.appendSlice(alloc, tmp[0..n]);
    }
}

fn waitForTransportSwitchAckFramed(
    fd: i32,
    desired_mode: ipc.TransportMode,
    read_buf: *ipc.SocketBuffer,
) !ipc.TransportSwitchAck {
    const deadline_ms = @as(i64, @intCast(std.time.milliTimestamp())) + use_ack_timeout_ms;
    while (true) {
        while (read_buf.next()) |msg| {
            if (msg.header.tag != .TransportSwitchAck) continue;
            const ack = try ipc.parseTransportSwitchAck(msg.payload);
            if (ack.mode == desired_mode) return ack;
        }

        const now_ms = @as(i64, @intCast(std.time.milliTimestamp()));
        if (now_ms >= deadline_ms) return error.UseAckTimeout;

        const wait_ms = @min(@as(i64, 200), deadline_ms - now_ms);
        var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&fds, @intCast(@max(@as(i64, 1), wait_ms))) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        if (fds[0].revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) return error.UnexpectedEof;
        if (fds[0].revents & posix.POLL.HUP != 0 and fds[0].revents & posix.POLL.IN == 0) return error.UnexpectedEof;
        if (fds[0].revents & posix.POLL.IN == 0) continue;

        const n = read_buf.read(fd) catch |err| {
            if (err == error.WouldBlock) continue;
            return err;
        };
        if (n == 0) return error.UnexpectedEof;
    }
}

fn activateStandbySsh(alloc: std.mem.Allocator, transport_mode: *RemoteTransport, standby_ssh: *?StandbySsh) !void {
    var standby = standby_ssh.* orelse return error.MissingSshPipes;
    standby_ssh.* = null;
    errdefer standby.deinit(alloc, true);

    var read_buf: ipc.SocketBuffer = undefined;
    switch (standby.control) {
        .line => |*buffer| {
            read_buf = try ipc.SocketBuffer.init(alloc);
            errdefer read_buf.deinit();
            if (buffer.items.len > 0) {
                try read_buf.buf.appendSlice(read_buf.alloc, buffer.items);
            }
            buffer.deinit(alloc);
        },
        .framed => |*buffer| {
            read_buf = buffer.*;
        },
    }

    var write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
    errdefer write_buf.deinit(alloc);

    transport_mode.* = .{ .ssh = .{
        .read_fd = standby.read_fd,
        .write_fd = standby.write_fd,
        .read_buf = read_buf,
        .write_buf = write_buf,
    } };
}

fn switchToStandbySsh(
    alloc: std.mem.Allocator,
    transport_mode: *RemoteTransport,
    standby_ssh: *?StandbySsh,
) !void {
    var standby = &(standby_ssh.* orelse return error.MissingSshPipes);
    switch (standby.control) {
        .line => |*buffer| {
            try sendUse(standby.write_fd, "ssh");
            try waitForUseAck(standby.read_fd, alloc, "ssh", buffer);
        },
        .framed => |*read_buf| {
            var req_buf: [8]u8 = undefined;
            try sendFramedMessage(
                standby.write_fd,
                alloc,
                .TransportSwitchRequest,
                ipc.encodeTransportSwitchRequest(&req_buf, .ssh),
            );
            _ = try waitForTransportSwitchAckFramed(standby.read_fd, .ssh, read_buf);
        },
    }

    try activateStandbySsh(alloc, transport_mode, standby_ssh);
}

fn performSshFallback(
    alloc: std.mem.Allocator,
    transport_mode: *RemoteTransport,
    standby_ssh: *?StandbySsh,
    reliable_send: *transport.ReliableSend,
    active_snapshot_id: *?u32,
    awaiting_ssh_snapshot: *bool,
    expected_ssh_snapshot_id: *?u32,
    next_ssh_snapshot_id: *u32,
    stdout_buf: *std.ArrayList(u8),
    deferred_output_buf: *std.ArrayList(u8),
    pending_output_epoch: *?u32,
    resync_pending: *bool,
    connect_debug: bool,
    reason: []const u8,
    disconnected_since_ns: *?i64,
    was_disconnected: *bool,
    pending_ssh_detach: *bool,
) !bool {
    if (standby_ssh.* == null) return false;

    switchToStandbySsh(alloc, transport_mode, standby_ssh) catch |err| {
        connectDebug(connect_debug, "failed to switch to SSH fallback: {s}", .{@errorName(err)});
        disableStandby(standby_ssh, alloc);
        return false;
    };

    _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b8") catch {};
    _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: UDP unavailable — switched to SSH tunnel\r\n") catch {};
    connectDebug(connect_debug, "switched to SSH fallback ({s})", .{reason});

    disconnected_since_ns.* = null;
    was_disconnected.* = false;
    pending_ssh_detach.* = false;
    active_snapshot_id.* = null;
    stdout_buf.clearRetainingCapacity();
    deferred_output_buf.clearRetainingCapacity();
    pending_output_epoch.* = null;
    resync_pending.* = false;

    if (transport_mode.* == .ssh) {
        var pending_replay = try reliable_send.collectPendingReliableFrames(alloc);
        defer pending_replay.deinit(alloc);
        for (pending_replay.items) |pending| {
            const replay_payload = try buildSshReplayPayload(alloc, pending.channel, pending.payload) orelse continue;
            defer alloc.free(replay_payload);
            try ipc.appendReliableReplay(alloc, &transport_mode.ssh.write_buf, pending.seq, @intFromEnum(pending.channel), replay_payload);
        }
        reliable_send.clearPending();

        const resumed_size = getTerminalSize();
        const resumed_snapshot_id = reserveSshSnapshotId(next_ssh_snapshot_id, awaiting_ssh_snapshot, expected_ssh_snapshot_id);
        const resumed_init = ipc.Init{ .rows = resumed_size.rows, .cols = resumed_size.cols, .snapshot_id = resumed_snapshot_id };
        try appendSshIpc(&transport_mode.ssh.write_buf, alloc, .Init, std.mem.asBytes(&resumed_init));
    }
    return true;
}

fn disableStandby(standby_ssh: *?StandbySsh, alloc: std.mem.Allocator) void {
    if (standby_ssh.*) |*standby| {
        standby.deinit(alloc, true);
        standby_ssh.* = null;
    }
}

fn takeActiveSshAsStandby(alloc: std.mem.Allocator, transport_mode: *RemoteTransport) !StandbySsh {
    if (transport_mode.* != .ssh) return error.InvalidTransportMode;

    const standby = StandbySsh{
        .read_fd = transport_mode.ssh.read_fd,
        .write_fd = transport_mode.ssh.write_fd,
        .control = .{ .framed = transport_mode.ssh.read_buf },
    };
    transport_mode.ssh.write_buf.deinit(alloc);
    return standby;
}

fn sendLocalCandidateRefresh(
    alloc: std.mem.Allocator,
    transport_mode: *RemoteTransport,
    standby_ssh: *?StandbySsh,
    candidates: []const nat.Candidate,
) !void {
    switch (transport_mode.*) {
        .udp => {
            if (standby_ssh.*) |*standby| {
                const send_result = switch (standby.control) {
                    .line => sendCandidates(standby.write_fd, alloc, candidates),
                    .framed => sendFramedCandidates(standby.write_fd, alloc, candidates),
                };
                send_result catch |err| {
                    disableStandby(standby_ssh, alloc);
                    return err;
                };
            }
        },
        .ssh => |*s| {
            const json_payload = try nat.encodeCandidatesPayloadJson(alloc, candidates);
            defer alloc.free(json_payload);
            try appendSshIpc(&s.write_buf, alloc, .CandidateRefresh, json_payload);
        },
    }
}

fn sendCurrentLocalCandidateRefresh(
    alloc: std.mem.Allocator,
    socket_capability: udp_mod.SocketCapability,
    sock: *udp_mod.UdpSocket,
    transport_mode: *RemoteTransport,
    standby_ssh: *?StandbySsh,
    srflx_refresh: *const AsyncSrflxRefresh,
    connect_debug: bool,
) !void {
    var refreshed_candidates = try srflx_refresh.buildCandidateSet(alloc, sock.bound_port, socket_capability);
    defer refreshed_candidates.deinit(alloc);

    connectDebug(connect_debug, "refreshed local candidates host={d} srflx={d}", .{
        countCandidatesByType(refreshed_candidates.items, .host),
        countCandidatesByType(refreshed_candidates.items, .srflx),
    });
    try sendLocalCandidateRefresh(alloc, transport_mode, standby_ssh, refreshed_candidates.items);
}

fn handleAsyncSrflxDatagram(
    alloc: std.mem.Allocator,
    socket_capability: udp_mod.SocketCapability,
    sock: *udp_mod.UdpSocket,
    transport_mode: *RemoteTransport,
    standby_ssh: *?StandbySsh,
    srflx_refresh: *AsyncSrflxRefresh,
    from: std.net.Address,
    data: []const u8,
    connect_debug: bool,
) !bool {
    return switch (srflx_refresh.handleDatagram(from, data)) {
        .ignored => false,
        .handled => true,
        .changed => blk: {
            try sendCurrentLocalCandidateRefresh(alloc, socket_capability, sock, transport_mode, standby_ssh, srflx_refresh, connect_debug);
            break :blk true;
        },
    };
}

fn applyUdpRepromotionState(
    snapshot_id: u32,
    active_snapshot_id: *?u32,
    awaiting_ssh_snapshot: *bool,
    expected_ssh_snapshot_id: *?u32,
    stdout_buf: *std.ArrayList(u8),
    deferred_output_buf: *std.ArrayList(u8),
    pending_output_epoch: *?u32,
    resync_pending: *bool,
    current_output_epoch: *u32,
) void {
    active_snapshot_id.* = null;
    awaiting_ssh_snapshot.* = false;
    expected_ssh_snapshot_id.* = null;
    stdout_buf.clearRetainingCapacity();
    deferred_output_buf.clearRetainingCapacity();
    pending_output_epoch.* = snapshot_id;
    resync_pending.* = false;
    current_output_epoch.* = snapshot_id;
}

fn handleClientNetworkChange(
    alloc: std.mem.Allocator,
    socket_capability: udp_mod.SocketCapability,
    peer: *udp_mod.Peer,
    sock: *udp_mod.UdpSocket,
    reliable_recv: *const transport.RecvState,
    transport_mode: *RemoteTransport,
    standby_ssh: *?StandbySsh,
    srflx_refresh: *AsyncSrflxRefresh,
    last_ack_send_ns: *i64,
    ack_dirty: *bool,
    connect_debug: bool,
    now: i64,
) void {
    connectDebug(connect_debug, "local network change detected", .{});
    peer.enterRecoveryMode(now);

    const started_srflx_refresh = srflx_refresh.start(alloc, sock) catch |err| blk: {
        connectDebug(connect_debug, "failed to start async srflx refresh after network change: {s}", .{@errorName(err)});
        break :blk false;
    };
    if (started_srflx_refresh) {
        connectDebug(connect_debug, "refreshing server-reflexive candidates asynchronously via {d} STUN servers", .{srflx_refresh.stun_servers.items.len});
    }

    sendCurrentLocalCandidateRefresh(alloc, socket_capability, sock, transport_mode, standby_ssh, srflx_refresh, connect_debug) catch |err| {
        connectDebug(connect_debug, "failed to send refreshed local candidates after network change: {s}", .{@errorName(err)});
    };

    var sent_any_heartbeat = false;
    if (peer.addr) |last_peer_addr| {
        var burst: u8 = 0;
        while (burst < network_change_heartbeat_burst) : (burst += 1) {
            sendProbeHeartbeatTo(peer, sock, last_peer_addr, reliable_recv) catch |err| {
                if (err == error.WouldBlock) break;
                connectDebug(connect_debug, "failed to send recovery heartbeat burst: {s}", .{@errorName(err)});
                break;
            };
            sent_any_heartbeat = true;
        }
    }

    if (sent_any_heartbeat) {
        last_ack_send_ns.* = now;
        ack_dirty.* = false;
    }
}

/// Remote attach: connect to a remote zmx session via UDP or SSH fallback.
pub fn remoteAttach(alloc: std.mem.Allocator, session_in: RemoteSession, options: RemoteAttachOptions) !void {
    var session = session_in;
    defer session.deinit(alloc);

    const fallback_addr = try resolveHostAddress(alloc, session.host, session.port);

    var udp_sock = try udp_mod.UdpSocket.bindEphemeral(fallback_addr.any.family);
    const socket_capability = udp_sock.capability;
    defer udp_sock.close();

    var peer = udp_mod.Peer.init(session.key, .to_server);

    var reliable_send = try transport.ReliableSend.init(alloc);
    defer reliable_send.deinit();
    var reliable_recv = transport.RecvState{};
    var reliable_inbox = try transport.ReliableInbox.init(alloc);
    defer reliable_inbox.deinit();
    var output_recv = transport.OutputRecvState{};

    // Set terminal to raw mode
    var orig_termios: c.termios = undefined;
    _ = c.tcgetattr(posix.STDIN_FILENO, &orig_termios);
    defer {
        _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSAFLUSH, &orig_termios);
        const restore_seq = "\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l" ++
            "\x1b[?2004l\x1b[?1004l\x1b[?1049l" ++
            "\x1b[<u" ++
            "\x1b[?25h";
        _ = posix.write(posix.STDOUT_FILENO, restore_seq) catch {};
    }

    var raw_termios = orig_termios;
    c.cfmakeraw(&raw_termios);
    raw_termios.c_cc[c.VLNEXT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VQUIT] = c._POSIX_VDISABLE;
    raw_termios.c_cc[c.VMIN] = 1;
    raw_termios.c_cc[c.VTIME] = 0;
    _ = c.tcsetattr(posix.STDIN_FILENO, c.TCSANOW, &raw_termios);

    _ = try posix.write(posix.STDOUT_FILENO, "\x1b[2J\x1b[H");
    setupSigwinchHandler();

    const stdin_flags = try posix.fcntl(posix.STDIN_FILENO, posix.F.GETFL, 0);
    _ = try posix.fcntl(posix.STDIN_FILENO, posix.F.SETFL, stdin_flags | posix.SOCK.NONBLOCK);
    defer {
        _ = posix.fcntl(posix.STDIN_FILENO, posix.F.SETFL, stdin_flags) catch {};
    }

    var stdout_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
    defer stdout_buf.deinit(alloc);
    var deferred_output_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
    defer deferred_output_buf.deinit(alloc);

    var transport_mode: RemoteTransport = .{ .udp = .{ .sock = &udp_sock, .peer = &peer } };
    defer transport_mode.deinit(alloc);

    var standby_ssh: ?StandbySsh = null;
    defer if (standby_ssh) |*standby| standby.deinit(alloc, true);
    var standby_reprobe: CandidateReprobe = .{};
    defer standby_reprobe.deinit(alloc);
    var ssh_reprobe: CandidateReprobe = .{};
    defer ssh_reprobe.deinit(alloc);
    var network_monitor = netmon.NetworkMonitor.init(alloc);
    defer network_monitor.deinit();
    var async_srflx_refresh = try AsyncSrflxRefresh.init(alloc, socket_capability, options.stun_servers);
    defer async_srflx_refresh.deinit(alloc);

    const decision = try probeAndSelectTransport(alloc, &session, options, fallback_addr, &udp_sock, &peer, &reliable_recv);
    if (decision == .udp and session.ssh != null) {
        standby_ssh = try StandbySsh.initLine(alloc, session.ssh.?);
        session.ssh = null;
        try sendUse(standby_ssh.?.write_fd, "udp");
        connectDebug(options.connect_debug, "selected UDP transport with SSH standby", .{});
    } else if (decision == .ssh) {
        if (session.ssh == null) return error.MissingSshPipes;
        standby_ssh = try StandbySsh.initLine(alloc, session.ssh.?);
        session.ssh = null;
        try switchToStandbySsh(alloc, &transport_mode, &standby_ssh);
        _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: using SSH tunnel (no UDP connectivity)\r\n") catch {};
        connectDebug(options.connect_debug, "selected SSH transport", .{});
    }
    var was_disconnected = false;
    var disconnected_since_ns: ?i64 = null;
    var session_ended = false;
    var session_end_deadline_ns: ?i64 = null;
    var pending_ssh_detach = false;
    var pending_ssh_detach_ns: ?i64 = null;

    var last_ack_send_ns: i64 = @intCast(std.time.nanoTimestamp());
    var ack_dirty = false;
    var last_resync_request_ns: i64 = 0;
    var resync_backoff_ns: i64 = initial_resync_backoff_ns;
    var resync_pending = false;
    var active_snapshot_id: ?u32 = null;
    var awaiting_ssh_snapshot = false;
    var expected_ssh_snapshot_id: ?u32 = null;
    var next_ssh_snapshot_id: u32 = initial_ssh_snapshot_id;
    var ssh_snapshot_restarts: u8 = 0;
    var ssh_eof = false;
    var ssh_write_closed = false;
    var current_output_epoch: u32 = 0;
    var pending_output_epoch: ?u32 = null;
    var pending_udp_switch: PendingUdpSwitch = .{};

    const size = getTerminalSize();
    const init_snapshot_id = switch (transport_mode) {
        .udp => @as(u32, 0),
        .ssh => reserveSshSnapshotId(&next_ssh_snapshot_id, &awaiting_ssh_snapshot, &expected_ssh_snapshot_id),
    };
    const init = ipc.Init{ .rows = size.rows, .cols = size.cols, .snapshot_id = init_snapshot_id };
    switch (transport_mode) {
        .udp => {
            var init_buf: [64]u8 = undefined;
            const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&init), &init_buf);
            try sendReliablePayload(&peer, &udp_sock, &reliable_send, &reliable_recv, .reliable_ipc, init_ipc, last_ack_send_ns);
        },
        .ssh => |*s| {
            try appendSshIpc(&s.write_buf, alloc, .Init, std.mem.asBytes(&init));
            _ = try ssh_reprobe.startPersistent(alloc, socket_capability, session.server_candidates.items, last_ack_send_ns);
        },
    }

    while (true) {
        const now: i64 = @intCast(std.time.nanoTimestamp());

        if (transport_mode == .ssh and pending_udp_switch.timedOut(now)) {
            connectDebug(options.connect_debug, "timed out pending UDP switch request", .{});
            pending_udp_switch.clear();
        } else if (transport_mode == .ssh and pending_udp_switch.shouldRetry(now) and !ssh_write_closed and transport_mode.ssh.write_buf.items.len == 0) {
            try queueUdpSwitchRequest(&transport_mode.ssh.write_buf, alloc, &pending_udp_switch, now);
            connectDebug(options.connect_debug, "retrying pending UDP switch request", .{});
        }

        try async_srflx_refresh.maybeRetry(&udp_sock, now);

        if (sigwinch_received.swap(false, .acq_rel)) {
            const new_size = getTerminalSize();
            switch (transport_mode) {
                .udp => {
                    try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Resize, std.mem.asBytes(&new_size), now);
                },
                .ssh => |*s| {
                    if (!pending_udp_switch.active) {
                        try appendSshIpc(&s.write_buf, alloc, .Resize, std.mem.asBytes(&new_size));
                    }
                },
            }
        }

        if (transport_mode == .udp) {
            const config = udp_mod.Config{};
            var retransmits = try reliable_send.collectRetransmits(alloc, now, peer.rto_us());
            defer retransmits.deinit(alloc);
            for (retransmits.items) |pkt| {
                peer.send(&udp_sock, pkt) catch {};
            }

            if (standby_reprobe.maybeNextProbeAddr(now)) |addr| {
                sendProbeHeartbeatTo(&peer, &udp_sock, addr, &reliable_recv) catch |err| {
                    if (err != error.WouldBlock) return err;
                };
            }

            if (ack_dirty and (now - last_ack_send_ns) >= ack_delay_ns) {
                sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
            } else if (peer.shouldSendHeartbeat(now, config)) {
                sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
            }

            const state = peer.updateState(now, config);
            if (state == .dead) {
                if (!session_ended) {
                    if (try performSshFallback(
                        alloc,
                        &transport_mode,
                        &standby_ssh,
                        &reliable_send,
                        &active_snapshot_id,
                        &awaiting_ssh_snapshot,
                        &expected_ssh_snapshot_id,
                        &next_ssh_snapshot_id,
                        &stdout_buf,
                        &deferred_output_buf,
                        &pending_output_epoch,
                        &resync_pending,
                        options.connect_debug,
                        "dead UDP state",
                        &disconnected_since_ns,
                        &was_disconnected,
                        &pending_ssh_detach,
                    )) {
                        pending_udp_switch.clear();
                        _ = try ssh_reprobe.startPersistent(alloc, socket_capability, session.server_candidates.items, now);
                        continue;
                    }

                    _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: connection lost permanently\r\n") catch {};
                    return;
                }
            }
            if (state == .disconnected and !was_disconnected) {
                _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b[7mzmx: connection lost — waiting to reconnect...\x1b[27m\x1b8") catch {};
                was_disconnected = true;
                sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
                sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
                disconnected_since_ns = now;
            } else if (state == .disconnected and disconnected_since_ns == null) {
                disconnected_since_ns = now;
            } else if (state == .connected and was_disconnected) {
                _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b8") catch {};
                was_disconnected = false;
                disconnected_since_ns = null;
            }

            if (state == .disconnected and shouldSwitchToStandbySsh(now, disconnected_since_ns, standby_ssh)) {
                if (!(try performSshFallback(
                    alloc,
                    &transport_mode,
                    &standby_ssh,
                    &reliable_send,
                    &active_snapshot_id,
                    &awaiting_ssh_snapshot,
                    &expected_ssh_snapshot_id,
                    &next_ssh_snapshot_id,
                    &stdout_buf,
                    &deferred_output_buf,
                    &pending_output_epoch,
                    &resync_pending,
                    options.connect_debug,
                    "disconnect timeout",
                    &disconnected_since_ns,
                    &was_disconnected,
                    &pending_ssh_detach,
                ))) {
                    continue;
                }
                pending_udp_switch.clear();
                _ = try ssh_reprobe.startPersistent(alloc, socket_capability, session.server_candidates.items, now);
                continue;
            }
        } else if (transport_mode == .ssh) {
            if (!pending_udp_switch.active) {
                if (ssh_reprobe.maybeNextProbeAddr(now)) |addr| {
                    sendProbeHeartbeatTo(&peer, &udp_sock, addr, &reliable_recv) catch |err| {
                        if (err != error.WouldBlock) return err;
                    };
                }
            }
        }

        var poll_fds: [6]posix.pollfd = undefined;
        var poll_count: usize = 0;

        const stdin_idx = poll_count;
        poll_fds[poll_count] = .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 };
        poll_count += 1;

        const transport_read_idx = poll_count;
        switch (transport_mode) {
            .udp => {
                poll_fds[poll_count] = .{ .fd = udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };
            },
            .ssh => |s| {
                poll_fds[poll_count] = .{ .fd = s.read_fd, .events = posix.POLL.IN, .revents = 0 };
            },
        }
        poll_count += 1;

        var udp_probe_idx: ?usize = null;
        if (transport_mode == .ssh) {
            udp_probe_idx = poll_count;
            poll_fds[poll_count] = .{ .fd = udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };
            poll_count += 1;
        }

        var standby_read_idx: ?usize = null;
        if (transport_mode == .udp and standby_ssh != null) {
            standby_read_idx = poll_count;
            poll_fds[poll_count] = .{ .fd = standby_ssh.?.read_fd, .events = posix.POLL.IN, .revents = 0 };
            poll_count += 1;
        }

        var netmon_idx: ?usize = null;
        if (network_monitor.pollFd() != null) {
            netmon_idx = poll_count;
            poll_fds[poll_count] = .{ .fd = network_monitor.pollFd().?, .events = posix.POLL.IN, .revents = 0 };
            poll_count += 1;
        }

        var stdout_idx: ?usize = null;
        if (stdout_buf.items.len > 0) {
            stdout_idx = poll_count;
            poll_fds[poll_count] = .{ .fd = posix.STDOUT_FILENO, .events = posix.POLL.OUT, .revents = 0 };
            poll_count += 1;
        }

        var ssh_write_idx: ?usize = null;
        if (transport_mode == .ssh and !ssh_write_closed and transport_mode.ssh.write_buf.items.len > 0) {
            ssh_write_idx = poll_count;
            poll_fds[poll_count] = .{ .fd = transport_mode.ssh.write_fd, .events = posix.POLL.OUT, .revents = 0 };
            poll_count += 1;
        }

        var poll_timeout: i64 = 500;
        if (transport_mode == .udp) {
            const config = udp_mod.Config{};
            poll_timeout = @min(@as(i64, config.heartbeat_interval_ms), poll_timeout);
            if (reliable_send.hasPending()) {
                const rto_ms = @divFloor(peer.rto_us(), 1000);
                poll_timeout = @min(poll_timeout, @max(@as(i64, 1), rto_ms));
            }
            const heartbeat_ms = @divFloor(peer.heartbeatDelayNs(now, config), std.time.ns_per_ms);
            poll_timeout = @min(poll_timeout, heartbeat_ms);
            if (standby_reprobe.pollDelayMs(now)) |reprobe_ms| {
                poll_timeout = @min(poll_timeout, reprobe_ms);
            }
        } else {
            if (pending_ssh_detach and transport_mode.ssh.write_buf.items.len > 0) {
                poll_timeout = @min(poll_timeout, @as(i64, 20));
            }
            if (ssh_reprobe.pollDelayMs(now)) |reprobe_ms| {
                poll_timeout = @min(poll_timeout, reprobe_ms);
            }
        }
        poll_timeout = @min(poll_timeout, @as(i64, network_monitor.pollTimeoutMs(now)));
        if (async_srflx_refresh.pollDelayMs(now)) |srflx_refresh_ms| {
            poll_timeout = @min(poll_timeout, srflx_refresh_ms);
        }
        if (ack_dirty) poll_timeout = @min(poll_timeout, @as(i64, 20));

        _ = posix.poll(poll_fds[0..poll_count], @intCast(poll_timeout)) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        const netmon_revents = if (netmon_idx) |idx| poll_fds[idx].revents else 0;
        const netmon_now: i64 = @intCast(std.time.nanoTimestamp());
        if (network_monitor.poll(netmon_now, netmon_revents)) {
            switch (transport_mode) {
                .udp => {
                    handleClientNetworkChange(
                        alloc,
                        socket_capability,
                        &peer,
                        &udp_sock,
                        &reliable_recv,
                        &transport_mode,
                        &standby_ssh,
                        &async_srflx_refresh,
                        &last_ack_send_ns,
                        &ack_dirty,
                        options.connect_debug,
                        netmon_now,
                    );
                },
                .ssh => {
                    handleClientNetworkChange(
                        alloc,
                        socket_capability,
                        &peer,
                        &udp_sock,
                        &reliable_recv,
                        &transport_mode,
                        &standby_ssh,
                        &async_srflx_refresh,
                        &last_ack_send_ns,
                        &ack_dirty,
                        options.connect_debug,
                        netmon_now,
                    );
                    pending_udp_switch.clear();
                    _ = try ssh_reprobe.startPersistent(alloc, socket_capability, session.server_candidates.items, netmon_now);
                },
            }
        }

        var ssh_read_hup = false;
        var ssh_write_hup = false;

        if (transport_mode == .ssh) {
            const ssh_read_revents = poll_fds[transport_read_idx].revents;
            if (ssh_read_revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                return;
            }
            ssh_read_hup = ssh_read_revents & posix.POLL.HUP != 0;
            if (ssh_write_idx) |idx| {
                const ssh_write_revents = poll_fds[idx].revents;
                if (ssh_write_revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                    return;
                }
                ssh_write_hup = ssh_write_revents & posix.POLL.HUP != 0;
            }
        }

        if (standby_read_idx) |idx| {
            if (poll_fds[idx].revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                disableStandby(&standby_ssh, alloc);
            }

            if (standby_ssh) |*standby| {
                switch (standby.control) {
                    .line => |*buffer| {
                        if (poll_fds[idx].revents & posix.POLL.IN != 0) {
                            while (true) {
                                var drain_buf: [256]u8 = undefined;
                                const n = posix.read(standby.read_fd, &drain_buf) catch |err| {
                                    if (err == error.WouldBlock) break;
                                    disableStandby(&standby_ssh, alloc);
                                    break;
                                };
                                if (n == 0) {
                                    disableStandby(&standby_ssh, alloc);
                                    break;
                                }

                                if (buffer.items.len + n > max_standby_buffer) {
                                    buffer.clearRetainingCapacity();
                                }
                                buffer.appendSlice(alloc, drain_buf[0..n]) catch {
                                    disableStandby(&standby_ssh, alloc);
                                    break;
                                };
                            }
                        }

                        if (standby_ssh != null) {
                            try handleUdpStandbyControlMessages(alloc, buffer, &session.server_candidates, socket_capability, &standby_reprobe, &peer, now, options.connect_debug);
                        }
                    },
                    .framed => |*read_buf| {
                        if (poll_fds[idx].revents & posix.POLL.IN != 0) {
                            while (true) {
                                const n = read_buf.read(standby.read_fd) catch |err| {
                                    if (err == error.WouldBlock) break;
                                    disableStandby(&standby_ssh, alloc);
                                    break;
                                };
                                if (n == 0) {
                                    disableStandby(&standby_ssh, alloc);
                                    break;
                                }

                                while (read_buf.next()) |msg| {
                                    if (msg.header.tag != .CandidateRefresh) continue;
                                    var candidates = nat.parseCandidatesPayloadJson(alloc, msg.payload) catch continue;
                                    defer candidates.deinit(alloc);
                                    try replaceCandidateSet(alloc, &session.server_candidates, socket_capability, candidates.items);
                                    if (try standby_reprobe.start(alloc, socket_capability, session.server_candidates.items, now)) {
                                        peer.enterRecoveryMode(now);
                                        connectDebug(options.connect_debug, "received refreshed server candidates over framed standby SSH ({d})", .{standby_reprobe.candidates.items.len});
                                    }
                                }
                            }
                        }
                    },
                }
            }

            if (standby_ssh != null and poll_fds[idx].revents & posix.POLL.HUP != 0 and poll_fds[idx].revents & posix.POLL.IN == 0) {
                disableStandby(&standby_ssh, alloc);
            }
        }

        if (!pending_ssh_detach and !(transport_mode == .ssh and pending_udp_switch.active) and poll_fds[stdin_idx].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR) != 0) {
            var input_raw: [4096]u8 = undefined;
            const n_opt: ?usize = posix.read(posix.STDIN_FILENO, &input_raw) catch |err| blk: {
                if (err == error.WouldBlock) break :blk null;
                return err;
            };
            if (n_opt) |n| {
                if (n > 0) {
                    const should_detach = input_raw[0] == 0x1C or isKittyCtrlBackslash(input_raw[0..n]);
                    switch (transport_mode) {
                        .udp => {
                            if (should_detach) {
                                try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Detach, "", now);
                                try drainUdpReliableSend(alloc, &peer, &udp_sock, &reliable_send);
                                return;
                            }
                            try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Input, input_raw[0..n], now);
                        },
                        .ssh => |*s| {
                            if (ssh_write_closed) {
                                // Read side may still have tail output to drain.
                            } else if (should_detach) {
                                try appendSshIpc(&s.write_buf, alloc, .Detach, "");
                                pending_ssh_detach = true;
                                pending_ssh_detach_ns = @intCast(std.time.nanoTimestamp());
                            } else {
                                try appendSshIpc(&s.write_buf, alloc, .Input, input_raw[0..n]);
                            }
                        },
                    }
                } else {
                    return;
                }
            }
        }

        var udp_repromotion_snapshot_id: ?u32 = null;
        const transport_read_ready = switch (transport_mode) {
            .udp => poll_fds[transport_read_idx].revents & posix.POLL.IN != 0,
            .ssh => |s| poll_fds[transport_read_idx].revents & posix.POLL.IN != 0 or s.read_buf.buf.items.len > 0,
        };
        if (transport_read_ready) {
            switch (transport_mode) {
                .udp => {
                    while (true) {
                        var raw_buf: [9000]u8 = undefined;
                        const raw = try udp_sock.recvRaw(&raw_buf) orelse break;

                        if (try handleAsyncSrflxDatagram(alloc, socket_capability, &udp_sock, &transport_mode, &standby_ssh, &async_srflx_refresh, raw.from, raw.data, options.connect_debug)) {
                            continue;
                        }

                        var decrypt_buf: [9000]u8 = undefined;
                        const decoded = try nat.decodeReprobeDatagram(&peer, &standby_reprobe, raw.data, raw.from, &decrypt_buf, false) orelse continue;
                        if (decoded.selected) {
                            connectDebug(options.connect_debug, "switched active UDP peer to refreshed candidate {f}", .{raw.from});
                        }

                        const packet = transport.parsePacket(decoded.plaintext) catch continue;
                        if (reliable_send.ack(packet.ack, packet.ack_bits)) |rtt_us| {
                            peer.reportRtt(rtt_us);
                        }

                        switch (packet.channel) {
                            .heartbeat => {},
                            .control, .reliable_ipc => {
                                ack_dirty = true;
                                if (!reliable_inbox.accepts(packet.seq)) continue;
                                if (reliable_recv.onReliable(packet.seq) != .accept) continue;

                                try reliable_inbox.push(packet.seq, packet.channel, packet.payload);
                                while (reliable_inbox.popReady()) |delivery| {
                                    defer delivery.deinit(alloc);

                                    switch (delivery.channel) {
                                        .control => {
                                            const ctrl = transport.parseControl(delivery.payload) catch continue;
                                            _ = ctrl;
                                        },
                                        .reliable_ipc => {
                                            var offset: usize = 0;
                                            while (offset < delivery.payload.len) {
                                                const remaining = delivery.payload[offset..];
                                                const msg_len = ipc.expectedLength(remaining) orelse break;
                                                if (remaining.len < msg_len) break;

                                                const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
                                                const payload = remaining[@sizeOf(ipc.Header)..msg_len];

                                                if (hdr.tag == .Output and payload.len > 0) {
                                                    if (stdout_buf.items.len + payload.len > max_stdout_buf) {
                                                        stdout_buf.clearRetainingCapacity();
                                                        try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, &resync_backoff_ns, &resync_pending, now);
                                                    } else {
                                                        active_snapshot_id = null;
                                                        deferred_output_buf.clearRetainingCapacity();
                                                        resync_backoff_ns = initial_resync_backoff_ns;
                                                        try stdout_buf.appendSlice(alloc, payload);
                                                    }
                                                } else if (hdr.tag == .Snapshot and payload.len >= @sizeOf(ipc.Snapshot)) {
                                                    const snapshot = std.mem.bytesToValue(ipc.Snapshot, payload[0..@sizeOf(ipc.Snapshot)]);
                                                    const snapshot_bytes = payload[@sizeOf(ipc.Snapshot)..];
                                                    if (active_snapshot_id) |current| {
                                                        if (snapshot.id < current) {
                                                            offset += msg_len;
                                                            continue;
                                                        }
                                                        if (snapshot.id > current) {
                                                            stdout_buf.clearRetainingCapacity();
                                                            deferred_output_buf.clearRetainingCapacity();
                                                            pending_output_epoch = null;
                                                            active_snapshot_id = snapshot.id;
                                                        }
                                                    } else {
                                                        stdout_buf.clearRetainingCapacity();
                                                        deferred_output_buf.clearRetainingCapacity();
                                                        pending_output_epoch = null;
                                                        active_snapshot_id = snapshot.id;
                                                    }

                                                    if (pending_output_epoch) |pending_epoch| {
                                                        if (pending_epoch != snapshot.id) {
                                                            deferred_output_buf.clearRetainingCapacity();
                                                            pending_output_epoch = null;
                                                        }
                                                    }

                                                    if (stdout_buf.items.len + snapshot_bytes.len > max_stdout_buf) {
                                                        stdout_buf.clearRetainingCapacity();
                                                        deferred_output_buf.clearRetainingCapacity();
                                                        pending_output_epoch = null;
                                                        try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, &resync_backoff_ns, &resync_pending, now);
                                                    } else {
                                                        resync_pending = false;
                                                        current_output_epoch = snapshot.id;
                                                        resync_backoff_ns = initial_resync_backoff_ns;
                                                        try stdout_buf.appendSlice(alloc, snapshot_bytes);
                                                        if (snapshot.isFinal()) {
                                                            active_snapshot_id = null;
                                                            if (stdout_buf.items.len + deferred_output_buf.items.len > max_stdout_buf) {
                                                                stdout_buf.clearRetainingCapacity();
                                                                deferred_output_buf.clearRetainingCapacity();
                                                                pending_output_epoch = null;
                                                                try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, &resync_backoff_ns, &resync_pending, now);
                                                            } else {
                                                                try stdout_buf.appendSlice(alloc, deferred_output_buf.items);
                                                                deferred_output_buf.clearRetainingCapacity();
                                                                pending_output_epoch = null;
                                                            }
                                                        }
                                                    }
                                                } else if (hdr.tag == .SessionEnd) {
                                                    session_ended = true;
                                                    session_end_deadline_ns = session_end_deadline_ns orelse now + session_end_grace_ns;
                                                }

                                                offset += msg_len;
                                            }
                                        },
                                        else => unreachable,
                                    }
                                }
                            },
                            .output => {
                                switch (output_recv.onPacket(packet.seq)) {
                                    .accept => {
                                        if (packet.payload.len == 0) continue;
                                        if (packet.payload.len < @sizeOf(transport.OutputPrefix)) continue;
                                        const prefix = std.mem.bytesToValue(transport.OutputPrefix, packet.payload[0..@sizeOf(transport.OutputPrefix)]);
                                        if (prefix.epoch < current_output_epoch) continue;
                                        if (resync_pending and active_snapshot_id == null) {
                                            if (prefix.epoch <= current_output_epoch) continue;
                                            if (pending_output_epoch) |pending_epoch| {
                                                if (pending_epoch != prefix.epoch) {
                                                    deferred_output_buf.clearRetainingCapacity();
                                                }
                                            }
                                            pending_output_epoch = prefix.epoch;
                                        } else if (prefix.epoch > current_output_epoch and active_snapshot_id == null) {
                                            current_output_epoch = prefix.epoch;
                                        }
                                        const output_payload = packet.payload[@sizeOf(transport.OutputPrefix)..];
                                        const awaiting_snapshot_for_epoch = active_snapshot_id != null or
                                            (pending_output_epoch != null and pending_output_epoch.? == prefix.epoch);
                                        const target_buf = if (awaiting_snapshot_for_epoch) &deferred_output_buf else &stdout_buf;
                                        if (target_buf.items.len + output_payload.len > max_stdout_buf) {
                                            stdout_buf.clearRetainingCapacity();
                                            deferred_output_buf.clearRetainingCapacity();
                                            try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, &resync_backoff_ns, &resync_pending, now);
                                        } else {
                                            resync_backoff_ns = initial_resync_backoff_ns;
                                            try target_buf.appendSlice(alloc, output_payload);
                                        }
                                    },
                                    .gap => {
                                        try requestResync(&peer, &udp_sock, &reliable_send, &reliable_recv, &last_resync_request_ns, &resync_backoff_ns, &resync_pending, now);
                                    },
                                    .duplicate, .stale => {},
                                }
                            },
                        }
                    }
                },
                .ssh => |*s| {
                    ssh_messages: {
                        while (s.read_buf.next()) |msg| {
                            if (msg.header.tag == .CandidateRefresh) {
                                var candidates = nat.parseCandidatesPayloadJson(alloc, msg.payload) catch continue;
                                defer candidates.deinit(alloc);
                                try replaceCandidateSet(alloc, &session.server_candidates, socket_capability, candidates.items);
                                _ = try ssh_reprobe.startPersistent(alloc, socket_capability, session.server_candidates.items, now);
                                connectDebug(options.connect_debug, "received refreshed server candidates over active SSH ({d})", .{session.server_candidates.items.len});
                                continue;
                            }
                            if (msg.header.tag == .TransportSwitchAck and pending_udp_switch.active) {
                                const ack = ipc.parseTransportSwitchAck(msg.payload) catch continue;
                                if (ack.mode == .udp) {
                                    udp_repromotion_snapshot_id = ack.baseline_snapshot_id;
                                    pending_udp_switch.clear();
                                    break :ssh_messages;
                                }
                                continue;
                            }

                            try handleSshMessage(alloc, &s.write_buf, msg, &reliable_inbox, &reliable_recv, &stdout_buf, &deferred_output_buf, &active_snapshot_id, &awaiting_ssh_snapshot, &expected_ssh_snapshot_id, &next_ssh_snapshot_id, &ssh_snapshot_restarts, &session_ended, &session_end_deadline_ns, now);
                        }

                        if (poll_fds[transport_read_idx].revents & posix.POLL.IN != 0) {
                            while (true) {
                                const n = s.read_buf.read(s.read_fd) catch |err| {
                                    if (err == error.WouldBlock) break;
                                    return err;
                                };
                                if (n == 0) {
                                    ssh_eof = true;
                                    break :ssh_messages;
                                }

                                while (s.read_buf.next()) |msg| {
                                    if (msg.header.tag == .CandidateRefresh) {
                                        var candidates = nat.parseCandidatesPayloadJson(alloc, msg.payload) catch continue;
                                        defer candidates.deinit(alloc);
                                        try replaceCandidateSet(alloc, &session.server_candidates, socket_capability, candidates.items);
                                        _ = try ssh_reprobe.startPersistent(alloc, socket_capability, session.server_candidates.items, now);
                                        connectDebug(options.connect_debug, "received refreshed server candidates over active SSH ({d})", .{session.server_candidates.items.len});
                                        continue;
                                    }
                                    if (msg.header.tag == .TransportSwitchAck and pending_udp_switch.active) {
                                        const ack = ipc.parseTransportSwitchAck(msg.payload) catch continue;
                                        if (ack.mode == .udp) {
                                            udp_repromotion_snapshot_id = ack.baseline_snapshot_id;
                                            pending_udp_switch.clear();
                                            break :ssh_messages;
                                        }
                                        continue;
                                    }

                                    try handleSshMessage(alloc, &s.write_buf, msg, &reliable_inbox, &reliable_recv, &stdout_buf, &deferred_output_buf, &active_snapshot_id, &awaiting_ssh_snapshot, &expected_ssh_snapshot_id, &next_ssh_snapshot_id, &ssh_snapshot_restarts, &session_ended, &session_end_deadline_ns, now);
                                }
                            }
                        }
                    }
                },
            }
        }

        if (transport_mode == .ssh and udp_probe_idx != null and poll_fds[udp_probe_idx.?].revents & posix.POLL.IN != 0) {
            while (true) {
                var raw_buf: [9000]u8 = undefined;
                const raw = try udp_sock.recvRaw(&raw_buf) orelse break;

                if (try handleAsyncSrflxDatagram(alloc, socket_capability, &udp_sock, &transport_mode, &standby_ssh, &async_srflx_refresh, raw.from, raw.data, options.connect_debug)) {
                    continue;
                }

                var decrypt_buf: [9000]u8 = undefined;
                const decoded = try nat.decodeReprobeDatagram(&peer, &ssh_reprobe, raw.data, raw.from, &decrypt_buf, true) orelse continue;
                if (decoded.selected) {
                    connectDebug(options.connect_debug, "authenticated revived UDP path {f}", .{raw.from});
                    if (!pending_udp_switch.active and transport_mode == .ssh and !ssh_write_closed) {
                        try queueUdpSwitchRequest(&transport_mode.ssh.write_buf, alloc, &pending_udp_switch, now);
                    }
                }
            }
        }

        if (udp_repromotion_snapshot_id) |snapshot_id| {
            const promoted_standby = try takeActiveSshAsStandby(alloc, &transport_mode);
            standby_ssh = promoted_standby;
            standby_reprobe.clear();
            transport_mode = .{ .udp = .{ .sock = &udp_sock, .peer = &peer } };
            ssh_eof = false;
            ssh_write_closed = false;
            pending_ssh_detach = false;
            pending_ssh_detach_ns = null;
            ssh_snapshot_restarts = 0;
            applyUdpRepromotionState(snapshot_id, &active_snapshot_id, &awaiting_ssh_snapshot, &expected_ssh_snapshot_id, &stdout_buf, &deferred_output_buf, &pending_output_epoch, &resync_pending, &current_output_epoch);

            const resumed_size = getTerminalSize();
            const resumed_init = ipc.Init{ .rows = resumed_size.rows, .cols = resumed_size.cols, .snapshot_id = snapshot_id };
            var init_buf: [64]u8 = undefined;
            const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&resumed_init), &init_buf);
            try sendReliablePayload(&peer, &udp_sock, &reliable_send, &reliable_recv, .reliable_ipc, init_ipc, now);
            connectDebug(options.connect_debug, "switched active transport back to UDP", .{});
            continue;
        }

        if (ssh_write_idx) |idx| {
            if (poll_fds[idx].revents & posix.POLL.OUT != 0) {
                if (transport_mode == .ssh) {
                    try flushWriteBuffer(transport_mode.ssh.write_fd, &transport_mode.ssh.write_buf, alloc);
                }
            }
        }

        if (pending_ssh_detach and transport_mode == .ssh) {
            if (transport_mode.ssh.write_buf.items.len == 0) return;
            const detach_elapsed = @as(i64, @intCast(std.time.nanoTimestamp())) - (pending_ssh_detach_ns orelse 0);
            if (detach_elapsed >= 2 * std.time.ns_per_s) return;
        }

        if (stdout_idx) |idx| {
            if (poll_fds[idx].revents & posix.POLL.OUT != 0 and stdout_buf.items.len > 0) {
                const written = posix.write(posix.STDOUT_FILENO, stdout_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk 0;
                    return err;
                };
                if (written > 0) {
                    try stdout_buf.replaceRange(alloc, 0, written, &[_]u8{});
                }
            }
        }

        if (transport_mode == .ssh) {
            const ssh_read_revents = poll_fds[transport_read_idx].revents;
            if (ssh_read_hup and ssh_read_revents & posix.POLL.IN == 0) {
                ssh_eof = true;
            }
            if (ssh_write_hup) {
                ssh_write_closed = true;
                pending_ssh_detach = false;
                transport_mode.ssh.write_buf.clearRetainingCapacity();
            }
        }

        if (ssh_eof and transport_mode == .ssh and stdout_buf.items.len == 0 and (ssh_write_closed or transport_mode.ssh.write_buf.items.len == 0)) {
            return;
        }

        if (session_ended and
            session_end_deadline_ns != null and
            now >= session_end_deadline_ns.? and
            active_snapshot_id == null and
            deferred_output_buf.items.len == 0 and
            !awaiting_ssh_snapshot)
        {
            while (stdout_buf.items.len > 0) {
                const written = posix.write(posix.STDOUT_FILENO, stdout_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) {
                        var out_poll = [_]posix.pollfd{.{ .fd = posix.STDOUT_FILENO, .events = posix.POLL.OUT, .revents = 0 }};
                        _ = posix.poll(&out_poll, 100) catch break :blk @as(usize, 0);
                        break :blk @as(usize, 0);
                    }
                    break :blk @as(usize, 0);
                };
                if (written > 0) {
                    try stdout_buf.replaceRange(alloc, 0, written, &[_]u8{});
                } else {
                    break;
                }
            }
            _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: remote session ended\r\n") catch {};
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseConnectLine valid" {
    const result = try parseConnectLine("ZMX_CONNECT udp 60042 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n");
    try std.testing.expect(result.port == 60042);
}

test "parseConnectLine invalid prefix" {
    try std.testing.expectError(error.InvalidConnectLine, parseConnectLine("INVALID udp 60042 key\n"));
}

test "parseConnectLine unsupported protocol" {
    try std.testing.expectError(error.UnsupportedProtocol, parseConnectLine("ZMX_CONNECT tcp 60042 key\n"));
}

test "parseConnect2Line keeps explicit bootstrap port" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var parsed = try parseConnect2Line(
        alloc,
        "ZMX_CONNECT2 {\"v\":2,\"key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"port\":60444,\"candidates\":[]}\n",
    );
    defer parsed.candidates.deinit(alloc);

    try std.testing.expectEqual(@as(u16, 60444), parsed.port);
}

test "ssh standby fallback threshold" {
    const now: i64 = 20 * std.time.ns_per_s;
    const standby = StandbySsh{ .read_fd = 1, .write_fd = 2, .control = .{ .line = .empty } };

    try std.testing.expect(!shouldSwitchToStandbySsh(now, null, standby));
    try std.testing.expect(!shouldSwitchToStandbySsh(now, now - 5 * std.time.ns_per_s, standby));
    try std.testing.expect(shouldSwitchToStandbySsh(now, now - 11 * std.time.ns_per_s, standby));
    try std.testing.expect(!shouldSwitchToStandbySsh(now, now - 11 * std.time.ns_per_s, null));
}

test "pending UDP switch retries and times out cleanly" {
    var pending: PendingUdpSwitch = .{};

    pending.arm(100);
    try std.testing.expect(pending.active);
    try std.testing.expect(!pending.shouldRetry(100 + udp_switch_request_retry_ns - 1));
    try std.testing.expect(pending.shouldRetry(100 + udp_switch_request_retry_ns));

    pending.arm(100 + udp_switch_request_retry_ns);
    try std.testing.expectEqual(@as(i64, 100), pending.started_at_ns);
    try std.testing.expectEqual(@as(i64, 100 + udp_switch_request_retry_ns), pending.last_request_ns);
    try std.testing.expect(!pending.timedOut(100 + udp_switch_request_timeout_ns - 1));
    try std.testing.expect(pending.timedOut(100 + udp_switch_request_timeout_ns));

    pending.clear();
    try std.testing.expect(!pending.active);
}

test "ssh output is buffered until the snapshot baseline is ready" {
    try std.testing.expect(shouldBufferSshOutput(null, true));
    try std.testing.expect(shouldBufferSshOutput(1, false));
    try std.testing.expect(!shouldBufferSshOutput(null, false));
}

test "ssh snapshot ids use a reserved namespace" {
    var next_snapshot_id = initial_ssh_snapshot_id;
    var awaiting = false;
    var expected: ?u32 = null;

    const first = reserveSshSnapshotId(&next_snapshot_id, &awaiting, &expected);
    try std.testing.expectEqual(initial_ssh_snapshot_id, first);
    try std.testing.expect(awaiting);
    try std.testing.expectEqual(@as(?u32, initial_ssh_snapshot_id), expected);
    try std.testing.expectEqual(initial_ssh_snapshot_id + 1, next_snapshot_id);
}

test "ssh replay drops redundant resync requests" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var ctrl_buf: [8]u8 = [_]u8{0} ** 8;
    const replay = try buildSshReplayPayload(alloc, .control, transport.buildControl(.resync_request, &ctrl_buf));
    try std.testing.expect(replay == null);
}

test "ssh replay strips Init while preserving later reliable IPC" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var payload = try std.ArrayList(u8).initCapacity(alloc, 32);
    defer payload.deinit(alloc);

    const init = ipc.Init{ .rows = 24, .cols = 80, .snapshot_id = 7 };
    try ipc.appendMessage(alloc, &payload, .Init, std.mem.asBytes(&init));
    try ipc.appendMessage(alloc, &payload, .Detach, "");

    const replay = (try buildSshReplayPayload(alloc, .reliable_ipc, payload.items)).?;
    defer alloc.free(replay);

    const msg_len = ipc.expectedLength(replay).?;
    try std.testing.expectEqual(msg_len, replay.len);
    const hdr = std.mem.bytesToValue(ipc.Header, replay[0..@sizeOf(ipc.Header)]);
    try std.testing.expect(hdr.tag == .Detach);
}

test "udp re-promotion state waits for the fresh baseline epoch" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var stdout_buf = try std.ArrayList(u8).initCapacity(alloc, 16);
    defer stdout_buf.deinit(alloc);
    var deferred_output_buf = try std.ArrayList(u8).initCapacity(alloc, 16);
    defer deferred_output_buf.deinit(alloc);
    try stdout_buf.appendSlice(alloc, "old");
    try deferred_output_buf.appendSlice(alloc, "deferred");

    var active_snapshot_id: ?u32 = 1;
    var awaiting_ssh_snapshot = true;
    var expected_ssh_snapshot_id: ?u32 = 7;
    var pending_output_epoch: ?u32 = 9;
    var resync_pending = true;
    var current_output_epoch: u32 = 3;

    applyUdpRepromotionState(42, &active_snapshot_id, &awaiting_ssh_snapshot, &expected_ssh_snapshot_id, &stdout_buf, &deferred_output_buf, &pending_output_epoch, &resync_pending, &current_output_epoch);

    try std.testing.expect(active_snapshot_id == null);
    try std.testing.expect(!awaiting_ssh_snapshot);
    try std.testing.expect(expected_ssh_snapshot_id == null);
    try std.testing.expectEqual(@as(usize, 0), stdout_buf.items.len);
    try std.testing.expectEqual(@as(usize, 0), deferred_output_buf.items.len);
    try std.testing.expectEqual(@as(?u32, 42), pending_output_epoch);
    try std.testing.expect(active_snapshot_id == null and pending_output_epoch.? == 42);
    try std.testing.expect(!resync_pending);
    try std.testing.expectEqual(@as(u32, 42), current_output_epoch);
}

test "standby candidate reprobe filters reset and select refreshed path" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var refreshed = [_]nat.Candidate{
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 60000), .source = "loopback" },
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 203, 0, 113, 20 }, 60002), .source = "host" },
        .{ .ctype = .srflx, .addr = std.net.Address.initIp4(.{ 198, 51, 100, 20 }, 60001), .source = "stun" },
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 203, 0, 113, 20 }, 60002), .source = "dup" },
    };

    var reprobe: CandidateReprobe = .{};
    defer reprobe.deinit(alloc);

    try std.testing.expect(try reprobe.start(alloc, .ipv4_only, &refreshed, 0));
    try std.testing.expectEqual(@as(usize, 2), reprobe.candidates.items.len);
    try std.testing.expect(reprobe.candidates.items[0].ctype == .host);
    try std.testing.expect(reprobe.candidates.items[1].ctype == .srflx);
    try std.testing.expectEqual(@as(i64, 0), reprobe.pollDelayMs(0).?);

    const first = reprobe.maybeNextProbeAddr(0).?;
    try std.testing.expect(nat.isAddressEqual(first, reprobe.candidates.items[0].addr));
    try std.testing.expect(!reprobe.onAuthenticatedRecv(std.net.Address.initIp4(.{ 203, 0, 113, 99 }, 60099)));
    try std.testing.expect(reprobe.onAuthenticatedRecv(reprobe.candidates.items[1].addr));
    try std.testing.expect(nat.isAddressEqual(reprobe.candidates.items[1].addr, reprobe.probe.selected.?));
    try std.testing.expect(reprobe.maybeNextProbeAddr(std.time.ns_per_s) == null);
}

test "ssh candidate reprobe persists across probe cycles" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var refreshed = [_]nat.Candidate{
        .{ .ctype = .srflx, .addr = std.net.Address.initIp4(.{ 198, 51, 100, 20 }, 60001), .source = "stun" },
        .{ .ctype = .host, .addr = std.net.Address.initIp4(.{ 203, 0, 113, 20 }, 60002), .source = "host" },
    };

    var reprobe: CandidateReprobe = .{};
    defer reprobe.deinit(alloc);

    try std.testing.expect(try reprobe.startPersistent(alloc, .ipv4_only, &refreshed, 0));

    var probe_now: i64 = 0;
    var sends: usize = 0;
    const total_probes = reprobe.candidates.items.len * @as(usize, reprobe.probe.attempts_per_candidate);
    while (sends < total_probes) : (sends += 1) {
        const addr = reprobe.maybeNextProbeAddr(probe_now).?;
        try std.testing.expect(nat.isAddressEqual(addr, reprobe.candidates.items[sends % reprobe.candidates.items.len].addr));
        probe_now += @as(i64, reprobe.probe.interval_ms) * std.time.ns_per_ms;
    }

    const restarted = reprobe.maybeNextProbeAddr(probe_now).?;
    try std.testing.expect(nat.isAddressEqual(restarted, reprobe.candidates.items[0].addr));
}

test "ssh candidate reprobe accepts authenticated peer-reflexive path" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var refreshed = [_]nat.Candidate{
        .{ .ctype = .srflx, .addr = std.net.Address.initIp4(.{ 198, 51, 100, 20 }, 60001), .source = "stun" },
    };

    var reprobe: CandidateReprobe = .{};
    defer reprobe.deinit(alloc);

    try std.testing.expect(try reprobe.startPersistent(alloc, .ipv4_only, &refreshed, 0));
    _ = reprobe.maybeNextProbeAddr(0).?;

    const peer_reflexive = std.net.Address.initIp4(.{ 203, 0, 113, 44 }, 62044);
    try std.testing.expect(reprobe.onAuthenticatedRecvPeerReflexive(peer_reflexive));
    try std.testing.expect(nat.isAddressEqual(peer_reflexive, reprobe.probe.selected.?));
}

test "standby UDP control messages start refreshed reprobes" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var standby_buffer = try std.ArrayList(u8).initCapacity(alloc, 256);
    defer standby_buffer.deinit(alloc);
    try standby_buffer.appendSlice(
        alloc,
        "ZMX_CANDIDATES2 {\"candidates\":[{\"ctype\":\"host\",\"endpoint\":\"203.0.113.10:60000\",\"source\":\"ifaddr\"}]}\n",
    );

    var reprobe: CandidateReprobe = .{};
    defer reprobe.deinit(alloc);
    var peer = udp_mod.Peer.init([_]u8{0} ** crypto.key_length, .to_server);
    var server_candidates = try std.ArrayList(nat.Candidate).initCapacity(alloc, 1);
    defer server_candidates.deinit(alloc);

    try handleUdpStandbyControlMessages(alloc, &standby_buffer, &server_candidates, .ipv4_only, &reprobe, &peer, 123, false);
    try std.testing.expectEqual(@as(usize, 0), standby_buffer.items.len);
    try std.testing.expectEqual(@as(usize, 1), reprobe.candidates.items.len);
    try std.testing.expectEqual(@as(usize, 1), server_candidates.items.len);
    try std.testing.expectEqual(@as(i64, 123), reprobe.next_probe_ns);
    try std.testing.expect(peer.recovery_mode);
}

test "async srflx refresh updates local candidates after a STUN response" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var refresh = try AsyncSrflxRefresh.init(alloc, .ipv4_only, &[_][]const u8{"127.0.0.1:3478"});
    defer refresh.deinit(alloc);

    var sock = try udp_mod.UdpSocket.bindEphemeral(posix.AF.INET);
    defer sock.close();

    try std.testing.expect(try refresh.start(alloc, &sock));
    try std.testing.expectEqual(@as(usize, 1), refresh.states.items.len);

    var initial = try refresh.buildCandidateSet(alloc, sock.bound_port, .ipv4_only);
    defer initial.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 0), countCandidatesByType(initial.items, .srflx));

    const state = &refresh.states.items[0];
    var msg: [32]u8 = [_]u8{0} ** 32;
    std.mem.writeInt(u16, msg[0..2], 0x0101, .big);
    std.mem.writeInt(u16, msg[2..4], 12, .big);
    std.mem.writeInt(u32, msg[4..8], nat.stun_magic_cookie, .big);
    msg[8..20].* = state.txn_id;
    std.mem.writeInt(u16, msg[20..22], 0x0020, .big);
    std.mem.writeInt(u16, msg[22..24], 8, .big);
    msg[24] = 0;
    msg[25] = 0x01;

    const port: u16 = 54321;
    const x_port = port ^ @as(u16, @truncate(nat.stun_magic_cookie >> 16));
    std.mem.writeInt(u16, msg[26..28], x_port, .big);

    const ip = [4]u8{ 203, 0, 113, 7 };
    const ip_u32 = std.mem.readInt(u32, &ip, .big);
    std.mem.writeInt(u32, msg[28..32], ip_u32 ^ nat.stun_magic_cookie, .big);

    try std.testing.expect(refresh.handleDatagram(state.server_addr, &msg) == .changed);

    var updated = try refresh.buildCandidateSet(alloc, sock.bound_port, .ipv4_only);
    defer updated.deinit(alloc);
    try std.testing.expectEqual(@as(usize, 1), countCandidatesByType(updated.items, .srflx));

    var saw_srflx = false;
    for (updated.items) |candidate| {
        if (candidate.ctype != .srflx) continue;
        saw_srflx = nat.isAddressEqual(candidate.addr, std.net.Address.initIp4(ip, port));
        if (saw_srflx) break;
    }
    try std.testing.expect(saw_srflx);
}

test "session name validation" {
    try std.testing.expect(isValidSessionName("abc-DEF_123.session"));
    try std.testing.expect(!isValidSessionName(""));
    try std.testing.expect(!isValidSessionName("oops;rm -rf /"));
}
