const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const nat = @import("nat.zig");
const builtin = @import("builtin");

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_stdout_buf = 4 * 1024 * 1024;
const max_bootstrap_line = 4096;
const default_probe_timeout_ms: u32 = 3000;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const initial_resync_backoff_ns = 250 * std.time.ns_per_ms;
const session_end_grace_ns = 2 * std.time.ns_per_s;

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

const Connect2Json = struct {
    v: u8,
    key: []const u8,
    candidates: []nat.CandidateWire,
    ssh_fallback: bool = false,
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
) !struct { key: crypto.Key, candidates: std.ArrayList(nat.Candidate) } {
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

    return .{ .key = key, .candidates = candidates };
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

fn writeAllFd(fd: i32, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(fd, bytes[off..]) catch |err| {
            if (err == error.WouldBlock) {
                var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                _ = try posix.poll(&fds, 1000);
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
    var wire_list = try std.ArrayList(nat.CandidateWire).initCapacity(alloc, candidates.len);
    defer wire_list.deinit(alloc);
    var owned_endpoints = try std.ArrayList([]u8).initCapacity(alloc, candidates.len);
    defer {
        for (owned_endpoints.items) |ep| alloc.free(ep);
        owned_endpoints.deinit(alloc);
    }

    for (candidates) |cand| {
        const endpoint = try nat.endpointForAddressAlloc(alloc, cand.addr);
        try owned_endpoints.append(alloc, endpoint);
        try wire_list.append(alloc, .{
            .ctype = cand.ctype,
            .endpoint = endpoint,
            .source = cand.source,
        });
    }

    const payload = nat.Candidates2Payload{ .candidates = wire_list.items };
    var builder: std.Io.Writer.Allocating = .init(alloc);
    defer builder.deinit();
    try builder.writer.print("ZMX_CANDIDATES2 {f}\n", .{std.json.fmt(payload, .{})});
    try writeAllFd(fd, builder.writer.buffered());
}

fn appendUniqueCandidate(list: *std.ArrayList(nat.Candidate), alloc: std.mem.Allocator, candidate: nat.Candidate, max_candidates: usize) !void {
    for (list.items) |existing| {
        if (nat.isAddressEqual(existing.addr, candidate.addr)) return;
    }
    if (list.items.len >= max_candidates) return;
    try list.append(alloc, candidate);
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
    socket_family: u16,
    stun_servers: []const []const u8,
) !std.ArrayList(nat.Candidate) {
    var candidates = try nat.gatherHostCandidates(alloc, sock.bound_port, socket_family, 8);
    errdefer candidates.deinit(alloc);

    var stun_addrs = try nat.resolveStunServers(alloc, socket_family, stun_servers);
    defer stun_addrs.deinit(alloc);

    for (stun_addrs.items) |stun_addr| {
        var stun_state = nat.StunState.init(stun_addr);
        stun_state.sendRequest(sock) catch {};
        const deadline = @as(i64, @intCast(std.time.nanoTimestamp())) + 4 * std.time.ns_per_s;

        while (@as(i64, @intCast(std.time.nanoTimestamp())) < deadline and stun_state.result == null and stun_state.waiting_response) {
            var poll_fds = [_]posix.pollfd{.{ .fd = sock.getFd(), .events = posix.POLL.IN, .revents = 0 }};
            _ = posix.poll(&poll_fds, 100) catch |err| {
                if (err == error.Interrupted) continue;
                break;
            };

            if (poll_fds[0].revents & posix.POLL.IN != 0) {
                while (true) {
                    var recv_buf: [1500]u8 = undefined;
                    const raw = sock.recvRaw(&recv_buf) catch break;
                    const packet = raw orelse break;
                    if (nat.isStunPacket(stun_addr, packet.from, packet.data)) {
                        _ = stun_state.handleResponse(packet.data) catch {};
                    }
                }
            }

            const now: i64 = @intCast(std.time.nanoTimestamp());
            stun_state.maybeRetry(sock, now) catch {};
        }

        if (stun_state.result) |srflx| {
            try appendUniqueCandidate(&candidates, alloc, srflx, 8);
            break;
        }
    }

    nat.sortCandidatesByPriority(candidates.items);
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

    var local_candidates = try gatherLocalCandidates(alloc, udp_sock, fallback_addr.any.family, options.stun_servers);
    defer local_candidates.deinit(alloc);

    try appendUniqueCandidate(&local_candidates, alloc, .{
        .ctype = .host,
        .addr = fallback_addr,
        .source = "ssh_host",
    }, 8);

    try sendCandidates(pipes.stdin_fd, alloc, local_candidates.items);

    var remote_candidates = try std.ArrayList(nat.Candidate).initCapacity(alloc, session.server_candidates.items.len + 1);
    defer remote_candidates.deinit(alloc);

    for (session.server_candidates.items) |candidate| {
        if (!nat.shouldUseCandidate(fallback_addr.any.family, candidate.addr)) continue;
        if (!nat.isCandidateAddressUsable(candidate.addr)) continue;
        try appendUniqueCandidate(&remote_candidates, alloc, candidate, 8);
    }
    try appendUniqueCandidate(&remote_candidates, alloc, .{
        .ctype = .host,
        .addr = fallback_addr,
        .source = "ssh_host",
    }, 8);

    nat.sortCandidatesByPriority(remote_candidates.items);
    if (remote_candidates.items.len == 0) return .ssh;

    var probe = nat.ProbeState{ .candidates = remote_candidates.items };
    var next_probe_ns: i64 = @intCast(std.time.nanoTimestamp());
    const probe_timeout_ns = @as(i64, clampProbeTimeoutMs(options.probe_timeout_ms)) * std.time.ns_per_ms;
    const deadline = next_probe_ns + probe_timeout_ns;

    while (@as(i64, @intCast(std.time.nanoTimestamp())) < deadline and !probe.isComplete()) {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        if (now >= next_probe_ns) {
            if (probe.nextProbeAddr()) |addr| {
                sendProbeHeartbeatTo(peer, udp_sock, addr, reliable_recv) catch |err| {
                    if (err != error.WouldBlock) return err;
                };
            }
            next_probe_ns = now + @as(i64, probe.interval_ms) * std.time.ns_per_ms;
        }

        const timeout_ns = @min(deadline - now, @max(@as(i64, 0), next_probe_ns - now));
        const timeout_ms: i32 = @intCast(@divFloor(timeout_ns, std.time.ns_per_ms));
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
                probe.onAuthenticatedRecv(raw.from);
            }
        }
    }

    if (probe.selected) |selected| {
        peer.addr = selected;
        return .udp;
    }
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

        const port = if (parsed.candidates.items.len > 0) parsed.candidates.items[0].addr.getPort() else 60000;

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

/// Remote attach: connect to a remote zmx session via UDP or SSH fallback.
pub fn remoteAttach(alloc: std.mem.Allocator, session_in: RemoteSession, options: RemoteAttachOptions) !void {
    var session = session_in;
    defer session.deinit(alloc);

    const fallback_addr = try resolveHostAddress(alloc, session.host, session.port);

    var udp_sock = try udp_mod.UdpSocket.bindEphemeral(fallback_addr.any.family);
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

    const decision = try probeAndSelectTransport(alloc, &session, options, fallback_addr, &udp_sock, &peer, &reliable_recv);
    if (decision == .udp and session.ssh != null) {
        try sendUse(session.ssh.?.stdin_fd, "udp");
        posix.close(session.ssh.?.stdin_fd);
        posix.close(session.ssh.?.stdout_fd);
        session.ssh = null;
        connectDebug(options.connect_debug, "selected UDP transport", .{});
    } else if (decision == .ssh) {
        if (session.ssh == null) return error.MissingSshPipes;
        try sendUse(session.ssh.?.stdin_fd, "ssh");
        _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: using SSH tunnel (no UDP connectivity)\r\n") catch {};
        connectDebug(options.connect_debug, "selected SSH transport", .{});

        transport_mode = .{ .ssh = .{
            .read_fd = session.ssh.?.stdout_fd,
            .write_fd = session.ssh.?.stdin_fd,
            .read_buf = try ipc.SocketBuffer.init(alloc),
            .write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096),
        } };
        session.ssh = null;
    }
    var was_disconnected = false;
    var session_ended = false;
    var session_end_deadline_ns: ?i64 = null;

    var last_ack_send_ns: i64 = @intCast(std.time.nanoTimestamp());
    var ack_dirty = false;
    var last_resync_request_ns: i64 = 0;
    var resync_backoff_ns: i64 = initial_resync_backoff_ns;
    var resync_pending = false;
    var active_snapshot_id: ?u32 = null;
    var current_output_epoch: u32 = 0;
    var pending_output_epoch: ?u32 = null;

    const size = getTerminalSize();
    const init = ipc.Init{ .rows = size.rows, .cols = size.cols, .snapshot_id = 0 };
    switch (transport_mode) {
        .udp => {
            var init_buf: [64]u8 = undefined;
            const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&init), &init_buf);
            try sendReliablePayload(&peer, &udp_sock, &reliable_send, &reliable_recv, .reliable_ipc, init_ipc, last_ack_send_ns);
        },
        .ssh => |*s| {
            try appendSshIpc(&s.write_buf, alloc, .Init, std.mem.asBytes(&init));
        },
    }

    while (true) {
        const now: i64 = @intCast(std.time.nanoTimestamp());

        if (sigwinch_received.swap(false, .acq_rel)) {
            const new_size = getTerminalSize();
            switch (transport_mode) {
                .udp => {
                    try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Resize, std.mem.asBytes(&new_size), now);
                },
                .ssh => |*s| {
                    try appendSshIpc(&s.write_buf, alloc, .Resize, std.mem.asBytes(&new_size));
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

            if (ack_dirty and (now - last_ack_send_ns) >= ack_delay_ns) {
                sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
            } else if (peer.shouldSendHeartbeat(now, config)) {
                sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
            }

            const state = peer.updateState(now, config);
            if (state == .dead) {
                if (!session_ended) {
                    _ = posix.write(posix.STDOUT_FILENO, "\r\nzmx: connection lost permanently\r\n") catch {};
                    return;
                }
            }
            if (state == .disconnected and !was_disconnected) {
                _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b[7mzmx: connection lost — waiting to reconnect...\x1b[27m\x1b8") catch {};
                was_disconnected = true;
                sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
                sendHeartbeat(&peer, &udp_sock, &reliable_recv, &last_ack_send_ns, &ack_dirty, now) catch {};
            } else if (state == .connected and was_disconnected) {
                _ = posix.write(posix.STDOUT_FILENO, "\x1b7\x1b[999;1H\x1b[2K\x1b8") catch {};
                was_disconnected = false;
            }
        }

        var poll_fds: [4]posix.pollfd = undefined;
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

        var stdout_idx: ?usize = null;
        if (stdout_buf.items.len > 0) {
            stdout_idx = poll_count;
            poll_fds[poll_count] = .{ .fd = posix.STDOUT_FILENO, .events = posix.POLL.OUT, .revents = 0 };
            poll_count += 1;
        }

        var ssh_write_idx: ?usize = null;
        if (transport_mode == .ssh and transport_mode.ssh.write_buf.items.len > 0) {
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
        }
        if (ack_dirty) poll_timeout = @min(poll_timeout, @as(i64, 20));

        _ = posix.poll(poll_fds[0..poll_count], @intCast(poll_timeout)) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        if (transport_mode == .ssh) {
            if (poll_fds[transport_read_idx].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                return;
            }
            if (ssh_write_idx) |idx| {
                if (poll_fds[idx].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                    return;
                }
            }
        }

        if (poll_fds[stdin_idx].revents & (posix.POLL.IN | posix.POLL.HUP | posix.POLL.ERR) != 0) {
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
                                return;
                            }
                            try sendIpcReliable(&peer, &udp_sock, &reliable_send, &reliable_recv, .Input, input_raw[0..n], now);
                        },
                        .ssh => |*s| {
                            if (should_detach) {
                                try appendSshIpc(&s.write_buf, alloc, .Detach, "");
                                try writeAllFd(s.write_fd, s.write_buf.items);
                                s.write_buf.clearRetainingCapacity();
                                return;
                            }
                            try appendSshIpc(&s.write_buf, alloc, .Input, input_raw[0..n]);
                        },
                    }
                } else {
                    return;
                }
            }
        }

        if (poll_fds[transport_read_idx].revents & posix.POLL.IN != 0) {
            switch (transport_mode) {
                .udp => {
                    while (true) {
                        var decrypt_buf: [9000]u8 = undefined;
                        const recv_result = try peer.recv(&udp_sock, &decrypt_buf);
                        const result = recv_result orelse break;

                        const packet = transport.parsePacket(result.data) catch continue;
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
                                        const target_buf = if (active_snapshot_id != null) &deferred_output_buf else &stdout_buf;
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
                    while (true) {
                        const n = s.read_buf.read(s.read_fd) catch |err| {
                            if (err == error.WouldBlock) break;
                            return err;
                        };
                        if (n == 0) {
                            return;
                        }

                        while (s.read_buf.next()) |msg| {
                            if (msg.header.tag == .Output and msg.payload.len > 0) {
                                if (stdout_buf.items.len + msg.payload.len > max_stdout_buf) {
                                    stdout_buf.clearRetainingCapacity();
                                } else {
                                    try stdout_buf.appendSlice(alloc, msg.payload);
                                }
                            } else if (msg.header.tag == .SessionEnd) {
                                session_ended = true;
                                session_end_deadline_ns = session_end_deadline_ns orelse now + session_end_grace_ns;
                            }
                        }
                    }
                },
            }
        }

        if (ssh_write_idx) |idx| {
            if (poll_fds[idx].revents & posix.POLL.OUT != 0) {
                if (transport_mode == .ssh) {
                    try flushWriteBuffer(transport_mode.ssh.write_fd, &transport_mode.ssh.write_buf, alloc);
                }
            }
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

        if (session_ended and
            session_end_deadline_ns != null and
            now >= session_end_deadline_ns.? and
            active_snapshot_id == null and
            deferred_output_buf.items.len == 0)
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

test "session name validation" {
    try std.testing.expect(isValidSessionName("abc-DEF_123.session"));
    try std.testing.expect(!isValidSessionName(""));
    try std.testing.expect(!isValidSessionName("oops;rm -rf /"));
}
