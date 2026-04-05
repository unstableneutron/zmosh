const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");
const nat = @import("nat.zig");

const log = std.log.scoped(.serve);

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_unix_write_buf = 1024 * 1024;
const max_output_coalesce = 256 * 1024;
const max_control_line = 4096;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const resync_cooldown_ns = 500 * std.time.ns_per_ms;
const stun_keepalive_ns = 25 * std.time.ns_per_s;
const shutdown_drain_ns = 2 * std.time.ns_per_s;
const default_probe_timeout_ms: u32 = 3000;
const standby_candidate_probe_burst: u8 = 2;

var sigterm_received: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn handleSigterm(_: i32, _: *const posix.siginfo_t, _: ?*anyopaque) callconv(.c) void {
    sigterm_received.store(true, .release);
}

fn setupSigtermHandler() void {
    const act: posix.Sigaction = .{
        .handler = .{ .sigaction = handleSigterm },
        .mask = posix.sigemptyset(),
        .flags = posix.SA.SIGINFO,
    };
    posix.sigaction(posix.SIG.TERM, &act, null);
}

/// Resolve the zmx socket directory, following the same logic as main.zig's Cfg.init.
fn resolveSocketDir(alloc: std.mem.Allocator) ![]const u8 {
    if (posix.getenv("ZMX_DIR")) |zmxdir|
        return try alloc.dupe(u8, zmxdir);
    const tmpdir = std.mem.trimRight(u8, posix.getenv("TMPDIR") orelse "/tmp", "/");
    const uid = posix.getuid();
    if (posix.getenv("XDG_RUNTIME_DIR")) |xdg_runtime|
        return try std.fmt.allocPrint(alloc, "{s}/zmx", .{xdg_runtime});
    return try std.fmt.allocPrint(alloc, "{s}/zmx-{d}", .{ tmpdir, uid });
}

/// Connect to the daemon's Unix socket (same as sessionConnect in main.zig).
fn connectUnix(path: []const u8) !i32 {
    var unix_addr = try std.net.Address.initUnix(path);
    const fd = try posix.socket(posix.AF.UNIX, posix.SOCK.STREAM | posix.SOCK.CLOEXEC, 0);
    errdefer posix.close(fd);
    try posix.connect(fd, &unix_addr.any, unix_addr.getOsSockLen());
    // Make non-blocking for poll loop
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.SOCK.NONBLOCK);
    return fd;
}

const GatewayTransport = union(enum) {
    udp,
    ssh: struct {
        read_fd: i32,
        write_fd: i32,
        read_buf: ipc.SocketBuffer,
        write_buf: std.ArrayList(u8),
    },

    fn deinit(self: *GatewayTransport, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .udp => {},
            .ssh => |*s| {
                s.read_buf.deinit();
                s.write_buf.deinit(alloc);
            },
        }
    }
};

const StandbySsh = struct {
    read_fd: i32,
    write_fd: i32,
    control_buf: std.ArrayList(u8),

    fn deinit(self: *StandbySsh, alloc: std.mem.Allocator, close_fds: bool) void {
        if (close_fds) {
            if (self.read_fd == self.write_fd) {
                posix.close(self.read_fd);
            } else {
                posix.close(self.read_fd);
                posix.close(self.write_fd);
            }
        }
        self.control_buf.deinit(alloc);
    }
};

const Candidates2Json = struct {
    candidates: []nat.CandidateWire,
};

const UseMode = enum {
    udp,
    ssh,
};

const StandbyControlMessage = union(enum) {
    use: UseMode,
    candidates: std.ArrayList(nat.Candidate),

    fn deinit(self: *StandbyControlMessage, alloc: std.mem.Allocator) void {
        switch (self.*) {
            .use => {},
            .candidates => |*list| list.deinit(alloc),
        }
    }
};

fn setNonBlocking(fd: i32) !void {
    const flags = try posix.fcntl(fd, posix.F.GETFL, 0);
    _ = try posix.fcntl(fd, posix.F.SETFL, flags | posix.SOCK.NONBLOCK);
}

fn clampProbeTimeoutMs(ms: u32) u32 {
    return std.math.clamp(ms, @as(u32, 500), @as(u32, 30_000));
}

fn connectDebug(enabled: bool, comptime fmt: []const u8, args: anytype) void {
    if (!enabled) return;
    std.debug.print("zmx serve debug: " ++ fmt ++ "\n", args);
}

fn readLineFd(fd: i32, buf: []u8) ![]const u8 {
    var total: usize = 0;
    while (total < buf.len) {
        const n = try posix.read(fd, buf[total..]);
        if (n == 0) break;
        total += n;
        if (std.mem.indexOfScalar(u8, buf[0..total], '\n') != null) break;
    }
    if (total == 0) return error.UnexpectedEof;
    const nl = std.mem.indexOfScalar(u8, buf[0..total], '\n') orelse total;
    if (nl == buf.len) return error.LineTooLong;
    return std.mem.trimRight(u8, buf[0..nl], "\r\n");
}

fn writeAllFd(fd: i32, bytes: []const u8) !void {
    const deadline_ns: i64 = @as(i64, @intCast(std.time.nanoTimestamp())) + 2 * std.time.ns_per_s;
    var off: usize = 0;
    while (off < bytes.len) {
        const n = posix.write(fd, bytes[off..]) catch |err| {
            if (err == error.WouldBlock) {
                if (@as(i64, @intCast(std.time.nanoTimestamp())) >= deadline_ns) return error.WriteFailed;
                var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
                _ = posix.poll(&fds, 200) catch |poll_err| {
                    if (poll_err == error.Interrupted) continue;
                    return error.WriteFailed;
                };
                continue;
            }
            return error.WriteFailed;
        };
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

fn sendUseAck(fd: i32, mode: []const u8) !void {
    var line_buf: [32]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buf, "ZMX_USE_OK {s}\n", .{mode});
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

fn socketFamily(fd: i32) !u16 {
    var src_addr: posix.sockaddr.storage = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    try posix.getsockname(fd, @ptrCast(&src_addr), &addr_len);

    var addr: std.net.Address = std.mem.zeroes(std.net.Address);
    const len = @min(@as(usize, @intCast(addr_len)), @sizeOf(std.net.Address));
    @memcpy(std.mem.asBytes(&addr)[0..len], std.mem.asBytes(&src_addr)[0..len]);
    return addr.any.family;
}

fn loadStunServerSpecs(alloc: std.mem.Allocator) !std.ArrayList([]const u8) {
    var specs = try std.ArrayList([]const u8).initCapacity(alloc, 4);
    if (posix.getenv("ZMX_STUN_SERVERS")) |raw| {
        var it = std.mem.splitScalar(u8, raw, ',');
        while (it.next()) |value| {
            const trimmed = std.mem.trim(u8, value, " \t");
            if (trimmed.len == 0) continue;
            try specs.append(alloc, trimmed);
        }
    }
    return specs;
}

fn parseConnectDebugEnv() bool {
    const raw = posix.getenv("ZMX_CONNECT_DEBUG") orelse return false;
    return std.mem.eql(u8, raw, "1") or
        std.ascii.eqlIgnoreCase(raw, "true") or
        std.ascii.eqlIgnoreCase(raw, "yes");
}

fn parseProbeTimeoutNs() i64 {
    const raw = posix.getenv("ZMX_PROBE_TIMEOUT_MS") orelse {
        return @as(i64, default_probe_timeout_ms) * std.time.ns_per_ms;
    };
    const parsed_ms = std.fmt.parseInt(u32, raw, 10) catch default_probe_timeout_ms;
    const clamped = clampProbeTimeoutMs(parsed_ms);
    return @as(i64, clamped) * std.time.ns_per_ms;
}

fn appendUniqueCandidate(list: *std.ArrayList(nat.Candidate), alloc: std.mem.Allocator, candidate: nat.Candidate, max_candidates: usize) !void {
    for (list.items) |existing| {
        if (nat.isAddressEqual(existing.addr, candidate.addr)) return;
    }
    if (list.items.len >= max_candidates) return;
    try list.append(alloc, candidate);
}

fn findServerReflexiveCandidate(candidates: []const nat.Candidate) ?std.net.Address {
    for (candidates) |candidate| {
        if (candidate.ctype == .srflx) return candidate.addr;
    }
    return null;
}

fn sendConnect2(
    fd: i32,
    alloc: std.mem.Allocator,
    key: crypto.Key,
    port: u16,
    candidates: []const nat.Candidate,
) !void {
    const encoded_key = crypto.keyToBase64(key);

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

    const payload = nat.Connect2Payload{
        .key = &encoded_key,
        .port = port,
        .candidates = wire_list.items,
        .ssh_fallback = true,
    };

    var builder: std.Io.Writer.Allocating = .init(alloc);
    defer builder.deinit();
    try builder.writer.print("ZMX_CONNECT2 {f}\n", .{std.json.fmt(payload, .{})});
    try writeAllFd(fd, builder.writer.buffered());
}

fn parseCandidatesLine(alloc: std.mem.Allocator, line: []const u8) !std.ArrayList(nat.Candidate) {
    if (!std.mem.startsWith(u8, line, "ZMX_CANDIDATES2 ")) return error.InvalidControlMessage;
    const json_payload = line["ZMX_CANDIDATES2 ".len..];

    var parsed = try std.json.parseFromSlice(Candidates2Json, alloc, json_payload, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    var out = try std.ArrayList(nat.Candidate).initCapacity(alloc, parsed.value.candidates.len);
    errdefer out.deinit(alloc);
    for (parsed.value.candidates) |wire| {
        const candidate = try nat.wireToCandidate(wire);
        if (!nat.isCandidateAddressUsable(candidate.addr)) continue;
        try out.append(alloc, candidate);
    }
    return out;
}

fn parseUseLine(line: []const u8) !UseMode {
    if (std.mem.eql(u8, line, "ZMX_USE udp")) return .udp;
    if (std.mem.eql(u8, line, "ZMX_USE ssh")) return .ssh;
    return error.InvalidControlMessage;
}

fn parseStandbyControlLine(alloc: std.mem.Allocator, line: []const u8) !StandbyControlMessage {
    if (std.mem.startsWith(u8, line, "ZMX_CANDIDATES2 ")) {
        return .{ .candidates = try parseCandidatesLine(alloc, line) };
    }
    return .{ .use = try parseUseLine(line) };
}

fn buildSshPromotionReplayPayload(alloc: std.mem.Allocator, channel: transport.Channel, payload: []const u8) !?[]u8 {
    if (channel != .reliable_ipc) return try alloc.dupe(u8, payload);

    var filtered = try std.ArrayList(u8).initCapacity(alloc, payload.len);
    defer filtered.deinit(alloc);

    var offset: usize = 0;
    while (offset < payload.len) {
        const remaining = payload[offset..];
        const msg_len = ipc.expectedLength(remaining) orelse return try alloc.dupe(u8, payload);
        if (remaining.len < msg_len) return try alloc.dupe(u8, payload);

        const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
        if (hdr.tag != .Snapshot) {
            try filtered.appendSlice(alloc, remaining[0..msg_len]);
        }
        offset += msg_len;
    }

    if (filtered.items.len == 0) return null;
    return try filtered.toOwnedSlice(alloc);
}

fn gatherLocalCandidates(
    alloc: std.mem.Allocator,
    sock: *udp.UdpSocket,
    socket_family: u16,
    stun_servers: []const std.net.Address,
) !std.ArrayList(nat.Candidate) {
    var out = try nat.gatherHostCandidates(alloc, sock.bound_port, socket_family, 8);
    errdefer out.deinit(alloc);

    for (stun_servers) |server_addr| {
        var stun_state = nat.StunState.init(server_addr);
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
                    if (nat.isStunPacket(server_addr, packet.from, packet.data)) {
                        _ = stun_state.handleResponse(packet.data) catch {};
                    }
                }
            }

            const now: i64 = @intCast(std.time.nanoTimestamp());
            stun_state.maybeRetry(sock, now) catch {};
        }

        if (stun_state.result) |srflx| {
            try appendUniqueCandidate(&out, alloc, srflx, 8);
            break;
        }
    }

    nat.sortCandidatesByPriority(out.items);
    return out;
}

fn sendProbeHeartbeatTo(
    peer: *udp.Peer,
    sock: *udp.UdpSocket,
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

fn probeCandidates(
    alloc: std.mem.Allocator,
    sock: *udp.UdpSocket,
    peer: *udp.Peer,
    socket_family: u16,
    candidates: []const nat.Candidate,
    reliable_recv: *const transport.RecvState,
    probe_timeout_ns: i64,
) !?std.net.Address {
    var filtered = try std.ArrayList(nat.Candidate).initCapacity(alloc, candidates.len);
    defer filtered.deinit(alloc);
    for (candidates) |cand| {
        if (!nat.shouldUseCandidate(socket_family, cand.addr)) continue;
        if (!nat.isCandidateAddressUsable(cand.addr)) continue;
        try appendUniqueCandidate(&filtered, alloc, cand, 8);
    }
    nat.sortCandidatesByPriority(filtered.items);
    if (filtered.items.len == 0) return null;

    var probe = nat.ProbeState{ .candidates = filtered.items };
    var next_probe_ns: i64 = @intCast(std.time.nanoTimestamp());
    const deadline = next_probe_ns + probe_timeout_ns;

    while (@as(i64, @intCast(std.time.nanoTimestamp())) < deadline and !probe.isComplete()) {
        const now: i64 = @intCast(std.time.nanoTimestamp());
        if (now >= next_probe_ns) {
            if (probe.nextProbeAddr()) |addr| {
                sendProbeHeartbeatTo(peer, sock, addr, reliable_recv) catch |err| {
                    if (err != error.WouldBlock) return err;
                };
            }
            next_probe_ns = now + @as(i64, probe.interval_ms) * std.time.ns_per_ms;
        }

        const timeout_ns = @min(deadline - now, @max(@as(i64, 0), next_probe_ns - now));
        const timeout_ms: i32 = @intCast(@divFloor(timeout_ns, std.time.ns_per_ms));
        var poll_fds = [_]posix.pollfd{.{ .fd = sock.getFd(), .events = posix.POLL.IN, .revents = 0 }};
        _ = posix.poll(&poll_fds, timeout_ms) catch |err| {
            if (err == error.Interrupted) continue;
            return err;
        };

        if (poll_fds[0].revents & posix.POLL.IN != 0) {
            while (true) {
                var raw_buf: [9000]u8 = undefined;
                const raw = try sock.recvRaw(&raw_buf) orelse break;

                var decrypt_buf: [9000]u8 = undefined;
                const old_addr = peer.addr;
                const decoded = try peer.decodeAndUpdate(raw.data, raw.from, &decrypt_buf);
                peer.addr = old_addr;
                if (decoded == null) continue;
                probe.onAuthenticatedRecv(raw.from);
            }
        }
    }

    return probe.selected;
}

pub const Gateway = struct {
    alloc: std.mem.Allocator,
    udp_sock: udp.UdpSocket,
    unix_fd: i32,
    peer: udp.Peer,
    unix_read_buf: ipc.SocketBuffer,
    unix_write_buf: std.ArrayList(u8),
    output_coalesce_buf: std.ArrayList(u8),

    reliable_send: transport.ReliableSend,
    reliable_recv: transport.RecvState,
    reliable_inbox: transport.ReliableInbox,
    output_seq: u32,
    output_epoch: u32,
    socket_family: u16,

    config: udp.Config,
    running: bool,

    last_output_flush_ns: i64,
    last_ack_send_ns: i64,
    ack_dirty: bool,

    last_resync_request_ns: i64,
    snapshot_id: u32,
    snapshot_in_flight_id: ?u32,
    ssh_baseline_snapshot_id: ?u32,
    ssh_baseline_pending: bool,
    have_client_size: bool,
    last_resize: ipc.Resize,
    transport: GatewayTransport,
    standby_ssh: ?StandbySsh,
    stun_servers: std.ArrayList(std.net.Address),
    stun_server_idx: usize,
    stun_state: ?nat.StunState,
    last_stun_keepalive_ns: i64,
    last_srflx: ?std.net.Address,

    pub fn init(
        alloc: std.mem.Allocator,
        session_name: []const u8,
        config: udp.Config,
    ) !Gateway {
        const socket_dir = try resolveSocketDir(alloc);
        defer alloc.free(socket_dir);

        const socket_path = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ socket_dir, session_name });
        defer alloc.free(socket_path);

        // Connect to the daemon's Unix socket
        const unix_fd = connectUnix(socket_path) catch |err| {
            log.err("failed to connect to daemon socket={s} err={s}", .{ socket_path, @errorName(err) });
            return err;
        };
        errdefer posix.close(unix_fd);

        // Bind a UDP socket in the configured port range
        var udp_sock = try udp.UdpSocket.bind(config.port_range_start, config.port_range_end);
        errdefer udp_sock.close();

        // Generate session key
        const key = crypto.generateKey();
        const encoded_key = crypto.keyToBase64(key);

        const socket_family = try socketFamily(udp_sock.getFd());
        const connect_debug = parseConnectDebugEnv();
        const probe_timeout_ns = parseProbeTimeoutNs();

        var stun_specs = try loadStunServerSpecs(alloc);
        defer stun_specs.deinit(alloc);
        var stun_servers = try nat.resolveStunServers(alloc, socket_family, stun_specs.items);
        errdefer stun_servers.deinit(alloc);

        // Initialize peer (we send to_client, recv to_server from remote client)
        var peer = udp.Peer.init(key, .to_client);
        var transport_mode: GatewayTransport = .udp;
        errdefer transport_mode.deinit(alloc);
        var standby_ssh: ?StandbySsh = null;
        errdefer if (standby_ssh) |*standby| standby.deinit(alloc, true);
        var initial_srflx: ?std.net.Address = null;
        const bootstrap_v2 = std.mem.eql(u8, posix.getenv("ZMX_BOOTSTRAP") orelse "", "2");

        connectDebug(connect_debug, "bootstrap_v2={} probe_timeout_ms={d} stun_servers={d}", .{
            bootstrap_v2,
            @divFloor(probe_timeout_ns, std.time.ns_per_ms),
            stun_servers.items.len,
        });

        if (bootstrap_v2) {
            var local_candidates = try gatherLocalCandidates(alloc, &udp_sock, socket_family, stun_servers.items);
            defer local_candidates.deinit(alloc);
            initial_srflx = findServerReflexiveCandidate(local_candidates.items);

            try sendConnect2(posix.STDOUT_FILENO, alloc, key, udp_sock.bound_port, local_candidates.items);

            var line_buf: [max_control_line]u8 = undefined;
            const candidates_line = try readLineFd(posix.STDIN_FILENO, &line_buf);
            var remote_candidates = try parseCandidatesLine(alloc, candidates_line);
            defer remote_candidates.deinit(alloc);

            var probe_recv = transport.RecvState{};
            if (try probeCandidates(alloc, &udp_sock, &peer, socket_family, remote_candidates.items, &probe_recv, probe_timeout_ns)) |selected| {
                peer.addr = selected;
            }

            const use_line = try readLineFd(posix.STDIN_FILENO, &line_buf);
            const use_mode = try parseUseLine(use_line);
            if (use_mode == .udp) {
                try setNonBlocking(posix.STDIN_FILENO);
                try setNonBlocking(posix.STDOUT_FILENO);
                standby_ssh = .{
                    .read_fd = posix.STDIN_FILENO,
                    .write_fd = posix.STDOUT_FILENO,
                    .control_buf = try std.ArrayList(u8).initCapacity(alloc, 128),
                };
            } else {
                try sendUseAck(posix.STDOUT_FILENO, "ssh");
                try setNonBlocking(posix.STDIN_FILENO);
                try setNonBlocking(posix.STDOUT_FILENO);
                transport_mode = .{ .ssh = .{
                    .read_fd = posix.STDIN_FILENO,
                    .write_fd = posix.STDOUT_FILENO,
                    .read_buf = try ipc.SocketBuffer.init(alloc),
                    .write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096),
                } };
            }
        } else {
            // Print bootstrap line for SSH capture
            var out_buf: [256]u8 = undefined;
            const line = std.fmt.bufPrint(&out_buf, "ZMX_CONNECT udp {d} {s}\n", .{ udp_sock.bound_port, encoded_key }) catch unreachable;
            _ = try posix.write(posix.STDOUT_FILENO, line);

            // Close stdout so SSH session can terminate
            posix.close(posix.STDOUT_FILENO);
        }

        const unix_read_buf = try ipc.SocketBuffer.init(alloc);
        const unix_write_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
        const output_coalesce_buf = try std.ArrayList(u8).initCapacity(alloc, 4096);
        const reliable_send = try transport.ReliableSend.init(alloc);
        const reliable_inbox = try transport.ReliableInbox.init(alloc);

        const now: i64 = @intCast(std.time.nanoTimestamp());

        log.info("gateway started session={s} udp_port={d}", .{ session_name, udp_sock.bound_port });

        return .{
            .alloc = alloc,
            .udp_sock = udp_sock,
            .unix_fd = unix_fd,
            .peer = peer,
            .unix_read_buf = unix_read_buf,
            .unix_write_buf = unix_write_buf,
            .output_coalesce_buf = output_coalesce_buf,
            .reliable_send = reliable_send,
            .reliable_recv = .{},
            .reliable_inbox = reliable_inbox,
            .output_seq = 1,
            .output_epoch = 0,
            .socket_family = socket_family,
            .config = config,
            .running = true,
            .last_output_flush_ns = now,
            .last_ack_send_ns = now,
            .ack_dirty = false,
            .last_resync_request_ns = 0,
            .snapshot_id = 0,
            .snapshot_in_flight_id = null,
            .ssh_baseline_snapshot_id = null,
            .ssh_baseline_pending = transport_mode == .ssh,
            .have_client_size = false,
            .last_resize = .{ .rows = 24, .cols = 80 },
            .transport = transport_mode,
            .standby_ssh = standby_ssh,
            .stun_servers = stun_servers,
            .stun_server_idx = 0,
            .stun_state = null,
            .last_stun_keepalive_ns = now,
            .last_srflx = initial_srflx,
        };
    }

    pub fn run(self: *Gateway) !void {
        setupSigtermHandler();
        var was_disconnected = false;

        if (self.transport == .ssh) {
            return self.runSsh();
        }

        while (self.running) {
            if (sigterm_received.swap(false, .acq_rel)) {
                log.info("SIGTERM received, shutting down gateway", .{});
                break;
            }

            const now: i64 = @intCast(std.time.nanoTimestamp());

            // Check peer state
            const state = self.peer.updateState(now, self.config);
            if (state == .dead) {
                log.info("peer dead (alive timeout), shutting down", .{});
                break;
            }
            if (state == .disconnected and !was_disconnected) {
                was_disconnected = true;
                self.sendHeartbeat(now) catch {};
                self.sendHeartbeat(now) catch {};
            } else if (state == .connected and was_disconnected) {
                was_disconnected = false;
            }

            try self.flushRetransmits(now);
            try self.flushOutput(now, false);

            if (self.peer.addr != null) {
                if (self.ack_dirty and (now - self.last_ack_send_ns >= ack_delay_ns)) {
                    self.sendHeartbeat(now) catch |err| {
                        if (err != error.NoPeerAddress and err != error.WouldBlock) return err;
                    };
                } else if (self.peer.shouldSendHeartbeat(now, self.config)) {
                    self.sendHeartbeat(now) catch |err| {
                        if (err != error.NoPeerAddress and err != error.WouldBlock) return err;
                    };
                }
            }

            if (self.stun_servers.items.len > 0 and (now - self.last_stun_keepalive_ns) >= stun_keepalive_ns) {
                self.sendStunKeepalive(now) catch |err| {
                    if (err != error.WouldBlock) return err;
                };
            }

            if (self.stun_state) |*stun_state| {
                stun_state.maybeRetry(&self.udp_sock, now) catch |err| {
                    if (err != error.WouldBlock) return err;
                };
            }

            // Build poll fds
            var poll_fds: [3]posix.pollfd = undefined;
            var poll_count: usize = 2;
            poll_fds[0] = .{ .fd = self.udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };

            var unix_events: i16 = posix.POLL.IN;
            if (self.unix_write_buf.items.len > 0) {
                unix_events |= posix.POLL.OUT;
            }
            poll_fds[1] = .{ .fd = self.unix_fd, .events = unix_events, .revents = 0 };

            var standby_idx: ?usize = null;
            if (self.standby_ssh) |standby| {
                standby_idx = poll_count;
                poll_fds[poll_count] = .{ .fd = standby.read_fd, .events = posix.POLL.IN, .revents = 0 };
                poll_count += 1;
            }

            const poll_timeout = self.computePollTimeoutMs(now);
            _ = posix.poll(poll_fds[0..poll_count], poll_timeout) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };

            if (standby_idx) |idx| {
                if (try self.handleStandbySshEvents(poll_fds[idx].revents)) {
                    return self.runSsh();
                }
            }

            // Handle incoming UDP datagrams → decrypt → decode transport packet
            if (poll_fds[0].revents & posix.POLL.IN != 0) {
                while (true) {
                    var raw_buf: [9000]u8 = undefined;
                    const raw = try self.udp_sock.recvRaw(&raw_buf) orelse break;

                    if (self.handleStunDatagram(raw.from, raw.data)) {
                        continue;
                    }

                    var decrypt_buf: [9000]u8 = undefined;
                    const decoded = try self.peer.decodeAndUpdate(raw.data, raw.from, &decrypt_buf) orelse continue;
                    try self.handleTransportPacket(decoded, now);
                }
            }

            // Handle Unix socket read → forward to UDP transport
            if (poll_fds[1].revents & posix.POLL.IN != 0) {
                while (true) {
                    const n = self.unix_read_buf.read(self.unix_fd) catch |err| {
                        if (err == error.WouldBlock) break;
                        log.warn("unix read error: {s}", .{@errorName(err)});
                        self.running = false;
                        break;
                    };
                    if (!self.running) break;
                    if (n == 0) {
                        log.info("daemon closed connection", .{});
                        self.running = false;
                        break;
                    }

                    while (self.unix_read_buf.next()) |msg| {
                        try self.forwardDaemonMessage(msg.header.tag, msg.payload, now);
                    }
                }
            }

            // Flush buffered writes to Unix socket
            if (poll_fds[1].revents & posix.POLL.OUT != 0) {
                if (self.unix_write_buf.items.len > 0) {
                    const written = posix.write(self.unix_fd, self.unix_write_buf.items) catch |err| blk: {
                        if (err == error.WouldBlock) break :blk @as(usize, 0);
                        log.warn("unix write error: {s}", .{@errorName(err)});
                        self.running = false;
                        break :blk @as(usize, 0);
                    };
                    if (written > 0) {
                        self.unix_write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
                    }
                }
            }

            if (poll_fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                log.info("unix socket closed/error", .{});
                break;
            }
        }

        // Notify client that the session has ended.
        if (self.peer.addr != null) {
            const shutdown_now: i64 = @intCast(std.time.nanoTimestamp());
            self.flushOutput(shutdown_now, true) catch |err| {
                log.debug("failed to flush output during shutdown: {s}", .{@errorName(err)});
            };
            self.sendIpcReliable(.SessionEnd, "", shutdown_now) catch |err| {
                log.debug("failed to send SessionEnd: {s}", .{@errorName(err)});
            };
            self.drainUdpShutdown(shutdown_now) catch |err| {
                log.debug("failed to drain UDP shutdown: {s}", .{@errorName(err)});
            };
        }
    }

    fn sendStunKeepalive(self: *Gateway, now: i64) !void {
        if (self.stun_servers.items.len == 0) return;
        const idx = self.stun_server_idx % self.stun_servers.items.len;
        const server = self.stun_servers.items[idx];
        self.stun_server_idx = (idx + 1) % self.stun_servers.items.len;
        self.stun_state = nat.StunState.init(server);
        try self.stun_state.?.sendRequest(&self.udp_sock);
        self.last_stun_keepalive_ns = now;
    }

    fn sendStandbyCandidateRefresh(self: *Gateway, srflx_addr: std.net.Address) !void {
        if (self.standby_ssh == null) return;

        var refreshed = try nat.gatherHostCandidates(self.alloc, self.udp_sock.bound_port, self.socket_family, 8);
        defer refreshed.deinit(self.alloc);
        try appendUniqueCandidate(&refreshed, self.alloc, .{
            .ctype = .srflx,
            .addr = srflx_addr,
            .source = "stun",
        }, 8);
        nat.sortCandidatesByPriority(refreshed.items);

        sendCandidates(self.standby_ssh.?.write_fd, self.alloc, refreshed.items) catch |err| {
            self.standby_ssh.?.deinit(self.alloc, true);
            self.standby_ssh = null;
            return err;
        };
    }

    fn handleStunDatagram(self: *Gateway, from: std.net.Address, data: []const u8) bool {
        const state = &(self.stun_state orelse return false);
        if (!state.waiting_response) return false;
        if (!nat.isStunPacket(state.server_addr, from, data)) return false;

        const parsed = state.handleResponse(data) catch return true;
        if (parsed) |candidate| {
            const mapping_changed = if (self.last_srflx) |old|
                !nat.isAddressEqual(old, candidate.addr)
            else
                false;

            if (mapping_changed) {
                log.warn("stun mapping changed old={f} new={f}", .{ self.last_srflx.?, candidate.addr });
                self.sendStandbyCandidateRefresh(candidate.addr) catch |err| {
                    log.warn("failed to send refreshed standby candidates: {s}", .{@errorName(err)});
                };
            }
            self.last_srflx = candidate.addr;
        }
        if (!state.waiting_response) {
            self.stun_state = null;
        }
        return true;
    }

    fn handleStandbyCandidateRefresh(self: *Gateway, candidates: []const nat.Candidate, now: i64) !void {
        self.peer.enterRecoveryMode(now);

        var filtered = try std.ArrayList(nat.Candidate).initCapacity(self.alloc, candidates.len);
        defer filtered.deinit(self.alloc);
        for (candidates) |candidate| {
            if (!nat.shouldUseCandidate(self.socket_family, candidate.addr)) continue;
            if (!nat.isCandidateAddressUsable(candidate.addr)) continue;
            try appendUniqueCandidate(&filtered, self.alloc, candidate, 8);
        }
        nat.sortCandidatesByPriority(filtered.items);

        for (filtered.items) |candidate| {
            var burst: u8 = 0;
            while (burst < standby_candidate_probe_burst) : (burst += 1) {
                sendProbeHeartbeatTo(&self.peer, &self.udp_sock, candidate.addr, &self.reliable_recv) catch |err| {
                    if (err == error.WouldBlock) return;
                    return err;
                };
            }
        }
    }

    fn handleStandbySshEvents(self: *Gateway, revents: i16) !bool {
        if (self.standby_ssh == null) return false;

        if (revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
            log.info("standby ssh control channel closed", .{});
            self.standby_ssh.?.deinit(self.alloc, true);
            self.standby_ssh = null;
            return false;
        }

        if (revents & posix.POLL.IN == 0) {
            if (revents & posix.POLL.HUP != 0) {
                log.info("standby ssh control channel closed", .{});
                self.standby_ssh.?.deinit(self.alloc, true);
                self.standby_ssh = null;
            }
            return false;
        }

        while (true) {
            var tmp: [256]u8 = undefined;
            const n = posix.read(self.standby_ssh.?.read_fd, &tmp) catch |err| {
                if (err == error.WouldBlock) break;
                log.warn("standby ssh control read failed: {s}", .{@errorName(err)});
                self.standby_ssh.?.deinit(self.alloc, true);
                self.standby_ssh = null;
                return false;
            };
            if (n == 0) {
                log.info("standby ssh control reached EOF", .{});
                self.standby_ssh.?.deinit(self.alloc, true);
                self.standby_ssh = null;
                return false;
            }

            var standby = &self.standby_ssh.?;
            try standby.control_buf.appendSlice(self.alloc, tmp[0..n]);
            if (standby.control_buf.items.len > max_control_line) {
                log.warn("standby ssh control line too long; disabling fallback channel", .{});
                standby.deinit(self.alloc, true);
                self.standby_ssh = null;
                return false;
            }
        }

        while (self.standby_ssh != null) {
            var standby = &self.standby_ssh.?;
            const nl_idx = std.mem.indexOfScalar(u8, standby.control_buf.items, '\n') orelse break;
            const line = std.mem.trimRight(u8, standby.control_buf.items[0..nl_idx], "\r\n");
            var msg = parseStandbyControlLine(self.alloc, line) catch {
                log.warn("invalid standby ssh control message: {s}", .{line});
                try standby.control_buf.replaceRange(self.alloc, 0, nl_idx + 1, &[_]u8{});
                continue;
            };
            defer msg.deinit(self.alloc);
            try standby.control_buf.replaceRange(self.alloc, 0, nl_idx + 1, &[_]u8{});

            switch (msg) {
                .use => |mode| {
                    if (mode == .ssh) {
                        sendUseAck(standby.write_fd, "ssh") catch {
                            standby.deinit(self.alloc, true);
                            self.standby_ssh = null;
                            return false;
                        };
                        try self.promoteStandbyToSsh();
                        return true;
                    }
                },
                .candidates => |candidates| {
                    self.handleStandbyCandidateRefresh(candidates.items, @intCast(std.time.nanoTimestamp())) catch |err| {
                        log.warn("standby candidate refresh failed: {s}", .{@errorName(err)});
                    };
                },
            }
        }

        if (self.standby_ssh != null and revents & posix.POLL.HUP != 0) {
            log.info("standby ssh control channel reached EOF", .{});
            self.standby_ssh.?.deinit(self.alloc, true);
            self.standby_ssh = null;
        }

        return false;
    }

    fn promoteStandbyToSsh(self: *Gateway) !void {
        var standby = self.standby_ssh orelse return error.NoStandbySsh;
        self.standby_ssh = null;

        var close_fds = true;
        defer standby.deinit(self.alloc, close_fds);

        var read_buf = try ipc.SocketBuffer.init(self.alloc);
        errdefer read_buf.deinit();
        if (standby.control_buf.items.len > 0) {
            try read_buf.buf.appendSlice(read_buf.alloc, standby.control_buf.items);
        }

        var write_buf = try std.ArrayList(u8).initCapacity(self.alloc, 4096);
        errdefer write_buf.deinit(self.alloc);

        self.transport = .{ .ssh = .{
            .read_fd = standby.read_fd,
            .write_fd = standby.write_fd,
            .read_buf = read_buf,
            .write_buf = write_buf,
        } };
        self.snapshot_in_flight_id = null;
        self.ssh_baseline_snapshot_id = null;
        self.ssh_baseline_pending = true;
        self.last_resync_request_ns = 0;

        var pending_replay = try self.reliable_send.collectPendingReliableFrames(self.alloc);
        defer pending_replay.deinit(self.alloc);
        for (pending_replay.items) |pending| {
            const replay_payload = try buildSshPromotionReplayPayload(self.alloc, pending.channel, pending.payload) orelse continue;
            defer self.alloc.free(replay_payload);
            try ipc.appendReliableReplay(self.alloc, &self.transport.ssh.write_buf, pending.seq, @intFromEnum(pending.channel), replay_payload);
        }
        self.reliable_send.clearPending();

        if (self.output_coalesce_buf.items.len > 0) {
            // SSH promotion always triggers a fresh snapshot request from the client,
            // so replaying buffered UDP output here risks duplicating state against it.
            self.output_coalesce_buf.clearRetainingCapacity();
        }

        close_fds = false;
    }

    fn runSsh(self: *Gateway) !void {
        var ssh = &self.transport.ssh;
        var ssh_read_eof = false;
        var ssh_write_closed = false;
        var daemon_eof = false;

        while (self.running) {
            if (sigterm_received.swap(false, .acq_rel)) {
                log.info("SIGTERM received, shutting down gateway", .{});
                break;
            }

            var poll_fds: [3]posix.pollfd = undefined;
            var poll_count: usize = 2;

            poll_fds[0] = .{ .fd = ssh.read_fd, .events = if (ssh_read_eof) 0 else posix.POLL.IN, .revents = 0 };

            var unix_events: i16 = if (daemon_eof) 0 else posix.POLL.IN;
            if (!daemon_eof and self.unix_write_buf.items.len > 0) unix_events |= posix.POLL.OUT;
            poll_fds[1] = .{ .fd = self.unix_fd, .events = unix_events, .revents = 0 };

            var ssh_write_idx: ?usize = null;
            if (!ssh_write_closed and ssh.write_buf.items.len > 0) {
                ssh_write_idx = poll_count;
                poll_fds[poll_count] = .{ .fd = ssh.write_fd, .events = posix.POLL.OUT, .revents = 0 };
                poll_count += 1;
            }

            _ = posix.poll(poll_fds[0..poll_count], 250) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };

            const ssh_read_revents = poll_fds[0].revents;
            const unix_revents = poll_fds[1].revents;
            var ssh_write_revents: i16 = 0;

            if (!ssh_read_eof and ssh_read_revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                self.running = false;
            }
            if (!daemon_eof and unix_revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                self.running = false;
            }
            if (ssh_write_idx) |idx| {
                ssh_write_revents = poll_fds[idx].revents;
                if (ssh_write_revents & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                    ssh_write_closed = true;
                    ssh.write_buf.clearRetainingCapacity();
                }
            }
            if (!self.running) break;

            try self.drainBufferedSshMessages();
            if (!self.running) break;

            if (!ssh_read_eof and poll_fds[0].revents & posix.POLL.IN != 0) {
                while (true) {
                    const n = ssh.read_buf.read(ssh.read_fd) catch |err| {
                        if (err == error.WouldBlock) break;
                        self.running = false;
                        break;
                    };
                    if (!self.running) break;
                    if (n == 0) {
                        ssh_read_eof = true;
                        break;
                    }

                    try self.drainBufferedSshMessages();
                    if (!self.running) break;
                }
            }

            if (!ssh_write_closed) {
                if (ssh_write_idx) |idx| {
                    if (poll_fds[idx].revents & posix.POLL.OUT != 0) {
                        const written = posix.write(ssh.write_fd, ssh.write_buf.items) catch |err| blk: {
                            if (err == error.WouldBlock) break :blk @as(usize, 0);
                            ssh_write_closed = true;
                            ssh.write_buf.clearRetainingCapacity();
                            break :blk @as(usize, 0);
                        };
                        if (written > 0) {
                            ssh.write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
                        }
                    }
                }
            }

            if (!daemon_eof and poll_fds[1].revents & posix.POLL.IN != 0) {
                while (true) {
                    const n = self.unix_read_buf.read(self.unix_fd) catch |err| {
                        if (err == error.WouldBlock) break;
                        self.running = false;
                        break;
                    };
                    if (!self.running) break;
                    if (n == 0) {
                        daemon_eof = true;
                        self.unix_write_buf.clearRetainingCapacity();
                        break;
                    }

                    while (self.unix_read_buf.next()) |msg| {
                        if (self.ssh_baseline_pending) {
                            if (msg.header.tag == .Output) {
                                continue;
                            }
                            if (msg.header.tag == .Snapshot) {
                                const expected_snapshot_id = self.ssh_baseline_snapshot_id orelse continue;
                                if (msg.payload.len < @sizeOf(ipc.Snapshot)) continue;
                                const snapshot = std.mem.bytesToValue(ipc.Snapshot, msg.payload[0..@sizeOf(ipc.Snapshot)]);
                                if (snapshot.id != expected_snapshot_id) continue;
                                if (snapshot.isFinal()) {
                                    self.ssh_baseline_snapshot_id = null;
                                    self.ssh_baseline_pending = false;
                                }
                            }
                        }

                        self.appendSshMessage(msg.header.tag, msg.payload) catch |err| {
                            log.warn("ssh write buffer overflow: {s}", .{@errorName(err)});
                            self.running = false;
                            break;
                        };
                    }
                    if (!self.running) break;
                }
            }

            if (!daemon_eof and poll_fds[1].revents & posix.POLL.OUT != 0 and self.unix_write_buf.items.len > 0) {
                const written = posix.write(self.unix_fd, self.unix_write_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk @as(usize, 0);
                    self.running = false;
                    break :blk @as(usize, 0);
                };
                if (written > 0) {
                    self.unix_write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
                }
            }

            if (!ssh_read_eof and ssh_read_revents & posix.POLL.HUP != 0 and ssh_read_revents & posix.POLL.IN == 0) {
                ssh_read_eof = true;
            }
            if (!daemon_eof and unix_revents & posix.POLL.HUP != 0 and unix_revents & posix.POLL.IN == 0) {
                daemon_eof = true;
                self.unix_write_buf.clearRetainingCapacity();
            }
            if (ssh_write_revents & posix.POLL.HUP != 0) {
                ssh_write_closed = true;
                ssh.write_buf.clearRetainingCapacity();
            }

            if ((daemon_eof and ssh.write_buf.items.len == 0) or ssh_write_closed) {
                break;
            }
        }

        if (!ssh_write_closed and ssh.write_buf.items.len > 0) {
            writeAllFd(ssh.write_fd, ssh.write_buf.items) catch {};
        }
    }

    fn drainBufferedSshMessages(self: *Gateway) !void {
        var ssh = &self.transport.ssh;
        while (ssh.read_buf.next()) |msg| {
            if (msg.header.tag == .ReliableReplay) {
                const replay = ipc.parseReliableReplay(msg.payload) catch continue;
                const channel = std.meta.intToEnum(transport.Channel, replay.channel) catch continue;
                if (!self.reliable_inbox.accepts(replay.seq)) continue;
                if (self.reliable_recv.onReliable(replay.seq) != .accept) continue;
                try self.reliable_inbox.push(replay.seq, channel, replay.payload);
                while (self.reliable_inbox.popReady()) |delivery| {
                    defer delivery.deinit(self.alloc);
                    switch (delivery.channel) {
                        .control => {
                            const ctrl = transport.parseControl(delivery.payload) catch continue;
                            self.handleReliableControl(ctrl) catch |err| {
                                log.warn("failed to handle replayed control message: {s}", .{@errorName(err)});
                                self.running = false;
                                break;
                            };
                        },
                        .reliable_ipc => {
                            self.trackClientResize(delivery.payload);
                            self.appendUnixWrite(delivery.payload) catch |err| {
                                log.warn("unix write buffer overflow: {s}", .{@errorName(err)});
                                self.running = false;
                                break;
                            };
                        },
                        else => unreachable,
                    }
                }
                continue;
            }

            if (msg.header.tag == .Init and msg.payload.len == @sizeOf(ipc.Init)) {
                const init_msg = std.mem.bytesToValue(ipc.Init, msg.payload);
                self.last_resize = .{ .rows = init_msg.rows, .cols = init_msg.cols };
                self.have_client_size = true;
                self.ssh_baseline_snapshot_id = init_msg.snapshot_id;
                self.ssh_baseline_pending = true;
            } else if (msg.header.tag == .Resize and msg.payload.len == @sizeOf(ipc.Resize)) {
                self.last_resize = std.mem.bytesToValue(ipc.Resize, msg.payload);
                self.have_client_size = true;
            }
            self.appendUnixMessage(msg.header.tag, msg.payload) catch |err| {
                log.warn("unix write buffer overflow: {s}", .{@errorName(err)});
                self.running = false;
                break;
            };
        }
    }

    fn computePollTimeoutMs(self: *Gateway, now: i64) i32 {
        var timeout: i64 = @min(@as(i64, self.config.heartbeat_interval_ms), 1000);

        if (self.output_coalesce_buf.items.len > 0) {
            const flush_due = self.last_output_flush_ns + self.outputFlushIntervalNs();
            const remaining_ns = flush_due - now;
            const remaining_ms = if (remaining_ns <= 0) 0 else @divFloor(remaining_ns, std.time.ns_per_ms);
            timeout = @min(timeout, remaining_ms);
        }

        if (self.reliable_send.hasPending()) {
            const rto_ms = @divFloor(self.peer.rto_us(), 1000);
            timeout = @min(timeout, @max(@as(i64, 1), rto_ms));
        }

        const heartbeat_ms = @divFloor(self.peer.heartbeatDelayNs(now, self.config), std.time.ns_per_ms);
        timeout = @min(timeout, heartbeat_ms);

        if (self.ack_dirty) timeout = @min(timeout, @as(i64, 20));

        return @intCast(@max(@as(i64, 0), timeout));
    }

    fn drainUdpShutdown(self: *Gateway, started_ns: i64) !void {
        if (!self.reliable_send.hasPending()) return;

        const deadline_ns = started_ns + shutdown_drain_ns;
        while (self.reliable_send.hasPending()) {
            const now: i64 = @intCast(std.time.nanoTimestamp());
            if (now >= deadline_ns) break;

            try self.flushRetransmits(now);
            if (self.ack_dirty and (now - self.last_ack_send_ns >= ack_delay_ns)) {
                self.sendHeartbeat(now) catch |err| {
                    if (err != error.NoPeerAddress and err != error.WouldBlock) return err;
                };
            }

            const remaining_ms = @max(@as(i64, 1), @divFloor(deadline_ns - now, std.time.ns_per_ms));
            const rto_ms = @max(@as(i64, 1), @divFloor(self.peer.rto_us(), 1000));
            const poll_timeout: i32 = @intCast(@min(remaining_ms, rto_ms));
            var poll_fds = [_]posix.pollfd{.{ .fd = self.udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 }};
            _ = posix.poll(&poll_fds, poll_timeout) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };

            if (poll_fds[0].revents & posix.POLL.IN == 0) continue;
            while (true) {
                var raw_buf: [9000]u8 = undefined;
                const raw = try self.udp_sock.recvRaw(&raw_buf) orelse break;

                if (self.handleStunDatagram(raw.from, raw.data)) continue;

                var decrypt_buf: [9000]u8 = undefined;
                const decoded = try self.peer.decodeAndUpdate(raw.data, raw.from, &decrypt_buf) orelse continue;
                try self.handleTransportPacket(decoded, now);
            }
        }
    }

    fn outputFlushIntervalNs(self: *const Gateway) i64 {
        const srtt_us = self.peer.srtt_us orelse 32_000;
        const paced_us = std.math.clamp(@divFloor(srtt_us, 8), @as(i64, 2_000), @as(i64, 8_000));
        return paced_us * std.time.ns_per_us;
    }

    fn sendHeartbeat(self: *Gateway, now: i64) !void {
        var pkt_buf: [1200]u8 = undefined;
        const pkt = try transport.buildUnreliable(
            .heartbeat,
            0,
            self.reliable_recv.ack(),
            self.reliable_recv.ackBits(),
            "",
            &pkt_buf,
        );
        try self.peer.send(&self.udp_sock, pkt);
        self.last_ack_send_ns = now;
        self.ack_dirty = false;
    }

    fn flushRetransmits(self: *Gateway, now: i64) !void {
        var packets = try self.reliable_send.collectRetransmits(self.alloc, now, self.peer.rto_us());
        defer packets.deinit(self.alloc);

        for (packets.items) |packet| {
            self.peer.send(&self.udp_sock, packet) catch |err| {
                if (err == error.NoPeerAddress or err == error.WouldBlock) continue;
                return err;
            };
        }
    }

    fn flushOutput(self: *Gateway, now: i64, force: bool) !void {
        if (self.output_coalesce_buf.items.len == 0) return;
        if (!force and (now - self.last_output_flush_ns) < self.outputFlushIntervalNs()) return;

        if (self.peer.addr == null) {
            self.output_coalesce_buf.clearRetainingCapacity();
            self.last_output_flush_ns = now;
            return;
        }

        var sent_off: usize = 0;
        while (sent_off < self.output_coalesce_buf.items.len) {
            const max_chunk_len = transport.max_payload_len - @sizeOf(transport.OutputPrefix);
            const end = @min(sent_off + max_chunk_len, self.output_coalesce_buf.items.len);

            var pkt_buf: [1200]u8 = undefined;
            const prefix = transport.OutputPrefix{ .epoch = self.output_epoch };
            @memcpy(pkt_buf[0..@sizeOf(transport.OutputPrefix)], std.mem.asBytes(&prefix));
            @memcpy(pkt_buf[@sizeOf(transport.OutputPrefix) .. @sizeOf(transport.OutputPrefix) + (end - sent_off)], self.output_coalesce_buf.items[sent_off..end]);
            const chunk = pkt_buf[0 .. @sizeOf(transport.OutputPrefix) + (end - sent_off)];
            const seq = self.output_seq;
            self.output_seq +%= 1;
            const pkt = try transport.buildUnreliable(
                .output,
                seq,
                self.reliable_recv.ack(),
                self.reliable_recv.ackBits(),
                chunk,
                &pkt_buf,
            );

            self.peer.send(&self.udp_sock, pkt) catch |err| {
                if (err == error.WouldBlock) {
                    log.debug("udp output send would block; dropping stale output and requesting resync", .{});
                    self.output_coalesce_buf.clearRetainingCapacity();
                    try self.requestSnapshot(now);
                    self.last_output_flush_ns = now;
                    return;
                }
                if (err == error.NoPeerAddress) {
                    self.output_coalesce_buf.clearRetainingCapacity();
                    self.last_output_flush_ns = now;
                    return;
                }
                return err;
            };

            sent_off = end;
        }

        if (sent_off > 0) {
            self.output_coalesce_buf.replaceRange(self.alloc, 0, sent_off, &[_]u8{}) catch unreachable;
        }

        self.last_output_flush_ns = now;
    }

    fn trackClientResize(self: *Gateway, payload: []const u8) void {
        var offset: usize = 0;
        while (offset < payload.len) {
            const remaining = payload[offset..];
            const msg_len = ipc.expectedLength(remaining) orelse break;
            if (remaining.len < msg_len) break;

            const hdr = std.mem.bytesToValue(ipc.Header, remaining[0..@sizeOf(ipc.Header)]);
            const msg_payload = remaining[@sizeOf(ipc.Header)..msg_len];
            if (hdr.tag == .Init and msg_payload.len == @sizeOf(ipc.Init)) {
                const init_msg = std.mem.bytesToValue(ipc.Init, msg_payload);
                self.last_resize = .{ .rows = init_msg.rows, .cols = init_msg.cols };
                self.have_client_size = true;
            } else if (hdr.tag == .Resize and msg_payload.len == @sizeOf(ipc.Resize)) {
                self.last_resize = std.mem.bytesToValue(ipc.Resize, msg_payload);
                self.have_client_size = true;
            }

            offset += msg_len;
        }
    }

    fn appendUnixWrite(self: *Gateway, payload: []const u8) !void {
        if (self.unix_write_buf.items.len + payload.len > max_unix_write_buf) {
            return error.UnixWriteBackpressure;
        }
        try self.unix_write_buf.appendSlice(self.alloc, payload);
    }

    fn appendUnixMessage(self: *Gateway, tag: ipc.Tag, payload: []const u8) !void {
        if (self.unix_write_buf.items.len + @sizeOf(ipc.Header) + payload.len > max_unix_write_buf) {
            return error.UnixWriteBackpressure;
        }
        try ipc.appendMessage(self.alloc, &self.unix_write_buf, tag, payload);
    }

    fn appendSshMessage(self: *Gateway, tag: ipc.Tag, payload: []const u8) !void {
        if (self.transport != .ssh) return error.InvalidTransportMode;
        if (tag == .Snapshot) {
            if (payload.len < @sizeOf(ipc.Snapshot)) return;

            const snapshot = std.mem.bytesToValue(ipc.Snapshot, payload[0..@sizeOf(ipc.Snapshot)]);
            const snapshot_data = payload[@sizeOf(ipc.Snapshot)..];
            const max_chunk_payload = (max_unix_write_buf - @sizeOf(ipc.Header)) - @sizeOf(ipc.Snapshot);

            if (snapshot_data.len == 0) {
                const chunk_snapshot = ipc.Snapshot{ .id = snapshot.id, .flags = 0x1 };
                try self.ensureSshWriteCapacity(@sizeOf(ipc.Header) + @sizeOf(ipc.Snapshot));
                try ipc.appendMessage(self.alloc, &self.transport.ssh.write_buf, .Snapshot, std.mem.asBytes(&chunk_snapshot));
                return;
            }

            var off: usize = 0;
            while (off < snapshot_data.len) {
                const end = @min(off + max_chunk_payload, snapshot_data.len);
                const chunk_snapshot = ipc.Snapshot{
                    .id = snapshot.id,
                    .flags = if (end == snapshot_data.len) 0x1 else 0,
                };
                const chunk_len = @sizeOf(ipc.Snapshot) + (end - off);
                const chunk_payload = try self.alloc.alloc(u8, chunk_len);
                defer self.alloc.free(chunk_payload);
                @memcpy(chunk_payload[0..@sizeOf(ipc.Snapshot)], std.mem.asBytes(&chunk_snapshot));
                @memcpy(chunk_payload[@sizeOf(ipc.Snapshot)..], snapshot_data[off..end]);
                try self.ensureSshWriteCapacity(@sizeOf(ipc.Header) + chunk_payload.len);
                try ipc.appendMessage(self.alloc, &self.transport.ssh.write_buf, .Snapshot, chunk_payload);
                off = end;
            }
            return;
        }

        try self.ensureSshWriteCapacity(@sizeOf(ipc.Header) + payload.len);
        try ipc.appendMessage(self.alloc, &self.transport.ssh.write_buf, tag, payload);
    }

    fn ensureSshWriteCapacity(self: *Gateway, needed: usize) !void {
        if (self.transport != .ssh) return error.InvalidTransportMode;
        if (needed > max_unix_write_buf) return error.SshWriteBackpressure;

        while (self.transport.ssh.write_buf.items.len + needed > max_unix_write_buf) {
            try self.flushQueuedSshWrites();
            if (self.transport.ssh.write_buf.items.len + needed <= max_unix_write_buf) return;

            var fds = [_]posix.pollfd{.{ .fd = self.transport.ssh.write_fd, .events = posix.POLL.OUT, .revents = 0 }};
            _ = posix.poll(&fds, 250) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };
            if (fds[0].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                return error.SshWriteBackpressure;
            }
            if (fds[0].revents & posix.POLL.OUT == 0) {
                return error.SshWriteBackpressure;
            }
            try self.flushQueuedSshWrites();
        }
    }

    fn flushQueuedSshWrites(self: *Gateway) !void {
        if (self.transport != .ssh) return error.InvalidTransportMode;
        while (self.transport.ssh.write_buf.items.len > 0) {
            const written = posix.write(self.transport.ssh.write_fd, self.transport.ssh.write_buf.items) catch |err| {
                if (err == error.WouldBlock) return;
                return err;
            };
            if (written == 0) return error.SshWriteBackpressure;
            self.transport.ssh.write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
        }
    }

    fn requestSnapshot(self: *Gateway, now: i64) !void {
        if ((now - self.last_resync_request_ns) < resync_cooldown_ns) return;
        self.last_resync_request_ns = now;
        self.snapshot_id +%= 1;
        self.snapshot_in_flight_id = self.snapshot_id;
        self.output_epoch = self.snapshot_id;
        self.output_coalesce_buf.clearRetainingCapacity();

        const size = if (self.have_client_size) self.last_resize else ipc.Resize{ .rows = 24, .cols = 80 };
        var init_buf: [64]u8 = undefined;
        const init_msg = ipc.Init{ .rows = size.rows, .cols = size.cols, .snapshot_id = self.snapshot_id };
        const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&init_msg), &init_buf);
        try self.appendUnixWrite(init_ipc);
        log.debug("requested terminal snapshot id={d} rows={d} cols={d}", .{ self.snapshot_id, size.rows, size.cols });
    }

    fn handleReliableControl(self: *Gateway, ctrl: transport.Control) !void {
        if (ctrl == .resync_request) {
            try self.requestSnapshot(@intCast(std.time.nanoTimestamp()));
        }
    }

    fn handleTransportPacket(self: *Gateway, plaintext: []const u8, now: i64) !void {
        _ = now;
        const packet = transport.parsePacket(plaintext) catch |err| {
            log.debug("transport parse failed: {s}", .{@errorName(err)});
            return;
        };

        if (self.reliable_send.ack(packet.ack, packet.ack_bits)) |rtt_us| {
            self.peer.reportRtt(rtt_us);
        }

        switch (packet.channel) {
            .heartbeat => {},
            .output => {
                // Client never sends output channel packets.
            },
            .reliable_ipc, .control => {
                self.ack_dirty = true;
                if (!self.reliable_inbox.accepts(packet.seq)) return;
                const action = self.reliable_recv.onReliable(packet.seq);
                if (action != .accept) return;

                try self.reliable_inbox.push(packet.seq, packet.channel, packet.payload);

                while (self.reliable_inbox.popReady()) |delivery| {
                    defer delivery.deinit(self.alloc);

                    if (delivery.channel == .reliable_ipc) {
                        self.trackClientResize(delivery.payload);
                        self.appendUnixWrite(delivery.payload) catch |err| {
                            log.warn("unix write buffer overflow: {s}", .{@errorName(err)});
                            self.running = false;
                            return;
                        };
                    } else {
                        const ctrl = transport.parseControl(delivery.payload) catch continue;
                        self.handleReliableControl(ctrl) catch |err| {
                            log.warn("failed to queue snapshot request: {s}", .{@errorName(err)});
                            self.running = false;
                        };
                    }
                }
            },
        }
    }

    fn sendReliablePayload(self: *Gateway, channel: transport.Channel, payload: []const u8, now: i64) !void {
        const packet = try self.reliable_send.buildAndTrack(
            channel,
            payload,
            self.reliable_recv.ack(),
            self.reliable_recv.ackBits(),
            now,
        );
        self.peer.send(&self.udp_sock, packet) catch |err| {
            if (err == error.NoPeerAddress or err == error.WouldBlock) return;
            return err;
        };
    }

    fn sendIpcReliable(self: *Gateway, tag: ipc.Tag, payload: []const u8, now: i64) !void {
        if (payload.len <= max_ipc_payload) {
            var buf: [transport.max_payload_len]u8 = undefined;
            const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
            try self.sendReliablePayload(.reliable_ipc, ipc_bytes, now);
            return;
        }

        var off: usize = 0;
        while (off < payload.len) {
            const end = @min(off + max_ipc_payload, payload.len);
            var buf: [transport.max_payload_len]u8 = undefined;
            const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
            try self.sendReliablePayload(.reliable_ipc, ipc_bytes, now);
            off = end;
        }
    }

    fn sendSnapshotReliable(self: *Gateway, payload: []const u8, now: i64) !void {
        if (payload.len < @sizeOf(ipc.Snapshot)) return;

        const snapshot = std.mem.bytesToValue(ipc.Snapshot, payload[0..@sizeOf(ipc.Snapshot)]);
        const snapshot_data = payload[@sizeOf(ipc.Snapshot)..];
        const max_chunk_payload = max_ipc_payload - @sizeOf(ipc.Snapshot);

        if (snapshot_data.len == 0) {
            var wire_buf: [transport.max_payload_len]u8 = undefined;
            const chunk_snapshot = ipc.Snapshot{ .id = snapshot.id, .flags = 0x1 };
            const ipc_bytes = transport.buildIpcBytes(.Snapshot, std.mem.asBytes(&chunk_snapshot), &wire_buf);
            try self.sendReliablePayload(.reliable_ipc, ipc_bytes, now);
            return;
        }

        var off: usize = 0;
        while (off < snapshot_data.len) {
            const end = @min(off + max_chunk_payload, snapshot_data.len);
            const chunk_snapshot = ipc.Snapshot{
                .id = snapshot.id,
                .flags = if (end == snapshot_data.len) 0x1 else 0,
            };
            var chunk_buf: [max_ipc_payload]u8 = undefined;
            @memcpy(chunk_buf[0..@sizeOf(ipc.Snapshot)], std.mem.asBytes(&chunk_snapshot));
            @memcpy(chunk_buf[@sizeOf(ipc.Snapshot) .. @sizeOf(ipc.Snapshot) + (end - off)], snapshot_data[off..end]);
            const chunk = chunk_buf[0 .. @sizeOf(ipc.Snapshot) + (end - off)];

            var wire_buf: [transport.max_payload_len]u8 = undefined;
            const ipc_bytes = transport.buildIpcBytes(.Snapshot, chunk, &wire_buf);
            try self.sendReliablePayload(.reliable_ipc, ipc_bytes, now);
            off = end;
        }
    }

    fn forwardDaemonMessage(self: *Gateway, tag: ipc.Tag, payload: []const u8, now: i64) !void {
        if (tag == .Output) {
            if (self.snapshot_in_flight_id != null) {
                return;
            }
            if (self.output_coalesce_buf.items.len + payload.len > max_output_coalesce) {
                log.debug("output coalesce buffer overflow; dropping stale output and requesting snapshot", .{});
                self.output_coalesce_buf.clearRetainingCapacity();
                try self.requestSnapshot(now);
                return;
            }
            try self.output_coalesce_buf.appendSlice(self.alloc, payload);
            if (self.output_coalesce_buf.items.len >= transport.max_payload_len * 4) {
                try self.flushOutput(now, true);
            }
            return;
        }

        if (tag == .Snapshot) {
            if (payload.len < @sizeOf(ipc.Snapshot)) return;
            const snapshot = std.mem.bytesToValue(ipc.Snapshot, payload[0..@sizeOf(ipc.Snapshot)]);
            if (self.snapshot_in_flight_id) |pending_id| {
                if (snapshot.id < pending_id) return;
            }
            try self.flushOutput(now, true);
            try self.sendSnapshotReliable(payload, now);
            self.snapshot_in_flight_id = null;
            return;
        }

        try self.flushOutput(now, true);
        try self.sendIpcReliable(tag, payload, now);
    }

    pub fn deinit(self: *Gateway) void {
        posix.close(self.unix_fd);
        self.udp_sock.close();
        if (self.standby_ssh) |*standby| {
            standby.deinit(self.alloc, true);
            self.standby_ssh = null;
        }
        self.unix_read_buf.deinit();
        self.unix_write_buf.deinit(self.alloc);
        self.output_coalesce_buf.deinit(self.alloc);
        self.reliable_inbox.deinit();
        self.reliable_send.deinit();
        self.transport.deinit(self.alloc);
        self.stun_servers.deinit(self.alloc);
    }
};

/// Entry point for `zmx serve <session>`.
pub fn serveMain(alloc: std.mem.Allocator, session_name: []const u8) !void {
    var gw = try Gateway.init(alloc, session_name, .{});
    defer gw.deinit();
    try gw.run();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "bootstrap output format" {
    const key = crypto.generateKey();
    const encoded = crypto.keyToBase64(key);
    const port: u16 = 60042;

    var buf: [256]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, "ZMX_CONNECT udp {d} {s}\n", .{ port, encoded });

    // Verify it starts with the expected prefix
    try std.testing.expect(std.mem.startsWith(u8, line, "ZMX_CONNECT udp "));

    // Parse back
    var it = std.mem.splitScalar(u8, std.mem.trimRight(u8, line, "\n"), ' ');
    try std.testing.expectEqualStrings("ZMX_CONNECT", it.next().?);
    try std.testing.expectEqualStrings("udp", it.next().?);
    const port_str = it.next().?;
    const parsed_port = try std.fmt.parseInt(u16, port_str, 10);
    try std.testing.expect(parsed_port == 60042);
    const key_str = it.next().?;
    const decoded_key = try crypto.keyFromBase64(key_str);
    try std.testing.expectEqual(key, decoded_key);
}

test "resolveSocketDir returns valid path" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const dir = try resolveSocketDir(alloc);
    defer alloc.free(dir);
    try std.testing.expect(dir.len > 0);
    try std.testing.expect(std.mem.indexOf(u8, dir, "zmx") != null);
}

test "standby control parser accepts use messages" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var msg = try parseStandbyControlLine(alloc, "ZMX_USE ssh");
    defer msg.deinit(alloc);

    switch (msg) {
        .use => |mode| try std.testing.expect(mode == .ssh),
        .candidates => try std.testing.expect(false),
    }
}

test "standby control parser accepts candidate refresh messages" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var msg = try parseStandbyControlLine(
        alloc,
        "ZMX_CANDIDATES2 {\"candidates\":[{\"ctype\":\"host\",\"endpoint\":\"203.0.113.10:60000\",\"source\":\"ifaddr\"}]}",
    );
    defer msg.deinit(alloc);

    switch (msg) {
        .use => try std.testing.expect(false),
        .candidates => |list| {
            try std.testing.expectEqual(@as(usize, 1), list.items.len);
            try std.testing.expect(list.items[0].ctype == .host);
            try std.testing.expectEqual(@as(u16, 60000), list.items[0].addr.getPort());
        },
    }
}

test "stun datagrams are ignored without active stun state" {
    var gateway: Gateway = undefined;
    gateway.stun_state = null;
    gateway.last_srflx = null;

    const from = std.net.Address.initIp4(.{ 1, 2, 3, 4 }, 3478);
    var pkt: [20]u8 = [_]u8{0} ** 20;
    std.mem.writeInt(u32, pkt[4..8], nat.stun_magic_cookie, .big);

    try std.testing.expect(!gateway.handleStunDatagram(from, &pkt));
}

test "ssh promotion replay drops stale snapshots but preserves later reliable IPC" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var payload = try std.ArrayList(u8).initCapacity(alloc, 48);
    defer payload.deinit(alloc);

    const snapshot = ipc.Snapshot{ .id = 5, .flags = 0x1 };
    try ipc.appendMessage(alloc, &payload, .Snapshot, std.mem.asBytes(&snapshot));
    try ipc.appendMessage(alloc, &payload, .SessionEnd, "");

    const replay = (try buildSshPromotionReplayPayload(alloc, .reliable_ipc, payload.items)).?;
    defer alloc.free(replay);

    const msg_len = ipc.expectedLength(replay).?;
    try std.testing.expectEqual(msg_len, replay.len);
    const hdr = std.mem.bytesToValue(ipc.Header, replay[0..@sizeOf(ipc.Header)]);
    try std.testing.expect(hdr.tag == .SessionEnd);
}
