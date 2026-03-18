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
const resync_cooldown_ns = 250 * std.time.ns_per_ms;
const stun_keepalive_ns = 25 * std.time.ns_per_s;
const default_probe_timeout_ms: u32 = 3000;

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

const Candidates2Json = struct {
    candidates: []nat.CandidateWire,
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
    var off: usize = 0;
    while (off < bytes.len) {
        const n = try posix.write(fd, bytes[off..]);
        if (n == 0) return error.WriteFailed;
        off += n;
    }
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

fn sendConnect2(
    fd: i32,
    alloc: std.mem.Allocator,
    key: crypto.Key,
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

fn parseUseLine(line: []const u8) !enum { udp, ssh } {
    if (std.mem.eql(u8, line, "ZMX_USE udp")) return .udp;
    if (std.mem.eql(u8, line, "ZMX_USE ssh")) return .ssh;
    return error.InvalidControlMessage;
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
    peer.last_send_time = now;
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
    output_seq: u32,

    config: udp.Config,
    running: bool,

    last_output_flush_ns: i64,
    last_ack_send_ns: i64,
    ack_dirty: bool,

    last_resync_request_ns: i64,
    have_client_size: bool,
    last_resize: ipc.Resize,
    transport: GatewayTransport,
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
        const bootstrap_v2 = std.mem.eql(u8, posix.getenv("ZMX_BOOTSTRAP") orelse "", "2");

        connectDebug(connect_debug, "bootstrap_v2={} probe_timeout_ms={d} stun_servers={d}", .{
            bootstrap_v2,
            @divFloor(probe_timeout_ns, std.time.ns_per_ms),
            stun_servers.items.len,
        });

        if (bootstrap_v2) {
            var local_candidates = try gatherLocalCandidates(alloc, &udp_sock, socket_family, stun_servers.items);
            defer local_candidates.deinit(alloc);

            try sendConnect2(posix.STDOUT_FILENO, alloc, key, local_candidates.items);

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
                posix.close(posix.STDIN_FILENO);
                posix.close(posix.STDOUT_FILENO);
            } else {
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
            .output_seq = 1,
            .config = config,
            .running = true,
            .last_output_flush_ns = now,
            .last_ack_send_ns = now,
            .ack_dirty = false,
            .last_resync_request_ns = 0,
            .have_client_size = false,
            .last_resize = .{ .rows = 24, .cols = 80 },
            .transport = transport_mode,
            .stun_servers = stun_servers,
            .stun_server_idx = 0,
            .stun_state = null,
            .last_stun_keepalive_ns = now,
            .last_srflx = null,
        };
    }

    pub fn run(self: *Gateway) !void {
        setupSigtermHandler();

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
            var poll_fds: [2]posix.pollfd = undefined;
            poll_fds[0] = .{ .fd = self.udp_sock.getFd(), .events = posix.POLL.IN, .revents = 0 };

            var unix_events: i16 = posix.POLL.IN;
            if (self.unix_write_buf.items.len > 0) {
                unix_events |= posix.POLL.OUT;
            }
            poll_fds[1] = .{ .fd = self.unix_fd, .events = unix_events, .revents = 0 };

            const poll_timeout = self.computePollTimeoutMs(now);
            _ = posix.poll(&poll_fds, poll_timeout) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };

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
            self.sendIpcReliable(.SessionEnd, "", @intCast(std.time.nanoTimestamp())) catch |err| {
                log.debug("failed to send SessionEnd: {s}", .{@errorName(err)});
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

    fn handleStunDatagram(self: *Gateway, from: std.net.Address, data: []const u8) bool {
        if (self.stun_state) |*state| {
            if (!nat.isStunPacket(state.server_addr, from, data)) return false;
            const parsed = state.handleResponse(data) catch return true;
            if (parsed) |candidate| {
                if (self.last_srflx) |old| {
                    if (!nat.isAddressEqual(old, candidate.addr)) {
                        log.warn("stun mapping changed old={f} new={f}", .{ old, candidate.addr });
                    }
                }
                self.last_srflx = candidate.addr;
            }
        }
        return true;
    }

    fn runSsh(self: *Gateway) !void {
        var ssh = &self.transport.ssh;

        while (self.running) {
            if (sigterm_received.swap(false, .acq_rel)) {
                log.info("SIGTERM received, shutting down gateway", .{});
                break;
            }

            var poll_fds: [3]posix.pollfd = undefined;
            var poll_count: usize = 2;

            poll_fds[0] = .{ .fd = ssh.read_fd, .events = posix.POLL.IN, .revents = 0 };

            var unix_events: i16 = posix.POLL.IN;
            if (self.unix_write_buf.items.len > 0) unix_events |= posix.POLL.OUT;
            poll_fds[1] = .{ .fd = self.unix_fd, .events = unix_events, .revents = 0 };

            var ssh_write_idx: ?usize = null;
            if (ssh.write_buf.items.len > 0) {
                ssh_write_idx = poll_count;
                poll_fds[poll_count] = .{ .fd = ssh.write_fd, .events = posix.POLL.OUT, .revents = 0 };
                poll_count += 1;
            }

            _ = posix.poll(poll_fds[0..poll_count], 250) catch |err| {
                if (err == error.Interrupted) continue;
                return err;
            };

            if (poll_fds[0].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                self.running = false;
            }
            if (poll_fds[1].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                self.running = false;
            }
            if (ssh_write_idx) |idx| {
                if (poll_fds[idx].revents & (posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL) != 0) {
                    self.running = false;
                }
            }
            if (!self.running) break;

            if (poll_fds[0].revents & posix.POLL.IN != 0) {
                while (true) {
                    const n = ssh.read_buf.read(ssh.read_fd) catch |err| {
                        if (err == error.WouldBlock) break;
                        self.running = false;
                        break;
                    };
                    if (!self.running) break;
                    if (n == 0) {
                        self.running = false;
                        break;
                    }

                    while (ssh.read_buf.next()) |msg| {
                        if ((msg.header.tag == .Init or msg.header.tag == .Resize) and msg.payload.len == @sizeOf(ipc.Resize)) {
                            self.last_resize = std.mem.bytesToValue(ipc.Resize, msg.payload);
                            self.have_client_size = true;
                        }
                        ipc.appendMessage(self.alloc, &self.unix_write_buf, msg.header.tag, msg.payload) catch |err| {
                            log.warn("unix write buffer overflow: {s}", .{@errorName(err)});
                            self.running = false;
                            break;
                        };
                    }
                    if (!self.running) break;
                }
            }

            if (ssh_write_idx) |idx| {
                if (poll_fds[idx].revents & posix.POLL.OUT != 0) {
                    const written = posix.write(ssh.write_fd, ssh.write_buf.items) catch |err| blk: {
                        if (err == error.WouldBlock) break :blk @as(usize, 0);
                        self.running = false;
                        break :blk @as(usize, 0);
                    };
                    if (written > 0) {
                        ssh.write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
                    }
                }
            }

            if (poll_fds[1].revents & posix.POLL.IN != 0) {
                while (true) {
                    const n = self.unix_read_buf.read(self.unix_fd) catch |err| {
                        if (err == error.WouldBlock) break;
                        self.running = false;
                        break;
                    };
                    if (!self.running) break;
                    if (n == 0) {
                        self.running = false;
                        break;
                    }

                    while (self.unix_read_buf.next()) |msg| {
                        ipc.appendMessage(self.alloc, &ssh.write_buf, msg.header.tag, msg.payload) catch |err| {
                            log.warn("ssh write buffer overflow: {s}", .{@errorName(err)});
                            self.running = false;
                            break;
                        };
                    }
                    if (!self.running) break;
                }
            }

            if (poll_fds[1].revents & posix.POLL.OUT != 0 and self.unix_write_buf.items.len > 0) {
                const written = posix.write(self.unix_fd, self.unix_write_buf.items) catch |err| blk: {
                    if (err == error.WouldBlock) break :blk @as(usize, 0);
                    self.running = false;
                    break :blk @as(usize, 0);
                };
                if (written > 0) {
                    self.unix_write_buf.replaceRange(self.alloc, 0, written, &[_]u8{}) catch unreachable;
                }
            }
        }

        ipc.appendMessage(self.alloc, &ssh.write_buf, .SessionEnd, "") catch {};
        writeAllFd(ssh.write_fd, ssh.write_buf.items) catch {};
    }

    fn computePollTimeoutMs(self: *const Gateway, now: i64) i32 {
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

        if (self.ack_dirty) timeout = @min(timeout, @as(i64, 20));

        return @intCast(@max(@as(i64, 0), timeout));
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
            const end = @min(sent_off + transport.max_payload_len, self.output_coalesce_buf.items.len);
            const chunk = self.output_coalesce_buf.items[sent_off..end];

            var pkt_buf: [1200]u8 = undefined;
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
            if ((hdr.tag == .Init or hdr.tag == .Resize) and msg_payload.len == @sizeOf(ipc.Resize)) {
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

    fn requestSnapshot(self: *Gateway, now: i64) !void {
        if ((now - self.last_resync_request_ns) < resync_cooldown_ns) return;
        self.last_resync_request_ns = now;

        const size = if (self.have_client_size) self.last_resize else ipc.Resize{ .rows = 24, .cols = 80 };
        var init_buf: [64]u8 = undefined;
        const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&size), &init_buf);
        try self.appendUnixWrite(init_ipc);
        log.debug("requested terminal snapshot rows={d} cols={d}", .{ size.rows, size.cols });
    }

    fn handleTransportPacket(self: *Gateway, plaintext: []const u8, now: i64) !void {
        const packet = transport.parsePacket(plaintext) catch |err| {
            log.debug("transport parse failed: {s}", .{@errorName(err)});
            return;
        };

        self.reliable_send.ack(packet.ack, packet.ack_bits);

        switch (packet.channel) {
            .heartbeat => {},
            .output => {
                // Client never sends output channel packets.
            },
            .reliable_ipc, .control => {
                self.ack_dirty = true;
                const action = self.reliable_recv.onReliable(packet.seq);
                if (action != .accept) return;

                if (packet.channel == .reliable_ipc) {
                    self.trackClientResize(packet.payload);
                    self.appendUnixWrite(packet.payload) catch |err| {
                        log.warn("unix write buffer overflow: {s}", .{@errorName(err)});
                        self.running = false;
                        return;
                    };
                } else {
                    const ctrl = transport.parseControl(packet.payload) catch return;
                    if (ctrl == .resync_request) {
                        self.requestSnapshot(now) catch |err| {
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

    fn forwardDaemonMessage(self: *Gateway, tag: ipc.Tag, payload: []const u8, now: i64) !void {
        if (tag == .Output) {
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

        try self.flushOutput(now, true);
        try self.sendIpcReliable(tag, payload, now);
    }

    pub fn deinit(self: *Gateway) void {
        posix.close(self.unix_fd);
        self.udp_sock.close();
        self.unix_read_buf.deinit();
        self.unix_write_buf.deinit(self.alloc);
        self.output_coalesce_buf.deinit(self.alloc);
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
