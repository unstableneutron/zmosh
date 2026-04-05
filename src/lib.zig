const std = @import("std");
const posix = std.posix;
const crypto = @import("crypto.zig");
const udp_mod = @import("udp.zig");
const ipc = @import("ipc.zig");
const transport = @import("transport.zig");

const max_ipc_payload = transport.max_payload_len - @sizeOf(ipc.Header);
const max_input_len = 1024 * 1024;
const max_output_buf = 4 * 1024 * 1024;
const ack_delay_ns = 20 * std.time.ns_per_ms;
const initial_resync_backoff_ns = 250 * std.time.ns_per_ms;
const session_end_grace_ns = 2 * std.time.ns_per_s;

// Silence all logging in library mode.
pub const std_options: std.Options = .{
    .logFn = struct {
        fn f(
            comptime _: std.log.Level,
            comptime _: anytype,
            comptime _: []const u8,
            _: anytype,
        ) void {}
    }.f,
};

// ---------------------------------------------------------------------------
// C API types
// ---------------------------------------------------------------------------

pub const Status = enum(c_int) {
    ok = 0,
    err_resolve = 1,
    err_socket = 2,
    err_invalid_key = 3,
    err_disconnected = 4,
    err_dead = 5,
    err_poll = 6,
    err_null = 7,
    err_send = 8,
    err_too_large = 9,
};

pub const State = enum(c_int) {
    connected = 0,
    disconnected = 1,
    dead = 2,
};

pub const OutputFn = *const fn (?*anyopaque, [*]const u8, u32) callconv(.c) void;
pub const StateFn = *const fn (?*anyopaque, State) callconv(.c) void;
pub const SessionEndFn = *const fn (?*anyopaque) callconv(.c) void;

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

const Session = struct {
    udp_sock: udp_mod.UdpSocket,
    peer: udp_mod.Peer,
    config: udp_mod.Config,

    reliable_send: transport.ReliableSend,
    reliable_recv: transport.RecvState,
    reliable_inbox: transport.ReliableInbox,
    output_recv: transport.OutputRecvState,

    last_ack_send_ns: i64,
    ack_dirty: bool,
    last_resync_request_ns: i64,
    resync_backoff_ns: i64,
    resync_pending: bool,
    active_snapshot_id: ?u32,
    current_output_epoch: u32,
    pending_output_epoch: ?u32,
    deferred_output_buf: std.ArrayList(u8),
    session_end_deadline_ns: ?i64,
    session_end_notified: bool,

    output_cb: OutputFn,
    state_cb: ?StateFn,
    end_cb: ?SessionEndFn,
    ctx: ?*anyopaque,

    last_state: udp_mod.PeerState,
    session_ended: bool,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sendHeartbeat(s: *Session, now: i64) !void {
    var pkt_buf: [1200]u8 = undefined;
    const pkt = try transport.buildUnreliable(
        .heartbeat,
        0,
        s.reliable_recv.ack(),
        s.reliable_recv.ackBits(),
        "",
        &pkt_buf,
    );
    try s.peer.send(&s.udp_sock, pkt);
    s.last_ack_send_ns = now;
    s.ack_dirty = false;
}

fn sendReliablePayload(s: *Session, channel: transport.Channel, payload: []const u8, now: i64) !void {
    const packet = try s.reliable_send.buildAndTrack(
        channel,
        payload,
        s.reliable_recv.ack(),
        s.reliable_recv.ackBits(),
        now,
    );
    s.peer.send(&s.udp_sock, packet) catch |err| {
        if (err == error.NoPeerAddress or err == error.WouldBlock) return;
        return err;
    };
}

fn sendIpcReliable(s: *Session, tag: ipc.Tag, payload: []const u8, now: i64) !void {
    if (payload.len <= max_ipc_payload) {
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload, &buf);
        try sendReliablePayload(s, .reliable_ipc, ipc_bytes, now);
        return;
    }

    var off: usize = 0;
    while (off < payload.len) {
        const end = @min(off + max_ipc_payload, payload.len);
        var buf: [transport.max_payload_len]u8 = undefined;
        const ipc_bytes = transport.buildIpcBytes(tag, payload[off..end], &buf);
        try sendReliablePayload(s, .reliable_ipc, ipc_bytes, now);
        off = end;
    }
}

fn requestResync(s: *Session, now: i64) !void {
    if ((now - s.last_resync_request_ns) < s.resync_backoff_ns) return;

    var ctrl_buf: [8]u8 = undefined;
    const payload = transport.buildControl(.resync_request, &ctrl_buf);
    try sendReliablePayload(s, .control, payload, now);
    s.last_resync_request_ns = now;
    s.resync_backoff_ns = @min(s.resync_backoff_ns * 2, std.time.ns_per_s);
    s.resync_pending = true;
}

// ---------------------------------------------------------------------------
// Exported C API
// ---------------------------------------------------------------------------

export fn zmosh_connect(
    host: ?[*:0]const u8,
    port: u16,
    key_base64: ?[*:0]const u8,
    rows: u16,
    cols: u16,
    output_cb: ?OutputFn,
    state_cb: ?StateFn,
    end_cb: ?SessionEndFn,
    ctx: ?*anyopaque,
    status: ?*Status,
) ?*Session {
    const set_status = struct {
        fn f(s: ?*Status, v: Status) void {
            if (s) |p| p.* = v;
        }
    }.f;

    const host_str = host orelse {
        set_status(status, .err_null);
        return null;
    };
    const key_str = key_base64 orelse {
        set_status(status, .err_null);
        return null;
    };
    const cb = output_cb orelse {
        set_status(status, .err_null);
        return null;
    };

    // Decode key
    const key = crypto.keyFromBase64(std.mem.span(key_str)) catch {
        set_status(status, .err_invalid_key);
        return null;
    };

    // Resolve address
    const addr = std.net.Address.resolveIp(std.mem.span(host_str), port) catch blk: {
        const list = std.net.getAddressList(std.heap.page_allocator, std.mem.span(host_str), port) catch {
            set_status(status, .err_resolve);
            return null;
        };
        defer list.deinit();
        if (list.addrs.len == 0) {
            set_status(status, .err_resolve);
            return null;
        }
        break :blk list.addrs[0];
    };

    // Create UDP socket — ephemeral port
    const sock_fd = posix.socket(
        addr.any.family,
        posix.SOCK.DGRAM | posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC,
        0,
    ) catch {
        set_status(status, .err_socket);
        return null;
    };
    var udp_sock = udp_mod.UdpSocket{ .fd = sock_fd, .bound_port = 0 };

    // Init peer
    var peer = udp_mod.Peer.init(key, .to_server);
    peer.addr = addr;

    const now: i64 = @intCast(std.time.nanoTimestamp());
    var reliable_send = transport.ReliableSend.init(std.heap.page_allocator) catch {
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    errdefer reliable_send.deinit();
    var reliable_inbox = transport.ReliableInbox.init(std.heap.page_allocator) catch {
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    errdefer reliable_inbox.deinit();
    var deferred_output_buf = std.ArrayList(u8).initCapacity(std.heap.page_allocator, 4096) catch {
        reliable_inbox.deinit();
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    errdefer deferred_output_buf.deinit(std.heap.page_allocator);

    // Send Init with terminal size (reliable)
    const init = ipc.Init{ .rows = rows, .cols = cols, .snapshot_id = 0 };
    var init_buf: [64]u8 = undefined;
    const init_ipc = transport.buildIpcBytes(.Init, std.mem.asBytes(&init), &init_buf);

    const init_packet = reliable_send.buildAndTrack(.reliable_ipc, init_ipc, 0, 0, now) catch {
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    peer.send(&udp_sock, init_packet) catch {
        // Keep session alive; packet will be retried by zmosh_poll.
    };

    // Allocate session
    const session = std.heap.page_allocator.create(Session) catch {
        reliable_send.deinit();
        udp_sock.close();
        set_status(status, .err_socket);
        return null;
    };
    session.* = .{
        .udp_sock = udp_sock,
        .peer = peer,
        .config = .{},
        .reliable_send = reliable_send,
        .reliable_recv = .{},
        .reliable_inbox = reliable_inbox,
        .output_recv = .{},
        .last_ack_send_ns = now,
        .ack_dirty = false,
        .last_resync_request_ns = 0,
        .resync_backoff_ns = initial_resync_backoff_ns,
        .resync_pending = false,
        .active_snapshot_id = null,
        .current_output_epoch = 0,
        .pending_output_epoch = null,
        .deferred_output_buf = deferred_output_buf,
        .session_end_deadline_ns = null,
        .session_end_notified = false,
        .output_cb = cb,
        .state_cb = state_cb,
        .end_cb = end_cb,
        .ctx = ctx,
        .last_state = .connected,
        .session_ended = false,
    };

    set_status(status, .ok);
    return session;
}

export fn zmosh_get_fd(session: ?*const Session) c_int {
    const s = session orelse return -1;
    return s.udp_sock.getFd();
}

export fn zmosh_poll(session: ?*Session) Status {
    const s = session orelse return .err_null;
    if (s.session_ended and s.session_end_notified) return .ok;

    const now: i64 = @intCast(std.time.nanoTimestamp());

    // Retransmit reliable packets.
    var retransmits = s.reliable_send.collectRetransmits(std.heap.page_allocator, now, s.peer.rto_us()) catch return .err_poll;
    defer retransmits.deinit(std.heap.page_allocator);
    for (retransmits.items) |pkt| {
        s.peer.send(&s.udp_sock, pkt) catch {};
    }

    // Heartbeat + delayed ACKs.
    if (s.ack_dirty and (now - s.last_ack_send_ns) >= ack_delay_ns) {
        sendHeartbeat(s, now) catch {};
    } else if (s.peer.shouldSendHeartbeat(now, s.config)) {
        sendHeartbeat(s, now) catch {};
    }

    // State check
    const state = s.peer.updateState(now, s.config);
    const mapped: State = switch (state) {
        .connected => .connected,
        .disconnected => .disconnected,
        .dead => .dead,
    };
    if (state != s.last_state) {
        s.last_state = state;
        if (s.state_cb) |cb| cb(s.ctx, mapped);
    }
    if (state == .dead and !s.session_ended) return .err_dead;

    // Recv loop — drain all pending datagrams
    while (true) {
        var decrypt_buf: [9000]u8 = undefined;
        const recv_result = s.peer.recv(&s.udp_sock, &decrypt_buf) catch |err| {
            if (err == error.WouldBlock) break;
            return .err_poll;
        };
        const result = recv_result orelse break;

        const packet = transport.parsePacket(result.data) catch continue;
        if (s.reliable_send.ack(packet.ack, packet.ack_bits)) |rtt_us| {
            s.peer.reportRtt(rtt_us);
        }

        switch (packet.channel) {
            .heartbeat => {},
            .control, .reliable_ipc => {
                s.ack_dirty = true;
                if (!s.reliable_inbox.accepts(packet.seq)) continue;
                if (s.reliable_recv.onReliable(packet.seq) != .accept) continue;

                s.reliable_inbox.push(packet.seq, packet.channel, packet.payload) catch return .err_poll;
                while (s.reliable_inbox.popReady()) |delivery| {
                    defer delivery.deinit(std.heap.page_allocator);

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
                                    s.active_snapshot_id = null;
                                    s.deferred_output_buf.clearRetainingCapacity();
                                    s.resync_backoff_ns = initial_resync_backoff_ns;
                                    s.output_cb(s.ctx, payload.ptr, @intCast(payload.len));
                                } else if (hdr.tag == .Snapshot and payload.len >= @sizeOf(ipc.Snapshot)) {
                                    const snapshot = std.mem.bytesToValue(ipc.Snapshot, payload[0..@sizeOf(ipc.Snapshot)]);
                                    const snapshot_bytes = payload[@sizeOf(ipc.Snapshot)..];
                                    if (s.active_snapshot_id) |current| {
                                        if (snapshot.id < current) {
                                            offset += msg_len;
                                            continue;
                                        }
                                        if (snapshot.id > current) {
                                            s.deferred_output_buf.clearRetainingCapacity();
                                            s.pending_output_epoch = null;
                                        }
                                    } else {
                                        s.deferred_output_buf.clearRetainingCapacity();
                                        s.pending_output_epoch = null;
                                    }
                                    if (s.pending_output_epoch) |pending_epoch| {
                                        if (pending_epoch != snapshot.id) {
                                            s.deferred_output_buf.clearRetainingCapacity();
                                            s.pending_output_epoch = null;
                                        }
                                    }
                                    s.active_snapshot_id = snapshot.id;
                                    s.resync_pending = false;
                                    s.current_output_epoch = snapshot.id;
                                    s.resync_backoff_ns = initial_resync_backoff_ns;
                                    if (snapshot_bytes.len > 0) {
                                        s.output_cb(s.ctx, snapshot_bytes.ptr, @intCast(snapshot_bytes.len));
                                    }
                                    if (snapshot.isFinal()) {
                                        s.active_snapshot_id = null;
                                        if (s.deferred_output_buf.items.len > 0) {
                                            s.output_cb(s.ctx, s.deferred_output_buf.items.ptr, @intCast(s.deferred_output_buf.items.len));
                                            s.deferred_output_buf.clearRetainingCapacity();
                                            s.pending_output_epoch = null;
                                        }
                                    }
                                } else if (hdr.tag == .SessionEnd) {
                                    s.session_ended = true;
                                    s.session_end_deadline_ns = s.session_end_deadline_ns orelse now + session_end_grace_ns;
                                }

                                offset += msg_len;
                            }
                        },
                        else => unreachable,
                    }
                }
            },
            .output => {
                switch (s.output_recv.onPacket(packet.seq)) {
                    .accept => {
                        if (packet.payload.len > 0) {
                            if (packet.payload.len < @sizeOf(transport.OutputPrefix)) continue;
                            const prefix = std.mem.bytesToValue(transport.OutputPrefix, packet.payload[0..@sizeOf(transport.OutputPrefix)]);
                            if (prefix.epoch < s.current_output_epoch) continue;
                            if (s.resync_pending and s.active_snapshot_id == null) {
                                if (prefix.epoch <= s.current_output_epoch) continue;
                                if (s.pending_output_epoch) |pending_epoch| {
                                    if (pending_epoch != prefix.epoch) {
                                        s.deferred_output_buf.clearRetainingCapacity();
                                    }
                                }
                                s.pending_output_epoch = prefix.epoch;
                            } else if (prefix.epoch > s.current_output_epoch and s.active_snapshot_id == null) {
                                s.current_output_epoch = prefix.epoch;
                            }
                            const output_payload = packet.payload[@sizeOf(transport.OutputPrefix)..];
                            if (s.active_snapshot_id != null) {
                                if (s.deferred_output_buf.items.len + output_payload.len > max_output_buf) {
                                    s.deferred_output_buf.clearRetainingCapacity();
                                    requestResync(s, now) catch {};
                                } else {
                                    s.resync_backoff_ns = initial_resync_backoff_ns;
                                    s.deferred_output_buf.appendSlice(std.heap.page_allocator, output_payload) catch return .err_poll;
                                }
                            } else {
                                s.resync_backoff_ns = initial_resync_backoff_ns;
                                s.output_cb(s.ctx, output_payload.ptr, @intCast(output_payload.len));
                            }
                        }
                    },
                    .gap => {
                        requestResync(s, now) catch {};
                    },
                    .duplicate, .stale => {},
                }
            },
        }
    }

    if (s.session_ended and
        s.session_end_deadline_ns != null and
        now >= s.session_end_deadline_ns.? and
        s.active_snapshot_id == null and
        s.deferred_output_buf.items.len == 0)
    {
        if (!s.session_end_notified) {
            s.session_end_notified = true;
            if (s.end_cb) |cb| cb(s.ctx);
        }
    }

    return .ok;
}

export fn zmosh_send_input(session: ?*Session, data: ?[*]const u8, len: u32) Status {
    const s = session orelse return .err_null;
    const d = data orelse return .err_null;
    if (len == 0) return .ok;
    if (len > max_input_len) return .err_too_large;

    const now: i64 = @intCast(std.time.nanoTimestamp());
    const payload = d[0..len];
    var off: usize = 0;
    while (off < payload.len) {
        const end = @min(off + max_ipc_payload, payload.len);
        sendIpcReliable(s, .Input, payload[off..end], now) catch return .err_send;
        off = end;
    }
    return .ok;
}

export fn zmosh_resize(session: ?*Session, rows: u16, cols: u16) Status {
    const s = session orelse return .err_null;

    const size = ipc.Resize{ .rows = rows, .cols = cols };
    const now: i64 = @intCast(std.time.nanoTimestamp());
    sendIpcReliable(s, .Resize, std.mem.asBytes(&size), now) catch return .err_send;
    return .ok;
}

export fn zmosh_network_changed(session: ?*Session) Status {
    const s = session orelse return .err_null;
    const now: i64 = @intCast(std.time.nanoTimestamp());
    s.peer.enterRecoveryMode(now);
    sendHeartbeat(s, now) catch {};
    sendHeartbeat(s, now) catch {};
    return .ok;
}

export fn zmosh_disconnect(session: ?*Session) void {
    const s = session orelse return;

    const now: i64 = @intCast(std.time.nanoTimestamp());
    sendIpcReliable(s, .Detach, "", now) catch {};

    s.deferred_output_buf.deinit(std.heap.page_allocator);
    s.reliable_inbox.deinit();
    s.reliable_send.deinit();
    s.udp_sock.close();
    std.heap.page_allocator.destroy(s);
}
