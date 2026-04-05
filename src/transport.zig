const std = @import("std");
const ipc = @import("ipc.zig");

pub const version: u8 = 1;
pub const max_payload_len: usize = 1100;
const header_len: usize = 20;

pub const Channel = enum(u8) {
    heartbeat = 0,
    reliable_ipc = 1,
    output = 2,
    control = 3,
};

pub const Control = enum(u8) {
    resync_request = 1,
};

pub const Packet = struct {
    channel: Channel,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    payload: []const u8,
};

pub const ReliableAction = enum {
    accept,
    duplicate,
    stale,
};

pub const OutputAction = enum {
    accept,
    duplicate,
    stale,
    gap,
};

pub const OutputPrefix = packed struct {
    epoch: u32,
};

/// RFC 1982 serial number arithmetic: returns true if `a` is after `b`.
pub fn seqAfter(a: u32, b: u32) bool {
    return a != b and @as(i32, @bitCast(a -% b)) > 0;
}

fn seqDist(a: u32, b: u32) u32 {
    return a -% b;
}

pub const RecvState = struct {
    latest: u32 = 0,
    mask: u32 = 0,
    has_latest: bool = false,

    pub fn onReliable(self: *RecvState, seq: u32) ReliableAction {
        if (!self.has_latest) {
            self.latest = seq;
            self.mask = 0;
            self.has_latest = true;
            return .accept;
        }

        if (seqAfter(seq, self.latest)) {
            const shift = seqDist(seq, self.latest);
            if (shift > 32) {
                self.mask = 0;
            } else if (shift == 32) {
                self.mask = @as(u32, 1) << 31;
            } else {
                self.mask <<= @intCast(shift);
                self.mask |= @as(u32, 1) << @intCast(shift - 1);
            }
            self.latest = seq;
            return .accept;
        }

        if (seq == self.latest) return .duplicate;

        const diff = seqDist(self.latest, seq);
        if (diff > 32) return .stale;

        const bit: u32 = @as(u32, 1) << @intCast(diff - 1);
        if (self.mask & bit != 0) return .duplicate;
        self.mask |= bit;
        return .accept;
    }

    pub fn ack(self: *const RecvState) u32 {
        return if (self.has_latest) self.latest else 0;
    }

    pub fn ackBits(self: *const RecvState) u32 {
        return if (self.has_latest) self.mask else 0;
    }
};

pub const OutputRecvState = struct {
    latest: u32 = 0,
    has_latest: bool = false,

    pub fn onPacket(self: *OutputRecvState, seq: u32) OutputAction {
        if (!self.has_latest) {
            self.latest = seq;
            self.has_latest = true;
            return .accept;
        }

        if (seq == self.latest +% 1) {
            self.latest = seq;
            return .accept;
        }

        if (!seqAfter(seq, self.latest)) {
            return .duplicate;
        }

        // seq jumped ahead.
        self.latest = seq;
        return .gap;
    }
};

pub const ReliableDelivery = struct {
    seq: u32,
    channel: Channel,
    payload: []u8,

    pub fn deinit(self: ReliableDelivery, alloc: std.mem.Allocator) void {
        alloc.free(self.payload);
    }
};

pub const PendingReliableFrame = struct {
    seq: u32,
    channel: Channel,
    payload: []const u8,
};

pub const ReliableInbox = struct {
    alloc: std.mem.Allocator,
    next_seq: u32 = 1,
    pending: std.ArrayList(ReliableDelivery),

    pub fn accepts(self: *const ReliableInbox, seq: u32) bool {
        if (seq == self.next_seq) return true;
        if (!seqAfter(seq, self.next_seq)) return false;
        return seqDist(seq, self.next_seq) <= 32;
    }

    pub fn init(alloc: std.mem.Allocator) !ReliableInbox {
        return .{
            .alloc = alloc,
            .pending = try std.ArrayList(ReliableDelivery).initCapacity(alloc, 8),
        };
    }

    pub fn deinit(self: *ReliableInbox) void {
        for (self.pending.items) |delivery| {
            delivery.deinit(self.alloc);
        }
        self.pending.deinit(self.alloc);
    }

    pub fn push(self: *ReliableInbox, seq: u32, channel: Channel, payload: []const u8) !void {
        const owned_payload = try self.alloc.dupe(u8, payload);
        errdefer self.alloc.free(owned_payload);

        try self.pending.append(self.alloc, .{
            .seq = seq,
            .channel = channel,
            .payload = owned_payload,
        });
    }

    pub fn popReady(self: *ReliableInbox) ?ReliableDelivery {
        var i: usize = 0;
        while (i < self.pending.items.len) : (i += 1) {
            if (self.pending.items[i].seq == self.next_seq) {
                const delivery = self.pending.swapRemove(i);
                self.next_seq +%= 1;
                return delivery;
            }
        }
        return null;
    }
};

pub const ReliableSend = struct {
    alloc: std.mem.Allocator,
    next_seq: u32 = 1,
    pending: std.ArrayList(Pending),

    const Pending = struct {
        seq: u32,
        sent_ns: i64,
        retries: u8,
        packet: []u8,
    };

    pub fn init(alloc: std.mem.Allocator) !ReliableSend {
        return .{
            .alloc = alloc,
            .pending = try std.ArrayList(Pending).initCapacity(alloc, 16),
        };
    }

    pub fn deinit(self: *ReliableSend) void {
        for (self.pending.items) |p| {
            self.alloc.free(p.packet);
        }
        self.pending.deinit(self.alloc);
    }

    pub fn hasPending(self: *const ReliableSend) bool {
        return self.pending.items.len > 0;
    }

    pub fn buildAndTrack(
        self: *ReliableSend,
        channel: Channel,
        payload: []const u8,
        ack_seq: u32,
        ack_bits: u32,
        now_ns: i64,
    ) ![]const u8 {
        const seq = self.next_seq;
        self.next_seq +%= 1;

        const packet = try self.alloc.alloc(u8, header_len + payload.len);
        writeHeader(packet[0..header_len], channel, seq, ack_seq, ack_bits, payload.len);
        if (payload.len > 0) {
            @memcpy(packet[header_len..], payload);
        }

        try self.pending.append(self.alloc, .{
            .seq = seq,
            .sent_ns = now_ns,
            .retries = 0,
            .packet = packet,
        });

        return packet;
    }

    pub fn ack(self: *ReliableSend, ack_seq: u32, ack_bits: u32) ?i64 {
        var rtt_sample: ?i64 = null;
        const now_ns: i64 = @intCast(std.time.nanoTimestamp());
        var i: usize = self.pending.items.len;
        while (i > 0) {
            i -= 1;
            const p = self.pending.items[i];
            if (isAcked(p.seq, ack_seq, ack_bits)) {
                if (p.retries == 0 and rtt_sample == null) {
                    const rtt_ns = now_ns - p.sent_ns;
                    if (rtt_ns > 0) {
                        rtt_sample = @divFloor(rtt_ns, std.time.ns_per_us);
                    }
                }
                self.alloc.free(p.packet);
                _ = self.pending.swapRemove(i);
            }
        }
        return rtt_sample;
    }

    pub fn collectRetransmits(
        self: *ReliableSend,
        alloc: std.mem.Allocator,
        now_ns: i64,
        rto_us: i64,
    ) !std.ArrayList([]const u8) {
        var out = try std.ArrayList([]const u8).initCapacity(alloc, 4);
        const interval_ns = @max(@as(i64, 1), rto_us) * std.time.ns_per_us;

        for (self.pending.items) |*p| {
            if (now_ns - p.sent_ns >= interval_ns) {
                p.sent_ns = now_ns;
                p.retries +%= 1;
                try out.append(alloc, p.packet);
            }
        }

        return out;
    }

    pub fn appendPendingReliableIpc(self: *ReliableSend, alloc: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
        if (self.pending.items.len == 0) return;

        const ordered = try alloc.alloc(Pending, self.pending.items.len);
        defer alloc.free(ordered);
        @memcpy(ordered, self.pending.items);

        var i: usize = 1;
        while (i < ordered.len) : (i += 1) {
            const key = ordered[i];
            var j = i;
            while (j > 0 and seqAfter(ordered[j - 1].seq, key.seq)) : (j -= 1) {
                ordered[j] = ordered[j - 1];
            }
            ordered[j] = key;
        }

        for (ordered) |pending| {
            const packet = parsePacket(pending.packet) catch continue;
            if (packet.channel != .reliable_ipc) continue;
            try out.appendSlice(alloc, packet.payload);
        }
    }

    pub fn collectPendingReliableFrames(self: *ReliableSend, alloc: std.mem.Allocator) !std.ArrayList(PendingReliableFrame) {
        var out = try std.ArrayList(PendingReliableFrame).initCapacity(alloc, self.pending.items.len);
        errdefer out.deinit(alloc);
        if (self.pending.items.len == 0) return out;

        const ordered = try alloc.alloc(Pending, self.pending.items.len);
        defer alloc.free(ordered);
        @memcpy(ordered, self.pending.items);

        var i: usize = 1;
        while (i < ordered.len) : (i += 1) {
            const key = ordered[i];
            var j = i;
            while (j > 0 and seqAfter(ordered[j - 1].seq, key.seq)) : (j -= 1) {
                ordered[j] = ordered[j - 1];
            }
            ordered[j] = key;
        }

        for (ordered) |pending| {
            const packet = parsePacket(pending.packet) catch continue;
            if (packet.channel != .reliable_ipc and packet.channel != .control) continue;
            try out.append(alloc, .{ .seq = pending.seq, .channel = packet.channel, .payload = packet.payload });
        }
        return out;
    }

    pub fn clearPending(self: *ReliableSend) void {
        for (self.pending.items) |pending| {
            self.alloc.free(pending.packet);
        }
        self.pending.clearRetainingCapacity();
    }

    fn isAcked(seq: u32, ack_seq: u32, ack_bits: u32) bool {
        if (ack_seq == 0) return false;
        if (seq == ack_seq) return true;
        if (seqAfter(seq, ack_seq)) return false;

        const diff = seqDist(ack_seq, seq);
        if (diff == 0) return true;
        if (diff > 32) return false;

        const bit: u32 = @as(u32, 1) << @intCast(diff - 1);
        return (ack_bits & bit) != 0;
    }
};

pub fn writeHeader(dst: []u8, channel: Channel, seq: u32, ack: u32, ack_bits: u32, payload_len: usize) void {
    std.debug.assert(dst.len >= header_len);
    std.debug.assert(payload_len <= std.math.maxInt(u16));

    dst[0] = version;
    dst[1] = @intFromEnum(channel);
    dst[2] = 0;
    dst[3] = 0;

    std.mem.writeInt(u32, dst[4..8], seq, .big);
    std.mem.writeInt(u32, dst[8..12], ack, .big);
    std.mem.writeInt(u32, dst[12..16], ack_bits, .big);
    std.mem.writeInt(u16, dst[16..18], @intCast(payload_len), .big);
    std.mem.writeInt(u16, dst[18..20], 0, .big);
}

pub fn parsePacket(data: []const u8) !Packet {
    if (data.len < header_len) return error.PacketTooShort;
    if (data[0] != version) return error.UnsupportedVersion;

    const channel_int = data[1];
    const channel = std.meta.intToEnum(Channel, channel_int) catch return error.InvalidChannel;

    const seq = std.mem.readInt(u32, data[4..8], .big);
    const ack = std.mem.readInt(u32, data[8..12], .big);
    const ack_bits = std.mem.readInt(u32, data[12..16], .big);
    const len = std.mem.readInt(u16, data[16..18], .big);

    if (data.len != header_len + len) return error.InvalidLength;

    return .{
        .channel = channel,
        .seq = seq,
        .ack = ack,
        .ack_bits = ack_bits,
        .payload = data[header_len..],
    };
}

pub fn buildUnreliable(
    channel: Channel,
    seq: u32,
    ack: u32,
    ack_bits: u32,
    payload: []const u8,
    out: []u8,
) ![]const u8 {
    const total = header_len + payload.len;
    if (out.len < total) return error.BufferTooSmall;

    if (payload.len > 0) {
        // Some callers stage the payload in `out` before prepending the transport
        // header, so move the payload into place before writing the header.
        const dest = out[header_len..total];
        const dest_addr = @intFromPtr(dest.ptr);
        const src_addr = @intFromPtr(payload.ptr);
        const overlaps = dest_addr < (src_addr + payload.len) and src_addr < (dest_addr + dest.len);
        if (overlaps) {
            if (dest_addr > src_addr) {
                std.mem.copyBackwards(u8, dest, payload);
            } else if (dest_addr < src_addr) {
                std.mem.copyForwards(u8, dest, payload);
            }
        } else {
            @memcpy(dest, payload);
        }
    }

    writeHeader(out[0..header_len], channel, seq, ack, ack_bits, payload.len);
    return out[0..total];
}

pub fn buildControl(control: Control, out: *[8]u8) []const u8 {
    out[0] = @intFromEnum(control);
    @memset(out[1..], 0);
    return out[0..1];
}

pub fn parseControl(payload: []const u8) !Control {
    if (payload.len < 1) return error.InvalidControl;
    return std.meta.intToEnum(Control, payload[0]) catch error.InvalidControl;
}

pub fn buildIpcBytes(tag: ipc.Tag, payload: []const u8, buf: []u8) []const u8 {
    const header = ipc.Header{ .tag = tag, .len = @intCast(payload.len) };
    const hdr_bytes = std.mem.asBytes(&header);
    const total = @sizeOf(ipc.Header) + payload.len;
    std.debug.assert(buf.len >= total);
    @memcpy(buf[0..@sizeOf(ipc.Header)], hdr_bytes);
    if (payload.len > 0) {
        @memcpy(buf[@sizeOf(ipc.Header)..total], payload);
    }
    return buf[0..total];
}

test "transport header round trip" {
    var buf: [64]u8 = undefined;
    const payload = "abc";
    const pkt = try buildUnreliable(.output, 7, 6, 0x55, payload, &buf);
    const parsed = try parsePacket(pkt);
    try std.testing.expect(parsed.channel == .output);
    try std.testing.expectEqual(@as(u32, 7), parsed.seq);
    try std.testing.expectEqual(@as(u32, 6), parsed.ack);
    try std.testing.expectEqual(@as(u32, 0x55), parsed.ack_bits);
    try std.testing.expectEqualStrings(payload, parsed.payload);
}

test "buildUnreliable handles payload slices that alias output buffer" {
    const payload_len = header_len + 12;
    var expected: [payload_len]u8 = undefined;
    for (&expected, 0..) |*byte, i| byte.* = @intCast(i);

    var buf: [header_len + payload_len]u8 = undefined;
    @memcpy(buf[0..payload_len], &expected);

    const pkt = try buildUnreliable(.output, 7, 6, 0x55, buf[0..payload_len], &buf);
    const parsed = try parsePacket(pkt);

    try std.testing.expect(parsed.channel == .output);
    try std.testing.expectEqualSlices(u8, &expected, parsed.payload);
}

test "seqAfter handles wrap-around" {
    try std.testing.expect(seqAfter(2, 1));
    try std.testing.expect(!seqAfter(1, 2));
    try std.testing.expect(!seqAfter(5, 5));
    try std.testing.expect(seqAfter(0, std.math.maxInt(u32)));
    try std.testing.expect(seqAfter(1, std.math.maxInt(u32)));
    try std.testing.expect(!seqAfter(std.math.maxInt(u32), 0));
}

test "RecvState.onReliable across wrap" {
    var recv = RecvState{};
    recv.latest = std.math.maxInt(u32) - 1;
    recv.has_latest = true;
    recv.mask = 0;
    try std.testing.expect(recv.onReliable(std.math.maxInt(u32)) == .accept);
    try std.testing.expect(recv.onReliable(0) == .accept);
    try std.testing.expectEqual(@as(u32, 0), recv.ack());
}

test "OutputRecvState across wrap" {
    var out = OutputRecvState{};
    out.latest = std.math.maxInt(u32);
    out.has_latest = true;
    try std.testing.expect(out.onPacket(0) == .accept);
    try std.testing.expectEqual(@as(u32, 0), out.latest);
}

test "reliable recv window" {
    var recv = RecvState{};
    try std.testing.expect(recv.onReliable(10) == .accept);
    try std.testing.expect(recv.onReliable(9) == .accept);
    try std.testing.expect(recv.onReliable(9) == .duplicate);
    try std.testing.expect(recv.onReliable(11) == .accept);
    try std.testing.expectEqual(@as(u32, 11), recv.ack());
}

test "reliable recv window keeps the 32-packet boundary acked" {
    var recv = RecvState{};
    try std.testing.expect(recv.onReliable(10) == .accept);
    try std.testing.expect(recv.onReliable(42) == .accept);
    try std.testing.expectEqual(@as(u32, 42), recv.ack());
    try std.testing.expectEqual(@as(u32, 1) << 31, recv.ackBits());
}

test "ReliableInbox delivers reliable packets in order" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var inbox = try ReliableInbox.init(alloc);
    defer inbox.deinit();

    try inbox.push(2, .control, "two");
    try std.testing.expect(inbox.popReady() == null);

    try inbox.push(1, .reliable_ipc, "one");

    const first = inbox.popReady().?;
    defer first.deinit(alloc);
    try std.testing.expect(first.seq == 1);
    try std.testing.expect(first.channel == .reliable_ipc);
    try std.testing.expectEqualStrings("one", first.payload);

    const second = inbox.popReady().?;
    defer second.deinit(alloc);
    try std.testing.expect(second.seq == 2);
    try std.testing.expect(second.channel == .control);
    try std.testing.expectEqualStrings("two", second.payload);

    try std.testing.expect(inbox.popReady() == null);
}

test "ReliableInbox rejects packets too far ahead of next_seq" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var inbox = try ReliableInbox.init(alloc);
    defer inbox.deinit();

    try std.testing.expect(inbox.accepts(1));
    try std.testing.expect(inbox.accepts(33));
    try std.testing.expect(!inbox.accepts(34));
}

test "output gap detection" {
    var out = OutputRecvState{};
    try std.testing.expect(out.onPacket(1) == .accept);
    try std.testing.expect(out.onPacket(3) == .gap);
    try std.testing.expect(out.onPacket(2) == .duplicate);
}

test "ReliableSend.ack returns null for retransmitted packets" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var send = try ReliableSend.init(alloc);
    defer send.deinit();

    const now: i64 = 100 * std.time.ns_per_s;
    _ = try send.buildAndTrack(.reliable_ipc, "test", 0, 0, now);
    send.pending.items[0].retries = 1;

    const rtt = send.ack(1, 0);
    try std.testing.expect(rtt == null);
}

test "ReliableSend.ack returns single RTT from multiple acked packets" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var send = try ReliableSend.init(alloc);
    defer send.deinit();

    const now_ns: i64 = @intCast(std.time.nanoTimestamp());
    _ = try send.buildAndTrack(.reliable_ipc, "a", 0, 0, now_ns - 50 * std.time.ns_per_ms);
    _ = try send.buildAndTrack(.reliable_ipc, "b", 0, 0, now_ns - 20 * std.time.ns_per_ms);

    const rtt = send.ack(2, 1);
    try std.testing.expect(rtt != null);
    try std.testing.expect(rtt.? > 0);
    try std.testing.expect(send.pending.items.len == 0);
}

test "ReliableSend.ack returns RTT when packet is acked by ack bits only" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    var send = try ReliableSend.init(alloc);
    defer send.deinit();

    const now_ns: i64 = @intCast(std.time.nanoTimestamp());
    _ = try send.buildAndTrack(.reliable_ipc, "a", 0, 0, now_ns - 50 * std.time.ns_per_ms);
    _ = try send.buildAndTrack(.reliable_ipc, "b", 0, 0, now_ns - 20 * std.time.ns_per_ms);

    const rtt = send.ack(3, 0b10);
    try std.testing.expect(rtt != null);
    try std.testing.expect(rtt.? > 0);
    try std.testing.expect(send.pending.items.len == 1);
    try std.testing.expect(send.pending.items[0].seq == 2);
}
