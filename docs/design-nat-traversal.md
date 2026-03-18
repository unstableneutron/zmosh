# NAT Traversal & SSH Fallback for zmosh

Design document for improving zmosh's remote connectivity when the server
lacks manually forwarded UDP ports.

**Status:** Draft v2 (post-review)  
**Author:** Analysis thread  
**Date:** 2026-03-17

---

## Problem

zmosh remote sessions require the server to have UDP ports 60000–61000
reachable from the internet. This fails when:

- The server sits behind a consumer NAT or CGNAT without manual port forwarding
- Enterprise firewalls block inbound UDP
- Both client and server sit behind NATs (double-NAT)
- The server runs on a cloud VM with restrictive security groups

Users who can SSH into a server should be able to use zmosh remote sessions
without additional firewall configuration.

## Goals

1. **Auto-discover reachable endpoints** — server learns its public IP:port
   via STUN (treated as a hint, not authoritative)
2. **Keep NAT bindings alive** — server maintains its mapping even when no
   client is connected
3. **Exchange candidates** — client and server share candidate addresses
   over the existing SSH signaling channel
4. **Hole-punch** — both sides probe candidate pairs using a dedicated probe
   state machine (separate from `peer.addr`)
5. **Fall back to SSH** — when UDP fails entirely, tunnel IPC over the
   already-open SSH connection

## Non-Goals

- Full ICE / SDP implementation
- WebRTC or WebTransport stack
- Public relay infrastructure (TURN) — deferred to a future phase
- NAT-PMP / PCP / UPnP — deferred until STUN + punch + SSH fallback ships
- Predictive local echo

---

## Architecture Overview

```
Phase 1: Bootstrap + SSH fallback    (both sides, ~250 LOC)
Phase 2: STUN + hole punching        (both sides, ~300 LOC)
Phase 3: NAT keepalive               (server-side, ~50 LOC)
```

All phases preserve the gateway architecture. The daemon and its Unix socket
IPC remain untouched. Changes live in `serve.zig`, `remote.zig`, and a new
`nat.zig` module.

---

## Phase 1 — Bootstrap Refactor + SSH Fallback

This phase provides immediate value: if UDP fails, the session works anyway.
It also forces the correct bootstrap architecture for Phase 2.

### 1.1 Capability-Negotiated v2 Bootstrap

**Problem:** Old clients cannot parse `ZMX_CONNECT2`. Emitting it by default
breaks backward compatibility.

**Solution:** Client opt-in via environment variable in the SSH command.

The client sets `ZMX_BOOTSTRAP=2` in the remote command:

```
ssh host -- ZMX_BOOTSTRAP=2 ... zmosh serve <session>
```

Server behavior:
- **`ZMX_BOOTSTRAP=2` set** → emit `ZMX_CONNECT2 <json>\n`, keep pipes open
- **`ZMX_BOOTSTRAP` unset** → emit `ZMX_CONNECT udp <port> <key>\n` (legacy),
  close stdout immediately

Client behavior:
- Parse `ZMX_CONNECT2` if present → v2 flow
- Parse `ZMX_CONNECT` if present → legacy flow (unchanged)

Compatibility matrix:

| Client | Server | Result |
|--------|--------|--------|
| new | new | v2 (candidates + fallback) |
| new | old | old server ignores env var, emits v1, client uses legacy UDP |
| old | new | no env var, server emits v1, old client works unchanged |

### 1.2 SSH Signaling Protocol

All control messages are **line-delimited** with a prefix. No raw JSON
without framing.

**Server → client (stdout):**
```
ZMX_CONNECT2 {"v":2,"key":"<b64>","candidates":[...],"ssh_fallback":true}\n
```

**Client → server (stdin):**
```
ZMX_CANDIDATES2 {"candidates":[...]}\n
ZMX_USE udp\n
```
or:
```
ZMX_CANDIDATES2 {"candidates":[...]}\n
ZMX_USE ssh\n
```

After `ZMX_USE ssh\n`, both sides switch stdin/stdout to raw IPC mode
(length-prefixed `ipc.Header` framing). After `ZMX_USE udp\n`, the client
closes SSH pipes and the server closes stdin/stdout.

**Buffer size:** The SSH stdout reader in `remote.zig` must be enlarged from
512 bytes to 4096 bytes to accommodate JSON candidate lists.

### 1.2.1 User-Control Flags (Implemented)

Remote attach exposes explicit operator controls:

- `--nat-traversal=auto|off` (default: `auto`)
  - `auto`: use `ZMX_BOOTSTRAP=2`, exchange candidates, probe, and fall back to SSH
  - `off`: force legacy bootstrap (`ZMX_BOOTSTRAP=0`) and legacy UDP connect flow only
- `--stun-server <host:port>` (repeatable)
  - Configures one or more STUN servers used for candidate discovery
  - If omitted, defaults are used
- `--probe-timeout-ms <ms>`
  - Overrides total probe window (clamped to safe bounds)
- `--connect-debug`
  - Enables client/server connectivity debug logs during bootstrap/probe/selection

`--stun-server` supports multiple values by design. The implementation resolves
all configured servers, uses the first successful response for srflx candidate
discovery, and rotates through configured servers for server keepalives.

### 1.3 Shell Injection Fix

**Current risk:** `remote.zig` interpolates `TERM`, `COLORTERM`, and
`session` directly into the SSH command string. A malicious session name
could inject shell commands.

**Fix:** Shell-escape all interpolated values, or pass them as separate
arguments. For `session`, validate it contains only `[a-zA-Z0-9._-]`.

### 1.4 SSH Fallback Transport

Introduce a transport union:

```zig
pub const RemoteTransport = union(enum) {
    udp: struct {
        sock: *udp.UdpSocket,
        peer: *udp.Peer,
    },
    ssh: struct {
        read_fd: i32,   // SSH stdout (client) or stdin (gateway)
        write_fd: i32,  // SSH stdin (client) or stdout (gateway)
        read_buf: ipc.SocketBuffer,
    },
};
```

**Gateway changes (`serve.zig`):**
- Do NOT close stdout at line 112 when `ZMX_BOOTSTRAP=2`
- Read control messages from stdin during probe window
- On `ZMX_USE ssh`: replace UDP fd in poll set with stdin/stdout fds,
  bridge SSH ↔ Unix socket using `ipc.Header` framing
- No zmosh encryption needed — SSH provides it

**Client changes (`remote.zig`):**
- `connectRemote()` returns a bootstrap handle (not just host/port/key)
  that keeps the SSH child process and pipes alive
- After probe window: send `ZMX_USE udp\n` or `ZMX_USE ssh\n`
- In SSH mode: poll SSH child stdout fd, write IPC to SSH child stdin fd
- Show status: `"zmx: using SSH tunnel (no UDP connectivity)"`
- Set SSH child pipe fds to non-blocking for poll integration

**Tradeoffs vs UDP mode:**

| Property | UDP mode | SSH fallback |
|----------|----------|-------------|
| Roaming | ✅ survives IP changes | ❌ TCP breaks |
| Latency | ~1 RTT | TCP + SSH overhead |
| Head-of-line blocking | None | TCP ordering |
| Sleep/wake recovery | Single packet | Needs reconnect |
| Works through any firewall | Needs UDP | ✅ if SSH works |
| Encryption | XChaCha20 | SSH (already encrypted) |

---

## Phase 2 — STUN Discovery + UDP Hole Punching

### 2.1 STUN Client (new: `src/nat.zig`)

Async STUN Binding Request/Response on the session socket (RFC 5389).

**Critical design rule:** STUN shares the same UDP socket as zmosh traffic.
There is no separate STUN socket. The gateway/client must **demux** incoming
datagrams before passing them to crypto decode.

**Demux strategy** (in the UDP read path):
1. `recvfrom()` a raw datagram
2. If source address matches a configured STUN server AND the first 4 bytes
   contain the STUN magic cookie (`0x2112A442` at offset 4): consume as STUN
3. Otherwise: pass to `peer.recv()` for zmosh crypto decode

**STUN state machine:**

```zig
pub const StunState = struct {
    txn_id: [12]u8,
    server_addr: std.net.Address,
    sent_ns: i64,
    retries: u8,          // max 3, intervals: 500ms, 1s, 2s (RFC 5389 §7.2.1)
    result: ?Candidate,

    pub fn sendRequest(self: *StunState, sock_fd: i32) !void;
    pub fn handleResponse(self: *StunState, data: []const u8) !?Candidate;
};
```

**STUN response parsing:**
- Verify message type (0x0101 = Binding Success), magic cookie, txn_id match
- Parse XOR-MAPPED-ADDRESS (type 0x0020): handle both IPv4 (family 0x01)
  and IPv6 (family 0x02) — IPv6 XOR uses magic cookie + txn_id
- Attributes are padded to 4-byte boundaries
- FINGERPRINT attribute is optional; ignore if present

**Important:** On address-dependent NATs, the STUN-discovered port is only a
**hint**. The external port the remote peer sees may differ. The actual
usable address is the **peer-reflexive** address — the source address seen
on the first authenticated packet. The design must treat srflx candidates as
"worth trying" but not authoritative.

**STUN server set:** Support multiple configured STUN servers (user-provided
or defaults). Fail over during discovery if one server is unreachable.

### 2.2 Candidate Gathering

**Candidate types:**

```zig
pub const CandidateType = enum { host, srflx };

pub const Candidate = struct {
    ctype: CandidateType,
    addr: std.net.Address,
    source: []const u8,
};
```

**Gathering (both sides):**
1. Enumerate local interfaces → host candidates (filter out loopback,
   link-local, multicast, Docker/bridge interfaces)
2. Send STUN Binding Request from session socket → srflx candidate
3. Cap at 8 candidates total

**Address family rule:** Only probe candidates whose address family matches
the session socket. If the socket is AF_INET6 dual-stack, probe both.
If AF_INET, probe only IPv4 candidates.

### 2.3 Probe State Machine (NOT `peer.addr`)

**Critical fix:** Do NOT use `peer.addr` during probing. The existing
roaming logic would cause the address to oscillate between candidates.

Instead, use a dedicated probe state:

```zig
pub const ProbeState = struct {
    candidates: []Candidate,     // remote candidates to try
    current_idx: usize,
    attempts_per_candidate: u8,  // 5
    interval_ms: u32,            // 200
    selected: ?std.net.Address,  // locked in on first authenticated recv

    pub fn nextProbeAddr(self: *ProbeState) ?std.net.Address;
    pub fn onAuthenticatedRecv(self: *ProbeState, from: std.net.Address) void;
    pub fn isComplete(self: *ProbeState) bool;
};
```

**Probe flow:**
1. Both sides gather candidates and exchange them via SSH signaling
2. Both sides enter probe mode: send encrypted heartbeat packets to each
   remote candidate, cycling through the list
3. When a side receives an authenticated packet, it records `from` as
   `selected` and stops probing
4. After probe completes (success or 3s timeout):
   - Success: assign `peer.addr = probe.selected`, send `ZMX_USE udp\n`
   - Failure: send `ZMX_USE ssh\n`, enter SSH fallback
5. Send `.Init` message ONLY after transport is selected (move from current
   location at `remote.zig:321`)

**Probe packets:** Use `transport.buildUnreliable(.heartbeat, ...)` — no
new packet format needed. The encrypted heartbeat serves as both connectivity
check and NAT hole-punch.

**Probe schedule:**
- 5 attempts per candidate at 200ms intervals
- Priority: IPv6 global → srflx → host/LAN
- Total window: ~3 seconds

### 2.4 Raw Datagram Receive Refactor

The current `Peer.recv()` calls `UdpSocket.recvFrom()` internally.
For STUN demux, extract the raw receive so the caller can inspect before
crypto decode:

```zig
// New: raw receive that returns before crypto
pub fn recvRaw(sock: *UdpSocket, buf: []u8) !?struct { data: []u8, from: std.net.Address };

// Existing: crypto decode + roaming (unchanged, but called after demux)
pub fn decodeAndUpdate(self: *Peer, raw: []const u8, from: std.net.Address, buf: []u8) !?[]u8;
```

---

## Phase 3 — NAT Keepalive

When no client is connected, the server's NAT binding expires (30s–5min
typically). The gateway must keep it alive.

**Mechanism:** Every 25 seconds, send a STUN Binding Request from the
session socket. This:
- Maintains the NAT binding via outbound traffic
- Re-discovers the mapping if the NAT reassigns it
- Costs ~20 bytes per request

**Integration:** Add `last_stun_keepalive_ns` to `Gateway` struct. In the
poll loop, after heartbeat check, fire STUN keepalive if 25s have elapsed.
Handle STUN response in the demux path (Phase 2 infrastructure).

If the mapping changes (detected via STUN response), log a warning. Future
work could re-signal the new mapping to the client.

---

## Implementation Plan

### New file: `src/nat.zig` (~200 lines)

- `StunState` — async STUN state machine (send, retry, parse response)
- `Candidate` struct and `CandidateType` enum
- `gatherHostCandidates()` — enumerate local interfaces, filter junk
- `isStunPacket()` — demux check for raw datagrams
- `ProbeState` — probe state machine for hole punching
- Unit tests for STUN message encode/decode (known byte sequences, no network)
- Unit tests for candidate filtering

### Modified: `src/remote.zig` (~150 lines changed)

- `connectRemote()`: return bootstrap handle keeping SSH child alive;
  add `ZMX_BOOTSTRAP=2` to SSH command; parse `ZMX_CONNECT2` or `ZMX_CONNECT`;
  enlarge read buffer to 4096; shell-escape interpolated values
- New `probeAndSelect()`: probe phase, send `ZMX_USE udp/ssh`
- `remoteAttach()`: defer `.Init` until after transport selection;
  transport abstraction in poll loop; SSH fallback branch

### Modified: `src/serve.zig` (~120 lines changed)

- `Gateway.init()`: conditional stdout close; gather server candidates;
  emit `ZMX_CONNECT2` when `ZMX_BOOTSTRAP=2`; read client candidates from
  stdin
- `Gateway.run()`: STUN demux in UDP read path; probe state machine;
  SSH fallback mode; STUN keepalive timer (Phase 3)
- Read `ZMX_USE` from stdin to determine mode

### Modified: `src/udp.zig` (~30 lines)

- Add `UdpSocket.bindEphemeral()` (bind port 0)
- Add `UdpSocket.getLocalPort()` via `getsockname()`
- Extract `recvRaw()` from `Peer.recv()` for STUN demux

### Test strategy

- Unit tests: STUN encode/decode against known byte sequences
- Unit tests: `ZMX_CONNECT2` JSON parse/emit round-trip
- Unit tests: candidate filtering (loopback, link-local, multicast rejected)
- Unit tests: `ProbeState` state machine transitions
- Unit tests: `StunState` retry logic
- Integration test: loopback probe (two sockets on localhost, simulates
  hole-punch)
- Manual test: two machines on different networks

---

## Security Considerations

- **Candidate exchange over SSH** is encrypted and authenticated by SSH.
  No additional risk. Private/Tailscale IPs are shared with the peer, which
  is acceptable since the peer is authenticated via SSH.
- **Shell injection** in the SSH command is a pre-existing bug. Fix by
  validating session names against `[a-zA-Z0-9._-]` and shell-escaping
  `TERM`/`COLORTERM`.
- **Spoofed STUN responses** are mitigated by checking source address matches
  configured STUN server AND txn_id matches the outstanding request.
- **JSON input** is bounded (4096 bytes max) and parsed with `std.json`.
  No streaming or unbounded allocation.

---

## Risks and Mitigations

| Risk | Severity | Mitigation |
|------|----------|-----------|
| STUN server unreachable | MED | Try multiple servers; proceed without srflx candidate; SSH fallback |
| Address-dependent NAT makes srflx inaccurate | HIGH | Treat srflx as hint; rely on peer-reflexive addr from authenticated packets |
| SSH pipe buffering adds latency | MED | IPC messages are small; no `TCP_NODELAY` control from this process |
| JSON bootstrap exceeds read buffer | HIGH | Enlarge to 4096 bytes; reject if larger |
| `peer.addr` oscillation during probing | HIGH | Dedicated `ProbeState`; assign `peer.addr` only after lock-in |
| STUN response arrives mixed with zmosh traffic | HIGH | Demux before crypto decode using magic cookie + source addr check |
| Old client connects to new server | MED | Capability negotiation via `ZMX_BOOTSTRAP` env var |

---

## Future Work (Deferred)

- **NAT-PMP / PCP / UPnP IGD** — automated port forwarding on consumer routers
- **TURN relay** — for symmetric NAT + blocked SSH scenarios
- **Candidate re-negotiation** — re-punch mid-session if NAT mapping changes
- **QUIC/WebTransport relay** on port 443 — ultimate firewall bypass
- **Persistent relay service** — hosted zmosh relay for zero-config NAT traversal
