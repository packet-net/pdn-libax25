# ADR-001: PF_PACKET Monitoring Support

Status: **Proposed** (deferred pending design review)
Issue: [#12](https://github.com/packet-net/pdn-libax25/issues/12)

## Problem

Raw channel-monitoring apps (`listen`, `mheardd`, `axlisten`) open
`AF_PACKET`/`SOCK_RAW` sockets to sniff every frame on an AX.25 interface.
With the kernel `AF_AX25` stack removed (Linux 7.1), there is no
`ARPHRD_AX25` netdevice for these apps to attach to. The `LD_PRELOAD`
interposer handles `AF_AX25` connected/UI paths but has no answer for
`PF_PACKET` monitors.

## Options Considered

### Option 1: Synthesized frame feed (interposer)

Interpose `socket(AF_PACKET, SOCK_RAW, htons(ETH_P_AX25))`, create a
socketpair-backed fd, subscribe to the RHPv2 `custom`-mode UI stream, and
synthesize raw AX.25 frames (`[dest 7B][src 7B][0x03][PID][info...]`) for
each inbound datagram.

**Feasibility findings:**

- RHPv2 `custom` mode already delivers all UI frames heard on a bound port
  (promiscuous within that port). The `on_dgram` callback provides source,
  dest, and `[PID][info...]` — enough to reconstruct a raw UI frame.
- The existing `DgramPump` (in-memory queue + socketpair readiness signal)
  is directly reusable for frame delivery.
- A new `ioctl()` interposition point is needed for `SIOCGIFINDEX` /
  `SIOCGIFHWADDR` so monitoring apps can resolve the synthetic interface.
- Frame synthesis is straightforward: the 7-byte shifted callsign encoding
  already exists in `addr.rs`; the UI control byte is `0x03`.

**Key constraint:** Only UI frames are visible. Connected-mode (I-frame)
traffic is not exposed by RHPv2 custom mode. This means `mheardd` will see
UI/beacon traffic but not connected sessions it doesn't own. Whether this is
acceptable depends on the operator's monitoring needs.

### Option 2: Out-of-tree kernel module

A small tap/netdevice that re-exposes an `ARPHRD_AX25`-like interface fed by
the pdn node.

**Rejected:** Reintroduces a kernel dependency the project is explicitly
trying to shed. Also requires matching the kernel's AX.25 frame delivery
semantics exactly (including connected-mode visibility), which is a larger
surface than the interposer approach.

### Option 3: Separate monitor tool (no interposition)

A standalone tool that subscribes to the node's monitor stream directly
(no `LD_PRELOAD`). Cleaner separation, but doesn't help existing apps
(`mheardd`, `listen`) that expect `AF_PACKET`.

## Proposed Architecture (if Option 1 is pursued)

1. **`FdKind` enum** replaces `FdState.dgram: bool` — variants:
   `Seqpacket`, `Dgram`, `Monitor`.

2. **`ports.rs`** (new module): minimal axports parser assigning synthetic
   1-based ifindices. Fallback env vars (`AX25_PORT_CALL`, `AX25_PORT_NAME`)
   for single-port/CI setups.

3. **`addr.rs`**: `SockaddrLl` struct, `synthesize_raw_ax25_frame()`,
   `write_sockaddr_ll()`.

4. **`real.rs`**: add `ioctl` to the dlsym table.

5. **`lib.rs`**: intercept `socket(AF_PACKET, SOCK_RAW, ETH_P_AX25)`,
   `ioctl(SIOCGIFINDEX/SIOCGIFHWADDR)`, `bind(sockaddr_ll)`,
   `read()`/`recvfrom()` on monitor fds. Write path returns `EOPNOTSUPP`.

6. **Datagram struct** gains a `dest` field (currently discarded in
   `InterposeSink::on_dgram`).

7. **E2E test**: mock server pushes a dgram after bind; test reads from the
   PF_PACKET fd and asserts the raw frame layout.

## Open Questions

- Is UI-only visibility acceptable, or does monitoring need connected-mode
  frames too? If the latter, RHPv2 needs a new push type (the protocol's
  forward-compat design allows this — unknown push types are silently
  ignored by old clients).
- Should the monitor see frames from all ports simultaneously, or one port
  per socket (matching kernel `bind()` semantics)?
- Is `ioctl` interposition too invasive for the `LD_PRELOAD` surface? An
  alternative is requiring apps to use `if_nametoindex()` (which we could
  interpose more narrowly).
- Should this live in the interposer at all, or as a separate small daemon
  that creates a TUN-like feed? (Overlaps with Option 3.)

## References

- `samples/ax25_ui_monitor.c` — existing AF_AX25 SOCK_DGRAM monitor (works today)
- `crates/ax25-interpose/src/state.rs` — DgramPump architecture
- `crates/rhpv2/src/client.rs:61` — `on_dgram` callback (promiscuous UI)
- pdn `docs/network-integration-adr.md` §9 (interop rationale)
