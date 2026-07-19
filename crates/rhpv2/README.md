# rhpv2

A Rust client for the **RHPv2** wire protocol (Radio Host Protocol v2) over TCP,
as used by the [pdn](https://github.com/packet-net) AX.25 packet-radio stack and
compatible engines (xrouter).

RHPv2 lets a host application drive an AX.25 stack over a local TCP socket — the
packet-radio analogue of a sockets API:

- open connected-mode (I-frame) links and stream data over them,
- listen for and accept inbound calls,
- send and receive connectionless UI frames (beacons, APRS, custom PIDs).

> **RHPv2, not v1.** RHP v1 was a different, wire-incompatible protocol. This
> crate speaks v2 only — hence the name.

## Usage

```rust,no_run
use rhpv2::{RhpClient, BufferingSink};

// A sink receives inbound data and async link-state changes on a background
// reader thread. BufferingSink just accumulates bytes per handle.
let sink = BufferingSink::new();
let client = RhpClient::connect(sink.clone())?;      // 127.0.0.1:9000 by default

// Outbound connected-mode call.
let conn = client.open_connect("MYCALL-1", "REMOTE-1")?;
if client.wait_connected(conn.handle, None).is_ok() {
    client.send(conn.handle, b"hello over AX.25\r")?;
}
client.close(conn.handle)?;
# Ok::<(), rhpv2::RhpError>(())
```

The server address can be overridden with the `PDN_RHP_ADDR` environment
variable, or by using [`RhpClient::connect_to`].

## Wire protocol

- **Transport** — persistent TCP, default `127.0.0.1:9000`.
- **Framing** — 2-byte big-endian length prefix + that many bytes of UTF-8 JSON.
- **`data` fields** — Latin-1 (one byte per code point), not base64.
- **Ids** — requests carry a monotonic non-zero `id`; replies echo it; async
  pushes carry a per-connection `seqno` and no `id`.

## Provenance

Clean-room implementation from the RHPv2 wire spec (PWP-0222 / PWP-0245), with
the MIT reference client (`RhpV2.Client`) used as a model only. pdn's own
`Packet.Rhp2` is not linked.

## Licence

AGPL-3.0-or-later. See [`COPYING`](https://github.com/packet-net/pdn-libax25/blob/main/COPYING).
