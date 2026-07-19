// SPDX-License-Identifier: AGPL-3.0-or-later

//! A client for the **RHPv2** wire protocol (Radio Host Protocol v2) over TCP,
//! as used by the pdn AX.25 packet-radio stack and compatible engines (xrouter).
//!
//! RHPv2 lets a host application drive an AX.25 stack over a local TCP socket:
//! open connected-mode links, stream data over them, accept inbound calls, and
//! send/receive connectionless UI frames — the packet-radio analogue of a
//! sockets API. [`RhpClient`] owns the connection and a background reader
//! thread; inbound data and async state changes are delivered through an
//! [`RhpEventSink`] you supply ([`BufferingSink`] is a ready-made one).
//!
//! This is a clean-room implementation from the RHPv2 wire spec (PWP-0222 /
//! PWP-0245) with the MIT reference client (`RhpV2.Client`) used as a model
//! only; pdn's own `Packet.Rhp2` is not linked. Note RHPv2 is a distinct,
//! wire-incompatible successor to RHP v1 — hence the `v2` in the crate name.
//!
//! # Wire summary
//! * **transport** — persistent TCP, default `127.0.0.1:9000` (env `PDN_RHP_ADDR`).
//! * **framing** — 2-byte big-endian length prefix + that many bytes of UTF-8 JSON.
//! * **`data` fields** — Latin-1 (one byte per code point), not base64.
//! * **ids** — requests carry a monotonic non-zero `id`; replies echo it; async
//!   pushes carry a per-connection `seqno` and no `id`.
//!
//! # Example
//! ```no_run
//! use rhpv2::{RhpClient, BufferingSink};
//!
//! let sink = BufferingSink::new();
//! let client = RhpClient::connect(sink.clone())?;
//!
//! // Place an outbound connected-mode call and stream some data.
//! let conn = client.open_connect("MYCALL-1", "REMOTE-1")?;
//! if client.wait_connected(conn.handle, None).is_ok() {
//!     client.send(conn.handle, b"hello over AX.25\r")?;
//! }
//! client.close(conn.handle)?;
//! # Ok::<(), rhpv2::RhpError>(())
//! ```

pub mod client;
pub mod codec;
pub mod errors;
pub mod framing;
pub mod messages;

pub use client::{
    AcceptInfo, BufferingSink, ConnPhase, NullSink, OpenResult, RhpClient, RhpError, RhpEventSink,
};
pub use errors::errcode_to_errno;
pub use messages::STATUS_CONNECTED;
