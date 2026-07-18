// SPDX-License-Identifier: LGPL-3.0-or-later
//
// `rhp` — a client for pdn's RHPv2 wire protocol over loopback TCP.
//
// This crate is shared internally by `libax25` and `ax25-interpose`. It is a
// clean-room implementation from the RHPv2 wire spec (rhp2lib-net/docs/
// protocol.md, PWP-0222 / PWP-0245) and the MIT reference client
// (rhp2lib-net/src/RhpV2.Client) used as a model only — pdn's own
// `Packet.Rhp2` (GPL/AGPL) is NOT linked.
//
// Wire summary:
//   * transport: persistent TCP, default 127.0.0.1:9000 (env PDN_RHP_ADDR).
//   * framing: 2-byte big-endian length + that many bytes of UTF-8 JSON.
//   * `data` fields are Latin-1 (one byte per code point), not base64.
//   * requests carry a monotonic non-zero `id`; replies echo it; async pushes
//     carry a per-connection `seqno` and no `id`.

pub mod client;
pub mod codec;
pub mod errors;
pub mod framing;
pub mod messages;

pub use client::{BufferingSink, NullSink, OpenResult, RhpClient, RhpError, RhpEventSink};
pub use errors::errcode_to_errno;
