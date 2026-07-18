// SPDX-License-Identifier: LGPL-3.0-or-later
//
// RHPv2 message shapes.
//
// Requests are typed structs so serde serialises fields in declaration order,
// putting `type` first on the wire as the spec requires (serde_json's
// `json!` map would otherwise reorder keys). Replies and async pushes are
// parsed loosely from `serde_json::Value` because real xrouter emits several
// case/shape variants (errCode vs errcode, port as string vs int, etc. — see
// rhp2lib-net/docs/protocol.md "Spec quirks").

use serde::Serialize;

/// `flags:128` (Active) on an `open` — mandatory to perform a connect.
pub const OPEN_FLAG_ACTIVE: u32 = 128;
/// `flags:0` (Passive) — a listener.
pub const OPEN_FLAG_PASSIVE: u32 = 0;

/// RHP `status` StatusFlags: the link is up (SABM/UA complete). An outbound
/// `open` (connect) reports success by a later async `status` push carrying this
/// bit — the openReply alone only means the request was accepted, not that the
/// AX.25 link came up.
pub const STATUS_CONNECTED: i64 = 0x02;

/// Max `send.data` characters per request (real xrouter drops sends above ~8KB).
pub const MAX_SEND_CHUNK: usize = 8100;

// ----------------------------------------------------------------------------
// Requests (client -> server). `type` is declared first in every struct.
// ----------------------------------------------------------------------------

#[derive(Serialize)]
pub struct OpenReq<'a> {
    #[serde(rename = "type")]
    pub typ: &'static str, // "open"
    pub id: u64,
    pub pfam: &'a str, // "ax25"
    pub mode: &'a str, // "stream"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<&'a str>,
    pub local: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<&'a str>,
    pub flags: u32,
}

#[derive(Serialize)]
pub struct SendReq<'a> {
    #[serde(rename = "type")]
    pub typ: &'static str, // "send"
    pub id: u64,
    pub handle: u64,
    pub data: &'a str, // Latin-1 wire string (see codec.rs)
}

#[derive(Serialize)]
pub struct CloseReq {
    #[serde(rename = "type")]
    pub typ: &'static str, // "close"
    pub id: u64,
    pub handle: u64,
}

#[derive(Serialize)]
pub struct SocketReq<'a> {
    #[serde(rename = "type")]
    pub typ: &'static str, // "socket"
    pub id: u64,
    pub pfam: &'a str,
    pub mode: &'a str,
}

#[derive(Serialize)]
pub struct BindReq<'a> {
    #[serde(rename = "type")]
    pub typ: &'static str, // "bind"
    pub id: u64,
    pub handle: u64,
    pub local: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<&'a str>,
}

#[derive(Serialize)]
pub struct ListenReq {
    #[serde(rename = "type")]
    pub typ: &'static str, // "listen"
    pub id: u64,
    pub handle: u64,
    pub flags: u32,
}

#[derive(Serialize)]
pub struct AuthReq<'a> {
    #[serde(rename = "type")]
    pub typ: &'static str, // "auth"
    pub id: u64,
    pub user: &'a str,
    pub pass: &'a str,
}

// ----------------------------------------------------------------------------
// Reply / push accessors over a parsed serde_json::Value.
// ----------------------------------------------------------------------------

/// A decoded reply or async-push frame.
#[derive(Debug, Clone)]
pub struct Frame {
    pub value: serde_json::Value,
}

impl Frame {
    pub fn parse(bytes: &[u8]) -> serde_json::Result<Frame> {
        Ok(Frame {
            value: serde_json::from_slice(bytes)?,
        })
    }

    /// The `type` discriminator, or "" if missing.
    pub fn typ(&self) -> &str {
        self.value.get("type").and_then(|v| v.as_str()).unwrap_or("")
    }

    /// The correlation `id`, if present (replies echo it; pushes omit it).
    pub fn id(&self) -> Option<u64> {
        self.value.get("id").and_then(|v| v.as_u64())
    }

    /// The socket `handle`, if present.
    pub fn handle(&self) -> Option<u64> {
        self.value.get("handle").and_then(|v| v.as_u64())
    }

    /// The `child` handle on an `accept` push.
    pub fn child(&self) -> Option<u64> {
        self.value.get("child").and_then(|v| v.as_u64())
    }

    /// Per-connection `seqno` on an async push, if present.
    pub fn seqno(&self) -> Option<u64> {
        self.value.get("seqno").and_then(|v| v.as_u64())
    }

    /// `errCode` (reads both the capitalised wire form and the lowercase spec
    /// form). Missing => 0 (Ok).
    pub fn errcode(&self) -> i64 {
        self.value
            .get("errCode")
            .or_else(|| self.value.get("errcode"))
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
    }

    /// StatusFlags on a `status` push. Real engines carry the bitfield in a
    /// `flags` (or `status`) field; the interim plumbing reused `errCode`, so we
    /// read `flags`/`status` first and fall back to `errCode` for compatibility.
    pub fn status_flags(&self) -> i64 {
        self.value
            .get("flags")
            .or_else(|| self.value.get("status"))
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| self.errcode())
    }

    /// `errText`, reading both case variants.
    pub fn errtext(&self) -> Option<&str> {
        self.value
            .get("errText")
            .or_else(|| self.value.get("errtext"))
            .and_then(|v| v.as_str())
    }

    /// The `data` wire string on a `recv`/`send` frame.
    pub fn data_str(&self) -> Option<&str> {
        self.value.get("data").and_then(|v| v.as_str())
    }

    /// The `remote` address string (on `accept`).
    pub fn remote(&self) -> Option<&str> {
        self.value.get("remote").and_then(|v| v.as_str())
    }

    /// The `local` address string (on `accept`).
    pub fn local(&self) -> Option<&str> {
        self.value.get("local").and_then(|v| v.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_request_serialises_type_first_and_omits_none() {
        let req = OpenReq {
            typ: "open",
            id: 7,
            pfam: "ax25",
            mode: "stream",
            port: None,
            local: "M0LTE",
            remote: Some("GB7RDG"),
            flags: OPEN_FLAG_ACTIVE,
        };
        let s = serde_json::to_string(&req).unwrap();
        // `type` must be the first key on the wire.
        assert!(s.starts_with("{\"type\":\"open\""), "got: {s}");
        // `port` (None) must be omitted.
        assert!(!s.contains("port"), "got: {s}");
        assert!(s.contains("\"flags\":128"));
        assert!(s.contains("\"remote\":\"GB7RDG\""));
    }

    #[test]
    fn reply_reads_capitalised_errcode() {
        let f = Frame::parse(br#"{"type":"openReply","id":7,"handle":42,"errCode":0,"errText":"Ok"}"#)
            .unwrap();
        assert_eq!(f.typ(), "openReply");
        assert_eq!(f.id(), Some(7));
        assert_eq!(f.handle(), Some(42));
        assert_eq!(f.errcode(), 0);
        assert_eq!(f.errtext(), Some("Ok"));
    }

    #[test]
    fn push_has_seqno_and_no_id() {
        let f = Frame::parse(br#"{"type":"recv","handle":42,"data":"hi","seqno":3}"#).unwrap();
        assert_eq!(f.id(), None);
        assert_eq!(f.seqno(), Some(3));
        assert_eq!(f.data_str(), Some("hi"));
    }

    #[test]
    fn status_flags_reads_flags_then_falls_back_to_errcode() {
        // Explicit `flags` field wins.
        let f = Frame::parse(br#"{"type":"status","handle":7,"flags":2}"#).unwrap();
        assert_eq!(f.status_flags(), STATUS_CONNECTED);
        // A `status` field is also honoured.
        let f = Frame::parse(br#"{"type":"status","handle":7,"status":2}"#).unwrap();
        assert_eq!(f.status_flags(), STATUS_CONNECTED);
        // Legacy plumbing carried the bitfield in errCode.
        let f = Frame::parse(br#"{"type":"status","handle":7,"errCode":2}"#).unwrap();
        assert_eq!(f.status_flags(), STATUS_CONNECTED);
    }
}
