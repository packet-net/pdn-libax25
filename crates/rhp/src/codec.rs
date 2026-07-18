// SPDX-License-Identifier: LGPL-3.0-or-later
//
// RHPv2 `data` field codec.
//
// The RHPv2 wire carries binary payloads in the JSON `data` string using a
// Latin-1 (ISO-8859-1) mapping: each payload byte 0x00..=0xFF maps to exactly
// one Unicode code point U+0000..=U+00FF, and vice versa. This is NOT base64.
// serde_json handles the JSON escaping of control characters on top of this.
//
// This mirrors the reference MIT client's RhpDataEncoding (rhp2lib-net,
// src/RhpV2.Client/Protocol/RhpDataEncoding.cs) which uses Encoding.Latin1.

/// Encode raw bytes as a Latin-1 wire string (one code point per byte).
pub fn to_wire_string(bytes: &[u8]) -> String {
    // `u8 as char` yields U+0000..=U+00FF, i.e. the Latin-1 code point.
    bytes.iter().map(|&b| b as char).collect()
}

/// Decode a Latin-1 wire string back to raw bytes (one byte per code point).
///
/// Well-formed RHP `data` only ever contains code points 0x00..=0xFF. If a
/// peer sends a code point above 0xFF (out of spec), we take the low byte,
/// keeping the decoder total and panic-free on the C-ABI boundary.
pub fn from_wire_string(s: &str) -> Vec<u8> {
    s.chars().map(|c| c as u8).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_all_256_byte_values() {
        let bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let wire = to_wire_string(&bytes);
        // One code point per byte.
        assert_eq!(wire.chars().count(), 256);
        let back = from_wire_string(&wire);
        assert_eq!(back, bytes);
    }

    #[test]
    fn round_trips_awkward_control_and_high_bytes() {
        // 0x00 (NUL), 0x0D (CR), 0x0A (LF), 0x22 ("), 0x5C (\), 0x80, 0xFF.
        for &b in &[0x00u8, 0x0D, 0x0A, 0x22, 0x5C, 0x7F, 0x80, 0xA0, 0xFF] {
            let wire = to_wire_string(&[b]);
            assert_eq!(wire.chars().count(), 1);
            assert_eq!(from_wire_string(&wire), vec![b]);
        }
    }

    #[test]
    fn survives_json_serialization_round_trip() {
        // The real path pushes the wire string through serde_json, which
        // escapes control characters. Round-trip through a JSON value to prove
        // NUL/CR/quote/backslash and high bytes survive intact.
        let bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        let wire = to_wire_string(&bytes);
        let json = serde_json::to_string(&serde_json::json!({ "data": wire })).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let decoded = from_wire_string(parsed["data"].as_str().unwrap());
        assert_eq!(decoded, bytes);
    }
}
