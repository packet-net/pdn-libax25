// SPDX-License-Identifier: LGPL-3.0-or-later
//
// AX.25 sockaddr <-> callsign string helpers for the interposer.
//
// The 7-byte shifted callsign encoding is the standard AX.25 one; this is a
// small clean-room copy of the same logic in the libax25 crate's addr.rs (kept
// separate so the two cdylibs don't link each other). ve7fet libax25's
// axutils.c (GPL) was read as a reference only.

use libc::{c_char, c_int};

/// AF_AX25 (Linux family 3) and SOCK_SEQPACKET (5) — the pair we intercept.
pub const AF_AX25: i32 = 3;
pub const SOCK_SEQPACKET: i32 = 5;
/// setsockopt level for AX.25 options.
pub const SOL_AX25: i32 = 257;

// Kept for the full sockaddr shape and future digipeater-path support.
#[allow(dead_code)]
pub const AX25_MAX_DIGIS: usize = 8;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ax25Address {
    pub ax25_call: [c_char; 7],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockaddrAx25 {
    pub sax25_family: u16,
    pub sax25_call: Ax25Address,
    pub sax25_ndigis: c_int,
}

// Full sockaddr including digipeaters — retained for the digipeater path
// (TODO(N1)); currently only the leading fields are parsed via SockaddrAx25.
#[allow(dead_code)]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FullSockaddrAx25 {
    pub fsa_ax25: SockaddrAx25,
    pub fsa_digipeater: [Ax25Address; AX25_MAX_DIGIS],
}

/// Decode a 7-byte shifted callsign to "CALL" or "CALL-SSID".
pub fn decode(call: &[c_char; 7]) -> String {
    let mut s = String::with_capacity(10);
    for i in 0..6 {
        let c = ((call[i] as u8) >> 1) & 0x7F;
        if c != b' ' {
            s.push(c as char);
        }
    }
    let b6 = call[6] as u8;
    if b6 & 0x1E != 0 {
        s.push('-');
        s.push_str(&(((b6 >> 1) & 0x0F)).to_string());
    }
    s
}

/// Encode "CALL" or "CALL-SSID" to 7 shifted bytes. Invalid input yields an
/// all-spaces / SSID-0 address rather than failing (best-effort for the ABI).
pub fn encode(call: &str) -> [c_char; 7] {
    let mut buf = [0u8; 7];
    let (base, ssid) = match call.split_once('-') {
        Some((b, s)) => (b, s.parse::<u8>().unwrap_or(0) & 0x0F),
        None => (call, 0),
    };
    let bytes = base.as_bytes();
    for i in 0..6 {
        let c = if i < bytes.len() {
            bytes[i].to_ascii_uppercase()
        } else {
            b' '
        };
        buf[i] = c << 1;
    }
    buf[6] = (ssid << 1) & 0x1E;
    let mut out = [0 as c_char; 7];
    for i in 0..7 {
        out[i] = buf[i] as c_char;
    }
    out
}

/// Read the callsign from a raw `sockaddr` that is really a `sockaddr_ax25`
/// (or `full_sockaddr_ax25`). Returns None if the pointer/len is too small.
pub unsafe fn read_call(addr: *const libc::sockaddr, len: libc::socklen_t) -> Option<String> {
    if addr.is_null() {
        return None;
    }
    let need = std::mem::size_of::<u16>() + std::mem::size_of::<Ax25Address>();
    if (len as usize) < need {
        return None;
    }
    let sa = &*(addr as *const SockaddrAx25);
    Some(decode(&sa.sax25_call.ax25_call))
}

/// Write a callsign into a caller-provided `sockaddr` buffer as a
/// `sockaddr_ax25`, updating `*len`. Used by getsockname / getpeername.
pub unsafe fn write_call(
    addr: *mut libc::sockaddr,
    len: *mut libc::socklen_t,
    call: &str,
) {
    if addr.is_null() || len.is_null() {
        return;
    }
    let full_len = std::mem::size_of::<SockaddrAx25>();
    let avail = *len as usize;
    let sa = SockaddrAx25 {
        sax25_family: AF_AX25 as u16,
        sax25_call: Ax25Address { ax25_call: encode(call) },
        sax25_ndigis: 0,
    };
    let src = &sa as *const SockaddrAx25 as *const u8;
    let n = avail.min(full_len);
    std::ptr::copy_nonoverlapping(src, addr as *mut u8, n);
    *len = full_len as libc::socklen_t;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trips() {
        for call in ["M0LTE", "M0LTE-1", "GB7RDG-15", "G0ABC"] {
            let enc = encode(call);
            assert_eq!(decode(&enc), call);
        }
    }
}
