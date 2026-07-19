// SPDX-License-Identifier: AGPL-3.0-or-later
//
// AX.25 callsign <-> 7-byte shifted network encoding.
//
// This is a clean-room reimplementation of the standard AX.25 address encoding.
// It is functionally equivalent to ve7fet libax25's axutils.c (GPL:
// ax25_aton_entry / ax25_aton / ax25_ntoa / ax25_cmp / ax25_validate), which
// was READ as a semantic reference only. The encoding itself is the trivial,
// standard AX.25 one (each of 6 callsign chars shifted left one bit, 7th byte =
// SSID << 1 with the control/reserved/last bits left clear) — not copied.

use libc::{c_char, c_int};
use std::cell::RefCell;
use std::ffi::CStr;

/// AF_AX25 address family (Linux `AF_AX25` == 3).
pub const AF_AX25: u16 = 3;
/// Maximum number of digipeaters in a `full_sockaddr_ax25`.
pub const AX25_MAX_DIGIS: usize = 8;

/// `ax25_address`: 6 callsign chars + SSID byte, all shifted. Matches the C
/// layout in `<netax25/ax25.h>`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct Ax25Address {
    pub ax25_call: [c_char; 7],
}

/// `struct sockaddr_ax25` from `<netax25/ax25.h>`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SockaddrAx25 {
    pub sax25_family: u16, // sa_family_t
    pub sax25_call: Ax25Address,
    pub sax25_ndigis: c_int,
}

/// `struct full_sockaddr_ax25` from `<netax25/ax25.h>`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FullSockaddrAx25 {
    pub fsa_ax25: SockaddrAx25,
    pub fsa_digipeater: [Ax25Address; AX25_MAX_DIGIS],
}

// ----------------------------------------------------------------------------
// Pure Rust core (unit tested), used by the FFI wrappers below.
// ----------------------------------------------------------------------------

/// Encode one callsign token ("CALL" or "CALL-SSID") into 7 shifted bytes.
/// Returns `None` on an invalid symbol or out-of-range SSID (like upstream's
/// -1 return).
pub(crate) fn encode_entry(name: &str) -> Option<[u8; 7]> {
    let bytes = name.as_bytes();
    let mut buf = [0u8; 7];
    let mut ct = 0usize;
    let mut idx = 0usize;

    while ct < 6 {
        if idx >= bytes.len() {
            break;
        }
        let c = bytes[idx].to_ascii_uppercase();
        if c == b'-' {
            break;
        }
        if !c.is_ascii_alphanumeric() {
            return None;
        }
        buf[ct] = c << 1;
        idx += 1;
        ct += 1;
    }

    // Space-pad the remaining callsign positions (' ' << 1 == 0x40).
    while ct < 6 {
        buf[ct] = b' ' << 1;
        ct += 1;
    }

    // Optional SSID: upstream skips exactly one char (the '-') then scans an int.
    let mut ssid: i32 = 0;
    if idx < bytes.len() {
        idx += 1; // skip the '-' (or trailing char, matching upstream quirk)
        match scan_int(&name[idx.min(name.len())..]) {
            Some(v) if (0..=15).contains(&v) => ssid = v,
            _ => return None,
        }
    }

    // 7th byte: SSID in bits 1..4; control/reserved/last bits left clear.
    buf[6] = (((ssid + b'0' as i32) << 1) & 0x1E) as u8;
    Some(buf)
}

/// Minimal `sscanf("%d")` clone: optional leading spaces, optional sign, digits.
fn scan_int(s: &str) -> Option<i32> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() && (b[i] == b' ' || b[i] == b'\t') {
        i += 1;
    }
    let mut neg = false;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        neg = b[i] == b'-';
        i += 1;
    }
    let start = i;
    let mut val: i64 = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        val = val * 10 + (b[i] - b'0') as i64;
        i += 1;
    }
    if i == start {
        return None; // no digits
    }
    Some(if neg { -(val as i32) } else { val as i32 })
}

/// Decode 7 shifted bytes back to "CALL" or "CALL-SSID" (SSID 0 is omitted).
pub(crate) fn decode_entry(call: &[u8; 7]) -> String {
    let mut s = String::with_capacity(10);
    for n in 0..6 {
        let c = (call[n] >> 1) & 0x7F;
        if c != b' ' {
            s.push(c as char);
        }
    }
    // Nonzero SSID bits -> print "-<ssid>".
    if call[6] & 0x1E != 0 {
        let ssid = (call[6] >> 1) & 0x0F;
        s.push('-');
        s.push_str(&ssid.to_string());
    }
    s
}

/// Compare two shifted callsigns: 0 identical, 1 differ, 2 only SSID differs.
pub(crate) fn cmp_entry(a: &[u8; 7], b: &[u8; 7]) -> i32 {
    for i in 0..6 {
        if (a[i] & 0xFE) != (b[i] & 0xFE) {
            return 1;
        }
    }
    if (a[6] & 0x1E) != (b[6] & 0x1E) {
        return 2;
    }
    0
}

/// Validate a shifted callsign: the 6 decoded chars must be alnum or space.
pub(crate) fn validate_entry(call: &[u8; 7]) -> bool {
    for i in 0..6 {
        let c = (call[i] >> 1) & 0x7F;
        let ok = c.is_ascii_uppercase() || c.is_ascii_digit() || c == b' ';
        if !ok {
            return false;
        }
    }
    true
}

fn as_i8(b: [u8; 7]) -> [c_char; 7] {
    let mut out = [0 as c_char; 7];
    for i in 0..7 {
        out[i] = b[i] as c_char;
    }
    out
}

fn as_u8(b: &[c_char; 7]) -> [u8; 7] {
    let mut out = [0u8; 7];
    for i in 0..7 {
        out[i] = b[i] as u8;
    }
    out
}

// ----------------------------------------------------------------------------
// Exported data symbols.
// ----------------------------------------------------------------------------

/// The special "null" AX.25 address (all spaces, SSID 0), as in axutils.c.
#[no_mangle]
pub static null_ax25_address: Ax25Address = Ax25Address {
    ax25_call: [0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x00],
};

/// Library version string (`extern char libax25_version[]`).
#[no_mangle]
pub static libax25_version: [u8; 18] = {
    let src = b"pdn-libax25 0.1.0\0";
    let mut a = [0u8; 18];
    let mut i = 0;
    while i < src.len() {
        a[i] = src[i];
        i += 1;
    }
    a
};

// ----------------------------------------------------------------------------
// FFI wrappers (C ABI).
// ----------------------------------------------------------------------------

thread_local! {
    // Static return buffer for ax25_ntoa, matching upstream's "subsequent calls
    // destroy previous" contract but made thread-safe with thread-local storage.
    static NTOA_BUF: RefCell<[c_char; 16]> = const { RefCell::new([0; 16]) };
}

/// `int ax25_aton_entry(const char *name, char *buf)` — -1 on error, 0 on ok.
#[no_mangle]
pub unsafe extern "C" fn ax25_aton_entry(name: *const c_char, buf: *mut c_char) -> c_int {
    if name.is_null() || buf.is_null() {
        return -1;
    }
    let Ok(name) = CStr::from_ptr(name).to_str() else {
        return -1;
    };
    match encode_entry(name) {
        Some(entry) => {
            let dst = std::slice::from_raw_parts_mut(buf, 7);
            for i in 0..7 {
                dst[i] = entry[i] as c_char;
            }
            0
        }
        None => -1,
    }
}

/// `char *ax25_ntoa(const ax25_address *a)` — pointer to a per-thread buffer.
#[no_mangle]
pub unsafe extern "C" fn ax25_ntoa(a: *const Ax25Address) -> *mut c_char {
    NTOA_BUF.with(|cell| {
        let ptr = cell.as_ptr() as *mut c_char;
        if a.is_null() {
            *ptr = 0;
            return ptr;
        }
        let call = as_u8(&(*a).ax25_call);
        let text = decode_entry(&call);
        let bytes = text.as_bytes();
        let n = bytes.len().min(15);
        let dst = std::slice::from_raw_parts_mut(ptr, 16);
        for i in 0..n {
            dst[i] = bytes[i] as c_char;
        }
        dst[n] = 0;
        ptr
    })
}

/// `int ax25_cmp(const ax25_address *a, const ax25_address *b)`.
#[no_mangle]
pub unsafe extern "C" fn ax25_cmp(a: *const Ax25Address, b: *const Ax25Address) -> c_int {
    if a.is_null() || b.is_null() {
        return 1;
    }
    cmp_entry(&as_u8(&(*a).ax25_call), &as_u8(&(*b).ax25_call))
}

/// `int ax25_validate(const char *call)` — call is in shifted 7-byte format.
#[no_mangle]
pub unsafe extern "C" fn ax25_validate(call: *const c_char) -> c_int {
    if call.is_null() {
        return 0; // FALSE
    }
    let raw = std::slice::from_raw_parts(call as *const u8, 7);
    let mut arr = [0u8; 7];
    arr.copy_from_slice(raw);
    if validate_entry(&arr) {
        1
    } else {
        0
    }
}

/// `int ax25_aton(const char *call, struct full_sockaddr_ax25 *sax)`.
#[no_mangle]
pub unsafe extern "C" fn ax25_aton(call: *const c_char, sax: *mut FullSockaddrAx25) -> c_int {
    if call.is_null() || sax.is_null() {
        return -1;
    }
    let Ok(call) = CStr::from_ptr(call).to_str() else {
        return -1;
    };
    let tokens: Vec<&str> = call.split_whitespace().collect();
    fill_sax(&tokens, sax)
}

/// `int ax25_aton_arglist(const char *call[], struct full_sockaddr_ax25 *sax)`.
#[no_mangle]
pub unsafe extern "C" fn ax25_aton_arglist(
    call: *const *const c_char,
    sax: *mut FullSockaddrAx25,
) -> c_int {
    if call.is_null() || sax.is_null() {
        return -1;
    }
    let mut tokens: Vec<&str> = Vec::new();
    let mut i = 0isize;
    loop {
        let p = *call.offset(i);
        if p.is_null() {
            break;
        }
        match CStr::from_ptr(p).to_str() {
            Ok(s) => tokens.push(s),
            Err(_) => return -1,
        }
        i += 1;
    }
    fill_sax(&tokens, sax)
}

/// Shared tail of ax25_aton / ax25_aton_arglist: place callsign + digipeaters.
unsafe fn fill_sax(tokens: &[&str], sax: *mut FullSockaddrAx25) -> c_int {
    // Match upstream: an empty input still yields one (all-spaces) entry.
    let owned;
    let tokens: &[&str] = if tokens.is_empty() {
        owned = [""];
        &owned
    } else {
        tokens
    };

    let mut n = 0usize; // placements so far (call counts as the first)
    for &tok in tokens {
        // Skip an optional "V"/"VIA" separator immediately after the callsign.
        if n == 1 && (tok.eq_ignore_ascii_case("v") || tok.eq_ignore_ascii_case("via")) {
            continue;
        }
        let entry = match encode_entry(tok) {
            Some(e) => e,
            None => return -1,
        };
        if n == 0 {
            (*sax).fsa_ax25.sax25_call.ax25_call = as_i8(entry);
        } else {
            let di = n - 1;
            if di >= AX25_MAX_DIGIS {
                break;
            }
            (*sax).fsa_digipeater[di].ax25_call = as_i8(entry);
        }
        n += 1;
        if n > AX25_MAX_DIGIS {
            break; // callsign + up to 8 digipeaters
        }
    }

    (*sax).fsa_ax25.sax25_ndigis = n as c_int - 1;
    (*sax).fsa_ax25.sax25_family = AF_AX25;
    std::mem::size_of::<FullSockaddrAx25>() as c_int
}

/// `char *strupr(char *s)`.
#[no_mangle]
pub unsafe extern "C" fn strupr(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return s;
    }
    let mut p = s;
    while *p != 0 {
        let c = *p as u8;
        *p = c.to_ascii_uppercase() as c_char;
        p = p.add(1);
    }
    s
}

/// `char *strlwr(char *s)`.
#[no_mangle]
pub unsafe extern "C" fn strlwr(s: *mut c_char) -> *mut c_char {
    if s.is_null() {
        return s;
    }
    let mut p = s;
    while *p != 0 {
        let c = *p as u8;
        *p = c.to_ascii_lowercase() as c_char;
        p = p.add(1);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(call: &str) -> String {
        let e = encode_entry(call).expect("encode");
        decode_entry(&e)
    }

    #[test]
    fn m0lte_1_round_trips() {
        let e = encode_entry("M0LTE-1").unwrap();
        // 'M'<<1, '0'<<1, 'L'<<1, 'T'<<1, 'E'<<1, ' '<<1, then SSID 1 << 1.
        assert_eq!(
            e,
            [
                b'M' << 1,
                b'0' << 1,
                b'L' << 1,
                b'T' << 1,
                b'E' << 1,
                b' ' << 1,
                (1u8 << 1),
            ]
        );
        assert_eq!(decode_entry(&e), "M0LTE-1");
    }

    #[test]
    fn ssid_zero_is_omitted_on_decode() {
        assert_eq!(roundtrip("M0LTE"), "M0LTE");
        assert_eq!(roundtrip("M0LTE-0"), "M0LTE");
    }

    #[test]
    fn high_ssid_round_trips() {
        assert_eq!(roundtrip("GB7RDG-15"), "GB7RDG-15");
        assert_eq!(roundtrip("GB7RDG-10"), "GB7RDG-10");
    }

    #[test]
    fn six_char_callsign_round_trips() {
        assert_eq!(roundtrip("GB7RDG"), "GB7RDG");
    }

    #[test]
    fn invalid_symbol_rejected() {
        assert!(encode_entry("M0*TE").is_none());
        assert!(encode_entry("M0LTE-16").is_none()); // SSID out of range
        assert!(encode_entry("M0LTE-99").is_none());
    }

    #[test]
    fn cmp_detects_ssid_only_difference() {
        let a = encode_entry("M0LTE-1").unwrap();
        let b = encode_entry("M0LTE-2").unwrap();
        let c = encode_entry("M0LTE-1").unwrap();
        let d = encode_entry("G0ABC-1").unwrap();
        assert_eq!(cmp_entry(&a, &c), 0);
        assert_eq!(cmp_entry(&a, &b), 2);
        assert_eq!(cmp_entry(&a, &d), 1);
    }

    #[test]
    fn validate_accepts_real_and_rejects_garbage() {
        assert!(validate_entry(&encode_entry("M0LTE-1").unwrap()));
        // Byte with a low bit set that decodes to a control char is invalid.
        let bad = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00];
        assert!(!validate_entry(&bad));
    }

    #[test]
    fn null_address_decodes_empty() {
        let null = as_u8(&null_ax25_address.ax25_call);
        assert_eq!(decode_entry(&null), "");
    }
}
