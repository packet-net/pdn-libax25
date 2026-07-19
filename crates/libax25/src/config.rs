// SPDX-License-Identifier: AGPL-3.0-or-later
//
// axports parsing.
//
// Clean-room reimplementation of ve7fet libax25's axconfig.c (GPL, READ as a
// semantic reference only). THE CRITICAL DIFFERENCE: upstream (axconfig.c lines
// ~302-373) walks /proc/net/dev, does an SIOCGIFHWADDR ioctl on every
// interface, and keeps only axports lines whose callsign matches an *up*
// ARPHRD_AX25 kernel netdevice. Since the AF_AX25 kernel stack is gone (Linux
// 7.1) there are no such netdevices, so upstream would return 0 active ports
// and every app would refuse to start. We OMIT the netdevice check entirely:
// every well-formed axports line is an active port, routed via pdn RHP instead
// of a kernel interface.
//
// axports line format:  name callsign speed paclen window description

use crate::addr::{encode_entry, Ax25Address};
use libc::{c_char, c_int};
use std::ffi::CString;
use std::sync::{Mutex, OnceLock};

/// Default axports path (override with env `AX25_AXPORTS` for testing).
const DEFAULT_AXPORTS: &str = "/etc/ax25/axports";

/// A parsed axports entry (pure-Rust intermediate; unit tested).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ParsedPort {
    pub name: String,
    pub call: String, // uppercased, trailing "-0" stripped (upstream behaviour)
    pub baud: i32,
    pub paclen: i32,
    pub window: i32,
    pub description: String,
}

/// Parse the contents of an axports file. Invalid lines are skipped (like
/// upstream, which prints a warning and drops the line). NO netdevice filter.
pub(crate) fn parse_axports(content: &str) -> Vec<ParsedPort> {
    let mut out: Vec<ParsedPort> = Vec::new();

    for raw in content.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let mut rest = trimmed;
        let name = pop_token(&mut rest);
        let call = pop_token(&mut rest);
        let baud = pop_token(&mut rest);
        let paclen = pop_token(&mut rest);
        let window = pop_token(&mut rest);
        let desc = rest.trim();

        let (name, call, baud, paclen, window) = match (name, call, baud, paclen, window) {
            (Some(n), Some(c), Some(b), Some(p), Some(w)) => (n, c, b, p, w),
            _ => continue, // missing required fields
        };
        if desc.is_empty() {
            continue; // upstream requires a description field
        }

        // Validate numerics like upstream: baud >= 0, paclen > 0, window > 0.
        let baud: i32 = baud.parse().unwrap_or(-1);
        let paclen: i32 = paclen.parse().unwrap_or(0);
        let window: i32 = window.parse().unwrap_or(0);
        if baud < 0 || paclen <= 0 || window <= 0 {
            continue;
        }

        // Uppercase the callsign; strip a trailing "-0" (upstream axconfig.c).
        let mut call = call.to_ascii_uppercase();
        if let Some(pos) = call.find("-0") {
            call.truncate(pos);
        }

        // Reject a line whose callsign is not encodable (invalid symbol/SSID).
        if encode_entry(&call).is_none() {
            continue;
        }

        // Skip duplicate port names / callsigns, like upstream.
        if out.iter().any(|p| p.name.eq_ignore_ascii_case(name) || p.call == call) {
            continue;
        }

        out.push(ParsedPort {
            name: name.to_string(),
            call,
            baud,
            paclen,
            window,
            description: desc.to_string(),
        });
    }

    out
}

fn pop_token<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let s = rest.trim_start();
    if s.is_empty() {
        *rest = s;
        return None;
    }
    let end = s.find(|c: char| c == ' ' || c == '\t').unwrap_or(s.len());
    let (tok, tail) = s.split_at(end);
    *rest = tail;
    Some(tok)
}

// ----------------------------------------------------------------------------
// Global loaded-port table (C-string backed for stable pointer returns).
// ----------------------------------------------------------------------------

struct CPort {
    name: CString,
    call: CString,
    device: CString,
    description: CString,
    name_s: String,
    call_s: String,
    device_s: String,
    baud: c_int,
    window: c_int,
    paclen: c_int,
}

fn ports() -> &'static Mutex<Vec<CPort>> {
    static PORTS: OnceLock<Mutex<Vec<CPort>>> = OnceLock::new();
    PORTS.get_or_init(|| Mutex::new(Vec::new()))
}

fn star() -> *const c_char {
    static STAR: OnceLock<CString> = OnceLock::new();
    STAR.get_or_init(|| CString::new("*").unwrap()).as_ptr()
}

fn axports_path() -> String {
    std::env::var("AX25_AXPORTS").unwrap_or_else(|_| DEFAULT_AXPORTS.to_string())
}

// ----------------------------------------------------------------------------
// FFI exports.
// ----------------------------------------------------------------------------

/// `int ax25_config_load_ports(void)` — parse axports, return active-port count.
///
/// Idempotent: on a second call it returns the already-loaded count without
/// reloading, so previously-returned `char *` pointers stay valid.
#[no_mangle]
pub extern "C" fn ax25_config_load_ports() -> c_int {
    let mut guard = ports().lock().unwrap();
    if !guard.is_empty() {
        return guard.len() as c_int;
    }

    let content = match std::fs::read_to_string(axports_path()) {
        Ok(c) => c,
        Err(_) => return 0,
    };

    for p in parse_axports(&content) {
        // No kernel netdevice exists; use the port name as the device label.
        let device = p.name.clone();
        guard.push(CPort {
            name: CString::new(p.name.clone()).unwrap_or_default(),
            call: CString::new(p.call.clone()).unwrap_or_default(),
            device: CString::new(device.clone()).unwrap_or_default(),
            description: CString::new(p.description.clone()).unwrap_or_default(),
            name_s: p.name,
            call_s: p.call,
            device_s: device,
            baud: p.baud,
            window: p.window,
            paclen: p.paclen,
        });
    }

    guard.len() as c_int
}

/// is_same_call: compare two callsign strings ignoring case and treating a
/// missing SSID as equivalent to "-0" (mirrors upstream axconfig.c).
fn is_same_call(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> String {
        let s = s.to_ascii_uppercase();
        match s.split_once('-') {
            Some((base, ssid)) if ssid == "0" => base.to_string(),
            _ => s,
        }
    };
    norm(a) == norm(b)
}

/// Find a port by name (case-insensitive) or by callsign (is_same_call).
fn find_index(guard: &[CPort], query: &str) -> Option<usize> {
    guard
        .iter()
        .position(|p| p.name_s.eq_ignore_ascii_case(query) || is_same_call(&p.call_s, query))
}

unsafe fn cstr_arg<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    std::ffi::CStr::from_ptr(p).to_str().ok()
}

/// `char *ax25_config_get_next(char *name)`.
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_next(name: *const c_char) -> *mut c_char {
    let guard = ports().lock().unwrap();
    if guard.is_empty() {
        return std::ptr::null_mut();
    }
    if name.is_null() {
        return guard[0].name.as_ptr() as *mut c_char;
    }
    let Some(q) = cstr_arg(name) else {
        return std::ptr::null_mut();
    };
    match find_index(&guard, q) {
        Some(i) if i + 1 < guard.len() => guard[i + 1].name.as_ptr() as *mut c_char,
        _ => std::ptr::null_mut(),
    }
}

/// `char *ax25_config_get_name(char *device)`.
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_name(device: *const c_char) -> *mut c_char {
    let guard = ports().lock().unwrap();
    let Some(dev) = cstr_arg(device) else {
        return std::ptr::null_mut();
    };
    match guard.iter().find(|p| p.device_s == dev) {
        Some(p) => p.name.as_ptr() as *mut c_char,
        None => std::ptr::null_mut(),
    }
}

/// `char *ax25_config_get_addr(char *name)` — port name -> callsign.
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_addr(name: *const c_char) -> *mut c_char {
    let guard = ports().lock().unwrap();
    let Some(q) = cstr_arg(name) else {
        return std::ptr::null_mut();
    };
    match find_index(&guard, q) {
        Some(i) => guard[i].call.as_ptr() as *mut c_char,
        None => std::ptr::null_mut(),
    }
}

/// `char *ax25_config_get_dev(char *name)` — port name -> device.
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_dev(name: *const c_char) -> *mut c_char {
    let guard = ports().lock().unwrap();
    let Some(q) = cstr_arg(name) else {
        return std::ptr::null_mut();
    };
    match find_index(&guard, q) {
        Some(i) => guard[i].device.as_ptr() as *mut c_char,
        None => std::ptr::null_mut(),
    }
}

/// `char *ax25_config_get_port(ax25_address *callsign)` — callsign -> port name.
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_port(callsign: *const Ax25Address) -> *mut c_char {
    if callsign.is_null() {
        return std::ptr::null_mut();
    }
    // null address == "all ports" == "*".
    if crate::addr::ax25_cmp(callsign, &crate::addr::null_ax25_address) == 0 {
        return star() as *mut c_char;
    }
    let guard = ports().lock().unwrap();
    for p in guard.iter() {
        if let Some(entry) = encode_entry(&p.call_s) {
            let mut addr = Ax25Address { ax25_call: [0; 7] };
            for i in 0..7 {
                addr.ax25_call[i] = entry[i] as c_char;
            }
            if crate::addr::ax25_cmp(callsign, &addr) == 0 {
                return p.name.as_ptr() as *mut c_char;
            }
        }
    }
    std::ptr::null_mut()
}

/// `int ax25_config_get_window(char *name)`.
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_window(name: *const c_char) -> c_int {
    let guard = ports().lock().unwrap();
    let Some(q) = cstr_arg(name) else { return 0 };
    find_index(&guard, q).map(|i| guard[i].window).unwrap_or(0)
}

/// `int ax25_config_get_paclen(char *name)`.
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_paclen(name: *const c_char) -> c_int {
    let guard = ports().lock().unwrap();
    let Some(q) = cstr_arg(name) else { return 0 };
    find_index(&guard, q).map(|i| guard[i].paclen).unwrap_or(0)
}

/// `int ax25_config_get_baud(char *name)` (part of the upstream ABI).
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_baud(name: *const c_char) -> c_int {
    let guard = ports().lock().unwrap();
    let Some(q) = cstr_arg(name) else { return 0 };
    find_index(&guard, q).map(|i| guard[i].baud).unwrap_or(0)
}

/// `char *ax25_config_get_desc(char *name)` (part of the upstream ABI).
#[no_mangle]
pub unsafe extern "C" fn ax25_config_get_desc(name: *const c_char) -> *mut c_char {
    let guard = ports().lock().unwrap();
    let Some(q) = cstr_arg(name) else {
        return std::ptr::null_mut();
    };
    match find_index(&guard, q) {
        Some(i) => guard[i].description.as_ptr() as *mut c_char,
        None => std::ptr::null_mut(),
    }
}

/// Default uid→callsign map path (override with env `AX25_CALLS` for testing).
const DEFAULT_CALLS: &str = "/etc/ax25/ax25_calls";

/// A parsed uid→callsign entry.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CallEntry {
    pub uid: c_int,
    pub call: String,
}

/// Parse a uid→callsign map file. Format: `uid callsign` per line; comments
/// (`#`) and blank lines are skipped. Invalid lines are dropped silently.
pub(crate) fn parse_calls(content: &str) -> Vec<CallEntry> {
    let mut out: Vec<CallEntry> = Vec::new();
    for raw in content.lines() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let mut rest = trimmed;
        let uid_tok = pop_token(&mut rest);
        let call_tok = pop_token(&mut rest);
        let (uid_tok, call_tok) = match (uid_tok, call_tok) {
            (Some(u), Some(c)) => (u, c),
            _ => continue,
        };
        let Ok(uid) = uid_tok.parse::<c_int>() else {
            continue;
        };
        let call = call_tok.to_ascii_uppercase();
        if encode_entry(&call).is_none() {
            continue;
        }
        if out.iter().any(|e| e.uid == uid) {
            continue;
        }
        out.push(CallEntry { uid, call });
    }
    out
}

struct CCallEntry {
    uid: c_int,
    call: CString,
}

fn call_table() -> &'static Mutex<Vec<CCallEntry>> {
    static TABLE: OnceLock<Mutex<Vec<CCallEntry>>> = OnceLock::new();
    TABLE.get_or_init(|| Mutex::new(Vec::new()))
}

fn calls_path() -> String {
    std::env::var("AX25_CALLS").unwrap_or_else(|_| DEFAULT_CALLS.to_string())
}

/// Load the uid→callsign table (idempotent).
fn load_calls() {
    let mut guard = call_table().lock().unwrap();
    if !guard.is_empty() {
        return;
    }
    let Ok(content) = std::fs::read_to_string(calls_path()) else {
        return;
    };
    for e in parse_calls(&content) {
        guard.push(CCallEntry {
            uid: e.uid,
            call: CString::new(e.call).unwrap_or_default(),
        });
    }
}

/// `char *get_call(int uid)` — map a uid to a callsign.
///
/// Resolution order:
/// 1. `AX25_CALLSIGN` env var (testing / single-user override).
/// 2. `/etc/ax25/ax25_calls` (or `$AX25_CALLS`): `uid callsign` per line.
/// 3. First port callsign from axports (single-operator station default).
///
/// Returns NULL only if no mapping can be resolved at all.
#[no_mangle]
pub extern "C" fn get_call(uid: c_int) -> *mut c_char {
    // (1) Environment override — applies to any uid.
    if let Ok(call) = std::env::var("AX25_CALLSIGN") {
        if !call.is_empty() {
            static ENV_CALL: OnceLock<Mutex<Option<CString>>> = OnceLock::new();
            let slot = ENV_CALL.get_or_init(|| Mutex::new(None));
            let mut guard = slot.lock().unwrap();
            if guard.is_none() {
                *guard = CString::new(call).ok();
            }
            if let Some(ref cs) = *guard {
                return cs.as_ptr() as *mut c_char;
            }
        }
    }

    // (2) Config-file lookup by uid.
    load_calls();
    {
        let guard = call_table().lock().unwrap();
        if let Some(entry) = guard.iter().find(|e| e.uid == uid) {
            return entry.call.as_ptr() as *mut c_char;
        }
    }

    // (3) Fallback: first axports port callsign.
    {
        let guard = ports().lock().unwrap();
        if let Some(p) = guard.first() {
            return p.call.as_ptr() as *mut c_char;
        }
    }

    std::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# axports sample
# name callsign speed paclen window description
radio   M0LTE-1   9600   255    4      2m packet via pdn
hf      GB7RDG-0  1200   128    2      HF gateway

144     G0ABC     9600   256    7      spare port
";

    #[test]
    fn parses_all_valid_lines_without_netdevice_filter() {
        let ports = parse_axports(SAMPLE);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].name, "radio");
        assert_eq!(ports[0].call, "M0LTE-1");
        assert_eq!(ports[0].baud, 9600);
        assert_eq!(ports[0].paclen, 255);
        assert_eq!(ports[0].window, 4);
        assert_eq!(ports[0].description, "2m packet via pdn");
    }

    #[test]
    fn strips_trailing_dash_zero_from_callsign() {
        let ports = parse_axports(SAMPLE);
        // "GB7RDG-0" is stored as "GB7RDG".
        assert_eq!(ports[1].call, "GB7RDG");
    }

    #[test]
    fn skips_comments_blank_lines_and_bad_lines() {
        let input = "\
# comment
good   M0LTE   9600 255 4 ok desc

bad_missing_fields   M0LTE
zerowin   G0XYZ   9600 255 0 window is zero
";
        let ports = parse_axports(input);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].name, "good");
    }

    #[test]
    fn rejects_duplicate_name_and_callsign() {
        let input = "\
p1   M0LTE   9600 255 4 first
p1   G0XYZ   9600 255 4 dup name
p2   M0LTE   9600 255 4 dup call
";
        let ports = parse_axports(input);
        assert_eq!(ports.len(), 1);
    }

    // ---- parse_calls tests ----

    #[test]
    fn parses_uid_callsign_lines() {
        let input = "\
# uid callsign
1000 M0LTE-1
1001 g0abc
";
        let entries = parse_calls(input);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].uid, 1000);
        assert_eq!(entries[0].call, "M0LTE-1");
        assert_eq!(entries[1].uid, 1001);
        assert_eq!(entries[1].call, "G0ABC");
    }

    #[test]
    fn skips_comments_blanks_and_invalid_lines() {
        let input = "\
# comment
0 M0LTE

notanum G0XYZ
1000
1001 !!!invalid!!!
";
        let entries = parse_calls(input);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid, 0);
        assert_eq!(entries[0].call, "M0LTE");
    }

    #[test]
    fn rejects_duplicate_uid() {
        let input = "\
1000 M0LTE
1000 G0XYZ
";
        let entries = parse_calls(input);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].call, "M0LTE");
    }
}
