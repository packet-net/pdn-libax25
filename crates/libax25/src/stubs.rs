// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Thin no-op / stub exports for the remainder of the ve7fet libax25 ABI, so
// that binaries linked against `-lax25` resolve every symbol they reference.
//
// These cover the parts of libax25 that make no sense (or aren't needed yet)
// without the kernel AX.25 stack: Rose/NetRom config, tty locking, daemonising,
// and the /proc/net/ax25* parsers. Each is a clearly-marked stub returning a
// benign value (NULL / 0 / -1). Reimplement as needed for pdn in later work.
//
// The real helper surface (address + axports parsing) lives in addr.rs and
// config.rs. `get_call` and `null_ax25_address`/`libax25_version` live there.

use libc::{c_char, c_int, c_void};
use std::ffi::CStr;
use std::ptr;

// ----------------------------------------------------------------------------
// Rose address helpers (rose_aton / rose_ntoa / rose_cmp).
// ----------------------------------------------------------------------------

/// `rose_address` from `<netrose/rose.h>`: 5 packed BCD bytes.
#[repr(C)]
pub struct RoseAddress {
    pub rose_addr: [c_char; 5],
}

/// `int rose_aton(const char *addr, char *buf)`.
///
/// Reimplements the standard 10-digit-decimal -> 5-byte BCD packing (trivial,
/// clean-room; ve7fet axutils.c read as reference).
#[no_mangle]
pub unsafe extern "C" fn rose_aton(addr: *const c_char, buf: *mut c_char) -> c_int {
    if addr.is_null() || buf.is_null() {
        return -1;
    }
    let Ok(s) = CStr::from_ptr(addr).to_str() else {
        return -1;
    };
    let b = s.as_bytes();
    if b.len() != 10 || !b.iter().all(|c| c.is_ascii_digit()) {
        return -1;
    }
    let dst = std::slice::from_raw_parts_mut(buf, 5);
    for i in 0..5 {
        let hi = b[i * 2] - b'0';
        let lo = b[i * 2 + 1] - b'0';
        dst[i] = ((hi << 4) | lo) as c_char;
    }
    0
}

thread_local! {
    static ROSE_BUF: std::cell::RefCell<[c_char; 12]> = const { std::cell::RefCell::new([0; 12]) };
}

/// `char *rose_ntoa(const rose_address *a)`.
#[no_mangle]
pub unsafe extern "C" fn rose_ntoa(a: *const RoseAddress) -> *mut c_char {
    ROSE_BUF.with(|cell| {
        let ptr = cell.as_ptr() as *mut c_char;
        if a.is_null() {
            *ptr = 0;
            return ptr;
        }
        let src = &(*a).rose_addr;
        let dst = std::slice::from_raw_parts_mut(ptr, 12);
        for i in 0..5 {
            let byte = src[i] as u8;
            dst[i * 2] = b'0'.wrapping_add((byte >> 4) & 0x0F) as c_char;
            dst[i * 2 + 1] = b'0'.wrapping_add(byte & 0x0F) as c_char;
        }
        dst[10] = 0;
        ptr
    })
}

/// `int rose_cmp(const rose_address *a, const rose_address *b)`.
#[no_mangle]
pub unsafe extern "C" fn rose_cmp(a: *const RoseAddress, b: *const RoseAddress) -> c_int {
    if a.is_null() || b.is_null() {
        return 1;
    }
    for i in 0..5 {
        if (*a).rose_addr[i] != (*b).rose_addr[i] {
            return 1;
        }
    }
    0
}

// ----------------------------------------------------------------------------
// NetRom config (nr_config_*): no NetRom without the kernel stack yet.
// TODO(N2): back these with pdn's NetRom layer when it exists.
// ----------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn nr_config_load_ports() -> c_int {
    0
}
#[no_mangle]
pub extern "C" fn nr_config_get_next(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn nr_config_get_name(_dev: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn nr_config_get_addr(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn nr_config_get_dev(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn nr_config_get_port(_call: *const c_void) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn nr_config_get_alias(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn nr_config_get_paclen(_name: *const c_char) -> c_int {
    0
}
#[no_mangle]
pub extern "C" fn nr_config_get_desc(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}

// ----------------------------------------------------------------------------
// Rose config (rs_config_*): no Rose without the kernel stack yet.
// TODO(N2): back these with pdn's Rose layer when it exists.
// ----------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn rs_config_load_ports() -> c_int {
    0
}
#[no_mangle]
pub extern "C" fn rs_config_get_next(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn rs_config_get_name(_dev: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn rs_config_get_addr(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn rs_config_get_dev(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn rs_config_get_port(_addr: *const RoseAddress) -> *mut c_char {
    ptr::null_mut()
}
#[no_mangle]
pub extern "C" fn rs_config_get_paclen(_name: *const c_char) -> c_int {
    0
}
#[no_mangle]
pub extern "C" fn rs_config_get_desc(_name: *const c_char) -> *mut c_char {
    ptr::null_mut()
}

// ----------------------------------------------------------------------------
// tty helpers: no serial KISS TNC handling in the interpose model.
// TODO(N3): a native KISS path could reuse these; stubbed for now.
// ----------------------------------------------------------------------------

/// `int tty_raw(int fd, int hwflag)` — TRUE on success. We do nothing.
#[no_mangle]
pub extern "C" fn tty_raw(_fd: c_int, _hwflag: c_int) -> c_int {
    1
}
/// `int tty_speed(int fd, int speed)`.
#[no_mangle]
pub extern "C" fn tty_speed(_fd: c_int, _speed: c_int) -> c_int {
    1
}
/// `int tty_is_locked(char *tty)` — FALSE (never locked).
#[no_mangle]
pub extern "C" fn tty_is_locked(_tty: *const c_char) -> c_int {
    0
}
/// `int tty_lock(char *tty)` — TRUE (pretend success).
#[no_mangle]
pub extern "C" fn tty_lock(_tty: *const c_char) -> c_int {
    1
}
/// `int tty_unlock(char *tty)` — TRUE.
#[no_mangle]
pub extern "C" fn tty_unlock(_tty: *const c_char) -> c_int {
    1
}

// ----------------------------------------------------------------------------
// daemon_start: apps that daemonise call this. Reimplement the standard
// double-nothing here as a no-op success — the interpose model prefers the app
// stays in the foreground under a supervisor. TODO(N3): honour it if needed.
// ----------------------------------------------------------------------------

/// `int daemon_start(int ignsigcld)` — non-zero on success.
#[no_mangle]
pub extern "C" fn daemon_start(_ignsigcld: c_int) -> c_int {
    1
}

// ----------------------------------------------------------------------------
// /proc/net/ax25* parsers: no such proc files without the kernel stack.
// All readers return NULL (empty), all frees are no-ops, finders return NULL.
// TODO(N2): synthesise these from pdn's live connection table for tools like
// `axlisten`, `listen`, `netromr` that introspect kernel state.
// ----------------------------------------------------------------------------

macro_rules! null_reader {
    ($name:ident) => {
        #[no_mangle]
        pub extern "C" fn $name() -> *mut c_void {
            ptr::null_mut()
        }
    };
}
macro_rules! noop_free {
    ($name:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(_p: *mut c_void) {}
    };
}

null_reader!(read_proc_ax25);
noop_free!(free_proc_ax25);
null_reader!(read_proc_ax25_route);
noop_free!(free_proc_ax25_route);
null_reader!(read_proc_nr);
noop_free!(free_proc_nr);
null_reader!(read_proc_nr_neigh);
noop_free!(free_proc_nr_neigh);
null_reader!(read_proc_nr_nodes);
noop_free!(free_proc_nr_nodes);
null_reader!(read_proc_rs);
noop_free!(free_proc_rs);
null_reader!(read_proc_rs_neigh);
noop_free!(free_proc_rs_neigh);
null_reader!(read_proc_rs_nodes);
noop_free!(free_proc_rs_nodes);
null_reader!(read_proc_rs_routes);
noop_free!(free_proc_rs_route);

/// `struct proc_ax25 *find_link(const char *src, const char *dest, const char *dev)`.
#[no_mangle]
pub extern "C" fn find_link(
    _src: *const c_char,
    _dest: *const c_char,
    _dev: *const c_char,
) -> *mut c_void {
    ptr::null_mut()
}
/// `struct proc_nr_neigh *find_neigh(int addr, struct proc_nr_neigh *neigh)`.
#[no_mangle]
pub extern "C" fn find_neigh(_addr: c_int, _neigh: *mut c_void) -> *mut c_void {
    ptr::null_mut()
}
/// `struct proc_nr_nodes *find_node(char *addr, struct proc_nr_nodes *nodes)`.
#[no_mangle]
pub extern "C" fn find_node(_addr: *const c_char, _nodes: *mut c_void) -> *mut c_void {
    ptr::null_mut()
}
