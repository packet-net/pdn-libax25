// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Cached lookups of the *real* libc symbols via dlsym(RTLD_NEXT, ...).
//
// Every interposed wrapper falls through to these for non-AF_AX25 fds, and uses
// them internally so it never re-enters its own interposed symbol (which would
// recurse infinitely — e.g. calling `close` from inside our `close`).

use libc::{c_int, c_void, nfds_t, size_t, sockaddr, socklen_t, ssize_t};
use std::ffi::CString;
use std::sync::atomic::{AtomicUsize, Ordering};

fn load(name: &str) -> usize {
    let cname = CString::new(name).expect("symbol name");
    let p = unsafe { libc::dlsym(libc::RTLD_NEXT, cname.as_ptr()) };
    p as usize
}

macro_rules! real_fn {
    ($getter:ident, $sym:literal, $ty:ty) => {
        pub fn $getter() -> $ty {
            static P: AtomicUsize = AtomicUsize::new(0);
            let mut p = P.load(Ordering::Acquire);
            if p == 0 {
                p = load($sym);
                P.store(p, Ordering::Release);
            }
            // SAFETY: $ty is the correct C signature for symbol $sym; the
            // pointer size matches a function pointer on all supported targets.
            unsafe { std::mem::transmute::<usize, $ty>(p) }
        }
    };
}

pub type SocketFn = unsafe extern "C" fn(c_int, c_int, c_int) -> c_int;
pub type BindFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
pub type ConnectFn = unsafe extern "C" fn(c_int, *const sockaddr, socklen_t) -> c_int;
pub type ListenFn = unsafe extern "C" fn(c_int, c_int) -> c_int;
pub type AcceptFn = unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int;
pub type NameFn = unsafe extern "C" fn(c_int, *mut sockaddr, *mut socklen_t) -> c_int;
pub type SetsockoptFn =
    unsafe extern "C" fn(c_int, c_int, c_int, *const c_void, socklen_t) -> c_int;
pub type ReadFn = unsafe extern "C" fn(c_int, *mut c_void, size_t) -> ssize_t;
pub type WriteFn = unsafe extern "C" fn(c_int, *const c_void, size_t) -> ssize_t;
pub type RecvFn = unsafe extern "C" fn(c_int, *mut c_void, size_t, c_int) -> ssize_t;
pub type SendFn = unsafe extern "C" fn(c_int, *const c_void, size_t, c_int) -> ssize_t;
pub type SelectFn = unsafe extern "C" fn(
    c_int,
    *mut libc::fd_set,
    *mut libc::fd_set,
    *mut libc::fd_set,
    *mut libc::timeval,
) -> c_int;
pub type PollFn = unsafe extern "C" fn(*mut libc::pollfd, nfds_t, c_int) -> c_int;
pub type CloseFn = unsafe extern "C" fn(c_int) -> c_int;

real_fn!(socket, "socket", SocketFn);
real_fn!(bind, "bind", BindFn);
real_fn!(connect, "connect", ConnectFn);
real_fn!(listen, "listen", ListenFn);
real_fn!(accept, "accept", AcceptFn);
real_fn!(getsockname, "getsockname", NameFn);
real_fn!(getpeername, "getpeername", NameFn);
real_fn!(setsockopt, "setsockopt", SetsockoptFn);
real_fn!(read, "read", ReadFn);
real_fn!(write, "write", WriteFn);
real_fn!(recv, "recv", RecvFn);
real_fn!(send, "send", SendFn);
real_fn!(select, "select", SelectFn);
real_fn!(poll, "poll", PollFn);
real_fn!(close, "close", CloseFn);
