// SPDX-License-Identifier: LGPL-3.0-or-later
//
// ax25-interpose — an LD_PRELOAD libc interposer that lets UNMODIFIED Linux ham
// apps (ax25-apps, ax25-tools, FBB) use the pdn AX.25 stack instead of the
// (removed) kernel AF_AX25 stack.
//
// It wraps the libc socket/IO calls, detects AF_AX25 (family 3) +
// SOCK_SEQPACKET sockets, and routes those to a pdn RHPv2 connection
// (127.0.0.1:9000 by default). Every non-AX.25 call is passed straight through
// to the real libc symbol resolved with dlsym(RTLD_NEXT, ...).
//
// Model: an AX.25 socket is backed by a real `socketpair` so the app's
// select/poll/read keep working with real libc; a background reader thread in
// the `rhp` client writes inbound data into our end of the pair, and our
// write/send wrappers forward outbound data to RHP `send`.
//
// STATUS: the outbound connect + data + close path is implemented; the inbound
// listener/accept path is skeleton-level with clearly marked TODO(N1) items.
//
// Build output is `libax25_interpose.so`; use it via LD_PRELOAD (or symlink to
// `ax25-interpose.so`).

mod addr;
mod real;
mod state;

use addr::{AF_AX25, SOCK_SEQPACKET, SOL_AX25};
use libc::{c_int, c_void, size_t, sockaddr, socklen_t, ssize_t};

// AX.25 setsockopt option names we care about (from <netax25/ax25.h>).
const AX25_WINDOW: c_int = 1;
const AX25_PACLEN: c_int = 10;

#[inline]
unsafe fn set_errno(e: c_int) {
    *libc::__errno_location() = e;
}

// ----------------------------------------------------------------------------
// socket / bind / listen / connect
// ----------------------------------------------------------------------------

/// `int socket(int domain, int type, int protocol)`.
#[no_mangle]
pub unsafe extern "C" fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int {
    // Mask CLOEXEC/NONBLOCK flags before comparing the socket type.
    let base = ty & !(libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK);
    if domain == AF_AX25 && base == SOCK_SEQPACKET {
        match state::create_ax25_fd() {
            Some(fd) => return fd,
            None => {
                set_errno(libc::ENFILE);
                return -1;
            }
        }
    }
    real::socket()(domain, ty, protocol)
}

/// `int bind(int fd, const struct sockaddr *addr, socklen_t len)`.
#[no_mangle]
pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    if state::is_ax25_fd(fd) {
        if let Some(call) = addr::read_call(addr, len) {
            if let Some(s) = state::fds().lock().unwrap().get_mut(&fd) {
                s.local = Some(call);
            }
        }
        return 0;
    }
    real::bind()(fd, addr, len)
}

/// `int listen(int fd, int backlog)`.
///
/// Not in the minimum interpose set, but wrapped so the listener path can set
/// up the RHP listener when the app calls listen() (otherwise real libc would
/// reject listen() on our connected socketpair fd).
#[no_mangle]
pub unsafe extern "C" fn listen(fd: c_int, backlog: c_int) -> c_int {
    if !state::is_ax25_fd(fd) {
        return real::listen()(fd, backlog);
    }
    let local = state::fds().lock().unwrap().get(&fd).and_then(|s| s.local.clone());
    let Some(local) = local else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let Some(client) = state::ensure_client() else {
        set_errno(libc::ECONNREFUSED);
        return -1;
    };
    let result = (|| -> Result<u64, rhp::RhpError> {
        let h = client.socket()?;
        client.bind(h, &local, None)?;
        client.listen(h)?;
        Ok(h)
    })();
    match result {
        Ok(h) => {
            if let Some(s) = state::fds().lock().unwrap().get_mut(&fd) {
                s.handle = Some(h);
                s.listening = true;
            }
            0
        }
        Err(e) => {
            set_errno(e.to_errno());
            -1
        }
    }
}

/// `int connect(int fd, const struct sockaddr *addr, socklen_t len)`.
#[no_mangle]
pub unsafe extern "C" fn connect(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    if !state::is_ax25_fd(fd) {
        return real::connect()(fd, addr, len);
    }
    let Some(remote) = addr::read_call(addr, len) else {
        set_errno(libc::EINVAL);
        return -1;
    };
    let local = state::fds()
        .lock()
        .unwrap()
        .get(&fd)
        .and_then(|s| s.local.clone())
        .or_else(|| std::env::var("AX25_SRC_CALL").ok())
        .unwrap_or_else(|| "NOCALL".to_string());

    let Some(client) = state::ensure_client() else {
        set_errno(libc::ECONNREFUSED);
        return -1;
    };

    // NOTE: AX.25 connect is asynchronous on the wire — the RHP openReply
    // arrives before the SABM/UA handshake completes. We treat a successful
    // openReply as "connected" for this skeleton. TODO(N1): wait for a
    // status(Connected) push before returning, and honour O_NONBLOCK.
    match client.open_connect(&local, &remote) {
        Ok(res) => {
            let inner = {
                let mut g = state::fds().lock().unwrap();
                let Some(s) = g.get_mut(&fd) else {
                    set_errno(libc::EBADF);
                    return -1;
                };
                s.handle = Some(res.handle);
                s.remote = Some(remote);
                s.inner_fd
            };
            state::handle_inner().lock().unwrap().insert(res.handle, inner);
            0
        }
        Err(e) => {
            set_errno(e.to_errno());
            -1
        }
    }
}

// ----------------------------------------------------------------------------
// accept / getsockname / getpeername
// ----------------------------------------------------------------------------

/// `int accept(int fd, struct sockaddr *addr, socklen_t *len)`.
///
/// Skeleton: blocks (busy-waits) until an `accept` push queues a child. The
/// child gets its own socketpair-backed fd wired to the child RHP handle.
#[no_mangle]
pub unsafe extern "C" fn accept(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    if !state::is_ax25_fd(fd) {
        return real::accept()(fd, addr, len);
    }
    let (listener_handle, local) = {
        let g = state::fds().lock().unwrap();
        match g.get(&fd) {
            Some(s) => (s.handle, s.local.clone()),
            None => {
                set_errno(libc::EBADF);
                return -1;
            }
        }
    };
    let Some(listener_handle) = listener_handle else {
        set_errno(libc::EINVAL);
        return -1;
    };

    // TODO(N1): replace this busy-wait with a condvar or eventfd so accept()
    // blocks efficiently and honours O_NONBLOCK / a timeout.
    let info = loop {
        if let Some(info) = state::accepts()
            .lock()
            .unwrap()
            .get_mut(&listener_handle)
            .and_then(|q| q.pop_front())
        {
            break info;
        }
        if state::ensure_client().map(|c| c.is_closed()).unwrap_or(true) {
            set_errno(libc::ECONNABORTED);
            return -1;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };

    let Some(child_fd) = state::create_ax25_fd() else {
        set_errno(libc::ENFILE);
        return -1;
    };
    let inner = {
        let mut g = state::fds().lock().unwrap();
        let s = g.get_mut(&child_fd).expect("just created");
        s.handle = Some(info.child_handle);
        s.remote = info.remote.clone();
        s.local = info.local.clone().or(local);
        s.inner_fd
    };
    state::handle_inner()
        .lock()
        .unwrap()
        .insert(info.child_handle, inner);

    if let Some(remote) = &info.remote {
        addr::write_call(addr, len, remote);
    }
    child_fd
}

/// `int getsockname(int fd, struct sockaddr *addr, socklen_t *len)`.
#[no_mangle]
pub unsafe extern "C" fn getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    if state::is_ax25_fd(fd) {
        let local = state::fds()
            .lock()
            .unwrap()
            .get(&fd)
            .and_then(|s| s.local.clone())
            .unwrap_or_default();
        addr::write_call(addr, len, &local);
        return 0;
    }
    real::getsockname()(fd, addr, len)
}

/// `int getpeername(int fd, struct sockaddr *addr, socklen_t *len)`.
#[no_mangle]
pub unsafe extern "C" fn getpeername(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    if state::is_ax25_fd(fd) {
        let remote = state::fds()
            .lock()
            .unwrap()
            .get(&fd)
            .and_then(|s| s.remote.clone())
            .unwrap_or_default();
        addr::write_call(addr, len, &remote);
        return 0;
    }
    real::getpeername()(fd, addr, len)
}

// ----------------------------------------------------------------------------
// setsockopt
// ----------------------------------------------------------------------------

/// `int setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)`.
///
/// For AX.25 fds we ALWAYS return 0 — apps (e.g. ax25_config-driven ones) treat
/// a setsockopt failure as fatal. WINDOW/PACLEN are captured for a future OPEN;
/// the rest are accepted and ignored.
#[no_mangle]
pub unsafe extern "C" fn setsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *const c_void,
    optlen: socklen_t,
) -> c_int {
    if state::is_ax25_fd(fd) {
        if level == SOL_AX25
            && !optval.is_null()
            && (optlen as usize) >= std::mem::size_of::<c_int>()
        {
            let v = *(optval as *const c_int) as u32;
            if let Some(s) = state::fds().lock().unwrap().get_mut(&fd) {
                match optname {
                    AX25_WINDOW => s.window = Some(v),
                    AX25_PACLEN => s.paclen = Some(v),
                    _ => { /* T1/T2/T3/N2/EXTSEQ/... captured as no-ops (TODO(N1)) */ }
                }
            }
        }
        return 0;
    }
    real::setsockopt()(fd, level, optname, optval, optlen)
}

// ----------------------------------------------------------------------------
// read / write / recv / send
// ----------------------------------------------------------------------------

/// `ssize_t read(int fd, void *buf, size_t count)`.
///
/// For AX.25 fds the inbound bytes are already in the socketpair (the reader
/// thread wrote them to our end), so a plain real read serves them.
#[no_mangle]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    real::read()(fd, buf, count)
}

/// `ssize_t recv(int fd, void *buf, size_t len, int flags)`.
#[no_mangle]
pub unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    // Our AX.25 fd is a real socketpair socket, so recv() (incl. MSG_PEEK) works
    // against it directly.
    real::recv()(fd, buf, len, flags)
}

/// `ssize_t write(int fd, const void *buf, size_t count)`.
#[no_mangle]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    if state::is_ax25_fd(fd) {
        return ax25_send(fd, buf, count);
    }
    real::write()(fd, buf, count)
}

/// `ssize_t send(int fd, const void *buf, size_t len, int flags)`.
#[no_mangle]
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    if state::is_ax25_fd(fd) {
        return ax25_send(fd, buf, len);
    }
    real::send()(fd, buf, len, flags)
}

unsafe fn ax25_send(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    let handle = state::fds().lock().unwrap().get(&fd).and_then(|s| s.handle);
    let Some(handle) = handle else {
        set_errno(libc::ENOTCONN);
        return -1;
    };
    let Some(client) = state::ensure_client() else {
        set_errno(libc::EIO);
        return -1;
    };
    let data = std::slice::from_raw_parts(buf as *const u8, count);
    match client.send(handle, data) {
        Ok(()) => count as ssize_t,
        Err(e) => {
            set_errno(e.to_errno());
            -1
        }
    }
}

// ----------------------------------------------------------------------------
// select / poll — pure passthrough (our fds are real socketpair fds).
// ----------------------------------------------------------------------------

/// `int select(int nfds, fd_set *r, fd_set *w, fd_set *e, struct timeval *t)`.
#[no_mangle]
pub unsafe extern "C" fn select(
    nfds: c_int,
    readfds: *mut libc::fd_set,
    writefds: *mut libc::fd_set,
    exceptfds: *mut libc::fd_set,
    timeout: *mut libc::timeval,
) -> c_int {
    real::select()(nfds, readfds, writefds, exceptfds, timeout)
}

/// `int poll(struct pollfd *fds, nfds_t nfds, int timeout)`.
#[no_mangle]
pub unsafe extern "C" fn poll(
    fds: *mut libc::pollfd,
    nfds: libc::nfds_t,
    timeout: c_int,
) -> c_int {
    real::poll()(fds, nfds, timeout)
}

// ----------------------------------------------------------------------------
// close
// ----------------------------------------------------------------------------

/// `int close(int fd)`.
#[no_mangle]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    if state::is_ax25_fd(fd) {
        let handle = state::fds().lock().unwrap().get(&fd).and_then(|s| s.handle);
        if let Some(h) = handle {
            if let Some(client) = state::ensure_client() {
                let _ = client.close(h);
            }
        }
        state::destroy_ax25_fd(fd);
        return 0;
    }
    real::close()(fd)
}
