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
// write/send wrappers forward outbound data to RHP `send`. Writes we cannot
// interpose (glibc stdio — dprintf/fprintf — flushes via the non-interposable
// __write alias / raw syscall) still land in the socketpair, so an OutboundPump
// drains our end and forwards them to the same RHP `send` (issue #7).
//
// STATUS: both directions are implemented.
//   * Outbound: connect() waits for the async status(Connected) push (blocking),
//     or returns EINPROGRESS + becomes writable on completion with a drainable
//     SO_ERROR (O_NONBLOCK), rather than treating the openReply as "connected".
//   * Inbound: socket/bind/listen/accept are wired; accept() blocks on the RHP
//     client's accept condvar (or EAGAIN under O_NONBLOCK), returns a child fd
//     with the caller's callsign, and getsockname() reports the local port call
//     in the layout ax25d reads.
//   * recv never silently drops: a per-handle buffer + flusher thread applies
//     back-pressure without stalling the shared reader thread.
//
// Build output is `libax25_interpose.so`; use it via LD_PRELOAD (or symlink to
// `ax25-interpose.so`).

mod addr;
mod real;
mod state;

use addr::{AF_AX25, SOCK_DGRAM, SOCK_SEQPACKET, SOL_AX25};
use libc::{c_int, c_void, size_t, sockaddr, socklen_t, ssize_t};
use state::DgramOutcome;
use std::time::Duration;

// AX.25 setsockopt option names we care about (from <netax25/ax25.h>).
const AX25_WINDOW: c_int = 1;
const AX25_PACLEN: c_int = 10;
/// AX25_PIDINCL (option 8): when set, the app's buffer carries the AX.25 PID as
/// its first byte on send, and recv prepends the PID byte — the kernel AF_AX25
/// convention used to send e.g. IP (PID 0xCC) over a datagram socket.
const AX25_PIDINCL: c_int = 8;

/// Default AX.25 PID for UI frames: 0xF0 = "no Layer 3", the beacon/APRS default.
const AX25_PID_NO_L3: i64 = 0xF0;

/// How long a blocking connect() waits for the AX.25 SABM/UA handshake before
/// giving up with ETIMEDOUT. Generous, because SABM is retried (T1 * N2) and a
/// real link can take tens of seconds to come up; the wait also aborts early if
/// the engine reports failure or the transport drops.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(300);

/// True if `fd` is currently in non-blocking mode. fcntl is not interposed, so
/// this reads the real socketpair fd's flags directly.
unsafe fn is_nonblocking(fd: c_int) -> bool {
    let flags = libc::fcntl(fd, libc::F_GETFL);
    flags >= 0 && (flags & libc::O_NONBLOCK) != 0
}

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
    if domain == AF_AX25 && (base == SOCK_SEQPACKET || base == SOCK_DGRAM) {
        // SOCK_SEQPACKET -> connected session; SOCK_DGRAM -> connectionless UI.
        match state::create_ax25_fd(base == SOCK_DGRAM) {
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
///
/// For a connected (SEQPACKET) socket this just records the local callsign for a
/// later connect/listen. For a connectionless (DGRAM/UI) socket it eagerly opens
/// the RHP `custom`-mode handle and binds the callsign (port null = all ports), so
/// the engine starts delivering inbound UI on that port to us.
#[no_mangle]
pub unsafe extern "C" fn bind(fd: c_int, addr: *const sockaddr, len: socklen_t) -> c_int {
    if !state::is_ax25_fd(fd) {
        return real::bind()(fd, addr, len);
    }
    let call = addr::read_call(addr, len);
    if let Some(call) = &call {
        if let Some(s) = state::fds().lock().unwrap().get_mut(&fd) {
            s.local = Some(call.clone());
        }
    }
    if state::is_dgram_fd(fd) {
        // Open + bind the dgram handle now so RX starts flowing.
        return match ensure_dgram_handle(fd) {
            Ok(_) => 0,
            Err(errno) => {
                set_errno(errno);
                -1
            }
        };
    }
    0
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

    // A connect() on a connectionless UI socket has no handshake: it only records
    // a default destination so plain send()/write() (with no explicit dest) know
    // where to go. Make sure the dgram handle exists, then store the remote.
    if state::is_dgram_fd(fd) {
        if let Err(errno) = ensure_dgram_handle(fd) {
            set_errno(errno);
            return -1;
        }
        if let Some(s) = state::fds().lock().unwrap().get_mut(&fd) {
            s.remote = Some(remote);
        }
        return 0;
    }

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

    // AX.25 connect is asynchronous on the wire: the RHP openReply only means
    // the `open` was accepted; the link is not up until a status(Connected) push
    // (or it fails via a close push / error). So `open_connect` starts it, then
    // we wait for that transition — respecting O_NONBLOCK.
    let res = match client.open_connect(&local, &remote) {
        Ok(res) => res,
        Err(e) => {
            set_errno(e.to_errno());
            return -1;
        }
    };

    let (app_fd, inner) = {
        let mut g = state::fds().lock().unwrap();
        let Some(s) = g.get_mut(&fd) else {
            set_errno(libc::EBADF);
            return -1;
        };
        s.handle = Some(res.handle);
        s.remote = Some(remote);
        (s.app_fd, s.inner_fd)
    };
    state::recv_pump().register(res.handle, inner);

    if is_nonblocking(fd) {
        // Standard non-blocking-connect idiom: return EINPROGRESS now; make the
        // fd become writable once the link resolves (the reader thread drains
        // the gate on status/close); the app then reads SO_ERROR via getsockopt.
        state::arm_connect_gate(res.handle, app_fd, inner);
        // Close the race where the link resolved between `open_connect` and
        // arming the gate (the reader's drain would have found no gate): if the
        // result is already in, drain now. resolve_connect_gate is idempotent.
        if client.connect_result(res.handle).is_some() {
            state::resolve_connect_gate(res.handle);
        }
        set_errno(libc::EINPROGRESS);
        return -1;
    }

    // Blocking connect: park until the link comes up or fails.
    match client.wait_connected(res.handle, Some(CONNECT_TIMEOUT)) {
        Ok(()) => {
            // Link is up (and never gated on the blocking path): start forwarding
            // bypassed stdio/dprintf writes from the socketpair to RHP (issue #7).
            state::outbound_pump().register(res.handle, inner);
            0
        }
        Err(errno) => {
            set_errno(errno);
            -1
        }
    }
}

// ----------------------------------------------------------------------------
// accept / getsockname / getpeername
// ----------------------------------------------------------------------------

/// `int accept(int fd, struct sockaddr *addr, socklen_t *len)`.
///
/// Blocks (on the RHP client's accept condvar — no busy-wait) until an `accept`
/// push queues a child, honouring O_NONBLOCK (EAGAIN when nothing waits). The
/// child gets its own socketpair-backed fd wired to the child RHP handle, and
/// the returned `addr` is filled with the caller's callsign.
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
    let Some(client) = state::ensure_client() else {
        set_errno(libc::ECONNABORTED);
        return -1;
    };

    let info = if is_nonblocking(fd) {
        match client.try_accept(listener_handle) {
            Some(info) => info,
            None => {
                set_errno(libc::EAGAIN);
                return -1;
            }
        }
    } else {
        // Block until a child arrives (None => the transport dropped).
        match client.wait_accept(listener_handle, None) {
            Some(info) => info,
            None => {
                set_errno(libc::ECONNABORTED);
                return -1;
            }
        }
    };

    let Some(child_fd) = state::create_ax25_fd(false) else {
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
    state::recv_pump().register(info.child_handle, inner);
    // Forward any writes that bypass our interposition (stdio/dprintf flush via
    // the non-interposable __write) from the socketpair to RHP (issue #7). A child
    // socket is never gated, so it is safe to register immediately.
    state::outbound_pump().register(info.child_handle, inner);

    // Fill the returned peer sockaddr with the caller's callsign.
    if let Some(remote) = &info.remote {
        addr::write_call(addr, len, remote);
    }
    child_fd
}

/// `int getsockname(int fd, struct sockaddr *addr, socklen_t *len)`.
///
/// Returns a `full_sockaddr_ax25` with the local bound callsign in
/// `fsa_digipeater[0]` — the layout `ax25d` reads to identify the local port a
/// connection came in on.
#[no_mangle]
pub unsafe extern "C" fn getsockname(fd: c_int, addr: *mut sockaddr, len: *mut socklen_t) -> c_int {
    if state::is_ax25_fd(fd) {
        let local = state::fds()
            .lock()
            .unwrap()
            .get(&fd)
            .and_then(|s| s.local.clone())
            .unwrap_or_default();
        addr::write_sockname(addr, len, &local);
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
                    AX25_PIDINCL => s.pidincl = v != 0,
                    _ => { /* T1/T2/T3/N2/EXTSEQ/... captured as no-ops (TODO(N1)) */ }
                }
            }
        }
        return 0;
    }
    real::setsockopt()(fd, level, optname, optval, optlen)
}

/// `int getsockopt(int fd, int level, int optname, void *optval, socklen_t *optlen)`.
///
/// The one option we must implement for AX.25 fds is `SOL_SOCKET`/`SO_ERROR`:
/// the non-blocking-connect idiom reads it (once the fd is writable) to collect
/// the pending connect result (0 on success, an errno on failure). Other
/// SOL_SOCKET options are served by the real socketpair; SOL_AX25 gets report 0.
#[no_mangle]
pub unsafe extern "C" fn getsockopt(
    fd: c_int,
    level: c_int,
    optname: c_int,
    optval: *mut c_void,
    optlen: *mut socklen_t,
) -> c_int {
    if state::is_ax25_fd(fd) {
        if level == libc::SOL_SOCKET && optname == libc::SO_ERROR {
            if optval.is_null() || optlen.is_null() || (*optlen as usize) < std::mem::size_of::<c_int>() {
                set_errno(libc::EINVAL);
                return -1;
            }
            let handle = state::fds().lock().unwrap().get(&fd).and_then(|s| s.handle);
            let err: c_int = match handle {
                Some(h) => state::ensure_client().map(|c| c.take_connect_error(h)).unwrap_or(0),
                None => 0,
            };
            *(optval as *mut c_int) = err;
            *optlen = std::mem::size_of::<c_int>() as socklen_t;
            return 0;
        }
        if level == SOL_AX25 {
            // Report success with a zeroed value; app AX.25 gets are advisory.
            if !optval.is_null() && !optlen.is_null() && (*optlen as usize) >= std::mem::size_of::<c_int>() {
                *(optval as *mut c_int) = 0;
                *optlen = std::mem::size_of::<c_int>() as socklen_t;
            }
            return 0;
        }
        // Other SOL_SOCKET options: the underlying socketpair answers correctly.
        return real::getsockopt()(fd, level, optname, optval, optlen);
    }
    real::getsockopt()(fd, level, optname, optval, optlen)
}

// ----------------------------------------------------------------------------
// read / write / recv / send
// ----------------------------------------------------------------------------

/// `ssize_t read(int fd, void *buf, size_t count)`.
///
/// For a connected AX.25 fd the inbound bytes are already in the socketpair (the
/// reader thread wrote them to our end), so a plain real read serves them. A
/// dgram fd delivers one whole datagram from the datagram pump instead.
#[no_mangle]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: size_t) -> ssize_t {
    if state::is_dgram_fd(fd) {
        return ax25_dgram_recv(fd, buf, count, 0, std::ptr::null_mut(), std::ptr::null_mut());
    }
    real::read()(fd, buf, count)
}

/// `ssize_t recv(int fd, void *buf, size_t len, int flags)`.
#[no_mangle]
pub unsafe extern "C" fn recv(fd: c_int, buf: *mut c_void, len: size_t, flags: c_int) -> ssize_t {
    if state::is_dgram_fd(fd) {
        // recv() is recvfrom() with a NULL source address.
        return recvfrom(fd, buf, len, flags, std::ptr::null_mut(), std::ptr::null_mut());
    }
    // A connected AX.25 fd is a real socketpair socket, so recv() (incl.
    // MSG_PEEK) works against it directly.
    real::recv()(fd, buf, len, flags)
}

/// `ssize_t recvfrom(int fd, void *buf, size_t len, int flags,
///                   struct sockaddr *src, socklen_t *srclen)`.
///
/// For a dgram fd this returns one whole UI datagram and fills `src` with the
/// sender's callsign. For a connected fd it behaves like recv() (bytes from the
/// socketpair), filling `src` with the peer callsign if asked.
#[no_mangle]
pub unsafe extern "C" fn recvfrom(
    fd: c_int,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
    src: *mut sockaddr,
    srclen: *mut socklen_t,
) -> ssize_t {
    if state::is_dgram_fd(fd) {
        return ax25_dgram_recv(fd, buf, len, flags, src, srclen);
    }
    if state::is_ax25_fd(fd) {
        // Connected AX.25 socket: bytes are in the socketpair. Fill the peer
        // callsign for callers that pass a source buffer.
        let n = real::recv()(fd, buf, len, flags);
        if n >= 0 && !src.is_null() {
            let remote = state::fds().lock().unwrap().get(&fd).and_then(|s| s.remote.clone());
            if let Some(remote) = remote {
                addr::write_call(src, srclen, &remote);
            }
        }
        return n;
    }
    real::recvfrom()(fd, buf, len, flags, src, srclen)
}

/// `ssize_t write(int fd, const void *buf, size_t count)`.
#[no_mangle]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: size_t) -> ssize_t {
    if state::is_dgram_fd(fd) {
        // write() on a dgram socket sends to the connected default remote.
        return ax25_dgram_send(fd, buf, count, std::ptr::null(), 0);
    }
    if state::is_ax25_fd(fd) {
        return ax25_send(fd, buf, count);
    }
    real::write()(fd, buf, count)
}

/// `ssize_t send(int fd, const void *buf, size_t len, int flags)`.
#[no_mangle]
pub unsafe extern "C" fn send(fd: c_int, buf: *const c_void, len: size_t, flags: c_int) -> ssize_t {
    if state::is_dgram_fd(fd) {
        return ax25_dgram_send(fd, buf, len, std::ptr::null(), 0);
    }
    if state::is_ax25_fd(fd) {
        return ax25_send(fd, buf, len);
    }
    real::send()(fd, buf, len, flags)
}

/// `ssize_t sendto(int fd, const void *buf, size_t len, int flags,
///                 const struct sockaddr *dest, socklen_t destlen)`.
///
/// The datagram send path: for a dgram fd, sends one UI frame to the callsign in
/// `dest` (or the connected default remote if `dest` is NULL). A connected fd
/// ignores `dest` and behaves like send().
#[no_mangle]
pub unsafe extern "C" fn sendto(
    fd: c_int,
    buf: *const c_void,
    len: size_t,
    flags: c_int,
    dest: *const sockaddr,
    destlen: socklen_t,
) -> ssize_t {
    if state::is_dgram_fd(fd) {
        return ax25_dgram_send(fd, buf, len, dest, destlen);
    }
    if state::is_ax25_fd(fd) {
        // Connected socket: sendto's destination is ignored (already connected).
        return ax25_send(fd, buf, len);
    }
    real::sendto()(fd, buf, len, flags, dest, destlen)
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
    // Route through the outbound pump so any bytes the app wrote via a path we
    // could not interpose (stdio/dprintf flush) are flushed to RHP *before* this
    // buffer — keeping an interleaved stdio-then-write() stream in order (issue #7).
    match state::outbound_pump().send_ordered(&client, handle, data) {
        Ok(()) => count as ssize_t,
        Err(errno) => {
            set_errno(errno);
            -1
        }
    }
}

// ----------------------------------------------------------------------------
// Connectionless UI (SOCK_DGRAM) helpers.
// ----------------------------------------------------------------------------

/// Ensure a dgram fd has an RHP `custom`-mode handle (opening + binding it on
/// first use), registered with the datagram pump for RX. Returns the handle or an
/// errno. Idempotent: a second call just returns the existing handle.
unsafe fn ensure_dgram_handle(fd: c_int) -> Result<u64, c_int> {
    // Fast path: handle already allocated.
    let local = {
        let g = state::fds().lock().unwrap();
        match g.get(&fd) {
            Some(s) => {
                if let Some(h) = s.handle {
                    return Ok(h);
                }
                s.local.clone()
            }
            None => return Err(libc::EBADF),
        }
    };

    let Some(client) = state::ensure_client() else {
        return Err(libc::ECONNREFUSED);
    };
    let handle = client.socket_dgram().map_err(|e| e.to_errno())?;
    // Bind the local callsign so the engine delivers inbound UI to us. port=None
    // (all ports). An unbound socket (no local yet) can still send.
    if let Some(local) = &local {
        if let Err(e) = client.bind(handle, local, None) {
            let _ = client.close(handle);
            return Err(e.to_errno());
        }
    }

    // Store the handle and register for RX. Guard against a racing caller having
    // set one already (single-threaded apps never hit this).
    let (app_fd, inner_fd, existing) = {
        let mut g = state::fds().lock().unwrap();
        let Some(s) = g.get_mut(&fd) else {
            let _ = client.close(handle);
            return Err(libc::EBADF);
        };
        match s.handle {
            Some(h) => (s.app_fd, s.inner_fd, Some(h)),
            None => {
                s.handle = Some(handle);
                (s.app_fd, s.inner_fd, None)
            }
        }
    };
    match existing {
        Some(h) => {
            let _ = client.close(handle); // lost the race; discard our handle
            Ok(h)
        }
        None => {
            state::dgram_pump().register(handle, app_fd, inner_fd);
            Ok(handle)
        }
    }
}

/// Send one UI frame. `dest` (if non-NULL) is the destination sockaddr; else the
/// connected default remote is used. Applies the AX25_PIDINCL convention.
unsafe fn ax25_dgram_send(
    fd: c_int,
    buf: *const c_void,
    count: size_t,
    dest: *const sockaddr,
    destlen: socklen_t,
) -> ssize_t {
    let handle = match ensure_dgram_handle(fd) {
        Ok(h) => h,
        Err(e) => {
            set_errno(e);
            return -1;
        }
    };
    let (default_remote, local, pidincl) = {
        let g = state::fds().lock().unwrap();
        match g.get(&fd) {
            Some(s) => (s.remote.clone(), s.local.clone(), s.pidincl),
            None => {
                set_errno(libc::EBADF);
                return -1;
            }
        }
    };

    // Destination: an explicit sendto() address, else the connect()ed remote.
    let remote = if !dest.is_null() {
        match addr::read_call(dest, destlen) {
            Some(r) => r,
            None => {
                set_errno(libc::EINVAL);
                return -1;
            }
        }
    } else {
        match default_remote {
            Some(r) => r,
            None => {
                set_errno(libc::EDESTADDRREQ);
                return -1;
            }
        }
    };
    let local = local
        .or_else(|| std::env::var("AX25_SRC_CALL").ok())
        .unwrap_or_else(|| "NOCALL".to_string());

    // Custom mode carries the PID as data[0]. With AX25_PIDINCL the app's buffer
    // is already [PID][info…] and is sent as-is (the natural fit); otherwise
    // prepend the default 0xF0 (no Layer 3) -> [0xF0] ++ app.
    let app = std::slice::from_raw_parts(buf as *const u8, count);
    let wire: Vec<u8> = if pidincl {
        app.to_vec()
    } else {
        let mut v = Vec::with_capacity(app.len() + 1);
        v.push(AX25_PID_NO_L3 as u8);
        v.extend_from_slice(app);
        v
    };
    if wire.is_empty() {
        // pdn rejects empty custom `data` (errCode 1); under PIDINCL there is not
        // even room for the PID octet. Fail locally.
        set_errno(libc::EINVAL);
        return -1;
    }

    let Some(client) = state::ensure_client() else {
        set_errno(libc::EIO);
        return -1;
    };
    match client.sendto(handle, &remote, &local, &wire) {
        // Report the whole app buffer consumed (incl. the PID byte if PIDINCL).
        Ok(()) => count as ssize_t,
        Err(e) => {
            set_errno(e.to_errno());
            -1
        }
    }
}

/// Receive one UI datagram from the datagram pump, filling `src` with the sender
/// callsign. Blocks (honouring O_NONBLOCK / MSG_DONTWAIT) until one arrives.
unsafe fn ax25_dgram_recv(
    fd: c_int,
    buf: *mut c_void,
    len: size_t,
    flags: c_int,
    src: *mut sockaddr,
    srclen: *mut socklen_t,
) -> ssize_t {
    let handle = match ensure_dgram_handle(fd) {
        Ok(h) => h,
        Err(e) => {
            set_errno(e);
            return -1;
        }
    };
    let pidincl = state::fds().lock().unwrap().get(&fd).map(|s| s.pidincl).unwrap_or(false);
    let nonblock = is_nonblocking(fd) || (flags & libc::MSG_DONTWAIT) != 0;

    loop {
        match state::dgram_pump().recv_one(handle) {
            DgramOutcome::Got(dg) => {
                // The custom payload is [PID][info…]. PIDINCL apps want it whole;
                // otherwise strip the leading PID octet and deliver just the info.
                let payload: &[u8] = if pidincl || dg.data.is_empty() {
                    &dg.data
                } else {
                    &dg.data[1..]
                };
                let n = payload.len().min(len); // datagram truncated to the buffer
                if n > 0 {
                    std::ptr::copy_nonoverlapping(payload.as_ptr(), buf as *mut u8, n);
                }
                if !src.is_null() {
                    addr::write_call(src, srclen, dg.source.as_deref().unwrap_or(""));
                }
                return n as ssize_t;
            }
            DgramOutcome::Eof => return 0,
            DgramOutcome::NoHandle => {
                set_errno(libc::ENOTCONN);
                return -1;
            }
            DgramOutcome::Empty => {
                if nonblock {
                    set_errno(libc::EAGAIN);
                    return -1;
                }
                // Park on the socketpair readiness signal, then retry the queue.
                let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                real::poll()(&mut pfd, 1, -1);
            }
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

// ----------------------------------------------------------------------------
// End-to-end tests.
//
// These exercise the real C entry points (socket/connect/accept/getsockopt/…)
// in-process against a mock RHP server. Because the interposer's #[no_mangle]
// symbols are present in the test binary they interpose the whole process, but
// every non-AX.25 fd delegates to real libc via dlsym(RTLD_NEXT), so std / the
// mock server keep working — exactly as under LD_PRELOAD.
//
// The interposer keeps ONE process-global RHP client (cached on first use), so
// all scenarios share a single mock over one connection and MUST live in a
// single #[test] to avoid cross-test interference on that global state.
// ----------------------------------------------------------------------------
#[cfg(test)]
mod e2e_tests {
    use crate::addr::{
        self, Ax25Address, FullSockaddrAx25, SockaddrAx25, AF_AX25, SOCK_DGRAM, SOCK_SEQPACKET,
        SOL_AX25,
    };
    use libc::{c_int, c_void, sockaddr, socklen_t};
    use rhp::framing::{read_frame, write_frame};
    use rhp::messages::Frame;
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::io::AsRawFd;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Delay the mock waits before pushing an async status(Connected) / accept,
    /// so tests can prove we actually wait for the async event.
    const PUSH_DELAY: Duration = Duration::from_millis(150);

    fn errno() -> c_int {
        unsafe { *libc::__errno_location() }
    }

    fn sax25(call: &str) -> SockaddrAx25 {
        SockaddrAx25 {
            sax25_family: AF_AX25 as u16,
            sax25_call: Ax25Address { ax25_call: addr::encode(call) },
            sax25_ndigis: 0,
        }
    }

    /// A request-driven mock RHP server. Correlates replies by `id`; injects
    /// status/accept pushes after `PUSH_DELAY`. Returns its `host:port`.
    fn spawn_mock() -> (String, Arc<Mutex<Vec<Frame>>>, Arc<Mutex<Vec<Frame>>>) {
        // Captures every `sendto` (UI) and `send` (connected) the interposer emits.
        let sendtos: Arc<Mutex<Vec<Frame>>> = Arc::new(Mutex::new(Vec::new()));
        let sends: Arc<Mutex<Vec<Frame>>> = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let sendtos_srv = sendtos.clone();
        let sends_srv = sends.clone();
        std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let mut reader = sock.try_clone().unwrap();
            let writer = Arc::new(Mutex::new(sock));
            let next = Arc::new(AtomicU64::new(100));

            let reply = |w: &Arc<Mutex<TcpStream>>, id: u64, handle: Option<u64>| {
                let body = match handle {
                    Some(h) => format!(
                        r#"{{"type":"reply","id":{id},"handle":{h},"errCode":0,"errText":"Ok"}}"#
                    ),
                    None => format!(r#"{{"type":"reply","id":{id},"errCode":0,"errText":"Ok"}}"#),
                };
                write_frame(&mut *w.lock().unwrap(), body.as_bytes()).unwrap();
            };

            loop {
                let bytes = match read_frame(&mut reader) {
                    Ok(Some(b)) => b,
                    _ => break,
                };
                let f = match Frame::parse(&bytes) {
                    Ok(f) => f,
                    Err(_) => continue,
                };
                let id = f.id().unwrap_or(0);
                match f.typ() {
                    "open" => {
                        let h = next.fetch_add(1, Ordering::Relaxed);
                        reply(&writer, id, Some(h));
                        // Link comes up asynchronously after a delay.
                        let w = writer.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(PUSH_DELAY);
                            let push = format!(r#"{{"type":"status","handle":{h},"flags":2}}"#);
                            let _ = write_frame(&mut *w.lock().unwrap(), push.as_bytes());
                        });
                    }
                    "socket" => {
                        let h = next.fetch_add(1, Ordering::Relaxed);
                        reply(&writer, id, Some(h));
                    }
                    "sendto" => {
                        // Record the emitted UI frame, then ack it.
                        sendtos_srv.lock().unwrap().push(f.clone());
                        reply(&writer, id, None);
                        // Echo an inbound UI frame back on the same handle after a
                        // delay, so the recvfrom tests prove they wait for RX and so
                        // both PIDINCL states can be exercised. Custom mode: the PID
                        // is data[0] (0xF0), the info field is "beacon-rx", and there
                        // is no `pid` field.
                        if let Some(h) = f.handle() {
                            let w = writer.clone();
                            std::thread::spawn(move || {
                                std::thread::sleep(PUSH_DELAY);
                                let mut push = format!(
                                    r#"{{"type":"recv","handle":{h},"remote":"G0ABC-1","local":"GB7RDG-2","port":"0","data":""#
                                );
                                push.push('\u{F0}'); // PID octet
                                push.push_str("beacon-rx");
                                push.push_str("\"}");
                                let _ = write_frame(&mut *w.lock().unwrap(), push.as_bytes());
                            });
                        }
                    }
                    "send" => {
                        // Record the emitted connected-mode data frame, then ack.
                        sends_srv.lock().unwrap().push(f.clone());
                        reply(&writer, id, None);
                    }
                    "listen" => {
                        let lh = f.handle().unwrap();
                        reply(&writer, id, None);
                        // An inbound connection arrives after a delay.
                        let child = next.fetch_add(1, Ordering::Relaxed);
                        let w = writer.clone();
                        std::thread::spawn(move || {
                            std::thread::sleep(PUSH_DELAY);
                            let push = format!(
                                r#"{{"type":"accept","handle":{lh},"child":{child},"remote":"M0ABC-2","local":"GB7RDG-1"}}"#
                            );
                            let _ = write_frame(&mut *w.lock().unwrap(), push.as_bytes());
                        });
                    }
                    // bind / close / anything else: bare ack.
                    _ => reply(&writer, id, None),
                }
            }
        });
        (addr, sendtos, sends)
    }

    fn poll_writable(fd: c_int, timeout_ms: c_int) -> bool {
        let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        n > 0 && (pfd.revents & libc::POLLOUT) != 0
    }

    #[test]
    fn interposer_connect_and_accept_end_to_end() {
        let (mock_addr, sendtos, sends) = spawn_mock();
        std::env::set_var("PDN_RHP_ADDR", mock_addr);

        // ---- (a) blocking connect unblocks only after status(Connected) ----
        let fd = unsafe { crate::socket(AF_AX25, SOCK_SEQPACKET, 0) };
        assert!(fd >= 0, "socket() failed");
        let remote = sax25("GB7RDG");
        let start = Instant::now();
        let rc = unsafe {
            crate::connect(
                fd,
                &remote as *const SockaddrAx25 as *const sockaddr,
                std::mem::size_of::<SockaddrAx25>() as socklen_t,
            )
        };
        assert_eq!(rc, 0, "blocking connect should succeed (errno {})", errno());
        assert!(
            start.elapsed() >= PUSH_DELAY - Duration::from_millis(40),
            "blocking connect returned before status(Connected)"
        );
        unsafe { crate::close(fd) };

        // ---- (b) non-blocking connect: EINPROGRESS, writable + SO_ERROR==0 ----
        let nfd = unsafe { crate::socket(AF_AX25, SOCK_SEQPACKET, 0) };
        assert!(nfd >= 0);
        let fl = unsafe { libc::fcntl(nfd, libc::F_GETFL) };
        unsafe { libc::fcntl(nfd, libc::F_SETFL, fl | libc::O_NONBLOCK) };
        let rc = unsafe {
            crate::connect(
                nfd,
                &remote as *const SockaddrAx25 as *const sockaddr,
                std::mem::size_of::<SockaddrAx25>() as socklen_t,
            )
        };
        assert_eq!(rc, -1, "non-blocking connect must return -1");
        assert_eq!(errno(), libc::EINPROGRESS, "expected EINPROGRESS");
        // Not writable yet: the link is still coming up.
        assert!(!poll_writable(nfd, 0), "fd writable before Connected");
        // SO_ERROR is still pending (0) while connecting.
        let mut so_err: c_int = -1;
        let mut olen = std::mem::size_of::<c_int>() as socklen_t;
        unsafe {
            crate::getsockopt(
                nfd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_err as *mut c_int as *mut libc::c_void,
                &mut olen,
            )
        };
        assert_eq!(so_err, 0, "pending connect should report SO_ERROR 0");
        // Becomes writable once Connected, then SO_ERROR drains to 0.
        assert!(poll_writable(nfd, 2000), "fd never became writable after Connected");
        let mut so_err: c_int = -1;
        unsafe {
            crate::getsockopt(
                nfd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_err as *mut c_int as *mut libc::c_void,
                &mut olen,
            )
        };
        assert_eq!(so_err, 0, "SO_ERROR should be 0 after a successful connect");
        unsafe { crate::close(nfd) };

        // ---- (c) accept() returns a child fd with the caller's callsign ----
        let lfd = unsafe { crate::socket(AF_AX25, SOCK_SEQPACKET, 0) };
        assert!(lfd >= 0);
        let local = sax25("GB7RDG-1");
        assert_eq!(
            unsafe {
                crate::bind(
                    lfd,
                    &local as *const SockaddrAx25 as *const sockaddr,
                    std::mem::size_of::<SockaddrAx25>() as socklen_t,
                )
            },
            0
        );
        assert_eq!(unsafe { crate::listen(lfd, 5) }, 0, "listen failed (errno {})", errno());

        let mut peer: FullSockaddrAx25 = unsafe { std::mem::zeroed() };
        let mut plen = std::mem::size_of::<FullSockaddrAx25>() as socklen_t;
        let child = unsafe {
            crate::accept(lfd, &mut peer as *mut FullSockaddrAx25 as *mut sockaddr, &mut plen)
        };
        assert!(child >= 0, "accept failed (errno {})", errno());
        // accept fills the peer sockaddr with the caller's callsign.
        assert_eq!(addr::decode(&peer.fsa_ax25.sax25_call.ax25_call), "M0ABC-2");

        // getsockname on the child returns the local port callsign in digi[0].
        let mut me: FullSockaddrAx25 = unsafe { std::mem::zeroed() };
        let mut mlen = std::mem::size_of::<FullSockaddrAx25>() as socklen_t;
        assert_eq!(
            unsafe {
                crate::getsockname(child, &mut me as *mut FullSockaddrAx25 as *mut sockaddr, &mut mlen)
            },
            0
        );
        assert_eq!(addr::decode(&me.fsa_digipeater[0].ax25_call), "GB7RDG-1");

        // ---- (c2) accepting-side early send (issue #4, accepting side) --------
        // A banner written to the child fd IMMEDIATELY after accept() — before any
        // inbound recv on the child — must be emitted as an RHP `send`, not gated
        // on a first inbound frame. (The connecting-side counterpart, an early
        // recv arriving before the fd registers, is covered by the deterministic
        // state::tests::early_recv_before_register_is_delivered_not_dropped.)
        let banner = "Welcome to GB7RDG BBS";
        let wn = unsafe { crate::write(child, banner.as_ptr() as *const c_void, banner.len()) };
        assert_eq!(wn, banner.len() as isize, "child write failed (errno {})", errno());
        assert!(
            sends.lock().unwrap().iter().any(|f| f.data_str() == Some(banner)),
            "accepting-side banner was not emitted as an RHP send"
        );

        // ---- (c3) issue #7: a dprintf/stdio banner reaches RHP send -----------
        // glibc stdio (dprintf/fprintf/buffered printf) flushes through the
        // internal __write alias / raw write(2) syscall, which LD_PRELOAD of the
        // public `write` symbol CANNOT intercept (verified on glibc 2.39). We call
        // the REAL glibc dprintf here so this exercises exactly that
        // non-interposable path against the child's socketpair fd. The bytes still
        // land in our socketpair; the OutboundPump must drain them to RHP `send`.
        // Before the fix these bytes were never forwarded and this timed out.
        extern "C" {
            fn dprintf(fd: c_int, fmt: *const libc::c_char, ...) -> c_int;
        }
        let stdio_banner = "STDIO-BANNER via dprintf\n";
        let fmt = std::ffi::CString::new("%s").unwrap();
        let arg = std::ffi::CString::new(stdio_banner).unwrap();
        let dn = unsafe { dprintf(child, fmt.as_ptr(), arg.as_ptr()) };
        assert_eq!(dn as usize, stdio_banner.len(), "dprintf wrote {dn} bytes");
        // The OutboundPump forwards asynchronously; wait (bounded) for the mock.
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen = false;
        while Instant::now() < deadline {
            if sends.lock().unwrap().iter().any(|f| f.data_str() == Some(stdio_banner)) {
                seen = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            seen,
            "issue #7: a dprintf (stdio) banner never reached RHP send — the \
             OutboundPump did not drain the bypassed write from the socketpair"
        );

        unsafe { crate::close(child) };
        unsafe { crate::close(lfd) };

        // ---- (d) dgram: socket -> bind -> sendto, then a blocking recvfrom gets
        // the echoed UI. Without AX25_PIDINCL the leading PID octet is stripped. --
        let dfd = unsafe { crate::socket(AF_AX25, SOCK_DGRAM, 0) };
        assert!(dfd >= 0, "dgram socket() failed");
        let dlocal = sax25("GB7RDG-2");
        assert_eq!(
            unsafe {
                crate::bind(
                    dfd,
                    &dlocal as *const SockaddrAx25 as *const sockaddr,
                    std::mem::size_of::<SockaddrAx25>() as socklen_t,
                )
            },
            0,
            "dgram bind failed (errno {})",
            errno()
        );

        // sendto with the default PID 0xF0 prepended (no AX25_PIDINCL set yet).
        let beacon = b"de GB7RDG-2 beacon";
        let dest = sax25("BEACON");
        let n = unsafe {
            crate::sendto(
                dfd,
                beacon.as_ptr() as *const c_void,
                beacon.len(),
                0,
                &dest as *const SockaddrAx25 as *const sockaddr,
                std::mem::size_of::<SockaddrAx25>() as socklen_t,
            )
        };
        assert_eq!(n, beacon.len() as isize, "sendto returned {n} (errno {})", errno());

        // recvfrom blocks until the injected UI frame arrives, fills the source.
        let mut src: SockaddrAx25 = unsafe { std::mem::zeroed() };
        let mut slen = std::mem::size_of::<SockaddrAx25>() as socklen_t;
        let mut rbuf = [0u8; 128];
        let rn = unsafe {
            crate::recvfrom(
                dfd,
                rbuf.as_mut_ptr() as *mut c_void,
                rbuf.len(),
                0,
                &mut src as *mut SockaddrAx25 as *mut sockaddr,
                &mut slen,
            )
        };
        assert!(rn > 0, "dgram recvfrom failed (errno {})", errno());
        assert_eq!(&rbuf[..rn as usize], b"beacon-rx", "wrong UI payload");
        assert_eq!(addr::decode(&src.sax25_call.ax25_call), "G0ABC-1", "wrong source");

        // ---- (e) AX25_PIDINCL: the app's [PID][info…] buffer is sent as-is -----
        let on: c_int = 1;
        unsafe {
            crate::setsockopt(
                dfd,
                SOL_AX25,
                crate::AX25_PIDINCL,
                &on as *const c_int as *const c_void,
                std::mem::size_of::<c_int>() as socklen_t,
            )
        };
        let ip_frame = [0xCCu8, b'i', b'p']; // PID 0xCC (IP), info "ip"
        let n2 = unsafe {
            crate::sendto(
                dfd,
                ip_frame.as_ptr() as *const c_void,
                ip_frame.len(),
                0,
                &dest as *const SockaddrAx25 as *const sockaddr,
                std::mem::size_of::<SockaddrAx25>() as socklen_t,
            )
        };
        assert_eq!(n2, ip_frame.len() as isize, "PIDINCL sendto returned {n2}");

        // ---- (f) RX under AX25_PIDINCL: the echoed frame is delivered whole,
        // with the leading PID octet kept (the second sendto triggered the echo).
        let mut src2: SockaddrAx25 = unsafe { std::mem::zeroed() };
        let mut slen2 = std::mem::size_of::<SockaddrAx25>() as socklen_t;
        let mut rbuf2 = [0u8; 128];
        let rn2 = unsafe {
            crate::recvfrom(
                dfd,
                rbuf2.as_mut_ptr() as *mut c_void,
                rbuf2.len(),
                0,
                &mut src2 as *mut SockaddrAx25 as *mut sockaddr,
                &mut slen2,
            )
        };
        assert!(rn2 > 0, "PIDINCL recvfrom failed (errno {})", errno());
        // PID 0xF0 is kept as byte 0, then the info "beacon-rx".
        let mut expected = vec![0xF0u8];
        expected.extend_from_slice(b"beacon-rx");
        assert_eq!(&rbuf2[..rn2 as usize], &expected[..], "PIDINCL must keep the PID octet");
        assert_eq!(addr::decode(&src2.sax25_call.ax25_call), "G0ABC-1", "wrong source");

        // Assert the two captured sendto frames carried the right custom `data`.
        // Custom mode: PID is data[0], no `pid` field.
        let captured = sendtos.lock().unwrap();
        assert_eq!(captured.len(), 2, "expected two sendto frames");
        assert_eq!(captured[0].remote(), Some("BEACON"));
        assert_eq!(captured[0].local(), Some("GB7RDG-2"));
        // (a) default path: 0xF0 prepended, then the app bytes.
        assert_eq!(
            captured[0].data_str().map(rhp::codec::from_wire_string),
            Some({
                let mut v = vec![0xF0u8];
                v.extend_from_slice(b"de GB7RDG-2 beacon");
                v
            }),
            "default PID 0xF0 must be prepended as data[0]"
        );
        // (b) PIDINCL path: the app's [0xCC]['i']['p'] buffer sent unchanged.
        assert_eq!(
            captured[1].data_str().map(rhp::codec::from_wire_string),
            Some(vec![0xCCu8, b'i', b'p']),
            "PIDINCL must send the [PID][info…] buffer as-is"
        );
        drop(captured);

        unsafe { crate::close(dfd) };
    }

    #[test]
    fn non_ax25_socket_passes_through() {
        // A plain TCP socket must be untouched by the interposer (delegated to
        // real libc), proving passthrough survives whole-process interposition.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let s = TcpStream::connect(addr).unwrap();
        assert!(!crate::state::is_ax25_fd(s.as_raw_fd()));
        drop(s);
        drop(l);
    }
}
