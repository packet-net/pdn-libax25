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

use addr::{AF_AX25, SOCK_SEQPACKET, SOL_AX25};
use libc::{c_int, c_void, size_t, sockaddr, socklen_t, ssize_t};
use std::time::Duration;

// AX.25 setsockopt option names we care about (from <netax25/ax25.h>).
const AX25_WINDOW: c_int = 1;
const AX25_PACLEN: c_int = 10;

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
        Ok(()) => 0,
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
    state::recv_pump().register(info.child_handle, inner);

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
    use crate::addr::{self, Ax25Address, FullSockaddrAx25, SockaddrAx25, AF_AX25, SOCK_SEQPACKET};
    use libc::{c_int, sockaddr, socklen_t};
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
    fn spawn_mock() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
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
                    // bind / send / close / anything else: bare ack.
                    _ => reply(&writer, id, None),
                }
            }
        });
        addr
    }

    fn poll_writable(fd: c_int, timeout_ms: c_int) -> bool {
        let mut pfd = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
        let n = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        n > 0 && (pfd.revents & libc::POLLOUT) != 0
    }

    #[test]
    fn interposer_connect_and_accept_end_to_end() {
        std::env::set_var("PDN_RHP_ADDR", spawn_mock());

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

        unsafe { crate::close(child) };
        unsafe { crate::close(lfd) };
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
