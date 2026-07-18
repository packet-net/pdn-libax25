// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Global interposer state: the fd -> AX.25 socket map, the shared RHP client,
// and the event sink that pumps RHP `recv`/`accept`/`status`/`close` pushes back
// into the app-visible socketpair fds.

use libc::{c_int, c_void};
use rhp::{RhpClient, RhpEventSink, STATUS_CONNECTED};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, Once, OnceLock};

use crate::real;

/// State for one app-visible AX.25 fd.
pub struct FdState {
    /// The fd handed to the application (one end of a socketpair). Also the map
    /// key; kept here for clarity.
    pub app_fd: c_int,
    /// Our end of the socketpair. The reader thread writes inbound RHP data
    /// here so it becomes readable/pollable on `app_fd` with real libc calls.
    pub inner_fd: c_int,
    /// RHP handle, once `connect`/`listen` has established one.
    pub handle: Option<u64>,
    /// Local (bound) callsign.
    pub local: Option<String>,
    /// Remote (peer) callsign.
    pub remote: Option<String>,
    /// True once this fd is an RHP listener.
    pub listening: bool,
    /// Captured AX.25 socket options (applied to a future OPEN where sensible).
    pub paclen: Option<u32>,
    pub window: Option<u32>,
}

pub fn fds() -> &'static Mutex<HashMap<c_int, FdState>> {
    static M: OnceLock<Mutex<HashMap<c_int, FdState>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

// ----------------------------------------------------------------------------
// Non-blocking connect gate.
//
// A socketpair is writable from birth, but the non-blocking-connect idiom needs
// the fd to become writable only once the AX.25 link is up. We gate it purely
// via the socketpair's own buffer state (so real select/poll/epoll keep working
// unmodified): `arm_connect_gate` fills the app_fd -> inner_fd pipe so the app's
// end is NOT writable; `resolve_connect_gate` (run from the reader thread when
// the connect resolves, success or failure) drains that filler so the app's end
// becomes writable again, at which point the app reads SO_ERROR for the result.
//
// The filler travels the app_fd -> inner_fd direction; inbound recv data travels
// inner_fd -> app_fd, so draining the filler never touches real received bytes.
// The app never writes to app_fd directly (its write()/send() are interposed to
// RHP), so once drained the app end stays writable.
// ----------------------------------------------------------------------------

/// Map RHP handle -> inner_fd whose app end is currently gated non-writable.
fn connect_gates() -> &'static Mutex<HashMap<u64, c_int>> {
    static M: OnceLock<Mutex<HashMap<u64, c_int>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Make `app_fd` non-writable until the connect resolves, by filling its send
/// buffer. Bounds the filler by shrinking the send buffer first.
pub fn arm_connect_gate(handle: u64, app_fd: c_int, inner_fd: c_int) {
    // Shrink app_fd's send buffer so the fill is cheap. This buffer only ever
    // carries our filler (app writes are interposed away), so shrinking it does
    // not affect data throughput. Use real setsockopt: our own setsockopt would
    // treat this AX.25 fd specially and no-op.
    let sz: c_int = 1024;
    unsafe {
        real::setsockopt()(
            app_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sz as *const c_int as *const c_void,
            std::mem::size_of::<c_int>() as libc::socklen_t,
        );
    }
    let buf = [0u8; 1024];
    let send = real::send();
    loop {
        let n = unsafe {
            send(
                app_fd,
                buf.as_ptr() as *const c_void,
                buf.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if n <= 0 {
            break; // EAGAIN => send buffer full => app_fd no longer writable
        }
    }
    connect_gates().lock().unwrap().insert(handle, inner_fd);
}

/// Drain the filler for a resolved connect so `app_fd` becomes writable. No-op
/// for handles that were never gated (e.g. blocking connects, child sockets).
pub fn resolve_connect_gate(handle: u64) {
    let inner = connect_gates().lock().unwrap().remove(&handle);
    if let Some(inner) = inner {
        let recv = real::recv();
        let mut buf = [0u8; 1024];
        loop {
            let n = unsafe {
                recv(inner, buf.as_mut_ptr() as *mut c_void, buf.len(), libc::MSG_DONTWAIT)
            };
            if n <= 0 {
                break;
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Receive pump: never-lose-data delivery of RHP recv bytes into the socketpair.
//
// The single RHP reader thread must not block on a slow app socketpair (that
// would stall every other connection — head-of-line blocking / deadlock), so we
// do NOT block it. Instead each handle keeps an overflow buffer: on_recv writes
// what fits immediately and buffers the rest; a dedicated flusher thread waits
// for the app to drain its end (poll for POLLOUT on inner_fd) and pushes the
// backlog through, preserving order. Data is therefore never silently dropped.
// A server close is delivered (SHUT_WR) only after the backlog is flushed.
// ----------------------------------------------------------------------------

struct PendingRecv {
    inner_fd: c_int,
    buf: VecDeque<u8>,
    /// Server-initiated close seen; SHUT_WR once the backlog is flushed.
    eof: bool,
    /// The EOF SHUT_WR has been performed (do it exactly once).
    eof_done: bool,
}

pub struct RecvPump {
    state: Mutex<HashMap<u64, PendingRecv>>,
    cv: Condvar,
}

impl RecvPump {
    fn new() -> RecvPump {
        RecvPump { state: Mutex::new(HashMap::new()), cv: Condvar::new() }
    }

    /// Register a handle's inner socketpair fd for recv delivery.
    pub fn register(&self, handle: u64, inner_fd: c_int) {
        self.state.lock().unwrap().insert(
            handle,
            PendingRecv { inner_fd, buf: VecDeque::new(), eof: false, eof_done: false },
        );
    }

    /// Forget a handle (its fd is being torn down by the owner).
    pub fn unregister(&self, handle: u64) {
        self.state.lock().unwrap().remove(&handle);
    }

    /// Deliver inbound bytes, buffering whatever the socketpair cannot take now.
    pub fn push(&self, handle: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut st = self.state.lock().unwrap();
        let Some(e) = st.get_mut(&handle) else {
            return; // fd already gone
        };
        let mut dead = false;
        if e.buf.is_empty() {
            // Fast path: try to hand the bytes straight to the socketpair.
            match nb_write(e.inner_fd, data) {
                WriteOutcome::Wrote(n) if n < data.len() => {
                    e.buf.extend(data[n..].iter().copied());
                    self.cv.notify_all();
                }
                WriteOutcome::Wrote(_) => {} // fully delivered
                WriteOutcome::WouldBlock => {
                    e.buf.extend(data.iter().copied());
                    self.cv.notify_all();
                }
                // App end gone; drop the handle rather than buffer forever.
                WriteOutcome::Fatal => dead = true,
            }
        } else {
            // Preserve ordering: never overtake already-buffered bytes.
            e.buf.extend(data.iter().copied());
            self.cv.notify_all();
        }
        if dead {
            st.remove(&handle);
        }
    }

    /// Note a server-initiated close; EOF is signalled after the backlog drains.
    pub fn mark_eof(&self, handle: u64) {
        if let Some(e) = self.state.lock().unwrap().get_mut(&handle) {
            e.eof = true;
            self.cv.notify_all();
        }
    }

    /// Transport gone: EOF every live handle (after flushing what it can).
    pub fn shutdown_all(&self) {
        let mut st = self.state.lock().unwrap();
        for e in st.values_mut() {
            e.eof = true;
        }
        self.cv.notify_all();
    }

    /// Drain every entry as far as the socketpairs allow; return the inner fds
    /// that still have a backlog (blocked on the app reading). Runs under lock;
    /// all writes to inner fds happen here so a torn-down fd is never written.
    fn drain_pass(&self) -> Vec<c_int> {
        let mut blocked = Vec::new();
        let mut dead: Vec<u64> = Vec::new();
        let mut st = self.state.lock().unwrap();
        for (&handle, e) in st.iter_mut() {
            let mut fatal = false;
            while !e.buf.is_empty() {
                let (front, _) = e.buf.as_slices();
                match nb_write(e.inner_fd, front) {
                    WriteOutcome::Wrote(n) => {
                        e.buf.drain(..n);
                    }
                    WriteOutcome::WouldBlock => break, // socketpair full; wait
                    WriteOutcome::Fatal => {
                        // The app end is gone (EPIPE/ECONNRESET). Nothing can be
                        // delivered; drop the entry so we don't spin on a dead fd.
                        fatal = true;
                        break;
                    }
                }
            }
            if fatal {
                dead.push(handle);
            } else if !e.buf.is_empty() {
                blocked.push(e.inner_fd);
            } else if e.eof && !e.eof_done {
                unsafe {
                    libc::shutdown(e.inner_fd, libc::SHUT_WR);
                }
                e.eof_done = true;
            }
        }
        for h in dead {
            st.remove(&h);
        }
        blocked
    }

    fn has_work(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .values()
            .any(|e| !e.buf.is_empty() || (e.eof && !e.eof_done))
    }
}

/// The shared recv pump (starts its flusher thread on first use).
pub fn recv_pump() -> &'static RecvPump {
    static M: OnceLock<RecvPump> = OnceLock::new();
    let pump = M.get_or_init(RecvPump::new);
    static START: Once = Once::new();
    START.call_once(|| {
        std::thread::Builder::new()
            .name("ax25-recv-flush".into())
            .spawn(|| flusher_loop(recv_pump()))
            .ok();
    });
    pump
}

fn flusher_loop(pump: &'static RecvPump) {
    loop {
        // Park until there is a backlog or a pending EOF to deliver.
        {
            let st = pump.state.lock().unwrap();
            let _guard = pump
                .cv
                .wait_while(st, |m| !m.values().any(|e| !e.buf.is_empty() || (e.eof && !e.eof_done)))
                .unwrap();
        }
        // Drain as much as possible, then wait for the app to make room.
        let blocked = pump.drain_pass();
        if !blocked.is_empty() {
            let mut pfds: Vec<libc::pollfd> = blocked
                .iter()
                .map(|&fd| libc::pollfd { fd, events: libc::POLLOUT, revents: 0 })
                .collect();
            unsafe {
                real::poll()(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, 100);
            }
        } else if !pump.has_work() {
            // Nothing left; loop back to park on the condvar.
            continue;
        }
    }
}

/// Outcome of a non-blocking socketpair write.
enum WriteOutcome {
    /// Wrote this many bytes (>= 1).
    Wrote(usize),
    /// The socketpair is full (EAGAIN); retry after the app reads.
    WouldBlock,
    /// The app end is gone (EPIPE/ECONNRESET/EBADF); the handle is dead.
    Fatal,
}

/// A single non-blocking write to a socketpair inner fd. Uses real libc so it
/// never re-enters our interposer. Distinguishes EAGAIN (retryable back-pressure)
/// from a fatal peer-gone error so the flusher never spins on a dead fd.
fn nb_write(inner_fd: c_int, data: &[u8]) -> WriteOutcome {
    if data.is_empty() {
        return WriteOutcome::Wrote(0);
    }
    let send = real::send();
    let n = unsafe {
        send(
            inner_fd,
            data.as_ptr() as *const c_void,
            data.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if n > 0 {
        return WriteOutcome::Wrote(n as usize);
    }
    let err = unsafe { *libc::__errno_location() };
    if err == libc::EAGAIN || err == libc::EWOULDBLOCK || err == libc::EINTR {
        WriteOutcome::WouldBlock
    } else {
        WriteOutcome::Fatal
    }
}

/// Is this fd one of ours (an AF_AX25 socket we created)?
pub fn is_ax25_fd(fd: c_int) -> bool {
    fds().lock().unwrap().contains_key(&fd)
}

/// Lazily connect (and cache) the shared RHP client. Returns None on failure.
pub fn ensure_client() -> Option<Arc<RhpClient>> {
    static CLIENT: OnceLock<Mutex<Option<Arc<RhpClient>>>> = OnceLock::new();
    let cell = CLIENT.get_or_init(|| Mutex::new(None));
    let mut guard = cell.lock().unwrap();
    if let Some(c) = guard.as_ref() {
        if !c.is_closed() {
            return Some(c.clone());
        }
    }
    match RhpClient::connect(Arc::new(InterposeSink)) {
        Ok(c) => {
            let arc = Arc::new(c);
            *guard = Some(arc.clone());
            Some(arc)
        }
        Err(_) => None,
    }
}

/// Create a socketpair-backed AX.25 fd and register it. Returns the app fd.
pub fn create_ax25_fd() -> Option<c_int> {
    let mut pair = [0 as c_int; 2];
    // socketpair is not interposed, so this calls real libc directly.
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, pair.as_mut_ptr()) };
    if r != 0 {
        return None;
    }
    let (app_fd, inner_fd) = (pair[0], pair[1]);
    fds().lock().unwrap().insert(
        app_fd,
        FdState {
            app_fd,
            inner_fd,
            handle: None,
            local: None,
            remote: None,
            listening: false,
            paclen: None,
            window: None,
        },
    );
    Some(app_fd)
}

/// Tear down an AX.25 fd: unregister maps and close both socketpair ends.
pub fn destroy_ax25_fd(fd: c_int) {
    let state = fds().lock().unwrap().remove(&fd);
    if let Some(s) = state {
        if let Some(h) = s.handle {
            // Remove pump/gate entries BEFORE closing the fd so the flusher can
            // never write to (or a reused) fd behind our back.
            recv_pump().unregister(h);
            connect_gates().lock().unwrap().remove(&h);
        }
        let close = real::close();
        unsafe {
            close(s.inner_fd);
            close(s.app_fd);
        }
    }
}

/// The event sink installed on the RHP client. Runs on the reader thread.
///
/// `accept` pushes are handled by the RHP client's internal accept queue (see
/// `RhpClient::wait_accept`), so this sink does not override `on_accept`.
pub struct InterposeSink;

impl RhpEventSink for InterposeSink {
    fn on_recv(&self, handle: u64, data: &[u8]) {
        recv_pump().push(handle, data);
    }

    fn on_status(&self, handle: u64, flags: i64) {
        // Once the link is up, release a non-blocking connect's writability gate.
        if flags & STATUS_CONNECTED != 0 {
            resolve_connect_gate(handle);
        }
    }

    fn on_close(&self, handle: u64) {
        // A close on a still-gated handle is a failed non-blocking connect:
        // release the gate so the app wakes and reads SO_ERROR. On an already
        // connected handle this is a no-op and we just signal EOF.
        resolve_connect_gate(handle);
        recv_pump().mark_eof(handle);
    }

    fn on_disconnect(&self) {
        // Transport gone: release every gate and EOF every live handle so
        // blocked reads/selects return.
        let gates: Vec<u64> = connect_gates().lock().unwrap().keys().copied().collect();
        for h in gates {
            resolve_connect_gate(h);
        }
        recv_pump().shutdown_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Back-pressure: pushing far more than a socketpair can hold must never
    /// drop or reorder bytes, and a close (EOF) must arrive only after the whole
    /// backlog has been delivered.
    #[test]
    fn recv_pump_never_drops_data_and_eof_follows_backlog() {
        let mut sv = [0 as c_int; 2];
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
        assert_eq!(r, 0, "socketpair failed");
        let (app_fd, inner_fd) = (sv[0], sv[1]);

        // A unique handle that cannot collide with other tests in this binary.
        let handle: u64 = 0x5EED_0001;
        let pump = recv_pump();
        pump.register(handle, inner_fd);

        // Far exceed the socketpair's buffer so most of it must be buffered and
        // flushed as the reader drains. Fill with a checkable pattern.
        let total = 1024 * 1024;
        let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        pump.push(handle, &data);
        // Close arrives while a large backlog is still queued.
        pump.mark_eof(handle);

        // Read everything back until EOF; the flusher drains as we make room.
        let mut got: Vec<u8> = Vec::with_capacity(total);
        let mut buf = [0u8; 8192];
        loop {
            let n = unsafe {
                libc::read(app_fd, buf.as_mut_ptr() as *mut c_void, buf.len())
            };
            if n == 0 {
                break; // EOF (SHUT_WR), delivered only after the backlog drained
            }
            assert!(n > 0, "read error at {} bytes", got.len());
            got.extend_from_slice(&buf[..n as usize]);
        }

        assert_eq!(got.len(), total, "lost data under back-pressure");
        assert_eq!(got, data, "data reordered/corrupted under back-pressure");

        pump.unregister(handle);
        unsafe {
            libc::close(app_fd);
            libc::close(inner_fd);
        }
    }
}
