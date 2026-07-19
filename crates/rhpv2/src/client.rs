// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Synchronous, multiplexed RHPv2 client.
//
// One TCP connection to the pdn RHP engine (127.0.0.1:9000 by default),
// persistent and shared by many logical AX.25 connections. A single background
// reader thread demultiplexes inbound frames:
//   * frames with an `id` matching a pending request wake that request;
//   * everything else (recv / accept / status / server-initiated close) is an
//     async push dispatched to the installed `RhpEventSink`.
//
// This mirrors the reference MIT client (rhp2lib-net RhpClient.cs) but is
// synchronous with a thread instead of async/await, because it is driven from
// libc-interposed calls that are themselves synchronous.
//
// Beyond the sink, the client keeps two internal registries so callers can wait
// on asynchronous link events without racing the reader thread:
//   * a per-handle *connect state* (Pending -> Connected / Failed), fed by the
//     post-open `status`/`close` pushes — an outbound AX.25 connect is not
//     complete on the openReply, only once a status(Connected) push arrives;
//   * a per-listener *accept queue*, fed by `accept` pushes, so a blocking
//     accept() can park on a condvar instead of busy-waiting.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use crate::codec;
use crate::errors::errcode_to_errno;
use crate::framing::{read_frame, write_frame};
use crate::messages::{
    AuthReq, BindReq, CloseReq, Frame, ListenReq, OpenReq, SendReq, SendToReq, SocketReq,
    MAX_SEND_CHUNK, OPEN_FLAG_ACTIVE, OPEN_FLAG_PASSIVE, STATUS_CONNECTED,
};

/// Default request/reply timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Callbacks for asynchronous server pushes. Implemented by the interposer to
/// wire RHP `recv` bytes into a socketpair, react to link-state changes, etc.
///
/// All methods are called from the single reader thread and must not block for
/// long or re-enter the client with a request/reply call.
///
/// Note: `accept` pushes are ALSO queued internally (see [`RhpClient::wait_accept`])
/// and the post-open connect transition is tracked internally (see
/// [`RhpClient::wait_connected`]); the sink callbacks are additional hooks, not
/// the source of truth for those two flows.
pub trait RhpEventSink: Send + Sync {
    /// Inbound data on a connected (stream) handle.
    fn on_recv(&self, _handle: u64, _data: &[u8]) {}
    /// An inbound connectionless UI datagram on a `custom`-mode handle. `source`
    /// is the sender's callsign, `dest` the destination it was addressed to, and
    /// `data` the raw custom payload whose first octet is the AX.25 PID (`[PID]
    /// [info…]`). All UI heard on the bound port is delivered (promiscuous),
    /// matching pdn's connectionless RX.
    fn on_dgram(
        &self,
        _handle: u64,
        _source: Option<String>,
        _dest: Option<String>,
        _data: &[u8],
    ) {
    }
    /// A listener accepted an inbound connection (`child` is the new handle).
    fn on_accept(&self, _listener: u64, _child: u64, _remote: Option<String>, _local: Option<String>) {}
    /// Link-state change for a handle (RHP StatusFlags bitfield).
    fn on_status(&self, _handle: u64, _flags: i64) {}
    /// Server-initiated close (EOF) for a handle.
    fn on_close(&self, _handle: u64) {}
    /// The transport itself went away; all handles are dead.
    fn on_disconnect(&self) {}
}

/// A sink that ignores everything (useful when only request/reply is needed).
pub struct NullSink;
impl RhpEventSink for NullSink {}

/// Errors surfaced by high-level client operations.
#[derive(Debug)]
pub enum RhpError {
    /// Transport failure (socket closed, IO error).
    Io(io::Error),
    /// No reply arrived within the timeout.
    Timeout,
    /// The server returned a non-zero `errCode`.
    Server { errcode: i64, errtext: Option<String> },
}

impl RhpError {
    /// Best-effort POSIX errno for this failure (for the interposer).
    pub fn to_errno(&self) -> i32 {
        match self {
            RhpError::Io(_) => libc::EIO,
            RhpError::Timeout => libc::ETIMEDOUT,
            RhpError::Server { errcode, .. } => errcode_to_errno(*errcode),
        }
    }
}

impl From<io::Error> for RhpError {
    fn from(e: io::Error) -> Self {
        RhpError::Io(e)
    }
}

impl std::fmt::Display for RhpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RhpError::Io(e) => write!(f, "rhp transport error: {e}"),
            RhpError::Timeout => write!(f, "rhp request timed out"),
            RhpError::Server { errcode, errtext } => {
                write!(f, "rhp server error {errcode} ({})", errtext.as_deref().unwrap_or("?"))
            }
        }
    }
}

impl std::error::Error for RhpError {}

/// Outcome of a successful `open`.
#[derive(Debug, Clone)]
pub struct OpenResult {
    pub handle: u64,
    pub errcode: i64,
    pub errtext: Option<String>,
}

/// The link state of an outbound connect handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnPhase {
    /// `open` accepted; awaiting the SABM/UA handshake (status(Connected)).
    Pending,
    /// The AX.25 link is up.
    Connected,
    /// The connect failed; carries the POSIX errno to report.
    Failed(i32),
}

/// A pending inbound connection surfaced by an `accept` push.
#[derive(Debug, Clone)]
pub struct AcceptInfo {
    /// The new child handle for the accepted connection.
    pub child_handle: u64,
    /// The remote (caller) callsign, if the engine reported one.
    pub remote: Option<String>,
    /// The local callsign the caller reached, if the engine reported one.
    pub local: Option<String>,
}

type PendingMap = Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>;

/// Per-handle connect-state registry, updated by the reader thread from
/// post-open `status`/`close` pushes.
#[derive(Default)]
struct ConnRegistry {
    map: Mutex<HashMap<u64, ConnPhase>>,
    cv: Condvar,
}

impl ConnRegistry {
    /// Arm tracking for a freshly-opened outbound handle. Never downgrades a
    /// state a racing push already set (the status push can be processed before
    /// `open_connect` returns).
    fn set_pending(&self, handle: u64) {
        self.map.lock().unwrap().entry(handle).or_insert(ConnPhase::Pending);
    }

    fn mark_connected(&self, handle: u64) {
        self.map.lock().unwrap().insert(handle, ConnPhase::Connected);
        self.cv.notify_all();
    }

    /// Fail a still-pending connect. A close on an already-Connected handle is a
    /// normal EOF, not a connect failure, so we only transition from Pending.
    fn mark_failed(&self, handle: u64, errno: i32) {
        {
            let mut m = self.map.lock().unwrap();
            if let Some(p) = m.get_mut(&handle) {
                if *p == ConnPhase::Pending {
                    *p = ConnPhase::Failed(errno);
                }
            }
        }
        self.cv.notify_all();
    }

    /// Transport went away: fault every in-flight connect so waiters wake.
    fn fail_all_pending(&self, errno: i32) {
        {
            let mut m = self.map.lock().unwrap();
            for p in m.values_mut() {
                if *p == ConnPhase::Pending {
                    *p = ConnPhase::Failed(errno);
                }
            }
        }
        self.cv.notify_all();
    }

    fn result(&self, handle: u64) -> Option<Result<(), i32>> {
        match self.map.lock().unwrap().get(&handle) {
            Some(ConnPhase::Connected) => Some(Ok(())),
            Some(ConnPhase::Failed(e)) => Some(Err(*e)),
            _ => None,
        }
    }

    /// Read-and-clear the pending connect error (SO_ERROR semantics): returns
    /// the errno once, then reports success on subsequent reads.
    fn take_error(&self, handle: u64) -> i32 {
        let mut m = self.map.lock().unwrap();
        match m.get_mut(&handle) {
            Some(p) => {
                let e = if let ConnPhase::Failed(x) = *p { x } else { 0 };
                if e != 0 {
                    *p = ConnPhase::Connected;
                }
                e
            }
            None => 0,
        }
    }

    fn forget(&self, handle: u64) {
        self.map.lock().unwrap().remove(&handle);
    }
}

/// Per-listener queue of accepted children, updated by the reader thread.
#[derive(Default)]
struct AcceptRegistry {
    map: Mutex<HashMap<u64, VecDeque<AcceptInfo>>>,
    cv: Condvar,
}

impl AcceptRegistry {
    fn push(&self, listener: u64, info: AcceptInfo) {
        self.map.lock().unwrap().entry(listener).or_default().push_back(info);
        self.cv.notify_all();
    }

    fn forget(&self, listener: u64) {
        self.map.lock().unwrap().remove(&listener);
    }
}

/// A live RHPv2 client connection.
pub struct RhpClient {
    writer: Mutex<TcpStream>,
    next_id: AtomicU64,
    pending: PendingMap,
    conns: Arc<ConnRegistry>,
    accepts: Arc<AcceptRegistry>,
    closed: Arc<AtomicBool>,
    timeout: Duration,
    _sink: Arc<dyn RhpEventSink>,
}

impl RhpClient {
    /// Resolve the RHP engine address: `PDN_RHP_ADDR` env (host:port) or the
    /// default `127.0.0.1:9000`.
    pub fn default_addr() -> String {
        std::env::var("PDN_RHP_ADDR").unwrap_or_else(|_| "127.0.0.1:9000".to_string())
    }

    /// Connect to the default (or env-overridden) engine address.
    pub fn connect(sink: Arc<dyn RhpEventSink>) -> Result<RhpClient, RhpError> {
        let addr = Self::default_addr();
        Self::connect_to(addr, sink)
    }

    /// Connect to a specific address (used by tests and by `connect`).
    pub fn connect_to<A: ToSocketAddrs>(
        addr: A,
        sink: Arc<dyn RhpEventSink>,
    ) -> Result<RhpClient, RhpError> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        let read_half = stream.try_clone()?;

        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let conns: Arc<ConnRegistry> = Arc::new(ConnRegistry::default());
        let accepts: Arc<AcceptRegistry> = Arc::new(AcceptRegistry::default());
        let closed = Arc::new(AtomicBool::new(false));

        // Reader thread: demux id-matched replies vs async pushes.
        {
            let pending = pending.clone();
            let conns = conns.clone();
            let accepts = accepts.clone();
            let closed = closed.clone();
            let sink = sink.clone();
            std::thread::Builder::new()
                .name("rhp-reader".into())
                .spawn(move || reader_loop(read_half, pending, conns, accepts, closed, sink))
                .map_err(RhpError::Io)?;
        }

        let client = RhpClient {
            writer: Mutex::new(stream),
            next_id: AtomicU64::new(0),
            pending,
            conns,
            accepts,
            closed,
            timeout: DEFAULT_TIMEOUT,
            _sink: sink,
        };

        // Optional auth (loopback clients skip this).
        if let (Ok(user), Ok(pass)) = (
            std::env::var("PDN_RHP_USER"),
            std::env::var("PDN_RHP_PASS"),
        ) {
            client.auth(&user, &pass)?;
        }

        Ok(client)
    }

    /// True once the transport has closed.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn next_id(&self) -> u64 {
        // Monotonic, never zero.
        1 + self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Serialise + send a request, then block for the id-matched reply.
    fn request(&self, id: u64, bytes: &[u8]) -> Result<Frame, RhpError> {
        let (tx, rx) = mpsc::channel::<Frame>();
        self.pending.lock().unwrap().insert(id, tx);

        let send_result = {
            let mut w = self.writer.lock().unwrap();
            write_frame(&mut *w, bytes)
        };
        if let Err(e) = send_result {
            self.pending.lock().unwrap().remove(&id);
            return Err(RhpError::Io(e));
        }

        let reply = rx.recv_timeout(self.timeout);
        self.pending.lock().unwrap().remove(&id);
        match reply {
            Ok(frame) => Ok(frame),
            Err(RecvTimeoutError::Timeout) => Err(RhpError::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                Err(RhpError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "rhp connection closed")))
            }
        }
    }

    /// Send a fire-and-forget request whose reply we do not correlate.
    #[allow(dead_code)]
    fn send_oneway(&self, bytes: &[u8]) -> Result<(), RhpError> {
        let mut w = self.writer.lock().unwrap();
        write_frame(&mut *w, bytes).map_err(RhpError::Io)
    }

    fn check_ok(frame: &Frame) -> Result<(), RhpError> {
        let code = frame.errcode();
        // xrouter quirk: connectReply mirrors the handle in errCode on success
        // but sets errText="Ok". Treat textual Ok as success regardless of code.
        let ok_text = frame.errtext().map(|t| t.eq_ignore_ascii_case("ok")).unwrap_or(false);
        if code != 0 && !ok_text {
            return Err(RhpError::Server {
                errcode: code,
                errtext: frame.errtext().map(|s| s.to_string()),
            });
        }
        Ok(())
    }

    // ---- high-level operations -------------------------------------------

    /// Authenticate (only when the engine requires it; loopback skips this).
    pub fn auth(&self, user: &str, pass: &str) -> Result<(), RhpError> {
        let id = self.next_id();
        let req = AuthReq { typ: "auth", id, user, pass };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)
    }

    /// Outbound connect: `open` with `flags:128` (Active). Returns the handle.
    ///
    /// A successful return means only that the engine accepted the `open` — the
    /// AX.25 link is not up yet. The handle is registered as [`ConnPhase::Pending`];
    /// callers must [`wait_connected`](Self::wait_connected) (or poll
    /// [`connect_result`](Self::connect_result)) for the SABM/UA handshake.
    pub fn open_connect(&self, local: &str, remote: &str) -> Result<OpenResult, RhpError> {
        let res = self.open(local, Some(remote), OPEN_FLAG_ACTIVE)?;
        self.conns.set_pending(res.handle);
        Ok(res)
    }

    /// Passive listener open (no remote, `flags:0`).
    pub fn open_listen(&self, local: &str) -> Result<OpenResult, RhpError> {
        self.open(local, None, OPEN_FLAG_PASSIVE)
    }

    fn open(&self, local: &str, remote: Option<&str>, flags: u32) -> Result<OpenResult, RhpError> {
        let id = self.next_id();
        let req = OpenReq {
            typ: "open",
            id,
            pfam: "ax25",
            mode: "stream",
            port: None,
            local,
            remote,
            flags,
        };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)?;
        let handle = reply.handle().ok_or_else(|| RhpError::Server {
            errcode: 1,
            errtext: Some("openReply missing handle".into()),
        })?;
        Ok(OpenResult {
            handle,
            errcode: reply.errcode(),
            errtext: reply.errtext().map(|s| s.to_string()),
        })
    }

    /// Block until an outbound connect handle reaches a terminal state.
    ///
    /// Returns `Ok(())` once a status(Connected) push arrives, or `Err(errno)`
    /// if the connect failed (a `close` push, or the transport dropping). With
    /// `timeout = None` this blocks until resolved or the transport dies; with
    /// `Some(d)` it gives up after `d` and returns `Err(ETIMEDOUT)`.
    pub fn wait_connected(&self, handle: u64, timeout: Option<Duration>) -> Result<(), i32> {
        let mut m = self.conns.map.lock().unwrap();
        loop {
            match m.get(&handle) {
                Some(ConnPhase::Connected) => return Ok(()),
                Some(ConnPhase::Failed(e)) => return Err(*e),
                _ => {}
            }
            if self.closed.load(Ordering::SeqCst) {
                return Err(libc::ECONNRESET);
            }
            m = match timeout {
                None => self.conns.cv.wait(m).unwrap(),
                Some(d) => {
                    let (mm, res) = self.conns.cv.wait_timeout(m, d).unwrap();
                    if res.timed_out() {
                        return match mm.get(&handle) {
                            Some(ConnPhase::Connected) => Ok(()),
                            Some(ConnPhase::Failed(e)) => Err(*e),
                            _ => Err(libc::ETIMEDOUT),
                        };
                    }
                    mm
                }
            };
        }
    }

    /// Non-blocking peek at an outbound connect's outcome: `None` while pending,
    /// `Some(Ok)` once connected, `Some(Err(errno))` once failed.
    pub fn connect_result(&self, handle: u64) -> Option<Result<(), i32>> {
        self.conns.result(handle)
    }

    /// Read-and-clear the pending connect error for SO_ERROR: returns the errno
    /// once (0 if connected/pending), then 0 on subsequent reads.
    pub fn take_connect_error(&self, handle: u64) -> i32 {
        self.conns.take_error(handle)
    }

    /// Send data on a connected handle, chunking to <= MAX_SEND_CHUNK bytes.
    pub fn send(&self, handle: u64, data: &[u8]) -> Result<(), RhpError> {
        if data.is_empty() {
            return self.send_chunk(handle, &[]);
        }
        for chunk in data.chunks(MAX_SEND_CHUNK) {
            self.send_chunk(handle, chunk)?;
        }
        Ok(())
    }

    fn send_chunk(&self, handle: u64, chunk: &[u8]) -> Result<(), RhpError> {
        let id = self.next_id();
        let wire = codec::to_wire_string(chunk);
        let req = SendReq { typ: "send", id, handle, data: &wire };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)
    }

    /// Send one connectionless UI datagram (`sendto`, RHPv2 `custom` mode).
    /// `remote` is the destination callsign, `local` the source (bound) callsign,
    /// and `data` the custom payload whose first octet is the AX.25 PID (`[PID]
    /// [info…]`; 0xF0 for no-Layer-3). pdn rejects an empty `data` (errCode 1), so
    /// callers should filter that before calling.
    pub fn sendto(
        &self,
        handle: u64,
        remote: &str,
        local: &str,
        data: &[u8],
    ) -> Result<(), RhpError> {
        let id = self.next_id();
        let wire = codec::to_wire_string(data);
        let req = SendToReq { typ: "sendto", id, handle, remote, local, data: &wire };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)
    }

    /// Close a handle. Also drops any connect-state / accept-queue entries.
    pub fn close(&self, handle: u64) -> Result<(), RhpError> {
        self.conns.forget(handle);
        self.accepts.forget(handle);
        let id = self.next_id();
        let req = CloseReq { typ: "close", id, handle };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)
    }

    // ---- BSD-style listener path (socket/bind/listen) --------------------

    /// Allocate a connected-stream socket handle (`socket`, mode `stream`).
    pub fn socket(&self) -> Result<u64, RhpError> {
        self.socket_mode("stream")
    }

    /// Allocate a connectionless-UI socket handle (`socket`, mode `custom`). The
    /// PID travels in `data[0]` of each `sendto`/`recv` (RHPv2 `custom`), not a
    /// separate field.
    pub fn socket_dgram(&self) -> Result<u64, RhpError> {
        self.socket_mode("custom")
    }

    fn socket_mode(&self, mode: &str) -> Result<u64, RhpError> {
        let id = self.next_id();
        let req = SocketReq { typ: "socket", id, pfam: "ax25", mode };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)?;
        reply.handle().ok_or_else(|| RhpError::Server {
            errcode: 1,
            errtext: Some("socketReply missing handle".into()),
        })
    }

    /// Bind a local callsign (and optional port) to a handle.
    pub fn bind(&self, handle: u64, local: &str, port: Option<&str>) -> Result<(), RhpError> {
        let id = self.next_id();
        let req = BindReq { typ: "bind", id, handle, local, port };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)
    }

    /// Start listening on a bound handle.
    pub fn listen(&self, handle: u64) -> Result<(), RhpError> {
        let id = self.next_id();
        let req = ListenReq { typ: "listen", id, handle, flags: 0 };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)
    }

    /// Block until an inbound connection is accepted on `listener`.
    ///
    /// Returns `Some(info)` for the next queued `accept` push, or `None` if the
    /// transport dropped (or the timeout elapsed). With `timeout = None` this
    /// blocks indefinitely; with `Some(d)` it returns `None` after `d`.
    pub fn wait_accept(&self, listener: u64, timeout: Option<Duration>) -> Option<AcceptInfo> {
        let mut m = self.accepts.map.lock().unwrap();
        loop {
            if let Some(q) = m.get_mut(&listener) {
                if let Some(info) = q.pop_front() {
                    return Some(info);
                }
            }
            if self.closed.load(Ordering::SeqCst) {
                return None;
            }
            m = match timeout {
                None => self.accepts.cv.wait(m).unwrap(),
                Some(d) => {
                    let (mut mm, res) = self.accepts.cv.wait_timeout(m, d).unwrap();
                    if res.timed_out() {
                        return mm.get_mut(&listener).and_then(|q| q.pop_front());
                    }
                    mm
                }
            };
        }
    }

    /// Non-blocking accept: pop the next queued child, or `None` if none waiting.
    pub fn try_accept(&self, listener: u64) -> Option<AcceptInfo> {
        self.accepts.map.lock().unwrap().get_mut(&listener).and_then(|q| q.pop_front())
    }
}

/// Wrap a serde_json error as an RhpError::Io (serialisation cannot really fail
/// for our owned structs, but keeps the `?` ergonomics clean).
fn json_io(e: serde_json::Error) -> RhpError {
    RhpError::Io(io::Error::new(io::ErrorKind::InvalidData, e))
}

fn reader_loop(
    mut stream: TcpStream,
    pending: PendingMap,
    conns: Arc<ConnRegistry>,
    accepts: Arc<AcceptRegistry>,
    closed: Arc<AtomicBool>,
    sink: Arc<dyn RhpEventSink>,
) {
    loop {
        match read_frame(&mut stream) {
            Ok(None) => break,             // clean EOF
            Ok(Some(bytes)) => {
                let frame = match Frame::parse(&bytes) {
                    Ok(f) => f,
                    Err(_) => continue,    // skip undecodable frame
                };

                // id-matched reply?
                if let Some(id) = frame.id() {
                    if let Some(tx) = pending.lock().unwrap().remove(&id) {
                        let _ = tx.send(frame);
                        continue;
                    }
                    // id present but unknown: fall through to push dispatch.
                }

                dispatch_push(&frame, &conns, &accepts, &sink);
            }
            Err(_) => break,               // transport error
        }
    }

    closed.store(true, Ordering::SeqCst);
    // Fault any in-flight requests so their callers stop waiting.
    pending.lock().unwrap().clear();
    // Fault in-flight connects and wake blocked accepts.
    conns.fail_all_pending(libc::ECONNRESET);
    accepts.cv.notify_all();
    sink.on_disconnect();
}

fn dispatch_push(
    frame: &Frame,
    conns: &Arc<ConnRegistry>,
    accepts: &Arc<AcceptRegistry>,
    sink: &Arc<dyn RhpEventSink>,
) {
    match frame.typ() {
        "recv" => {
            if let Some(h) = frame.handle() {
                let data = frame.data_str().map(codec::from_wire_string).unwrap_or_default();
                if frame.is_dgram_recv() {
                    // Connectionless UI (custom mode): carries source (remote) and
                    // dest (local); the PID is data[0] of `data`.
                    let source = frame.remote().map(|s| s.to_string());
                    let dest = frame.local().map(|s| s.to_string());
                    sink.on_dgram(h, source, dest, &data);
                } else {
                    sink.on_recv(h, &data);
                }
            }
        }
        "accept" => {
            if let (Some(listener), Some(child)) = (frame.handle(), frame.child()) {
                let remote = frame.remote().map(|s| s.to_string());
                let local = frame.local().map(|s| s.to_string());
                accepts.push(
                    listener,
                    AcceptInfo { child_handle: child, remote: remote.clone(), local: local.clone() },
                );
                sink.on_accept(listener, child, remote, local);
            }
        }
        "status" => {
            if let Some(h) = frame.handle() {
                let flags = frame.status_flags();
                if flags & STATUS_CONNECTED != 0 {
                    conns.mark_connected(h);
                }
                sink.on_status(h, flags);
            }
        }
        "close" => {
            // Server-initiated close (no id) == EOF, or a connect that failed
            // before the link came up. When the close carries a reason (errCode),
            // surface that errno; otherwise a bare close during connect is a
            // refusal (DM / busy / SABM timeout).
            if let Some(h) = frame.handle() {
                let errno = match frame.errcode() {
                    0 => libc::ECONNREFUSED,
                    code => errcode_to_errno(code),
                };
                conns.mark_failed(h, errno);
                sink.on_close(h);
            }
        }
        _ => { /* unknown push: ignore for forward-compat */ }
    }
}

// ----------------------------------------------------------------------------
// A simple buffering sink for standalone / test use.
// ----------------------------------------------------------------------------

/// A sink that buffers recv bytes per handle and records EOF, so a caller can
/// poll for received data without a socketpair. Used by tests; the interposer
/// installs its own socketpair-backed sink instead.
#[derive(Default)]
pub struct BufferingSink {
    inner: Mutex<HashMap<u64, HandleBuf>>,
}

#[derive(Default)]
struct HandleBuf {
    data: Vec<u8>,
    eof: bool,
}

impl BufferingSink {
    pub fn new() -> Arc<BufferingSink> {
        Arc::new(BufferingSink::default())
    }

    /// Drain any buffered bytes for a handle.
    pub fn take(&self, handle: u64) -> Vec<u8> {
        let mut map = self.inner.lock().unwrap();
        map.get_mut(&handle).map(|b| std::mem::take(&mut b.data)).unwrap_or_default()
    }

    /// Whether the handle has seen a server-initiated close.
    pub fn is_eof(&self, handle: u64) -> bool {
        self.inner.lock().unwrap().get(&handle).map(|b| b.eof).unwrap_or(false)
    }
}

impl RhpEventSink for BufferingSink {
    fn on_recv(&self, handle: u64, data: &[u8]) {
        self.inner.lock().unwrap().entry(handle).or_default().data.extend_from_slice(data);
    }
    fn on_close(&self, handle: u64) {
        self.inner.lock().unwrap().entry(handle).or_default().eof = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    /// A minimal mock RHP server: accepts one connection, runs `handler` on it.
    fn spawn_mock<F>(handler: F) -> String
    where
        F: FnOnce(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            handler(sock);
        });
        addr
    }

    #[test]
    fn open_correlates_reply_by_id() {
        let addr = spawn_mock(|mut sock| {
            // Read the open request, echo its id in an openReply.
            let req = read_frame(&mut sock).unwrap().unwrap();
            let f = Frame::parse(&req).unwrap();
            assert_eq!(f.typ(), "open");
            let id = f.id().unwrap();
            let reply = format!(
                r#"{{"type":"openReply","id":{id},"handle":42,"errCode":0,"errText":"Ok"}}"#
            );
            write_frame(&mut sock, reply.as_bytes()).unwrap();
            // Keep the socket open briefly so the client can read the reply.
            std::thread::sleep(Duration::from_millis(100));
        });

        let client = RhpClient::connect_to(addr, Arc::new(NullSink)).unwrap();
        let res = client.open_connect("M0LTE-1", "GB7RDG").unwrap();
        assert_eq!(res.handle, 42);
    }

    #[test]
    fn recv_push_routes_to_sink() {
        let addr = spawn_mock(|mut sock| {
            let req = read_frame(&mut sock).unwrap().unwrap();
            let f = Frame::parse(&req).unwrap();
            let id = f.id().unwrap();
            let reply =
                format!(r#"{{"type":"openReply","id":{id},"handle":7,"errCode":0,"errText":"Ok"}}"#);
            write_frame(&mut sock, reply.as_bytes()).unwrap();
            // Async recv push (no id), data "AB" == [0x41,0x42].
            write_frame(&mut sock, br#"{"type":"recv","handle":7,"data":"AB","seqno":0}"#).unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });

        let sink = BufferingSink::new();
        let client = RhpClient::connect_to(addr, sink.clone()).unwrap();
        let res = client.open_connect("M0LTE", "GB7RDG").unwrap();
        assert_eq!(res.handle, 7);

        // Give the push time to arrive.
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(sink.take(7), vec![0x41, 0x42]);
    }

    #[test]
    fn server_error_maps_to_errno() {
        let addr = spawn_mock(|mut sock| {
            let req = read_frame(&mut sock).unwrap().unwrap();
            let f = Frame::parse(&req).unwrap();
            let id = f.id().unwrap();
            // errCode 8 == Bad/missing family == EAFNOSUPPORT.
            let reply = format!(
                r#"{{"type":"openReply","id":{id},"errCode":8,"errText":"Bad family"}}"#
            );
            write_frame(&mut sock, reply.as_bytes()).unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        let client = RhpClient::connect_to(addr, Arc::new(NullSink)).unwrap();
        let err = client.open_connect("M0LTE", "GB7RDG").unwrap_err();
        assert_eq!(err.to_errno(), libc::EAFNOSUPPORT);
    }

    #[test]
    fn connect_completes_only_after_status_connected_push() {
        // The mock accepts the open, then sleeps before sending status(Connected).
        // We prove the handle stays Pending until that push, then flips Connected.
        let addr = spawn_mock(|mut sock| {
            let req = read_frame(&mut sock).unwrap().unwrap();
            let id = Frame::parse(&req).unwrap().id().unwrap();
            let reply =
                format!(r#"{{"type":"openReply","id":{id},"handle":5,"errCode":0,"errText":"Ok"}}"#);
            write_frame(&mut sock, reply.as_bytes()).unwrap();
            sock.flush().unwrap();
            // Link handshake takes time.
            std::thread::sleep(Duration::from_millis(150));
            write_frame(&mut sock, br#"{"type":"status","handle":5,"flags":2}"#).unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        let client = Arc::new(RhpClient::connect_to(addr, Arc::new(NullSink)).unwrap());
        let res = client.open_connect("M0LTE", "GB7RDG").unwrap();
        assert_eq!(res.handle, 5);

        // openReply alone must NOT count as connected.
        assert_eq!(client.connect_result(5), None, "connected on openReply alone");

        // Block until connected; prove we actually waited for the push.
        let start = std::time::Instant::now();
        let outcome = client.wait_connected(5, Some(Duration::from_secs(5)));
        assert_eq!(outcome, Ok(()));
        assert!(
            start.elapsed() >= Duration::from_millis(120),
            "wait_connected returned before the status push arrived"
        );
        assert_eq!(client.connect_result(5), Some(Ok(())));
    }

    #[test]
    fn connect_fails_on_close_push() {
        let addr = spawn_mock(|mut sock| {
            let req = read_frame(&mut sock).unwrap().unwrap();
            let id = Frame::parse(&req).unwrap().id().unwrap();
            let reply =
                format!(r#"{{"type":"openReply","id":{id},"handle":9,"errCode":0,"errText":"Ok"}}"#);
            write_frame(&mut sock, reply.as_bytes()).unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(80));
            // Link never came up: the engine closes the handle (e.g. DM / busy).
            write_frame(&mut sock, br#"{"type":"close","handle":9}"#).unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(80));
        });

        let client = RhpClient::connect_to(addr, Arc::new(NullSink)).unwrap();
        let res = client.open_connect("M0LTE", "GB7RDG").unwrap();
        assert_eq!(res.handle, 9);

        let outcome = client.wait_connected(9, Some(Duration::from_secs(5)));
        assert_eq!(outcome, Err(libc::ECONNREFUSED));
        // SO_ERROR drain: reports the errno once, then 0.
        assert_eq!(client.take_connect_error(9), libc::ECONNREFUSED);
        assert_eq!(client.take_connect_error(9), 0);
    }

    #[test]
    fn connect_failure_uses_close_reason_errcode() {
        // A close push carrying an errCode should surface that specific errno,
        // not the generic ECONNREFUSED.
        let addr = spawn_mock(|mut sock| {
            let req = read_frame(&mut sock).unwrap().unwrap();
            let id = Frame::parse(&req).unwrap().id().unwrap();
            let reply =
                format!(r#"{{"type":"openReply","id":{id},"handle":4,"errCode":0,"errText":"Ok"}}"#);
            write_frame(&mut sock, reply.as_bytes()).unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(60));
            // errCode 15 == No route == EHOSTUNREACH.
            write_frame(&mut sock, br#"{"type":"close","handle":4,"errCode":15}"#).unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(60));
        });

        let client = RhpClient::connect_to(addr, Arc::new(NullSink)).unwrap();
        let res = client.open_connect("M0LTE", "GB7RDG").unwrap();
        assert_eq!(res.handle, 4);
        assert_eq!(
            client.wait_connected(4, Some(Duration::from_secs(5))),
            Err(libc::EHOSTUNREACH)
        );
    }

    #[test]
    fn accept_push_surfaces_child_with_peer_callsign() {
        let addr = spawn_mock(|mut sock| {
            // socket -> bind -> listen, each id-matched with a reply carrying the handle.
            for _ in 0..3 {
                let req = read_frame(&mut sock).unwrap().unwrap();
                let f = Frame::parse(&req).unwrap();
                let id = f.id().unwrap();
                let reply = format!(
                    r#"{{"type":"{}Reply","id":{id},"handle":3,"errCode":0,"errText":"Ok"}}"#,
                    f.typ()
                );
                write_frame(&mut sock, reply.as_bytes()).unwrap();
                sock.flush().unwrap();
            }
            std::thread::sleep(Duration::from_millis(100));
            // Inbound connection: an accept push naming the caller.
            write_frame(
                &mut sock,
                br#"{"type":"accept","handle":3,"child":77,"remote":"M0ABC-2","local":"GB7RDG-1"}"#,
            )
            .unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(100));
        });

        let client = RhpClient::connect_to(addr, Arc::new(NullSink)).unwrap();
        let h = client.socket().unwrap();
        client.bind(h, "GB7RDG-1", None).unwrap();
        client.listen(h).unwrap();

        // Nothing queued yet.
        assert!(client.try_accept(h).is_none());

        let info = client.wait_accept(h, Some(Duration::from_secs(5))).expect("accept");
        assert_eq!(info.child_handle, 77);
        assert_eq!(info.remote.as_deref(), Some("M0ABC-2"));
        assert_eq!(info.local.as_deref(), Some("GB7RDG-1"));
    }

    #[test]
    fn socket_dgram_requests_custom_mode_and_sendto_carries_pid_in_data() {
        // Capture the socket + sendto requests the client emits so we can assert
        // the custom mode and the sendto remote/local/data (PID in data[0]).
        let seen: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_w = seen.clone();
        let addr = spawn_mock(move |mut sock| {
            for _ in 0..2 {
                let req = read_frame(&mut sock).unwrap().unwrap();
                let f = Frame::parse(&req).unwrap();
                seen_w.lock().unwrap().push(f.value.clone());
                let id = f.id().unwrap();
                let reply = format!(
                    r#"{{"type":"{}Reply","id":{id},"handle":21,"errCode":0,"errText":"Ok"}}"#,
                    f.typ()
                );
                write_frame(&mut sock, reply.as_bytes()).unwrap();
                sock.flush().unwrap();
            }
            std::thread::sleep(Duration::from_millis(100));
        });

        let client = RhpClient::connect_to(addr, Arc::new(NullSink)).unwrap();
        let h = client.socket_dgram().unwrap();
        assert_eq!(h, 21);
        // The caller passes the whole custom payload: PID 0xF0 as data[0].
        let mut wire = vec![0xF0u8];
        wire.extend_from_slice(b"de M0LTE");
        client.sendto(h, "BEACON", "M0LTE-2", &wire).unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen[0]["type"], "socket");
        assert_eq!(seen[0]["mode"], "custom");
        assert_eq!(seen[1]["type"], "sendto");
        assert_eq!(seen[1]["remote"], "BEACON");
        assert_eq!(seen[1]["local"], "M0LTE-2");
        assert!(seen[1].get("pid").is_none(), "custom mode carries no pid field");
        // data[0] is the PID (0xF0 == '\u{F0}'), remainder the info field.
        assert_eq!(seen[1]["data"], "\u{F0}de M0LTE");
    }

    /// A sink that records the last dgram delivered (source/dest/data). In custom
    /// mode `data` is the raw `[PID][info…]` payload.
    #[derive(Default)]
    struct DgramSink {
        last: Mutex<Option<(Option<String>, Option<String>, Vec<u8>)>>,
    }
    impl RhpEventSink for DgramSink {
        fn on_dgram(
            &self,
            _handle: u64,
            source: Option<String>,
            dest: Option<String>,
            data: &[u8],
        ) {
            *self.last.lock().unwrap() = Some((source, dest, data.to_vec()));
        }
    }

    #[test]
    fn dgram_recv_push_routes_to_on_dgram_with_source_and_pid_in_data() {
        let addr = spawn_mock(|mut sock| {
            let req = read_frame(&mut sock).unwrap().unwrap();
            let id = Frame::parse(&req).unwrap().id().unwrap();
            let reply = format!(
                r#"{{"type":"socketReply","id":{id},"handle":8,"errCode":0,"errText":"Ok"}}"#
            );
            write_frame(&mut sock, reply.as_bytes()).unwrap();
            // Inbound UI frame: source G0ABC-1 -> dest APRS, port 0, custom data
            // "\u{F0}!pos" (PID 0xF0 as data[0], then the info "!pos").
            write_frame(
                &mut sock,
                "{\"type\":\"recv\",\"handle\":8,\"remote\":\"G0ABC-1\",\"local\":\"APRS\",\"port\":\"0\",\"data\":\"\u{F0}!pos\"}".as_bytes(),
            )
            .unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });

        let sink = Arc::new(DgramSink::default());
        let client = RhpClient::connect_to(addr, sink.clone()).unwrap();
        assert_eq!(client.socket_dgram().unwrap(), 8);
        std::thread::sleep(Duration::from_millis(80));

        let got = sink.last.lock().unwrap().clone().expect("dgram delivered");
        assert_eq!(got.0.as_deref(), Some("G0ABC-1"));
        assert_eq!(got.1.as_deref(), Some("APRS"));
        // data[0] is the PID (0xF0), remainder the info field.
        assert_eq!(got.2, vec![0xF0, b'!', b'p', b'o', b's']);
    }

    #[test]
    fn transport_drop_faults_blocked_connect_and_accept() {
        // The mock answers the open then hangs up; both waiters must unblock.
        let addr = spawn_mock(|mut sock| {
            let req = read_frame(&mut sock).unwrap().unwrap();
            let id = Frame::parse(&req).unwrap().id().unwrap();
            let reply =
                format!(r#"{{"type":"openReply","id":{id},"handle":11,"errCode":0,"errText":"Ok"}}"#);
            write_frame(&mut sock, reply.as_bytes()).unwrap();
            sock.flush().unwrap();
            std::thread::sleep(Duration::from_millis(80));
            // drop `sock` -> transport EOF
        });

        let client = RhpClient::connect_to(addr, Arc::new(NullSink)).unwrap();
        let res = client.open_connect("M0LTE", "GB7RDG").unwrap();
        // Blocking connect wakes with an error when the transport dies.
        assert!(client.wait_connected(res.handle, None).is_err());
        // A blocking accept on some listener also wakes (returns None).
        assert!(client.wait_accept(999, None).is_none());
    }
}
