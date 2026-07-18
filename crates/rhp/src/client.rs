// SPDX-License-Identifier: LGPL-3.0-or-later
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

use std::collections::HashMap;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::codec;
use crate::errors::errcode_to_errno;
use crate::framing::{read_frame, write_frame};
use crate::messages::{
    AuthReq, BindReq, CloseReq, Frame, ListenReq, OpenReq, SendReq, SocketReq, MAX_SEND_CHUNK,
    OPEN_FLAG_ACTIVE, OPEN_FLAG_PASSIVE,
};

/// Default request/reply timeout.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Callbacks for asynchronous server pushes. Implemented by the interposer to
/// wire RHP `recv` bytes into a socketpair, queue accepted children, etc.
///
/// All methods are called from the single reader thread and must not block for
/// long or re-enter the client with a request/reply call.
pub trait RhpEventSink: Send + Sync {
    /// Inbound data on a connected handle.
    fn on_recv(&self, _handle: u64, _data: &[u8]) {}
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

type PendingMap = Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>;

/// A live RHPv2 client connection.
pub struct RhpClient {
    writer: Mutex<TcpStream>,
    next_id: AtomicU64,
    pending: PendingMap,
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
        let closed = Arc::new(AtomicBool::new(false));

        // Reader thread: demux id-matched replies vs async pushes.
        {
            let pending = pending.clone();
            let closed = closed.clone();
            let sink = sink.clone();
            std::thread::Builder::new()
                .name("rhp-reader".into())
                .spawn(move || reader_loop(read_half, pending, closed, sink))
                .map_err(RhpError::Io)?;
        }

        let client = RhpClient {
            writer: Mutex::new(stream),
            next_id: AtomicU64::new(0),
            pending,
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
    pub fn open_connect(&self, local: &str, remote: &str) -> Result<OpenResult, RhpError> {
        self.open(local, Some(remote), OPEN_FLAG_ACTIVE)
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

    /// Close a handle.
    pub fn close(&self, handle: u64) -> Result<(), RhpError> {
        let id = self.next_id();
        let req = CloseReq { typ: "close", id, handle };
        let bytes = serde_json::to_vec(&req).map_err(json_io)?;
        let reply = self.request(id, &bytes)?;
        Self::check_ok(&reply)
    }

    // ---- BSD-style listener path (socket/bind/listen) --------------------

    /// Allocate a socket handle (`socket`).
    pub fn socket(&self) -> Result<u64, RhpError> {
        let id = self.next_id();
        let req = SocketReq { typ: "socket", id, pfam: "ax25", mode: "stream" };
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
}

/// Wrap a serde_json error as an RhpError::Io (serialisation cannot really fail
/// for our owned structs, but keeps the `?` ergonomics clean).
fn json_io(e: serde_json::Error) -> RhpError {
    RhpError::Io(io::Error::new(io::ErrorKind::InvalidData, e))
}

fn reader_loop(
    mut stream: TcpStream,
    pending: PendingMap,
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

                dispatch_push(&frame, &sink);
            }
            Err(_) => break,               // transport error
        }
    }

    closed.store(true, Ordering::SeqCst);
    // Fault any in-flight requests so their callers stop waiting.
    pending.lock().unwrap().clear();
    sink.on_disconnect();
}

fn dispatch_push(frame: &Frame, sink: &Arc<dyn RhpEventSink>) {
    match frame.typ() {
        "recv" => {
            if let Some(h) = frame.handle() {
                let data = frame.data_str().map(codec::from_wire_string).unwrap_or_default();
                sink.on_recv(h, &data);
            }
        }
        "accept" => {
            if let (Some(listener), Some(child)) = (frame.handle(), frame.child()) {
                sink.on_accept(
                    listener,
                    child,
                    frame.remote().map(|s| s.to_string()),
                    frame.local().map(|s| s.to_string()),
                );
            }
        }
        "status" => {
            if let Some(h) = frame.handle() {
                sink.on_status(h, frame.errcode());
            }
        }
        "close" => {
            // Server-initiated close (no id) == EOF.
            if let Some(h) = frame.handle() {
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
}
