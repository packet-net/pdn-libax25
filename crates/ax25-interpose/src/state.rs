// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Global interposer state: the fd -> AX.25 socket map, the shared RHP client,
// and the event sink that pumps RHP `recv`/`accept`/`close` pushes back into
// the app-visible socketpair fds.

use libc::{c_int, c_void};
use rhp::{RhpClient, RhpEventSink};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

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

/// A pending inbound connection queued by an `accept` push.
#[derive(Clone)]
pub struct AcceptInfo {
    pub child_handle: u64,
    pub remote: Option<String>,
    pub local: Option<String>,
}

pub fn fds() -> &'static Mutex<HashMap<c_int, FdState>> {
    static M: OnceLock<Mutex<HashMap<c_int, FdState>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Map RHP handle -> our inner socketpair fd (for the reader thread to route
/// recv bytes / EOF without touching the big fd map's lock ordering).
pub fn handle_inner() -> &'static Mutex<HashMap<u64, c_int>> {
    static M: OnceLock<Mutex<HashMap<u64, c_int>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Map listener RHP handle -> queue of accepted children awaiting `accept()`.
pub fn accepts() -> &'static Mutex<HashMap<u64, VecDeque<AcceptInfo>>> {
    static M: OnceLock<Mutex<HashMap<u64, VecDeque<AcceptInfo>>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
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
            handle_inner().lock().unwrap().remove(&h);
            accepts().lock().unwrap().remove(&h);
        }
        let close = real::close();
        unsafe {
            close(s.inner_fd);
            close(s.app_fd);
        }
    }
}

/// The event sink installed on the RHP client. Runs on the reader thread.
pub struct InterposeSink;

impl RhpEventSink for InterposeSink {
    fn on_recv(&self, handle: u64, data: &[u8]) {
        let inner = handle_inner().lock().unwrap().get(&handle).copied();
        if let Some(inner) = inner {
            let write = real::write();
            let mut off = 0usize;
            while off < data.len() {
                let n = unsafe {
                    write(
                        inner,
                        data[off..].as_ptr() as *const c_void,
                        data.len() - off,
                    )
                };
                if n <= 0 {
                    break; // socketpair full/closed; drop the rest (TODO(N1): buffer)
                }
                off += n as usize;
            }
        }
    }

    fn on_accept(&self, listener: u64, child: u64, remote: Option<String>, local: Option<String>) {
        accepts()
            .lock()
            .unwrap()
            .entry(listener)
            .or_default()
            .push_back(AcceptInfo {
                child_handle: child,
                remote,
                local,
            });
    }

    fn on_close(&self, handle: u64) {
        // Signal EOF to the app by shutting down the write side of our end.
        let inner = handle_inner().lock().unwrap().get(&handle).copied();
        if let Some(inner) = inner {
            unsafe {
                libc::shutdown(inner, libc::SHUT_WR);
            }
        }
    }

    fn on_disconnect(&self) {
        // Transport gone: EOF every live inner fd so blocked reads return.
        let map = handle_inner().lock().unwrap();
        for (_h, &inner) in map.iter() {
            unsafe {
                libc::shutdown(inner, libc::SHUT_WR);
            }
        }
    }
}
