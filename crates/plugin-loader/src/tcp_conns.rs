// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST STAND-IN FOR THE HOST'S CONNECTION TABLE: [`TcpConns`] serves the `tcp` transport to a
//! plugin's declared needs, so a store (or any kind) that reaches a real backend over the host's
//! connector can be opened on a [`Dispatcher`](crate::dispatch::Dispatcher) in a test without the
//! process's connector. As the connector does, it dials `host:port` (bounded by the open's
//! timeout), a `unix:/absolute/path` target over a unix-domain socket, and secures a stream on
//! `upgrade_secure` with the TLS a test hands it ([`TcpConns::with_tls`], a [`SecureDial`]): TLS
//! stays in the connector and this crate names no TLS library, so a test hands it a double of the
//! connector's (whose real `upgrade_secure` its own suite proves). A read with nothing ready answers
//! PENDING and wakes the ticket shortly after, so a plugin's pending path is exercised. A test double: it never ships
//! (`test-support`).

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;

/// How long after a read found nothing its ticket is woken to look again.
const POLL: Duration = Duration::from_millis(1);

/// A unix-domain target's prefix, as the connector reads it.
pub const UNIX_PREFIX: &str = "unix:";

/// The TLS a table secures a stream with on `upgrade_secure`, handed to it by a test
/// ([`TcpConns::with_tls`]): the connector's, never this crate's.
pub trait SecureDial: Send + Sync {
    /// Secure the blocking `tcp` for `server` to a completed handshake: verifying the peer against
    /// the trust this dial was built with, or, on `verify_off`, checking no certificate (only the
    /// handshake's signature).
    ///
    /// # Errors
    /// `server` is unusable, or the handshake failed.
    fn secure(
        &self,
        server: &str,
        verify_off: bool,
        tcp: TcpStream,
    ) -> std::io::Result<Box<dyn SecuredSock>>;
}

/// A stream [`SecureDial::secure`] secured: its bytes, the socket under it, and its close.
pub trait SecuredSock: Read + Write + Send {
    /// The socket under the session.
    fn tcp(&self) -> &TcpStream;
    /// Send the close alert, flush it and shut the socket down.
    fn close(&mut self);
}

/// One connection's socket.
enum Sock {
    Tcp(TcpStream),
    Unix(UnixStream),
    Tls(Box<dyn SecuredSock>),
    Gone,
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            Self::Unix(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
            Self::Gone => Ok(0),
        }
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            Self::Unix(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
            Self::Gone => Err(ErrorKind::NotConnected.into()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            Self::Unix(s) => s.flush(),
            Self::Tls(s) => s.flush(),
            Self::Gone => Ok(()),
        }
    }
}

struct Conn {
    sock: Sock,
    target: String,
}

/// THE TEST CONNECTION TABLE.
pub struct TcpConns {
    slab: ConnSlab<Mutex<Conn>>,
    wake: Arc<dyn Fn(u64) + Send + Sync>,
    tls: Option<Arc<dyn SecureDial>>,
    timeouts: Mutex<Vec<u64>>,
    /// Each declared need's egress class, by owner and need.
    classes: Mutex<std::collections::HashMap<(InstanceId, NeedId), u32>>,
}

impl std::fmt::Debug for TcpConns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConns").finish_non_exhaustive()
    }
}

impl TcpConns {
    /// Each open's dial timeout, milliseconds (`0` = none stated), in order.
    #[must_use]
    pub fn dial_timeouts(&self) -> Vec<u64> {
        self.timeouts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// How many needs have been declared on this table, by every owner.
    #[must_use]
    pub fn declarations(&self) -> usize {
        self.classes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// A table waking a parked read's ticket through `wake` (the dispatcher's
    /// [`conn_waker`](crate::dispatch::Dispatcher::conn_waker)); `upgrade_secure` is refused.
    #[must_use]
    pub fn new(wake: Arc<dyn Fn(u64) + Send + Sync>) -> Self {
        Self {
            slab: ConnSlab::default(),
            wake,
            tls: None,
            timeouts: Mutex::new(Vec::new()),
            classes: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// [`TcpConns::new`], securing a stream on `upgrade_secure` with `tls`.
    #[must_use]
    pub fn with_tls(wake: Arc<dyn Fn(u64) + Send + Sync>, tls: Arc<dyn SecureDial>) -> Self {
        Self {
            tls: Some(tls),
            ..Self::new(wake)
        }
    }
}

fn io(e: &std::io::Error) -> ConnError {
    match e.kind() {
        ErrorKind::TimedOut | ErrorKind::WouldBlock => ConnError::Timeout,
        _ => ConnError::Closed,
    }
}

/// The host of a `host:port` (or `[v6]:port`) target.
fn host_of(target: &str) -> String {
    let t = target.rsplit_once(':').map_or(target, |(h, _)| h);
    t.trim_start_matches('[').trim_end_matches(']').to_owned()
}

fn dial(target: &str, timeout_ms: u64) -> Result<Sock, ConnError> {
    if let Some(path) = target.strip_prefix(UNIX_PREFIX) {
        let s = UnixStream::connect(path).map_err(|_| ConnError::Refused)?;
        s.set_nonblocking(true).map_err(|e| io(&e))?;
        return Ok(Sock::Unix(s));
    }
    let s = if timeout_ms == 0 {
        TcpStream::connect(target).map_err(|_| ConnError::Refused)?
    } else {
        // Every address the name resolves to, in order, as the connector tries them.
        let addrs: Vec<_> = target
            .to_socket_addrs()
            .map_err(|_| ConnError::Refused)?
            .collect();
        let mut last = ConnError::Refused;
        let mut got = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)) {
                Ok(s) => {
                    got = Some(s);
                    break;
                }
                Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                    last = ConnError::Timeout;
                }
                Err(_) => {}
            }
        }
        got.ok_or(last)?
    };
    s.set_nodelay(true).map_err(|e| io(&e))?;
    s.set_nonblocking(true).map_err(|e| io(&e))?;
    Ok(Sock::Tcp(s))
}

impl Conns for TcpConns {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        self.timeouts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(desc.timeout_ms);
        let sock = dial(desc.target, desc.timeout_ms)?;
        self.slab.insert(
            caller,
            need,
            Mutex::new(Conn {
                sock,
                target: desc.target.to_owned(),
            }),
        )
    }

    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        let (_, c) = self.slab.get(caller, conn)?;
        let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
        let mut done = 0;
        while done < bytes.len() {
            match c.sock.write(&bytes[done..]) {
                Ok(0) => return Err(ConnError::Closed),
                Ok(n) => done += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(POLL),
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(io(&e)),
            }
        }
        loop {
            match c.sock.flush() {
                Ok(()) => return Ok(done),
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::sleep(POLL),
                Err(e) => return Err(io(&e)),
            }
        }
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (_, c) = self.slab.get(caller, conn)?;
        let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
        match c.sock.read(buf) {
            Ok(0) => Err(ConnError::Closed),
            Ok(n) => Ok(Piece {
                kind: PieceKind::Body,
                stream: StreamId(0),
                len: n,
                end: false,
                status: None,
                status_code: None,
                status_namespace: None,
                retry_after_secs: None,
                reason: None,
            }),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if ticket != 0 {
                    // Look again shortly: the ticket is woken, and the read made again.
                    let wake = self.wake.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(POLL);
                        wake(ticket);
                    });
                }
                Err(ConnError::Pending)
            }
            Err(e) => Err(io(&e)),
        }
    }

    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Refused)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.slab.get(caller, conn)?;
        Ok(ConnFacts::default())
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let c = self.slab.remove(caller, conn)?;
        let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
        match std::mem::replace(&mut c.sock, Sock::Gone) {
            Sock::Tcp(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            Sock::Unix(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            Sock::Tls(mut s) => s.close(),
            Sock::Gone => {}
        }
        Ok(())
    }
}

impl DeclaredConns for TcpConns {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        if spec.transport != "tcp" {
            return Err(ConnError::Refused);
        }
        self.classes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((owner, need), spec.egress_class);
        self.slab.declare(owner, need);
        Ok(())
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }

    /// TLS from the stream's next byte, through the table's TLS ([`TcpConns::with_tls`]):
    /// verifying, or, on `verify_off` (an operator-infrastructure need's only, as the connector
    /// rules), checking no certificate; the handshake runs to completion here (a test double may
    /// block its caller). A table without TLS refuses every upgrade.
    fn upgrade_secure(
        &self,
        caller: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        _: Option<&str>,
        verify_off: bool,
        _: u64,
    ) -> Result<(), ConnError> {
        let (need, c) = self.slab.get(caller, conn)?;
        if verify_off {
            let class = self
                .classes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&(caller, need))
                .copied();
            if class
                != Some(busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE)
            {
                return Err(ConnError::Refused);
            }
        }
        let secure = self.tls.clone().ok_or(ConnError::Refused)?;
        let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
        let server = name.map_or_else(|| host_of(&c.target), str::to_owned);
        let Sock::Tcp(tcp) = std::mem::replace(&mut c.sock, Sock::Gone) else {
            return Err(ConnError::Refused);
        };
        tcp.set_nonblocking(false).map_err(|e| io(&e))?;
        let tls = secure
            .secure(&server, verify_off, tcp)
            .map_err(|_| ConnError::Refused)?;
        tls.tcp().set_nonblocking(true).map_err(|e| io(&e))?;
        c.sock = Sock::Tls(tls);
        Ok(())
    }

    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "tcp"
    }
}
