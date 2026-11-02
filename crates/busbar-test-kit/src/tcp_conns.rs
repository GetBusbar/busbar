// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(unix)]
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

const POLL: Duration = Duration::from_millis(1);

use crate::stand_in::StreamFacts;

pub trait SecureDial: Send + Sync {
    fn secure(
        &self,
        server: &str,
        verify_off: bool,
        tcp: TcpStream,
    ) -> std::io::Result<Box<dyn SecuredSock>>;
}

pub trait DialGuard: Send + Sync {
    fn judge(&self, target: &str, class: u32) -> Result<std::net::SocketAddr, ConnError>;
}

pub trait SecuredSock: Read + Write + Send {
    fn tcp(&self) -> &TcpStream;

    fn close(&mut self);
}

enum Sock {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
    Tls(Box<dyn SecuredSock>),

    Late {
        prefix: String,
        timeout_ms: u64,
        asked: bool,
    },
    Gone,
}

impl Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.read(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
            Self::Late { .. } => Err(ErrorKind::NotConnected.into()),
            Self::Gone => Ok(0),
        }
    }
}

impl Write for Sock {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(s) => s.write(buf),
            #[cfg(unix)]
            Self::Unix(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
            Self::Late { .. } | Self::Gone => Err(ErrorKind::NotConnected.into()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush(),
            #[cfg(unix)]
            Self::Unix(s) => s.flush(),
            Self::Tls(s) => s.flush(),
            Self::Late { .. } | Self::Gone => Ok(()),
        }
    }
}

struct Conn {
    sock: Sock,

    target: String,

    at: String,
}

pub struct TcpConns {
    facts: StreamFacts,
    slab: ConnSlab<Mutex<Conn>>,
    wake: busbar_contract::conn::ConnWake,
    tls: Option<Arc<dyn SecureDial>>,
    timeouts: Mutex<Vec<u64>>,

    classes: Mutex<std::collections::HashMap<(InstanceId, NeedId), (u32, u64)>>,

    late: bool,

    guard: Option<Arc<dyn DialGuard>>,
}

impl std::fmt::Debug for TcpConns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConns").finish_non_exhaustive()
    }
}

impl TcpConns {
    #[must_use]
    pub fn dial_timeouts(&self) -> Vec<u64> {
        self.timeouts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn declarations(&self) -> usize {
        self.classes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn new(wake: busbar_contract::conn::ConnWake) -> Self {
        Self::serving(StreamFacts::stand_in(), wake)
    }

    #[must_use]
    pub fn serving(facts: StreamFacts, wake: busbar_contract::conn::ConnWake) -> Self {
        Self {
            facts,
            slab: ConnSlab::default(),
            wake,
            tls: None,
            timeouts: Mutex::new(Vec::new()),
            classes: Mutex::new(std::collections::HashMap::new()),
            late: false,
            guard: None,
        }
    }

    #[must_use]
    pub fn dialling_late(wake: busbar_contract::conn::ConnWake) -> Self {
        Self {
            late: true,
            ..Self::new(wake)
        }
    }

    #[must_use]
    pub fn judged(self, guard: Arc<dyn DialGuard>) -> Self {
        Self {
            guard: Some(guard),
            ..self
        }
    }

    #[must_use]
    pub fn with_tls(wake: busbar_contract::conn::ConnWake, tls: Arc<dyn SecureDial>) -> Self {
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

fn host_of(target: &str) -> String {
    let t = target.rsplit_once(':').map_or(target, |(h, _)| h);
    t.trim_start_matches('[').trim_end_matches(']').to_owned()
}

fn dial(target: &str, local_prefix: &str, timeout_ms: u64) -> Result<Sock, ConnError> {
    let local = target
        .strip_prefix(local_prefix)
        .filter(|_| !local_prefix.is_empty());
    #[cfg(unix)]
    if let Some(path) = local {
        let s = UnixStream::connect(path).map_err(|_| ConnError::Refused)?;
        s.set_nonblocking(true).map_err(|e| io(&e))?;
        return Ok(Sock::Unix(s));
    }
    #[cfg(not(unix))]
    let target = if let Some(address) = local {
        let at: std::net::SocketAddr = address.parse().map_err(|_| ConnError::Refused)?;
        if !at.ip().is_loopback() {
            return Err(ConnError::Refused);
        }
        address
    } else {
        target
    };
    let s = if timeout_ms == 0 {
        TcpStream::connect(target).map_err(|_| ConnError::Refused)?
    } else {
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

fn land(c: &mut Conn) -> Result<(), ConnError> {
    if let Sock::Late {
        prefix, timeout_ms, ..
    } = &c.sock
    {
        let dialled = dial(&c.at, prefix, *timeout_ms);
        c.sock = match dialled {
            Ok(sock) => sock,
            Err(e) => {
                c.sock = Sock::Gone;
                return Err(e);
            }
        };
    }
    Ok(())
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
        let local = !self.facts.local_prefix.is_empty()
            && desc.target.starts_with(&self.facts.local_prefix);
        let at = match &self.guard {
            Some(guard) if !local => {
                let class = self
                    .classes
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&(caller, need))
                    .map(|(class, _)| *class)
                    .unwrap_or(0);
                guard.judge(desc.target, class)?.to_string()
            }
            _ => desc.target.to_owned(),
        };
        let sock = if self.late {
            Sock::Late {
                prefix: self.facts.local_prefix.clone(),
                timeout_ms: desc.timeout_ms,
                asked: false,
            }
        } else {
            dial(&at, &self.facts.local_prefix, desc.timeout_ms)?
        };
        self.slab.insert(
            caller,
            need,
            Mutex::new(Conn {
                sock,
                target: desc.target.to_owned(),
                at,
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
        land(&mut c).map_err(|_| ConnError::Closed)?;
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
        land(&mut c).map_err(|_| ConnError::Closed)?;
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
                fault: None,
                reason: None,
                declared_len: None,
            }),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                if ticket != 0 {
                    let wake = self.wake.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(POLL);
                        wake(caller, ticket);
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
        let (_, c) = self.slab.get(caller, conn)?;
        let secured = matches!(
            c.lock().unwrap_or_else(PoisonError::into_inner).sock,
            Sock::Tls(_)
        );
        Ok(ConnFacts {
            peer_cert: secured.then(|| busbar_contract::transport::CertFacts {
                subject: String::new(),
                issuer: String::new(),
                fingerprint: "secured-by-the-tls-double".to_string(),
            }),
            ..ConnFacts::default()
        })
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        let c = self.slab.remove(caller, conn)?;
        let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
        match std::mem::replace(&mut c.sock, Sock::Gone) {
            Sock::Tcp(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            #[cfg(unix)]
            Sock::Unix(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            Sock::Tls(mut s) => s.close(),
            Sock::Late { .. } | Sock::Gone => {}
        }
        Ok(())
    }
}

impl DeclaredConns for TcpConns {
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        let dial_timeout_ms = if dial_timeout_ms == 0 {
            self.classes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&(caller, need))
                .map_or(0, |(_, timeout)| *timeout)
        } else {
            dial_timeout_ms
        };
        self.open_with_security(
            caller,
            need,
            &OpenDesc {
                timeout_ms: if dial_timeout_ms == 0 {
                    desc.timeout_ms
                } else {
                    dial_timeout_ms
                },
                ..desc.clone()
            },
            require_secure,
        )
    }

    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        if spec.transport.is_empty() || spec.transport != self.facts.transport {
            return Err(ConnError::Refused);
        }
        self.classes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((owner, need), (spec.egress_class, spec.timeout_ms));
        self.slab.declare(owner, need);
        Ok(())
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }

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
                .map(|(class, _)| *class);
            if class
                != Some(busbar_contract::abi::host::conn::connector::EGRESS_OPERATOR_INFRASTRUCTURE)
            {
                return Err(ConnError::Refused);
            }
        }
        let secure = self.tls.clone().ok_or(ConnError::Refused)?;
        let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
        let server = name.map_or_else(|| host_of(&c.target), str::to_owned);
        land(&mut c)?;
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
        !transport.is_empty() && transport == self.facts.transport
    }

    fn landed(&self, caller: InstanceId, conn: ConnId, ticket: u64) -> Result<(), ConnError> {
        let (_, c) = self.slab.get(caller, conn)?;
        let mut c = c.lock().unwrap_or_else(PoisonError::into_inner);
        match &mut c.sock {
            Sock::Late { asked, .. } if !*asked => {
                *asked = true;
                let wake = self.wake.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(POLL);
                    wake(caller, ticket);
                });
                Err(ConnError::Pending)
            }
            _ => land(&mut c),
        }
    }
}
