// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST'S I/O, `io.*` (`busbar_contract::abi::host::io`; `BUSBAR-1.6.0.md` THE DESIGN §5: "No
//! plugin opens a socket, dials, binds or does TLS"; TRANSPORT-STACK (2): a carrier writes "with
//! readiness via core `io.*`"): the ONE place in this crate that holds an OS handle — a stream
//! socket (TCP or unix-domain), a listener, a spawned program's two pipes — and moves bytes over it.
//! Every other module reaches the wire through a carrier's slots ([`crate::carrier`]), and the
//! carrier reaches it through here.
//!
//! [`HostIo`] implements the contract's [`IoHost`]: the loader's `io` slots dispatch every carrier
//! instance's `io.*` call into it, and a handle belongs to the instance whose call made it.
//!
//! * THE DESTINATION GUARD STAYS ONE CHECK (THE DESIGN §5, OWNER ruling 2026-10-02): the connector
//!   judges and pins every address before it asks a carrier to dial, and ADMITS exactly what it
//!   judged for the dial's ticket ([`HostIo::admit`]); `open` reaches only an admitted address,
//!   `listen` binds only an admitted bind, `spawn` starts only the admitted program. Anything else is
//!   refused before any system call.
//! * Readiness is the calling worker's reactor's ([`crate::io`]): a call that cannot progress
//!   answers `Pending` with the ticket's waker registered, never a block, never a thread.
//! * A stream is non-blocking, `TCP_NODELAY`, probed after 60 s idle (1.5.5's `tcp_keepalive`); a
//!   listener reuses its address and port (one per acceptor); a program is spawned with no shell, an
//!   absolute path and only the environment its settings state, its error output the host's, and
//!   killed when its handle is closed or dropped.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::{Context, Poll, Waker};

use busbar_contract::abi::host::io::{DIR_BOTH, DIR_READ, DIR_WRITE};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::conn::Program;
use busbar_contract::io_host::{IoHost, IoRefusal, IoResult, Spawn};

use crate::io::{self as reactor, Direction, Registered};
use crate::socket::{self, Sock};

/// What the connector admitted for one op's ticket: the one thing that op may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    /// `open` of exactly these addresses (each `ip:port`, or `unix:` and an absolute path): the
    /// address the destination judge pinned.
    Dial(Vec<String>),
    /// `listen` on exactly this bind (`ip:port`).
    Bind(String),
    /// `spawn` of exactly this program.
    Spawn(Program),
}

/// Why an `open` failed, as the connector's own dial reported it: refused (no one listens), or
/// failed (the socket could not be made), with the system's text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenFailure {
    /// The far end said no.
    Refused(String),
    /// The socket could not be made, or the call was off a worker.
    Failed(String),
}

/// What one op's admission came to: the handle it made, and the last `open` failure.
#[derive(Debug, Default)]
struct Admitted {
    what: Option<Admission>,
    made: Option<u64>,
    failure: Option<OpenFailure>,
}

/// A spawned program: the child the handle owns and the host's ends of its two pipes.
struct Pipes {
    child: Mutex<tokio::process::Child>,
    stdin: Mutex<Option<tokio::net::unix::pipe::Sender>>,
    stdout: tokio::net::unix::pipe::Receiver,
}

enum Kind {
    Stream {
        sock: Registered<Sock>,
        connecting: AtomicBool,
    },
    Listener(Registered<TcpListener>),
    /// Boxed: a program is spawned once per member, its pipes are larger than a socket.
    Program(Box<Pipes>),
}

struct Entry {
    owner: u64,
    kind: Kind,
}

/// THE HOST'S I/O (module docs).
#[derive(Default)]
pub struct HostIo {
    handles: RwLock<HashMap<u64, Arc<Entry>>>,
    admitted: Mutex<HashMap<Ticket, Admitted>>,
    next: AtomicU64,
}

impl std::fmt::Debug for HostIo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostIo")
            .field("handles", &self.held())
            .finish_non_exhaustive()
    }
}

fn failed(e: &io::Error) -> IoRefusal {
    IoRefusal::Failed(e.to_string())
}

/// What a non-blocking attempt answered: progress, nothing yet (wait), or the error.
fn polled<T>(p: Poll<io::Result<T>>) -> Poll<IoResult<T>> {
    p.map(|r| r.map_err(|e| failed(&e)))
}

/// The process's one host I/O: every connector, carrier and wire of the process is served from it
/// unless built over another ([`crate::Connector::with_io`]).
static PROCESS: std::sync::OnceLock<Arc<HostIo>> = std::sync::OnceLock::new();

/// The process's one host I/O ([`PROCESS`]).
#[must_use]
pub fn process() -> Arc<HostIo> {
    Arc::clone(PROCESS.get_or_init(|| Arc::new(HostIo::new())))
}

impl HostIo {
    /// A host I/O holding nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many handles it holds.
    #[must_use]
    pub fn held(&self) -> usize {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// ADMIT `what` for the op about to run on `ticket` (the destination guard's pinned address, the
    /// bind, the program): the one thing that op may reach.
    pub fn admit(&self, ticket: Ticket, what: Admission) {
        self.admitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                ticket,
                Admitted {
                    what: Some(what),
                    ..Admitted::default()
                },
            );
    }

    /// The op on `ticket` is done: its admission is withdrawn, and what it came to answered — the
    /// handle it made and the last `open` failure.
    pub fn settle(&self, ticket: Ticket) -> (Option<u64>, Option<OpenFailure>) {
        let a = self
            .admitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ticket)
            .unwrap_or_default();
        (a.made, a.failure)
    }

    /// What the op on `ticket` made so far (an `accept` on a listener's ticket: the latest).
    #[must_use]
    pub fn made(&self, ticket: Ticket) -> Option<u64> {
        self.admitted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&ticket)
            .and_then(|a| a.made)
    }

    fn admits(&self, ticket: Ticket, check: impl FnOnce(&Admission) -> bool) -> IoResult<()> {
        let held = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
        match held.get(&ticket).and_then(|a| a.what.as_ref()) {
            Some(what) if check(what) => Ok(()),
            _ => Err(IoRefusal::Refused(
                "the host did not admit this for the op that asked".into(),
            )),
        }
    }

    fn record(&self, ticket: Ticket, made: Option<u64>, failure: Option<OpenFailure>) {
        let mut held = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
        let a = held.entry(ticket).or_default();
        if made.is_some() {
            a.made = made;
        }
        if failure.is_some() {
            a.failure = failure;
        }
    }

    fn hold(&self, owner: u64, kind: Kind) -> u64 {
        let id = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        self.handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, Arc::new(Entry { owner, kind }));
        id
    }

    fn entry(&self, owner: u64, id: u64) -> IoResult<Arc<Entry>> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .filter(|e| e.owner == owner)
            .cloned()
            .ok_or_else(IoRefusal::unknown)
    }

    /// TAKE a stream handle's socket off the host's table, as the byte stream moves on to the
    /// kernel's own serving loop (the root's non-plane listeners hand each accepted socket up): it
    /// leaves the reactor, non-blocking. `None` for no such stream, or one still referenced.
    #[must_use]
    pub fn take_stream(&self, id: u64) -> Option<TcpStream> {
        let entry = self
            .handles
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id)?;
        let entry = Arc::into_inner(entry)?;
        match entry.kind {
            Kind::Stream { sock, .. } => match sock.deregister() {
                Sock::Tcp(s) => Some(s),
                Sock::Unix(_) => None,
            },
            _ => None,
        }
    }

    /// SHUT the write half of handle `id` (a stream's FIN; a program's input closed), as the layer a
    /// detached stream moved on to ends its writing and keeps reading. A handle no longer held is
    /// already shut.
    pub fn shut_write(&self, id: u64) {
        let Ok(e) = self.lookup(id) else {
            return;
        };
        match &e.kind {
            Kind::Stream { sock, .. } => {
                let _ = sock.get_ref().shutdown(Shutdown::Write);
            }
            Kind::Program(p) => {
                p.stdin
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
            }
            Kind::Listener(_) => {}
        }
    }

    /// Whether the program handle `id` runs has exited (without waiting for it); `false` for any
    /// other handle, and for one no longer held.
    #[must_use]
    pub fn program_exited(&self, id: u64) -> bool {
        let Ok(e) = self.lookup(id) else {
            return false;
        };
        match &e.kind {
            Kind::Program(p) => !matches!(
                p.child
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .try_wait(),
                Ok(None)
            ),
            _ => false,
        }
    }

    /// The process id of the program handle `id` runs; `None` for any other handle, or once reaped.
    #[must_use]
    pub fn program_id(&self, id: u64) -> Option<u32> {
        let e = self.lookup(id).ok()?;
        match &e.kind {
            Kind::Program(p) => p.child.lock().unwrap_or_else(PoisonError::into_inner).id(),
            _ => None,
        }
    }

    fn lookup(&self, id: u64) -> IoResult<Arc<Entry>> {
        self.handles
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&id)
            .cloned()
            .ok_or_else(IoRefusal::unknown)
    }

    fn release(&self, owner: u64, id: u64) -> IoResult<Arc<Entry>> {
        let mut held = self.handles.write().unwrap_or_else(PoisonError::into_inner);
        match held.get(&id) {
            Some(e) if e.owner == owner => held.remove(&id).ok_or_else(IoRefusal::unknown),
            _ => Err(IoRefusal::unknown()),
        }
    }

    /// Begin a connect to `addr`: a unix-domain path or an `ip:port`.
    fn connect(addr: &str) -> Result<Sock, OpenFailure> {
        if let Some(path) = socket::unix_path(addr) {
            return socket::connect_unix(path)
                .map(Sock::Unix)
                .map_err(|e| match e.kind() {
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
                        OpenFailure::Refused(format!("no socket listens at `{path}`: {e}"))
                    }
                    _ => OpenFailure::Failed(e.to_string()),
                });
        }
        let at: SocketAddr = addr.parse().map_err(|_| {
            OpenFailure::Refused(format!(
                "`{addr}` is not an address the connector dials without resolving a name"
            ))
        })?;
        socket::connect(at)
            .map(Sock::Tcp)
            .map_err(|e| OpenFailure::Failed(e.to_string()))
    }
}

/// THE HOST'S OWN LISTENING SOCKET: a root's non-plane bind (its data door, its admin surface) when
/// the build loads no carrier to listen through. Each socket it accepts is handed up whole to the
/// kernel's serving loop; nothing here reads or writes it.
#[derive(Debug)]
pub struct HostListener {
    sock: Registered<TcpListener>,
    local: SocketAddr,
}

impl HostListener {
    /// Bind `bind` (`ip:port`) on the calling worker's reactor, address and port reused.
    ///
    /// # Errors
    ///
    /// The address does not parse or cannot be bound, or the caller is not on a worker.
    pub fn bind(bind: &str) -> io::Result<Self> {
        let l = socket::listen(bind)?;
        let local = l.local_addr()?;
        Ok(Self {
            sock: reactor::register(l)?,
            local,
        })
    }

    /// The address bound.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The next socket and its far end; an aborted or interrupted accept is retried at once (1.5.5).
    ///
    /// # Errors
    ///
    /// The accept failed (fd exhaustion): the caller backs off.
    pub fn poll_accept(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        loop {
            match std::task::ready!(self.sock.poll_io(Direction::Read, cx, TcpListener::accept)) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                    ) => {}
                other => return Poll::Ready(other),
            }
        }
    }
}

fn shutdown(how: u32) -> Shutdown {
    match how {
        DIR_READ => Shutdown::Read,
        DIR_WRITE => Shutdown::Write,
        _ => Shutdown::Both,
    }
}

impl IoHost for HostIo {
    fn open(&self, owner: u64, ticket: Ticket, addr: &str) -> IoResult<u64> {
        self.admits(
            ticket,
            |a| matches!(a, Admission::Dial(at) if at.iter().any(|x| x == addr)),
        )?;
        let sock = match Self::connect(addr) {
            Ok(s) => s,
            Err(f) => {
                let text = match &f {
                    OpenFailure::Refused(t) | OpenFailure::Failed(t) => t.clone(),
                };
                self.record(ticket, None, Some(f));
                return Err(IoRefusal::Failed(text));
            }
        };
        let sock = reactor::register(sock).map_err(|e| {
            self.record(ticket, None, Some(OpenFailure::Failed(e.to_string())));
            failed(&e)
        })?;
        let id = self.hold(
            owner,
            Kind::Stream {
                sock,
                connecting: AtomicBool::new(true),
            },
        );
        self.record(ticket, Some(id), None);
        Ok(id)
    }

    fn listen(&self, owner: u64, ticket: Ticket, bind: &str) -> IoResult<(u64, String)> {
        self.admits(ticket, |a| matches!(a, Admission::Bind(b) if b == bind))?;
        let l = socket::listen(bind).map_err(|e| failed(&e))?;
        let local = l.local_addr().map_err(|e| failed(&e))?;
        let sock = reactor::register(l).map_err(|e| failed(&e))?;
        let id = self.hold(owner, Kind::Listener(sock));
        self.record(ticket, Some(id), None);
        Ok((id, local.to_string()))
    }

    fn accept(
        &self,
        owner: u64,
        ticket: Ticket,
        listener: u64,
        waker: &Waker,
    ) -> Poll<IoResult<(u64, String)>> {
        let e = match self.entry(owner, listener) {
            Ok(e) => e,
            Err(r) => return Poll::Ready(Err(r)),
        };
        let Kind::Listener(l) = &e.kind else {
            return Poll::Ready(Err(IoRefusal::unknown()));
        };
        let mut cx = Context::from_waker(waker);
        loop {
            match l.poll_io(Direction::Read, &mut cx, TcpListener::accept) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok((stream, peer))) => {
                    // A per-connection transient was the far end's; the accept carries on.
                    if stream.set_nonblocking(true).is_err() {
                        continue;
                    }
                    let _ = stream.set_nodelay(true);
                    let sock = match reactor::register(Sock::Tcp(stream)) {
                        Ok(s) => s,
                        Err(e) => return Poll::Ready(Err(failed(&e))),
                    };
                    let id = self.hold(
                        owner,
                        Kind::Stream {
                            sock,
                            connecting: AtomicBool::new(false),
                        },
                    );
                    self.record(ticket, Some(id), None);
                    return Poll::Ready(Ok((id, peer.to_string())));
                }
                // 1.5.5's accept loop: an aborted or interrupted accept is retried at once.
                Poll::Ready(Err(e))
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                    ) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(failed(&e))),
            }
        }
    }

    fn read(&self, owner: u64, id: u64, buf: &mut [u8], waker: &Waker) -> Poll<IoResult<usize>> {
        let e = match self.entry(owner, id) {
            Ok(e) => e,
            Err(r) => return Poll::Ready(Err(r)),
        };
        let mut cx = Context::from_waker(waker);
        match &e.kind {
            Kind::Stream { sock, .. } => {
                polled(sock.poll_io(Direction::Read, &mut cx, |mut s| s.read(buf)))
            }
            Kind::Program(p) => loop {
                if let Err(err) = std::task::ready!(p.stdout.poll_read_ready(&mut cx)) {
                    return Poll::Ready(Err(failed(&err)));
                }
                match p.stdout.try_read(buf) {
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    other => return Poll::Ready(other.map_err(|err| failed(&err))),
                }
            },
            Kind::Listener(_) => Poll::Ready(Err(IoRefusal::unknown())),
        }
    }

    fn write(&self, owner: u64, id: u64, bytes: &[u8], waker: &Waker) -> Poll<IoResult<usize>> {
        let e = match self.entry(owner, id) {
            Ok(e) => e,
            Err(r) => return Poll::Ready(Err(r)),
        };
        let mut cx = Context::from_waker(waker);
        match &e.kind {
            Kind::Stream { sock, .. } => {
                polled(sock.poll_io(Direction::Write, &mut cx, |mut s| s.write(bytes)))
            }
            Kind::Program(p) => {
                let stdin = p.stdin.lock().unwrap_or_else(PoisonError::into_inner);
                let Some(w) = stdin.as_ref() else {
                    return Poll::Ready(Err(failed(&io::ErrorKind::BrokenPipe.into())));
                };
                loop {
                    if let Err(err) = std::task::ready!(w.poll_write_ready(&mut cx)) {
                        return Poll::Ready(Err(failed(&err)));
                    }
                    match w.try_write(bytes) {
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                        other => return Poll::Ready(other.map_err(|err| failed(&err))),
                    }
                }
            }
            Kind::Listener(_) => Poll::Ready(Err(IoRefusal::unknown())),
        }
    }

    fn ready(&self, owner: u64, id: u64, dir: u32, waker: &Waker) -> Poll<IoResult<()>> {
        let e = match self.entry(owner, id) {
            Ok(e) => e,
            Err(r) => return Poll::Ready(Err(r)),
        };
        let mut cx = Context::from_waker(waker);
        match &e.kind {
            Kind::Stream { sock, connecting } => {
                if dir == DIR_WRITE && connecting.load(Ordering::Acquire) {
                    return match socket::poll_connected(sock, &mut cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Ok(())) => {
                            connecting.store(false, Ordering::Release);
                            Poll::Ready(Ok(()))
                        }
                        Poll::Ready(Err(err)) => Poll::Ready(Err(failed(&err))),
                    };
                }
                let d = if dir == DIR_READ {
                    Direction::Read
                } else {
                    Direction::Write
                };
                sock.poll_ready(d, &mut cx)
                    .map(|r| r.map(|_| ()).map_err(|err| failed(&err)))
            }
            // A program's pipes are open from the spawn.
            Kind::Program(_) | Kind::Listener(_) => Poll::Ready(Ok(())),
        }
    }

    fn shut(&self, owner: u64, id: u64, how: u32) -> IoResult<()> {
        let e = self.entry(owner, id)?;
        match &e.kind {
            Kind::Stream { sock, .. } => match sock.get_ref().shutdown(shutdown(how)) {
                Err(err) if err.kind() != io::ErrorKind::NotConnected => Err(failed(&err)),
                _ => Ok(()),
            },
            Kind::Program(p) => {
                if how & DIR_WRITE != 0 || how == DIR_BOTH {
                    p.stdin
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take();
                }
                Ok(())
            }
            Kind::Listener(_) => Ok(()),
        }
    }

    fn close(&self, owner: u64, id: u64) -> IoResult<()> {
        let e = self.release(owner, id)?;
        // A program is its handle's own: it ends with it.
        if let Kind::Program(p) = &e.kind {
            let _ = p
                .child
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .start_kill();
        }
        Ok(())
    }

    fn spawn(&self, owner: u64, ticket: Ticket, spawn: &Spawn<'_>) -> IoResult<u64> {
        self.admits(ticket, |a| {
            matches!(a, Admission::Spawn(p) if p.command == spawn.program
                && p.args.iter().map(String::as_str).eq(spawn.args.iter().copied())
                && p.env.iter().map(|(k, v)| (k.as_str(), v.as_str())).eq(spawn.env.iter().copied()))
        })?;
        if !spawn.program.starts_with('/') {
            return Err(IoRefusal::Refused(
                "a program is spawned by its absolute path only".into(),
            ));
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(IoRefusal::Failed(reactor::NOT_ON_A_WORKER.into()));
        }
        // Two OS pipes: the child reads one and writes the other; the host keeps the far ends.
        // The child's error output is the host's own (a spawned command inherits it).
        let (child_reads, host_writes) = std::io::pipe().map_err(|e| failed(&e))?;
        let (host_reads, child_writes) = std::io::pipe().map_err(|e| failed(&e))?;
        // The command (and the child's ends of the pipes it holds) is dropped with this statement,
        // so the child sees the end of its input when the host closes its end.
        let child = tokio::process::Command::new(spawn.program)
            .args(spawn.args)
            .env_clear()
            .envs(spawn.env.iter().copied())
            .stdin(child_reads)
            .stdout(child_writes)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| failed(&e))?;
        let stdin = tokio::net::unix::pipe::Sender::from_owned_fd(host_writes.into())
            .map_err(|e| failed(&e))?;
        let stdout = tokio::net::unix::pipe::Receiver::from_owned_fd(host_reads.into())
            .map_err(|e| failed(&e))?;
        let id = self.hold(
            owner,
            Kind::Program(Box::new(Pipes {
                child: Mutex::new(child),
                stdin: Mutex::new(Some(stdin)),
                stdout,
            })),
        );
        self.record(ticket, Some(id), None);
        Ok(id)
    }

    fn ends(&self, owner: u64, id: u64) -> IoResult<(u16, String)> {
        let e = self.entry(owner, id)?;
        match &e.kind {
            Kind::Stream { sock, .. } => match sock.get_ref() {
                Sock::Tcp(s) => {
                    let local = s.local_addr().map_err(|err| failed(&err))?.port();
                    let peer = s.peer_addr().map_err(|err| failed(&err))?.to_string();
                    Ok((local, peer))
                }
                Sock::Unix(_) => Ok((0, String::new())),
            },
            Kind::Listener(l) => Ok((
                l.get_ref().local_addr().map_err(|err| failed(&err))?.port(),
                String::new(),
            )),
            Kind::Program(_) => Ok((0, String::new())),
        }
    }
}

#[cfg(test)]
#[path = "tests/hostio_tests.rs"]
mod tests;
