// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's OS sockets: a non-blocking dial (TCP, or a unix-domain stream for an
//! operator-infrastructure need, [`UNIX_TARGET`]) and a per-acceptor listener. Nothing here waits;
//! the caller registers the socket with [`crate::io::register`] and waits on its readiness.

use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::task::{Context, Poll};

use socket2::{Domain, Protocol, Socket, Type};

use crate::io::{Direction, Registered};

/// The listen backlog of one acceptor's socket.
const BACKLOG: i32 = 1024;

/// An authority this host dials without resolving a name: an IP literal with its port, or
/// `localhost`. A name is the kernel's destination judge's to resolve (it pins the address the
/// egress rules judged), so the connector refuses one rather than resolve it on a worker.
#[must_use]
pub fn address_of(authority: &str) -> Option<SocketAddr> {
    if let Ok(addr) = authority.parse::<SocketAddr>() {
        return Some(addr);
    }
    let (host, port) = authority.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    host.eq_ignore_ascii_case("localhost")
        .then(|| SocketAddr::from(([127, 0, 0, 1], port)))
}

/// The prefix of a UNIX-DOMAIN target (ARCHITECT ruling 2026-10-03 12:10Z, VALKEY-UNIX: the
/// connector serves unix-domain targets for operator-infrastructure needs): `unix:/absolute/path`.
pub const UNIX_TARGET: &str = "unix:";

/// The socket path a unix-domain target names: `unix:` then an absolute path (one leading `/`;
/// `unix://…`, a URL spelling, is not this form and is read as any other target). `None` for every
/// other target.
#[must_use]
pub fn unix_path(target: &str) -> Option<&str> {
    let path = target.strip_prefix(UNIX_TARGET)?;
    (path.starts_with('/') && !path.starts_with("//") && path.len() > 1).then_some(path)
}

/// A dialled stream socket: TCP, or a unix-domain stream ([`unix_path`]). Both are non-blocking
/// descriptors served the same way: read, write, readiness on the reactor, shutdown.
#[derive(Debug)]
pub enum Sock {
    /// A TCP stream.
    Tcp(TcpStream),
    /// A unix-domain stream.
    Unix(UnixStream),
}

impl AsRawFd for Sock {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            Self::Tcp(s) => s.as_raw_fd(),
            Self::Unix(s) => s.as_raw_fd(),
        }
    }
}

impl Read for &Sock {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Sock::Tcp(s) => (&*s).read(buf),
            Sock::Unix(s) => (&*s).read(buf),
        }
    }
}

impl Write for &Sock {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Sock::Tcp(s) => (&*s).write(buf),
            Sock::Unix(s) => (&*s).write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Sock::Tcp(s) => (&*s).flush(),
            Sock::Unix(s) => (&*s).flush(),
        }
    }
}

impl Sock {
    /// Shut down `how`.
    ///
    /// # Errors
    ///
    /// The OS refused.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.shutdown(how),
            Self::Unix(s) => s.shutdown(how),
        }
    }
}

/// A connecting stream socket whose connect [`poll_connected`] can settle.
pub trait Connecting: AsRawFd {
    /// The socket's pending error (`SO_ERROR`).
    ///
    /// # Errors
    ///
    /// The OS refused the query.
    fn pending_error(&self) -> io::Result<Option<io::Error>>;
    /// `Ok` once connected; `NotConnected` while the connect is in flight.
    ///
    /// # Errors
    ///
    /// `NotConnected`, or the socket's failure.
    fn connected(&self) -> io::Result<()>;
}

impl Connecting for TcpStream {
    fn pending_error(&self) -> io::Result<Option<io::Error>> {
        self.take_error()
    }
    fn connected(&self) -> io::Result<()> {
        self.peer_addr().map(|_| ())
    }
}

impl Connecting for Sock {
    fn pending_error(&self) -> io::Result<Option<io::Error>> {
        match self {
            Self::Tcp(s) => s.take_error(),
            Self::Unix(s) => s.take_error(),
        }
    }
    fn connected(&self) -> io::Result<()> {
        match self {
            Self::Tcp(s) => s.peer_addr().map(|_| ()),
            Self::Unix(s) => s.peer_addr().map(|_| ()),
        }
    }
}

/// Begin a non-blocking connect to the unix-domain socket at `path`: the socket comes back at once,
/// the connect in flight (or done: a local connect usually completes at once).
///
/// # Errors
///
/// The socket could not be made, or the connect failed at once (no such socket, refused).
pub fn connect_unix(path: &str) -> io::Result<UnixStream> {
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    socket.set_nonblocking(true)?;
    match socket.connect(&socket2::SockAddr::unix(path)?) {
        Ok(()) => {}
        Err(e) if in_progress(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(socket.into())
}

/// Begin a non-blocking connect to `addr`: the socket comes back at once, the connect in flight.
///
/// # Errors
///
/// The socket could not be made, or the connect failed at once.
pub fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if in_progress(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(socket.into())
}

fn in_progress(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::EINPROGRESS)
}

/// Whether the connect [`connect`] began has completed: Ready(Ok) connected, Ready(Err) refused,
/// Pending with `cx`'s waker on the socket's write readiness.
///
/// # Errors
///
/// The far end refused, or the socket failed.
pub fn poll_connected<T: Connecting>(
    sock: &Registered<T>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    loop {
        let ready = std::task::ready!(sock.poll_ready(Direction::Write, cx))?;
        if let Some(e) = sock.get_ref().pending_error()? {
            return Poll::Ready(Err(e));
        }
        match sock.get_ref().connected() {
            Ok(()) => return Poll::Ready(Ok(())),
            Err(e) if e.kind() == io::ErrorKind::NotConnected => ready.clear_ready(),
            Err(e) => return Poll::Ready(Err(e)),
        }
    }
}

/// A non-blocking listener on `bind`, with address and port reuse: every acceptor (one per worker)
/// binds its own on the one address, and the kernel balances connections across them.
///
/// # Errors
///
/// The address does not parse or cannot be bound.
pub fn listen(bind: &str) -> io::Result<TcpListener> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an ip:port bind address"))?;
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(BACKLOG)?;
    Ok(socket.into())
}
