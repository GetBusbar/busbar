// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's OS sockets: a non-blocking dial (TCP, or a unix-domain stream for an

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::fd::{AsFd, BorrowedFd};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(windows)]
use std::os::windows::io::{AsSocket, BorrowedSocket};
use std::task::{Context, Poll};

use socket2::{Domain, Protocol, Socket, Type};

use crate::io::{Direction, Registered, Source};

/// The listen backlog of one acceptor's socket.
const BACKLOG: i32 = 1024;

/// An authority this host dials without resolving a name: an IP literal with its port, or
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

/// How long a dialled socket sits idle before the OS probes it (1.5.5's `tcp_keepalive`).
pub const KEEPALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// The prefix of a UNIX-DOMAIN target (the
pub const UNIX_TARGET: &str = "unix:";

/// The socket path a unix-domain target names: `unix:` then an absolute path (one leading `/`;
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
    #[cfg(unix)]
    Unix(UnixStream),
}

/// The stream's own descriptor, lent for the borrow (a [`socket2::SockRef`] of it).
#[cfg(unix)]
impl AsFd for Sock {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Self::Tcp(s) => s.as_fd(),
            Self::Unix(s) => s.as_fd(),
        }
    }
}

/// The stream's own socket, lent for the borrow (a [`socket2::SockRef`] of it).
#[cfg(windows)]
impl AsSocket for Sock {
    fn as_socket(&self) -> BorrowedSocket<'_> {
        match self {
            Self::Tcp(s) => s.as_socket(),
        }
    }
}

/// The far end's IP address, when `socket` is a connected TCP stream (a unix-domain stream's
/// peer is a path: none).
#[must_use]
pub fn peer_ip(socket: &Socket) -> Option<std::net::IpAddr> {
    socket
        .peer_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .map(|a| a.ip())
}

/// Whether `socket` is idle and open: nothing to read, no error, not closed by the far end.
/// A look at the kernel's buffer (`MSG_PEEK`) that consumes nothing; anything else than "would
/// block" (data waiting, EOF, an error) is not idle.
#[must_use]
pub fn idle_and_open(socket: &Socket) -> bool {
    let mut byte = [std::mem::MaybeUninit::<u8>::uninit(); 1];
    matches!(socket.peek(&mut byte), Err(e) if e.kind() == io::ErrorKind::WouldBlock)
}

/// Begin a non-blocking connect to the unix-domain socket at `path`: the socket comes back at once,
#[cfg(unix)]
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
pub fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    socket.set_tcp_nodelay(true)?;

    socket.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(KEEPALIVE_IDLE))?;
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        Err(e) if in_progress(&e) => {}
        Err(e) => return Err(e),
    }
    Ok(socket.into())
}

fn in_progress(e: &io::Error) -> bool {
    if e.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(unix)]
    return e.raw_os_error() == Some(libc::EINPROGRESS);
    #[cfg(windows)]
    false
}

/// Whether the connect [`connect`] began has completed: Ready(Ok) connected, Ready(Err) refused,
pub fn poll_connected<T: Source>(
    sock: &Registered<T>,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    sock.poll_io(Direction::Write, cx, |socket| {
        if let Some(error) = socket.take_error()? {
            return Err(error);
        }
        match socket.peer_addr().map(|_| ()) {
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {
                Err(io::ErrorKind::WouldBlock.into())
            }
            other => other,
        }
    })
}

/// A non-blocking listener on `bind`, with address and port reuse: every acceptor (one per worker)
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

#[cfg(test)]
#[path = "tests/socket_tests.rs"]
mod tests;
