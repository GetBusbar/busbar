// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's OS sockets: a non-blocking dial and a per-acceptor listener. Nothing here waits; the
//! caller registers the socket with [`crate::io::register`] and waits on its readiness.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
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
pub fn poll_connected(sock: &Registered<TcpStream>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    loop {
        let ready = std::task::ready!(sock.poll_ready(Direction::Write, cx))?;
        if let Some(e) = sock.get_ref().take_error()? {
            return Poll::Ready(Err(e));
        }
        match sock.get_ref().peer_addr() {
            Ok(_) => return Poll::Ready(Ok(())),
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
