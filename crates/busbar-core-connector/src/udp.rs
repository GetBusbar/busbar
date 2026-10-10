// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's UDP sockets — the DATAGRAM carrier. The host owns every OS socket; a plugin never
//! binds one. The stream carriers are a separate path: a datagram has
//! a peer per read and no connection, so it is never folded into the stream socket types.
//!
//! One bound port serves every media association on it: each read answers the datagram AND the
//! peer it came from, each write names the peer it goes to, and the dtls engine
//! ([`crate::dtls`]) demultiplexes by path. Nothing here waits: a read or write that would block
//! answers `None`, and the caller waits on the socket's read/write readiness — the per-worker
//! reactor registration (`io::register` of the socket from [`UdpPort::get_ref`]) is where readiness
//! comes from once the connector drives the port.
//!
//! A port binds one concrete address. A wildcard bind (`0.0.0.0`, `[::]`) is refused: ICE host
//! candidates advertise the address a datagram is answered FROM, and a wildcard socket answers from
//! whichever interface the route picks — so every advertised address is a port of its own.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

/// The largest datagram a read accepts: the whole IPv4/IPv6 UDP payload range. A read buffer of
/// this size never truncates.
pub const MAX_DATAGRAM: usize = 65_536;
/// Kernel buffer the port asks for each way — a few hundred milliseconds of many sessions' audio.
const SOCKET_BUFFER: usize = 1 << 20;

/// One bound, non-blocking UDP port.
#[derive(Debug)]
pub struct UdpPort {
    socket: UdpSocket,
    local: SocketAddr,
}

/// Bind a non-blocking UDP port on `bind` (a concrete `ip:port`; port `0` picks one).
///
/// # Errors
///
/// `bind` is not an `ip:port`, names a wildcard address, or cannot be bound.
pub fn bind(bind: &str) -> io::Result<UdpPort> {
    let addr: SocketAddr = bind
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not an ip:port bind address"))?;
    if addr.ip().is_unspecified() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a udp port binds a concrete address, never a wildcard",
        ));
    }
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    // Best effort: an OS that caps the buffers still binds.
    let _ = socket.set_recv_buffer_size(SOCKET_BUFFER);
    let _ = socket.set_send_buffer_size(SOCKET_BUFFER);
    socket.bind(&addr.into())?;
    let socket: UdpSocket = socket.into();
    let local = socket.local_addr()?;
    Ok(UdpPort { socket, local })
}

impl UdpPort {
    /// The address the port is bound to.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// The next datagram into `buf` and the peer it came from; `None` when none is waiting.
    /// `buf` of [`MAX_DATAGRAM`] bytes never truncates.
    ///
    /// # Errors
    ///
    /// The socket failed (an ICMP-reported unreachable peer surfaces here on some OSes; the caller
    /// treats it as a per-datagram event, never a reason to close the port).
    pub fn try_recv_from(&self, buf: &mut [u8]) -> io::Result<Option<(usize, SocketAddr)>> {
        match self.socket.recv_from(buf) {
            Ok(got) => Ok(Some(got)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Send `datagram` to `to` whole; `None` when the socket's send buffer is full.
    ///
    /// # Errors
    ///
    /// The socket failed, or the datagram was sent short (UDP never splits one).
    pub fn try_send_to(&self, datagram: &[u8], to: SocketAddr) -> io::Result<Option<()>> {
        match self.socket.send_to(datagram, to) {
            Ok(n) if n == datagram.len() => Ok(Some(())),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "datagram sent short",
            )),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// The socket, for registering its readiness with the reactor.
    #[must_use]
    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }
}

#[cfg(test)]
#[path = "tests/udp_tests.rs"]
mod tests;
