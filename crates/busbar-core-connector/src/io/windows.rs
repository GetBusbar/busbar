// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native IOCP readiness. Tokio owns a duplicate of the socket while the host keeps its
//! original descriptor for nonblocking operations and transfers. Every custom operation goes
//! through `try_io`, including Mio's Windows rearm path after `WouldBlock`.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::task::{Context, Poll};

use tokio::io::Interest;

use super::{enter_process_runtime, Direction, NOT_ON_A_WORKER};

/// Socket types the Windows reactor can register.
pub trait Source: private::Source {}
impl<T: private::Source> Source for T {}

mod private {
    use super::*;

    pub trait Source {
        fn registration(&self) -> io::Result<Registration>;
    }
}

/// The typed registration behind a host socket.
#[doc(hidden)]
#[derive(Debug)]
pub struct Registration(Backend);

#[derive(Debug)]
enum Backend {
    Stream(tokio::net::TcpStream),
    Listener(tokio::net::TcpListener),
    Datagram(tokio::net::UdpSocket),
}

impl private::Source for TcpStream {
    fn registration(&self) -> io::Result<Registration> {
        tokio::net::TcpStream::from_std(self.try_clone()?)
            .map(Backend::Stream)
            .map(Registration)
    }
}

impl private::Source for TcpListener {
    fn registration(&self) -> io::Result<Registration> {
        tokio::net::TcpListener::from_std(self.try_clone()?)
            .map(Backend::Listener)
            .map(Registration)
    }
}

impl private::Source for UdpSocket {
    fn registration(&self) -> io::Result<Registration> {
        tokio::net::UdpSocket::from_std(self.try_clone()?)
            .map(Backend::Datagram)
            .map(Registration)
    }
}

impl private::Source for crate::socket::Sock {
    fn registration(&self) -> io::Result<Registration> {
        match self {
            Self::Tcp(stream) => private::Source::registration(stream),
        }
    }
}

/// A socket registered on the calling worker's native IOCP reactor.
#[derive(Debug)]
pub struct Registered<T: Source> {
    // Drop the registration before the original socket.
    registration: Registration,
    io: T,
}

/// Register a nonblocking socket on the calling worker's reactor.
pub fn register<T: Source>(io: T) -> io::Result<Registered<T>> {
    let _entered = enter_process_runtime();
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(io::Error::other(NOT_ON_A_WORKER));
    }
    Ok(Registered {
        registration: private::Source::registration(&io)?,
        io,
    })
}

impl<T: Source> Registered<T> {
    /// Wait for native readiness, registering the caller's waker.
    pub fn poll_ready(&self, dir: Direction, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match (&self.registration.0, dir) {
            (Backend::Stream(s), Direction::Read) => s.poll_read_ready(cx),
            (Backend::Stream(s), Direction::Write) => s.poll_write_ready(cx),
            (Backend::Datagram(s), Direction::Read) => s.poll_recv_ready(cx),
            (Backend::Datagram(s), Direction::Write) => s.poll_send_ready(cx),
            (Backend::Listener(_), _) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a listener is polled with poll_accept",
            ))),
        }
    }

    /// Remove the IOCP registration and return the original socket.
    #[must_use]
    pub fn deregister(self) -> T {
        drop(self.registration);
        self.io
    }

    /// Borrow the original socket without changing its registration.
    #[must_use]
    pub fn get_ref(&self) -> &T {
        &self.io
    }

    /// Perform a custom nonblocking operation, rearming IOCP after `WouldBlock`.
    pub fn poll_io<R>(
        &self,
        dir: Direction,
        cx: &mut Context<'_>,
        mut op: impl FnMut(&T) -> io::Result<R>,
    ) -> Poll<io::Result<R>> {
        let interest = match dir {
            Direction::Read => Interest::READABLE,
            Direction::Write => Interest::WRITABLE,
        };
        loop {
            std::task::ready!(self.poll_ready(dir, cx))?;
            let result = match &self.registration.0 {
                Backend::Stream(s) => s.try_io(interest, || op(&self.io)),
                Backend::Datagram(s) => s.try_io(interest, || op(&self.io)),
                Backend::Listener(_) => unreachable!("poll_ready refuses listener I/O"),
            };
            match result {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                other => return Poll::Ready(other),
            }
        }
    }
}

impl Registered<TcpListener> {
    /// Accept on the registered listener, retaining Tokio/Mio's native accept bookkeeping.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        let Backend::Listener(listener) = &self.registration.0 else {
            unreachable!("a TcpListener has a listener registration")
        };
        let (stream, peer) = std::task::ready!(listener.poll_accept(cx))?;
        Poll::Ready(stream.into_std().map(|stream| (stream, peer)))
    }
}
