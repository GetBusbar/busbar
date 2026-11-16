// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `io.*` — READINESS ON THE PER-WORKER REACTOR (`BUSBAR-1.6.0.md` THE DESIGN, §5 and §11.2).
//!
//! A registered socket MOVES INTO its own tokio type (`TcpStream`, `UnixStream`, `UdpSocket`,
//! `TcpListener`), which owns the one descriptor and its reactor registration for the
//! registration's whole life. Nothing is lent to the reactor, so nothing here is `unsafe`
//! (UNSAFE-MIN r3.1 §4.3). A custom operation runs through tokio's own `try_io`, on a
//! [`SockRef`] of that same descriptor.

use std::io;
use std::marker::PhantomData;
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::task::{Context, Poll};

use socket2::SockRef;
use tokio::io::{Interest, ReadBuf};

use super::{enter_process_runtime, Direction, NOT_ON_A_WORKER};

/// Socket types the reactor can register.
pub trait Source: private::Source {}
impl<T: private::Source> Source for T {}

mod private {
    use super::*;

    pub trait Source: Sized {
        /// Move the socket into its tokio type, registering it on the current reactor.
        fn registration(self) -> io::Result<Registration>;
        /// Take the socket back off the reactor.
        fn deregistered(registration: Registration) -> io::Result<Self>;
    }
}

/// The typed registration behind a host socket.
#[doc(hidden)]
#[derive(Debug)]
pub struct Registration(Backend);

#[derive(Debug)]
enum Backend {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
    Listener(tokio::net::TcpListener),
    Datagram(tokio::net::UdpSocket),
}

impl Backend {
    /// The registered descriptor, lent for the borrow.
    fn socket(&self) -> SockRef<'_> {
        match self {
            Self::Tcp(s) => SockRef::from(s),
            Self::Unix(s) => SockRef::from(s),
            Self::Listener(s) => SockRef::from(s),
            Self::Datagram(s) => SockRef::from(s),
        }
    }

    /// One attempt of `op` gated by tokio's readiness for `dir`. `WouldBlock` (from tokio, or
    /// answered by `op`) clears that readiness, closed states excepted.
    fn try_io<R>(
        &self,
        dir: Direction,
        op: impl FnOnce(&socket2::Socket) -> io::Result<R>,
    ) -> io::Result<R> {
        let interest = match dir {
            Direction::Read => Interest::READABLE,
            Direction::Write => Interest::WRITABLE,
        };
        match self {
            Self::Tcp(s) => s.try_io(interest, || op(&SockRef::from(s))),
            Self::Unix(s) => s.try_io(interest, || op(&SockRef::from(s))),
            Self::Datagram(s) => s.try_io(interest, || op(&SockRef::from(s))),
            Self::Listener(_) => Err(listener_io()),
        }
    }
}

/// What a byte operation on a listener answers: a listener is polled with `poll_accept`.
fn listener_io() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "a listener is polled with poll_accept",
    )
}

/// A registration handed back as another socket type than the one registered.
fn mismatched() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the registration holds another socket type",
    )
}

impl private::Source for TcpStream {
    fn registration(self) -> io::Result<Registration> {
        tokio::net::TcpStream::from_std(self)
            .map(Backend::Tcp)
            .map(Registration)
    }

    fn deregistered(registration: Registration) -> io::Result<Self> {
        match registration.0 {
            Backend::Tcp(s) => s.into_std(),
            _ => Err(mismatched()),
        }
    }
}

impl private::Source for TcpListener {
    fn registration(self) -> io::Result<Registration> {
        tokio::net::TcpListener::from_std(self)
            .map(Backend::Listener)
            .map(Registration)
    }

    fn deregistered(registration: Registration) -> io::Result<Self> {
        match registration.0 {
            Backend::Listener(l) => l.into_std(),
            _ => Err(mismatched()),
        }
    }
}

impl private::Source for UdpSocket {
    fn registration(self) -> io::Result<Registration> {
        tokio::net::UdpSocket::from_std(self)
            .map(Backend::Datagram)
            .map(Registration)
    }

    fn deregistered(registration: Registration) -> io::Result<Self> {
        match registration.0 {
            Backend::Datagram(s) => s.into_std(),
            _ => Err(mismatched()),
        }
    }
}

impl private::Source for crate::socket::Sock {
    fn registration(self) -> io::Result<Registration> {
        match self {
            Self::Tcp(stream) => private::Source::registration(stream),
            Self::Unix(stream) => tokio::net::UnixStream::from_std(stream)
                .map(Backend::Unix)
                .map(Registration),
        }
    }

    fn deregistered(registration: Registration) -> io::Result<Self> {
        match registration.0 {
            Backend::Tcp(s) => s.into_std().map(Self::Tcp),
            Backend::Unix(s) => s.into_std().map(Self::Unix),
            _ => Err(mismatched()),
        }
    }
}

/// A socket registered on the calling worker's reactor.
#[derive(Debug)]
pub struct Registered<T: Source> {
    registration: Registration,
    socket: PhantomData<fn() -> T>,
}

/// `io.register`: put the non-blocking `io` on the calling worker's reactor.
pub fn register<T: Source>(io: T) -> io::Result<Registered<T>> {
    let _entered = enter_process_runtime();
    if tokio::runtime::Handle::try_current().is_err() {
        return Err(io::Error::other(NOT_ON_A_WORKER));
    }
    Ok(Registered {
        registration: private::Source::registration(io)?,
        socket: PhantomData,
    })
}

impl<T: Source> Registered<T> {
    /// `io.poll_ready`: Ready once `dir` may make progress; Pending with `cx`'s waker registered.
    pub fn poll_ready(&self, dir: Direction, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match (&self.registration.0, dir) {
            (Backend::Tcp(s), Direction::Read) => s.poll_read_ready(cx),
            (Backend::Tcp(s), Direction::Write) => s.poll_write_ready(cx),
            (Backend::Unix(s), Direction::Read) => s.poll_read_ready(cx),
            (Backend::Unix(s), Direction::Write) => s.poll_write_ready(cx),
            (Backend::Datagram(s), Direction::Read) => s.poll_recv_ready(cx),
            (Backend::Datagram(s), Direction::Write) => s.poll_send_ready(cx),
            (Backend::Listener(_), _) => Poll::Ready(Err(listener_io())),
        }
    }

    /// `io.deregister`: take the socket back off the reactor, whole.
    pub fn deregister(self) -> io::Result<T> {
        private::Source::deregistered(self.registration)
    }

    /// The registered descriptor, lent for the borrow (no registration change).
    #[must_use]
    pub fn socket(&self) -> SockRef<'_> {
        self.registration.0.socket()
    }

    /// One non-blocking attempt of `op` in `dir`, repeated across fresh edges: `WouldBlock` clears
    /// readiness and waits for the next edge.
    pub fn poll_io<R>(
        &self,
        dir: Direction,
        cx: &mut Context<'_>,
        mut op: impl FnMut(&socket2::Socket) -> io::Result<R>,
    ) -> Poll<io::Result<R>> {
        loop {
            std::task::ready!(self.poll_ready(dir, cx))?;
            match self.registration.0.try_io(dir, &mut op) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                other => return Poll::Ready(other),
            }
        }
    }

    /// One non-blocking attempt of a sized `op` in `dir` (`want` = the bytes asked for).
    /// `WouldBlock` clears readiness and waits for a fresh edge (as [`Registered::poll_io`]). On
    /// edge-triggered selectors only ([`SHORT_CLEARS`], tokio `PollEvented`'s gate), a SHORT
    /// transfer (`0 < n < want`) also clears it, so the next attempt waits for a fresh edge
    /// instead of making a syscall that answers `EAGAIN`: the short count is answered to tokio's
    /// `try_io` as `WouldBlock` (its one readiness clear) and to the caller as the count.
    /// `READ_CLOSED` / `WRITE_CLOSED` stay set (tokio masks them out of a clear), so a FIN is never
    /// lost.
    pub fn poll_io_sized(
        &self,
        dir: Direction,
        want: usize,
        cx: &mut Context<'_>,
        mut op: impl FnMut(&socket2::Socket) -> io::Result<usize>,
    ) -> Poll<io::Result<usize>> {
        loop {
            std::task::ready!(self.poll_ready(dir, cx))?;
            let mut short = None;
            let attempt = self.registration.0.try_io(dir, |socket| match op(socket) {
                Ok(n) if SHORT_CLEARS && n > 0 && n < want => {
                    short = Some(n);
                    Err(io::ErrorKind::WouldBlock.into())
                }
                other => other,
            });
            match (attempt, short) {
                (_, Some(n)) => return Poll::Ready(Ok(n)),
                (Err(e), None) if e.kind() == io::ErrorKind::WouldBlock => {}
                (other, None) => return Poll::Ready(other),
            }
        }
    }
}

/// Whether a SHORT transfer (`0 < n < want`) proves the socket drained, so readiness may be
/// cleared without a `WouldBlock` attempt: true only on edge-triggered selectors (epoll, kqueue),
/// exactly tokio 1.53.3's gate (`io/poll_evented.rs`, issue 5866; keep in sync with it). mio's
/// poll(2) backend (`mio_unsupported_force_poll_poll`, and targets such as AIX, Solaris, Haiku)
/// is level-triggered and keeps today's behaviour.
pub const SHORT_CLEARS: bool = cfg!(all(
    not(mio_unsupported_force_poll_poll),
    any(
        // epoll
        target_os = "android",
        target_os = "illumos",
        target_os = "linux",
        target_os = "redox",
        // kqueue
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "tvos",
        target_os = "visionos",
        target_os = "watchos",
    ),
));

impl Registered<TcpListener> {
    /// Accept the next socket on the registered listener. Tokio registers what it accepts; it is
    /// taken straight back off, so the caller gets the plain socket, as before.
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<io::Result<(TcpStream, SocketAddr)>> {
        let Backend::Listener(listener) = &self.registration.0 else {
            return Poll::Ready(Err(mismatched()));
        };
        // Off a task, the accepted socket's (momentary) registration needs the process reactor.
        let _entered = enter_process_runtime();
        let (stream, peer) = std::task::ready!(listener.poll_accept(cx))?;
        Poll::Ready(stream.into_std().map(|stream| (stream, peer)))
    }
}

impl Registered<UdpSocket> {
    /// The next datagram into `buf` and the peer it came from; Pending with `cx`'s waker
    /// registered. A datagram longer than `buf` is truncated to it, as `recv_from` does.
    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let Backend::Datagram(socket) = &self.registration.0 else {
            return Poll::Ready(Err(mismatched()));
        };
        let mut read = ReadBuf::new(buf);
        let from = std::task::ready!(socket.poll_recv_from(cx, &mut read))?;
        Poll::Ready(Ok((read.filled().len(), from)))
    }
}
