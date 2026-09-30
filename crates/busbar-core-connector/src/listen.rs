// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LISTEN: one listener per INBOUND need, the server-side mirror of [`crate::compose`]'s dial. Every connection it accepts is composed as
//! `socket -> [TLS] -> framer`, the framing begun on `SIDE_ACCEPT` ([`Connection::accepted`]).
//!
//! The accept is bounded, and nothing here starts a thread or a task:
//!
//! * at most [`AcceptLimits::max_conns`] connections are held at once; one past it is accepted and
//!   closed at once, no byte written;
//! * a TLS handshake is bounded by [`AcceptLimits::handshake_timeout`] (1.5.5's
//!   `limits.tls_handshake_timeout_secs`, default 10 s) and a handshake past it is dropped; the
//!   framer's own deadlines bound what follows;
//! * an accept error backs off as 1.5.5's accept loop did: a per-connection transient (an aborted
//!   or interrupted accept) retries at once, anything else (fd exhaustion) waits 5 ms, doubling to
//!   250 ms, until an accept succeeds.

use std::future::Future;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use crate::compose::{Accept, Connection, Failure, Slot};
use crate::framer::FramerDoor;
use crate::io::{self as reactor, Direction, Registered};
use crate::socket;

/// A listener's connection cap when its settings name none (new in 1.6.0).
pub const DEFAULT_MAX_CONNS: usize = 1024;

/// A TLS handshake's bound when its settings name none: 1.5.5's `limits.tls_handshake_timeout_secs`
/// default.
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The first accept-error backoff (1.5.5).
const BACKOFF_FIRST: Duration = Duration::from_millis(5);
/// The accept-error backoff's cap (1.5.5).
const BACKOFF_CAP: Duration = Duration::from_millis(250);

/// The bounds one listener keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptLimits {
    /// The most connections held at once.
    pub max_conns: usize,
    /// The bound on a TLS handshake.
    pub handshake_timeout: Duration,
}

impl Default for AcceptLimits {
    fn default() -> Self {
        Self {
            max_conns: DEFAULT_MAX_CONNS,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
        }
    }
}

/// One accepted connection and the peer it came from.
#[derive(Debug)]
pub struct Accepted {
    /// The composed connection.
    pub conn: Connection,
    /// The far end's address.
    pub peer: SocketAddr,
}

/// One socket a stream listener admitted ([`Listening::poll_accept_stream`]).
#[derive(Debug)]
pub struct Handed {
    /// The socket, non-blocking, on no reactor.
    pub stream: TcpStream,
    /// The far end.
    pub peer: SocketAddr,
    /// The listener's slot, freed when dropped.
    pub slot: Slot,
}

/// The root's stream listener as the kernel's accept source: each admitted socket, with its slot
/// held for as long as the kernel serves it.
impl busbar_kernel::tls::Admits for Listening {
    async fn admit(&mut self) -> busbar_kernel::tls::Admitted {
        let h = futures::future::poll_fn(|cx| self.poll_accept_stream(cx)).await;
        busbar_kernel::tls::Admitted {
            stream: h.stream,
            peer: h.peer,
            hold: Some(Box::new(h.slot)),
        }
    }
}

/// One listener: bound for one inbound need (framed), or for one of the root's own binds (a
/// stream listener, [`Listening::bind_stream`]).
pub struct Listening {
    /// The entry every connection is framed through; `None` = a stream listener.
    door: Option<Arc<dyn FramerDoor>>,
    sock: Registered<TcpListener>,
    local: SocketAddr,
    accept: Accept,
    max_conns: usize,
    live: Arc<AtomicUsize>,
    backoff: Option<Duration>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl std::fmt::Debug for Listening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listening")
            .field("entry", &self.door.as_ref().map(|d| d.facts().name.clone()))
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl Listening {
    /// Bind `bind` (`ip:port`) on the calling worker's reactor, framing every connection through
    /// `door`, secured by `tls` where set with the protocols `alpn` agreeable.
    ///
    /// # Errors
    ///
    /// The address does not parse or cannot be bound, or the caller is not on a worker.
    pub fn bind(
        door: Arc<dyn FramerDoor>,
        bind: &str,
        tls: Option<Arc<rustls::ServerConfig>>,
        alpn: Vec<Vec<u8>>,
        limits: AcceptLimits,
    ) -> std::io::Result<Self> {
        let mut l = Self::bind_stream(bind, limits)?;
        l.door = Some(door);
        l.accept.tls = tls;
        l.accept.alpn = alpn;
        Ok(l)
    }

    /// A STREAM LISTENER, for the root's own, NON-PLANE binds only (its data door and its admin
    /// surface): bind `bind` (`ip:port`) on the calling worker's reactor, bounded by `limits`'
    /// connection cap and 1.5.5's accept backoff, and hand each admitted socket up as it arrived
    /// ([`Listening::poll_accept_stream`]) to be secured and served by the kernel's hardened HTTP
    /// loop. The admin surface keeps it; the data door's use is TRANSITIONAL: once the plane
    /// driver serves the data door (K1 U6/U7), its connections are framed ([`Listening::bind`])
    /// and this hand-up stops being its path.
    ///
    /// # Errors
    ///
    /// The address does not parse or cannot be bound, or the caller is not on a worker.
    pub fn bind_stream(bind: &str, limits: AcceptLimits) -> std::io::Result<Self> {
        let l = socket::listen(bind)?;
        let local = l.local_addr()?;
        let sock = reactor::register(l)?;
        Ok(Self {
            door: None,
            sock,
            local,
            accept: Accept {
                tls: None,
                alpn: Vec::new(),
                handshake_timeout: limits.handshake_timeout,
            },
            max_conns: limits.max_conns,
            live: Arc::new(AtomicUsize::new(0)),
            backoff: None,
            sleep: None,
        })
    }

    /// The address bound.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// How many connections this listener holds now.
    #[must_use]
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// The next admitted connection: `Pending` with `cx`'s waker on the listening socket (or on
    /// the backoff's timer). A connection past the cap is accepted and closed here, never answered.
    ///
    /// # Errors
    ///
    /// The accepted socket could not be composed (it is dropped; the listener stays up).
    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<Accepted, Failure>> {
        let Some(door) = self.door.clone() else {
            return Poll::Ready(Err(Failure::Refused(
                "a stream listener frames nothing".into(),
            )));
        };
        let (stream, peer, slot) = std::task::ready!(self.poll_socket(cx));
        Poll::Ready(
            Connection::accepted(door, stream, &self.accept, Some(slot))
                .map(|conn| Accepted { conn, peer }),
        )
    }

    /// The next admitted socket of a STREAM listener ([`Listening::bind_stream`]), as it arrived:
    /// non-blocking, on no reactor, with the listener's slot for it. For the root's own non-plane
    /// binds only; a plane's connections are framed ([`Listening::poll_accept`]).
    pub fn poll_accept_stream(&mut self, cx: &mut Context<'_>) -> Poll<Handed> {
        loop {
            let (stream, peer, slot) = std::task::ready!(self.poll_socket(cx));
            if stream.set_nonblocking(true).is_ok() {
                return Poll::Ready(Handed { stream, peer, slot });
            }
        }
    }

    /// The next socket under the cap: one past it is accepted and closed at once, no byte
    /// written; an accept error backs off as 1.5.5's did.
    fn poll_socket(&mut self, cx: &mut Context<'_>) -> Poll<(TcpStream, SocketAddr, Slot)> {
        loop {
            if let Some(sleep) = self.sleep.as_mut() {
                std::task::ready!(sleep.as_mut().poll(cx));
                self.sleep = None;
            }
            match self.sock.poll_io(Direction::Read, cx, TcpListener::accept) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok((stream, peer))) => {
                    self.backoff = None;
                    let Some(slot) = Slot::take(&self.live, self.max_conns) else {
                        // Over the cap: closed at once, no byte written.
                        drop(stream);
                        continue;
                    };
                    return Poll::Ready((stream, peer, slot));
                }
                Poll::Ready(Err(e)) => {
                    if let Some(d) = self.next_delay(&e) {
                        self.sleep = Some(Box::pin(tokio::time::sleep(d)));
                    }
                }
            }
        }
    }

    /// 1.5.5's accept backoff: `None` = retry now.
    fn next_delay(&mut self, e: &std::io::Error) -> Option<Duration> {
        if matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::Interrupted
        ) {
            self.backoff = None;
            return None;
        }
        let d = self
            .backoff
            .map_or(BACKOFF_FIRST, |prev| (prev * 2).min(BACKOFF_CAP));
        self.backoff = Some(d);
        Some(d)
    }
}

#[cfg(test)]
#[path = "tests/listen_tests.rs"]
mod tests;
