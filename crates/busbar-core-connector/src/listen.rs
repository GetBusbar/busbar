// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LISTEN: one listener per INBOUND need, the server-side mirror of [`crate::compose`]'s dial. The

use std::future::Future;
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{AcceptIn, AcceptOut};
use busbar_contract::transport::codes::MAX_ADDR;

use crate::carrier::{text, Carried, Carry, Driven};
use crate::compose::{Accept, Connection, Failure, Slot, Via};
use crate::framer::FramerDoor;
use crate::hostio::HostListener;

/// The room a carrier's `listen`/`accept` answer writes its address text into ([`MAX_ADDR`] bytes), on
/// the stack.
pub(crate) const ADDR_CAP: usize = MAX_ADDR as usize;

/// A listener's connection cap when its settings name none (new in 1.6.0).
pub const DEFAULT_MAX_CONNS: usize = 1024;

/// A TLS handshake's bound when its settings name none: 1.5.5's `limits.tls_handshake_timeout_secs`
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// 1.5.5's accept-error backoff, on backon: 5 ms doubling to a 250 ms cap, no jitter, no retry
/// limit. `next_delay` answers `None` (retry now) for an aborted or interrupted accept, which also
/// starts the sequence over, and the next delay for anything else (fd exhaustion and the like).
/// The root listener and the connector's `Listening` share this one.
#[derive(Debug, Default)]
pub struct AcceptBackoff(Option<backon::ExponentialBackoff>);

impl AcceptBackoff {
    /// The first delay.
    pub const FIRST: Duration = Duration::from_millis(5);
    /// The cap.
    pub const CAP: Duration = Duration::from_millis(250);
    const DELAYS: backon::ExponentialBuilder = backon::ExponentialBuilder::new()
        .with_min_delay(Self::FIRST)
        .with_max_delay(Self::CAP)
        .without_max_times();

    /// Start the sequence over (an accept succeeded).
    pub fn reset(&mut self) {
        self.0 = None;
    }

    /// `None` = retry now; otherwise how long to wait before accepting again.
    pub fn next_delay(&mut self, e: &std::io::Error) -> Option<Duration> {
        use backon::BackoffBuilder as _;
        if matches!(
            e.kind(),
            std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::Interrupted
        ) {
            self.0 = None;
            return None;
        }
        self.0.get_or_insert_with(|| Self::DELAYS.build()).next()
    }
}

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

/// ONE CONNECTION AN INBOUND LISTENER ADMITTED: the accepted socket, not yet on any worker's reactor
pub struct Admitted {
    /// The accepted socket, non-blocking.
    pub stream: std::net::TcpStream,
    /// The far end.
    pub peer: SocketAddr,
    /// Held for as long as the connection is served.
    pub hold: Option<Box<dyn Send>>,
}

/// AN INBOUND LISTENER, as the accept loop drains it: the next admitted connection. Accept errors,
pub trait Admits: Send {
    /// The next admitted connection.
    fn admit(&mut self) -> impl Future<Output = Admitted> + Send + '_;
}

/// The root's stream listener as the root's accept source (`busbar::root::listener`): each
impl Admits for Listening {
    async fn admit(&mut self) -> Admitted {
        let h = futures::future::poll_fn(|cx| self.poll_accept_stream(cx)).await;
        Admitted {
            stream: h.stream,
            peer: h.peer,
            hold: Some(Box::new(h.slot)),
        }
    }
}

/// A LISTENER'S STOP, held off its worker: [`ListenStop::stop`] takes the listener out of service from any thread.
pub struct ListenStop {
    _held: (),
}

impl ListenStop {
    /// Stop the listener.
    pub fn stop(&self) {}
}

/// What a listener's connections become.
enum Mode {
    /// Framed through this entry, over the carrier.
    Framed(Arc<dyn FramerDoor>),
    /// The carrier carried as itself.
    Carried,
    /// Handed up whole to the kernel's own serving loop (the root's non-plane binds).
    HandUp,
}

/// Where a listener's connections come from.
enum Source {
    /// The carrier's listener, accepted on its own side; `bound` is the host's listening handle
    Carrier {
        via: Via,
        listener: u64,
        side: Driven,
        bound: Option<u64>,
    },
    /// The host's own listening socket: a STREAM listener with no carrier loaded to listen through
    Host(HostListener),
}

/// One listener: bound for one inbound need (framed, or the carrier carried as itself), or for one
pub struct Listening {
    mode: Mode,
    source: Source,
    local: SocketAddr,
    accept: Accept,
    max_conns: usize,
    live: Arc<AtomicUsize>,
    backoff: AcceptBackoff,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl std::fmt::Debug for Listening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry = match &self.mode {
            Mode::Framed(d) => Some(d.facts().name.as_str()),
            _ => None,
        };
        f.debug_struct("Listening")
            .field("entry", &entry)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

pub(crate) fn other(t: String) -> std::io::Error {
    std::io::Error::other(t)
}

/// What a carrier's `listen` came to: its listener token, the side its accepts run on, the host's
pub(crate) type Bound = (u64, Driven, Option<u64>, SocketAddr);

use crate::off_path::lines::listen_through;

impl Listening {
    /// Bind `bind` (`ip:port`) through the carrier `via`, framing every connection through `door`
    pub fn bind(
        door: Option<Arc<dyn FramerDoor>>,
        via: &Via,
        bind: &str,
        tls: Option<Arc<rustls::ServerConfig>>,
        alpn: Vec<Vec<u8>>,
        limits: AcceptLimits,
    ) -> std::io::Result<Self> {
        let (listener, side, bound, local) = listen_through(via, bind)?;
        Ok(Self {
            mode: door.map_or(Mode::Carried, Mode::Framed),
            source: Source::Carrier {
                via: via.clone(),
                listener,
                side,
                bound,
            },
            local,
            accept: Accept {
                tls,
                alpn,
                handshake_timeout: limits.handshake_timeout,
            },
            max_conns: limits.max_conns,
            live: Arc::new(AtomicUsize::new(0)),
            backoff: AcceptBackoff::default(),
            sleep: None,
        })
    }

    /// A STREAM LISTENER, for the root's own, NON-PLANE binds only (its data door and its admin
    pub fn bind_stream(
        via: Option<&Via>,
        bind: &str,
        limits: AcceptLimits,
    ) -> std::io::Result<Self> {
        let (source, local) = match via {
            Some(via) => {
                let (listener, side, bound, local) = listen_through(via, bind)?;
                (
                    Source::Carrier {
                        via: via.clone(),
                        listener,
                        side,
                        bound,
                    },
                    local,
                )
            }
            None => {
                let l = HostListener::bind(bind)?;
                let local = l.local_addr();
                (Source::Host(l), local)
            }
        };
        Ok(Self {
            mode: Mode::HandUp,
            source,
            local,
            accept: Accept {
                tls: None,
                alpn: Vec::new(),
                handshake_timeout: limits.handshake_timeout,
            },
            max_conns: limits.max_conns,
            live: Arc::new(AtomicUsize::new(0)),
            backoff: AcceptBackoff::default(),
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

    /// This listener's stop, to be held off its worker.
    #[must_use]
    pub fn stopper(&self) -> ListenStop {
        ListenStop { _held: () }
    }

    /// The next admitted connection: `Pending` with `cx`'s waker on the carrier's accept (or on
    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<Accepted, Failure>> {
        let door = match &self.mode {
            Mode::Framed(d) => Some(Arc::clone(d)),
            Mode::Carried => None,
            Mode::HandUp => {
                return Poll::Ready(Err(Failure::Refused(
                    "a stream listener frames nothing".into(),
                )));
            }
        };
        let (got, peer, slot) = std::task::ready!(self.poll_conn(cx));
        let Got::Carried(carried) = got else {
            return Poll::Ready(Err(Failure::Refused(
                "a stream listener frames nothing".into(),
            )));
        };
        Poll::Ready(
            Connection::accepted(door, carried, &self.accept, Some(slot))
                .map(|conn| Accepted { conn, peer }),
        )
    }

    /// The next admitted socket of a STREAM listener ([`Listening::bind_stream`]), as it arrived:
    pub(crate) fn poll_accept_stream(&mut self, cx: &mut Context<'_>) -> Poll<Handed> {
        loop {
            let (got, peer, slot) = std::task::ready!(self.poll_conn(cx));
            let stream = match got {
                Got::Carried(carried) => carried.hand_up(),
                Got::Host(stream) => Some(stream),
            };
            if let Some(stream) = stream.filter(|s| s.set_nonblocking(true).is_ok()) {
                return Poll::Ready(Handed { stream, peer, slot });
            }
        }
    }

    /// The next connection under the cap: one past it is accepted and closed at once, no byte
    fn poll_conn(&mut self, cx: &mut Context<'_>) -> Poll<(Got, SocketAddr, Slot)> {
        loop {
            if let Some(sleep) = self.sleep.as_mut() {
                std::task::ready!(sleep.as_mut().poll(cx));
                self.sleep = None;
            }
            let got = match &mut self.source {
                Source::Carrier {
                    via,
                    listener,
                    side,
                    ..
                } => std::task::ready!(accept_through(via, *listener, side, cx))
                    .map_err(std::io::Error::other),
                Source::Host(l) => {
                    std::task::ready!(l.poll_accept(cx)).map(|(s, peer)| (Got::Host(s), peer))
                }
            };
            match got {
                Ok((got, peer)) => {
                    self.backoff.reset();
                    let Some(slot) = Slot::take(&self.live, self.max_conns) else {
                        drop(got);
                        continue;
                    };
                    return Poll::Ready((got, peer, slot));
                }
                Err(e) => {
                    if let Some(d) = self.next_delay(&e) {
                        self.sleep = Some(Box::pin(tokio::time::sleep(d)));
                    }
                }
            }
        }
    }
}

/// A RETIRED LISTENER STOPS ACCEPTING AT ONCE (T1): the host's listening handle its carrier's
impl Drop for Listening {
    fn drop(&mut self) {
        if let Source::Carrier {
            via, side, bound, ..
        } = &mut self.source
        {
            side.cancel(via.door.as_ref());
            let (made, _) = via.io.settle(side.ticket());
            if let Some(h) = made {
                via.io.retire_handle(h);
            }
            if let Some(h) = bound {
                via.io.retire_listener(*h);
            }
        }
    }
}

impl Listening {
    /// The listener's [`AcceptBackoff`]: `None` = retry now.
    fn next_delay(&mut self, e: &std::io::Error) -> Option<Duration> {
        self.backoff.next_delay(e)
    }
}

/// What one accept came to.
pub(crate) enum Got {
    /// The carrier's connection.
    Carried(Carried),
    /// The host's own socket (a stream listener with no carrier).
    Host(TcpStream),
}

/// The carrier's `accept` on its listener's side: the connection and its far end.
pub(crate) fn accept_through(
    via: &Via,
    listener: u64,
    side: &mut Driven,
    cx: &mut Context<'_>,
) -> Poll<Result<(Got, SocketAddr), String>> {
    let mut peer = [0_u8; ADDR_CAP];
    let mut i: AcceptIn = blank_in();
    i.listener = listener;
    i.peer_buf = peer.as_mut_ptr();
    i.peer_cap = peer.len();
    let mut o: AcceptOut = blank_out();
    let Some(c) = side.cross(via.door.as_ref(), Carry::Accept(&mut i, &mut o), Some(cx)) else {
        return Poll::Pending;
    };
    let (handle, _) = via.io.settle(side.ticket());
    if c.outcome != Outcome::Ready {
        if let Some(h) = handle {
            via.io.retire_handle(h);
        }
        return Poll::Ready(Err(text(&c)));
    }
    let Some(carried) =
        Carried::accepted(Arc::clone(&via.door), Arc::clone(&via.io), o.conn, handle)
    else {
        if let Some(h) = handle {
            via.io.retire_handle(h);
        }
        return Poll::Ready(Err("the transport is no carrier the host drives".into()));
    };
    let n = usize::try_from(o.peer_written).unwrap_or(0).min(peer.len());
    let at = String::from_utf8_lossy(&peer[..n])
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    Poll::Ready(Ok((Got::Carried(carried), at)))
}

#[cfg(test)]
#[path = "tests/listen_tests.rs"]
mod tests;
