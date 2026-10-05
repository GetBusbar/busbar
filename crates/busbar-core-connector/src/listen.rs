// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LISTEN: one listener per INBOUND need, the server-side mirror of [`crate::compose`]'s dial. The
//! CARRIER listens and accepts (TRANSPORT-STACK (2): the accept loop is the carrier's), the host
//! binding only the address it admitted; every connection it accepts is composed as
//! `carrier -> [TLS] -> framer`, the framing begun on `SIDE_ACCEPT` ([`Connection::accepted`]).
//!
//! The accept is bounded, and nothing here starts a thread or a task:
//!
//! * at most [`AcceptLimits::max_conns`] connections are held at once; one past it is accepted and
//!   closed at once, no byte written;
//! * a TLS handshake is bounded by [`AcceptLimits::handshake_timeout`] (1.5.5's
//!   `limits.tls_handshake_timeout_secs`, default 10 s) and a handshake past it is dropped; the
//!   framer's own deadlines bound what follows;
//! * an accept error backs off as 1.5.5's accept loop did: a per-connection transient (an aborted
//!   or interrupted accept) retries at once (the host's), anything else (fd exhaustion) waits 5 ms,
//!   doubling to 250 ms, until an accept succeeds.

use std::future::Future;
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{AcceptIn, AcceptOut, ListenIn, ListenOut, MAX_ADDR};

use crate::carrier::{text, Carried, Carry, Driven};
use crate::compose::{Accept, Connection, Failure, Slot, Via};
use crate::framer::FramerDoor;
use crate::hostio::{Admission, HostListener};

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
    /// The carrier's listener, accepted on its own side.
    Carrier {
        via: Via,
        listener: u64,
        side: Driven,
    },
    /// The host's own listening socket: a STREAM listener with no carrier loaded to listen through
    /// (a build that links none); its sockets are handed up as they arrive.
    Host(HostListener),
}

/// One listener: bound for one inbound need (framed, or the carrier carried as itself), or for one
/// of the root's own binds (a stream listener, [`Listening::bind_stream`]).
pub struct Listening {
    mode: Mode,
    source: Source,
    local: SocketAddr,
    accept: Accept,
    max_conns: usize,
    live: Arc<AtomicUsize>,
    backoff: Option<Duration>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl std::fmt::Debug for Listening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entry = match &self.mode {
            Mode::Framed(d) => Some(d.facts().name.clone()),
            _ => None,
        };
        f.debug_struct("Listening")
            .field("entry", &entry)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

fn other(t: String) -> std::io::Error {
    std::io::Error::other(t)
}

/// The carrier's `listen` on `bind`, the host admitting exactly it: the listener and the address
/// bound.
fn listen_through(via: &Via, bind: &str) -> std::io::Result<(u64, Driven, SocketAddr)> {
    let mut side = Driven::of(via.door.as_ref())
        .ok_or_else(|| other("the transport is no carrier the host drives".into()))?;
    via.io.admit(side.ticket(), Admission::Bind(bind.to_owned()));
    let mut addr = vec![0_u8; usize::try_from(MAX_ADDR).unwrap_or(256)];
    let mut i: ListenIn = blank_in();
    i.bind = busbar_contract::abi::mechanism::call::AbiStr {
        ptr: bind.as_ptr(),
        len: bind.len(),
    };
    i.addr_buf = addr.as_mut_ptr();
    i.addr_cap = addr.len();
    let mut o: ListenOut = blank_out();
    let c = side.cross(via.door.as_ref(), Carry::Listen(&mut i, &mut o), None);
    let _ = via.io.settle(side.ticket());
    match c {
        Some(c) if c.outcome == Outcome::Ready => {
            let n = usize::try_from(o.addr_written).unwrap_or(0).min(addr.len());
            let local = String::from_utf8_lossy(&addr[..n])
                .parse::<SocketAddr>()
                .map_err(|_| other("the carrier bound no address".into()))?;
            Ok((o.listener, side, local))
        }
        Some(c) => Err(other(text(&c))),
        None => Err(other("a listen may not pend".into())),
    }
}

impl Listening {
    /// Bind `bind` (`ip:port`) through the carrier `via`, framing every connection through `door`
    /// (`None` = the carrier carried as itself), secured by `tls` where set with the protocols
    /// `alpn` agreeable.
    ///
    /// # Errors
    ///
    /// The carrier or the host would not bind the address.
    pub fn bind(
        door: Option<Arc<dyn FramerDoor>>,
        via: &Via,
        bind: &str,
        tls: Option<Arc<rustls::ServerConfig>>,
        alpn: Vec<Vec<u8>>,
        limits: AcceptLimits,
    ) -> std::io::Result<Self> {
        let (listener, side, local) = listen_through(via, bind)?;
        Ok(Self {
            mode: door.map_or(Mode::Carried, Mode::Framed),
            source: Source::Carrier {
                via: via.clone(),
                listener,
                side,
            },
            local,
            accept: Accept {
                tls,
                alpn,
                handshake_timeout: limits.handshake_timeout,
            },
            max_conns: limits.max_conns,
            live: Arc::new(AtomicUsize::new(0)),
            backoff: None,
            sleep: None,
        })
    }

    /// A STREAM LISTENER, for the root's own, NON-PLANE binds only (its data door and its admin
    /// surface): bind `bind` (`ip:port`) through the carrier `via` (or, with no carrier loaded to
    /// listen through, on the host's own socket), bounded by `limits`' connection cap and 1.5.5's
    /// accept backoff, and hand each admitted socket up as it arrived
    /// ([`Listening::poll_accept_stream`]) to be secured and served by the kernel's hardened HTTP
    /// loop: the byte stream moves on. The admin surface keeps it; the data door's use is
    /// TRANSITIONAL: once the plane driver serves the data door (K1 U6/U7), its connections are
    /// framed ([`Listening::bind`]) and this hand-up stops being its path.
    ///
    /// # Errors
    ///
    /// The address does not parse or cannot be bound, or the caller is not on a worker.
    pub fn bind_stream(via: Option<&Via>, bind: &str, limits: AcceptLimits) -> std::io::Result<Self> {
        let (source, local) = match via {
            Some(via) => {
                let (listener, side, local) = listen_through(via, bind)?;
                (
                    Source::Carrier {
                        via: via.clone(),
                        listener,
                        side,
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

    /// The next admitted connection: `Pending` with `cx`'s waker on the carrier's accept (or on
    /// the backoff's timer). A connection past the cap is accepted and closed here, never answered.
    ///
    /// # Errors
    ///
    /// The accepted connection could not be composed (it is dropped; the listener stays up).
    pub fn poll_accept(&mut self, cx: &mut Context<'_>) -> Poll<Result<Accepted, Failure>> {
        let door = match &self.mode {
            Mode::Framed(d) => Some(Arc::clone(d)),
            Mode::Carried => None,
            Mode::HandUp => {
                return Poll::Ready(Err(Failure::Refused(
                    "a stream listener frames nothing".into(),
                )))
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
    /// non-blocking, on no reactor, with the listener's slot for it. For the root's own non-plane
    /// binds only; a plane's connections are framed ([`Listening::poll_accept`]).
    ///
    /// Securing the socket is deliberately NOT done here: the kernel's placement balancer hands
    /// bare, pre-TLS sockets across data workers, and handshaking at accept would pin every
    /// connection to the worker that accepted it (1.5.5's per-core placement). The serving loop
    /// runs the connector's prepared connection security, under the configured handshake bound,
    /// after placement.
    // TRANSITIONAL: drains at K1 U6/U7 (1.6.0-TODO.md) for the data door; the admin surface keeps it.
    pub fn poll_accept_stream(&mut self, cx: &mut Context<'_>) -> Poll<Handed> {
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
    /// written; an accept error backs off as 1.5.5's did.
    fn poll_conn(&mut self, cx: &mut Context<'_>) -> Poll<(Got, SocketAddr, Slot)> {
        loop {
            if let Some(sleep) = self.sleep.as_mut() {
                std::task::ready!(sleep.as_mut().poll(cx));
                self.sleep = None;
            }
            let got = match &mut self.source {
                Source::Carrier { via, listener, side } => {
                    std::task::ready!(accept_through(via, *listener, side, cx))
                }
                Source::Host(l) => std::task::ready!(l.poll_accept(cx))
                    .map(|(s, peer)| (Got::Host(s), peer))
                    .map_err(|e| e.to_string()),
            };
            match got {
                Ok((got, peer)) => {
                    self.backoff = None;
                    let Some(slot) = Slot::take(&self.live, self.max_conns) else {
                        // Over the cap: closed at once, no byte written.
                        drop(got);
                        continue;
                    };
                    return Poll::Ready((got, peer, slot));
                }
                Err(_) => {
                    let d = self
                        .backoff
                        .map_or(BACKOFF_FIRST, |prev| (prev * 2).min(BACKOFF_CAP));
                    self.backoff = Some(d);
                    self.sleep = Some(Box::pin(tokio::time::sleep(d)));
                }
            }
        }
    }
}

/// What one accept came to.
enum Got {
    /// The carrier's connection.
    Carried(Carried),
    /// The host's own socket (a stream listener with no carrier).
    Host(TcpStream),
}

/// The carrier's `accept` on its listener's side: the connection and its far end.
fn accept_through(
    via: &Via,
    listener: u64,
    side: &mut Driven,
    cx: &mut Context<'_>,
) -> Poll<Result<(Got, SocketAddr), String>> {
    let mut peer = vec![0_u8; usize::try_from(MAX_ADDR).unwrap_or(256)];
    let mut i: AcceptIn = blank_in();
    i.listener = listener;
    i.peer_buf = peer.as_mut_ptr();
    i.peer_cap = peer.len();
    let mut o: AcceptOut = blank_out();
    let Some(c) = side.cross(via.door.as_ref(), Carry::Accept(&mut i, &mut o), Some(cx)) else {
        return Poll::Pending;
    };
    if c.outcome != Outcome::Ready {
        return Poll::Ready(Err(text(&c)));
    }
    let handle = via.io.made(side.ticket());
    let Some(carried) = Carried::accepted(
        Arc::clone(&via.door),
        Arc::clone(&via.io),
        o.conn,
        handle,
    ) else {
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
