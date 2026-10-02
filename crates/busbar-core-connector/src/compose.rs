// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! COMPOSE: one connection, `socket -> [TLS] -> framer` (`BUSBAR-1.6.0.md` THE DESIGN, §5), dialled
//! ([`Connection::dial`], the framing begun on `SIDE_DIAL`) or accepted ([`Connection::accepted`],
//! the server-side mirror: TLS as the server, the framing begun on `SIDE_ACCEPT`).
//!
//! The socket is the host's, non-blocking, its readiness on the dialling worker's reactor
//! ([`crate::io`]); connection security is `rustls` driven sans-IO here, with the protocol offer
//! (ALPN) the entry's registration states; the framer is the entry's table ([`crate::framer`]).
//! The connection is a state machine the caller polls — it holds no thread and no task, and every
//! wait is Pending with the caller's waker registered on the socket or the timer:
//!
//! * the bytes the socket reads go through TLS to the framer's `ingest`;
//! * the framer's wire bytes go through TLS to the socket;
//! * a deadline the framer states is a timer on the worker's clock, and at it the framer's `timer`
//!   runs; the open itself is bounded by the dial's own timeout;
//! * the frame pieces come out per stream, in order; `YIELD_ENDED` ends the connection.

use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use busbar_contract::abi::transport::{CLOSE_NORMAL, SIDE_ACCEPT, SIDE_DIAL};

use crate::endpoint;
use crate::framer::{self, Established, FramerDoor, Framing, Got, Yielded};
use crate::io::{self as reactor, Direction, Registered};
use crate::socket;

/// How much one socket read takes.
const READ_CHUNK: usize = 16 * 1024;

/// The open's bound when the caller states none.
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// The stream a dialled connection's own exchange rides.
pub const EXCHANGE_STREAM: u64 = 1;

/// THE WRITE BUFFER CAP: the most bytes one connection holds on a caller's behalf and not yet on the
/// socket (writes made before the framing began, and framed bytes the socket has not taken). A write
/// past it is taken short, and a write with no room is taken not at all, so a caller that writes
/// faster than its far end reads cannot grow the host's memory.
pub const WRITE_BUFFER_BYTES: usize = 256 * 1024;

/// Why a connection did not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The target was refused before any dial (a cloud metadata host, a name the connector does
    /// not resolve, a target the entry does not locate) or the far end said no.
    Refused(String),
    /// The open, or a deadline the framer stated, passed.
    Timeout,
    /// The connection is closed.
    Closed,
    /// The socket, connection security or the framer failed the connection.
    Failed(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(why) => write!(f, "refused: {why}"),
            Self::Timeout => f.write_str("the connection's deadline passed"),
            Self::Closed => f.write_str("the connection is closed"),
            Self::Failed(why) => write!(f, "failed: {why}"),
        }
    }
}

impl std::error::Error for Failure {}

/// A first message: its envelope fields and its body.
pub type Opening = (Vec<(String, Vec<u8>)>, Vec<u8>);

/// What a dial asks for.
#[derive(Clone)]
pub struct Dial {
    /// The target, as the entry's `locate` reads it.
    pub target: String,
    /// The client TLS config, where the target asks for connection security (its ALPN offer is
    /// set per dial from `alpn`).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// The protocols offered in the TLS handshake, most preferred first.
    pub alpn: Vec<Vec<u8>>,
    /// The bound on the open: connect and handshake.
    pub open_timeout: Duration,
    /// The first message, as envelope fields and a body; `None` sends nothing first.
    pub opening: Option<Opening>,
    /// The first message's head words, method and target (`framer::encode_head`); empty = none.
    pub head_words: HeadWords,
}

/// A message's head words, method and target; empty = none.
pub type HeadWords = (Vec<u8>, Vec<u8>);

impl std::fmt::Debug for Dial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dial")
            .field("target", &self.target)
            .field("tls", &self.tls.is_some())
            .field("open_timeout", &self.open_timeout)
            .finish_non_exhaustive()
    }
}

enum Phase {
    Connecting,
    Handshaking,
    Open,
    Ended,
    Failed(Failure),
}

/// One composed connection.
pub struct Connection {
    door: Arc<dyn FramerDoor>,
    sock: Registered<TcpStream>,
    target: String,
    /// `SIDE_DIAL` | `SIDE_ACCEPT`.
    side: u32,
    /// Client TLS on a dialled connection, server TLS on an accepted one.
    tls: Option<rustls::Connection>,
    framing: Option<Framing>,
    established: Established,
    phase: Phase,
    /// Bytes for the socket (ciphertext under TLS).
    out: VecDeque<u8>,
    /// Frame pieces the caller has not taken.
    inbox: VecDeque<Got>,
    /// The first message, sent once the framing begins.
    opening: Option<Opening>,
    /// Its head words.
    head_words: HeadWords,
    /// Writes the caller made before the framing began, in order: `(stream, bytes, end)`.
    early: Vec<(u64, Vec<u8>, bool, bool)>,
    open_deadline: Option<Instant>,
    framer_deadline: Option<Instant>,
    sleep: Option<(Instant, Pin<Box<tokio::time::Sleep>>)>,
    /// The listener's hold on one of its connection slots, freed when the connection is dropped.
    _slot: Option<Slot>,
}

/// One of a listener's connection slots, held by the connection it admitted and freed on drop.
#[derive(Debug)]
pub struct Slot(Arc<std::sync::atomic::AtomicUsize>);

impl Slot {
    /// Take a slot of `live` when fewer than `max` are held; `None` = the listener is full.
    #[must_use]
    pub fn take(live: &Arc<std::sync::atomic::AtomicUsize>, max: usize) -> Option<Self> {
        use std::sync::atomic::Ordering;
        live.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            (n < max).then_some(n + 1)
        })
        .ok()
        .map(|_| Self(Arc::clone(live)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

/// What an accept asks for: the server TLS (its protocol offer set per accept from `alpn`) and the
/// bound on the handshake.
#[derive(Clone)]
pub struct Accept {
    /// The server TLS config; `None` = the listener is in the clear.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// The protocols the server agrees to, most preferred first (the claiming framer's offer).
    pub alpn: Vec<Vec<u8>>,
    /// The bound on the handshake; the framer's own deadlines bound the rest.
    pub handshake_timeout: Duration,
}

impl std::fmt::Debug for Accept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Accept")
            .field("tls", &self.tls.is_some())
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("entry", &self.door.facts().name)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

fn failed(e: impl std::fmt::Display) -> Failure {
    Failure::Failed(e.to_string())
}

impl Connection {
    /// Dial `dial.target` through `door`: the endpoint check, the entry's `locate`, a second
    /// endpoint check on the authority it named, then a non-blocking connect registered on the
    /// calling worker's reactor. The connection comes back at once, its open in flight.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] before any socket exists; [`Failure::Failed`] off a worker or when the
    /// socket cannot be made.
    pub fn dial(door: Arc<dyn FramerDoor>, dial: Dial) -> Result<Self, Failure> {
        let planned = Planned::locate(door, dial)?;
        let addr = socket::address_of(planned.authority()).ok_or_else(|| {
            Failure::Refused(format!(
                "`{}` is not an address the connector dials without resolving a name",
                planned.authority()
            ))
        })?;
        planned.dial_at(addr)
    }
}

/// A dial located but not yet dialled: the target and the authority the entry named passed the
/// endpoint check, and the address to dial is still to be judged.
pub struct Planned {
    door: Arc<dyn FramerDoor>,
    dial: Dial,
    located: framer::Located,
}

impl std::fmt::Debug for Planned {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Planned")
            .field("target", &self.dial.target)
            .finish_non_exhaustive()
    }
}

impl Planned {
    /// The endpoint check, the entry's `locate`, and a second endpoint check on the authority it
    /// named.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`]: the target or the authority is refused, or the entry locates nothing.
    pub fn locate(door: Arc<dyn FramerDoor>, dial: Dial) -> Result<Self, Failure> {
        endpoint::check(&dial.target).map_err(|e| Failure::Refused(e.to_string()))?;
        let located = framer::locate(door.as_ref(), &dial.target)
            .map_err(|e| Failure::Refused(e.to_string()))?;
        endpoint::check(&located.authority).map_err(|e| Failure::Refused(e.to_string()))?;
        Ok(Self {
            door,
            dial,
            located,
        })
    }

    /// The authority the entry named (`host:port`), as the judge reads it.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.located.authority
    }

    /// Whether the entry located a target asking for connection security.
    #[must_use]
    pub fn secure(&self) -> bool {
        self.located.secure
    }

    /// Dial exactly `addr` — the address judged for [`Self::authority`] — with the name the entry
    /// located offered to connection security: a non-blocking connect registered on the calling
    /// worker's reactor. The connection comes back at once, its open in flight.
    ///
    /// # Errors
    ///
    /// [`Failure::Refused`] when security is asked for and none is set; [`Failure::Failed`] off a
    /// worker or when the socket cannot be made.
    pub fn dial_at(self, addr: std::net::SocketAddr) -> Result<Connection, Failure> {
        let Self {
            door,
            dial,
            located,
        } = self;
        let tls = if located.secure {
            let base = dial.tls.clone().ok_or_else(|| {
                Failure::Refused("the target asks for connection security and none is set".into())
            })?;
            let mut config = (*base).clone();
            config.alpn_protocols.clone_from(&dial.alpn);
            let host = located.name.clone().unwrap_or_else(|| {
                located
                    .authority
                    .rsplit_once(':')
                    .map_or(located.authority.clone(), |(h, _)| h.to_owned())
            });
            let name = rustls::pki_types::ServerName::try_from(
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
            )
            .map_err(|e| Failure::Refused(format!("the name offered is not a server name: {e}")))?;
            Some(rustls::Connection::Client(
                rustls::ClientConnection::new(Arc::new(config), name).map_err(failed)?,
            ))
        } else {
            None
        };
        let sock = reactor::register(socket::connect(addr).map_err(failed)?).map_err(failed)?;
        let established = Established {
            offered_name: tls.as_ref().and(located.name.clone()),
            agreed_protocol: None,
            claim: door.facts().claims.first().map(|c| (*c).to_owned()),
        };
        Ok(Connection {
            door,
            sock,
            target: dial.target,
            side: SIDE_DIAL,
            tls,
            framing: None,
            established,
            phase: Phase::Connecting,
            out: VecDeque::new(),
            inbox: VecDeque::new(),
            opening: dial.opening,
            head_words: dial.head_words,
            early: Vec::new(),
            open_deadline: Some(Instant::now() + dial.open_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: None,
        })
    }
}

impl Connection {
    /// Take `stream`, accepted by a listener, on the calling worker's reactor: server TLS first when
    /// `accept.tls` is set (bounded by the handshake timeout, the protocol agreed off
    /// `accept.alpn`), then the framing begun on `SIDE_ACCEPT`. `slot` is the listener's hold,
    /// freed when the connection is dropped.
    ///
    /// # Errors
    ///
    /// [`Failure::Failed`] off a worker or when the socket or TLS cannot be set up;
    /// [`Failure::Refused`] when the framer will not frame a clear connection.
    pub fn accepted(
        door: Arc<dyn FramerDoor>,
        stream: TcpStream,
        accept: &Accept,
        slot: Option<Slot>,
    ) -> Result<Self, Failure> {
        stream.set_nonblocking(true).map_err(failed)?;
        let _ = stream.set_nodelay(true);
        let tls = match &accept.tls {
            None => None,
            Some(base) => {
                let mut config = (**base).clone();
                config.alpn_protocols.clone_from(&accept.alpn);
                Some(rustls::Connection::Server(
                    rustls::ServerConnection::new(Arc::new(config)).map_err(failed)?,
                ))
            }
        };
        let sock = reactor::register(stream).map_err(failed)?;
        let established = Established {
            offered_name: None,
            agreed_protocol: None,
            claim: door.facts().claims.first().map(|c| (*c).to_owned()),
        };
        let mut conn = Self {
            door,
            sock,
            target: String::new(),
            side: SIDE_ACCEPT,
            tls,
            framing: None,
            established,
            phase: Phase::Handshaking,
            out: VecDeque::new(),
            inbox: VecDeque::new(),
            opening: None,
            head_words: HeadWords::default(),
            early: Vec::new(),
            open_deadline: Some(Instant::now() + accept.handshake_timeout),
            framer_deadline: None,
            sleep: None,
            _slot: slot,
        };
        if conn.tls.is_none() {
            conn.begin()?;
        }
        Ok(conn)
    }

    /// Whether the connection is past its handshake and framing.
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self.phase, Phase::Open)
    }
}

impl Connection {
    /// What connection security established (the agreed protocol, the name offered).
    #[must_use]
    pub fn established(&self) -> &Established {
        &self.established
    }

    /// The next frame piece: `Ready(Ok(Some))` a piece, `Ready(Ok(None))` the connection ended,
    /// `Pending` with `cx`'s waker on the socket and the timer.
    ///
    /// # Errors
    ///
    /// Why the connection failed.
    pub fn poll_piece(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Got>, Failure>> {
        loop {
            if let Some(p) = self.inbox.pop_front() {
                return Poll::Ready(Ok(Some(p)));
            }
            match &self.phase {
                Phase::Ended => return Poll::Ready(Ok(None)),
                Phase::Failed(f) => return Poll::Ready(Err(f.clone())),
                _ => {}
            }
            match self.drive(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(f) => self.phase = Phase::Failed(f),
            }
        }
    }

    /// Whether a piece (or the end) is ready, without taking it.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            if !self.inbox.is_empty() || matches!(self.phase, Phase::Ended | Phase::Failed(_)) {
                return Poll::Ready(());
            }
            match self.drive(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(f) => self.phase = Phase::Failed(f),
            }
        }
    }

    /// The bytes held for the socket: early writes and framed bytes it has not taken.
    fn buffered(&self) -> usize {
        self.out.len() + self.early.iter().map(|(_, b, _, _)| b.len()).sum::<usize>()
    }

    /// Offer `bytes` on the connection's exchange (`end` = the caller's message is complete, `text` =
    /// it is a text message),
    /// answering how many were taken: framed now if the framing has begun, else once it does; the
    /// socket takes them as its readiness allows, driven by `cx`. At most the room left under
    /// [`WRITE_BUFFER_BYTES`] is taken (`end` holds only when all of `bytes` was), so `Ok(0)` for a
    /// non-empty `bytes` means the buffer is full until the socket drains it.
    ///
    /// # Errors
    ///
    /// The connection is closed or failed, or the framer refused the bytes.
    pub fn write(
        &mut self,
        bytes: &[u8],
        end: bool,
        text: bool,
        cx: &mut Context<'_>,
    ) -> Result<usize, Failure> {
        self.emit(EXCHANGE_STREAM, bytes, end, text, cx)
    }

    /// Offer `bytes` on `stream` (`end` = the stream's message is complete, `text` = it is a text
    /// message): the framer's `emit`
    /// on that stream, now if the framing has begun, else once it does. An accepted connection
    /// answers each piece on the stream the piece came on.
    ///
    /// # Errors
    ///
    /// The connection is closed or failed, or the framer refused the bytes.
    pub fn emit(
        &mut self,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
        cx: &mut Context<'_>,
    ) -> Result<usize, Failure> {
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended => return Err(Failure::Closed),
            _ => {}
        }
        // Let the socket take what it can before measuring the room.
        if let Err(f) = self.drive(cx) {
            self.phase = Phase::Failed(f.clone());
            return Err(f);
        }
        let take = bytes
            .len()
            .min(WRITE_BUFFER_BYTES.saturating_sub(self.buffered()));
        if take == 0 && !bytes.is_empty() {
            return Ok(0);
        }
        let (bytes, end) = (&bytes[..take], end && take == bytes.len());
        match &self.phase {
            Phase::Failed(f) => return Err(f.clone()),
            Phase::Ended => return Err(Failure::Closed),
            Phase::Open => {
                let framing = self.framing.as_mut().ok_or(Failure::Closed)?;
                let y = framing.emit(stream, bytes, end, text).map_err(failed)?;
                self.absorb(y)?;
            }
            Phase::Connecting | Phase::Handshaking => {
                self.early.push((stream, bytes.to_vec(), end, text));
            }
        }
        if let Err(f) = self.drive(cx) {
            self.phase = Phase::Failed(f.clone());
            return Err(f);
        }
        Ok(take)
    }

    /// One pass: connect, handshake, flush, read, and keep the deadlines. `Ok(true)` = something
    /// moved; `Ok(false)` = nothing can until a waker fires.
    fn drive(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut moved = false;
        if matches!(self.phase, Phase::Connecting) {
            match socket::poll_connected(&self.sock, cx) {
                Poll::Ready(Ok(())) => {
                    moved = true;
                    if self.tls.is_some() {
                        self.phase = Phase::Handshaking;
                        self.tls_out()?;
                    } else {
                        self.begin()?;
                    }
                }
                Poll::Ready(Err(e)) => return Err(Failure::Refused(e.to_string())),
                Poll::Pending => {}
            }
        }
        if !matches!(self.phase, Phase::Connecting) {
            moved |= self.flush(cx)?;
            moved |= self.read(cx)?;
        }
        moved |= self.keep_deadlines(cx)?;
        Ok(moved)
    }

    /// Write what the socket owes, as far as its readiness allows.
    fn flush(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut moved = false;
        while !self.out.is_empty() {
            let (a, _) = self.out.as_slices();
            match self.sock.poll_io(Direction::Write, cx, |mut s| s.write(a)) {
                Poll::Ready(Ok(0)) => return Err(Failure::Closed),
                Poll::Ready(Ok(n)) => {
                    self.out.drain(..n);
                    moved = true;
                }
                Poll::Ready(Err(e)) => return Err(failed(e)),
                Poll::Pending => break,
            }
        }
        Ok(moved)
    }

    /// Read what the socket has, and hand it on.
    fn read(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let mut buf = [0_u8; READ_CHUNK];
        match self
            .sock
            .poll_io(Direction::Read, cx, |mut s| s.read(&mut buf))
        {
            Poll::Ready(Ok(0)) => {
                self.feed(&[], true)?;
                Ok(true)
            }
            Poll::Ready(Ok(n)) => {
                self.feed(&buf[..n], false)?;
                Ok(true)
            }
            Poll::Ready(Err(e)) => Err(failed(e)),
            Poll::Pending => Ok(false),
        }
    }

    /// The open's bound and the framer's deadline: the earlier is a timer on the worker's clock.
    fn keep_deadlines(&mut self, cx: &mut Context<'_>) -> Result<bool, Failure> {
        let now = Instant::now();
        if matches!(self.phase, Phase::Connecting | Phase::Handshaking) {
            if self.open_deadline.is_some_and(|at| at <= now) {
                return Err(Failure::Timeout);
            }
        } else {
            self.open_deadline = None;
        }
        let mut moved = false;
        if self.framer_deadline.is_some_and(|at| at <= now) {
            self.framer_deadline = None;
            if let Some(framing) = self.framing.as_mut() {
                let y = framing.timer().map_err(|e| match e.outcome {
                    busbar_contract::abi::mechanism::call::Outcome::Failed => Failure::Timeout,
                    _ => failed(e),
                })?;
                self.absorb(y)?;
                moved = true;
            }
        }
        let next = match (self.open_deadline, self.framer_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        match next {
            None => self.sleep = None,
            Some(at) => {
                if self.sleep.as_ref().is_none_or(|(when, _)| *when != at) {
                    self.sleep = Some((
                        at,
                        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(at))),
                    ));
                }
                if let Some((_, sleep)) = self.sleep.as_mut() {
                    if sleep.as_mut().poll(cx).is_ready() {
                        self.sleep = None;
                        moved = true;
                    }
                }
            }
        }
        Ok(moved)
    }

    /// Begin the framing over what the open established, then send the first message and any
    /// early writes.
    fn begin(&mut self) -> Result<(), Failure> {
        let (framing, y) = Framing::begin(
            Arc::clone(&self.door),
            self.side,
            &self.target,
            &self.established,
        )
        .map_err(|e| Failure::Refused(e.to_string()))?;
        self.framing = Some(framing);
        self.phase = Phase::Open;
        self.absorb(y)?;
        if let Some((fields, body)) = self.opening.take() {
            let (method, target) = std::mem::take(&mut self.head_words);
            if !fields.is_empty() || !body.is_empty() || !method.is_empty() || !target.is_empty() {
                let fields: Vec<(&str, &[u8])> = fields
                    .iter()
                    .map(|(n, v)| (n.as_str(), v.as_slice()))
                    .collect();
                let message =
                    framer::encode_head(self.door.as_ref(), &method, &target, &fields, &body)
                        .map_err(|e| Failure::Refused(e.to_string()))?;
                let framing = self.framing.as_mut().ok_or(Failure::Closed)?;
                let y = framing
                    .emit(EXCHANGE_STREAM, &message, true, false)
                    .map_err(failed)?;
                self.absorb(y)?;
            }
        }
        for (stream, bytes, end, text) in std::mem::take(&mut self.early) {
            let framing = self.framing.as_mut().ok_or(Failure::Closed)?;
            let y = framing.emit(stream, &bytes, end, text).map_err(failed)?;
            self.absorb(y)?;
        }
        Ok(())
    }

    /// What the socket read: through TLS (finishing its handshake) to the framer.
    fn feed(&mut self, bytes: &[u8], end: bool) -> Result<(), Failure> {
        let Some(tls) = self.tls.as_mut() else {
            return self.ingest(bytes, end);
        };
        let mut rest = bytes;
        while !rest.is_empty() {
            tls.read_tls(&mut rest).map_err(failed)?;
            tls.process_new_packets()
                .map_err(|e| Failure::Refused(format!("tls: {e}")))?;
        }
        if matches!(self.phase, Phase::Handshaking) {
            if end {
                return Err(Failure::Refused(
                    "tls: the far end closed the handshake".into(),
                ));
            }
            if !self.tls.as_ref().is_some_and(|t| t.is_handshaking()) {
                self.established.agreed_protocol = self
                    .tls
                    .as_ref()
                    .and_then(|t| t.alpn_protocol().map(<[u8]>::to_vec));
                if let Some(rustls::Connection::Server(s)) = self.tls.as_ref() {
                    self.established.offered_name = s.server_name().map(str::to_owned);
                }
                self.begin()?;
            }
        }
        let mut plain = Vec::new();
        let mut closed = end;
        if let Some(tls) = self.tls.as_mut() {
            let mut buf = [0_u8; READ_CHUNK];
            loop {
                match tls.reader().read(&mut buf) {
                    Ok(0) => {
                        closed = true;
                        break;
                    }
                    Ok(n) => plain.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(failed(e)),
                }
            }
        }
        self.tls_out()?;
        if matches!(self.phase, Phase::Open) && (!plain.is_empty() || closed) {
            self.ingest(&plain, closed)?;
        }
        Ok(())
    }

    fn ingest(&mut self, bytes: &[u8], end: bool) -> Result<(), Failure> {
        let Some(framing) = self.framing.as_mut() else {
            return if end { Err(Failure::Closed) } else { Ok(()) };
        };
        let y = framing.ingest(bytes, end).map_err(failed)?;
        self.absorb(y)
    }

    /// Take what the framer answered: its wire bytes to the socket (through TLS), its pieces to
    /// the inbox, its deadline to the timer, its end to the connection.
    fn absorb(&mut self, y: Yielded) -> Result<(), Failure> {
        if !y.wire.is_empty() {
            match self.tls.as_mut() {
                Some(tls) => {
                    tls.writer().write_all(&y.wire).map_err(failed)?;
                    self.tls_out()?;
                }
                None => self.out.extend(y.wire),
            }
        }
        self.inbox.extend(y.pieces);
        self.framer_deadline = y.deadline_ns.map(framer::instant_of);
        if y.ended {
            self.phase = Phase::Ended;
        }
        Ok(())
    }

    /// Move whatever TLS owes the far side into the socket's queue.
    fn tls_out(&mut self) -> Result<(), Failure> {
        if let Some(tls) = self.tls.as_mut() {
            let mut bytes = Vec::new();
            while tls.wants_write() {
                tls.write_tls(&mut bytes).map_err(failed)?;
            }
            self.out.extend(bytes);
        }
        Ok(())
    }

    /// Close: the framing finishes, TLS says goodbye, and what that owes is written as far as the
    /// socket takes it now.
    pub fn close(mut self) {
        let framed = self.framing.is_some();
        if let Some(framing) = self.framing.take() {
            let y = framing.finish(CLOSE_NORMAL);
            let _ = self.absorb(y);
        }
        // A handshake that never finished is dropped, not said goodbye to (1.5.5's handshake
        // timeout drops the connection).
        if let Some(tls) = self.tls.as_mut().filter(|_| framed) {
            tls.send_close_notify();
            let _ = self.tls_out();
        }
        let waker = std::task::Waker::noop();
        let _ = self.flush(&mut Context::from_waker(waker));
    }
}

#[cfg(test)]
#[path = "tests/compose_tests.rs"]
mod tests;
