// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TRANSPORT ENTRY OVER HOST SOCKETS: [`HostWire`] serves one transport entry over the host's
//! socket through the connector's own host-side surface, a carrier as itself or a framer over the
//! carrier the connector chose. No entry composes over another (`BUSBAR-1.6.0.md` TRANSPORT-STACK
//! (2), :4721: every entry states an EMPTY `composes_over`, and the carrier is the connector's
//! choice from the target's scheme); a stream another entry handed up is ADOPTED by the entry the
//! connector picks for it ([`HostWire::adopt_from`]), never by a list the entry states.
//! The connector is core and presents no plugin face; the composition root adapts this surface to
//! the kernel's legacy transport seam, so the kernel's listeners, accept loop and upgrades drive it
//! the way they drive any transport.
//!
//! The sockets are the host's, and a CARRIER moves their bytes ([`crate::carrier`]): a dial rides the
//! entry itself when it is a carrier (carried as itself: every read a frame, every write a frame's
//! bytes), else the address carrier the wire was handed ([`crate::carrier::AddressCarrier`]) under the
//! entry's framer ([`crate::framer`]); a connection handed up (`detach`) gives the carried stream to
//! the layer above with the bytes the framer took and did not answer in front of it. Nothing here
//! starts a thread. A close ends whatever is parked on the connection — a read on a silent peer, a
//! write into a peer that stopped reading — at once.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::transport::{
    CLOSE_NORMAL, FAULT_NONE, ROLE_CARRIER, ROLE_FRAMER, SIDE_ACCEPT, SIDE_DIAL,
};
use busbar_contract::transport::wire::{
    ArrivalRecord, CloseReason, Conn, ConnHandle, Direction as FrameDirection, FrameMeta, RawIo,
    RawStream, TransportError,
};
use busbar_contract::transport::FrameStream;
use busbar_contract::{
    DestinationFacts, Frame, Fut, Refusal, ScratchBytes, SlabBytes, StreamId, TransportKeyHandle,
    VerifiedDestination,
};

use crate::carrier::{Carried, CarrierStream, Dest, DialFailure};
use crate::framer::{self, Established, FramerDoor, Framing, Got, Yielded};
use crate::hostio::HostIo;
use crate::socket;

/// How long a dial may wait for the far end's handshake.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How many bytes one socket read takes.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// One transport entry over host sockets.
pub struct HostWire {
    door: Arc<dyn FramerDoor>,
    /// The host I/O its carriers are served from.
    io: Arc<HostIo>,
    /// The carrier its framed connections ride; `None` = the address carrier [`HostWire::riding`].
    under: Option<Arc<dyn FramerDoor>>,
    /// Where its framed connections find the address carrier when no `under` was given.
    riding: Option<crate::carrier::AddressCarrier>,
    key: &'static str,
    conns: Arc<Mutex<HashMap<u64, Arc<HostConn>>>>,
    next: AtomicU64,
    dial_timeout: Duration,
}

impl std::fmt::Debug for HostWire {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostWire")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// One connection's host state.
struct HostConn {
    id: u64,
    peer: String,
    local_port: u16,
    /// The transports this connection stands on, bottom first, this entry last.
    chain: Vec<&'static str>,
    sock: Mutex<Option<Io>>,
    /// The entry is a carrier carried as itself: no framing, every read a frame.
    raw: bool,
    framing: Mutex<Option<Framing>>,
    /// Frames the framer answered and no reader has taken.
    ready: Mutex<VecDeque<Got>>,
    /// Bytes the framer owes the far end that a reader's ingest produced (a handshake answer, a
    /// pong, a close answer) and the socket has not yet taken: they go out before anything else.
    owed: Mutex<Vec<u8>>,
    closed: AtomicBool,
    /// The wakers parked on the connection, woken by a close.
    parked: Mutex<Vec<Waker>>,
}

impl HostConn {
    fn park(&self, cx: &Context<'_>) {
        let mut parked = self.parked.lock().expect("parked");
        if !parked.iter().any(|w| w.will_wake(cx.waker())) {
            parked.push(cx.waker().clone());
        }
    }

    /// Mark the connection closed and wake whatever is parked on it. The flag is stored first, so
    /// a poll that parks and then re-reads the flag cannot miss both.
    fn finalise(&self) {
        self.closed.store(true, Ordering::Release);
        let mut sock = self.sock.lock().expect("socket");
        match sock.as_ref() {
            Some(Io::Carried(c)) => c.close(),
            // A handed-up stream ends when its last holder lets it go.
            Some(Io::HandedUp(_)) => *sock = None,
            None => {}
        }
        drop(sock);
        for w in self.parked.lock().expect("parked").drain(..) {
            w.wake();
        }
    }

    fn socket(&self) -> Option<Io> {
        self.sock.lock().expect("socket").clone()
    }

    /// Write `bytes` whole, raced against the close.
    async fn send(&self, bytes: &[u8]) -> Result<(), TransportError> {
        let owed = std::mem::take(&mut *self.owed.lock().expect("owed"));
        let bytes: std::borrow::Cow<'_, [u8]> = if owed.is_empty() {
            bytes.into()
        } else {
            [owed.as_slice(), bytes].concat().into()
        };
        let bytes = &*bytes;
        let sock = self.socket().ok_or(TransportError::Closed)?;
        let mut at = 0;
        while at < bytes.len() {
            let n = futures::future::poll_fn(|cx| {
                if self.closed.load(Ordering::Acquire) {
                    return Poll::Ready(Err(TransportError::Closed));
                }
                self.park(cx);
                if self.closed.load(Ordering::Acquire) {
                    return Poll::Ready(Err(TransportError::Closed));
                }
                sock.poll_write(cx, &bytes[at..])
                    .map_err(|e| map_io_err(&e))
            })
            .await?;
            if n == 0 {
                return Err(TransportError::Closed);
            }
            at += n;
        }
        futures::future::poll_fn(|cx| sock.poll_flush(cx))
            .await
            .map_err(|e| map_io_err(&e))
    }
}

impl HostConn {
    /// Offer what the framer owes the far end to the socket, without waiting: what it takes is
    /// gone, the rest waits for the next offer or the next send.
    fn offer_owed(&self, cx: &mut Context<'_>) {
        let Some(sock) = self.socket() else { return };
        let mut owed = self.owed.lock().expect("owed");
        while !owed.is_empty() {
            match sock.poll_write(cx, &owed) {
                Poll::Ready(Ok(n)) if n > 0 => {
                    owed.drain(..n);
                }
                _ => break,
            }
        }
        if owed.is_empty() {
            let _ = sock.poll_flush(cx);
        }
    }

    /// DRIVE the connection until the framer's answer to what it read satisfies `done`: read,
    /// ingest, keep the frames for the reader, send what the framer owes. An upgrade's handshake
    /// is driven here (the adopted side's answer, a dialled side's held messages going out once
    /// the far end answered), where no reader drives it yet.
    async fn drive_until(
        &self,
        bound: Duration,
        done: fn(&Yielded) -> bool,
    ) -> Result<(), TransportError> {
        let driven = async {
            loop {
                let sock = self.socket().ok_or(TransportError::Closed)?;
                let mut buf = vec![0_u8; READ_CHUNK_BYTES];
                let n = futures::future::poll_fn(|cx| {
                    if self.closed.load(Ordering::Acquire) {
                        return Poll::Ready(Err(TransportError::Closed));
                    }
                    self.park(cx);
                    sock.poll_read(cx, &mut buf).map_err(|e| map_io_err(&e))
                })
                .await?;
                let y = {
                    let mut framing = self.framing.lock().expect("framing");
                    let f = framing.as_mut().ok_or(TransportError::Closed)?;
                    f.ingest(&buf[..n], n == 0)
                        .map_err(|_| TransportError::Framing)?
                };
                let finished = done(&y);
                self.ready
                    .lock()
                    .expect("ready")
                    .extend(y.pieces.iter().cloned());
                self.owed.lock().expect("owed").extend_from_slice(&y.wire);
                self.send(&[]).await?;
                if finished {
                    return Ok(());
                }
                if n == 0 || y.ended {
                    return Err(TransportError::Closed);
                }
            }
        };
        tokio::time::timeout(bound, driven)
            .await
            .map_err(|_| TransportError::Timeout)?
    }
}

/// Whether a framer's answer carries bytes for the far end (an upgrade's answer, held messages
/// going out).
fn answers(y: &Yielded) -> bool {
    !y.wire.is_empty()
}

/// Whether an adopted framing has answered what the lower layer handed up: bytes for the far end
/// (an upgrade's answer) or a frame for the reader (a framing with no handshake of its own).
fn opened(y: &Yielded) -> bool {
    !y.wire.is_empty() || !y.pieces.is_empty()
}

/// What one connection reads and writes: a carrier's connection, or the stream another entry
/// handed up ([`HostWire::adopt_from`]).
#[derive(Clone)]
enum Io {
    Carried(Arc<Carried>),
    HandedUp(Arc<Mutex<Box<dyn RawIo>>>),
}

impl Io {
    fn poll_read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self {
            Io::Carried(c) => c.poll_read(cx, buf).map_ok(|(n, _)| n),
            Io::HandedUp(s) => {
                let mut s = s.lock().expect("stream");
                futures::io::AsyncRead::poll_read(std::pin::Pin::new(&mut **s), cx, buf)
            }
        }
    }

    fn poll_write(&self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            Io::Carried(c) => c.poll_write(cx, bytes, false),
            Io::HandedUp(s) => {
                let mut s = s.lock().expect("stream");
                futures::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut **s), cx, bytes)
            }
        }
    }

    fn poll_flush(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Io::Carried(c) => c.poll_flush(cx),
            Io::HandedUp(s) => {
                let mut s = s.lock().expect("stream");
                futures::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut **s), cx)
            }
        }
    }
}

struct Handle {
    id: u64,
    peer: String,
}

impl ConnHandle for Handle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// A carrier's refusal of a connect, in the system's words, as the transport seam spells it.
fn map_text(text: &str) -> TransportError {
    if text.contains("refused") {
        TransportError::Refused
    } else if text.contains("timed out") {
        TransportError::Timeout
    } else if text.contains("reset") || text.contains("aborted") {
        TransportError::Reset
    } else {
        TransportError::Closed
    }
}

/// An I/O error as the transport seam spells it.
#[must_use]
pub fn map_io_err(e: &io::Error) -> TransportError {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => TransportError::Refused,
        io::ErrorKind::TimedOut => TransportError::Timeout,
        io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => TransportError::Reset,
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::InvalidInput => {
            TransportError::AddressRefused
        }
        // A carrier's error carries the system's words, not its kind.
        io::ErrorKind::Other => map_text(&e.to_string()),
        _ => TransportError::Closed,
    }
}

impl HostWire {
    /// The entry behind `door`, over host sockets. Its registry key is its first claim.
    ///
    /// # Errors
    ///
    /// The entry states no claim, or names another transport it composes over (no transport names
    /// another: the carrier is the connector's choice).
    pub fn new(door: Arc<dyn FramerDoor>) -> Result<Self, String> {
        let facts = door.facts();
        let Some(&key) = facts.claims.first() else {
            return Err(format!("transport `{}` states no claim", facts.name));
        };
        if !facts.composes_over.is_empty() {
            return Err(format!(
                "transport `{}` names a transport it composes over; no transport names another \
                 (the carrier is the connector's choice from the target's scheme)",
                facts.name
            ));
        }
        Ok(Self {
            door,
            io: crate::hostio::process(),
            under: None,
            riding: None,
            key,
            conns: Arc::new(Mutex::new(HashMap::new())),
            next: AtomicU64::new(1),
            dial_timeout: DIAL_TIMEOUT,
        })
    }

    /// The same wire with its framed connections riding the carrier `under`, served from `io`.
    #[must_use]
    pub fn over(mut self, under: Arc<dyn FramerDoor>, io: Arc<HostIo>) -> Self {
        self.under = Some(under);
        self.io = io;
        self
    }

    /// The same wire, its framed connections riding the address carrier `carrier` answers at each
    /// dial (the serving connector's; [`crate::carrier::AddressCarrier`]).
    #[must_use]
    pub fn riding(mut self, carrier: crate::carrier::AddressCarrier) -> Self {
        self.riding = Some(carrier);
        self
    }

    /// Whether this wire's entry is a carrier, carried as itself.
    fn is_carrier(&self) -> bool {
        self.door.facts().role == ROLE_CARRIER
    }

    /// The same wire with the dial's handshake bounded by `budget`.
    #[must_use]
    pub fn with_dial_timeout(mut self, budget: Duration) -> Self {
        self.dial_timeout = budget;
        self
    }

    fn get(&self, id: u64) -> Option<Arc<HostConn>> {
        self.conns.lock().expect("conns").get(&id).cloned()
    }

    /// Hold `carried`, its connect settled, as a connection of this wire: framed by the entry,
    /// begun on `side` for `target`, or carried as itself when the entry is a carrier.
    fn frame(
        &self,
        carried: Arc<Carried>,
        peer: String,
        local_port: u16,
        side: u32,
        target: &str,
    ) -> Result<(Conn, Vec<u8>), TransportError> {
        let chain = vec![self.key];
        if self.is_carrier() {
            return Ok(self.hold_io(
                Io::Carried(carried),
                peer,
                local_port,
                chain,
                None,
                Yielded::default(),
            ));
        }
        let (framing, y) =
            Framing::begin(Arc::clone(&self.door), side, target, &self.established())
                .map_err(|_| TransportError::Framing)?;
        Ok(self.hold_io(
            Io::Carried(carried),
            peer,
            local_port,
            chain,
            Some(framing),
            y,
        ))
    }

    /// What a framing on this entry is told the handshake established: its claim.
    fn established(&self) -> Established {
        Established {
            claim: Some(self.key.to_owned()),
            ..Established::default()
        }
    }

    /// Hold `io` as a connection framed by `framing`, the pieces its opening yielded waiting for the
    /// first reader; answers the connection and the bytes the opening owes the far end.
    fn hold_io(
        &self,
        io: Io,
        peer: String,
        local_port: u16,
        chain: Vec<&'static str>,
        framing: Option<Framing>,
        y: Yielded,
    ) -> (Conn, Vec<u8>) {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.conns.lock().expect("conns").insert(
            id,
            Arc::new(HostConn {
                id,
                peer: peer.clone(),
                local_port,
                chain,
                sock: Mutex::new(Some(io)),
                raw: framing.is_none(),
                framing: Mutex::new(framing),
                ready: Mutex::new(y.pieces.into()),
                owed: Mutex::new(Vec::new()),
                closed: AtomicBool::new(false),
                parked: Mutex::new(Vec::new()),
            }),
        );
        (Conn::new(Arc::new(Handle { id, peer })), y.wire)
    }

    /// Send what a connection's opening owes the far end, if anything; a send that fails ends it.
    async fn open_with(&self, conn: Conn, opening: Vec<u8>) -> Result<Conn, TransportError> {
        if opening.is_empty() {
            return Ok(conn);
        }
        let c = self.get(conn.id()).ok_or(TransportError::Closed)?;
        if let Err(e) = c.send(&opening).await {
            if let Some(gone) = self.conns.lock().expect("conns").remove(&c.id) {
                gone.finalise();
            }
            return Err(e);
        }
        Ok(conn)
    }

    /// ADOPT the stream another entry handed up (`raw`, that entry's own
    /// [`busbar_contract::Transport::detach`]): framed from here on by this entry (or by `door`, the
    /// same entry opened under a listener's own settings), begun on the accept side (an upgrade the
    /// far end asked the other entry for). WHICH entry adopts is the connector's choice (the upgrade's
    /// scheme), never a list this entry states. The stream carries in front of it whatever the other
    /// entry took and did not answer. `below` is the chain that entry reported for the connection
    /// (bottom first); the adopted connection reports it with this entry on top.
    ///
    /// # Errors
    ///
    /// [`TransportError::Framing`]: the entry refused to adopt it.
    pub async fn adopt_from(
        &self,
        raw: RawStream,
        below: Vec<&'static str>,
        door: Option<Arc<dyn FramerDoor>>,
    ) -> Result<Conn, TransportError> {
        let door = door.unwrap_or_else(|| Arc::clone(&self.door));
        let (framing, y) = Framing::adopt(door, SIDE_ACCEPT, &[], &self.established())
            .map_err(|_| TransportError::Framing)?;
        let mut chain = if below.is_empty() {
            vec![raw.from()]
        } else {
            below
        };
        chain.push(self.key);
        let peer = raw.peer().to_owned();
        let io = Io::HandedUp(Arc::new(Mutex::new(raw.into_io())));
        let (conn, opening) = self.hold_io(io, peer, 0, chain, Some(framing), y);
        let answered = !opening.is_empty();
        let conn = self.open_with(conn, opening).await?;
        // THE UPGRADE IS ANSWERED BEFORE THE CONNECTION IS HANDED OVER, as an adopting layer's
        // handshake always was: the framer reads the request the lower layer handed up and answers
        // it, so a write that follows meets an open connection.
        if !answered {
            let c = self.get(conn.id()).ok_or(TransportError::Closed)?;
            if let Err(e) = c.drive_until(self.dial_timeout, opened).await {
                if let Some(gone) = self.conns.lock().expect("conns").remove(&c.id) {
                    gone.finalise();
                }
                return Err(e);
            }
        }
        Ok(conn)
    }

    /// Dial `authority` directly: the endpoint check, then a non-blocking connect on the calling
    /// worker's reactor, bounded by the dial timeout.
    ///
    /// # Errors
    ///
    /// The authority is refused, the far end refused, or the handshake outlived its bound.
    pub async fn dial_authority(&self, authority: &str) -> Result<Conn, TransportError> {
        self.dial_at(authority, authority).await
    }

    /// DIAL A DECLARED TARGET (SEAM-4n, ARCHITECT ruling): the framer is handed the FULL target
    /// its need declared (`scheme://host:port/path`) and derives what it needs from it; the carrier
    /// dials the authority the entry's `locate` reads off it. A target that asks for connection
    /// security is refused before any socket exists: this wire secures nothing, so a secure target
    /// over it would go out in the clear.
    ///
    /// # Errors
    ///
    /// The entry refuses the target, the target asks for connection security, the authority is
    /// refused, the far end refused, or the handshake outlived its bound.
    pub async fn dial_target(&self, target: &str) -> Result<Conn, TransportError> {
        let located = framer::locate(self.door.as_ref(), target)
            .map_err(|_| TransportError::AddressRefused)?;
        if located.secure {
            return Err(TransportError::AddressRefused);
        }
        self.dial_at(&located.authority, target).await
    }

    /// Dial `authority` and begin the dialled framing for `target`: through the entry itself when
    /// it is a carrier, else through the carrier its framed connections ride.
    async fn dial_at(&self, authority: &str, target: &str) -> Result<Conn, TransportError> {
        crate::endpoint::check(authority).map_err(|_| TransportError::AddressRefused)?;
        let addr = socket::address_of(authority).ok_or(TransportError::AddressRefused)?;
        let carrier = if self.is_carrier() {
            Arc::clone(&self.door)
        } else {
            self.under
                .clone()
                .or_else(|| self.riding.as_ref().and_then(|carrier| carrier()))
                .ok_or(TransportError::AddressRefused)?
        };
        let carried = Carried::dial(
            carrier,
            Arc::clone(&self.io),
            &Dest::Authority(addr.to_string()),
        )
        .map_err(|f| match f {
            DialFailure::Refused(_) => TransportError::Refused,
            DialFailure::Failed(_) => TransportError::Closed,
        })?;
        let carried = Arc::new(carried);
        let connected = futures::future::poll_fn(|cx| carried.poll_connected(cx));
        match tokio::time::timeout(self.dial_timeout, connected).await {
            Err(_) => return Err(TransportError::Timeout),
            Ok(Err(e)) => return Err(map_text(&e)),
            Ok(Ok(())) => {}
        }
        let local_port = carried.arrival().map_or(0, |(_, port)| port);
        let (conn, opening) =
            self.frame(carried, addr.to_string(), local_port, SIDE_DIAL, target)?;
        self.open_with(conn, opening).await
    }

    /// The connections this wire holds.
    #[must_use]
    pub fn live(&self) -> usize {
        self.conns.lock().expect("conns").len()
    }
}

/// THE HOST-SIDE SURFACE. What the host drives on a wire: listen, accept, dial, read, write, hand
/// up, close. The connector is core and presents no plugin face; the composition root adapts this
/// surface to the kernel's legacy transport seam where it still needs one.
impl HostWire {
    /// The entry's registry key: its first claim.
    #[must_use]
    pub fn key(&self) -> &'static str {
        self.key
    }

    /// What the host records about `conn` on arrival: its peer, the local port, this entry as the chain.
    pub fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        let held = self.get(conn.id());
        ArrivalRecord {
            source: conn.peer(),
            port: held.as_ref().map_or(0, |c| c.local_port),
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: held.map_or_else(|| vec![self.key], |c| c.chain.clone()),
        }
    }

    /// Hold an accepted socket as a framed connection, begun on the accept side: the tests' far
    /// end. Nothing listens through this seam in the product: an inbound socket is the
    /// connector's listener's ([`crate::listen::Listening`], the one listener source).
    #[cfg(test)]
    pub(crate) fn accepted(&self, carried: Carried, peer: String) -> Result<Conn, TransportError> {
        let carried = Arc::new(carried);
        let local_port = carried.arrival().map_or(0, |(_, port)| port);
        self.frame(carried, peer, local_port, SIDE_ACCEPT, "")
            .map(|(conn, _)| conn)
    }

    /// Dial a verified upstream destination at its declared target: a URL is handed to the framer
    /// whole ([`Self::dial_target`]); a bare `host:port` is its own target ([`Self::dial_authority`]).
    pub fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let target = match dest.facts() {
                DestinationFacts::Upstream { address, .. } => {
                    address.authority().ok_or(TransportError::AddressRefused)?
                }
                _ => return Err(TransportError::AddressRefused),
            };
            if target.contains("://") {
                self.dial_target(target).await
            } else {
                self.dial_authority(target).await
            }
        })
    }

    /// The inbound frames on `conn`, as the framer yields them from the socket.
    pub fn frames(&self, conn: Conn) -> FrameStream {
        let held = self.get(conn.id());
        let conns = Arc::clone(&self.conns);
        let mut ended = false;
        Box::pin(futures::stream::poll_fn(move |cx| {
            let Some(c) = held.as_ref() else {
                return Poll::Ready(None);
            };
            loop {
                c.offer_owed(cx);
                if let Some(got) = c.ready.lock().expect("ready").pop_front() {
                    // A stream the framer FAILED (`PIECE_STREAM_FAILED`: a message past the
                    // ceiling, a protocol breach) is an error to its reader, not a clean end.
                    if got.failed {
                        ended = true;
                        return Poll::Ready(Some(Err(TransportError::Framing)));
                    }
                    let n = got.bytes.len() as u64;
                    let frame = Frame {
                        direction: FrameDirection::Inbound,
                        stream: StreamId(got.stream),
                        bytes: SlabBytes::new(Arc::from(got.bytes)),
                        meta: FrameMeta {
                            bytes: n,
                            transport_units: None,
                            status: None,
                            status_code: None,
                            retry_after_secs: None,
                            text: got.text,
                        },
                    };
                    return Poll::Ready(Some(Ok((StreamId(got.stream), frame))));
                }
                if ended || c.closed.load(Ordering::Acquire) {
                    return Poll::Ready(None);
                }
                c.park(cx);
                if c.closed.load(Ordering::Acquire) {
                    return Poll::Ready(None);
                }
                let Some(sock) = c.socket() else {
                    return Poll::Ready(None);
                };
                let mut buf = [0_u8; READ_CHUNK_BYTES];
                let read = match sock.poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(r) => r,
                };
                let (bytes, end) = match read {
                    Ok(0) => (&buf[..0], true),
                    // A carrier carried as itself: every read is a frame.
                    Ok(n) if c.raw => {
                        c.ready.lock().expect("ready").push_back(Got {
                            stream: 0,
                            bytes: buf[..n].to_vec(),
                            end_of_frame: true,
                            status_code: None,
                            status_class: 0,
                            fault: FAULT_NONE,
                            retry_after_secs: None,
                            fields: false,
                            text: false,
                            reason: None,
                            failed: false,
                        });
                        continue;
                    }
                    Ok(n) => (&buf[..n], false),
                    Err(e) => {
                        // A read error is the connection's end: it is deregistered and finalised
                        // as a close would, never left registered with its socket pinned.
                        if let Some(gone) = conns.lock().expect("conns").remove(&c.id) {
                            gone.finalise();
                        }
                        ended = true;
                        return Poll::Ready(Some(Err(map_io_err(&e))));
                    }
                };
                if c.raw && end {
                    ended = true;
                    continue;
                }
                let mut framing = c.framing.lock().expect("framing");
                let Some(f) = framing.as_mut() else {
                    return Poll::Ready(None);
                };
                match f.ingest(bytes, end) {
                    Ok(y) => {
                        c.ready.lock().expect("ready").extend(y.pieces);
                        // What the framer answers to what it read (a pong, a close answer, an
                        // upgrade's answer) is owed to the far end, ahead of anything else.
                        c.owed.lock().expect("owed").extend_from_slice(&y.wire);
                        ended |= y.ended || end;
                    }
                    Err(_) => {
                        ended = true;
                        return Poll::Ready(Some(Err(TransportError::Framing)));
                    }
                }
            }
        }))
    }

    /// Write `bytes` on `stream` of `conn` through the framer, as one text message where `text`
    /// (`FrameMeta::text` on the frame being written).
    pub fn write<'a>(
        &'a self,
        conn: &'a Conn,
        stream: StreamId,
        bytes: ScratchBytes<'a>,
        text: bool,
    ) -> Fut<'a, usize> {
        Box::pin(async move {
            let c = self.get(conn.id()).ok_or(TransportError::Closed)?;
            // A carrier carried as itself writes the bytes as they are.
            if c.raw {
                c.send(bytes.as_slice()).await?;
                return Ok(bytes.len());
            }
            let wire = {
                let mut framing = c.framing.lock().expect("framing");
                let f = framing.as_mut().ok_or(TransportError::Closed)?;
                f.emit(stream.0, bytes.as_slice(), true, text)
                    .map_err(|_| TransportError::Framing)?
                    .wire
            };
            let held = wire.is_empty() && !bytes.as_slice().is_empty();
            c.send(&wire).await?;
            // A message a FRAMER HELD (its upgrade not yet answered by the far end) goes out once
            // the far end's answer is read: the connection is driven until it does. A carrier
            // frames nothing and holds nothing.
            if held && self.door.facts().role == ROLE_FRAMER {
                c.drive_until(self.dial_timeout, answers).await?;
            }
            Ok(bytes.len())
        })
    }

    /// Encode an envelope in the entry's framing, into `arena`.
    ///
    /// # Errors
    ///
    /// The framer cannot represent it, or the arena is exhausted.
    pub fn encode_envelope<'a>(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::PlaneAlloc,
    ) -> Result<ScratchBytes<'a>, busbar_contract::transport::wire::Encode> {
        let bytes = framer::encode(self.door.as_ref(), fields, body)
            .map_err(|_| busbar_contract::transport::wire::Encode::Unrepresentable)?;
        arena
            .alloc_bytes(&bytes)
            .map_err(|_| busbar_contract::transport::wire::Encode::ScratchExhausted)
    }

    /// Adopt a connection from another layer: this entry frames the host's own socket, so it refuses.
    pub fn adopt<'a>(&'a self, _conn: Conn, _keys: &'a TransportKeyHandle) -> Fut<'a, Conn> {
        // This entry frames the host's own socket: nothing is adopted onto it, it only hands a
        // connection up.
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }

    /// Hand `conn` up: its socket, with the bytes the framer took and did not answer in front of it.
    pub fn detach(&self, conn: &Conn) -> Option<RawStream> {
        let c = self.get(conn.id())?;
        let taken = {
            let mut sock = c.sock.lock().expect("socket");
            // A stream handed up to this entry is handed up no further: no layer composes over
            // a composed one here.
            let Some(Io::Carried(arc)) = sock.take() else {
                return None;
            };
            // A reader still holds the stream: the upgrade never races a read.
            if Arc::strong_count(&arc) > 1 {
                *sock = Some(Io::Carried(arc));
                return None;
            }
            arc
        };
        self.conns.lock().expect("conns").remove(&c.id);
        let mut left: Vec<u8> = c
            .ready
            .lock()
            .expect("ready")
            .drain(..)
            .flat_map(|g| g.bytes)
            .collect();
        if let Some(f) = c.framing.lock().expect("framing").take() {
            left.extend(f.detach().unwrap_or_default());
        }
        Some(RawStream::new(
            self.key,
            c.peer.clone(),
            Box::new(CarrierStream::new(taken, left)),
        ))
    }

    /// Close `conn`: the framer finishes, and whatever is parked on it ends.
    pub fn close(&self, conn: Conn, _reason: CloseReason) {
        let removed = self.conns.lock().expect("conns").remove(&conn.id());
        if let Some(c) = removed {
            if let Some(f) = c.framing.lock().expect("framing").take() {
                let _ = f.finish(CLOSE_NORMAL);
            }
            c.finalise();
        }
    }

    /// Deliver a Unit 0 refusal on `conn` through the framer, then finalise the connection.
    pub fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let c = self.get(conn.id()).ok_or(TransportError::Closed)?;
            let wire = {
                let mut framing = c.framing.lock().expect("framing");
                framing
                    .as_mut()
                    .ok_or(TransportError::Closed)
                    .and_then(|f| {
                        // A Unit 0 refusal's bytes are the transport's whole envelope, rendered
                        // before any plane: they state no neutral status apart from themselves.
                        f.refuse(stream.map(|s| s.0), bytes.as_slice(), 0)
                            .map_err(|_| TransportError::Framing)
                    })
                    .map(|y| y.wire)
            };
            let delivered = match wire {
                Ok(wire) => c.send(&wire).await,
                Err(e) => Err(e),
            };
            // A refusal finalises the connection on every path out, delivered or not.
            if let Some(gone) = self.conns.lock().expect("conns").remove(&c.id) {
                gone.finalise();
            }
            delivered
        })
    }
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod tests;
