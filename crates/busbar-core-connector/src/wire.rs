// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A FRAMER ENTRY OVER HOST SOCKETS: [`HostWire`] serves one transport entry that frames directly
//! over the host's socket (an empty `composes_over`) through the connector's own host-side surface.
//! The connector is core and presents no plugin face; the composition root adapts this surface to
//! the kernel's legacy transport seam, so the kernel's listeners, accept loop and upgrades drive it
//! the way they drive any transport.
//!
//! The sockets are the host's: listened, accepted, dialled, read and written here, non-blocking,
//! their readiness on the calling worker's reactor ([`crate::io`]). Every byte in or out goes
//! through the entry's framer ([`crate::framer`]); a connection handed up (`detach`) gives the socket
//! to the layer above with the bytes the framer took and did not answer in front of it. Nothing
//! here starts a thread. A close ends whatever is parked on the connection — a read on a silent
//! peer, a write into a peer that stopped reading — at once.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use busbar_contract::abi::transport::{CLOSE_NORMAL, SIDE_DIAL};
use busbar_contract::transport::wire::{
    ArrivalRecord, CloseReason, Conn, ConnHandle, Direction as FrameDirection, FrameMeta,
    RawStream, TransportError,
};
use busbar_contract::transport::FrameStream;
use busbar_contract::{
    DestinationFacts, Frame, Fut, Refusal, ScratchBytes, SlabBytes, StreamId, TransportKeyHandle,
    VerifiedDestination,
};

use crate::framer::{self, Established, FramerDoor, Framing, Got};
use crate::io::{self as reactor, Direction, Registered};
use crate::socket;
use crate::stream::HostStream;

/// How long a dial may wait for the far end's handshake.
pub const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How many bytes one socket read takes.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// One transport entry over host sockets.
pub struct HostWire {
    door: Arc<dyn FramerDoor>,
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
    sock: Mutex<Option<Arc<Registered<TcpStream>>>>,
    framing: Mutex<Option<Framing>>,
    /// Frames the framer answered and no reader has taken.
    ready: Mutex<VecDeque<Got>>,
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
        if let Some(sock) = self.sock.lock().expect("socket").as_ref() {
            let _ = sock.get_ref().shutdown(Shutdown::Both);
        }
        for w in self.parked.lock().expect("parked").drain(..) {
            w.wake();
        }
    }

    fn socket(&self) -> Option<Arc<Registered<TcpStream>>> {
        self.sock.lock().expect("socket").clone()
    }

    /// Write `bytes` whole, raced against the close.
    async fn send(&self, bytes: &[u8]) -> Result<(), TransportError> {
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
                sock.poll_io(Direction::Write, cx, |mut s| s.write(&bytes[at..]))
                    .map_err(|e| map_io_err(&e))
            })
            .await?;
            if n == 0 {
                return Err(TransportError::Closed);
            }
            at += n;
        }
        Ok(())
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
        _ => TransportError::Closed,
    }
}

impl HostWire {
    /// The entry behind `door`, over host sockets. Its registry key is its first claim.
    ///
    /// # Errors
    ///
    /// The entry states no claim, or composes over a layer (it does not frame the host's socket).
    pub fn new(door: Arc<dyn FramerDoor>) -> Result<Self, String> {
        let facts = door.facts();
        let Some(&key) = facts.claims.first() else {
            return Err(format!("transport `{}` states no claim", facts.name));
        };
        if !facts.composes_over.is_empty() {
            return Err(format!(
                "transport `{}` composes over a layer; only a framer over the host's socket is \
                 served here",
                facts.name
            ));
        }
        Ok(Self {
            door,
            key,
            conns: Arc::new(Mutex::new(HashMap::new())),
            next: AtomicU64::new(1),
            dial_timeout: DIAL_TIMEOUT,
        })
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

    #[cfg(test)]
    fn hold(
        &self,
        stream: TcpStream,
        peer: String,
        side: u32,
        target: &str,
    ) -> Result<Conn, TransportError> {
        stream.set_nonblocking(true).map_err(|e| map_io_err(&e))?;
        let local_port = stream.local_addr().map_or(0, |a| a.port());
        let sock = reactor::register(stream).map_err(|e| map_io_err(&e))?;
        self.frame(Arc::new(sock), peer, local_port, side, target)
    }

    fn frame(
        &self,
        sock: Arc<Registered<TcpStream>>,
        peer: String,
        local_port: u16,
        side: u32,
        target: &str,
    ) -> Result<Conn, TransportError> {
        let established = Established {
            claim: Some(self.key.to_owned()),
            ..Established::default()
        };
        let (framing, _) = Framing::begin(Arc::clone(&self.door), side, target, &established)
            .map_err(|_| TransportError::Framing)?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.conns.lock().expect("conns").insert(
            id,
            Arc::new(HostConn {
                id,
                peer: peer.clone(),
                local_port,
                sock: Mutex::new(Some(sock)),
                framing: Mutex::new(Some(framing)),
                ready: Mutex::new(VecDeque::new()),
                closed: AtomicBool::new(false),
                parked: Mutex::new(Vec::new()),
            }),
        );
        Ok(Conn::new(Arc::new(Handle { id, peer })))
    }

    /// Dial `authority` directly: the endpoint check, then a non-blocking connect on the calling
    /// worker's reactor, bounded by the dial timeout.
    ///
    /// # Errors
    ///
    /// The authority is refused, the far end refused, or the handshake outlived its bound.
    pub async fn dial_authority(&self, authority: &str) -> Result<Conn, TransportError> {
        crate::endpoint::check(authority).map_err(|_| TransportError::AddressRefused)?;
        let addr = socket::address_of(authority).ok_or(TransportError::AddressRefused)?;
        let sock = reactor::register(socket::connect(addr).map_err(|e| map_io_err(&e))?)
            .map_err(|e| map_io_err(&e))?;
        let connected = futures::future::poll_fn(|cx| socket::poll_connected(&sock, cx));
        match tokio::time::timeout(self.dial_timeout, connected).await {
            Err(_) => return Err(TransportError::Timeout),
            Ok(Err(e)) => return Err(map_io_err(&e)),
            Ok(Ok(())) => {}
        }
        let local_port = sock.get_ref().local_addr().map_or(0, |a| a.port());
        self.frame(
            Arc::new(sock),
            addr.to_string(),
            local_port,
            SIDE_DIAL,
            authority,
        )
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
        let port = self.get(conn.id()).map_or(0, |c| c.local_port);
        ArrivalRecord {
            source: conn.peer(),
            port,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec![self.key],
        }
    }

    /// Hold an accepted socket as a framed connection, begun on the accept side: the tests' far
    /// end. Nothing listens through this seam in the product: an inbound socket is the
    /// connector's listener's ([`crate::listen::Listening`], the one listener source).
    #[cfg(test)]
    pub(crate) fn accepted(&self, stream: TcpStream, peer: String) -> Result<Conn, TransportError> {
        self.hold(
            stream,
            peer,
            busbar_contract::abi::transport::SIDE_ACCEPT,
            "",
        )
    }

    /// Dial a verified upstream destination: its authority, as [`Self::dial_authority`] does.
    pub fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let authority = match dest.facts() {
                DestinationFacts::Upstream { address, .. } => {
                    address.authority().ok_or(TransportError::AddressRefused)?
                }
                _ => return Err(TransportError::AddressRefused),
            };
            self.dial_authority(authority).await
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
                if let Some(got) = c.ready.lock().expect("ready").pop_front() {
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
                let read = match sock.poll_io(Direction::Read, cx, |mut s| s.read(&mut buf)) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(r) => r,
                };
                let (bytes, end) = match read {
                    Ok(0) => (&buf[..0], true),
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
                let mut framing = c.framing.lock().expect("framing");
                let Some(f) = framing.as_mut() else {
                    return Poll::Ready(None);
                };
                match f.ingest(bytes, end) {
                    Ok(y) => {
                        c.ready.lock().expect("ready").extend(y.pieces);
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

    /// Write `bytes` on `stream` of `conn` through the framer.
    pub fn write<'a>(
        &'a self,
        conn: &'a Conn,
        stream: StreamId,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, usize> {
        Box::pin(async move {
            let c = self.get(conn.id()).ok_or(TransportError::Closed)?;
            let wire = {
                let mut framing = c.framing.lock().expect("framing");
                let f = framing.as_mut().ok_or(TransportError::Closed)?;
                f.emit(stream.0, bytes.as_slice(), true)
                    .map_err(|_| TransportError::Framing)?
                    .wire
            };
            c.send(&wire).await?;
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
            let arc = sock.take()?;
            match Arc::try_unwrap(arc) {
                Ok(reg) => reg,
                // A reader still holds the socket: the upgrade never races a read.
                Err(arc) => {
                    *sock = Some(arc);
                    return None;
                }
            }
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
            Box::new(HostStream::new(taken, left)),
        ))
    }

    /// The layer this entry composes over: none, it frames the host's own socket.
    pub fn composed_over(&self) -> Option<&'static str> {
        // The entry frames the host's own socket: nothing built it over a lower layer.
        None
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
                        f.refuse(stream.map(|s| s.0), bytes.as_slice())
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
