// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT ADAPTER: a transport admitted over the HOT-tier ABI ([`DynTransport`], either door)
//! as the host's own [`busbar_contract::Transport`] — so the composition root folds a dropped-in wire
//! into the SAME transport axis, through the SAME registration, as a linked one (#2 rule (1): one
//! contract, one loading path; #3 OWNER-LOCKED: transport is swappable, compiled in OR dropped in).
//!
//! # Why it lives here (#83)
//!
//! This crate is "the host-facing machinery for FETCHING, VERIFYING, LOADING and SUPERVISING a
//! plugin" (roster def 15). Presenting a loaded plugin to the host as the trait the host already
//! drives is that machinery, and its precedents are here: [`crate::store_adapter`] presents a loaded
//! store as the three unit-side store seams, and the hook seam presents a loaded hook as the async
//! routing policy. It is not the composition root's (def 1: "decides nothing a library could
//! decide"), and not the contract's (def 13: shapes only — this is runtime machinery).
//!
//! # The bridge, and what it costs (#30)
//!
//! None. The HOT decl's slots are POLL-shaped (airlock minor 28): each answers Ready | Pending |
//! Error at once, so every trait method drives them INLINE from the host's reactor, on the task that
//! awaits it — no thread handoff, no blocking pool. A slot that answers Pending keeps the task's
//! [`WakeToken`] and wakes it through the host's waker handle when the operation may progress; the
//! task polls the slot again. Each connection holds two tokens (its reading and its writing, which
//! run on different tasks at once) and each listener one. The added latency per crossing — the
//! waker registration, the guarded indirect call and the answer's decode — is measured by
//! `tests::the_adapters_added_latency_per_crossing_is_measured` against the HOT-lane budget.
//!
//! Nothing is left behind when a caller stops waiting: a dropped `accept` or `read` simply is not
//! polled again, and a dial dropped before its connection opened closes it.
//!
//! # What the ABI does not carry
//!
//! The decl carries `listen` / `connect` and the poll slots over opaque handles and nothing else, so
//! this adapter answers the trait's remaining methods as a byte stream answers them: the envelope of
//! an outbound message is its body, an adoption from another layer is a
//! [`TransportError::HandoffMismatch`], and a key handle is not presented (a transport that needs
//! configuration is handed the kernel-built [`busbar_plugin::hot::transport::WireConfig`], which no
//! caller of this adapter mints yet).

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use busbar_contract::transport::wire::{
    ArrivalRecord, CloseReason, Conn, ConnHandle, Direction, Encode, FrameMeta, Listener,
    ListenerHandle, RawStream, TransportError,
};
use busbar_contract::transport::{Transport, TransportSettings, TRANSPORT_ABI};
use busbar_contract::{
    DestinationFacts, Frame, Fut, Kind, PlaneAlloc, Plugin, Refusal, ScratchBytes, SlabBytes,
    StreamId, TransportConfigView, TransportKeyHandle, VerifiedDestination,
};
use busbar_plugin::hot::transport::WireOutcome;

use crate::transport::{wire_settings, BuiltTransport, DynTransport, WakeToken, WirePoll};

/// How many bytes one `poll_read` may fill for the frame pump: the buffer every read on a
/// connection's pump reuses.
pub const READ_CHUNK_BYTES: usize = 16 * 1024;

/// A HOT-lane transport, built, presented as the host's [`Transport`].
pub struct WireTransport {
    hosted: Arc<Hosted>,
}

/// The built wire and what the adapter keeps beside it. Shared with the futures and streams in flight.
struct Hosted {
    built: BuiltTransport<'static>,
    key: &'static str,
    /// The layer this wire was built over, where it was built over one: its key, and the layer
    /// itself, kept alive for as long as the built state that points into it.
    lower: Option<(&'static str, Arc<Hosted>)>,
    /// The stack as an arrival reports it, bottom layer first.
    chain: Vec<&'static str>,
    /// Each listener this adapter handed out (by its node-local identity): the wire's listener
    /// handle, and the token its accepts wait on.
    listeners: Mutex<HashMap<u64, (u64, Arc<WakeToken>)>>,
    /// Every live connection this adapter handed out and has not closed or detached.
    conns: Mutex<HashMap<u64, Arc<Tokens>>>,
}

/// One connection's two waits: its reading and its writing run on different tasks at once.
#[derive(Default)]
struct Tokens {
    read: WakeToken,
    write: WakeToken,
}

impl std::fmt::Debug for WireTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireTransport")
            .field("key", &self.hosted.key)
            .field(
                "composed_over",
                &self.hosted.lower.as_ref().map(|(k, _)| *k),
            )
            .finish_non_exhaustive()
    }
}

/// A slot's refusal in the transport kind's own vocabulary: `1..=10` are that vocabulary in order;
/// an operation the wire does not implement, or a fault it answered, closes the operation.
fn refusal(outcome: WireOutcome) -> TransportError {
    match outcome {
        WireOutcome::Refused => TransportError::Refused,
        WireOutcome::Timeout => TransportError::Timeout,
        WireOutcome::Reset => TransportError::Reset,
        WireOutcome::HandshakeFailed => TransportError::HandshakeFailed,
        WireOutcome::KeyUnavailable => TransportError::KeyUnavailable,
        WireOutcome::AddressRefused => TransportError::AddressRefused,
        WireOutcome::Backpressure => TransportError::Backpressure,
        WireOutcome::Framing => TransportError::Framing,
        WireOutcome::HandoffMismatch => TransportError::HandoffMismatch,
        WireOutcome::Ok
        | WireOutcome::Closed
        | WireOutcome::Unsupported
        | WireOutcome::Fault
        | WireOutcome::Pending => TransportError::Closed,
    }
}

/// ONE CROSSING, awaited: register the task with `token`, poll the slot with it, and park until the
/// wire wakes the token (module docs, "The bridge").
async fn polled<T>(
    token: &WakeToken,
    mut slot: impl FnMut(u64) -> WirePoll<T>,
) -> Result<T, TransportError> {
    std::future::poll_fn(|cx| {
        token.register(cx.waker());
        slot(token.id()).map_err(refusal)
    })
    .await
}

/// Offer every one of `bytes` to `conn`, then flush them onto the wire.
async fn write_all(
    built: &BuiltTransport<'static>,
    conn: u64,
    token: &WakeToken,
    bytes: &[u8],
) -> Result<(), TransportError> {
    let mut at = 0;
    while at < bytes.len() {
        at += polled(token, |t| built.poll_write(conn, t, &bytes[at..])).await?;
    }
    polled(token, |t| built.poll_flush(conn, t)).await
}

impl WireTransport {
    /// BUILD `wire` over `lower` (the adapter built beneath it, where the root composed it over a
    /// HOT-lane layer) from the deployment's `settings` — the linked row's `build(lower, settings)`,
    /// over the ABI.
    ///
    /// # Errors
    ///
    /// The wire's `init` slot refused, or is absent.
    pub fn build(
        wire: &'static DynTransport,
        lower: Option<&WireTransport>,
        settings: &TransportSettings,
    ) -> Result<Self, WireOutcome> {
        let built = wire.build(lower.map(|l| &l.hosted.built), &wire_settings(settings))?;
        let lower = lower.map(|l| (l.hosted.key, Arc::clone(&l.hosted)));
        let mut chain = lower
            .as_ref()
            .map_or_else(Vec::new, |(_, l)| l.chain.clone());
        chain.push(wire.key());
        Ok(Self {
            hosted: Arc::new(Hosted {
                built,
                key: wire.key(),
                lower,
                chain,
                listeners: Mutex::new(HashMap::new()),
                conns: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// The admitted transport this adapter drives.
    #[must_use]
    pub fn wire(&self) -> &'static DynTransport {
        self.hosted.built.transport()
    }
}

impl Hosted {
    /// Hand out a connection the wire minted, with its two tokens.
    fn conn(&self, id: u64, peer: String) -> Conn {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, Arc::new(Tokens::default()));
        Conn::new(Arc::new(WireConn { id, peer }))
    }

    /// Forget a connection, answering its tokens if it was live here.
    fn forget(&self, id: u64) -> Option<Arc<Tokens>> {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id)
    }

    /// A live connection's tokens.
    fn tokens(&self, id: u64) -> Option<Arc<Tokens>> {
        self.conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .cloned()
    }
}

/// The opaque connection the host is handed: the wire's own handle and the peer it reported.
struct WireConn {
    id: u64,
    peer: String,
}

impl ConnHandle for WireConn {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

/// The opaque listener the host is handed: the address the wire bound.
struct WireListener {
    addr: String,
}

impl ListenerHandle for WireListener {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}

/// Closes a connection a dial began unless the dial handed it out: a dial dropped before its
/// connection opened leaves nothing open in the wire.
struct Opening<'a> {
    built: &'a BuiltTransport<'static>,
    conn: Option<u64>,
}

impl Drop for Opening<'_> {
    fn drop(&mut self) {
        if let Some(conn) = self.conn {
            self.built.close_now(conn);
        }
    }
}

impl Plugin for WireTransport {
    fn key(&self) -> &'static str {
        self.hosted.key
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> busbar_contract::transport::AbiVersion {
        TRANSPORT_ABI
    }
}

impl Transport for WireTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: conn.peer(),
            // The decl reports no local port for a connection.
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: self.hosted.chain.clone(),
        }
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        // The wire answers an absent bind itself: the adapter decides no address.
        let bind = cfg.bind().unwrap_or_default().to_string();
        Box::pin(async move {
            // `listen` answers at once: a bind waits on no peer.
            let (id, addr) = self.hosted.built.listen(&bind, None).map_err(refusal)?;
            let listener = Listener::new(Arc::new(WireListener { addr }));
            self.hosted
                .listeners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(listener.id(), (id, Arc::new(WakeToken::new())));
            Ok(listener)
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let (listener, token) = self
                .hosted
                .listeners
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(&l.id())
                .cloned()
                .ok_or(TransportError::Closed)?;
            let built = &self.hosted.built;
            // The connection is handed out in the same poll that took it: an accept dropped while
            // pending took nothing.
            let (id, peer) = polled(&token, |t| built.poll_accept(listener, t)).await?;
            Ok(self.hosted.conn(id, peer))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let authority = match dest.facts() {
                DestinationFacts::Upstream { address, .. } => address
                    .authority()
                    .ok_or(TransportError::AddressRefused)?
                    .to_string(),
                _ => return Err(TransportError::AddressRefused),
            };
            let built = &self.hosted.built;
            let id = built.connect(&authority, None).map_err(refusal)?;
            let mut opening = Opening {
                built,
                conn: Some(id),
            };
            // The dial's refusal (or its opening) is what the connection's first flush answers.
            polled(&WakeToken::new(), |t| built.poll_flush(id, t)).await?;
            opening.conn = None;
            Ok(self.hosted.conn(id, authority))
        })
    }

    fn frames(&self, conn: Conn) -> busbar_contract::transport::FrameStream {
        let state = (
            Arc::clone(&self.hosted),
            conn.id(),
            vec![0_u8; READ_CHUNK_BYTES],
            false,
        );
        Box::pin(futures::stream::unfold(
            state,
            |(hosted, id, mut buf, ended)| async move {
                let tokens = if ended { None } else { hosted.tokens(id) }?;
                let read = polled(&tokens.read, |t| hosted.built.poll_read(id, t, &mut buf)).await;
                match read {
                    Ok(0) => None,
                    Ok(n) => {
                        let frame = Frame {
                            direction: Direction::Inbound,
                            stream: StreamId(0),
                            bytes: SlabBytes::new(Arc::<[u8]>::from(&buf[..n])),
                            meta: FrameMeta {
                                bytes: n as u64,
                                transport_units: None,
                                status: None,
                                status_code: None,
                                retry_after_secs: None,
                            },
                        };
                        Some((Ok((StreamId(0), frame)), (hosted, id, buf, false)))
                    }
                    Err(e) => Some((Err(e), (hosted, id, buf, true))),
                }
            },
        ))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        _stream: StreamId,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, usize> {
        let id = conn.id();
        Box::pin(async move {
            let tokens = self.hosted.tokens(id).ok_or(TransportError::Closed)?;
            // Straight from the arena: the write is driven inline, so the bytes are on the wire (or
            // refused) before the arena can be reset.
            write_all(&self.hosted.built, id, &tokens.write, bytes.as_slice()).await?;
            Ok(bytes.len())
        })
    }

    /// The decl moves bytes and nothing else, so an outbound message's bytes are its body.
    fn encode_envelope<'a>(
        &self,
        _fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn PlaneAlloc,
    ) -> Result<ScratchBytes<'a>, Encode> {
        arena
            .alloc_bytes(body)
            .map_err(|_| Encode::ScratchExhausted)
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn Transport,
        _conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        // The decl has no adoption slot: a stream from another layer cannot cross it.
        Box::pin(async { Err(TransportError::HandoffMismatch) })
    }

    /// The connection's bytes as a stream of their own, driven through the same poll slots: this
    /// adapter forgets the connection, and the stream closes it when it is closed or dropped.
    fn detach(&self, conn: &Conn) -> Option<RawStream> {
        let tokens = self.hosted.forget(conn.id())?;
        Some(RawStream::new(
            self.hosted.key,
            conn.peer(),
            Box::new(WireIo {
                hosted: Arc::clone(&self.hosted),
                id: conn.id(),
                tokens,
                closed: false,
            }),
        ))
    }

    fn composed_over(&self) -> Option<&'static str> {
        self.hosted.lower.as_ref().map(|(key, _)| *key)
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        if self.hosted.forget(conn.id()).is_some() {
            self.hosted.built.close_now(conn.id());
        }
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let id = conn.id();
            let tokens = self.hosted.forget(id).ok_or(TransportError::Closed)?;
            let built = &self.hosted.built;
            // A refusal finalises the connection on every path out, delivered or not.
            let delivered = write_all(built, id, &tokens.write, bytes.as_slice()).await;
            built.close_now(id);
            delivered
        })
    }
}

/// A detached connection's bytes: every poll is the wire's own poll slot, inline; `close` when
/// closed or dropped.
struct WireIo {
    hosted: Arc<Hosted>,
    id: u64,
    tokens: Arc<Tokens>,
    closed: bool,
}

/// A slot's refusal as the I/O error a byte stream reports.
fn wire_io_error(outcome: WireOutcome) -> io::Error {
    let kind = match refusal(outcome) {
        TransportError::Refused => io::ErrorKind::ConnectionRefused,
        TransportError::Timeout => io::ErrorKind::TimedOut,
        TransportError::Reset => io::ErrorKind::ConnectionReset,
        _ => io::ErrorKind::BrokenPipe,
    };
    io::Error::new(kind, format!("transport slot answered {outcome:?}"))
}

impl WireIo {
    /// One poll of one slot with `token`, as a byte stream's answer.
    fn poll_slot<T>(
        token: &WakeToken,
        cx: &mut Context<'_>,
        slot: impl FnOnce(u64) -> WirePoll<T>,
    ) -> Poll<io::Result<T>> {
        token.register(cx.waker());
        slot(token.id()).map_err(wire_io_error)
    }
}

impl futures::io::AsyncRead for WireIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || out.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let (built, id) = (&self.hosted.built, self.id);
        Self::poll_slot(&self.tokens.read, cx, |t| built.poll_read(id, t, out))
    }
}

impl futures::io::AsyncWrite for WireIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let (built, id) = (&self.hosted.built, self.id);
        Self::poll_slot(&self.tokens.write, cx, |t| built.poll_write(id, t, bytes))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        let (built, id) = (&self.hosted.built, self.id);
        Self::poll_slot(&self.tokens.write, cx, |t| built.poll_flush(id, t))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        std::task::ready!(self.as_mut().poll_flush(cx))?;
        let (built, id) = (&self.hosted.built, self.id);
        std::task::ready!(Self::poll_slot(&self.tokens.write, cx, |t| built.poll_close(id, t)))?;
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

impl Drop for WireIo {
    fn drop(&mut self) {
        // Closing wakes a read parked on the connection, and nothing waits on it any more.
        if !self.closed {
            self.hosted.built.close_now(self.id);
        }
    }
}

#[cfg(test)]
#[path = "tests/transport_adapter_tests.rs"]
mod tests;
