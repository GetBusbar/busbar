// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NATIVE DIAL: one outbound connection framed by an admitted MIN-3 transport instance in its client role
//! (ABI-MIN3-INTERFACE §8.7 ROLE_CLIENT; dial decision v2, sections 2 and 3; deletion plan step E2).
//!
//! Core owns the socket, the connection security and the judgement of the address; the framer turns core's
//! request head and body into bytes and the far end's bytes back into streams. This file drives that:
//!
//! 1. [`locate`]: the destination URL by core's scheme table (`http` plain on 80, `https` secured on 443; `ws`
//!    and `wss` name the WebSocket carrier; anything else is refused). No plugin is asked what a URL means.
//! 2. [`NativeConnection::dial`]: a non-blocking connect to the address the caller judged (the name's other
//!    admitted addresses tried in order on a refused connect), then the client TLS handshake where secured,
//!    offering the instance's own `alpn(ROLE_CLIENT)` list and holding the far end to the destination's sealed
//!    key pin.
//! 3. [`NativeConnection::poll_send_head`]: `begin(ROLE_CLIENT)` on the first exchange (after the handshake
//!    agreed its protocol), then `emit(0, E_HEAD)` with the head's records and each `defaults(ROLE_CLIENT)` line
//!    the head lacks; the framer's STREAM_OPENED names the stream. Body pieces are `emit(stream, E_BODY)`, the
//!    message's end `emit(stream, E_END)`.
//! 4. [`NativeConnection::poll_read`]: the far end's bytes go to `ingest`; what the framer answers is handed up
//!    in the connection table's own [`Piece`] terms: the head as one field block carrying the status (classified
//!    by core, never by the framer), the body, the trailers, the end.
//!
//! MEMORY (the owner's allocation ruling): nothing is made for a dialled connection before it is used. The
//! socket and the TLS state are made by `dial`; the framer's session at the first exchange; the outbound byte
//! buffer and the per-stream inbox when bytes are queued, each released (wiped, then its memory given back) when
//! it empties. Every buffer that held request or answer bytes is a [`SecureVec`], wiped in one block. No pool,
//! no table, no cap of its own: what a session can make the engine hold is bounded by the windows the session
//! itself stated (`outbound::credit`), per stream and per connection.

use std::collections::VecDeque;
use std::future::Future as _;
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use busbar_contract::conn::{ConnCause, Piece, PieceKind};
use busbar_contract::ids::StreamId;
use busbar_contract::secure::SecureVec;
use busbar_contract::storage::StorageSource;
use busbar_contract::transport::wire::{WireFault, WireStatusClass};
use busbar_kernel::config_validate::schemes::{dial_scheme_of_url, DialScheme};
use busbar_plugin_abi::plane::CARRIER_DEFAULT;
use busbar_plugin_abi::records::{
    record_size, tag, Fixed, PairRec, Records, U32Rec, U64Rec, Writer,
};
use busbar_plugin_abi::transport as wire;
use busbar_ports::transport::{ConnIn, TransportPort};

use crate::framed_stream::session::{Act, Ended, TransportConn};
use crate::io::{Direction, Registered};

#[cfg(test)]
#[path = "native_dial/tests.rs"]
mod tests;

// Where the dial meets the outbound parts (delivery, sealing, credit, the proxy tunnel, the race over
// a name's addresses): the dial keeps its socket, its TLS session and its queue, and decides nothing
// about those itself.
#[path = "native_dial/drive.rs"]
pub(crate) mod drive;
pub use drive::Tunnel;

use crate::outbound::connect::{Lane, Race, Step as RaceStep};
use crate::outbound::delivery::{Reason, Role};
use crate::outbound::seal::Slots;
use crate::outbound::tunnel::{Dialling, Step};
use crate::outbound::wire::Wire;

/// One socket read. A stack buffer, wiped after each read: it never outlives the call.
const READ_CHUNK: usize = 16 * 1024;

/// The status numbering a native HTTP head is stated in (the far end's `WireStatus` namespace, as the HTTP
/// transport stated it on the old path, so the breaker's records keep their keys across the switch).
const HTTP_NAMESPACE: &str = "http";

/// Between a field's name and its value, and after the value, in the field block a head is handed up as (the
/// block the connection table's readers parse: `name: value\r\n` per field).
const SEPARATOR: &[u8] = b": ";
const LINE_END: &[u8] = b"\r\n";

/// The fields never handed up from a dialled answer: hop-by-hop, the connection's own (RFC 9110 §7.6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
];

/// The cause stages a failed connection reports (`ConnCause::stage`), the connection table's own numbering.
pub mod stage {
    pub use busbar_contract::conn::codes::{
        CAUSE_CONNECT as CONNECT, CAUSE_DEADLINE as DEADLINE, CAUSE_FRAMER as FRAMER,
        CAUSE_SECURITY as SECURITY,
    };

    /// A failure at the operator's proxy (the tunnel refused, the proxy unreachable, its own TLS): the proxy's,
    /// never a provider's. No breaker is charged for it.
    pub const PROXY: u64 = crate::outbound::tunnel::CAUSE_PROXY;
}

/// The admitted MIN-3 transport instance that carries one outbound carrier, as the connector holds it. The
/// root builds it once at boot from its carrier table (two reference counts); it is held for the process.
#[derive(Clone)]
pub struct NativeCarrier {
    /// The image identity (the instance name), for causes and logs.
    pub instance: Arc<str>,
    /// The opened port.
    pub port: Arc<dyn TransportPort>,
    /// `busbar_plugin_abi::plane::CARRIER_*`.
    pub carrier: u32,
    /// `limits.stream_stall_ms` for the session's held streams (`None` = the kind's default).
    pub stall_ms: Option<u32>,
}

impl std::fmt::Debug for NativeCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeCarrier")
            .field("instance", &self.instance)
            .field("carrier", &self.carrier)
            .finish_non_exhaustive()
    }
}

/// Where a destination URL dials, by core's scheme table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// `host:port` as the judge reads it (an IPv6 literal keeps its brackets).
    pub authority: String,
    /// The name offered in SNI where secured (the host, without brackets); `None` in the clear.
    pub name: Option<String>,
    /// The dial runs connection security from its first byte.
    pub secure: bool,
    /// The carrier the scheme means when the plane says `CARRIER_DEFAULT`.
    pub carrier: u32,
    /// The scheme's row: `scheme.carrier(named)` checks a carrier a plane names explicitly.
    pub scheme: DialScheme,
}

/// Read `target` by core's one scheme table (`busbar_kernel::config_validate::schemes`, dial decision v2 section
/// 3.2), which configuration validation reads too. Userinfo is refused (it is never a destination's, and
/// configuration validation refuses it first).
///
/// # Errors
/// The refusal, in words naming the scheme or the part that is wrong.
pub fn locate(target: &str) -> Result<Located, String> {
    let row = dial_scheme_of_url(target).map_err(|refused| refused.to_string())?;
    let (secure, port) = (row.secured, row.default_port);
    let carrier = row
        .carrier(CARRIER_DEFAULT)
        .map_err(|refused| refused.to_string())?;
    let rest = target.split_once("://").map_or("", |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err("the destination names no host".to_owned());
    }
    if authority.contains('@') {
        return Err("the destination carries userinfo, which is never dialled".to_owned());
    }
    let (host, explicit) = split_port(authority)?;
    if host.is_empty() {
        return Err("the destination names no host".to_owned());
    }
    let port = explicit.unwrap_or(port);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    Ok(Located {
        authority: format!("{host}:{port}"),
        name: secure.then(|| bare.to_owned()),
        secure,
        carrier,
        scheme: row,
    })
}

/// `host` and its explicit port, if any. An IPv6 literal is bracketed; a port is 1..=65535.
fn split_port(authority: &str) -> Result<(&str, Option<u16>), String> {
    let at = if authority.starts_with('[') {
        let close = authority
            .find(']')
            .ok_or_else(|| "the destination's IPv6 literal is not closed".to_owned())?;
        match &authority[close + 1..] {
            "" => return Ok((authority, None)),
            rest if rest.starts_with(':') => close + 1,
            _ => return Err("the destination's host is not followed by a port".to_owned()),
        }
    } else {
        match authority.rfind(':') {
            Some(at) => at,
            None => return Ok((authority, None)),
        }
    };
    let port = authority[at + 1..]
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| "the destination's port is not 1..=65535".to_owned())?;
    Ok((&authority[..at], Some(port)))
}

/// What one dial needs. The caller has judged `addr` for `located.authority` under its own policy.
pub struct NativeDial {
    /// Where the destination dials ([`locate`]).
    pub located: Located,
    /// The judged address.
    pub addr: SocketAddr,
    /// The name's other admitted addresses, in the resolver's order: a refused connect moves to the next.
    pub also: Vec<SocketAddr>,
    /// The connector's client TLS config where `located.secure` (the destination's sealed config wins).
    pub tls: Option<Arc<rustls::ClientConfig>>,
    /// The destination's sealed anchors: the key pin the far end is held to and the identity presented.
    pub anchors: Option<Arc<crate::tls::client::Sealed>>,
    /// The bound on connect and handshake.
    pub open_timeout: Duration,
    /// The connection's storage account: what the framer's session charges its answers to.
    pub storage: StorageSource,
    /// The operator's proxy this dial goes through; `None` = straight to the target. With a tunnel, `addr`
    /// and `also` are the proxy's judged addresses, and the plaintext rule was applied to the target's.
    pub tunnel: Option<Tunnel>,
}

/// One request head as core hands it to the framer. Its values are moved in, not copied; the target and every
/// value are wiped when the head is dropped, which is right after its records are encoded.
pub struct NativeHead {
    /// The method (`GET`, `POST`).
    pub method: Vec<u8>,
    /// The request target: path and query.
    pub target: Vec<u8>,
    /// The fields, in order, credentials included (applied by core's auth binding before this point).
    pub fields: Vec<(String, Vec<u8>)>,
    /// The body's whole length when core holds it before the head goes (`H_BODY_LEN`); `None` = streamed.
    pub body_len: Option<u64>,
    /// The request's remaining deadline when the head goes (`H_BUDGET_NS`); `None` = none.
    pub budget: Option<Duration>,
    /// The operator accepted plaintext for this destination (the route's own judged acceptance or an
    /// exact per-destination entry, never the app-wide acceptance): only then may a sealed value of this
    /// head cross a connection that is not secured.
    pub sealed_in_clear: bool,
}

impl Drop for NativeHead {
    fn drop(&mut self) {
        drop(SecureVec::from(std::mem::take(&mut self.target)));
        for (_, value) in self.fields.drain(..) {
            drop(SecureVec::from(value));
        }
    }
}

/// The words of a `STREAM_BUSY` answer.
const BUSY: &str = "the connection takes no new stream now";

/// Why a native dial failed: the stage, whether it was core's own outbound head the framer refused (a local
/// fault: no destination is charged for it), and the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeFailure {
    /// The stage and the error's own text; `outbound` = core's own emit was refused.
    pub cause: ConnCause,
}

impl NativeFailure {
    fn at(stage: u64, text: impl Into<String>) -> Self {
        Self {
            cause: ConnCause {
                stage,
                text: text.into(),
                outbound: false,
            },
        }
    }

    /// The transport answered `STREAM_BUSY`: the connection takes no new stream now. Nothing of the
    /// request left the engine.
    fn busy() -> Self {
        Self::at(stage::FRAMER, BUSY)
    }

    /// The failure is a `STREAM_BUSY` ([`Self::busy`]): the request goes to another connection.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        self.cause.stage == stage::FRAMER && self.cause.text == BUSY
    }

    fn outbound(text: impl Into<String>) -> Self {
        Self {
            cause: ConnCause {
                stage: stage::FRAMER,
                text: text.into(),
                outbound: true,
            },
        }
    }
}

impl std::fmt::Display for NativeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.cause.text)
    }
}

impl std::error::Error for NativeFailure {}

/// What the framer handed up for one stream and its reader has not taken yet.
enum Inbound {
    /// The head: its status, its reason phrase (HTTP/1.1 only), the length it declared, and its field block.
    Head {
        status: Option<u32>,
        declared_len: Option<u64>,
        block: SecureVec,
    },
    /// Body bytes; `taken` of them were already handed up.
    Body {
        bytes: SecureVec,
        taken: usize,
        /// The piece ends its message (a message stream's `MSG_FIN`; always, on a byte stream).
        last: bool,
    },
    /// The trailers' field block.
    Trailers(SecureVec),
    /// STREAM_END.
    End,
    /// STREAM_RESET, with the wire's code.
    Reset(u32),
}

/// One open stream: its inbox (made when its first piece arrives, released when it empties) and its state.
struct Stream {
    id: u64,
    inbox: VecDeque<Inbound>,
    /// STREAM_FULL: core must not emit on it until STREAM_WRITABLE.
    full: bool,
    /// The end (or a reset) was handed up: the stream is over.
    over: bool,
    /// The head was handed up (a later field block is the trailers).
    answered: bool,
}

/// Where the connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connecting,
    Handshaking,
    Open,
    Failed,
    Closed,
}

/// One dialled connection framed by a ROLE_CLIENT [`TransportConn`].
pub struct NativeConnection {
    carrier: NativeCarrier,
    located: Located,
    sock: Registered<TcpStream>,
    /// The steps below the session: connect, the proxy's own TLS, the CONNECT, the target's TLS.
    dialling: Dialling,
    /// Delivery, sealed values, credit and lending state of this connection's streams.
    wire: Wire,
    /// Which of the name's admitted addresses is connected to, when.
    race: Race,
    /// The first lane's socket (`sock`) is in flight.
    first_live: bool,
    /// The other address family's socket, while the race has one in flight.
    second: Option<(Registered<TcpStream>, SocketAddr)>,
    /// The race's next wake.
    race_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// The race's time zero.
    started: Instant,
    last_connect_error: Option<io::Error>,
    /// Bytes the proxy sent past its answer's head: the tunnel's first bytes.
    tunnelled: SecureVec,
    /// Sealed values a `STREAM_BUSY` handed back, or the exchange offered for a head sent again.
    handed_back: Option<Slots>,
    peer: SocketAddr,
    phase: Phase,
    tls: Option<rustls::ClientConnection>,
    /// The key the far end is held to, where the destination's anchors pin one.
    pin: Option<String>,
    presented: Arc<AtomicBool>,
    peer_key_pin: Option<String>,
    agreed: Option<Vec<u8>>,
    storage: StorageSource,
    session: Option<TransportConn>,
    /// Bytes for the socket (ciphertext under TLS), wiped as the socket takes them, released when empty.
    out: SecureVec,
    streams: Vec<Stream>,
    /// The framer's WAKE_AT, as a host instant, and the timer that fires it.
    wake: Option<Pin<Box<tokio::time::Sleep>>>,
    /// The far end ended its stream.
    eof: bool,
    /// The framer answered CLOSE: once `out` is written, the connection ends.
    closing: bool,
    open_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    flushed: u64,
    cause: Option<ConnCause>,
}

impl std::fmt::Debug for NativeConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeConnection")
            .field("instance", &self.carrier.instance)
            .field("authority", &self.located.authority)
            .field("phase", &self.phase)
            .finish_non_exhaustive()
    }
}

/// A sleep on the process's one runtime, whichever thread polls it.
fn sleep_for(after: Duration) -> Pin<Box<tokio::time::Sleep>> {
    let _entered = crate::io::enter_process_runtime();
    Box::pin(tokio::time::sleep(after))
}

/// The host's monotonic reading on the clock a framer's WAKE_AT is stated on.
fn mono() -> u64 {
    busbar_plugin_abi::host_side::host_vt::vt::mono()
}

fn io_failure(stage: u64) -> impl Fn(io::Error) -> NativeFailure {
    move |error| NativeFailure::at(stage, error.to_string())
}

fn session_failure(ended: &Ended) -> NativeFailure {
    match ended {
        Ended::Capacity => NativeFailure::at(
            stage::FRAMER,
            "the framer's answer exceeded the connection's storage account",
        ),
        Ended::Fault(reason) => NativeFailure::at(
            stage::FRAMER,
            format!("the transport broke its answer grammar ({reason:?}) and was charged"),
        ),
        Ended::Port(error) => NativeFailure::at(stage::FRAMER, format!("{error:?}")),
        Ended::Misuse(what) => {
            NativeFailure::at(stage::FRAMER, format!("core misused the session: {what}"))
        }
    }
}

impl NativeConnection {
    /// Begin the connect to `dial.addr` and set up the client handshake where the destination is secured.
    /// Returns at once; the polls below drive the connect and the handshake.
    ///
    /// # Errors
    /// A synchronous refusal: a secured destination with no client config, a name that is not a server name,
    /// the socket's own refusal when no other address is left.
    pub fn dial(carrier: NativeCarrier, dial: NativeDial) -> Result<Self, NativeFailure> {
        let NativeDial {
            located,
            addr,
            also,
            tls,
            anchors,
            open_timeout,
            storage,
            tunnel,
        } = dial;
        let dialling = drive::dialling_for(tunnel, located.secure)?;
        let presented = Arc::new(AtomicBool::new(false));
        let tls = if located.secure {
            let base = anchors
                .as_ref()
                .and_then(|sealed| sealed.tls.clone())
                .or(tls)
                .ok_or_else(|| {
                    NativeFailure::at(
                        stage::SECURITY,
                        "the destination asks for connection security and none is set",
                    )
                })?;
            // rustls takes the protocol offer in the config: this connection's copy carries the instance's own
            // client offer, made once for this handshake and dropped with the connection.
            let mut config = (*base).clone();
            config.alpn_protocols = carrier
                .port
                .alpn(wire::ROLE_CLIENT)
                .iter()
                .map(|id| id.as_bytes().to_vec())
                .collect();
            if anchors
                .as_ref()
                .is_some_and(|sealed| sealed.key_pin.is_some())
            {
                config.resumption = rustls::client::Resumption::disabled();
            }
            if let Some(identity) = anchors.as_ref().and_then(|sealed| sealed.identity.clone()) {
                config.client_auth_cert_resolver = Arc::new(crate::tls::client::Presenting::new(
                    identity,
                    Arc::clone(&presented),
                ));
            }
            let host = located.name.as_deref().unwrap_or_default();
            let name = rustls::pki_types::ServerName::try_from(host)
                .map(|name| name.to_owned())
                .map_err(|error| {
                    NativeFailure::at(
                        stage::SECURITY,
                        format!("the name offered is not a server name: {error}"),
                    )
                })?;
            Some(
                rustls::ClientConnection::new(Arc::new(config), name)
                    .map_err(|error| NativeFailure::at(stage::SECURITY, error.to_string()))?,
            )
        } else {
            None
        };
        // The race over the name's admitted addresses: each its share of the open deadline, the other
        // address family started after a short delay. Its first connect begins here.
        let mut addrs: smallvec::SmallVec<[SocketAddr; 8]> = smallvec::SmallVec::new();
        addrs.push(addr);
        addrs.extend(also);
        let deadline_ns = u64::try_from(open_timeout.as_nanos()).unwrap_or(u64::MAX);
        let mut race = Race::new(&addrs, 0, deadline_ns);
        let mut refused = None;
        let (sock, peer) = loop {
            match race.step(0) {
                RaceStep::Connect(Lane::First, at) => {
                    match crate::socket::connect(at).and_then(crate::io::register) {
                        Ok(sock) => break (sock, at),
                        Err(error) => {
                            refused = Some(error);
                            race.failed(Lane::First, 0);
                        }
                    }
                }
                RaceStep::Connect(Lane::Second, _) | RaceStep::Wait(_) | RaceStep::Failed => {
                    return Err(io_failure(stage::CONNECT)(
                        refused.unwrap_or_else(|| io::Error::other("no address to dial")),
                    ));
                }
            }
        };
        Ok(Self {
            carrier,
            located,
            sock,
            dialling,
            wire: Wire::new(Role::Attempt),
            race,
            first_live: true,
            second: None,
            race_timer: None,
            started: Instant::now(),
            last_connect_error: None,
            tunnelled: SecureVec::new(),
            handed_back: None,
            peer,
            phase: Phase::Connecting,
            tls,
            pin: anchors.as_ref().and_then(|sealed| sealed.key_pin.clone()),
            presented,
            peer_key_pin: None,
            agreed: None,
            storage,
            session: None,
            out: SecureVec::new(),
            streams: Vec::new(),
            wake: None,
            eof: false,
            closing: false,
            open_deadline: Some(sleep_for(open_timeout)),
            flushed: 0,
            cause: None,
        })
    }

    // ---------------------------------------------------------------------------------------------------------
    // The exchange.

    /// Open one exchange: on the first, `begin(ROLE_CLIENT)` once the handshake agreed its protocol; then
    /// `emit(0, E_HEAD)` with `head`'s records, and E_END at once unless `body_follows`. `head` is taken (and
    /// wiped) once its records are encoded. Ready with the stream the framer opened.
    pub fn poll_send_head(
        &mut self,
        cx: &mut Context<'_>,
        head: &mut Option<NativeHead>,
        body_follows: bool,
    ) -> Poll<Result<u64, NativeFailure>> {
        if let Err(failure) = self.progress(cx) {
            return Poll::Ready(Err(failure));
        }
        if self.phase != Phase::Open {
            return Poll::Pending;
        }
        if self.closing || self.eof {
            return Poll::Ready(Err(NativeFailure::at(
                stage::FRAMER,
                "the connection is closing: it takes no new exchange",
            )));
        }
        if let Err(failure) = self.begin_session() {
            return Poll::Ready(Err(self.fail(failure)));
        }
        // The head is lent, not taken: its owner keeps it while the request may still be sent again
        // (`outbound::redial::keeps_head`) and wipes it by dropping it. Its sealed values leave its fields
        // here, into slots the engine alone holds; on a head sent again they are offered back
        // (`offer_sealed`) and nothing is taken from the fields a second time.
        let Some(lent) = head.as_mut() else {
            return Poll::Ready(Err(NativeFailure::outbound("no head to send")));
        };
        let again = self.handed_back.take();
        let in_clear = lent.sealed_in_clear;
        // A refusal here is the engine's own and of this request alone: the connection is untouched.
        let records = match self.seal_and_encode(lent, again, in_clear) {
            Ok(records) => records,
            Err(failure) => return Poll::Ready(Err(failure)),
        };
        let stream = match self.emit(0, wire::E_HEAD, 0, &records) {
            Ok(Some(stream)) => stream,
            Ok(None) if self.handed_back.is_some() => {
                // STREAM_BUSY: no stream opened, nothing written, nothing of the head kept. Not a fault
                // and not the connection's failure: the exchange offers the same head elsewhere.
                return Poll::Ready(Err(NativeFailure::busy()));
            }
            Ok(None) => {
                return Poll::Ready(Err(self.fail(NativeFailure::outbound(
                    "the transport answered a request head without opening a stream",
                ))))
            }
            Err(failure) => return Poll::Ready(Err(self.fail(failure))),
        };
        drop(records);
        self.streams.push(Stream {
            id: stream,
            inbox: VecDeque::new(),
            full: false,
            over: false,
            answered: false,
        });
        if !body_follows {
            self.wire.emitting_end(stream);
            if let Err(failure) = self.emit(stream, wire::E_END, 0, &[]) {
                return Poll::Ready(Err(self.fail(failure)));
            }
        }
        if let Err(failure) = self.progress(cx) {
            return Poll::Ready(Err(failure));
        }
        Poll::Ready(Ok(stream))
    }

    /// The sealed values of the head about to be sent again (handed back by a `STREAM_BUSY`, or by a
    /// failed attempt on another connection): offered here, then `poll_send_head`.
    pub(crate) fn offer_sealed(&mut self, slots: Slots) {
        self.handed_back = Some(slots);
    }

    /// One body piece on `stream`, then E_END when `end`. Ready with the bytes taken: `0` while the stream is
    /// held by STREAM_FULL or the socket has not taken what is queued (the wake comes with the next readiness).
    pub fn poll_send_body(
        &mut self,
        cx: &mut Context<'_>,
        stream: u64,
        bytes: &[u8],
        end: bool,
    ) -> Poll<Result<usize, NativeFailure>> {
        if let Err(failure) = self.progress(cx) {
            return Poll::Ready(Err(failure));
        }
        let Some(at) = self.streams.iter().position(|one| one.id == stream) else {
            return Poll::Ready(Err(NativeFailure::outbound(
                "a body for a stream that is not open",
            )));
        };
        // The room is the session's own windows (per stream and per connection), never a figure of the
        // engine's: one request with a full window cannot fill the socket queue and starve the others.
        let room = self.body_room(stream);
        if self.streams[at].full || (room == 0 && !bytes.is_empty()) {
            return Poll::Pending;
        }
        let take = bytes.len().min(room);
        if take > 0 {
            self.wire.emitting_body(stream, take as u64);
            if let Err(failure) = self.emit(stream, wire::E_BODY, 0, &bytes[..take]) {
                return Poll::Ready(Err(self.fail(failure)));
            }
        }
        if end && take == bytes.len() {
            self.wire.emitting_end(stream);
            if let Err(failure) = self.emit(stream, wire::E_END, 0, &[]) {
                return Poll::Ready(Err(self.fail(failure)));
            }
        }
        if let Err(failure) = self.progress(cx) {
            return Poll::Ready(Err(failure));
        }
        Poll::Ready(Ok(take))
    }

    /// The next piece of `stream` into `buf`, in the connection table's terms. A body larger than `buf` is
    /// handed in parts; a head whose field block does not fit is refused (the caller's buffer is the
    /// connection table's own read bound).
    pub fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        stream: u64,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, NativeFailure>> {
        loop {
            if let Some(piece) = self.take_piece(stream, buf) {
                // The reader took body bytes: on a multiplexed session that is the credit that reopens the
                // stream's window (`CONSUMED`), given once half the window is owed.
                if let Ok(taken) = &piece {
                    if taken.kind == PieceKind::Body && taken.len > 0 {
                        if let Err(failure) = self.give_credit(stream, taken.len) {
                            return Poll::Ready(Err(self.fail(failure)));
                        }
                    }
                }
                return Poll::Ready(piece);
            }
            if let Some(cause) = &self.cause {
                return Poll::Ready(Err(NativeFailure {
                    cause: cause.clone(),
                }));
            }
            match self.progress(cx) {
                Err(failure) => return Poll::Ready(Err(failure)),
                Ok(true) => continue,
                Ok(false) => {}
            }
            if self.take_piece_ready(stream) {
                continue;
            }
            if self.eof || self.phase == Phase::Closed {
                return Poll::Ready(Err(NativeFailure::at(
                    stage::FRAMER,
                    "the far end closed the connection before the answer ended",
                )));
            }
            return Poll::Pending;
        }
    }

    /// Whether the next read of `stream` will not pend: a piece is waiting, or the connection failed or
    /// ended. Otherwise the connection is moved as far as it goes and `cx`'s waker is kept on its socket
    /// and its timer, so a wait over several connections names the one that answered.
    pub fn poll_ready(&mut self, cx: &mut Context<'_>, stream: u64) -> bool {
        if self.take_piece_ready(stream) || self.cause.is_some() {
            return true;
        }
        match self.progress(cx) {
            Err(_) => true,
            Ok(_) => self.take_piece_ready(stream) || self.eof || self.phase == Phase::Closed,
        }
    }

    /// Everything queued for the socket is on it.
    pub fn poll_flushed(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), NativeFailure>> {
        if let Err(failure) = self.progress(cx) {
            return Poll::Ready(Err(failure));
        }
        if self.phase == Phase::Open && self.out.is_empty() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    /// Core is done with `stream` before its end (the caller went away): `emit(stream, E_RESET)` and forget it.
    pub fn reset(&mut self, stream: u64) {
        let Some(at) = self.streams.iter().position(|one| one.id == stream) else {
            return;
        };
        let over = self.streams[at].over;
        self.streams.swap_remove(at);
        if !over && self.session.as_ref().is_some_and(TransportConn::is_live) {
            // Code 0: core's own cancel, no wire code (the framer maps it to its protocol's cancel). Only this
            // stream is reset: the others on the connection finish.
            self.wire.stopping(stream, Reason::Cancelled);
            let _ = self.emit(stream, wire::E_RESET, 0, &[]);
        }
        let _ = self.stream_over(stream, false);
    }

    /// The exchange on `stream` ended and its reader took everything: the stream is forgotten.
    pub fn finish(&mut self, stream: u64) {
        if let Some(at) = self
            .streams
            .iter()
            .position(|one| one.id == stream && one.over && one.inbox.is_empty())
        {
            self.streams.swap_remove(at);
            let _ = self.stream_over(stream, false);
        }
    }

    // ---------------------------------------------------------------------------------------------------------
    // State.

    /// The connection can still carry an exchange.
    #[must_use]
    pub fn live(&self) -> bool {
        matches!(
            self.phase,
            Phase::Connecting | Phase::Handshaking | Phase::Open
        ) && !self.closing
            && !self.eof
            && self.session.as_ref().is_none_or(TransportConn::is_live)
    }

    /// Live, no stream open, nothing queued for the socket: the next exchange to the same destination may ride it.
    #[must_use]
    pub fn reusable(&self) -> bool {
        self.streams.is_empty() && self.session_reusable()
    }

    /// The session carries several streams at once and takes another now: a second exchange may open
    /// while one is open. The session's own statement (`SESSION`, `STREAM_BUSY`, `NO_NEW_STREAMS`),
    /// never the protocol's name.
    #[must_use]
    pub fn multiplexes(&self) -> bool {
        self.session_multiplexes()
    }

    /// The connection runs connection security.
    #[must_use]
    pub fn secured(&self) -> bool {
        self.tls.is_some()
    }

    /// The protocol the handshake agreed, if any.
    #[must_use]
    pub fn agreed_alpn(&self) -> Option<&[u8]> {
        self.agreed.as_deref()
    }

    /// The far end's key pin, read off its verified leaf certificate.
    #[must_use]
    pub fn peer_key_pin(&self) -> Option<&str> {
        self.peer_key_pin.as_deref()
    }

    /// Whether the handshake presented busbar's client identity.
    #[must_use]
    pub fn client_identity(&self) -> bool {
        self.presented.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Every byte the socket has taken.
    #[must_use]
    pub fn flushed(&self) -> u64 {
        self.flushed
    }

    /// Where the destination dials.
    #[must_use]
    pub fn located(&self) -> &Located {
        &self.located
    }

    /// The address the connection reached.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Why the connection failed, once it has.
    #[must_use]
    pub fn cause(&self) -> Option<&ConnCause> {
        self.cause.as_ref()
    }

    /// `emit(0, E_CLOSE, CR_NORMAL)` when the session is live, then one non-blocking attempt to write what it
    /// answered; the connection is dropped (its buffers wiped) on return.
    pub fn close(mut self) {
        if let Some(session) = self.session.as_mut() {
            let now = Instant::now();
            if session.close(wire::CR_NORMAL, now).is_ok() {
                // E_CLOSE's answer is parts like any other: checked, then queued as one run.
                let _ = self.apply_outbound();
            }
        }
        if let Some(tls) = self.tls.as_mut() {
            tls.send_close_notify();
        }
        let _ = self.drain_target();
        // The engine's own TLS session to the proxy, where the proxy is reached over TLS, closes last.
        self.dialling.close(&mut self.out);
        let _ = self.write_now();
        self.outbound_gone(Reason::Shutdown);
    }

    // ---------------------------------------------------------------------------------------------------------
    // The driving.

    /// Move the connection as far as it goes without waiting: the connect, the handshake, the queued bytes,
    /// the socket's bytes into the framer, the framer's timer. `Ok(true)` = something was handed up.
    fn progress(&mut self, cx: &mut Context<'_>) -> Result<bool, NativeFailure> {
        if let Some(cause) = &self.cause {
            return Err(NativeFailure {
                cause: cause.clone(),
            });
        }
        let result = self.progress_inner(cx);
        result.map_err(|failure| self.fail(failure))
    }

    fn progress_inner(&mut self, cx: &mut Context<'_>) -> Result<bool, NativeFailure> {
        if matches!(self.phase, Phase::Connecting | Phase::Handshaking) {
            if let Some(deadline) = self.open_deadline.as_mut() {
                if deadline.as_mut().poll(cx).is_ready() {
                    return Err(NativeFailure::at(
                        stage::DEADLINE,
                        "the connection's open deadline passed",
                    ));
                }
            }
        }
        if self.phase == Phase::Connecting {
            // The race over the name's addresses, then the first step below the session (the proxy's own
            // TLS, the CONNECT). The phase stays `Connecting` to the dial's caller until the tunnel, where
            // there is one, is open.
            self.progress_connect(cx)?;
            if self.socket_connecting() {
                return Ok(false);
            }
        }
        // The target's TLS writes nothing until the tunnel under it is open.
        self.drain_target()?;
        self.write_ready(cx)?;
        let handed = self.read_ready(cx)?;
        if self.phase == Phase::Handshaking {
            self.finish_handshake()?;
        }
        let woke = self.timer_ready(cx)?;
        if self.closing && self.out.is_empty() {
            self.phase = Phase::Closed;
        }
        Ok(handed || woke)
    }

    /// The handshake has ended: hold the far end to the pin, note the agreed protocol, open for exchanges.
    fn finish_handshake(&mut self) -> Result<(), NativeFailure> {
        let Some(tls) = self.tls.as_ref() else {
            return Ok(());
        };
        if tls.is_handshaking() {
            return Ok(());
        }
        self.peer_key_pin = tls
            .peer_certificates()
            .and_then(|chain| chain.first())
            .and_then(|leaf| crate::tls::client::peer_key_pin(leaf.as_ref()));
        if let Some(pin) = self.pin.as_deref() {
            if self.peer_key_pin.as_deref() != Some(pin) {
                return Err(NativeFailure::at(
                    stage::SECURITY,
                    "the far end's key does not match the destination's pinned key",
                ));
            }
        }
        self.agreed = tls.alpn_protocol().map(<[u8]>::to_vec);
        self.open_deadline = None;
        self.phase = Phase::Open;
        Ok(())
    }

    /// `begin(ROLE_CLIENT)`, once, after the handshake.
    fn begin_session(&mut self) -> Result<(), NativeFailure> {
        if self.session.is_some() {
            return Ok(());
        }
        let alpn = self
            .agreed
            .as_deref()
            .and_then(|id| std::str::from_utf8(id).ok())
            .unwrap_or_default();
        // On a tunnelled dial the transport is told the target's judged address (nothing, where the proxy
        // resolves the name), never the proxy's.
        let told = match self.dialling.tunnel_peer() {
            None => Some(self.peer),
            Some(target) => target,
        };
        let peer = told.map(|addr| crate::StackText::<{ crate::SOCKET_TEXT }>::of(&addr));
        let leaf = self
            .tls
            .as_ref()
            .and_then(|tls| tls.peer_certificates())
            .and_then(|chain| chain.first())
            .map(|leaf| leaf.as_ref().to_vec());
        let conn = ConnIn {
            role: wire::ROLE_CLIENT,
            flags: 0,
            alpn,
            sni: self.located.name.as_deref().unwrap_or_default(),
            peer: peer.as_ref().map_or("", |text| text.as_str()),
            local: "",
            tls_peer_cert: leaf.as_deref().unwrap_or_default(),
            leftover: &[],
            head: &[],
            local_fingerprint: "",
            mono_ns: mono(),
        };
        let session = TransportConn::begin(
            Arc::clone(&self.carrier.port),
            &conn,
            self.carrier.stall_ms,
            Instant::now(),
            self.storage.clone(),
        )
        .map_err(|ended| session_failure(&ended))?;
        self.session = Some(session);
        self.apply_last()?;
        Ok(())
    }

    /// One `emit` and what its answer asks; `Ok(Some(stream))` when it answered STREAM_OPENED.
    fn emit(
        &mut self,
        stream: u64,
        piece: u32,
        arg: u32,
        bytes: &[u8],
    ) -> Result<Option<u64>, NativeFailure> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| NativeFailure::outbound("no framing session"))?;
        session
            .emit(stream, piece, arg, bytes, Instant::now())
            .map_err(|ended| {
                let mut failure = session_failure(&ended);
                failure.cause.outbound = matches!(ended, Ended::Port(_));
                failure
            })?;
        self.apply_last()
    }

    /// Hand the socket's bytes to the framer while it reads; `Ok(true)` = a piece was handed up.
    fn read_ready(&mut self, cx: &mut Context<'_>) -> Result<bool, NativeFailure> {
        let mut handed = false;
        let mut chunk = [0_u8; READ_CHUNK];
        loop {
            if self.eof || self.socket_connecting() {
                break;
            }
            // A multiplexed session is always read: the windows it stated bound what can arrive, and a slow
            // reader stalls its own stream only. A session with one stream is read when its reader holds
            // nothing.
            if !self.reads_socket() {
                break;
            }
            let read = self
                .sock
                .poll_io_sized(Direction::Read, chunk.len(), cx, |socket| {
                    (&*socket).read(&mut chunk)
                });
            let n = match read {
                Poll::Pending => break,
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(error)) => {
                    chunk.fill(0);
                    return Err(io_failure(stage::CONNECT)(error));
                }
            };
            let fed = self.feed(&chunk[..n], n == 0);
            chunk[..n].fill(0);
            handed |= fed?;
            if n == 0 {
                self.eof = true;
                break;
            }
        }
        Ok(handed)
    }

    /// Bytes the socket read: through TLS where secured, then to `ingest`. `end` = the far end's EOF.
    fn feed(&mut self, bytes: &[u8], end: bool) -> Result<bool, NativeFailure> {
        // Below the session first: the proxy's own TLS and its answer to the CONNECT take the bytes while
        // the tunnel is made, and a tunnel through a TLS proxy unwraps every later read.
        let lowered = self.below_session(bytes)?;
        if matches!(
            self.dialling.step(),
            Step::ProxyHandshake | Step::Tunnelling
        ) {
            if end {
                return Err(drive::proxy_failure(crate::outbound::tunnel::ProxyFailure(
                    "the proxy closed the connection before the tunnel was open".to_owned(),
                )));
            }
            return Ok(false);
        }
        let bytes = lowered.as_ref().map_or(bytes, |inner| inner.as_slice());
        let mut plain = SecureVec::new();
        if let Some(tls) = self.tls.as_mut() {
            let mut rest = bytes;
            while !rest.is_empty() {
                if tls
                    .read_tls(&mut rest)
                    .map_err(io_failure(stage::SECURITY))?
                    == 0
                {
                    break;
                }
                let state = tls
                    .process_new_packets()
                    .map_err(|error| NativeFailure::at(stage::SECURITY, error.to_string()))?;
                let ready = state.plaintext_bytes_to_read();
                if ready > 0 {
                    let at = plain.len();
                    plain
                        .extend(&vec![0; ready])
                        .map_err(|_| NativeFailure::at(stage::FRAMER, "tls read buffer"))?;
                    tls.reader()
                        .read_exact(&mut plain[at..])
                        .map_err(io_failure(stage::SECURITY))?;
                }
            }
            if end {
                tls.read_tls(&mut io::empty())
                    .map_err(io_failure(stage::SECURITY))?;
            }
            self.dialling
                .drain_target(tls, &mut self.out)
                .map_err(io_failure(stage::SECURITY))?;
            if self.phase == Phase::Handshaking {
                if end {
                    return Err(NativeFailure::at(
                        stage::CONNECT,
                        "the far end closed the connection during the handshake",
                    ));
                }
                return Ok(false);
            }
        } else {
            plain
                .extend(bytes)
                .map_err(|_| NativeFailure::at(stage::FRAMER, "read buffer"))?;
        }
        if self.session.is_none() {
            // Bytes before any exchange: nothing asked for them.
            return if plain.is_empty() && end {
                Ok(false)
            } else if plain.is_empty() {
                Ok(false)
            } else {
                Err(NativeFailure::at(
                    stage::FRAMER,
                    "the far end sent bytes before any request",
                ))
            };
        }
        let before = self.inbox_pieces();
        if !plain.is_empty() {
            self.ingest(plain.as_slice())?;
        }
        if end {
            self.ingest(&[])?;
        }
        Ok(self.inbox_pieces() > before)
    }

    fn ingest(&mut self, bytes: &[u8]) -> Result<(), NativeFailure> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| NativeFailure::at(stage::FRAMER, "no framing session"))?;
        session
            .ingest(bytes, Instant::now())
            .map_err(|ended| session_failure(&ended))?;
        self.apply_last().map(|_| ())
    }

    /// The framer's WAKE_AT has passed: `timer`.
    fn timer_ready(&mut self, cx: &mut Context<'_>) -> Result<bool, NativeFailure> {
        let Some(wake) = self.wake.as_mut() else {
            return Ok(false);
        };
        if wake.as_mut().poll(cx).is_pending() {
            return Ok(false);
        }
        self.wake = None;
        let before = self.inbox_pieces();
        if let Some(session) = self.session.as_mut() {
            session
                .timer(Instant::now())
                .map_err(|ended| session_failure(&ended))?;
            self.apply_last()?;
        }
        Ok(self.inbox_pieces() > before)
    }

    /// Act on the session's last answer, in order. `Ok(Some(stream))` = it carried STREAM_OPENED.
    ///
    /// Everything the answer writes or states about the connection goes through the outbound driver first
    /// (`apply_outbound`): the parts are checked against the output model, the sealed grammar and the
    /// windows, then queued for the socket as one run with the sealed values in place. A breach writes
    /// nothing of the answer. What is left here is what the far end sent up: heads, bodies, trailers, ends
    /// and resets for the streams' readers, the transport's timer, and its per-stream backpressure.
    fn apply_last(&mut self) -> Result<Option<u64>, NativeFailure> {
        let outcome = self.apply_outbound()?;
        let opened = outcome.opened;
        // A WebSocket upstream's body pieces are messages: a piece ends its frame only with MSG_FIN.
        let messages = self.located.carrier == busbar_plugin_abi::plane::CARRIER_WEBSOCKET;
        let Self {
            session,
            streams,
            wake,
            ..
        } = self;
        let Some(session) = session.as_mut() else {
            return Ok(None);
        };
        let acts = session.actions();
        for act in acts.iter() {
            match act {
                // The driver's: already checked, queued and recorded.
                Act::Session(_)
                | Act::Opened(_)
                | Act::Busy
                | Act::NoNewStreams
                | Act::WirePart { .. }
                | Act::WireSealed(_)
                | Act::WireEnd { .. }
                | Act::Close { .. } => {}
                Act::Wake(at) => {
                    let after = Duration::from_nanos(at.saturating_sub(mono()));
                    *wake = Some(sleep_for(after));
                }
                Act::Upgrade { .. } => {
                    return Err(NativeFailure::at(
                        stage::FRAMER,
                        "the transport asked to upgrade a dialled connection",
                    ));
                }
                Act::Full(stream) => {
                    if let Some(one) = streams.iter_mut().find(|one| one.id == *stream) {
                        one.full = true;
                    }
                }
                Act::Writable(stream) => {
                    if let Some(one) = streams.iter_mut().find(|one| one.id == *stream) {
                        one.full = false;
                    }
                }
                Act::Head {
                    stream,
                    end_stream,
                    head,
                } => {
                    let one = stream_of(streams, *stream)?;
                    let inbound = head_of(head.as_slice(), one.answered)?;
                    one.answered = true;
                    one.inbox.push_back(inbound);
                    if *end_stream {
                        one.inbox.push_back(Inbound::End);
                    }
                }
                Act::Body {
                    stream,
                    bytes,
                    flags,
                } => {
                    let one = stream_of(streams, *stream)?;
                    one.inbox.push_back(Inbound::Body {
                        bytes: SecureVec::from(bytes.as_slice()),
                        taken: 0,
                        last: !messages || flags & wire::MSG_FIN != 0,
                    });
                }
                Act::Trailers { stream, pairs } => {
                    let one = stream_of(streams, *stream)?;
                    one.inbox
                        .push_back(Inbound::Trailers(field_block(pairs.as_slice())?));
                }
                Act::End(stream) => stream_of(streams, *stream)?.inbox.push_back(Inbound::End),
                Act::Reset { stream, code, .. } => {
                    stream_of(streams, *stream)?
                        .inbox
                        .push_back(Inbound::Reset(*code));
                }
            }
        }
        Ok(opened)
    }

    /// Whether `stream` has a piece waiting.
    fn take_piece_ready(&self, stream: u64) -> bool {
        self.streams
            .iter()
            .any(|one| one.id == stream && !one.inbox.is_empty())
    }

    /// The next waiting piece of `stream`, copied into `buf` (and released from the inbox once whole).
    fn take_piece(&mut self, stream: u64, buf: &mut [u8]) -> Option<Result<Piece, NativeFailure>> {
        let one = self.streams.iter_mut().find(|one| one.id == stream)?;
        let first = one.inbox.front_mut()?;
        let id = StreamId(stream);
        let piece = match first {
            Inbound::Head {
                status,
                declared_len,
                block,
            } => {
                if block.len() > buf.len() {
                    return Some(Err(NativeFailure::at(
                        stage::FRAMER,
                        "the far end's head does not fit the reader's buffer",
                    )));
                }
                buf[..block.len()].copy_from_slice(block.as_slice());
                let code = *status;
                Piece {
                    kind: PieceKind::Fields,
                    stream: id,
                    len: block.len(),
                    end: true,
                    status: code.map(class_of),
                    status_code: code,
                    status_namespace: code.map(|_| HTTP_NAMESPACE.to_owned()),
                    retry_after_secs: retry_after(block.as_slice()),
                    fault: code.and_then(fault_of),
                    reason: None,
                    declared_len: *declared_len,
                }
            }
            Inbound::Body { bytes, taken, last } => {
                let rest = &bytes.as_slice()[*taken..];
                let n = rest.len().min(buf.len());
                buf[..n].copy_from_slice(&rest[..n]);
                *taken += n;
                let whole = *taken == bytes.len();
                let piece = plain_piece(PieceKind::Body, id, n, whole && *last);
                if !whole {
                    return Some(Ok(piece));
                }
                piece
            }
            Inbound::Trailers(block) => {
                if block.len() > buf.len() {
                    return Some(Err(NativeFailure::at(
                        stage::FRAMER,
                        "the far end's trailers do not fit the reader's buffer",
                    )));
                }
                buf[..block.len()].copy_from_slice(block.as_slice());
                plain_piece(PieceKind::Fields, id, block.len(), true)
            }
            Inbound::End => {
                one.over = true;
                plain_piece(PieceKind::Completion, id, 0, true)
            }
            Inbound::Reset(code) => {
                let text = format!("the far end reset the stream (code {code})");
                one.over = true;
                one.inbox.clear();
                return Some(Err(NativeFailure::at(stage::FRAMER, text)));
            }
        };
        one.inbox.pop_front();
        if one.inbox.is_empty() {
            one.inbox = VecDeque::new();
        }
        Some(Ok(piece))
    }

    fn inbox_pieces(&self) -> usize {
        self.streams.iter().map(|one| one.inbox.len()).sum()
    }

    /// Plaintext for the socket, through TLS where secured.
    /// Write what the socket takes now; wake on writability while bytes remain.
    fn write_ready(&mut self, cx: &mut Context<'_>) -> Result<(), NativeFailure> {
        let before = self.flushed;
        while !self.out.is_empty() && !self.socket_connecting() {
            let want = self.out.len();
            let out = &self.out;
            match self
                .sock
                .poll_io_sized(Direction::Write, want, cx, |socket| {
                    (&*socket).write(out.as_slice())
                }) {
                Poll::Pending => break,
                Poll::Ready(Ok(0)) => {
                    return Err(NativeFailure::at(
                        stage::CONNECT,
                        "the socket took no bytes",
                    ))
                }
                Poll::Ready(Ok(n)) => {
                    self.out.consume(n);
                    self.flushed = self.flushed.saturating_add(n as u64);
                }
                Poll::Ready(Err(error)) => return Err(io_failure(stage::CONNECT)(error)),
            }
        }
        self.out.shrink_when_empty(0);
        if self.flushed != before {
            // What the operating system accepted is the delivery evidence of every stream.
            self.socket_took();
        }
        Ok(())
    }

    /// One non-blocking write attempt with no waker (the close path).
    fn write_now(&mut self) -> io::Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        let n = (&*self.sock.socket()).write(self.out.as_slice())?;
        self.out.consume(n);
        self.flushed = self.flushed.saturating_add(n as u64);
        self.socket_took();
        Ok(())
    }

    /// Record the failure once; every later call answers it.
    fn fail(&mut self, failure: NativeFailure) -> NativeFailure {
        if self.cause.is_none() {
            self.cause = Some(failure.cause.clone());
        }
        self.phase = Phase::Failed;
        // Every open request's delivery verdict is frozen as the socket's progress stands, and every
        // sealed value still held for it is wiped. A stream whose values the exchange takes back to send
        // again (`stream_over(stream, true)`) is read before this by `Exchange::attempt_failed`: the
        // streams are therefore left to the exchanges, and only the bytes go.
        self.wire_failed(&failure);
        self.streams.clear();
        self.out.clear();
        self.out.shrink_when_empty(0);
        failure
    }

    /// The request head as the framer's records: H_METHOD, H_PATH, H_AUTHORITY, H_SCHEME, PAIR* (the head's
    /// fields, then each default line it lacks), then H_BODY_LEN and H_BUDGET_NS where known. Sized once; the
    /// buffer is wiped when dropped.
    fn head_records(&self, head: &NativeHead) -> Result<SecureVec, NativeFailure> {
        let method = std::str::from_utf8(&head.method)
            .map_err(|_| NativeFailure::outbound("the request method is not text"))?;
        let path = std::str::from_utf8(&head.target)
            .map_err(|_| NativeFailure::outbound("the request target is not text"))?;
        let host = self
            .located
            .authority
            .strip_suffix(if self.located.secure { ":443" } else { ":80" })
            .unwrap_or(&self.located.authority);
        let scheme = if self.located.secure { "https" } else { "http" };
        let defaults = self.carrier.port.defaults(wire::ROLE_CLIENT);
        let lacking = |name: &str| {
            !head
                .fields
                .iter()
                .any(|(have, _)| have.eq_ignore_ascii_case(name))
        };
        let text = |s: &str| record_size(s.len());
        let pair = |name: &str, value: &[u8]| {
            record_size(std::mem::size_of::<PairRec>() + name.len() + value.len())
        };
        let mut extent = [text(method), text(path), text(host), text(scheme)]
            .into_iter()
            .try_fold(0_usize, |sum, one| one.and_then(|n| sum.checked_add(n)));
        for (name, value) in &head.fields {
            extent = extent.and_then(|sum| pair(name, value).and_then(|n| sum.checked_add(n)));
        }
        for (name, value) in defaults.iter().filter(|(name, _)| lacking(name)) {
            extent = extent
                .and_then(|sum| pair(name, value.as_bytes()).and_then(|n| sum.checked_add(n)));
        }
        let pod = record_size(std::mem::size_of::<U64Rec>());
        for wanted in [head.body_len.is_some(), head.budget.is_some()] {
            if wanted {
                extent = extent.and_then(|sum| pod.and_then(|n| sum.checked_add(n)));
            }
        }
        let extent = extent
            .ok_or_else(|| NativeFailure::outbound("the request head is too large to encode"))?;
        let mut records = SecureVec::zeroed(extent);
        let mut writer = Fixed::new(&mut records[..]);
        let written = (|| {
            writer.put_text(tag::H_METHOD, method)?;
            writer.put_text(tag::H_PATH, path)?;
            writer.put_text(tag::H_AUTHORITY, host)?;
            writer.put_text(tag::H_SCHEME, scheme)?;
            for (name, value) in &head.fields {
                writer.put_pair(tag::PAIR, name, value)?;
            }
            for (name, value) in defaults.iter().filter(|(name, _)| lacking(name)) {
                writer.put_pair(tag::PAIR, name, value.as_bytes())?;
            }
            if let Some(len) = head.body_len {
                writer.put_pod(tag::H_BODY_LEN, &U64Rec { value: len })?;
            }
            if let Some(budget) = head.budget {
                let ns = u64::try_from(budget.as_nanos()).unwrap_or(u64::MAX).max(1);
                writer.put_pod(tag::H_BUDGET_NS, &U64Rec { value: ns })?;
            }
            Ok::<usize, busbar_plugin_abi::records::Full>(writer.len())
        })()
        .map_err(|_| NativeFailure::outbound("the request head did not fit its own size"))?;
        records.truncate(written);
        Ok(records)
    }
}

impl Drop for NativeConnection {
    fn drop(&mut self) {
        // The buffers wipe themselves; the inboxes hold `SecureVec`s; the sealed values' slots wipe when the
        // driver lets go of them. Nothing else holds request bytes.
        self.outbound_gone(Reason::CallerGone);
        self.streams.clear();
    }
}

fn stream_of(streams: &mut [Stream], id: u64) -> Result<&mut Stream, NativeFailure> {
    streams.iter_mut().find(|one| one.id == id).ok_or_else(|| {
        NativeFailure::at(
            stage::FRAMER,
            "the transport answered on a stream core did not open",
        )
    })
}

/// A STREAM_HEAD's records as the piece handed up: H_STATUS, then PAIR* as the field block (hop-by-hop fields
/// dropped). A second head on a stream (an interim 1xx answer is the framer's to absorb) is refused.
fn head_of(records: &[u8], answered: bool) -> Result<Inbound, NativeFailure> {
    if answered {
        return Err(NativeFailure::at(
            stage::FRAMER,
            "the transport handed up a second head on one stream",
        ));
    }
    let mut status = None;
    let mut declared_len = None;
    for record in Records::new(records) {
        let record =
            record.map_err(|_| NativeFailure::at(stage::FRAMER, "a malformed head record"))?;
        match record.tag {
            tag::H_STATUS => {
                status = Some(
                    record
                        .pod::<U32Rec>()
                        .map_err(|_| NativeFailure::at(stage::FRAMER, "a malformed status"))?
                        .value,
                );
            }
            tag::PAIR => {
                let (name, value) = record
                    .pair()
                    .map_err(|_| NativeFailure::at(stage::FRAMER, "a malformed head field"))?;
                if name.eq_ignore_ascii_case("content-length") {
                    declared_len = std::str::from_utf8(value)
                        .ok()
                        .and_then(|v| v.trim().parse::<u64>().ok());
                }
            }
            _ => {}
        }
    }
    Ok(Inbound::Head {
        status,
        declared_len,
        block: field_block(records)?,
    })
}

/// The PAIR records of `records` as one field block, `name: value\r\n` per field, hop-by-hop fields (and those
/// a `connection` field nominates) dropped. Sized once.
fn field_block(records: &[u8]) -> Result<SecureVec, NativeFailure> {
    let malformed = |_| NativeFailure::at(stage::FRAMER, "a malformed head field");
    let pairs = || {
        Records::new(records).filter_map(|record| match record {
            Ok(record) if record.tag == tag::PAIR => Some(record.pair()),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
    };
    let mut nominated: Vec<&[u8]> = Vec::new();
    for pair in pairs() {
        let (name, value) = pair.map_err(malformed)?;
        if name.eq_ignore_ascii_case("connection") {
            nominated.push(value);
        }
    }
    let kept = |name: &str| {
        let lower = name.to_ascii_lowercase();
        !HOP_BY_HOP.contains(&lower.as_str())
            && !nominated.iter().any(|list| {
                list.split(|b| *b == b',')
                    .any(|n| n.trim_ascii().eq_ignore_ascii_case(lower.as_bytes()))
            })
    };
    let mut size = 0_usize;
    for pair in pairs() {
        let (name, value) = pair.map_err(malformed)?;
        if kept(name) {
            size = size.saturating_add(name.len() + SEPARATOR.len() + value.len() + LINE_END.len());
        }
    }
    let mut block = SecureVec::with_capacity(size)
        .map_err(|_| NativeFailure::at(stage::FRAMER, "head buffer"))?;
    for pair in pairs() {
        let (name, value) = pair.map_err(malformed)?;
        if kept(name) {
            block.extend_from_slice(name.as_bytes());
            block.extend_from_slice(SEPARATOR);
            block.extend_from_slice(value);
            block.extend_from_slice(LINE_END);
        }
    }
    Ok(block)
}

/// The far end's `retry-after`, in seconds: a number of them, or a date (RFC 9110 section 10.2.3; v1.5.5
/// honoured both). The wall clock is read once, and only for a date.
fn retry_after(block: &[u8]) -> Option<u64> {
    block
        .split(|b| *b == b'\n')
        .filter_map(|line| {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            let at = line.windows(SEPARATOR.len()).position(|w| w == SEPARATOR)?;
            Some((&line[..at], &line[at + SEPARATOR.len()..]))
        })
        .find(|(name, _)| name.eq_ignore_ascii_case(b"retry-after"))
        .and_then(|(_, value)| {
            let text = std::str::from_utf8(value).ok()?.trim();
            text.parse().ok().or_else(|| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs();
                crate::outbound::retry_after::seconds(text, now)
            })
        })
}

/// Core's class of an HTTP status (the fee decision's leg): 2xx success, 4xx the caller's, 5xx the far end's.
fn class_of(status: u32) -> WireStatusClass {
    match status {
        200..=299 => WireStatusClass::Success,
        400..=499 => WireStatusClass::CallerFault,
        500..=599 => WireStatusClass::FarEndFault,
        _ => WireStatusClass::Other,
    }
}

/// Core's breaker reading of an HTTP status: the table the HTTP transport stated on the old path, now core's.
fn fault_of(status: u32) -> Option<WireFault> {
    match status {
        401 | 403 => Some(WireFault::Hard),
        408 | 500..=599 => Some(WireFault::Transient),
        429 => Some(WireFault::RateLimit),
        400..=499 => Some(WireFault::Caller),
        _ => None,
    }
}

fn plain_piece(kind: PieceKind, stream: StreamId, len: usize, end: bool) -> Piece {
    Piece {
        kind,
        stream,
        len,
        end,
        status: None,
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}
