// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NATIVE DIAL ON THE OUTBOUND PARTS: the four places where [`NativeConnection`] meets
//! [`crate::outbound`]. Each function here replaces a named block of `native_dial.rs`; the dial
//! keeps its socket, its TLS session to the target and its socket queue, and decides nothing
//! itself about delivery, sealing, credit, the proxy or which address is tried.
//!
//! DECLARED by `native_dial.rs`, which is switched to these functions. What the one compile will
//! ask of other lines is the last paragraph of this comment (the session adapter's `Act` and
//! `TransportConn::consumed`).
//!
//! Fields `NativeConnection` gains (all made by `dial`, none before it):
//!
//! ```text
//! dialling: Dialling,                 // tunnel::Dialling::direct(..) or ::through(..)
//! wire: Wire,                         // Wire::new(Role::Attempt)
//! race: Race,                         // connect::Race::new(&[addr, also..], 0, open_timeout)
//! first_live: bool,                   // the first lane's socket (`sock`) is in flight
//! second: Option<(Registered<TcpStream>, SocketAddr)>,   // the other family's socket
//! race_timer: Option<Pin<Box<tokio::time::Sleep>>>,      // the race's next wake
//! started: Instant,                   // the race's time zero
//! last_connect_error: Option<io::Error>,
//! tunnelled: SecureVec,               // bytes the proxy sent past its answer's head
//! handed_back: Option<Slots>,         // sealed values a STREAM_BUSY returned
//! ```
//!
//! `NativeDial` gains `tunnel: Option<Tunnel>`; `NativeHead` gains `sealed_in_clear: bool` (the
//! destination's own plaintext acceptance, `Connector::sealed_in_clear`), passed to
//! `seal_and_encode` as `destination_accepts`; `Act` gains the transport 2.0 variants `out_of`
//! reads (`Session`, `Busy`, `NoNewStreams`, `WireSealed`, and `WireEnd { stream, how, arg }`,
//! `Reset { stream, code, flags }`, `WirePart { class: u32, .. }`), which the session adapter makes
//! with `crate::outbound::records::decode`; `TransportConn` gains
//! `consumed(stream, count, now)` = `emit(stream, E_CONSUMED)` with the count in `credit`.
//!
//! Fields it loses: `fallback` (the race holds the addresses), `agreed`'s use in `multiplexes()`
//! (the session states it), `paused` (transport 2.0 has no PAUSE/RESUME), and the two constants
//! `WRITE_HELD_MAX` / `INBOX_HELD_MAX` as bounds of a multiplexed session (the windows are).

use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::records::tag::{H_SEALED_PAIR, H_SEALED_QUERY};
use busbar_plugin_abi::records::{record_size, Fixed, Writer};
// The head vocabulary's sealed record (contract: `vocab::head1`): the name's length and the value's
// length, then the name. No value bytes, ever.
use busbar_plugin_abi::transport as wire;
use busbar_plugin_abi::vocab::head1::SealedPairRec;

use super::{sleep_for, stage, NativeConnection, NativeFailure, NativeHead, Phase};
use crate::framed_stream::session::Act;
use crate::outbound::connect::{Lane, Step as RaceStep};
use crate::outbound::delivery::Reason;
use crate::outbound::records::{Out, StreamReset, WireEnd, WirePart};
use crate::outbound::redial::Ended;
use crate::outbound::seal::{Place, Slots};
use crate::outbound::tunnel::{ProxyFailure, Step, CAUSE_PROXY};
use crate::outbound::wire::{Fault, Outcome};

/// A DIAL THROUGH THE OPERATOR'S PROXY: the new `NativeDial::tunnel` (`None` = straight to the
/// target). `native_dial.rs` re-exports it (`pub use drive::Tunnel;`). The socket connects to the
/// proxy (`NativeDial::addr` and `also` are then the proxy's judged addresses); TLS to the target,
/// inside the tunnel, still names the target.
pub struct Tunnel {
    hop: std::sync::Arc<crate::proxy_route::ProxyHop>,
    target: crate::outbound::tunnel::Target,
    trust: Option<std::sync::Arc<rustls::ClientConfig>>,
}

impl Tunnel {
    /// The CONNECT names the target's judged address (the engine resolved the name: the
    /// standard). `trust` = the client TLS settings for the proxy's own host, read only when the
    /// proxy is reached over TLS.
    #[must_use]
    pub fn to_address(
        hop: std::sync::Arc<crate::proxy_route::ProxyHop>,
        target: SocketAddr,
        trust: Option<std::sync::Arc<rustls::ClientConfig>>,
    ) -> Self {
        Self::planned(hop, crate::outbound::tunnel::Target::Addr(target), trust)
    }

    /// The CONNECT names the target by name (`outbound.proxy_resolution: proxy`, the operator's
    /// deliberate choice).
    #[must_use]
    pub fn to_name(
        hop: std::sync::Arc<crate::proxy_route::ProxyHop>,
        authority: &str,
        trust: Option<std::sync::Arc<rustls::ClientConfig>>,
    ) -> Self {
        Self::planned(
            hop,
            crate::outbound::tunnel::Target::Name(authority.to_owned()),
            trust,
        )
    }

    pub(crate) fn planned(
        hop: std::sync::Arc<crate::proxy_route::ProxyHop>,
        target: crate::outbound::tunnel::Target,
        trust: Option<std::sync::Arc<rustls::ClientConfig>>,
    ) -> Self {
        Self { hop, target, trust }
    }
}

/// CALLED by `NativeConnection::dial` to make the connection's `dialling` field from
/// `NativeDial::tunnel`.
///
/// # Errors
/// A proxy reached over TLS with no trust to verify it by, or its name is not a server name:
/// stage `CAUSE_PROXY`, before any socket.
pub(super) fn dialling_for(
    tunnel: Option<Tunnel>,
    secure_target: bool,
) -> Result<crate::outbound::tunnel::Dialling, NativeFailure> {
    match tunnel {
        None => Ok(crate::outbound::tunnel::Dialling::direct(secure_target)),
        Some(Tunnel { hop, target, trust }) => {
            crate::outbound::tunnel::Dialling::through(hop, target, secure_target, trust.as_ref())
                .map_err(proxy_failure)
        }
    }
}

/// A failure at the operator's proxy, as the dial reports it: its own stage, never `outbound`.
pub(super) fn proxy_failure(failure: ProxyFailure) -> NativeFailure {
    NativeFailure::at(CAUSE_PROXY, failure.0)
}

/// A fault of the transport's answer, in words for the cause (no value, no length of a value).
fn fault_text(fault: Fault) -> String {
    match fault {
        Fault::Output(breach) => format!(
            "the transport broke rule {} of its output and was charged",
            breach.rule()
        ),
        Fault::Sealed(breach) => {
            format!("the transport broke the sealed-value grammar ({breach:?}) and was charged")
        }
        Fault::Window(overrun) => {
            format!("the transport overran a window it stated ({overrun:?}) and was charged")
        }
        Fault::Order(what) => format!("the transport's answer is out of order ({what})"),
        Fault::Queue => "the write buffer refused the transport's output".to_owned(),
    }
}

/// How a failed attempt ended, for [`crate::outbound::redial::decide`]: read from the failure's
/// stage, and from the far end's own reset where there was one. `began` = the transport's session
/// had begun on this connection (a failure before that is the dial's).
pub(crate) fn ended_of(failure: &NativeFailure, far_end: Option<Ended>, began: bool) -> Ended {
    if failure.cause.outbound {
        return Ended::Local;
    }
    match failure.cause.stage {
        CAUSE_PROXY => Ended::Proxy,
        stage::DEADLINE if began => Ended::Deadline,
        stage::CONNECT | stage::SECURITY | stage::DEADLINE if !began => Ended::Dial,
        _ => far_end.unwrap_or(Ended::Connection),
    }
}

/// One item of the session's answer as the outbound driver reads it, and where its bytes are.
/// Inbound heads, trailers, timers and flow records are not the driver's: the dial's own arms
/// keep them.
fn out_of(act: &Act) -> Option<(Out, Option<crate::framed_stream::session::Span>)> {
    Some(match act {
        Act::Session(session) => (Out::Session(*session), None),
        Act::Opened(stream) => (Out::Opened(*stream), None),
        Act::Busy => (Out::Busy, None),
        Act::NoNewStreams => (Out::NoNewStreams, None),
        Act::WirePart {
            stream,
            class,
            bytes,
        } => (
            Out::Part {
                part: WirePart {
                    stream: *stream,
                    class: *class,
                    _r: 0,
                },
                len: bytes.len() as u32,
            },
            Some(*bytes),
        ),
        Act::WireSealed(sealed) => (Out::Sealed(*sealed), None),
        Act::WireEnd { stream, how, arg } => (
            Out::End(WireEnd {
                stream: *stream,
                how: *how,
                arg: *arg,
            }),
            None,
        ),
        Act::Body { stream, bytes, .. } => (
            Out::Body {
                stream: *stream,
                len: bytes.len() as u32,
            },
            None,
        ),
        Act::End(stream) => (Out::Ended(*stream), None),
        Act::Reset {
            stream,
            code,
            flags,
        } => (
            Out::Reset(StreamReset {
                stream: *stream,
                code: *code,
                flags: *flags,
            }),
            None,
        ),
        Act::Close { .. } => (Out::Close, None),
        _ => return None,
    })
}

impl NativeConnection {
    /// The race's clock: nanoseconds since the dial began. One reading per call.
    fn race_now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// Begin the connect the race asked for. A socket the system refuses at once is the race's
    /// failure like any other.
    fn begin_connect(&mut self, lane: Lane, addr: SocketAddr, now: u64) {
        match crate::socket::connect(addr).and_then(crate::io::register) {
            Ok(sock) => match lane {
                Lane::First => {
                    self.sock = sock;
                    self.peer = addr;
                    self.first_live = true;
                }
                Lane::Second => self.second = Some((sock, addr)),
            },
            Err(error) => {
                self.last_connect_error = Some(error);
                self.race.failed(lane, now);
            }
        }
    }

    /// REPLACES the `Phase::Connecting` block of `progress_inner` (the `poll_connected` match and
    /// its fallback): the race over the name's addresses, then the first step below the session.
    /// Returns with `self.phase` moved on when a socket connected.
    pub(super) fn progress_connect(&mut self, cx: &mut Context<'_>) -> Result<(), NativeFailure> {
        if self.phase != Phase::Connecting || self.dialling.step() != Step::Connecting {
            return Ok(());
        }
        let now = self.race_now();
        let mut won = None;
        if self.first_live {
            match crate::socket::poll_connected(&self.sock, cx) {
                Poll::Pending => {}
                Poll::Ready(Ok(())) => won = Some(Lane::First),
                Poll::Ready(Err(error)) => {
                    self.first_live = false;
                    self.last_connect_error = Some(error);
                    self.race.failed(Lane::First, now);
                }
            }
        }
        if won.is_none() {
            if let Some((sock, _)) = self.second.as_ref() {
                match crate::socket::poll_connected(sock, cx) {
                    Poll::Pending => {}
                    Poll::Ready(Ok(())) => won = Some(Lane::Second),
                    Poll::Ready(Err(error)) => {
                        self.second = None;
                        self.last_connect_error = Some(error);
                        self.race.failed(Lane::Second, now);
                    }
                }
            }
        }
        if let Some(lane) = won {
            if lane == Lane::Second {
                if let Some((sock, addr)) = self.second.take() {
                    // The first lane's socket is closed by the drop.
                    self.sock = sock;
                    self.peer = addr;
                }
            }
            // The other lane's socket, if any, is closed by the drop.
            let _loser = self.race.connected(lane);
            self.second = None;
            self.first_live = false;
            self.race_timer = None;
            let step = self
                .dialling
                .connected(&mut self.out)
                .map_err(proxy_failure)?;
            self.phase = match step {
                Step::Open => {
                    self.open_deadline = None;
                    Phase::Open
                }
                Step::Handshaking => Phase::Handshaking,
                // The proxy's steps run while the dial is still, to its caller, connecting.
                Step::Connecting | Step::ProxyHandshake | Step::Tunnelling => Phase::Connecting,
            };
            return Ok(());
        }
        loop {
            match self.race.step(now) {
                RaceStep::Connect(lane, addr) => {
                    if lane == Lane::First {
                        self.first_live = false;
                    } else {
                        self.second = None;
                    }
                    self.begin_connect(lane, addr, now);
                    // The new socket has no waker yet: poll again at once.
                    cx.waker().wake_by_ref();
                }
                RaceStep::Wait(at) => {
                    let mut timer = sleep_for(Duration::from_nanos(at.saturating_sub(now)));
                    // Registers this task for the race's next wake.
                    let _ = std::future::Future::poll(timer.as_mut(), cx);
                    self.race_timer = Some(timer);
                    return Ok(());
                }
                RaceStep::Failed => {
                    let error = self
                        .last_connect_error
                        .take()
                        .unwrap_or_else(|| io::Error::other("no address answered the connect"));
                    // Through a proxy the addresses are the proxy's: the failure is the proxy's, and no
                    // provider is charged for it.
                    let stage = if self.dialling.tunnelled() {
                        CAUSE_PROXY
                    } else {
                        stage::CONNECT
                    };
                    return Err(NativeFailure::at(stage, error.to_string()));
                }
            }
        }
    }

    /// CALLED FIRST in `feed`, with the bytes the socket read: the steps below the session take
    /// them while the tunnel is being made, and a tunnel through a TLS proxy unwraps every later
    /// read. Returns the bytes for the layer above (the target's TLS, or the transport): `None` =
    /// `bytes` itself, unchanged.
    pub(super) fn below_session(
        &mut self,
        bytes: &[u8],
    ) -> Result<Option<SecureVec>, NativeFailure> {
        match self.dialling.step() {
            Step::ProxyHandshake | Step::Tunnelling => {
                let mut inner = std::mem::take(&mut self.tunnelled);
                let step = self
                    .dialling
                    .feed(bytes, &mut self.out, &mut inner)
                    .map_err(proxy_failure)?;
                match step {
                    Step::Handshaking => self.phase = Phase::Handshaking,
                    Step::Open => {
                        self.open_deadline = None;
                        self.phase = Phase::Open;
                    }
                    Step::Connecting | Step::ProxyHandshake | Step::Tunnelling => {}
                }
                // What the proxy sent past its answer's head is the tunnel's first bytes.
                Ok(Some(inner))
            }
            Step::Connecting | Step::Handshaking | Step::Open if self.dialling.wraps() => {
                let mut inner = SecureVec::new();
                self.dialling
                    .from_socket(bytes, &mut self.out, &mut inner)
                    .map_err(proxy_failure)?;
                Ok(Some(inner))
            }
            Step::Connecting | Step::Handshaking | Step::Open => Ok(None),
        }
    }

    /// REPLACES, in `apply_last`, the arms `Write`, `WirePart`, `WireEnd`, `Abort`, `Quiescent`,
    /// `Close`, `Opened`, `Pause` and `Resume`: the whole answer goes through the outbound driver
    /// first (checked, then queued for the socket as one run with the sealed values in place);
    /// `apply_last` then runs its inbound arms (`Head`, `Body`, `Trailers`, `End`, `Reset`,
    /// `Wake`, `Upgrade`, `Full`, `Writable`) exactly as before.
    pub(super) fn apply_outbound(&mut self) -> Result<Outcome, NativeFailure> {
        let Self {
            session,
            tls,
            out,
            wire,
            dialling,
            flushed,
            closing,
            handed_back,
            ..
        } = self;
        let Some(session) = session.as_mut() else {
            return Ok(Outcome::default());
        };
        let acts = session.actions();
        let mut items: smallvec::SmallVec<[Out; 16]> = smallvec::SmallVec::new();
        let mut spans: smallvec::SmallVec<[Option<crate::framed_stream::session::Span>; 16]> =
            smallvec::SmallVec::new();
        for act in acts.iter() {
            if let Some((item, span)) = out_of(act) {
                items.push(item);
                spans.push(span);
            }
        }
        let answered = wire.answer(
            &items,
            |index| spans[index].map_or(&[][..], |span| acts.bytes(span)),
            tls.as_mut(),
            dialling,
            out,
            *flushed,
        );
        let mut outcome = match answered {
            Ok(outcome) => outcome,
            Err(fault) => {
                if fault.charged() {
                    wire.faulted();
                } else {
                    wire.gone(Reason::CallerGone);
                }
                return Err(NativeFailure::at(stage::FRAMER, fault_text(fault)));
            }
        };
        if outcome.closing {
            *closing = true;
        }
        if let Some(slots) = outcome.busy.take() {
            // Kept for the exchange: it offers the same head on another connection.
            *handed_back = Some(slots);
            outcome.busy = Some(Slots::default());
        }
        Ok(outcome)
    }

    /// CALLED in `write_ready` after the socket took bytes (`self.flushed` moved): the delivery
    /// ledger learns what the operating system accepted.
    pub(super) fn socket_took(&mut self) {
        // `flushed` counts what the socket took; what is still queued is not accepted.
        self.wire.accepted(self.flushed);
    }

    /// The open deadline passed. While the proxy's own steps were still running (its connect, its TLS, its
    /// answer to the CONNECT) the failure is the proxy's; after the tunnel is open it is the target's.
    pub(super) fn open_deadline_passed(&self) -> NativeFailure {
        let at_proxy = self.dialling.tunnelled()
            && matches!(
                self.dialling.step(),
                Step::Connecting | Step::ProxyHandshake | Step::Tunnelling
            );
        if at_proxy {
            NativeFailure::at(
                CAUSE_PROXY,
                "the proxy did not open the tunnel before the open deadline",
            )
        } else {
            NativeFailure::at(stage::DEADLINE, "the connection's open deadline passed")
        }
    }

    /// The socket has not connected yet (the race over the name's addresses is still running): nothing is
    /// read or written.
    pub(super) fn socket_connecting(&self) -> bool {
        self.dialling.step() == Step::Connecting
    }

    /// The target's TLS records that no run carries (its handshake, its close), queued for the socket
    /// through the proxy's layer where there is one. Nothing is written before the tunnel under the
    /// target's TLS is open.
    pub(super) fn drain_target(&mut self) -> Result<(), NativeFailure> {
        if !matches!(self.dialling.step(), Step::Handshaking | Step::Open) {
            return Ok(());
        }
        let Some(tls) = self.tls.as_mut() else {
            return Ok(());
        };
        self.dialling
            .drain_target(tls, &mut self.out)
            .map_err(|error| NativeFailure::at(stage::SECURITY, error.to_string()))
    }

    /// CALLED in `fail`: the delivery verdict of every open request is frozen with the reason the
    /// connection failed for. The sealed values stay for the exchanges that may send again.
    pub(super) fn wire_failed(&mut self, failure: &NativeFailure) {
        let reason = if failure.cause.stage == stage::DEADLINE {
            Reason::Deadline
        } else {
            Reason::CallerGone
        };
        self.wire.failed(reason);
    }

    /// CALLED in `poll_read` when the reader took `len` body bytes of `stream`: on a multiplexed
    /// session, the credit that reopens the stream's window, given as `emit(stream, E_CONSUMED)`.
    pub(super) fn give_credit(&mut self, stream: u64, len: usize) -> Result<(), NativeFailure> {
        let Some(count) = self.reader_took(stream, len) else {
            return Ok(());
        };
        let Some(session) = self.session.as_mut().filter(|session| session.is_live()) else {
            return Ok(());
        };
        session
            .consumed(stream, count, std::time::Instant::now())
            .map_err(|ended| super::session_failure(&ended))?;
        self.apply_outbound().map(|_| ())
    }

    /// CALLED in `fail` and in `Drop`: every open request's verdict is frozen and every sealed
    /// value wiped.
    pub(super) fn outbound_gone(&mut self, reason: Reason) {
        self.wire.gone(reason);
        self.tunnelled.clear();
        self.handed_back = None;
    }

    /// The sealed values a `STREAM_BUSY` handed back, for the exchange to offer elsewhere.
    pub(crate) fn take_handed_back(&mut self) -> Option<Slots> {
        self.handed_back.take()
    }

    /// REPLACES the body of `poll_send_head` between `begin_session` and the `emit(0, E_HEAD)`:
    /// the head's sealed values leave its fields, the plaintext rule is applied before any byte
    /// exists outside the engine, the records are written (pairs, then the sealed records, then
    /// the engine's own two), and the slots are offered to the driver. `destination_accepts` =
    /// the route's own judged acceptance or an exact per-destination entry, never the app-wide
    /// acceptance.
    ///
    /// `handed_back` = the sealed values of this same head, returned by a `STREAM_BUSY` or by a
    /// failed attempt that is being sent again: the head's fields no longer hold them, so they
    /// are offered as they are and nothing is taken from the fields a second time.
    ///
    /// # Errors
    /// A refusal that is the engine's own (`outbound`): unreadable sealing metadata, or a sealed
    /// value that would cross a connection in the clear. Nothing was emitted.
    pub(super) fn seal_and_encode(
        &mut self,
        head: &mut NativeHead,
        handed_back: Option<Slots>,
        destination_accepts: bool,
    ) -> Result<SecureVec, NativeFailure> {
        if self.located.carrier == busbar_plugin_abi::plane::CARRIER_WEBSOCKET {
            crate::outbound::ws::drop_handshake_lines(&mut head.fields);
        }
        let slots = match handed_back {
            Some(slots) => slots,
            None => Slots::take_from(&mut head.fields).map_err(NativeFailure::outbound)?,
        };
        slots
            .admit(self.tls.is_some(), destination_accepts)
            .map_err(NativeFailure::outbound)?;
        let records = self.head_records_with(head, &slots)?;
        self.wire.offer(slots);
        Ok(records)
    }

    /// `head_records` with the sealed records: the existing sizing and writing, plus one
    /// `H_SEALED_PAIR` or `H_SEALED_QUERY` per slot, in slot order, after the pairs and before
    /// `H_BODY_LEN` / `H_BUDGET_NS`.
    fn head_records_with(
        &self,
        head: &NativeHead,
        slots: &Slots,
    ) -> Result<SecureVec, NativeFailure> {
        let plain = self.head_records(head)?;
        if slots.is_empty() {
            return Ok(plain);
        }
        let fixed = std::mem::size_of::<SealedPairRec>();
        let mut extent = Some(plain.len());
        for declared in slots.declared() {
            extent = extent.and_then(|sum| {
                record_size(fixed + declared.name.len()).and_then(|n| sum.checked_add(n))
            });
        }
        let extent = extent
            .ok_or_else(|| NativeFailure::outbound("the request head is too large to encode"))?;
        // The engine's own two records (`H_BODY_LEN`, `H_BUDGET_NS`) end the head: the sealed
        // records go before them. `head_records` wrote them last, so the head is re-encoded with
        // the sealed records in their place.
        let tail = self.own_records_len(head)?;
        let pairs_end = plain.len() - tail;
        let mut records = SecureVec::zeroed(extent);
        records[..pairs_end].copy_from_slice(&plain[..pairs_end]);
        let written = {
            let mut writer = Fixed::new(&mut records[pairs_end..extent - tail]);
            for declared in slots.declared() {
                let rec = SealedPairRec {
                    name_len: declared.name.len() as u32,
                    len: declared.len,
                };
                let tag = match declared.place {
                    Place::Header => H_SEALED_PAIR,
                    Place::Query => H_SEALED_QUERY,
                };
                writer
                    .put_pod_tail(tag, &rec, declared.name.as_bytes())
                    .map_err(|_| {
                        NativeFailure::outbound("the request head did not fit its own size")
                    })?;
            }
            writer.len()
        };
        let sealed_end = pairs_end + written;
        records[sealed_end..sealed_end + tail].copy_from_slice(&plain[pairs_end..]);
        records.truncate(sealed_end + tail);
        Ok(records)
    }

    /// The encoded length of the engine's own trailing records of `head` (`H_BODY_LEN`,
    /// `H_BUDGET_NS`), as `head_records` writes them.
    fn own_records_len(&self, head: &NativeHead) -> Result<usize, NativeFailure> {
        let pod = record_size(std::mem::size_of::<busbar_plugin_abi::records::U64Rec>())
            .ok_or_else(|| NativeFailure::outbound("the request head is too large to encode"))?;
        Ok(pod * (usize::from(head.body_len.is_some()) + usize::from(head.budget.is_some())))
    }

    /// REPLACES `multiplexes()`: the session's own statement, never the protocol's name.
    pub(crate) fn session_multiplexes(&self) -> bool {
        self.wire.in_use().shares()
    }

    /// REPLACES `reusable()`: live, no stream open, nothing queued, and the session has said
    /// neither `CLOSE` nor `NO_NEW_STREAMS`. A WebSocket connection is never kept.
    pub(super) fn session_reusable(&self) -> bool {
        self.live()
            && self.phase == Phase::Open
            && self.out.is_empty()
            && self.wire.in_use().idle()
            && self.located.carrier != busbar_plugin_abi::plane::CARRIER_WEBSOCKET
    }

    /// REPLACES the `self.inbox_held() >= INBOX_HELD_MAX` and `self.paused` tests of
    /// `read_ready`: the session's windows decide, or for a session with one stream, its reader.
    pub(super) fn reads_socket(&self) -> bool {
        self.wire.reads_socket()
    }

    /// REPLACES `WRITE_HELD_MAX - self.out.len()` in `poll_send_body`: how many body bytes may be
    /// emitted on `stream` now.
    pub(super) fn body_room(&self, stream: u64) -> usize {
        usize::try_from(
            self.wire
                .write_room(stream, self.flushed, self.out.len() as u64),
        )
        .unwrap_or(usize::MAX)
    }

    /// CALLED by `take_piece` when the reader took `len` body bytes of `stream`: the credit to
    /// give the transport, emitted as `CONSUMED` by the caller (`emit(stream, E_CONSUMED)` with
    /// the count in the call's `credit`).
    pub(super) fn reader_took(&mut self, stream: u64, len: usize) -> Option<u64> {
        self.wire.taken(stream, len as u64)
    }

    /// The delivery state of `stream`'s request as the record words it: `none`, `part` or `whole`.
    #[must_use]
    pub fn sent_word(&self, stream: u64) -> &'static str {
        self.wire.state_of(stream).as_str()
    }

    /// How much of `stream`'s request the operating system accepted, as it stands.
    pub(crate) fn sent_state(&self, stream: u64) -> crate::outbound::delivery::State {
        self.wire.state_of(stream)
    }

    /// How the far end itself ended `stream`, where it said so (a reset, with or without its
    /// statement that it did not act on the stream).
    pub(crate) fn far_end_ended(&self, stream: u64) -> Option<Ended> {
        self.wire.ended_how(stream)
    }

    /// What the connection has said about taking streams (`crate::outbound::lend::choose` reads it).
    pub(crate) fn lending(&self) -> crate::outbound::lend::InUse {
        self.wire.in_use()
    }

    /// A piece of `stream` is waiting for its reader.
    pub(crate) fn has_piece(&self, stream: u64) -> bool {
        self.take_piece_ready(stream)
    }

    /// The transport's session has begun on this connection.
    pub(crate) fn session_began(&self) -> bool {
        self.session.is_some()
    }

    /// The answer's head of `stream` was handed up.
    pub(crate) fn answered(&self, stream: u64) -> bool {
        self.streams
            .iter()
            .any(|one| one.id == stream && one.answered)
    }

    /// The engine can no longer send `stream`'s head again: its sealed values are wiped now.
    pub(crate) fn release_head(&mut self, stream: u64) {
        self.wire.release_head(stream);
    }

    /// The engine is done with `stream` on this connection. With `resend`, its sealed values come
    /// back rewound for the next head; the credit the stream still owed is given to the transport
    /// so the connection's window is not left closed behind it. REPLACES the bookkeeping half of
    /// `finish` and `reset` (which keep their `emit(E_RESET)` and their `streams` removal).
    pub(crate) fn stream_over(&mut self, stream: u64, resend: bool) -> Option<Slots> {
        let (slots, credit) = self.wire.over(stream, resend);
        if let Some(count) = credit {
            if let Some(session) = self.session.as_mut().filter(|session| session.is_live()) {
                // `emit(stream, E_CONSUMED)` with `count` in the call's `credit`: nothing is
                // written for it but what the transport answers (a window update).
                if session
                    .consumed(stream, count, std::time::Instant::now())
                    .is_ok()
                {
                    let _ = self.apply_outbound();
                }
            }
        }
        slots
    }
}

/// MESSAGES ON A WEBSOCKET UPSTREAM (`native_conns/messages.rs` is the exchange's side).
impl NativeConnection {
    /// One piece of a message on `stream`: `emit(stream, E_BODY)` with the message's flags.
    /// Ready with the bytes taken (`0` while the stream is held or the socket queue is not
    /// drained: the wake comes with the next readiness). A message piece is taken whole or not
    /// at all, so a frame is never split by the engine.
    pub fn poll_send_message(
        &mut self,
        cx: &mut Context<'_>,
        stream: u64,
        bytes: &[u8],
        flags: u32,
    ) -> Poll<Result<usize, NativeFailure>> {
        if let Err(failure) = self.progress(cx) {
            return Poll::Ready(Err(failure));
        }
        let Some(at) = self.streams.iter().position(|one| one.id == stream) else {
            return Poll::Ready(Err(NativeFailure::outbound(
                "a message for a stream that is not open",
            )));
        };
        if self.streams[at].full || self.body_room(stream) < bytes.len() {
            return Poll::Pending;
        }
        self.wire.emitting_body(stream, bytes.len() as u64);
        if let Err(failure) = self.emit(stream, wire::E_BODY, flags, bytes) {
            return Poll::Ready(Err(self.fail(failure)));
        }
        if let Err(failure) = self.progress(cx) {
            return Poll::Ready(Err(failure));
        }
        Poll::Ready(Ok(bytes.len()))
    }

    /// The engine's close of the session on `stream`: `emit(stream, E_END)`. The transport writes
    /// its close frame; the session's delivery verdict is `whole` once that frame is accepted and
    /// flushed.
    pub fn poll_close_stream(
        &mut self,
        cx: &mut Context<'_>,
        stream: u64,
    ) -> Poll<Result<(), NativeFailure>> {
        if let Err(failure) = self.progress(cx) {
            return Poll::Ready(Err(failure));
        }
        self.wire.emitting_end(stream);
        if let Err(failure) = self.emit(stream, wire::E_END, 0, &[]) {
            return Poll::Ready(Err(self.fail(failure)));
        }
        match self.progress(cx) {
            Err(failure) => Poll::Ready(Err(failure)),
            Ok(_) => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::conn::ConnCause;

    fn failure(stage: u64, outbound: bool) -> NativeFailure {
        NativeFailure {
            cause: ConnCause {
                stage,
                text: String::new(),
                outbound,
            },
        }
    }

    #[test]
    fn a_failure_is_read_into_how_the_attempt_ended() {
        assert_eq!(
            ended_of(&failure(stage::FRAMER, true), None, true),
            Ended::Local
        );
        assert_eq!(
            ended_of(&failure(CAUSE_PROXY, false), None, false),
            Ended::Proxy
        );
        assert_eq!(
            ended_of(&failure(stage::CONNECT, false), None, false),
            Ended::Dial
        );
        assert_eq!(
            ended_of(&failure(stage::SECURITY, false), None, false),
            Ended::Dial
        );
        assert_eq!(
            ended_of(&failure(stage::DEADLINE, false), None, false),
            Ended::Dial
        );
        assert_eq!(
            ended_of(&failure(stage::DEADLINE, false), None, true),
            Ended::Deadline
        );
        assert_eq!(
            ended_of(&failure(stage::CONNECT, false), None, true),
            Ended::Connection,
            "a kept connection that turned out closed"
        );
        assert_eq!(
            ended_of(
                &failure(stage::FRAMER, false),
                Some(Ended::NotProcessed),
                true
            ),
            Ended::NotProcessed
        );
    }

    #[test]
    fn a_proxy_failure_has_its_own_stage_and_is_never_the_engines_own_head() {
        let failed = proxy_failure(ProxyFailure(
            "the proxy refused the tunnel (status 403)".into(),
        ));
        assert_eq!(failed.cause.stage, CAUSE_PROXY);
        assert!(!failed.cause.outbound);
    }

    #[test]
    fn a_fault_text_names_the_rule_and_no_value() {
        use crate::outbound::delivery::Breach;
        use crate::outbound::seal::SealBreach;
        assert!(fault_text(Fault::Output(Breach::L6)).contains("L6"));
        let sealed = fault_text(Fault::Sealed(SealBreach::Uncovered));
        assert!(sealed.contains("Uncovered"));
    }
}
