// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NATIVE DIAL ON THE OUTBOUND PARTS: the four places where [`NativeConnection`] meets
//! [`crate::outbound`]. Each function here replaces a named block of `native_dial.rs`; the dial
//! keeps its socket, its TLS session to the target and its socket queue, and decides nothing
//! itself about delivery, sealing, credit, the proxy or which address is tried.
//!
//! NOT YET DECLARED: `native_dial.rs` gains `#[path = "native_dial/drive.rs"] mod drive;` in the
//! same change that gives `NativeConnection` the fields listed below and switches the four call
//! sites. Until then the crate builds without this file.
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
//! Fields it loses: `fallback` (the race holds the addresses), `agreed`'s use in `multiplexes()`
//! (the session states it), `paused` (transport 2.0 has no PAUSE/RESUME), and the two constants
//! `WRITE_HELD_MAX` / `INBOX_HELD_MAX` as bounds of a multiplexed session (the windows are).

use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::records::{record_size, Fixed, Writer};

use super::{sleep_for, stage, NativeConnection, NativeFailure, NativeHead, Phase};
use crate::framed_stream::session::Act;
use crate::outbound::connect::{Lane, Step as RaceStep};
use crate::outbound::delivery::Reason;
use crate::outbound::records::{Out, StreamReset, WireEnd, WirePart};
use crate::outbound::redial::Ended;
use crate::outbound::seal::{Place, Slots};
use crate::outbound::tunnel::{ProxyFailure, Step, CAUSE_PROXY};
use crate::outbound::wire::{Fault, Outcome};

/// The head vocabulary's sealed records (the contract's `vocab::H_SEALED_PAIR` and
/// `vocab::H_SEALED_QUERY`, with `vocab::SealedPairRec`): replaced by the contract's own names
/// when the contract crate is the dependency.
const H_SEALED_PAIR: u16 = 0x0027;
const H_SEALED_QUERY: u16 = 0x0028;

/// The fixed part of a sealed head record: the name's length and the value's length. Its tail is
/// the name. No value bytes, ever.
#[repr(C)]
#[derive(Clone, Copy)]
struct SealedPairRec {
    name_len: u32,
    len: u32,
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
pub(super) fn ended_of(failure: &NativeFailure, far_end: Option<Ended>, began: bool) -> Ended {
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
                    return Err(NativeFailure::at(stage::CONNECT, error.to_string()));
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

    /// CALLED in `fail` and in `Drop`: every open request's verdict is frozen and every sealed
    /// value wiped.
    pub(super) fn outbound_gone(&mut self, reason: Reason) {
        self.wire.gone(reason);
        self.tunnelled.clear();
        self.handed_back = None;
    }

    /// The sealed values a `STREAM_BUSY` handed back, for the exchange to offer elsewhere.
    pub(super) fn take_handed_back(&mut self) -> Option<Slots> {
        self.handed_back.take()
    }

    /// REPLACES the body of `poll_send_head` between `begin_session` and the `emit(0, E_HEAD)`:
    /// the head's sealed values leave its fields, the plaintext rule is applied before any byte
    /// exists outside the engine, the records are written (pairs, then the sealed records, then
    /// the engine's own two), and the slots are offered to the driver. `destination_accepts` =
    /// the route's own judged acceptance or an exact per-destination entry, never the app-wide
    /// acceptance.
    ///
    /// # Errors
    /// A refusal that is the engine's own (`outbound`): unreadable sealing metadata, or a sealed
    /// value that would cross a connection in the clear. Nothing was emitted.
    pub(super) fn seal_and_encode(
        &mut self,
        head: &mut NativeHead,
        destination_accepts: bool,
    ) -> Result<SecureVec, NativeFailure> {
        if self.located.carrier == busbar_plugin_abi::plane::CARRIER_WEBSOCKET {
            crate::outbound::ws::drop_handshake_lines(&mut head.fields);
        }
        let slots = Slots::take_from(&mut head.fields).map_err(NativeFailure::outbound)?;
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
    pub(super) fn session_multiplexes(&self) -> bool {
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
