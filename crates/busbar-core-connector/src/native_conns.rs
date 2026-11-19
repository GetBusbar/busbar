// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTION TABLE'S SECOND KIND OF ENTRY: an exchange dialled natively (dial decision v2, deletion plan step
//! E2, half B; the seam `E2-SEAM.md` revision 2). The connection is a [`NativeConnection`] framed by the admitted
//! MIN-3 transport instance the root assigned the destination's carrier ([`Connector::carry_natively`]); nothing
//! here names the old framer interface.
//!
//! - A need whose scheme no old entry serves and core's scheme table dials is held as a [`NativeNeed`].
//! - Its open locates the target by the scheme table, holds it to the need's egress class, its trust and its sealed
//!   anchors exactly as a framed open is held, judges the address, and dials (or is lent an idle connection to the
//!   same key). The whole request (head and body) is handed to the connection; it is sent as the connection can.
//! - Its reads hand the connection's pieces up unchanged.
//! - Its close keeps the connection for the next exchange to the same key when the answer was read to its end and
//!   the connection is [`NativeConnection::reusable`]; otherwise it resets an unfinished stream and closes.
//!
//! MEMORY: nothing is made for an entry before its open; the entry keeps the request's head (wiped when sent) and
//! the body the opener lent (a shared reference, never a copy); it keeps no read buffer: every piece goes straight
//! from the connection into the caller's buffer. Reuse of an idle connection is HTTP keep-alive, bounded by the
//! deployment's `limits.pool_max_idle_per_host` (connections kept per key) and `limits.pool_idle_timeout_secs`
//! (how long one is kept), the same posture the framed pool holds ([`crate::pool::PoolPosture`]). An idle
//! connection holds its socket, its TLS state and its framer's session: no stream, nothing queued.
//!
//! LOCKS: no plugin code runs under a host lock. An entry's exchange is taken out of its slot for the call and put
//! back after it (a second caller in the meantime is told Pending and woken when it is back).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::conn::{ConnCause, ConnError, NeedRefusal, Piece, PieceKind};
use busbar_contract::storage::StorageSource;
use foldhash::{HashMap, HashMapExt as _};

use super::native_dial::{
    stage, Located, NativeCarrier, NativeConnection, NativeDial, NativeFailure, NativeHead,
};
use super::pool::{PoolKey, PoolPosture};
use super::{class_admits, Answer, Within};

// The open through the operator's proxy (the two judgements, the tunnelled dial).
#[path = "native_conns/route.rs"]
mod route;
// Sending a request again, from the evidence of what was sent of it.
#[path = "native_conns/again.rs"]
mod again;
// Messages on a WebSocket upstream.
#[path = "native_conns/messages.rs"]
mod messages;
// Many requests on one connection, owned by one core.
#[path = "native_conns/shared.rs"]
mod shared;

/// The carriers the root assigned at boot and the account every native dial's framer session is charged to.
pub(crate) struct Natives {
    pub(crate) carriers: Vec<NativeCarrier>,
    pub(crate) storage: StorageSource,
}

impl Natives {
    /// The instance that carries `carrier`, if the build assigned one.
    pub(crate) fn carrier(&self, carrier: u32) -> Option<&NativeCarrier> {
        self.carriers.iter().find(|one| one.carrier == carrier)
    }
}

/// What the connector holds for one need served natively: what its opens are held to, made once at declare and
/// shared by every open (an `Arc`).
pub(crate) struct NativeNeed {
    pub(crate) egress_class: u32,
    /// The target the need's `target_from` resolved to; `None` = the opener names it.
    pub(crate) declared_target: Option<Arc<str>>,
    /// The need's own client config (its operator CA on top of the public roots), else the connector's.
    pub(crate) tls: Option<Arc<rustls::ClientConfig>>,
    pub(crate) tls_policy: Option<busbar_contract::transport::trust::EgressTrust>,
}

/// Where a target goes, as a need's entry locates it.
pub(crate) struct Placed {
    /// `host:port`.
    pub(crate) authority: String,
    pub(crate) secure: bool,
}

/// A dial whose judgement pended: everything the dial needs once the address is known.
#[derive(Clone)]
pub(crate) struct PendingDial {
    pub(crate) carrier: NativeCarrier,
    pub(crate) located: Located,
    pub(crate) tls: Option<Arc<rustls::ClientConfig>>,
    pub(crate) anchors: Option<Arc<crate::tls::client::Sealed>>,
    pub(crate) open_timeout: Duration,
    pub(crate) egress_class: u32,
    /// Plaintext is admitted to the destination (the opener's core-held acceptance, or an exact
    /// `advanced.tls.destinations` entry).
    pub(crate) plain: bool,
    pub(crate) within: Within,
}

/// Where an entry's connection is.
pub(crate) enum State {
    /// The judge has not answered yet.
    Judging {
        answer: Answer,
        dial: PendingDial,
        /// The operator's proxy this dial goes through, with the judgement of the proxy's own host.
        via: Option<route::Via>,
    },
    Dialled(NativeConnection),
    /// A stream on a connection other exchanges on this core ride too (its session multiplexes).
    Shared(Arc<shared::Shared>),
    /// Failed or handed back.
    Gone,
}

/// The request still to be handed to the connection.
pub(crate) struct Sending {
    /// Taken (and wiped) when its records are encoded.
    pub(crate) head: Option<NativeHead>,
    /// The opener's body, shared with it (never copied here).
    pub(crate) body: busbar_contract::conn::Bytes,
    pub(crate) sent: usize,
}

/// One exchange on one native connection.
pub(crate) struct Exchange {
    pub(crate) state: State,
    pub(crate) sending: Option<Sending>,
    pub(crate) stream: Option<u64>,
    /// The answer's end was read: the connection may serve the next exchange.
    pub(crate) ended: bool,
    pub(crate) failed: Option<ConnError>,
    /// Why it failed, where a stage is known.
    pub(crate) cause: Option<ConnCause>,
    /// Where the connection goes back to when the exchange ended whole; `None` = it is never kept. Moved into the
    /// idle set with the connection (never copied).
    pub(crate) key: Option<PoolKey>,
    /// What it takes to dial this same request again; `None` once it can no longer be sent again.
    pub(crate) reopen: Option<again::Reopen>,
    /// The connection was lent (kept idle, or a stream on one in use), not dialled for this exchange.
    pub(crate) kept: bool,
    /// The one redial of this exchange is spent.
    pub(crate) redialled: bool,
    /// The connector must judge and dial again before the next poll (`Connector::redial_native`).
    pub(crate) resend: bool,
    /// Sealed values handed back for the next head (by a busy connection or a failed attempt).
    pub(crate) sealed: Option<crate::outbound::seal::Slots>,
    /// What is recorded of each attempt, in order.
    pub(crate) evidence: smallvec::SmallVec<[crate::outbound::redial::Recorded; 2]>,
    /// The final failure charges the provider's breaker.
    pub(crate) charge: bool,
    /// A WebSocket upstream's states; `None` for an HTTP exchange.
    pub(crate) ws: Option<crate::outbound::ws::Upstream>,
}

/// The exchange's slot in its entry: out while a call has it.
struct Slot {
    exchange: Option<Exchange>,
    out: bool,
    /// The calls that found it out, woken when it is back.
    missed: Vec<Waker>,
}

/// A native entry of the connection table, beside the framed one in [`super::Held`].
pub(crate) struct NativeHeld {
    slot: Mutex<Slot>,
    /// The core whose idle set the connection goes back to: the core the open ran on, which dialled it or was lent
    /// it from its own set.
    pub(crate) core: usize,
    /// The upstream is a WebSocket: a write after the open is a message.
    messages: bool,
}

impl NativeHeld {
    pub(crate) fn new(exchange: Exchange, core: usize) -> Self {
        Self {
            messages: exchange.ws.is_some(),
            slot: Mutex::new(Slot {
                exchange: Some(exchange),
                out: false,
                missed: Vec::new(),
            }),
            core,
        }
    }

    /// The upstream is a WebSocket: a write after the open is a message.
    pub(crate) fn carries_messages(&self) -> bool {
        self.messages
    }

    /// Take the exchange out for one call; `None` (with `waker` kept) while another call has it.
    pub(crate) fn begin(&self, waker: &Waker) -> Option<Exchange> {
        let incoming = waker.clone();
        let mut slot = self.slot.lock().expect("native slot");
        if slot.out {
            if !slot.missed.iter().any(|w| w.will_wake(waker)) {
                slot.missed.push(incoming);
            }
            return None;
        }
        let exchange = slot.exchange.take()?;
        slot.out = true;
        Some(exchange)
    }

    /// Put the exchange back and wake the calls that found it out, with no lock held.
    pub(crate) fn end(&self, exchange: Exchange) {
        let missed = {
            let mut slot = self
                .slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            slot.exchange = Some(exchange);
            slot.out = false;
            std::mem::take(&mut slot.missed)
        };
        for w in missed {
            w.wake();
        }
    }

    /// Whether the entry's next read will not pend, for a wait over several connections. While another call
    /// has the exchange out the answer is no, and `waker` is woken when it is back. An exchange that is not
    /// yet reading an answer (judging, dialling, sending) is named ready, as before: its read is what drives
    /// it, and that read pends with the waker kept.
    pub(crate) fn ready(&self, waker: &Waker) -> bool {
        let Some(mut exchange) = self.begin(waker) else {
            // Out with another call: not ready, and that call's end wakes `waker`. Gone for good (the entry
            // is closing): its read answers at once.
            let slot = self
                .slot
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return !slot.out;
        };
        let ready = exchange.read_ready(&mut Context::from_waker(waker));
        self.end(exchange);
        ready
    }

    /// The exchange for good (the entry is closing); `None` while a call has it out (that call's exchange is
    /// dropped with the entry).
    pub(crate) fn take(&self) -> Option<Exchange> {
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.exchange.take()
    }
}

/// The address a native dial goes to, judged: refused, or dialled now.
pub(crate) fn dial_at(
    dial: PendingDial,
    addr: std::net::SocketAddr,
    also: Vec<std::net::SocketAddr>,
    storage: &StorageSource,
    why: &mut Option<NeedRefusal>,
) -> Result<NativeConnection, ConnError> {
    let PendingDial {
        carrier,
        located,
        tls,
        anchors,
        open_timeout,
        egress_class,
        plain,
        within,
    } = dial;
    if !class_admits(egress_class, located.secure, plain, &within, addr) {
        crate::conns::egress_audit::dial_refused(
            &located.authority,
            Some(egress_class),
            "plaintext",
            None,
            &mut None,
        );
        *why = Some(NeedRefusal::Policy(super::refusal_text::PLAINTEXT));
        return Err(ConnError::Refused);
    }
    // The other addresses are tried only where the same rule admits them.
    let mut also = also;
    let mut at = 0;
    while at < also.len() {
        if class_admits(egress_class, located.secure, plain, &within, also[at]) {
            at += 1;
        } else {
            also.swap_remove(at);
        }
    }
    NativeConnection::dial(
        carrier,
        NativeDial {
            located,
            addr,
            also,
            tls,
            anchors,
            open_timeout,
            storage: storage.clone(),
            tunnel: None,
        },
    )
    .map_err(|failure| {
        *why = Some(crate::cold::conns::native_unreached(&failure));
        error_of(&failure)
    })
}

/// What a native failure answers the connection's caller.
pub(crate) fn error_of(failure: &NativeFailure) -> ConnError {
    if failure.cause.stage == stage::DEADLINE {
        ConnError::Timeout
    } else {
        ConnError::Fault
    }
}

impl Exchange {
    /// Whether the next read will not pend ([`NativeHeld::ready`]).
    fn read_ready(&mut self, cx: &mut Context<'_>) -> bool {
        if self.failed.is_some() || self.ended {
            return true;
        }
        match (&mut self.state, self.stream) {
            (State::Dialled(conn), Some(stream)) => conn.poll_ready(cx, stream),
            (State::Shared(shared), Some(stream)) => {
                shared.with(|conn| conn.poll_ready(cx, stream))
            }
            _ => true,
        }
    }

    /// Drive the judgement and the dial until a connection exists. `Pending` with `cx`'s waker kept.
    fn connected(
        &mut self,
        cx: &mut Context<'_>,
        storage: &StorageSource,
    ) -> Poll<Result<(), ConnError>> {
        if let Some(error) = self.failed {
            return Poll::Ready(Err(error));
        }
        // The target's judgement and, where the operator's proxy carries the dial, the judgement of the
        // proxy's own host: the dial begins when every one asked for has answered.
        let got = match &self.state {
            State::Dialled(_) | State::Shared(_) => return Poll::Ready(Ok(())),
            State::Gone => return Poll::Ready(Err(ConnError::Closed)),
            State::Judging {
                answer,
                via: Some(via),
                ..
            } => route::both_judged(answer, via, cx).map(|(target, proxy)| (target, Some(proxy))),
            State::Judging {
                answer, via: None, ..
            } => {
                let mut a = answer.lock().expect("judgement");
                match a.0.take() {
                    Some(verdict) => Some(((verdict, std::mem::take(&mut a.2)), None)),
                    None => {
                        let previous = a.1.replace(cx.waker().clone());
                        drop(a);
                        drop(previous);
                        None
                    }
                }
            }
        };
        let Some(((verdict, also), proxy)) = got else {
            return Poll::Pending;
        };
        let State::Judging { dial, via, .. } = std::mem::replace(&mut self.state, State::Gone)
        else {
            return Poll::Ready(Err(ConnError::Closed));
        };
        let mut why = None;
        let dialled = match (via, proxy) {
            // Through the proxy: the two judgements, the tunnel's target, the plaintext rule on the
            // target's own address. A refused target never reaches the proxy.
            (Some(via), Some(proxy)) => {
                route::dial_through(dial, via, verdict, proxy, storage, &mut why)
            }
            _ => match verdict {
                Err(v) => {
                    crate::conns::egress_audit::dial_refused(
                        &dial.located.authority,
                        Some(dial.egress_class),
                        crate::conns::egress_audit::verdict_name(v),
                        None,
                        &mut None,
                    );
                    Err(super::pended_verdict(v))
                }
                Ok(addr) => dial_at(dial, addr, also, storage, &mut why),
            },
        };
        match dialled {
            Ok(conn) => {
                self.state = State::Dialled(conn);
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                // A dial refused or failed at the operator's proxy before any connection existed is the
                // proxy's: the cause says so, and the walk charges no provider for it.
                if let Some(NeedRefusal::ProxyPolicy(_) | NeedRefusal::ProxyUnreached(_)) = &why {
                    self.cause = Some(ConnCause {
                        stage: stage::PROXY,
                        text: route::text::PROXY_UNREACHED.to_owned(),
                        outbound: false,
                    });
                    self.evidence
                        .push(crate::outbound::redial::Recorded::AtProxy);
                }
                self.failed = Some(error);
                Poll::Ready(Err(error))
            }
        }
    }

    /// A failed attempt, decided from what was sent of it (`again::attempt_failed`): `Pending` when the
    /// same request is being sent again on a fresh dial (the connector's `redial_native` wakes the caller),
    /// else the failure.
    fn attempt_ended<T>(&mut self, failure: &NativeFailure) -> Poll<Result<T, ConnError>> {
        match self.attempt_failed(failure) {
            ConnError::Pending => Poll::Pending,
            error => Poll::Ready(Err(error)),
        }
    }

    /// Hand the request to the connection as far as it takes it: `Ready(Ok)` once all of it was handed over.
    /// The head and the body stay with the exchange while the request may still be sent again, and are let
    /// go of (the head wiped) the moment it may not.
    fn send(
        &mut self,
        cx: &mut Context<'_>,
        storage: &StorageSource,
    ) -> Poll<Result<u64, ConnError>> {
        if self.resend {
            // The connector dials afresh before the next poll.
            return Poll::Pending;
        }
        std::task::ready!(self.connected(cx, storage))?;
        let Some(mut conn) = shared::riding(&mut self.state) else {
            return Poll::Ready(Err(ConnError::Closed));
        };
        let Some(sending) = self.sending.as_mut() else {
            return Poll::Ready(self.stream.ok_or(ConnError::Closed));
        };
        let stream = match self.stream {
            Some(stream) => stream,
            None => {
                // A head sent again: its sealed values never left the engine and are offered back.
                if let Some(slots) = self.sealed.take() {
                    conn.offer_sealed(slots);
                }
                let follows = !sending.body.is_empty();
                match conn.poll_send_head(cx, &mut sending.head, follows) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(failure)) => return self.attempt_ended(&failure),
                    Poll::Ready(Ok(stream)) => {
                        self.stream = Some(stream);
                        stream
                    }
                }
            }
        };
        while sending.sent < sending.body.len() {
            match conn.poll_send_body(cx, stream, &sending.body[sending.sent..], true) {
                Poll::Ready(Ok(0)) | Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(n)) => sending.sent += n,
                Poll::Ready(Err(failure)) => return self.attempt_ended(&failure),
            }
        }
        // The head and the body were handed over: they are let go of as soon as the evidence says the
        // request can no longer be sent again (the socket accepted a byte of it, or its answer began).
        self.let_go_of_head(false);
        Poll::Ready(Ok(stream))
    }

    /// The next piece of the answer into `buf`.
    pub(crate) fn read(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
        storage: &StorageSource,
    ) -> Poll<Result<Piece, ConnError>> {
        if self.ended {
            return Poll::Ready(Err(ConnError::Closed));
        }
        let stream = match std::task::ready!(self.send(cx, storage)) {
            Ok(stream) => stream,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let Some(mut conn) = shared::riding(&mut self.state) else {
            return Poll::Ready(Err(ConnError::Closed));
        };
        match conn.poll_read(cx, stream, buf) {
            Poll::Pending => {
                self.let_go_of_head(false);
                Poll::Pending
            }
            Poll::Ready(Err(failure)) => self.attempt_ended(&failure),
            Poll::Ready(Ok(piece)) => {
                // A WebSocket upstream: the answer's head opens (or refuses) the session, its end closes it.
                self.message_read(&piece);
                if piece.kind == PieceKind::Completion {
                    self.ended = true;
                    if let Some(mut conn) = shared::riding(&mut self.state) {
                        conn.finish(stream);
                    }
                }
                // An answer has begun: nothing of this request is ever sent again.
                self.let_go_of_head(self.ended);
                Poll::Ready(Ok(piece))
            }
        }
    }

    /// A write after the open. The open handed the connection the whole request (its end included), so only an
    /// empty write is taken; the rest of the request is sent here as the connection takes it.
    pub(crate) fn write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        storage: &StorageSource,
    ) -> Result<usize, ConnError> {
        match self.send(cx, storage) {
            Poll::Pending => Err(ConnError::Pending),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(_)) if bytes.is_empty() => Ok(0),
            // A WebSocket upstream carries messages after its open (a binary piece that ends its message;
            // the connection table'"'"'s typed write is `Connector::write_native_message`).
            Poll::Ready(Ok(_)) if self.ws.is_some() => {
                self.write_message(cx, bytes, (false, true), storage)
            }
            Poll::Ready(Ok(_)) => Err(ConnError::Closed),
        }
    }

    /// The connection, once it exists.
    pub(crate) fn connection(&self) -> Option<&NativeConnection> {
        match &self.state {
            State::Dialled(conn) => Some(conn),
            // A shared connection is not this exchange's alone to describe.
            State::Shared(_) | State::Judging { .. } | State::Gone => None,
        }
    }

    /// The connection for good, as its entry closes: kept for reuse (`Ok`) when its answer was read to its end and
    /// it can carry another exchange; else (`Err`) whatever is left of it, its unfinished stream reset.
    pub(crate) fn release(self) -> Result<(PoolKey, NativeConnection), Option<NativeConnection>> {
        let Self {
            state,
            stream,
            ended,
            failed,
            key,
            ..
        } = self;
        // A stream on a shared connection: only the stream is given up (reset when its answer was not read
        // to its end; the others finish). The connection stays in its core's set for the opens that follow.
        if let State::Shared(shared) = &state {
            if let Some(stream) = stream {
                shared.leave(stream, !ended);
            }
            return Err(None);
        }
        let State::Dialled(mut conn) = state else {
            return Err(None);
        };
        // A WebSocket connection is never kept (`conn.reusable()` answers no for its carrier).
        if let Some(key) = key.filter(|_| ended && failed.is_none() && conn.reusable()) {
            return Ok((key, conn));
        }
        if let Some(stream) = stream.filter(|_| !ended) {
            conn.reset(stream);
        }
        Err(Some(conn))
    }
}

/// One core's idle connections, by key, and when its next sweep of expired ones is due.
pub(crate) struct CoreIdle {
    /// The core's connections in use that other opens to the same key may ride, with what is known of
    /// each key. Empty until a session states that it multiplexes; a key's entry goes with its last
    /// connection.
    pub(crate) in_use: Mutex<shared::InUse<PoolKey, Arc<shared::Shared>>>,
    pub(crate) map: Mutex<HashMap<PoolKey, Vec<(NativeConnection, Instant)>>>,
    /// In nanoseconds since [`Idle::epoch`]; `u64::MAX` = none due.
    pub(crate) sweep_due: AtomicU64,
}

impl Default for CoreIdle {
    fn default() -> Self {
        Self {
            in_use: Mutex::new(shared::InUse::new()),
            map: Mutex::new(HashMap::new()),
            sweep_due: AtomicU64::new(u64::MAX),
        }
    }
}

/// THE IDLE NATIVE CONNECTIONS, PER CORE (DESIGN-request-on-one-thread T5): HTTP keep-alive. A connection goes
/// back to the core that dialled it and is lent only to an open on that core, so no lock is shared between cores and
/// no socket is polled from another core. The cores' sets are made at the first connection kept (one slot per
/// worker shard, `pool::shard_count`: the machine's parallelism, at most 16), not at start.
///
/// Bound, per core: `limits.pool_max_idle_per_host` connections per key (the deployment's posture, the figure the
/// framed pool holds), each for at most `limits.pool_idle_timeout_secs`; an empty key is removed with its list, so
/// nothing is held for a destination with no idle connection.
pub(crate) struct Idle {
    pub(crate) cores: std::sync::OnceLock<Box<[CoreIdle]>>,
    /// The instant the store was made: what each core's `sweep_due` counts from.
    pub(crate) epoch: Instant,
}

impl Default for Idle {
    fn default() -> Self {
        Self {
            cores: std::sync::OnceLock::new(),
            epoch: Instant::now(),
        }
    }
}

impl Idle {
    /// A connection in use on `core` to `key` that takes another stream now.
    pub(crate) fn lend_stream(
        &self,
        core: usize,
        key: &PoolKey,
        now: Instant,
        posture: PoolPosture,
    ) -> Option<Arc<shared::Shared>> {
        let held = self.core(core)?;
        let mut set = held.in_use.lock().expect("native connections in use");
        shared::lend_stream(&mut set, key, false, now, posture.idle_timeout)
    }

    /// Share `exchange`'s connection on `core` once its session states that it multiplexes.
    pub(crate) fn share(&self, core: usize, exchange: &mut Exchange, posture: PoolPosture) {
        if !matches!(&exchange.state, State::Dialled(conn) if conn.multiplexes()) {
            return;
        }
        let cores = self
            .cores
            .get_or_init(|| crate::off_path::conns::idle_cores(super::pool::shard_count()));
        if let Some(held) = cores.get(core) {
            let mut set = held.in_use.lock().expect("native connections in use");
            exchange.share(&mut set);
            // One pass over the core's shared connections, at a promotion (rare, never per request):
            // those that failed, drained, or idled past the timeout leave the set and are closed.
            let now = Instant::now();
            set.sweep(|conn| {
                !conn.in_use().finished() && !conn.idle_past(now, posture.idle_timeout)
            });
        }
    }

    /// `core`'s set, where any connection was ever kept.
    fn core(&self, core: usize) -> Option<&CoreIdle> {
        self.cores.get().and_then(|cores| cores.get(core))
    }

    /// An idle connection to `key` that `core` holds, still able to carry an exchange: one the posture's timeout let
    /// lapse, or whose far end closed it while it idled, is closed here and the next is tried.
    pub(crate) fn take(
        &self,
        core: usize,
        key: &PoolKey,
        now: Instant,
        posture: PoolPosture,
    ) -> Option<NativeConnection> {
        let held = self.core(core)?;
        loop {
            let got = {
                let mut map = held.map.lock().expect("idle native connections");
                let list = map.get_mut(key)?;
                let one = list.pop();
                if list.is_empty() {
                    map.remove(key);
                }
                one
            };
            let (mut conn, since) = got?;
            if now.saturating_duration_since(since) >= posture.idle_timeout {
                conn.close();
                continue;
            }
            // One look at the socket with no waker: a far end that closed the idle connection is seen here.
            let _ = conn.poll_flushed(&mut Context::from_waker(Waker::noop()));
            if conn.reusable() {
                return Some(conn);
            }
            conn.close();
        }
    }

    /// Keep `conn` on `core` (the core that dialled it) for the next exchange to `key`; past the posture's bound it
    /// is closed instead. Expired connections of every key on that core are closed when its sweep is due.
    pub(crate) fn put(
        &self,
        core: usize,
        key: PoolKey,
        conn: NativeConnection,
        now: Instant,
        posture: PoolPosture,
    ) {
        let cores = self
            .cores
            .get_or_init(|| crate::off_path::conns::idle_cores(super::pool::shard_count()));
        let Some(held) = cores.get(core) else {
            conn.close();
            return;
        };
        let refused = {
            let mut map = held.map.lock().expect("idle native connections");
            let list = map.entry(key).or_default();
            // The stated figure is the deployment's, divided across the cores (at least one per core), as
            // v1.5.5 divided it across its worker threads: not the whole figure on every core.
            if list.len()
                >= crate::outbound::lend::idle_bound(posture.max_idle_per_host, cores.len())
            {
                Some(conn)
            } else {
                list.push((conn, now));
                None
            }
        };
        if let Some(conn) = refused {
            conn.close();
        }
        let at =
            u64::try_from(now.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX);
        let due = held.sweep_due.load(Ordering::Acquire);
        if due == u64::MAX {
            let next = at
                .saturating_add(u64::try_from(posture.idle_timeout.as_nanos()).unwrap_or(u64::MAX));
            held.sweep_due.store(next, Ordering::Release);
        } else if at >= due {
            crate::off_path::conns::sweep_native_idle(held, self.epoch, now, posture);
        }
    }
}

impl super::Connector {
    /// The need `owner` declared as `need`, where it is served natively.
    pub(crate) fn native_need(
        &self,
        owner: super::InstanceId,
        need: super::NeedId,
    ) -> Option<Arc<NativeNeed>> {
        self.native_needs
            .lock()
            .expect("native needs")
            .get(&(owner, need))
            .map(Arc::clone)
    }

    /// Whether core's scheme table dials `transport` (a scheme word) natively.
    pub(crate) fn dials_natively(transport: &str) -> bool {
        busbar_kernel::config_validate::schemes::dial_scheme(transport).is_ok()
    }

    /// The trust anchors an open of `caller`'s `need` naming `member` at `authority` (lower-cased) is held to:
    /// the registration's own seal at that authority, else the destination's, which every registration sealed
    /// there must agree with; re-based on the policy in force (`own`: the need has its own client config, and
    /// its policy). Answers the anchors, the authority (lent and handed back) and the registration they are the
    /// registration's own under.
    pub(crate) fn anchors_for(
        &self,
        caller: super::InstanceId,
        need: super::NeedId,
        member: &str,
        authority: String,
        (own_tls, own_policy): (
            bool,
            Option<&busbar_contract::transport::trust::EgressTrust>,
        ),
    ) -> Result<
        (
            Option<Arc<crate::tls::client::Sealed>>,
            String,
            Option<String>,
        ),
        ConnError,
    > {
        let own = (!member.is_empty())
            .then(|| {
                self.member_anchored
                    .lock()
                    .expect("anchors")
                    .get(caller, need, member)
                    .filter(|(at, _)| *at == authority)
                    .map(|(_, sealed)| sealed.clone())
            })
            .flatten();

        let anchored_as = own.is_some().then(|| crate::off_path::conns::owned(member));

        // The lowered authority keys the anchor books here and the pool below: it is made once,
        // lent to the books' key and taken back.
        let (anchors, authority) = match own {
            Some(sealed) => (sealed, authority),
            None => {
                let at = (caller, need, authority);
                let anchored = self.anchored.lock().expect("anchors");
                let own = anchored.get(&at);
                let anchors = match self.registered.lock().expect("anchors").get(&at) {
                    Some(registered) => registered.held(own)?,
                    None => own.cloned(),
                };
                drop(anchored);
                (anchors, at.2)
            }
        };

        let anchors = if let Some(sealed) = anchors.as_ref().filter(|s| !s.extra_anchors.is_empty())
        {
            let current = if own_tls {
                own_policy
            } else {
                self.tls_policy.as_ref()
            };
            if sealed.policy.as_ref() != current {
                Some(crate::tls::client::rebase(sealed, current).map_err(|_| ConnError::Refused)?)
            } else {
                anchors
            }
        } else {
            anchors
        };
        Ok((anchors, authority, anchored_as))
    }

    /// The head defaults of a native need at `target` (empty = the need's own): the carrier's own client lines,
    /// and the host states the body's length (the framer is handed it as `H_BODY_LEN`).
    pub(crate) fn native_head(
        &self,
        native: &NativeNeed,
        target: &str,
    ) -> Result<busbar_contract::conn::HeadDefaults, ConnError> {
        let target = match (target, native.declared_target.as_deref()) {
            ("", Some(declared)) => declared,
            (named, _) => named,
        };
        let located = super::native_dial::locate(target).map_err(|_| ConnError::Refused)?;
        let carrier = self
            .native
            .get()
            .and_then(|natives| natives.carrier(located.carrier))
            .ok_or(ConnError::Refused)?;
        Ok(busbar_contract::conn::HeadDefaults {
            lines: crate::off_path::conns::native_defaults(
                carrier
                    .port
                    .defaults(busbar_plugin_abi::transport::ROLE_CLIENT),
            ),
            states_length: true,
        })
    }

    /// THE NATIVE OPEN: `desc` on `caller`'s natively served `need`, held to everything a framed open is held to.
    /// `started` is the open's one clock reading.
    pub(crate) fn open_native(
        &self,
        (caller, need): (super::InstanceId, super::NeedId),
        desc: &super::OpenDesc<'_>,
        native: &NativeNeed,
        (started, open_timeout): (Instant, Duration),
        require_secure: bool,
        owned: Option<super::OwnedHead>,
        why: &mut Option<NeedRefusal>,
    ) -> Result<super::Held, ConnError> {
        let declared_target = native.declared_target.as_deref();
        let target = match (desc.target, declared_target) {
            ("", Some(declared)) => declared,
            (named, _) => named,
        };
        crate::conns::endpoint::named(target).map_err(|_| ConnError::Refused)?;
        let located = super::native_dial::locate(target).map_err(|_| {
            *why = Some(NeedRefusal::Policy(super::refusal_text::UNLOCATED));
            ConnError::Refused
        })?;
        if require_secure && !located.secure {
            return Err(ConnError::AuthRefused);
        }
        if let Some(declared) = declared_target {
            let pinned = super::native_dial::locate(declared).map_err(|_| ConnError::Refused)?;
            if !pinned.authority.eq_ignore_ascii_case(&located.authority)
                || pinned.secure != located.secure
            {
                return Err(ConnError::Refused);
            }
        }
        if !super::scheme_admits(native.egress_class, located.secure) {
            *why = Some(NeedRefusal::Policy(super::refusal_text::PLAINTEXT));
            return Err(ConnError::Refused);
        }
        let natives = self.native.get();
        let Some((carrier, natives)) =
            natives.and_then(|natives| natives.carrier(located.carrier).map(|one| (one, natives)))
        else {
            crate::cold::conns::no_native_carrier(located.carrier);
            *why = Some(NeedRefusal::Policy(super::refusal_text::NO_CARRIER));
            return Err(ConnError::Refused);
        };
        // The operator's egress proxy is honoured here as on every other dial: a destination its choice
        // selects is tunnelled through it (`route::dial_through`), never dialled around it and never refused
        // for it.
        let tls = match &native.tls {
            Some(own) => Some(Arc::clone(own)),
            None => self.tls_for(target)?,
        };
        let (anchors, authority, anchored_as) = self.anchors_for(
            caller,
            need,
            desc.member,
            crate::off_path::conns::lowered(&located.authority),
            (native.tls.is_some(), native.tls_policy.as_ref()),
        )?;
        if anchors.as_ref().is_some_and(|a| {
            (a.key_pin.is_some() || !a.extra_anchors.is_empty()) && !located.secure
        }) {
            return Err(ConnError::Refused);
        }
        let reach = !desc.member.is_empty()
            && self
                .reaching
                .lock()
                .expect("reach")
                .get(caller, need, desc.member)
                .is_some_and(|(at, secure)| {
                    at.eq_ignore_ascii_case(&located.authority) && *secure == located.secure
                });
        let judged_class = crate::conns::guard::judged_class(
            native.egress_class,
            declared_target.is_some() && desc.member.is_empty(),
        );
        let core = self.pools.shard();
        let posture = self.pools.posture();
        let key = (posture.max_idle_per_host > 0 && desc.within.is_empty()).then(|| {
            self.pools.keyed(PoolKey {
                owner: caller,
                need,
                door: Arc::as_ptr(&carrier.port).cast::<()>() as usize,
                authority,
                secure: located.secure,
                name: crate::off_path::conns::owned_name(located.name.as_deref()),
                class: (judged_class, native.egress_class),
                reach,
                anchored_as,
                trust: tls.clone().map(super::pool::Same::of),
                sealed: anchors.clone().map(super::pool::Same::of),
                hash: 0,
            })
        });
        let plain =
            self.plaintext_accepted(caller, desc) || self.plaintext_admitted(&located.authority);
        // A WebSocket upstream: the open is the handshake; after its 101 the exchange carries messages both
        // ways and its connection is never kept or shared.
        let websocket = located.carrier == busbar_plugin_abi::plane::CARRIER_WEBSOCKET;
        let sending = Sending {
            head: Some(NativeHead {
                method: crate::off_path::conns::owned_bytes(desc.method),
                target: crate::off_path::conns::owned_bytes(desc.head_target),
                fields: super::opening_fields(desc.fields, owned),
                body_len: (!desc.body.is_empty()).then(|| desc.body.len() as u64),
                budget: (desc.timeout_ms != 0).then(|| Duration::from_millis(desc.timeout_ms)),
                // A sealed value crosses a connection that is not secured only by the destination's own
                // acceptance, never the owner-wide one.
                sealed_in_clear: self.sealed_in_clear(desc, &located.authority),
            }),
            body: desc.body.clone(),
            sent: 0,
        };
        let secure = located.secure;
        let dial = PendingDial {
            carrier: carrier.clone(),
            plain,
            located,
            tls,
            anchors,
            open_timeout,
            egress_class: native.egress_class,
            within: Within::from_slice(desc.within),
        };
        // What it takes to dial this same request again, kept while the evidence may still allow it.
        let reopen = again::Reopen {
            dial: dial.clone(),
            judged_class,
            reach,
        };
        let held = |state, key, kept: bool| {
            let exchange = Exchange {
                state,
                sending: Some(sending),
                stream: None,
                ended: false,
                failed: None,
                cause: None,
                key,
                reopen: Some(reopen),
                kept,
                redialled: false,
                resend: false,
                sealed: None,
                evidence: smallvec::SmallVec::new(),
                charge: false,
                ws: websocket.then(crate::outbound::ws::Upstream::new),
            };
            let mut held = super::Held::over(None, None, None).bounded(started, desc.timeout_ms);
            held.native = Some(NativeHeld::new(exchange, core));
            held
        };
        // Many requests on one connection: a connection in use on this core to the same key, whose session
        // multiplexes and takes another stream now, carries this exchange as one more stream. No dial, no
        // handshake, no socket. The key separates owner, need, trust, seal and reach, so a stream is never
        // opened on a connection another registration's trust made; the plaintext rule is the idle set's.
        if let Some(shared) = key
            .as_ref()
            .filter(|_| secure || plain)
            .and_then(|key| self.native_idle.lend_stream(core, key, started, posture))
        {
            return Ok(held(State::Shared(shared), None, true));
        }
        // HTTP keep-alive: an idle connection this core dialled to the same key carries the exchange (it was judged
        // when it was dialled, under this very key, and tunnelled then where the operator's proxy carries it:
        // nothing about the proxy is done again). A plaintext one is lent only to an open whose own plaintext
        // admission holds: the key does not carry the opener's acceptance, so an open without it dials and is held
        // to the plaintext rule.
        if let Some(conn) = key
            .as_ref()
            .filter(|_| secure || plain)
            .and_then(|key| self.native_idle.take(core, key, started, posture))
        {
            return Ok(held(State::Dialled(conn), key, true));
        }
        let answer: Answer = Arc::new(Mutex::new((None, None, Vec::new())));
        let judged = self.judge_into(
            &dial.located.authority,
            secure,
            judged_class,
            reach,
            &answer,
        );
        // The operator's proxy, where its choice selects this destination: the target is judged first, as for
        // a direct dial, and the proxy's own host second (operator infrastructure). A target the guard refuses
        // is never shown to the proxy.
        let via = match &judged {
            Some(Err(_)) => None,
            _ => self.via_for(secure, &dial.located.authority)?,
        };
        let state = match (judged, via) {
            (None, via) => State::Judging { answer, dial, via },
            (Some(Err(v)), _) => {
                crate::conns::egress_audit::dial_refused(
                    &dial.located.authority,
                    Some(dial.egress_class),
                    crate::conns::egress_audit::verdict_name(v),
                    None,
                    &mut None,
                );
                *why = Some(crate::cold::conns::verdict_reason(v, false));
                return Err(ConnError::Refused);
            }
            (Some(Ok(addr)), None) => {
                State::Dialled(dial_at(dial, addr, Vec::new(), &natives.storage, why)?)
            }
            (Some(Ok(addr)), Some(via)) => {
                // The target answered at once; the dial waits for the proxy's own judgement.
                answer.lock().expect("judgement").0 = Some(Ok(addr));
                State::Judging {
                    answer,
                    dial,
                    via: Some(via),
                }
            }
        };
        Ok(held(state, key, false))
    }

    /// One read of a native entry.
    pub(crate) fn read_native(
        &self,
        native: &NativeHeld,
        waker: &Waker,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let Some(storage) = self.native.get().map(|natives| &natives.storage) else {
            return Err(ConnError::Closed);
        };
        let Some(mut exchange) = native.begin(waker) else {
            return Err(ConnError::Pending);
        };
        let read = exchange.read(&mut Context::from_waker(waker), buf, storage);
        // A request the evidence allows to be sent again (a kept connection that turned out closed with
        // nothing sent, a stream the far end refused unprocessed, a busy connection) is judged and dialled
        // afresh here; the caller's read pends and its ticket is woken to drive the new dial.
        let again = self.redial_native(&mut exchange, waker);
        // A connection whose session states that it multiplexes is shared from here on: later opens to the
        // same key on this core ride it.
        self.native_idle
            .share(native.core, &mut exchange, self.pools.posture());
        native.end(exchange);
        again?;
        match read {
            Poll::Pending => Err(ConnError::Pending),
            Poll::Ready(read) => read,
        }
    }

    /// One write on a native entry.
    pub(crate) fn write_native(
        &self,
        native: &NativeHeld,
        bytes: &[u8],
    ) -> Result<usize, ConnError> {
        let Some(storage) = self.native.get().map(|natives| &natives.storage) else {
            return Err(ConnError::Closed);
        };
        let Some(mut exchange) = native.begin(Waker::noop()) else {
            return Err(ConnError::Pending);
        };
        let wrote = exchange.write(&mut Context::from_waker(Waker::noop()), bytes, storage);
        let again = self.redial_native(&mut exchange, Waker::noop());
        native.end(exchange);
        again?;
        wrote
    }

    /// One message piece on a native entry whose upstream is a WebSocket (`text` = the message's kind on
    /// its first piece; `end` = this piece ends the message; an empty piece with `end` after a finished
    /// message is the engine's close).
    pub(crate) fn write_native_message(
        &self,
        native: &NativeHeld,
        waker: &Waker,
        bytes: &[u8],
        (text, end): (bool, bool),
    ) -> Result<usize, ConnError> {
        let Some(storage) = self.native.get().map(|natives| &natives.storage) else {
            return Err(ConnError::Closed);
        };
        let Some(mut exchange) = native.begin(waker) else {
            return Err(ConnError::Pending);
        };
        let wrote =
            exchange.write_message(&mut Context::from_waker(waker), bytes, (text, end), storage);
        let again = self.redial_native(&mut exchange, waker);
        // A connection whose session states that it multiplexes is shared from here on: later opens to the
        // same key on this core ride it.
        self.native_idle
            .share(native.core, &mut exchange, self.pools.posture());
        native.end(exchange);
        again?;
        wrote
    }

    /// Whether a native entry's connection has landed (dialled, secured, nothing queued).
    pub(crate) fn landed_native(
        &self,
        native: &NativeHeld,
        waker: &Waker,
    ) -> Result<(), ConnError> {
        let Some(storage) = self.native.get().map(|natives| &natives.storage) else {
            return Err(ConnError::Closed);
        };
        let Some(mut exchange) = native.begin(waker) else {
            return Err(ConnError::Pending);
        };
        let mut cx = Context::from_waker(waker);
        let landed = match exchange.connected(&mut cx, storage) {
            Poll::Pending => Err(ConnError::Pending),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Ready(Ok(())) => match &mut exchange.state {
                State::Dialled(conn) => match conn.poll_flushed(&mut cx) {
                    Poll::Pending => Err(ConnError::Pending),
                    Poll::Ready(Ok(())) => Ok(()),
                    Poll::Ready(Err(failure)) => Err(exchange.attempt_failed(&failure)),
                },
                // A shared connection landed when the exchange that dialled it did.
                State::Shared(_) => Ok(()),
                State::Judging { .. } | State::Gone => Err(ConnError::Closed),
            },
        };
        let again = self.redial_native(&mut exchange, waker);
        // A connection whose session states that it multiplexes is shared from here on: later opens to the
        // same key on this core ride it.
        self.native_idle
            .share(native.core, &mut exchange, self.pools.posture());
        native.end(exchange);
        again?;
        landed
    }

    /// Why a native entry failed, where it did.
    pub(crate) fn native_cause(native: &NativeHeld) -> Option<ConnCause> {
        let exchange = native.begin(Waker::noop())?;
        let cause = exchange
            .cause
            .clone()
            .or_else(|| exchange.connection().and_then(|conn| conn.cause().cloned()));
        native.end(exchange);
        cause
    }

    /// The facts of a native entry's connection, once it exists.
    pub(crate) fn native_facts(
        native: &NativeHeld,
    ) -> Result<busbar_contract::transport::ConnFacts, ConnError> {
        let Some(exchange) = native.begin(Waker::noop()) else {
            return Err(ConnError::Pending);
        };
        let facts = exchange
            .connection()
            .map(crate::off_path::conns::native_facts)
            .ok_or(ConnError::Pending);
        native.end(exchange);
        facts
    }

    /// THE NATIVE CLOSE: the connection goes back to its core's idle set when its answer was read whole and it can
    /// carry another exchange; otherwise its unfinished stream is reset and it is closed. No lock is held while it
    /// writes.
    pub(crate) fn close_native(&self, native: &NativeHeld) {
        let Some(exchange) = native.take() else {
            return;
        };
        match exchange.release() {
            Ok((key, conn)) => {
                // The close's one clock reading: when the connection began to idle.
                let now = Instant::now();
                self.native_idle
                    .put(native.core, key, conn, now, self.pools.posture());
            }
            Err(Some(conn)) => conn.close(),
            Err(None) => {}
        }
    }
}
