// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION FAR END (`BUSBAR-1.6.0.md` Part 3, §12 "The route pump"; THE DESIGN, §5 "One
//! outbound request, kernel to wire", section 6): the kernel's egress walk for one unit, one attempt at a
//! time, as the pump asks for it. The driver builds no second walk: every pick is the egress
//! unit's own stepper ([`Walk`]) — the pick over the pool with its breaker and its permits, the
//! pool's exhaustion terminals and their Retry-After floor — and the breaker's classification of
//! the far end's status and its record ([`Breaker::judge`], [`Breaker::observe`]) are the egress
//! unit's ports. This file keeps the attempt and the wire, which is the connector's.
//!
//! Per attempt, in order:
//!
//! 1. [`FarEnd::member`]: the walk's next step (breaker admit + permit, probe owned by the
//!    attempt), or the pool's terminal: the shed with its Retry-After floor, the spill into a
//!    fallback pool, the one breaker bypass (least-bad), or the bounded wait for a permit (queue).
//! 2. [`FarEnd::send`]: the durable dispatch record, then ONE `fields` call to the member's auth
//!    binding (THE DESIGN, section 6: the kernel's one call, no kernel-side cache), whose fields lead the
//!    head before the plane's (1.5.5's egress order), then the connector's open on the plane's declared need, at the target
//!    the member's sealed `base_url` and the plane's path spell. The connector judges and pins the
//!    address and dials exactly it (CONNECTOR-19), so a name's refusal keeps 1.5.5's timing.
//! 3. [`FarEnd::next`]: the connector's pieces, read through the task's own waker
//!    ([`PollConns::poll_read`]). On the first status the breaker classifies it (the step-24
//!    `Disposition`, 1.5.5's attempt classifier): a success is recorded and spends one unit of the
//!    member's lifetime budget; a caller fault is relayed to the plane as it came; a hard failure
//!    (a rejected key: 401/403) takes the member down across every pool and is relayed to the
//!    plane, whose verdict decides (an auth failure ends the unit, rendered in the caller's own
//!    dialect; a billing one asks to retry); a passthrough member's 401/403 is the caller's own
//!    key failing and records nothing; a transient failure is recorded and the piece fails over
//!    before the plane sees it. A failure before any answer — refused, reset, the attempt's cap —
//!    fails over too.
//! 4. [`FarEnd::write`], for a duplex session's HELD far end only: once the attempt's far end has
//!    answered, each later turn's frame goes into the same connection (`Conns::write`, one message
//!    per frame), never a second dial; the reads of step 3 go on until its answer ends.
//!
//! Deadlines are 1.5.5's: the walk's whole budget is the pool's request timeout, measured from the
//! unit's start; the first answer is bounded by the member's attempt cap (never beyond what the walk
//! has left); the whole send by the walk's remaining budget, or the stream ceiling for a streamed
//! answer (the plane's stated one, else the deployment's). A plane that states a stream ceiling
//! also has it stamped as the unit's deadline once the route is known ([`Egress::deadline_ns`]).
//!
//! The kernel names no plane here and no plugin: the connection table is the contract's
//! [`PollConns`], the auth binding the contract's [`OutboundAuth`], and both are handed in by the
//! composition root.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::proxy::egress_unit::{
    attempt::attempt_cap_ms,
    ports::{
        disposition, net, Breaker, Capacity, Clock, DestinationId, Dispatched, Disposition,
        Journal, Outcome, Permit, Telemetry, UpstreamStatus,
    },
    walk::budget_secs,
    Member, Pool, Shed, Step, Taken, Walk, WalkPorts, WeightedFloor,
};
use busbar_contract::abi::auth::{AuthPoint, AuthPoints, STYLE_NEEDS_HEADERS};
use busbar_contract::abi::transport::{
    STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
};
use busbar_contract::auth_calls::{AuthField, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::caps::{Pass, Route};
use busbar_contract::conn::{
    ConnError, ConnId, InstanceId, NeedId, OpenDesc, PieceKind, PollConns,
};
use busbar_contract::redacted::Redacted;
use busbar_contract::transport::registry::status_ns;
use busbar_contract::transport::wire::{WireStatus, WireStatusClass};

use super::route::{FarEnd, FarPiece, OutboundRequest, Pick};

/// The bytes one read of the far end takes.
const READ_BYTES: usize = 16 * 1024;

/// The longest pause between two offers of a held far end's frame its connection's buffer had no
/// room for, milliseconds.
const WRITE_PAUSE_MAX_MS: u64 = 64;

/// 1.5.5's cap on a buffered far-end ERROR body (`limits.upstream_error_body_max_bytes`, default
/// 256 KiB; v1.5.5 `DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES`, config/mod.rs): the default for
/// [`Egress::error_body_max`].
pub const DEFAULT_ERROR_BODY_MAX: usize = 256 * 1024;

/// One member's sealed route: the need the plane declared for it, the `base_url` the target is
/// joined onto, and its auth binding.
#[derive(Clone)]
pub struct MemberRoute {
    /// The plane instance's declared need the connection opens on, resolved once at config load
    /// by the member's auth key ([`super::resolve_member_needs`]).
    pub need: NeedId,
    /// The provider's `base_url`, as the operator spelled it.
    pub base_url: String,
    /// The auth binding the root opened at generation seal; `None` = no auth fields.
    pub auth: Option<AuthBinding>,
    /// The provider the member is served by: the metering row's provider column, as 1.5.5's
    /// `lane.provider` (v1.5.5 `crates/busbar/src/proxy/usage.rs` `ledger_and_meter`).
    pub provider: String,
    /// Which of the far end's response head fields cross to the plane: its need's declared keep
    /// rule (THE DESIGN §5, "The response head and trailers": the kernel copies only those).
    pub keep: ResponseKeep,
    /// EVERY need bound for the member beside [`Self::need`] (ARCHITECT Q-L5B-NEEDS 2026-10-03: one
    /// binding per (transport, auth)), each with its keep rule: a far request that names one of
    /// them (`OutboundRequest::need`) opens on it. Empty = the member rides [`Self::need`] alone.
    pub rides: Vec<(NeedId, ResponseKeep)>,
    /// The member's trust anchors (the transport pin, ARCHITECT 2026-10-03): the far end's key pin and
    /// busbar's client identity, sealed into the connector at the egress's composition so every
    /// connection to the member, the walk's and the plane's own, is held to them. Default = none.
    pub anchors: busbar_contract::transport::trust::Anchors,
    /// The base URL a bound need dials, where its transport spells the member's `base_url` in its
    /// own scheme (a framer composed over the base URL's carrier: the same authority and path, read
    /// by that framer); a need not listed dials [`Self::base_url`]. Composed by the root, which
    /// knows the linked transports; the kernel names no scheme.
    pub spelled: Vec<(NeedId, String)>,
}

/// The need a far request opens on: its id, its keep rule and the base URL it dials.
#[derive(Debug, Clone, Copy)]
pub struct Ride<'a> {
    /// The need.
    pub need: NeedId,
    /// Its response-head rule.
    pub keep: &'a ResponseKeep,
    /// The base URL the far request's target is joined onto.
    pub base_url: &'a str,
}

impl MemberRoute {
    /// The need a far request opens on: the one it names (its declared index plus one), else the
    /// member's own; `None` when it names a need not bound for the member. It dials the base URL
    /// that need spells ([`Self::spelled`]), else the member's own.
    #[must_use]
    pub fn ride(&self, named: u32) -> Option<Ride<'_>> {
        let (need, keep) = match named.checked_sub(1) {
            Some(index) if self.need.0 != index => self
                .rides
                .iter()
                .find(|(need, _)| need.0 == index)
                .map(|(need, keep)| (*need, keep))?,
            _ => (self.need, &self.keep),
        };
        let base_url = self
            .spelled
            .iter()
            .find(|(n, _)| *n == need)
            .map_or(self.base_url.as_str(), |(_, url)| url.as_str());
        Some(Ride {
            need,
            keep,
            base_url,
        })
    }
}

/// A NEED'S RESPONSE-HEAD RULE, as its Statement declares it (`Need::keep_mode`,
/// `keep_response_headers`, `deny_response_headers`): the far end's head fields that reach the plane.
/// The default keeps nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResponseKeep {
    /// `KEEP_NAMED` or `KEEP_ALL_EXCEPT_DENIED`.
    pub mode: u32,
    /// Under `KEEP_NAMED`: the fields kept (lower-case).
    pub kept: Vec<String>,
    /// Under `KEEP_ALL_EXCEPT_DENIED`: the fields never kept beyond the kernel's own (lower-case).
    pub denied: Vec<String>,
}

impl ResponseKeep {
    /// Whether the field `name` (lower-case) crosses, the answer's `connection` fields `nominated`
    /// (`abi::host::conn::connector::keeps_response_field`, the one rule).
    #[must_use]
    pub fn keeps<'a>(&self, name: &str, nominated: impl IntoIterator<Item = &'a [u8]>) -> bool {
        let kept: Vec<&str> = self.kept.iter().map(String::as_str).collect();
        let denied: Vec<&str> = self.denied.iter().map(String::as_str).collect();
        busbar_contract::abi::host::conn::connector::keeps_response_field(
            self.mode, &kept, &denied, name, nominated,
        )
    }
}

/// A member's auth binding: the auth instance, the handle its `open_outbound` answered, the
/// style's `STYLE_*` flags and the auth points it needs (what `fields` reads).
#[derive(Clone)]
pub struct AuthBinding {
    /// The auth instance serving the member's style.
    pub auth: Arc<dyn OutboundAuth>,
    /// The handle.
    pub handle: u64,
    /// `abi::auth::STYLE_NEEDS_HEADERS`.
    pub style_flags: u32,
    /// The style's `StyleDecl::points`: a style that signs the body states `HeadBody` and is
    /// called there with the whole body; any other is called at `Head`.
    pub points: AuthPoints,
    /// The member is configured `upstream_credentials: passthrough`: its one auth call carries
    /// the caller's own verified credential (THE DESIGN, section 6.6, style `caller-credential`). No other
    /// binding is ever handed it.
    pub passthrough: bool,
}

/// THE EGRESS OF ONE PLANE INSTANCE, sealed per generation by the composition root: its connection
/// table and its caller id, the walk's ports, its pools and the route of every member.
pub struct Egress {
    /// The plane instance the connections are opened for.
    pub caller: InstanceId,
    /// The connection table.
    pub conns: Arc<dyn PollConns>,
    /// The breaker.
    pub breaker: Arc<dyn Breaker>,
    /// The pools' permits.
    pub capacity: Arc<dyn Capacity>,
    /// The clock and its sleep.
    pub clock: Arc<dyn Clock>,
    /// The write-ahead dispatch record.
    pub journal: Arc<dyn Journal>,
    /// The counters.
    pub telemetry: Arc<dyn Telemetry>,
    /// The weighted floor's credits, per pool.
    pub floor: WeightedFloor,
    /// The pools, by name.
    pub pools: HashMap<String, Pool>,
    /// Every member's route.
    pub routes: HashMap<DestinationId, MemberRoute>,
    /// The ceiling on a streamed answer's whole send, seconds: the deployment's, for a plane that
    /// states none of its own.
    pub stream_ceiling_secs: u64,
    /// THE PLANE'S STATED STREAM CEILING, seconds (its tail's `stream_ceiling_secs`; ARCHITECT
    /// ruling 2026-10-07, STREAM-CEILING): a streamed answer's whole send, and the unit's deadline
    /// ([`Egress::deadline_ns`]). `0` = the plane states none: no unit deadline, and a streamed
    /// answer's send runs under [`Egress::stream_ceiling_secs`].
    pub stated_ceiling_secs: u64,
    /// The most bytes of a relayed non-success answer's body the plane is handed (the operator's
    /// `limits.upstream_error_body_max_bytes`, [`DEFAULT_ERROR_BODY_MAX`] unset). What overruns it
    /// is dropped and the answer ends there, as 1.5.5's capped read did: an error envelope is far
    /// smaller, and one that overruns it can only be malformed or hostile.
    pub error_body_max: usize,
}

/// What one unit's walk is told at its start.
#[derive(Debug, Clone)]
pub struct UnitRoute {
    /// The unit the walk serves: every dispatch record it writes names it (ARCHITECT P3 (c),
    /// 2026-10-02).
    pub unit: busbar_contract::UnitKey,
    /// The pool the unit routes over.
    pub pool: String,
    /// The sticky-routing key, if any.
    pub affinity: Option<u64>,
    /// The caller asked for a streamed answer.
    pub wants_stream: bool,
    /// The dispatch record's leg.
    pub leg: u8,
    /// The caller's verified credential, as the identity step read it, for a member configured for
    /// passthrough. Zeroised on drop; never logged, stored or handed to the plane.
    pub caller_credential: Option<Redacted<Vec<u8>>>,
    /// The unit's operation is performed AT MOST ONCE (the plane's `ROUTE_ONCE`): a member that
    /// ANSWERED with a failure is not retried on another; its answer reaches the plane as it came.
    /// A walk still moves on before anything was answered.
    pub once: bool,
}

impl Default for UnitRoute {
    /// A route over no pool for unit `0` (the key no minted unit has).
    fn default() -> Self {
        UnitRoute {
            unit: busbar_contract::UnitKey::new(0),
            pool: String::new(),
            affinity: None,
            wants_stream: false,
            leg: 0,
            caller_credential: None,
            once: false,
        }
    }
}

impl Egress {
    /// The walk's whole budget for a unit over `pool`, seconds (the pool's request timeout).
    #[must_use]
    pub fn budget_secs(&self, pool: &str) -> u64 {
        budget_secs(&self.pools, pool)
    }

    /// The walk's ports over this egress.
    fn ports(&self) -> WalkPorts<'_> {
        WalkPorts {
            breaker: self.breaker.as_ref(),
            capacity: self.capacity.as_ref(),
            clock: self.clock.as_ref(),
            telemetry: self.telemetry.as_ref(),
            floor: &self.floor,
            pools: &self.pools,
        }
    }

    /// THE UNIT'S DEADLINE on the dispatcher's clock (`now_ns`), read once its route is known
    /// (ARCHITECT ruling 2026-10-07, STREAM-CEILING): the plane's stated stream ceiling from now,
    /// for a unit whose answer streams on a plane that states one. It bounds the whole streamed
    /// answer and a caller that stops reading it alike. `0` (none) otherwise: a plane that states
    /// no ceiling keeps the previous release's unbounded stream, and a buffered answer is bounded
    /// by the walk's own budget.
    #[must_use]
    pub fn deadline_ns(&self, route: &UnitRoute, now_ns: u64) -> u64 {
        if !route.wants_stream || self.stated_ceiling_secs == 0 {
            return 0;
        }
        now_ns.saturating_add(self.stated_ceiling_secs.saturating_mul(1_000_000_000))
    }

    /// The ceiling on a streamed answer's whole send, seconds: the plane's stated one, else the
    /// deployment's.
    fn send_ceiling_secs(&self) -> u64 {
        if self.stated_ceiling_secs == 0 {
            self.stream_ceiling_secs
        } else {
            self.stated_ceiling_secs
        }
    }

    /// One unit's far end, its walk starting now.
    #[must_use]
    pub fn unit(&self, route: UnitRoute) -> EgressFarEnd<'_> {
        let walk = Walk::start(&self.ports(), &route.pool);
        EgressFarEnd {
            egress: self,
            route,
            state: Mutex::new(State {
                walk,
                live: None,
                probe: None,
            }),
            probe_of: None,
        }
    }

    /// THE FAR END OF ONE HEALTH PROBE (K7) of `destination`, its walk bounded by `timeout`: pinned
    /// to that ONE member, which it reaches past the breaker's admission (a probe exists to reach a
    /// suppressed member) and without a permit, a dispatch record or the request counters, as
    /// 1.5.5's prober did. Its answer is recorded on every cell of the member ([`Breaker::probed`]).
    /// `None` for a member with no route, or one configured for passthrough: it holds no
    /// credential of its own, so a probe could only collect a refusal (1.5.5: "no key, no probe").
    #[must_use]
    pub fn probe(&self, destination: DestinationId, timeout: Duration) -> Option<EgressFarEnd<'_>> {
        let route = self.routes.get(&destination)?;
        if route.auth.as_ref().is_some_and(|a| a.passthrough) {
            return None;
        }
        let member = self
            .pools
            .values()
            .flat_map(|p| &p.members)
            .find(|m| m.destination == destination)?
            .clone();
        let walk = Walk::pinned(&self.ports(), timeout.as_secs().max(1));
        Some(EgressFarEnd {
            egress: self,
            route: UnitRoute::default(),
            state: Mutex::new(State {
                walk,
                live: None,
                probe: Some(member),
            }),
            probe_of: Some(destination),
        })
    }
}

/// The attempt in flight.
struct Live {
    pool: String,
    member: Member,
    permit: Option<Permit>,
    /// The probe this attempt owns, until it records an outcome.
    probe: Option<u64>,
    conn: Option<ConnId>,
    record: Dispatched,
    /// Degraded (a terminal's dispatch): an answered failure is relayed, never failed over.
    degraded: bool,
    /// The member relays the caller's own credential: its 401/403 is the caller's key failing.
    passthrough: bool,
    /// When the send started, ms.
    anchor_ms: u128,
    /// The far end answered.
    answered: bool,
    /// One unit of lifetime budget was spent on the success.
    spent: bool,
    /// A byte of the success's STREAMED answer reached the plane, so it is on its way to the
    /// caller (its first byte is delivered). Never set on a buffered answer: the caller receives
    /// none of it until the whole body is in.
    delivered: bool,
    /// The answer ended.
    ended: bool,
    /// A relayed non-success answer: how many more of its body's bytes the plane may be handed.
    error_left: Option<usize>,
    /// The keep rule of the need the attempt opened on.
    keep: ResponseKeep,
}

/// One unit's state: the egress unit's walk, the attempt in flight, and a health probe's one
/// member, not yet taken.
struct State {
    walk: Walk,
    live: Option<Live>,
    probe: Option<Member>,
}

/// ONE UNIT'S FAR END over its [`Egress`].
pub struct EgressFarEnd<'e> {
    egress: &'e Egress,
    route: UnitRoute,
    state: Mutex<State>,
    /// The member a health probe is pinned to; `None` for a unit's walk.
    probe_of: Option<DestinationId>,
}

fn exhausted(shed: &Shed) -> Pick {
    Pick::Exhausted {
        status: u32::from(shed.status),
        retry_after: shed
            .retry_after_secs
            .map(|s| u32::try_from(s).unwrap_or(u32::MAX)),
    }
}

/// The status class number a far-end piece carries (`abi::transport::STATUS_*`).
fn class_code(class: Option<WireStatusClass>) -> u32 {
    u32::from(match class {
        Some(WireStatusClass::Success) | None => STATUS_SUCCESS,
        Some(WireStatusClass::CallerFault) => STATUS_CALLER_FAULT,
        Some(WireStatusClass::FarEndFault) => STATUS_FAR_END_FAULT,
        Some(WireStatusClass::Other) => STATUS_OTHER,
    })
}

/// `base_url` + the plane's target: the base's trailing `/` trimmed, then the target as the plane
/// answered it.
fn join(base: &str, target: &[u8]) -> String {
    format!(
        "{}{}",
        base.trim_end_matches('/'),
        String::from_utf8_lossy(target)
    )
}

/// The authority (`host[:port]`) and the path of a joined target.
fn split(url: &str) -> (&str, &str) {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    }
}

/// A head the framer encodes. It carries auth values (credential material), so its bytes are
/// zeroised when it drops, once the connector's open has taken its copy.
struct Head(Vec<(String, Vec<u8>)>);

impl Head {
    fn wipe(&mut self) {
        for (_, v) in &mut self.0 {
            zeroize::Zeroize::zeroize(v);
        }
    }
}

impl Drop for Head {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Why an attempt ended before any answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NoAnswer {
    /// The far end could not be reached, or dropped the connection.
    Connect,
    /// A deadline passed first: the member's own attempt cap, or the walk's.
    Timeout,
}

impl NoAnswer {
    fn of(err: ConnError) -> Self {
        if err == ConnError::Timeout {
            Self::Timeout
        } else {
            Self::Connect
        }
    }
}

/// A far-end piece that ends the attempt without reaching the plane: fail over.
fn fail_over() -> FarPiece {
    FarPiece {
        fail_over: true,
        last: true,
        ..FarPiece::default()
    }
}

impl EgressFarEnd<'_> {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Settle the attempt before the next: close its connection, give back its permit, a probe it
    /// still owns, a budget unit a delivery that did not complete spent, and a dispatch record no
    /// answer settled.
    fn settle(&self, w: &mut State) {
        let Some(mut live) = w.live.take() else {
            return;
        };
        let e = self.egress;
        if let Some(conn) = live.conn.take() {
            let _closed = e.conns.close(e.caller, conn);
        }
        if let Some(epoch) = live.probe.take() {
            e.breaker.release_probe(
                &live.pool,
                live.member.destination,
                epoch,
                e.clock.now_secs(),
            );
        }
        // A unit dropped mid-answer refunds unless a byte of a streamed answer was delivered (spec
        // Part 2 #62, #77(2); v1.5.5 `crates/busbar/src/proxy/response_body.rs:279-306`). A buffered
        // answer dropped mid-read refunds, as 1.5.5's `budget_guard` did (`engine/mod.rs:229-256`).
        if live.spent && !live.ended && !live.delivered {
            e.breaker.refund_budget(live.member.destination);
        }
        if !live.answered && self.probe_of.is_none() {
            e.journal.abandoned(&live.record);
        }
        drop(live.permit.take());
    }

    fn metric_pool<'m>(pool: &'m str, member: &'m Member) -> &'m str {
        if pool.is_empty() {
            &member.name
        } else {
            pool
        }
    }

    /// Make the member the walk took the live attempt.
    fn admit_taken(&self, w: &mut State, taken: Taken) -> Pick {
        let Taken {
            pool,
            member,
            permit,
            probe,
            degraded,
            attempt,
        } = taken;
        self.claim_member(w, pool, member, Some(permit), probe, degraded, attempt)
    }

    /// Make `member` of `pool` the live attempt: the walk's take, or a health probe's one member
    /// (no permit, no probe epoch, not degraded).
    #[allow(clippy::too_many_arguments)]
    fn claim_member(
        &self,
        w: &mut State,
        pool: String,
        member: Member,
        permit: Option<Permit>,
        probe: Option<u64>,
        degraded: bool,
        attempt: u32,
    ) -> Pick {
        let record = Dispatched {
            leg: self.route.leg,
            attempt,
            pool: pool.clone(),
            destination: member.destination,
            lane: member.lane,
            unit: self.route.unit,
        };
        let name = member.name.clone();
        let route = self.egress.routes.get(&member.destination);
        let passthrough = member.passthrough
            || route
                .and_then(|r| r.auth.as_ref())
                .is_some_and(|a| a.passthrough);
        let provider = route.map(|r| r.provider.clone()).unwrap_or_default();
        w.live = Some(Live {
            pool: pool.clone(),
            member,
            permit,
            probe,
            conn: None,
            record,
            degraded,
            passthrough,
            anchor_ms: 0,
            answered: false,
            spent: false,
            delivered: false,
            ended: false,
            error_left: None,
            keep: ResponseKeep::default(),
        });
        Pick::Member {
            name,
            pool,
            passthrough,
            provider,
        }
    }

    /// THE WALK'S NEXT MEMBER, or its terminal: the egress unit's stepper, asked under the unit's
    /// lock; its one bounded wait (the queue) is awaited outside it.
    async fn next_member(&self, token: &Pass<Route>) -> Pick {
        let ports = self.egress.ports();
        let wait = {
            let mut w = self.lock();
            self.settle(&mut w);
            if !w.walk.ctx().expired(self.egress.clock.now_secs()) {
                if let Some(member) = w.probe.take() {
                    // ONE member: a probe that brings no answer has nowhere to fail over to, so
                    // every step after this one answers the pinned walk's shed.
                    return self.claim_member(&mut w, String::new(), member, None, None, false, 1);
                }
            }
            match w.walk.next(&ports, self.route.affinity, token) {
                Step::Take(taken) => return self.admit_taken(&mut w, taken),
                Step::Shed(shed) => return exhausted(&shed),
                Step::Wait(wait) => wait,
            }
        };
        let parked = self.lock().walk.park(&ports, &wait, token);
        let parked = match parked {
            Ok(parked) => parked,
            Err(shed) => return exhausted(&shed),
        };
        let waited = parked.wait(&ports).await;
        let mut w = self.lock();
        match w.walk.waited(&ports, waited, token) {
            Ok(taken) => self.admit_taken(&mut w, taken),
            Err(shed) => exhausted(&shed),
        }
    }

    /// A failure before any answer: a transient record on the member's cell; the attempt fails
    /// over. Counted as 1.5.5 counted it (v1.5.5 `crates/busbar/src/proxy/engine/mod.rs:1713-1781`):
    /// a member's own attempt cap that fires is an `attempt_timeout` on both series; any other
    /// failure is a `transient_upstream` failure that fails over under its network cause, `timeout`
    /// (the walk's own deadline) or `connect`.
    fn no_answer(&self, token: &Pass<Route>, cause: NoAnswer) -> FarPiece {
        let e = self.egress;
        let mut w = self.lock();
        if let Some(live) = w.live.as_mut() {
            let now = e.clock.now_secs();
            live.probe = None;
            let (failure, failover) = match cause {
                NoAnswer::Connect => (disposition::TRANSIENT, net::CONNECT),
                NoAnswer::Timeout if live.member.attempt_timeout_ms.is_some() => {
                    (disposition::ATTEMPT_TIMEOUT, disposition::ATTEMPT_TIMEOUT)
                }
                NoAnswer::Timeout => (disposition::TRANSIENT, net::TIMEOUT),
            };
            let outcome = Outcome::Transient { retry_after: None };
            if let Some(destination) = self.probe_of {
                // A probe's transport failure is a transient on every cell (1.5.5).
                e.breaker.probed(destination, outcome, now, token);
            } else {
                let pool = Self::metric_pool(&live.pool, &live.member).to_string();
                let destination = live.member.destination;
                if e.breaker
                    .observe(&live.pool, destination, outcome, now, token)
                {
                    e.telemetry.breaker_trip(&pool, destination);
                }
                e.telemetry.upstream_failure(&pool, destination, failure);
                e.telemetry.failover(&pool, failover);
            }
        }
        self.settle(&mut w);
        fail_over()
    }

    /// The live attempt's cap, ms: the member's attempt timeout, never beyond what the walk has
    /// left, never zero; the walk's remaining budget for a member with no cap.
    fn attempt_cap(&self) -> u64 {
        let w = self.lock();
        let remaining = w.walk.ctx().remaining_ms(self.egress.clock.now_millis());
        w.live
            .as_ref()
            .and_then(|l| l.member.attempt_timeout_ms)
            .map_or(remaining.max(1), |ms| attempt_cap_ms(ms, remaining))
    }

    /// Whether the live attempt's member is reached through its pool with the caller's credential.
    fn live_passthrough(&self) -> bool {
        self.lock()
            .live
            .as_ref()
            .is_some_and(|l| l.member.passthrough)
    }

    /// ONE CALL to the member's auth binding for this attempt's fields (THE DESIGN, section 6).
    async fn auth_fields(
        &self,
        binding: &AuthBinding,
        request: &OutboundRequest,
        url: &str,
        extensions: Vec<u8>,
    ) -> Option<Vec<AuthField>> {
        let (authority, path_query) = split(url);
        let (path, query) = match path_query.split_once('?') {
            Some((p, q)) => (p, Some(q.as_bytes().to_vec())),
            None => (path_query, None),
        };
        // The one call is made at the style's request point: `HeadBody` lends the whole body (the
        // style hashes it itself), `Head` lends none.
        let point = if binding.points.has(AuthPoint::HeadBody) {
            AuthPoint::HeadBody
        } else {
            AuthPoint::Head
        };
        let facts = FieldsRequest {
            point,
            body: (point == AuthPoint::HeadBody).then(|| request.body.clone()),
            method: request.verb.clone(),
            authority: authority.to_string(),
            path: path.as_bytes().to_vec(),
            query,
            timestamp: self.egress.clock.now_secs(),
            headers: if binding.style_flags & STYLE_NEEDS_HEADERS != 0 {
                request.fields.clone()
            } else {
                Vec::new()
            },
            // A passthrough member's one auth call is lent the caller's verified credential; a
            // caller who presented none lends an empty one, so nothing is presented (never the
            // operator's own key), as 1.5.5's `present_caller` did.
            caller_credential: if binding.passthrough || self.live_passthrough() {
                Some(
                    self.route
                        .caller_credential
                        .clone()
                        .unwrap_or_else(|| Redacted::new(Vec::new())),
                )
            } else {
                None
            },
            // The per-call scope the plane stated for this attempt (ARCHITECT round 5
            // Q-L3B-EXCHANGE (B): the caller's down-scope), in the call's extensions blob.
            extensions,
            ..FieldsRequest::default()
        };
        let answer = match binding.auth.fields_now(binding.handle, &facts) {
            Some(answer) => answer,
            // A plugin that must wait (a token refreshing) is awaited no longer than the attempt
            // may still take: its cap, never beyond what the walk has left (1.5.5's bound).
            None => tokio::time::timeout(
                Duration::from_millis(self.attempt_cap()),
                binding.auth.fields(binding.handle, facts, 0),
            )
            .await
            .unwrap_or(Fields::Failed),
        };
        match answer {
            Fields::Ready(fields) => Some(fields),
            Fields::Refused | Fields::Failed => None,
        }
    }

    /// Send the attempt: the dispatch record, the auth fields, the connector's open.
    async fn send_attempt(&self, token: &Pass<Route>, mut request: OutboundRequest) -> bool {
        let e = self.egress;
        // Busbar is invisible to upstreams; the per-connection mechanics are the connection's own.
        crate::proxy::strip_re_derived(&mut request.fields);
        // THE PLANE'S PER-CALL SCOPE rides its request as the host's own field
        // (`abi::auth::SCOPE_REQUEST_FIELD`): taken out here, before anything is encoded, and lent
        // to the member's auth call in its extensions blob. No wire carries it.
        let mut scope = None;
        request.fields.retain(|(name, value)| {
            if busbar_contract::abi::auth::is_scope_field(name) {
                scope.get_or_insert_with(|| value.clone());
                false
            } else {
                true
            }
        });
        let extensions = busbar_contract::abi::auth::scope_extensions(scope.as_deref());
        let (destination, record) = {
            let w = self.lock();
            let Some(live) = w.live.as_ref() else {
                return false;
            };
            (live.member.destination, live.record.clone())
        };
        let Some(route) = e.routes.get(&destination).cloned() else {
            return false;
        };
        // THE NEED IT RIDES: the one the far request names, bound for the member; a need the member
        // has no binding for is no destination's fault, and nothing is recorded or dialled.
        let Some((need, keep, base_url)) = route
            .ride(request.need)
            .map(|r| (r.need, r.keep.clone(), r.base_url.to_string()))
        else {
            let mut w = self.lock();
            self.settle(&mut w);
            return false;
        };
        // THE TARGET IS A PATH. Joined onto the operator's base_url, anything else could move the
        // authority (`@evil.test/x` makes `api.host@evil.test`) and carry the member's auth fields
        // to a host nobody configured: refused before the record, the auth call or the dial, and
        // nothing is recorded against the member. Then 1. the dispatch record, durable BEFORE the
        // dial; when it cannot be written nothing was recorded either. Neither has anything to
        // abandon. A probe moves no money and dispatches nothing a recovery would settle: it
        // writes no record.
        let path = request.target.starts_with(b"/");
        // A plane field whose name is not an RFC 9110 token is refused the same way: a `:` in a name
        // (`authorization:x`) is re-read as another field when the framer renders and parses its
        // head again, which steps around the same-name auth replacement below (whole names).
        let named = request
            .fields
            .iter()
            .all(|(n, _)| busbar_contract::header::is_header_name_token(n));
        let unrecorded =
            path && named && self.probe_of.is_none() && e.journal.dispatched(&record).is_err();
        if !path || !named || unrecorded {
            let mut w = self.lock();
            if let Some(live) = w.live.as_mut() {
                live.answered = true;
            }
            self.settle(&mut w);
            if unrecorded {
                // A dispatch this node cannot prove it recorded must not happen, on this member
                // or any other: the unit is refused at once with the internal error, as 1.5.5
                // refused every internal failure before a dispatch (v1.5.5
                // `crates/busbar/src/proxy/engine/mod.rs:1514-1526`, `:1621-1631`).
                w.walk.refuse(Shed::internal());
            }
            return false;
        }
        let url = join(&base_url, &request.target);
        // 2. The one auth call; its fields lead the head (1.5.5's order).
        let mut auth = Vec::new();
        if let Some(binding) = &route.auth {
            match self.auth_fields(binding, &request, &url, extensions).await {
                Some(fields) => auth = fields,
                None => {
                    // Not the destination's fault: nothing recorded against it; the next member.
                    let mut w = self.lock();
                    self.settle(&mut w);
                    return false;
                }
            }
        }
        // The method and the path (with its query) are the request's head words
        // (`OpenDesc::method`, `OpenDesc::head_target`), never fields: the framer writes its own
        // wire head from them.
        let (_, path) = split(&url);
        // The head's fields the framer encodes: the auth fields, then the plane's. It holds the
        // auth values, so it wipes itself when the open has taken it.
        let mut head = Head(Vec::with_capacity(request.fields.len() + auth.len()));
        // The auth fields FIRST, then the plane's: 1.5.5's egress header order.
        head.0.extend(auth.iter().map(|f| {
            (
                String::from_utf8_lossy(&f.name).into_owned(),
                f.value.expose_secret().clone(),
            )
        }));
        // A plane field named like an auth field never doubles it: the auth binding's stands.
        head.0.extend(
            request
                .fields
                .iter()
                .filter(|(n, _)| !auth.iter().any(|f| f.name.eq_ignore_ascii_case(n)))
                .map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), v.clone())),
        );
        drop(auth);
        let borrowed: Vec<(&str, &[u8])> = head
            .0
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_slice()))
            .collect();
        let cap_ms = self.attempt_cap();
        let pool = {
            let w = self.lock();
            w.live
                .as_ref()
                .map(|l| Self::metric_pool(&l.pool, &l.member).to_string())
                .unwrap_or_default()
        };
        if self.probe_of.is_none() {
            e.telemetry.upstream_attempt(&pool, destination);
        }
        // 3. The connector: the judged, pinned dial and the framer's encode.
        let opened = e.conns.open(
            e.caller,
            need,
            &OpenDesc {
                target: &url,
                fields: &borrowed,
                // A TEXT message rides no opening: the connection opens bare and the message is
                // written to it as text once open (the opening carries no text bit).
                body: if request.text { &[] } else { &request.body },
                timeout_ms: cap_ms,
                method: &request.verb,
                head_target: path.as_bytes(),
                within: &[],
                // The registration the member route reaches: what the host sealed for it alone
                // (its private reach) applies to this dial.
                member: &route.provider,
            },
        );
        let now_ms = e.clock.now_millis();
        match opened {
            Ok(conn) => {
                {
                    let mut w = self.lock();
                    if let Some(live) = w.live.as_mut() {
                        live.keep = keep;
                        live.conn = Some(conn);
                        live.anchor_ms = now_ms;
                    }
                }
                if request.text && !request.body.is_empty() {
                    return self.write_to(conn, &request.body, true).await;
                }
                true
            }
            Err(err) => {
                let _ = self.no_answer(token, NoAnswer::of(err));
                false
            }
        }
    }

    /// A HELD FAR END's next frame: `body`, as one message, into the live attempt's connection,
    /// once its far end has answered and while its answer has not ended. The connection's own
    /// buffer takes it; while it is full the write waits a short, growing pause and offers the rest
    /// again (the table's write registers no waker), bounded by the session's own waits.
    async fn write_frame(&self, body: Vec<u8>, text: bool) -> bool {
        let conn = {
            let w = self.lock();
            match w.live.as_ref() {
                Some(live) if live.answered && !live.ended => live.conn,
                _ => None,
            }
        };
        let Some(conn) = conn else {
            return false;
        };
        self.write_to(conn, &body, text).await
    }

    /// Write `body` whole to `conn` as one message (`text` = a text message), pausing on a full
    /// buffer.
    async fn write_to(&self, conn: ConnId, body: &[u8], text: bool) -> bool {
        let e = self.egress;
        let (mut at, mut pause_ms) = (0, 1);
        loop {
            match e.conns.write(e.caller, conn, &body[at..], true, text) {
                Ok(n) => {
                    at += n;
                    if at >= body.len() {
                        return true;
                    }
                    pause_ms = 1;
                }
                Err(ConnError::Pending) => {
                    tokio::time::sleep(Duration::from_millis(pause_ms)).await;
                    pause_ms = (pause_ms * 2).min(WRITE_PAUSE_MAX_MS);
                }
                Err(_) => return false,
            }
        }
    }

    /// The next piece of the live attempt's answer.
    async fn next_piece(&self, token: &Pass<Route>) -> Option<FarPiece> {
        let e = self.egress;
        let (conn, answered, wait_ms) = {
            let w = self.lock();
            let live = w.live.as_ref()?;
            if live.ended {
                return None;
            }
            let conn = live.conn?;
            let now = e.clock.now_millis();
            let remaining = w.walk.ctx().remaining_ms(now);
            let wait = if live.answered {
                // The whole send: the stream ceiling from the anchor, or what is left of the walk's
                // budget, which is already measured from the unit's start (subtracting the time
                // since the anchor again cut a buffered answer at half its budget).
                if self.route.wants_stream {
                    let ceiling = e.send_ceiling_secs().max(1).saturating_mul(1000);
                    let spent =
                        u64::try_from(now.saturating_sub(live.anchor_ms)).unwrap_or(u64::MAX);
                    ceiling.saturating_sub(spent)
                } else {
                    remaining.max(1)
                }
            } else {
                live.member
                    .attempt_timeout_ms
                    .map_or(remaining.max(1), |ms| attempt_cap_ms(ms, remaining))
            };
            (conn, live.answered, wait)
        };
        let mut buf = vec![0u8; READ_BYTES];
        let read = tokio::time::timeout(
            Duration::from_millis(wait_ms),
            std::future::poll_fn(|cx| e.conns.poll_read(e.caller, conn, cx, &mut buf)),
        )
        .await;
        let piece = match read {
            Err(_elapsed) if !answered => {
                return Some(self.no_answer(token, NoAnswer::Timeout));
            }
            Ok(Err(err)) if !answered => {
                return Some(self.no_answer(token, NoAnswer::of(err)));
            }
            // After the first answer a failure or a spent deadline ends the answer here: the
            // caller has what arrived, and there is nothing to fail over to.
            Err(_) | Ok(Err(_)) => return Some(self.cut(token)),
            Ok(Ok(piece)) => piece,
        };
        match piece.kind {
            PieceKind::Completion => Some(self.end(true)),
            // THE FAR END'S HEAD (HEAD-FIELDS: a framer yields the response head as the FIRST
            // Fields piece, always): the answer's status, and the head fields its need keeps.
            PieceKind::Fields if !answered => Some(self.head(token, &piece, &buf[..piece.len])),
            // The far end's fields after its body (trailers): handed to the plane, which decides
            // what they mean (one that reads a trailer status reads it; any other ignores them).
            PieceKind::Fields | PieceKind::HookReply => {
                let piece = FarPiece {
                    bytes: buf[..piece.len].to_vec(),
                    fields: true,
                    ..FarPiece::default()
                };
                if let Some(live) = self.lock().live.as_mut() {
                    delivered(live, &piece, self.route.wants_stream);
                }
                Some(piece)
            }
            PieceKind::Body if answered => Some(self.capped(FarPiece {
                bytes: buf[..piece.len].to_vec(),
                ..FarPiece::default()
            })),
            PieceKind::Body => Some(self.first(token, &piece, buf[..piece.len].to_vec())),
        }
    }

    /// The answer's HEAD: its status judged as the first answer is ([`Self::first`]), and the
    /// fields of its block the member's need keeps, names lower-case, in the far end's order.
    fn head(
        &self,
        token: &Pass<Route>,
        piece: &busbar_contract::conn::Piece,
        block: &[u8],
    ) -> FarPiece {
        use busbar_contract::abi::transport::fields::lines;
        let keep = {
            let w = self.lock();
            w.live.as_ref().map(|l| l.keep.clone()).unwrap_or_default()
        };
        let nominated: Vec<&[u8]> = lines(block)
            .filter(|(n, _)| n.eq_ignore_ascii_case(b"connection"))
            .map(|(_, v)| v)
            .collect();
        let head: Vec<(Vec<u8>, Vec<u8>)> = lines(block)
            .filter_map(|(n, v)| {
                let name = String::from_utf8_lossy(n).to_ascii_lowercase();
                keep.keeps(&name, nominated.iter().copied())
                    .then(|| (name.into_bytes(), v.to_vec()))
            })
            .collect();
        let mut answer = self.first(token, piece, Vec::new());
        if !answer.fail_over {
            answer.head = head;
        }
        answer
    }

    /// A body piece of the answer, under the error-body cap when the answer is a relayed failure.
    fn capped(&self, piece: FarPiece) -> FarPiece {
        let mut w = self.lock();
        let Some(live) = w.live.as_mut() else {
            return piece;
        };
        let piece = cap(live, piece);
        delivered(live, &piece, self.route.wants_stream);
        if piece.last {
            // The rest is never read: the connection closes and the member's slot frees.
            self.settle(&mut w);
        }
        piece
    }

    /// THE ANSWER WAS CUT after its head: the connection failed or the send's deadline passed
    /// before it completed. A success's head was recorded as a success, but the answer never
    /// arrived intact, so a COMPENSATING transient failure is recorded against the member (v1.5.5
    /// `crates/busbar/src/proxy/response_body.rs:279-306`, `:358-409`). The budget unit its success
    /// spent is given back unless a byte of a STREAMED answer was delivered: a stream cut before its
    /// first byte (1.5.5's pre-first-byte arm, `response_body.rs:358-409`) and a buffered answer cut
    /// at any point (its buffered read, `engine/mod.rs:329-353`, and its non-stream body's
    /// post-first-byte arm, `response_body.rs:358-409`) delivered nothing to the caller. After a
    /// streamed answer's first byte a cut is NOT a refund: the delivered units settle like any
    /// other end (spec Part 2 #62, #77(2); `response_body.rs:279-306`). A relayed failure's body
    /// that is cut recorded its own outcome on its head and is not compensated.
    fn cut(&self, token: &Pass<Route>) -> FarPiece {
        let e = self.egress;
        {
            let w = self.lock();
            if let Some(live) = w.live.as_ref().filter(|l| l.error_left.is_none()) {
                let pool = Self::metric_pool(&live.pool, &live.member).to_string();
                if e.breaker.observe(
                    &live.pool,
                    live.member.destination,
                    Outcome::Transient { retry_after: None },
                    e.clock.now_secs(),
                    token,
                ) {
                    e.telemetry.breaker_trip(&pool, live.member.destination);
                }
            }
        }
        self.end(false)
    }

    /// The answer ended: `clean` keeps the budget unit its success spent.
    fn end(&self, clean: bool) -> FarPiece {
        let mut w = self.lock();
        if let Some(live) = w.live.as_mut() {
            if !clean && live.spent && !live.delivered {
                // A delivery that did not complete gives its budget unit back unless a byte of a
                // streamed answer was delivered: a mid-stream cut is not a refund (spec Part 2 #62,
                // #77(2)); a buffered answer delivered nothing (v1.5.5 `engine/mod.rs:329-353`).
                self.egress.breaker.refund_budget(live.member.destination);
            }
            live.spent = false;
            live.ended = true;
        }
        self.settle(&mut w);
        FarPiece {
            last: true,
            ..FarPiece::default()
        }
    }

    /// THE FIRST ANSWER: the breaker's Disposition of its status (step 24).
    fn first(
        &self,
        token: &Pass<Route>,
        piece: &busbar_contract::conn::Piece,
        bytes: Vec<u8>,
    ) -> FarPiece {
        let e = self.egress;
        let now = e.clock.now_secs();
        // The numbering the far end's status is in, when it is one the kernel reserves; the
        // first reserved numbering otherwise (the one a response head carries).
        let namespace = piece
            .status_namespace
            .as_deref()
            .and_then(|ns| status_ns::RESERVED.iter().copied().find(|r| *r == ns))
            .unwrap_or(status_ns::RESERVED[0]);
        let status = UpstreamStatus {
            class: piece.status,
            code: piece.status_code.map(|c| WireStatus::new(namespace, c)),
            retry_after: piece.retry_after_secs,
        };
        let far_status = Some((piece.status_code.unwrap_or(0), class_code(piece.status)));
        let mut w = self.lock();
        let Some(live) = w.live.as_mut() else {
            return fail_over();
        };
        live.answered = true;
        if let Some(destination) = self.probe_of {
            // THE PROBE'S ANSWER, classified as organic traffic is, recorded on every cell of its
            // member; the plane is handed the first piece as the whole answer and the rest is
            // never read.
            let outcome = if matches!(status.class, Some(WireStatusClass::Success) | None) {
                Outcome::Success
            } else {
                e.breaker.classify(destination, status).outcome
            };
            e.breaker.probed(destination, outcome, now, token);
            live.ended = true;
            self.settle(&mut w);
            return FarPiece {
                bytes,
                status: far_status,
                last: true,
                ..FarPiece::default()
            };
        }
        let pool = Self::metric_pool(&live.pool, &live.member).to_string();
        let destination = live.member.destination;
        if matches!(status.class, Some(WireStatusClass::Success) | None) {
            e.breaker
                .observe(&live.pool, destination, Outcome::Success, now, token);
            // The request owns the probe through the outcome it just recorded.
            live.probe = None;
            live.spent = e.breaker.spend_budget(destination);
            live.delivered = self.route.wants_stream && !bytes.is_empty();
            return FarPiece {
                bytes,
                status: far_status,
                last: false,
                fail_over: false,
                fields: false,
                head: Vec::new(),
            };
        }
        let classified = e.breaker.classify(destination, status);
        let hard = matches!(classified.disposition, Disposition::HardDown);
        // A passthrough member's rejected key is the CALLER's, not the destination's: nothing is
        // recorded and the answer goes back as it came (1.5.5's attempt classifier).
        let callers_key = hard && live.passthrough;
        if !callers_key
            && e.breaker
                .observe(&live.pool, destination, classified.outcome, now, token)
        {
            e.telemetry.breaker_trip(&pool, destination);
        }
        // A recorded outcome resolves a probe this attempt won. An answer that records NOTHING (the
        // caller's own fault, a request too large for the window, a passthrough member's rejected
        // key) resolves none, so the probe stays the attempt's and the settle gives it back,
        // owner-checked: 1.5.5 released it on exactly these exits or the member stayed wedged
        // half-open (v1.5.5 `crates/busbar/src/proxy/engine/mod.rs:1900-1912`, `:2131-2138`).
        if !callers_key && !matches!(classified.outcome, Outcome::RecordNothing) {
            live.probe = None;
        }
        // The caller's own fault is not the destination's, a hard-down is the plane's to render
        // (its verdict: an auth failure ends the unit, a billing one retries), a degraded dispatch
        // relays the upstream's answer, and an operation performed at most once is not repeated on
        // another member once one answered: each reaches the plane as it came.
        let client_fault = matches!(classified.disposition, Disposition::ClientFault);
        if client_fault || hard || live.degraded || self.route.once {
            if !client_fault && !callers_key {
                e.telemetry
                    .upstream_failure(&pool, destination, classified.label);
            }
            live.error_left = Some(e.error_body_max);
            let piece = cap(
                live,
                FarPiece {
                    bytes,
                    status: far_status,
                    last: false,
                    fail_over: false,
                    fields: false,
                    head: Vec::new(),
                },
            );
            if piece.last {
                self.settle(&mut w);
            }
            return piece;
        }
        e.telemetry
            .upstream_failure(&pool, destination, classified.label);
        e.telemetry.failover(&pool, classified.label);
        if matches!(classified.disposition, Disposition::ContextLength) {
            // Every ADMISSIBLE member whose window is at or below the one that refused would refuse
            // too: the walk's own exclusion.
            let (pool, failed) = (live.pool.clone(), live.member.clone());
            w.walk.refused_for_size(&e.ports(), &pool, &failed);
        }
        self.settle(&mut w);
        fail_over()
    }
}

impl Drop for EgressFarEnd<'_> {
    /// A unit dropped mid-attempt settles it: the connection closed, the permit and an owned probe
    /// given back, the budget unit of a delivery that did not complete refunded.
    fn drop(&mut self) {
        let mut w = self.lock();
        self.settle(&mut w);
    }
}

impl FarEnd for EgressFarEnd<'_> {
    fn deadline_ns(&self, now_ns: u64) -> u64 {
        self.egress.deadline_ns(&self.route, now_ns)
    }

    fn member<'a>(
        &'a self,
        token: &'a Pass<Route>,
        _attempt_no: u32,
    ) -> impl Future<Output = Pick> + Send + 'a {
        self.next_member(token)
    }

    fn send<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        self.send_attempt(token, request)
    }

    fn next<'a>(
        &'a self,
        token: &'a Pass<Route>,
    ) -> impl Future<Output = Option<FarPiece>> + Send + 'a {
        self.next_piece(token)
    }

    fn write<'a>(
        &'a self,
        _token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        self.write_frame(request.body, request.text)
    }
}

#[cfg(test)]
#[path = "tests/far_end_tests.rs"]
mod tests;

/// Whether `piece`, handed to the plane, delivers a byte of `live`'s SUCCESS answer to the caller:
/// from then on a cut is not a refund (spec Part 2 #62). Only a `streamed` answer delivers as it
/// goes; a buffered one reaches the caller whole or not at all, so every cut of it refunds, as
/// 1.5.5's buffered read did (v1.5.5 `crates/busbar/src/proxy/engine/mod.rs:329-353`).
fn delivered(live: &mut Live, piece: &FarPiece, streamed: bool) {
    if streamed && live.answered && live.error_left.is_none() && !piece.bytes.is_empty() {
        live.delivered = true;
    }
}

/// THE ERROR-BODY CAP on one body piece of `live`'s answer: a success's body passes whole; a relayed
/// failure's is handed over up to what is left of the cap, and a piece that overruns it is cut
/// there and ends the answer (the caller settles the attempt; the rest is never read).
fn cap(live: &mut Live, mut piece: FarPiece) -> FarPiece {
    let Some(left) = live.error_left.as_mut() else {
        return piece;
    };
    if piece.bytes.len() <= *left {
        *left -= piece.bytes.len();
        return piece;
    }
    piece.bytes.truncate(*left);
    *left = 0;
    live.ended = true;
    piece.last = true;
    piece
}
