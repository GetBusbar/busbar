// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PRODUCTION FAR END (`BUSBAR-1.6.0.md` Part 3, §12 "The route pump"; THE DESIGN, §5 "One
//! outbound request, kernel to wire", section 6): the kernel's egress walk for one unit, one attempt at a
//! time, as the pump asks for it. The driver builds no second walk: every decision here is the
//! egress unit's own — the pick over the pool with its breaker and its
//! permits ([`select::pick_among`]), the pool's exhaustion terminals and their Retry-After floor
//! ([`exhaustion::retry_after_secs`]), the breaker's classification of the far end's status and
//! its record ([`Breaker::classify`], [`Breaker::observe`]) — and the wire is the connector's.
//!
//! Per attempt, in order:
//!
//! 1. [`FarEnd::member`]: the walk's pick (breaker admit + permit, probe owned by the attempt), or
//!    the pool's terminal: the shed with its Retry-After floor, the spill into a fallback pool, the
//!    one breaker bypass (least-bad), or the bounded wait for a permit (queue).
//! 2. [`FarEnd::send`]: the durable dispatch record, then ONE `fields` call to the member's auth
//!    binding (THE DESIGN, section 6: the kernel's one call, no kernel-side cache), whose fields lead the
//!    head before the plane's (1.5.5's egress order), then the connector's open on the plane's declared need, at the target
//!    the member's sealed `base_url` and the plane's path spell. The connector judges and pins the
//!    address and dials exactly it (CONNECTOR-19), so a name's refusal keeps 1.5.5's timing.
//! 3. [`FarEnd::next`]: the connector's pieces, read through the task's own waker
//!    ([`PollConns::poll_read`]). On the first status the breaker classifies it (the step-24
//!    `Disposition`): a success is recorded and spends one unit of the member's lifetime budget; a
//!    caller fault is relayed to the plane as it came; a transient or hard failure is recorded
//!    (a 401 takes the member down across every pool) and the piece fails over before the plane
//!    sees it. A failure before any answer — refused, reset, the attempt's cap — fails over too.
//!
//! Deadlines are 1.5.5's: the walk's whole budget is the pool's request timeout, measured from the
//! unit's start; the first answer is bounded by the member's attempt cap (never beyond what the walk
//! has left); the whole send by the walk's remaining budget, or the stream ceiling for a streamed
//! answer.
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
    exhaustion::retry_after_secs,
    ports::{
        disposition, net, Breaker, Capacity, Clock, DestinationId, Dispatched, Disposition,
        Journal, Outcome, Permit, Telemetry, Unavailable, UpstreamStatus,
    },
    race,
    select::{pick_among, PickInput},
    walk::exclude_smaller_windows,
    Member, OnExhausted, Pool, RequestCtx, Shed, WeightedFloor,
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

/// 1.5.5's cap on a buffered far-end ERROR body (`limits.upstream_error_body_max_bytes`, default
/// 256 KiB; v1.5.5 `DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES`, config/mod.rs): the default for
/// [`Egress::error_body_max`].
pub const DEFAULT_ERROR_BODY_MAX: usize = 256 * 1024;

/// One member's sealed route: the need the plane declared for it, the `base_url` the target is
/// joined onto, and its auth binding.
#[derive(Clone)]
pub struct MemberRoute {
    /// The plane instance's declared need the connection opens on.
    pub need: NeedId,
    /// The provider's `base_url`, as the operator spelled it.
    pub base_url: String,
    /// The auth binding the root opened at generation seal; `None` = no auth fields.
    pub auth: Option<AuthBinding>,
    /// The provider the member is served by: the metering row's provider column, as 1.5.5's
    /// `lane.provider` (v1.5.5 `crates/busbar/src/proxy/usage.rs` `ledger_and_meter`).
    pub provider: String,
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
    /// The ceiling on a streamed answer's whole send, seconds.
    pub stream_ceiling_secs: u64,
    /// The most bytes of a relayed non-success answer's body the plane is handed (the operator's
    /// `limits.upstream_error_body_max_bytes`, [`DEFAULT_ERROR_BODY_MAX`] unset). What overruns it
    /// is dropped and the answer ends there, as 1.5.5's capped read did: an error envelope is far
    /// smaller, and one that overruns it can only be malformed or hostile.
    pub error_body_max: usize,
}

/// What one unit's walk is told at its start.
#[derive(Debug, Clone, Default)]
pub struct UnitRoute {
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
}

impl Egress {
    /// The walk's whole budget for a unit over `pool`, seconds (the pool's request timeout).
    #[must_use]
    pub fn budget_secs(&self, pool: &str) -> u64 {
        self.pools.get(pool).map_or(0, |p| p.failover.timeout_secs)
    }

    /// THE UNIT'S DEADLINE on the dispatcher's clock (`now_ns`): the pool's request timeout, or the
    /// stream ceiling when the answer streams — the bound 1.5.5 put on the whole exchange. `0` (none)
    /// only for a pool with no timeout.
    #[must_use]
    pub fn deadline_ns(&self, route: &UnitRoute, now_ns: u64) -> u64 {
        let secs = if route.wants_stream {
            self.stream_ceiling_secs.max(self.budget_secs(&route.pool))
        } else {
            self.budget_secs(&route.pool)
        };
        if secs == 0 {
            return 0;
        }
        now_ns.saturating_add(secs.saturating_mul(1_000_000_000))
    }

    /// One unit's far end, its walk starting now.
    #[must_use]
    pub fn unit(&self, route: UnitRoute) -> EgressFarEnd<'_> {
        let ctx = RequestCtx::new(
            self.budget_secs(&route.pool),
            self.clock.now_secs(),
            self.clock.now_millis(),
        );
        let phase = Phase::Primary(route.pool.clone());
        EgressFarEnd {
            egress: self,
            route,
            walk: Mutex::new(Walk {
                ctx,
                phase,
                hops: 0,
                live: None,
            }),
        }
    }
}

/// Where the walk is.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    /// The ordered walk over the unit's pool.
    Primary(String),
    /// The pool's members are spent: its terminal runs next.
    Terminal(String),
    /// A spill into this pool (degraded).
    Spill(String),
    /// Every path is spent: the next pick is this shed.
    Shed(u16, Option<u64>),
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
    /// When the send started, ms.
    anchor_ms: u128,
    /// The far end answered.
    answered: bool,
    /// One unit of lifetime budget was spent on the success.
    spent: bool,
    /// The answer ended.
    ended: bool,
    /// A relayed non-success answer: how many more of its body's bytes the plane may be handed.
    error_left: Option<usize>,
}

/// One unit's walk.
struct Walk {
    ctx: RequestCtx,
    phase: Phase,
    /// Primary attempts taken.
    hops: usize,
    live: Option<Live>,
}

/// ONE UNIT'S FAR END over its [`Egress`].
pub struct EgressFarEnd<'e> {
    egress: &'e Egress,
    route: UnitRoute,
    walk: Mutex<Walk>,
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

/// The phase that answers `shed` from here on.
fn shed_phase(shed: &Pick) -> Phase {
    match shed {
        Pick::Exhausted {
            status,
            retry_after,
        } => Phase::Shed(
            u16::try_from(*status).unwrap_or(503),
            retry_after.map(u64::from),
        ),
        Pick::Member { .. } => Phase::Shed(503, None),
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

/// A far-end piece that ends the attempt without reaching the plane: fail over.
fn fail_over() -> FarPiece {
    FarPiece {
        fail_over: true,
        last: true,
        ..FarPiece::default()
    }
}

impl EgressFarEnd<'_> {
    fn lock(&self) -> std::sync::MutexGuard<'_, Walk> {
        self.walk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Settle the attempt before the next: close its connection, give back its permit, a probe it
    /// still owns, a budget unit a delivery that did not complete spent, and a dispatch record no
    /// answer settled.
    fn settle(&self, w: &mut Walk) {
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
        if live.spent && !live.ended {
            e.breaker.refund_budget(live.member.destination);
        }
        if !live.answered {
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

    /// Make `member` of `pool` the live attempt: excluded from every later pick of the unit.
    fn take(
        &self,
        w: &mut Walk,
        pool: &str,
        member: Member,
        permit: Permit,
        probe: Option<u64>,
        degraded: bool,
    ) -> Pick {
        w.ctx.exclude(member.destination);
        let attempt = u32::try_from(w.hops).unwrap_or(u32::MAX);
        let record = Dispatched {
            leg: self.route.leg,
            attempt,
            pool: pool.to_string(),
            destination: member.destination,
            lane: member.lane,
        };
        let name = member.name.clone();
        let route = self.egress.routes.get(&member.destination);
        let passthrough = route
            .and_then(|r| r.auth.as_ref())
            .is_some_and(|a| a.passthrough);
        let provider = route.map(|r| r.provider.clone()).unwrap_or_default();
        w.live = Some(Live {
            pool: pool.to_string(),
            member,
            permit: Some(permit),
            probe,
            conn: None,
            record,
            degraded,
            anchor_ms: 0,
            answered: false,
            spent: false,
            ended: false,
            error_left: None,
        });
        Pick::Member {
            name,
            pool: pool.to_string(),
            passthrough,
            provider,
        }
    }

    /// One pick over `pool`'s members, the ones this unit has not tried.
    fn pick(&self, w: &mut Walk, pool: &Pool, token: &Pass<Route>, primary: bool) -> Option<Pick> {
        let e = self.egress;
        let members = pool.admissible_members();
        let now = e.clock.now_secs();
        let mut picked = pick_among(
            &PickInput {
                breaker: e.breaker.as_ref(),
                capacity: e.capacity.as_ref(),
                floor: &e.floor,
                pool: &pool.name,
                members: &members,
                affinity: if primary { self.route.affinity } else { None },
                preference: None,
                now,
                token,
            },
            &mut w.ctx,
        )?;
        let member = members
            .iter()
            .find(|m| m.destination == picked.destination)?
            .clone();
        let probe = picked.take_probe_epoch();
        Some(self.take(w, &pool.name, member, picked.permit, probe, !primary))
    }

    /// The shed for `pool`: refuse, with the wait its own members justify.
    fn shed(&self, pool: &str, token: &Pass<Route>) -> Pick {
        let e = self.egress;
        let members = e
            .pools
            .get(pool)
            .map(|p| p.admissible_members().into_owned())
            .unwrap_or_default();
        let secs = retry_after_secs(
            e.breaker.as_ref(),
            &members,
            pool,
            e.clock.now_secs(),
            token,
        );
        exhausted(&Shed::overloaded(secs))
    }

    /// THE WALK'S NEXT MEMBER, or its terminal.
    async fn next_member(&self, token: &Pass<Route>) -> Pick {
        let e = self.egress;
        loop {
            let terminal = {
                let mut w = self.lock();
                self.settle(&mut w);
                if w.ctx.expired(e.clock.now_secs()) {
                    return exhausted(&Shed::request_timeout());
                }
                match w.phase.clone() {
                    Phase::Shed(status, retry_after) => {
                        return exhausted(&Shed {
                            status,
                            retry_after_secs: retry_after,
                            ..Shed::overloaded(0)
                        })
                    }
                    Phase::Primary(name) => {
                        let Some(pool) = e.pools.get(&name) else {
                            return exhausted(&Shed::empty_pool());
                        };
                        if pool.admissible_members().is_empty() {
                            return exhausted(&Shed::empty_pool());
                        }
                        if w.hops <= pool.failover.max_hops {
                            if let Some(pick) = self.pick(&mut w, pool, token, true) {
                                w.hops += 1;
                                return pick;
                            }
                        }
                        w.phase = Phase::Terminal(name);
                        continue;
                    }
                    Phase::Spill(name) => {
                        let Some(pool) = e.pools.get(&name) else {
                            return self.shed(&name, token);
                        };
                        if let Some(pick) = self.pick(&mut w, pool, token, false) {
                            return pick;
                        }
                        w.phase = Phase::Terminal(name);
                        continue;
                    }
                    Phase::Terminal(name) => {
                        w.ctx.mark_pool_visited(&name);
                        let Some(pool) = e.pools.get(&name) else {
                            return self.shed(&name, token);
                        };
                        match &pool.on_exhausted {
                            OnExhausted::Status503 => return self.shed(&name, token),
                            OnExhausted::FallbackPool(target) => {
                                if w.ctx.is_pool_visited(target) || !e.pools.contains_key(target) {
                                    // The loop guard, or a target never configured: the shed with
                                    // the empty-set floor.
                                    let secs = retry_after_secs(
                                        e.breaker.as_ref(),
                                        &[],
                                        target,
                                        e.clock.now_secs(),
                                        token,
                                    );
                                    return exhausted(&Shed::overloaded(secs));
                                }
                                w.ctx.mark_pool_visited(target);
                                w.phase = Phase::Spill(target.clone());
                                continue;
                            }
                            OnExhausted::LeastBad => {
                                // A least-bad dispatch that brings no answer is the shed.
                                let shed = self.shed(&name, token);
                                w.phase = shed_phase(&shed);
                                return self.least_bad(&mut w, pool, token).unwrap_or(shed);
                            }
                            OnExhausted::Queue { max_ms } => (name, *max_ms),
                        }
                    }
                }
            };
            return self.queue(token, &terminal.0, terminal.1).await;
        }
    }

    /// The one documented breaker bypass: the admissible member with the soonest cooldown and a
    /// free slot, owning no probe (`exhaustion::handle_least_bad`).
    fn least_bad(&self, w: &mut Walk, pool: &Pool, token: &Pass<Route>) -> Option<Pick> {
        let e = self.egress;
        let now = e.clock.now_secs();
        let members = pool.admissible_members();
        let mut ranked: Vec<&Member> = members
            .iter()
            .filter(|m| e.breaker.admissible(m.destination))
            .collect();
        ranked.sort_by_key(|m| {
            e.breaker
                .cooldown_remaining(&pool.name, m.destination, now, token)
        });
        let (member, permit) = ranked.into_iter().find_map(|m| {
            e.capacity
                .try_acquire(m.destination)
                .map(|p| ((*m).clone(), p))
        })?;
        Some(self.take(w, &pool.name, member, permit, None, true))
    }

    /// The bounded wait for a slot on a member passed over AT CAPACITY, then the breaker re-asked
    /// on the member that freed one (`exhaustion::handle_queue`); the shed when nothing frees.
    async fn queue(&self, token: &Pass<Route>, pool_name: &str, max_ms: u64) -> Pick {
        let e = self.egress;
        let Some(pool) = e.pools.get(pool_name) else {
            return self.shed(pool_name, token);
        };
        let (mut waiting, bound_ms, started) = {
            let w = self.lock();
            let mut waiting: Vec<DestinationId> = Vec::new();
            for (destination, reason) in w.ctx.excluded_reasons() {
                if matches!(reason, Unavailable::AtCapacity { .. })
                    && !waiting.contains(destination)
                {
                    waiting.push(*destination);
                }
            }
            let started = e.clock.now_millis();
            (waiting, max_ms.min(w.ctx.remaining_ms(started)), started)
        };
        let members = pool.admissible_members();
        e.telemetry.queued(&pool.name, 1);
        let pick = loop {
            if waiting.is_empty() {
                break None;
            }
            let spent = e.clock.now_millis().saturating_sub(started);
            let left = bound_ms.saturating_sub(u64::try_from(spent).unwrap_or(u64::MAX));
            let won =
                race::deadline_first(e.capacity.acquire_any(&waiting), e.clock.sleep(left)).await;
            let Ok(Some((destination, permit))) = won else {
                break None;
            };
            match e
                .breaker
                .try_admit(&pool.name, destination, e.clock.now_secs())
            {
                Ok(admit) => {
                    let Some(member) = members.iter().find(|m| m.destination == destination) else {
                        break None;
                    };
                    let mut w = self.lock();
                    let pick = self.take(
                        &mut w,
                        &pool.name,
                        member.clone(),
                        permit,
                        admit.probe_epoch,
                        true,
                    );
                    break Some(pick);
                }
                Err(_) => {
                    drop(permit);
                    waiting.retain(|d| *d != destination);
                }
            }
        };
        e.telemetry.queued(&pool.name, -1);
        let shed = self.shed(pool_name, token);
        self.lock().phase = shed_phase(&shed);
        pick.unwrap_or(shed)
    }

    /// A failure before any answer: a transient record on the member's cell, counted under
    /// `label`; the attempt fails over (`attempt::transport_failure`).
    fn no_answer(&self, token: &Pass<Route>, label: &'static str) -> FarPiece {
        let e = self.egress;
        let mut w = self.lock();
        if let Some(live) = w.live.as_mut() {
            let now = e.clock.now_secs();
            live.probe = None;
            let pool = Self::metric_pool(&live.pool, &live.member).to_string();
            if e.breaker.observe(
                &live.pool,
                live.member.destination,
                Outcome::Transient { retry_after: None },
                now,
                token,
            ) {
                e.telemetry.breaker_trip(&pool, live.member.destination);
            }
            e.telemetry
                .upstream_failure(&pool, live.member.destination, label);
            e.telemetry.failover(&pool, label);
        }
        self.settle(&mut w);
        fail_over()
    }

    /// The live attempt's cap, ms: the member's attempt timeout, never beyond what the walk has
    /// left, never zero; the walk's remaining budget for a member with no cap.
    fn attempt_cap(&self) -> u64 {
        let w = self.lock();
        let remaining = w.ctx.remaining_ms(self.egress.clock.now_millis());
        w.live
            .as_ref()
            .and_then(|l| l.member.attempt_timeout_ms)
            .map_or(remaining.max(1), |ms| attempt_cap_ms(ms, remaining))
    }

    /// ONE CALL to the member's auth binding for this attempt's fields (THE DESIGN, section 6).
    async fn auth_fields(
        &self,
        binding: &AuthBinding,
        request: &OutboundRequest,
        url: &str,
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
            caller_credential: if binding.passthrough {
                self.route.caller_credential.clone()
            } else {
                None
            },
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
    async fn send_attempt(&self, token: &Pass<Route>, request: OutboundRequest) -> bool {
        let e = self.egress;
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
        // THE TARGET IS A PATH. Joined onto the operator's base_url, anything else could move the
        // authority (`@evil.test/x` makes `api.host@evil.test`) and carry the member's auth fields
        // to a host nobody configured: refused before the record, the auth call or the dial, and
        // nothing is recorded against the member.
        if !request.target.starts_with(b"/") {
            let mut w = self.lock();
            if let Some(live) = w.live.as_mut() {
                live.answered = true; // nothing was dispatched, so nothing to abandon
            }
            self.settle(&mut w);
            return false;
        }
        // 1. The dispatch record, durable BEFORE the dial.
        if e.journal.dispatched(&record).is_err() {
            let mut w = self.lock();
            if let Some(live) = w.live.as_mut() {
                live.answered = true; // nothing to abandon: nothing was recorded
            }
            self.settle(&mut w);
            return false;
        }
        let url = join(&route.base_url, &request.target);
        // 2. The one auth call; its fields lead the head (1.5.5's order).
        let mut auth = Vec::new();
        if let Some(binding) = &route.auth {
            match self.auth_fields(binding, &request, &url).await {
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
        head.0.extend(
            request
                .fields
                .iter()
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
        e.telemetry.upstream_attempt(&pool, destination);
        // 3. The connector: the judged, pinned dial and the framer's encode.
        let opened = e.conns.open(
            e.caller,
            route.need,
            &OpenDesc {
                target: &url,
                fields: &borrowed,
                body: &request.body,
                timeout_ms: cap_ms,
                method: &request.verb,
                head_target: path.as_bytes(),
                within: &[],
            },
        );
        let now_ms = e.clock.now_millis();
        match opened {
            Ok(conn) => {
                let mut w = self.lock();
                if let Some(live) = w.live.as_mut() {
                    live.conn = Some(conn);
                    live.anchor_ms = now_ms;
                }
                true
            }
            Err(err) => {
                let label = if err == ConnError::Timeout {
                    net::TIMEOUT
                } else {
                    net::CONNECT
                };
                let _ = self.no_answer(token, label);
                false
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
            let remaining = w.ctx.remaining_ms(now);
            let wait = if live.answered {
                // The whole send: the walk's budget, or the stream ceiling, from the anchor.
                let budget = if self.route.wants_stream {
                    e.stream_ceiling_secs.max(1).saturating_mul(1000)
                } else {
                    remaining.max(1)
                };
                let spent = u64::try_from(now.saturating_sub(live.anchor_ms)).unwrap_or(u64::MAX);
                budget.saturating_sub(spent)
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
                return Some(self.no_answer(token, disposition::ATTEMPT_TIMEOUT));
            }
            Ok(Err(err)) if !answered => {
                let label = if err == ConnError::Timeout {
                    net::TIMEOUT
                } else {
                    net::CONNECT
                };
                return Some(self.no_answer(token, label));
            }
            // After the first answer a failure or a spent deadline ends the answer here: the
            // caller has what arrived, and there is nothing to fail over to.
            Err(_) | Ok(Err(_)) => return Some(self.end(false)),
            Ok(Ok(piece)) => piece,
        };
        match piece.kind {
            PieceKind::Completion => Some(self.end(true)),
            // The far end's fields after its body (trailers): handed to the plane, which decides
            // what they mean (one that reads a trailer status reads it; any other ignores them).
            PieceKind::Fields | PieceKind::HookReply => Some(FarPiece {
                bytes: buf[..piece.len].to_vec(),
                fields: true,
                ..FarPiece::default()
            }),
            PieceKind::Body if answered => Some(self.capped(FarPiece {
                bytes: buf[..piece.len].to_vec(),
                ..FarPiece::default()
            })),
            PieceKind::Body => Some(self.first(token, &piece, buf[..piece.len].to_vec())),
        }
    }

    /// A body piece of the answer, under the error-body cap when the answer is a relayed failure.
    fn capped(&self, piece: FarPiece) -> FarPiece {
        let mut w = self.lock();
        let Some(live) = w.live.as_mut() else {
            return piece;
        };
        let piece = cap(live, piece);
        if piece.last {
            // The rest is never read: the connection closes and the member's slot frees.
            self.settle(&mut w);
        }
        piece
    }

    /// The answer ended: `clean` keeps the budget unit its success spent.
    fn end(&self, clean: bool) -> FarPiece {
        let mut w = self.lock();
        if let Some(live) = w.live.as_mut() {
            if !clean && live.spent {
                // A delivery that did not complete gives its budget unit back.
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
        let pool = Self::metric_pool(&live.pool, &live.member).to_string();
        let destination = live.member.destination;
        if matches!(status.class, Some(WireStatusClass::Success) | None) {
            e.breaker
                .observe(&live.pool, destination, Outcome::Success, now, token);
            // The request owns the probe through the outcome it just recorded.
            live.probe = None;
            live.spent = e.breaker.spend_budget(destination);
            return FarPiece {
                bytes,
                status: far_status,
                last: false,
                fail_over: false,
                fields: false,
                head: Vec::new(),
            };
        }
        let (classified, tripped) = e.breaker.judge(&live.pool, destination, status, now, token);
        if tripped {
            e.telemetry.breaker_trip(&pool, destination);
        }
        live.probe = None;
        // The caller's own fault is not the destination's, and a degraded dispatch relays the
        // upstream's answer: either reaches the plane as it came.
        if matches!(classified.disposition, Disposition::ClientFault) || live.degraded {
            if !matches!(classified.disposition, Disposition::ClientFault) {
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
            if let Some(pool) = e.pools.get(&live.pool) {
                let failed = live.member.clone();
                exclude_smaller_windows(&pool.admissible_members(), &failed, &mut w.ctx);
            }
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
}

#[cfg(test)]
#[path = "tests/far_end_tests.rs"]
mod tests;

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
