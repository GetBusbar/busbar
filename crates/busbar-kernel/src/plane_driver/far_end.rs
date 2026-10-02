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
    ports::{
        disposition, net, Breaker, Capacity, Clock, DestinationId, Dispatched, Disposition,
        Journal, Outcome, Permit, Telemetry, UpstreamStatus,
    },
    walk::budget_secs,
    Member, Pool, Shed, Step, Taken, Walk, WalkPorts, WeightedFloor,
};
use busbar_contract::abi::auth::{STYLE_NEEDS_BODY_HASH, STYLE_NEEDS_HEADERS};
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

/// A member's auth binding: the auth instance, the handle its `open_outbound` answered, and the
/// style's `STYLE_*` flags (what `fields` reads).
#[derive(Clone)]
pub struct AuthBinding {
    /// The auth instance serving the member's style.
    pub auth: Arc<dyn OutboundAuth>,
    /// The handle.
    pub handle: u64,
    /// `abi::auth::STYLE_NEEDS_BODY_HASH` | `abi::auth::STYLE_NEEDS_HEADERS`.
    pub style_flags: u32,
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
        let walk = Walk::start(&self.ports(), &route.pool);
        EgressFarEnd {
            egress: self,
            route,
            state: Mutex::new(State { walk, live: None }),
        }
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

/// One unit's state: the egress unit's walk, and the attempt in flight.
struct State {
    walk: Walk,
    live: Option<Live>,
}

/// ONE UNIT'S FAR END over its [`Egress`].
pub struct EgressFarEnd<'e> {
    egress: &'e Egress,
    route: UnitRoute,
    state: Mutex<State>,
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

    /// Make the member the walk took the live attempt.
    fn take(&self, w: &mut State, taken: Taken) -> Pick {
        let Taken {
            pool,
            member,
            permit,
            probe,
            degraded,
            attempt,
        } = taken;
        let record = Dispatched {
            leg: self.route.leg,
            attempt,
            pool: pool.clone(),
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
            pool: pool.clone(),
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
            match w.walk.next(&ports, self.route.affinity, token) {
                Step::Take(taken) => return self.take(&mut w, taken),
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
            Ok(taken) => self.take(&mut w, taken),
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
                .upstream_failure(&pool, live.member.destination, failure);
            e.telemetry.failover(&pool, failover);
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
        let facts = FieldsRequest {
            method: request.verb.clone(),
            authority: authority.to_string(),
            path: path.as_bytes().to_vec(),
            query,
            timestamp: self.egress.clock.now_secs(),
            body_hash: (binding.style_flags & STYLE_NEEDS_BODY_HASH != 0).then(|| {
                let d = ring::digest::digest(&ring::digest::SHA256, &request.body);
                let mut h = [0u8; 32];
                h.copy_from_slice(d.as_ref());
                h
            }),
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
        // nothing is recorded against the member. Then 1. the dispatch record, durable BEFORE the
        // dial; when it cannot be written nothing was recorded either. Neither has anything to
        // abandon.
        if !request.target.starts_with(b"/") || e.journal.dispatched(&record).is_err() {
            let mut w = self.lock();
            if let Some(live) = w.live.as_mut() {
                live.answered = true;
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
                let _ = self.no_answer(token, NoAnswer::of(err));
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
            let remaining = w.walk.ctx().remaining_ms(now);
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

    /// THE ANSWER WAS CUT after its first piece: the connection failed or the send's deadline
    /// passed before it completed. A success's head was recorded as a success, but the answer never
    /// arrived intact, so a COMPENSATING transient failure is recorded against the member, and the
    /// budget unit its success spent is given back — 1.5.5's mid-body transfer failure (v1.5.5
    /// `crates/busbar/src/proxy/engine/mod.rs:329-353`, buffered; `crates/busbar/src/proxy/
    /// response_body.rs:358-409`, streamed). A relayed failure's body that is cut recorded its own
    /// outcome on its head and is not compensated.
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
        // A recorded outcome resolves a probe this attempt won. An answer that records NOTHING (the
        // caller's own fault, a request too large for the window) resolves none, so the probe stays
        // the attempt's and the settle gives it back, owner-checked: 1.5.5 released it on exactly
        // these exits or the member stayed wedged half-open (v1.5.5
        // `crates/busbar/src/proxy/engine/mod.rs:1900-1912`, `:2131-2138`).
        if !matches!(classified.outcome, Outcome::RecordNothing) {
            live.probe = None;
        }
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
