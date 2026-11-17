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

use busbar_contract::abi::auth::{AuthPoint, AuthPoints, STYLE_NEEDS_HEADERS};
use busbar_contract::abi::host::conn::connector::CAUSE_FRAMER;
use busbar_contract::abi::plane::RefusalCode;
use busbar_contract::abi::transport::{
    FAULT_NONE, STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
};
use busbar_contract::auth_calls::{AuthField, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::caps::{CallId, Pass, ReasonCode, Route};
use busbar_contract::conn::{
    ConnCause, ConnError, ConnId, InstanceId, NeedId, OpenDesc, PieceKind, PollConns,
};
use busbar_contract::transport::wire::{WireFault, WireStatus, WireStatusClass};
use busbar_kernel_egress::{
    attempt::attempt_cap_ms,
    ports::{
        disposition, net, Breaker, Capacity, Classified, Clock, DestinationId, Dispatched,
        Disposition, Journal, Outcome, Permit, StatedLabels, Telemetry, UpstreamStatus,
    },
    walk::budget_secs,
    Member, Pool, Shape, Shed, Step, Taken, Walk, WalkPorts,
};

use super::hooks::{CandidateFacts, Candidates, Constraint};
use super::route::{FarEnd, FarPiece, OutboundRequest, Pick};

use busbar_contract::conn::CONTENT_LENGTH;

const READ_BYTES: usize = 16 * 1024;

const WRITE_PAUSE_MAX_MS: u64 = 64;

pub const DEFAULT_ERROR_BODY_MAX: usize = 256 * 1024;

/// One member's sealed route: the need the plane declared for it, the `base_url` the target is
/// joined onto, and its auth binding.
#[derive(Clone)]
pub struct MemberRoute {
    /// Shared configured authorization is never used for this route.
    pub connection_required: bool,
    /// The plane instance's declared need the connection opens on, resolved once at config load
    /// by the member's auth key ([`super::resolve_member_needs`]).
    pub need: NeedId,
    /// The provider's `base_url`, as the operator spelled it, less any `user:pass@` (row 74, F25:
    /// the root reads that userinfo into a basic credential that leads the auth binding's answers;
    /// this route holds none of its bytes).
    pub base_url: String,
    /// The auth binding the root opened at generation seal; `None` = no auth fields.
    pub auth: Option<AuthBinding>,
    /// The provider the member is served by: the metering row's provider column, as 1.5.5's
    /// `lane.provider` (v1.5.5 `crates/busbar/src/proxy/usage.rs` `ledger_and_meter`).
    pub provider: String,
    /// Which of the far end's response head fields cross to the plane: its need's declared keep
    /// rule (THE DESIGN §5, "The response head and trailers": the kernel copies only those).
    pub keep: ResponseKeep,
    /// Every need bound for the member beside [`Self::need`], one per (transport, auth),
    /// each with its keep rule: a far request that names one of
    /// them (`OutboundRequest::need`) opens on it. Empty = the member rides [`Self::need`] alone.
    pub rides: Vec<(NeedId, ResponseKeep)>,
    /// The member's trust anchors: the far end's key pin and
    /// busbar's client identity, sealed into the connector at the egress's composition so every
    /// connection to the member, the walk's and the plane's own, is held to them. Default = none.
    pub anchors: busbar_contract::transport::trust::Anchors,
    /// Explicit per-need trust for independently declared destinations.
    pub ride_anchors: Vec<(NeedId, busbar_contract::transport::trust::Anchors)>,
    /// The base URL a bound need dials, where its transport spells the member's `base_url` in its
    /// own scheme (a framer composed over the base URL's carrier: the same authority and path, read
    /// by that framer); a need not listed dials [`Self::base_url`]. Composed by the root, which
    /// knows the linked transports; the kernel names no scheme.
    pub spelled: Vec<(NeedId, String)>,
}

/// The need a far request opens on: its id, its keep rule and the base URL it dials.
#[derive(Clone, Copy)]
pub struct Ride<'a> {
    /// The need.
    pub need: NeedId,
    /// Its response-head rule.
    pub keep: &'a ResponseKeep,
    /// The base URL the far request's target is joined onto.
    pub base_url: &'a str,
}

impl MemberRoute {
    pub fn anchors_for(&self, need: NeedId) -> &busbar_contract::transport::trust::Anchors {
        self.ride_anchors
            .iter()
            .find(|(id, _)| *id == need)
            .map_or(&self.anchors, |(_, anchors)| anchors)
    }

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
    #[must_use]
    pub fn keeps<'a>(&self, name: &str, nominated: impl IntoIterator<Item = &'a [u8]>) -> bool {
        busbar_contract::abi::host::conn::connector::keeps_response_field_of(
            self.mode,
            &self.kept,
            &self.denied,
            name,
            nominated,
        )
    }
}

/// A member's auth binding: the auth instance, the handle its `open_outbound` answered, the
/// style's `STYLE_*` flags and the auth points it needs (what `fields` reads).
#[derive(Clone)]
pub struct ConfiguredAuthBinding {
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
    /// A binding refreshed off the request path (`auth_calls::PerRequestHandle`): its current
    /// handle is asked for each attempt, in place of `handle`; one that answers none refuses the
    /// unit `credential_unavailable`. `None` = the handle stands for the generation.
    pub per_request: Option<Arc<dyn busbar_contract::auth_calls::PerRequestHandle>>,
}

/// The existing configured owner and the native retained owner are separate call paths.
#[derive(Clone)]
pub enum AuthBinding {
    Configured(ConfiguredAuthBinding),
    Native(crate::auth_bindings::native::NativeRouteBindings),
}
impl AuthBinding {
    fn passthrough(&self) -> bool {
        matches!(self, Self::Configured(binding) if binding.passthrough)
    }
}

pub type BreakerSource = Arc<dyn Fn() -> Arc<dyn Breaker> + Send + Sync>;

#[must_use]
pub fn fixed_breaker(breaker: Arc<dyn Breaker>) -> BreakerSource {
    Arc::new(move || Arc::clone(&breaker))
}

pub struct Egress {
    pub caller: InstanceId,

    pub conns: Arc<dyn PollConns>,

    pub breaker: BreakerSource,

    pub capacity: Arc<dyn Capacity>,

    pub clock: Arc<dyn Clock>,

    pub journal: Arc<dyn Journal>,

    pub telemetry: Arc<dyn Telemetry>,

    pub pools: foldhash::HashMap<String, Pool>,

    pub routes: HashMap<DestinationId, MemberRoute>,

    pub stream_ceiling_secs: u64,

    pub stated_ceiling_secs: u64,

    pub error_body_max: usize,
}

/// What one unit's walk is told at its start.
#[derive(Debug, Clone)]
pub struct UnitRoute {
    /// Native receipt grants retain full member identity, including the instance prefix.
    pub native_member_grants: Option<std::collections::BTreeMap<String, Vec<String>>>,
    /// Core-owned member grants, keyed by the actual pool being walked.
    /// A present map denies pools absent from it, including on fallback and retry.
    pub member_grants: Option<std::collections::BTreeMap<String, Vec<String>>>,
    /// Host-issued confinement of a nested dispatch to one configured member.
    /// Hook rankings and pool spill cannot widen this binding.
    pub allowed_member: Option<String>,
    /// Deployment-level requirement independent of the plane's selected binding.
    pub connection_required: bool,
    /// Live host request context; no binding crosses the plane ABI.
    pub authorization: Option<Arc<crate::host_units::UnitRecords>>,
    /// The unit the walk serves; every dispatch
    /// record it writes names this unit.
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
    pub caller_credential: Option<crate::auth::CallerCredential>,
    /// The unit's operation is performed AT MOST ONCE (the plane's `ROUTE_ONCE`): a member that
    /// ANSWERED with a failure is not retried on another; its answer reaches the plane as it came.
    /// A walk still moves on before anything was answered.
    pub once: bool,
    /// The plane instance's core-held `insecure_transport.accept` (TRANSPORT-SECURITY-POLICY §3). `Some` = every
    /// dial this unit makes is judged by `transport_verdict` before the connector sees it (a plaintext target is
    /// refused unless the set holds PLAINTEXT); `None` = the legacy path, judged by the connector's guard alone
    /// (O1, owner undecided).
    pub accept: Option<busbar_plugin_abi::host_side::caller::Accept>,
}

/// Whether `url` may be dialled under `accept`: `transport_verdict` with the TLS mode the URL's scheme states
/// (`https://` and `wss://` are TLS, every other scheme is not). `WaiveVerify` still dials verified: the
/// connector's open takes no unverified mode, which is stricter than the acceptance allows, never looser.
#[must_use]
pub(super) fn dial_admitted(
    accept: Option<busbar_plugin_abi::host_side::caller::Accept>,
    url: &str,
) -> bool {
    use busbar_plugin_abi::host_side::caller::{transport_verdict, Verdict};
    use busbar_plugin_abi::need::need_flag::{TLS_NONE, TLS_REQUIRED};
    let Some(accept) = accept else {
        return true;
    };
    let named = |prefix: &str| {
        url.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    };
    let tls = if named("https://") || named("wss://") {
        TLS_REQUIRED
    } else {
        TLS_NONE
    };
    !matches!(transport_verdict(accept, tls, url), Verdict::Refuse)
}

impl Default for UnitRoute {
    fn default() -> Self {
        UnitRoute {
            native_member_grants: None,
            member_grants: None,
            allowed_member: None,
            connection_required: false,
            authorization: None,
            unit: busbar_contract::UnitKey::new(0),
            pool: String::new(),
            affinity: None,
            wants_stream: false,
            leg: 0,
            caller_credential: None,
            once: false,
            accept: None,
        }
    }
}

impl Egress {
    #[must_use]
    pub fn budget_secs(&self, pool: &str) -> u64 {
        budget_secs(&self.pools, pool)
    }

    fn ports<'p>(&'p self, breaker: &'p dyn Breaker) -> WalkPorts<'p> {
        WalkPorts {
            breaker,
            capacity: self.capacity.as_ref(),
            clock: self.clock.as_ref(),
            telemetry: self.telemetry.as_ref(),
            pools: &self.pools,
        }
    }

    #[must_use]
    pub fn deadline_ns(&self, route: &UnitRoute, now_ns: u64) -> u64 {
        if !route.wants_stream || self.stated_ceiling_secs == 0 {
            return 0;
        }
        now_ns.saturating_add(self.stated_ceiling_secs.saturating_mul(1_000_000_000))
    }

    fn send_ceiling_secs(&self) -> u64 {
        if self.stated_ceiling_secs == 0 {
            self.stream_ceiling_secs
        } else {
            self.stated_ceiling_secs
        }
    }

    #[must_use]
    pub fn unit(&self, route: UnitRoute) -> EgressFarEnd<'_> {
        let breaker = (self.breaker)();
        let walk = Walk::start(&self.ports(breaker.as_ref()), &route.pool);
        EgressFarEnd {
            egress: self,
            breaker,
            route,
            state: Mutex::new(State {
                walk,
                retiring: 0,
                walking: false,
                walk_refusal: None,
                live: None,
                completed: None,
                probe: None,
                refused: None,
                unsent: None,
                local: None,
                credential_refused: false,
                sent: false,
                failed: None,
            }),
            probe_of: None,
            described: None,
            signals: None,
            constraint: Mutex::new(None),
            scratch: Mutex::new(Vec::new()),
        }
    }

    #[must_use]
    pub fn probe(&self, destination: DestinationId, timeout: Duration) -> Option<EgressFarEnd<'_>> {
        let route = self.routes.get(&destination)?;
        if matches!(&route.auth, Some(AuthBinding::Native(_)))
            || route.auth.as_ref().is_some_and(|a| a.passthrough())
        {
            return None;
        }
        let member = self
            .pools
            .values()
            .flat_map(|p| &p.members)
            .find(|m| m.destination == destination)?
            .clone();
        Some(self.probe_member(String::new(), member, timeout))
    }

    /// A native probe retains the exact configured pool/member selection.
    pub fn probe_selected(
        &self,
        pool: &str,
        qualified_member: &str,
        destination: DestinationId,
        timeout: Duration,
    ) -> Option<EgressFarEnd<'_>> {
        let route = self.routes.get(&destination)?;
        match route.auth.as_ref() {
            Some(AuthBinding::Native(bindings)) => {
                bindings.select(pool, qualified_member, destination).ok()?;
            }
            Some(AuthBinding::Configured(binding)) if binding.passthrough => return None,
            _ => {}
        }
        let member = self
            .pools
            .get(pool)?
            .members
            .iter()
            .find(|member| {
                !member.passthrough
                    && member.name == qualified_member
                    && member.destination == destination
            })?
            .clone();
        Some(self.probe_member(pool.to_owned(), member, timeout))
    }

    fn probe_member(&self, pool: String, member: Member, timeout: Duration) -> EgressFarEnd<'_> {
        let destination = member.destination;
        let breaker = (self.breaker)();
        let walk = Walk::pinned(&self.ports(breaker.as_ref()), timeout.as_secs().max(1));
        EgressFarEnd {
            egress: self,
            breaker,
            route: UnitRoute {
                pool,
                ..UnitRoute::default()
            },
            state: Mutex::new(State {
                walk,
                retiring: 0,
                walking: false,
                walk_refusal: None,
                live: None,
                completed: None,
                probe: Some(member),
                refused: None,
                unsent: None,
                local: None,
                credential_refused: false,
                sent: false,
                failed: None,
            }),
            probe_of: Some(destination),
            described: None,
            signals: None,
            constraint: Mutex::new(None),
            scratch: Mutex::new(Vec::new()),
        }
    }
}

struct Live {
    pool: String,
    member: Member,
    permit: Option<Permit>,

    probe: Option<u64>,
    conn: Option<ConnId>,
    record: Dispatched,

    degraded: bool,

    passthrough: bool,

    anchor_ms: u128,

    anchor_us: u128,

    answered: bool,

    spent: bool,

    delivered: bool,

    ended: bool,

    error_left: Option<usize>,

    keep: ResponseKeep,

    unjudged: Option<Unjudged>,

    failing: Option<Classified>,

    stated: Option<StatedLabels>,

    fault_reason: Option<String>,

    taken: bool,

    kept: bool,

    call: CallId,
}

/// The transport's reading of a relayed answer, held for the plane's.
#[derive(Clone)]
struct Unjudged {
    /// The transport's classification.
    classified: Classified,
    /// The frame's class (the fee leg), so the plane's reading is classified as an answer.
    class: Option<WireStatusClass>,
    /// The answer's numbered status, carried beside the plane's reading as it was beside the
    /// transport's.
    code: Option<WireStatus>,
    /// The wait the answer stated.
    retry_after: Option<u64>,
    /// The answer's head was already recorded as a success: a reading of the answer that is a
    /// success again records nothing more (one answer, one success).
    after_success: bool,
}

fn wire_code(piece: &busbar_contract::conn::Piece) -> Option<WireStatus> {
    let namespace = piece.status_namespace.as_deref()?;
    if namespace.is_empty()
        || namespace.len() > busbar_contract::abi::transport::status::MAX_NAMESPACE_BYTES
    {
        return None;
    }
    piece
        .status_code
        .map(|code| WireStatus::new(namespace, code))
}

struct State {
    walk: Walk,

    walking: bool,

    retiring: usize,
    walk_refusal: Option<Shed>,
    live: Option<Live>,
    // A fully consumed response can authorize one new exchange on this same member.
    completed: Option<(String, Member, CallId)>,
    probe: Option<Member>,

    refused: Option<ReasonCode>,

    unsent: Option<RefusalCode>,

    /// The host's OWN fault refused this unit (its outbound framer could not render the request):
    /// audited whether or not bytes were handed to the connection, since the member did nothing.
    local: Option<RefusalCode>,
    /// The attempt in hand failed on its member's own credential. Attempt-scoped, as `unsent`
    /// is: both are cleared when each attempt is installed (`EgressFarEnd::admit_taken`).
    credential_refused: bool,

    sent: bool,

    failed: Option<&'static str>,
}

struct Walking<'a, 'e> {
    owner: &'a EgressFarEnd<'e>,
    walk: Walk,
}

impl Walking<'_, '_> {
    fn publish(&self) {
        self.owner.lock().walk = self.walk.clone();
    }
}

impl Drop for Walking<'_, '_> {
    fn drop(&mut self) {
        let mut w = self.owner.lock();
        if let Some(shed) = w.walk_refusal.take() {
            self.walk.refuse(shed);
        }
        w.walk = self.walk.clone();
        w.walking = false;
    }
}

struct Retiring<'a, 'e>(&'a EgressFarEnd<'e>);
impl Drop for Retiring<'_, '_> {
    fn drop(&mut self) {
        self.0.lock().retiring -= 1;
    }
}

struct Retirement<'a, 'e> {
    owner: &'a EgressFarEnd<'e>,
    live: Live,
}

impl Retirement<'_, '_> {
    fn finish(&mut self) {
        self.owner.record_unjudged(&mut self.live, None);
        let e = self.owner.egress;
        if let Some(conn) = self.live.conn.take() {
            let _closed = e.conns.close(e.caller, conn);
        }
        if let Some(epoch) = self.live.probe.take() {
            self.owner.breaker().release_probe(
                &self.live.pool,
                self.live.member.destination,
                epoch,
                e.clock.now_secs(),
            );
        }
        if self.live.spent && !self.live.ended && !self.live.delivered && !self.live.taken {
            self.live.spent = false;
            self.owner
                .breaker()
                .refund_budget(self.live.member.destination);
        }
        if !self.live.answered && self.owner.probe_of.is_none() {
            self.live.answered = true;
            e.journal.abandoned(&self.live.record);
        }
        drop(self.live.permit.take());
    }
}

impl Drop for Retirement<'_, '_> {
    fn drop(&mut self) {
        self.finish();
    }
}

struct Reading {
    pool: String,
    metric_pool: String,
    destination: DestinationId,
    passthrough: bool,
    probe: Option<u64>,
    stated: Option<StatedLabels>,
    reason: Option<String>,
    call: CallId,
    breaker: Arc<dyn Breaker>,
    clock: Arc<dyn Clock>,
}

impl Reading {
    fn take(owner: &EgressFarEnd<'_>, live: &mut Live) -> Self {
        Reading {
            pool: live.pool.clone(),
            metric_pool: EgressFarEnd::metric_pool(&live.pool, &live.member).to_string(),
            destination: live.member.destination,
            passthrough: live.passthrough,
            stated: live.stated.clone(),
            reason: live.fault_reason.take(),
            call: live.call,
            breaker: owner.breaker.clone(),
            clock: owner.egress.clock.clone(),
            probe: live.probe.take(),
        }
    }
}

impl Drop for Reading {
    fn drop(&mut self) {
        if let Some(epoch) = self.probe.take() {
            self.breaker
                .release_probe(&self.pool, self.destination, epoch, self.clock.now_secs());
        }
    }
}

pub struct EgressFarEnd<'e> {
    egress: &'e Egress,

    breaker: Arc<dyn Breaker>,
    route: UnitRoute,
    state: Mutex<State>,

    probe_of: Option<DestinationId>,

    described: Option<Arc<HashMap<String, MemberFacts>>>,

    signals: Option<Arc<dyn MemberSignals>>,

    constraint: Mutex<Option<Constraint>>,

    scratch: Mutex<Vec<u8>>,
}

/// ONE MEMBER'S LIVE STANDING, as the ranking hooks read it (1.5.5 fed every candidate these from
/// the lane store, and the ones a deployment declares as catalog signals): its latency signal, its
/// free concurrency, its remaining lifetime budget, and its breaker state, recent error rate and
/// p95 latency in the routing pool.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MemberStanding {
    /// The latency signal (milliseconds), once a sample is recorded.
    pub latency_ms: Option<f64>,
    /// The free concurrency.
    pub available_concurrency: usize,
    /// The remaining lifetime request budget; `None` = unlimited.
    pub budget_remaining: Option<i64>,
    /// The breaker state in the pool (`closed` | `open` | `half_open`).
    pub breaker_state: Option<&'static str>,
    /// The recent error rate in the pool, once an outcome is in its window.
    pub error_rate: Option<f64>,
    /// The p95 latency (whole milliseconds), once a sample is held.
    pub latency_p95_ms: Option<u64>,
}

pub trait MemberSignals: Send + Sync {
    fn standing(&self, pool: &str, destination: DestinationId) -> MemberStanding;
}

/// What the operator states of one member for the hooks: its tags, its tier and its cost.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemberFacts {
    /// The member's model, as the hooks name it (empty = the member's name).
    pub model: String,
    /// The operator's tags.
    pub tags: Vec<String>,
    /// The operator's tier.
    pub tier: Option<String>,
    /// The operator's cost per million tokens.
    pub cost_per_mtok: Option<f64>,
}

impl EgressFarEnd<'_> {
    #[must_use]
    pub fn described(mut self, facts: Arc<HashMap<String, MemberFacts>>) -> Self {
        self.described = Some(facts);
        self
    }

    #[must_use]
    pub fn signals(mut self, signals: Arc<dyn MemberSignals>) -> Self {
        self.signals = Some(signals);
        self
    }

    /// Judges every dial of this far end under the plane instance's core-held `accept` ([`UnitRoute::accept`]).
    #[must_use]
    pub fn accepting(mut self, accept: busbar_plugin_abi::host_side::caller::Accept) -> Self {
        self.route.accept = Some(accept);
        self
    }

    fn facts_of(&self, member: &Member) -> Option<&MemberFacts> {
        self.described.as_ref().and_then(|d| d.get(&member.name))
    }

    fn tags_of(&self, member: &Member) -> &[String] {
        self.facts_of(member).map_or(&[], |f| f.tags.as_slice())
    }

    fn constrained(
        &self,
        members: Vec<Member>,
        primary: bool,
    ) -> Result<(Vec<Member>, Vec<DestinationId>), ()> {
        let constraint = self
            .constraint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(c) = constraint else {
            return Ok((members, Vec::new()));
        };
        if primary {
            // The preferred set is a group, never a ranking. Encode its lexicographic priority
            // ahead of the configured tiers so the existing picker still applies ordinary rank
            // or SWRR inside each group, plus its normal affinity and admission rules.
            let tiers: Vec<(bool, u32)> =
                c.prioritize.as_ref().map_or_else(Vec::new, |preferred| {
                    let mut tiers: Vec<_> = members
                        .iter()
                        .enumerate()
                        .map(|(i, m)| (!preferred.contains(&i), m.tier))
                        .collect();
                    tiers.sort();
                    tiers.dedup();
                    tiers
                });
            let kept: Vec<Member> = members
                .iter()
                .enumerate()
                .filter(|(i, _)| c.keep.as_ref().is_none_or(|k| k.contains(i)))
                .map(|(i, m)| {
                    let mut member = m.clone();
                    if let Some(preferred) = &c.prioritize {
                        member.tier = tiers
                            .binary_search(&(!preferred.contains(&i), m.tier))
                            .expect("every member's tier was collected")
                            as u32;
                    }
                    member
                })
                .collect();
            let order: Vec<DestinationId> = c
                .order
                .iter()
                .flatten()
                .filter_map(|i| members.get(*i))
                .map(|m| m.destination)
                .collect();
            return Ok((kept, order));
        }
        let tagged = members
            .iter()
            .enumerate()
            .map(|(i, m)| (i, self.tags_of(m)));
        let kept = c.enforce(tagged).map_err(|_| ())?;
        Ok((
            kept.into_iter()
                .filter_map(|i| members.get(i).cloned())
                .collect(),
            Vec::new(),
        ))
    }
}

impl Shape for EgressFarEnd<'_> {
    fn shape(
        &self,
        pool: &str,
        members: Vec<Member>,
        primary: bool,
    ) -> Option<(Vec<Member>, Vec<DestinationId>)> {
        let (mut members, mut order) = self.constrained(members, primary).ok()?;
        if let Some(grants) = &self.route.native_member_grants {
            members.retain(|m| {
                grants
                    .get(pool)
                    .is_some_and(|allowed| allowed.iter().any(|name| name == &m.name))
            });
            order.retain(|id| members.iter().any(|m| m.destination == *id));
        }
        if let Some(grants) = &self.route.member_grants {
            members.retain(|m| {
                grants.get(pool).is_some_and(|allowed| {
                    allowed.iter().any(|name| {
                        super::route::operator_name(m.name.as_bytes()) == name.as_bytes()
                    })
                })
            });
            order.retain(|id| members.iter().any(|m| m.destination == *id));
        }
        if let Some(allowed) = &self.route.allowed_member {
            members
                .retain(|m| super::route::operator_name(m.name.as_bytes()) == allowed.as_bytes());
            order.retain(|id| members.iter().any(|m| m.destination == *id));
        }
        Some((members, order))
    }
}

fn exhausted(shed: &Shed) -> Pick {
    Pick::Exhausted {
        status: u32::from(shed.status),
        retry_after: shed
            .retry_after_secs
            .map(|s| u32::try_from(s).unwrap_or(u32::MAX)),
        detail: shed.detail,
    }
}

fn shed_pick(shed: &Shed) -> Pick {
    if shed.gate_rejected {
        Pick::Vetoed {
            status: u32::from(shed.status),
            text: shed.detail.to_string(),
        }
    } else {
        exhausted(shed)
    }
}

/// `us` as an `f64`: exact below 2^53, as `us as f64` is, without a lossy cast.
fn micros_f64(us: u64) -> f64 {
    let high = u32::try_from(us >> 32).unwrap_or(u32::MAX);
    let low = u32::try_from(us & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(high) * 4_294_967_296.0 + f64::from(low)
}

fn class_code(class: Option<WireStatusClass>) -> u32 {
    u32::from(match class {
        Some(WireStatusClass::Success) | None => STATUS_SUCCESS,
        Some(WireStatusClass::CallerFault) => STATUS_CALLER_FAULT,
        Some(WireStatusClass::FarEndFault) => STATUS_FAR_END_FAULT,
        Some(WireStatusClass::Other) => STATUS_OTHER,
    })
}

fn join(base: &str, target: &[u8]) -> String {
    let base: std::borrow::Cow<'_, str> = match base.split_once("://") {
        Some((scheme, _))
            if base.contains('\\')
                && busbar_contract::net::UrlFamily::of(&scheme.to_ascii_lowercase())
                    == busbar_contract::net::UrlFamily::Web =>
        {
            std::borrow::Cow::Owned(base.replace('\\', "/"))
        }
        _ => std::borrow::Cow::Borrowed(base),
    };
    format!(
        "{}{}",
        base.trim_end_matches('/'),
        String::from_utf8_lossy(target)
    )
}

/// The audit action of an upstream dial the instance's `insecure_transport` does not cover (the connector's own
/// action for a refused Need, TRANSPORT-SECURITY-POLICY §4).
pub(crate) const INSECURE_TRANSPORT_REFUSED: &str = "egress.insecure_transport_refused";

fn split(url: &str) -> (&str, &str) {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    }
}

struct Scratch<'a> {
    buf: Vec<u8>,
    home: &'a Mutex<Vec<u8>>,
}

impl<'a> Scratch<'a> {
    fn lend(home: &'a Mutex<Vec<u8>>) -> Self {
        let mut buf = std::mem::take(
            &mut *home
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        if buf.len() != READ_BYTES {
            buf = vec![0u8; READ_BYTES];
        }
        Scratch { buf, home }
    }
}

impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        *self
            .home
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = std::mem::take(&mut self.buf);
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

fn fail_over() -> FarPiece {
    FarPiece {
        fail_over: true,
        last: true,
        ..FarPiece::default()
    }
}

/// Say, at WARN, why `provider`'s credential could not be presented to its upstream `base_url`:
/// once per (provider, cause) change, never per request (a refusal repeats on every request until
/// the configuration changes). The upstream is named by its scheme and host only.
fn warn_credential_refused(provider: &str, base_url: &str, err: ConnError) {
    static LAST: std::sync::OnceLock<Mutex<foldhash::HashMap<String, ConnError>>> =
        std::sync::OnceLock::new();
    {
        let mut last = LAST
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match last.get_mut(provider) {
            Some(seen) if *seen == err => return,
            Some(seen) => *seen = err,
            None => crate::cold::far_end_first_refusal(&mut last, provider, err),
        }
    }
    if err == ConnError::AuthRefused {
        let (scheme, rest) = base_url.split_once("://").unwrap_or(("", base_url));
        let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
        tracing::warn!(
            provider,
            "{provider}: the credential requires a secure connection; upstream `{scheme}://{host}` \
             is plaintext, so it is not presented (credential_unavailable)"
        );
    } else {
        tracing::warn!(
            provider,
            "{provider}: the provider refused the credential (credential_unavailable)"
        );
    }
}

impl EgressFarEnd<'_> {
    fn breaker(&self) -> &dyn Breaker {
        self.breaker.as_ref()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn retiring(&self) -> Retiring<'_, '_> {
        self.lock().retiring += 1;
        Retiring(self)
    }

    fn owns_attempt(&self, attempt: u32, destination: DestinationId) -> bool {
        self.lock()
            .live
            .as_ref()
            .is_some_and(|l| l.record.attempt == attempt && l.member.destination == destination)
    }

    fn settle_attempt(&self, record: &Dispatched) {
        let live = {
            let mut w = self.lock();
            if w.live.as_ref().is_some_and(|l| {
                l.record.attempt == record.attempt && l.member.destination == record.destination
            }) {
                w.live.take()
            } else {
                None
            }
        };
        self.retire(live);
    }

    fn settle(&self) {
        let live = self.lock().live.take();
        self.retire(live);
    }

    fn retire(&self, live: Option<Live>) {
        let _retirement = self.retiring();
        let Some(live) = live else {
            return;
        };
        let mut retirement = Retirement { owner: self, live };
        retirement.finish();
    }

    fn settle_read(&self) {
        let live = {
            let mut w = self.lock();
            if w.live.as_ref().is_some_and(|l| l.unjudged.is_some()) {
                return;
            }
            w.live.take()
        };
        self.retire(live);
    }

    fn record_reading(
        &self,
        read: &mut Reading,
        token: &Pass<Route>,
        classified: Classified,
        now: u64,
    ) {
        let hard = matches!(classified.disposition, Disposition::HardDown);
        let callers_key = hard && read.passthrough;
        if !callers_key
            && self.breaker().observe_stated(
                &read.pool,
                read.destination,
                classified.outcome,
                read.reason.as_deref(),
                now,
                token,
            )
        {
            self.egress
                .telemetry
                .breaker_trip(&read.metric_pool, read.destination);
        }
        if !callers_key && !matches!(classified.outcome, Outcome::RecordNothing) {
            read.probe = None;
        }
    }

    fn record(&self, live: &mut Live, token: &Pass<Route>, classified: Classified, now: u64) {
        let mut read = Reading::take(self, live);
        self.record_reading(&mut read, token, classified, now);
        live.probe = read.probe.take();
    }

    fn release_reading(&self, read: Reading) {
        drop(read);
    }

    fn record_held(&self, read: &mut Reading, held: Unjudged, plane: Option<(&Pass<Route>, u8)>) {
        let stated = plane.and_then(|(_, f)| WireFault::from_code(f));
        read.reason = read.reason.take().filter(|_| stated.is_some());
        let classified = match stated {
            Some(fault) => self.breaker().classify(
                read.destination,
                UpstreamStatus {
                    class: held.class,
                    fault: Some(fault),
                    code: held.code,
                    retry_after: held.retry_after,
                },
            ),
            None => held.classified,
        };
        if held.after_success && matches!(classified.outcome, Outcome::Success) {
            return;
        }
        let now = self.egress.clock.now_secs();
        let own;
        let token = match plane {
            Some((token, _)) => token,
            None => {
                own = Pass::<Route>::mint_bound(&crate::seal::acquire(), read.call);
                &own
            }
        };
        if let Some(probed) = self.probe_of {
            self.breaker()
                .probed(probed, classified.outcome, now, token);
            return;
        }
        self.record_reading(read, token, classified, now);
        let inside_success =
            held.after_success && matches!(held.class, Some(WireStatusClass::Success));
        let hard = matches!(classified.disposition, Disposition::HardDown);
        let client_fault = matches!(classified.disposition, Disposition::ClientFault);
        if !inside_success && !client_fault && !(hard && read.passthrough) {
            self.egress.telemetry.upstream_failure_stated(
                &read.metric_pool,
                read.destination,
                classified.label,
                read.stated.as_ref(),
            );
        }
    }

    fn record_unjudged(&self, live: &mut Live, plane: Option<(&Pass<Route>, u8)>) {
        let Some(held) = live.unjudged.take() else {
            return;
        };
        let mut read = Reading::take(self, live);
        self.record_held(&mut read, held, plane);
        live.probe = read.probe.take();
    }

    fn metric_pool<'m>(pool: &'m str, member: &'m Member) -> &'m str {
        if pool.is_empty() {
            &member.name
        } else {
            pool
        }
    }

    fn admit_taken(&self, taken: Taken, call: CallId) -> Pick {
        let Taken {
            pool,
            member,
            permit,
            probe,
            degraded,
            attempt,
        } = taken;
        self.claim_member(pool, member, Some(permit), probe, degraded, (attempt, call))
    }

    fn claim_member(
        &self,
        pool: String,
        member: Member,
        permit: Option<Permit>,
        probe: Option<u64>,
        degraded: bool,
        (attempt, call): (u32, CallId),
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
                .is_some_and(|a| a.passthrough());
        let provider = route.map(|r| r.provider.clone()).unwrap_or_default();
        let live = Live {
            pool: pool.clone(),
            member,
            permit,
            probe,
            conn: None,
            record,
            degraded,
            passthrough,
            anchor_ms: 0,
            anchor_us: 0,
            answered: false,
            spent: false,
            delivered: false,
            ended: false,
            error_left: None,
            keep: ResponseKeep::default(),
            unjudged: None,
            failing: None,
            stated: None,
            fault_reason: None,
            taken: false,
            kept: false,
            call,
        };
        let old = {
            let mut w = self.lock();
            w.credential_refused = false;
            w.unsent = None;
            w.live.replace(live)
        };
        self.retire(old);
        Pick::Member {
            name,
            pool,
            passthrough,
            provider,
        }
    }

    async fn next_member(&self, token: &Pass<Route>) -> Pick {
        let mut walking = {
            let mut w = self.lock();
            if w.walking || w.retiring != 0 {
                return exhausted(&Shed::internal());
            }
            w.walking = true;
            w.completed = None;
            Walking {
                owner: self,
                walk: w.walk.clone(),
            }
        };

        self.settle();
        let ports = self.egress.ports(self.breaker());
        let now = self.egress.clock.now_secs();
        let probe = {
            let mut w = self.lock();
            if let Some(reason) = w.refused.take() {
                return Pick::Refused(reason);
            }
            if !walking.walk.ctx().expired(now) {
                w.probe.take()
            } else {
                None
            }
        };
        if let Some(member) = probe {
            return self.claim_member(
                self.route.pool.clone(),
                member,
                None,
                None,
                false,
                (1, token.call()),
            );
        }
        let wait = match walking
            .walk
            .next_shaped(&ports, self.route.affinity, Some(self), token)
        {
            Step::Take(taken) => return self.admit_taken(taken, token.call()),
            Step::Shed(shed) => return shed_pick(&shed),
            Step::Wait(wait) => wait,
        };
        let parked = match walking.walk.park(&ports, &wait, token) {
            Ok(parked) => parked,
            Err(shed) => return exhausted(&shed),
        };
        walking.publish();
        let waited = parked.wait(&ports).await;
        match walking.walk.waited(&ports, waited, token) {
            Ok(taken) => self.admit_taken(taken, token.call()),
            Err(shed) => exhausted(&shed),
        }
    }

    fn no_answer(&self, token: &Pass<Route>, cause: NoAnswer) -> FarPiece {
        let e = self.egress;
        let _retirement = self.retiring();
        let live = self.lock().live.take();
        if let Some(live) = live {
            let mut retirement = Retirement { owner: self, live };
            let live = &mut retirement.live;
            let now = e.clock.now_secs();
            let (failure, failover) = match cause {
                NoAnswer::Connect => (disposition::TRANSIENT, net::CONNECT),
                NoAnswer::Timeout if live.member.attempt_timeout_ms.is_some() => {
                    (disposition::ATTEMPT_TIMEOUT, disposition::ATTEMPT_TIMEOUT)
                }
                NoAnswer::Timeout => (disposition::TRANSIENT, net::TIMEOUT),
            };
            let outcome = Outcome::Transient { retry_after: None };
            if let Some(destination) = self.probe_of {
                self.breaker().probed(destination, outcome, now, token);
            } else {
                let pool = Self::metric_pool(&live.pool, &live.member).to_string();
                let destination = live.member.destination;
                if self
                    .breaker()
                    .observe(&live.pool, destination, outcome, now, token)
                {
                    e.telemetry.breaker_trip(&pool, destination);
                }
                e.telemetry.upstream_failure_stated(
                    &pool,
                    destination,
                    failure,
                    live.stated.as_ref(),
                );
                e.telemetry.failover(&pool, failover);
            }
            live.probe = None;
            self.lock().failed = Some(failover);
            retirement.finish();
        }
        fail_over()
    }

    /// THE HOST'S OWN OUTBOUND FRAMER FAULT before any answer (`cause` names `CAUSE_FRAMER`,
    /// `outbound`): the host could not render the request, so no member can cure it and none is
    /// to blame. The attempt settles WITHOUT a breaker charge or a stated upstream failure, the
    /// walk is refused as internal (500, no Retry-After, no fail-over: every member would meet the
    /// same framer), the unit is audited `Internal`, and one diagnostic explains it.
    fn local_fault(&self, _token: &Pass<Route>, cause: &ConnCause) -> FarPiece {
        let named = self.lock().live.as_ref().map(|live| {
            (
                Self::metric_pool(&live.pool, &live.member).to_string(),
                live.member.name.clone(),
            )
        });
        let (pool, member) = named.unwrap_or_default();
        tracing::error!(
            diag = "BUSBAR-EGRESS-LOCAL-FRAMER",
            pool = %pool,
            member = %member,
            error = %cause.text,
            "the host's own framer could not render the request for the upstream; refused as an \
             internal error and not charged to the member"
        );
        {
            let mut w = self.lock();
            w.local = Some(RefusalCode::Internal);
            if w.walking {
                w.walk_refusal = Some(Shed::internal());
            } else {
                w.walk.refuse(Shed::internal());
            }
        }
        self.settle();
        fail_over()
    }

    fn attempt_cap(&self) -> u64 {
        let now = self.egress.clock.now_millis();
        let w = self.lock();
        let remaining = w.walk.ctx().remaining_ms(now);
        match w.live.as_ref().and_then(|l| l.member.attempt_timeout_ms) {
            Some(ms) => attempt_cap_ms(ms, remaining),
            None if self.route.wants_stream => {
                self.egress.send_ceiling_secs().max(1).saturating_mul(1000)
            }
            None => remaining.max(1),
        }
    }

    fn live_passthrough(&self) -> bool {
        self.lock().live.as_ref().is_some_and(|l| l.passthrough)
    }

    async fn native_credential(
        &self,
        binding: &crate::auth_bindings::native::NativeBinding,
        request: &OutboundRequest,
        url: &str,
        scope: Option<&[u8]>,
        defaults: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<crate::auth_bindings::native::NativeCredential, busbar_ports::PortError> {
        use busbar_plugin_abi::types::{Bytes, Pair, Str};
        fn pairs(rows: &[(Vec<u8>, Vec<u8>)]) -> Vec<Pair<'_>> {
            rows.iter()
                .filter_map(|(name, value)| {
                    std::str::from_utf8(name).ok().map(|name| Pair {
                        name: Str::new(name),
                        value: Bytes::new(value),
                    })
                })
                .collect::<Vec<_>>()
        }
        let plane = pairs(&request.fields);
        let transport = pairs(defaults);
        let headers = crate::auth::upstream_binding::upstream_head(&plane, &transport);
        let invalid = || busbar_ports::PortError::Refused {
            code: busbar_plugin_abi::fail::refused::R_POLICY,
            text: "native outbound input is invalid".into(),
            error: None,
        };
        let method = std::str::from_utf8(&request.verb).map_err(|_| invalid())?;
        let scope = if binding.scoped() {
            scope
                .map(std::str::from_utf8)
                .transpose()
                .map_err(|_| invalid())?
        } else {
            None
        };
        let input = busbar_ports::auth::UpstreamIn {
            method,
            url,
            headers: &headers,
            body_sha256: binding
                .needs_body_hash()
                .then(|| busbar_contract::crypto::sha256(&request.body)),
            caller_cred: &[],
            scope,
            caller_grant: None,
            min_valid_s: 0,
        };
        binding
            .credential(
                busbar_ports::CallCx {
                    deadline: std::time::Instant::now() + Duration::from_millis(self.attempt_cap()),
                    request_id: self.route.unit.get(),
                    stack: Default::default(),
                },
                &input,
            )
            .await
    }

    async fn auth_fields(
        &self,
        binding: &ConfiguredAuthBinding,
        handle: u64,
        request: &OutboundRequest,
        url: &str,
        extensions: Vec<u8>,
        defaults: &[(Vec<u8>, Vec<u8>)],
    ) -> Option<Vec<AuthField>> {
        let (authority, path_query) = split(url);
        let (path, query) = match path_query.split_once('?') {
            Some((p, q)) => (p, Some(q.as_bytes().to_vec())),
            None => (path_query, None),
        };

        let point = if binding.points.has(AuthPoint::HeadBody) {
            AuthPoint::HeadBody
        } else {
            AuthPoint::Head
        };
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::AuthFieldsCopy);
        let facts = FieldsRequest {
            point,
            body: (point == AuthPoint::HeadBody).then(|| request.body.clone()),
            method: request.verb.clone(),
            authority: authority.to_string(),
            path: path.as_bytes().to_vec(),
            query,
            timestamp: self.egress.clock.now_secs(),

            headers: if binding.style_flags & STYLE_NEEDS_HEADERS != 0 {
                request.fields.iter().chain(defaults).cloned().collect()
            } else {
                Vec::new()
            },

            caller_credential: if binding.passthrough || self.live_passthrough() {
                Some(self.route.caller_credential.as_ref().map_or_else(
                    busbar_contract::SharedSecret::default,
                    crate::auth::CallerCredential::lend,
                ))
            } else {
                None
            },

            extensions,
            ..FieldsRequest::default()
        };
        let answer = match binding.auth.fields_now(handle, &facts) {
            Some(answer) => answer,

            None => tokio::time::timeout(
                Duration::from_millis(self.attempt_cap()),
                binding.auth.fields(handle, facts, 0),
            )
            .await
            .unwrap_or(Fields::Failed),
        };
        match answer {
            Fields::Ready(fields) => Some(fields),
            Fields::Refused | Fields::Failed => None,
        }
    }

    async fn send_attempt(
        &self,
        token: &Pass<Route>,
        mut request: OutboundRequest,
        mut selected: Option<&mut super::port_egress::SelectedHandoff>,
    ) -> bool {
        let e = self.egress;

        if selected
            .as_ref()
            .is_some_and(|handoff| !handoff.accepts_request(&request))
        {
            return false;
        }

        busbar_kernel_egress::upstream::strip_re_derived(&mut request.fields);

        let mut scope = None;

        let mut waived = false;

        let mut pin = None;
        request.fields.retain(|(name, value)| {
            if busbar_contract::abi::auth::is_scope_field(name) {
                scope.get_or_insert_with(|| value.clone());
                false
            } else if busbar_contract::abi::auth::is_no_member_auth_field(name) {
                waived = true;
                false
            } else if busbar_contract::abi::host::conn::connector::is_within_field(name) {
                pin = Some(value.clone());
                false
            } else {
                !busbar_contract::conn::is_sealed_query_field(name)
            }
        });
        busbar_kernel_egress::upstream::apply_upstream_encoding(&mut request.fields);
        let extensions = busbar_contract::abi::auth::scope_extensions(scope.as_deref());

        let live = {
            let w = self.lock();
            w.live.as_ref().map(|live| {
                (
                    live.member.destination,
                    live.pool.clone(),
                    live.member.name.clone(),
                    busbar_kernel_ledger::cost::split_plane_lane(&live.member.name)
                        .1
                        .to_owned(),
                    live.record.clone(),
                )
            })
        };
        let Some((destination, selected_pool, qualified_member, member, record)) = live else {
            self.lock().unsent = Some(RefusalCode::UnsentNoAttempt);
            return false;
        };
        if selected.as_ref().is_some_and(|handoff| {
            !handoff.accepts(&selected_pool, &qualified_member, self.route.unit)
                || request.attempt_no != record.attempt
        }) {
            self.settle_attempt(&record);
            return false;
        }
        let Some(route) = e.routes.get(&destination).cloned() else {
            self.lock().unsent = Some(RefusalCode::UnsentNoRoute);
            return false;
        };

        let Some((need, keep, base_url)) = route
            .ride(request.need)
            .map(|r| (r.need, r.keep.clone(), r.base_url.to_string()))
        else {
            self.lock().unsent = Some(RefusalCode::UnsentNeedUnbound);
            self.settle_attempt(&record);
            return false;
        };

        let path = request.target.starts_with(b"/");

        let named = request
            .fields
            .iter()
            .all(|(n, _)| busbar_contract::header::is_header_name_token(n));
        let unrecorded =
            path && named && self.probe_of.is_none() && e.journal.dispatched(&record).is_err();
        if !self.owns_attempt(record.attempt, destination) {
            return false;
        }
        if !path || !named || unrecorded {
            let mut w = self.lock();
            if let Some(live) = w.live.as_mut() {
                live.answered = true;
            }
            w.unsent = Some(if !path {
                RefusalCode::UnsentTargetNotPath
            } else if !named {
                RefusalCode::UnsentFieldName
            } else {
                RefusalCode::UnsentUnrecorded
            });
            if unrecorded {
                if w.walking {
                    w.walk_refusal = Some(Shed::internal());
                } else {
                    w.walk.refuse(Shed::internal());
                }
            }
            drop(w);
            self.settle_attempt(&record);
            return false;
        }

        let Some(within) = pin.as_deref().map_or(Some(Vec::new()), |v| {
            busbar_contract::abi::host::conn::connector::within_of(v)
        }) else {
            self.lock().unsent = Some(RefusalCode::UnsentOpenRefused);
            self.settle_attempt(&record);
            return false;
        };
        let url = join(&base_url, &request.target);
        if !dial_admitted(self.route.accept, &url) {
            let destination = split(&url).0.rsplit('@').next().unwrap_or_default();
            // TRANSPORT-SECURITY-POLICY §4 "Visibility": every refusal is an audit row, as the connector writes
            // for a Need (`dest:<host>:<instance>`; the walk's pool is the plane instance's).
            crate::audit_ring::AUDIT.record_by(
                INSECURE_TRANSPORT_REFUSED,
                &format!("dest:{destination}:{}", self.route.pool),
                crate::audit_ring::OUTCOME_REJECTED,
                "system",
            );
            tracing::warn!(
                action = INSECURE_TRANSPORT_REFUSED,
                destination,
                "an upstream dial was refused: no insecure_transport acceptance covers it"
            );
            self.lock().unsent = Some(RefusalCode::UnsentOpenRefused);
            self.settle_attempt(&record);
            return false;
        }

        let (located, carried) = match e
            .conns
            .locate_head(e.caller, need, &url, self.attempt_cap())
        {
            Ok(located) => located,
            Err(_) => {
                self.lock().unsent = Some(RefusalCode::UnsentOpenRefused);
                self.settle_attempt(&record);
                return false;
            }
        };
        let pending = self
            .route
            .authorization
            .as_ref()
            .and_then(|units| units.take_prepared(self.route.unit.get()));
        let delegated = self
            .route
            .authorization
            .as_ref()
            .and_then(|units| units.outbound(self.route.unit.get()));
        let bound = pending.is_some()
            || delegated.is_some()
            || route.connection_required
            || self.route.connection_required;
        let presented = if let Some(pending) = pending {
            pending
                .take(need.0, &member, &url, e.clock.now_secs())
                .map(crate::host_outbound::Presentation::Body)
        } else {
            delegated.and_then(|bound| bound.present(need.0, &member, &url, e.clock.now_secs()))
        };
        if bound && presented.is_none() {
            self.lock().refused = Some(ReasonCode::CredentialUnavailable);
            self.settle_attempt(&record);
            return false;
        }
        let (prepared, mut auth) = match presented {
            Some(crate::host_outbound::Presentation::Body(body)) => {
                if request.text || !request.body.is_empty() {
                    self.lock().refused = Some(ReasonCode::CredentialUnavailable);
                    self.settle_attempt(&record);
                    return false;
                }
                (Some(crate::host_outbound::Body(body)), Vec::new())
            }
            Some(crate::host_outbound::Presentation::Field(field)) => (None, vec![field]),
            None => (None, Vec::new()),
        };
        let protected = prepared.is_some();
        let opening: &[u8] = prepared.as_ref().map_or_else(
            || {
                if request.text {
                    &[][..]
                } else {
                    &request.body[..]
                }
            },
            AsRef::as_ref,
        );
        let defaults = located.completing(
            |name| {
                request
                    .fields
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(name))
            },
            opening.len(),
        );

        if let Some(AuthBinding::Configured(binding)) =
            route.auth.as_ref().filter(|_| !waived && !bound)
        {
            let handle = match &binding.per_request {
                Some(per) => per.handle_now(),
                None => Some(binding.handle),
            };
            let Some(handle) = handle else {
                self.lock().refused = Some(ReasonCode::CredentialUnavailable);
                self.settle_attempt(&record);
                return false;
            };
            match self
                .auth_fields(binding, handle, &request, &url, extensions, &defaults)
                .await
            {
                Some(fields) => auth = fields,
                None => {
                    {
                        let mut w = self.lock();
                        w.unsent = Some(RefusalCode::UnsentAuthFailed);
                        w.credential_refused = true;
                    }
                    self.settle_attempt(&record);
                    return false;
                }
            }
        }
        let mut native = None;
        if let Some(AuthBinding::Native(bindings)) = route.auth.as_ref().filter(|_| !bound) {
            if self.live_passthrough() {
                self.lock().refused = Some(ReasonCode::CredentialUnavailable);
                self.settle_attempt(&record);
                return false;
            }
            let result = match bindings.select(&selected_pool, &qualified_member, destination) {
                Ok(crate::auth_bindings::native::SelectedCredential::None) => Ok(None),
                Ok(crate::auth_bindings::native::SelectedCredential::Required(binding)) => self
                    .native_credential(binding, &request, &url, scope.as_deref(), &defaults)
                    .await
                    .map(Some),
                Err(error) => Err(error),
            };
            match result {
                Ok(value) => native = value,
                Err(_) => {
                    let mut walk = self.lock();
                    walk.unsent = Some(RefusalCode::UnsentAuthFailed);
                    walk.credential_refused = true;
                    drop(walk);
                    self.settle_attempt(&record);
                    return false;
                }
            }
        }
        if !self.owns_attempt(record.attempt, destination) {
            return false;
        }

        let native_requires_secure = native
            .as_ref()
            .is_some_and(|fields| fields.require_secure());
        let native_names = native
            .as_ref()
            .map(|fields| fields.sealed_names())
            .unwrap_or_default();
        let native_selected = matches!(&route.auth, Some(AuthBinding::Native(_)));
        let (_, path) = split(&url);

        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::OutboundHead);
        let mut head = busbar_contract::conn::OwnedHead::with_capacity(
            request.fields.len() + auth.len() + defaults.len(),
        );

        if let Some(fields) = native {
            fields.append_to(&mut head);
        }
        head.extend(auth.iter().filter(|f| !f.query).map(|f| {
            (
                String::from_utf8_lossy(&f.name).into_owned(),
                f.value.expose(&crate::seal::lend()).clone(),
            )
        }));
        head.extend(auth.iter().filter(|f| f.query).map(|f| {
            (
                busbar_contract::conn::SEALED_QUERY_FIELD.to_owned(),
                f.query_pair(&crate::seal::lend())
                    .into_exposed(&crate::seal::lend()),
            )
        }));

        head.extend(
            request
                .fields
                .iter()
                .filter(|(n, _)| {
                    !auth
                        .iter()
                        .any(|f| !f.query && f.name.eq_ignore_ascii_case(n))
                        && !native_names
                            .iter()
                            .any(|name| name.as_bytes().eq_ignore_ascii_case(n))
                })
                .filter(|(n, _)| {
                    !native_selected
                        || !std::str::from_utf8(n)
                            .is_ok_and(crate::auth::upstream_binding::framer_owned)
                })
                .filter(|(n, _)| !busbar_contract::conn::is_sealed_fields_field(n))
                .filter(|(n, _)| !busbar_contract::conn::is_sealed_query_field(n))
                .map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), v.clone())),
        );

        head.extend(
            defaults
                .iter()
                .filter(|(n, _)| {
                    !n.eq_ignore_ascii_case(CONTENT_LENGTH)
                        && (!native_selected
                            || !std::str::from_utf8(n)
                                .is_ok_and(crate::auth::upstream_binding::framer_owned))
                        && !auth
                            .iter()
                            .any(|f| !f.query && f.name.eq_ignore_ascii_case(n))
                        && !native_names
                            .iter()
                            .any(|name| name.as_bytes().eq_ignore_ascii_case(n))
                })
                .map(|(n, v)| (String::from_utf8_lossy(n).into_owned(), v.clone())),
        );

        let mut sealed: Vec<String> = auth
            .iter()
            .filter(|f| !f.query)
            .map(|f| String::from_utf8_lossy(&f.name).to_ascii_lowercase())
            .collect();
        sealed.extend(native_names);
        if !sealed.is_empty() {
            head.push(
                busbar_contract::conn::SEALED_FIELDS_FIELD.to_owned(),
                sealed.join(",").into_bytes(),
            );
        }
        let require_secure =
            protected || auth.iter().any(|f| f.require_secure) || native_requires_secure;
        drop(auth);
        let cap_ms = self.attempt_cap();
        let (pool, stated, degraded) = {
            let w = self.lock();
            w.live.as_ref().map_or_else(Default::default, |l| {
                (
                    Self::metric_pool(&l.pool, &l.member).to_string(),
                    l.stated.clone(),
                    l.degraded,
                )
            })
        };

        if self.probe_of.is_none() && !degraded {
            e.telemetry
                .upstream_attempt_stated(&pool, destination, stated.as_ref());
        }
        if !self.owns_attempt(record.attempt, destination) {
            return false;
        }

        // The head built above is the one the open sends: it moves into the connection, which
        // keeps it for the dial (and wipes it) without copying it again.
        if let Some(handoff) = selected.as_mut() {
            if !handoff.commit() {
                self.settle_attempt(&record);
                return false;
            }
        }
        let opened = e.conns.open_owned(
            e.caller,
            need,
            &OpenDesc {
                completed_head: None,
                target: &url,
                fields: &[],

                body: if let Some(prepared) = prepared {
                    bytes::Bytes::from_owner(prepared)
                } else if request.text {
                    bytes::Bytes::new()
                } else {
                    std::mem::take(&mut request.body).into()
                },
                timeout_ms: cap_ms,
                method: &request.verb,
                head_target: path.as_bytes(),
                within: &within,

                member: &route.provider,

                unit: self.route.unit.get(),
            },
            head,
            require_secure,
            carried.as_deref(),
        );
        let now_us = e.clock.now_micros();
        let now_ms = now_us / 1000;
        match opened {
            Ok(conn) => {
                {
                    let mut w = self.lock();
                    if !w.live.as_ref().is_some_and(|l| {
                        l.record.attempt == record.attempt && l.member.destination == destination
                    }) {
                        drop(w);
                        let _closed = e.conns.close(e.caller, conn);
                        return false;
                    }
                    w.sent = true;
                    if let Some(live) = w.live.as_mut() {
                        live.keep = keep;
                        live.conn = Some(conn);
                        live.anchor_ms = now_ms;
                        live.anchor_us = now_us;
                    }
                }
                if request.text && !request.body.is_empty() {
                    return self.write_to(conn, &request.body, true).await;
                }
                true
            }

            Err(err) if err.is_auth() => {
                if self.owns_attempt(record.attempt, destination) {
                    {
                        let mut w = self.lock();
                        w.unsent = Some(RefusalCode::UnsentAuthFailed);
                        w.credential_refused = true;
                    }
                    warn_credential_refused(&route.provider, &route.base_url, err);
                }
                self.settle_attempt(&record);
                false
            }
            Err(err) => {
                if !self.owns_attempt(record.attempt, destination) {
                    return false;
                }
                let _ = self.no_answer(token, NoAnswer::of(err));
                self.lock().unsent = Some(RefusalCode::UnsentOpenRefused);
                false
            }
        }
    }

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

    async fn next_piece(&self, token: &Pass<Route>) -> Option<FarPiece> {
        let e = self.egress;
        let now = e.clock.now_millis();
        let (conn, answered, wait_ms, target) = {
            let w = self.lock();
            let live = w.live.as_ref()?;
            if live.ended {
                return None;
            }
            let conn = live.conn?;
            let remaining = w.walk.ctx().remaining_ms(now);

            let stream_left = || {
                let ceiling = e.send_ceiling_secs().max(1).saturating_mul(1000);
                let spent = u64::try_from(now.saturating_sub(live.anchor_ms)).unwrap_or(u64::MAX);
                ceiling.saturating_sub(spent)
            };
            let wait = match (live.answered, live.member.attempt_timeout_ms) {
                (true, _) if self.route.wants_stream => stream_left(),
                (true, _) => remaining.max(1),

                (false, Some(ms)) => attempt_cap_ms(ms, remaining),

                (false, None) if self.route.wants_stream => stream_left(),
                (false, None) => remaining.max(1),
            };
            (
                conn,
                live.answered,
                wait,
                (live.record.attempt, live.member.destination),
            )
        };
        let mut scratch = Scratch::lend(&self.scratch);
        let read = tokio::time::timeout(
            Duration::from_millis(wait_ms),
            std::future::poll_fn(|cx| e.conns.poll_read(e.caller, conn, cx, &mut scratch.buf)),
        )
        .await;
        if !self.owns_attempt(target.0, target.1) {
            return None;
        }
        let piece = match read {
            Err(_elapsed) if !answered => {
                return Some(self.no_answer(token, NoAnswer::Timeout));
            }

            Ok(Err(err)) if !answered && err.is_auth() => {
                self.lock().credential_refused = true;
                if let Some(route) = e.routes.get(&target.1) {
                    warn_credential_refused(&route.provider, &route.base_url, err);
                }
                self.settle();
                return Some(fail_over());
            }
            Ok(Err(ConnError::Fault)) if !answered => {
                let cause = e.conns.failure_cause(e.caller, conn);
                return Some(match cause {
                    Some(cause) if cause.stage == CAUSE_FRAMER && cause.outbound => {
                        self.local_fault(token, &cause)
                    }
                    _ => self.no_answer(token, NoAnswer::of(ConnError::Fault)),
                });
            }
            Ok(Err(err)) if !answered => {
                return Some(self.no_answer(token, NoAnswer::of(err)));
            }

            Err(_) | Ok(Err(_)) => return Some(self.cut(token)),
            Ok(Ok(piece)) => piece,
        };
        let buf = &scratch.buf;
        let out = match piece.kind {
            PieceKind::Completion => self.end(true),

            PieceKind::Fields if !answered => self.head(token, &piece, &buf[..piece.len]),

            PieceKind::Fields | PieceKind::HookReply => {
                self.trailers(&piece, buf[..piece.len].to_vec())
            }
            PieceKind::Body if answered => self.capped(FarPiece {
                bytes: buf[..piece.len].to_vec(),
                ..FarPiece::default()
            }),
            PieceKind::Body => self.first(token, &piece, buf[..piece.len].to_vec()),
        };

        drop(scratch);

        let failing = self
            .lock()
            .live
            .as_ref()
            .is_some_and(|l| l.failing.is_some());
        if out.fail_over && failing {
            return Some(self.failed_over(token).await);
        }
        Some(out)
    }

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

    fn trailers(&self, piece: &busbar_contract::conn::Piece, bytes: Vec<u8>) -> FarPiece {
        let mut out = FarPiece {
            bytes,
            fields: true,
            ..FarPiece::default()
        };
        let target = {
            let w = self.lock();
            w.live
                .as_ref()
                .filter(|l| {
                    piece.status_code.is_some()
                        && !matches!(piece.status, Some(WireStatusClass::Success) | None)
                        && l.error_left.is_none()
                        && l.unjudged.is_none()
                })
                .map(|l| (l.record.attempt, l.member.destination))
        };
        let classified = target.map(|(_, destination)| {
            self.breaker().classify(
                destination,
                UpstreamStatus {
                    class: piece.status,
                    fault: piece.fault,
                    code: wire_code(piece),
                    retry_after: piece.retry_after_secs,
                },
            )
        });
        let mut w = self.lock();
        let Some(live) = w.live.as_mut() else {
            return out;
        };
        if let Some(code) = piece.status_code {
            out.status = Some((code, class_code(piece.status)));
        }
        if target == Some((live.record.attempt, live.member.destination)) {
            if let Some(classified) = classified {
                live.unjudged = Some(Unjudged {
                    classified,
                    class: piece.status,
                    code: wire_code(piece),
                    retry_after: piece.retry_after_secs,
                    after_success: true,
                });
                live.ended = true;
                out.last = true;
            }
        }
        delivered(live, &out, self.route.wants_stream);
        drop(w);
        if out.last {
            self.settle_read();
        }
        out
    }

    fn capped(&self, piece: FarPiece) -> FarPiece {
        let mut w = self.lock();
        let Some(live) = w.live.as_mut() else {
            return piece;
        };
        let piece = cap(live, piece);
        delivered(live, &piece, self.route.wants_stream);
        drop(w);
        if piece.last {
            self.settle_read();
        }
        piece
    }

    fn cut(&self, token: &Pass<Route>) -> FarPiece {
        let e = self.egress;
        let target = {
            let w = self.lock();
            w.live
                .as_ref()
                .filter(|l| l.error_left.is_none())
                .map(|live| {
                    (
                        live.record.attempt,
                        live.pool.clone(),
                        Self::metric_pool(&live.pool, &live.member).to_string(),
                        live.member.destination,
                    )
                })
        };
        if let Some((attempt, pool, metric_pool, destination)) = target {
            if self.breaker().observe(
                &pool,
                destination,
                Outcome::Transient { retry_after: None },
                e.clock.now_secs(),
                token,
            ) {
                e.telemetry.breaker_trip(&metric_pool, destination);
            }
            if !self.owns_attempt(attempt, destination) {
                return FarPiece {
                    cut: true,
                    last: true,
                    ..FarPiece::default()
                };
            }
        }

        FarPiece {
            cut: true,
            ..self.end(false)
        }
    }

    fn end(&self, clean: bool) -> FarPiece {
        let mut w = self.lock();
        let mut refund = None;
        let target = w
            .live
            .as_ref()
            .map(|l| (l.record.attempt, l.member.destination));
        if let Some(live) = w.live.as_mut() {
            if !clean && live.spent && !live.delivered {
                refund = Some(live.member.destination);
            }
            live.kept = clean && live.spent;
            live.spent = false;
            live.ended = true;

            let success = live.answered && live.error_left.is_none();
            if clean && success && live.unjudged.is_none() && self.probe_of.is_none() {
                live.unjudged = Some(Unjudged {
                    classified: Classified {
                        disposition: Disposition::ClientFault,
                        outcome: Outcome::Success,
                        label: Disposition::ClientFault.label(),
                    },
                    class: Some(WireStatusClass::Success),
                    code: None,
                    retry_after: None,
                    after_success: true,
                });
            }
        }
        drop(w);
        if let Some(destination) = refund {
            self.breaker().refund_budget(destination);
        }
        if target.is_some_and(|(attempt, destination)| self.owns_attempt(attempt, destination)) {
            self.settle_read();
        }
        FarPiece {
            last: true,
            ..FarPiece::default()
        }
    }

    fn first(
        &self,
        token: &Pass<Route>,
        piece: &busbar_contract::conn::Piece,
        bytes: Vec<u8>,
    ) -> FarPiece {
        let e = self.egress;
        let status = UpstreamStatus {
            class: piece.status,
            fault: piece.fault,
            code: wire_code(piece),
            retry_after: piece.retry_after_secs,
        };
        let far_status = Some((piece.status_code.unwrap_or(0), class_code(piece.status)));
        let success = matches!(status.class, Some(WireStatusClass::Success) | None);
        let target = {
            let mut w = self.lock();
            let Some(live) = w.live.as_mut() else {
                return fail_over();
            };
            live.answered = true;
            (live.record.attempt, live.member.destination)
        };
        let now = e.clock.now_secs();
        if let Some(destination) = self.probe_of {
            if success {
                let _retirement = self.retiring();
                let live = {
                    let mut w = self.lock();
                    if !w
                        .live
                        .as_ref()
                        .is_some_and(|l| (l.record.attempt, l.member.destination) == target)
                    {
                        return fail_over();
                    }
                    let mut live = w.live.take();
                    if let Some(live) = live.as_mut() {
                        live.ended = true;
                    }
                    live
                };
                if let Some(live) = live {
                    let mut retirement = Retirement { owner: self, live };
                    self.breaker()
                        .probed(destination, Outcome::Success, now, token);
                    retirement.live.probe = None;
                    retirement.finish();
                }
            } else {
                let classified = self.breaker().classify(destination, status.clone());
                let mut w = self.lock();
                if let Some(live) = w
                    .live
                    .as_mut()
                    .filter(|l| (l.record.attempt, l.member.destination) == target)
                {
                    live.ended = true;
                    live.unjudged = Some(Unjudged {
                        classified,
                        class: status.class,
                        code: status.code,
                        retry_after: status.retry_after,
                        after_success: false,
                    });
                }
            }
            return FarPiece {
                bytes,
                status: far_status,
                last: true,
                ..FarPiece::default()
            };
        }
        if success {
            let (mut reading, anchor_us, degraded) = {
                let mut w = self.lock();
                let Some(live) = w
                    .live
                    .as_mut()
                    .filter(|l| (l.record.attempt, l.member.destination) == target)
                else {
                    return fail_over();
                };
                (Reading::take(self, live), live.anchor_us, live.degraded)
            };
            self.breaker()
                .observe(&reading.pool, target.1, Outcome::Success, now, token);
            reading.probe = None;
            let spent = self.breaker().spend_budget(target.1);
            let committed = {
                let mut w = self.lock();
                if let Some(live) = w
                    .live
                    .as_mut()
                    .filter(|l| (l.record.attempt, l.member.destination) == target)
                {
                    live.spent = spent;
                    live.delivered = self.route.wants_stream && !bytes.is_empty();
                    true
                } else {
                    false
                }
            };
            if !committed {
                if spent {
                    self.breaker().refund_budget(target.1);
                }
                return fail_over();
            }
            let head_us = e.clock.now_micros().saturating_sub(anchor_us);
            e.telemetry.upstream_latency(
                target.1,
                micros_f64(u64::try_from(head_us).unwrap_or(u64::MAX)) / 1000.0,
            );
            if !self.owns_attempt(target.0, target.1) {
                return fail_over();
            }
            return FarPiece {
                bytes,
                status: far_status,
                relayed: degraded,
                ..FarPiece::default()
            };
        }
        let classified = self.breaker().classify(target.1, status.clone());
        let hard = matches!(classified.disposition, Disposition::HardDown);
        let client_fault = matches!(classified.disposition, Disposition::ClientFault);
        let mut w = self.lock();
        let Some(live) = w
            .live
            .as_mut()
            .filter(|l| (l.record.attempt, l.member.destination) == target)
        else {
            return fail_over();
        };
        if client_fault || hard || live.degraded || self.route.once {
            live.unjudged = Some(Unjudged {
                classified,
                class: status.class,
                code: status.code,
                retry_after: status.retry_after,
                after_success: false,
            });
            live.error_left = Some(e.error_body_max);
            let relayed = live.degraded;
            let piece = cap(
                live,
                FarPiece {
                    bytes,
                    status: far_status,
                    relayed,
                    ..FarPiece::default()
                },
            );
            drop(w);
            if piece.last {
                self.settle_read();
            }
            return piece;
        }
        live.failing = Some(classified);
        fail_over()
    }

    async fn failed_over(&self, token: &Pass<Route>) -> FarPiece {
        let e = self.egress;
        let target = {
            let w = self.lock();
            let Some(live) = w.live.as_ref().filter(|l| l.failing.is_some()) else {
                return fail_over();
            };
            (live.record.attempt, live.member.destination)
        };
        let mut left = e.error_body_max;
        let mut scratch = Scratch::lend(&self.scratch);
        while left > 0 {
            let now = e.clock.now_millis();
            let (conn, wait_ms) = {
                let w = self.lock();
                let Some(live) = w.live.as_ref().filter(|l| {
                    l.failing.is_some() && (l.record.attempt, l.member.destination) == target
                }) else {
                    return fail_over();
                };
                let Some(conn) = live.conn else {
                    break;
                };
                let wait = if self.route.wants_stream {
                    let ceiling = e.send_ceiling_secs().max(1).saturating_mul(1000);
                    let spent =
                        u64::try_from(now.saturating_sub(live.anchor_ms)).unwrap_or(u64::MAX);
                    ceiling.saturating_sub(spent)
                } else {
                    w.walk.ctx().remaining_ms(now).max(1)
                };
                (conn, wait)
            };
            let read = tokio::time::timeout(
                Duration::from_millis(wait_ms),
                std::future::poll_fn(|cx| e.conns.poll_read(e.caller, conn, cx, &mut scratch.buf)),
            )
            .await;
            if !self.owns_attempt(target.0, target.1) {
                return fail_over();
            }
            match read {
                Ok(Ok(piece)) if !matches!(piece.kind, PieceKind::Completion) => {
                    left = left.saturating_sub(piece.len.max(1));
                }

                _ => break,
            }
        }
        let _retirement = self.retiring();
        let live = {
            let mut w = self.lock();
            if w.live.as_ref().is_some_and(|l| {
                l.failing.is_some() && (l.record.attempt, l.member.destination) == target
            }) {
                w.live.take()
            } else {
                None
            }
        };
        if let Some(live) = live {
            let mut retirement = Retirement { owner: self, live };
            let live = &mut retirement.live;
            if let Some(classified) = live.failing.take() {
                let pool = Self::metric_pool(&live.pool, &live.member).to_string();
                let destination = live.member.destination;
                self.record(live, token, classified, e.clock.now_secs());
                e.telemetry.upstream_failure_stated(
                    &pool,
                    destination,
                    classified.label,
                    live.stated.as_ref(),
                );
                e.telemetry.failover(&pool, classified.label);
                let mut w = self.lock();
                if matches!(classified.disposition, Disposition::ContextLength) {
                    w.walk
                        .refused_for_size(&e.ports(self.breaker()), &live.pool, &live.member);
                }
                w.failed = Some(classified.label);
            }
            retirement.finish();
        }
        fail_over()
    }
}

impl Drop for EgressFarEnd<'_> {
    fn drop(&mut self) {
        let live = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .live
            .take();
        self.retire(live);
    }
}

impl FarEnd for EgressFarEnd<'_> {
    fn member_wait(&self, token: &Pass<Route>, member: &str) -> Option<u32> {
        let pool = self.egress.pools.get(&self.route.pool)?;
        let at = pool
            .members
            .iter()
            .find(|m| super::route::operator_name(m.name.as_bytes()) == member.as_bytes())?;
        let left = self.breaker().cooldown_remaining(
            &pool.name,
            at.destination,
            self.egress.clock.now_secs(),
            token,
        );
        Some(u32::try_from(left.max(1)).unwrap_or(u32::MAX))
    }

    fn stated(&self, _token: &Pass<Route>, labels: StatedLabels) {
        if let Some(live) = self.lock().live.as_mut() {
            live.stated = Some(labels);
        }
    }

    fn judged(&self, token: &Pass<Route>, fault: u8) {
        self.judged_stating(token, fault, None);
    }

    /// The plane's wait joins the answer's own (the longer one holds) before the verdict is recorded, so the
    /// breaker's classification and the walk's exhaustion wait read it (IF §12.3).
    fn judged_waiting(&self, token: &Pass<Route>, fault: u8, retry_after_s: Option<u64>) {
        if let Some(wait) = retry_after_s {
            let mut w = self.lock();
            if let Some(held) = w.live.as_mut().and_then(|live| live.unjudged.as_mut()) {
                held.retry_after = Some(held.retry_after.map_or(wait, |stated| stated.max(wait)));
            }
        }
        self.judged_stating(token, fault, None);
    }

    fn taken(&self, _token: &Pass<Route>) {
        if let Some(live) = self.lock().live.as_mut() {
            live.taken = true;
        }
    }

    fn judged_stating(&self, token: &Pass<Route>, fault: u8, reason: Option<&str>) {
        let (target, held, mut read, refund, ended) = {
            let mut w = self.lock();
            let Some(live) = w.live.as_mut() else {
                return;
            };
            if fault != FAULT_NONE && live.unjudged.is_some() {
                live.fault_reason = reason.map(str::to_string);
            }
            let refund =
                if fault != FAULT_NONE && live.ended && live.kept && !live.delivered && !live.taken
                {
                    live.kept = false;
                    Some(live.member.destination)
                } else {
                    None
                };
            let held = if fault != FAULT_NONE || live.ended {
                live.unjudged.take()
            } else {
                None
            };
            let read = held.as_ref().map(|_| Reading::take(self, live));
            (
                (live.record.attempt, live.member.destination),
                held,
                read,
                refund,
                live.ended,
            )
        };

        if let Some(destination) = refund {
            self.breaker().refund_budget(destination);
        }
        if let (Some(held), Some(read)) = (held, read.as_mut()) {
            self.record_held(read, held, Some((token, fault)));
        }
        let retired = {
            let mut w = self.lock();
            if let Some(live) = w
                .live
                .as_mut()
                .filter(|l| (l.record.attempt, l.member.destination) == target)
            {
                if let Some(read) = read.as_mut() {
                    live.probe = read.probe.take();
                }
                if ended {
                    if fault == FAULT_NONE && !live.delivered {
                        w.completed = Some((live.pool.clone(), live.member.clone(), live.call));
                    }
                    w.live.take()
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(read) = read {
            self.release_reading(read);
        }
        self.retire(retired);
    }

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

    fn attempt_span(&self, _token: &Pass<Route>) -> tracing::Span {
        // Below the hot-path level the span is disabled: take no lock for its fields.
        if !crate::observability::hotpath_enabled() {
            return tracing::Span::none();
        }
        let w = self.lock();
        let Some(live) = w.live.as_ref() else {
            return tracing::Span::none();
        };
        let span = super::timing::attempt_span();
        span.record("lane", live.member.destination.get());
        span.record("degraded", live.degraded);
        span
    }

    fn send<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
    ) -> impl Future<Output = bool> + Send + 'a {
        self.send_attempt(token, request, None)
    }

    fn send_selected<'a>(
        &'a self,
        token: &'a Pass<Route>,
        request: OutboundRequest,
        handoff: &'a mut super::port_egress::SelectedHandoff,
    ) -> impl Future<Output = bool> + Send + 'a {
        self.send_attempt(token, request, Some(handoff))
    }

    fn next<'a>(
        &'a self,
        token: &'a Pass<Route>,
    ) -> impl Future<Output = Option<FarPiece>> + Send + 'a {
        self.next_piece(token)
    }

    async fn followup<'a>(&'a self, token: &'a Pass<Route>, mut request: OutboundRequest) -> bool {
        let taken = {
            let mut w = self.lock();
            if w.live.is_some() || w.walking || w.retiring != 0 || self.probe_of.is_some() {
                return false;
            }
            let Some((pool, member, call)) = w.completed.take() else {
                return false;
            };
            if call != token.call() || request.pool != pool || request.member != member.name {
                return false;
            }
            // Shape consults this far end's locks, so call it outside the state lock.
            w.walking = true;
            (pool, member.destination, w.walk.clone())
        };
        let (pool, destination, walk) = taken;
        let mut walking = Walking { owner: self, walk };
        let ports = self.egress.ports(self.breaker());
        let Some(taken) = walking
            .walk
            .continue_member(&ports, &pool, destination, self, token)
        else {
            return false;
        };
        request.attempt_no = taken.attempt;
        self.admit_taken(taken, token.call());
        drop(walking);
        self.send_attempt(token, request, None).await
    }

    fn candidates(&self, _token: &Pass<Route>) -> Option<Candidates> {
        let pool = self.egress.pools.get(&self.route.pool)?;
        let members = pool.admissible_members();
        Some(Candidates {
            pool: pool.name.clone(),
            members: members
                .iter()
                .enumerate()
                .filter(|(_, m)| {
                    self.route
                        .native_member_grants
                        .as_ref()
                        .is_none_or(|grants| {
                            grants
                                .get(&pool.name)
                                .is_some_and(|allowed| allowed.iter().any(|name| name == &m.name))
                        })
                })
                .filter(|(_, m)| {
                    self.route.member_grants.as_ref().is_none_or(|grants| {
                        grants.get(&pool.name).is_some_and(|allowed| {
                            allowed.iter().any(|name| {
                                super::route::operator_name(m.name.as_bytes()) == name.as_bytes()
                            })
                        })
                    })
                })
                .filter(|(_, m)| {
                    self.route.allowed_member.as_ref().is_none_or(|allowed| {
                        super::route::operator_name(m.name.as_bytes()) == allowed.as_bytes()
                    })
                })
                .map(|(idx, m)| {
                    let facts = self.facts_of(m);
                    let standing = self
                        .signals
                        .as_ref()
                        .map(|s| s.standing(&pool.name, m.destination))
                        .unwrap_or_default();
                    CandidateFacts {
                        idx,
                        model: facts
                            .filter(|f| !f.model.is_empty())
                            .map_or_else(|| m.name.clone(), |f| f.model.clone()),
                        provider: self
                            .egress
                            .routes
                            .get(&m.destination)
                            .map(|r| r.provider.clone())
                            .unwrap_or_default(),
                        weight: m.weight,
                        context_max: m.context_max.and_then(|c| usize::try_from(c).ok()),
                        tier: facts.and_then(|f| f.tier.clone()),
                        cost_per_mtok: facts.and_then(|f| f.cost_per_mtok),
                        route_cost: busbar_contract::SignalBag::new(),
                        tags: facts.map(|f| f.tags.clone()).unwrap_or_default(),
                        latency_ms: standing.latency_ms,
                        available_concurrency: standing.available_concurrency,
                        budget_remaining: standing.budget_remaining,
                        breaker_state: standing.breaker_state,
                        error_rate: standing.error_rate,
                        latency_p95_ms: standing.latency_p95_ms,
                    }
                })
                .collect(),
        })
    }

    fn scope(&self, _token: &Pass<Route>) -> Option<super::RoutedScope> {
        let pool = self.egress.pools.get(&self.route.pool)?;
        Some(super::RoutedScope {
            pool: pool.name.clone(),
            container: String::new(),
        })
    }

    fn candidate_lane(&self, token: &Pass<Route>, index: usize) -> Option<String> {
        // Indexes are stable positions in this exact admissible pool, including filtered gaps.
        let candidates = self.candidates(token)?;
        if !candidates
            .members
            .iter()
            .any(|candidate| candidate.idx == index)
        {
            return None;
        }
        self.egress
            .pools
            .get(&self.route.pool)?
            .admissible_members()
            .get(index)
            .map(|member| member.name.clone())
    }

    fn remaining(&self, _token: &Pass<Route>) -> Option<usize> {
        let w = self.lock();
        let Some((name, primary)) = w.walk.walking() else {
            return Some(0);
        };
        let pool = self.egress.pools.get(name)?;
        let members = self
            .shape(&pool.name, pool.admissible_members().into_owned(), primary)
            .map(|(members, _)| members)
            .unwrap_or_default();
        Some(
            members
                .iter()
                .filter(|m| !w.walk.ctx().is_excluded(m.destination))
                .count(),
        )
    }

    fn failure(&self, _token: &Pass<Route>) -> Option<&'static str> {
        self.lock().failed
    }

    fn unsent(&self, _token: &Pass<Route>) -> Option<RefusalCode> {
        let w = self.lock();
        w.local.or_else(|| w.unsent.filter(|_| !w.sent))
    }

    fn credential_refused(&self, _token: &Pass<Route>) -> bool {
        self.lock().credential_refused
    }

    fn constrain(&self, _token: &Pass<Route>, constraint: Constraint) {
        *self
            .constraint
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(constraint);
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
pub(super) mod tests;

fn delivered(live: &mut Live, piece: &FarPiece, streamed: bool) {
    if streamed && live.answered && live.error_left.is_none() && !piece.bytes.is_empty() {
        live.delivered = true;
    }
}

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

impl<'a> std::fmt::Debug for Ride<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ride")
            .field("need", &self.need)
            .field("keep", &self.keep)
            .field("base_url", &"<redacted>")
            .finish()
    }
}
