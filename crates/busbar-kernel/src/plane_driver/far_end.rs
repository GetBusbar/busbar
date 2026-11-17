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
