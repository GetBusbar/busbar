// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The driver's request-stage hooks run at the head
//! of the route leg, after admission, over the
//! plane's own projection of the unit's request (`project`, pure, ticketless), in the order the
//! previous release ran them:
//!
//! 1. the REWRITE chain (`prompt: rw` gates, the global ones then the pool's): each hook sees the
//!    request as the previous one left it; a rewrite goes back to the plane (`ProjectIn::rewrite`),
//!    which applies it in its own dialect and re-projects; a reject stops the unit;
//! 2. the global request-stage TAPS, fire-and-forget, each handed the view its grant allows;
//! 3. the decision GATES (global, then the pool's, stable-sorted by priority), fired concurrently
//!    and reconciled over the one chain: a reject wins (the first in the chain surfaces), restricts
//!    intersect, and the last ordering gate wins, filtered to what the restricts left;
//! 4. the pool's BASE route policy, when no gate ordered;
//! 5. the `candidate` stage taps over the final candidate set; the walk is then CONSTRAINED to it
//!    ([`super::FarEnd::constrain`]), the restricts riding along so a fallback pool honours them.
//!
//! Per attempt the `routing` stage taps observe the walk; the `response` stage taps fire once, at
//! the answer's head (or at the refusal the caller is answered with). A veto wears the hook's own
//! clamped status and sanitised words, rendered by the plane in its dialect (`REFUSAL_GATE`).
//!
//! The engine here is the previous release's, dialect-blind: the kernel never reads a body. What a
//! hook sees of the request is what the plane projected; what it sees of the candidates is what the
//! walk reports ([`super::FarEnd::candidates`]). A unit no hook binds pays nothing: no projection,
//! no allocation beyond the binder's answer.

use std::collections::HashSet;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use busbar_contract::abi::hook::{
    MessageView, SignalEntry, REQUEST_HAS_MAX_TOKENS, REQUEST_HAS_TOOLS, REQUEST_STREAM,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome as AbiOutcome, Span};
use busbar_contract::abi::plane::{ProjectIn, ProjectOut, CLAIM_PROBE, SPAN_ABSENT};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::{Pass, Route};
use busbar_contract::hooks::{
    BudgetBucketState, CallerIdentity, Candidate, PromptProjection, RoutingContext,
    RoutingDecision, RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_contract::signal::{Signal, SignalBag, SignalValue};
use busbar_kernel_audit::record::{HookApplied, HookHead};

use super::{blob, FarEnd, PlaneUnits};
use crate::config::PolicyOnError;
use crate::diagnostics::{
    DECISION_GATE_REJECTED, DECISION_GATE_RESTRICT_REJECT, DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
    ON_ERROR_FALLBACK_ANSWERED, ON_ERROR_FALLBACK_DEADLINE_EXCEEDED, ON_ERROR_FALLBACK_HOOK_FAILED,
    ROUTING_POLICY_DEADLINE_EXCEEDED, ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
    ROUTING_POLICY_REJECTED, ROUTING_POLICY_RESTRICT_REJECT,
    ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
};
use crate::hooks::taps::{fire_stage_taps_where, spawn_bounded_tap, StageShape};
use crate::hooks::{
    content_capped, failed_call_refuses, FallbackHook, RequestedSignals, ResolvedPolicy, TapEntry,
    REQUIRED_HOOK_UNAVAILABLE_MESSAGE, REQUIRED_HOOK_UNAVAILABLE_STATUS,
};
use crate::snapshot::{ROUTE_POLICY_REJECTIONS_TOTAL, ROUTE_POLICY_SELECTIONS_TOTAL};
use busbar_contract::hook_wire::reply::{clamp_reject_status, sanitize_reject_message};
use busbar_contract::hook_wire::HookStageProjection;

pub(crate) mod policy;

pub trait HookBinder: Send + Sync {
    fn bind(&self, bind: &Bind<'_>) -> Option<UnitHooks>;

    fn order(&self) -> HookOrder {
        HookOrder::Routed
    }

    fn bind_gated(&self, container: &str, principal: Option<&str>) -> Option<GatedHooks> {
        let _ = (container, principal);
        None
    }

    fn denied(&self, dialect: u32, status: u16) {
        let _ = (dialect, status);
    }

    fn dialect(&self, dialect: u32) -> String {
        let _ = dialect;
        String::new()
    }
}

/// ONE UNIT'S HOOK FACTS, as its hook stage reports them: every hook that ran for it, in the order
/// it ran, by the key the deployment configured it under (never the instance serving it), with its
/// decision head and whether it failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HooksRan {
    /// The unit the hooks ran for: the record is sealed under that unit's facts.
    pub unit: busbar_contract::UnitKey,
    /// The hooks, in the order they ran.
    pub hooks: Vec<HookApplied>,
}

pub trait HookJournal: Send + Sync {
    fn hooks_ran(&self, record: &HooksRan);
}

fn head_of(decided: &Decided) -> HookHead {
    match decided {
        Decided::Reject | Decided::RejectRequest { .. } => HookHead::Veto,
        Decided::Order { .. } | Decided::Restrict { .. } => HookHead::Modify,
        Decided::Weighted => HookHead::Pass,
    }
}

fn applied(hook: &str, head: HookHead, failed: bool) -> HookApplied {
    HookApplied {
        hook: hook.to_string(),
        head,
        failed,
    }
}

fn rewrite_applied(hook: &str, outcome: &TransformOutcome) -> HookApplied {
    match outcome {
        TransformOutcome::Rewrite(_) => applied(hook, HookHead::Modify, false),
        TransformOutcome::Reject { status, message } => applied(
            hook,
            HookHead::Veto,
            *status == REQUIRED_HOOK_UNAVAILABLE_STATUS
                && message.as_str() == REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
        ),
        TransformOutcome::Abstain => applied(hook, HookHead::Pass, false),
        TransformOutcome::Failed { .. } => applied(hook, HookHead::Pass, true),
    }
}

/// What a binder is told of one unit.
#[derive(Debug, Clone, Copy)]
pub struct Bind<'a> {
    /// The pool the walk routes the unit over (empty when the walk names none).
    pub pool: &'a str,
    /// The principal the kernel verified, when there is one.
    pub principal: Option<&'a str>,
    /// The dialect the unit arrived in: the index into the plane's dialects.
    pub dialect: u32,
    /// The unit's correlation id, where its host minted one (`DriverSteps::request_span`); the
    /// binder mints one from the process's counter where it is `None`.
    pub request_id: Option<u64>,
}

/// The stage taps a unit binds, by stage.
#[derive(Clone, Default)]
pub struct StageTaps {
    /// The global request-stage taps (`kind: tap`).
    pub request: Vec<TapEntry>,
    /// The `candidate` stage.
    pub candidate: Vec<TapEntry>,
    /// The `routing` stage, once per attempt.
    pub routing: Vec<TapEntry>,
    /// The `response` stage.
    pub response: Vec<TapEntry>,
}

impl StageTaps {
    fn is_empty(&self) -> bool {
        self.request.is_empty()
            && self.candidate.is_empty()
            && self.routing.is_empty()
            && self.response.is_empty()
    }
}

/// The caller's governance key, as a hook granted `user` is shown it (never its secret).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallerKey {
    /// The key's id.
    pub id: String,
    /// The key's display name.
    pub name: String,
}

pub type GroupScope = Arc<dyn Fn(&[String]) -> bool + Send + Sync>;

pub type RewriteChain = Vec<(Duration, Arc<dyn RoutingPolicy>)>;

pub type HookRead = Arc<dyn Fn(&str, Option<&str>, &str, bool) + Send + Sync>;

pub struct UnitHooks {
    pub request_id: u64,

    pub rewrites: RewriteChain,

    pub gates: Vec<(u16, ResolvedPolicy)>,

    pub policy: Option<ResolvedPolicy>,

    pub taps: StageTaps,

    pub key: Option<CallerKey>,

    pub rate_headroom: Option<f64>,

    pub budget: Vec<BudgetBucketState>,

    pub requested: RequestedSignals,

    pub groups: GroupScope,

    pub reads: HookRead,

    pub dialect: String,
}

impl std::fmt::Debug for UnitHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnitHooks")
            .field("request_id", &self.request_id)
            .field("rewrites", &self.rewrites.len())
            .field("gates", &self.gates.len())
            .field("policy", &self.policy.is_some())
            .finish_non_exhaustive()
    }
}

impl UnitHooks {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rewrites.is_empty()
            && self.gates.is_empty()
            && self.policy.is_none()
            && self.taps.is_empty()
    }
}

pub struct BoundHooks {
    pub rewrites: RewriteChain,

    pub gates: Vec<(u16, ResolvedPolicy)>,

    pub pool_rewrites: std::collections::HashMap<String, RewriteChain>,

    pub pool_gates: std::collections::HashMap<String, Vec<(u16, ResolvedPolicy)>>,

    pub pool_policies: std::collections::HashMap<String, ResolvedPolicy>,

    pub taps: StageTaps,

    pub requested: RequestedSignals,

    pub next_request_id: Arc<dyn Fn() -> u64 + Send + Sync>,

    pub caller: Arc<dyn CallerFacts>,

    pub dialects: Vec<String>,
}

pub trait CallerFacts: Send + Sync {
    fn key(&self, principal: &str) -> Option<CallerKey>;

    fn in_groups(&self, principal: Option<&str>, groups: &[String]) -> bool;

    fn rate_headroom(&self, principal: &str, pool: &str) -> Option<f64>;

    fn budget(&self, principal: &str) -> Vec<BudgetBucketState>;

    fn hook_read(&self, hook: &str, principal: Option<&str>, dialect: &str, identity: bool);

    fn denied_taps(&self, taps: &[TapEntry], request_id: u64, dialect: &str, status: u16) {
        let shape = StageShape::zeroed(request_id, "", dialect, false);
        fire_stage_taps_where(
            taps,
            &shape,
            stage_at(
                "response",
                None,
                None,
                None,
                None,
                Some("rejected_by_auth"),
                Some(status),
            ),
            SignalBag::default(),
            &|groups: &[String]| self.in_groups(None, groups),
        );
    }
}

struct Parts {
    rewrites: RewriteChain,
    gates: Vec<(u16, ResolvedPolicy)>,
    policy: Option<ResolvedPolicy>,
    taps: StageTaps,
    requested: RequestedSignals,
}

type Scope<'a> = (
    &'a [(Duration, Arc<dyn RoutingPolicy>)],
    &'a [(u16, ResolvedPolicy)],
);

impl Parts {
    fn of(
        global: Scope<'_>,
        pool: Scope<'_>,
        policy: Option<ResolvedPolicy>,
        taps: StageTaps,
        requested: RequestedSignals,
    ) -> Option<Self> {
        let mut rewrites = global.0.to_vec();
        rewrites.extend(pool.0.iter().cloned());
        let mut gates = global.1.to_vec();
        gates.extend(pool.1.iter().cloned());
        gates.sort_by_key(|(priority, _)| *priority);
        let idle = rewrites.is_empty() && gates.is_empty() && policy.is_none() && taps.is_empty();
        (!idle).then_some(Parts {
            rewrites,
            gates,
            policy,
            taps,
            requested,
        })
    }

    fn bind(
        self,
        bind: &Bind<'_>,
        (caller, dialects): (&Arc<dyn CallerFacts>, &[String]),
        request_id: u64,
    ) -> UnitHooks {
        let principal = bind.principal.map(str::to_string);
        let groups_caller = Arc::clone(caller);
        let reads_caller = Arc::clone(caller);
        UnitHooks {
            request_id,
            rewrites: self.rewrites,
            gates: self.gates,
            policy: self.policy,
            taps: self.taps,
            key: bind.principal.and_then(|p| caller.key(p)),
            rate_headroom: bind
                .principal
                .and_then(|p| caller.rate_headroom(p, bind.pool)),
            budget: bind.principal.map(|p| caller.budget(p)).unwrap_or_default(),
            requested: self.requested,
            groups: Arc::new(move |groups: &[String]| {
                groups_caller.in_groups(principal.as_deref(), groups)
            }),
            reads: Arc::new(
                move |hook: &str, principal: Option<&str>, dialect: &str, id: bool| {
                    reads_caller.hook_read(hook, principal, dialect, id);
                },
            ),
            dialect: dialects
                .get(bind.dialect as usize)
                .cloned()
                .unwrap_or_default(),
        }
    }
}

fn denied_taps(
    caller: &dyn CallerFacts,
    taps: &[TapEntry],
    request_id: u64,
    dialects: &[String],
    (dialect, status): (u32, u16),
) {
    if taps.is_empty() {
        return;
    }
    let dialect = dialects.get(dialect as usize).map_or("", String::as_str);
    caller.denied_taps(taps, request_id, dialect, status);
}

impl HookBinder for BoundHooks {
    fn dialect(&self, dialect: u32) -> String {
        self.dialects
            .get(dialect as usize)
            .cloned()
            .unwrap_or_default()
    }

    fn bind(&self, bind: &Bind<'_>) -> Option<UnitHooks> {
        let parts = Parts::of(
            (&self.rewrites, &self.gates),
            (
                self.pool_rewrites
                    .get(bind.pool)
                    .map_or(&[][..], Vec::as_slice),
                self.pool_gates
                    .get(bind.pool)
                    .map_or(&[][..], Vec::as_slice),
            ),
            self.pool_policies.get(bind.pool).cloned(),
            self.taps.clone(),
            self.requested,
        )?;
        Some(parts.bind(
            bind,
            (&self.caller, &self.dialects),
            bind.request_id.unwrap_or_else(|| (self.next_request_id)()),
        ))
    }

    fn denied(&self, dialect: u32, status: u16) {
        if self.taps.response.is_empty() {
            return;
        }
        denied_taps(
            &*self.caller,
            &self.taps.response,
            (self.next_request_id)(),
            &self.dialects,
            (dialect, status),
        );
    }
}

pub struct HostHooks {
    pub host: Arc<dyn crate::plane_driver::EngineHost>,

    pub caller: Arc<dyn CallerFacts>,

    pub dialects: Vec<String>,

    pub plane_key: String,
}

impl HookBinder for HostHooks {
    fn dialect(&self, dialect: u32) -> String {
        self.dialects
            .get(dialect as usize)
            .cloned()
            .unwrap_or_default()
    }

    fn bind(&self, bind: &Bind<'_>) -> Option<UnitHooks> {
        let h = &*self.host;

        let (mut rewrites, mut gates) = if self.plane_key.is_empty() {
            (Vec::new(), Vec::new())
        } else {
            (
                h.plane_rewrites_of(&self.plane_key, crate::hooks::SECTION_SCOPE),
                h.plane_gates_of(&self.plane_key, crate::hooks::SECTION_SCOPE),
            )
        };
        rewrites.extend(h.pool_rewrites(bind.pool).iter().cloned());
        gates.extend(h.pool_gates(bind.pool).iter().cloned());
        let parts = Parts::of(
            (h.rewrite_hooks(), h.global_gates()),
            (rewrites.as_slice(), gates.as_slice()),
            h.pool_policy(bind.pool).cloned(),
            StageTaps {
                request: h.tap_hooks().to_vec(),
                candidate: h.tap_hooks_candidate().to_vec(),
                routing: h.tap_hooks_routing().to_vec(),
                response: h.tap_hooks_response().to_vec(),
            },
            *h.requested_signals(),
        )?;
        Some(parts.bind(
            bind,
            (&self.caller, &self.dialects),
            bind.request_id.unwrap_or_else(|| h.next_request_id()),
        ))
    }

    fn denied(&self, dialect: u32, status: u16) {
        let taps = self.host.tap_hooks_response();
        if taps.is_empty() {
            return;
        }
        denied_taps(
            &*self.caller,
            taps,
            self.host.next_request_id(),
            &self.dialects,
            (dialect, status),
        );
    }
}

/// ONE CANDIDATE, as the walk reports it to the hooks: its configuration and its live signals.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CandidateFacts {
    /// The member's stable index in the pool (what an order names).
    pub idx: usize,
    /// The member's model.
    pub model: String,
    /// The member's provider.
    pub provider: String,
    /// The member's weight.
    pub weight: u32,
    /// The member's context ceiling.
    pub context_max: Option<usize>,
    /// The member's tier.
    pub tier: Option<String>,
    /// The member's cost per million tokens.
    pub cost_per_mtok: Option<f64>,
    /// The host's plane-declared cost terms, already priced for this lane and generation.
    pub route_cost: SignalBag,
    /// The member's tags.
    pub tags: Vec<String>,
    /// The member's latency average, in milliseconds.
    pub latency_ms: Option<f64>,
    /// The member's free concurrency.
    pub available_concurrency: usize,
    /// The member's lifetime budget left.
    pub budget_remaining: Option<i64>,
    /// The member's breaker state (`closed`, `open`, `half_open`).
    pub breaker_state: Option<&'static str>,
    /// The member's error rate.
    pub error_rate: Option<f64>,
    /// The member's p95 latency, in milliseconds.
    pub latency_p95_ms: Option<u64>,
}

/// The candidates of the pool the walk routes a unit over.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Candidates {
    /// The pool.
    pub pool: String,
    /// Its live members, in pool order.
    pub members: Vec<CandidateFacts>,
}

/// A restrict a hook decided: only members carrying one of `tags_any`; `on_empty` when none does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Restrict {
    /// The tags, any of which admits a member.
    pub tags_any: Vec<String>,
    /// What an empty intersection does.
    pub on_empty: PolicyOnError,
    /// The deciding hook.
    pub name: std::sync::Arc<str>,
}

/// THE CONSTRAINT THE HOOKS PUT ON THE WALK.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Constraint {
    /// The members of the routed pool the walk may pick from (`None` = every one).
    pub keep: Option<Vec<usize>>,
    /// The order the walk tries them in (`None` = the walk's own pick).
    pub order: Option<Vec<usize>>,
    /// The policy that ordered or restricted, when one did.
    pub policy: Option<std::sync::Arc<str>>,
    /// Every restrict the hooks decided, re-applied to a fallback pool's members.
    pub restricts: Vec<Restrict>,
}

impl Constraint {
    pub fn enforce<'m>(
        &self,
        members: impl IntoIterator<Item = (usize, &'m [String])> + Clone,
    ) -> Result<Vec<usize>, &Restrict> {
        let mut kept: Vec<(usize, &'m [String])> = members.into_iter().collect();
        for r in &self.restricts {
            let narrowed: Vec<(usize, &'m [String])> = kept
                .iter()
                .copied()
                .filter(|(_, tags)| tags.iter().any(|t| r.tags_any.iter().any(|w| w == t)))
                .collect();
            if narrowed.is_empty() {
                if matches!(r.on_empty, PolicyOnError::Weighted) {
                    continue;
                }
                return Err(r);
            }
            kept = narrowed;
        }
        Ok(kept.into_iter().map(|(idx, _)| idx).collect())
    }
}

/// THE PLANE'S PROJECTION of a unit's request, owned: what every hook payload of the unit is
/// built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    /// The pool the plane names (the walk's, when it names one, wins).
    pub pool: String,
    /// The dialect the unit arrived in.
    pub dialect: String,
    /// The wire turn count.
    pub message_count: usize,
    /// The screenable characters.
    pub total_chars: usize,
    /// The caller's output cap.
    pub max_tokens: Option<u32>,
    /// The request declares tools.
    pub has_tools: bool,
    /// The caller asked for a stream.
    pub stream: bool,
    /// The prompt's system field.
    pub system: Option<String>,
    /// The prompt's turns.
    pub turns: Vec<(String, String)>,
    /// The end user.
    pub end_user: Option<String>,
    /// The body a rewrite left, when this projection answered one.
    pub rewritten: Option<Vec<u8>>,
    /// The session the request continues, as the plane read it (`RequestView::session`).
    pub session: Option<Vec<u8>>,
    /// The plane's projected body (`ProjectOut::body`), when it states one: what a gate-first
    /// plane's gates screen.
    pub projected: Option<Vec<u8>>,
    /// The plane stated `PROJECT_REWRITE_NOT_APPLICABLE`: the rewrite this projection carried, for
    /// which it answers no rewritten body, does not apply to the unit (its operation has no
    /// conversation to frame one into). Read only where the call carried a rewrite and no
    /// rewritten body came back.
    pub rewrite_not_applicable: bool,
}

impl Default for Projection {
    fn default() -> Self {
        Self::empty(String::new(), String::new())
    }
}

impl Drop for Projection {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.pool.zeroize();
        self.dialect.zeroize();
        self.system.zeroize();
        self.turns.zeroize();
        self.end_user.zeroize();
        self.rewritten.zeroize();
        self.session.zeroize();
        self.projected.zeroize();
    }
}

impl Projection {
    fn empty(pool: String, dialect: String) -> Self {
        Self {
            pool,
            dialect,
            message_count: 0,
            total_chars: 0,
            max_tokens: None,
            has_tools: false,
            stream: false,
            system: None,
            turns: Vec::new(),
            end_user: None,
            rewritten: None,
            session: None,
            projected: None,
            rewrite_not_applicable: false,
        }
    }

    fn prompt(&self) -> PromptProjection<'_> {
        content_capped(PromptProjection {
            system: self.system.as_deref().map(std::borrow::Cow::Borrowed),
            messages: self
                .turns
                .iter()
                .map(|(r, t)| {
                    (
                        std::borrow::Cow::Borrowed(r.as_str()),
                        std::borrow::Cow::Borrowed(t.as_str()),
                    )
                })
                .collect(),
        })
    }

    fn request<'a>(
        &'a self,
        request_id: u64,
        pool: &'a str,
        prompt: bool,
        identity: Option<CallerIdentity>,
    ) -> RoutingRequest<'a> {
        RoutingRequest {
            request_id,
            pool,
            ingress_protocol: &self.dialect,
            requested_model: None,
            message_count: self.message_count,
            tool_count: 0,
            has_tools: self.has_tools,
            total_chars: self.total_chars,
            system_chars: 0,
            max_tokens: self.max_tokens,
            stream: self.stream,
            prompt: prompt.then(|| self.prompt()),
            identity,
            signals: SignalBag::default(),
            session: self.session.as_deref(),
        }
    }

    fn shape<'a>(&'a self, request_id: u64, pool: &'a str) -> StageShape<'a> {
        StageShape {
            request_id,
            pool,
            ingress_protocol: &self.dialect,
            message_count: self.message_count,
            has_tools: self.has_tools,
            total_chars: self.total_chars,
            max_tokens: self.max_tokens,
            stream: self.stream,
        }
    }
}

/// Why the request stage stopped the unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stopped {
    /// A hook (or the engine for a hook) refused: its status and its words.
    Veto(Veto),
    /// The plane could not read the request a hook had to see.
    Unreadable,
    /// The plane answered FAULT to a `project` where no rewrite hook was known to be configured
    /// (the unit's first `project`; the gate-first stage's is made before its entry is bound): the
    /// caller decides whether a configured rewrite hook makes it the shared 500 ([`fault_veto`]) or
    /// the hooks judge the body as 1.5.5 judged one it could not parse, a Null body, and the
    /// request proceeds. `marked`: the plane marked the FAULT as its own word on an unparseable
    /// body (`abi::plane::project_fault_unparseable`); an unmarked FAULT (a panic, no crossing, a
    /// quarantined or broken plane) never takes the Null view, and is the shared 500 where a
    /// rewrite is configured or unreadable otherwise.
    Unparseable {
        /// The plane's unparseable-body mark was on the FAULT.
        marked: bool,
    },
}

/// A hook's refusal, clamped and sanitised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Veto {
    /// The status the caller is answered with.
    pub status: u32,
    /// The words.
    pub text: String,
    /// The vetoing hook's name, where a named hook vetoed (handed to the plane's `refusal`).
    pub hook: Option<String>,
}

#[path = "../gated.rs"]
pub mod gated;
pub use gated::{GatedHooks, GatedScan, GenerationHost, HookOrder, HostGatedHooks, PrincipalKeys};

fn fault_veto() -> Stopped {
    veto(
        busbar_contract::abi::plane::PROJECT_FAULT_STATUS,
        busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE,
    )
}

fn veto(status: u16, text: impl Into<String>) -> Stopped {
    Stopped::Veto(Veto {
        status: u32::from(status),
        text: text.into(),
        hook: None,
    })
}

fn veto_by(status: u16, text: impl Into<String>, hook: &str) -> Stopped {
    Stopped::Veto(Veto {
        status: u32::from(status),
        text: text.into(),
        hook: Some(hook.to_string()),
    })
}

fn stage_at<'a>(
    at: &'a str,
    model: Option<&'a str>,
    attempt_number: Option<u32>,
    remaining_candidates: Option<usize>,
    previous_failure: Option<&'a str>,
    outcome: Option<&'a str>,
    status: Option<u16>,
) -> HookStageProjection<'a> {
    HookStageProjection {
        at,
        model,
        attempt_number,
        remaining_candidates,
        previous_failure,
        outcome,
        status,
    }
}

/// What one decision came to.
#[derive(Debug, Clone, PartialEq)]
enum Decided {
    /// This ranked order.
    Order {
        order: Vec<usize>,
        name: std::sync::Arc<str>,
    },
    /// No opinion: the walk's own pick.
    Weighted,
    /// A load-bearing hook could not answer.
    Reject,
    /// The hook refused the request.
    RejectRequest {
        status: u16,
        message: String,
        name: std::sync::Arc<str>,
    },
    /// Only members carrying one of these tags.
    Restrict {
        tags_any: Vec<String>,
        name: std::sync::Arc<str>,
        on_empty: PolicyOnError,
    },
}

static FAULT_WINDOW: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

fn fault_enter(key: &str) -> bool {
    FAULT_WINDOW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(key.to_string())
}

fn fault_clear(key: &str) {
    let mut set = FAULT_WINDOW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !set.is_empty() {
        set.remove(key);
    }
}

fn map_answer(
    answer: RoutingDecision,
    name: std::sync::Arc<str>,
    candidates: &[Candidate<'_>],
    on_empty: &PolicyOnError,
) -> Decided {
    match answer {
        RoutingDecision::Prefer(order) => {
            let valid: HashSet<usize> = candidates.iter().map(|c| c.idx).collect();
            match RoutingDecision::from_ranked(order, &valid) {
                RoutingDecision::Prefer(order) => Decided::Order { order, name },
                _ => Decided::Weighted,
            }
        }
        RoutingDecision::Abstain => Decided::Weighted,
        RoutingDecision::Reject { status, message } => Decided::RejectRequest {
            status: clamp_reject_status(status),
            message: sanitize_reject_message(&message),
            name,
        },
        RoutingDecision::Restrict { tags_any } => Decided::Restrict {
            tags_any,
            name,
            on_empty: on_empty.clone(),
        },
    }
}

fn coerce_on_error(
    on_error: &PolicyOnError,
    candidates: &[Candidate<'_>],
    name: std::sync::Arc<str>,
) -> Decided {
    if failed_call_refuses(on_error) {
        return Decided::Reject;
    }
    match on_error {
        PolicyOnError::First => Decided::Order {
            order: candidates.iter().map(|c| c.idx).collect(),
            name,
        },
        PolicyOnError::Weighted | PolicyOnError::Reject => Decided::Weighted,
    }
}

struct Asked<'a> {
    view: &'a Projection,
    hooks: &'a UnitHooks,
    pool: &'a str,
    candidates: &'a [Candidate<'a>],

    named: bool,
}

impl Asked<'_> {
    fn identity(&self) -> CallerIdentity {
        CallerIdentity {
            key_id: self.hooks.key.as_ref().map(|k| k.id.clone()),
            key_name: self.hooks.key.as_ref().map(|k| k.name.clone()),
            user: self.view.end_user.clone(),
        }
    }

    fn read(&self, hook: &str, identity: bool) {
        let whose = self.hooks.key.as_ref().map(|k| k.id.as_str());
        (self.hooks.reads)(hook, whose, &self.view.dialect, identity);
    }

    async fn decide(&self, resolved: &ResolvedPolicy) -> (Decided, Option<HookApplied>) {
        let ResolvedPolicy::Policy {
            policy,
            on_error,
            on_error_chain,
            timeout,
            send_prompt,
            send_user,
            on_empty,
        } = resolved;
        if self.named && self.candidates.is_empty() {
            return (Decided::Weighted, None);
        }
        let req = self.view.request(
            self.hooks.request_id,
            self.pool,
            *send_prompt,
            send_user.then(|| self.identity()),
        );
        let ctx = RoutingContext {
            pool: self.pool,
            budget_remaining: None,
            budget: &self.hooks.budget,
        };
        if req.prompt.is_some() {
            self.read(policy.name(), req.identity.is_some());
        }
        let key = format!("{}@{}", policy.name(), self.pool);
        let decided = match tokio::time::timeout(
            *timeout,
            policy.decide(&req, self.candidates, &ctx, *timeout),
        )
        .await
        {
            Ok(Ok(answer)) => {
                fault_clear(&key);
                let decided = map_answer(answer, policy.name_arc(), self.candidates, on_empty);
                let ran = applied(policy.name(), head_of(&decided), false);
                return (decided, Some(ran));
            }
            Ok(Err(e)) => {
                if fault_enter(&key) {
                    crate::diag_warn!(
                        ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
                        policy = policy.name(),
                        pool = self.pool,
                        error = %e,
                        "routing policy failed; applying on_error fallback"
                    );
                } else {
                    crate::diag_debug!(
                        ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
                        policy = policy.name(),
                        pool = self.pool,
                        error = %e,
                        "routing policy still failing; applying on_error fallback"
                    );
                }
                self.on_error_chain(on_error_chain, on_error, &req, &ctx, policy.name_arc())
                    .await
            }
            Err(_) => {
                if fault_enter(&key) {
                    crate::diag_warn!(
                        ROUTING_POLICY_DEADLINE_EXCEEDED,
                        policy = policy.name(),
                        pool = self.pool,
                        timeout_ms = timeout.as_millis() as u64,
                        "routing policy deadline exceeded; applying on_error fallback"
                    );
                } else {
                    crate::diag_debug!(
                        ROUTING_POLICY_DEADLINE_EXCEEDED,
                        policy = policy.name(),
                        pool = self.pool,
                        timeout_ms = timeout.as_millis() as u64,
                        "routing policy deadline still exceeded; applying on_error fallback"
                    );
                }
                self.on_error_chain(on_error_chain, on_error, &req, &ctx, policy.name_arc())
                    .await
            }
        };

        let ran = applied(policy.name(), head_of(&decided), true);
        (decided, Some(ran))
    }

    async fn on_error_chain(
        &self,
        chain: &[FallbackHook],
        terminal: &PolicyOnError,
        req: &RoutingRequest<'_>,
        ctx: &RoutingContext<'_>,
        failed: std::sync::Arc<str>,
    ) -> Decided {
        for fb in chain {
            let fb_req = RoutingRequest {
                prompt: if fb.send_prompt {
                    req.prompt.clone()
                } else {
                    None
                },
                identity: if fb.send_user {
                    req.identity.clone()
                } else {
                    None
                },
                ..req.clone()
            };
            if fb_req.prompt.is_some() {
                self.read(fb.policy.name(), fb_req.identity.is_some());
            }
            let key = format!("{}@{}", fb.policy.name(), self.pool);
            match tokio::time::timeout(
                fb.timeout,
                fb.policy.decide(&fb_req, self.candidates, ctx, fb.timeout),
            )
            .await
            {
                Ok(Ok(answer)) => {
                    fault_clear(&key);
                    crate::diag_debug!(
                        ON_ERROR_FALLBACK_ANSWERED,
                        policy = &failed[..],
                        fallback = fb.policy.name(),
                        pool = self.pool,
                        "on_error fallback hook answered for the failed gate"
                    );
                    return map_answer(answer, fb.policy.name_arc(), self.candidates, &fb.on_empty);
                }
                Ok(Err(e)) => {
                    if fault_enter(&key) {
                        crate::diag_warn!(
                            ON_ERROR_FALLBACK_HOOK_FAILED,
                            fallback = fb.policy.name(),
                            pool = self.pool,
                            error = %e,
                            "on_error fallback hook failed; continuing down the chain"
                        );
                    } else {
                        crate::diag_debug!(
                            ON_ERROR_FALLBACK_HOOK_FAILED,
                            fallback = fb.policy.name(),
                            pool = self.pool,
                            error = %e,
                            "on_error fallback hook still failing; continuing down the chain"
                        );
                    }
                }
                Err(_) => {
                    if fault_enter(&key) {
                        crate::diag_warn!(
                            ON_ERROR_FALLBACK_DEADLINE_EXCEEDED,
                            fallback = fb.policy.name(),
                            pool = self.pool,
                            timeout_ms = fb.timeout.as_millis() as u64,
                            "on_error fallback hook deadline exceeded; continuing down the chain"
                        );
                    } else {
                        crate::diag_debug!(
                            ON_ERROR_FALLBACK_DEADLINE_EXCEEDED,
                            fallback = fb.policy.name(),
                            pool = self.pool,
                            timeout_ms = fb.timeout.as_millis() as u64,
                            "on_error fallback hook deadline still exceeded; continuing down the chain"
                        );
                    }
                }
            }
        }
        coerce_on_error(terminal, self.candidates, failed)
    }
}

fn candidates_of<'a>(
    facts: &'a [CandidateFacts],
    hooks: &UnitHooks,
    keep: &HashSet<usize>,
) -> Vec<Candidate<'a>> {
    facts
        .iter()
        .filter(|c| keep.contains(&c.idx))
        .map(|c| {
            let mut signals = c.route_cost.clone();
            let wants = &hooks.requested;
            if !wants.is_empty() {
                if wants.wants(Signal::CandidateBreakerState) {
                    if let Some(state) = c.breaker_state {
                        signals.push(
                            Signal::CandidateBreakerState,
                            SignalValue::Str(std::borrow::Cow::Borrowed(state)),
                        );
                    }
                }
                if wants.wants(Signal::CandidateErrorRate) {
                    if let Some(rate) = c.error_rate {
                        signals.push(Signal::CandidateErrorRate, SignalValue::F64(rate));
                    }
                }
                if wants.wants(Signal::CandidateLatencyP95Ms) {
                    if let Some(p95) = c.latency_p95_ms {
                        signals.push(Signal::CandidateLatencyP95Ms, SignalValue::U64(p95));
                    }
                }
            }
            Candidate {
                idx: c.idx,
                model: &c.model,
                provider: &c.provider,
                weight: c.weight,
                context_max: c.context_max,
                tier: c.tier.as_deref(),
                cost_per_mtok: c.cost_per_mtok,
                tags: &c.tags,
                latency_ms: c.latency_ms,
                available_concurrency: c.available_concurrency,
                budget_remaining: c.budget_remaining,
                rate_headroom: hooks.rate_headroom,
                signals,
            }
        })
        .collect()
}

fn narrow(keep: &mut HashSet<usize>, facts: &[CandidateFacts], tags_any: &[String]) -> bool {
    let narrowed: HashSet<usize> = facts
        .iter()
        .filter(|c| keep.contains(&c.idx))
        .filter(|c| c.tags.iter().any(|t| tags_any.iter().any(|w| w == t)))
        .map(|c| c.idx)
        .collect();
    if narrowed.is_empty() {
        return false;
    }
    *keep = narrowed;
    true
}

fn rewrite_bytes(rw: &busbar_contract::hooks::RewriteReply) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Crossing<'a> {
        messages: &'a [serde_json::Value],
        tools: &'a [serde_json::Value],
    }
    serde_json::to_vec(&Crossing {
        messages: &rw.messages,
        tools: &rw.tools,
    })
    .unwrap_or_default()
}

pub(crate) fn record_request_id(request_id: u64) {
    let current = tracing::Span::current();
    let hosts = current
        .metadata()
        .is_some_and(|m| m.name() == "forward" && m.fields().field("request_id").is_some());
    if hosts {
        current.record("request_id", request_id);
    } else {
        let span = tracing::debug_span!(
            target: "busbar::proxy::engine",
            "forward",
            request_id = tracing::field::Empty
        );
        span.record("request_id", request_id);
    }
}

#[cfg(test)]
#[path = "tests/rewrite_crossing_tests.rs"]
mod rewrite_crossing_tests;

#[cfg(test)]
#[path = "tests/section_attach_tests.rs"]
mod section_attach_tests;

#[cfg(not(test))]
type ProjectBytes = Vec<u8>;
#[cfg(test)]
type ProjectBytes = project_arena_custody_tests::ObservedArena;

struct ProjectBufs {
    signals: Vec<SignalEntry>,
    messages: Vec<MessageView>,
    arena: ProjectArena,
}

struct ProjectArena(zeroize::Zeroizing<ProjectBytes>);

impl From<Vec<u8>> for ProjectArena {
    fn from(bytes: Vec<u8>) -> Self {
        #[cfg(test)]
        let bytes: ProjectBytes = bytes.into();
        Self(zeroize::Zeroizing::new(bytes))
    }
}

impl std::ops::Deref for ProjectArena {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl std::ops::DerefMut for ProjectArena {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

impl ProjectArena {
    fn grow(&mut self, needed: usize) {
        if needed <= self.len() {
            return;
        }
        let mut grown = Self::from(vec![0; needed]);
        grown[..self.len()].copy_from_slice(self);
        *self = grown;
    }
}

#[cfg(test)]
#[path = "tests/project_arena_custody_tests.rs"]
mod project_arena_custody_tests;

const SIGNALS_CAP: usize = 16;
const MESSAGES_CAP: usize = 64;

impl<S, F: FarEnd, C> PlaneUnits<'_, S, F, C> {
    fn project(&self, rewrite: Option<&[u8]>, faultable: bool) -> Result<Projection, Stopped> {
        let a = &self.arrival;
        let unit = self.lock().unit;
        let body = self.lock().body.clone().unwrap_or_else(|| a.body.clone());
        let fields: Vec<Field> = a
            .fields
            .iter()
            .map(|(n, v)| Field {
                name: AbiStr::over(n),
                value: AbiStr::over(v),
            })
            .collect();
        let mut bufs = ProjectBufs {
            signals: vec![
                SignalEntry {
                    id: 0,
                    tag: 0,
                    value: busbar_contract::abi::hook::SignalValue { u64_: 0 }
                };
                SIGNALS_CAP
            ],
            messages: vec![
                MessageView {
                    role: AbiStr::over(b""),
                    text: AbiStr::over(b"")
                };
                MESSAGES_CAP
            ],
            arena: vec![0u8; self.driver.config.caps.arena.max(4096)].into(),
        };
        let mut input = ProjectIn {
            claim: a.claim,
            target: AbiStr::over(&a.target),
            fields: fields.as_ptr(),
            fields_len: fields.len(),
            body: blob(&body),
            signals_buf: bufs.signals.as_mut_ptr(),
            signals_cap: bufs.signals.len(),
            arena_buf: bufs.arena.as_mut_ptr(),
            arena_cap: bufs.arena.len(),
            rewrite: rewrite.map_or(Blob::ABSENT, blob),
            messages_buf: bufs.messages.as_mut_ptr(),
            messages_cap: bufs.messages.len(),
            unit,
            ..blank_in()
        };
        let mut o: ProjectOut = blank_out();
        let outcome = self
            .driver
            .calls
            .project(&mut input, &mut o, &mut |short, i| {
                bufs.signals.resize(
                    (short.signals_needed as usize).max(bufs.signals.len()),
                    bufs.signals[0],
                );
                bufs.messages.resize(
                    (short.messages_needed as usize).max(bufs.messages.len()),
                    bufs.messages[0],
                );
                bufs.arena.grow(
                    usize::try_from(short.arena_needed)
                        .unwrap_or(usize::MAX)
                        .max(bufs.arena.len()),
                );
                i.signals_buf = bufs.signals.as_mut_ptr();
                i.signals_cap = bufs.signals.len();
                i.messages_buf = bufs.messages.as_mut_ptr();
                i.messages_cap = bufs.messages.len();
                i.arena_buf = bufs.arena.as_mut_ptr();
                i.arena_cap = bufs.arena.len();
            });

        if busbar_contract::abi::plane::project_faults(outcome, faultable || rewrite.is_some()) {
            tracing::error!(
                "the plane could not apply a request rewrite it must not leave unapplied; \
                 rejecting rather than forwarding the body un-rewritten"
            );
            return Err(fault_veto());
        }

        if outcome == AbiOutcome::Fault {
            return Err(Stopped::Unparseable {
                marked: busbar_contract::abi::plane::project_fault_unparseable(outcome, &o),
            });
        }
        if outcome != AbiOutcome::Ready {
            return Err(Stopped::Unreadable);
        }

        let base = bufs.arena.as_ptr() as usize;
        let text = |s: AbiStr| -> String {
            if s.ptr.is_null() || s.len == 0 {
                return String::new();
            }
            let at = (s.ptr as usize).wrapping_sub(base);
            bufs.arena
                .get(at..at.saturating_add(s.len))
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .unwrap_or_default()
        };
        let opt = |s: AbiStr| (!s.ptr.is_null()).then(|| text(s));
        let span = |sp: Span| -> Option<Vec<u8>> {
            if sp.offset == SPAN_ABSENT || sp.len == 0 {
                return None;
            }
            let start = sp.offset as usize;
            bufs.arena
                .get(start..start + sp.len as usize)
                .map(<[u8]>::to_vec)
        };
        let v = o.view;
        let turns = bufs
            .messages
            .iter()
            .take(o.prompt.messages_len)
            .map(|m| (text(m.role), text(m.text)))
            .collect();
        Ok(Projection {
            pool: text(v.pool),
            dialect: text(v.ingress_dialect),
            message_count: usize::try_from(v.message_count).unwrap_or(usize::MAX),
            total_chars: usize::try_from(v.total_chars).unwrap_or(usize::MAX),
            max_tokens: (v.flags & REQUEST_HAS_MAX_TOKENS != 0).then_some(v.max_tokens),
            has_tools: v.flags & REQUEST_HAS_TOOLS != 0,
            stream: v.flags & REQUEST_STREAM != 0,
            system: opt(o.prompt.system),
            turns,
            end_user: opt(o.end_user),
            rewritten: span(o.rewritten),
            projected: span(o.body),
            rewrite_not_applicable: v.flags
                & busbar_contract::abi::plane::PROJECT_REWRITE_NOT_APPLICABLE
                != 0,
            session: (v.session.fmt == busbar_contract::abi::mechanism::call::BLOB_OCTETS
                && !v.session.ptr.is_null())
            .then(|| {
                let at = (v.session.ptr as usize).wrapping_sub(base);
                bufs.arena
                    .get(at..at.saturating_add(v.session.len))
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default()
            }),
        })
    }

    pub(crate) fn state_stage(&self, token: &Pass<Route>) {
        if self.arrival.claim == CLAIM_PROBE {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let d = self.driver;

        let (unit, principal, arrived_in) = {
            let st = self.lock();
            let Some(arrived_in) = st.decoded.as_ref().map(|x| x.dialect) else {
                return;
            };
            (
                st.unit,
                st.principal.as_ref().map(|p| p.as_str().to_string()),
                arrived_in,
            )
        };
        let dialect = arrived_in;
        let (scope, dialect) = match &d.hooks {
            Some(binder) => (
                self.far.scope(token).unwrap_or_else(|| {
                    let pool = self
                        .far
                        .candidates(token)
                        .map(|c| c.pool)
                        .unwrap_or_default();
                    super::RoutedScope {
                        container: pool.clone(),
                        pool,
                    }
                }),
                binder.dialect(dialect),
            ),
            None => (super::RoutedScope::default(), String::new()),
        };
        let stage = SessionStage::new(
            Arc::clone(&d.label),
            runtime,
            d.hooks.clone(),
            (scope, principal, dialect),
            arrived_in,
        );
        let _held = d.services.units().staged(unit, Arc::new(stage));
    }

    pub(crate) async fn request_stage(&self, token: &Pass<Route>) -> Result<(), Stopped>
    where
        S: super::DriverSteps,
    {
        let mut ran = Vec::new();
        let stage = self.run_request_stage(token, &mut ran).await;
        self.report_hooks(ran);
        stage
    }

    pub(crate) fn report_hooks(&self, hooks: Vec<HookApplied>) {
        let Some(journal) = self.driver.hook_journal.as_ref() else {
            return;
        };
        if hooks.is_empty() {
            return;
        }
        let unit = busbar_contract::UnitKey::new(self.lock().unit);
        journal.hooks_ran(&HooksRan { unit, hooks });
    }

    async fn run_request_stage(
        &self,
        token: &Pass<Route>,
        ran: &mut Vec<HookApplied>,
    ) -> Result<(), Stopped>
    where
        S: super::DriverSteps,
    {
        let Some(binder) = self.driver.hooks.as_ref() else {
            return Ok(());
        };

        if self.arrival.claim == CLAIM_PROBE {
            return Ok(());
        }

        if binder.order() == HookOrder::Gated {
            if self.lock().screened {
                return Ok(());
            }
            return self.gated_stage(&**binder).await;
        }
        let facts = self.far.candidates(token);
        let named = facts.is_some();
        let walk_pool = facts.as_ref().map(|c| c.pool.clone()).unwrap_or_default();
        let principal = self
            .lock()
            .principal
            .as_ref()
            .map(|p| p.as_str().to_string());
        let (dialect, request_id) = {
            let st = self.lock();
            (st.decoded.as_ref().map_or(0, |d| d.dialect), st.request_id)
        };
        let Some(hooks) = binder.bind(&Bind {
            pool: &walk_pool,
            principal: principal.as_deref(),
            dialect,
            request_id,
        }) else {
            return Ok(());
        };
        self.lock().hooked_pool.clone_from(&walk_pool);

        record_request_id(hooks.request_id);

        let faultable = !hooks.rewrites.is_empty();

        let first = self.project(None, faultable).map_err(|e| match e {
            Stopped::Unparseable { marked: false } => Stopped::Unreadable,
            other => other,
        });
        let mut view = match first {
            Ok(view) => view,

            Err(Stopped::Unparseable { .. }) => {
                Projection::empty(walk_pool.clone(), hooks.dialect.clone())
            }

            Err(Stopped::Unreadable)
                if hooks.rewrites.is_empty()
                    && hooks.gates.is_empty()
                    && hooks.policy.is_none() =>
            {
                Projection::empty(walk_pool.clone(), hooks.dialect.clone())
            }
            Err(stopped) => {
                let zeroed = Projection::empty(String::new(), hooks.dialect.clone());
                self.lock().hooked = Some((hooks, zeroed));
                return Err(stopped);
            }
        };
        let pool = if walk_pool.is_empty() {
            view.pool.clone()
        } else {
            walk_pool
        };
        self.lock().hooked_pool.clone_from(&pool);

        for (timeout, hook) in &hooks.rewrites {
            let req = view.request(hooks.request_id, &pool, true, None);
            if req.prompt.is_some() {
                (hooks.reads)(hook.name(), None, &view.dialect, false);
            }
            let outcome = hook.transform(&req, *timeout).await;
            drop(req);
            ran.push(rewrite_applied(hook.name(), &outcome));
            match outcome {
                TransformOutcome::Rewrite(rw) => {
                    let bytes = rewrite_bytes(&rw);
                    match self.project(Some(&bytes), true) {
                        Ok(next) if next.rewritten.is_some() || rw.messages.is_empty() => {
                            if let Some(body) = &next.rewritten {
                                self.lock().body = Some(bytes::Bytes::copy_from_slice(body));
                            }
                            view = next;
                        }

                        Ok(next) if next.rewrite_not_applicable => {
                            gated::rewrite_not_applicable(hook.name(), ran);
                            tracing::warn!(
                                hook = hook.name(),
                                pool = %pool,
                                "rewrite not applicable to this request; forwarded unmodified"
                            );
                        }
                        Err(fault @ Stopped::Veto(_)) => {
                            self.lock().hooked = Some((hooks, view));
                            return Err(fault);
                        }

                        Ok(_) | Err(_) => {
                            let (status, message) = gated::refused_rewrite(&**hook, &pool, ran);
                            self.lock().hooked = Some((hooks, view));
                            return Err(veto(status, message));
                        }
                    }
                }
                TransformOutcome::Reject { status, message } => {
                    self.lock().hooked = Some((hooks, view));

                    let (status, message) = gated::rewrite_refusal(status, &message);
                    return Err(veto(status, message));
                }
                TransformOutcome::Abstain => {}
                TransformOutcome::Failed { message } => {
                    tracing::warn!(
                        hook = hook.name(),
                        pool = %pool,
                        error = %message,
                        "rewrite hook could not answer; proceeding with the original body"
                    );
                }
            }
        }

        fire_request_taps(&hooks, &view, &pool);

        let all: Vec<CandidateFacts> = facts.map(|c| c.members).unwrap_or_default();
        let mut keep: HashSet<usize> = all.iter().map(|c| c.idx).collect();
        let mut constraint = Constraint::default();
        let decided = self
            .decide_route(
                &hooks,
                &view,
                (&pool, named),
                &all,
                (&mut keep, &mut constraint),
                ran,
            )
            .await;
        if let Err(stopped) = decided {
            self.lock().hooked = Some((hooks, view));
            return Err(stopped);
        }

        if !hooks.taps.candidate.is_empty() {
            fire_stage_taps_where(
                &hooks.taps.candidate,
                &view.shape(hooks.request_id, &pool),
                stage_at("candidate", None, None, Some(keep.len()), None, None, None),
                SignalBag::default(),
                &*hooks.groups,
            );
        }
        if keep.len() != all.len() {
            let mut kept: Vec<usize> = keep.iter().copied().collect();
            kept.sort_unstable();
            constraint.keep = Some(kept);
        }
        self.lock().route_policy = constraint.policy.clone();
        if constraint != Constraint::default() {
            self.far.constrain(token, constraint);
        }
        self.lock().hooked = Some((hooks, view));
        Ok(())
    }

    async fn decide_route(
        &self,
        hooks: &UnitHooks,
        view: &Projection,
        (pool, named): (&str, bool),
        all: &[CandidateFacts],
        (keep, constraint): (&mut HashSet<usize>, &mut Constraint),
        ran: &mut Vec<HookApplied>,
    ) -> Result<(), Stopped> {
        let mut gate_order: Option<(Vec<usize>, std::sync::Arc<str>)> = None;
        if !hooks.gates.is_empty() {
            let shown = candidates_of(all, hooks, keep);
            let asked = Asked {
                view,
                hooks,
                pool,
                candidates: &shown,
                named,
            };
            let judged =
                futures::future::join_all(hooks.gates.iter().map(|(_, gate)| asked.decide(gate)))
                    .await;

            let outcomes: Vec<Decided> = judged
                .into_iter()
                .map(|(decided, hook)| {
                    ran.extend(hook);
                    decided
                })
                .collect();

            for outcome in &outcomes {
                match outcome {
                    Decided::RejectRequest {
                        status,
                        message,
                        name,
                    } => {
                        metrics::counter!(
                            ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => name.to_string(),
                            "pool" => pool.to_string(),
                            "status" => status.to_string(),
                        )
                        .increment(1);
                        crate::diag_debug!(
                            DECISION_GATE_REJECTED,
                            policy = &name[..],
                            pool = pool,
                            status,
                            message = %message,
                            "decision gate rejected the request"
                        );
                        return Err(veto(*status, message.clone()));
                    }
                    Decided::Reject => {
                        return Err(veto(
                            REQUIRED_HOOK_UNAVAILABLE_STATUS,
                            REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                        ));
                    }
                    _ => {}
                }
            }

            for outcome in &outcomes {
                if let Decided::Restrict {
                    tags_any,
                    name,
                    on_empty,
                } = outcome
                {
                    constraint.restricts.push(Restrict {
                        tags_any: tags_any.clone(),
                        on_empty: on_empty.clone(),
                        name: Arc::clone(name),
                    });
                    if narrow(keep, all, tags_any) {
                        metrics::counter!(
                            ROUTE_POLICY_SELECTIONS_TOTAL,
                            "policy" => name.to_string(),
                            "pool" => pool.to_string(),
                        )
                        .increment(1);
                        constraint.policy = Some(Arc::clone(name));
                    } else if matches!(on_empty, PolicyOnError::Weighted) {
                        crate::diag_debug!(
                            DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
                            policy = &name[..],
                            pool = pool,
                            "decision gate restrict left no eligible lane; on_empty: weighted \
                             escape — this gate's restriction is skipped"
                        );
                    } else {
                        metrics::counter!(
                            ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => name.to_string(),
                            "pool" => pool.to_string(),
                            "status" => "503".to_string(),
                        )
                        .increment(1);
                        crate::diag_debug!(
                            DECISION_GATE_RESTRICT_REJECT,
                            policy = &name[..],
                            pool = pool,
                            "decision gate restrict left no eligible lane (on_empty: reject)"
                        );
                        return Err(veto(
                            503,
                            "No upstream satisfies a required gate's restriction. Please retry \
                             shortly.",
                        ));
                    }
                }
            }

            for outcome in outcomes {
                if let Decided::Order { order, name } = outcome {
                    let filtered: Vec<usize> =
                        order.into_iter().filter(|i| keep.contains(i)).collect();
                    gate_order = (!filtered.is_empty()).then_some((filtered, name));
                }
            }
            if let Some((_, name)) = &gate_order {
                metrics::counter!(
                    ROUTE_POLICY_SELECTIONS_TOTAL,
                    "policy" => name.to_string(),
                    "pool" => pool.to_string(),
                )
                .increment(1);
            }
        }
        if let Some((order, name)) = gate_order {
            constraint.order = Some(order);
            constraint.policy = Some(name);
            return Ok(());
        }
        let Some(policy) = &hooks.policy else {
            return Ok(());
        };
        let shown = candidates_of(all, hooks, keep);
        let asked = Asked {
            view,
            hooks,
            pool,
            candidates: &shown,
            named,
        };
        let (decided, hook) = Box::pin(asked.decide(policy)).await;
        ran.extend(hook);
        match decided {
            Decided::Order { order, name } => {
                metrics::counter!(
                    ROUTE_POLICY_SELECTIONS_TOTAL,
                    "policy" => name.to_string(),
                    "pool" => pool.to_string(),
                )
                .increment(1);
                constraint.order = Some(order);
                constraint.policy = Some(name);
                Ok(())
            }
            Decided::Weighted => Ok(()),
            Decided::Reject => Err(veto(
                503,
                "The routing policy could not select an upstream. Please retry shortly.",
            )),
            Decided::RejectRequest {
                status,
                message,
                name,
            } => {
                metrics::counter!(
                    ROUTE_POLICY_REJECTIONS_TOTAL,
                    "policy" => name.to_string(),
                    "pool" => pool.to_string(),
                    "status" => status.to_string(),
                )
                .increment(1);
                crate::diag_debug!(
                    ROUTING_POLICY_REJECTED,
                    policy = &name[..],
                    pool = pool,
                    status,
                    message = %message,
                    "routing policy rejected the request"
                );
                Err(veto(status, message))
            }
            Decided::Restrict {
                tags_any,
                name,
                on_empty,
            } => {
                constraint.restricts.push(Restrict {
                    tags_any: tags_any.clone(),
                    on_empty: on_empty.clone(),
                    name: Arc::clone(&name),
                });
                if narrow(keep, all, &tags_any) {
                    metrics::counter!(
                        ROUTE_POLICY_SELECTIONS_TOTAL,
                        "policy" => name.to_string(),
                        "pool" => pool.to_string(),
                    )
                    .increment(1);
                    constraint.policy = Some(name);
                    Ok(())
                } else if matches!(on_empty, PolicyOnError::Weighted) {
                    crate::diag_debug!(
                        ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
                        policy = &name[..],
                        pool = pool,
                        "routing policy restrict left no eligible lane; on_empty: weighted \
                         escape to full-pool SWRR"
                    );
                    Ok(())
                } else {
                    metrics::counter!(
                        ROUTE_POLICY_REJECTIONS_TOTAL,
                        "policy" => name.to_string(),
                        "pool" => pool.to_string(),
                        "status" => "503".to_string(),
                    )
                    .increment(1);
                    crate::diag_debug!(
                        ROUTING_POLICY_RESTRICT_REJECT,
                        policy = &name[..],
                        pool = pool,
                        "routing policy restrict left no eligible lane (on_empty: reject)"
                    );
                    Err(veto(
                        503,
                        "No upstream satisfies the routing policy's restriction. Please retry \
                         shortly.",
                    ))
                }
            }
        }
    }

    pub(crate) fn routing_tap(
        &self,
        attempt_no: u32,
        member: &str,
        remaining: Option<usize>,
        failed: Option<&'static str>,
    ) {
        let st = self.lock();
        let Some((hooks, view)) = st.hooked.as_ref() else {
            return;
        };
        if hooks.taps.routing.is_empty() {
            return;
        }
        fire_stage_taps_where(
            &hooks.taps.routing,
            &view.shape(hooks.request_id, &st.hooked_pool),
            stage_at(
                "routing",
                Some(member),
                Some(attempt_no),
                remaining,
                failed,
                None,
                None,
            ),
            SignalBag::default(),
            &*hooks.groups,
        );
    }

    pub(crate) fn response_tap(&self, gate: bool, status: u32) {
        let mut st = self.lock();
        if st.responded {
            return;
        }
        let Some((hooks, view)) = st.hooked.as_ref() else {
            return;
        };
        if !hooks.taps.response.is_empty() {
            let status = u16::try_from(status).unwrap_or(u16::MAX);
            let outcome = if gate {
                "rejected_by_gate"
            } else if (200..300).contains(&status) {
                "ok"
            } else {
                "failed"
            };
            fire_stage_taps_where(
                &hooks.taps.response,
                &view.shape(hooks.request_id, &st.hooked_pool),
                stage_at(
                    "response",
                    None,
                    None,
                    None,
                    None,
                    Some(outcome),
                    Some(status),
                ),
                SignalBag::default(),
                &*hooks.groups,
            );
        }
        st.responded = true;
    }
}

fn fire_request_taps(hooks: &UnitHooks, view: &Projection, pool: &str) {
    let taps = &hooks.taps.request;
    if taps.is_empty() {
        return;
    }
    let firing: Vec<&TapEntry> = taps.iter().filter(|t| (hooks.groups)(&t.3)).collect();
    let frame = |with_prompt: bool| {
        let req = view.request(hooks.request_id, pool, with_prompt, None);
        busbar_contract::abi::host::hook::NotifyFrame::build(&req, None, with_prompt)
    };
    let shape_only = firing.iter().any(|t| !t.1).then(|| frame(false));
    let with_prompt = firing.iter().any(|t| t.1).then(|| frame(true));
    for (timeout, send_prompt, hook, _) in firing {
        let tap = if *send_prompt {
            with_prompt.clone()
        } else {
            shape_only.clone()
        };
        let Some(tap) = tap else { continue };
        if *send_prompt {
            (hooks.reads)(hook.name(), None, &view.dialect, false);
        }
        let policy = Arc::clone(hook);
        let budget = *timeout;
        spawn_bounded_tap(async move { policy.notify(tap, budget).await });
    }
}

pub const CONTENT_ROLE: &str = "content";

pub const STAGE_GONE: &str = "the unit's hook stage is no longer running";

pub struct SessionStage {
    instance: Arc<str>,
    runtime: tokio::runtime::Handle,
    binder: Option<Arc<dyn HookBinder>>,

    pool: String,

    container: String,
    principal: Option<String>,
    dialect: String,

    arrived_in: u32,
    bound: std::sync::OnceLock<Option<UnitHooks>>,
}

impl std::fmt::Debug for SessionStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStage")
            .field("instance", &self.instance)
            .field("pool", &self.pool)
            .finish_non_exhaustive()
    }
}

fn gated_unit(g: GatedHooks, dialect: String) -> UnitHooks {
    UnitHooks {
        request_id: g.request_id,
        rewrites: g.rewrites,
        gates: g.gates,
        policy: None,
        taps: StageTaps::default(),
        key: g.key.map(|k| CallerKey {
            id: k.id.clone(),
            name: k.name.clone(),
        }),
        rate_headroom: None,
        budget: Vec::new(),
        requested: crate::hooks::RequestedSignals::default(),
        groups: Arc::new(|_: &[String]| true),
        reads: g.reads,
        dialect,
    }
}

struct OwedStage(Option<crate::host_units::StageDone>);

impl OwedStage {
    fn answer(mut self, a: crate::host_units::StageAnswer) {
        if let Some(done) = self.0.take() {
            done(a);
        }
    }
}

impl Drop for OwedStage {
    fn drop(&mut self) {
        if let Some(done) = self.0.take() {
            done(crate::host_units::StageAnswer::Failed(STAGE_GONE));
        }
    }
}

impl SessionStage {
    #[must_use]
    pub fn new(
        instance: Arc<str>,
        runtime: tokio::runtime::Handle,
        binder: Option<Arc<dyn HookBinder>>,
        (scope, principal, dialect): (super::RoutedScope, Option<String>, String),
        arrived_in: u32,
    ) -> Self {
        let gated = binder
            .as_ref()
            .is_some_and(|b| b.order() == HookOrder::Gated);
        Self {
            instance,
            runtime,
            binder,
            pool: if gated {
                scope.container.clone()
            } else {
                scope.pool
            },
            container: scope.container,
            principal,
            dialect,
            arrived_in,
            bound: std::sync::OnceLock::new(),
        }
    }

    fn hooks(&self) -> Option<&UnitHooks> {
        self.bound
            .get_or_init(|| {
                let b = self.binder.as_ref()?;
                if b.order() == HookOrder::Gated {
                    return b
                        .bind_gated(&self.container, self.principal.as_deref())
                        .map(|g| gated_unit(g, self.dialect.clone()));
                }
                b.bind(&Bind {
                    pool: &self.pool,
                    principal: self.principal.as_deref(),
                    dialect: self.arrived_in,
                    request_id: None,
                })
            })
            .as_ref()
    }

    fn view(&self, system: Option<String>, turns: Vec<(String, String)>) -> Projection {
        let total_chars = turns.iter().map(|(_, t)| t.chars().count()).sum::<usize>()
            + system.as_deref().map_or(0, |s| s.chars().count());
        let mut view = Projection::empty(self.pool.clone(), self.dialect.clone());
        view.message_count = turns.len();
        view.total_chars = total_chars;
        view.system = system;
        view.turns = turns;
        view
    }

    fn spawn<Fut>(
        self: Arc<Self>,
        done: crate::host_units::StageDone,
        job: impl FnOnce(Arc<Self>) -> Fut + Send + 'static,
    ) where
        Fut: std::future::Future<Output = crate::host_units::StageAnswer> + Send + 'static,
    {
        let owed = OwedStage(Some(done));
        let runtime = self.runtime.clone();
        drop(runtime.spawn(async move {
            let answer = job(self).await;
            owed.answer(answer);
        }));
    }

    async fn gate(&self, view: &Projection) -> crate::host_units::StageAnswer {
        use crate::host_units::StageAnswer;
        let Some(hooks) = self.hooks() else {
            return StageAnswer::Pass;
        };
        let identity = CallerIdentity {
            key_id: hooks.key.as_ref().map(|k| k.id.clone()),
            key_name: hooks.key.as_ref().map(|k| k.name.clone()),
            user: None,
        };
        for (
            _,
            ResolvedPolicy::Policy {
                policy,
                on_error,
                timeout,
                send_prompt,
                send_user,
                ..
            },
        ) in &hooks.gates
        {
            let req = view.request(
                hooks.request_id,
                &self.pool,
                *send_prompt,
                send_user.then(|| identity.clone()),
            );
            if req.prompt.is_some() {
                (hooks.reads)(
                    policy.name(),
                    self.principal.as_deref(),
                    &view.dialect,
                    req.identity.is_some(),
                );
            }
            let ctx = RoutingContext {
                pool: &self.pool,
                budget_remaining: None,
                budget: &[],
            };
            let decided =
                tokio::time::timeout(*timeout, policy.decide(&req, &[], &ctx, *timeout)).await;
            match decided {
                Ok(Ok(RoutingDecision::Reject { status, message })) => {
                    return StageAnswer::Stop {
                        status: clamp_reject_status(status),
                        words: sanitize_reject_message(&message),
                    };
                }

                Ok(Ok(_)) => {}
                Ok(Err(_)) | Err(_) => {
                    tracing::warn!(
                        hook = policy.name(),
                        pool = %self.pool,
                        "in-session gate could not answer; applying its on_error"
                    );

                    if failed_call_refuses(on_error) {
                        return StageAnswer::Stop {
                            status: REQUIRED_HOOK_UNAVAILABLE_STATUS,
                            words: REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_string(),
                        };
                    }
                }
            }
        }
        StageAnswer::Pass
    }

    async fn rewrite(&self, from: u32, view: &Projection) -> crate::host_units::StageAnswer {
        use crate::host_units::StageAnswer;
        let Some(hooks) = self.hooks() else {
            return StageAnswer::Pass;
        };
        let most = busbar_contract::abi::host::service::HOOK_FROM_MAX as usize;
        for (i, (timeout, hook)) in hooks
            .rewrites
            .iter()
            .enumerate()
            .take(most)
            .skip(from as usize)
        {
            let req = view.request(hooks.request_id, &self.pool, true, None);
            if req.prompt.is_some() {
                (hooks.reads)(hook.name(), None, &view.dialect, false);
            }
            match hook.transform(&req, *timeout).await {
                TransformOutcome::Rewrite(rw) => {
                    return StageAnswer::Rewrote {
                        index: u32::try_from(i).unwrap_or(u32::MAX),
                        rewrite: rewrite_bytes(&rw),
                    };
                }
                TransformOutcome::Reject { status, message } => {
                    let (status, words) = gated::rewrite_refusal(status, &message);
                    return StageAnswer::Stop { status, words };
                }
                TransformOutcome::Abstain => {}
                TransformOutcome::Failed { message } => {
                    tracing::warn!(
                        hook = hook.name(),
                        pool = %self.pool,
                        error = %message,
                        "in-session rewrite hook could not answer; proceeding unchanged"
                    );
                }
            }
        }
        StageAnswer::Pass
    }
}

impl crate::host_units::UnitHookStage for SessionStage {
    fn instance(&self) -> &str {
        &self.instance
    }

    fn call(
        self: Arc<Self>,
        ask: busbar_contract::services::HookAsk,
        done: crate::host_units::StageDone,
    ) {
        self.spawn(done, move |stage| async move {
            let view = stage.view(ask.system, ask.messages);
            if ask.stage == busbar_contract::abi::host::service::HOOK_REWRITE {
                stage.rewrite(ask.from, &view).await
            } else {
                stage.gate(&view).await
            }
        });
    }

    fn scan(self: Arc<Self>, content: Vec<u8>, done: crate::host_units::StageDone) {
        self.spawn(done, move |stage| async move {
            let text = String::from_utf8_lossy(&content).into_owned();
            let view = stage.view(None, vec![(CONTENT_ROLE.to_string(), text)]);
            stage.gate(&view).await
        });
    }
}
