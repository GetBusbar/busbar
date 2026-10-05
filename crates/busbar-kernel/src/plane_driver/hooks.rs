// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK STAGE ON THE DRIVER (`BUSBAR-1.6.0.md` Part 3, section 12, "Hooks"; ARCHITECT K5,
//! 2026-10-02): the request-stage hooks run at the head of the route leg, after admission, over the
//! plane's own projection of the unit's request (`project`, pure, ticketless), in the order the
//! previous release ran them for an LLM unit:
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

use super::{blob, FarEnd, PlaneUnits};
use crate::config::PolicyOnError;
use crate::diagnostics::{
    DECISION_GATE_REJECTED, DECISION_GATE_RESTRICT_REJECT, DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
    ON_ERROR_FALLBACK_ANSWERED, ON_ERROR_FALLBACK_DEADLINE_EXCEEDED, ON_ERROR_FALLBACK_HOOK_FAILED,
    ROUTING_POLICY_DEADLINE_EXCEEDED, ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK,
    ROUTING_POLICY_REJECTED, ROUTING_POLICY_RESTRICT_REJECT,
    ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
};
use crate::hooks::wire::{clamp_reject_status, sanitize_reject_message, HookStageProjection};
use crate::hooks::{
    content_capped, failed_call_refuses, FallbackHook, RequestedSignals, ResolvedPolicy, TapEntry,
    REQUIRED_HOOK_UNAVAILABLE_MESSAGE, REQUIRED_HOOK_UNAVAILABLE_STATUS,
};
use crate::metrics::{ROUTE_POLICY_REJECTIONS_TOTAL, ROUTE_POLICY_SELECTIONS_TOTAL};
use crate::proxy::proxy_vocab::{fire_stage_taps_where, spawn_bounded_tap, StageShape};

// ── what the composition root hands the driver ──────────────────────────────────────────────────

/// WHICH HOOKS BIND TO A UNIT: the composition root's hook configuration, asked once per unit at
/// the head of its route leg.
pub trait HookBinder: Send + Sync {
    /// The hooks a unit routed over `bind.pool` binds, for its verified caller; `None` = none (the
    /// unit pays nothing more).
    fn bind(&self, bind: &Bind<'_>) -> Option<UnitHooks>;

    /// The order this plane's units run their request-stage hooks in (the plane's tail statement,
    /// `abi::plane::TAIL_HOOKS_GATED`); [`HookOrder::Routed`] unless the binder says otherwise.
    fn order(&self) -> HookOrder {
        HookOrder::Routed
    }

    /// GATE-FIRST: the hooks the deployment attached to the entry `container` the plane's
    /// `project` names, for the verified `principal`; `None` = none (the unit pays nothing more).
    fn bind_gated(&self, container: &str, principal: Option<&str>) -> Option<GatedHooks> {
        let _ = (container, principal);
        None
    }

    /// A unit refused at authentication: the `response` stage taps see the previous release's
    /// synthetic `rejected_by_auth` completion, under the status the caller was answered with, in
    /// the zeroed shape (no body was read), labelled with the dialect (the index into the plane's
    /// dialects) the refusal was written in.
    fn denied(&self, dialect: u32, status: u16) {
        let _ = (dialect, status);
    }
}

/// What a binder is told of one unit.
#[derive(Debug, Clone, Copy)]
pub struct Bind<'a> {
    /// The pool the walk routes the unit over (empty when the walk names none).
    pub pool: &'a str,
    /// The principal the kernel verified, when there is one.
    pub principal: Option<&'a str>,
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

/// A predicate over a tap's `groups:` scope: does it admit this unit's caller.
pub type GroupScope = Arc<dyn Fn(&[String]) -> bool + Send + Sync>;

/// A rewrite chain: each hook with its deadline, in order.
pub type RewriteChain = Vec<(Duration, Arc<dyn RoutingPolicy>)>;

/// The access amendment a hook handed the prompt leaves: `(hook, principal, dialect, identity)`.
pub type HookRead = Arc<dyn Fn(&str, Option<&str>, &str, bool) + Send + Sync>;

/// THE HOOKS ONE UNIT BINDS, as the binder resolved them.
pub struct UnitHooks {
    /// The unit's correlation id: every hook payload and tap of the unit carries it.
    pub request_id: u64,
    /// The rewrite chain, the global gates then the pool's.
    pub rewrites: RewriteChain,
    /// The decision gates, global then the pool's, stable-sorted by priority.
    pub gates: Vec<(u16, ResolvedPolicy)>,
    /// The pool's base route policy (`None` = weighted).
    pub policy: Option<ResolvedPolicy>,
    /// The stage taps.
    pub taps: StageTaps,
    /// The caller's governance key, for a hook granted `user`.
    pub key: Option<CallerKey>,
    /// The caller's rate headroom (a candidate's `rate_headroom`).
    pub rate_headroom: Option<f64>,
    /// The caller's budget chain (the decision context's `budget`).
    pub budget: Vec<BudgetBucketState>,
    /// The catalog signals some hook declared.
    pub requested: RequestedSignals,
    /// The tap selection over a tap's `groups:` scope.
    pub groups: GroupScope,
    /// The access amendment of a hook handed the prompt.
    pub reads: HookRead,
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
    /// No hook of any stage is bound.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rewrites.is_empty()
            && self.gates.is_empty()
            && self.policy.is_none()
            && self.taps.is_empty()
    }
}

/// THE BINDER OVER A STATIC HOOK CONFIGURATION: the global hooks and each pool's, resolved once
/// for a generation (the composition root builds it from the deployment's `hooks:`), with the
/// caller's key, headroom and budget asked of `caller` per unit.
pub struct BoundHooks {
    /// The global rewrite chain.
    pub rewrites: RewriteChain,
    /// The global decision gates, sorted by priority.
    pub gates: Vec<(u16, ResolvedPolicy)>,
    /// Each pool's own rewrite chain.
    pub pool_rewrites: std::collections::HashMap<String, RewriteChain>,
    /// Each pool's own decision gates, in configuration order.
    pub pool_gates: std::collections::HashMap<String, Vec<(u16, ResolvedPolicy)>>,
    /// Each pool's base route policy.
    pub pool_policies: std::collections::HashMap<String, ResolvedPolicy>,
    /// The stage taps.
    pub taps: StageTaps,
    /// The catalog signals some hook declared.
    pub requested: RequestedSignals,
    /// The unit's correlation id, from the process's one counter.
    pub next_request_id: Arc<dyn Fn() -> u64 + Send + Sync>,
    /// What the hooks may know of a verified caller.
    pub caller: Arc<dyn CallerFacts>,
    /// The plane's dialects, in its tail's order (the label of an authentication refusal's tap).
    pub dialects: Vec<String>,
}

/// WHAT THE HOOKS MAY KNOW OF A VERIFIED CALLER, asked per unit: its governance key, its group
/// binding (the tap selection), its rate headroom and its budget chain.
pub trait CallerFacts: Send + Sync {
    /// The caller's governance key.
    fn key(&self, principal: &str) -> Option<CallerKey>;
    /// Whether a hook scoped to `groups` (empty = every caller) fires for the caller.
    fn in_groups(&self, principal: Option<&str>, groups: &[String]) -> bool;
    /// The caller's rate headroom over `pool`.
    fn rate_headroom(&self, principal: &str, pool: &str) -> Option<f64>;
    /// The caller's budget chain.
    fn budget(&self, principal: &str) -> Vec<BudgetBucketState>;
    /// Leave the access amendment of a hook handed the prompt.
    fn hook_read(&self, hook: &str, principal: Option<&str>, dialect: &str, identity: bool);
    /// Fire the `response` taps of a unit refused at authentication.
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

/// The hooks one unit binds, before the caller's facts: `None` when no hook of any stage is bound.
struct Parts {
    rewrites: RewriteChain,
    gates: Vec<(u16, ResolvedPolicy)>,
    policy: Option<ResolvedPolicy>,
    taps: StageTaps,
    requested: RequestedSignals,
}

/// One scope's rewrite chain and gates.
type Scope<'a> = (
    &'a [(Duration, Arc<dyn RoutingPolicy>)],
    &'a [(u16, ResolvedPolicy)],
);

impl Parts {
    /// The global rewrites then the pool's; the global gates then the pool's, stable-sorted by
    /// priority (ties keep the globals first, then configuration order).
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

    /// The unit's hooks, with what `caller` knows of the verified principal.
    fn bind(self, bind: &Bind<'_>, caller: &Arc<dyn CallerFacts>, request_id: u64) -> UnitHooks {
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
        }
    }
}

/// The `response` taps of a unit refused at authentication, labelled with the plane's dialect.
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
        Some(parts.bind(bind, &self.caller, (self.next_request_id)()))
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

/// THE BINDER OVER THE DEPLOYMENT'S OWN HOOK CONFIGURATION: the engine host the composition root
/// mints over the generation (its global and per-pool rewrites, gates, policies and taps, its
/// declared signals and its one request-id counter), with what `caller` knows of a verified
/// principal.
pub struct HostHooks {
    /// The generation's engine host.
    pub host: Arc<dyn crate::plane_host::EngineHost>,
    /// What the hooks may know of a verified caller.
    pub caller: Arc<dyn CallerFacts>,
    /// The plane's dialects, in its tail's order.
    pub dialects: Vec<String>,
}

impl HookBinder for HostHooks {
    fn bind(&self, bind: &Bind<'_>) -> Option<UnitHooks> {
        let h = &*self.host;
        let parts = Parts::of(
            (h.rewrite_hooks(), h.global_gates()),
            (h.pool_rewrites(bind.pool), h.pool_gates(bind.pool)),
            h.pool_policy(bind.pool).cloned(),
            StageTaps {
                request: h.tap_hooks().to_vec(),
                candidate: h.tap_hooks_candidate().to_vec(),
                routing: h.tap_hooks_routing().to_vec(),
                response: h.tap_hooks_response().to_vec(),
            },
            *h.requested_signals(),
        )?;
        Some(parts.bind(bind, &self.caller, h.next_request_id()))
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

// ── what the walk tells the hooks ───────────────────────────────────────────────────────────────

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
    pub name: &'static str,
}

/// THE CONSTRAINT THE HOOKS PUT ON THE WALK.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Constraint {
    /// The members of the routed pool the walk may pick from (`None` = every one).
    pub keep: Option<Vec<usize>>,
    /// The order the walk tries them in (`None` = the walk's own pick).
    pub order: Option<Vec<usize>>,
    /// The policy that ordered or restricted, when one did.
    pub policy: Option<&'static str>,
    /// Every restrict the hooks decided, re-applied to a fallback pool's members.
    pub restricts: Vec<Restrict>,
}

impl Constraint {
    /// The members of `members` (index, tags) a fallback pool keeps under these restricts, or the
    /// fail-closed refusal of a required restrict nothing satisfies (the previous release's
    /// `enforce_restricts`).
    ///
    /// # Errors
    ///
    /// The deciding restrict, when it is required and no member carries its tags.
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

// ── the plane's view of the request ─────────────────────────────────────────────────────────────

/// THE PLANE'S PROJECTION of a unit's request, owned: what every hook payload of the unit is
/// built from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
}

impl Projection {
    /// The prompt view, under the content ceiling.
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

    /// The request a hook is handed: the shape always; the prompt and the identity as granted.
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

    /// The stage taps' shape.
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
}

/// A hook's refusal, clamped and sanitised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Veto {
    /// The status the caller is answered with.
    pub status: u32,
    /// The words.
    pub text: String,
}

#[path = "gated.rs"]
pub mod gated;
pub use gated::{GatedHooks, GatedScan, GenerationHost, HookOrder, HostGatedHooks, PrincipalKeys};

fn veto(status: u16, text: impl Into<String>) -> Stopped {
    Stopped::Veto(Veto {
        status: u32::from(status),
        text: text.into(),
    })
}

/// One stage object.
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

// ── the decision engine (the previous release's, dialect-blind) ─────────────────────────────────

/// What one decision came to.
#[derive(Debug, Clone, PartialEq)]
enum Decided {
    /// This ranked order.
    Order {
        order: Vec<usize>,
        name: &'static str,
    },
    /// No opinion: the walk's own pick.
    Weighted,
    /// A load-bearing hook could not answer.
    Reject,
    /// The hook refused the request.
    RejectRequest {
        status: u16,
        message: String,
        name: &'static str,
    },
    /// Only members carrying one of these tags.
    Restrict {
        tags_any: Vec<String>,
        name: &'static str,
        on_empty: PolicyOnError,
    },
}

/// The warn-once latch of a failing hook, keyed `hook@pool`: the first failure warns, the rest log
/// at debug until a success clears it.
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

/// Map a decision: an order normalised against the candidates (an empty one abstains), a reject
/// clamped and sanitised (for every producer), a restrict carried with its `on_empty`.
fn map_decision(
    decision: RoutingDecision,
    name: &'static str,
    candidates: &[Candidate<'_>],
    on_empty: &PolicyOnError,
) -> Decided {
    match decision {
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

/// A failed hook's terminal: `first` is the configured member order, a load-bearing hook refuses,
/// anything else the walk's own pick.
fn coerce_on_error(
    on_error: &PolicyOnError,
    candidates: &[Candidate<'_>],
    name: &'static str,
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

/// What one decision is asked over.
struct Asked<'a> {
    view: &'a Projection,
    hooks: &'a UnitHooks,
    pool: &'a str,
    candidates: &'a [Candidate<'a>],
    principal: Option<&'a str>,
    /// The walk named its candidates (an empty pool, then, has nothing to rank).
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
        (self.hooks.reads)(hook, self.principal, &self.view.dialect, identity);
    }

    /// One decision of `resolved`, under its deadline, its failure walked down its on-error chain.
    async fn decide(&self, resolved: &ResolvedPolicy) -> Decided {
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
            // Nothing to rank: the walk's own exhaustion answers.
            return Decided::Weighted;
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
        match tokio::time::timeout(
            *timeout,
            policy.decide(&req, self.candidates, &ctx, *timeout),
        )
        .await
        {
            Ok(Ok(decision)) => {
                fault_clear(&key);
                map_decision(decision, policy.name(), self.candidates, on_empty)
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
                self.on_error_chain(on_error_chain, on_error, &req, &ctx, policy.name())
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
                self.on_error_chain(on_error_chain, on_error, &req, &ctx, policy.name())
                    .await
            }
        }
    }

    /// A failed hook's fallback chain: each link projected per its own grants, the first that
    /// answers decides, every link failing lands on the terminal.
    async fn on_error_chain(
        &self,
        chain: &[FallbackHook],
        terminal: &PolicyOnError,
        req: &RoutingRequest<'_>,
        ctx: &RoutingContext<'_>,
        failed: &'static str,
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
                Ok(Ok(decision)) => {
                    fault_clear(&key);
                    crate::diag_debug!(
                        ON_ERROR_FALLBACK_ANSWERED,
                        policy = failed,
                        fallback = fb.policy.name(),
                        pool = self.pool,
                        "on_error fallback hook answered for the failed gate"
                    );
                    return map_decision(decision, fb.policy.name(), self.candidates, &fb.on_empty);
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

/// The candidates the hooks are shown, from what the walk reports.
fn candidates_of<'a>(
    facts: &'a [CandidateFacts],
    hooks: &UnitHooks,
    keep: &HashSet<usize>,
) -> Vec<Candidate<'a>> {
    facts
        .iter()
        .filter(|c| keep.contains(&c.idx))
        .map(|c| {
            let mut signals = SignalBag::new();
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

/// Narrow `keep` by one restrict: the members carrying one of its tags, or the decision `on_empty`
/// makes when none does (`Ok(false)`: a weighted escape, `keep` unchanged).
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

// ── the stage, on the unit ──────────────────────────────────────────────────────────────────────

/// The buffers one `project` crossing lends.
struct ProjectBufs {
    signals: Vec<SignalEntry>,
    messages: Vec<MessageView>,
    arena: Vec<u8>,
}

const SIGNALS_CAP: usize = 16;
const MESSAGES_CAP: usize = 64;

impl<S, F: FarEnd, C> PlaneUnits<'_, S, F, C> {
    /// `project`, ticketless, with the one re-call a short answer earns; `rewrite` is a
    /// request-stage hook's rewrite for the plane to apply first.
    fn project(&self, rewrite: Option<&[u8]>) -> Result<Projection, Stopped> {
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
            arena: vec![0u8; self.driver.config.caps.arena.max(4096)],
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
                bufs.arena.resize(
                    usize::try_from(short.arena_needed)
                        .unwrap_or(usize::MAX)
                        .max(bufs.arena.len()),
                    0,
                );
                i.signals_buf = bufs.signals.as_mut_ptr();
                i.signals_cap = bufs.signals.len();
                i.messages_buf = bufs.messages.as_mut_ptr();
                i.messages_cap = bufs.messages.len();
                i.arena_buf = bufs.arena.as_mut_ptr();
                i.arena_cap = bufs.arena.len();
            });
        if outcome != AbiOutcome::Ready {
            return Err(Stopped::Unreadable);
        }
        // The dispatcher validated the answer against the buffers this call lent
        // (`check_project`): every string lies in the arena written, every turn in the turn
        // buffer. A string is read back as its offset into the arena, never through its pointer.
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

    /// THE REQUEST STAGE, at the head of the route leg (module doc, steps 1-5).
    pub(crate) async fn request_stage(&self, token: &Pass<Route>) -> Result<(), Stopped> {
        let Some(binder) = self.driver.hooks.as_ref() else {
            return Ok(());
        };
        // A health probe is the kernel's own unit: no caller, no request a hook screens.
        if self.arrival.claim == CLAIM_PROBE {
            return Ok(());
        }
        // A GATE-FIRST plane runs its entry's gates, then its rewrites (`gated`).
        if binder.order() == HookOrder::Gated {
            return self.gated_stage(&**binder, token).await;
        }
        let facts = self.far.candidates(token);
        let named = facts.is_some();
        let walk_pool = facts.as_ref().map(|c| c.pool.clone()).unwrap_or_default();
        let principal = self
            .lock()
            .principal
            .as_ref()
            .map(|p| p.as_str().to_string());
        let Some(hooks) = binder.bind(&Bind {
            pool: &walk_pool,
            principal: principal.as_deref(),
        }) else {
            return Ok(());
        };
        // The unit's correlation id, a native `u64` on its span (never a formatted string), the
        // same value every hook payload and tap of the unit carries.
        let span = tracing::debug_span!("forward", request_id = tracing::field::Empty);
        span.record("request_id", hooks.request_id);
        let mut view = match self.project(None) {
            Ok(view) => view,
            Err(stopped) => {
                // The unit's response taps still see it, in the zeroed shape.
                self.lock().hooked = Some((hooks, Projection::default()));
                return Err(stopped);
            }
        };
        let pool = if walk_pool.is_empty() {
            view.pool.clone()
        } else {
            walk_pool
        };
        let principal = principal.as_deref();

        // 1. THE REWRITE CHAIN.
        for (timeout, hook) in &hooks.rewrites {
            let req = view.request(hooks.request_id, &pool, true, None);
            if req.prompt.is_some() {
                (hooks.reads)(hook.name(), None, &view.dialect, false);
            }
            let outcome = hook.transform(&req, *timeout).await;
            drop(req);
            match outcome {
                TransformOutcome::Rewrite(rw) => {
                    let bytes = serde_json::to_vec(&serde_json::json!({
                        "messages": rw.messages,
                        "tools": rw.tools,
                    }))
                    .unwrap_or_default();
                    match self.project(Some(&bytes)) {
                        Ok(next) => {
                            if let Some(body) = &next.rewritten {
                                self.lock().body = Some(Arc::from(body.as_slice()));
                            }
                            view = next;
                        }
                        Err(stopped) => {
                            self.lock().hooked = Some((hooks, view));
                            return Err(stopped);
                        }
                    }
                }
                TransformOutcome::Reject { status, message } => {
                    self.lock().hooked = Some((hooks, view));
                    return Err(veto(
                        clamp_reject_status(status),
                        sanitize_reject_message(&message),
                    ));
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

        // 2. THE GLOBAL REQUEST-STAGE TAPS, each handed the view its grant allows.
        fire_request_taps(&hooks, &view, &pool);

        // 3. THE DECISION GATES, then 4. THE BASE POLICY.
        let all: Vec<CandidateFacts> = facts.map(|c| c.members).unwrap_or_default();
        let mut keep: HashSet<usize> = all.iter().map(|c| c.idx).collect();
        let mut constraint = Constraint::default();
        let decided = self
            .decide_route(
                &hooks,
                &view,
                (&pool, named),
                &all,
                &mut keep,
                &mut constraint,
                principal,
            )
            .await;
        if let Err(stopped) = decided {
            self.lock().hooked = Some((hooks, view));
            return Err(stopped);
        }

        // 5. THE CANDIDATE TAPS, then the walk's constraint.
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
        self.lock().route_policy = constraint.policy;
        if constraint != Constraint::default() {
            self.far.constrain(token, constraint);
        }
        self.lock().hooked = Some((hooks, view));
        self.lock().hooked_pool = pool;
        Ok(())
    }

    /// Steps 3 and 4: the gates reconciled, then the base policy when no gate ordered.
    #[allow(clippy::too_many_arguments)]
    async fn decide_route(
        &self,
        hooks: &UnitHooks,
        view: &Projection,
        (pool, named): (&str, bool),
        all: &[CandidateFacts],
        keep: &mut HashSet<usize>,
        constraint: &mut Constraint,
        principal: Option<&str>,
    ) -> Result<(), Stopped> {
        let mut gate_order: Option<(Vec<usize>, &'static str)> = None;
        if !hooks.gates.is_empty() {
            let shown = candidates_of(all, hooks, keep);
            let asked = Asked {
                view,
                hooks,
                pool,
                candidates: &shown,
                principal,
                named,
            };
            let outcomes: Vec<Decided> =
                futures::future::join_all(hooks.gates.iter().map(|(_, gate)| asked.decide(gate)))
                    .await;
            // A REJECT WINS: the first in chain order surfaces.
            for outcome in &outcomes {
                match outcome {
                    Decided::RejectRequest {
                        status,
                        message,
                        name,
                    } => {
                        metrics::counter!(
                            ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => *name,
                            "pool" => pool.to_string(),
                            "status" => status.to_string(),
                        )
                        .increment(1);
                        crate::diag_debug!(
                            DECISION_GATE_REJECTED,
                            policy = name,
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
            // RESTRICTS INTERSECT, in chain order.
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
                        name,
                    });
                    if narrow(keep, all, tags_any) {
                        metrics::counter!(
                            ROUTE_POLICY_SELECTIONS_TOTAL,
                            "policy" => *name,
                            "pool" => pool.to_string(),
                        )
                        .increment(1);
                        constraint.policy = Some(name);
                    } else if matches!(on_empty, PolicyOnError::Weighted) {
                        crate::diag_debug!(
                            DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
                            policy = name,
                            pool = pool,
                            "decision gate restrict left no eligible lane; on_empty: weighted \
                             escape — this gate's restriction is skipped"
                        );
                    } else {
                        metrics::counter!(
                            ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => *name,
                            "pool" => pool.to_string(),
                            "status" => "503".to_string(),
                        )
                        .increment(1);
                        crate::diag_debug!(
                            DECISION_GATE_RESTRICT_REJECT,
                            policy = name,
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
            // THE LAST ORDER WINS, filtered to what the restricts left; one that filters to empty
            // abstains to the base, never to a lower gate's order.
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
                    "policy" => *name,
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
            principal,
            named,
        };
        match Box::pin(asked.decide(policy)).await {
            Decided::Order { order, name } => {
                metrics::counter!(
                    ROUTE_POLICY_SELECTIONS_TOTAL,
                    "policy" => name,
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
                    "policy" => name,
                    "pool" => pool.to_string(),
                    "status" => status.to_string(),
                )
                .increment(1);
                crate::diag_debug!(
                    ROUTING_POLICY_REJECTED,
                    policy = name,
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
                    name,
                });
                if narrow(keep, all, &tags_any) {
                    metrics::counter!(
                        ROUTE_POLICY_SELECTIONS_TOTAL,
                        "policy" => name,
                        "pool" => pool.to_string(),
                    )
                    .increment(1);
                    constraint.policy = Some(name);
                    Ok(())
                } else if matches!(on_empty, PolicyOnError::Weighted) {
                    crate::diag_debug!(
                        ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
                        policy = name,
                        pool = pool,
                        "routing policy restrict left no eligible lane; on_empty: weighted \
                         escape to full-pool SWRR"
                    );
                    Ok(())
                } else {
                    metrics::counter!(
                        ROUTE_POLICY_REJECTIONS_TOTAL,
                        "policy" => name,
                        "pool" => pool.to_string(),
                        "status" => "503".to_string(),
                    )
                    .increment(1);
                    crate::diag_debug!(
                        ROUTING_POLICY_RESTRICT_REJECT,
                        policy = name,
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

    /// THE `routing` STAGE TAP of one attempt: the member, the attempt number, what the walk has
    /// left untried, and why the previous attempt failed over.
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

    /// THE `response` STAGE TAP, once per unit: `gate` = the hooks refused it (the synthetic
    /// `rejected_by_gate`), else a 2xx is `ok` and anything else `failed`.
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

/// Step 2: the global request-stage taps, fire-and-forget; a `prompt: ro` tap is handed the
/// prompt view, every other tap the shape only. At most two views are built.
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
