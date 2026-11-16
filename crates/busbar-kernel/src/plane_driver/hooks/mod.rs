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

use std::borrow::Cow;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use busbar_contract::abi::hook::{
    MessageView, SignalEntry, REQUEST_HAS_MAX_TOKENS, REQUEST_HAS_TOOLS, REQUEST_STREAM,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome as AbiOutcome, Span};
use busbar_contract::abi::plane::{
    ProjectIn, ProjectOut, CLAIM_PROBE, PROJECT_IN_OBSERVE_ONLY, SPAN_ABSENT,
};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::caps::{Pass, Route};
use busbar_contract::hooks::{
    BudgetBucketState, CallerIdentity, Candidate, PromptProjection, RoutingContext,
    RoutingDecision, RoutingPolicy, RoutingRequest, TransformOutcome,
};
use busbar_contract::secure::{SecureString, SecureVec};
use busbar_contract::signal::{Signal, SignalBag, SignalValue};
use busbar_kernel_audit::record::{HookApplied, HookHead};

use super::{blob, FarEnd, PlaneUnits};
use crate::config::PolicyOnError;
use crate::diagnostics::{
    DECISION_GATE_REJECTED, DECISION_GATE_RESTRICT_REJECT, DECISION_GATE_RESTRICT_WEIGHTED_ESCAPE,
    ON_ERROR_FALLBACK_ANSWERED, ON_ERROR_FALLBACK_DEADLINE_EXCEEDED, ON_ERROR_FALLBACK_HOOK_FAILED,
    ROUTING_POLICY_ABSTAINED_UNPRICED, ROUTING_POLICY_DEADLINE_EXCEEDED,
    ROUTING_POLICY_FAILED_ON_ERROR_FALLBACK, ROUTING_POLICY_REJECTED,
    ROUTING_POLICY_RESTRICT_REJECT, ROUTING_POLICY_RESTRICT_WEIGHTED_ESCAPE,
};
use crate::hooks::taps::{fire_stage_taps_where, spawn_bounded_tap, StageShape};
use crate::hooks::{
    content_capped, failed_call_refuses, FallbackHook, RequestedSignals, ResolvedPolicy, TapEntry,
    REQUIRED_HOOK_UNAVAILABLE_MESSAGE, REQUIRED_HOOK_UNAVAILABLE_STATUS,
};
use crate::snapshot::{
    HOOK_PROJECT_OVER_CAP_TOTAL, ROUTE_POLICY_REJECTIONS_TOTAL, ROUTE_POLICY_SELECTIONS_TOTAL,
};
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

/// The dialect name at `dialect` in a binder's dialect table, empty when it has none.
pub fn dialect_at(dialects: &[String], dialect: u32) -> String {
    dialects.get(dialect as usize).cloned().unwrap_or_default()
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

    /// Whether the node keeps the end user on its unit records (`records.user`, ADMIN-API-1.6
    /// §3.5). `false` (the default) leaves the driver no work for it.
    fn keeps_end_user(&self) -> bool {
        false
    }

    /// The end user the plane projected for `unit`, once, from the unit's first projection.
    fn end_user(&self, _unit: busbar_contract::UnitKey, _user: &str) {}

    /// The unit's request header fields at Decode, for the record's allow-listed labels
    /// (`records.labels`, ADMIN-API-1.6 §3.5). A node keeping none returns at once.
    fn decoded_fields(&self, _unit: busbar_contract::UnitKey, _fields: &[(Vec<u8>, Vec<u8>)]) {}
}

thread_local! {
    /// The thread's spare hook-facts buffer: a unit's hook stage takes it and its report hands it
    /// back cleared, so units on one thread reuse one allocation.
    static RAN_SPARE: std::cell::Cell<Vec<HookApplied>> = const { std::cell::Cell::new(Vec::new()) };
}

/// The buffer a unit's hook stage records the hooks that ran into: the thread's spare.
pub(crate) fn ran_buffer() -> Vec<HookApplied> {
    RAN_SPARE.with(std::cell::Cell::take)
}

fn head_of(decided: &Decided) -> HookHead {
    match decided {
        Decided::Reject | Decided::RejectRequest { .. } => HookHead::Veto,
        Decided::Order { .. } | Decided::Prioritize { .. } | Decided::Restrict { .. } => {
            HookHead::Modify
        }
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

pub type HookRead = Arc<
    dyn for<'a> Fn(
            &'a [&'a str],
            Option<&'a str>,
            &'a str,
            bool,
        ) -> crate::audit::amend::ReadConfirmation<'a>
        + Send
        + Sync,
>;

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

    /// No bound hook stops, changes or routes the request on its content: no rewrite, no gate,
    /// and at most a content-blind policy ([`ResolvedPolicy::reads_request`]). Taps of any stage
    /// only observe. What `project` states to the plane as
    /// [`busbar_contract::abi::plane::PROJECT_IN_OBSERVE_ONLY`].
    #[must_use]
    pub fn observe_only(&self) -> bool {
        self.rewrites.is_empty()
            && self.gates.is_empty()
            && self.policy.as_ref().is_none_or(|p| !p.reads_request())
    }

    /// No rewrite, gate or policy is bound: an unreadable first view leaves the unit to its
    /// ordinary protocol handling. Implies [`Self::observe_only`], never the reverse.
    #[must_use]
    pub fn idle(&self) -> bool {
        self.rewrites.is_empty() && self.gates.is_empty() && self.policy.is_none()
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

    fn hook_read<'a>(
        &'a self,
        hook: &'a str,
        principal: Option<&'a str>,
        dialect: &'a str,
        identity: bool,
    ) -> crate::audit::amend::ReadConfirmation<'a>;

    /// Record that every hook in `hooks` is handed the content, confirmed before any of them is.
    /// A host that can commit the set together overrides this; the default records them in order.
    fn hook_reads<'a>(
        &'a self,
        hooks: &'a [&'a str],
        principal: Option<&'a str>,
        dialect: &'a str,
        identity: bool,
    ) -> crate::audit::amend::ReadConfirmation<'a> {
        Box::pin(async move {
            for hook in hooks {
                self.hook_read(hook, principal, dialect, identity).await?;
            }
            Ok(())
        })
    }

    fn denied_taps(&self, taps: &[TapEntry], request_id: u64, dialect: &str, status: u16) {
        let shape = StageShape::zeroed(request_id, "", dialect, false);
        fire_stage_taps_where(
            taps,
            &shape,
            &stage_at(
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
                move |hooks: &[&str], principal: Option<&str>, dialect: &str, id: bool| {
                    let caller = reads_caller.clone();
                    Box::pin(async move { caller.hook_reads(hooks, principal, dialect, id).await })
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
        dialect_at(&self.dialects, dialect)
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
        dialect_at(&self.dialects, dialect)
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
    /// An unordered preferred set; all other kept members remain fallback. Ordinary ranking,
    /// configured tiers and weighted rotation apply inside each group; affinity keeps precedence.
    pub prioritize: Option<Vec<usize>>,
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

/// THE PLANE'S PROJECTION of a unit's request: what every hook payload of the unit is built
/// from. It borrows the projection arena (or the session stage's own ask) and copies nothing out
/// of it; only a string that is not UTF-8 is held as its own lossy copy, wiped when it drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection<'a> {
    /// The pool the plane names (the walk's, when it names one, wins).
    pub pool: Cow<'a, str>,
    /// The dialect the unit arrived in.
    pub dialect: Cow<'a, str>,
    /// The wire turn count.
    pub message_count: usize,
    /// The screenable characters.
    pub total_chars: usize,
    /// The caller's output cap.
    pub max_tokens: Option<u32>,
    /// The request declares tools.
    pub has_tools: bool,
    /// Explicit plane assurance, never inferred from projected text being nonempty.
    pub text_complete: bool,
    /// The caller asked for a stream.
    pub stream: bool,
    /// The prompt's system field.
    pub system: Option<Cow<'a, str>>,
    /// The prompt's turns.
    pub turns: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    /// The end user.
    pub end_user: Option<Cow<'a, str>>,
    /// The body a rewrite left, when this projection answered one.
    pub rewritten: Option<&'a [u8]>,
    /// The session the request continues, as the plane read it (`RequestView::session`).
    pub session: Option<&'a [u8]>,
    /// The plane's projected body (`ProjectOut::body`), when it states one: what a gate-first
    /// plane's gates screen.
    pub projected: Option<&'a [u8]>,
    /// The plane stated `PROJECT_REWRITE_NOT_APPLICABLE`: the rewrite this projection carried, for
    /// which it answers no rewritten body, does not apply to the unit (its operation has no
    /// conversation to frame one into). Read only where the call carried a rewrite and no
    /// rewritten body came back.
    pub rewrite_not_applicable: bool,
}

/// Wipe a string this projection owns: a lossy copy of text that was not UTF-8. Borrowed text
/// is wiped by its owner.
fn wipe_owned(text: &mut Cow<'_, str>) {
    if let Cow::Owned(owned) = text {
        crate::host_chains::wipe(owned);
    }
}

impl Drop for Projection<'_> {
    fn drop(&mut self) {
        wipe_owned(&mut self.pool);
        wipe_owned(&mut self.dialect);
        self.system.iter_mut().for_each(wipe_owned);
        self.end_user.iter_mut().for_each(wipe_owned);
        for (role, text) in &mut self.turns {
            wipe_owned(role);
            wipe_owned(text);
        }
    }
}

impl<'a> Projection<'a> {
    fn empty(pool: &'a str, dialect: &'a str) -> Self {
        Self {
            pool: Cow::Borrowed(pool),
            dialect: Cow::Borrowed(dialect),
            message_count: 0,
            total_chars: 0,
            max_tokens: None,
            has_tools: false,
            text_complete: false,
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
            system: self.system.as_deref().map(Cow::Borrowed),
            messages: self
                .turns
                .iter()
                .map(|(r, t)| (Cow::Borrowed(&**r), Cow::Borrowed(&**t)))
                .collect(),
        })
    }

    fn request<'s>(
        &'s self,
        request_id: u64,
        pool: &'s str,
        prompt: bool,
        identity: Option<CallerIdentity>,
        requested: &RequestedSignals,
    ) -> RoutingRequest<'s> {
        let prompt = prompt.then(|| self.prompt());
        let mut signals = SignalBag::default();
        if let Some(projected) = prompt
            .as_ref()
            .filter(|_| requested.wants(Signal::RequestTextComplete))
        {
            signals.push(
                Signal::RequestTextComplete,
                SignalValue::Bool(self.complete_text_projection(projected)),
            );
        }
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
            prompt,
            identity,
            signals,
            session: self.session,
        }
    }

    fn complete_text_projection(&self, projected: &PromptProjection<'_>) -> bool {
        self.text_complete
            && !self.has_tools
            && projected.system.as_deref() == self.system.as_deref()
            && projected.messages.len() == self.turns.len()
            && projected.messages.iter().zip(&self.turns).all(
                |((role, text), (original_role, original_text))| {
                    role == original_role && text == original_text
                },
            )
    }
}

/// The shape a unit's later stage taps report (`routing`, `response`): owned, and holding no
/// prompt text, so nothing of the caller's request stays resident past the request stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ShapeFacts {
    dialect: String,
    message_count: usize,
    has_tools: bool,
    total_chars: usize,
    max_tokens: Option<u32>,
    stream: bool,
}

impl ShapeFacts {
    fn of(view: &Projection<'_>) -> Self {
        Self {
            dialect: view.dialect.to_string(),
            message_count: view.message_count,
            has_tools: view.has_tools,
            total_chars: view.total_chars,
            max_tokens: view.max_tokens,
            stream: view.stream,
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
    /// The plane answered FAULT before the hook configuration was bound. A marked parse
    /// failure may pass only when no enforcement hook requires a projection; gates and
    /// routing policies must never judge fabricated empty facts.
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
    crate::cold::hooks_veto_by(status, text, hook)
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
    /// This unordered preferred set, composed with the ordinary routing policy.
    Prioritize {
        candidates: Vec<usize>,
        name: std::sync::Arc<str>,
    },
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

/// The `(policy, pool)` pairs inside a failure window: a pair's first failure warns, its repeats are
/// debug, and its next answer closes the window. Keyed by policy, then pool, so a lookup composes
/// nothing.
static FAULT_WINDOW: LazyLock<Mutex<PairWindow>> = LazyLock::new(Mutex::default);

/// `(policy, pool)` pairs, keyed by policy, then pool, so a lookup composes nothing.
pub(crate) type PairWindow = foldhash::HashMap<String, foldhash::HashSet<String>>;

fn fault_enter(policy: &str, pool: &str) -> bool {
    let mut window = FAULT_WINDOW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if window.get(policy).is_some_and(|pools| pools.contains(pool)) {
        return false;
    }
    crate::cold::hooks_pair_first_seen(&mut window, policy, pool);
    true
}

fn fault_clear(policy: &str, pool: &str) {
    let mut window = FAULT_WINDOW
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if window.is_empty() {
        return;
    }
    if let Some(pools) = window.get_mut(policy) {
        pools.remove(pool);
    }
}

/// `raw`, kept in order where it names one of `candidates`, each index once (what
/// [`RoutingDecision::from_ranked`] keeps), compacted in place.
fn ranked(mut raw: Vec<usize>, candidates: &[Candidate<'_>]) -> RoutingDecision {
    let mut kept = 0;
    for i in 0..raw.len() {
        let idx = raw[i];
        if candidates.iter().any(|c| c.idx == idx) && !raw[..kept].contains(&idx) {
            raw[kept] = idx;
            kept += 1;
        }
    }
    raw.truncate(kept);
    if raw.is_empty() {
        RoutingDecision::Abstain
    } else {
        RoutingDecision::Prefer(raw)
    }
}

/// `tags`, each trimmed in place, the empty ones dropped, in order.
fn trimmed_tags(mut tags: Vec<String>) -> Vec<String> {
    let mut kept = 0;
    for i in 0..tags.len() {
        let tag = &mut tags[i];
        let end = tag.trim_end().len();
        tag.truncate(end);
        let start = tag.len() - tag.trim_start().len();
        tag.drain(..start);
        if !tag.is_empty() {
            tags.swap(kept, i);
            kept += 1;
        }
    }
    tags.truncate(kept);
    tags
}

static UNRANKED_WARNED: LazyLock<Mutex<PairWindow>> = LazyLock::new(Mutex::default);

/// The ordering policy answered and made no choice: the walk is SWRR. Say so once per
/// policy@pool when no shown member carries a fully priced routing-cost recipe.
/// Returns whether it logged (for tests).
fn note_unranked(policy: &str, pool: &str, shown: &[Candidate<'_>]) -> bool {
    if shown.is_empty() || shown.iter().any(has_known_cost) {
        return false;
    }
    let mut warned = UNRANKED_WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fresh = !warned.get(policy).is_some_and(|pools| pools.contains(pool));
    if fresh {
        crate::cold::hooks_pair_first_seen(&mut warned, policy, pool);
    }
    drop(warned);
    if fresh {
        crate::diag_warn!(
            ROUTING_POLICY_ABSTAINED_UNPRICED,
            policy = policy,
            pool = pool,
            "routing policy '{policy}' made no choice for pool '{pool}' and no member has a known \
             routing cost; the pool is using weighted round-robin. If this policy ranks by cost, \
             price every member's lane for the plane's cost classes in rate_card (a named hook \
             also needs signals: [candidate_route_cost])"
        );
    }
    fresh
}

/// True when the core's unfiltered bag decodes to at least one term and every term is priced.
fn has_known_cost(c: &Candidate<'_>) -> bool {
    let (mut terms, mut priced) = (0usize, true);
    let recipe = busbar_contract::signal::route_cost::visit(&c.signals, |t| {
        terms += 1;
        priced &= t.price_per_unit.is_some();
    });
    matches!(recipe, Ok(true)) && terms > 0 && priced
}

fn unranked_clear(policy: &str, pool: &str) {
    let mut set = UNRANKED_WARNED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(pools) = set.get_mut(policy) {
        pools.remove(pool);
    }
}

#[cfg(test)]
#[path = "tests/unranked_tests.rs"]
mod unranked_tests;

fn map_answer(
    answer: RoutingDecision,
    name: std::sync::Arc<str>,
    candidates: &[Candidate<'_>],
    on_empty: &PolicyOnError,
) -> Decided {
    match answer {
        RoutingDecision::Prioritize(set) => match ranked(set, candidates) {
            RoutingDecision::Prefer(candidates) => Decided::Prioritize { candidates, name },
            _ => Decided::Weighted,
        },
        RoutingDecision::Prefer(order) => match ranked(order, candidates) {
            RoutingDecision::Prefer(order) => Decided::Order { order, name },
            _ => Decided::Weighted,
        },
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
        PolicyOnError::First => {
            let order = candidates.iter().map(|c| c.idx).collect();
            Decided::Order { order, name }
        }
        PolicyOnError::Weighted | PolicyOnError::Reject => Decided::Weighted,
    }
}

struct Asked<'a> {
    view: &'a Projection<'a>,
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
            user: self.view.end_user.as_deref().map(str::to_owned),
        }
    }

    async fn read(
        &self,
        hook: &str,
        identity: bool,
    ) -> Result<(), busbar_kernel_audit::amend::AmendPersistError> {
        let whose = self.hooks.key.as_ref().map(|k| k.id.as_str());
        (self.hooks.reads)(&[hook], whose, &self.view.dialect, identity).await
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
            &self.hooks.requested,
        );
        let ctx = RoutingContext {
            pool: self.pool,
            budget_remaining: None,
            budget: &self.hooks.budget,
        };
        if req.prompt.is_some()
            && self
                .read(policy.name(), req.identity.is_some())
                .await
                .is_err()
        {
            return (Decided::Reject, None);
        }
        let decided = match tokio::time::timeout(
            *timeout,
            policy.decide(&req, self.candidates, &ctx, *timeout),
        )
        .await
        {
            Ok(Ok(answer)) => {
                fault_clear(policy.name(), self.pool);
                let decided = map_answer(answer, policy.name_arc(), self.candidates, on_empty);
                let ran = applied(policy.name(), head_of(&decided), false);
                return (decided, Some(ran));
            }
            Ok(Err(e)) => {
                if fault_enter(policy.name(), self.pool) {
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
                if fault_enter(policy.name(), self.pool) {
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
            let mut signals = SignalBag::default();
            for (signal, value) in req.signals.iter() {
                if fb.send_prompt || *signal != Signal::RequestTextComplete {
                    signals.push(*signal, value.clone());
                }
            }
            let fb_req = RoutingRequest {
                signals,
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
            if fb_req.prompt.is_some()
                && self
                    .read(fb.policy.name(), fb_req.identity.is_some())
                    .await
                    .is_err()
            {
                return Decided::Reject;
            }
            match tokio::time::timeout(
                fb.timeout,
                fb.policy.decide(&fb_req, self.candidates, ctx, fb.timeout),
            )
            .await
            {
                Ok(Ok(answer)) => {
                    fault_clear(fb.policy.name(), self.pool);
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
                    if fault_enter(fb.policy.name(), self.pool) {
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
                    if fault_enter(fb.policy.name(), self.pool) {
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

fn candidates_of<'a>(facts: &'a [CandidateFacts], hooks: &UnitHooks) -> Vec<Candidate<'a>> {
    facts
        .iter()
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

/// Narrow the unit's own member list in place to the members carrying one of `tags_any`; `false`
/// (nothing changed) when none does.
fn narrow(all: &mut Vec<CandidateFacts>, tags_any: &[String]) -> bool {
    let carries = |c: &CandidateFacts| c.tags.iter().any(|t| tags_any.iter().any(|w| w == t));
    if !all.iter().any(carries) {
        return false;
    }
    let mut kept = 0;
    for i in 0..all.len() {
        if carries(&all[i]) {
            all.swap(kept, i);
            kept += 1;
        }
    }
    all.truncate(kept);
    true
}

/// `set`, kept in order where it names one of the unit's members, compacted in place.
fn members_only(mut set: Vec<usize>, all: &[CandidateFacts]) -> Vec<usize> {
    let mut kept = 0;
    for i in 0..set.len() {
        let idx = set[i];
        if all.iter().any(|c| c.idx == idx) {
            set[kept] = idx;
            kept += 1;
        }
    }
    set.truncate(kept);
    set
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

/// One `project` call's working set. Only the arena outlives the call: the signal and message
/// buffers hold raw pointers into it and are never held across an await.
struct ProjectBufs {
    signals: Vec<SignalEntry>,
    messages: Vec<MessageView>,
    arena: ProjectArena,
}

struct ProjectArena(ProjectBytes);

impl Drop for ProjectArena {
    fn drop(&mut self) {
        crate::host_chains::wipe(&mut self.0);
    }
}

impl zeroize::ZeroizeOnDrop for ProjectArena {}

impl From<Vec<u8>> for ProjectArena {
    fn from(bytes: Vec<u8>) -> Self {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::ProjectArena);
        #[cfg(test)]
        let bytes: ProjectBytes = bytes.into();
        Self(bytes)
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

    /// Ready this arena for another projection: wipe it in place. The slice is wiped, never the
    /// `Vec` (whose `Zeroize` would clear it to length 0 and cost a SHORT answer and a fresh
    /// allocation on every reuse), so the allocation and its length are kept.
    fn reset(&mut self) {
        crate::host_chains::wipe(&mut self[..]);
    }
}

#[cfg(test)]
#[path = "tests/project_arena_custody_tests.rs"]
mod project_arena_custody_tests;

#[cfg(test)]
#[path = "tests/project_copy_tests.rs"]
mod project_copy_tests;

#[cfg(test)]
#[path = "tests/observe_only_tests.rs"]
mod observe_only_tests;

const SIGNALS_CAP: usize = 16;
const MESSAGES_CAP: usize = 64;

// An honest plane states each signal id at most once, so it never needs more signal entries than
// the catalog has ids. The catalog fits the default buffer, which is why the signals bound below
// (`in / 8 + SIGNALS_CAP`) never refuses an honest plane.
const _: () = assert!(Signal::ALL.len() <= SIGNALS_CAP);

/// The projection arena may grow to this many times the plane's input (the unit's body and the
/// rewrite it applies), plus the default arena. The arena holds the projected body, the turn text
/// and the rewritten body (each at most the input) and the plane's framing; a plane re-escaping
/// into ASCII-only JSON grows a part up to 6x (`\u00XX` for one byte), so 8x covers the worst
/// escaped part with the plain ones and the framing. The default arena covers the small strings
/// and an empty body.
const ARENA_INPUT_FACTOR: usize = 8;

/// An arena offset range: `None` is the empty string (or an absent span).
type Cut = Option<std::ops::Range<usize>>;

/// The plane's answer to one `project` call, as offsets into the arena it was written into:
/// scalars and offsets only, never pointers, so it crosses an await with its arena.
struct ProjectAt {
    pool: Cut,
    dialect: Cut,
    message_count: usize,
    total_chars: usize,
    max_tokens: Option<u32>,
    has_tools: bool,
    text_complete: bool,
    stream: bool,
    system: Option<Cut>,
    turns: Vec<(Cut, Cut)>,
    end_user: Option<Cut>,
    rewritten: Cut,
    session: Option<Cut>,
    projected: Cut,
    rewrite_not_applicable: bool,
}

/// The text at `cut`, borrowed when it is UTF-8; otherwise today's lossy replacement, the one
/// copy a projection makes.
fn text_at<'a>(arena: &'a [u8], cut: &Cut) -> Cow<'a, str> {
    let Some(bytes) = cut.clone().and_then(|r| arena.get(r)) else {
        return Cow::Borrowed("");
    };
    let text = String::from_utf8_lossy(bytes);
    if matches!(text, Cow::Owned(_)) {
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::ProjectCopy);
    }
    text
}

fn bytes_at<'a>(arena: &'a [u8], cut: &Cut) -> Option<&'a [u8]> {
    cut.clone().and_then(|r| arena.get(r))
}

impl ProjectAt {
    fn view<'a>(&self, arena: &'a [u8]) -> Projection<'a> {
        Projection {
            pool: text_at(arena, &self.pool),
            dialect: text_at(arena, &self.dialect),
            message_count: self.message_count,
            total_chars: self.total_chars,
            max_tokens: self.max_tokens,
            has_tools: self.has_tools,
            text_complete: self.text_complete,
            stream: self.stream,
            system: self.system.as_ref().map(|c| text_at(arena, c)),
            turns: self
                .turns
                .iter()
                .map(|(role, text)| (text_at(arena, role), text_at(arena, text)))
                .collect(),
            end_user: self.end_user.as_ref().map(|c| text_at(arena, c)),
            rewritten: bytes_at(arena, &self.rewritten),
            session: self
                .session
                .as_ref()
                .map(|c| bytes_at(arena, c).unwrap_or_default()),
            projected: bytes_at(arena, &self.projected),
            rewrite_not_applicable: self.rewrite_not_applicable,
        }
    }

    /// The pool the plane named, without reading the rest of the answer.
    fn pool<'a>(&self, arena: &'a [u8]) -> Cow<'a, str> {
        text_at(arena, &self.pool)
    }

    /// The body a rewrite left, copied out of the arena to become the unit's body: it outlives
    /// the stage and is re-sent on every attempt, after the arena is wiped. The one copy a
    /// rewrite costs.
    fn rewritten_body(&self, arena: &[u8]) -> Option<bytes::Bytes> {
        let body = bytes_at(arena, &self.rewritten)?;
        busbar_contract::stage_probe::tick(busbar_contract::stage_probe::Derive::ProjectCopy);
        Some(bytes::Bytes::copy_from_slice(body))
    }
}

/// A projection and the arena it borrows.
struct Projected {
    arena: ProjectArena,
    at: ProjectAt,
}

impl Projected {
    fn view(&self) -> Projection<'_> {
        self.at.view(&self.arena)
    }

    /// The end user the plane stated, read alone: the turns are not projected.
    fn end_user(&self) -> Option<Cow<'_, str>> {
        self.at
            .end_user
            .as_ref()
            .map(|cut| text_at(&self.arena, cut))
    }

    /// Take a re-projection's answer as current, and hand back the superseded arena wiped, as
    /// the next re-projection's spare.
    fn accept(&mut self, mut arena: ProjectArena, at: ProjectAt) -> ProjectArena {
        std::mem::swap(&mut self.arena, &mut arena);
        self.at = at;
        arena.reset();
        arena
    }
}

/// The walk's request stage's current view: the plane's projection, or the empty one a unit
/// with no enforcement hook falls back to when the plane cannot project.
enum StageView<'w> {
    Projected(Projected),
    Fallback(Projection<'w>),
}

impl StageView<'_> {
    fn view(&self) -> Projection<'_> {
        match self {
            Self::Projected(projected) => projected.view(),
            Self::Fallback(view) => view.clone(),
        }
    }

    /// The pool the plane named, read alone: the turns are not projected, so an invalid turn's
    /// lossy copy is made once, by the view the hooks read, not again here.
    fn pool(&self) -> Cow<'_, str> {
        match self {
            Self::Projected(projected) => projected.at.pool(&projected.arena),
            Self::Fallback(view) => Cow::Borrowed(&*view.pool),
        }
    }

    /// Take a re-projection's answer as current; the superseded arena comes back wiped, when
    /// there was one.
    fn accept(&mut self, arena: ProjectArena, at: ProjectAt) -> Option<ProjectArena> {
        match self {
            Self::Projected(projected) => Some(projected.accept(arena, at)),
            Self::Fallback(_) => {
                *self = Self::Projected(Projected { arena, at });
                None
            }
        }
    }
}

/// The plane asked for more room than its input can need.
struct OverCap {
    part: &'static str,
    needed: usize,
    cap: usize,
}

impl<S, F: FarEnd, C> PlaneUnits<'_, S, F, C> {
    /// The configured projection arena size.
    fn default_arena(&self) -> usize {
        self.driver.config.caps.arena.max(4096)
    }

    /// A fresh projection arena, of the configured size.
    fn fresh_arena(&self) -> ProjectArena {
        vec![0u8; self.default_arena()].into()
    }

    /// Ask the plane to project the unit's request into `arena`, and hand the arena back beside
    /// the answer (kept by the caller for reuse, or dropped and wiped).
    fn project(
        &self,
        arena: ProjectArena,
        rewrite: Option<&[u8]>,
        faultable: bool,
        observe_only: bool,
    ) -> (ProjectArena, Result<ProjectAt, Stopped>) {
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
        // The room the plane may ask for, sized from what it was given: it cannot need more turns
        // than its input spells out (each turn costs at least 2 input bytes), more signal entries
        // than the catalog has ids, or more arena than `ARENA_INPUT_FACTOR` times its input.
        let given = body.len().saturating_add(rewrite.map_or(0, <[u8]>::len));
        let arena_cap = given
            .saturating_mul(ARENA_INPUT_FACTOR)
            .saturating_add(self.default_arena());
        let messages_cap = given / 2 + MESSAGES_CAP;
        let signals_cap = given / 8 + SIGNALS_CAP;
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
            arena,
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
            flags: if observe_only {
                PROJECT_IN_OBSERVE_ONLY
            } else {
                0
            },
            ..blank_in()
        };
        let mut o: ProjectOut = blank_out();
        let mut over_cap: Option<OverCap> = None;
        let outcome = self
            .driver
            .calls
            .project(&mut input, &mut o, &mut |short, i| {
                if over_cap.is_some() {
                    return;
                }
                let arena_needed = usize::try_from(short.arena_needed).unwrap_or(usize::MAX);
                let messages_needed = short.messages_needed as usize;
                let signals_needed = short.signals_needed as usize;
                over_cap = [
                    ("arena", arena_needed, arena_cap),
                    ("messages", messages_needed, messages_cap),
                    ("signals", signals_needed, signals_cap),
                ]
                .into_iter()
                .find(|(_, needed, cap)| needed > cap)
                .map(|(part, needed, cap)| OverCap { part, needed, cap });
                if over_cap.is_some() {
                    return;
                }
                bufs.signals
                    .resize(signals_needed.max(bufs.signals.len()), bufs.signals[0]);
                bufs.messages
                    .resize(messages_needed.max(bufs.messages.len()), bufs.messages[0]);
                bufs.arena.grow(arena_needed.max(bufs.arena.len()));
                i.signals_buf = bufs.signals.as_mut_ptr();
                i.signals_cap = bufs.signals.len();
                i.messages_buf = bufs.messages.as_mut_ptr();
                i.messages_cap = bufs.messages.len();
                i.arena_buf = bufs.arena.as_mut_ptr();
                i.arena_cap = bufs.arena.len();
            });

        if let Some(over) = over_cap {
            tracing::warn!(
                part = over.part,
                needed = over.needed,
                cap = over.cap,
                "the plane asked for more projection room than the request it was given can need; \
                 refusing the projection"
            );
            metrics::counter!(HOOK_PROJECT_OVER_CAP_TOTAL, "part" => over.part).increment(1);
            let stopped = if rewrite.is_some() {
                fault_veto()
            } else {
                Stopped::Unreadable
            };
            return (bufs.arena, Err(stopped));
        }

        if busbar_contract::abi::plane::project_faults(outcome, faultable || rewrite.is_some()) {
            tracing::error!(
                "the plane could not apply a request rewrite it must not leave unapplied; \
                 rejecting rather than forwarding the body un-rewritten"
            );
            return (bufs.arena, Err(fault_veto()));
        }

        if outcome == AbiOutcome::Fault {
            let marked = busbar_contract::abi::plane::project_fault_unparseable(outcome, &o);
            return (bufs.arena, Err(Stopped::Unparseable { marked }));
        }
        if outcome != AbiOutcome::Ready {
            return (bufs.arena, Err(Stopped::Unreadable));
        }

        let base = bufs.arena.as_ptr() as usize;
        let room = bufs.arena.len();
        let within = |at: usize, len: usize| -> Cut {
            let end = at.checked_add(len)?;
            (end <= room).then_some(at..end)
        };
        let text = |s: AbiStr| -> Cut {
            if s.ptr.is_null() || s.len == 0 {
                return None;
            }
            within((s.ptr as usize).wrapping_sub(base), s.len)
        };
        let opt = |s: AbiStr| (!s.ptr.is_null()).then(|| text(s));
        let span = |sp: Span| -> Cut {
            if sp.offset == SPAN_ABSENT || sp.len == 0 {
                return None;
            }
            within(sp.offset as usize, sp.len as usize)
        };
        let v = o.view;
        let turns = bufs
            .messages
            .iter()
            .take(o.prompt.messages_len)
            .map(|m| (text(m.role), text(m.text)))
            .collect();
        let at = ProjectAt {
            pool: text(v.pool),
            dialect: text(v.ingress_dialect),
            message_count: usize::try_from(v.message_count).unwrap_or(usize::MAX),
            total_chars: usize::try_from(v.total_chars).unwrap_or(usize::MAX),
            max_tokens: (v.flags & REQUEST_HAS_MAX_TOKENS != 0).then_some(v.max_tokens),
            has_tools: v.flags & REQUEST_HAS_TOOLS != 0,
            text_complete: v.flags & busbar_contract::abi::hook::REQUEST_TEXT_COMPLETE != 0,
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
            .then(|| within((v.session.ptr as usize).wrapping_sub(base), v.session.len)),
        };
        (bufs.arena, Ok(at))
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
        let mut ran = ran_buffer();
        let scope =
            crate::hook_child::Scope::new(Arc::clone(&self.driver.services), self.lock().unit);
        let stage = crate::hook_child::SCOPE
            .scope(scope, self.run_request_stage(token, &mut ran))
            .await;
        self.report_hooks(ran);
        if stage.is_ok() {
            self.note_unprojected_end_user();
        }
        stage
    }

    /// `records.user` (ADMIN-API-1.6 §3.5): the journal to tell the unit's end user to, when the
    /// node keeps it and has not been told yet. Off, this is the one check a unit pays.
    fn end_user_wanted(&self) -> Option<&Arc<dyn HookJournal>> {
        let journal = self.driver.hook_journal.as_ref()?;
        (journal.keeps_end_user() && !self.lock().end_user_noted).then_some(journal)
    }

    /// Tell the node the end user the unit's first projection stated; a projection that states
    /// none keeps none. Once per unit.
    fn note_end_user(&self, journal: &dyn HookJournal, user: Option<&str>) {
        let unit = {
            let mut st = self.lock();
            if std::mem::replace(&mut st.end_user_noted, true) {
                return;
            }
            st.unit
        };
        if let Some(user) = user.filter(|user| !user.is_empty()) {
            journal.end_user(busbar_contract::UnitKey::new(unit), user);
        }
    }

    /// A unit whose request stage projected nothing (no hook bound): project it once for its end
    /// user alone, when the node keeps it. A projection that fails keeps no user.
    fn note_unprojected_end_user(&self) {
        let Some(journal) = self.end_user_wanted() else {
            return;
        };
        if self.arrival.claim == CLAIM_PROBE {
            return;
        }
        let (arena, at) = self.project(self.fresh_arena(), None, false, true);
        let projected = at.ok().map(|at| Projected { arena, at });
        let user = projected.as_ref().and_then(Projected::end_user);
        self.note_end_user(&**journal, user.as_deref());
    }

    /// Journal the hooks that ran for the unit, then hand the buffer back as the thread's spare.
    pub(crate) fn report_hooks(&self, mut hooks: Vec<HookApplied>) {
        if let Some(journal) = self.driver.hook_journal.as_ref() {
            if !hooks.is_empty() {
                let unit = busbar_contract::UnitKey::new(self.lock().unit);
                let record = HooksRan { unit, hooks };
                journal.hooks_ran(&record);
                hooks = record.hooks;
            }
        }
        hooks.clear();
        RAN_SPARE.with(|spare| spare.set(hooks));
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
        let (walk_pool, members) = facts.map(|c| (c.pool, c.members)).unwrap_or_default();
        let bound = {
            let st = self.lock();
            binder.bind(&Bind {
                pool: &walk_pool,
                principal: st.principal.as_ref().map(|p| p.as_str()),
                dialect: st.decoded.as_ref().map_or(0, |d| d.dialect),
                request_id: st.request_id,
            })
        };
        let Some(hooks) = bound else {
            return Ok(());
        };
        self.lock().hooked_pool.clone_from(&walk_pool);

        record_request_id(hooks.request_id);

        let faultable = !hooks.rewrites.is_empty();

        // The stage's arenas: the current view's, and a spare a rewrite re-projects into. A stage
        // run allocates at most these two, whatever its rewrite count.
        let (arena, first) =
            self.project(self.fresh_arena(), None, faultable, hooks.observe_only());
        let first = first.map_err(|e| match e {
            Stopped::Unparseable { .. } => Stopped::Unreadable,
            other => other,
        });
        let mut cur = match first {
            Ok(at) => StageView::Projected(Projected { arena, at }),

            Err(Stopped::Unreadable) if hooks.idle() => {
                drop(arena);
                StageView::Fallback(Projection::empty(&walk_pool, &hooks.dialect))
            }
            Err(stopped) => {
                drop(arena);
                let shape = ShapeFacts::of(&Projection::empty("", &hooks.dialect));
                self.lock().hooked = Some((hooks, shape));
                return Err(stopped);
            }
        };
        if let (Some(journal), StageView::Projected(projected)) = (self.end_user_wanted(), &cur) {
            self.note_end_user(&**journal, projected.end_user().as_deref());
        }
        let mut spare: Option<ProjectArena> = None;
        let pool: Cow<'_, str> = if walk_pool.is_empty() {
            Cow::Owned(cur.pool().into_owned())
        } else {
            Cow::Borrowed(&walk_pool)
        };
        {
            let mut st = self.lock();
            st.hooked_pool.clear();
            st.hooked_pool.push_str(&pool);
        }

        for (timeout, hook) in &hooks.rewrites {
            let view = cur.view();
            let req = view.request(hooks.request_id, &pool, true, None, &hooks.requested);
            if req.prompt.is_some() {
                (hooks.reads)(&[hook.name()], None, &view.dialect, false)
                    .await
                    .map_err(|_| fault_veto())?;
            }
            let outcome = hook.transform(&req, *timeout).await;
            drop(req);
            drop(view);
            ran.push(rewrite_applied(hook.name(), &outcome));
            match outcome {
                TransformOutcome::Rewrite(rw) => {
                    let bytes = rewrite_bytes(&rw);
                    let arena = spare.take().unwrap_or_else(|| self.fresh_arena());
                    let (mut arena, next) = self.project(arena, Some(&bytes), true, false);
                    match next {
                        Ok(at) if at.rewritten.is_some() || rw.messages.is_empty() => {
                            if let Some(body) = at.rewritten_body(&arena) {
                                self.lock().body = Some(body);
                            }
                            spare = cur.accept(arena, at);
                        }

                        Ok(at) if at.rewrite_not_applicable => {
                            arena.reset();
                            spare = Some(arena);
                            gated::rewrite_not_applicable(hook.name(), ran);
                            tracing::warn!(
                                hook = hook.name(),
                                pool = %pool,
                                "rewrite not applicable to this request; forwarded unmodified"
                            );
                        }
                        Err(fault @ Stopped::Veto(_)) => {
                            drop(arena);
                            let shape = ShapeFacts::of(&cur.view());
                            drop(cur);
                            self.lock().hooked = Some((hooks, shape));
                            return Err(fault);
                        }

                        Ok(_) | Err(_) => {
                            drop(arena);
                            let (status, message) = gated::refused_rewrite(&**hook, &pool, ran);
                            let shape = ShapeFacts::of(&cur.view());
                            drop(cur);
                            self.lock().hooked = Some((hooks, shape));
                            return Err(veto(status, message));
                        }
                    }
                }
                TransformOutcome::Reject { status, message } => {
                    let shape = ShapeFacts::of(&cur.view());
                    drop(cur);
                    self.lock().hooked = Some((hooks, shape));

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
        drop(spare);

        let view = cur.view();
        fire_request_taps(&hooks, &view, &pool);

        // The unit's own member list, narrowed in place by the gates' and the policy's restricts.
        let mut all: Vec<CandidateFacts> = members;
        let members = all.len();
        let mut constraint = Constraint::default();
        let decided = self
            .decide_route(
                &hooks,
                &view,
                (&pool, named),
                (&mut all, &mut constraint),
                ran,
            )
            .await;
        let shape = ShapeFacts::of(&view);
        drop(view);
        drop(cur);
        if let Err(stopped) = decided {
            self.lock().hooked = Some((hooks, shape));
            return Err(stopped);
        }

        if !hooks.taps.candidate.is_empty() {
            fire_stage_taps_where(
                &hooks.taps.candidate,
                &shape.shape(hooks.request_id, &pool),
                &stage_at("candidate", None, None, Some(all.len()), None, None, None),
                SignalBag::default(),
                &*hooks.groups,
            );
        }
        if all.len() != members {
            let mut kept: Vec<usize> = all.iter().map(|c| c.idx).collect();
            kept.sort();
            constraint.keep = Some(kept);
        }
        self.lock().route_policy.clone_from(&constraint.policy);
        if constraint != Constraint::default() {
            self.far.constrain(token, constraint);
        }
        self.lock().hooked = Some((hooks, shape));
        Ok(())
    }

    async fn decide_route(
        &self,
        hooks: &UnitHooks,
        view: &Projection<'_>,
        (pool, named): (&str, bool),
        (all, constraint): (&mut Vec<CandidateFacts>, &mut Constraint),
        ran: &mut Vec<HookApplied>,
    ) -> Result<(), Stopped> {
        let mut gate_order: Option<(Vec<usize>, std::sync::Arc<str>)> = None;
        if !hooks.gates.is_empty() {
            let shown = candidates_of(all, hooks);
            let asked = Asked {
                view,
                hooks,
                pool,
                candidates: &shown,
                named,
            };
            let mut judged =
                futures::future::join_all(hooks.gates.iter().map(|(_, gate)| asked.decide(gate)))
                    .await;
            for (_, hook) in &mut judged {
                ran.extend(hook.take());
            }

            for (outcome, _) in &judged {
                match outcome {
                    Decided::RejectRequest {
                        status,
                        message,
                        name,
                    } => {
                        metrics::counter!(
                            ROUTE_POLICY_REJECTIONS_TOTAL,
                            "policy" => Arc::clone(name),
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

            for (outcome, _) in &judged {
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
                    if narrow(all, tags_any) {
                        metrics::counter!(
                            ROUTE_POLICY_SELECTIONS_TOTAL,
                            "policy" => Arc::clone(name),
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
                            "policy" => Arc::clone(name),
                            "pool" => pool.to_string(),
                            "status" => "503",
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

            for (outcome, _) in judged {
                match outcome {
                    Decided::Prioritize { candidates, name } => {
                        let filtered = members_only(candidates, all);
                        if !filtered.is_empty() {
                            constraint.prioritize = Some(filtered);
                            constraint.policy = Some(Arc::clone(&name));
                            metrics::counter!(
                                ROUTE_POLICY_SELECTIONS_TOTAL,
                                "policy" => Arc::clone(&name),
                                "pool" => pool.to_string(),
                            )
                            .increment(1);
                        }
                    }
                    Decided::Order { order, name } => {
                        let filtered = members_only(order, all);
                        gate_order = (!filtered.is_empty()).then_some((filtered, name));
                    }
                    _ => {}
                }
            }
            if let Some((_, name)) = &gate_order {
                metrics::counter!(
                    ROUTE_POLICY_SELECTIONS_TOTAL,
                    "policy" => Arc::clone(name),
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
        let shown = candidates_of(all, hooks);
        let asked = Asked {
            view,
            hooks,
            pool,
            candidates: &shown,
            named,
        };
        let (decided, hook) = Box::pin(asked.decide(policy)).await;
        let clean = hook.as_ref().is_some_and(|h| !h.failed);
        ran.extend(hook);
        match decided {
            Decided::Prioritize { candidates, name } => {
                unranked_clear(&name, pool);
                metrics::counter!(
                    ROUTE_POLICY_SELECTIONS_TOTAL,
                    "policy" => Arc::clone(&name),
                    "pool" => pool.to_string(),
                )
                .increment(1);
                constraint.prioritize = Some(candidates);
                constraint.policy = Some(name);
                Ok(())
            }
            Decided::Order { order, name } => {
                unranked_clear(&name, pool);
                metrics::counter!(
                    ROUTE_POLICY_SELECTIONS_TOTAL,
                    "policy" => Arc::clone(&name),
                    "pool" => pool.to_string(),
                )
                .increment(1);
                constraint.order = Some(order);
                constraint.policy = Some(name);
                Ok(())
            }
            Decided::Weighted => {
                if clean {
                    let ResolvedPolicy::Policy {
                        policy: ordering, ..
                    } = policy;
                    note_unranked(ordering.name(), pool, &shown);
                }
                Ok(())
            }
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
                    "policy" => Arc::clone(&name),
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
                if narrow(all, &tags_any) {
                    metrics::counter!(
                        ROUTE_POLICY_SELECTIONS_TOTAL,
                        "policy" => Arc::clone(&name),
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
                        "policy" => Arc::clone(&name),
                        "pool" => pool.to_string(),
                        "status" => "503",
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
        let Some((hooks, shape)) = st.hooked.as_ref() else {
            return;
        };
        if hooks.taps.routing.is_empty() {
            return;
        }
        fire_stage_taps_where(
            &hooks.taps.routing,
            &shape.shape(hooks.request_id, &st.hooked_pool),
            &stage_at(
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
        let Some((hooks, shape)) = st.hooked.as_ref() else {
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
                &shape.shape(hooks.request_id, &st.hooked_pool),
                &stage_at(
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

fn fire_request_taps(hooks: &UnitHooks, view: &Projection<'_>, pool: &str) {
    let taps = &hooks.taps.request;
    if taps.is_empty() {
        return;
    }
    let firing = || taps.iter().filter(|t| (hooks.groups)(&t.3));
    let frame = |with_prompt: bool| {
        let req = view.request(hooks.request_id, pool, with_prompt, None, &hooks.requested);
        busbar_contract::abi::host::hook::NotifyFrame::build(&req, None, with_prompt)
    };
    let shape_only = firing().any(|t| !t.1).then(|| frame(false));
    let with_prompt = firing().any(|t| t.1).then(|| frame(true));
    // Taps handed the prompt are recorded together: one access amendment each, one durable commit
    // for the fan-out, confirmed before any of them is notified. Every one of them fires, so the
    // recorded set is exact.
    let mut content = Vec::new();
    for (timeout, send_prompt, hook, _) in firing() {
        let tap = if *send_prompt {
            with_prompt.clone()
        } else {
            shape_only.clone()
        };
        let Some(tap) = tap else { continue };
        let policy = Arc::clone(hook);
        let budget = *timeout;
        if !*send_prompt {
            spawn_bounded_tap(async move { policy.notify(tap, budget).await });
            continue;
        }
        let Some(slot) = crate::hooks::taps::tap_slot() else {
            continue;
        };
        content.push((slot, policy, tap, budget));
    }
    if content.is_empty() {
        return;
    }
    let reads = hooks.reads.clone();
    let dialect = view.dialect.to_string();
    crate::detached::spawn_detached(async move {
        let names: Vec<&str> = content.iter().map(|t| t.1.name()).collect();
        if (reads)(&names, None, &dialect, false).await.is_err() {
            return;
        }
        for (slot, policy, tap, budget) in content {
            crate::detached::spawn_detached(async move {
                let _slot = slot;
                policy.notify(tap, budget).await;
            });
        }
    });
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

    /// The view a session-stage hook is shown, borrowed from the stage and the ask it answers
    /// (whose owners wipe it).
    fn view<'s>(
        &'s self,
        system: Option<&'s str>,
        turns: Vec<(Cow<'s, str>, Cow<'s, str>)>,
    ) -> Projection<'s> {
        let total_chars = turns.iter().map(|(_, t)| t.chars().count()).sum::<usize>()
            + system.map_or(0, |s| s.chars().count());
        let mut view = Projection::empty(&self.pool, &self.dialect);
        view.message_count = turns.len();
        view.total_chars = total_chars;
        view.system = system.map(Cow::Borrowed);
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

    async fn gate(&self, view: &Projection<'_>) -> crate::host_units::StageAnswer {
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
                &hooks.requested,
            );
            if req.prompt.is_some()
                && (hooks.reads)(
                    &[policy.name()],
                    self.principal.as_deref(),
                    &view.dialect,
                    req.identity.is_some(),
                )
                .await
                .is_err()
            {
                return StageAnswer::Stop {
                    status: 503,
                    words: crate::cold::hooks_audit_unconfirmed(),
                };
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
                            words: crate::cold::hooks_required_unavailable(),
                        };
                    }
                }
            }
        }
        StageAnswer::Pass
    }

    async fn rewrite(&self, from: u32, view: &Projection<'_>) -> crate::host_units::StageAnswer {
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
            let req = view.request(hooks.request_id, &self.pool, true, None, &hooks.requested);
            if req.prompt.is_some()
                && (hooks.reads)(&[hook.name()], None, &view.dialect, false)
                    .await
                    .is_err()
            {
                return StageAnswer::Stop {
                    status: 503,
                    words: crate::cold::hooks_audit_unconfirmed(),
                };
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
            // The ask's text is wiped however this task ends: answered, panicked or dropped.
            let system = ask.system.map(SecureString::from);
            let messages: Vec<(SecureString, SecureString)> = ask
                .messages
                .into_iter()
                .map(|(role, text)| (SecureString::from(role), SecureString::from(text)))
                .collect();
            let turns = messages
                .iter()
                .map(|(role, text)| (Cow::Borrowed(role.as_str()), Cow::Borrowed(text.as_str())))
                .collect();
            let view = stage.view(system.as_deref(), turns);
            if ask.stage == busbar_contract::abi::host::service::HOOK_REWRITE {
                stage.rewrite(ask.from, &view).await
            } else {
                stage.gate(&view).await
            }
        });
    }

    fn scan(self: Arc<Self>, content: Vec<u8>, done: crate::host_units::StageDone) {
        self.spawn(done, move |stage| async move {
            // The content, and its lossy text when it is not UTF-8, are wiped however this task
            // ends: answered, panicked or dropped.
            let content = SecureVec::from(content);
            let lossy: SecureString;
            let text = match std::str::from_utf8(&content) {
                Ok(text) => text,
                Err(_) => {
                    lossy = crate::cold::hooks_lossy_content(&content);
                    lossy.as_str()
                }
            };
            let view = stage.view(
                None,
                vec![(Cow::Borrowed(CONTENT_ROLE), Cow::Borrowed(text))],
            );
            stage.gate(&view).await
        });
    }
}

#[cfg(test)]
#[path = "tests/completeness_tests.rs"]
mod completeness_tests;
