// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND THROUGH THE MIN-3 PORT (W2-SW-HOOK, switch-over 2 of 7; IF §8.4, §11.3).
//!
//! The kernel asks a hook through its `HookAxis` (open, probe) and `HookCalls` (decide, transform,
//! notify) seam. This module serves that seam from the hook **port** ([`HookPort`], L6's adapter over
//! the kind's `Proxy`) instead of the 1.5.5 door: [`PortRows`] is the axis over any [`HookOpener`]
//! (the loader [`Registry`] in production, `Registry::open_hook`), and [`PortHook`] is one opened
//! instance. Each call reads the kernel's frame once, builds the §8.4 view ([`HookView`]: PJ_* and
//! S_* signals, CANDIDATE*, BUDGET*, CONVERSATION), calls `HookPort::on` at the matching point and
//! lowers the [`HookAnswer`] into the frame's own host buffers, so the kernel's verdict handling
//! (clamps, ORDER range drops, MESSAGE as operator text) is unchanged.
//!
//! Pushed configuration and status have no hook method in MIN-3 (IF §8.4): a push is a core
//! reconfigure (`Registry::reconfigure`), and metrics are METRIC records core keeps. `configure`
//! therefore answers the reconfigure refusal text and `status`/`describe` answer nothing.

use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::hook::{
    DecideOut, TransformOut, CLASS_GATE, CLASS_TAP, PROMPT_NO, PROMPT_RO, USER_NO, USER_RO,
};
use busbar_contract::abi::host::hook::{DecideFrame, NotifyFrame};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::hook::{Decoded, RewriteVerdict, Verdict};
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls, HookFacts, Pending, Probed};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::plugin_settings::ResolvedSettings;
use busbar_plugin_abi::fail::fact as pj;
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, InstanceLimits};
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::kinds::hook::hook::{self as abi, CandidateRec};

use crate::instance::{InstanceSpec, OpenError, Registry};
use busbar_ports::hook::{BudgetIn, CandidateIn, HookAnswer, HookCall, HookPort, HookView};
use busbar_ports::{CallCx, FactRef, PortError};

/// The text `configure` answers: MIN-3 hooks have no configure op (IF §8.4).
pub const CONFIGURE_IS_RECONFIGURE: &str =
    "a pushed hook configuration is a core reconfigure in 1.6 (the hook has no configure method)";

/// What the axis opens hook instances through. The loader [`Registry`] is the production opener;
/// a test opener hands back a kind-level double ([`HookPort`] implemented directly).
pub trait HookOpener: Send + Sync + 'static {
    /// Open instance `name` of the admitted hook image `module` with its bound settings.
    fn open<'a>(
        &'a self,
        module: &'a str,
        name: &'a str,
        config_json: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn HookPort>, OpenError>>;

    /// The D_WORD words of the admitted hook image `module` (§12.25), or `None` when no admitted
    /// hook image has that identity.
    fn words(&self, module: &str) -> Option<Vec<Box<str>>>;
}

/// Complete hook-opening context, bound to serving Needs by its owner.
pub struct BoundRegistry<N: Needs> {
    registry: Arc<Registry>,
    needs: Arc<N>,
    refs: Arc<dyn busbar_ports::binder::RefSource>,
}

impl<N: Needs> BoundRegistry<N> {
    pub fn new(
        registry: Arc<Registry>,
        needs: Arc<N>,
        refs: Arc<dyn busbar_ports::binder::RefSource>,
    ) -> Self {
        Self {
            registry,
            needs,
            refs,
        }
    }
}

impl<N: Needs> HookOpener for BoundRegistry<N> {
    fn open<'a>(
        &'a self,
        module: &'a str,
        name: &'a str,
        config_json: &'a [u8],
    ) -> BoxFut<'a, Result<Arc<dyn HookPort>, OpenError>> {
        Box::pin(async move {
            let spec = InstanceSpec {
                purpose: crate::instance::OpenPurpose::Canonical,
                identity: module,
                name,
                config_json,
                limits: InstanceLimits::default(),
                public_url: None,
                caller_upstreams: &[],
            };
            self.registry
                .open_hook(&spec, &self.needs, &self.refs)
                .await
        })
    }

    fn words(&self, module: &str) -> Option<Vec<Box<str>>> {
        self.registry
            .hook_words()
            .into_iter()
            .find(|(identity, _)| *identity == module)
            .map(|(_, words)| words.into_iter().map(Box::from).collect())
    }
}

/// What an open chain answers: the opener's result, or the elapsed budget.
pub type TimedOpen = Result<Result<Arc<dyn HookPort>, OpenError>, tokio::time::error::Elapsed>;

/// Runs one open chain to its end on a runtime the caller built (the kernel builds it through
/// `busbar_kernel::rt`, R40; this crate sits below the kernel and builds none).
pub type OpenDriver =
    Arc<dyn for<'a> Fn(BoxFut<'a, TimedOpen>) -> Result<TimedOpen, String> + Send + Sync>;

/// THE HOOK AXIS OVER THE PORT: what the kernel's `HookAxis` seam asks, answered from an opener.
pub struct PortRows {
    opener: Arc<dyn HookOpener>,
    driver: OpenDriver,
    linked: Vec<Box<str>>,
    first_party: Vec<Box<str>>,
    call_budget: Duration,
    seal: Arc<dyn KernelSeal + Send + Sync>,
}

impl std::fmt::Debug for PortRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortRows")
            .field("linked", &self.linked)
            .field("first_party", &self.first_party)
            .finish_non_exhaustive()
    }
}

impl PortRows {
    /// The axis over `opener`. `linked` names the compiled-in hook images, `first_party` the images
    /// linked or signed by the release key (admission decided both; the axis only reports them).
    #[must_use]
    pub fn new(
        opener: Arc<dyn HookOpener>,
        linked: Vec<Box<str>>,
        first_party: Vec<Box<str>>,
        call_budget: Duration,
        seal: Arc<dyn KernelSeal + Send + Sync>,
        driver: OpenDriver,
    ) -> Self {
        Self {
            opener,
            driver,
            linked,
            first_party,
            call_budget,
            seal,
        }
    }
}

fn open_error(module: &str, label: &str, e: &OpenError) -> String {
    match e {
        OpenError::Refused { refusal, .. } => {
            format!("hook '{label}' ({module}) refused to open: {refusal:?}")
        }
        OpenError::Config { code, text, .. } => {
            format!("hook '{label}' ({module}) refused its settings ({code}): {text}")
        }
        OpenError::Failed { code, text, .. } => {
            format!("hook '{label}' ({module}) failed to open ({code}): {text}")
        }
        OpenError::Call(call) => format!("hook '{label}' ({module}) open broke: {call:?}"),
        OpenError::Unknown(text) => format!("hook '{label}' ({module}): {text}"),
    }
}

impl HookAxis for PortRows {
    fn probe(&self, module: &str, _instance: &str, _settings: &ResolvedSettings) -> Option<Probed> {
        let words = self.opener.words(module)?;
        // MIN-3 has no gate/tap class: a hook serves the points it opens with (`HookPort::points`).
        // Before open every hook answers as a gate; a NOTIFY-only port is a tap once opened.
        let facts = HookFacts {
            name: module.to_owned(),
            class: CLASS_GATE,
            prompt: PROMPT_NO,
            user: USER_NO,
            infallible: false,
            words: words.iter().map(|w| w.to_string()).collect(),
        };
        Some((Some(facts), Vec::new()))
    }

    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &ResolvedSettings,
        budget: Duration,
    ) -> Result<Arc<dyn HookCalls>, String> {
        let config = settings
            .encode()
            .map_err(|e| format!("hook '{label}' ({module}): settings: {e}"))?
            .expose(&*self.seal)
            .clone();
        let opener = Arc::clone(&self.opener);
        let opened = (self.driver)(Box::pin(async move {
            tokio::time::timeout(budget, opener.open(module, label, &config)).await
        }))?;
        let port = match opened {
            Ok(Ok(port)) => port,
            Ok(Err(e)) => return Err(open_error(module, label, &e)),
            Err(_) => {
                return Err(format!(
                    "hook '{label}' ({module}) did not open within {budget:?}"
                ))
            }
        };
        Ok(Arc::new(PortHook::new(label, port)))
    }

    fn linked(&self, module: &str) -> bool {
        self.linked.iter().any(|m| &**m == module)
    }

    fn call_budget(&self) -> Duration {
        self.call_budget
    }

    fn first_party(&self, module: &str) -> bool {
        self.first_party.iter().any(|m| &**m == module)
    }
}

/// ONE OPENED HOOK INSTANCE, served through its port.
pub struct PortHook {
    name: Box<str>,
    port: Arc<dyn HookPort>,
}

impl std::fmt::Debug for PortHook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortHook")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl PortHook {
    /// The instance `name` over its opened `port`.
    #[must_use]
    pub fn new(name: &str, port: Arc<dyn HookPort>) -> Self {
        Self {
            name: name.into(),
            port,
        }
    }

    /// The prompt access this instance asked for (FB_WANTS_PROMPT), as the kernel's grant word.
    #[must_use]
    pub fn prompt(&self) -> u32 {
        if self.port.facts() & abi::FB_WANTS_PROMPT != 0 {
            PROMPT_RO
        } else {
            PROMPT_NO
        }
    }

    /// The identity access this instance asked for (FB_WANTS_IDENTITY), as the kernel's grant word.
    #[must_use]
    pub fn user(&self) -> u32 {
        if self.port.facts() & abi::FB_WANTS_IDENTITY != 0 {
            USER_RO
        } else {
            USER_NO
        }
    }

    /// The class the kernel files this instance under: a port serving POINT_ROUTE or POINT_REWRITE
    /// is a gate, a NOTIFY-only port a tap.
    #[must_use]
    pub fn class(&self) -> u32 {
        let points = self.port.points();
        if points & (point_bit(abi::POINT_ROUTE) | point_bit(abi::POINT_REWRITE)) != 0 {
            CLASS_GATE
        } else {
            CLASS_TAP
        }
    }

    fn serves(&self, point: u32) -> bool {
        self.port.points() & point_bit(point) != 0
    }
}

/// The D_POINTS mask bit of a decision point (the encoder's rule, `encode::hook`).
const fn point_bit(point: u32) -> u32 {
    1 << point
}

/// The view's owned parts, read once from the kernel's frame (`Decoded` borrows the frame).
#[derive(Default)]
struct Owned {
    signals: Vec<(u32, Fact)>,
    candidates: Vec<OwnedCandidate>,
    budgets: Vec<OwnedBudget>,
    conversation: Option<Vec<u8>>,
    body: Option<Vec<u8>>,
}

enum Fact {
    U(u64),
    Text(Box<str>),
}

struct OwnedCandidate {
    rec: CandidateRec,
    model: Box<str>,
    provider: Box<str>,
    tier: Option<Box<str>>,
    tags: Vec<Box<str>>,
}

struct OwnedBudget {
    id: Box<str>,
    period: Box<str>,
    group: Option<Box<str>>,
    pool: Option<Box<str>>,
    remaining_micros: i64,
    spend_micros_at_current_rate: Option<i64>,
    window_start_s: u64,
}

fn text(signals: &mut Vec<(u32, Fact)>, key: u32, value: &str) {
    if !value.is_empty() {
        signals.push((key, Fact::Text(value.into())));
    }
}

/// `x` in [0, 1] as parts per million, saturated.
fn ppm(x: f64) -> u32 {
    if x.is_nan() || x <= 0.0 {
        0
    } else {
        (x.min(1.0) * 1_000_000.0).round() as u32
    }
}

fn saturate(x: f64) -> u64 {
    if x.is_nan() || x <= 0.0 {
        0
    } else {
        x.round().min(u64::MAX as f64) as u64
    }
}

impl Owned {
    /// The request part of the view: the generic PJ_* projection and the hook's S_* keys.
    fn request(d: &Decoded<'_>, wants: u64) -> Self {
        let mut signals = Vec::new();
        signals.push((pj::PJ_MESSAGE_COUNT, Fact::U(d.message_count)));
        signals.push((pj::PJ_TOTAL_CHARS, Fact::U(d.total_chars)));
        signals.push((pj::PJ_TOOL_COUNT, Fact::U(u64::from(d.has_tools))));
        signals.push((pj::PJ_STREAM, Fact::U(u64::from(d.stream))));
        if let Some(max) = d.max_tokens {
            signals.push((pj::PJ_MAX_TOKENS, Fact::U(u64::from(max))));
        }
        text(&mut signals, abi::S_POOL, &d.pool);
        text(&mut signals, abi::S_INGRESS_PROTOCOL, &d.ingress_dialect);
        if let Some(remaining) = d.budget_remaining {
            signals.push((
                abi::S_BUDGET_REMAINING_MICROS,
                Fact::U(u64::try_from(remaining).unwrap_or(0)),
            ));
        }
        if let Some(user) = d.user.as_ref() {
            if let Some(subject) = user.user.as_deref() {
                text(&mut signals, abi::S_USER_SUBJECT, subject);
            }
            if let Some(id) = user.key_id.as_deref() {
                text(&mut signals, abi::S_KEY_ID, id);
            }
            if let Some(name) = user.key_name.as_deref() {
                text(&mut signals, abi::S_KEY_NAME, name);
            }
        }
        let mut owned = Self {
            signals,
            ..Self::default()
        };
        if let Some(prompt) = d.prompt.as_ref() {
            if wants & abi::FB_WANTS_PROMPT != 0 {
                let messages: Vec<serde_json::Value> = prompt
                    .messages
                    .iter()
                    .map(|(role, text)| serde_json::json!({"role": role, "text": text}))
                    .collect();
                let conversation = serde_json::json!({
                    "system": prompt.system.as_deref(),
                    "messages": messages,
                });
                owned.conversation = serde_json::to_vec(&conversation).ok();
            }
            if wants & abi::FB_WANTS_BODY != 0 {
                owned.body = prompt.body.map(<[u8]>::to_vec);
            }
        }
        owned
    }

    /// The whole POINT_ROUTE / POINT_REWRITE view: request, candidates, budgets.
    fn decide(d: &Decoded<'_>, wants: u64) -> Self {
        let mut owned = Self::request(d, wants);
        owned.candidates = d
            .candidates
            .iter()
            .map(|c| {
                let mut flags = 0;
                let mut rec = CandidateRec {
                    index: u32::try_from(c.idx).unwrap_or(u32::MAX),
                    flags: 0,
                    context_max: 0,
                    cost_per_mtok_micros: 0,
                    latency_ms: 0,
                    budget_remaining_micros: 0,
                    error_rate_ppm: 0,
                    breaker: 0,
                    rate_headroom_ppm: 0,
                    _r: 0,
                    weight: c.weight,
                    available_concurrency: u32::try_from(c.available_concurrency)
                        .unwrap_or(u32::MAX),
                };
                if let Some(max) = c.context_max {
                    flags |= abi::C_HAS_CONTEXT_MAX;
                    rec.context_max = max as u64;
                }
                if let Some(cost) = c.cost_per_mtok {
                    flags |= abi::C_HAS_COST;
                    rec.cost_per_mtok_micros = saturate(cost * 1_000_000.0);
                }
                if let Some(latency) = c.latency_ms {
                    flags |= abi::C_HAS_LATENCY;
                    rec.latency_ms = saturate(latency);
                }
                if let Some(remaining) = c.budget_remaining {
                    flags |= abi::C_HAS_BUDGET;
                    rec.budget_remaining_micros = remaining;
                }
                if let Some(headroom) = c.rate_headroom {
                    flags |= abi::C_HAS_RATE_HEADROOM;
                    rec.rate_headroom_ppm = ppm(headroom);
                }
                rec.flags = flags;
                OwnedCandidate {
                    rec,
                    model: Box::from(&*c.model),
                    provider: Box::from(&*c.provider),
                    tier: c.tier.as_deref().map(Box::from),
                    tags: c.tags.iter().map(|t| Box::from(&**t)).collect(),
                }
            })
            .collect();
        owned.budgets = d
            .budget
            .iter()
            .map(|b| OwnedBudget {
                id: Box::from(&*b.bucket_id),
                period: Box::from(&*b.budget_period),
                group: b.budget_group.as_deref().map(Box::from),
                pool: b.pool.as_deref().map(Box::from),
                remaining_micros: b.remaining_micros.unwrap_or(0),
                spend_micros_at_current_rate: Some(b.spend_micros_at_current_rate),
                window_start_s: b.window_start,
            })
            .collect();
        owned
    }

    /// The POINT_NOTIFY view from the tap frame's projection: the request keys and, on a stage tap,
    /// S_STAGE and the stage's keys (IF §8.4 round 17).
    fn notify(frame: &NotifyFrame) -> Self {
        let v = frame.projection_json();
        let request = &v["request"];
        let mut signals = Vec::new();
        let u = |key: &str| {
            request[key]
                .as_u64()
                .or_else(|| request[key].as_bool().map(u64::from))
        };
        for (name, key) in [
            ("message_count", pj::PJ_MESSAGE_COUNT),
            ("total_chars", pj::PJ_TOTAL_CHARS),
            ("has_tools", pj::PJ_TOOL_COUNT),
            ("stream", pj::PJ_STREAM),
            ("max_tokens", pj::PJ_MAX_TOKENS),
        ] {
            if let Some(n) = u(name) {
                signals.push((key, Fact::U(n)));
            }
        }
        for (name, key) in [
            ("pool", abi::S_POOL),
            ("ingress_protocol", abi::S_INGRESS_PROTOCOL),
        ] {
            if let Some(s) = request[name].as_str() {
                text(&mut signals, key, s);
            }
        }
        let stage = &v["stage"];
        if let Some(at) = stage["at"].as_str() {
            let at = match at {
                "candidate" => abi::STAGE_CANDIDATE,
                "routing" => abi::STAGE_ROUTING,
                _ => abi::STAGE_RESPONSE,
            };
            signals.push((abi::S_STAGE, Fact::U(at)));
            if let Some(model) = stage["model"].as_str() {
                text(&mut signals, abi::S_STAGE_MODEL, model);
            }
            for (name, key) in [
                ("attempt_number", abi::S_ATTEMPT),
                ("remaining_candidates", abi::S_REMAINING_CANDIDATES),
                ("status", abi::S_STATUS),
            ] {
                if let Some(n) = stage[name].as_u64() {
                    signals.push((key, Fact::U(n)));
                }
            }
            for (name, key) in [
                ("outcome", abi::S_OUTCOME),
                ("previous_failure", abi::S_PREVIOUS_FAILURE),
            ] {
                if let Some(s) = stage[name].as_str() {
                    text(&mut signals, key, s);
                }
            }
        }
        Self {
            signals,
            ..Self::default()
        }
    }
}

impl Owned {
    fn signal_refs(&self) -> Vec<(u32, FactRef<'_>)> {
        self.signals
            .iter()
            .map(|(key, fact)| {
                let fact = match fact {
                    Fact::U(n) => FactRef::U(*n),
                    Fact::Text(s) => FactRef::Text(s),
                };
                (*key, fact)
            })
            .collect()
    }

    fn tag_refs(&self) -> Vec<Vec<&str>> {
        self.candidates
            .iter()
            .map(|c| c.tags.iter().map(|t| &**t).collect())
            .collect()
    }

    fn candidate_refs<'o>(&'o self, tags: &'o [Vec<&'o str>]) -> Vec<CandidateIn<'o>> {
        self.candidates
            .iter()
            .zip(tags)
            .map(|(c, tags)| CandidateIn {
                rec: c.rec,
                model: &c.model,
                provider: &c.provider,
                tier: c.tier.as_deref(),
                tags,
                cost_terms: &[],
            })
            .collect()
    }

    fn budget_refs(&self) -> Vec<BudgetIn<'_>> {
        self.budgets
            .iter()
            .map(|b| BudgetIn {
                id: &b.id,
                period: &b.period,
                group: b.group.as_deref(),
                pool: b.pool.as_deref(),
                remaining_micros: b.remaining_micros,
                spend_micros_at_current_rate: b.spend_micros_at_current_rate,
                window_start_s: b.window_start_s,
            })
            .collect()
    }
}

/// How one port call ended, before it is lowered into the kernel's frame.
enum Called {
    Answer(HookAnswer),
    /// The plugin answered FAILED or REFUSED: the operator's `on_error` decides.
    Failed(String),
    /// The call itself broke (a FAULT, a closed instance): no answer can be had.
    Broken(String),
    TimedOut,
}

fn called(name: &str, r: Result<HookAnswer, PortError>) -> Called {
    match r {
        Ok(answer) => Called::Answer(answer),
        Err(PortError::Refused { code, text, .. }) => {
            Called::Failed(format!("hook '{name}' refused ({code}): {text}"))
        }
        Err(PortError::Failed { code, text, .. }) => {
            Called::Failed(format!("hook '{name}' failed ({code}): {text}"))
        }
        Err(PortError::Call(call)) => Called::Broken(format!("hook '{name}' broke: {call:?}")),
    }
}

/// Build the view from `owned` and call `port.on(point, view)`; a sync answer returns at once, an
/// `on_io` answer is awaited within `budget`. The view's parts are locals of this future, so the
/// I/O future's borrows of them live exactly as long as the call.
async fn ask(
    port: &dyn HookPort,
    name: &str,
    point: u32,
    owned: &Owned,
    budget: Duration,
) -> Called {
    let cx = CallCx {
        deadline: Instant::now() + budget,
        request_id: 0,
        stack: CallStack::default(),
    };
    let signals = owned.signal_refs();
    let tags = owned.tag_refs();
    let candidates = owned.candidate_refs(&tags);
    let budgets = owned.budget_refs();
    let view = HookView {
        signals: &signals,
        candidates: &candidates,
        budgets: &budgets,
        conversation: owned.conversation.as_deref(),
        body: owned.body.as_deref(),
        identity: None,
    };
    let out = match port.on(cx, point, &view) {
        HookCall::Done(r) => called(name, r),
        HookCall::Io(fut) => match tokio::time::timeout(budget, fut).await {
            Ok(r) => called(name, r),
            Err(_) => Called::TimedOut,
        },
    };
    out
}

fn indices(order: &[u32]) -> Vec<usize> {
    order.iter().map(|&i| i as usize).collect()
}

/// A POINT_ROUTE answer as the kernel's verdict (core clamps and range-checks it afterwards).
fn verdict(name: &str, a: &HookAnswer) -> Verdict {
    match a.verb {
        abi::VERB_ABSTAIN => Verdict::Abstain,
        abi::VERB_PREFER => Verdict::Prefer(indices(&a.order)),
        abi::VERB_PRIORITIZE => Verdict::Prioritize(indices(&a.order)),
        abi::VERB_RESTRICT => Verdict::Restrict(a.restrict.iter().map(|t| t.to_string()).collect()),
        abi::VERB_REJECT => Verdict::Reject {
            status: a.reject_status,
            message: a.message.as_deref().unwrap_or_default().to_owned(),
        },
        verb => Verdict::Failed(format!("hook '{name}' answered verb {verb} at POINT_ROUTE")),
    }
}

/// A POINT_REWRITE answer as the kernel's rewrite verdict. REWRITE carries the generic
/// CONVERSATION JSON shape (IF §8.4), handed on unchanged.
fn rewrite_verdict(name: &str, a: &HookAnswer) -> RewriteVerdict {
    match a.verb {
        abi::VERB_ABSTAIN => RewriteVerdict::Abstain,
        abi::VERB_REWRITE => match a.rewrite.as_ref() {
            Some(body) => RewriteVerdict::Rewrite(body.clone()),
            None => RewriteVerdict::Failed(format!("hook '{name}' answered REWRITE with no body")),
        },
        abi::VERB_REJECT => RewriteVerdict::Reject {
            status: a.reject_status,
            message: a.message.as_deref().unwrap_or_default().to_owned(),
        },
        verb => RewriteVerdict::Failed(format!(
            "hook '{name}' answered verb {verb} at POINT_REWRITE"
        )),
    }
}

fn decide_short(out: &DecideOut) -> bool {
    out.order_needed != 0 || out.reject_message_needed != 0 || out.restrict_tags_needed != 0
}

fn transform_short(out: &TransformOut) -> bool {
    out.reject_message_needed != 0 || out.rewrite_needed != 0
}

/// Lower `v` into `frame`'s host buffers, regrowing them once when the answer did not fit.
fn lower_decide(
    name: &str,
    frame: Arc<DecideFrame>,
    v: &Verdict,
    error: Option<String>,
) -> Answered<DecideOut> {
    let (outcome, out) = frame.answer_decide(v);
    if outcome == Outcome::Failed && decide_short(&out) {
        let grown = frame.regrown_decide(&out);
        let (outcome, out) = grown.answer_decide(v);
        if outcome == Outcome::Failed && decide_short(&out) {
            return Answered::Broken(format!(
                "hook '{name}': its answer does not fit after the re-call"
            ));
        }
        return Answered::Answer {
            outcome,
            out,
            error,
            frame: grown,
        };
    }
    Answered::Answer {
        outcome,
        out,
        error,
        frame,
    }
}

fn lower_transform(
    name: &str,
    frame: Arc<DecideFrame>,
    v: &RewriteVerdict,
    error: Option<String>,
) -> Answered<TransformOut> {
    let (outcome, out) = frame.answer_transform(v);
    if outcome == Outcome::Failed && transform_short(&out) {
        let grown = frame.regrown_transform(&out);
        let (outcome, out) = grown.answer_transform(v);
        if outcome == Outcome::Failed && transform_short(&out) {
            return Answered::Broken(format!(
                "hook '{name}': its answer does not fit after the re-call"
            ));
        }
        return Answered::Answer {
            outcome,
            out,
            error,
            frame: grown,
        };
    }
    Answered::Answer {
        outcome,
        out,
        error,
        frame,
    }
}

impl HookCalls for PortHook {
    fn name(&self) -> &str {
        &self.name
    }

    fn decide(&self, frame: Arc<DecideFrame>, budget: Duration) -> Pending<Answered<DecideOut>> {
        let port = Arc::clone(&self.port);
        let name = self.name.clone();
        let serves = self.serves(abi::POINT_ROUTE);
        Box::pin(async move {
            if !serves {
                return lower_decide(&name, frame, &Verdict::Abstain, None);
            }
            let owned = frame.decoded(|d| Owned::decide(d, port.facts()));
            match ask(&*port, &name, abi::POINT_ROUTE, &owned, budget).await {
                Called::Answer(a) => lower_decide(&name, frame, &verdict(&name, &a), None),
                Called::Failed(text) => {
                    lower_decide(&name, frame, &Verdict::Failed(text.clone()), Some(text))
                }
                Called::Broken(text) => Answered::Broken(text),
                Called::TimedOut => Answered::TimedOut,
            }
        })
    }

    fn transform(
        &self,
        frame: Arc<DecideFrame>,
        budget: Duration,
    ) -> Pending<Answered<TransformOut>> {
        let port = Arc::clone(&self.port);
        let name = self.name.clone();
        let serves = self.serves(abi::POINT_REWRITE);
        Box::pin(async move {
            if !serves {
                return lower_transform(&name, frame, &RewriteVerdict::Abstain, None);
            }
            let owned = frame.decoded(|d| Owned::decide(d, port.facts()));
            match ask(&*port, &name, abi::POINT_REWRITE, &owned, budget).await {
                Called::Answer(a) => {
                    lower_transform(&name, frame, &rewrite_verdict(&name, &a), None)
                }
                Called::Failed(text) => lower_transform(
                    &name,
                    frame,
                    &RewriteVerdict::Failed(text.clone()),
                    Some(text),
                ),
                Called::Broken(text) => Answered::Broken(text),
                Called::TimedOut => Answered::TimedOut,
            }
        })
    }

    fn notify(&self, frame: Arc<NotifyFrame>, budget: Duration) -> Pending<()> {
        let port = Arc::clone(&self.port);
        let name = self.name.clone();
        let serves = self.serves(abi::POINT_NOTIFY);
        Box::pin(async move {
            if !serves {
                return;
            }
            let owned = Owned::notify(&frame);
            // Fire-and-forget: at POINT_NOTIFY only METRIC is read, and core keeps the series.
            let _ = ask(&*port, &name, abi::POINT_NOTIFY, &owned, budget).await;
        })
    }

    fn configure(
        &self,
        _name: &str,
        _settings: &ResolvedSettings,
        _version: u64,
        _budget: Duration,
    ) -> Pending<Result<(), String>> {
        Box::pin(async { Err(CONFIGURE_IS_RECONFIGURE.to_owned()) })
    }

    fn status(&self, _budget: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(async { None })
    }

    fn describe(&self, _budget: Duration) -> Pending<Option<Vec<u8>>> {
        Box::pin(async { None })
    }
}

#[cfg(test)]
#[path = "../tests/hook_port_tests.rs"]
mod tests;
