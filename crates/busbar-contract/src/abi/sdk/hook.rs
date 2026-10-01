// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S SDK: a hook plugin over the hook kind's door (`abi::hook`), written against
//! typed views ([`Hook`]) or against the 1.5.5 JSON contract ([`HookHandler`], through
//! [`json_hook`]). [`hook_door!`](crate::hook_door) emits the door; every slot is the SDK's own.
//!
//! * [`Decoded`] — a `decide`/`transform` `in` read as a view borrowed from the host's `in` for
//!   the call (text and the prompt body zero-copy), and
//!   [`Decoded::projection_json`], the 1.5.5 wire JSON rebuilt byte for byte from it
//!   (`crate::hook_wire::build`, the same function the host once ran).
//! * [`DecodedTap`] — a `notify` `in`, and its 1.5.5 notify JSON.
//! * [`Verdict`] / [`RewriteVerdict`] — what `decide` / `transform` answer, lowered into the fixed
//!   `out` and the host's buffers by [`write_verdict`] / [`write_rewrite`], with the one
//!   short-buffer answer when a buffer is too small (nothing written, every `*_needed` stated).
//! * [`lower_decide_reply`] / [`lower_transform_reply`] — a 1.5.5 JSON reply lowered to a verdict,
//!   exactly as 1.5.5's host normalized it (reject > restrict > abstain > order; a reply that does not
//!   parse is FAILED). The host keeps the rest of 1.5.5's normalizing: the status clamp, the
//!   message sanitiser and cap, dropping an `idx` the candidates do not hold, the rewrite parse.
//!
//! Built ON the SDK's safe layer (SDK-SAFE, ARCHITECT ruling 366) and its generic lifecycle
//! (`abi::sdk::life`): every op is a [`SafeSlot`] over `Held<HookLife<P>>`, every read goes through
//! [`Lent`], every host buffer is a [`HostBuf`](crate::abi::sdk::HostBuf). This module adds only
//! the hook kind's own pieces.
//!
//! A hook that waits on the far end answers [`Poll::Pending`] from `decide`, `transform` or
//! `notify` while its one exchange ([`Op::exchange`]) pends: the op answers PENDING and the host
//! re-enters it on the wake, exactly as every other kind's ops (THE DESIGN, the plugin ABI: every
//! call is Ready or Pending(wake)).

use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::Poll;

use crate::abi::hook::validate::{check_notify_in, check_prompt_view};
use crate::abi::hook::{
    cancel, ConfigureIn, ConfigureOut, DecideIn, DecideOut, DescribeOut, NotifyIn, PromptView,
    ServeIn, ServeOut, SignalEntry, StatusOut, Tail, TransformOut, BUDGET_HAS_REMAINING_MICROS,
    CANDIDATE_HAS_BUDGET_REMAINING, CANDIDATE_HAS_CONTEXT_MAX, CANDIDATE_HAS_COST_PER_MTOK,
    CANDIDATE_HAS_LATENCY_MS, CANDIDATE_HAS_RATE_HEADROOM, CANDIDATE_HAS_TIER,
    REQUEST_HAS_MAX_TOKENS, REQUEST_HAS_TOOLS, REQUEST_STREAM, SIGNAL_TAG_BOOL, SIGNAL_TAG_F64,
    SIGNAL_TAG_I64, SIGNAL_TAG_STR, SIGNAL_TAG_U64, STAGE_AT_CANDIDATE, STAGE_AT_ROUTING,
    STAGE_HAS_ATTEMPT_NUMBER, STAGE_HAS_MODEL, STAGE_HAS_OUTCOME, STAGE_HAS_PREVIOUS_FAILURE,
    STAGE_HAS_PROJECTION, STAGE_HAS_REMAINING_CANDIDATES, STAGE_HAS_STATUS, VERB_ABSTAIN,
    VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
    VIEW_HAS_BUDGET_REMAINING, VIEW_HAS_PROMPT, VIEW_HAS_USER,
};
use crate::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome, BLOB_ABSENT, BLOB_JSON};
use crate::abi::mechanism::door::{KindTailHead, Statement};
use crate::abi::sdk::exchange::Op;
use crate::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use crate::abi::sdk::{HookHandler, Instance, Lent, LentList, Out, SafeSlot};
use crate::hook_wire::{HookStageProjection, OP_DECIDE, OP_NOTIFY, OP_TRANSFORM};
use crate::hooks::{
    BudgetBucketState, CallerIdentity, Candidate, PromptProjection, RoutingContext, RoutingRequest,
};
use crate::signal::{Signal, SignalBag, SignalValue};

// ── reading the host's views ─────────────────────────────────────────────────────────────────────
//
// Every read goes through the SDK's safe layer (`abi::sdk::lent`, SDK-SAFE): the `in` is a [`Lent`],
// its lists are [`LentList`]s and its strings and blobs are borrowed from the host for the call.
// The one piece the layer cannot state generically is the tagged signal union, read here.

/// A NULL string is absent; a present one is BORROWED from the host's view (lossily UTF-8: a copy
/// only when the bytes are not valid UTF-8).
fn text(s: Lent<'_, AbiStr>) -> Option<Cow<'_, str>> {
    (!s.ptr.is_null()).then(|| String::from_utf8_lossy(s.bytes()))
}

fn text_or_empty(s: Lent<'_, AbiStr>) -> Cow<'_, str> {
    text(s).unwrap_or(Cow::Borrowed(""))
}

/// One signal's value, by its tag; `None` for a tag outside the vocabulary.
fn signal_value(e: Lent<'_, SignalEntry>) -> Option<SignalValue> {
    let v = &e.get().value;
    // SAFETY: `tag` names the union's live field (the host writes the tag with the value, and
    // `check_*` rejects no tag here: an unknown tag is skipped, never read).
    Some(unsafe {
        match e.tag {
            SIGNAL_TAG_U64 => SignalValue::U64(v.u64_),
            SIGNAL_TAG_I64 => SignalValue::I64(v.i64_),
            SIGNAL_TAG_F64 => SignalValue::F64(v.f64_),
            SIGNAL_TAG_BOOL => SignalValue::Bool(v.boolean != 0),
            SIGNAL_TAG_STR => SignalValue::Str(Cow::Owned(
                text(Lent::new(&v.str_))
                    .map(Cow::into_owned)
                    .unwrap_or_default(),
            )),
            _ => return None,
        }
    })
}

fn bag(list: LentList<'_, SignalEntry>) -> SignalBag {
    let mut b = SignalBag::new();
    for e in list.iter() {
        if let (Some(sig), Some(v)) = (Signal::ALL.get(e.id as usize).copied(), signal_value(e)) {
            b.push(sig, v);
        }
    }
    b
}

/// The prompt a view carries, BORROWED from the host's view for the call: its system text, its
/// `(role, text)` messages and the raw origin-dialect body (zero-copy: the slice the host lent).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Prompt<'a> {
    /// The system text; `None` = none.
    pub system: Option<Cow<'a, str>>,
    /// Every message, `(role, text)`, in order.
    pub messages: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    /// The raw request body the host lent (`PromptView::body`); `None` when absent.
    pub body: Option<&'a [u8]>,
}

fn prompt(v: Lent<'_, PromptView>) -> Prompt<'_> {
    let body = v.field(|p| &p.body);
    Prompt {
        system: text(v.field(|p| &p.system)),
        messages: v
            .messages()
            .iter()
            .map(|m| {
                (
                    text_or_empty(m.field(|m| &m.role)),
                    text_or_empty(m.field(|m| &m.text)),
                )
            })
            .collect(),
        body: (!body.ptr.is_null() && body.fmt != BLOB_ABSENT).then(|| body.bytes()),
    }
}

/// The caller identity a view carries (OLD `CallerIdentity`), borrowed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct User<'a> {
    /// The key id.
    pub key_id: Option<Cow<'a, str>>,
    /// The key name.
    pub key_name: Option<Cow<'a, str>>,
    /// The end user.
    pub user: Option<Cow<'a, str>>,
}

/// One budget bucket of a view (OLD `BudgetBucketState`), borrowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket<'a> {
    /// The bucket id.
    pub bucket_id: Cow<'a, str>,
    /// The budget group.
    pub budget_group: Option<Cow<'a, str>>,
    /// The pool.
    pub pool: Option<Cow<'a, str>>,
    /// Spend at the current rate, in micros.
    pub spend_micros_at_current_rate: i64,
    /// What remains, in micros, if capped.
    pub remaining_micros: Option<i64>,
    /// The window start.
    pub window_start: u64,
    /// The budget period.
    pub budget_period: Cow<'a, str>,
}

/// One candidate of a [`Decoded`] view (the OLD `Candidate`), borrowed.
#[derive(Debug, Clone)]
pub struct DecodedCandidate<'a> {
    /// The `idx` an `order` answer names.
    pub idx: usize,
    /// The model.
    pub model: Cow<'a, str>,
    /// The provider.
    pub provider: Cow<'a, str>,
    /// The configured weight.
    pub weight: u32,
    /// The context window, if declared.
    pub context_max: Option<usize>,
    /// The tier, if declared.
    pub tier: Option<Cow<'a, str>>,
    /// The operator-declared price per million tokens, if declared.
    pub cost_per_mtok: Option<f64>,
    /// The operator tags.
    pub tags: Vec<Cow<'a, str>>,
    /// The rolling latency, once measured.
    pub latency_ms: Option<f64>,
    /// Free concurrency permits.
    pub available_concurrency: usize,
    /// The lane's remaining request budget, if capped.
    pub budget_remaining: Option<i64>,
    /// The rate headroom, if a rate limit applies.
    pub rate_headroom: Option<f64>,
    /// The candidate's declared signals, in push order.
    pub signals: SignalBag,
}

/// A `decide`/`transform` `in`, read as a view BORROWED from the host's `in` for the call (the
/// OLD `RoutingRequest`, candidates and `RoutingContext`): text and the prompt body are the host's
/// own bytes, never copied (the hooks law: memory ABI, body zero-copy).
#[derive(Debug, Clone)]
pub struct Decoded<'a> {
    /// The request id.
    pub request_id: u64,
    /// The pool.
    pub pool: Cow<'a, str>,
    /// The ingress dialect (1.5.5's `ingress_protocol` on the wire).
    pub ingress_dialect: Cow<'a, str>,
    /// The message count.
    pub message_count: u64,
    /// The total text size, in characters.
    pub total_chars: u64,
    /// `max_tokens`, if the request set it.
    pub max_tokens: Option<u32>,
    /// Whether the request declares tools.
    pub has_tools: bool,
    /// Whether the request streams.
    pub stream: bool,
    /// The request's declared signals, in push order.
    pub signals: SignalBag,
    /// The prompt, under a `prompt: ro|rw` grant.
    pub prompt: Option<Prompt<'a>>,
    /// The caller identity, under a `user: ro` grant.
    pub user: Option<User<'a>>,
    /// The candidates, in order.
    pub candidates: Vec<DecodedCandidate<'a>>,
    /// The pool's remaining request budget, if capped.
    pub budget_remaining: Option<i64>,
    /// The request's budget chain, innermost first.
    pub budget: Vec<Bucket<'a>>,
}

impl<'a> Decoded<'a> {
    /// Read `input`, borrowing it for the call.
    #[must_use]
    pub fn of(input: Lent<'a, DecideIn>) -> Self {
        let r = input.field(|i| &i.request);
        let candidates = input
            .candidates()
            .iter()
            .zip(input.candidate_dynamics().iter())
            .map(|(s, d)| DecodedCandidate {
                idx: s.idx as usize,
                model: text_or_empty(s.field(|s| &s.model)),
                provider: text_or_empty(s.field(|s| &s.provider)),
                weight: s.weight,
                context_max: (s.present & CANDIDATE_HAS_CONTEXT_MAX != 0)
                    .then_some(s.context_max as usize),
                tier: if s.present & CANDIDATE_HAS_TIER != 0 {
                    text(s.field(|s| &s.tier))
                } else {
                    None
                },
                cost_per_mtok: (s.present & CANDIDATE_HAS_COST_PER_MTOK != 0)
                    .then_some(s.cost_per_mtok),
                tags: s.tags().iter().map(text_or_empty).collect(),
                latency_ms: (d.present & CANDIDATE_HAS_LATENCY_MS != 0).then_some(d.latency_ms),
                available_concurrency: d.available_concurrency as usize,
                budget_remaining: (d.present & CANDIDATE_HAS_BUDGET_REMAINING != 0)
                    .then_some(d.budget_remaining),
                rate_headroom: (d.present & CANDIDATE_HAS_RATE_HEADROOM != 0)
                    .then_some(d.rate_headroom),
                signals: bag(d.signals()),
            })
            .collect();
        let user = input.field(|i| &i.user);
        Self {
            request_id: r.request_id,
            pool: text_or_empty(r.field(|r| &r.pool)),
            ingress_dialect: text_or_empty(r.field(|r| &r.ingress_dialect)),
            message_count: r.message_count,
            total_chars: r.total_chars,
            max_tokens: (r.flags & REQUEST_HAS_MAX_TOKENS != 0).then_some(r.max_tokens),
            has_tools: r.flags & REQUEST_HAS_TOOLS != 0,
            stream: r.flags & REQUEST_STREAM != 0,
            signals: bag(r.signals()),
            prompt: (input.present & VIEW_HAS_PROMPT != 0)
                .then(|| prompt(input.field(|i| &i.prompt))),
            user: (input.present & VIEW_HAS_USER != 0).then(|| User {
                key_id: text(user.field(|u| &u.key_id)),
                key_name: text(user.field(|u| &u.key_name)),
                user: text(user.field(|u| &u.user)),
            }),
            candidates,
            budget_remaining: (input.present & VIEW_HAS_BUDGET_REMAINING != 0)
                .then_some(input.budget_remaining),
            budget: input
                .budget()
                .iter()
                .map(|b| Bucket {
                    bucket_id: text_or_empty(b.field(|b| &b.bucket_id)),
                    budget_group: text(b.field(|b| &b.budget_group)),
                    pool: text(b.field(|b| &b.pool)),
                    spend_micros_at_current_rate: b.spend_micros_at_current_rate,
                    remaining_micros: (b.present & BUDGET_HAS_REMAINING_MICROS != 0)
                        .then_some(b.remaining_micros),
                    window_start: b.window_start,
                    budget_period: text_or_empty(b.field(|b| &b.budget_period)),
                })
                .collect(),
        }
    }

    /// The request as the OLD projection types, borrowing this view (the 1.5.5 JSON path only).
    fn request(&self) -> RoutingRequest<'_> {
        RoutingRequest {
            request_id: self.request_id,
            pool: &self.pool,
            ingress_protocol: &self.ingress_dialect,
            requested_model: None,
            message_count: self.message_count as usize,
            tool_count: 0,
            has_tools: self.has_tools,
            total_chars: self.total_chars as usize,
            system_chars: 0,
            max_tokens: self.max_tokens,
            stream: self.stream,
            prompt: self.prompt.as_ref().map(|p| PromptProjection {
                system: p.system.as_deref().map(Cow::Borrowed),
                messages: p
                    .messages
                    .iter()
                    .map(|(r, t)| (Cow::Borrowed(&**r), Cow::Borrowed(&**t)))
                    .collect(),
            }),
            identity: self.user.as_ref().map(|u| CallerIdentity {
                key_id: u.key_id.as_deref().map(str::to_string),
                key_name: u.key_name.as_deref().map(str::to_string),
                user: u.user.as_deref().map(str::to_string),
            }),
            signals: self.signals.clone(),
        }
    }

    fn candidates(&self) -> Vec<Candidate<'_>> {
        self.candidates
            .iter()
            .map(|c| Candidate {
                idx: c.idx,
                model: &c.model,
                provider: &c.provider,
                weight: c.weight,
                context_max: c.context_max,
                tier: c.tier.as_deref(),
                cost_per_mtok: c.cost_per_mtok,
                tags: &[],
                latency_ms: c.latency_ms,
                available_concurrency: c.available_concurrency,
                budget_remaining: c.budget_remaining,
                rate_headroom: c.rate_headroom,
                signals: c.signals.clone(),
            })
            .collect()
    }

    /// THE 1.5.5 PROJECTION: the JSON 1.5.5's host handed a hook for `op` (`decide` or
    /// `transform`), rebuilt byte for byte from this view. (The JSON contract is a copy by
    /// definition; a typed [`Hook`] never pays it.)
    #[must_use]
    pub fn projection_json(&self, op: &'static str) -> serde_json::Value {
        let req = self.request();
        let tags: Vec<Vec<String>> = self
            .candidates
            .iter()
            .map(|c| c.tags.iter().map(|t| t.to_string()).collect())
            .collect();
        let mut cands = self.candidates();
        for (c, t) in cands.iter_mut().zip(&tags) {
            c.tags = t;
        }
        let budget: Vec<BudgetBucketState> = self
            .budget
            .iter()
            .map(|b| BudgetBucketState {
                bucket_id: b.bucket_id.to_string(),
                budget_group: b.budget_group.as_deref().map(str::to_string),
                pool: b.pool.as_deref().map(str::to_string),
                spend_micros_at_current_rate: b.spend_micros_at_current_rate,
                remaining_micros: b.remaining_micros,
                window_start: b.window_start,
                budget_period: b.budget_period.to_string(),
            })
            .collect();
        let ctx = RoutingContext {
            pool: &self.pool,
            budget_remaining: self.budget_remaining,
            budget: &budget,
        };
        serde_json::to_value(crate::hook_wire::build(op, &req, &cands, &ctx))
            .unwrap_or_else(|_| serde_json::json!({}))
    }
}

/// The stage a [`DecodedTap`] observed (the OLD `HookStageProjection`), borrowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage<'a> {
    /// `candidate` | `routing` | `response`.
    pub at: &'static str,
    /// The dispatched model.
    pub model: Option<Cow<'a, str>>,
    /// The attempt number.
    pub attempt_number: Option<u32>,
    /// The candidates remaining.
    pub remaining_candidates: Option<usize>,
    /// Why the previous attempt failed.
    pub previous_failure: Option<Cow<'a, str>>,
    /// `ok` | `failed` | `rejected_by_gate`.
    pub outcome: Option<Cow<'a, str>>,
    /// The response status.
    pub status: Option<u16>,
}

/// A `notify` `in`, read as a view borrowed from the host's `in` for the call.
#[derive(Debug, Clone)]
pub struct DecodedTap<'a> {
    /// The request's shape, signals and (under the tap's `prompt: ro` grant) prompt; no
    /// candidates and no budget, as 1.5.5's taps had none.
    pub request: Decoded<'a>,
    /// The stage; `None` for a request-stage tap.
    pub stage: Option<Stage<'a>>,
}

impl<'a> DecodedTap<'a> {
    /// Read `input`, borrowing it for the call.
    #[must_use]
    pub fn of(input: Lent<'a, NotifyIn>) -> Self {
        let s = input.field(|i| &i.stage);
        let has = |bit: u32| s.stage_present & bit != 0;
        let opt = |bit: u32, f: Lent<'a, AbiStr>| if has(bit) { text(f) } else { None };
        let stage = has(STAGE_HAS_PROJECTION).then(|| Stage {
            at: match s.at {
                STAGE_AT_CANDIDATE => "candidate",
                STAGE_AT_ROUTING => "routing",
                _ => "response",
            },
            model: opt(STAGE_HAS_MODEL, s.field(|s| &s.model)),
            attempt_number: has(STAGE_HAS_ATTEMPT_NUMBER).then_some(s.attempt_number),
            remaining_candidates: has(STAGE_HAS_REMAINING_CANDIDATES)
                .then_some(s.remaining_candidates as usize),
            previous_failure: opt(STAGE_HAS_PREVIOUS_FAILURE, s.field(|s| &s.previous_failure)),
            outcome: opt(STAGE_HAS_OUTCOME, s.field(|s| &s.outcome)),
            status: has(STAGE_HAS_STATUS).then_some(s.status),
        });
        Self {
            request: Decoded {
                request_id: s.request_id,
                pool: text_or_empty(s.field(|s| &s.pool)),
                ingress_dialect: text_or_empty(s.field(|s| &s.ingress_dialect)),
                message_count: s.message_count,
                total_chars: s.total_chars,
                max_tokens: (s.flags & REQUEST_HAS_MAX_TOKENS != 0).then_some(s.max_tokens),
                has_tools: s.flags & REQUEST_HAS_TOOLS != 0,
                stream: s.flags & REQUEST_STREAM != 0,
                signals: bag(input.signals()),
                prompt: (input.present & VIEW_HAS_PROMPT != 0)
                    .then(|| prompt(input.field(|i| &i.prompt))),
                user: None,
                candidates: Vec::new(),
                budget_remaining: None,
                budget: Vec::new(),
            },
            stage,
        }
    }

    /// THE 1.5.5 NOTIFY PROJECTION, rebuilt byte for byte.
    #[must_use]
    pub fn projection_json(&self) -> serde_json::Value {
        let req = self.request.request();
        let ctx = RoutingContext {
            pool: &self.request.pool,
            budget_remaining: None,
            budget: &[],
        };
        let mut wire = crate::hook_wire::build(OP_NOTIFY, &req, &[], &ctx);
        wire.stage = self.stage.as_ref().map(|s| HookStageProjection {
            at: s.at,
            model: s.model.as_deref(),
            attempt_number: s.attempt_number,
            remaining_candidates: s.remaining_candidates,
            previous_failure: s.previous_failure.as_deref(),
            outcome: s.outcome.as_deref(),
            status: s.status,
        });
        serde_json::to_value(wire).unwrap_or_else(|_| serde_json::json!({}))
    }
}

// ── answering ────────────────────────────────────────────────────────────────────────────────────

/// What `decide` answers (the OLD `RoutingDecision`, before the host's normalizing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Prefer this order of candidate `idx`es (the host drops unknown ones and duplicates; an
    /// order that keeps none is an abstain).
    Prefer(Vec<usize>),
    /// No opinion.
    Abstain,
    /// Refuse the request. `status` is the hook's own opinion (the host clamps it to 400-499, and
    /// `None` answers 403); the host sanitises and caps `message`.
    Reject {
        /// The status, if the hook stated one that fits a `u16`.
        status: Option<u16>,
        /// The message.
        message: String,
    },
    /// Narrow to candidates carrying any of these tags (empty = the gate's `on_empty`).
    Restrict(Vec<String>),
    /// The hook could not answer (the operator's `on_error` decides).
    Failed(String),
}

/// What `transform` answers (the OLD `TransformOutcome`, before the host's normalizing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RewriteVerdict {
    /// Rewrite the request: the 1.5.5 rewrite JSON (`{"messages": [...], "tools"?: [...]}`) as
    /// bytes; the host parses it fail-closed.
    Rewrite(Vec<u8>),
    /// No change.
    Abstain,
    /// Refuse the request, as [`Verdict::Reject`].
    Reject {
        /// The status, if stated.
        status: Option<u16>,
        /// The message.
        message: String,
    },
    /// The hook could not answer.
    Failed(String),
}

/// Lower `v` into `out` and the host buffers `input` lends ([`HostBuf`](crate::abi::sdk::HostBuf)). A buffer too small answers
/// the ONE short FAILED: every dimension's `*_needed` its full size, nothing counted as written.
pub fn write_verdict(v: &Verdict, input: Lent<'_, DecideIn>, out: &mut DecideOut) -> Outcome {
    let mut order = input.order_buf();
    let mut reject = input.reject_message_buf();
    let mut tags = input.restrict_tags_buf();
    match v {
        Verdict::Prefer(o) => {
            for i in o {
                if let Ok(i) = u32::try_from(*i) {
                    order.push(i);
                }
            }
        }
        Verdict::Reject { message, .. } => {
            reject.extend(message.as_bytes());
        }
        Verdict::Restrict(t) => {
            tags.extend(t.join("\0").as_bytes());
        }
        Verdict::Abstain | Verdict::Failed(_) => {}
    }
    let short = !(order.fits() && reject.fits() && tags.fits());
    (out.order_written, out.order_needed) = order.settle(short);
    (out.reject_message_written, out.reject_message_needed) = reject.settle(short);
    (out.restrict_tags_written, out.restrict_tags_needed) = tags.settle(short);
    if short {
        return Outcome::Failed;
    }
    match v {
        Verdict::Prefer(_) if order.asked() == 0 => out.verbs = VERB_ABSTAIN,
        Verdict::Prefer(_) => out.verbs = VERB_PREFER,
        Verdict::Abstain => out.verbs = VERB_ABSTAIN,
        Verdict::Reject { status, .. } => {
            out.verbs = VERB_REJECT;
            if let Some(s) = status {
                out.verbs |= VERB_HAS_REJECT_STATUS;
                out.reject_status = *s;
            }
        }
        Verdict::Restrict(_) => out.verbs = VERB_RESTRICT,
        Verdict::Failed(_) => return Outcome::Failed,
    }
    Outcome::Ready
}

/// [`write_verdict`]'s `transform` twin.
pub fn write_rewrite(
    v: &RewriteVerdict,
    input: Lent<'_, DecideIn>,
    out: &mut TransformOut,
) -> Outcome {
    let mut reject = input.reject_message_buf();
    let mut rewrite = input.rewrite_buf();
    match v {
        RewriteVerdict::Rewrite(b) => {
            rewrite.extend(b);
        }
        RewriteVerdict::Reject { message, .. } => {
            reject.extend(message.as_bytes());
        }
        RewriteVerdict::Abstain | RewriteVerdict::Failed(_) => {}
    }
    let short = !(reject.fits() && rewrite.fits());
    (out.reject_message_written, out.reject_message_needed) = reject.settle(short);
    (out.rewrite_written, out.rewrite_needed) = rewrite.settle(short);
    if short {
        return Outcome::Failed;
    }
    match v {
        RewriteVerdict::Rewrite(_) => out.verbs = VERB_REWRITE,
        RewriteVerdict::Abstain => out.verbs = VERB_ABSTAIN,
        RewriteVerdict::Reject { status, .. } => {
            out.verbs = VERB_REJECT;
            if let Some(s) = status {
                out.verbs |= VERB_HAS_REJECT_STATUS;
                out.reject_status = *s;
            }
        }
        RewriteVerdict::Failed(_) => return Outcome::Failed,
    }
    Outcome::Ready
}

/// The 1.5.5 reply's typed fields: a wrong type in any of them fails the whole parse (FAILED),
/// exactly as 1.5.5's host read it.
#[derive(serde::Deserialize, Default)]
struct Reply155 {
    #[serde(default)]
    order: Option<Vec<usize>>,
    #[serde(default)]
    abstain: bool,
    #[serde(default)]
    reject: Option<serde_json::Value>,
    #[serde(default)]
    restrict: Option<serde_json::Value>,
    #[serde(default)]
    rewrite: Option<serde_json::Value>,
}

/// A reject's status as the hook stated it: an integer that fits a `u16`, else none (the host then
/// answers 403, as 1.5.5 did for anything out of shape).
fn reject_of(r: &serde_json::Value) -> (Option<u16>, String) {
    let status = r
        .get("status")
        .and_then(serde_json::Value::as_i64)
        .and_then(|s| u16::try_from(s).ok());
    let message = r
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_string();
    (status, message)
}

/// A present reply verb: anything but an explicit `false` (JSON `null` reads as absent).
fn verb(v: &Option<serde_json::Value>) -> Option<&serde_json::Value> {
    v.as_ref().filter(|v| **v != serde_json::Value::Bool(false))
}

/// LOWER A 1.5.5 `decide` REPLY: reject > restrict > abstain > order; a reply whose typed fields
/// do not parse is FAILED; a malformed restrict restricts to nothing (the gate's `on_empty`).
#[must_use]
pub fn lower_decide_reply(reply: Result<serde_json::Value, String>) -> Verdict {
    let v = match reply {
        Ok(v) => v,
        Err(message) => return Verdict::Failed(message),
    };
    let parsed: Reply155 = match serde_json::from_value(v) {
        Ok(p) => p,
        Err(e) => return Verdict::Failed(format!("hook decide reply failed to parse: {e}")),
    };
    if let Some(r) = verb(&parsed.reject) {
        let (status, message) = reject_of(r);
        return Verdict::Reject { status, message };
    }
    if let Some(r) = verb(&parsed.restrict) {
        return Verdict::Restrict(
            crate::hook_wire::parse_restrict(r)
                .map(|r| r.tags_any)
                .unwrap_or_default(),
        );
    }
    if parsed.abstain {
        return Verdict::Abstain;
    }
    match parsed.order {
        Some(o) => Verdict::Prefer(o),
        None => Verdict::Abstain,
    }
}

/// LOWER A 1.5.5 `transform` REPLY: reject > rewrite > abstain; a reply that does not parse is
/// FAILED. The rewrite crosses as its JSON bytes; the host parses it fail-closed.
#[must_use]
pub fn lower_transform_reply(reply: Result<serde_json::Value, String>) -> RewriteVerdict {
    let v = match reply {
        Ok(v) => v,
        Err(message) => return RewriteVerdict::Failed(message),
    };
    let parsed: Reply155 = match serde_json::from_value(v) {
        Ok(p) => p,
        Err(e) => {
            return RewriteVerdict::Failed(format!("hook transform reply failed to parse: {e}"))
        }
    };
    if let Some(r) = verb(&parsed.reject) {
        let (status, message) = reject_of(r);
        return RewriteVerdict::Reject { status, message };
    }
    match parsed.rewrite {
        Some(rw) => RewriteVerdict::Rewrite(serde_json::to_vec(&rw).unwrap_or_default()),
        None => RewriteVerdict::Abstain,
    }
}

// ── the plugin ───────────────────────────────────────────────────────────────────────────────────

/// A hook plugin, over typed views: the SDK reads the host's `in` (after the kind's own checks on
/// it) as views BORROWED from the host for the call ([`Decoded`], [`DecodedTap`]; text and the
/// prompt body zero-copy), so a plugin never touches a host pointer and stays
/// `forbid(unsafe_code)`.
/// Every op has a default: the safe "no opinion" / "unsupported" answer.
///
/// `decide`, `transform` and `notify` are handed their [`Op`]: a hook that asks the far end makes
/// its one [`Op::exchange`] and answers [`Poll::Pending`] while it pends; the host re-enters the op
/// on the wake and the method runs again from the top (the exchange resumes where it parked).
pub trait Hook: Send + Sync {
    /// `decide`. Default: abstain.
    fn decide(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
        let _ = (view, op);
        Poll::Ready(Verdict::Abstain)
    }
    /// `transform`. Default: abstain.
    fn transform(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<RewriteVerdict> {
        let _ = (view, op);
        Poll::Ready(RewriteVerdict::Abstain)
    }
    /// `notify`. Default: nothing.
    fn notify(&self, tap: &DecodedTap<'_>, op: &Op<'_>) -> Poll<()> {
        let _ = (tap, op);
        Poll::Ready(())
    }
    /// `configure`: `true` acknowledges the version. Default: acknowledge.
    fn configure(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        version: u64,
    ) -> bool {
        let _ = (settings, version);
        true
    }
    /// `status`: the 1.5.5 status envelope (`{"status": {...}}`, or `{}` = unsupported).
    fn status(&self) -> serde_json::Value {
        serde_json::json!({})
    }
    /// `describe`: the 1.5.5 self-description envelope (`{"schema": ...}`, or `{}`).
    fn describe(&self) -> serde_json::Value {
        serde_json::json!({})
    }
}

/// A 1.5.5 JSON hook ([`HookHandler`]) as a [`Hook`]: each view rebuilt as the 1.5.5 JSON, each
/// reply lowered as the 1.5.5 host normalized it.
pub struct JsonHook(pub Box<dyn HookHandler>);

impl Hook for JsonHook {
    fn decide(&self, view: &Decoded<'_>, _: &Op<'_>) -> Poll<Verdict> {
        Poll::Ready(lower_decide_reply(
            self.0.decide_result(&view.projection_json(OP_DECIDE)),
        ))
    }
    fn transform(&self, view: &Decoded<'_>, _: &Op<'_>) -> Poll<RewriteVerdict> {
        Poll::Ready(lower_transform_reply(
            self.0.transform_result(&view.projection_json(OP_TRANSFORM)),
        ))
    }
    fn notify(&self, tap: &DecodedTap<'_>, _: &Op<'_>) -> Poll<()> {
        self.0.notify(&tap.projection_json());
        Poll::Ready(())
    }
    fn configure(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        version: u64,
    ) -> bool {
        self.0.configure(settings, version)
    }
    fn status(&self) -> serde_json::Value {
        self.0.status()
    }
    fn describe(&self) -> serde_json::Value {
        self.0.describe()
    }
}

/// A 1.5.5 JSON handler as a boxed [`Hook`].
#[must_use]
pub fn json_hook(handler: Box<dyn HookHandler>) -> Box<dyn Hook> {
    Box::new(JsonHook(handler))
}

/// How a plugin opens: its settings (the operator's JSON section, `"{}"` when none) to a [`Hook`].
pub trait HookOpen: 'static {
    /// Open an instance.
    ///
    /// # Errors
    /// Why the settings cannot open one (the operator reads it).
    fn open(settings: &str) -> Result<Box<dyn Hook>, String>;
}

/// The hook kind's Statement tail, for a plugin's `const`: `words` are its declared hook words.
#[must_use]
pub const fn tail(
    kind_class: u32,
    prompt_access: u32,
    user_access: u32,
    words: &'static [AbiStr],
) -> Tail {
    Tail {
        head: KindTailHead {
            size: std::mem::size_of::<Tail>() as u32,
            _reserved: 0,
        },
        kind_class,
        prompt_access,
        user_access,
        infallible: 0,
        _reserved: [0; 3],
        requested_signals: std::ptr::null(),
        requested_signals_len: 0,
        routes: std::ptr::null(),
        routes_len: 0,
        declared_words: if words.is_empty() {
            std::ptr::null()
        } else {
            words.as_ptr()
        },
        declared_words_len: words.len(),
    }
}

/// A Statement over `tail` (see [`crate::abi::sdk::door::statement`]).
#[must_use]
pub const fn statement_with_tail(base: Statement, tail: &'static Tail) -> Statement {
    Statement {
        kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
        ..base
    }
}

// ── the slots ────────────────────────────────────────────────────────────────────────────────────
//
// The lifecycle is the SDK's generic one (`abi::sdk::life`): the instance is `Held<HookLife<P>>`,
// whose leases hold the status/describe blobs and whose `Out::fail` keeps each failure text. What
// is left here is the hook kind's own: the typed hook behind a lock, and its ops, each a
// [`SafeSlot`] over that state.

/// One open hook instance: the hook its settings opened, swapped whole on `refresh`.
pub struct HookLife<P> {
    hook: RwLock<Arc<dyn Hook>>,
    open: PhantomData<fn() -> P>,
}

impl<P> std::fmt::Debug for HookLife<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookLife").finish_non_exhaustive()
    }
}

impl<P> HookLife<P> {
    fn hook(&self) -> Arc<dyn Hook> {
        self.hook
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The settings as text; `"{}"` when absent.
fn settings_text(bytes: &[u8]) -> Cow<'_, str> {
    if bytes.is_empty() {
        return Cow::Borrowed("{}");
    }
    String::from_utf8_lossy(bytes)
}

/// [`HookOpen::open`] over `settings`; its refusal is the plugin's own words.
fn opened<P: HookOpen>(settings: &[u8]) -> Result<Arc<dyn Hook>, Refusal> {
    P::open(&settings_text(settings))
        .map(Arc::<dyn Hook>::from)
        .map_err(Refusal::failed)
}

impl<P: HookOpen> Life for HookLife<P> {
    /// A hook op pends only on its exchange; a cancel aborts it (the SDK drops what it parked).
    const CANCEL: u32 = cancel::ABORTED;

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            hook: RwLock::new(opened::<P>(settings)?),
            open: PhantomData,
        })
    }

    /// Re-open the hook over the new settings; the old one serves until the swap.
    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let hook = opened::<P>(settings)?;
        *self.hook.write().unwrap_or_else(PoisonError::into_inner) = hook;
        Ok(Refreshed::default())
    }
}

/// A hook op: `$in`/`$out` over `Held<HookLife<P>>`, its body handed the held state.
macro_rules! hook_op {
    ($(#[$m:meta])* $name:ident, $in:ty, $out:ty,
     |$held:ident, $i:ident, $input:ident, $o:ident| $body:expr) => {
        $(#[$m])*
        #[derive(Debug)]
        pub struct $name<P>(PhantomData<P>);
        impl<P: HookOpen> SafeSlot for $name<P> {
            type In = $in;
            type Out = $out;
            type State = Held<HookLife<P>>;
            fn call(
                $i: Instance<'_, Held<HookLife<P>>>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome {
                let Some($held) = $i.get() else {
                    return Outcome::Fault;
                };
                $body
            }
        }
    };
}

/// The host's `decide`/`transform` `in` breaks the kind's own reading of it: a present prompt view
/// whose lists do not hold ([`check_prompt_view`]). A host bug: the SDK answers FAULT rather than
/// read it.
fn decide_in_breaks_a_rule(input: &DecideIn) -> bool {
    input.present & VIEW_HAS_PROMPT != 0 && check_prompt_view(&input.prompt).is_err()
}

hook_op!(
    /// `decide`: PENDING while the hook waits on its exchange, re-entered on the wake.
    Decide, DecideIn, DecideOut, |held, i, input, out| {
        if decide_in_breaks_a_rule(&input) {
            return Outcome::Fault;
        }
        let op = Op::new(&i, held.host());
        let Poll::Ready(v) = held.life().hook().decide(&Decoded::of(input), &op) else {
            return Outcome::Pending;
        };
        match (write_verdict(&v, input, out.raw()), v) {
            (Outcome::Failed, Verdict::Failed(m)) => out.fail(Refusal::failed(m)),
            (outcome, _) => outcome,
        }
    }
);

hook_op!(
    /// `transform`: PENDING while the hook waits on its exchange, re-entered on the wake.
    Transform, DecideIn, TransformOut, |held, i, input, out| {
        if decide_in_breaks_a_rule(&input) {
            return Outcome::Fault;
        }
        let op = Op::new(&i, held.host());
        let Poll::Ready(v) = held.life().hook().transform(&Decoded::of(input), &op) else {
            return Outcome::Pending;
        };
        match (write_rewrite(&v, input, out.raw()), v) {
            (Outcome::Failed, RewriteVerdict::Failed(m)) => out.fail(Refusal::failed(m)),
            (outcome, _) => outcome,
        }
    }
);

hook_op!(
    /// `notify`: PENDING while the hook waits on its exchange, re-entered on the wake.
    Notify, NotifyIn, OutHead, |held, i, input, _out| {
        if check_notify_in(&input).is_err() {
            return Outcome::Fault;
        }
        let op = Op::new(&i, held.host());
        match held.life().hook().notify(&DecodedTap::of(input), &op) {
            Poll::Ready(()) => Outcome::Ready,
            Poll::Pending => Outcome::Pending,
        }
    }
);

hook_op!(
    /// `configure`: a nack is FAILED (READY must ack the pushed version).
    Configure, ConfigureIn, ConfigureOut, |held, _i, input, out| {
        let text = settings_text(input.field(|i| &i.settings).bytes());
        let Ok(serde_json::Value::Object(settings)) = serde_json::from_str::<serde_json::Value>(&text) else {
            return out.fail(Refusal::failed("settings: must be a JSON object"));
        };
        if held.life().hook().configure(&settings, input.version) {
            out.set(|o| &o.acked_version, input.version);
            Outcome::Ready
        } else {
            out.fail(Refusal::failed(format!(
                "hook did not acknowledge settings_version {}",
                input.version
            )))
        }
    }
);

hook_op!(
    /// `status`: the 1.5.5 envelope, held under a lease.
    Status, InHead, StatusOut, |held, _i, _input, out| {
        let bytes = serde_json::to_vec(&held.life().hook().status()).unwrap_or_default();
        let o = out.raw();
        o.status = held.leases().blob(&mut o.head, bytes, BLOB_JSON);
        Outcome::Ready
    }
);

hook_op!(
    /// `describe`: the 1.5.5 envelope, held under a lease.
    Describe, InHead, DescribeOut, |held, _i, _input, out| {
        let bytes = serde_json::to_vec(&held.life().hook().describe()).unwrap_or_default();
        let o = out.raw();
        o.describe = held.leases().blob(&mut o.head, bytes, BLOB_JSON);
        Outcome::Ready
    }
);

hook_op!(
    /// `serve`: this SDK declares no routes, so no request reaches it; answers 404.
    Serve, ServeIn, ServeOut, |_held, _i, _input, out| {
        out.raw().status_code = 404;
        Outcome::Ready
    }
);

/// THE HOOK DOOR: a hook plugin's `pub extern "C" fn door()`, every slot the SDK's own (on the
/// safe layer) over the plugin's [`HookOpen`]. Invoked once in the plugin's logic crate.
///
/// ```ignore
/// busbar_contract::hook_door! {
///     open: MyOpen,
///     statement: busbar_contract::abi::sdk::door::statement("my-hook", "1.0.0", 64),
/// }
/// ```
#[macro_export]
macro_rules! hook_door {
    (open: $open:ty, statement: $statement:expr $(,)?) => {
        $crate::plugin_door! {
            ops: $crate::abi::hook::Ops,
            statement: $statement,
            lifecycle: life($crate::abi::sdk::hook::HookLife<$open>),
            kind_ops: {
                decide: $crate::abi::sdk::Safe<$crate::abi::sdk::hook::Decide<$open>>,
                transform: $crate::abi::sdk::Safe<$crate::abi::sdk::hook::Transform<$open>>,
                notify: $crate::abi::sdk::Safe<$crate::abi::sdk::hook::Notify<$open>>,
                configure: $crate::abi::sdk::Safe<$crate::abi::sdk::hook::Configure<$open>>,
                status: $crate::abi::sdk::Safe<$crate::abi::sdk::hook::Status<$open>>,
                describe: $crate::abi::sdk::Safe<$crate::abi::sdk::hook::Describe<$open>>,
                serve: $crate::abi::sdk::Safe<$crate::abi::sdk::hook::Serve<$open>>,
            },
        }
    };
}

#[cfg(test)]
#[path = "tests/hook_tests.rs"]
mod tests;
