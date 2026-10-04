// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 HOOK WIRE, REQUEST SIDE: the JSON projection a hook was handed (`decide`,
//! `transform`, `notify`), shared by the host and the SDK so the two can never drift. The HOST
//! never builds it on the request path any more (the design: hooks are on the memory ABI);
//! the SDK's [`crate::abi::sdk::hook`] rebuilds it, byte for byte, from the fixed views a hook is
//! handed, for a plugin written against the 1.5.5 JSON. Moved here from the kernel's
//! `hooks::wire` (an F12 relocation: the same lines, re-exported there).

use crate::hooks::{Candidate, RoutingContext, RoutingRequest};
use serde::Serialize;

/// PER-REQUEST message kinds — the explicit `op` discriminator every per-request payload carries
/// (before it, the three kinds were wire-indistinguishable; a hook binary receiving bytes
/// had to infer the kind from field presence/endpoint, and two registrations sharing one socket
/// provably could not tell them apart). MANAGEMENT messages stay key-discriminated (a top-level
/// `configure` / `describe` / `status` key); everything else is a per-request message and `op`
/// says which. The vocabulary is append-only — hooks MUST ignore unknown ops per the contract.
pub const OP_DECIDE: &str = "decide";
pub const OP_TRANSFORM: &str = "transform";
pub const OP_NOTIFY: &str = "notify";

/// The stable request schema sent to a hook: the request projection, every candidate, and context.
/// The request-side wire structs deliberately do NOT derive `Debug`: behind the opt-ins they
/// borrow prompt text and end-user identity, and a derived Debug would bypass the redacting
/// impls on `PromptProjection`/`CallerIdentity`.
#[derive(Serialize)]
pub struct HookRequest<'a> {
    /// The message kind: `decide` (a gate's blocking decision), `transform` (a rewrite pass), or
    /// `notify` (a fire-and-forget tap — never answer it). See [`OP_DECIDE`].
    pub op: &'static str,
    pub request: HookReqProjection<'a>,
    pub candidates: Vec<HookCandidate<'a>>,
    pub context: HookContext<'a>,
    /// TAP observation-stage payload — present ONLY on stage taps (`at: candidate|routing|response`);
    /// absent on request-stage taps and every gate, so the pre-stages wire is byte-identical
    /// (append-only schema).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stage: Option<HookStageProjection<'a>>,
}

/// The tap OBSERVATION-STAGE payload. Which fields are present depends on `at`:
/// `candidate` carries the surviving candidate count after the decision reconcile;
/// `routing` carries the full failover story (attempt number, dispatched target, remaining
/// candidates, and — from attempt 2 — why the previous attempt failed);
/// `response` carries the outcome (`ok` | `failed` | `rejected_by_gate` — the SYNTHETIC
/// completion that lets an audit tap see denials) and the response status.
#[derive(Serialize)]
pub struct HookStageProjection<'a> {
    pub at: &'a str,
    /// The dispatched candidate's model name (ONE name for one concept across the wire — the
    /// same string `candidates[].model` carries on decide payloads).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempt_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_candidates: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_failure: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

/// The request projection sent to a hook. THE CONTRACT: a **default bucket** of shape/metadata
/// signals is ALWAYS present (pool, protocol, counts, sizes, stream, max_tokens; plus every
/// candidate's metadata + live signals in `HookCandidate`) — nothing sensitive. On top of that, at
/// most **two access-gated SECURITY fields** ride the projection, each opted in per hook by an
/// explicit grant:
/// - `prompt` grant (`no|ro|rw`): `system` + `messages` (flattened text) — present when the grant
///   is `ro` OR `rw`. The REQUEST wire is IDENTICAL for `ro` and `rw` (a hook must SEE the prompt to
///   screen it or to rewrite it); the extra power of `rw` is on the REPLY only — a `rw` hook's
///   `rewrite` arm is applied, a `ro` hook's is dropped (enforced at the rewrite seam by the grant).
/// - `user` grant (`no|ro`): caller identity — present when `ro`.
///
/// A grant of `no` OMITS the field from the JSON entirely AND is fail-closed the other direction too
/// (a returned value for a field the hook wasn't granted is ignored): `ro`'s rewrite is dropped,
/// `no` sends nothing and accepts nothing back. These are the ONLY two fields that ever carry caller
/// content/identity.
#[derive(Serialize)]
pub struct HookReqProjection<'a> {
    /// The request correlation id (`RequestCtx::request_id`) — a plain integer on the wire (no
    /// per-request `format!`/allocation on busbar's side; `serde_json` writes a `u64` natively).
    /// The join key: the SAME value appears on this decide/transform/notify payload and on the
    /// `completion`-stage notify for the same request.
    pub request_id: u64,
    pub pool: &'a str,
    pub ingress_protocol: &'a str,
    pub message_count: usize,
    pub has_tools: bool,
    pub total_chars: usize,
    /// Omitted when the request declares none (ONE idiom for optional signals: absent = unset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    pub stream: bool,
    /// SECURITY (`prompt: ro|rw` grant): the flattened system prompt text. Absent when the grant is
    /// `no` — AND when granted but the request carries no (or an empty) system prompt, so a hook must
    /// key the grant off `messages` (always present, possibly `[]`, when granted), never off `system`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<&'a str>,
    /// SECURITY (`prompt: ro|rw` grant): every message as `{role, text}`. Absent when the grant is `no`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<HookMessage<'a>>>,
    /// SECURITY (`user: ro` grant): caller identity (key id/name + end-user field, NEVER the secret).
    /// Absent when the grant is `no`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<HookUser<'a>>,
    /// The declared-signal bag, `#[serde(flatten)]`ed so its entries render
    /// as flat top-level keys (`{"candidate_breaker_state": "closed", ...}`) alongside the fields
    /// above, never nested. EMPTY (the default: no consumer declared anything beyond the core
    /// fields above) flattens to ZERO additional keys — byte-identical to the pre-catalog wire.
    /// ADDITIVE: every field above this one is unchanged.
    #[serde(flatten)]
    pub signals: crate::signal::SignalBag,
}

/// One message of the opt-in prompt projection: the role plus the flattened text content.
#[derive(Serialize)]
pub struct HookMessage<'a> {
    pub role: &'a str,
    pub text: &'a str,
}

/// The opt-in caller identity: the governance virtual-key `id`/`name` (never the secret — the
/// projection is built FROM the resolved key record, the token itself is unreachable here) and the
/// request body's end-user identifier.
#[derive(Serialize)]
pub struct HookUser<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<&'a str>,
}

/// One candidate as seen by the hook. `idx` is the stable handle the hook echoes back in `order`;
/// the rest are the live signals + operator metadata a policy ranks on. The contract projects
/// EVERYTHING a built-in ranking strategy reads, so an external hook can implement any of them
/// identically ("no hook is different"): `weight` (SWRR), `provider` (provider-preference),
/// `context_max` (context-fit), plus the cost/latency/concurrency/headroom live signals.
#[derive(Serialize)]
pub struct HookCandidate<'a> {
    pub idx: usize,
    pub model: &'a str,
    /// Upstream provider name — lets a hook prefer/avoid a provider (a provider-preference strategy).
    pub provider: &'a str,
    /// The configured SWRR weight — lets an external hook implement a weighted-variant strategy (the
    /// signal the built-in `weighted` floor ranks on; projected so the contract is complete).
    pub weight: u32,
    /// Member context-window ceiling — lets a hook route by context-fit. `None` if unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_max: Option<usize>,
    // Optional live signals — omitted when unset (ONE idiom across the wire: absent = unset,
    // never a mix of `null` and absence).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_per_mtok: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    pub available_concurrency: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_headroom: Option<f64>,
    /// The member's operator-declared free-form `tags` (whatever the config author wrote — team
    /// names, regions, compliance labels). Omitted when the member declares none, so untagged
    /// configs keep the exact pre-tags payload.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub tags: &'a [String],
    /// The declared-signal bag — see [`HookReqProjection::signals`] for the
    /// full contract; identical here, flattened onto this candidate's own JSON object.
    #[serde(flatten)]
    pub signals: crate::signal::SignalBag,
}

/// The POOL-SCOPED signal bucket (distinct from the per-candidate signals). `request.pool` already
/// names the pool — it is not duplicated here.
#[derive(Serialize)]
pub struct HookContext<'a> {
    /// Pool-level remaining request budget; omitted when the pool is uncapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_remaining: Option<i64>,
    /// The request's BUDGET-CHAIN state (the caller key's bucket + every ancestor budget group,
    /// innermost first): `{bucket_id, budget_group?, spend_micros_at_current_rate,
    /// remaining_micros?, window_start, budget_period}` per bucket, derived at the current rate
    /// card. Omitted when empty (governance off / no key) so pre-cost-model payloads are
    /// byte-identical. The budget-aware-routing READ seam: a hook may downshift on it; busbar
    /// never routes on budget itself.
    #[serde(skip_serializing_if = "<[crate::hooks::BudgetBucketState]>::is_empty")]
    pub budget: &'a [crate::hooks::BudgetBucketState],
}

/// Build the wire projection from the live request/candidates/context. Borrows everywhere — the
/// projection is serialized immediately by the transport, never stored.
pub fn build<'a>(
    op: &'static str,
    req: &'a RoutingRequest<'_>,
    candidates: &'a [Candidate<'_>],
    ctx: &'a RoutingContext<'_>,
) -> HookRequest<'a> {
    HookRequest {
        op,
        request: HookReqProjection {
            request_id: req.request_id,
            pool: req.pool,
            ingress_protocol: req.ingress_protocol,
            message_count: req.message_count,
            has_tools: req.has_tools,
            total_chars: req.total_chars,
            max_tokens: req.max_tokens,
            stream: req.stream,
            // The opt-in projections: `None` (and thus ABSENT from the JSON) unless the pool set
            // `policy.send_prompt` / `policy.send_user` — `forward` only populates the source
            // fields behind those flags, so absence here is enforced upstream by construction.
            system: req.prompt.as_ref().and_then(|p| p.system.as_deref()),
            messages: req.prompt.as_ref().map(|p| {
                p.messages
                    .iter()
                    .map(|(role, text)| HookMessage {
                        role: role.as_ref(),
                        text: text.as_ref(),
                    })
                    .collect()
            }),
            user: req.identity.as_ref().map(|i| HookUser {
                key_id: i.key_id.as_deref(),
                key_name: i.key_name.as_deref(),
                user: i.user.as_deref(),
            }),
            signals: req.signals.clone(),
        },
        candidates: candidates
            .iter()
            .map(|c| HookCandidate {
                idx: c.idx,
                model: c.model,
                provider: c.provider,
                weight: c.weight,
                context_max: c.context_max,
                tier: c.tier,
                cost_per_mtok: c.cost_per_mtok,
                latency_ms: c.latency_ms,
                available_concurrency: c.available_concurrency,
                budget_remaining: c.budget_remaining,
                rate_headroom: c.rate_headroom,
                tags: c.tags,
                signals: c.signals.clone(),
            })
            .collect(),
        stage: None,
        context: HookContext {
            budget_remaining: ctx.budget_remaining,
            budget: ctx.budget,
        },
    }
}

/// A parsed, validated `restrict` reply: the set of tags a surviving candidate must carry at least
/// one of. FAIL-CLOSED — `parse_restrict` returns `None` for a malformed/empty restrict so the caller
/// routes it to `on_error`, never to an accidental allow-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictReply {
    pub tags_any: Vec<String>,
}

/// Parse the untyped `restrict` value fail-closed. A well-formed restrict is `{"tags_any": [non-empty
/// strings]}`; anything else (not an object, missing/empty/non-array `tags_any`, no usable string
/// entries) yields `None` — the caller treats that as the gate's `on_error`, never allow-all. Tag
/// strings are trimmed; empty/whitespace-only entries are dropped.
pub fn parse_restrict(value: &serde_json::Value) -> Option<RestrictReply> {
    let tags_any: Vec<String> = value
        .get("tags_any")?
        .as_array()?
        .iter()
        .filter_map(|t| t.as_str())
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();
    if tags_any.is_empty() {
        return None;
    }
    Some(RestrictReply { tags_any })
}
