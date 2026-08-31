// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE hook wire contract — shared by every out-of-process routing transport (HTTP webhook,
//! Unix-socket binary). A policy hook receives this exact JSON projection and returns this exact
//! reply shape, whatever the transport, so a hook graduates between transports (webhook prototype →
//! socket binary) without changing its logic. Versioned by shape, not a field, in v1: the schema is
//! append-only.

use super::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
use serde::{Deserialize, Serialize};

/// PER-REQUEST message kinds — the explicit `op` discriminator every per-request payload carries
/// (before it, the three kinds were wire-indistinguishable; a hook binary receiving bytes
/// had to infer the kind from field presence/endpoint, and two registrations sharing one socket
/// provably could not tell them apart). MANAGEMENT messages stay key-discriminated (a top-level
/// `configure` / `describe` / `status` key); everything else is a per-request message and `op`
/// says which. The vocabulary is append-only — hooks MUST ignore unknown ops per the contract.
pub(crate) const OP_DECIDE: &str = "decide";
pub(crate) const OP_TRANSFORM: &str = "transform";
pub(crate) const OP_NOTIFY: &str = "notify";

/// The stable request schema sent to a hook: the request projection, every candidate, and context.
/// The request-side wire structs deliberately do NOT derive `Debug`: behind the opt-ins they
/// borrow prompt text and end-user identity, and a derived Debug would bypass the redacting
/// impls on `PromptProjection`/`CallerIdentity`.
#[derive(Serialize)]
pub(crate) struct HookRequest<'a> {
    /// The message kind: `decide` (a gate's blocking decision), `transform` (a rewrite pass), or
    /// `notify` (a fire-and-forget tap — never answer it). See [`OP_DECIDE`].
    pub(crate) op: &'static str,
    pub(crate) request: HookReqProjection<'a>,
    pub(crate) candidates: Vec<HookCandidate<'a>>,
    pub(crate) context: HookContext<'a>,
    /// TAP observation-stage payload — present ONLY on stage taps (`at: candidate|routing|response`);
    /// absent on request-stage taps and every gate, so the pre-stages wire is byte-identical
    /// (append-only schema).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) stage: Option<HookStageProjection<'a>>,
}

/// The tap OBSERVATION-STAGE payload. Which fields are present depends on `at`:
/// `candidate` carries the surviving candidate count after the decision reconcile;
/// `routing` carries the full failover story (attempt number, dispatched target, remaining
/// candidates, and — from attempt 2 — why the previous attempt failed);
/// `response` carries the outcome (`ok` | `failed` | `rejected_by_gate` — the SYNTHETIC
/// completion that lets an audit tap see denials) and the response status.
#[derive(Serialize)]
pub(crate) struct HookStageProjection<'a> {
    pub(crate) at: &'static str,
    /// The dispatched candidate's model name (ONE name for one concept across the wire — the
    /// same string `candidates[].model` carries on decide payloads).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) model: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attempt_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) remaining_candidates: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) previous_failure: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) status: Option<u16>,
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
pub(crate) struct HookReqProjection<'a> {
    /// The request correlation id (`RequestCtx::request_id`) — a plain integer on the wire (no
    /// per-request `format!`/allocation on busbar's side; `serde_json` writes a `u64` natively).
    /// The join key: the SAME value appears on this decide/transform/notify payload and on the
    /// `completion`-stage notify for the same request.
    pub(crate) request_id: u64,
    pub(crate) pool: &'a str,
    pub(crate) ingress_protocol: &'a str,
    pub(crate) message_count: usize,
    pub(crate) has_tools: bool,
    pub(crate) total_chars: usize,
    /// Omitted when the request declares none (ONE idiom for optional signals: absent = unset).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) max_tokens: Option<u32>,
    pub(crate) stream: bool,
    /// SECURITY (`prompt: ro|rw` grant): the flattened system prompt text. Absent when the grant is
    /// `no` — AND when granted but the request carries no (or an empty) system prompt, so a hook must
    /// key the grant off `messages` (always present, possibly `[]`, when granted), never off `system`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) system: Option<&'a str>,
    /// SECURITY (`prompt: ro|rw` grant): every message as `{role, text}`. Absent when the grant is `no`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) messages: Option<Vec<HookMessage<'a>>>,
    /// SECURITY (`user: ro` grant): caller identity (key id/name + end-user field, NEVER the secret).
    /// Absent when the grant is `no`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<HookUser<'a>>,
    /// The declared-signal bag, `#[serde(flatten)]`ed so its entries render
    /// as flat top-level keys (`{"candidate_breaker_state": "closed", ...}`) alongside the fields
    /// above, never nested. EMPTY (the default: no consumer declared anything beyond the core
    /// fields above) flattens to ZERO additional keys — byte-identical to the pre-catalog wire.
    /// ADDITIVE: every field above this one is unchanged.
    #[serde(flatten)]
    pub(crate) signals: busbar_api::SignalBag,
}

/// One message of the opt-in prompt projection: the role plus the flattened text content.
#[derive(Serialize)]
pub(crate) struct HookMessage<'a> {
    pub(crate) role: &'a str,
    pub(crate) text: &'a str,
}

/// The opt-in caller identity: the governance virtual-key `id`/`name` (never the secret — the
/// projection is built FROM the resolved key record, the token itself is unreachable here) and the
/// request body's end-user identifier.
#[derive(Serialize)]
pub(crate) struct HookUser<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) user: Option<&'a str>,
}

/// One candidate as seen by the hook. `idx` is the stable handle the hook echoes back in `order`;
/// the rest are the live signals + operator metadata a policy ranks on. The contract projects
/// EVERYTHING a built-in ranking strategy reads, so an external hook can implement any of them
/// identically ("no hook is different"): `weight` (SWRR), `provider` (provider-preference),
/// `context_max` (context-fit), plus the cost/latency/concurrency/headroom live signals.
#[derive(Serialize)]
pub(crate) struct HookCandidate<'a> {
    pub(crate) idx: usize,
    pub(crate) model: &'a str,
    /// Upstream provider name — lets a hook prefer/avoid a provider (a provider-preference strategy).
    pub(crate) provider: &'a str,
    /// The configured SWRR weight — lets an external hook implement a weighted-variant strategy (the
    /// signal the built-in `weighted` floor ranks on; projected so the contract is complete).
    pub(crate) weight: u32,
    /// Member context-window ceiling — lets a hook route by context-fit. `None` if unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) context_max: Option<usize>,
    // Optional live signals — omitted when unset (ONE idiom across the wire: absent = unset,
    // never a mix of `null` and absence).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) tier: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cost_per_mtok: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) latency_ms: Option<f64>,
    pub(crate) available_concurrency: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) budget_remaining: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) rate_headroom: Option<f64>,
    /// The member's operator-declared free-form `tags` (whatever the config author wrote — team
    /// names, regions, compliance labels). Omitted when the member declares none, so untagged
    /// configs keep the exact pre-tags payload.
    #[serde(skip_serializing_if = "<[String]>::is_empty")]
    pub(crate) tags: &'a [String],
    /// The declared-signal bag — see [`HookReqProjection::signals`] for the
    /// full contract; identical here, flattened onto this candidate's own JSON object.
    #[serde(flatten)]
    pub(crate) signals: busbar_api::SignalBag,
}

/// The POOL-SCOPED signal bucket (distinct from the per-candidate signals). `request.pool` already
/// names the pool — it is not duplicated here.
#[derive(Serialize)]
pub(crate) struct HookContext<'a> {
    /// Pool-level remaining request budget; omitted when the pool is uncapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) budget_remaining: Option<i64>,
    /// The request's BUDGET-CHAIN state (the caller key's bucket + every ancestor budget group,
    /// innermost first): `{bucket_id, budget_group?, spend_micros_at_current_rate,
    /// remaining_micros?, window_start, budget_period}` per bucket, derived at the current rate
    /// card. Omitted when empty (governance off / no key) so pre-cost-model payloads are
    /// byte-identical. The budget-aware-routing READ seam: a hook may downshift on it; busbar
    /// never routes on budget itself.
    #[serde(skip_serializing_if = "<[busbar_api::BudgetBucketState]>::is_empty")]
    pub(crate) budget: &'a [busbar_api::BudgetBucketState],
}

/// The describe reply envelope, parsed liberally.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct DescribeReply {
    #[serde(default)]
    pub(crate) schema: Option<serde_json::Value>,
}

/// One hook-reported metric entry — a Prometheus/OpenMetrics-shaped observation (parsed liberally;
/// a malformed ENTRY is dropped whole, never the reply). This is the FROZEN metrics shape: a hook
/// reports its operational data (a Headroom compressor's tokens-saved, a router's decision latency)
/// and busbar surfaces it on the admin API + Prometheus for any dashboard. Beyond `name`+`type`
/// everything is optional, so the simplest hook sends `{name, type, value}` and a rich one uses the
/// rest. Modeled as an ARRAY (not a name→value map) precisely so several entries can share a `name`
/// and differ by `labels` — the per-dimension breakdown (per-strategy, per-model) a flat map cannot
/// carry and a real plugin dashboard needs first.
///
/// Anti-exfiltration holds structurally: `name`/label KEYS are charset-enforced, every string
/// (label values, `help`, `label`, `unit`) is sanitized + length-bounded, and every number must be
/// finite — a `prompt: ro` hook cannot smuggle content into a scrape.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct HookMetric {
    /// The series name: `^[a-z][a-z0-9_]{0,63}$` (counters SHOULD end `_total`).
    pub(crate) name: String,
    /// `counter` (monotonic over the hook's lifetime), `gauge` (a point-in-time level), or
    /// `histogram` (a distribution reported via `quantiles`).
    #[serde(rename = "type")]
    pub(crate) kind: String,
    /// The scalar value. Required for counter/gauge; for a histogram it is the observation COUNT
    /// (the distribution rides `quantiles`). Defaults to 0 when absent so a pure-histogram entry
    /// need not send it.
    #[serde(default)]
    pub(crate) value: f64,
    /// PROMETHEUS-STYLE DIMENSIONS (the per-strategy / per-model breakdown a dashboard drills into).
    /// Several entries may share `name` and differ here. Keys `^[a-z][a-z0-9_]{0,63}$`, values
    /// sanitized ≤ 64 chars; ≤ [`MAX_METRIC_LABELS`] pairs (excess/invalid pairs dropped).
    #[serde(default)]
    pub(crate) labels: Option<std::collections::BTreeMap<String, String>>,
    /// A `type: histogram` reported as a SUMMARY — precomputed quantiles (p50/p95/p99, what a mean
    /// hides). Keys are quantiles in `[0,1]` as strings (`"0.95"`), values finite. The alternative,
    /// for a hook that can bucket its samples, is `buckets` (a native Prometheus histogram). A hook
    /// sends whichever it can produce; both render on the Prometheus scrape.
    #[serde(default)]
    pub(crate) quantiles: Option<std::collections::BTreeMap<String, f64>>,
    /// A `type: histogram` reported as a native PROMETHEUS HISTOGRAM — keys are `le` upper bounds as
    /// strings (`"0.5"`, `"0.01"`, `"+Inf"`), values are the CUMULATIVE observation count at or below
    /// that bound (monotonic non-decreasing, the top bound holding `value`). Rendered as
    /// `name_bucket{le="…"}` + `name_count`, so a consumer can `histogram_quantile()` over it exactly
    /// as it would any Prometheus histogram — which is what lets a dashboard built for a hook's
    /// upstream tool (e.g. a compression tool's own `*_bucket` panels) work unchanged against busbar.
    /// Preferred over `quantiles` when both are present.
    #[serde(default)]
    pub(crate) buckets: Option<std::collections::BTreeMap<String, f64>>,
    /// PROVENANCE: `true` marks this value an ESTIMATE (e.g. Headroom's holdout-control savings)
    /// rather than a directly measured fact — a dashboard renders it distinctly.
    #[serde(default)]
    pub(crate) estimated: Option<bool>,
    /// Confidence interval for an estimated value (finite; `ci_low ≤ ci_high` or both dropped).
    #[serde(default)]
    pub(crate) ci_low: Option<f64>,
    #[serde(default)]
    pub(crate) ci_high: Option<f64>,
    /// Human display name (a UI falls back to `name`).
    #[serde(default)]
    pub(crate) help: Option<String>,
    #[serde(default)]
    pub(crate) label: Option<String>,
    /// Display unit token (`"ms"`, `"$"`, `"%"`, `"req/s"`, …) — max 16 chars, sanitized.
    #[serde(default)]
    pub(crate) unit: Option<String>,
    /// Rendering hint: `number` | `gauge` | `counter` | `sparkline` | `histogram` (else dropped).
    #[serde(default)]
    pub(crate) viz: Option<String>,
    /// Gauge normalization ceiling (finite number, else dropped).
    #[serde(default)]
    pub(crate) max: Option<f64>,
    // Time SERIES are the CONSUMER's job in 1.3 (a dashboard samples `status` and accumulates); an
    // engine-retained `series` member is the reserved append-only path (a future release). A hook
    // may send unknown members today — they are ignored, not an error.
}

/// The hook's `status` reply body (liberal: every field optional, unknown fields ignored),
/// deserialized into the shared `busbar_api::HookStatus` shape. `metrics` is the raw array of entry
/// objects (validated downstream by [`parse_status_metrics`]).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct StatusReply {
    #[serde(default)]
    pub(crate) settings_version: Option<u64>,
    #[serde(default)]
    // settings-leak-lint: allow — INBOUND wire reply the engine only consumes: the hook's echo of
    // the RESOLVED bag. It is never serialized to a reader (`hook_status` projects `settings_keys`
    // from it; `settings_drift_keys` compares key names), and this is the exact type whose leak
    // — historical #3 — the widened scan root exists to keep caught.
    pub(crate) settings: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(default)]
    pub(crate) metrics: Option<Vec<serde_json::Value>>,
}

impl From<StatusReply> for busbar_api::HookStatus {
    fn from(r: StatusReply) -> Self {
        busbar_api::HookStatus {
            settings_version: r.settings_version,
            settings: r.settings,
            metrics: r.metrics,
        }
    }
}

/// The `status` reply envelope (`{"status": {...}}`); `None`/absent = the hook doesn't speak it
/// (per the unknown-op contract rule, `{}` = unsupported → busbar fails open).
#[derive(Debug, Default, Deserialize)]
pub(crate) struct StatusEnvelope {
    #[serde(default)]
    pub(crate) status: Option<StatusReply>,
}

/// Per-reply cap on hook-reported metric entries (excess dropped — bounded registry).
pub(crate) const MAX_HOOK_METRICS: usize = 64;
/// Per-entry cap on label pairs (a labeled series stays small — cardinality guard).
pub(crate) const MAX_METRIC_LABELS: usize = 8;
/// Metric-help length cap (chars), sanitized through `sanitize_reject_message` before exposure.
pub(crate) const MAX_METRIC_HELP_CHARS: usize = 200;
/// Display-hint + label-value caps (same sanitize rule as help).
pub(crate) const MAX_METRIC_LABEL_CHARS: usize = 64;
pub(crate) const MAX_METRIC_UNIT_CHARS: usize = 16;

/// Validate a hook-reported metric NAME or LABEL KEY: `^[a-z][a-z0-9_]{0,63}$`. Anything else is
/// dropped — names/keys become Prometheus identifiers, so the charset is enforced structurally (a
/// hook granted `prompt: ro` physically cannot smuggle content into a scrape).
pub(crate) fn valid_metric_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= 64
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Char-boundary-safe sanitize + cap (`String::truncate` takes BYTES and panics off a
/// char boundary; `.chars().take(n)` is panic-free and matches the documented "≤ N chars" rule).
///
/// When the sanitized value is longer than `n`, the LAST char of the kept prefix is replaced by
/// an ellipsis marker (mirrors `config::migrate::one_line`'s truncation marker) so a hook's
/// over-cap name/label/help/unit string is never mistaken for the complete, real value once it
/// reaches an admin API reader or a Prometheus scrape — the truncation is observable in the
/// value itself, not silent. Total length stays ≤ `n` chars.
fn sanitize_cap(raw: &str, n: usize) -> String {
    let sanitized = sanitize_reject_message(raw);
    let chars: Vec<char> = sanitized.chars().collect();
    if chars.len() > n {
        let keep = n.saturating_sub(1);
        let mut capped: String = chars[..keep].iter().collect();
        capped.push('…');
        capped
    } else {
        sanitized
    }
}

/// Parse + validate the metrics ARRAY of a `status` reply FAIL-OPEN: a malformed entry (bad
/// name/type, non-finite value) is DROPPED whole, valid ones kept, capped at [`MAX_HOOK_METRICS`].
/// Within an entry, malformed OPTIONAL members (an out-of-charset label key, a non-finite quantile,
/// an inverted CI, an out-of-vocabulary viz) are dropped INDIVIDUALLY — the metric survives. Every
/// exposed string is sanitized + length-bounded; every number is finite.
pub(crate) fn parse_status_metrics(raw: &[serde_json::Value]) -> Vec<HookMetric> {
    let mut out = Vec::new();
    for v in raw {
        if out.len() >= MAX_HOOK_METRICS {
            break;
        }
        let Ok(mut m) = serde_json::from_value::<HookMetric>(v.clone()) else {
            continue;
        };
        // Drop the whole entry on the load-bearing invariants: name charset, known type, finite
        // scalar. (A histogram may legitimately carry value 0 — the distribution is in quantiles.)
        if !valid_metric_name(&m.name)
            || !matches!(m.kind.as_str(), "counter" | "gauge" | "histogram")
            || !m.value.is_finite()
        {
            continue;
        }
        // Labels: keep only charset-valid keys with sanitized values, capped in count.
        m.labels = m.labels.map(|labels| {
            labels
                .into_iter()
                .filter(|(k, _)| valid_metric_name(k))
                .map(|(k, val)| (k, sanitize_cap(&val, MAX_METRIC_LABEL_CHARS)))
                .take(MAX_METRIC_LABELS)
                .collect()
        });
        // Quantiles: keys parse to a probability in [0,1], values finite; drop the map if empty.
        // Capped like labels and buckets: the [0,1] filter does NOT bound the count — "0.5", "0.50",
        // "0.500" are all distinct keys that all parse in range — and the scrape renders one line per
        // quantile per metric, so an uncapped map defeats `scrape.rs`'s stated BOUNDED property.
        m.quantiles = m
            .quantiles
            .map(|q| {
                q.into_iter()
                    .filter(|(k, val)| {
                        val.is_finite() && k.parse::<f64>().is_ok_and(|p| (0.0..=1.0).contains(&p))
                    })
                    .take(MAX_METRIC_LABELS)
                    .collect::<std::collections::BTreeMap<_, _>>()
            })
            .filter(|q| !q.is_empty());
        // Buckets: keys are `le` bounds — a finite number or `"+Inf"` — values finite, non-negative
        // cumulative counts. Cap the bucket count (a histogram with 64 le bounds is already generous).
        // Drop the map if empty.
        m.buckets = m
            .buckets
            .map(|b| {
                b.into_iter()
                    .filter(|(k, val)| {
                        val.is_finite() && *val >= 0.0 && (k == "+Inf" || k.parse::<f64>().is_ok())
                    })
                    .take(MAX_METRIC_LABELS * 8)
                    .collect::<std::collections::BTreeMap<_, _>>()
            })
            .filter(|b| !b.is_empty());
        // Confidence interval: both finite and ordered, else drop the pair entirely.
        match (m.ci_low, m.ci_high) {
            (Some(lo), Some(hi)) if lo.is_finite() && hi.is_finite() && lo <= hi => {}
            _ => {
                m.ci_low = None;
                m.ci_high = None;
            }
        }
        m.help = m.help.map(|h| sanitize_cap(&h, MAX_METRIC_HELP_CHARS));
        m.label = m.label.map(|l| sanitize_cap(&l, MAX_METRIC_LABEL_CHARS));
        m.unit = m
            .unit
            .map(|u| sanitize_cap(&u, MAX_METRIC_UNIT_CHARS))
            .filter(|s| !s.is_empty());
        m.viz = m.viz.filter(|v| {
            matches!(
                v.as_str(),
                "number" | "gauge" | "counter" | "sparkline" | "histogram"
            )
        });
        m.max = m.max.filter(|v| v.is_finite());
        out.push(m);
    }
    out
}

/// The hook's reply. `order` is the ranked preference (candidate `idx` values, most-preferred
/// first); an explicit `abstain: true` (or an absent/empty `order`) means "no opinion". Both fields
/// are optional so an empty `{}` deserializes to Abstain. Unknown JSON fields are ignored, so a hook
/// may attach extra diagnostics without breaking the contract.
#[derive(Debug, Deserialize, Default)]
pub(crate) struct HookResponse {
    #[serde(default)]
    pub(crate) order: Option<Vec<usize>>,
    #[serde(default)]
    pub(crate) abstain: bool,
    /// REJECT the request outright: no upstream is dispatched, the caller gets a dialect-native
    /// error. Takes precedence over `order`/`abstain` — a hook that says both meant reject. The
    /// verb that makes a content-seeing hook (`policy.send_prompt`) a guardrail, not just a router.
    ///
    /// Deliberately an untyped `Value`, parsed best-effort by `normalize`: the verb is FAIL-CLOSED.
    /// Once a hook says "reject", a malformed detail (a status of 70000, a numeric message) must
    /// degrade to "reject with the defaults", never to "silently route the request" — a typed
    /// struct here would abort the WHOLE reply parse on a bad field and coerce the decision to
    /// `on_error`, routing a request the hook tried to stop. `{"reject": false}` (and JSON `null`,
    /// which maps to absent) is the one explicit "not rejecting" shape; anything else present
    /// rejects.
    #[serde(default)]
    pub(crate) reject: Option<serde_json::Value>,
    /// RESTRICT the surviving candidate set to members carrying ANY of these tags
    /// (`{"restrict": {"tags_any": [...]}}`). A compliance gate ("only BAA-covered lanes"). Untyped +
    /// FAIL-CLOSED like `reject`: a malformed restrict must fall to the gate's `on_error`/`on_empty`,
    /// never silently allow-all. Parsed by `parse_restrict`, folded into `RoutingDecision::Restrict`
    /// by `normalize`, and re-applied on every downstream failover hop by
    /// `proxy::select::enforce_restricts`.
    #[serde(default)]
    pub(crate) restrict: Option<serde_json::Value>,
    /// REWRITE the request body (`{"rewrite": {"messages": [...], "tools": [...]}}`) — the
    /// compression/redaction arm (Headroom). Untyped + FAIL-CLOSED: a malformed/oversize rewrite must
    /// proceed with the UNMODIFIED body, never a corrupted one. Requires the hook's `prompt: rw` grant.
    /// Parsed by `parse_rewrite` and applied by the priority-ordered transform pass at the `parsed.rewrite` read below.
    #[serde(default)]
    pub(crate) rewrite: Option<serde_json::Value>,
}

/// A parsed, validated `restrict` reply: the set of tags a surviving candidate must carry at least
/// one of. FAIL-CLOSED — `parse_restrict` returns `None` for a malformed/empty restrict so the caller
/// routes it to `on_error`, never to an accidental allow-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RestrictReply {
    pub(crate) tags_any: Vec<String>,
}

/// Parse the untyped `restrict` value fail-closed. A well-formed restrict is `{"tags_any": [non-empty
/// strings]}`; anything else (not an object, missing/empty/non-array `tags_any`, no usable string
/// entries) yields `None` — the caller treats that as the gate's `on_error`, never allow-all. Tag
/// strings are trimmed; empty/whitespace-only entries are dropped.
pub(crate) fn parse_restrict(value: &serde_json::Value) -> Option<RestrictReply> {
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

/// A parsed, validated `rewrite` reply — part of the hook contract (`busbar-api`); re-exported so
/// engine-internal paths are unchanged. FAIL-CLOSED: `parse_rewrite` (below) returns `None` for a
/// malformed rewrite so the caller proceeds with the ORIGINAL body, never a corrupted one.
pub(crate) use busbar_api::RewriteReply;

/// Parse the untyped `rewrite` value fail-closed. A well-formed rewrite is `{"messages": [...],
/// "tools"?: [...]}` with a NON-EMPTY messages array; anything else yields `None` (proceed with the
/// original body). `tools` is optional (defaults empty).
pub(crate) fn parse_rewrite(value: &serde_json::Value) -> Option<RewriteReply> {
    let messages: Vec<serde_json::Value> = value.get("messages")?.as_array()?.clone();
    if messages.is_empty() {
        return None;
    }
    let tools = value
        .get("tools")
        .and_then(|t| t.as_array())
        .cloned()
        .unwrap_or_default();
    Some(RewriteReply { messages, tools })
}

/// Extract a reject's (status, message) fail-closed: status CLAMPED to client errors (anything
/// else — absent, non-integer, 0, 200, 302, 500, 70000, -1 — becomes 403), message sanitized +
/// capped. ONE extraction for both the decide path (`normalize`) and the transform path (a `rw`
/// gate's reject) so the two can never diverge.
pub(crate) fn parse_reject_detail(reject: &serde_json::Value) -> (u16, String) {
    let status = reject
        .get("status")
        .and_then(|s| s.as_i64())
        .and_then(|s| u16::try_from(s).ok())
        .map(clamp_reject_status)
        .unwrap_or(REJECT_STATUS_DEFAULT);
    let message =
        sanitize_reject_message(reject.get("message").and_then(|m| m.as_str()).unwrap_or(""));
    (status, message)
}

/// Normalize a parsed reply on the TRANSFORM path: reject > rewrite > abstain. `restrict`/`order`
/// are decide-path verbs and are ignored here (documented in the contract). Shared by both
/// transports so they can never diverge.
pub(crate) fn transform_outcome(parsed: HookResponse) -> busbar_api::TransformOutcome {
    use busbar_api::TransformOutcome;
    if let Some(reject) = &parsed.reject {
        if *reject != serde_json::Value::Bool(false) {
            let (status, message) = parse_reject_detail(reject);
            return TransformOutcome::Reject { status, message };
        }
    }
    match parsed.rewrite.as_ref().and_then(parse_rewrite) {
        Some(rw) => TransformOutcome::Rewrite(rw),
        None => TransformOutcome::Abstain,
    }
}

/// Reject-status clamp range + fallback: any status outside 400..=499 becomes 403.
const REJECT_STATUS_DEFAULT: u16 = 403;

/// Clamp a hook-supplied reject status to the client-error range: anything outside 400..=499
/// becomes `REJECT_STATUS_DEFAULT` (403). Shared by `parse_reject_detail` (the transports' reply
/// seam) and forward's policy-outcome seam (defense in depth for a `RoutingDecision::Reject`
/// constructed directly by a policy impl), so no producer can mint a success/redirect/5xx.
pub(crate) fn clamp_reject_status(status: u16) -> u16 {
    if (400..=499).contains(&status) {
        status
    } else {
        REJECT_STATUS_DEFAULT
    }
}
/// Reject-message length cap (chars). Long enough for a real reason, short enough for an error body.
const REJECT_MESSAGE_MAX_CHARS: usize = 300;
/// Reject-message fallback when the hook sends none (or nothing survives sanitizing).
const REJECT_MESSAGE_DEFAULT: &str = "Request rejected by the routing policy.";

/// Sanitize a reject message for the client error body AND the operator log line: strip control
/// chars, the Unicode line/paragraph separators (U+2028/29 — several log/OTLP pipelines treat
/// them as newlines: a record-splitting vector like CRLF), and the invisible direction/zero-width
/// formatting chars (bidi overrides U+202A..=U+202E and isolates U+2066..=U+2069 can visually
/// spoof a log line in a terminal; zero-widths U+200B..=U+200F and U+FEFF hide content). Cap the
/// length; fall back to the canned default when nothing printable survives. When the sanitized
/// message is longer than the cap, the last char of the kept prefix is replaced by an ellipsis
/// marker so the caller who reads this back (the client error body AND the operator log line)
/// can tell it was shortened, rather than reading a message that silently ends mid-word and
/// looking complete.
///
/// Shared by `normalize` (the transports' reply path) and by `forward`'s seam mapping (defense in
/// depth for a `RoutingDecision::Reject` constructed directly by a policy impl), so the "safe to
/// log, safe for the client" guarantee holds for EVERY producer of a rejection.
pub(crate) fn sanitize_reject_message(raw: &str) -> String {
    let filtered: Vec<char> = raw
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    *c,
                    '\u{2028}'
                        | '\u{2029}'
                        | '\u{200B}'..='\u{200F}'
                        | '\u{202A}'..='\u{202E}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{FEFF}'
                )
        })
        .collect();
    let message: String = if filtered.len() > REJECT_MESSAGE_MAX_CHARS {
        let keep = REJECT_MESSAGE_MAX_CHARS.saturating_sub(1);
        let mut capped: String = filtered[..keep].iter().collect();
        capped.push('…');
        capped
    } else {
        filtered.into_iter().collect()
    };
    if message.trim().is_empty() {
        REJECT_MESSAGE_DEFAULT.to_string()
    } else {
        message
    }
}

/// Build the wire projection from the live request/candidates/context. Borrows everywhere — the
/// projection is serialized immediately by the transport, never stored.
pub(crate) fn build<'a>(
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

/// Normalize a parsed hook reply into a decision: `reject` (clamped + sanitized) wins over
/// everything; then explicit abstain / absent order → `Abstain`; otherwise the shared liberal
/// normalizer (drop unknown idxs, dedup, empty → Abstain). One normalization for every transport.
pub(crate) fn normalize(parsed: HookResponse, candidates: &[Candidate<'_>]) -> RoutingDecision {
    // FAIL-CLOSED: any `reject` value except an explicit `false` is a rejection (see the field
    // doc). Details are extracted best-effort; anything missing or out-of-shape falls back to the
    // safe defaults rather than downgrading the verb.
    if let Some(reject) = parsed.reject {
        if reject != serde_json::Value::Bool(false) {
            let (status, message) = parse_reject_detail(&reject);
            return RoutingDecision::Reject { status, message };
        }
    }
    // RESTRICT comes after reject (reject wins) and before order. FAIL-CLOSED like reject: any
    // `restrict` value except an explicit `false` restricts; a malformed one (parse_restrict → None)
    // yields an EMPTY tag set, which downstream resolves via the gate's `on_empty` — never allow-all.
    if let Some(restrict) = parsed.restrict {
        if restrict != serde_json::Value::Bool(false) {
            let tags_any = parse_restrict(&restrict)
                .map(|r| r.tags_any)
                .unwrap_or_default();
            return RoutingDecision::Restrict { tags_any };
        }
    }
    if parsed.abstain {
        return RoutingDecision::Abstain;
    }
    let Some(order) = parsed.order else {
        return RoutingDecision::Abstain;
    };
    let valid: std::collections::HashSet<usize> = candidates.iter().map(|c| c.idx).collect();
    RoutingDecision::from_ranked(order, &valid)
}

#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod tests;
