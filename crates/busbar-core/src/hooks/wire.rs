// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE hook wire contract — REPLY side (shared by every out-of-process routing transport: HTTP
//! webhook, Unix-socket binary). A policy hook returns this exact reply shape whatever the transport,
//! so a hook graduates between transports without changing its logic. Versioned by shape, not a field,
//! in v1: the schema is append-only.
//!
//! The REQUEST-side projection (`HookRequest`/`build`/the op constants/the reject clamp+sanitize) lives
//! in the NEUTRAL substrate at [`busbar_substrate::hooks::wire`] so the LLM model plane names it
//! without reaching back into core; it is RE-EXPORTED below so every core-internal
//! `crate::hooks::wire::…` path (proxy_vocab, plugin, auth, admin, the tests) is unchanged. The
//! reply-side normalizers + the settings-bag-carrying [`StatusReply`] stay HERE — inside the
//! settings-leak-lint scan root that must keep watching any raw operator-settings bag.

use super::{Candidate, RoutingDecision};
use serde::Deserialize;

// RE-EXPORT the substrate request-side contract so `crate::hooks::wire::{…}` resolves by-identity for
// every historical core caller (proxy_vocab builds `HookRequest`; plugin.rs calls `build`; auth/admin
// name `HookStageProjection`; the tests exercise `build`) and for the reject clamp/sanitize the
// reply-side normalizers below share with the forward seam.
pub use busbar_substrate::hooks::wire::{
    build, clamp_reject_status, sanitize_reject_message, HookCandidate, HookContext, HookMessage,
    HookReqProjection, HookRequest, HookStageProjection, HookUser, OP_DECIDE, OP_NOTIFY,
    OP_TRANSFORM, REJECT_MESSAGE_DEFAULT, REJECT_MESSAGE_MAX_CHARS, REJECT_STATUS_DEFAULT,
};

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
pub use busbar_api::RewriteReply;

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
