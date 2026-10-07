// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 HOOK WIRE, REPLY SIDE: what the HOST still reads of a hook's 1.5.5 JSON after the hook
//! switch-over (the design: hooks are on the memory ABI; a hook's `decide`/`transform` reply
//! crosses as the hook kind's fixed `out`, lowered from 1.5.5 JSON on the PLUGIN side by
//! `abi::sdk::hook::lower_decide_reply` / `lower_transform_reply`, and read back by the kernel's host
//! hook stage, `plane_driver::hooks::policy`). Moved here from the kernel's `hooks::wire` (P2 D4,
//! ARCHITECT Q-D4-HOOKS 2026-10-04: the hook reply wire shapes live in the contract, beside the
//! request side in [`super`]). What is here is the host's half of 1.5.5's reply contract, which the
//! fixed `out` does not do for it: the reject-status clamp and message sanitiser, the rewrite parsed
//! fail-closed, and the `status`/`describe` blobs (1.5.5 JSON, carried verbatim by the ABI) with the
//! bounded hook-metrics shape they report. The settings-bag-carrying [`StatusReply`] stays inside the
//! settings-leak-lint scan root.

use serde::Deserialize;

/// The describe reply envelope, parsed liberally.
#[derive(Debug, Default, Deserialize)]
pub struct DescribeReply {
    /// The hook's settings schema, as it described it.
    #[serde(default)]
    pub schema: Option<serde_json::Value>,
}

/// One hook-reported metric entry — a Prometheus/OpenMetrics-shaped observation (parsed liberally;
/// a malformed ENTRY is dropped whole, never the reply). This is the FROZEN metrics shape: a hook
/// reports its operational data (a prompt compressor's tokens-saved, a router's decision latency)
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
pub struct HookMetric {
    /// The series name: `^[a-z][a-z0-9_]{0,63}$` (counters SHOULD end `_total`).
    pub name: String,
    /// `counter` (monotonic over the hook's lifetime), `gauge` (a point-in-time level), or
    /// `histogram` (a distribution reported via `quantiles`).
    #[serde(rename = "type")]
    pub kind: String,
    /// The scalar value. Required for counter/gauge; for a histogram it is the observation COUNT
    /// (the distribution rides `quantiles`). Defaults to 0 when absent so a pure-histogram entry
    /// need not send it.
    #[serde(default)]
    pub value: f64,
    /// PROMETHEUS-STYLE DIMENSIONS (the per-strategy / per-model breakdown a dashboard drills into).
    /// Several entries may share `name` and differ here. Keys `^[a-z][a-z0-9_]{0,63}$`, values
    /// sanitized ≤ 64 chars; ≤ [`MAX_METRIC_LABELS`] pairs (excess/invalid pairs dropped).
    #[serde(default)]
    pub labels: Option<std::collections::BTreeMap<String, String>>,
    /// A `type: histogram` reported as a SUMMARY — precomputed quantiles (p50/p95/p99, what a mean
    /// hides). Keys are quantiles in `[0,1]` as strings (`"0.95"`), values finite. The alternative,
    /// for a hook that can bucket its samples, is `buckets` (a native Prometheus histogram). A hook
    /// sends whichever it can produce; both render on the Prometheus scrape.
    #[serde(default)]
    pub quantiles: Option<std::collections::BTreeMap<String, f64>>,
    /// A `type: histogram` reported as a native PROMETHEUS HISTOGRAM — keys are `le` upper bounds as
    /// strings (`"0.5"`, `"0.01"`, `"+Inf"`), values are the CUMULATIVE observation count at or below
    /// that bound (monotonic non-decreasing, the top bound holding `value`). Rendered as
    /// `name_bucket{le="…"}` + `name_count`, so a consumer can `histogram_quantile()` over it exactly
    /// as it would any Prometheus histogram — which is what lets a dashboard built for a hook's
    /// upstream tool (e.g. a compression tool's own `*_bucket` panels) work unchanged against busbar.
    /// Preferred over `quantiles` when both are present.
    #[serde(default)]
    pub buckets: Option<std::collections::BTreeMap<String, f64>>,
    /// PROVENANCE: `true` marks this value an ESTIMATE (e.g. a compressor's holdout-control savings)
    /// rather than a directly measured fact — a dashboard renders it distinctly.
    #[serde(default)]
    pub estimated: Option<bool>,
    /// Confidence interval for an estimated value (finite; `ci_low ≤ ci_high` or both dropped).
    #[serde(default)]
    pub ci_low: Option<f64>,
    /// The interval's upper bound (see `ci_low`).
    #[serde(default)]
    pub ci_high: Option<f64>,
    /// Human display name (a UI falls back to `name`).
    #[serde(default)]
    pub help: Option<String>,
    /// A short display label.
    #[serde(default)]
    pub label: Option<String>,
    /// Display unit token (`"ms"`, `"$"`, `"%"`, `"req/s"`, …) — max 16 chars, sanitized.
    #[serde(default)]
    pub unit: Option<String>,
    /// Rendering hint: `number` | `gauge` | `counter` | `sparkline` | `histogram` (else dropped).
    #[serde(default)]
    pub viz: Option<String>,
    /// Gauge normalization ceiling (finite number, else dropped).
    #[serde(default)]
    pub max: Option<f64>,
    // Time SERIES are the CONSUMER's job in 1.3 (a dashboard samples `status` and accumulates); an
    // engine-retained `series` member is the reserved append-only path (a future release). A hook
    // may send unknown members today — they are ignored, not an error.
}

/// The hook's `status` reply body (liberal: every field optional, unknown fields ignored),
/// deserialized into the shared `crate::hooks::HookStatus` shape. `metrics` is the raw array of entry
/// objects (validated downstream by [`parse_status_metrics`]).
#[derive(Debug, Default, Deserialize)]
pub struct StatusReply {
    /// The settings version the hook says it is running.
    #[serde(default)]
    pub settings_version: Option<u64>,
    /// The hook's echo of its resolved settings bag.
    #[serde(default)]
    // settings-leak-lint: allow — INBOUND wire reply the engine only consumes: the hook's echo of
    // the RESOLVED bag. It is never serialized to a reader (`hook_status` projects `settings_keys`
    // from it; `settings_drift_keys` compares key names), and this is the exact type whose leak
    // — historical #3 — the widened scan root exists to keep caught.
    pub settings: Option<serde_json::Map<String, serde_json::Value>>,
    /// The raw metric entries, validated by [`parse_status_metrics`].
    #[serde(default)]
    pub metrics: Option<Vec<serde_json::Value>>,
}

impl From<StatusReply> for crate::hooks::HookStatus {
    fn from(r: StatusReply) -> Self {
        crate::hooks::HookStatus {
            settings_version: r.settings_version,
            settings: r.settings,
            metrics: r.metrics,
        }
    }
}

/// The `status` reply envelope (`{"status": {...}}`); `None`/absent = the hook doesn't speak it
/// (per the unknown-op contract rule, `{}` = unsupported → busbar fails open).
#[derive(Debug, Default, Deserialize)]
pub struct StatusEnvelope {
    /// The `status` member; absent = the hook does not speak it.
    #[serde(default)]
    pub status: Option<StatusReply>,
}

/// Per-reply cap on hook-reported metric entries (excess dropped — bounded registry).
pub const MAX_HOOK_METRICS: usize = 64;
/// Per-entry cap on label pairs (a labeled series stays small — cardinality guard).
pub const MAX_METRIC_LABELS: usize = 8;
/// Metric-help length cap (chars), sanitized through `sanitize_reject_message` before exposure.
pub const MAX_METRIC_HELP_CHARS: usize = 200;
/// Display-hint + label-value caps (same sanitize rule as help).
pub const MAX_METRIC_LABEL_CHARS: usize = 64;
/// Display-unit cap (chars).
pub const MAX_METRIC_UNIT_CHARS: usize = 16;

/// Validate a hook-reported metric NAME or LABEL KEY: `^[a-z][a-z0-9_]{0,63}$`. Anything else is
/// dropped — names/keys become Prometheus identifiers, so the charset is enforced structurally (a
/// hook granted `prompt: ro` physically cannot smuggle content into a scrape).
pub fn valid_metric_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= 64
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Char-boundary-safe sanitize + cap (`String::truncate` takes BYTES and panics off a
/// char boundary; `.chars().take(n)` is panic-free and matches the documented "≤ N chars" rule).
/// An over-cap value is cut at the cap with nothing added, as 1.5.5 cut it.
pub fn sanitize_cap(raw: &str, n: usize) -> String {
    sanitize_reject_message(raw).chars().take(n).collect()
}

/// Parse + validate the metrics ARRAY of a `status` reply FAIL-OPEN: a malformed entry (bad
/// name/type, non-finite value) is DROPPED whole, valid ones kept, capped at [`MAX_HOOK_METRICS`].
/// Within an entry, malformed OPTIONAL members (an out-of-charset label key, a non-finite quantile,
/// an inverted CI, an out-of-vocabulary viz) are dropped INDIVIDUALLY — the metric survives. Every
/// exposed string is sanitized + length-bounded; every number is finite.
pub fn parse_status_metrics(raw: &[serde_json::Value]) -> Vec<HookMetric> {
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

use crate::hooks::RewriteReply;

/// Parse the untyped `rewrite` value fail-closed. A well-formed rewrite is `{"messages": [...],
/// "tools"?: [...]}` with a NON-EMPTY messages array; anything else yields `None` (proceed with the
/// original body). `tools` is optional (defaults empty).
pub fn parse_rewrite(value: &serde_json::Value) -> Option<RewriteReply> {
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

/// Reject-status clamp range + fallback: any status outside 400..=499 becomes 403.
pub const REJECT_STATUS_DEFAULT: u16 = 403;

/// Clamp a hook-supplied reject status to the client-error range: anything outside 400..=499
/// becomes `REJECT_STATUS_DEFAULT` (403). Shared by the hook reply read-back (`policy::reject_of`)
/// and forward's policy-outcome seam (defense in depth for a `RoutingDecision::Reject`
/// constructed directly by a policy impl), so no producer can mint a success/redirect/5xx.
pub fn clamp_reject_status(status: u16) -> u16 {
    if (400..=499).contains(&status) {
        status
    } else {
        REJECT_STATUS_DEFAULT
    }
}
/// Reject-message length cap (chars). Long enough for a real reason, short enough for an error body.
pub const REJECT_MESSAGE_MAX_CHARS: usize = 300;
/// Reject-message fallback when the hook sends none (or nothing survives sanitizing).
pub const REJECT_MESSAGE_DEFAULT: &str = "Request rejected by the routing policy.";

/// Sanitize a reject message for the client error body AND the operator log line: strip control
/// chars, the Unicode line/paragraph separators (U+2028/29 — several log/OTLP pipelines treat
/// them as newlines: a record-splitting vector like CRLF), and the invisible direction/zero-width
/// formatting chars (bidi overrides U+202A..=U+202E and isolates U+2066..=U+2069 can visually
/// spoof a log line in a terminal; zero-widths U+200B..=U+200F and U+FEFF hide content). Cap the
/// length (cut at the cap with nothing added, the 1.5.5 bytes); fall back to the canned default
/// when nothing printable survives.
///
/// Shared by the hook reply read-back (`policy::reject_of`) and by `forward`'s seam mapping (defense in
/// depth for a `RoutingDecision::Reject` constructed directly by a policy impl), so the "safe to
/// log, safe for the client" guarantee holds for EVERY producer of a rejection.
pub fn sanitize_reject_message(raw: &str) -> String {
    let message: String = raw
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
        .take(REJECT_MESSAGE_MAX_CHARS)
        .collect();
    if message.trim().is_empty() {
        REJECT_MESSAGE_DEFAULT.to_string()
    } else {
        message
    }
}
