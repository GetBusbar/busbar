// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 HOOK WIRE, REPLY SIDE: what the HOST still reads of a hook's 1.5.5 JSON after the hook

use serde::Deserialize;

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
    pub settings: Option<crate::plugin_settings::Settings>,
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

/// Per-reply cap on hook-reported metric entries (excess dropped — bounded registry).
pub const MAX_HOOK_METRICS: usize = 64;
/// Per-entry cap on label pairs (a labeled series stays small — cardinality guard).
pub const MAX_METRIC_LABELS: usize = 8;
/// Metric-help length cap (chars), sanitized through `sanitize_cap` before exposure.
pub const MAX_METRIC_HELP_CHARS: usize = 200;
/// Display-hint + label-value caps (same sanitize rule as help).
pub const MAX_METRIC_LABEL_CHARS: usize = 64;
/// Display-unit cap (chars).
pub const MAX_METRIC_UNIT_CHARS: usize = 16;

/// Validate a hook-reported metric NAME or LABEL KEY: `^[a-z][a-z0-9_]{0,63}$`. Anything else is
pub fn valid_metric_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && name.len() <= 64
        && bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

/// Char-boundary-safe sanitize + cap (`String::truncate` takes BYTES and panics off a
pub fn sanitize_cap(raw: &str, n: usize) -> String {
    sanitize_cap_counted(raw, n).0
}

/// The characters [`sanitize_cap`] keeps: no control characters, no line/paragraph separators,
/// zero-width or bidi-override formatting, and no BOM.
fn kept(c: &char) -> bool {
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
}

/// Which plugin-supplied text a cap applies to. A closed set, so it is safe as a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TextField {
    /// A hook's reject message ([`REJECT_MESSAGE_MAX_CHARS`]).
    RejectMessage,
    /// A metric's `help` ([`MAX_METRIC_HELP_CHARS`]).
    MetricHelp,
    /// A metric's `label` display hint ([`MAX_METRIC_LABEL_CHARS`]).
    MetricLabel,
    /// A metric's `unit` ([`MAX_METRIC_UNIT_CHARS`]).
    MetricUnit,
    /// A metric label VALUE ([`MAX_METRIC_LABEL_CHARS`]).
    MetricLabelValue,
    /// A plugin diagnostic's message.
    DiagMessage,
    /// A plugin diagnostic's field value.
    DiagField,
}

impl TextField {
    /// Every field, in declaration order.
    pub const ALL: [TextField; 7] = [
        TextField::RejectMessage,
        TextField::MetricHelp,
        TextField::MetricLabel,
        TextField::MetricUnit,
        TextField::MetricLabelValue,
        TextField::DiagMessage,
        TextField::DiagField,
    ];

    /// The field's stable name, as a log field and a metric label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            TextField::RejectMessage => "reject_message",
            TextField::MetricHelp => "metric_help",
            TextField::MetricLabel => "metric_label",
            TextField::MetricUnit => "metric_unit",
            TextField::MetricLabelValue => "metric_label_value",
            TextField::DiagMessage => "diag_message",
            TextField::DiagField => "diag_field",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// The cuts one parse made, per [`TextField`]: how many values were over their cap, and the longest
/// of them. Every length is the SANITISED length in chars (control and format characters removed,
/// before the cap), not the raw length on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TextCuts {
    cuts: [(u32, usize); 7],
}

impl TextCuts {
    /// Notes one value of `field` cut from `sanitised_chars` chars.
    pub fn record(&mut self, field: TextField, sanitised_chars: usize) {
        let (count, max_sanitised) = &mut self.cuts[field.index()];
        *count = count.saturating_add(1);
        *max_sanitised = (*max_sanitised).max(sanitised_chars);
    }

    /// Each field that was cut at least once: `(field, count, max_sanitised)`.
    pub fn iter(&self) -> impl Iterator<Item = (TextField, u32, usize)> + '_ {
        TextField::ALL
            .into_iter()
            .zip(self.cuts)
            .filter(|(_, (count, _))| *count > 0)
            .map(|(field, (count, max_sanitised))| (field, count, max_sanitised))
    }

    /// No value was cut.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cuts.iter().all(|(count, _)| *count == 0)
    }
}

/// [`sanitize_cap`], also returning the sanitised length in chars when it was over `n` (the value
/// was cut), else `None`. One pass: the first `n` kept chars are collected, the rest only counted.
pub fn sanitize_cap_counted(raw: &str, n: usize) -> (String, Option<usize>) {
    let mut out = String::new();
    let mut sanitised = 0usize;
    for c in raw.chars().filter(kept) {
        if sanitised < n {
            out.push(c);
        }
        sanitised += 1;
    }
    (out, (sanitised > n).then_some(sanitised))
}

/// [`sanitize_reject_message`], also returning the sanitised length in chars when it was over
/// [`REJECT_MESSAGE_MAX_CHARS`], else `None`. A cut is reported even when the kept text is all
/// whitespace and the default message is returned instead.
pub fn sanitize_reject_message_counted(raw: &str) -> (String, Option<usize>) {
    let (message, cut) = sanitize_cap_counted(raw, REJECT_MESSAGE_MAX_CHARS);
    if message.trim().is_empty() {
        (REJECT_MESSAGE_DEFAULT.to_string(), cut)
    } else {
        (message, cut)
    }
}

/// [`sanitize_cap_counted`], noting a cut of `field` in `cuts`.
fn cap_noting(cuts: &mut TextCuts, field: TextField, raw: &str, n: usize) -> String {
    let (value, cut) = sanitize_cap_counted(raw, n);
    if let Some(sanitised_chars) = cut {
        cuts.record(field, sanitised_chars);
    }
    value
}

/// Parse + validate the metrics ARRAY of a `status` reply FAIL-OPEN: a malformed entry (bad
pub fn parse_status_metrics(raw: &[serde_json::Value]) -> Vec<HookMetric> {
    parse_status_metrics_counted(raw).0
}

/// [`parse_status_metrics`], also returning the cuts it made to the metrics it kept. Only label
/// values that are kept (within [`MAX_METRIC_LABELS`]) are counted.
pub fn parse_status_metrics_counted(raw: &[serde_json::Value]) -> (Vec<HookMetric>, TextCuts) {
    let mut cuts = TextCuts::default();
    let mut out = Vec::new();
    for v in raw {
        if out.len() >= MAX_HOOK_METRICS {
            break;
        }
        let Ok(m) = serde_json::from_value::<HookMetric>(v.clone()) else {
            continue;
        };
        if let Some(m) = bound_metric(m, &mut cuts) {
            out.push(m);
        }
    }
    (out, cuts)
}

/// One reported metric, validated and bounded as [`parse_status_metrics_counted`] bounds each
/// entry it keeps: `None` when the entry is refused (a bad name, an unknown type, a value that is
/// not finite), else the entry with its strings capped, noting each cut in `cuts`. An entry that
/// arrives typed (a plugin's back-channel metric, read off its declared family) is bounded here
/// exactly as one read off a reply's JSON array is.
pub fn bound_metric(mut m: HookMetric, cuts: &mut TextCuts) -> Option<HookMetric> {
    if !valid_metric_name(&m.name)
        || !matches!(m.kind.as_str(), "counter" | "gauge" | "histogram")
        || !m.value.is_finite()
    {
        return None;
    }

    m.labels = m.labels.map(|labels| {
        labels
            .into_iter()
            .filter(|(k, _)| valid_metric_name(k))
            .map(|(k, val)| {
                let val = cap_noting(
                    cuts,
                    TextField::MetricLabelValue,
                    &val,
                    MAX_METRIC_LABEL_CHARS,
                );
                (k, val)
            })
            .take(MAX_METRIC_LABELS)
            .collect()
    });

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

    m.buckets = m
        .buckets
        .map(|b| {
            b.into_iter()
                .filter(|(k, val)| {
                    val.is_finite()
                        && *val >= 0.0
                        && (k == "+Inf" || k.parse::<f64>().is_ok_and(f64::is_finite))
                })
                .take(MAX_METRIC_LABELS * 8)
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .filter(|b| !b.is_empty());

    match (m.ci_low, m.ci_high) {
        (Some(lo), Some(hi)) if lo.is_finite() && hi.is_finite() && lo <= hi => {}
        _ => {
            m.ci_low = None;
            m.ci_high = None;
        }
    }
    m.help = m
        .help
        .map(|h| cap_noting(cuts, TextField::MetricHelp, &h, MAX_METRIC_HELP_CHARS));
    m.label = m
        .label
        .map(|l| cap_noting(cuts, TextField::MetricLabel, &l, MAX_METRIC_LABEL_CHARS));
    m.unit = m
        .unit
        .map(|u| cap_noting(cuts, TextField::MetricUnit, &u, MAX_METRIC_UNIT_CHARS))
        .filter(|s| !s.is_empty());
    m.viz = m.viz.filter(|v| {
        matches!(
            v.as_str(),
            "number" | "gauge" | "counter" | "sparkline" | "histogram"
        )
    });
    m.max = m.max.filter(|v| v.is_finite());
    Some(m)
}

/// A back-channel metric in the shape a plugin publishes it ([`PluginMetric`], the published
/// shape of an envelope's `metrics` entries) as the host's own entry: field for field, the entry
/// its JSON form deserializes into.
///
/// [`PluginMetric`]: crate::observe::PluginMetric
impl From<crate::observe::PluginMetric> for HookMetric {
    fn from(m: crate::observe::PluginMetric) -> Self {
        HookMetric {
            name: m.name,
            kind: m.kind,
            value: m.value,
            labels: m.labels,
            quantiles: m.quantiles,
            buckets: m.buckets,
            estimated: m.estimated,
            ci_low: m.ci_low,
            ci_high: m.ci_high,
            help: m.help,
            label: m.label,
            unit: m.unit,
            viz: m.viz,
            max: m.max,
        }
    }
}

use crate::hooks::RewriteReply;

/// Parse the untyped `rewrite` value fail-closed. A well-formed rewrite is `{"messages": [...],
pub fn parse_rewrite(value: &serde_json::Value) -> Option<RewriteReply> {
    crate::stage_probe::tick(crate::stage_probe::Derive::ProjectCopy);
    let messages: Vec<serde_json::Value> = value.get("messages")?.as_array()?.clone();
    if messages.is_empty() {
        return None;
    }
    let tools = match value.get("tools") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(t) => t.as_array()?.clone(),
    };
    Some(RewriteReply { messages, tools })
}

/// Reject-status clamp range + fallback: any status outside 400..=499 becomes 403.
pub const REJECT_STATUS_DEFAULT: u16 = 403;

/// Clamp a hook-supplied reject status to the client-error range: anything outside 400..=499
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
pub fn sanitize_reject_message(raw: &str) -> String {
    sanitize_reject_message_counted(raw).0
}

#[cfg(test)]
mod bc2_rewrite_tests {
    use super::*;

    #[test]
    fn non_array_tools_is_refused() {
        let v = serde_json::json!({"messages":[{}],"tools":"x"});
        assert!(parse_rewrite(&v).is_none());
        assert!(parse_rewrite(&serde_json::json!({"messages":[{}],"tools":null})).is_some());
    }
}
