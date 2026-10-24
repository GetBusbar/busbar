// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROMETHEUS EXPORT SINK — `export.<name>.module: prometheus`.
//!
//! A PULL sink on the export kind's memory ABI. The host keeps what only the host can own: the
//! recorder every emit site writes, its scrape-time gauges and the hook-metrics cache, which it
//! lends through its kind-neutral snapshot service. This sink owns the rest (`BUSBAR-1.6.0.md` §5
//! l.626-628, Appendix A B.5 l.3829): it carries the `metrics` stream, it validates the settings an
//! operator writes for it, it declares the well-known `GET /metrics` and `GET /metrics/hooks` as its
//! own routes behind the data key, and its `serve` reads the host's families (`snapshot.read`, in
//! the recorder's order) and answers the exposition in 1.5.5's bytes and content types. A snapshot
//! the host hands to `scrape` renders the same way into the host's buffer.
//!
//! One door, both ways in: [`door::door`] is the row a busbar build links, and the sibling
//! `busbar-export-prometheus-plugin` cdylib exports the same door as its one symbol.

#![deny(unsafe_code)]

pub mod door;

use busbar_contract::abi::sdk::{MetricFamily, MetricSample};

/// Render the host recorder's snapshot (the export kind's families) in the Prometheus TEXT
/// exposition format, family by family: `# HELP` (when present), `# TYPE`, the samples, a blank
/// line. Every label value and number is written as the snapshot carries it, so rendering a
/// snapshot of the host's own exposition reproduces it byte for byte.
fn render_exposition(families: &[MetricFamily]) -> String {
    let mut out = String::new();
    for f in families {
        if let Some(help) = &f.help {
            out.push_str(&format!("# HELP {} {help}\n", f.name));
        }
        out.push_str(&format!("# TYPE {} {}\n", f.name, f.kind));
        for s in &f.samples {
            out.push_str(&s.name);
            if !s.labels.is_empty() {
                let labels: Vec<String> = s
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{k}=\"{v}\""))
                    .collect();
                out.push_str(&format!("{{{}}}", labels.join(",")));
            }
            out.push_str(&format!(" {}\n", s.value));
        }
        out.push('\n');
    }
    out
}

/// Render the host's HOOK families (`/metrics/hooks`, the export kind's `scrape` with
/// `SCRAPE_FLAG_HOOK_FAMILIES`) in 1.5.5's hook exposition layout: families by name (the order the
/// host folded them in, kept stable by name), `# HELP` when present then `# TYPE`, each family's
/// samples in the order handed (hooks by name, then each hook's own report order), and NO blank line
/// between families. Every label value and number is written as the host spelled it.
pub fn render_hooks(families: &[MetricFamily]) -> String {
    let mut ordered: Vec<&MetricFamily> = families.iter().collect();
    ordered.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = String::new();
    for f in ordered {
        if let Some(help) = &f.help {
            out.push_str(&format!("# HELP {} {help}\n", f.name));
        }
        out.push_str(&format!("# TYPE {} {}\n", f.name, f.kind));
        for s in &f.samples {
            out.push_str(&s.name);
            if !s.labels.is_empty() {
                let labels: Vec<String> = s
                    .labels
                    .iter()
                    .map(|(k, v)| format!("{k}=\"{v}\""))
                    .collect();
                out.push_str(&format!("{{{}}}", labels.join(",")));
            }
            out.push_str(&format!(" {}\n", s.value));
        }
    }
    out
}

/// THE LIMITS CHECK across every configured instance of this sink, in configuration order: the sink
/// states the `one_instance` mark, so a second instance is refused in 1.5.5's words (shadow-oracle
/// cell `boot.refusal__BOOT-102__validate`), once per extra instance, naming the first.
pub fn check_limits(instances: &[String]) -> Vec<String> {
    let Some((first, rest)) = instances.split_first() else {
        return Vec::new();
    };
    rest.iter()
        .map(|name| {
            format!(
                "export.{name}: a second `module: {ALIAS}` instance (already defined as '{first}'). \
                 Prometheus serves the ONE well-known /metrics route, so a second instance could \
                 only be silently ignored — keep a single instance."
            )
        })
        .collect()
}

/// The row's canonical name.
pub const NAME: &str = "busbar-stub-export-scrape";

/// The `module:` an operator writes — the name 1.5.5 spelled the built-in by — the row's alias on
/// either door.
pub const ALIAS: &str = "prometheus";

/// What this sink DECLARES to the host (the manifest's `declares` section, `declares.json`, which
/// `busbar-plugin-pack --declares-file` signs into the tarball): it reports no series, raises no
/// code of its own and has no destination.
pub const DECLARES: &str = include_str!("../declares.json");

/// The `settings:` an operator writes for this sink — the same shape, field for field, the
/// configuration grammar has frozen for it since 1.5.3, so a refusal reads exactly as it always has.
/// The VALUES are the host's to act on (the recorder's retention window, the scrape-time gauge
/// bound); this sink only says whether they are well formed.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrometheusSettings {
    /// REQUIRED: the retention window of the rolling quantile summary, in seconds — positive.
    buffer_seconds: u64,
    /// The bound on per-key scrape-time gauges.
    #[serde(default)]
    #[allow(dead_code)]
    key_gauge_limit: usize,
}

/// The zero-retention refusal, word for word as the configuration has always reported it.
const ZERO_RETENTION: &str =
    "the `module: prometheus` export instance sets settings.buffer_seconds: 0, \
     which retains no observations — every scrape would report empty quantiles while still paying \
     the recording cost. Name a positive retention window in seconds, or remove the instance to \
     turn metrics off";

/// The settings refusal, as one complete line: a malformed bag is `settings: <serde's words>`; a
/// zero retention window asks the recorder to keep nothing while still paying to record it, which
/// is refused rather than served inert (omitting the instance is how collection is turned off).
///
/// # Errors
/// The line, when the settings are refused.
pub fn validate(settings: &[u8]) -> Result<(), String> {
    let parsed = serde_json::from_slice(settings)
        .and_then(serde_json::from_value::<PrometheusSettings>)
        .map_err(|e| format!("settings: {e}"))?;
    if parsed.buffer_seconds == 0 {
        return Err(ZERO_RETENTION.to_string());
    }
    Ok(())
}

/// The Prometheus text exposition of the snapshot: `# HELP`, `# TYPE`, the samples and the
/// family-closing blank line, every label value and number exactly as the recorder wrote it — in
/// the STABLE order [`canonical_order`] gives it.
pub fn render(families: &[MetricFamily]) -> String {
    render_exposition(&canonical_order(families))
}

/// A family kind's place in the stable order: counters, then gauges, then distributions
/// (histogram and summary), then anything else.
fn kind_rank(kind: &str) -> u8 {
    match kind {
        "counter" => 0,
        "gauge" => 1,
        "histogram" | "summary" => 2,
        _ => 3, // "untyped" or anything else the wire never actually carries
    }
}

/// The snapshot in a STABLE order: families grouped by KIND — every counter, then every gauge,
/// then every histogram/summary (a distribution) — and by name within a kind's group; and within a
/// family its series by their labels. The recorder hands families and series over in its maps' hash
/// order, which differs from boot to boot; the same metrics must scrape to the same bytes.
///
/// THE KIND GROUPING is not this sink's invention: it is v1.5.5's own wire behaviour, forced by the
/// `metrics-exporter-prometheus` renderer both v1.5.5 and this host still link — `render_to_write`
/// drains its counters map whole, then its gauges map whole, then its distributions (histogram +
/// summary) map whole, three separate passes in that fixed order, every release. A v1.5.5 capture's
/// FAMILY ORDER WITHIN a kind is not code-determined (hash-map order, "varies between runs" — a
/// prior capture cannot pin it), but WHICH KIND'S BLOCK COMES FIRST is code-determined and never
/// varies. Sorting by name within a kind is a legitimate, deterministic pick from among the orders
/// v1.5.5's own hash-random renderer could already have produced.
///
/// A SERIES is every sample sharing one label set once `le` / `quantile` are set aside — a
/// histogram's `_bucket` lines with its `_sum` and `_count`, a summary's quantiles with its `_sum`
/// and `_count`. A series is moved as a unit and its own lines keep the order the recorder wrote
/// them in (buckets ascending, then `_sum`, then `_count`), so every output is one of the orders
/// the recorder could already print.
fn canonical_order(families: &[MetricFamily]) -> Vec<MetricFamily> {
    let mut out = families.to_vec();
    out.sort_by(|a, b| {
        kind_rank(&a.kind)
            .cmp(&kind_rank(&b.kind))
            .then_with(|| a.name.cmp(&b.name))
    });
    for family in &mut out {
        let mut series: std::collections::BTreeMap<Vec<(String, String)>, Vec<MetricSample>> =
            std::collections::BTreeMap::new();
        for sample in std::mem::take(&mut family.samples) {
            let key = sample
                .labels
                .iter()
                .filter(|(k, _)| k != "le" && k != "quantile")
                .cloned()
                .collect();
            series.entry(key).or_default().push(sample);
        }
        family.samples = series.into_values().flatten().collect();
    }
    out
}
