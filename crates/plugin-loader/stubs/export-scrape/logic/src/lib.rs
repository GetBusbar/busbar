// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![deny(unsafe_code)]

pub mod door;

use busbar_contract::abi::sdk::{MetricFamily, MetricSample};

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

pub const NAME: &str = "busbar-stub-export-scrape";

pub const ALIAS: &str = "prometheus";

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

const ZERO_RETENTION: &str =
    "the `module: prometheus` export instance sets settings.buffer_seconds: 0, \
     which retains no observations — every scrape would report empty quantiles while still paying \
     the recording cost. Name a positive retention window in seconds, or remove the instance to \
     turn metrics off";

pub fn validate(settings: &[u8]) -> Result<(), String> {
    let parsed = serde_json::from_slice(settings)
        .and_then(serde_json::from_value::<PrometheusSettings>)
        .map_err(|e| format!("settings: {e}"))?;
    if parsed.buffer_seconds == 0 {
        return Err(ZERO_RETENTION.to_string());
    }
    Ok(())
}

pub fn render(families: &[MetricFamily]) -> String {
    render_exposition(&canonical_order(families))
}

fn kind_rank(kind: &str) -> u8 {
    match kind {
        "counter" => 0,
        "gauge" => 1,
        "histogram" | "summary" => 2,
        _ => 3,
    }
}

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
