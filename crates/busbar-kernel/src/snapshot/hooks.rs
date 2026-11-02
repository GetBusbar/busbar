// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::export_calls::{Family, Sample};
use busbar_contract::hook_wire::reply::HookMetric;
use std::collections::HashMap;
use std::sync::RwLock;
use zeroize::{Zeroize, Zeroizing};

/// A private hook identity retained by a cache or in-flight refresh.
#[derive(Hash, PartialEq, Eq)]
struct HookName(String);

impl std::borrow::Borrow<str> for HookName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl Drop for HookName {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone)]
struct Metrics(Vec<HookMetric>);

impl Drop for Metrics {
    fn drop(&mut self) {
        for m in &mut self.0 {
            m.name.zeroize();
            m.kind.zeroize();
            m.help.zeroize();
            m.label.zeroize();
            m.unit.zeroize();
            m.viz.zeroize();
            if let Some(labels) = m.labels.take() {
                for (mut k, mut v) in labels {
                    k.zeroize();
                    v.zeroize();
                }
            }
            for map in [&mut m.quantiles, &mut m.buckets] {
                if let Some(entries) = map.take() {
                    for (mut key, _) in entries {
                        key.zeroize();
                    }
                }
            }
        }
    }
}

pub(crate) const HOOK_METRICS_TTL_SECS: u64 = 10;

struct Cached {
    fetched_at: u64,
    metrics: Metrics,
}

static CACHE: RwLock<Option<HashMap<HookName, Cached>>> = RwLock::new(None);

static IN_FLIGHT: RwLock<Option<std::collections::HashSet<HookName>>> = RwLock::new(None);

struct InFlight(HookName);

impl InFlight {
    fn claim(name: &str) -> Option<InFlight> {
        let mut guard = IN_FLIGHT.write().unwrap_or_else(|e| e.into_inner());
        let set = guard.get_or_insert_with(std::collections::HashSet::new);
        set.insert(HookName(name.to_string()))
            .then(|| InFlight(HookName(name.to_string())))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        let mut guard = IN_FLIGHT.write().unwrap_or_else(|e| e.into_inner());
        if let Some(set) = guard.as_mut() {
            set.remove(&self.0);
        }
    }
}

fn is_stale(name: &str, now: u64) -> bool {
    let guard = CACHE.read().unwrap_or_else(|e| e.into_inner());
    match guard.as_ref().and_then(|m| m.get(name)) {
        Some(c) => now.saturating_sub(c.fetched_at) >= HOOK_METRICS_TTL_SECS,
        None => true,
    }
}

fn store(name: &str, metrics: Vec<HookMetric>, now: u64) {
    let metrics = Metrics(metrics);
    let mut guard = CACHE.write().unwrap_or_else(|e| e.into_inner());
    let retired = guard.get_or_insert_with(HashMap::new).insert(
        HookName(name.to_string()),
        Cached {
            fetched_at: now,
            metrics,
        },
    );
    drop(guard);
    drop(retired);
}

fn prune_absent<'a>(keep: impl Iterator<Item = &'a str>) {
    let keep: std::collections::HashSet<&str> = keep.collect();
    let mut guard = CACHE.write().unwrap_or_else(|e| e.into_inner());
    let retired: Vec<_> = if let Some(m) = guard.as_mut() {
        if m.keys().any(|k| !keep.contains(k.0.as_str())) {
            m.extract_if(|k, _| !keep.contains(k.0.as_str())).collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    drop(guard);
    for (name, cached) in retired {
        drop(name);
        drop(cached);
    }
}

fn snapshot() -> Vec<(Zeroizing<String>, Metrics)> {
    let guard = CACHE.read().unwrap_or_else(|e| e.into_inner());
    guard
        .as_ref()
        .map(|m| {
            m.iter()
                .map(|(k, v)| (Zeroizing::new(k.0.clone()), v.metrics.clone()))
                .collect()
        })
        .unwrap_or_default()
}

async fn refresh(
    claim: InFlight,
    hook: crate::config::HookCfg,
    settings_version: u64,
    env: crate::hooks::HookEnv,
) {
    let name = &claim.0 .0;
    let metrics = match crate::hooks::fetch_status(name, &hook, settings_version, &env).await {
        Some(status) => status
            .metrics
            .as_ref()
            .map(|m| busbar_contract::hook_wire::reply::parse_status_metrics(m))
            .unwrap_or_default(),

        None => Vec::new(),
    };
    store(name, metrics, busbar_kernel::store::now());
}

pub(crate) fn families(app: &crate::state::App) -> Vec<Family> {
    let now = busbar_kernel::store::now();

    prune_absent(app.hook_registry.keys().map(String::as_str));

    for (name, hook) in app.hook_registry.iter() {
        if !is_stale(name, now) {
            continue;
        }
        let Some(claim) = InFlight::claim(name) else {
            continue;
        };
        tokio::spawn(refresh(
            claim,
            hook.clone(),
            app.config_version,
            app.hook_env.clone(),
        ));
    }
    let snapshot = snapshot();
    fold_families(
        snapshot
            .iter()
            .map(|(name, metrics)| (name.as_str(), metrics.0.as_slice())),
    )
}

type MetricGroup<'a> = (
    &'static str,
    Option<&'a str>,
    Vec<(&'a str, &'a HookMetric)>,
);

#[cfg(test)]
pub(crate) fn families_of(hooks: &[(String, Vec<HookMetric>)]) -> Vec<Family> {
    fold_families(
        hooks
            .iter()
            .map(|(name, metrics)| (name.as_str(), metrics.as_slice())),
    )
}

fn fold_families<'a>(hooks: impl Iterator<Item = (&'a str, &'a [HookMetric])>) -> Vec<Family> {
    let mut order: Vec<&str> = Vec::new();
    let mut groups: HashMap<&str, MetricGroup<'_>> = HashMap::new();
    let mut sorted: Vec<_> = hooks.collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (hook_name, metrics) in sorted {
        for m in metrics {
            if m.name.starts_with("busbar_") {
                continue;
            }
            let prom_type = prom_type_of(m);
            let entry = groups.entry(m.name.as_str()).or_insert_with(|| {
                order.push(m.name.as_str());
                (prom_type, m.help.as_deref(), Vec::new())
            });
            if entry.0 != prom_type {
                continue;
            }
            if entry.1.is_none() {
                entry.1 = m.help.as_deref();
            }
            entry.2.push((hook_name, m));
        }
    }

    let mut out = Vec::with_capacity(order.len());
    order.sort();
    for name in &order {
        let (ptype, help, entries) = &groups[name];
        let mut samples = Vec::new();
        for (hook_name, m) in entries {
            match *ptype {
                "histogram" => histogram_samples(&mut samples, name, hook_name, m),
                "summary" => summary_samples(&mut samples, name, hook_name, m),
                _ => samples.push(Sample {
                    name: (*name).to_string(),
                    labels: render_labels(hook_name, m.labels.as_ref(), &[]),
                    value: fmt_f64(m.value),
                }),
            }
        }
        out.push(Family {
            name: (*name).to_string(),
            help: help.as_deref().map(escape_help),
            unit: None,
            kind: busbar_contract::export_calls::kind_of(ptype)
                .unwrap_or(busbar_contract::abi::export::SCRAPE_KIND_UNTYPED),
            samples,
        });
    }
    out
}

fn prom_type_of(m: &HookMetric) -> &'static str {
    match m.kind.as_str() {
        "counter" => "counter",
        "gauge" => "gauge",
        "histogram" if m.buckets.is_some() => "histogram",
        "histogram" => "summary",
        _ => "untyped",
    }
}

fn histogram_samples(out: &mut Vec<Sample>, name: &str, hook: &str, m: &HookMetric) {
    let mut saw_inf = false;
    if let Some(buckets) = &m.buckets {
        let mut rows: Vec<(&String, &f64)> = buckets.iter().collect();
        rows.sort_by(|a, b| {
            let pa = if a.0 == "+Inf" {
                f64::INFINITY
            } else {
                a.0.parse().unwrap_or(f64::INFINITY)
            };
            let pb = if b.0 == "+Inf" {
                f64::INFINITY
            } else {
                b.0.parse().unwrap_or(f64::INFINITY)
            };
            pa.partial_cmp(&pb).unwrap_or(std::cmp::Ordering::Equal)
        });
        for (le, count) in rows {
            if le == "+Inf" {
                saw_inf = true;
            }
            out.push(Sample {
                name: sample_name(name, "_bucket"),
                labels: render_labels(hook, m.labels.as_ref(), &[("le", le)]),
                value: fmt_f64(*count),
            });
        }
    }

    if !saw_inf {
        out.push(Sample {
            name: sample_name(name, "_bucket"),
            labels: render_labels(hook, m.labels.as_ref(), &[("le", "+Inf")]),
            value: fmt_f64(m.value),
        });
    }
    out.push(Sample {
        name: sample_name(name, "_count"),
        labels: render_labels(hook, m.labels.as_ref(), &[]),
        value: fmt_f64(m.value),
    });
}

fn summary_samples(out: &mut Vec<Sample>, name: &str, hook: &str, m: &HookMetric) {
    if let Some(qs) = &m.quantiles {
        for (q, v) in qs {
            out.push(Sample {
                name: name.to_string(),
                labels: render_labels(hook, m.labels.as_ref(), &[("quantile", q)]),
                value: fmt_f64(*v),
            });
        }
    }
    out.push(Sample {
        name: sample_name(name, "_count"),
        labels: render_labels(hook, m.labels.as_ref(), &[]),
        value: fmt_f64(m.value),
    });
}

fn render_labels(
    hook: &str,
    labels: Option<&std::collections::BTreeMap<String, String>>,
    extra: &[(&str, &str)],
) -> Vec<(String, String)> {
    let mut parts: Vec<(String, String)> = Vec::new();
    parts.push(("hook".to_string(), escape_label(hook)));
    if let Some(m) = labels {
        for (k, v) in m {
            if k == "hook" || extra.iter().any(|(ek, _)| ek == k) {
                continue;
            }
            parts.push((k.clone(), escape_label(v)));
        }
    }
    for (k, v) in extra {
        parts.push(((*k).to_string(), escape_label(v)));
    }
    parts
}

fn sample_name(name: &str, suffix: &str) -> String {
    let capacity = name
        .len()
        .checked_add(suffix.len())
        .expect("metric name size overflow");
    let mut out = Zeroizing::new(String::with_capacity(capacity));
    out.push_str(name);
    out.push_str(suffix);
    std::mem::take(&mut *out)
}

fn escape_label(s: &str) -> String {
    escape(s, true)
}

fn escape_help(s: &str) -> String {
    escape(s, false)
}

fn escape(s: &str, quotes: bool) -> String {
    let cap = s.len().checked_mul(2).expect("metric escape size overflow");
    let mut out = Zeroizing::new(String::with_capacity(cap));
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '"' if quotes => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    std::mem::take(&mut *out)
}

fn fmt_f64(v: f64) -> String {
    if !v.is_finite() {
        return "0".to_string();
    }
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

#[cfg(test)]
#[path = "../tests/snapshot_hooks_tests.rs"]
mod tests;
