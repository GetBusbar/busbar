// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    BUCKET_BUDGET_REMAINING_CENTS, BUCKET_SPEND_CENTS, BUCKET_TOKENS, GOVERNED_ADMISSIONS_LIVE,
    KEY_SPEND_CENTS, KEY_TOKENS_TOTAL, UNIT_CHECKPOINTS_TERMINAL,
};
use crate::diagnostics::{
    diag_debug, diag_warn, METRICS_KEY_GAUGE_LIMIT_EXCEEDED,
    METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED, METRICS_SCRAPE_KEY_USAGE_READ_FAILED,
    METRICS_SCRAPE_LIST_KEYS_FAILED,
};
use crate::state::App;

pub(super) fn set_gauge(gauge: metrics::Gauge, value: impl Into<i128>) {
    let exact: i128 = value.into();
    gauge.set(exact as f64);
}

fn set_count_gauge(gauge: metrics::Gauge, value: busbar_contract::count::Count) {
    // Floating point belongs only at the metrics display boundary.
    gauge.set(value.micros() as f64 / 1_000_000.0);
}

fn metric_labels(
    key: &busbar_contract::records::VirtualKey,
) -> impl Iterator<Item = (&String, &String)> {
    key.labels.iter()
}

pub(super) async fn refresh_money_gauges(app: &App, now: u64) -> Result<(), &'static str> {
    if let Some(gov) = &app.governance {
        refresh_governance_gauges(gov, &app.cost, now).await?;
    }
    Ok(())
}

pub(super) async fn refresh_governance_gauges(
    gov: &crate::governance::GovState,
    cost: &crate::cost::CostModel,
    now: u64,
) -> Result<(), &'static str> {
    // The admission gate first: in memory, so a store outage below never hides it.
    let gate = gov.admissions();
    set_gauge(metrics::gauge!(UNIT_CHECKPOINTS_TERMINAL), gate.terminal());
    set_gauge(metrics::gauge!(GOVERNED_ADMISSIONS_LIVE), gate.live());
    let keys = match gov.all_keys_async().await {
        Ok(ks) => ks,
        Err(e) => {
            diag_debug!(METRICS_SCRAPE_LIST_KEYS_FAILED, error = %e, "metrics scrape: failed to list virtual keys; skipping per-key spend/token gauges");
            return Err("the current key snapshot is unavailable");
        }
    };

    let key_gauge_limit = crate::limits::key_gauge_limit();

    static KEY_GAUGE_LIMIT_WARNED: std::sync::atomic::AtomicBool =
        std::sync::atomic::AtomicBool::new(false);
    if keys.len() > key_gauge_limit {
        if !KEY_GAUGE_LIMIT_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
            diag_warn!(
                METRICS_KEY_GAUGE_LIMIT_EXCEEDED,
                key_count = keys.len(),
                limit = key_gauge_limit,
                "metrics scrape: virtual-key count exceeds per-key gauge limit; emitting gauges \
                 for only the first `limit` keys to bound cardinality and scrape-path DB load",
            );
        } else {
            diag_debug!(
                METRICS_KEY_GAUGE_LIMIT_EXCEEDED,
                key_count = keys.len(),
                limit = key_gauge_limit,
                "metrics scrape: virtual-key count still exceeds per-key gauge limit; emitting \
                 gauges for only the first `limit` keys to bound cardinality and scrape-path DB \
                 load",
            );
        }
    } else {
        KEY_GAUGE_LIMIT_WARNED.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    let keys = &keys[..keys.len().min(key_gauge_limit)];
    let ids: Vec<(&str, &str)> = keys
        .iter()
        .map(|key| (key.id.as_str(), crate::governance::WINDOW_TOTAL))
        .collect();
    let views = match gov.scrape_usage_async(cost, &ids, now).await {
        Ok(views) => views,
        Err(e) => {
            diag_debug!(METRICS_SCRAPE_KEY_USAGE_READ_FAILED, error = %e, "metrics scrape: usage read failed; skipping keys");
            return Err("the current key usage snapshot is unavailable");
        }
    };
    for (key, view) in keys.iter().zip(views) {
        let labels: Vec<metrics::Label> = metric_labels(key)
            .map(|(k, v)| metrics::Label::new(k.clone(), v.clone()))
            .collect();
        let mut base = Vec::with_capacity(labels.len() + 1);
        base.push(metrics::Label::new("key", key.id.clone()));
        base.extend(labels.iter().cloned());
        set_gauge(
            metrics::gauge!(KEY_SPEND_CENTS, base.clone()),
            view.usage.spend_cents,
        );
        set_count_gauge(metrics::gauge!(KEY_TOKENS_TOTAL, base), view.usage.tokens);

        for (model, tokens) in view.models {
            for (tier, v) in crate::governance::token_series(&model, &tokens) {
                let mut series = Vec::with_capacity(labels.len() + 3);
                series.push(metrics::Label::new("bucket", key.id.clone()));
                series.extend(labels.iter().cloned());
                series.push(metrics::Label::new("model", model.clone()));
                series.push(metrics::Label::new("tier", tier));
                set_count_gauge(metrics::gauge!(BUCKET_TOKENS, series), v);
            }
        }
    }

    let buckets: Vec<_> = cost
        .groups()
        .iter()
        .flat_map(|group| group.buckets.iter().map(move |bucket| (group, bucket)))
        .collect();
    let ids: Vec<(&str, &str)> = buckets
        .iter()
        .map(|(_, bucket)| (bucket.bucket_id.as_str(), bucket.window))
        .collect();
    let views = match gov.scrape_usage_async(cost, &ids, now).await {
        Ok(views) => views,
        Err(e) => {
            diag_debug!(METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED, error = %e, "metrics scrape: group ledger read failed; skipping");
            return Err("the current group usage snapshot is unavailable");
        }
    };
    for ((group, bucket), view) in buckets.into_iter().zip(views) {
        let dims = |extra: &[(&'static str, String)]| -> Vec<metrics::Label> {
            let mut labels = vec![
                metrics::Label::new("bucket", bucket.bucket_id.clone()),
                metrics::Label::new("group", group.name.clone()),
                metrics::Label::new("window", bucket.window),
            ];
            for (k, v) in extra {
                labels.push(metrics::Label::new(*k, v.clone()));
            }
            labels
        };
        let derived = view.usage;
        set_gauge(
            metrics::gauge!(BUCKET_SPEND_CENTS, dims(&[])),
            derived.spend_cents,
        );

        if let Some(cap) = bucket.budget_cap {
            let remaining = cap.saturating_sub(derived.spend_cents).max(0);
            set_gauge(
                metrics::gauge!(BUCKET_BUDGET_REMAINING_CENTS, dims(&[])),
                remaining,
            );
        }
        for (model, tokens) in view.models {
            for (tier, v) in crate::governance::token_series(&model, &tokens) {
                set_count_gauge(
                    metrics::gauge!(
                        BUCKET_TOKENS,
                        dims(&[("model", model.clone()), ("tier", tier)])
                    ),
                    v,
                );
            }
        }
    }
    Ok(())
}
