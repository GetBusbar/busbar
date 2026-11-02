// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    BUCKET_BUDGET_REMAINING_CENTS, BUCKET_SPEND_CENTS, BUCKET_TOKENS, KEY_SPEND_CENTS,
    KEY_TOKENS_TOTAL,
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

fn metric_labels(
    key: &busbar_contract::records::VirtualKey,
) -> impl Iterator<Item = (&String, &String)> {
    key.labels.iter()
}

pub(super) fn refresh_money_gauges(app: &App, now: u64) {
    if let Some(gov) = &app.governance {
        refresh_governance_gauges(gov, &app.cost, now);
    }
}

pub(super) fn refresh_governance_gauges(
    gov: &crate::governance::GovState,
    cost: &crate::cost::CostModel,
    now: u64,
) {
    let keys = match gov.all_keys() {
        Ok(ks) => ks,
        Err(e) => {
            diag_debug!(METRICS_SCRAPE_LIST_KEYS_FAILED, error = %e, "metrics scrape: failed to list virtual keys; skipping per-key spend/token gauges");
            Vec::new()
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
    for key in keys.iter().take(key_gauge_limit) {
        let usage = match gov.viewed_usage_for(cost, &key.id, now) {
            Ok(Some(u)) => u,
            Ok(None) => continue,
            Err(e) => {
                diag_debug!(METRICS_SCRAPE_KEY_USAGE_READ_FAILED, key = %key.id, error = %e, "metrics scrape: usage read failed; skipping key");
                continue;
            }
        };

        let base_labels = |extra: &[(&'static str, String)]| -> Vec<metrics::Label> {
            let mut labels: Vec<metrics::Label> = vec![metrics::Label::new("key", key.id.clone())];
            for (k, v) in metric_labels(key) {
                labels.push(metrics::Label::new(k.clone(), v.clone()));
            }
            for (k, v) in extra {
                labels.push(metrics::Label::new(*k, v.clone()));
            }
            labels
        };
        set_gauge(
            metrics::gauge!(KEY_SPEND_CENTS, base_labels(&[])),
            usage.spend_cents,
        );
        set_gauge(
            metrics::gauge!(KEY_TOKENS_TOTAL, base_labels(&[])),
            usage.tokens,
        );

        for (model, tokens) in
            gov.bucket_model_tokens(&key.id, crate::governance::WINDOW_TOTAL, now)
        {
            for (tier, v) in crate::governance::token_series(&model, &tokens) {
                let mut labels: Vec<metrics::Label> =
                    vec![metrics::Label::new("bucket", key.id.clone())];
                for (k, val) in metric_labels(key) {
                    labels.push(metrics::Label::new(k.clone(), val.clone()));
                }
                labels.push(metrics::Label::new("model", model.clone()));
                labels.push(metrics::Label::new("tier", tier));
                set_gauge(metrics::gauge!(BUCKET_TOKENS, labels), v);
            }
        }
    }

    for group in cost.groups() {
        for bucket in &group.buckets {
            let derived = match gov.viewed_bucket_usage(
                cost,
                &bucket.bucket_id,
                bucket.window,
                true,
                now,
            ) {
                Ok(u) => u,
                Err(e) => {
                    diag_debug!(METRICS_SCRAPE_GROUP_LEDGER_READ_FAILED, bucket = %bucket.bucket_id, error = %e, "metrics scrape: group ledger read failed; skipping");
                    continue;
                }
            };
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
            for (model, tokens) in gov.bucket_model_tokens(&bucket.bucket_id, bucket.window, now) {
                for (tier, v) in crate::governance::token_series(&model, &tokens) {
                    set_gauge(
                        metrics::gauge!(
                            BUCKET_TOKENS,
                            dims(&[("model", model.clone()), ("tier", tier)])
                        ),
                        v,
                    );
                }
            }
        }
    }
}
