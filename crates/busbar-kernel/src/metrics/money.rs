// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MONEY GAUGES of the `/metrics` exposition — refreshed at scrape time, never on the request
//! hot path.
//!
//! * `busbar_key_spend_cents` / `busbar_key_tokens_total` — per virtual key.
//! * `busbar_bucket_spend_cents` / `busbar_bucket_budget_remaining_cents` — per budget-group bucket,
//!   derived from the ledger x the CURRENT rate card (reprice-on-read).
//! * `busbar_bucket_tokens` — per (bucket, model, tier), the counts every spend figure is priced from.
//!
//! # INTEGERS UP TO ONE NAMED BOUNDARY
//!
//! Every figure here is an integer — cents are `i64`, token counts `u64` — from the ledger read to
//! the call that hands it to the recorder. The `metrics` facade stores a gauge as floating-point bits
//! (`Gauge::set<T: IntoF64>`, and `IntoF64` has no impl for a 64-bit integer), and the Prometheus
//! exporter prints that value. So there is exactly ONE place this file converts, [`set_gauge`], and
//! it is declared in `no-float-money`'s `MONEY_EGRESS` table: the gate scans this file whole and
//! refuses a float anywhere outside that one function's body.
//!
//! The served bytes are those of 1.5.5 by construction: 1.5.5 cast the integer straight into the
//! same gauge through the same exporter, and an integer rounds to the same float whichever integer
//! type it is widened through (`as` rounds to nearest, ties to even, from every integer type). Exact
//! up to 2^53; above that the rounding is the one 1.5.5 already served. Pinned by
//! `metrics::tests::money_gauge_bytes_are_the_1_5_5_bytes`.

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

/// THE MONEY EGRESS BOUNDARY — the one function in this file that may name a float.
///
/// Takes the figure as an integer and hands the gauge the value the recorder stores. Widening to
/// `i128` first loses nothing (every `i64` and `u64` fits) and rounds to the same float the direct
/// cast does, so the rendered text is the text 1.5.5 rendered.
pub(super) fn set_gauge(gauge: metrics::Gauge, value: impl Into<i128>) {
    let exact: i128 = value.into();
    gauge.set(exact as f64);
}

/// Refresh every money gauge for this scrape. No-op when governance is disabled. `now` is the
/// scrape's single clock read, shared with the lane gauges.
pub(super) fn refresh_money_gauges(app: &App, now: u64) {
    // ── Governance: per-key spend, budget-remaining, tokens ────────────────────────────────────
    if let Some(gov) = &app.governance {
        // `all_keys()` lists every VirtualKey from the SQLite store; this is a low-frequency scrape
        // path. On error we skip only the PER-KEY gauge refresh below (by treating the key list as
        // empty) rather than returning a stale/wrong per-key value. This must NOT `return` out of
        // the whole function: the group-bucket loop just below does not consume `keys` at all (it
        // walks `app.cost.groups()` and has its own per-bucket error handling), and the lane-health
        // gauges further down don't touch governance at all — an unrelated governance-store hiccup
        // must not blind Prometheus to a breaker tripping during that exact window (see
        // GAUGE_IDLE_TIMEOUT: a skipped refresh leaves the last-known value looking "current" for up
        // to 24h).
        let keys = match gov.all_keys() {
            Ok(ks) => ks,
            Err(e) => {
                diag_debug!(METRICS_SCRAPE_LIST_KEYS_FAILED, error = %e, "metrics scrape: failed to list virtual keys; skipping per-key spend/token gauges");
                Vec::new()
            }
        };
        // Cap per-key gauge emission. Above this many keys, emitting one series per key per scrape
        // (×3 gauges) would blow up Prometheus cardinality AND walk the store once per key on every
        // scrape. Bound BOTH by emitting at most `key_gauge_limit` keys; warn when truncating so the
        // condition is visible. Generous default — normal deployments never reach it. (A configurable
        // limit / top-N-by-spend selection is a v1.x refinement.)
        // Operator-tunable via `metrics.key_gauge_limit` (default 2000).
        let key_gauge_limit = crate::limits::key_gauge_limit();
        // Warn-once latch: the key count exceeding the gauge limit is an actionable but STABLE
        // condition (it persists across every scrape until the operator tunes
        // `metrics.key_gauge_limit` or the key count drops), and this scrape runs on every /metrics
        // pull. Warn on the TRANSITION into the over-limit state; hold subsequent scrapes at debug so
        // a busy scrape cadence cannot spam. Cleared when the count falls back under the limit so a
        // future breach re-warns.
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
            // `usage_for` queries the SQLite store for the key's current-window counters.
            let usage = match gov.usage_for(&app.cost, &key.id, now) {
                Ok(Some(u)) => u,
                Ok(None) => continue, // key vanished between list and get — skip
                Err(e) => {
                    diag_debug!(METRICS_SCRAPE_KEY_USAGE_READ_FAILED, key = %key.id, error = %e, "metrics scrape: usage read failed; skipping key");
                    continue;
                }
            };
            // key label = the operator-visible virtual-key id (`vk_<hex>`), never the bearer
            // secret. The key's MINT-TIME labels (e.g. team=growth) are echoed onto every series
            // so external Grafana can `sum by (team)` and Alertmanager can fire per team WITHOUT
            // busbar knowing what "team" means. Label KEYS are operator-chosen at mint (bounded by
            // the admin surface), never request bytes.
            let base_labels = |extra: &[(&'static str, String)]| -> Vec<metrics::Label> {
                let mut labels: Vec<metrics::Label> =
                    vec![metrics::Label::new("key", key.id.clone())];
                for (k, v) in &key.labels {
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
            // 1.5.0: keys are PURE AUTH (no inline budget cap), so there is no per-key
            // budget-remaining gauge; remaining/limit headroom lives on the GROUP buckets below.
            // Per-(bucket, model, tier) token gauges from the key bucket's ledger (the raw
            // material any external per-model cost dashboard multiplies by its own catalog). The
            // key's attribution bucket accrues in the all-time window.
            for (model, tokens) in
                gov.bucket_model_tokens(&key.id, crate::governance::WINDOW_TOTAL, now)
            {
                let tier_v = |u: &str| tokens.get(u).copied().unwrap_or(0);
                for (tier, v) in [
                    ("input", tier_v(busbar_api::UNIT_INPUT)),
                    ("output", tier_v(busbar_api::UNIT_OUTPUT)),
                    ("cache_read", tier_v(busbar_api::UNIT_CACHE_READ)),
                    ("cache_write", tier_v(busbar_api::UNIT_CACHE_WRITE)),
                ] {
                    let mut labels: Vec<metrics::Label> =
                        vec![metrics::Label::new("bucket", key.id.clone())];
                    for (k, val) in &key.labels {
                        labels.push(metrics::Label::new(k.clone(), val.clone()));
                    }
                    labels.push(metrics::Label::new("model", model.clone()));
                    labels.push(metrics::Label::new("tier", tier));
                    set_gauge(metrics::gauge!(BUCKET_TOKENS, labels), v);
                }
            }
        }

        // ── GROUP buckets: derived spend + remaining + per-(model, tier) tokens, one series per
        // (group, window) enforcement bucket. Bounded by |groups| x |windows-in-use| (operator-
        // owned names + the fixed window vocabulary). Spend derives fresh from the ledger x the
        // CURRENT rate card (reprice-on-read), fee included (each bucket counts its own requests).
        // The `group` and `window` labels are the 1.5.0 limit dimensions; `bucket` stays the raw
        // ledger id for join-ability with the store.
        for group in app.cost.groups() {
            for bucket in &group.buckets {
                let derived = match gov.derived_bucket_usage(
                    &app.cost,
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
                // Budget-remaining: only for a bucket that carries a `budget` cap.
                if let Some(cap) = bucket.budget_cap {
                    let remaining = cap.saturating_sub(derived.spend_cents).max(0);
                    set_gauge(
                        metrics::gauge!(BUCKET_BUDGET_REMAINING_CENTS, dims(&[])),
                        remaining,
                    );
                }
                for (model, tokens) in
                    gov.bucket_model_tokens(&bucket.bucket_id, bucket.window, now)
                {
                    let tier_v = |u: &str| tokens.get(u).copied().unwrap_or(0);
                    for (tier, v) in [
                        ("input", tier_v(busbar_api::UNIT_INPUT)),
                        ("output", tier_v(busbar_api::UNIT_OUTPUT)),
                        ("cache_read", tier_v(busbar_api::UNIT_CACHE_READ)),
                        ("cache_write", tier_v(busbar_api::UNIT_CACHE_WRITE)),
                    ] {
                        set_gauge(
                            metrics::gauge!(
                                BUCKET_TOKENS,
                                dims(&[("model", model.clone()), ("tier", tier.to_string())])
                            ),
                            v,
                        );
                    }
                }
            }
        }
    }
}
