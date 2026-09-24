// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/metrics.rs`.

use super::*;
use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
use crate::test_support::{LaneSpec, TestApp};
use std::sync::Arc;
// Named directly now that the recorder-install half (which imported it) lives in the substrate.
use std::time::Duration;

#[test]
fn test_render_exposes_emitted_counter() {
    init();
    metrics::counter!(
        REQUESTS_TOTAL,
        "ingress_protocol" => "acme",
        "pool" => "default",
        "outcome" => "ok"
    )
    .increment(1);

    let out = render();
    assert!(
        out.contains(REQUESTS_TOTAL),
        "exposition should contain the emitted counter; got:\n{out}"
    );
    // The label set and incremented value should be present in the scrape.
    assert!(
        out.contains("outcome=\"ok\""),
        "label should render; got:\n{out}"
    );
}

/// Closes the `enabled`/`recorder_installed`/`retaining`/`describe`/`GAUGE_IDLE_TIMEOUT`
/// coverage gaps together, since `ENABLED`/`HANDLE` are process-global `OnceLock`s that
/// can only be driven through their "resolved" state once per test binary — every other test
/// in this module already calls `init()`, so by the time this runs the globals are certainly
/// resolved either way; the assertions below are meaningful regardless of ordering.
#[test]
fn test_enabled_recorder_installed_retaining_and_describe_after_init() {
    init();
    assert!(
        enabled(),
        "enabled() must be true once init() has run (ENABLED.set(true))"
    );
    assert!(
        recorder_installed(),
        "recorder_installed() must be true once init()'s recorder install completes"
    );
    assert!(
        retaining(),
        "retaining() must be true once the recorder is installed"
    );
    // describe() registers HELP text via describe_counter! — observable in the exposition as
    // a `# HELP <metric> <text>` line. A no-op describe() (the `with ()` mutant) would leave
    // this line absent even though the counter itself still renders once emitted.
    metrics::counter!(
        REQUESTS_TOTAL,
        "ingress_protocol" => "describe_probe",
        "pool" => "describe_probe",
        "outcome" => "describe_probe"
    )
    .increment(1);
    let out = render();
    assert!(
        out.contains("# HELP busbar_requests_total"),
        "describe() must have registered REQUESTS_TOTAL's HELP text; got:\n{out}"
    );
}

/// The gauge idle-eviction window is exactly 24h, not some other magnitude a mutated
/// `*`/`+`/`/` in `24 * 60 * 60` could silently produce.
#[test]
fn test_gauge_idle_timeout_is_exactly_24_hours() {
    assert_eq!(GAUGE_IDLE_TIMEOUT, Duration::from_secs(86_400));
    assert_eq!(GAUGE_IDLE_TIMEOUT, Duration::from_secs(24 * 60 * 60));
}

#[test]
fn test_init_is_idempotent_and_does_not_panic() {
    // Regression: `init()` no longer `expect()`s the recorder install. Calling it repeatedly
    // (as startup + every test does) must be a no-op past the first install and must never
    // panic — even though the global recorder can only be installed once per process. A second
    // install attempt would fail, but the `OnceLock` short-circuits it.
    init();
    init();
    init();
    // After init, render must not panic and (in a process where install succeeded) is non-empty
    // only once a metric is emitted; the key assertion is simply that the calls return cleanly.
    let _ = render();
}

/// Helper: build a minimal `GovState` backed by an in-memory SQLite store.
fn gov_with_key(key: VirtualKey) -> Arc<GovState> {
    let store = Arc::new(MemoryStore::new());
    store.put_key(&key).unwrap();
    Arc::new(GovState::new(store, None).unwrap())
}

fn sample_vkey(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: format!("hash-{id}"),
        name: format!("key-{id}"),
        allowed_scopes: None,
        enabled: true,
        created_at: 1_700_000_000,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

/// `refresh_scrape_gauges` with governance enabled must emit `KEY_SPEND_CENTS`,
/// `KEY_TOKENS_TOTAL`, and `KEY_BUDGET_REMAINING_CENTS` for each key with a budget cap.
#[test]
fn test_scrape_gauges_key_spend_and_remaining() {
    init();

    let key = sample_vkey("vk_spend_test01");
    let gov = gov_with_key(key.clone());

    // Seed a durable ledger directly: 200 requests (derived spend = 200 cents at the
    // TestApp default `CostModel::flat(1)`) plus 5000 tokens so the tokens gauge is nonzero.
    let usage_store = gov.store();
    usage_store
        .put_usage(
            &key.id,
            0,
            &busbar_api::UsageLedger {
                requests: 200,
                billable_requests: 200,
                models: vec![busbar_api::ModelTokens {
                    model: "m".to_string(),
                    usage_units: std::collections::BTreeMap::from([(
                        busbar_api::UNIT_INPUT.to_string(),
                        5000u64,
                    )]),
                }],
            },
        )
        .unwrap();

    // Build a minimal App with governance.
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_OPENAI, "http://m"))
        .pool("pool-a", &[(0, 1)])
        .governance(gov)
        .build();

    refresh_scrape_gauges(&app);

    let out = render();
    // The key id must appear in the output (cardinality-bounded label).
    assert!(
        out.contains("vk_spend_test01"),
        "key id must appear as label in scrape output; got:\n{out}"
    );
    assert!(
        out.contains(KEY_SPEND_CENTS),
        "spend gauge must be present; got:\n{out}"
    );
    assert!(
        out.contains(KEY_TOKENS_TOTAL),
        "tokens gauge must be present; got:\n{out}"
    );
    // 1.5.0: keys are pure auth (no cap), so no per-key budget-remaining gauge exists; the
    // remaining/limit dimension lives on the GROUP buckets (asserted below).
    assert!(
        !out.contains("busbar_key_budget_remaining_cents"),
        "the removed per-key remaining gauge must not resurface; got:\n{out}"
    );
}

/// A group bucket WITHOUT a `budget` cap must NOT emit `BUCKET_BUDGET_REMAINING_CENTS` - the
/// gauge is meaningless without a ceiling and would just be 0. (The per-key remaining gauge is
/// gone entirely: keys are pure auth.)
#[test]
fn test_scrape_gauges_uncapped_group_bucket_no_remaining() {
    init();

    let mut key = sample_vkey("vk_uncapped_test01");
    key.group = Some("uncapped-grp".to_string());
    let gov = gov_with_key(key);

    // The group carries only a requests limit: its minute bucket exists but has NO budget cap.
    let groups: std::collections::BTreeMap<String, crate::config::GroupCfg> =
        std::collections::BTreeMap::from([(
            "uncapped-grp".to_string(),
            crate::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![crate::config::groups::LimitCfg {
                    metric: crate::config::groups::LimitMetric::Requests,
                    amount: 100,
                    per: Some(crate::config::groups::LimitWindow::Minute),
                    scope: None,
                    on_exhaust: None,
                    downgrade_to: None,
                }],
                ..Default::default()
            },
        )]);
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_OPENAI, "http://m"))
        .pool("pool-b", &[(0, 1)])
        .governance(gov)
        .cost(crate::cost::CostModel::resolve_parts(None, 0, &groups))
        .build();

    refresh_scrape_gauges(&app);

    let out = render();
    // The remaining gauge for the budget-less bucket must NOT appear.
    // NOTE: other tests in this process may have emitted it for different buckets; we can only
    // check that this bucket id does not appear on a budget-remaining line.
    let remaining_lines: Vec<&str> = out
        .lines()
        .filter(|l| l.contains(BUCKET_BUDGET_REMAINING_CENTS))
        .collect();
    for line in &remaining_lines {
        assert!(
                !line.contains("uncapped-grp"),
                "a budget-less group bucket must not appear in budget_remaining_cents lines; got:\n{line}"
            );
    }
    // Its spend series DOES appear, keyed by the new (bucket, group, window) dimensions.
    assert!(
        out.lines().any(|l| l.contains(BUCKET_SPEND_CENTS)
            && l.contains("group:uncapped-grp@minute")
            && l.contains("window=\"minute\"")),
        "the group bucket's spend gauge carries the group/window dimensions; got:\n{out}"
    );
}

/// The 1.5.0 cost-model exposure: `busbar_bucket_tokens{bucket, model, tier}` series for key
/// AND budget-group buckets, derived `busbar_bucket_spend_cents` / `_budget_remaining_cents`
/// for group buckets, and the key's MINT-TIME labels echoed onto its series (so external
/// dashboards can `sum by (team)` without busbar knowing what a team is).
#[test]
#[allow(clippy::field_reassign_with_default)]
fn test_scrape_gauges_bucket_model_tier_and_key_labels() {
    init();

    let mut key = sample_vkey("vk_bucket_test1");
    key.group = Some("growth".to_string());
    key.labels = std::collections::BTreeMap::from([("team".to_string(), "growth".to_string())]);
    let gov = gov_with_key(key.clone());

    // A cost model with the growth group; flat fee 1 (TestApp default shape).
    let groups = std::collections::BTreeMap::from([(
        "growth".to_string(),
        crate::config::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![crate::config::groups::LimitCfg {
                metric: crate::config::groups::LimitMetric::Budget,
                amount: 1_000,
                per: Some(crate::config::groups::LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = crate::cost::CostModel::resolve_parts(None, 1, &groups);

    // Accrue per-model tier tokens through the REAL accrual path (fans out to key + group).
    gov.record_usage(
        &cost,
        &key,
        "",
        "gpt-5",
        &std::collections::BTreeMap::from([
            (busbar_api::UNIT_INPUT.to_string(), 100u64),
            (busbar_api::UNIT_OUTPUT.to_string(), 40),
            (busbar_api::UNIT_CACHE_READ.to_string(), 7),
            (busbar_api::UNIT_CACHE_WRITE.to_string(), 3),
        ]),
        1_700_000_000,
    );

    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_OPENAI, "http://m"))
        .pool("pool-b", &[(0, 1)])
        .governance(gov)
        .cost(crate::cost::CostModel::resolve_parts(None, 1, &groups))
        .build();
    refresh_scrape_gauges(&app);
    let out = render();

    // Key-bucket per-(model, tier) series with the mint label echoed.
    let key_line = out
        .lines()
        .find(|l| {
            l.starts_with("busbar_bucket_tokens")
                && l.contains("bucket=\"vk_bucket_test1\"")
                && l.contains("model=\"gpt-5\"")
                && l.contains("tier=\"input\"")
        })
        .unwrap_or_else(|| panic!("key-bucket input-tier series missing: {out}"));
    assert!(
        key_line.contains("team=\"growth\""),
        "mint labels echo onto metric series: {key_line}"
    );
    assert!(
        key_line.trim_end().ends_with("100"),
        "input tier value: {key_line}"
    );

    // Group-bucket series exist too (the chain accrual fanned out), keyed by the 1.5.0
    // per-(group, window) bucket id and carrying the group/window dimensions.
    assert!(
        out.lines().any(|l| l.starts_with("busbar_bucket_tokens")
            && l.contains("bucket=\"group:growth@total\"")
            && l.contains("group=\"growth\"")
            && l.contains("window=\"total\"")
            && l.contains("tier=\"output\"")),
        "group-bucket token series missing: {out}"
    );
    // Derived group spend (0 without a rate card and no admitted request) + remaining
    // (= full cap).
    assert!(
        out.lines()
            .any(|l| l.starts_with("busbar_bucket_spend_cents")
                && l.contains("bucket=\"group:growth@total\"")),
        "group spend gauge missing"
    );
    assert!(
        out.lines()
            .any(|l| l.starts_with("busbar_bucket_budget_remaining_cents")
                && l.contains("bucket=\"group:growth@total\"")
                && l.trim_end().ends_with("1000")),
        "group remaining gauge = full cap when token spend derives to 0: {out}"
    );
}

/// `refresh_scrape_gauges` must emit at most `key_gauge_limit` (2000) distinct per-key series
/// even when the governance store holds more than that many virtual keys.
///
/// The truncation logic (`keys.iter().take(key_gauge_limit)`) is exercised by creating
/// key_gauge_limit + 1 keys, running a scrape, and asserting the count of distinct `key=`
/// label values in the `busbar_key_spend_cents` lines is ≤ key_gauge_limit.
///
/// Creating 2001 rows in an in-memory SQLite instance is fast (< 50 ms on any modern machine);
/// using `put_key` directly on the store bypasses the `GovState` cache and is the simplest
/// deterministic way to seed a large key set.
#[test]
fn test_key_gauge_limit_truncation() {
    init();
    // The default key-gauge limit is 2000 (no limits installed in this test ⇒ the historical
    // default). We use the same value here to keep the test self-consistent.
    const LIMIT: usize = crate::config::DEFAULT_KEY_GAUGE_LIMIT;
    let store = Arc::new(MemoryStore::new());

    // Insert LIMIT + 1 keys so the truncation branch fires.
    for i in 0..=(LIMIT) {
        let id = format!("vk_limit_{i:04x}");
        let key = VirtualKey {
            id: id.clone(),
            generation_hash: format!("hash-limit-{i}"),
            name: format!("key-limit-{i}"),
            allowed_scopes: None,
            enabled: true,
            created_at: 1_700_000_000,
            group: None,
            labels: Default::default(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
            ..Default::default()
        };
        store.put_key(&key).unwrap();
        // Seed minimal usage so the key has a row in usage_counters and the spend gauge is
        // actually emitted (keys with zero usage_for results are skipped).
        store
            .put_usage(
                &id,
                0,
                &busbar_api::UsageLedger {
                    requests: 1,
                    billable_requests: 1,
                    models: vec![busbar_api::ModelTokens {
                        model: "m".to_string(),
                        usage_units: std::collections::BTreeMap::from([(
                            busbar_api::UNIT_INPUT.to_string(),
                            10u64,
                        )]),
                    }],
                },
            )
            .unwrap();
    }

    let gov = Arc::new(GovState::new(store, None).unwrap());
    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_OPENAI, "http://m"))
        .pool("pool-limit", &[(0, 1)])
        .governance(gov)
        .build();

    refresh_scrape_gauges(&app);

    let out = render();

    // Count distinct `key=` values that appear on busbar_key_spend_cents data lines
    // (i.e. non-comment lines that contain the metric name). Each emitted series produces one
    // such line, so this counts emitted series directly.
    let spend_series_count = out
        .lines()
        .filter(|l| !l.starts_with('#') && l.contains(KEY_SPEND_CENTS))
        .filter(|l| l.contains("vk_limit_"))
        .count();

    // EXACTLY the limit, not merely "at most" it. `<= LIMIT` is satisfied by any truncation at all
    // — a `.take(1)`, a `.take(0)` guarded by the `> 0` floor below, an off-by-a-thousand — so the
    // pair of bounds it replaces bracketed the answer between 1 and 2000 and called that a proof.
    // With LIMIT + 1 keys seeded, all of them carrying usage (so none is skipped for a zero
    // `usage_for`), the cap is BINDING and the emitted count is a single determined number: LIMIT.
    // Asserting that number is what makes a regression in either direction — a cap that stopped
    // capping (2001) or one that clamped far below its own value — a failure here.
    assert_eq!(
        spend_series_count,
        LIMIT,
        "refresh_scrape_gauges must emit EXACTLY key_gauge_limit ({LIMIT}) per-key series when \
         {} keys are present: the cap must bind, and must bind AT its own value",
        LIMIT + 1
    );
}

/// Build an `App` backed by a governance store seeded with `n` distinct virtual keys, each
/// with minimal usage so its per-key spend gauge actually emits. Shared by the key-gauge-limit
/// boundary tests below.
fn app_with_n_keys(n: usize) -> Arc<App> {
    let store = Arc::new(MemoryStore::new());
    for i in 0..n {
        let id = format!("vk_bound_{i:04x}");
        let key = VirtualKey {
            id: id.clone(),
            generation_hash: format!("hash-bound-{i}"),
            name: format!("key-bound-{i}"),
            allowed_scopes: None,
            enabled: true,
            created_at: 1_700_000_000,
            group: None,
            labels: Default::default(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
            ..Default::default()
        };
        store.put_key(&key).unwrap();
        store
            .put_usage(
                &id,
                0,
                &busbar_api::UsageLedger {
                    requests: 1,
                    billable_requests: 1,
                    models: vec![busbar_api::ModelTokens {
                        model: "m".to_string(),
                        usage_units: std::collections::BTreeMap::from([(
                            busbar_api::UNIT_INPUT.to_string(),
                            1u64,
                        )]),
                    }],
                },
            )
            .unwrap();
    }
    let gov = Arc::new(GovState::new(store, None).unwrap());
    TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_OPENAI, "http://m"))
        .pool("pool-bound", &[(0, 1)])
        .governance(gov)
        .build()
}

/// `keys.len() > key_gauge_limit` is the EXACT boundary that gates the truncation warning: a
/// mutated `>` (e.g. `<`) would make the warning fire on the WRONG side of the boundary
/// (never at `limit + 1`, always below `limit`, or some other inversion) — `render()`'s output
/// is unaffected either way (`.take(key_gauge_limit)` bounds emission unconditionally), so
/// this can only be proven via the actual `tracing::warn!` call, not the metric text.
#[test]
fn test_key_gauge_limit_warning_fires_exactly_past_the_boundary() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;
    init();
    const LIMIT: usize = crate::config::DEFAULT_KEY_GAUGE_LIMIT;

    // AT the limit: no warning.
    let app_at_limit = app_with_n_keys(LIMIT);
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        refresh_scrape_gauges(&app_at_limit);
    });
    assert!(
        !cap.messages()
            .iter()
            .any(|m| m.contains("per-key gauge limit")),
        "exactly key_gauge_limit ({LIMIT}) keys must NOT trigger the truncation warning; got: {:?}",
        cap.messages()
    );

    // ONE past the limit: warning fires.
    let app_over_limit = app_with_n_keys(LIMIT + 1);
    let cap2 = WarnCapture::default();
    let subscriber2 = tracing_subscriber::registry().with(cap2.clone());
    tracing::subscriber::with_default(subscriber2, || {
        refresh_scrape_gauges(&app_over_limit);
    });
    assert!(
        cap2.messages()
            .iter()
            .any(|m| m.contains("per-key gauge limit")),
        "key_gauge_limit + 1 ({}) keys MUST trigger the truncation warning; got: {:?}",
        LIMIT + 1,
        cap2.messages()
    );
}

/// Cardinality invariant: label values in the scrape output must NOT contain raw bearer secrets
/// (which start with `sk-bb-`). The key id (`vk_<hex>`) is the only key-identifying label.
#[test]
fn test_cardinality_invariant_no_raw_secret_in_labels() {
    init();

    let key = sample_vkey("vk_carinv_test01");
    let gov = gov_with_key(key);

    let app = TestApp::new()
        .lane(LaneSpec::new("m", crate::proto::PROTO_OPENAI, "http://m"))
        .pool("pool-ci", &[(0, 1)])
        .governance(gov)
        .build();

    refresh_scrape_gauges(&app);

    let out = render();
    assert!(
            !out.contains("sk-bb-"),
            "raw bearer secret prefix must never appear as a label value in the scrape output; got:\n{out}"
        );
}
/// A gauge whose subject is gone must stop being exported; one still being refreshed must not.
///
/// Per-key gauges are only `set` while iterating LIVE keys, so without an idle timeout a deleted
/// key's spend was re-rendered with its final value for the life of the process — `/metrics`
/// growing with lifetime key churn, and dashboards showing a deleted key's spend as current.
///
/// Driven through a LOCALLY-built recorder: installing is global and once-per-process, but
/// building is not, so the reaping behaviour can be exercised on a short window.
#[test]
fn a_gauge_that_stops_being_refreshed_is_expired() {
    let idle = Duration::from_millis(60);
    let recorder = super::recorder_builder(Duration::from_secs(1), idle)
        .expect("builder")
        .build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        metrics::gauge!("busbar_test_deleted_subject").set(1.0);
        metrics::gauge!("busbar_test_live_subject").set(1.0);
    });
    let before = handle.render();
    assert!(before.contains("busbar_test_deleted_subject"), "{before}");
    assert!(before.contains("busbar_test_live_subject"));

    std::thread::sleep(idle * 3);
    // Only the live subject is refreshed — exactly what `refresh_scrape_gauges` does for the
    // keys that still exist.
    metrics::with_local_recorder(&recorder, || {
        metrics::gauge!("busbar_test_live_subject").set(2.0);
    });

    let after = handle.render();
    assert!(
        !after.contains("busbar_test_deleted_subject"),
        "a gauge nothing refreshes must stop being exported, got:\n{after}"
    );
    assert!(
        after.contains("busbar_test_live_subject"),
        "a refreshed gauge must survive, got:\n{after}"
    );
}

/// Counters and histograms must NOT be reaped: expiring a counter resets it and breaks `rate()`,
/// and expiring a histogram discards its summary. Only gauges are in the mask.
#[test]
fn only_gauges_are_expired() {
    let idle = Duration::from_millis(60);
    let recorder = super::recorder_builder(Duration::from_secs(1), idle)
        .expect("builder")
        .build_recorder();
    let handle = recorder.handle();

    metrics::with_local_recorder(&recorder, || {
        metrics::counter!("busbar_test_idle_counter").increment(7);
        metrics::histogram!("busbar_test_idle_histogram").record(1.0);
    });
    std::thread::sleep(idle * 3);

    let after = handle.render();
    assert!(
        after.contains("busbar_test_idle_counter"),
        "an idle counter must survive — expiring it would reset it and break rate(), got:\n{after}"
    );
    assert!(
        after.contains("busbar_test_idle_histogram"),
        "an idle histogram must survive, got:\n{after}"
    );
}

/// Item 24: the money gauges moved into `metrics/money.rs` and now reach the recorder through ONE
/// named boundary, `money::set_gauge`, instead of an inline `as f64` at each site. The served
/// `/metrics` text must be the text 1.5.5 served. For every probe value the SAME family is written
/// once the 1.5.5 way (the direct cast, kept here as the reference) and once through the boundary,
/// under two distinct `key` labels, and the rendered value text of the two lines must be identical
/// byte for byte — including above 2^53 and at the type extremes, where the float rounds. For every
/// value whose magnitude is at most 2^53 the rendered text must also be exactly the integer's
/// decimal digits: the served figure is the exact integer.
#[test]
fn money_gauge_bytes_are_the_1_5_5_bytes() {
    init();
    const P53: i64 = 1 << 53;
    let cents: &[i64] = &[
        0,
        1,
        -1,
        200,
        123_456_789,
        P53 - 1,
        P53,
        -P53,
        P53 + 1,
        i64::MAX,
        i64::MIN,
    ];
    let counts: &[u64] = &[0, 1, 5000, (1u64 << 53) + 1, u64::MAX];

    fn value_of(out: &str, family: &str, key: &str) -> String {
        let needle = format!("key=\"{key}\"");
        let line = out
            .lines()
            .find(|l| l.starts_with(family) && l.contains(&needle))
            .unwrap_or_else(|| panic!("no `{family}` line for {key}; got:\n{out}"));
        line.rsplit(' ').next().unwrap().to_string()
    }

    let mut probes: Vec<(&str, String, String, i128)> = Vec::new();
    for (i, &v) in cents.iter().enumerate() {
        for family in [
            KEY_SPEND_CENTS,
            BUCKET_SPEND_CENTS,
            BUCKET_BUDGET_REMAINING_CENTS,
        ] {
            let old = format!("vk_pin24_old_c{i}");
            let new = format!("vk_pin24_new_c{i}");
            metrics::gauge!(family, "key" => old.clone()).set(v as f64);
            money::set_gauge(metrics::gauge!(family, "key" => new.clone()), v);
            probes.push((family, old, new, i128::from(v)));
        }
    }
    for (i, &v) in counts.iter().enumerate() {
        for family in [KEY_TOKENS_TOTAL, BUCKET_TOKENS] {
            let old = format!("vk_pin24_old_t{i}");
            let new = format!("vk_pin24_new_t{i}");
            metrics::gauge!(family, "key" => old.clone()).set(v as f64);
            money::set_gauge(metrics::gauge!(family, "key" => new.clone()), v);
            probes.push((family, old, new, i128::from(v)));
        }
    }

    let out = render();
    for (family, old, new, v) in &probes {
        let was = value_of(&out, family, old);
        let now = value_of(&out, family, new);
        assert_eq!(
            was, now,
            "`{family}` for {v}: 1.5.5 served `{was}`, the money boundary serves `{now}`"
        );
        if v.unsigned_abs() <= 1u128 << 53 {
            assert_eq!(
                now,
                v.to_string(),
                "`{family}` for {v}: below 2^53 the served figure must be the exact integer"
            );
        }
    }
}
