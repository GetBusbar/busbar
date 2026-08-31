// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/metrics.rs`.

use super::*;
use crate::governance::{GovState, MemoryStore, Store, VirtualKey};
use crate::store::LaneRuntime;
use crate::test_support::{LaneSpec, TestApp};
use std::sync::Arc;

#[test]
fn test_render_exposes_emitted_counter() {
    init();
    metrics::counter!(
        REQUESTS_TOTAL,
        "ingress_protocol" => "anthropic",
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
                    tokens: crate::governance::TierTokens {
                        input: 5000,
                        output: 0,
                        cache_read: 0,
                        cache_write: 0,
                    },
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
        &busbar_api::TierTokens {
            input: 100,
            output: 40,
            cache_read: 7,
            cache_write: 3,
        },
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

/// `refresh_scrape_gauges` with no governance must not panic and must emit `LANE_STATE` gauges.
#[test]
fn test_scrape_gauges_lane_state_no_governance() {
    init();

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "model-x",
            crate::proto::PROTO_OPENAI,
            "http://x",
        ))
        .pool("pool-x", &[(0, 1)])
        .build();

    // Must not panic.
    refresh_scrape_gauges(&app);

    let out = render();
    assert!(
        out.contains(LANE_STATE),
        "lane_state gauge must appear in exposition; got:\n{out}"
    );
    assert!(
        out.contains("pool=\"pool-x\""),
        "pool label must appear; got:\n{out}"
    );
}

/// Find the trailing numeric value of the exposition line for `metric` labeled with `pool`.
fn gauge_value(out: &str, metric: &str, pool: &str) -> Option<f64> {
    // Match the metric name at an EXACT boundary (`name{`), not a bare prefix: `busbar_lane_available`
    // is a prefix of `busbar_lane_available_permits`, so a `starts_with(metric)` match picked
    // whichever of the two happened to render first — and prometheus group order is non-deterministic
    // (recorder HashMap iteration), which made every prefix-of-another-metric assertion flaky. All
    // these gauges carry labels, so requiring the `{` after the name is exact and stable.
    let needle = format!("{metric}{{");
    out.lines()
        .find(|l| {
            !l.starts_with('#') && l.starts_with(&needle) && l.contains(&format!("pool=\"{pool}\""))
        })
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.trim().parse::<f64>().ok())
}

/// `/metrics` renders per-lane availability from the UNIFIED `classify` taxonomy. On saturation,
/// `busbar_lane_available` flips 1→0 (the inverted successor to the ad-hoc `busbar_lane_at_capacity`),
/// `busbar_lane_available_permits` drops 1→0, `busbar_lane_inflight` rises 0→1, and
/// `busbar_lane_recovery_hint_ms` reports the honest at-capacity floor (2000ms).
#[test]
fn test_scrape_gauges_lane_available_flips_on_saturation() {
    init();

    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let app = TestApp::new()
        .lane(
            LaneSpec::new("cap-model", crate::proto::PROTO_OPENAI, "http://c")
                .max(1)
                .sem(sem.clone()),
        )
        .pool("cap-pool", &[(0, 1)])
        .build();

    // Idle: available, one permit, no inflight, no recovery hint.
    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "cap-pool"),
        Some(1.0),
        "an idle bounded lane must report available=1; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE_PERMITS, "cap-pool"),
        Some(1.0),
        "an idle max_concurrent=1 lane has 1 available permit; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_INFLIGHT, "cap-pool"),
        Some(0.0),
        "an idle lane has 0 inflight; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_RECOVERY_HINT_MS, "cap-pool"),
        Some(0.0),
        "an available lane has recovery_hint_ms=0; got:\n{out}"
    );

    // The renamed gauge fully replaces the ad-hoc one — the old series must be gone.
    assert!(
        !out.contains("busbar_lane_at_capacity"),
        "the ad-hoc busbar_lane_at_capacity gauge must be removed; got:\n{out}"
    );

    // Saturate by holding the only permit → the unified gauges must flip.
    let _held = sem
        .clone()
        .try_acquire_owned()
        .expect("hold the only permit");
    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "cap-pool"),
        Some(0.0),
        "a saturated bounded lane must report available=0; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE_PERMITS, "cap-pool"),
        Some(0.0),
        "a saturated bounded lane must report 0 available permits; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_INFLIGHT, "cap-pool"),
        Some(1.0),
        "the held permit is 1 inflight; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_RECOVERY_HINT_MS, "cap-pool"),
        Some(2000.0),
        "an at-capacity lane's recovery hint floors at 2000ms; got:\n{out}"
    );
}

/// The doc contract: an UNBOUNDED lane (no `max_concurrent`) emits NO `busbar_lane_available_permits`
/// sample (rather than a misleading infinite/zero one), so PromQL rules can treat the gauge's mere
/// PRESENCE as "this lane is bounded". The lane is still scraped (`busbar_lane_available` is present),
/// but the permits gauge must be absent for it.
#[test]
fn test_scrape_gauges_unbounded_lane_omits_available_permits() {
    init();

    // `max >= Semaphore::MAX_PERMITS` is the store's unbounded sentinel (no `max_concurrent`).
    let app = TestApp::new()
        .lane(
            LaneSpec::new("unb-model", crate::proto::PROTO_OPENAI, "http://u")
                .max(tokio::sync::Semaphore::MAX_PERMITS),
        )
        .pool("unb-pool", &[(0, 1)])
        .build();

    refresh_scrape_gauges(&app);
    let out = render();
    // The lane IS scraped (availability present)…
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "unb-pool"),
        Some(1.0),
        "an unbounded lane is still scraped and reports available=1; got:\n{out}"
    );
    // …but its available-permits gauge must be ABSENT (no meaningful count for an unbounded lane).
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE_PERMITS, "unb-pool"),
        None,
        "an unbounded lane must emit NO busbar_lane_available_permits sample; got:\n{out}"
    );
}

/// In `/metrics`: a breaker-Open lane reports `busbar_lane_available=0` with a breaker-derived
/// `busbar_lane_recovery_hint_ms`, while the INDEPENDENT `busbar_lane_state` breaker gauge reads
/// tripped and `busbar_lane_available_permits` still exposes the capacity axis — the two are never
/// collapsed into a single signal.
#[test]
fn test_scrape_gauges_breaker_open_lane_unavailable() {
    init();

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "brk-model",
            crate::proto::PROTO_OPENAI,
            "http://b",
        ))
        .pool("brk-pool", &[(0, 1)])
        .build();

    // Trip the pool cell Open with a cooldown 30s out.
    let t = crate::state::now();
    app.store.force_open_in("brk-pool", 0, t + 30);

    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "brk-pool"),
        Some(0.0),
        "a breaker-Open lane must classify unavailable; got:\n{out}"
    );
    // Independent breaker axis: LANE_STATE reads tripped (2).
    assert_eq!(
        gauge_value(&out, LANE_STATE, "brk-pool"),
        Some(2.0),
        "the independent breaker gauge must read tripped; got:\n{out}"
    );
    // Breaker-derived recovery hint (~30s = 30000ms), NOT the at-capacity floor.
    assert_eq!(
        gauge_value(&out, LANE_RECOVERY_HINT_MS, "brk-pool"),
        Some(30000.0),
        "recovery hint must be the breaker's until, ~30000ms; got:\n{out}"
    );
}

/// `busbar_pool_queued{pool}` is defined for every configured pool, not only for pools that have
/// queued: it must appear (reading 0) for every configured pool on the very first scrape.
#[test]
fn test_scrape_gauges_pool_queued_defined_reads_zero() {
    init();
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "q-model",
            crate::proto::PROTO_OPENAI,
            "http://q",
        ))
        .pool("q-pool", &[(0, 1)])
        .build();
    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, POOL_QUEUED, "q-pool"),
        Some(0.0),
        "busbar_pool_queued must be defined and read 0 for each pool; got:\n{out}"
    );
}

/// `busbar_pool_queued` renders the LIVE `queued_depth` source. Park a request
/// (via the same RAII `QueuedDepth::park` guard `handle_queue` holds while waiting) and the gauge
/// must read the real depth, not a literal 0.
#[test]
fn test_scrape_gauges_pool_queued_reads_live_depth() {
    init();
    // Unique pool/model labels: the `metrics` recorder is process-global, so sharing a label with
    // another test would cross-contaminate this gauge across tests.
    let app = TestApp::new()
        .lane(LaneSpec::new(
            "q-live-model",
            crate::proto::PROTO_OPENAI,
            "http://q",
        ))
        .pool("q-live-pool", &[(0, 1)])
        .build();

    // Hold a park guard, as a real queued request would for the duration of its wait.
    let guard = app.queued_depth.park("q-live-pool");
    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, POOL_QUEUED, "q-live-pool"),
        Some(1.0),
        "busbar_pool_queued must reflect the live park depth (1 while parked); got:\n{out}"
    );

    // Dropping the guard (request left the queue) returns the depth to 0.
    drop(guard);
    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, POOL_QUEUED, "q-live-pool"),
        Some(0.0),
        "busbar_pool_queued must return to 0 once the parked request leaves; got:\n{out}"
    );
}

/// A `Store` whose `list_keys` fails on every call AFTER the first — the first call succeeds so
/// `GovState::new` (which loads the key cache via `list_keys` at construction time) can still
/// build successfully, and every call from then on (i.e. from `refresh_scrape_gauges`'s
/// `all_keys()`) fails, simulating a governance-store hiccup discovered exactly at scrape time.
/// Every other method delegates to a real in-memory `MemoryStore`.
struct ScrapeTimeBrokenKeyListStore {
    inner: MemoryStore,
    calls: std::sync::atomic::AtomicUsize,
}
impl Store for ScrapeTimeBrokenKeyListStore {
    fn list_keys(&self) -> crate::governance::StoreResult<Vec<VirtualKey>> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            self.inner.list_keys()
        } else {
            Err(crate::governance::StoreError(
                "governance store unavailable (simulated scrape-time outage)".into(),
            ))
        }
    }
    fn put_key(&self, key: &VirtualKey) -> crate::governance::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> crate::governance::StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn delete_key(&self, id: &str) -> crate::governance::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> crate::governance::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> crate::governance::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(
        &self,
        delta: &crate::governance::MeteringDelta,
    ) -> crate::governance::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(
        &self,
        bucket: u64,
    ) -> crate::governance::StoreResult<Vec<crate::governance::MeteringRow>> {
        self.inner.list_metering(bucket)
    }
}

/// Regression:
/// `refresh_scrape_gauges` must keep refreshing `busbar_lane_state` (and the group-bucket
/// gauges, which don't depend on `all_keys()` either) even when the governance store's
/// `all_keys()` call fails during the scrape. The old code did a bare `return` on that error,
/// which — given the metrics recorder's 24h gauge idle-timeout — left `busbar_lane_state`
/// showing stale/absent values for up to a day after a single transient governance-store
/// hiccup, hiding a breaker that trips during that exact window from lane-health alerting.
#[test]
fn test_scrape_gauges_lane_state_survives_governance_all_keys_failure() {
    init();

    let key = sample_vkey("vk_broken_store01");
    let store = Arc::new(ScrapeTimeBrokenKeyListStore {
        inner: MemoryStore::new(),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    store.put_key(&key).unwrap();
    // Construction consumes the ONE successful `list_keys` call.
    let gov = Arc::new(GovState::new(store, None).unwrap());

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "model-broken",
            crate::proto::PROTO_OPENAI,
            "http://broken",
        ))
        .pool("pool-broken", &[(0, 1)])
        .governance(gov)
        .build();

    // Every `all_keys()` call from here on fails (simulated scrape-time governance outage).
    refresh_scrape_gauges(&app);

    let out = render();
    // The lane-health gauge must still be present and labeled for this pool — it has nothing to
    // do with the governance store and must not be collateral damage of the failed key list.
    let lane_line = out.lines().find(|l| {
        l.contains(LANE_STATE) && l.contains("pool=\"pool-broken\"") && !l.starts_with('#')
    });
    assert!(
        lane_line.is_some(),
        "busbar_lane_state for pool-broken must still be emitted despite the governance \
             all_keys() failure; got:\n{out}"
    );
    // The per-key spend gauge (which DOES depend on the failed `all_keys()` read) must
    // correctly be absent — this is the one thing that should actually be skipped.
    assert!(
        !out.contains("vk_broken_store01"),
        "the failed key's id must not appear as a per-key gauge label; got:\n{out}"
    );
}

/// A healthy lane (no cooldown, not dead) must emit `busbar_lane_state = 0`.
#[test]
fn test_lane_state_healthy_is_zero() {
    init();

    let app = TestApp::new()
        .lane(LaneSpec::new(
            "model-h",
            crate::proto::PROTO_OPENAI,
            "http://h",
        ))
        .pool("pool-h", &[(0, 1)])
        .build();

    refresh_scrape_gauges(&app);

    let out = render();
    // Look for the lane_state line for pool-h. A healthy lane should carry value 0.
    let lane_line = out
        .lines()
        .find(|l| l.contains(LANE_STATE) && l.contains("pool=\"pool-h\"") && !l.starts_with('#'));
    assert!(
        lane_line.is_some(),
        "lane_state metric line for pool-h must be present; got:\n{out}"
    );
    let line = lane_line.unwrap();
    assert!(
        line.ends_with(" 0") || line.ends_with(" 0.0"),
        "healthy lane must have state 0; got:\n{line}"
    );
    // The `lane` label is the lane's MODEL string (NOT a numeric index), consistent with the
    // proxy engine counter sites so the gauge and counters can be PromQL-joined on `lane`.
    assert!(
        line.contains("lane=\"model-h\""),
        "lane label must be the model string, not a numeric index; got:\n{line}"
    );
}

/// A pool-scoped cell that is Open with a live cooldown, while the SAME underlying lane stays
/// usable via a SIBLING pool's untouched (Closed) cell, must render `busbar_lane_state = 1`
/// (HalfOpen) for the tripped pool — not 0 (would require `pool_cooldown == 0`) and not 2
/// (would require the lane itself being unusable everywhere). This is the ONLY reachable path
/// to state 1 for a pool-routed lane: `cell_ready_breaker` reports HALF_OPEN itself as NOT
/// ready, so "cooldown>0 but usable" only happens when a *different* cell for the same lane is
/// what makes `lane_usable_any_cell` true. Proves the `pool_cooldown > 0 && !snap.usable`
/// (line 794) and the by-model twin (line 825) guards distinguish state 1 from state 2 for
/// real, not just "some non-zero value".
#[test]
fn test_lane_state_half_open_via_sibling_pool_cell() {
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new(
            "model-ho",
            crate::proto::PROTO_OPENAI,
            "http://ho",
        ))
        .pool("pool-tripped", &[(0, 1)])
        .pool("pool-sibling", &[(0, 1)])
        .build_with_store();

    let now = crate::state::now();
    // Materialize the sibling pool's cell fresh (Closed, cooldown=0, ready) BEFORE tripping the
    // other pool — `lane_usable_any_cell` only sees cells that have been touched at least once.
    let _ = store.cell("pool-sibling", 0);
    // Trip pool-tripped's cell Open with a cooldown well into the future.
    store.force_open_in("pool-tripped", 0, now + 600);

    refresh_scrape_gauges(&app);
    let out = render();

    let tripped_line = out.lines().find(|l| {
        l.contains(LANE_STATE) && l.contains("pool=\"pool-tripped\"") && !l.starts_with('#')
    });
    assert!(
        tripped_line.is_some(),
        "lane_state for pool-tripped must be present; got:\n{out}"
    );
    let line = tripped_line.unwrap();
    assert!(
        line.ends_with(" 1") || line.ends_with(" 1.0"),
        "a cell with cooldown>0 but a usable sibling cell must report state 1 (HalfOpen), \
             not 0 (would need cooldown==0) or 2 (would need the lane unusable everywhere); \
             got:\n{line}"
    );

    // The untouched sibling pool's OWN cell is genuinely Closed/healthy — state 0 — proving
    // this isn't just "every pool on a partially-tripped lane reports 1".
    let sibling_line = out.lines().find(|l| {
        l.contains(LANE_STATE) && l.contains("pool=\"pool-sibling\"") && !l.starts_with('#')
    });
    assert!(
        sibling_line.is_some(),
        "lane_state for pool-sibling must be present; got:\n{out}"
    );
    let sline = sibling_line.unwrap();
    assert!(
        sline.ends_with(" 0") || sline.ends_with(" 0.0"),
        "the sibling pool's own untouched cell must report state 0; got:\n{sline}"
    );
}

/// The `by_model` (direct/no-pool routing) twin of the HalfOpen test above: the DEFAULT (`""`)
/// cell tripped Open with a cooldown, while a SIBLING per-pool cell for the same lane stays
/// fresh/Closed, must still report state 1 for the model-labeled gauge — proving line 825's
/// `cooldown > 0 && !snap.usable` guard (distinct code from the pool-loop's identical-looking
/// line 794 guard) is independently exercised. Every `TestApp` lane is auto-registered in
/// `by_model` regardless of pool membership, so adding a pool here (to materialize a per-pool
/// cell) doesn't remove the lane from the by_model gauge loop.
#[test]
fn test_lane_state_half_open_by_model_via_sibling_pool_cell() {
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new(
            "model-by",
            crate::proto::PROTO_OPENAI,
            "http://by",
        ))
        .pool("some-pool", &[(0, 1)])
        .build_with_store();

    let now = crate::state::now();
    // Materialize a per-pool cell fresh/Closed so `lane_usable_any_cell` has a ready cell to
    // find (without this, it would fall back to the default cell itself, which we're about to
    // trip — making usable/cooldown check the SAME cell and state 1 unreachable).
    let _ = store.cell("some-pool", 0);
    // Trip the DEFAULT ("") cell — the one `cooldown_remaining_in("", lane_idx, now)` reads in
    // the by_model loop.
    store.force_open_in("", 0, now + 600);

    refresh_scrape_gauges(&app);
    let out = render();

    let model_line = out
        .lines()
        .find(|l| l.contains(LANE_STATE) && l.contains("pool=\"model-by\"") && !l.starts_with('#'));
    assert!(
        model_line.is_some(),
        "lane_state for the by_model entry (pool label = model name) must be present; \
             got:\n{out}"
    );
    let line = model_line.unwrap();
    assert!(
        line.ends_with(" 1") || line.ends_with(" 1.0"),
        "default cell cooling down but the lane usable via a sibling per-pool cell must \
             report state 1 (HalfOpen) in the by_model gauge loop too; got:\n{line}"
    );
}

/// The `>` boundary in line 825's `cooldown > 0 && !snap.usable` guard specifically: with the
/// DEFAULT (`""`) cell UNTOUCHED (cooldown reads exactly 0, `by_model`'s direct-routing path
/// never went through it) while every per-pool cell for the SAME lane is Open/unusable, the
/// by_model gauge must report state 0 (the direct path's own cell is genuinely healthy — pool
/// brokenness on a completely separate traffic path is irrelevant to it), not 2. A mutated
/// `cooldown == 0` would flip this specific case to 2, since `0 == 0` is true where `0 > 0` is
/// false — the two operators only diverge exactly at cooldown == 0, which the other HalfOpen
/// tests (cooldown = 600) can never reach.
#[test]
fn test_lane_state_by_model_default_cell_untouched_zero_cooldown_reports_healthy() {
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new(
            "model-zero",
            crate::proto::PROTO_OPENAI,
            "http://zero",
        ))
        .pool("poolX", &[(0, 1)])
        .pool("poolY", &[(0, 1)])
        .build_with_store();

    let now = crate::state::now();
    // Trip EVERY per-pool cell Open (unexpired cooldown) — the lane is unusable via any pool.
    // The DEFAULT ("") cell is deliberately never touched: cooldown_remaining_in("", 0, now)
    // reads exactly 0 (its pristine untouched state), which is the boundary value that
    // distinguishes `>` from `==`.
    store.force_open_in("poolX", 0, now + 600);
    store.force_open_in("poolY", 0, now + 600);

    refresh_scrape_gauges(&app);
    let out = render();

    let model_line = out.lines().find(|l| {
        l.contains(LANE_STATE) && l.contains("pool=\"model-zero\"") && !l.starts_with('#')
    });
    assert!(
        model_line.is_some(),
        "lane_state for the by_model entry must be present; got:\n{out}"
    );
    let line = model_line.unwrap();
    assert!(
        line.ends_with(" 0") || line.ends_with(" 0.0"),
        "the untouched default cell (cooldown == 0) must report state 0 for the direct-routing \
             gauge regardless of unrelated pool cells being broken; got:\n{line}"
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
                        tokens: crate::governance::TierTokens {
                            input: 10,
                            output: 0,
                            cache_read: 0,
                            cache_write: 0,
                        },
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

    assert!(
            spend_series_count <= LIMIT,
            "refresh_scrape_gauges must emit at most key_gauge_limit ({LIMIT}) per-key series; got {spend_series_count}"
        );
    // Also assert we got at least 1 series (sanity — something was emitted).
    assert!(
        spend_series_count > 0,
        "at least one key spend series must be emitted; got 0"
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
                        tokens: crate::governance::TierTokens {
                            input: 1,
                            output: 0,
                            cache_read: 0,
                            cache_write: 0,
                        },
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
