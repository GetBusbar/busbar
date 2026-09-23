// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `/metrics` GAUGE TESTS, relocated here from `src/tests/metrics_tests.rs` (the "fix
//! the 38" pass after the A6/HostCtx dev-dependency-cycle cleanup): every test in this file builds a
//! `TestApp` with real lanes/pools and reads the topology back through `refresh_scrape_gauges` →
//! `App::engine_tables_view`, which — same as `endpoints_cross_plane.rs` — projects the FALLBACK
//! plane's own runtime slot through that plane decl's `viewer` fn-pointer. Only the REAL
//! `busbar_llm` plane sets `viewer`/`build_runtime` to something that actually returns lane/pool
//! tables; a neutral fake plane (all hooks `None`/no-op) would leave every gauge here reading the
//! empty `EMPTY_VIEW` projection — a different, false-negative failure from what these tests exist
//! to pin. That only type-checks with ONE `busbar_kernel` in the graph, which is exactly what an
//! integration-test target gives. See `plane_integration.rs`'s header for the same rationale, first
//! written there.
//!
//! Every OTHER test in `metrics_tests.rs` (counters, `describe()`, key-spend gauges, the gauge
//! idle-timeout constant, …) names no lane/pool topology and stays in the unit module.

use busbar_api::{UsageLedger, VirtualKey};
use busbar_kernel::governance::{
    GovState, MemoryStore, MeteringDelta, MeteringRow, Store, StoreError, StoreResult,
};
use busbar_kernel::metrics::{
    init, refresh_scrape_gauges, render, LANE_AVAILABLE, LANE_AVAILABLE_PERMITS, LANE_INFLIGHT,
    LANE_RECOVERY_HINT_MS, LANE_STATE, POOL_QUEUED,
};
use busbar_kernel::proto::PROTO_OPENAI;
use busbar_kernel::store::{now, LaneRuntime};
use busbar_kernel::test_support::{LaneSpec, TestApp};
use std::sync::Arc;

fn register_planes() {
    busbar_llm::testkit::install_test_seams();
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

/// `refresh_scrape_gauges` with no governance must not panic and must emit `LANE_STATE` gauges.
#[test]
fn test_scrape_gauges_lane_state_no_governance() {
    register_planes();
    init();

    let app = TestApp::new()
        .lane(LaneSpec::new("model-x", PROTO_OPENAI, "http://x"))
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

/// `/metrics` renders per-lane availability from the UNIFIED `classify` taxonomy. On saturation,
/// `busbar_lane_available` flips 1→0 (the inverted successor to the ad-hoc `busbar_lane_at_capacity`),
/// `busbar_lane_available_permits` drops 1→0, `busbar_lane_inflight` rises 0→1, and
/// `busbar_lane_recovery_hint_ms` reports the honest at-capacity floor (2000ms).
#[test]
fn test_scrape_gauges_lane_available_flips_on_saturation() {
    register_planes();
    init();

    let sem = Arc::new(tokio::sync::Semaphore::new(1));
    let app = TestApp::new()
        .lane(
            LaneSpec::new("cap-model", PROTO_OPENAI, "http://c")
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
    register_planes();
    init();

    // `max >= Semaphore::MAX_PERMITS` is the store's unbounded sentinel (no `max_concurrent`).
    let app = TestApp::new()
        .lane(
            LaneSpec::new("unb-model", PROTO_OPENAI, "http://u")
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
    register_planes();
    init();

    let app = TestApp::new()
        .lane(LaneSpec::new("brk-model", PROTO_OPENAI, "http://b"))
        .pool("brk-pool", &[(0, 1)])
        .build();

    // Trip the pool cell Open with a cooldown 30s out.
    let t = now();
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
    register_planes();
    init();
    let app = TestApp::new()
        .lane(LaneSpec::new("q-model", PROTO_OPENAI, "http://q"))
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
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        let n = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            self.inner.list_keys()
        } else {
            Err(StoreError(
                "governance store unavailable (simulated scrape-time outage)".into(),
            ))
        }
    }
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
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
    register_planes();
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
        .lane(LaneSpec::new("model-broken", PROTO_OPENAI, "http://broken"))
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
    register_planes();
    init();

    let app = TestApp::new()
        .lane(LaneSpec::new("model-h", PROTO_OPENAI, "http://h"))
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
/// guard and the by-model twin distinguish state 1 from state 2 for real, not just "some
/// non-zero value".
#[test]
fn test_lane_state_half_open_via_sibling_pool_cell() {
    register_planes();
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new("model-ho", PROTO_OPENAI, "http://ho"))
        .pool("pool-tripped", &[(0, 1)])
        .pool("pool-sibling", &[(0, 1)])
        .build_with_store();

    let t = now();
    // Materialize the sibling pool's cell fresh (Closed, cooldown=0, ready) BEFORE tripping the
    // other pool — `lane_usable_any_cell` only sees cells that have been touched at least once.
    // `cooldown_remaining_in` reads through the SAME lazy `cell()` lookup `force_open_in` writes
    // through, so this materializes the cell exactly as the crate-internal `store.cell(...)` call
    // the unit-test twin of this file used — without naming the `pub(crate)` accessor directly.
    let _ = store.cooldown_remaining_in("pool-sibling", 0, t);
    // Trip pool-tripped's cell Open with a cooldown well into the future.
    store.force_open_in("pool-tripped", 0, t + 600);

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
/// fresh/Closed, must still report state 1 for the model-labeled gauge. Every `TestApp` lane is
/// auto-registered in `by_model` regardless of pool membership, so adding a pool here (to
/// materialize a per-pool cell) doesn't remove the lane from the by_model gauge loop.
#[test]
fn test_lane_state_half_open_by_model_via_sibling_pool_cell() {
    register_planes();
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new("model-by", PROTO_OPENAI, "http://by"))
        .pool("some-pool", &[(0, 1)])
        .build_with_store();

    let t = now();
    // Materialize a per-pool cell fresh/Closed so `lane_usable_any_cell` has a ready cell to
    // find (without this, it would fall back to the default cell itself, which we're about to
    // trip — making usable/cooldown check the SAME cell and state 1 unreachable).
    let _ = store.cooldown_remaining_in("some-pool", 0, t);
    // Trip the DEFAULT ("") cell — the one `cooldown_remaining_in("", lane_idx, now)` reads in
    // the by_model loop.
    store.force_open_in("", 0, t + 600);

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

/// The `>` boundary in the by_model guard's `cooldown > 0 && !snap.usable` check specifically: with
/// the DEFAULT (`""`) cell UNTOUCHED (cooldown reads exactly 0, `by_model`'s direct-routing path
/// never went through it) while every per-pool cell for the SAME lane is Open/unusable, the
/// by_model gauge must report state 0 (the direct path's own cell is genuinely healthy — pool
/// brokenness on a completely separate traffic path is irrelevant to it), not 2. A mutated
/// `cooldown == 0` would flip this specific case to 2, since `0 == 0` is true where `0 > 0` is
/// false — the two operators only diverge exactly at cooldown == 0, which the other HalfOpen
/// tests (cooldown = 600) can never reach.
#[test]
fn test_lane_state_by_model_default_cell_untouched_zero_cooldown_reports_healthy() {
    register_planes();
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new("model-zero", PROTO_OPENAI, "http://zero"))
        .pool("poolX", &[(0, 1)])
        .pool("poolY", &[(0, 1)])
        .build_with_store();

    let t = now();
    // Trip EVERY per-pool cell Open (unexpired cooldown) — the lane is unusable via any pool.
    // The DEFAULT ("") cell is deliberately never touched: cooldown_remaining_in("", 0, now)
    // reads exactly 0 (its pristine untouched state), which is the boundary value that
    // distinguishes `>` from `==`.
    store.force_open_in("poolX", 0, t + 600);
    store.force_open_in("poolY", 0, t + 600);

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
