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

mod linked;

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
    linked::install();
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

/// SHARED LANE, one pool's OWN cell Open, the other pool's cell healthy: the tripped pool reads
/// `busbar_lane_state = 2` and the healthy pool reads `0`. The gauge reads each pool's own breaker
/// cell; a sibling pool's healthy cell on the same lane never softens a trip into `1` (that value
/// is reserved for a real half-open probe on the pool's own cell). The tripped pool's
/// `busbar_lane_available` on the same label pair reads 0, so the two gauges agree.
#[test]
fn test_lane_state_tripped_pool_reads_two_despite_healthy_sibling_pool() {
    register_planes();
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new("model-ho", PROTO_OPENAI, "http://ho"))
        .pool("pool-tripped", &[(0, 1)])
        .pool("pool-sibling", &[(0, 1)])
        .build_with_store();

    let t = now();
    // Materialize the sibling pool's cell (Closed, no cooldown) so the lane is genuinely usable
    // through it, then trip the other pool's cell Open with a cooldown well into the future.
    let _ = store.cooldown_remaining_in("pool-sibling", 0, t);
    store.force_open_in("pool-tripped", 0, t + 600);

    refresh_scrape_gauges(&app);
    let out = render();

    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-tripped"),
        Some(2.0),
        "a pool whose own cell is Open reads 2 (tripped) whatever a sibling pool's cell on the \
         same lane says; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_AVAILABLE, "pool-tripped"),
        Some(0.0),
        "the tripped pool admits nothing; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-sibling"),
        Some(0.0),
        "the sibling pool's own healthy cell reads 0; got:\n{out}"
    );
}

/// The `by_model` (direct/no-pool routing) twin: the DEFAULT (`""`) cell tripped Open while a
/// per-pool cell for the same lane stays Closed must read 2 for the model-labeled gauge — the
/// direct path's own cell is tripped, and the pool cell it does not route through cannot mask it.
#[test]
fn test_lane_state_by_model_tripped_default_cell_reads_two_despite_healthy_pool_cell() {
    register_planes();
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new("model-by", PROTO_OPENAI, "http://by"))
        .pool("some-pool", &[(0, 1)])
        .build_with_store();

    let t = now();
    let _ = store.cooldown_remaining_in("some-pool", 0, t);
    store.force_open_in("", 0, t + 600);

    refresh_scrape_gauges(&app);
    let out = render();

    assert_eq!(
        gauge_value(&out, LANE_STATE, "model-by"),
        Some(2.0),
        "the direct path's own default cell is Open: the by_model gauge reads 2; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_STATE, "some-pool"),
        Some(0.0),
        "the untouched pool cell reads 0; got:\n{out}"
    );
}

/// `1` is reachable, and ONLY through a real half-open probe on the pool's own cell: an Open cell
/// whose cooldown has elapsed reads 0 (the next request through it is the probe), and once a
/// dispatch wins that probe the cell is HalfOpen and the gauge reads 1. A sibling pool on the same
/// lane is untouched and reads 0 throughout.
#[test]
fn test_lane_state_half_open_probe_on_own_cell_reads_one() {
    register_planes();
    init();

    let (app, store) = TestApp::new()
        .lane(LaneSpec::new("model-probe", PROTO_OPENAI, "http://probe"))
        .pool("pool-probe", &[(0, 1)])
        .pool("pool-probe-sib", &[(0, 1)])
        .build_with_store();

    let t = now();
    let _ = store.cooldown_remaining_in("pool-probe-sib", 0, t);
    // Open with a cooldown that has already elapsed: the next dispatch through this cell probes.
    store.force_open_in("pool-probe", 0, t.saturating_sub(1));

    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-probe"),
        Some(0.0),
        "an Open cell whose cooldown elapsed admits the next request as its probe: reads 0; \
         got:\n{out}"
    );

    // A dispatch wins the single-flight probe: the pool's own cell is now HalfOpen.
    let probe = store
        .try_admit_breaker("pool-probe", 0, now())
        .expect("an elapsed Open cell admits the probe");
    assert!(
        probe.is_some(),
        "the admit must have WON the recovery probe"
    );

    refresh_scrape_gauges(&app);
    let out = render();
    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-probe"),
        Some(1.0),
        "a half-open probe in flight on the pool's own cell reads 1; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_STATE, "pool-probe-sib"),
        Some(0.0),
        "the sibling pool's own cell is not probing and reads 0; got:\n{out}"
    );
}

/// The gauge is PLANE-AGNOSTIC: the plane-neutral breaker cells every other plane dispatches
/// through get `busbar_lane_state` samples too, read from each cell alone — a tripped
/// destination reads 2, a healthy one 0 — with no plane named by the emitter.
#[test]
fn test_lane_state_emitted_for_plane_neutral_breaker_cells() {
    register_planes();
    init();

    let app = TestApp::new()
        .lane(LaneSpec::new("model-pn", PROTO_OPENAI, "http://pn"))
        .pool("pool-pn", &[(0, 1)])
        .build();

    let down = busbar_kernel::store::tool_key("t281-down");
    let up = busbar_kernel::store::agent_key("t281-up");
    let t = now();
    app.plane_breakers.force_open(&down, 0, t + 600);
    app.plane_breakers.record_success(&up, 0);

    refresh_scrape_gauges(&app);
    let out = render();

    assert_eq!(
        gauge_value(&out, LANE_STATE, &down),
        Some(2.0),
        "a tripped plane-neutral destination reads 2; got:\n{out}"
    );
    assert_eq!(
        gauge_value(&out, LANE_STATE, &up),
        Some(0.0),
        "a healthy plane-neutral destination reads 0; got:\n{out}"
    );
    let line = out
        .lines()
        .find(|l| {
            !l.starts_with('#')
                && l.starts_with(&format!("{LANE_STATE}{{"))
                && l.contains(&format!("pool=\"{down}\""))
        })
        .expect("sample present");
    assert!(
        line.contains("lane=\"0\""),
        "a single registered target is member position 0; got:\n{line}"
    );
}

/// The `cooldown > 0` boundary on the by_model gauge: with the DEFAULT (`""`) cell UNTOUCHED
/// (cooldown reads exactly 0 — `by_model`'s direct-routing path never went through it) while every
/// per-pool cell for the SAME lane is Open, the by_model gauge must report state 0 (the direct
/// path's own cell is genuinely healthy — pool cells on a separate traffic path are irrelevant to
/// it), not 2. A mutated `cooldown >= 0` would flip this case to 2; the tests with a 600s cooldown
/// can never reach that boundary.
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
