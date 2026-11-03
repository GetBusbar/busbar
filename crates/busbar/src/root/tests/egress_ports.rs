// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_kernel_egress::ports::{Capacity, Clock, DestinationId, Telemetry};

use super::{MemberPermits, NodeClock, WalkTelemetry};

const A: DestinationId = DestinationId::new(0);
const B: DestinationId = DestinationId::new(1);
const FREE: DestinationId = DestinationId::new(2);

#[tokio::test]
async fn the_clock_reads_the_wall_a_monotonic_origin_and_sleeps_on_the_timer() {
    let clock = NodeClock::new();
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    assert!(clock.now_secs().abs_diff(wall) <= 1, "whole wall seconds");
    let before = clock.now_millis();
    let started = std::time::Instant::now();
    clock.sleep(20).await;
    assert!(started.elapsed() >= Duration::from_millis(20), "slept");
    assert!(
        clock.now_millis() >= before + 20,
        "monotonic, in milliseconds"
    );
}

#[test]
fn a_limited_member_holds_its_slots_until_they_drop_and_an_unlimited_one_never_fills() {
    let permits = MemberPermits::new([(A, 1)]);
    let held = permits.try_acquire(A).expect("one slot");
    assert_eq!(held.destination(), A);
    assert!(permits.try_acquire(A).is_none(), "at capacity");
    drop(held);
    assert!(permits.try_acquire(A).is_some(), "freed on drop");
    let many: Vec<_> = (0..64).map(|_| permits.try_acquire(FREE)).collect();
    assert!(
        many.iter().all(Option::is_some),
        "no limit, never at capacity"
    );
}

#[tokio::test]
async fn a_waiter_takes_the_first_slot_freed_on_any_of_its_members() {
    let permits = std::sync::Arc::new(MemberPermits::new([(A, 1), (B, 1)]));
    let a = permits.try_acquire(A).expect("a's slot");
    let b = permits.try_acquire(B).expect("b's slot");
    let waiter = {
        let permits = std::sync::Arc::clone(&permits);
        tokio::spawn(async move {
            permits
                .acquire_any(&[A, B])
                .await
                .map(|(d, p)| (d, p.destination()))
        })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!waiter.is_finished(), "both members are full");
    drop(b);
    let got = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("woken")
        .expect("joined");
    assert_eq!(got, Some((B, B)), "the freed member's slot");
    drop(a);
}

#[tokio::test]
async fn a_wait_over_an_unlimited_member_answers_at_once() {
    let permits = MemberPermits::new([(A, 0)]);
    let got = permits.acquire_any(&[A, FREE]).await.map(|(d, _)| d);
    assert_eq!(got, Some(FREE));
}

#[test]
fn the_counters_label_a_member_by_name_and_keep_each_pools_depth() {
    let t = WalkTelemetry::new([(A, "first".to_string())]);
    assert_eq!(t.lane(A), "first");
    assert_eq!(t.lane(B), "", "a member the seal did not name");
    t.queued("p", 1);
    t.queued("p", 1);
    t.queued("q", 1);
    t.queued("p", -1);
    assert_eq!((t.depth("p"), t.depth("q")), (1, 1));
    t.queued("p", -5);
    assert_eq!(t.depth("p"), 0, "a depth never reads below empty");
}

/// A connection table that opens nothing: the sealing below never dials.
#[derive(Debug, Default)]
struct Shut;

impl busbar_contract::conn::Conns for Shut {
    fn open(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::NeedId,
        _: &busbar_contract::conn::OpenDesc<'_>,
    ) -> Result<busbar_contract::conn::ConnId, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Refused)
    }
    fn write(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: u64,
        _: &mut [u8],
    ) -> Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn wait(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: &[busbar_contract::conn::ConnId],
        _: u64,
    ) -> Result<usize, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn facts(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<busbar_contract::transport::ConnFacts, busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
    fn close(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
    ) -> Result<(), busbar_contract::conn::ConnError> {
        Err(busbar_contract::conn::ConnError::Closed)
    }
}

impl busbar_contract::conn::PollConns for Shut {
    fn poll_read(
        &self,
        _: busbar_contract::conn::InstanceId,
        _: busbar_contract::conn::ConnId,
        _: &mut std::task::Context<'_>,
        _: &mut [u8],
    ) -> std::task::Poll<Result<busbar_contract::conn::Piece, busbar_contract::conn::ConnError>>
    {
        std::task::Poll::Ready(Err(busbar_contract::conn::ConnError::Closed))
    }
}

/// A journal that keeps nothing: the sealing below dispatches nothing.
#[derive(Debug)]
struct Unwritten;

impl busbar_kernel_egress::ports::Journal for Unwritten {
    fn dispatched(
        &self,
        _: &busbar_kernel_egress::ports::Dispatched,
    ) -> Result<(), busbar_kernel_egress::ports::DurabilityUnavailable> {
        Ok(())
    }
    fn abandoned(&self, _: &busbar_kernel_egress::ports::Dispatched) {}
}

fn a_linked_dialect() -> String {
    let path = concat!(
        env!("BUSBAR_CORE_DIR"),
        "/src/root/tests/fixtures/plane_node_dialects.json"
    );
    let text = std::fs::read_to_string(path).expect("the dialect fixture reads");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("the fixture is JSON");
    fixture["body_model"]
        .as_object()
        .and_then(|dialects| dialects.keys().next().cloned())
        .expect("the fixture names a body-model dialect")
}

fn sealed_timeouts() -> busbar_kernel::plane_driver::Egress {
    crate::root::test_plane_registry::register();
    let dialect = a_linked_dialect();
    let mut defs = std::collections::HashMap::new();
    defs.insert(
        "far".to_string(),
        serde_yaml::from_str::<busbar_kernel::config::ProviderDef>(&format!(
            "protocol: {dialect}\nbase_url: https://far.invalid\n"
        ))
        .expect("a provider def"),
    );
    let yaml = "providers:\n  far:\n    api_key: { env: BUSBAR_TEST_KEY }\nmodels:\n  patient:\n    provider: far\n    \
                attempt_timeout_ms: 10000\n  plain:\n    provider: far\npools:\n  fast:\n    \
                members:\n      - model: patient\n        attempt_timeout_ms: 50\n      - model: \
                plain\n  slow:\n    members:\n      - model: patient\n";
    let deploy = busbar_kernel::config::deploy_from_yaml_str(yaml).expect("parses");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
    crate::dist_root_install::install();
    let empty = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: memory}\nauth: {chain: [], admin_auth: []}\nproviders: {}\nmodels: {}\n",
    )
    .expect("the serving deployment parses");
    let empty = busbar_kernel::config::resolve(&empty, &Default::default())
        .expect("the serving deployment resolves");
    let store = crate::root::real_store::store();
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        empty,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(busbar_contract::store_calls::OpenedStore {
            records: store.clone(),
            calls: Some(store),
        }),
        false,
    )
    .expect("the product builds the timeout sealing application");
    limits.keep().expect("the serving limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);
    let serving = crate::root::model_egress::ModelServing {
        pools: crate::root::model_egress::ModelPools::of(&cfg),
        lanes: [("patient".to_string(), 0), ("plain".to_string(), 1)]
            .into_iter()
            .collect(),
        app: crate::root::model_egress::LiveApp::fixed(app),
    };
    let route = |provider: &str| busbar_kernel::plane_driver::MemberRoute {
        need: busbar_contract::conn::NeedId(0),
        base_url: "https://far.invalid".to_string(),
        auth: None,
        provider: provider.to_string(),
        keep: busbar_kernel::plane_driver::ResponseKeep::default(),
        rides: Vec::new(),
        anchors: busbar_contract::transport::trust::Anchors::default(),
        spelled: Vec::new(),
    };
    let routes: std::collections::BTreeMap<String, busbar_kernel::plane_driver::MemberRoute> =
        [("patient", route("far")), ("plain", route("far"))]
            .into_iter()
            .map(|(model, sealed)| (model.to_string(), sealed))
            .collect();
    let facts =
        crate::root::door_steps::door_facts("door", &["pool"], &[], &[], "unit", Vec::new());
    let (egress, _shown) = crate::root::model_egress::compose(
        &facts,
        &serving,
        busbar_contract::conn::InstanceId(1),
        Arc::new(Shut),
        &routes,
        Arc::new(Unwritten),
        Arc::new(crate::root::egress_ports::NodeClock::new()),
        600,
    )
    .expect("the pools seal");
    egress
}

fn sealed_attempt_ms(
    egress: &busbar_kernel::plane_driver::Egress,
    pool: &str,
    model: &str,
) -> Option<u64> {
    egress
        .pools
        .get(pool)
        .unwrap_or_else(|| panic!("pool `{pool}` is sealed"))
        .members
        .iter()
        .find(|member| member.name == model)
        .unwrap_or_else(|| panic!("`{model}` is a member of `{pool}`"))
        .attempt_timeout_ms
}

#[cfg(linked_section_pools)]
#[test]
fn the_root_fixture_cohort_keeps_one_actual_fallback_after_timeout_resolution() {
    let actual = crate::root::test_plane_registry::fallback();
    assert!(actual.fallback);
    assert_ne!(actual.key, "neutral-test-fallback");
    crate::root::test_plane_registry::register();
    let egress = sealed_timeouts();
    assert_eq!(sealed_attempt_ms(&egress, "fast", "patient"), Some(50));
    let rows = busbar_kernel::plane_driver::registry::plane_decls();
    let fallback: Vec<_> = rows.iter().filter(|row| row.fallback).collect();
    assert_eq!(fallback.len(), 1);
    assert!(std::ptr::eq(*fallback[0], actual));
    assert_eq!(
        busbar_kernel::plane_driver::dispatch::fallback_key(),
        actual.key
    );
}

#[test]
fn a_members_attempt_timeout_wins_over_its_models_default() {
    let egress = sealed_timeouts();
    assert_eq!(
        sealed_attempt_ms(&egress, "fast", "patient"),
        Some(50),
        "the pool-member override must beat the model-level default"
    );
}

#[test]
fn test_model_default_applies_when_member_has_no_override() {
    let egress = sealed_timeouts();
    assert_eq!(
        sealed_attempt_ms(&egress, "slow", "patient"),
        Some(10_000),
        "a member with no override must fall back to the model-level cap"
    );
}

#[test]
fn test_no_cap_anywhere_is_none() {
    let egress = sealed_timeouts();
    assert_eq!(sealed_attempt_ms(&egress, "fast", "plain"), None);
}

#[test]
fn test_empty_cands_uses_model_default() {
    let egress = sealed_timeouts();
    assert_eq!(
        sealed_attempt_ms(&egress, "patient", "patient"),
        Some(10_000)
    );
    assert_eq!(sealed_attempt_ms(&egress, "plain", "plain"), None);
}

#[tokio::test]
async fn the_queue_frees_one_permit_to_exactly_one_of_two_waiters() {
    let permits = std::sync::Arc::new(MemberPermits::new([(A, 1)]));
    let held = permits.try_acquire(A).expect("the one slot");
    let (woke, mut wakes) = tokio::sync::mpsc::unbounded_channel();
    let waiters: Vec<_> = (0..2)
        .map(|_| {
            let (permits, woke) = (std::sync::Arc::clone(&permits), woke.clone());
            tokio::spawn(async move {
                let got = permits.acquire_any(&[A]).await;
                let _ = woke.send(got);
            })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        wakes.try_recv().is_err(),
        "both waiters park on the full member"
    );

    drop(held);
    let first = tokio::time::timeout(Duration::from_secs(5), wakes.recv())
        .await
        .expect("exactly one waiter must win the freed slot")
        .expect("a waiter answered")
        .expect("the slot was handed over");
    assert_eq!(first.0, A);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        wakes.try_recv().is_err(),
        "while the winner holds the only slot, the surviving waiter must still be parked (no herd)"
    );
    assert!(
        permits.try_acquire(A).is_none(),
        "the single freed slot is held by the one winner — none left for a second dispatcher"
    );

    drop(first);
    let second = tokio::time::timeout(Duration::from_secs(5), wakes.recv())
        .await
        .expect("the survivor wins the slot the winner freed")
        .expect("a waiter answered")
        .expect("the slot was handed over");
    assert_eq!(second.0, A);
    for waiter in waiters {
        tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("both waiters resolve")
            .expect("joined");
    }
}

#[tokio::test]
async fn a_slot_freed_as_its_waiter_parks_is_not_lost() {
    for _ in 0..50 {
        let permits = std::sync::Arc::new(MemberPermits::new([(A, 1)]));
        let held = permits.try_acquire(A).expect("the one slot");
        let waiter = {
            let permits = std::sync::Arc::clone(&permits);
            tokio::spawn(async move { permits.acquire_any(&[A]).await })
        };
        tokio::task::yield_now().await;
        drop(held);
        let got = tokio::time::timeout(Duration::from_millis(400), waiter)
            .await
            .expect("the freed slot reaches the waiter inside the short wait")
            .expect("joined")
            .expect("the slot was handed over");
        assert_eq!(got.0, A);
    }
}

#[test]
fn latency_reservoir_p95_is_nearest_rank_and_bounded() {
    use crate::root::model_egress::LatencyReservoir;
    let ring = LatencyReservoir::default();
    assert_eq!(ring.p95_ms(), None);
    for ms in 1..=100u32 {
        ring.record(f64::from(ms));
    }
    assert_eq!(ring.p95_ms(), Some(95));
    ring.record(f64::NAN);
    ring.record(0.0);
    ring.record(-3.0);
    assert_eq!(ring.p95_ms(), Some(95));
    let tiny = LatencyReservoir::default();
    tiny.record(0.2);
    assert_eq!(tiny.p95_ms(), Some(1));
    for _ in 0..1000 {
        ring.record(7.0);
    }
    assert_eq!(ring.p95_ms(), Some(7));
}

fn scraped(family: &str, labels: &[(&str, &str)]) -> f64 {
    busbar_kernel::snapshot::snapshot()
        .expect("the actual host recorder is installed")
        .iter()
        .flat_map(|f| &f.samples)
        .filter(|sample| sample.name == family)
        .filter(|sample| {
            labels
                .iter()
                .all(|(name, value)| sample.labels.iter().any(|(n, v)| n == name && v == value))
        })
        .filter_map(|sample| sample.value.parse::<f64>().ok())
        .sum()
}

#[test]
fn a_label_outside_the_bound_falls_back_and_counts_its_refusal() {
    use busbar_kernel_egress::ports::StatedLabels;
    busbar_kernel::snapshot::init_for_test(Duration::from_secs(60));
    let attempts = busbar_kernel::telemetry::UPSTREAM_ATTEMPTS_TOTAL;
    let refused = busbar_kernel::snapshot::PLUGIN_LABEL_REFUSED_TOTAL;
    let bound = super::LabelBound::new(["declared-word".to_string()]).reaching(
        "walked-red-arm",
        Vec::<String>::new(),
        ["entry-red-arm".to_string()],
    );
    let t = WalkTelemetry::new([(A, "own-red-arm".to_string())]).bounded(bound);
    let stated = |pool: &str, lane: &str| StatedLabels {
        pool: Some(pool.to_string()),
        lane: Some(lane.to_string()),
    };

    let before = scraped(refused, &[]);
    t.upstream_attempt_stated(
        "walked-red-arm",
        A,
        Some(&stated("entry-red-arm", "undeclared-word")),
    );
    assert!(
        scraped(refused, &[]) > before,
        "an undeclared lane word is counted refused"
    );
    assert!(
        scraped(
            attempts,
            &[("pool", "entry-red-arm"), ("lane", "own-red-arm")]
        ) >= 1.0,
        "its lane fell back to the walk's own, its reachable pool was taken: {:?}",
        busbar_kernel::snapshot::snapshot()
    );
    assert_eq!(
        scraped(attempts, &[("lane", "undeclared-word")]),
        0.0,
        "the undeclared word was never emitted"
    );

    let before = scraped(refused, &[]);
    t.upstream_failure_stated(
        "walked-red-arm",
        A,
        "transient_upstream",
        Some(&stated("unreachable-pool", "declared-word")),
    );
    assert!(
        scraped(refused, &[]) > before,
        "an unreachable pool is refused"
    );
    assert!(
        scraped(
            busbar_kernel::telemetry::UPSTREAM_FAILURES_TOTAL,
            &[("pool", "walked-red-arm"), ("lane", "declared-word")]
        ) >= 1.0,
        "its pool fell back to the walk's own, its declared lane word was taken"
    );

    let before = scraped(refused, &[]);
    t.upstream_attempt_stated(
        "walked-red-arm",
        A,
        Some(&stated("entry-red-arm", "declared-word")),
    );
    assert_eq!(
        scraped(refused, &[]),
        before,
        "words within the bound refuse nothing"
    );
}
