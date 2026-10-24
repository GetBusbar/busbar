// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS WALK'S PRODUCTION PORTS (ARCHITECT Q-SW8, 2026-10-02): the clock reads the wall and
//! a monotonic origin and sleeps on the runtime's timer; a member's `max_concurrent` slots are held
//! until dropped and handed to the longest waiter; the counters label a member by its name and keep
//! each pool's wait depth balanced.

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

// ── F25 REHOME: the attempt timeout a sealed member carries, the queue's one wake, the p95 ring ───

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

/// A dialect the root links, read as data off the node's dialect fixture (the root's sources name
/// no dialect).
fn a_linked_dialect() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/root/tests/fixtures/plane_node_dialects.json"
    );
    let text = std::fs::read_to_string(path).expect("the dialect fixture reads");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("the fixture is JSON");
    fixture["body_model"]
        .as_object()
        .and_then(|dialects| dialects.keys().next().cloned())
        .expect("the fixture names a body-model dialect")
}

/// THE MODEL-SERVING EGRESS, sealed by [`crate::root::model_egress::compose`] the way the serve
/// path seals it, over a deployment where model `patient` states a 10000 ms attempt timeout and
/// model `plain` states none; pool `fast` overrides `patient` to 50 ms and leaves `plain` bare, and
/// pool `slow` names `patient` with no override. Both models are also routable directly.
fn sealed_timeouts() -> busbar_kernel::plane_driver::Egress {
    // The deployment names `models:`/`pools:`, which config resolution hands a plane.
    busbar_kernel::test_support::register_neutral_test_plane();
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
    let app = busbar_kernel::test_support::TestApp::new().build();
    let serving = crate::root::model_egress::ModelServing {
        pools: crate::root::model_egress::ModelPools::of(&cfg),
        lanes: [("patient".to_string(), 0), ("plain".to_string(), 1)]
            .into_iter()
            .collect(),
        app: Arc::new(move || Arc::clone(&app)),
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

/// The attempt timeout the sealed `pool`'s member `model` carries.
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

/// LEGACY the retiring engine crate's `src/engine/tests/attempt_timeout_precedence_tests.rs::test_member_override_wins_over_model_default`
/// (coverage map v2 row 44). 1.5.5: the pool member's `attempt_timeout_ms` override wins over the
/// model-level default, so one model carries 10000 ms in one pool and 50 ms in another.
///
/// RED: the sealed member carries the model's 10000 ms (or nothing) instead of its pool's 50 ms.
#[test]
fn a_members_attempt_timeout_wins_over_its_models_default() {
    let egress = sealed_timeouts();
    assert_eq!(
        sealed_attempt_ms(&egress, "fast", "patient"),
        Some(50),
        "the pool-member override must beat the model-level default"
    );
}

/// LEGACY the retiring engine crate's `src/engine/tests/attempt_timeout_precedence_tests.rs::test_model_default_applies_when_member_has_no_override`
/// (coverage map v2 row 45). 1.5.5: a member without an override inherits the model-level default.
///
/// RED: a member that states no override loses its model's 10000 ms cap (or takes another pool's).
#[test]
fn test_model_default_applies_when_member_has_no_override() {
    let egress = sealed_timeouts();
    assert_eq!(
        sealed_attempt_ms(&egress, "slow", "patient"),
        Some(10_000),
        "a member with no override must fall back to the model-level cap"
    );
}

/// LEGACY the retiring engine crate's `src/engine/tests/attempt_timeout_precedence_tests.rs::test_no_cap_anywhere_is_none`
/// (coverage map v2 row 46). 1.5.5: with neither level set the attempt is uncapped (`None`): it
/// runs under the walk's budget alone.
///
/// RED: a member whose pool and model state no cap is sealed with one.
#[test]
fn test_no_cap_anywhere_is_none() {
    let egress = sealed_timeouts();
    assert_eq!(sealed_attempt_ms(&egress, "fast", "plain"), None);
}

/// LEGACY the retiring engine crate's `src/engine/tests/attempt_timeout_precedence_tests.rs::test_empty_cands_uses_model_default`
/// (coverage map v2 row 47). 1.5.5: a single-model route has no member rows at all, so the
/// model-level value is the only source: 10000 ms where the model states it, uncapped where it
/// states none.
///
/// RED: a route naming a model directly drops the model's own attempt timeout (or invents one).
#[test]
fn test_empty_cands_uses_model_default() {
    let egress = sealed_timeouts();
    assert_eq!(
        sealed_attempt_ms(&egress, "patient", "patient"),
        Some(10_000)
    );
    assert_eq!(sealed_attempt_ms(&egress, "plain", "plain"), None);
}

/// LEGACY the retiring engine crate's `src/engine/tests/on_exhausted_tests.rs::queue_two_waiters_one_freed_permit_wakes_exactly_one`
/// (coverage map v2 row 542). 1.5.5: with two waiters parked on a saturated one-slot member,
/// freeing ONE slot lets EXACTLY ONE dispatch; the other stays parked (no thundering herd, the cap
/// never exceeded) until the winner's slot frees in turn.
///
/// RED: one freed slot wakes both waiters, hands out a second slot, or loses the wake so neither
/// (or only the first) ever proceeds.
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

/// NO LOST WAKEUP: a slot freed in the window around the moment a waiter parks is kept for it, so
/// the waiter dispatches well inside a short wait rather than missing the wake and timing out.
/// Driven fifty times so the free lands on both sides of the park. Rehomes
/// the retired engine crate's `src/engine/tests/on_exhausted_tests.rs::queue_no_lost_wakeup_when_permit_freed_in_the_window`.
/// RED: a wake fired before the waiter registered is lost, and the waiter waits out its bound.
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

/// LEGACY the retiring engine crate's `src/engine/tests/signal_catalog_tests.rs::latency_reservoir_p95_is_nearest_rank_and_bounded`
/// (coverage map v2 row 612). 1.5.5: the reservoir behind `CandidateLatencyP95Ms` reads `None`
/// until a sample lands (never a fabricated 0); its p95 is nearest-rank in whole milliseconds
/// rounded up (1..=100 ms gives 95, a 0.2 ms sample gives 1); NaN, zero and negative samples are
/// ignored; and the ring is bounded, so after 1000 samples of 7 ms only those decide (7).
///
/// RED: an empty ring reads 0, the rank or the rounding moves, a garbage sample is counted, or the
/// ring stops evicting its oldest samples.
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

/// The value of the one exposition line of `family` whose labels hold every one of `labels`, `0`
/// when there is none.
fn scraped(family: &str, labels: &[&str]) -> f64 {
    busbar_kernel::snapshot::render()
        .lines()
        .filter(|l| l.starts_with(family) && !l.starts_with('#'))
        .filter(|l| labels.iter().all(|want| l.contains(want)))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

/// RED (the counter-label bound, ARCHITECT ruling: one optional per-attempt tail, bounded): a lane
/// word the plane never declared, and a pool its walk cannot reach, fall back to the walk's own
/// labels and count on `busbar_plugin_label_refused_total`; a declared word and a reachable entry
/// are taken. Without the bound the stated words would be emitted as given, and a plane could mint
/// a series per distinct string.
#[test]
fn a_label_outside_the_bound_falls_back_and_counts_its_refusal() {
    use busbar_kernel_egress::ports::StatedLabels;
    busbar_kernel::snapshot::init();
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
            &["pool=\"entry-red-arm\"", "lane=\"own-red-arm\""]
        ) >= 1.0,
        "its lane fell back to the walk's own, its reachable pool was taken: {}",
        busbar_kernel::snapshot::render()
    );
    assert_eq!(
        scraped(attempts, &["lane=\"undeclared-word\""]),
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
            &["pool=\"walked-red-arm\"", "lane=\"declared-word\""]
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
