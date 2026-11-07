// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Mutation, Page,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::records::{MeteringDelta, VirtualKey};
use busbar_contract::Count;
use busbar_kernel::cost::{CostModel, RawRateEra};
use busbar_kernel::governance::recovery::{RecoveryError, RecoveryEvent, RecoverySink};
use busbar_kernel::governance::{Adjustment, GovState};
use busbar_kernel::persistence::facade::CoreStore;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};

type RequestUnit = super::super::super::AdminRequest;
type Replay = super::super::super::bound::ReplayStore;

#[derive(Default)]
struct Journal(Mutex<Vec<RecoveryEvent>>);
#[async_trait::async_trait]
impl RecoverySink for Journal {
    async fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let mut events = self.0.lock().unwrap();
        if !events.contains(event) {
            events.push(event.clone());
        }
        Ok(())
    }
    async fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadPoint {
    Key,
    Usage,
    Metering,
}

struct FaultStore {
    inner: Arc<dyn PersistenceBackend>,
    read_failure: Mutex<Option<(ReadPoint, usize)>>,
    unavailable: AtomicBool,
    lose_reply: AtomicBool,
    submissions: AtomicUsize,
}
impl FaultStore {
    fn read_fault(&self, point: ReadPoint) -> Result<(), Failure> {
        if point == ReadPoint::Key && self.unavailable.load(Ordering::SeqCst) {
            return Err(Failure::Unavailable);
        }
        let mut failure = self.read_failure.lock().unwrap();
        if let Some((target, remaining)) = failure.as_mut() {
            if *target == point {
                *remaining -= 1;
                if *remaining == 0 {
                    *failure = None;
                    return Err(Failure::Unavailable);
                }
            }
        }
        Ok(())
    }
}
impl PersistenceBackend for FaultStore {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            if request
                .addresses
                .iter()
                .any(|a| a.key.first() == Some(&b'K'))
            {
                self.read_fault(ReadPoint::Key)?;
            }
            if request
                .addresses
                .iter()
                .any(|a| a.key.first() == Some(&b'U'))
            {
                self.read_fault(ReadPoint::Usage)?;
            }
            self.inner.read(request).await
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            if request.prefix.first() == Some(&b'M') {
                self.read_fault(ReadPoint::Metering)?;
            }
            self.inner.scan(request).await
        })
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let correction = candidate.candidate().mutations.iter().any(|m| {
                matches!(m, Mutation::Put { address, .. } if address.key.first() == Some(&b'U'))
            });
            if correction {
                self.submissions.fetch_add(1, Ordering::SeqCst);
            }
            let decision = self.inner.commit(candidate).await?;
            if correction && self.lose_reply.swap(false, Ordering::SeqCst) {
                assert!(
                    matches!(decision, Decision::Applied { .. }),
                    "fault follows a real commit"
                );
                return Err(Failure::Unknown);
            }
            Ok(decision)
        })
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
}

struct Fixture {
    store: Arc<CoreStore>,
    faults: Arc<FaultStore>,
    active: Arc<RwLock<Arc<GovState>>>,
    journal: Arc<Journal>,
    cost: Arc<CostModel>,
    adjuster: UsageAdjuster,
    replay: Replay,
    calls: Arc<AtomicUsize>,
    now: u64,
    era: u64,
}
impl Fixture {
    async fn new() -> Self {
        let backend = crate::root::real_store::native_backend().await;
        let faults = Arc::new(FaultStore {
            inner: backend,
            read_failure: Mutex::new(None),
            unavailable: AtomicBool::new(false),
            lose_reply: AtomicBool::new(false),
            submissions: AtomicUsize::new(0),
        });
        let store = crate::root::real_store::core_over(faults.clone()).await;
        let gov = Arc::new(
            GovState::new_with_core(store.clone(), None, None)
                .await
                .unwrap(),
        );
        let journal = Arc::new(Journal::default());
        gov.attach_recovery_sink(journal.clone()).await.unwrap();
        let key = VirtualKey {
            id: "exact-staging-key".into(),
            generation_hash: "exact-staging-generation".into(),
            enabled: true,
            revision: 1,
            ..Default::default()
        };
        store.identity().put_key(&key).await.unwrap();
        let rates = BTreeMap::from([(
            "lane".into(),
            busbar_kernel::config::RateEntryCfg {
                units: BTreeMap::from([("search_units".into(), Default::default())]),
                ..Default::default()
            },
        )]);
        let cost = Arc::new(CostModel::resolve_parts(Some(&rates), 0, &BTreeMap::new()));
        let now = busbar_kernel::store::now();
        let era = busbar_kernel::rate_apply::effective_from_at(now * 1000);
        gov.record_usage_served_in_era(
            &cost,
            &key,
            "pool",
            "lane",
            None,
            &BTreeMap::from([("search_units".into(), 1)]),
            now,
            RawRateEra::legacy(era),
        );
        gov.flush_budgets().await;
        store
            .ledger()
            .add_metering(&MeteringDelta {
                scale: 0,
                key_id: key.id.clone(),
                bucket: busbar_kernel::governance::metering_bucket(now),
                model: "lane".into(),
                provider: String::new(),
                tokens_input: 0,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 1,
                billable_requests: 1,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                priced_from_ms: era,
                usage_units: BTreeMap::from([("search_units".into(), 1)]),
            })
            .await
            .unwrap();
        // Setup writes are settled before the fault boundary is armed.
        faults.submissions.store(0, Ordering::SeqCst);
        journal.0.lock().unwrap().clear();
        let active = Arc::new(RwLock::new(gov));
        let calls = Arc::new(AtomicUsize::new(0));
        let adjuster: UsageAdjuster = {
            let active = active.clone();
            let cost = cost.clone();
            let calls = calls.clone();
            Arc::new(move |correction| {
                let gov = active.read().unwrap().clone();
                let cost = cost.clone();
                let calls = calls.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    gov.adjust_usage_exact_action_async(
                        &cost,
                        &Adjustment {
                            key_id: &correction.key,
                            pool: &correction.pool,
                            model: &correction.lane,
                            entry_era: era,
                            entry_id: None,
                            card_epoch_ms: correction.card_epoch_ms,
                            delta: &correction.delta,
                            now,
                        },
                        correction.action_id.as_deref(),
                    )
                    .await
                    .map(|result| result.map_err(Refused::Ledger))
                    .map_err(|error| error.to_string())
                })
            })
        };
        let replay: Replay = {
            let replay = Arc::new(
                busbar_core_admin::idempotency::durable::scoped_store(store.clone()).unwrap(),
            );
            Arc::new(move || Some(replay.clone()))
        };
        Self {
            store,
            faults,
            active,
            journal,
            cost,
            adjuster,
            replay,
            calls,
            now,
            era,
        }
    }

    fn unit(&self, action: &str, delta: &str) -> RequestUnit {
        RequestUnit {
            method: "POST".into(),
            path: "/api/v1/admin/adjust".into(),
            credential: None,
            headers: vec![("idempotency-key".into(), action.into())],
            body: serde_json::to_vec(&serde_json::json!({
                "key": "exact-staging-key", "lane": "lane",
                "entry": busbar_kernel::cost::EntryKey::new(self.era, [7; 8], 1).hex(),
                "card_epoch_ms": self.now * 1000, "pool": "pool",
                "delta": {"search_units": delta}, "reason": "exact range regression"
            }))
            .unwrap(),
            at: self.now,
            unit: 1,
        }
    }
    async fn ask(&self, unit: &RequestUnit) -> AdminAnswer {
        adjust_request(
            unit,
            &unit.body,
            busbar_contract::authz::Scope::Full,
            "actor",
            Some(&self.replay),
            &|_| true,
            &self.adjuster,
        )
        .await
        .unwrap()
    }
    async fn count(&self) -> Count {
        let stored = self
            .store
            .ledger()
            .get_usage("exact-staging-key", 0)
            .await
            .unwrap();
        let lane = stored
            .models
            .iter()
            .find(|row| row.model == "lane")
            .unwrap();
        assert_eq!(lane.scale, 6);
        Count::from_stored(lane.usage_units["search_units"], lane.scale).unwrap()
    }
    async fn restart(&self) {
        let restarted = Arc::new(
            GovState::new_with_core(self.store.clone(), None, None)
                .await
                .unwrap(),
        );
        restarted
            .attach_recovery_sink(self.journal.clone())
            .await
            .unwrap();
        restarted
            .hydrate_budgets_async(&self.cost, self.now)
            .await
            .unwrap();
        *self.active.write().unwrap() = restarted;
    }
    async fn assert_clear(&self) {
        let active = self.active.read().unwrap().clone();
        assert!(active.recovery().list(None, 10).await.unwrap().is_empty());
    }
}

fn assert_effect(answer: &AdminAnswer, status: u16, effect: &str) {
    assert_eq!(answer.status, status);
    let receipt: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
    assert_eq!(receipt["effect"], effect);
    assert_eq!(receipt["recovery"], "receipt");
}

#[tokio::test]
async fn wide_count_applies_replays_restarts_and_restores_exactly() {
    for delta in ["9007199254740993.000001", "9223372036854.775808"] {
        let fixture = Fixture::new().await;
        let unit = fixture.unit("wide", delta);
        let first = fixture.ask(&unit).await;
        assert_effect(&first, 200, "applied");
        let expected = Count::ONE
            .checked_add(Count::parse(delta).unwrap())
            .unwrap();
        assert_eq!(fixture.count().await, expected);
        fixture.restart().await;
        assert_eq!(fixture.ask(&unit).await.body, first.body);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.count().await, expected);
        assert_eq!(
            fixture.ask(&fixture.unit("wide", "0.000001")).await.status,
            409
        );
        let inverse = fixture.unit("inverse", &format!("-{delta}"));
        assert_effect(&fixture.ask(&inverse).await, 200, "applied");
        assert_eq!(fixture.count().await, Count::ONE);
        fixture.restart().await;
        assert_eq!(fixture.count().await, Count::ONE);
        fixture.assert_clear().await;
    }
}

#[tokio::test]
async fn signed_minimum_and_result_overflow_refuse_before_effect() {
    let fixture = Fixture::new().await;
    let day = busbar_kernel::governance::metering_bucket(fixture.now);
    let before = fixture
        .store
        .ledger()
        .get_usage("exact-staging-key", 0)
        .await
        .unwrap();
    let metered = fixture.store.ledger().list_metering(day).await.unwrap();
    for (action, delta) in [
        ("minimum", "-170141183460469231731687303715884.105728"),
        ("overflow", "170141183460469231731687303715884.105727"),
    ] {
        let unit = fixture.unit(action, delta);
        let first = fixture.ask(&unit).await;
        assert_effect(&first, 400, "not_applied");
        assert_eq!(fixture.ask(&unit).await.body, first.body);
        assert_eq!(
            fixture
                .store
                .ledger()
                .get_usage("exact-staging-key", 0)
                .await
                .unwrap(),
            before
        );
        assert_eq!(
            fixture.store.ledger().list_metering(day).await.unwrap(),
            metered
        );
        assert!(fixture.journal.0.lock().unwrap().is_empty());
        fixture.assert_clear().await;
    }
}

#[tokio::test]
async fn exhausted_gross_adjustment_counter_is_known_not_applied_without_reservation() {
    let fixture = Fixture::new().await;
    // Raw total reaches the exact Count maximum and returns to one. Both immutable gross
    // adjustment counters retain MAX-ONE, so another two-unit credit cannot be represented.
    let magnitude = "170141183460469231731687303715883.105727";
    assert_effect(
        &fixture.ask(&fixture.unit("maximum", magnitude)).await,
        200,
        "applied",
    );
    assert_eq!(fixture.count().await, busbar_contract::count::MAX);
    assert_effect(
        &fixture
            .ask(&fixture.unit("restore", &format!("-{magnitude}")))
            .await,
        200,
        "applied",
    );
    assert_eq!(fixture.count().await, Count::ONE);
    let events_before = fixture.journal.0.lock().unwrap().clone();
    let bounded = fixture.unit("exhausted-gross", "2");
    let first = fixture.ask(&bounded).await;
    assert_effect(&first, 503, "not_applied");
    assert_eq!(fixture.ask(&bounded).await.body, first.body);
    assert_eq!(fixture.count().await, Count::ONE);
    assert_eq!(*fixture.journal.0.lock().unwrap(), events_before);
    fixture.assert_clear().await;
    // A representable new action still works; no private candidate became a reservation.
    assert_effect(
        &fixture.ask(&fixture.unit("small", "0.000001")).await,
        200,
        "applied",
    );
    assert_eq!(
        fixture.count().await,
        Count::ONE.checked_add(Count::EPSILON).unwrap()
    );
}

#[tokio::test]
async fn preparation_reads_and_unavailability_refuse_without_submission_and_replay_not_applied() {
    for failure in [
        None,
        Some((ReadPoint::Key, 1)),
        Some((ReadPoint::Key, 2)),
        Some((ReadPoint::Usage, 1)),
        Some((ReadPoint::Usage, 2)),
        Some((ReadPoint::Usage, 3)),
        Some((ReadPoint::Usage, 4)),
        Some((ReadPoint::Metering, 1)),
    ] {
        let fixture = Fixture::new().await;
        let day = busbar_kernel::governance::metering_bucket(fixture.now);
        let buckets = [
            ("exact-staging-key", 0),
            (busbar_kernel::governance::ADJUST_UP_BUCKET, day),
            (busbar_kernel::governance::ADJUST_DOWN_BUCKET, day),
        ];
        let mut before = Vec::new();
        for (bucket, window) in &buckets {
            before.push(
                fixture
                    .store
                    .ledger()
                    .get_usage(bucket, *window)
                    .await
                    .unwrap(),
            );
        }
        let metered = fixture.store.ledger().list_metering(day).await.unwrap();
        *fixture.faults.read_failure.lock().unwrap() = failure;
        fixture
            .faults
            .unavailable
            .store(failure.is_none(), Ordering::SeqCst);
        let unit = fixture.unit("pre-submit-failure", "0.000001");
        let first = fixture.ask(&unit).await;
        assert_effect(&first, 503, "not_applied");
        assert_eq!(fixture.ask(&unit).await.body, first.body);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.faults.submissions.load(Ordering::SeqCst), 0);
        assert!(
            fixture.faults.read_failure.lock().unwrap().is_none(),
            "the requested read failed"
        );
        for ((bucket, window), previous) in buckets.iter().zip(before) {
            assert_eq!(
                fixture
                    .store
                    .ledger()
                    .get_usage(bucket, *window)
                    .await
                    .unwrap(),
                previous
            );
        }
        assert_eq!(
            fixture.store.ledger().list_metering(day).await.unwrap(),
            metered
        );
        assert!(fixture.journal.0.lock().unwrap().is_empty());
        fixture.assert_clear().await;
        fixture.faults.unavailable.store(false, Ordering::SeqCst);
        assert_effect(
            &fixture.ask(&fixture.unit("fresh-action", "0.000001")).await,
            200,
            "applied",
        );
        assert_eq!(
            fixture.count().await,
            Count::ONE.checked_add(Count::EPSILON).unwrap()
        );
    }
}

#[tokio::test]
async fn committed_correction_lost_reply_stays_unknown_and_replay_does_not_resubmit() {
    let fixture = Fixture::new().await;
    fixture.faults.lose_reply.store(true, Ordering::SeqCst);
    let unit = fixture.unit("lost-committed-reply", "0.000001");
    let first = fixture.ask(&unit).await;
    assert_eq!(first.status, 409);
    let receipt: serde_json::Value = serde_json::from_slice(&first.body).unwrap();
    assert_eq!(receipt["effect"], "unknown");
    assert_eq!(receipt["recovery"], "reconcile_ledger_recovery");
    assert_eq!(
        fixture.count().await,
        Count::ONE.checked_add(Count::EPSILON).unwrap()
    );
    assert_eq!(fixture.faults.submissions.load(Ordering::SeqCst), 1);
    assert!(!fixture.journal.0.lock().unwrap().is_empty());
    let active = fixture.active.read().unwrap().clone();
    assert!(!active.recovery().list(None, 10).await.unwrap().is_empty());
    assert_eq!(fixture.ask(&unit).await.body, first.body);
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.faults.submissions.load(Ordering::SeqCst), 1);

    // A new action must reconcile existing custody before checking its own backend availability.
    // Losing that reconciliation reply is still unknown, even while backend reads are unavailable.
    fixture.faults.unavailable.store(true, Ordering::SeqCst);
    fixture.faults.lose_reply.store(true, Ordering::SeqCst);
    let blocked = fixture
        .ask(&fixture.unit("new-action-during-custody", "0.000001"))
        .await;
    let blocked_receipt: serde_json::Value = serde_json::from_slice(&blocked.body).unwrap();
    assert_eq!(blocked.status, 409);
    assert_eq!(blocked_receipt["effect"], "unknown");
    assert_eq!(fixture.faults.submissions.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture.count().await,
        Count::ONE.checked_add(Count::EPSILON).unwrap()
    );
}
