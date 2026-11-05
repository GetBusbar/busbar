// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::{MeteringDelta, VirtualKey};
use busbar_contract::Count;
use busbar_kernel::cost::{CostModel, RawRateEra};
use busbar_kernel::governance::recovery::{RecoveryError, RecoveryEvent, RecoverySink};
use busbar_kernel::governance::{Adjustment, GovState};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, RwLock};

type RequestUnit = super::super::super::AdminRequest;
type Replay = super::super::super::bound::ReplayStore;

#[derive(Default)]
struct Journal(Mutex<Vec<RecoveryEvent>>);
impl RecoverySink for Journal {
    fn persist(&self, event: &RecoveryEvent) -> Result<(), RecoveryError> {
        let mut events = self.0.lock().unwrap();
        if !events.contains(event) {
            events.push(event.clone());
        }
        Ok(())
    }
    fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        Ok(self.0.lock().unwrap().clone())
    }
}

struct Fixture {
    store: Arc<dyn RecordStore>,
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
    fn new() -> Self {
        let store = crate::root::real_store::records();
        let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
        let journal = Arc::new(Journal::default());
        gov.attach_recovery_sink(journal.clone()).unwrap();
        let key = VirtualKey {
            id: "exact-staging-key".into(),
            generation_hash: "exact-staging-generation".into(),
            enabled: true,
            revision: 1,
            ..Default::default()
        };
        store.put_key(&key).unwrap();
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
        store
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
            .unwrap();
        let active = Arc::new(RwLock::new(gov));
        let calls = Arc::new(AtomicUsize::new(0));
        let adjuster: UsageAdjuster = {
            let active = active.clone();
            let cost = cost.clone();
            let calls = calls.clone();
            Arc::new(move |correction| {
                calls.fetch_add(1, Ordering::SeqCst);
                active
                    .read()
                    .unwrap()
                    .adjust_usage_exact_action(
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
                    .map(|result| result.map_err(Refused::Ledger))
                    .map_err(|error| error.to_string())
            })
        };
        let replay: Replay = {
            let store = store.clone();
            Arc::new(move || Some(store.clone()))
        };
        Self {
            store,
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
    fn ask(&self, unit: &RequestUnit) -> AdminAnswer {
        adjust_request(
            unit,
            &unit.body,
            busbar_contract::authz::Scope::Full,
            "actor",
            Some(&self.replay),
            &|_| true,
            &self.adjuster,
        )
        .unwrap()
    }
    fn count(&self) -> Count {
        let stored = self.store.get_usage("exact-staging-key", 0).unwrap();
        let lane = stored
            .models
            .iter()
            .find(|row| row.model == "lane")
            .unwrap();
        assert_eq!(lane.scale, 6);
        Count::from_stored(lane.usage_units["search_units"], lane.scale).unwrap()
    }
    fn restart(&self) {
        let restarted = Arc::new(GovState::new(self.store.clone(), None).unwrap());
        restarted
            .attach_recovery_sink(self.journal.clone())
            .unwrap();
        restarted.hydrate_budgets(&self.cost, self.now).unwrap();
        *self.active.write().unwrap() = restarted;
    }
    fn assert_clear(&self) {
        assert!(self
            .active
            .read()
            .unwrap()
            .recovery()
            .list(None, 10)
            .unwrap()
            .is_empty());
    }
}

fn assert_effect(answer: &AdminAnswer, status: u16, effect: &str) {
    assert_eq!(answer.status, status);
    let receipt: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
    assert_eq!(receipt["effect"], effect);
    assert_eq!(receipt["recovery"], "receipt");
}

#[test]
fn wide_count_applies_replays_restarts_and_restores_exactly() {
    for delta in ["9007199254740993.000001", "9223372036854.775808"] {
        let fixture = Fixture::new();
        let unit = fixture.unit("wide", delta);
        let first = fixture.ask(&unit);
        assert_effect(&first, 200, "applied");
        let expected = Count::ONE
            .checked_add(Count::parse(delta).unwrap())
            .unwrap();
        assert_eq!(fixture.count(), expected);
        fixture.restart();
        assert_eq!(fixture.ask(&unit).body, first.body);
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.count(), expected);
        assert_eq!(fixture.ask(&fixture.unit("wide", "0.000001")).status, 409);
        let inverse = fixture.unit("inverse", &format!("-{delta}"));
        assert_effect(&fixture.ask(&inverse), 200, "applied");
        assert_eq!(fixture.count(), Count::ONE);
        fixture.restart();
        assert_eq!(fixture.count(), Count::ONE);
        fixture.assert_clear();
    }
}

#[test]
fn signed_minimum_and_result_overflow_refuse_before_effect() {
    let fixture = Fixture::new();
    let day = busbar_kernel::governance::metering_bucket(fixture.now);
    let before = fixture.store.get_usage("exact-staging-key", 0).unwrap();
    let metered = fixture.store.list_metering(day).unwrap();
    for (action, delta) in [
        ("minimum", "-170141183460469231731687303715884.105728"),
        ("overflow", "170141183460469231731687303715884.105727"),
    ] {
        let unit = fixture.unit(action, delta);
        let first = fixture.ask(&unit);
        assert_effect(&first, 400, "not_applied");
        assert_eq!(fixture.ask(&unit).body, first.body);
        assert_eq!(
            fixture.store.get_usage("exact-staging-key", 0).unwrap(),
            before
        );
        assert_eq!(fixture.store.list_metering(day).unwrap(), metered);
        assert!(fixture.journal.0.lock().unwrap().is_empty());
        fixture.assert_clear();
    }
}

#[test]
fn exhausted_gross_adjustment_counter_is_known_not_applied_without_reservation() {
    let fixture = Fixture::new();
    // Raw total reaches the exact Count maximum and returns to one. Both immutable gross
    // adjustment counters retain MAX-ONE, so another two-unit credit cannot be represented.
    let magnitude = "170141183460469231731687303715883.105727";
    assert_effect(
        &fixture.ask(&fixture.unit("maximum", magnitude)),
        200,
        "applied",
    );
    assert_eq!(fixture.count(), busbar_contract::count::MAX);
    assert_effect(
        &fixture.ask(&fixture.unit("restore", &format!("-{magnitude}"))),
        200,
        "applied",
    );
    assert_eq!(fixture.count(), Count::ONE);
    let events_before = fixture.journal.0.lock().unwrap().clone();
    let bounded = fixture.unit("exhausted-gross", "2");
    let first = fixture.ask(&bounded);
    assert_effect(&first, 503, "not_applied");
    assert_eq!(fixture.ask(&bounded).body, first.body);
    assert_eq!(fixture.count(), Count::ONE);
    assert_eq!(*fixture.journal.0.lock().unwrap(), events_before);
    fixture.assert_clear();
    // A representable new action still works; no private candidate became a reservation.
    assert_effect(
        &fixture.ask(&fixture.unit("small", "0.000001")),
        200,
        "applied",
    );
    assert_eq!(
        fixture.count(),
        Count::ONE.checked_add(Count::EPSILON).unwrap()
    );
}
