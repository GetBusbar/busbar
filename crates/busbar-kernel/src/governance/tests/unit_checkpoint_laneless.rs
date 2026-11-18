// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! UPG-H2: a unit that ends in a pool/kernel 503 before any member binds its lane is
//! checkpointed with `lane: ""` and no counts. That checkpoint must not leave an unnamed-lane
//! model row in any budget cell: such a row prices as `LaneUnpriced` and poisons the usage
//! read, `/metrics` and admission for the whole bucket (the key and every group in its chain).

use super::*;
use crate::governance::recovery::{tests::Journal, RecoveryKind};
use crate::governance::unit_checkpoint::{UnitCheckpoint, UnitCheckpointSink, UnitTarget};
use busbar_contract::records::{ModelTokens, UsageLedger};

const MODEL: &str = "m";

#[derive(Default)]
struct MemoryCheckpoint(std::sync::Mutex<Vec<UnitCheckpoint>>);

#[async_trait::async_trait]
impl UnitCheckpointSink for MemoryCheckpoint {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        snapshot.validate()?;
        let mut held = self.0.lock().unwrap();
        held.retain(|kept| kept.id != snapshot.id);
        held.push(snapshot.clone());
        Ok(())
    }
    async fn remove(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.0.lock().unwrap().retain(|kept| kept.id != snapshot.id);
        Ok(())
    }
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

/// Unnamed-lane model rows in a cell, including its unresolved correction branch.
fn laneless_rows(cell: &BudgetCell) -> usize {
    let own = cell.models.iter().filter(|m| m.model.is_empty()).count();
    own + cell
        .correction
        .as_ref()
        .map_or(0, |branch| laneless_rows(&branch.accepted))
}

fn grouped_cost() -> CostModel {
    model_with_card(
        &[(
            "g",
            group_cfg(
                None,
                true,
                vec![limit(LimitMetric::Budget, 1_000, Some(LimitWindow::Day))],
            ),
        )],
        0,
        &[(MODEL, 1.0, 1.0)],
    )
}

fn targets(cm: &CostModel, key: &VirtualKey, now: u64) -> Vec<UnitTarget> {
    cm.chain_for(key)
        .expect("the key's chain resolves")
        .iter()
        .map(|bucket| UnitTarget {
            bucket: bucket.bucket_id.to_string(),
            window: budget_window(bucket.window, now),
            group: bucket.group_name.map(str::to_string),
        })
        .collect()
}

/// The terminal checkpoint of a unit refused by the pool before any member was picked.
fn laneless_unit(cm: &CostModel, key: &VirtualKey, now: u64, id: u8) -> UnitCheckpoint {
    UnitCheckpoint {
        id: [id; 16],
        revision: 0,
        unit: u64::from(id),
        principal: key.id.clone(),
        group: key.group.clone().unwrap_or_default(),
        arrived: now,
        lane: String::new(),
        provider: None,
        era_at: era_now(),
        era_entry: None,
        units: BTreeMap::new(),
        targets: targets(cm, key, now),
        metered: false,
        ended: false,
        terminal: None,
        audit: None,
        measurement: None,
        unread: None,
        partitions: None,
    }
}

#[track_caller]
fn assert_no_laneless_rows(gov: &GovState, targets: &[UnitTarget], when: &str) {
    for target in targets {
        let map = gov.budget.read(&target.bucket);
        if let Some(cell) = map.get(target.bucket.as_str()) {
            assert_eq!(
                laneless_rows(cell),
                0,
                "{when}: bucket `{}` holds an unnamed-lane row",
                target.bucket
            );
        }
    }
}

#[track_caller]
fn assert_priced_at_zero(gov: &GovState, cm: &CostModel, key: &VirtualKey, now: u64, when: &str) {
    let states = gov.budget_state(cm, key, now);
    assert!(!states.is_empty(), "{when}: the chain has budget states");
    for state in states {
        assert_eq!(
            state.spend_micros_at_current_rate, 0,
            "{when}: bucket `{}` must price (no LaneUnpriced) at zero spend",
            state.bucket_id
        );
    }
}

async fn attach(gov: &GovState, journal: &Arc<Journal>, sink: &Arc<MemoryCheckpoint>) {
    gov.attach_recovery_sink(journal.clone()).await.unwrap();
    gov.attach_unit_checkpoint_sink(sink.clone()).await.unwrap();
    assert!(gov.unit_checkpoints_enabled());
}

#[tokio::test]
async fn a_laneless_failed_unit_leaves_no_unnamed_lane_row_and_the_group_keeps_serving() {
    let store = crate::real_store::core().await;
    let journal = Arc::new(Journal::default());
    let sink = Arc::new(MemoryCheckpoint::default());
    let cm = grouped_cost();
    let first_key = key("vk_laneless_first", Some("g"));
    let second_key = key("vk_laneless_second", Some("g"));
    store.identity().put_key(&first_key).await.unwrap();
    store.identity().put_key(&second_key).await.unwrap();
    let now = crate::store::now();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    attach(&gov, &journal, &sink).await;

    let grant = gov
        .try_admit(&cm, &first_key, "", now)
        .expect("nothing spent yet");
    let unit = laneless_unit(&cm, &first_key, now, 0x42);
    let targets = unit.targets.clone();
    assert_eq!(
        targets.len(),
        2,
        "the key bucket and the group's day bucket"
    );

    // (a) the live terminal checkpoint.
    assert!(gov.finish_unit_checkpoint(unit.clone()));
    assert_no_laneless_rows(&gov, &targets, "after the terminal checkpoint");
    for target in &targets {
        let map = gov.budget.read(&target.bucket);
        let cell = map
            .get(target.bucket.as_str())
            .expect("the admission opened the cell");
        assert_eq!(cell.requests, 1, "the failed request is still counted");
    }
    assert_priced_at_zero(&gov, &cm, &first_key, now, "after the terminal checkpoint");
    let usage = gov
        .derived_bucket_usage_async(&cm, &first_key.id, WINDOW_TOTAL, true, now)
        .await
        .expect("the key's usage read prices");
    assert_eq!((usage.requests, usage.spend_cents), (1, 0));
    drop(grant);
    gov.try_admit(&cm, &second_key, "", now)
        .expect("another key in the group is not refused as exhausted");
    gov.try_admit(&cm, &first_key, "", now)
        .expect("the same key is not refused as exhausted");

    // (b) the recovery custody built from the same snapshot carries no usage row.
    let events = gov.unit_terminal_events(&unit).unwrap();
    assert!(
        events.iter().all(|event| event.kind != RecoveryKind::Usage),
        "a count-free unit hands no usage row to recovery custody"
    );
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(sink.replay().await.unwrap().is_empty());
    assert_no_laneless_rows(&gov, &targets, "after the checkpoint flush");
    gov.flush_budgets().await;
    drop(gov);

    // (c) a restart reloads every cell from the same Store.
    let restarted = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    attach(&restarted, &journal, &sink).await;
    restarted.hydrate_budgets_async(&cm, now).await.unwrap();
    assert_no_laneless_rows(&restarted, &targets, "after reload");
    assert_priced_at_zero(&restarted, &cm, &first_key, now, "after reload");
    restarted
        .try_admit(&cm, &second_key, "", now)
        .expect("the reloaded group admits");
}

#[tokio::test]
async fn a_correction_cut_and_its_custody_restore_leave_no_unnamed_lane_row() {
    let store = crate::real_store::core().await;
    let journal = Arc::new(Journal::default());
    let sink = Arc::new(MemoryCheckpoint::default());
    let cm = grouped_cost();
    let key = key("vk_laneless_correction", Some("g"));
    store.identity().put_key(&key).await.unwrap();
    let now = crate::store::now();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    attach(&gov, &journal, &sink).await;

    let served = gov.try_admit(&cm, &key, "", now).unwrap();
    gov.record_usage(&cm, &key, "", MODEL, &toks(100, 0), now);
    metered(&gov, &key.id, MODEL, 100, now).await;
    drop(served);
    let failed = gov.try_admit(&cm, &key, "", now).unwrap();
    let unit = laneless_unit(&cm, &key, now, 0x43);
    let targets = unit.targets.clone();
    assert!(gov.finish_unit_checkpoint(unit));
    drop(failed);
    gov.flush_unit_checkpoints().await.unwrap();
    assert_no_laneless_rows(&gov, &targets, "before the correction");

    // (d) the correction cut, left in durable custody by a lost recovery acknowledgement.
    journal
        .fail_after_write
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), -60)]);
    let adjustment = crate::governance::Adjustment {
        key_id: &key.id,
        pool: "",
        model: MODEL,
        entry_era: era_now(),
        entry_id: None,
        card_epoch_ms: now * 1_000,
        delta: &delta,
        now,
    };
    let _ = gov.adjust_usage_async(&cm, &adjustment).await;
    assert_no_laneless_rows(&gov, &targets, "after the correction cut");
    drop(gov);
    journal
        .fail_after_write
        .store(false, std::sync::atomic::Ordering::SeqCst);

    let restarted = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    attach(&restarted, &journal, &sink).await;
    let _ = restarted.hydrate_budgets_async(&cm, now).await;
    assert_no_laneless_rows(&restarted, &targets, "after the custody restore");
}

#[tokio::test]
async fn a_store_poisoned_by_an_unnamed_lane_row_heals_on_load() {
    let store = crate::real_store::core().await;
    let cm = grouped_cost();
    let key = key("vk_laneless_poisoned", Some("g"));
    store.identity().put_key(&key).await.unwrap();
    let now = crate::store::now();
    let targets = targets(&cm, &key, now);
    for target in &targets {
        store
            .ledger()
            .put_usage(
                &target.bucket,
                target.window,
                &UsageLedger {
                    requests: 1,
                    billable_requests: 0,
                    models: vec![ModelTokens {
                        scale: 0,
                        model: String::new(),
                        usage_units: BTreeMap::new(),
                    }],
                },
            )
            .await
            .unwrap();
    }
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    gov.hydrate_budgets_async(&cm, now)
        .await
        .expect("a count-free unnamed-lane row owes nothing and loads");
    assert_no_laneless_rows(&gov, &targets, "after loading the poisoned Store");
    assert_priced_at_zero(&gov, &cm, &key, now, "after loading the poisoned Store");
    gov.try_admit(&cm, &key, "", now)
        .expect("the healed group admits");
}

/// UPG-H9 (`cooldown__trip_then_serve`): the trip (pool 503) and the in-cooldown breaker
/// refusal (pool 503, no pick) are two lane-less units in a row; the request after the
/// cooldown is served on a named lane. Neither refusal may make the bucket refuse the next
/// admission as exhausted, and only the served unit is billed.
#[tokio::test]
async fn laneless_trip_then_refusal_then_serve_keeps_bucket_admissible() {
    let store = crate::real_store::core().await;
    let journal = Arc::new(Journal::default());
    let sink = Arc::new(MemoryCheckpoint::default());
    let cm = grouped_cost();
    let key = key("vk_laneless_trip_then_serve", Some("g"));
    store.identity().put_key(&key).await.unwrap();
    let now = crate::store::now();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    attach(&gov, &journal, &sink).await;

    // (a) the trip: admitted, refused by the pool before any member binds its lane.
    let trip = gov
        .try_admit(&cm, &key, "", now)
        .expect("nothing spent yet");
    let unit = laneless_unit(&cm, &key, now, 0x51);
    let targets = unit.targets.clone();
    assert_eq!(
        targets.len(),
        2,
        "the key bucket and the group's day bucket"
    );
    assert!(gov.finish_unit_checkpoint(unit));
    drop(trip);
    assert_no_laneless_rows(&gov, &targets, "after the trip");

    // (b) the in-cooldown request: admitted, then refused by the breaker-open pool.
    let refused = gov
        .try_admit(&cm, &key, "", now)
        .expect("the request inside the cooldown is not refused as exhausted");
    assert!(gov.finish_unit_checkpoint(laneless_unit(&cm, &key, now, 0x52)));
    drop(refused);
    assert_no_laneless_rows(&gov, &targets, "after the in-cooldown refusal");

    // (c) past the cooldown: admitted and served on the named lane.
    let served = gov
        .try_admit(&cm, &key, "", now)
        .expect("the request past the cooldown is not refused as exhausted");
    gov.record_usage(&cm, &key, "", MODEL, &toks(100, 50), now);
    drop(served);
    gov.flush_unit_checkpoints().await.unwrap();

    assert_no_laneless_rows(&gov, &targets, "after the served request");
    for target in &targets {
        let map = gov.budget.read(&target.bucket);
        let cell = map
            .get(target.bucket.as_str())
            .expect("the admissions opened the cell");
        assert_eq!(
            cell.requests, 3,
            "bucket `{}`: both refusals and the served request are counted",
            target.bucket
        );
    }
    let states = gov.budget_state(&cm, &key, now);
    assert_eq!(states.len(), 2, "the key and the group are priced");
    for state in states {
        assert_eq!(
            state.spend_micros_at_current_rate, 150,
            "bucket `{}` prices (no LaneUnpriced) at the served unit's spend only",
            state.bucket_id
        );
    }
}

/// WHO: the settlement flusher's pass over four terminal units, each with one metering
/// operation to settle.
/// DOES: (SHUTDOWN-HANG F3.3, 8.3) the pass keeps its recovery events phase by phase: every
/// Intent in one keep (T), every Applied in one (K1), every Settled in one (K2). No event is
/// kept outside its phase's batch, and every unit is settled and removed.
/// WHY: one keep per operation per state made a drain cost three store round trips per
/// operation, so settlement at shutdown was bounded by store latency (SHUTDOWN-HANG 1.7).
#[tokio::test]
async fn a_flush_pass_keeps_each_recovery_phase_in_one_batch() {
    let store = crate::real_store::core().await;
    let journal = Arc::new(Journal::default());
    let sink = Arc::new(MemoryCheckpoint::default());
    let cm = grouped_cost();
    let key = key("vk_lockstep_phases", Some("g"));
    store.identity().put_key(&key).await.unwrap();
    let now = crate::store::now();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    attach(&gov, &journal, &sink).await;
    for id in 0x61..=0x64u8 {
        let grant = gov.try_admit(&cm, &key, "", now).expect("admitted");
        let mut unit = laneless_unit(&cm, &key, now, id);
        unit.metered = true;
        unit.provider = Some("lockstep".into());
        assert!(gov.finish_unit_checkpoint(unit));
        drop(grant);
    }
    gov.flush_unit_checkpoints().await.unwrap();
    assert!(
        sink.replay().await.unwrap().is_empty(),
        "every unit is settled and removed"
    );
    assert_eq!(
        journal.batches.lock().unwrap().clone(),
        vec![4, 4, 4],
        "T, K1 and K2: one keep of four events each"
    );
    assert_eq!(
        journal.persists.load(std::sync::atomic::Ordering::Relaxed),
        12,
        "no event is kept outside its phase's batch"
    );
}

/// Signs unit checkpoints and confirms every audit line (the line is not under test here).
struct Signer(busbar_kernel_audit::AuditSigningKey);
#[async_trait::async_trait]
impl crate::governance::unit_checkpoint_store::UnitCheckpointAudit for Signer {
    fn keys(&self) -> busbar_kernel_audit::AuditKeySet {
        let mut keys = busbar_kernel_audit::AuditKeySet::new();
        keys.insert(
            busbar_kernel_audit::AuditVerifyingKey::from_hex(&self.0.public_key_hex()).unwrap(),
        );
        keys
    }
    async fn sign_checkpoints(&self, bodies: &[&[u8]]) -> RecordStoreResult<Vec<Vec<u8>>> {
        Ok(bodies
            .iter()
            .map(|body| self.0.sign_checkpoint_body(body))
            .collect())
    }
    async fn confirm(
        &self,
        _: &UnitCheckpoint,
        _: Option<crate::persistence::journal::runtime::Carried>,
    ) -> RecordStoreResult<()> {
        Ok(())
    }
    async fn recover(&self, _: &UnitCheckpoint) -> RecordStoreResult<()> {
        Ok(())
    }
}

/// WHO: the settlement flusher draining one pass of finished units with no handoffs, over the
/// store-backed recovery and unit checkpoint sinks, with no concurrent appender.
/// DOES: (SHUTDOWN-HANG F3.3, 8.3) the whole pass holds the node journal's lane exactly nine
/// times, whatever the batch size: P 2 (append, select), T 2, K1 2, K2 2, R 1 (delete); V, A and
/// every custody confirmation are lane-free (no fallback).
/// WHY: per-item lane holds capped settlement at about one item per store round trip and queued
/// every request-path append behind the flusher.
#[tokio::test]
async fn a_flush_pass_holds_the_journal_lane_nine_times() {
    let store = crate::real_store::core().await;
    let cm = grouped_cost();
    let key = key("vk_lane_holds", Some("g"));
    store.identity().put_key(&key).await.unwrap();
    let now = crate::store::now();
    let journal = crate::persistence::journal::runtime::RuntimeJournal::open(
        store.core(),
        7,
        crate::persistence::journal::runtime::BufferBudget {
            records: 1024,
            bytes: 4 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    gov.attach_recovery_sink(Arc::new(
        crate::governance::persistence::recovery::StoreRecovery::new(
            journal.clone(),
            crate::teller::Kernel::new().durability_token(),
        )
        .unwrap(),
    ))
    .await
    .unwrap();
    assert_eq!(journal.lane_fallbacks(), 0, "nothing has confirmed yet");
    let evidence = Arc::new(
        crate::governance::unit_checkpoint_store::UnitCheckpointEvidence::new(
            journal.clone(),
            crate::teller::Kernel::new().durability_token(),
        ),
    );
    gov.attach_unit_checkpoint_sink(Arc::new(
        crate::governance::unit_checkpoint_store::StoreUnitCheckpoints::new(
            evidence,
            Arc::new(Signer(busbar_kernel_audit::AuditSigningKey::from_seed(
                &[0x39; 32],
            ))),
        ),
    ))
    .await
    .unwrap();
    assert!(gov.unit_checkpoints_enabled());
    // The replay confirm at attach runs on a journal nobody has claimed yet: 6426a6a085 decides
    // it under the driver, on purpose, exactly once.
    let attached = journal.lane_fallbacks();
    assert_eq!(
        attached, 1,
        "one lane fallback at attach, for the unclaimed journal"
    );
    for id in 0x71..=0x74u8 {
        let grant = gov.try_admit(&cm, &key, "", now).expect("admitted");
        let mut unit = laneless_unit(&cm, &key, now, id);
        unit.metered = true;
        unit.provider = Some("lane-holds".into());
        unit.audit = Some(b"{}".to_vec().into());
        assert!(gov.finish_unit_checkpoint(unit));
        drop(grant);
    }
    let before = journal.lane_holds();
    gov.flush_unit_checkpoints().await.unwrap();
    assert_eq!(
        journal.lane_holds() - before,
        9,
        "one pass: P 2, T 2, K1 2, K2 2, R 1"
    );
    assert_eq!(
        journal.lane_fallbacks() - attached,
        0,
        "no confirmation in the pass took the lane"
    );
}
