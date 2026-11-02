// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const MODEL: &str = "ordinary-unknown-model";
const FIRST_INPUT: u64 = 7;
const LATER_INPUT: u64 = 11;

struct UnknownFlushStore {
    inner: MemoryStore,
    fail_after_commit: std::sync::atomic::AtomicBool,
    unwind: bool,
}
impl RecordStore for UnknownFlushStore {
    fn supports_usage_batch_deduped(&self) -> bool {
        true
    }
    fn add_usage_batch_deduped(
        &self,
        op: busbar_contract::abi::store::OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.inner.add_usage_batch_deduped(op, cells)?;
        self.after_commit()
    }
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket: &str, window: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(bucket, window)
    }
    fn put_usage(&self, bucket: &str, window: u64, row: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(bucket, window, row)
    }
    fn add_usage(&self, bucket: &str, window: u64, delta: &UsageDelta) -> RecordStoreResult<()> {
        self.inner.add_usage(bucket, window, delta)?;
        self.after_commit()
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, day: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(day)
    }
}
impl UnknownFlushStore {
    fn after_commit(&self) -> RecordStoreResult<()> {
        if self.fail_after_commit.swap(false, Ordering::SeqCst) {
            if self.unwind {
                panic!("planted unwind after ordinary usage commit");
            }
            return Err(RecordStoreError("planted lost ordinary usage reply".into()));
        }
        Ok(())
    }
}

fn accrue_plain(gov: &GovState, bucket: &str, count: u64) {
    let mut cells = gov.budget.write(bucket);
    let cell = cells
        .entry(bucket.to_string())
        .or_insert_with(|| BudgetCell::fresh(0));
    cell.accrue(MODEL, 0, &tt(count));
    cell.dirty = true;
    cell.last_touch = crate::store::now();
}

fn ordinary_unknown_result_retries_once(unwind: bool) {
    let store = Arc::new(UnknownFlushStore {
        inner: MemoryStore::new(),
        fail_after_commit: std::sync::atomic::AtomicBool::new(true),
        unwind,
    });
    let key = sample_key("vk_ordinary_unknown_commit", "ordinary-unknown-generation");
    store.put_key(&key).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue_plain(&gov, &key.id, FIRST_INPUT);
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gov.flush_budgets()));
    assert_eq!(first.is_err(), unwind);
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().tokens_for(MODEL),
        Some(FIRST_INPUT)
    );
    accrue_plain(&gov, &key.id, LATER_INPUT);
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().tokens_for(MODEL),
        Some(FIRST_INPUT + LATER_INPUT),
        "a committed ordinary flush must not be applied again when its reply was unknown"
    );
}

#[test]
fn ordinary_small_usage_unknown_reply_does_not_duplicate_committed_effect() {
    ordinary_unknown_result_retries_once(false);
}

#[test]
fn ordinary_small_usage_unwind_does_not_duplicate_committed_effect() {
    ordinary_unknown_result_retries_once(true);
}

#[derive(Default)]
struct RecoveryJournal(std::sync::Mutex<Vec<super::super::recovery::RecoveryEvent>>);
impl super::super::recovery::RecoverySink for RecoveryJournal {
    fn replay(
        &self,
    ) -> Result<Vec<super::super::recovery::RecoveryEvent>, super::super::recovery::RecoveryError>
    {
        Ok(self.0.lock().unwrap().clone())
    }
    fn persist(
        &self,
        event: &super::super::recovery::RecoveryEvent,
    ) -> Result<(), super::super::recovery::RecoveryError> {
        let mut events = self.0.lock().unwrap();
        if !events.contains(event) {
            events.push(event.clone());
        }
        Ok(())
    }
}

#[test]
fn ordinary_product_flush_quarantines_old_unknown_and_continues_fresh_positive_usage() {
    use super::super::recovery::{RecoveryResolution, RecoveryState, RecoveryVerdict};
    let store = Arc::new(UnknownFlushStore {
        inner: MemoryStore::new(),
        fail_after_commit: std::sync::atomic::AtomicBool::new(true),
        unwind: false,
    });
    let key = sample_key("vk_durable_unknown_commit", "durable-unknown-generation");
    store.put_key(&key).unwrap();
    let journal = Arc::new(RecoveryJournal::default());
    let original = GovState::new(store.clone(), None).unwrap();
    original.attach_recovery_sink(journal.clone()).unwrap();
    accrue_plain(&original, &key.id, FIRST_INPUT);
    original.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().tokens_for(MODEL),
        Some(FIRST_INPUT)
    );
    let intent = original.recovery().list(None, 10).unwrap().pop().unwrap();
    assert_eq!(intent.state, RecoveryState::Intent);
    drop(original);

    let gov = GovState::new(store.clone(), None).unwrap();
    gov.attach_recovery_sink(journal).unwrap();
    let cost = flat_cost(0);
    gov.hydrate_budgets(&cost, crate::store::now()).unwrap();
    let unknown = gov.recovery_event(intent.operation_id).unwrap();
    assert_eq!(unknown.state, RecoveryState::LandedUnknown);
    accrue_plain(&gov, &key.id, LATER_INPUT);
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().tokens_for(MODEL),
        Some(FIRST_INPUT + LATER_INPUT)
    );

    {
        let mut cells = gov.budget.write(&key.id);
        let cell = cells.get_mut(&key.id).unwrap();
        cell.mutate(|cell| {
            let units = &mut cell
                .models
                .iter_mut()
                .find(|model| &*model.model == MODEL)
                .unwrap()
                .cur;
            *units.get_mut("input").unwrap() -= FIRST_INPUT;
            cell.dirty = true;
        });
    }
    gov.flush_budgets();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().tokens_for(MODEL),
        Some(FIRST_INPUT + LATER_INPUT),
        "dependent negative remains quarantined while fresh positive has posted"
    );
    let selected = gov.recovery_event(intent.operation_id).unwrap();
    let resolution = RecoveryResolution {
        operation_id: intent.operation_id,
        body_fingerprint: intent.body_fingerprint,
        expected_revision: selected.revision,
        verdict: RecoveryVerdict::Landed,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "operator".into(),
        reason: "original backend receipt confirmed after sender retirement".into(),
    };
    let settled = gov.recovery().resolve(&cost, resolution.clone()).unwrap();
    assert_eq!(settled.state, RecoveryState::Settled);
    gov.recovery().resolve(&cost, resolution).unwrap();
    assert_eq!(
        store.get_usage(&key.id, 0).unwrap().tokens_for(MODEL),
        Some(LATER_INPUT)
    );
}
