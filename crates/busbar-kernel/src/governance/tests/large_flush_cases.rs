// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::store::OpId;
use std::collections::VecDeque;

const MODEL: &str = "m";
const HISTORICAL_ERA: u64 = 42;
const LARGE_INPUT: u64 = i64::MAX as u64 + 100;
const CONCURRENT_INPUT: u64 = 7;
const NEXT_INPUT: u64 = 11;
const GROUP_BUCKET: &str = "group:g@minute";

type Batch = (OpId, Vec<(String, u64, UsageDelta)>);
#[derive(Clone, Copy)]
enum Reply {
    Confirm,
    FailBefore,
    LoseAfter,
    CancelAfter,
}
struct ChunkStore {
    inner: Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    legacy: bool,
    replies: std::sync::Mutex<VecDeque<Reply>>,
    batches: std::sync::Mutex<Vec<Batch>>,
    before_batch: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    before_delete: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl Default for ChunkStore {
    fn default() -> Self {
        Self {
            inner: crate::real_store::store(),
            legacy: false,
            replies: Default::default(),
            batches: Default::default(),
            before_batch: Default::default(),
            before_delete: Default::default(),
        }
    }
}
impl RecordStore for ChunkStore {
    fn supports_usage_batch_deduped(&self) -> bool {
        !self.legacy
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
        let hook = self.before_delete.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        self.inner.delete_key(id)
    }
    fn get_usage(&self, id: &str, window: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(id, window)
    }
    fn put_usage(&self, id: &str, window: u64, row: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(id, window, row)
    }
    fn add_usage(&self, id: &str, window: u64, delta: &UsageDelta) -> RecordStoreResult<()> {
        self.add_usage_batch_deduped(crate::door::op_id(), &[(id, window, delta.clone())])
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, day: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(day)
    }
    fn supports_usage_correction(&self) -> bool {
        true
    }
    fn apply_usage_correction(
        &self,
        request: &busbar_contract::records::correction::Request,
    ) -> RecordStoreResult<busbar_contract::records::correction::Decision> {
        self.inner.apply_usage_correction(request)
    }
    fn add_usage_batch_deduped(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> RecordStoreResult<()> {
        self.batches.lock().unwrap().push((
            op,
            cells
                .iter()
                .map(|(bucket, window, delta)| (bucket.to_string(), *window, delta.clone()))
                .collect(),
        ));
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(Reply::Confirm);
        let hook = self.before_batch.lock().unwrap().take();
        if let Some(hook) = hook {
            hook();
        }
        if matches!(reply, Reply::FailBefore) {
            return Err(RecordStoreError("planted pre-commit chunk failure".into()));
        }
        self.inner.add_usage_batch_deduped(op, cells)?;
        match reply {
            Reply::LoseAfter => Err(RecordStoreError(
                "planted lost chunk acknowledgement".into(),
            )),
            Reply::CancelAfter => panic!("planted caller cancellation after chunk commit"),
            Reply::Confirm | Reply::FailBefore => Ok(()),
        }
    }
}
fn input(store: &dyn RecordStore, bucket: &str, window: u64) -> u64 {
    store
        .get_usage(bucket, window)
        .unwrap()
        .models
        .iter()
        .filter(|row| row.model == MODEL)
        .map(|row| {
            row.usage_units
                .get(busbar_contract::records::UNIT_INPUT)
                .copied()
                .unwrap_or(0)
        })
        .sum()
}
fn accrue_dated(gov: &GovState, key: &VirtualKey, count: u64, now: u64) {
    let window = super::super::budget_window(super::super::WINDOW_TOTAL, now);
    let mut cells = gov.budget.write(&key.id);
    let cell = cells
        .entry(key.id.clone())
        .or_insert_with(|| BudgetCell::fresh(window));
    cell.accrue(MODEL, HISTORICAL_ERA, &toks(count, 0));
    cell.dirty = true;
    cell.last_touch = now;
}
fn setup(id: &str) -> (Arc<ChunkStore>, GovState, VirtualKey, u64) {
    let store = Arc::new(ChunkStore::default());
    let key = key(id, None);
    store.put_key(&key).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    let now = crate::store::now();
    (store, gov, key, now)
}

fn dated_input(store: &dyn RecordStore, bucket: &str, window: u64) -> u64 {
    let dated_model = format!("{HISTORICAL_ERA}{}{}", super::super::ERA_MODEL_SEP, MODEL);
    store
        .get_usage(&super::super::era_bucket(bucket), window)
        .unwrap()
        .models
        .iter()
        .find(|row| row.model == dated_model)
        .and_then(|row| row.usage_units.get(busbar_contract::records::UNIT_INPUT))
        .copied()
        .unwrap_or(0)
}

#[test]
fn ordinary_small_unknown_commit_keeps_paired_rows_and_later_accrual_exact() {
    let (store, gov, key, now) = setup("vk_small_unknown_flush");
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::LoseAfter);
    assert_eq!(gov.flush_budgets(), 0);
    assert_eq!(input(store.as_ref(), &key.id, 0), CONCURRENT_INPUT);
    assert_eq!(
        dated_input(store.as_ref(), &key.id, 0),
        CONCURRENT_INPUT,
        "plain and historical rows share one atomic application"
    );
    accrue_dated(&gov, &key, NEXT_INPUT, now);
    gov.flush_budgets();
    assert_eq!(
        input(store.as_ref(), &key.id, 0),
        CONCURRENT_INPUT + NEXT_INPUT
    );
    assert_eq!(
        dated_input(store.as_ref(), &key.id, 0),
        CONCURRENT_INPUT + NEXT_INPUT
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(
        batches[0], batches[1],
        "unknown operation keeps its immutable body"
    );
    assert_ne!(
        batches[1].0, batches[2].0,
        "later accrual has a separate identity"
    );
}

#[test]
fn raw_entry_identity_survives_unknown_budget_flush_and_later_same_timestamp_counts() {
    const OLD_ID_HEX: &str = "010101010101010101010101";
    const NEW_ID_HEX: &str = "020202020202020202020202";
    let old = RawRateEra::entry(0, EntryId::parse_hex(OLD_ID_HEX).unwrap());
    let new = RawRateEra::entry(0, EntryId::parse_hex(NEW_ID_HEX).unwrap());
    for reply in [Reply::LoseAfter, Reply::CancelAfter] {
        let (store, gov, key, now) = setup("vk_exact_raw_unknown_flush");
        let cost = model(&[]);
        gov.record_usage_served_in_era(
            &cost,
            &key,
            "",
            MODEL,
            None,
            &toks(CONCURRENT_INPUT, 0),
            now,
            old,
        );
        store.replies.lock().unwrap().push_back(reply);
        if matches!(reply, Reply::CancelAfter) {
            assert!(
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gov.flush_budgets()))
                    .is_err()
            );
        } else {
            assert_eq!(gov.flush_budgets(), 0);
        }
        gov.record_usage_served_in_era(
            &cost,
            &key,
            "",
            MODEL,
            None,
            &toks(NEXT_INPUT, 0),
            now,
            new,
        );
        gov.flush_budgets_final();
        assert_eq!(
            input(store.as_ref(), &key.id, 0),
            CONCURRENT_INPUT + NEXT_INPUT
        );
        let dated = store
            .get_usage(&super::super::era_bucket(&key.id), 0)
            .unwrap();
        for (era, expected) in [(old, CONCURRENT_INPUT), (new, NEXT_INPUT)] {
            let name = super::super::era_model(era, MODEL);
            let segment = dated.models.iter().find(|row| row.model == name).unwrap();
            assert_eq!(
                segment
                    .usage_units
                    .get(busbar_contract::records::UNIT_INPUT),
                Some(&expected)
            );
        }
        assert_eq!(
            dated.models.len(),
            2,
            "opening identities are separately persisted"
        );
        let batches = store.batches.lock().unwrap();
        assert_eq!(
            batches[0], batches[1],
            "the uncertain packet never adopts the newer identity"
        );
        assert!(batches[0]
            .1
            .iter()
            .flat_map(|(_, _, delta)| &delta.models)
            .all(|row| row.model != super::super::era_model(new, MODEL)));
    }
}

#[test]
fn ordinary_small_plain_only_unknown_commit_replays_once() {
    let (store, gov, key, now) = setup("vk_small_plain_unknown_flush");
    {
        let mut cells = gov.budget.write(&key.id);
        let cell = cells
            .entry(key.id.clone())
            .or_insert_with(|| BudgetCell::fresh(0));
        cell.accrue(MODEL, 0, &toks(CONCURRENT_INPUT, 0));
        cell.dirty = true;
        cell.last_touch = now;
    }
    store.replies.lock().unwrap().push_back(Reply::LoseAfter);
    assert_eq!(gov.flush_budgets(), 0);
    gov.flush_budgets();
    assert_eq!(input(store.as_ref(), &key.id, 0), CONCURRENT_INPUT);
    assert_eq!(dated_input(store.as_ref(), &key.id, 0), 0);
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
    assert_eq!(batches[0].1.len(), 1, "zero dated body is omitted");
}

#[test]
fn ordinary_small_unwind_after_commit_keeps_custody_until_next_tick() {
    let (store, gov, key, now) = setup("vk_small_cancelled_flush");
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::CancelAfter);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gov.flush_budgets())).is_err()
    );
    accrue_dated(&gov, &key, NEXT_INPUT, now);
    gov.flush_budgets();
    assert_eq!(
        input(store.as_ref(), &key.id, 0),
        CONCURRENT_INPUT + NEXT_INPUT
    );
    assert_eq!(
        dated_input(store.as_ref(), &key.id, 0),
        CONCURRENT_INPUT + NEXT_INPUT
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[test]
fn ordinary_small_zero_net_debt_does_not_enter_store() {
    let (store, gov, key, now) = setup("vk_small_zero_flush");
    accrue_dated(&gov, &key, 0, now);
    assert_eq!(gov.flush_budgets(), 0);
    assert!(store.batches.lock().unwrap().is_empty());
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[test]
fn ordinary_small_flush_preserves_explicit_legacy_store_support() {
    let store = Arc::new(ChunkStore {
        legacy: true,
        ..ChunkStore::default()
    });
    let key = key("vk_small_legacy_flush", None);
    store.put_key(&key).unwrap();
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue_dated(&gov, &key, CONCURRENT_INPUT, crate::store::now());
    assert_eq!(gov.flush_budgets(), 1);
    assert_eq!(input(store.as_ref(), &key.id, 0), CONCURRENT_INPUT);
    assert_eq!(dated_input(store.as_ref(), &key.id, 0), CONCURRENT_INPUT);
    let batches = store.batches.lock().unwrap();
    assert_eq!(
        batches.len(),
        2,
        "legacy ordinary API keeps its separate row calls"
    );
    assert_ne!(batches[0].0, batches[1].0);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[test]
fn key_deletion_reconciles_small_unknown_commit_before_purging_usage() {
    let (store, gov, key, now) = setup("vk_small_delete_unknown_flush");
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::LoseAfter);
    gov.flush_budgets();
    store.replies.lock().unwrap().push_back(Reply::FailBefore);
    assert!(gov.delete_key(&key.id).is_err());
    assert!(store
        .get_key(&key.id)
        .unwrap()
        .unwrap()
        .deleted_at
        .is_none());
    gov.delete_key(&key.id).unwrap();
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
    assert_eq!(batches[1], batches[2]);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    assert!(!gov.budget.read(&key.id).contains_key(&key.id));
}

#[test]
fn ordinary_large_positive_debt_flushes_all_chunks_with_historical_counts() {
    let (store, gov, key, now) = setup("vk_large_positive_chunks");
    accrue_dated(&gov, &key, u64::MAX, now);
    gov.flush_budgets();
    assert_eq!(input(store.as_ref(), &key.id, 0), u64::MAX);
    let era = store
        .get_usage(&super::super::era_bucket(&key.id), 0)
        .unwrap();
    let dated_model = format!("{HISTORICAL_ERA}{}{}", super::super::ERA_MODEL_SEP, MODEL);
    assert_eq!(
        era.models
            .iter()
            .find(|row| row.model == dated_model)
            .unwrap()
            .usage_units[busbar_contract::records::UNIT_INPUT],
        u64::MAX
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(
        batches.len(),
        3,
        "u64::MAX uses the signed wire range without a new counter limit"
    );
    assert!(batches.windows(2).all(|pair| pair[0].0 != pair[1].0));
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    drop(batches);
    assert_eq!(gov.flush_budgets(), 0);
}

#[test]
fn ordinary_large_negative_debt_uses_the_full_signed_range() {
    let (store, gov, key, now) = setup("vk_large_negative_chunks");
    accrue_dated(&gov, &key, u64::MAX, now);
    gov.flush_budgets();
    store.batches.lock().unwrap().clear();

    {
        let mut cells = gov.budget.write(&key.id);
        let cell = cells.get_mut(&key.id).unwrap();
        for model in &mut cell.models {
            model.cur.clear();
        }
        cell.dirty = true;
    }
    gov.flush_budgets();
    assert_eq!(input(store.as_ref(), &key.id, 0), 0);
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches.len(), 2);
    assert_eq!(
        batches[0].1[0].2.models[0].usage_units[busbar_contract::records::UNIT_INPUT],
        i64::MIN
    );
    assert_eq!(
        batches[1].1[0].2.models[0].usage_units[busbar_contract::records::UNIT_INPUT],
        -i64::MAX
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[test]
fn confirmed_chunk_is_not_repeated_when_a_later_chunk_fails() {
    let (store, gov, key, now) = setup("vk_large_partial_chunks");
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    store
        .replies
        .lock()
        .unwrap()
        .extend([Reply::Confirm, Reply::FailBefore]);
    gov.flush_budgets();
    assert_eq!(input(store.as_ref(), &key.id, 0), i64::MAX as u64);
    let first = store.batches.lock().unwrap().clone();
    assert_eq!(first.len(), 2);
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    gov.flush_budgets();
    assert_eq!(
        input(store.as_ref(), &key.id, 0),
        LARGE_INPUT + CONCURRENT_INPUT
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(
        batches[1], batches[2],
        "only the unresolved second chunk replays"
    );
    assert_ne!(batches[0].0, batches[2].0);
}

#[test]
fn lost_chunk_commit_reply_keeps_exact_identity_and_later_accrual() {
    let (store, gov, key, now) = setup("vk_large_unknown_chunks");
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::LoseAfter);
    gov.flush_budgets();
    assert_eq!(input(store.as_ref(), &key.id, 0), i64::MAX as u64);
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    assert!(gov.hydrate_budgets(&model(&[]), now).is_err());
    gov.flush_budgets();
    assert_eq!(
        input(store.as_ref(), &key.id, 0),
        LARGE_INPUT + CONCURRENT_INPUT
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(
        batches[0], batches[1],
        "a committed chunk is retried with the original body and id"
    );
    assert_ne!(batches[1].0, batches[2].0);
}

#[test]
fn cancellation_after_chunk_commit_retains_custody_without_stranding_other_windows() {
    let (store, gov, key, now) = setup("vk_large_cancelled_chunks");
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    let other = super::key("vk_small_after_chunk_cancellation", None);
    store.put_key(&other).unwrap();
    gov.record_usage(
        &model(&[]),
        &other,
        "",
        MODEL,
        &toks(CONCURRENT_INPUT, 0),
        now,
    );
    store.replies.lock().unwrap().push_back(Reply::CancelAfter);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gov.flush_budgets())).is_err()
    );
    gov.flush_budgets();
    assert_eq!(input(store.as_ref(), &key.id, 0), LARGE_INPUT);
    assert_eq!(input(store.as_ref(), &other.id, 0), CONCURRENT_INPUT);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
}

#[test]
fn in_flight_large_chunks_preserve_roll_refund_and_independent_window_correction() {
    in_flight_flush_preserves_roll_refund_and_independent_window_correction(LARGE_INPUT);
}

#[test]
fn in_flight_small_flush_preserves_roll_refund_and_independent_window_correction() {
    in_flight_flush_preserves_roll_refund_and_independent_window_correction(CONCURRENT_INPUT);
}

fn in_flight_flush_preserves_roll_refund_and_independent_window_correction(initial_input: u64) {
    let store = Arc::new(ChunkStore::default());
    let key = key("vk_large_window_overlap", Some("g"));
    store.put_key(&key).unwrap();
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let cm = minute_fee_model();
    let now = crate::governance::budget_window(
        super::super::WINDOW_MINUTE,
        crate::store::now().saturating_sub(120),
    );
    let next = super::super::window_end(super::super::WINDOW_MINUTE, now).unwrap();
    let charged = gov.try_admit(&cm, &key, "", now).unwrap();
    gov.record_usage(&cm, &key, "", MODEL, &toks(initial_input, 0), now);
    metered(&gov, &key.id, MODEL, initial_input, now);
    let independent = super::key("vk_other_correction_window", Some("g"));
    store.put_key(&independent).unwrap();
    metered(&gov, &independent.id, MODEL, 1, next);
    let (mutator, mutated_key) = (gov.clone(), key.clone());
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        let cm = minute_fee_model();
        mutator.record_usage(
            &cm,
            &mutated_key,
            "",
            MODEL,
            &toks(CONCURRENT_INPUT, 0),
            now,
        );
        mutator.refund_charge(charged.charge());
        mutator.try_admit(&cm, &mutated_key, "", next).unwrap();
        mutator.record_usage(&cm, &mutated_key, "", MODEL, &toks(NEXT_INPUT, 0), next);
        let epoch =
            |seconds| u64::try_from(std::time::Duration::from_secs(seconds).as_millis()).unwrap();
        let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), 1)]);
        assert!(
            mutator
                .adjust_usage(
                    &cm,
                    &super::super::Adjustment {
                        key_id: &mutated_key.id,
                        pool: "",
                        model: MODEL,
                        entry_era: era_now(),
                        entry_id: None,
                        card_epoch_ms: epoch(now),
                        delta: &delta,
                        now
                    }
                )
                .is_err(),
            "same target window stays owned by its flight"
        );
        mutator
            .adjust_usage(
                &cm,
                &super::super::Adjustment {
                    key_id: &independent.id,
                    pool: "",
                    model: MODEL,
                    entry_era: era_now(),
                    entry_id: None,
                    card_epoch_ms: epoch(next),
                    delta: &delta,
                    now: next,
                },
            )
            .unwrap()
            .unwrap();
    }));
    gov.flush_budgets();
    gov.flush_budgets();
    assert_eq!(
        input(store.as_ref(), GROUP_BUCKET, now),
        initial_input + CONCURRENT_INPUT
    );
    assert_eq!(input(store.as_ref(), GROUP_BUCKET, next), NEXT_INPUT + 1);
    assert_eq!(
        store
            .get_usage(GROUP_BUCKET, now)
            .unwrap()
            .billable_requests,
        0
    );
    assert_eq!(
        store
            .get_usage(GROUP_BUCKET, next)
            .unwrap()
            .billable_requests,
        1
    );
    assert_eq!(
        input(store.as_ref(), &key.id, 0),
        initial_input + CONCURRENT_INPUT + NEXT_INPUT
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[test]
fn key_deletion_settles_unknown_large_chunks_before_releasing_raw_custody() {
    let (store, gov, key, now) = setup("vk_large_delete_chunks");
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::FailBefore);
    gov.flush_budgets();
    store.replies.lock().unwrap().push_back(Reply::FailBefore);
    assert!(gov.delete_key(&key.id).is_err());
    assert!(store
        .get_key(&key.id)
        .unwrap()
        .unwrap()
        .deleted_at
        .is_none());
    assert_eq!(gov.budget_flushes.lock().unwrap().len(), 1);
    gov.delete_key(&key.id).unwrap();
    assert!(store
        .get_key(&key.id)
        .unwrap()
        .is_none_or(|row| row.deleted_at.is_some()));
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    assert!(!gov.budget.read(&key.id).contains_key(&key.id));
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
    assert_eq!(batches[1], batches[2]);
}

#[test]
fn accrual_between_capture_and_snapshot_gets_its_own_large_flight() {
    let (store, gov, key, now) = setup("vk_large_capture_trigger");
    let gov = Arc::new(gov);
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    let later = super::key("vk_grows_after_capture", None);
    store.put_key(&later).unwrap();
    gov.record_usage(
        &model(&[]),
        &later,
        "",
        MODEL,
        &toks(CONCURRENT_INPUT, 0),
        now,
    );
    let (writer, later_key) = (gov.clone(), later.clone());
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        writer.record_usage(
            &model(&[]),
            &later_key,
            "",
            MODEL,
            &toks(LARGE_INPUT, 0),
            now,
        );
    }));
    gov.flush_budgets();
    assert_eq!(input(store.as_ref(), &key.id, 0), LARGE_INPUT);
    assert_eq!(
        input(store.as_ref(), &later.id, 0),
        LARGE_INPUT + CONCURRENT_INPUT
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[test]
fn concurrent_flush_driver_cannot_lend_the_same_chunk_twice() {
    let (store, gov, key, now) = setup("vk_large_concurrent_drivers");
    let gov = Arc::new(gov);
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    let (second, observed) = (gov.clone(), store.clone());
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(second.flush_budgets(), 0);
        assert_eq!(observed.batches.lock().unwrap().len(), 1);
    }));
    gov.flush_budgets();
    assert_eq!(input(store.as_ref(), &key.id, 0), LARGE_INPUT);
    assert_eq!(store.batches.lock().unwrap().len(), 2);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

fn final_flush_joins_active_ordinary_runner(reply: Reply, legacy: bool) {
    const EARLY_RETURN_OBSERVATION: std::time::Duration = std::time::Duration::from_secs(1);
    let store = Arc::new(ChunkStore {
        legacy,
        ..ChunkStore::default()
    });
    let key = key("vk_final_active_ordinary_flush", None);
    store.put_key(&key).unwrap();
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    let now = crate::store::now();
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    store.replies.lock().unwrap().push_back(reply);
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    }));
    let periodic_gov = gov.clone();
    let periodic = std::thread::spawn(move || periodic_gov.flush_budgets());
    entered_rx.recv().unwrap();
    accrue_dated(&gov, &key, NEXT_INPUT, now);
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let final_gov = gov.clone();
    let final_flush = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let flushed = final_gov.flush_budgets_final();
        finished_tx.send(flushed).unwrap();
    });
    started_rx.recv().unwrap();
    let early_result = finished_rx.recv_timeout(EARLY_RETURN_OBSERVATION);

    release_tx.send(()).unwrap();
    let periodic_result = periodic.join();
    final_flush.join().unwrap();
    assert!(
        matches!(
            early_result,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ),
        "final flush returned while the periodic store call still owned unsettled debt"
    );
    assert_eq!(
        periodic_result.is_err(),
        matches!(reply, Reply::CancelAfter)
    );
    assert_eq!(
        input(store.as_ref(), &key.id, 0),
        CONCURRENT_INPUT + NEXT_INPUT
    );
    assert_eq!(
        dated_input(store.as_ref(), &key.id, 0),
        CONCURRENT_INPUT + NEXT_INPUT
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    let batches = store.batches.lock().unwrap();
    if matches!(reply, Reply::LoseAfter | Reply::CancelAfter) {
        assert_eq!(
            batches[0], batches[1],
            "final owner reconciles the original operation"
        );
    }
}

#[test]
fn final_budget_flush_waits_for_active_runner_and_persists_later_accrual() {
    final_flush_joins_active_ordinary_runner(Reply::Confirm, false);
}

#[test]
fn final_budget_flush_waits_for_active_legacy_snapshots_and_persists_later_accrual() {
    final_flush_joins_active_ordinary_runner(Reply::Confirm, true);
}

#[test]
fn final_budget_flush_reconciles_unknown_active_runner_commit() {
    final_flush_joins_active_ordinary_runner(Reply::LoseAfter, false);
}

#[test]
fn final_budget_flush_recovers_custody_after_active_runner_unwind() {
    final_flush_joins_active_ordinary_runner(Reply::CancelAfter, false);
}

#[test]
fn final_budget_flush_same_thread_reentry_returns_without_lending_active_body() {
    let (store, gov, key, now) = setup("vk_final_reentrant_ordinary_flush");
    let gov = Arc::new(gov);
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    let (reentrant, observed) = (gov.clone(), store.clone());
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(reentrant.flush_budgets_final(), 0);
        assert_eq!(observed.batches.lock().unwrap().len(), 1);
    }));
    gov.flush_budgets_final();
    assert_eq!(input(store.as_ref(), &key.id, 0), CONCURRENT_INPUT);
    assert_eq!(dated_input(store.as_ref(), &key.id, 0), CONCURRENT_INPUT);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[test]
fn deletion_excludes_new_large_flight_capture_until_the_key_purge_finishes() {
    let (store, gov, key, now) = setup("vk_large_delete_capture_race");
    let gov = Arc::new(gov);
    let (writer, written_key, observed) = (gov.clone(), key.clone(), store.clone());
    *store.before_delete.lock().unwrap() = Some(Box::new(move || {
        accrue_dated(&writer, &written_key, LARGE_INPUT, now);
        assert_eq!(writer.flush_budgets(), 0);
        assert!(observed.batches.lock().unwrap().is_empty());
    }));
    gov.delete_key(&key.id).unwrap();
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    assert!(!gov.budget.read(&key.id).contains_key(&key.id));
    assert!(gov.deleting_budget_buckets.lock().unwrap().is_empty());
}
