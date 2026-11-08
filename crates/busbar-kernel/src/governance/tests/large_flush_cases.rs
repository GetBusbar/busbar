// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::records::OpId;
use futures::FutureExt;
use std::collections::VecDeque;

const MODEL: &str = "m";
const HISTORICAL_ERA: u64 = 42;
const LARGE_INPUT: u64 = i64::MAX as u64 / 1_000_000 + 100;
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
#[derive(Default)]
struct ChunkFaults {
    replies: std::sync::Mutex<VecDeque<Reply>>,
    batches: std::sync::Mutex<Vec<Batch>>,
    before_batch: std::sync::Mutex<Option<native_ledger_fixture::Hook>>,
    before_delete: std::sync::Mutex<Option<native_ledger_fixture::Hook>>,
}
struct ChunkStore {
    inner: Arc<CoreStore>,
    native: Arc<CoreStore>,
    faults: Arc<ChunkFaults>,
}
impl std::ops::Deref for ChunkStore {
    type Target = ChunkFaults;
    fn deref(&self) -> &ChunkFaults {
        &self.faults
    }
}
impl CoreHandle for Arc<ChunkStore> {
    fn core(&self) -> Arc<CoreStore> {
        self.native.clone()
    }
}
impl ChunkStore {
    async fn new() -> Self {
        let backend = crate::real_store::native_backend().await;
        let inner = crate::real_store::core_over(backend.clone()).await;
        // Keep the independent writer admitted when the faulted writer opens.
        let initial = inner.first_start().unwrap();
        assert_eq!(
            initial.freeze(Vec::new()).await.unwrap(),
            crate::persistence::startup::Progress::Advanced
        );
        assert_eq!(
            initial.publish().await.unwrap(),
            crate::persistence::startup::Progress::Advanced
        );
        let faults = Arc::new(ChunkFaults::default());
        let native = crate::real_store::core_over(Arc::new(ChunkBackend {
            inner: backend,
            faults: faults.clone(),
        }))
        .await;
        Self {
            inner,
            native,
            faults,
        }
    }
    fn ledger(&self) -> crate::governance::persistence::ledger::Ledger<'_> {
        self.native.ledger()
    }
    fn identity(&self) -> crate::governance::persistence::identity::Identity<'_> {
        self.native.identity()
    }
}
struct ChunkBackend {
    inner: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    faults: Arc<ChunkFaults>,
}
fn observed_delta(change: &busbar_contract::records::correction::UsageChange) -> UsageDelta {
    let mut before = change.expected.clone();
    let mut after = change.replacement.clone();
    before.normalize_scale6().unwrap();
    after.normalize_scale6().unwrap();
    let mut models: BTreeMap<String, BTreeMap<String, i128>> = BTreeMap::new();
    for (row, sign) in [(&before, -1), (&after, 1)] {
        for model in &row.models {
            for (unit, count) in &model.usage_units {
                let slot = models
                    .entry(model.model.clone())
                    .or_default()
                    .entry(unit.clone())
                    .or_default();
                *slot = slot.checked_add(count.checked_mul(sign).unwrap()).unwrap();
            }
        }
    }
    UsageDelta {
        requests: i64::try_from(i128::from(after.requests) - i128::from(before.requests)).unwrap(),
        billable_requests: i64::try_from(
            i128::from(after.billable_requests) - i128::from(before.billable_requests),
        )
        .unwrap(),
        models: models
            .into_iter()
            .filter_map(|(model, mut units)| {
                units.retain(|_, count| *count != 0);
                (!units.is_empty()).then_some(busbar_contract::records::ModelTokensDelta {
                    model,
                    scale: COUNT_SCALE,
                    usage_units: units,
                })
            })
            .collect(),
    }
}
impl busbar_contract::persistence::PersistenceBackend for ChunkBackend {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.inner.info()
    }
    fn read(
        &self,
        r: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        self.inner.read(r)
    }
    fn scan(
        &self,
        r: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        self.inner.scan(r)
    }
    fn clock(
        &self,
        d: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.inner.clock(d)
    }
    fn commit(
        &self,
        prepared: busbar_contract::persistence::PreparedCandidate,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        Box::pin(async move {
            use busbar_contract::persistence::{Failure, Mutation};
            let changes = usage_changes(&prepared);
            let usage = !changes.is_empty() && !is_correction(&changes);
            let reply = if usage {
                self.faults.batches.lock().unwrap().push((
                    OpId(prepared.candidate().id.operation),
                    changes
                        .iter()
                        .map(|change| {
                            (
                                change.address.bucket_id.clone(),
                                change.address.window_start,
                                observed_delta(change),
                            )
                        })
                        .collect(),
                ));
                let reply = self
                    .faults
                    .replies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Reply::Confirm);
                let hook = self.faults.before_batch.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook().await;
                }
                reply
            } else {
                Reply::Confirm
            };
            if prepared
                .candidate()
                .mutations
                .iter()
                .any(|m| matches!(m,Mutation::Put {address,..} if address.key.first()==Some(&b'K')))
            {
                let hook = self.faults.before_delete.lock().unwrap().take();
                if let Some(hook) = hook {
                    hook().await;
                }
            }
            if matches!(reply, Reply::FailBefore) {
                return Err(Failure::Unknown);
            }
            let result = self.inner.commit(prepared).await;
            match reply {
                Reply::LoseAfter => Err(Failure::Unknown),
                Reply::CancelAfter => panic!("planted caller cancellation after native commit"),
                _ => result,
            }
        })
    }
}

async fn input_count(store: &CoreStore, bucket: &str, window: u64) -> Count {
    Count::total(
        store
            .ledger()
            .get_usage(bucket, window)
            .await
            .unwrap()
            .models
            .iter()
            .filter(|row| row.model == MODEL)
            .map(|row| {
                Count::from_stored(
                    row.usage_units
                        .get(busbar_contract::records::UNIT_INPUT)
                        .copied()
                        .unwrap_or(0),
                    row.scale,
                )
                .unwrap()
            }),
    )
    .unwrap()
}
async fn input(store: &CoreStore, bucket: &str, window: u64) -> u64 {
    input_count(store, bucket, window).await.whole_for_test()
}
fn accrue_dated(gov: &GovState, key: &VirtualKey, count: u64, now: u64) {
    accrue_exact_dated(gov, key, whole_count(count), now);
}
fn accrue_exact_dated(gov: &GovState, key: &VirtualKey, count: Count, now: u64) {
    let window = super::super::budget_window(super::super::WINDOW_TOTAL, now);
    let mut cells = gov.budget.write(&key.id);
    let cell = cells
        .entry(key.id.clone())
        .or_insert_with(|| BudgetCell::fresh(window));
    cell.accrue_raw(
        MODEL,
        RawRateEra::legacy(HISTORICAL_ERA),
        &BTreeMap::from([("input".into(), count)]),
    )
    .unwrap();
    cell.dirty = true;
    cell.last_touch = now;
}
async fn setup(id: &str) -> (Arc<ChunkStore>, GovState, VirtualKey, u64) {
    let store = Arc::new(ChunkStore::new().await);
    let key = key(id, None);
    store.identity().put_key(&key).await.unwrap();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    let now = crate::store::now();
    (store, gov, key, now)
}

async fn dated_input(store: &CoreStore, bucket: &str, window: u64) -> u64 {
    let dated_model = format!("{HISTORICAL_ERA}{}{}", super::super::ERA_MODEL_SEP, MODEL);
    let row = store
        .ledger()
        .get_usage(&super::super::era_bucket(bucket), window)
        .await
        .unwrap();
    row.models
        .iter()
        .find(|row| row.model == dated_model)
        .map_or(0, |row| {
            Count::from_stored(
                row.usage_units
                    .get(busbar_contract::records::UNIT_INPUT)
                    .copied()
                    .unwrap_or(0),
                row.scale,
            )
            .unwrap()
            .whole_for_test()
        })
}

#[tokio::test]
async fn ordinary_small_unknown_commit_keeps_paired_rows_and_later_accrual_exact() {
    let (store, gov, key, now) = setup("vk_small_unknown_flush").await;
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::LoseAfter);
    assert_eq!(gov.flush_budgets().await, 0);
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT
    );
    assert_eq!(
        dated_input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT,
        "plain and historical rows share one atomic application"
    );
    accrue_dated(&gov, &key, NEXT_INPUT, now);
    gov.flush_budgets().await;
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT + NEXT_INPUT
    );
    assert_eq!(
        dated_input(store.core().as_ref(), &key.id, 0).await,
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

#[tokio::test]
async fn raw_entry_identity_survives_unknown_budget_flush_and_later_same_timestamp_counts() {
    const OLD_ID_HEX: &str = "010101010101010101010101";
    const NEW_ID_HEX: &str = "020202020202020202020202";
    let old = RawRateEra::entry(0, EntryId::parse_hex(OLD_ID_HEX).unwrap());
    let new = RawRateEra::entry(0, EntryId::parse_hex(NEW_ID_HEX).unwrap());
    for reply in [Reply::LoseAfter, Reply::CancelAfter] {
        let (store, gov, key, now) = setup("vk_exact_raw_unknown_flush").await;
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
            assert!(std::panic::AssertUnwindSafe(gov.flush_budgets())
                .catch_unwind()
                .await
                .is_err());
        } else {
            assert_eq!(gov.flush_budgets().await, 0);
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
        gov.flush_budgets_final().await;
        assert_eq!(
            input(store.core().as_ref(), &key.id, 0).await,
            CONCURRENT_INPUT + NEXT_INPUT
        );
        let dated = store
            .ledger()
            .get_usage(&super::super::era_bucket(&key.id), 0)
            .await
            .unwrap();
        for (era, expected) in [(old, CONCURRENT_INPUT), (new, NEXT_INPUT)] {
            let name = super::super::era_model(era, MODEL);
            let segment = dated.models.iter().find(|row| row.model == name).unwrap();
            assert_eq!(
                Count::from_stored(
                    segment.usage_units[busbar_contract::records::UNIT_INPUT],
                    segment.scale
                )
                .unwrap(),
                whole_count(expected)
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

#[tokio::test]
async fn ordinary_small_plain_only_unknown_commit_replays_once() {
    let (store, gov, key, now) = setup("vk_small_plain_unknown_flush").await;
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
    assert_eq!(gov.flush_budgets().await, 0);
    gov.flush_budgets().await;
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT
    );
    assert_eq!(dated_input(store.core().as_ref(), &key.id, 0).await, 0);
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
    assert_eq!(batches[0].1.len(), 1, "zero dated body is omitted");
}

#[tokio::test]
async fn ordinary_small_unwind_after_commit_keeps_custody_until_next_tick() {
    let (store, gov, key, now) = setup("vk_small_cancelled_flush").await;
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::CancelAfter);
    assert!(std::panic::AssertUnwindSafe(gov.flush_budgets())
        .catch_unwind()
        .await
        .is_err());
    accrue_dated(&gov, &key, NEXT_INPUT, now);
    gov.flush_budgets().await;
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT + NEXT_INPUT
    );
    assert_eq!(
        dated_input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT + NEXT_INPUT
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ordinary_small_zero_net_debt_does_not_enter_store() {
    let (store, gov, key, now) = setup("vk_small_zero_flush").await;
    accrue_dated(&gov, &key, 0, now);
    assert_eq!(gov.flush_budgets().await, 0);
    assert!(store.batches.lock().unwrap().is_empty());
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn ordinary_small_flush_atomically_pairs_raw_and_dated_rows() {
    let store = Arc::new(ChunkStore::new().await);
    let key = key("vk_small_legacy_flush", None);
    store.identity().put_key(&key).await.unwrap();
    let gov = GovState::new_with_core(store.core(), None, None)
        .await
        .unwrap();
    accrue_dated(&gov, &key, CONCURRENT_INPUT, crate::store::now());
    assert_eq!(gov.flush_budgets().await, 1);
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT
    );
    assert_eq!(
        dated_input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(
        batches.len(),
        1,
        "mandatory native transaction pairs both raw rows"
    );
    assert_eq!(batches[0].1.len(), 2);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn key_deletion_reconciles_small_unknown_commit_before_purging_usage() {
    let (store, gov, key, now) = setup("vk_small_delete_unknown_flush").await;
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::LoseAfter);
    gov.flush_budgets().await;
    store.replies.lock().unwrap().push_back(Reply::FailBefore);
    assert!(gov.delete_key(&key.id).await.is_err());
    assert!(store
        .identity()
        .get_key(&key.id)
        .await
        .unwrap()
        .unwrap()
        .deleted_at
        .is_none());
    gov.delete_key(&key.id).await.unwrap();
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
    assert_eq!(batches[1], batches[2]);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    assert!(!gov.budget.read(&key.id).contains_key(&key.id));
}

#[tokio::test]
async fn ordinary_large_positive_debt_flushes_all_chunks_with_historical_counts() {
    let (store, gov, key, now) = setup("vk_large_positive_chunks").await;
    accrue_exact_dated(&gov, &key, Count::from_micros(i128::MAX), now);
    gov.flush_budgets().await;
    assert_eq!(
        input_count(store.core().as_ref(), &key.id, 0).await,
        Count::from_micros(i128::MAX)
    );
    let era = store
        .ledger()
        .get_usage(&super::super::era_bucket(&key.id), 0)
        .await
        .unwrap();
    let dated_model = format!("{HISTORICAL_ERA}{}{}", super::super::ERA_MODEL_SEP, MODEL);
    assert_eq!(
        era.models
            .iter()
            .find(|row| row.model == dated_model)
            .unwrap()
            .usage_units[busbar_contract::records::UNIT_INPUT],
        i128::MAX
    );
    {
        let batches = store.batches.lock().unwrap();
        assert_eq!(
            batches.len(),
            1,
            "the full Count range fits one signed wire operation"
        );
        assert!(batches.windows(2).all(|pair| pair[0].0 != pair[1].0));
        assert!(gov.budget_flushes.lock().unwrap().is_empty());
    }
    assert_eq!(gov.flush_budgets().await, 0);
}

#[tokio::test]
async fn ordinary_large_negative_debt_uses_the_full_signed_range() {
    let (store, gov, key, now) = setup("vk_large_negative_chunks").await;
    accrue_exact_dated(&gov, &key, Count::from_micros(i128::MAX), now);
    gov.flush_budgets().await;
    store.batches.lock().unwrap().clear();

    {
        let mut cells = gov.budget.write(&key.id);
        let cell = cells.get_mut(&key.id).unwrap();
        for model in &mut cell.models {
            model.cur.clear();
        }
        cell.dirty = true;
    }
    gov.flush_budgets().await;
    assert_eq!(input(store.core().as_ref(), &key.id, 0).await, 0);
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(
        batches[0].1[0].2.models[0].usage_units[busbar_contract::records::UNIT_INPUT],
        -i128::MAX
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn confirmed_large_operation_is_not_repeated_when_a_later_operation_fails() {
    let (store, gov, key, now) = setup("vk_large_partial_chunks").await;
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    store
        .replies
        .lock()
        .unwrap()
        .extend([Reply::Confirm, Reply::FailBefore]);
    gov.flush_budgets().await;
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    gov.flush_budgets().await;
    assert_eq!(
        input_count(store.core().as_ref(), &key.id, 0).await,
        whole_count(LARGE_INPUT)
    );
    let first = store.batches.lock().unwrap().clone();
    assert_eq!(first.len(), 2);
    gov.flush_budgets().await;
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        LARGE_INPUT + CONCURRENT_INPUT
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(
        batches[1], batches[2],
        "only the unresolved second chunk replays"
    );
    assert_ne!(batches[0].0, batches[2].0);
}

#[tokio::test]
async fn lost_chunk_commit_reply_keeps_exact_identity_and_later_accrual() {
    let (store, gov, key, now) = setup("vk_large_unknown_chunks").await;
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::LoseAfter);
    gov.flush_budgets().await;
    assert_eq!(
        input_count(store.core().as_ref(), &key.id, 0).await,
        whole_count(LARGE_INPUT)
    );
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    assert!(gov.hydrate_budgets_async(&model(&[]), now).await.is_err());
    gov.flush_budgets().await;
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        LARGE_INPUT + CONCURRENT_INPUT
    );
    let batches = store.batches.lock().unwrap();
    assert_eq!(
        batches[0], batches[1],
        "a committed chunk is retried with the original body and id"
    );
    assert_ne!(batches[1].0, batches[2].0);
}

#[tokio::test]
async fn cancellation_after_chunk_commit_retains_custody_without_stranding_other_windows() {
    let (store, gov, key, now) = setup("vk_large_cancelled_chunks").await;
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    let other = super::key("vk_small_after_chunk_cancellation", None);
    store.identity().put_key(&other).await.unwrap();
    gov.record_usage(
        &model(&[]),
        &other,
        "",
        MODEL,
        &toks(CONCURRENT_INPUT, 0),
        now,
    );
    store.replies.lock().unwrap().push_back(Reply::CancelAfter);
    assert!(std::panic::AssertUnwindSafe(gov.flush_budgets())
        .catch_unwind()
        .await
        .is_err());
    gov.flush_budgets().await;
    assert_eq!(input(store.core().as_ref(), &key.id, 0).await, LARGE_INPUT);
    assert_eq!(
        input(store.core().as_ref(), &other.id, 0).await,
        CONCURRENT_INPUT
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
}

#[tokio::test]
async fn in_flight_large_chunks_preserve_roll_refund_and_independent_window_correction() {
    in_flight_flush_preserves_roll_refund_and_independent_window_correction(LARGE_INPUT).await;
}

#[tokio::test]
async fn in_flight_small_flush_preserves_roll_refund_and_independent_window_correction() {
    in_flight_flush_preserves_roll_refund_and_independent_window_correction(CONCURRENT_INPUT).await;
}

async fn in_flight_flush_preserves_roll_refund_and_independent_window_correction(
    initial_input: u64,
) {
    let store = Arc::new(ChunkStore::new().await);
    let key = key("vk_large_window_overlap", Some("g"));
    store.identity().put_key(&key).await.unwrap();
    let gov = Arc::new(
        GovState::new_with_core(store.core(), None, None)
            .await
            .unwrap(),
    );
    let cm = minute_fee_model();
    let now = crate::governance::budget_window(
        super::super::WINDOW_MINUTE,
        crate::store::now().saturating_sub(120),
    );
    let next = super::super::window_end(super::super::WINDOW_MINUTE, now).unwrap();
    let charged = gov.try_admit(&cm, &key, "", now).unwrap();
    gov.record_usage(&cm, &key, "", MODEL, &toks(initial_input, 0), now);
    metered(&gov, &key.id, MODEL, initial_input, now).await;
    let independent = super::key("vk_other_correction_window", Some("g"));
    store.identity().put_key(&independent).await.unwrap();
    metered(&gov, &independent.id, MODEL, 1, next).await;
    let (mutator, mutated_key) = (gov.clone(), key.clone());
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
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
            let epoch = |seconds| {
                u64::try_from(std::time::Duration::from_secs(seconds).as_millis()).unwrap()
            };
            let delta = BTreeMap::from([(busbar_contract::records::UNIT_INPUT.into(), 1)]);
            assert!(
                mutator
                    .adjust_usage_async(
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
                    .await
                    .is_err(),
                "same target window stays owned by its flight"
            );
            mutator
                .adjust_usage_async(
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
                .await
                .unwrap()
                .unwrap();
        })
    }));
    gov.flush_budgets().await;
    gov.flush_budgets().await;
    assert_eq!(
        input(store.core().as_ref(), GROUP_BUCKET, now).await,
        initial_input + CONCURRENT_INPUT
    );
    assert_eq!(
        input(store.core().as_ref(), GROUP_BUCKET, next).await,
        NEXT_INPUT + 1
    );
    assert_eq!(
        store
            .ledger()
            .get_usage(GROUP_BUCKET, now)
            .await
            .unwrap()
            .billable_requests,
        0
    );
    assert_eq!(
        store
            .ledger()
            .get_usage(GROUP_BUCKET, next)
            .await
            .unwrap()
            .billable_requests,
        1
    );
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        initial_input + CONCURRENT_INPUT + NEXT_INPUT
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn key_deletion_settles_unknown_large_chunks_before_releasing_raw_custody() {
    let (store, gov, key, now) = setup("vk_large_delete_chunks").await;
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    store.replies.lock().unwrap().push_back(Reply::FailBefore);
    gov.flush_budgets().await;
    store.replies.lock().unwrap().push_back(Reply::FailBefore);
    assert!(gov.delete_key(&key.id).await.is_err());
    assert!(store
        .identity()
        .get_key(&key.id)
        .await
        .unwrap()
        .unwrap()
        .deleted_at
        .is_none());
    assert_eq!(gov.budget_flushes.lock().unwrap().len(), 1);
    gov.delete_key(&key.id).await.unwrap();
    assert!(store
        .identity()
        .get_key(&key.id)
        .await
        .unwrap()
        .is_none_or(|row| row.deleted_at.is_some()));
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    assert!(!gov.budget.read(&key.id).contains_key(&key.id));
    let batches = store.batches.lock().unwrap();
    assert_eq!(batches[0], batches[1]);
    assert_eq!(batches[1], batches[2]);
}

#[tokio::test]
async fn accrual_between_capture_and_snapshot_gets_its_own_large_flight() {
    let (store, gov, key, now) = setup("vk_large_capture_trigger").await;
    let gov = Arc::new(gov);
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    let later = super::key("vk_grows_after_capture", None);
    store.identity().put_key(&later).await.unwrap();
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
        Box::pin(async move {
            writer.record_usage(
                &model(&[]),
                &later_key,
                "",
                MODEL,
                &toks(LARGE_INPUT, 0),
                now,
            );
        })
    }));
    gov.flush_budgets().await;
    assert_eq!(input(store.core().as_ref(), &key.id, 0).await, LARGE_INPUT);
    assert_eq!(
        input(store.core().as_ref(), &later.id, 0).await,
        LARGE_INPUT + CONCURRENT_INPUT
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn concurrent_flush_driver_cannot_lend_the_same_chunk_twice() {
    let (store, gov, key, now) = setup("vk_large_concurrent_drivers").await;
    let gov = Arc::new(gov);
    accrue_dated(&gov, &key, LARGE_INPUT, now);
    let (second, observed) = (gov.clone(), store.clone());
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            assert_eq!(second.flush_budgets().await, 0);
            assert_eq!(observed.batches.lock().unwrap().len(), 1);
        })
    }));
    gov.flush_budgets().await;
    assert_eq!(input(store.core().as_ref(), &key.id, 0).await, LARGE_INPUT);
    assert_eq!(
        dated_input(store.core().as_ref(), &key.id, 0).await,
        LARGE_INPUT
    );
    // Usage counts now fit the full signed Count range in one wire operation.
    // The reentrant driver above must not submit that same operation again.
    assert_eq!(store.batches.lock().unwrap().len(), 1);
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    assert_eq!(gov.flush_budgets().await, 0);
    assert_eq!(store.batches.lock().unwrap().len(), 1);
}

async fn final_flush_joins_active_ordinary_runner(reply: Reply, _formerly_legacy: bool) {
    let store = Arc::new(ChunkStore::new().await);
    let key = key("vk_final_active_ordinary_flush", None);
    store.identity().put_key(&key).await.unwrap();
    let gov = Arc::new(
        GovState::new_with_core(store.core(), None, None)
            .await
            .unwrap(),
    );
    let now = crate::store::now();
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    store.replies.lock().unwrap().push_back(reply);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            entered_tx.send(()).unwrap();
            release_rx.await.unwrap();
        })
    }));
    let periodic_gov = gov.clone();
    let periodic = tokio::spawn(async move { periodic_gov.flush_budgets().await });
    entered_rx.await.unwrap();
    accrue_dated(&gov, &key, NEXT_INPUT, now);
    let final_flush = gov.flush_budgets_final();
    tokio::pin!(final_flush);
    assert!(
        futures::poll!(&mut final_flush).is_pending(),
        "final flush returned while the periodic Store call still owned unsettled debt"
    );
    release_tx.send(()).unwrap();
    let periodic_result = periodic.await;
    final_flush.await;
    assert_eq!(
        periodic_result.is_err(),
        matches!(reply, Reply::CancelAfter)
    );
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT + NEXT_INPUT
    );
    assert_eq!(
        dated_input(store.core().as_ref(), &key.id, 0).await,
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

#[tokio::test]
async fn final_budget_flush_waits_for_active_runner_and_persists_later_accrual() {
    final_flush_joins_active_ordinary_runner(Reply::Confirm, false).await;
}

#[tokio::test]
async fn final_budget_flush_waits_for_active_legacy_snapshots_and_persists_later_accrual() {
    final_flush_joins_active_ordinary_runner(Reply::Confirm, true).await;
}

#[tokio::test]
async fn final_budget_flush_reconciles_unknown_active_runner_commit() {
    final_flush_joins_active_ordinary_runner(Reply::LoseAfter, false).await;
}

#[tokio::test]
async fn final_budget_flush_recovers_custody_after_active_runner_unwind() {
    final_flush_joins_active_ordinary_runner(Reply::CancelAfter, false).await;
}

#[tokio::test]
async fn final_budget_flush_same_thread_reentry_returns_without_lending_active_body() {
    let (store, gov, key, now) = setup("vk_final_reentrant_ordinary_flush").await;
    let gov = Arc::new(gov);
    accrue_dated(&gov, &key, CONCURRENT_INPUT, now);
    let (reentrant, observed) = (gov.clone(), store.clone());
    *store.before_batch.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            assert_eq!(reentrant.flush_budgets_final().await, 0);
            assert_eq!(observed.batches.lock().unwrap().len(), 1);
        })
    }));
    gov.flush_budgets_final().await;
    assert_eq!(
        input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT
    );
    assert_eq!(
        dated_input(store.core().as_ref(), &key.id, 0).await,
        CONCURRENT_INPUT
    );
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn deletion_excludes_new_large_flight_capture_until_the_key_purge_finishes() {
    let (store, gov, key, now) = setup("vk_large_delete_capture_race").await;
    let gov = Arc::new(gov);
    let (writer, written_key, observed) = (gov.clone(), key.clone(), store.clone());
    *store.before_delete.lock().unwrap() = Some(Box::new(move || {
        Box::pin(async move {
            accrue_dated(&writer, &written_key, LARGE_INPUT, now);
            assert_eq!(writer.flush_budgets().await, 0);
            assert!(observed.batches.lock().unwrap().is_empty());
        })
    }));
    gov.delete_key(&key.id).await.unwrap();
    assert!(gov.budget_flushes.lock().unwrap().is_empty());
    assert!(!gov.budget.read(&key.id).contains_key(&key.id));
    assert!(gov.deleting_budget_buckets.lock().unwrap().is_empty());
}

#[path = "budget_flusher_recovery_cases.rs"]
mod budget_flusher_recovery_cases;
