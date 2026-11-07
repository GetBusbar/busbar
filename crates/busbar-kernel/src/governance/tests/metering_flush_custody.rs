use super::*;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision, ExpectedValue, Failure, Mutation,
    Page, PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::records::OpId;
use futures::FutureExt;
use std::collections::VecDeque;
use std::sync::Mutex;

const NOW: u64 = 1_700_200_000;
enum Reply {
    Lost,
    Unknown,
    Unwind,
    Block(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    ),
}
#[derive(Default)]
struct MeterFaults {
    replies: Mutex<VecDeque<Reply>>,
    calls: Mutex<Vec<(OpId, Vec<MeteringDelta>)>>,
    reenter: Mutex<Option<std::sync::Weak<GovState>>>,
}
struct UncertainStore {
    core: Arc<crate::persistence::facade::CoreStore>,
    faults: Arc<MeterFaults>,
}
impl std::ops::Deref for UncertainStore {
    type Target = MeterFaults;
    fn deref(&self) -> &MeterFaults {
        &self.faults
    }
}
impl UncertainStore {
    async fn new(replies: impl IntoIterator<Item = Reply>) -> Self {
        let faults = Arc::new(MeterFaults {
            replies: Mutex::new(replies.into_iter().collect()),
            ..Default::default()
        });
        let backend = Arc::new(MeterBackend {
            inner: crate::real_store::native_backend().await,
            faults: faults.clone(),
        });
        let core = crate::real_store::core_over(backend).await;
        Self { core, faults }
    }
}
#[derive(serde::Deserialize)]
struct StoredMeter {
    version: u32,
    record: MeteringRow,
}
fn meter(value: &busbar_contract::Secret<Vec<u8>>) -> MeteringRow {
    let stored: StoredMeter = serde_json::from_slice(value.expose(&crate::seal::lend())).unwrap();
    assert_eq!(stored.version, 1);
    stored.record
}
fn metering_changes(prepared: &PreparedCandidate) -> Vec<MeteringDelta> {
    prepared
        .candidate()
        .mutations
        .iter()
        .filter_map(|mutation| {
            let Mutation::Put { address, value } = mutation else {
                return None;
            };
            let parts = crate::persistence::keys::components(&address.key, b'M').ok()?;
            let [family, bucket, ..] = parts.as_slice() else {
                return None;
            };
            if *family != crate::governance::persistence::ledger::METERING.0 {
                return None;
            }
            let after = meter(value);
            let before = prepared
                .candidate()
                .predicates
                .iter()
                .find(|p| p.address == *address)
                .and_then(|p| match &p.expected {
                    ExpectedValue::Absent => None,
                    ExpectedValue::Exact(value) => Some(meter(value)),
                });
            let old = |read: fn(&MeteringRow) -> i128| before.as_ref().map(read).unwrap_or(0);
            let units = after
                .usage_units
                .iter()
                .filter_map(|(class, count)| {
                    let old = before
                        .as_ref()
                        .and_then(|row| row.usage_units.get(class))
                        .copied()
                        .unwrap_or(0);
                    let delta = count.checked_sub(old).unwrap();
                    (delta != 0).then_some((class.clone(), delta))
                })
                .collect();
            Some(MeteringDelta {
                scale: after.scale,
                key_id: after.key_id.clone(),
                bucket: u64::from_be_bytes((*bucket).try_into().unwrap()),
                model: after.model.clone(),
                provider: after.provider.clone(),
                tokens_input: after.tokens_input - old(|r| r.tokens_input),
                tokens_output: after.tokens_output - old(|r| r.tokens_output),
                tokens_cache_read: after.tokens_cache_read - old(|r| r.tokens_cache_read),
                tokens_cache_write: after.tokens_cache_write - old(|r| r.tokens_cache_write),
                requests: after.requests - before.as_ref().map(|r| r.requests).unwrap_or(0),
                billable_requests: after.billable_requests
                    - before.as_ref().map(|r| r.billable_requests).unwrap_or(0),
                key_group_at_use: after.key_group_at_use.clone(),
                pricing_version: after.pricing_version.clone(),
                priced_from_ms: after.priced_from_ms,
                usage_units: units,
            })
        })
        .collect()
}
struct MeterBackend {
    inner: Arc<dyn PersistenceBackend>,
    faults: Arc<MeterFaults>,
}
impl PersistenceBackend for MeterBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, r: Arc<Read>) -> Call<'_, ReadResult> {
        self.inner.read(r)
    }
    fn scan(&self, r: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(r)
    }
    fn clock(&self, d: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(d)
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let deltas = metering_changes(&prepared);
            if deltas.is_empty() {
                return self.inner.commit(prepared).await;
            }
            self.faults
                .calls
                .lock()
                .unwrap()
                .push((OpId(prepared.candidate().id.operation), deltas));
            let reenter = self.faults.reenter.lock().unwrap().take();
            if let Some(gov) = reenter.and_then(|gov| gov.upgrade()) {
                assert_eq!(gov.flush_metering_final().await, 0);
            }
            let reply = self.faults.replies.lock().unwrap().pop_front();
            if matches!(reply, Some(Reply::Unknown)) {
                return Err(Failure::Unknown);
            }
            let result = self.inner.commit(prepared).await;
            match reply {
                Some(Reply::Lost) => Err(Failure::Unknown),
                Some(Reply::Unwind) => {
                    panic!("applied native meter, caller unwound before acknowledgement")
                }
                Some(Reply::Block(entered, release)) => {
                    entered.send(()).unwrap();
                    release.await.unwrap();
                    Err(Failure::Unknown)
                }
                _ => result,
            }
        })
    }
}

fn accrue(gov: &GovState, input: u64, era: u64) {
    accrue_raw(gov, input, RawRateEra::legacy(era));
}

fn accrue_raw(gov: &GovState, input: u64, era: RawRateEra) {
    gov.record_metered_request_dated(
        "retry-key",
        "historical-group",
        "model",
        "provider",
        MeterCounts {
            requests: 1,
            tokens_input: whole_count(input),
            ..Default::default()
        },
        NOW,
        &|| era.effective_from,
        &|_| era,
    );
}

#[tokio::test]
async fn unknown_and_unwound_flushes_keep_exact_same_timestamp_entry_identity() {
    const FIRST_ID_HEX: &str = "010101010101010101010101";
    const SECOND_ID_HEX: &str = "020202020202020202020202";
    const SHARED_START: u64 = 0;
    let first = RawRateEra::entry(SHARED_START, EntryId::parse_hex(FIRST_ID_HEX).unwrap());
    let second = RawRateEra::entry(SHARED_START, EntryId::parse_hex(SECOND_ID_HEX).unwrap());
    let store = Arc::new(UncertainStore::new([Reply::Unknown, Reply::Unwind]).await);
    let gov = GovState::new_with_core(store.core.clone(), None, None)
        .await
        .unwrap();
    accrue_raw(&gov, 3, first);
    assert_eq!(gov.flush_metering().await, 0);
    accrue_raw(&gov, 5, second);
    assert!(std::panic::AssertUnwindSafe(gov.flush_metering())
        .catch_unwind()
        .await
        .is_err());
    assert_eq!(gov.flush_metering_final().await, 2);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0], calls[2]);
    assert_eq!(
        calls[0].1[0].pricing_version,
        first.entry_id.unwrap().metering_version()
    );
    assert_eq!(
        calls[3].1[0].pricing_version,
        second.entry_id.unwrap().metering_version()
    );
    assert_ne!(calls[0].0, calls[3].0);
    let rows = gov.metering_for_async(metering_bucket(NOW)).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .map(|row| Count::from_stored(row.tokens_input, row.scale)
                .unwrap()
                .whole_for_test())
            .sum::<u64>(),
        8
    );
    assert_eq!(rows.iter().map(|row| row.requests).sum::<u64>(), 2);
}

#[tokio::test]
async fn ordinary_refusal_requeues_the_original_exact_provenance() {
    const OLD_ID_HEX: &str = "030303030303030303030303";
    const NEW_ID_HEX: &str = "040404040404040404040404";
    let old = RawRateEra::entry(0, EntryId::parse_hex(OLD_ID_HEX).unwrap());
    let new = RawRateEra::entry(0, EntryId::parse_hex(NEW_ID_HEX).unwrap());
    let store = UncertainStore::new([Reply::Unknown]).await;

    let store = Arc::new(store);
    let gov = GovState::new_with_core(store.core.clone(), None, None)
        .await
        .unwrap();
    accrue_raw(&gov, 3, old);
    assert_eq!(gov.flush_metering().await, 0);
    accrue_raw(&gov, 5, new);
    assert_eq!(gov.flush_metering_final().await, 2);
    let rows = gov.metering_for_async(metering_bucket(NOW)).await.unwrap();
    assert_eq!(rows.len(), 2);
    for (era, count) in [(old, 3), (new, 5)] {
        let row = rows
            .iter()
            .find(|row| row.pricing_version == era.entry_id.unwrap().metering_version())
            .unwrap();
        assert_eq!(
            Count::from_stored(row.tokens_input, row.scale).unwrap(),
            whole_count(count)
        );
        assert_eq!(row.requests, 1);
    }
    assert_eq!(store.calls.lock().unwrap().len(), 3);
}

async fn requests(gov: &GovState) -> u64 {
    gov.metering_for_async(metering_bucket(NOW))
        .await
        .unwrap()
        .iter()
        .map(|r| r.requests)
        .sum()
}

#[tokio::test]
async fn lost_ack_then_unknown_replays_exact_body_before_fresh_arrivals() {
    let store = Arc::new(UncertainStore::new([Reply::Lost, Reply::Unknown]).await);
    let gov = GovState::new_with_core(store.core.clone(), None, None)
        .await
        .unwrap();
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering().await, 0);
    assert_eq!(requests(&gov).await, 1);
    accrue(&gov, 5, 123);
    accrue(&gov, 7, 456);
    assert_eq!(gov.flush_metering().await, 0);
    assert_eq!(requests(&gov).await, 1);
    gov.flush_metering().await;
    gov.flush_metering().await;
    assert_eq!(
        requests(&gov).await,
        3,
        "lost acknowledgement must not duplicate consumption"
    );
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0], calls[2]);
    assert_eq!(
        Count::from_stored(calls[0].1[0].tokens_input, calls[0].1[0].scale).unwrap(),
        whole_count(3)
    );
    assert_eq!(calls[0].1[0].priced_from_ms, 123);
    assert_eq!(calls[0].1[0].key_group_at_use, "historical-group");
    assert!(calls[3..].iter().all(|call| call.0 != calls[0].0));

    assert_eq!(gov.pending_metering_totals().1.requests, 0);
    let rows = gov.metering_for_async(metering_bucket(NOW)).await.unwrap();
    assert_eq!(rows.len(), 2, "historical pricing instants remain distinct");
    assert_eq!(
        rows.iter()
            .map(|r| Count::from_stored(r.tokens_input, r.scale)
                .unwrap()
                .whole_for_test())
            .sum::<u64>(),
        15
    );
}

#[tokio::test]
async fn unwind_retains_operation_and_releases_flush_owner() {
    let store = Arc::new(UncertainStore::new([Reply::Unwind]).await);
    let gov = GovState::new_with_core(store.core.clone(), None, None)
        .await
        .unwrap();
    accrue(&gov, 3, 123);
    assert!(std::panic::AssertUnwindSafe(gov.flush_metering())
        .catch_unwind()
        .await
        .is_err());
    assert_eq!(requests(&gov).await, 1);
    assert_eq!(gov.pending_metering_totals().1.requests, 1);
    assert_eq!(gov.flush_metering_final().await, 1);
    assert_eq!(requests(&gov).await, 1);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls[0], calls[1]);
}

#[tokio::test]
async fn concurrent_flush_and_abandoned_caller_leave_one_replay_owner() {
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let store = Arc::new(UncertainStore::new([Reply::Block(entered_tx, release_rx)]).await);
    let gov = Arc::new(
        GovState::new_with_core(store.core.clone(), None, None)
            .await
            .unwrap(),
    );
    accrue(&gov, 3, 123);
    let (finished, completion) = tokio::sync::oneshot::channel();
    let held = {
        let gov = gov.clone();
        tokio::spawn(async move {
            finished.send(gov.flush_metering().await).unwrap();
        })
    };
    entered_rx.await.unwrap();
    accrue(&gov, 5, 123);
    assert_eq!(
        gov.flush_metering().await,
        0,
        "another caller cannot replace the active operation"
    );
    assert_eq!(gov.pending_metering_totals().1.requests, 2);
    let final_flush = gov.flush_metering_final();
    tokio::pin!(final_flush);
    assert!(futures::poll!(&mut final_flush).is_pending());
    drop(held);
    release_tx.send(()).unwrap();
    assert_eq!(completion.await.unwrap(), 0);
    assert_eq!(final_flush.await, 2);
    assert_eq!(requests(&gov).await, 2);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls[0], calls[1]);
    assert_ne!(calls[0].0, calls[2].0);
}

#[tokio::test]
async fn acknowledged_independent_operations_each_apply_and_empty_flush_is_noop() {
    let store = Arc::new(UncertainStore::new([]).await);
    let gov = GovState::new_with_core(store.core.clone(), None, None)
        .await
        .unwrap();
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering().await, 1);
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering_final().await, 1);
    assert_eq!(requests(&gov).await, 2);
    assert_eq!(gov.flush_metering().await, 0);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1, calls[1].1);
    assert_ne!(calls[0].0, calls[1].0);
}

#[tokio::test]
async fn final_flush_reentry_does_not_wait_for_itself_or_change_the_operation() {
    let store = Arc::new(UncertainStore::new([]).await);
    let gov = Arc::new(
        GovState::new_with_core(store.core.clone(), None, None)
            .await
            .unwrap(),
    );
    *store.reenter.lock().unwrap() = Some(Arc::downgrade(&gov));
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering_final().await, 1);
    assert_eq!(requests(&gov).await, 1);
    assert_eq!(store.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn native_implementation_keeps_successful_ordinary_add_path() {
    let legacy = UncertainStore::new([]).await;

    let store = Arc::new(legacy);
    let gov = GovState::new_with_core(store.core.clone(), None, None)
        .await
        .unwrap();
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering().await, 1);
    assert_eq!(requests(&gov).await, 1);
    assert_eq!(store.calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn repeated_unknowns_retain_one_snapshot_and_coalesce_fresh_pending_separately() {
    let store = Arc::new(
        UncertainStore::new(
            std::iter::once(Reply::Lost).chain(std::iter::repeat_with(|| Reply::Unknown).take(8)),
        )
        .await,
    );
    let gov = GovState::new_with_core(store.core.clone(), None, None)
        .await
        .unwrap();
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering().await, 0);
    for _ in 0..8 {
        accrue(&gov, 5, 123);
        assert_eq!(gov.flush_metering().await, 0);
        assert_eq!(gov.pending_metering_totals().0, 2);
    }
    let calls = store.calls.lock().unwrap().clone();
    assert!(calls.iter().all(|call| call == &calls[0]));
    assert_eq!(gov.pending_metering_totals().1.requests, 9);
    assert_eq!(gov.flush_metering().await, 1);
    assert_eq!(gov.flush_metering().await, 1);
    assert_eq!(requests(&gov).await, 9);
}

#[tokio::test]
async fn expired_unknown_metering_is_not_replayed_by_periodic_or_final_flush() {
    let store = Arc::new(UncertainStore::new([Reply::Lost, Reply::Unknown]).await);
    let gov = GovState::new_with_core(store.core.clone(), None, None)
        .await
        .unwrap();
    let era = RawRateEra::entry(0, EntryId::parse_hex("050505050505050505050505").unwrap());
    accrue_raw(&gov, 3, era);
    assert_eq!(gov.flush_metering().await, 0);
    assert_eq!(gov.flush_metering().await, 0);
    let first = store.calls.lock().unwrap()[0].clone();
    assert_eq!(store.calls.lock().unwrap()[1], first);
    gov.pending_metering
        .flight
        .lock()
        .unwrap()
        .front_mut()
        .unwrap()
        .expire_attempt();
    accrue_raw(&gov, 5, era);

    for final_flush in [false, true, false] {
        assert_eq!(
            if final_flush {
                gov.flush_metering_final().await
            } else {
                gov.flush_metering().await
            },
            0
        );
        assert_eq!(
            store.calls.lock().unwrap().len(),
            2,
            "expired ids never cross the Store"
        );
        assert_eq!(
            requests(&gov).await,
            1,
            "the possibly committed body is never applied twice"
        );
        let (cells, counts) = gov.pending_metering_totals();
        assert_eq!(
            (cells, counts.requests, counts.tokens_input.whole_for_test()),
            (2, 2, 8)
        );
    }
    assert_eq!(
        first.1[0].pricing_version,
        era.entry_id.unwrap().metering_version()
    );
}
