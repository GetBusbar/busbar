use super::*;
use busbar_contract::abi::{sdk::store::SyncStore, store::OpId};
use std::collections::VecDeque;
use std::sync::{atomic::AtomicUsize, Barrier, Mutex};

const NOW: u64 = 1_700_200_000;

enum Reply {
    Lost,
    Unknown,
    Unwind,
    Block(Arc<Barrier>, Arc<Barrier>),
}

struct UncertainStore {
    inner: Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    replies: Mutex<VecDeque<Reply>>,
    calls: Mutex<Vec<(OpId, Vec<MeteringDelta>)>>,
    legacy_calls: AtomicUsize,
    supported: bool,
    reenter: Mutex<Option<std::sync::Weak<GovState>>>,
}

impl UncertainStore {
    fn new(replies: impl IntoIterator<Item = Reply>) -> Self {
        Self {
            inner: crate::real_store::store(),
            replies: Mutex::new(replies.into_iter().collect()),
            calls: Mutex::new(Vec::new()),
            legacy_calls: AtomicUsize::new(0),
            supported: true,
            reenter: Mutex::new(None),
        }
    }

    fn attempt(&self, op: OpId, deltas: &[MeteringDelta]) -> RecordStoreResult<()> {
        self.calls.lock().unwrap().push((op, deltas.to_vec()));
        let reenter = self.reenter.lock().unwrap().take();
        if let Some(gov) = reenter.and_then(|gov| gov.upgrade()) {
            assert_eq!(gov.flush_metering_final(), 0);
        }
        let reply = self.replies.lock().unwrap().pop_front();
        if matches!(reply, Some(Reply::Unknown)) {
            return Err(RecordStoreError("still unknown".into()));
        }
        SyncStore::add_metering_batch(&self.inner, op, deltas)
            .map_err(|e| RecordStoreError(format!("{e:?}")))?;
        match reply {
            Some(Reply::Lost) => Err(RecordStoreError("applied, acknowledgement lost".into())),
            Some(Reply::Unwind) => panic!("applied, caller unwound before acknowledgement"),
            Some(Reply::Block(entered, release)) => {
                entered.wait();
                release.wait();
                Err(RecordStoreError("cancelled reply after application".into()))
            }
            _ => Ok(()),
        }
    }
}

impl RecordStore for UncertainStore {
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
    fn get_usage(&self, id: &str, window: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(id, window)
    }
    fn put_usage(&self, id: &str, window: u64, row: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(id, window, row)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.legacy_calls.fetch_add(1, Ordering::SeqCst);
        self.attempt(crate::door::op_id(), std::slice::from_ref(delta))
    }
    fn supports_metering_batch_deduped(&self) -> bool {
        self.supported
    }
    fn add_metering_batch_deduped(
        &self,
        op: OpId,
        deltas: &[MeteringDelta],
    ) -> RecordStoreResult<()> {
        self.attempt(op, deltas)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
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
            tokens_input: input,
            ..Default::default()
        },
        NOW,
        &|| era.effective_from,
        &|_| era,
    );
}

#[test]
fn unknown_and_unwound_flushes_keep_exact_same_timestamp_entry_identity() {
    const FIRST_ID_HEX: &str = "010101010101010101010101";
    const SECOND_ID_HEX: &str = "020202020202020202020202";
    const SHARED_START: u64 = 0;
    let first = RawRateEra::entry(SHARED_START, EntryId::parse_hex(FIRST_ID_HEX).unwrap());
    let second = RawRateEra::entry(SHARED_START, EntryId::parse_hex(SECOND_ID_HEX).unwrap());
    let store = Arc::new(UncertainStore::new([Reply::Unknown, Reply::Unwind]));
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue_raw(&gov, 3, first);
    assert_eq!(gov.flush_metering(), 0);
    accrue_raw(&gov, 5, second);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gov.flush_metering())).is_err()
    );
    assert_eq!(gov.flush_metering_final(), 2);
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
    let rows = gov.metering_for(metering_bucket(NOW)).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows.iter().map(|row| row.tokens_input).sum::<u64>(), 8);
    assert_eq!(rows.iter().map(|row| row.requests).sum::<u64>(), 2);
}

#[test]
fn ordinary_refusal_requeues_the_original_exact_provenance() {
    const OLD_ID_HEX: &str = "030303030303030303030303";
    const NEW_ID_HEX: &str = "040404040404040404040404";
    let old = RawRateEra::entry(0, EntryId::parse_hex(OLD_ID_HEX).unwrap());
    let new = RawRateEra::entry(0, EntryId::parse_hex(NEW_ID_HEX).unwrap());
    let mut store = UncertainStore::new([Reply::Unknown]);
    store.supported = false;
    let store = Arc::new(store);
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue_raw(&gov, 3, old);
    assert_eq!(gov.flush_metering(), 0);
    accrue_raw(&gov, 5, new);
    assert_eq!(gov.flush_metering_final(), 2);
    let rows = gov.metering_for(metering_bucket(NOW)).unwrap();
    assert_eq!(rows.len(), 2);
    for (era, count) in [(old, 3), (new, 5)] {
        let row = rows
            .iter()
            .find(|row| row.pricing_version == era.entry_id.unwrap().metering_version())
            .unwrap();
        assert_eq!(row.tokens_input, count);
        assert_eq!(row.requests, 1);
    }
    assert_eq!(store.legacy_calls.load(Ordering::SeqCst), 3);
}

fn requests(gov: &GovState) -> u64 {
    gov.metering_for(metering_bucket(NOW))
        .unwrap()
        .iter()
        .map(|r| r.requests)
        .sum()
}

#[test]
fn lost_ack_then_unknown_replays_exact_body_before_fresh_arrivals() {
    let store = Arc::new(UncertainStore::new([Reply::Lost, Reply::Unknown]));
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering(), 0);
    assert_eq!(requests(&gov), 1);
    accrue(&gov, 5, 123);
    accrue(&gov, 7, 456);
    assert_eq!(gov.flush_metering(), 0);
    assert_eq!(requests(&gov), 1);
    gov.flush_metering();
    gov.flush_metering();
    assert_eq!(
        requests(&gov),
        3,
        "lost acknowledgement must not duplicate consumption"
    );
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls[0], calls[1]);
    assert_eq!(calls[0], calls[2]);
    assert_eq!(calls[0].1[0].tokens_input, 3);
    assert_eq!(calls[0].1[0].priced_from_ms, 123);
    assert_eq!(calls[0].1[0].key_group_at_use, "historical-group");
    assert!(calls[3..].iter().all(|call| call.0 != calls[0].0));
    assert_eq!(store.legacy_calls.load(Ordering::SeqCst), 0);
    assert_eq!(gov.pending_metering_totals().1.requests, 0);
    let rows = gov.metering_for(metering_bucket(NOW)).unwrap();
    assert_eq!(rows.len(), 2, "historical pricing instants remain distinct");
    assert_eq!(rows.iter().map(|r| r.tokens_input).sum::<u64>(), 15);
}

#[test]
fn unwind_retains_operation_and_releases_flush_owner() {
    let store = Arc::new(UncertainStore::new([Reply::Unwind]));
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue(&gov, 3, 123);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| gov.flush_metering())).is_err()
    );
    assert_eq!(requests(&gov), 1);
    assert_eq!(gov.pending_metering_totals().1.requests, 1);
    assert_eq!(gov.flush_metering_final(), 1);
    assert_eq!(requests(&gov), 1);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls[0], calls[1]);
}

#[test]
fn concurrent_flush_and_abandoned_caller_leave_one_replay_owner() {
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let store = Arc::new(UncertainStore::new([Reply::Block(
        entered.clone(),
        release.clone(),
    )]));
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    accrue(&gov, 3, 123);
    let (finished, completion) = std::sync::mpsc::channel();
    let held = {
        let gov = gov.clone();
        std::thread::spawn(move || finished.send(gov.flush_metering()).unwrap())
    };
    entered.wait();
    accrue(&gov, 5, 123);
    assert_eq!(
        gov.flush_metering(),
        0,
        "another caller cannot replace the active operation"
    );
    assert_eq!(gov.pending_metering_totals().1.requests, 2);
    let final_flush = {
        let gov = gov.clone();
        std::thread::spawn(move || gov.flush_metering_final())
    };
    drop(held);
    release.wait();
    assert_eq!(completion.recv().unwrap(), 0);
    assert_eq!(final_flush.join().unwrap(), 2);
    assert_eq!(requests(&gov), 2);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls[0], calls[1]);
    assert_ne!(calls[0].0, calls[2].0);
}

#[test]
fn acknowledged_independent_operations_each_apply_and_empty_flush_is_noop() {
    let store = Arc::new(UncertainStore::new([]));
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering(), 1);
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering_final(), 1);
    assert_eq!(requests(&gov), 2);
    assert_eq!(gov.flush_metering(), 0);
    let calls = store.calls.lock().unwrap();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1, calls[1].1);
    assert_ne!(calls[0].0, calls[1].0);
}

#[test]
fn final_flush_reentry_does_not_wait_for_itself_or_change_the_operation() {
    let store = Arc::new(UncertainStore::new([]));
    let gov = Arc::new(GovState::new(store.clone(), None).unwrap());
    *store.reenter.lock().unwrap() = Some(Arc::downgrade(&gov));
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering_final(), 1);
    assert_eq!(requests(&gov), 1);
    assert_eq!(store.calls.lock().unwrap().len(), 1);
}

#[test]
fn legacy_implementation_keeps_its_successful_ordinary_add_path() {
    let mut legacy = UncertainStore::new([]);
    legacy.supported = false;
    let store = Arc::new(legacy);
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering(), 1);
    assert_eq!(requests(&gov), 1);
    assert_eq!(store.legacy_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn repeated_unknowns_retain_one_snapshot_and_coalesce_fresh_pending_separately() {
    let store = Arc::new(UncertainStore::new(
        std::iter::once(Reply::Lost).chain(std::iter::repeat_with(|| Reply::Unknown).take(8)),
    ));
    let gov = GovState::new(store.clone(), None).unwrap();
    accrue(&gov, 3, 123);
    assert_eq!(gov.flush_metering(), 0);
    for _ in 0..8 {
        accrue(&gov, 5, 123);
        assert_eq!(gov.flush_metering(), 0);
        assert_eq!(gov.pending_metering_totals().0, 2);
    }
    let calls = store.calls.lock().unwrap().clone();
    assert!(calls.iter().all(|call| call == &calls[0]));
    assert_eq!(gov.pending_metering_totals().1.requests, 9);
    assert_eq!(gov.flush_metering(), 1);
    assert_eq!(gov.flush_metering(), 1);
    assert_eq!(requests(&gov), 9);
}

#[test]
fn expired_unknown_metering_is_not_replayed_by_periodic_or_final_flush() {
    let store = Arc::new(UncertainStore::new([Reply::Lost, Reply::Unknown]));
    let gov = GovState::new(store.clone(), None).unwrap();
    let era = RawRateEra::entry(0, EntryId::parse_hex("050505050505050505050505").unwrap());
    accrue_raw(&gov, 3, era);
    assert_eq!(gov.flush_metering(), 0);
    assert_eq!(gov.flush_metering(), 0);
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
                gov.flush_metering_final()
            } else {
                gov.flush_metering()
            },
            0
        );
        assert_eq!(
            store.calls.lock().unwrap().len(),
            2,
            "expired ids never cross the Store"
        );
        assert_eq!(
            requests(&gov),
            1,
            "the possibly committed body is never applied twice"
        );
        let (cells, counts) = gov.pending_metering_totals();
        assert_eq!((cells, counts.requests, counts.tokens_input), (2, 2, 8));
    }
    assert_eq!(
        first.1[0].pricing_version,
        era.entry_id.unwrap().metering_version()
    );
    assert_eq!(store.legacy_calls.load(Ordering::SeqCst), 0);
}
