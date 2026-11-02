//! A STORE'S RECORD SLOTS, IN THE TEST: the configured store as the root's journal reaches it
//! (`StoreCalls::record_put` / `record_get` / `record_scan`), over a map the test holds, so two books
//! built over one `RecordSlots` are one deployment restarted over one store. It counts the puts it
//! took and can be told to REFUSE them, which is how a store that has the slots but will not take a
//! write is posed. It keeps the single-use claims `redeem_plane_token` takes (the one atomic step a
//! minting boot races on), and a test can redeem one first as another node would. It can be told to
//! FAIL its scans, which is how a store that stops reading the journal back is posed. It can run a
//! PROBE at each scan, on the thread that scans, which is how a test looks at what the node holds
//! while the store is read. Every other slot answers FAILED: the journal must not reach them.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Waker};

use busbar_contract::abi::sdk::store::conditional::{Decision, Expected, Mutation, Request};
use busbar_contract::abi::store::OpId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{MeteringDelta, PlaneRecordRef, PlaneSelector, UsageDelta};
use busbar_contract::store_calls::{StoreCall, StoreCalls, StoreFailure};

/// The rows the double keeps: `(schema, key)` to the bytes.
type Rows = BTreeMap<(String, Vec<u8>), RecordBytes>;

/// The single-use claims the double has taken: `(kind, token)` to the instant each lapses.
type Claims = BTreeMap<(String, String), u64>;

/// What a test runs at each scan, on the thread that scans.
type ScanProbe = Arc<Mutex<Option<Arc<dyn Fn() + Send + Sync>>>>;

type PutProbe = Arc<Mutex<Option<Arc<dyn Fn() -> Option<StoreFailure> + Send + Sync>>>>;
type TransactionProbe =
    Arc<Mutex<Option<Arc<dyn Fn(&Request) -> Option<StoreFailure> + Send + Sync>>>>;

/// The double. Cheap to clone; every clone is the same store.
#[derive(Clone, Default)]
pub(crate) struct RecordSlots {
    rows: Arc<Mutex<Rows>>,
    claims: Arc<Mutex<Claims>>,
    refusing: Arc<AtomicBool>,
    unreadable: Arc<AtomicBool>,
    /// `0`: no budget. `n + 1`: take `n` more puts, then refuse every one after.
    budget: Arc<AtomicUsize>,
    puts: Arc<AtomicUsize>,
    probe: ScanProbe,
    put_probe: PutProbe,
    /// Keep every put and answer it FAILED: a store that committed and lost the ack.
    lost_acks: Arc<AtomicBool>,
    /// Calls remain genuinely Pending until the test releases them.
    paused: Arc<AtomicBool>,
    parked: Arc<Mutex<Vec<Waker>>>,
    receipts: Arc<Mutex<BTreeMap<[u8; 16], Request>>>,
    transaction_probe: TransactionProbe,
}

impl RecordSlots {
    /// An empty store that takes every put.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The same store as the root's journal reaches it.
    pub(crate) fn calls(&self) -> Arc<dyn StoreCalls> {
        Arc::new(self.clone())
    }

    /// Before the atomic transaction, outside every fixture lock. Tests can delay a particular
    /// immutable candidate while another writer changes its predicates.
    pub(crate) fn on_transaction(
        &self,
        probe: impl Fn(&Request) -> Option<StoreFailure> + Send + Sync + 'static,
    ) {
        *self
            .transaction_probe
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(probe));
    }

    /// Pause or release Store futures. Wake outside the fixture lock, as a backend completion does.
    pub(crate) fn pause(&self, paused: bool) {
        self.paused.store(paused, Ordering::Release);
        if !paused {
            let parked =
                std::mem::take(&mut *self.parked.lock().unwrap_or_else(|p| p.into_inner()));
            for waker in parked {
                waker.wake();
            }
        }
    }

    /// How many calls reached Pending and registered a wakeup.
    pub(crate) fn waiting(&self) -> usize {
        self.parked.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    async fn ready(&self) {
        std::future::poll_fn(|cx| {
            if !self.paused.load(Ordering::Acquire) {
                return Poll::Ready(());
            }
            let waker = cx.waker().clone();
            self.parked
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(waker);
            if self.paused.load(Ordering::Acquire) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }

    /// From now on, refuse (`true`) or take (`false`) every put.
    pub(crate) fn refuse(&self, refusing: bool) {
        self.budget.store(0, Ordering::Release);
        self.refusing.store(refusing, Ordering::Release);
    }

    /// From now on, fail (`true`) or answer (`false`) every scan: the store stops reading the
    /// journal back, as a remote store failing over does.
    pub(crate) fn fail_reads(&self, failing: bool) {
        self.unreadable.store(failing, Ordering::Release);
    }

    /// From now on, run `probe` at the start of every scan, on the thread that scans.
    pub(crate) fn on_scan(&self, probe: impl Fn() + Send + Sync + 'static) {
        *self.probe.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(probe));
    }

    /// Run before a put, without holding any fixture lock.
    pub(crate) fn on_put(&self, probe: impl Fn() -> Option<StoreFailure> + Send + Sync + 'static) {
        *self.put_probe.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(probe));
    }

    /// Take the next `n` puts, then refuse every one after until [`Self::refuse`] says otherwise:
    /// a store that answers no more partway through a record's parts.
    pub(crate) fn take_then_refuse(&self, n: usize) {
        self.budget.store(n.saturating_add(1), Ordering::Release);
    }

    /// Whether this put is refused: refusing outright, or past the budget.
    fn refuses_put(&self) -> bool {
        self.refusing.load(Ordering::Acquire)
            || self
                .budget
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |b| match b {
                    0 => None,
                    1 => Some(1),
                    b => Some(b - 1),
                })
                == Ok(1)
    }

    /// From now on, keep every put and answer it FAILED (`true`), or answer as usual (`false`):
    /// the write landed and the ack was lost, so the writer cannot tell.
    pub(crate) fn lose_acks(&self, losing: bool) {
        self.lost_acks.store(losing, Ordering::Release);
    }

    /// How many puts the store took.
    pub(crate) fn puts(&self) -> usize {
        self.puts.load(Ordering::Acquire)
    }

    /// Flip the last byte of the row at `(schema, key)`: an edit made to the store behind the node.
    pub(crate) fn corrupt(&self, schema: &str, key: &[u8]) {
        let mut rows = self.rows.lock().unwrap_or_else(|p| p.into_inner());
        let at = (schema.to_string(), key.to_vec());
        let row = rows.get(&at).expect("the row is there").as_slice().to_vec();
        let mut edited = row;
        if let Some(last) = edited.last_mut() {
            *last ^= 0xff;
        }
        rows.insert(at, RecordBytes::new(edited).expect("the same length"));
    }

    /// Redeem the single-use claim `(kind, token)` as another node would, until `expires_at`:
    /// `true` when this was its first redemption.
    pub(crate) fn redeem(&self, kind: &str, token: &str, expires_at: u64, now: u64) -> bool {
        let mut claims = self.claims.lock().unwrap_or_else(|p| p.into_inner());
        claims.retain(|_, lapses| *lapses > now);
        claims
            .insert((kind.to_string(), token.to_string()), expires_at)
            .is_none()
    }

    /// Keep `value` at `(schema, key)` as another node's write would.
    pub(crate) fn put_row(&self, schema: &str, key: &[u8], value: &[u8]) {
        self.rows.lock().unwrap_or_else(|p| p.into_inner()).insert(
            (schema.to_string(), key.to_vec()),
            RecordBytes::new(value.to_vec()).expect("a test row fits a slot"),
        );
    }

    /// How many rows the store holds under `schema`.
    pub(crate) fn rows_under(&self, schema: &str) -> usize {
        self.rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .filter(|(s, _)| s == schema)
            .count()
    }
}

/// A slot the journal must not reach.
fn not_this<'a, T: Send + 'a>() -> StoreCall<'a, T> {
    Box::pin(async { Err(StoreFailure::Failed("not a journal slot".to_string())) })
}

impl StoreCalls for RecordSlots {
    fn supports_record_transaction(&self) -> bool {
        true
    }

    fn record_transaction<'a>(&'a self, request: &'a Request) -> StoreCall<'a, Decision> {
        Box::pin(async move {
            self.ready().await;
            request
                .validate()
                .map_err(|why| StoreFailure::Refused(why.into()))?;
            let probe = self
                .transaction_probe
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(why) = probe.and_then(|probe| probe(request)) {
                return Err(why);
            }
            let probe = self
                .put_probe
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(why) = probe.and_then(|probe| probe()) {
                return Err(why);
            }
            let mut receipts = self.receipts.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(kept) = receipts.get(&request.op_id.0) {
                return if kept == request {
                    Ok(Decision::Applied)
                } else {
                    Err(StoreFailure::Conflict)
                };
            }
            if self.refuses_put() {
                return Err(StoreFailure::Refused(
                    "the test store refuses writes".into(),
                ));
            }
            let mut rows = self.rows.lock().unwrap_or_else(|p| p.into_inner());
            for p in &request.predicates {
                let got = rows.get(&(p.schema.clone(), p.key.clone()));
                let matches = match &p.expected {
                    Expected::Absent => got.is_none(),
                    Expected::Bytes(bytes) => got.is_some_and(|v| v.as_slice() == bytes.as_slice()),
                };
                if !matches {
                    return Ok(Decision::ConditionConflict);
                }
            }
            for m in &request.mutations {
                match m {
                    Mutation::Put { schema, key, value } => {
                        rows.insert(
                            (schema.clone(), key.clone()),
                            RecordBytes::new(value.clone()).expect("validated transaction"),
                        );
                        self.puts.fetch_add(1, Ordering::AcqRel);
                    }
                    Mutation::Delete { schema, key } => {
                        rows.remove(&(schema.clone(), key.clone()));
                    }
                    Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => rows.retain(|(s, key), _| {
                        s != schema
                            || !key.starts_with(prefix)
                            || key.len() as u64 != *exact_key_length
                    }),
                }
            }
            receipts.insert(request.op_id.0, request.clone());
            if self.lost_acks.load(Ordering::Acquire) {
                Err(StoreFailure::Failed(
                    "the test store lost the transaction ack".into(),
                ))
            } else {
                Ok(Decision::Applied)
            }
        })
    }
    fn add_usage_batch<'a>(
        &'a self,
        _: OpId,
        _: &'a [(&'a str, u64, UsageDelta)],
    ) -> StoreCall<'a, ()> {
        not_this()
    }
    fn add_metering_batch<'a>(&'a self, _: OpId, _: &'a [MeteringDelta]) -> StoreCall<'a, ()> {
        not_this()
    }
    fn record_put<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
        value: &'a RecordBytes,
    ) -> StoreCall<'a, ()> {
        Box::pin(async move {
            self.ready().await;
            let probe = self
                .put_probe
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            if let Some(failure) = probe.and_then(|probe| probe()) {
                return Err(failure);
            }
            let refused = self.refuses_put();
            if !refused {
                self.rows
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .insert((schema.to_string(), key.to_vec()), value.clone());
                self.puts.fetch_add(1, Ordering::AcqRel);
            }
            let lost = self.lost_acks.load(Ordering::Acquire);
            if refused {
                Err(StoreFailure::Refused(
                    "the test store refuses writes".to_string(),
                ))
            } else if lost {
                Err(StoreFailure::Failed(
                    "the test store lost the ack".to_string(),
                ))
            } else {
                Ok(())
            }
        })
    }
    fn record_get<'a>(
        &'a self,
        schema: &'a str,
        key: &'a [u8],
    ) -> StoreCall<'a, Option<RecordBytes>> {
        let got = self
            .rows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(schema.to_string(), key.to_vec()))
            .cloned();
        Box::pin(async move { Ok(got) })
    }
    fn record_scan<'a>(
        &'a self,
        schema: &'a str,
        prefix: &'a [u8],
        limit: u32,
    ) -> StoreCall<'a, Vec<(Vec<u8>, RecordBytes)>> {
        Box::pin(async move {
            self.ready().await;
            // Taken out of the lock before it runs, so a probe that waits on another scanning thread
            // (a barrier) does not hold every other scan behind it.
            let probe = self.probe.lock().unwrap_or_else(|p| p.into_inner()).clone();
            if let Some(probe) = probe {
                probe();
            }
            if self.unreadable.load(Ordering::Acquire) {
                return Err(StoreFailure::Failed(
                    "the test store will not read".to_string(),
                ));
            }
            let rows: Vec<(Vec<u8>, RecordBytes)> = self
                .rows
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .iter()
                .filter(|((s, k), _)| s == schema && k.starts_with(prefix))
                .take(limit as usize)
                .map(|((_, k), v)| (k.clone(), v.clone()))
                .collect();
            Ok(rows)
        })
    }
    fn upsert_plane_record<'a>(&'a self, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        not_this()
    }
    fn get_plane_record<'a>(&'a self, _: &'a str, _: &'a str) -> StoreCall<'a, Option<Vec<u8>>> {
        not_this()
    }
    fn append_plane_record<'a>(&'a self, _: OpId, _: PlaneRecordRef<'a>) -> StoreCall<'a, ()> {
        not_this()
    }
    fn list_plane_records<'a>(
        &'a self,
        _: &'a str,
        _: &'a PlaneSelector<'a>,
    ) -> StoreCall<'a, Vec<Vec<u8>>> {
        not_this()
    }
    fn delete_plane_record<'a>(&'a self, _: &'a str, _: &'a str) -> StoreCall<'a, ()> {
        not_this()
    }
    fn redeem_plane_token<'a>(
        &'a self,
        kind: &'a str,
        token: &'a str,
        expires_at: u64,
        now: u64,
    ) -> StoreCall<'a, bool> {
        let first = self.redeem(kind, token, expires_at, now);
        Box::pin(async move { Ok(first) })
    }
    fn plane_token_live<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: u64,
        _: u64,
    ) -> StoreCall<'a, bool> {
        not_this()
    }
}
