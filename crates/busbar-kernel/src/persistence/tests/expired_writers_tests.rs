// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHUTDOWN-HANG 8.14 at kernel level: F5's scan, its one closer, the lease delete and the
//! `shutdown.drain_incomplete` record, over a store double with a controllable store clock and
//! real fence semantics (control rows, `Exact` predicates, the store's own time guard). The double
//! is shared with 8.15 (`fence_settle_tests`). Each test owns fresh random writer ids, and asserts
//! on its own targets only: the record ledger and the admin audit queue are process-wide.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use busbar_contract::persistence::{
    control, Address, BackendInfo, Call, ClockObservation, CommitKey, DatasetId, Decision,
    Durability, ExpectedValue, Failure, Mutation, Page, PersistenceBackend, PreparedCandidate,
    Read, ReadResult, Scan, TimeGuard,
};
use busbar_contract::Secret;

use super::{
    host_key, undrained_records, writer_lease_key, Assignment, LeaseRow, ObservedBy,
    PredecessorFence, TestHold, UndrainedWriter, WriterRetirement, WriterRetirements,
    EXPIRED_PASS_MAX, INSTANCE, LEASE_TTL_MS, NODE_SCHEMA,
};
use crate::persistence::facade::{CoreStore, Limits, WriterAuthority};
use crate::persistence::undrained::Placement;

pub(super) const DATASET: DatasetId = DatasetId([1; 16]);
const CLOCK_AUTHORITY: [u8; 16] = [3; 16];
/// Every writer in the double shares the dataset's one writer epoch, as a real store's do.
pub(super) const EPOCH: u64 = 1;
/// The writer this process's own CoreStore attaches as.
pub(super) const OWN: [u8; 16] = [4; 16];
/// A registered writer that never retired: its row still admits execution epoch 1.
pub(super) const OPEN: control::Writer = control::Writer {
    retired_through: 0,
    admitted_through: 1,
};
/// A gracefully retired writer: `retired_through == admitted_through`.
pub(super) const RETIRED: control::Writer = control::Writer {
    retired_through: 1,
    admitted_through: 1,
};
/// The one closer's permanent fence.
pub(super) const CLOSED: control::Writer = control::Writer {
    retired_through: u64::MAX,
    admitted_through: u64::MAX,
};

pub(super) type Rows = BTreeMap<Address, Secret<Vec<u8>>>;
/// Runs inside the next fence commit, after its time guard and before its predicates.
pub(super) type FenceHook = Box<dyn FnOnce(&mut Rows) + Send>;

#[derive(Default)]
struct State {
    rows: Rows,
    generations: BTreeMap<[u8; 16], u64>,
    receipts: BTreeMap<[u8; 16], [u8; 32]>,
    sent: Vec<PreparedCandidate>,
    /// Applied fence Puts, by control address.
    fences: BTreeMap<Address, usize>,
    /// Applied Deletes, by address.
    deletes: BTreeMap<Address, usize>,
}

impl State {
    fn value(&self, at: &Address) -> Option<Secret<Vec<u8>>> {
        if at.namespace == control::GENERATION_NAMESPACE.0 {
            let namespace = <[u8; 16]>::try_from(at.key.as_slice()).ok()?;
            return self
                .generations
                .get(&namespace)
                .filter(|generation| **generation != 0)
                .map(|generation| Secret::new(generation.to_le_bytes().to_vec()));
        }
        self.rows.get(at).cloned()
    }

    fn bump(&mut self, namespace: [u8; 16]) {
        *self.generations.entry(namespace).or_default() += 1;
    }
}

/// One store several CoreStores attach to (one per simulated process). Fence commits can be
/// held, refused, answered `Unknown` after applying, or mutated in flight; scans can be held at
/// a barrier after their snapshot is taken.
#[derive(Default)]
pub(super) struct Store {
    state: Mutex<State>,
    /// The store clock, unix seconds.
    pub(super) now: AtomicU64,
    /// Seconds added to read and clock observations only, never to a commit's time guard.
    pub(super) observe_ahead: AtomicU64,
    pub(super) refuse_fences: AtomicBool,
    pub(super) lose_fence_reply: AtomicBool,
    hold_fence: Mutex<Option<Arc<TestHold>>>,
    before_fence: Mutex<Option<FenceHook>>,
    scan_barrier: Mutex<Option<Arc<tokio::sync::Barrier>>>,
}

pub(super) fn root_address() -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    }
}

pub(super) fn control_address(writer: [u8; 16]) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key(writer).to_vec(),
    }
}

pub(super) fn node_address(key: &[u8]) -> Address {
    crate::persistence::scoped::migration_address(true, INSTANCE, NODE_SCHEMA, key).unwrap()
}

pub(super) fn lease_address(writer: [u8; 16]) -> Address {
    node_address(&writer_lease_key(EPOCH, writer))
}

pub(super) fn lease_bytes(writer: [u8; 16], expires_ms: u64) -> Vec<u8> {
    LeaseRow {
        holder: writer,
        expires_ms,
    }
    .bytes()
}

/// The control row a fence candidate Puts, if it is one.
pub(super) fn fence_target(candidate: &PreparedCandidate) -> Option<Address> {
    candidate
        .candidate()
        .mutations
        .iter()
        .find_map(|mutation| match mutation {
            Mutation::Put { address, .. }
                if address.namespace == control::NAMESPACE.0
                    && address.key != control::DATASET_KEY =>
            {
                Some(address.clone())
            }
            _ => None,
        })
}

impl Store {
    pub(super) fn new() -> Arc<Self> {
        let store = Arc::new(Self::default());
        store.put(
            root_address(),
            control::Dataset {
                id: DATASET,
                writer_epoch: EPOCH,
            }
            .encode()
            .unwrap()
            .to_vec(),
        );
        store.admit(OWN);
        store
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn put(&self, address: Address, bytes: Vec<u8>) {
        let mut state = self.lock();
        state.bump(address.namespace);
        state.rows.insert(address, Secret::new(bytes));
    }

    /// Registers `writer` as an open writer (another process's own CoreStore).
    pub(super) fn admit(&self, writer: [u8; 16]) {
        self.put(control_address(writer), OPEN.encode().unwrap().to_vec());
    }

    /// A writer that never retired: open row, a lease row and one host assignment.
    pub(super) fn open_writer(&self, writer: [u8; 16], expires_ms: u64, host: &str, node: u64) {
        self.admit(writer);
        self.put_lease(writer, expires_ms);
        self.put_assignment(writer, host, node);
    }

    /// A gracefully retired writer whose lease row was left behind.
    pub(super) fn retired_writer(&self, writer: [u8; 16], expires_ms: u64, host: &str, node: u64) {
        self.put(control_address(writer), RETIRED.encode().unwrap().to_vec());
        self.put_lease(writer, expires_ms);
        self.put_assignment(writer, host, node);
    }

    pub(super) fn put_lease(&self, writer: [u8; 16], expires_ms: u64) {
        self.put(lease_address(writer), lease_bytes(writer, expires_ms));
    }

    fn put_assignment(&self, writer: [u8; 16], host: &str, node: u64) {
        self.put(
            node_address(&host_key(host)),
            Assignment {
                id: node,
                epoch: EPOCH,
                writer,
            }
            .bytes(),
        );
    }

    pub(super) fn put_node_row(&self, key: &[u8], value: Vec<u8>) {
        self.put(node_address(key), value);
    }

    pub(super) fn node_row(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.row(&node_address(key))
    }

    fn row(&self, at: &Address) -> Option<Vec<u8>> {
        self.lock()
            .rows
            .get(at)
            .map(|value| value.expose(&crate::seal::lend()).clone())
    }

    pub(super) fn control(&self, writer: [u8; 16]) -> Option<control::Writer> {
        self.row(&control_address(writer))
            .and_then(|bytes| control::Writer::decode(&bytes))
    }

    pub(super) fn lease(&self, writer: [u8; 16]) -> Option<Vec<u8>> {
        self.row(&lease_address(writer))
    }

    /// How many fences applied to `writer`'s control row.
    pub(super) fn fence_applies(&self, writer: [u8; 16]) -> usize {
        self.lock()
            .fences
            .get(&control_address(writer))
            .copied()
            .unwrap_or(0)
    }

    /// How many deletes of `writer`'s lease row applied.
    pub(super) fn lease_deletes(&self, writer: [u8; 16]) -> usize {
        self.lock()
            .deletes
            .get(&lease_address(writer))
            .copied()
            .unwrap_or(0)
    }

    /// Every fence candidate sent, in order.
    pub(super) fn fence_candidates(&self) -> Vec<PreparedCandidate> {
        self.lock()
            .sent
            .iter()
            .filter(|candidate| fence_target(candidate).is_some())
            .cloned()
            .collect()
    }

    /// Holds the next fence commit unanswered until `hold.release`.
    pub(super) fn hold_next_fence(&self, hold: Arc<TestHold>) {
        *self.hold_fence.lock().unwrap_or_else(|p| p.into_inner()) = Some(hold);
    }

    pub(super) fn before_next_fence(&self, hook: FenceHook) {
        *self.before_fence.lock().unwrap_or_else(|p| p.into_inner()) = Some(hook);
    }

    /// Every scan from now on returns only once `parties` scans have taken their snapshot.
    pub(super) fn barrier_scans(&self, parties: usize) {
        *self.scan_barrier.lock().unwrap_or_else(|p| p.into_inner()) =
            Some(Arc::new(tokio::sync::Barrier::new(parties)));
    }

    fn armed_hold(&self) -> Option<Arc<TestHold>> {
        self.hold_fence
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    fn armed_hook(&self) -> Option<FenceHook> {
        self.before_fence
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
    }

    fn armed_barrier(&self) -> Option<Arc<tokio::sync::Barrier>> {
        self.scan_barrier
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn observed(&self) -> ClockObservation {
        ClockObservation {
            authority: CLOCK_AUTHORITY,
            unix_seconds: self.now.load(Ordering::SeqCst)
                + self.observe_ahead.load(Ordering::SeqCst),
        }
    }

    fn page(&self, request: &Scan) -> Result<Page, Failure> {
        let state = self.lock();
        let generation = state
            .generations
            .get(&request.namespace.0)
            .copied()
            .unwrap_or(0);
        if request.generation.is_some_and(|seen| seen != generation) {
            return Err(Failure::StaleScan);
        }
        let seal = crate::seal::lend();
        let mut rows: Vec<(Address, Secret<Vec<u8>>)> = Vec::new();
        let mut bytes = 0;
        let mut more = false;
        for (at, value) in &state.rows {
            if at.namespace != request.namespace.0
                || !at.key.starts_with(&request.prefix)
                || request.after.as_ref().is_some_and(|after| at.key <= *after)
            {
                continue;
            }
            let size = at.key.len() + value.expose(&seal).len();
            if rows.len() == request.max_items || bytes + size > request.max_bytes {
                more = true;
                break;
            }
            bytes += size;
            rows.push((at.clone(), value.clone()));
        }
        let next = if more {
            rows.last().map(|(at, _)| at.key.clone())
        } else {
            None
        };
        Ok(Page {
            generation,
            rows,
            next,
        })
    }

    fn decide(&self, prepared: &PreparedCandidate, fence: bool) -> Result<Decision, Failure> {
        let hook = if fence { self.armed_hook() } else { None };
        let mut state = self.lock();
        let candidate = prepared.candidate();
        if let Some(digest) = state.receipts.get(&candidate.id.operation) {
            return Ok(if *digest == prepared.fingerprint() {
                Decision::Applied(candidate.result.clone())
            } else {
                Decision::OpIdConflict
            });
        }
        if fence && self.refuse_fences.load(Ordering::SeqCst) {
            return Err(Failure::Refused);
        }
        let seal = crate::seal::lend();
        let root = state
            .rows
            .get(&root_address())
            .and_then(|value| control::Dataset::decode(value.expose(&seal)));
        let writer = state
            .rows
            .get(&control_address(candidate.id.writer))
            .and_then(|value| control::Writer::decode(value.expose(&seal)));
        if !(root.is_some_and(|root| root.writer_epoch == candidate.id.writer_epoch)
            && writer.is_some_and(|writer| writer.admits(candidate.id.execution_epoch)))
        {
            return Ok(Decision::Fenced);
        }
        let now = self.now.load(Ordering::SeqCst);
        if candidate.time.is_some_and(|guard| !guard.permits(now)) {
            return Ok(Decision::TimeGuardFailed {
                observed_at: ClockObservation {
                    authority: CLOCK_AUTHORITY,
                    unix_seconds: now,
                },
            });
        }
        if let Some(hook) = hook {
            hook(&mut state.rows);
        }
        for predicate in &candidate.predicates {
            let found = state.value(&predicate.address);
            let holds = match &predicate.expected {
                ExpectedValue::Absent => found.is_none(),
                ExpectedValue::Exact(bytes) => found.as_ref() == Some(bytes),
            };
            if !holds {
                return Ok(Decision::ConditionConflict);
            }
        }
        for mutation in &candidate.mutations {
            match mutation {
                Mutation::Put { address, value } => {
                    state.bump(address.namespace);
                    if fence && address.namespace == control::NAMESPACE.0 {
                        *state.fences.entry(address.clone()).or_default() += 1;
                    }
                    state.rows.insert(address.clone(), value.clone());
                }
                Mutation::Delete(address) => {
                    state.bump(address.namespace);
                    *state.deletes.entry(address.clone()).or_default() += 1;
                    state.rows.remove(address);
                }
                Mutation::DeleteRange {
                    namespace,
                    prefix,
                    exact_key_length,
                } => {
                    state.bump(namespace.0);
                    state.rows.retain(|at, _| {
                        !(at.namespace == namespace.0
                            && at.key.starts_with(prefix)
                            && at.key.len() as u64 == *exact_key_length)
                    });
                }
            }
        }
        state
            .receipts
            .insert(candidate.id.operation, prepared.fingerprint());
        if fence && self.lose_fence_reply.swap(false, Ordering::SeqCst) {
            return Err(Failure::Unknown);
        }
        Ok(Decision::Applied(candidate.result.clone()))
    }
}

impl PersistenceBackend for Store {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DATASET,
            atomic_domain: [2; 16],
            clock_authority: CLOCK_AUTHORITY,
            physical_version: busbar_contract::abi::sdk::store::v4::slot::PHYSICAL_VERSION,
            durability: Durability::Local,
        }
    }

    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let observed_at = self.observed();
            if request
                .time
                .is_some_and(|guard| !guard.permits(observed_at.unix_seconds))
            {
                return Ok(ReadResult::TimeGuardFailed { observed_at });
            }
            let state = self.lock();
            Ok(ReadResult::Values {
                observed_at,
                values: request.addresses.iter().map(|at| state.value(at)).collect(),
            })
        })
    }

    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            let page = self.page(&request)?;
            if let Some(barrier) = self.armed_barrier() {
                barrier.wait().await;
            }
            Ok(page)
        })
    }

    fn commit(&self, prepared: PreparedCandidate, _key: CommitKey) -> Call<'_, Decision> {
        let fence = fence_target(&prepared).is_some();
        let hold = if fence { self.armed_hold() } else { None };
        self.lock().sent.push(prepared.clone());
        Box::pin(async move {
            if let Some(hold) = hold {
                hold.pass().await;
            }
            self.decide(&prepared, fence)
        })
    }

    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async move { Ok(self.observed()) })
    }
}

/// One simulated process's CoreStore over `store`, writing as `writer`.
pub(super) async fn attach(store: &Arc<Store>, writer: [u8; 16]) -> Arc<CoreStore> {
    let backend: Arc<dyn PersistenceBackend> = store.clone();
    Arc::new(
        CoreStore::attach(
            backend,
            WriterAuthority {
                writer_epoch: EPOCH,
                writer,
                execution_epoch: 1,
            },
            Limits {
                pending_operations: 64,
                conflict_retries: 1,
                // One page holds the whole NODE_SCHEMA of every test here.
                scan_items: 4096,
                scan_bytes: 1 << 22,
            },
        )
        .await
        .unwrap(),
    )
}

pub(super) fn writer_id() -> [u8; 16] {
    let mut id = [0; 16];
    while id == [0; 16] || id == OWN {
        busbar_contract::crypto::fill(&mut id).unwrap();
    }
    id
}

/// What F5 builds for a writer with one assignment on another host.
pub(super) fn seen(
    writer: [u8; 16],
    host: &str,
    node: u64,
    observed_by: ObservedBy,
) -> UndrainedWriter {
    UndrainedWriter {
        node: Some(node),
        other_nodes: Vec::new(),
        epoch: EPOCH,
        writer,
        host: Some(host.into()),
        observed_by,
    }
}

pub(super) fn placement(writer: [u8; 16]) -> Placement {
    undrained_records().placement((EPOCH, writer))
}

/// Offered exactly once: recorded, or (queue full) refused and held, never both, never retained.
fn assert_offered_once(writer: [u8; 16]) {
    let placement = placement(writer);
    assert!(
        placement.recorded.is_some() != placement.record_failed
            && !placement.retained
            && !placement.unconfirmed,
        "{placement:?}"
    );
}

pub(super) async fn reached(hold: &TestHold) {
    tokio::time::timeout(Duration::from_secs(10), hold.reached.notified())
        .await
        .expect("the held step is reached");
}

pub(super) async fn until(what: &str, mut done: impl FnMut() -> bool) {
    for _ in 0..1000 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Drains the admin audit queue through the native owner (installed by the caller with
/// `ensure_global_audit_stream_registered`), then every `shutdown.drain_incomplete` row in the
/// audit log, by writer hex.
pub(super) async fn durable_records() -> BTreeMap<String, Vec<String>> {
    assert!(
        crate::audit::auditlog::flush_pending().await.is_ok(),
        "the admin audit queue drains"
    );
    let mut by_writer: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in crate::audit::auditlog::AUDIT_LOG.list_filtered(
        0,
        usize::MAX,
        Some("shutdown.drain_incomplete"),
        None,
    ) {
        let writer = entry
            .resource
            .split_once("writer=")
            .map(|(_, rest)| rest.split(' ').next().unwrap_or_default().to_string());
        if let Some(writer) = writer {
            by_writer.entry(writer).or_default().push(entry.resource);
        }
    }
    by_writer
}

pub(super) fn records_for(records: &BTreeMap<String, Vec<String>>, writer: [u8; 16]) -> usize {
    records.get(&hex::encode(writer)).map_or(0, Vec::len)
}

fn stop_flag() -> (
    tokio::sync::watch::Sender<bool>,
    tokio::sync::watch::Receiver<bool>,
) {
    tokio::sync::watch::channel(false)
}

/// 8.14: a live writer renewing every 3 s while F5 runs 100 times elsewhere is never closed. The
/// scan already excludes a lease that has not been expired for one TTL, so it never reaches the
/// closer (`skipped_live` counts only a renewal that races the close: see the renewal test).
#[tokio::test]
async fn a_live_writer_renewing_every_3_s_is_never_closed() {
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, "f5-host").unwrap();
    let live = writer_id();
    store.now.store(1_000, Ordering::SeqCst);
    store.open_writer(live, 1_000_000 + LEASE_TTL_MS, "live-host", 11);
    let (_stop_tx, stop) = stop_flag();
    for _ in 0..100 {
        let pass = fence.run(stop.clone()).await;
        assert_eq!(
            (pass.closed, pass.invalid, pass.remaining),
            (0, 0, 0),
            "{pass:?}"
        );
        let now = store.now.fetch_add(3, Ordering::SeqCst) + 3;
        store.put_lease(live, now * 1_000 + LEASE_TTL_MS);
    }
    assert_eq!(store.control(live), Some(OPEN));
    assert_eq!(store.fence_applies(live), 0);
    assert!(store.lease(live).is_some());
    assert_eq!(placement(live), Placement::default());
}

/// 8.14: a lease expired 8 s ago is `Live` (not closed); at 9 s, and at 30 s, it is closed.
#[tokio::test]
async fn a_lease_expired_8_s_is_live_and_one_expired_9_s_is_closed() {
    let store = Store::new();
    let core = attach(&store, OWN).await;
    let fence = PredecessorFence::new(core.clone(), "f5-host").unwrap();
    let (at_8s, at_30s) = (writer_id(), writer_id());
    store.open_writer(at_8s, 100_000, "host-8s", 21);
    store.open_writer(at_30s, 79_000, "host-30s", 22);
    store.now.store(108, Ordering::SeqCst);
    // The one closer agrees with the scan: closable at expiry plus one TTL.
    let probe = WriterRetirements::default();
    assert!(matches!(
        probe
            .retire_after(&core, EPOCH, at_8s, LEASE_TTL_MS, None)
            .await,
        Ok(WriterRetirement::Live {
            retry_at_ms: 109_000
        })
    ));
    let (_stop_tx, stop) = stop_flag();
    let first = fence.run(stop.clone()).await;
    assert_eq!((first.closed, first.skipped_live), (1, 0), "{first:?}");
    assert_eq!(store.control(at_8s), Some(OPEN));
    assert_eq!(store.fence_applies(at_8s), 0);
    assert!(store.lease(at_8s).is_some());
    assert_eq!(placement(at_8s), Placement::default());
    assert_eq!(store.control(at_30s), Some(CLOSED));
    assert_eq!(store.lease_deletes(at_30s), 1);
    assert!(store.lease(at_30s).is_none());
    assert_offered_once(at_30s);

    store.now.store(109, Ordering::SeqCst);
    let second = fence.run(stop).await;
    assert_eq!((second.closed, second.skipped_live), (1, 0), "{second:?}");
    assert_eq!(store.control(at_8s), Some(CLOSED));
    assert_eq!(store.fence_applies(at_8s), 1);
    assert_eq!(store.lease_deletes(at_8s), 1);
    assert!(store.lease(at_8s).is_none());
    assert_offered_once(at_8s);
    assert_eq!(store.fence_applies(at_30s), 1, "closed once, never again");
}

/// 8.14: the store's time guard alone refuses a close whose `not_before` is in the future. The
/// double reports reads 20 s ahead, so the in-process liveness check passes; the commit's guard,
/// evaluated at the store's own time, refuses it with no effect.
#[tokio::test]
async fn the_store_time_guard_alone_refuses_an_early_close() {
    let store = Store::new();
    let core = attach(&store, OWN).await;
    let writer = writer_id();
    store.open_writer(writer, 100_000, "host-early", 31);
    store.now.store(100, Ordering::SeqCst);
    store.observe_ahead.store(20, Ordering::SeqCst);
    let retirements = WriterRetirements::default();
    let seen = seen(writer, "host-early", 31, ObservedBy::ExpiredLeasePass);
    assert!(matches!(
        retirements
            .retire_after(&core, EPOCH, writer, LEASE_TTL_MS, Some(seen))
            .await,
        Ok(WriterRetirement::Pending)
    ));
    let sent = store.fence_candidates();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0].candidate().time,
        Some(TimeGuard {
            not_before: Some(109),
            before: None
        })
    );
    assert_eq!(store.control(writer), Some(OPEN));
    assert_eq!(store.fence_applies(writer), 0);
    assert!(store.lease(writer).is_some());
    assert_eq!(
        retirements.retained(),
        0,
        "a decided refusal is not retained"
    );
    assert!(!retirements.take_closed_open(EPOCH, writer));
    assert_eq!(placement(writer), Placement::default(), "no record");
}

/// 8.14: a renewal landing between F5's scan and its close fails the close's `Exact(lease)`; the
/// writer stays open, and the closer's next read finds it live.
#[tokio::test]
async fn a_renewal_racing_the_close_fails_its_exact_lease_predicate() {
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, "f5-host").unwrap();
    let writer = writer_id();
    store.open_writer(writer, 100_000, "host-renewing", 41);
    store.now.store(109, Ordering::SeqCst);
    let renewed = lease_bytes(writer, 109_000 + LEASE_TTL_MS);
    let (at, bytes) = (lease_address(writer), renewed.clone());
    store.before_next_fence(Box::new(move |rows: &mut Rows| {
        rows.insert(at, Secret::new(bytes));
    }));
    let (_stop_tx, stop) = stop_flag();
    let pass = fence.run(stop).await;
    assert_eq!((pass.closed, pass.skipped_live), (0, 1), "{pass:?}");
    assert_eq!(store.fence_candidates().len(), 1);
    assert_eq!(store.control(writer), Some(OPEN));
    assert_eq!(store.fence_applies(writer), 0);
    assert_eq!(store.lease(writer), Some(renewed));
    assert_eq!(fence.retained(), 0);
    assert_eq!(placement(writer), Placement::default(), "no record");
}

/// 8.14: eight processes start together, and all run F5 over the same 20 unretired writers. Each
/// is closed once, its lease row deleted once, exactly one record each (20 in all,
/// `observed_by=expired_lease_pass`), and no pass errs. The scans are held at a barrier until all
/// eight have taken their snapshot, so every pass works through all 20.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn eight_starts_close_each_of_twenty_writers_once() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let store = Store::new();
    store.now.store(1_000, Ordering::SeqCst);
    let writers: Vec<[u8; 16]> = (0..20).map(|_| writer_id()).collect();
    for (i, writer) in writers.iter().enumerate() {
        store.open_writer(*writer, 100_000, &format!("dead-{i}"), 100 + i as u64);
    }
    let mut fences = Vec::new();
    for i in 0..8u8 {
        let own = [0x40 + i; 16];
        store.admit(own);
        let core = attach(&store, own).await;
        fences.push(PredecessorFence::new(core, &format!("f5-{i}")).unwrap());
    }
    store.barrier_scans(fences.len());
    let (_stop_tx, stop) = stop_flag();
    let runs: Vec<_> = fences
        .iter()
        .map(|fence| {
            let (fence, stop) = (fence.clone(), stop.clone());
            tokio::spawn(async move { fence.run(stop).await })
        })
        .collect();
    for run in runs {
        let pass = run.await.unwrap();
        assert_eq!(
            (pass.closed, pass.skipped_live, pass.invalid, pass.remaining),
            (20, 0, 0, 0),
            "every pass saw every writer closed, with no error: {pass:?}"
        );
    }
    for fence in &fences {
        assert_eq!(fence.retained(), 0);
    }
    let records = durable_records().await;
    for writer in &writers {
        assert_eq!(store.fence_applies(*writer), 1, "closed once");
        assert_eq!(store.control(*writer), Some(CLOSED));
        assert_eq!(store.lease_deletes(*writer), 1, "lease row deleted once");
        assert!(store.lease(*writer).is_none());
        let mine = records
            .get(&hex::encode(writer))
            .map(Vec::as_slice)
            .unwrap_or_default();
        assert_eq!(mine.len(), 1, "exactly one record: {mine:?}");
        assert!(
            mine[0].contains("observed_by=expired_lease_pass"),
            "{}",
            mine[0]
        );
        let placement = placement(*writer);
        assert!(
            !placement.retained && !placement.record_failed && !placement.unconfirmed,
            "{placement:?}"
        );
    }
    let total: usize = writers
        .iter()
        .map(|writer| records_for(&records, *writer))
        .sum();
    assert_eq!(total, 20);
}

/// 8.14: a gracefully retired writer whose lease row was left is fenced and its lease row
/// deleted, with no record; a second pass finds no lease row for it and closes nothing.
#[tokio::test]
async fn a_gracefully_retired_writer_is_fenced_with_no_record() {
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, "f5-host").unwrap();
    let writer = writer_id();
    store.retired_writer(writer, 100_000, "host-retired", 51);
    store.now.store(1_000, Ordering::SeqCst);
    let (_stop_tx, stop) = stop_flag();
    let first = fence.run(stop.clone()).await;
    assert_eq!(first.closed, 1, "{first:?}");
    assert_eq!(store.control(writer), Some(CLOSED));
    assert_eq!(store.fence_applies(writer), 1);
    assert_eq!(store.lease_deletes(writer), 1);
    assert!(store.lease(writer).is_none());
    assert_eq!(placement(writer), Placement::default(), "no record");
    assert!(!fence.retirements.take_closed_open(EPOCH, writer));
    let second = fence.run(stop).await;
    assert_eq!((second.closed, second.invalid), (0, 0), "{second:?}");
    assert_eq!(store.fence_applies(writer), 1);
    assert_eq!(store.fence_candidates().len(), 1, "nothing submitted again");
}

/// 8.14: 300 expired writers: 256 closed in the first start with 44 remaining, the rest in the
/// next. Paused time: each close's 50 ms re-read costs nothing.
#[tokio::test(start_paused = true)]
async fn three_hundred_expired_writers_close_over_two_starts() {
    let store = Store::new();
    store.now.store(1_000, Ordering::SeqCst);
    let fence = PredecessorFence::new(attach(&store, OWN).await, "f5-host").unwrap();
    let writers: Vec<[u8; 16]> = (0..300).map(|_| writer_id()).collect();
    for (i, writer) in writers.iter().enumerate() {
        store.open_writer(*writer, 100_000, &format!("gone-{i}"), 1_000 + i as u64);
    }
    let (_stop_tx, stop) = stop_flag();
    let first = fence.run(stop.clone()).await;
    assert_eq!(
        (first.closed, first.remaining),
        (EXPIRED_PASS_MAX, 300 - EXPIRED_PASS_MAX),
        "{first:?}"
    );
    let closed = writers
        .iter()
        .filter(|writer| store.fence_applies(**writer) == 1)
        .count();
    assert_eq!(closed, EXPIRED_PASS_MAX);
    for writer in writers
        .iter()
        .filter(|writer| store.fence_applies(**writer) == 0)
    {
        assert_eq!(store.control(*writer), Some(OPEN));
        assert!(store.lease(*writer).is_some());
        assert_eq!(placement(*writer), Placement::default());
    }
    let second = fence.run(stop).await;
    assert_eq!(
        (second.closed, second.remaining),
        (300 - EXPIRED_PASS_MAX, 0),
        "{second:?}"
    );
    for writer in &writers {
        assert_eq!(store.fence_applies(*writer), 1);
        assert_eq!(store.lease_deletes(*writer), 1);
        assert!(store.lease(*writer).is_none());
        assert_offered_once(*writer);
    }
}

/// 8.14: a malformed `writer:` row is never closed, and counted invalid once per pass.
#[tokio::test]
async fn a_malformed_writer_row_is_never_closed_and_counted_once_per_pass() {
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, "f5-host").unwrap();
    store.now.store(1_000, Ordering::SeqCst);
    let short_key = b"writer:short".to_vec();
    store.put_node_row(&short_key, lease_bytes([9; 16], 1));
    let bad_value = writer_lease_key(EPOCH, writer_id());
    store.put_node_row(&bad_value, vec![1, 2, 3]);
    let (_stop_tx, stop) = stop_flag();
    for _ in 0..2 {
        let pass = fence.run(stop.clone()).await;
        assert_eq!((pass.invalid, pass.closed), (2, 0), "{pass:?}");
    }
    assert!(store.node_row(&short_key).is_some());
    assert_eq!(store.node_row(&bad_value), Some(vec![1, 2, 3]));
    assert!(store.fence_candidates().is_empty());
}

/// A candidate's semantic body, without its operation id.
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    codec: u32,
    authority: (u64, [u8; 16], u64),
    predicates: Vec<(Address, Option<Vec<u8>>)>,
    mutations: Vec<(Address, Option<Vec<u8>>)>,
    time: Option<TimeGuard>,
}

fn shape(candidate: &PreparedCandidate) -> Shape {
    let seal = crate::seal::lend();
    let body = candidate.candidate();
    Shape {
        codec: body.codec,
        authority: (
            body.id.writer_epoch,
            body.id.writer,
            body.id.execution_epoch,
        ),
        predicates: body
            .predicates
            .iter()
            .map(|predicate| {
                (
                    predicate.address.clone(),
                    match &predicate.expected {
                        ExpectedValue::Absent => None,
                        ExpectedValue::Exact(value) => Some(value.expose(&seal).clone()),
                    },
                )
            })
            .collect(),
        mutations: body
            .mutations
            .iter()
            .map(|mutation| match mutation {
                Mutation::Put { address, value } => {
                    (address.clone(), Some(value.expose(&seal).clone()))
                }
                Mutation::Delete(address) => (address.clone(), None),
                Mutation::DeleteRange {
                    namespace, prefix, ..
                } => (
                    Address {
                        namespace: namespace.0,
                        key: prefix.clone(),
                    },
                    None,
                ),
            })
            .collect(),
        time: body.time,
    }
}

/// 8.14: `retire_after(.., 0, seen)` builds the same candidate as `retire(..)`, and with a 9 s
/// grace it differs only in `not_before`; with no grace the liveness check is today's expression.
#[tokio::test]
async fn retire_after_with_no_grace_builds_the_retire_candidate() {
    let store = Store::new();
    let core = attach(&store, OWN).await;
    let writer = writer_id();
    store.open_writer(writer, 100_000, "host-shape", 61);
    let seen = seen(writer, "host-shape", 61, ObservedBy::Successor);
    let retirements = WriterRetirements::default();
    store.now.store(99, Ordering::SeqCst);
    assert!(matches!(
        retirements.retire(&core, EPOCH, writer).await,
        Ok(WriterRetirement::Live {
            retry_at_ms: 100_000
        })
    ));
    assert!(matches!(
        retirements
            .retire_after(&core, EPOCH, writer, LEASE_TTL_MS, Some(seen.clone()))
            .await,
        Ok(WriterRetirement::Live {
            retry_at_ms: 109_000
        })
    ));
    // Every fence is refused before it crosses, so each call builds from the same rows.
    store.refuse_fences.store(true, Ordering::SeqCst);
    store.now.store(109, Ordering::SeqCst);
    for grace_ms in [None, Some(0), Some(LEASE_TTL_MS)] {
        let answer = match grace_ms {
            None => retirements.retire(&core, EPOCH, writer).await,
            Some(grace_ms) => {
                retirements
                    .retire_after(&core, EPOCH, writer, grace_ms, Some(seen.clone()))
                    .await
            }
        };
        assert!(matches!(answer, Ok(WriterRetirement::Pending)));
    }
    let sent = store.fence_candidates();
    assert_eq!(sent.len(), 3);
    let (retire, no_grace, grace) = (shape(&sent[0]), shape(&sent[1]), shape(&sent[2]));
    assert_eq!(retire, no_grace);
    assert_eq!(
        retire.time,
        Some(TimeGuard {
            not_before: Some(100),
            before: None
        })
    );
    assert_eq!(
        grace.time,
        Some(TimeGuard {
            not_before: Some(109),
            before: None
        })
    );
    assert_eq!(
        Shape {
            time: retire.time,
            ..grace
        },
        retire,
        "the grace moves only not_before"
    );
    assert!(
        retire
            .predicates
            .contains(&(lease_address(writer), Some(lease_bytes(writer, 100_000)))),
        "the close is guarded by the exact lease row"
    );
    let operations: std::collections::BTreeSet<[u8; 16]> = sent
        .iter()
        .map(|candidate| candidate.candidate().id.operation)
        .collect();
    assert_eq!(operations.len(), 3, "each build is its own attempt");
    assert_eq!(store.control(writer), Some(OPEN));
    assert_eq!(placement(writer), Placement::default());
}

/// 8.14: the stop flag set while a close is in flight. F5 returns after that close; its record is
/// made once (by `take_decided`, in that call); the writers it never reached are untouched, and
/// the next start closes them, with no second record for the first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stop_flag_during_a_close_records_it_once_and_leaves_the_rest() {
    crate::audit::auditlog::ensure_global_audit_stream_registered().await;
    let store = Store::new();
    store.now.store(1_000, Ordering::SeqCst);
    let fence = PredecessorFence::new(attach(&store, OWN).await, "f5-host").unwrap();
    let writers: Vec<[u8; 16]> = (0..5).map(|_| writer_id()).collect();
    for (i, writer) in writers.iter().enumerate() {
        store.open_writer(*writer, 100_000, &format!("stopped-{i}"), 300 + i as u64);
    }
    let hold = Arc::new(TestHold::default());
    store.hold_next_fence(hold.clone());
    let (stop_tx, stop) = stop_flag();
    let first = {
        let fence = fence.clone();
        tokio::spawn(async move { fence.run(stop).await })
    };
    reached(&hold).await;
    let target = fence_target(&store.fence_candidates()[0]);
    let held = *writers
        .iter()
        .find(|writer| Some(control_address(**writer)) == target)
        .expect("the held close is one of ours");
    stop_tx.send_modify(|stop| *stop = true);
    hold.release.notify_one();
    let pass = first.await.unwrap();
    assert_eq!(pass.closed, 0, "{pass:?}");
    assert_eq!(fence.retained(), 0);
    assert_eq!(store.control(held), Some(CLOSED));
    assert_eq!(store.fence_applies(held), 1);
    let offered = placement(held);
    assert!(
        offered.recorded.is_some() && !offered.retained && !offered.record_failed,
        "{offered:?}"
    );
    for writer in writers.iter().filter(|writer| **writer != held) {
        assert_eq!(store.control(*writer), Some(OPEN), "never reached");
        assert_eq!(store.fence_applies(*writer), 0);
        assert!(store.lease(*writer).is_some());
        assert_eq!(placement(*writer), Placement::default());
    }
    assert_eq!(store.fence_candidates().len(), 1);

    let (_stop_tx, stop) = stop_flag();
    let second = fence.run(stop).await;
    assert_eq!(second.closed, writers.len(), "{second:?}");
    let records = durable_records().await;
    for writer in &writers {
        assert_eq!(store.fence_applies(*writer), 1);
        assert!(store.lease(*writer).is_none());
        assert_eq!(records_for(&records, *writer), 1, "one record each");
    }
}

/// #258 (2): a writer that rolled its execution epoch once (`retired_through = 1`,
/// `admitted_through = 2`) and then died never retired: its row still has a live epoch. "Never
/// retired" is a property of the row's window, not of the dataset's writer epoch, so F5 closes it
/// and offers its `shutdown.drain_incomplete` record exactly once.
#[tokio::test]
async fn a_writer_that_rolled_its_epoch_and_died_is_recorded_as_never_retired() {
    let store = Store::new();
    let fence = PredecessorFence::new(attach(&store, OWN).await, "f5-host").unwrap();
    let writer = writer_id();
    store.open_writer(writer, 100_000, "host-rolled", 61);
    let rolled = control::Writer {
        retired_through: 1,
        admitted_through: 2,
    };
    store.put(control_address(writer), rolled.encode().unwrap().to_vec());
    store.now.store(1_000, Ordering::SeqCst);
    let (_stop_tx, stop) = stop_flag();
    let pass = fence.run(stop).await;
    assert_eq!(pass.closed, 1, "{pass:?}");
    assert_eq!(store.control(writer), Some(CLOSED));
    assert!(store.lease(writer).is_none());
    assert!(
        fence.retirements.take_closed_open(EPOCH, writer),
        "an open writer's close"
    );
    assert_offered_once(writer);
}
