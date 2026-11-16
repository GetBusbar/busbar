// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Running-unit checkpoint selection against a node journal that other services
//! keep appending to (UPG-A27c). An interposed memory backend injects a real
//! journal append while a unit checkpoint selection is in flight, counts
//! original-frame reads, parks a selection, or rewrites an original frame.

use super::recovery::{RecoveryEvent, RecoveryKind, RecoveryState};
use super::unit_checkpoint::{UnitCheckpoint, UnitCheckpointSink, UnitRemoval, UnitTarget};
use super::unit_checkpoint_store::{
    StoreUnitCheckpoints, UnitCheckpointAudit, UnitCheckpointEvidence,
};
use super::RecordStoreResult;
use crate::persistence::facade::{CoreStore, Limits, WriterAuthority};
use crate::persistence::journal::runtime::{BufferBudget, RuntimeJournal};
use busbar_contract::persistence::{
    control, Address, BackendInfo, Call, ClockObservation, DatasetId, Decision, Durability,
    ExpectedValue, Mutation, Page, PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::{Count, Secret};
use busbar_kernel_audit::{AuditKeySet, AuditSigningKey, AuditVerifyingKey};
use busbar_kernel_wal::{Entry, RecordClass};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const NODE: u64 = 7;
const UNITCP: &[u8] = b"busbar.unitcp.v1";
const JOURNAL: &[u8] = b"busbar.journal4\0";
const INJECTED: &[u8] = b"a27c concurrent request-path append";

/// What the interposer does with a running-unit checkpoint candidate.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Forward,
    /// Start a real journal append and wait up to 300 ms for it to land
    /// before forwarding the selection.
    AppendInWindow,
    /// Never forward the next selection (its future is dropped by the test).
    Park,
    /// Replace the selection's pinned original frame with `R(1)` first.
    Tamper,
    /// The same, for the next usage recovery selection.
    TamperRecovery,
}

#[derive(Default)]
struct Rows {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
}

/// One unit checkpoint candidate the backend received.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    operation: [u8; 16],
    head: Vec<u8>,
}

struct Mem {
    state: Mutex<Rows>,
    mode: Mutex<Mode>,
    journal: OnceLock<Arc<RuntimeJournal>>,
    unitcp_commits: AtomicUsize,
    appended_in_window: AtomicUsize,
    conflicts: AtomicUsize,
    original_reads: AtomicUsize,
    seen: Mutex<Vec<Seen>>,
    decisions: Mutex<Vec<&'static str>>,
    appenders: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Hold the reply to every applied journal append this long (the store applied it; the owner
    /// has not heard yet), so a pinned group is in flight with the head already moved.
    append_delay: Mutex<Option<Duration>>,
    appends_applied: AtomicUsize,
    /// The next multi-row unit checkpoint candidate finds this checkpoint's head row already
    /// taken by another candidate (written just before the candidate is applied).
    compete: Mutex<Option<[u8; 16]>>,
    /// Refuse, with no effect, every unit checkpoint candidate with more rows than this.
    max_rows: Mutex<Option<usize>>,
}

fn control_address(key: Vec<u8>) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key,
    }
}
fn row(state: &Rows, address: &Address) -> Option<Secret<Vec<u8>>> {
    if let Some(value) = state.rows.get(address) {
        return Some(value.clone());
    }
    if address.namespace != control::NAMESPACE.0 {
        return None;
    }
    let value = if address.key == control::DATASET_KEY {
        control::Dataset {
            id: DatasetId([1; 16]),
            writer_epoch: 2,
        }
        .encode()
        .unwrap()
        .to_vec()
    } else {
        control::Writer {
            retired_through: 2,
            admitted_through: 3,
        }
        .encode()
        .unwrap()
        .to_vec()
    };
    Some(Secret::new(value))
}
/// `busbar.journal4\0 ++ node ++ tag ++ ordinal`.
fn journal_key(tag: u8, ordinal: u64) -> Vec<u8> {
    [JOURNAL, &NODE.to_be_bytes(), &[tag], &ordinal.to_be_bytes()].concat()
}
fn journal_tag(key: &[u8]) -> Option<u8> {
    (key.len() == JOURNAL.len() + 17 && key.starts_with(JOURNAL)).then(|| key[JOURNAL.len() + 8])
}
fn is_unitcp(prepared: &PreparedCandidate) -> bool {
    prepared
        .candidate()
        .mutations
        .iter()
        .any(|mutation| match mutation {
            Mutation::Put { address, .. } | Mutation::Delete(address) => {
                address.key.starts_with(UNITCP)
            }
            Mutation::DeleteRange { .. } => false,
        })
}
/// A usage recovery selection.
fn is_recovery(prepared: &PreparedCandidate) -> bool {
    prepared
        .candidate()
        .mutations
        .iter()
        .any(|mutation| match mutation {
            Mutation::Put { address, .. } => address.key.starts_with(b"busbar.recover1\0"),
            _ => false,
        })
}
/// A node journal append: it moves the journal head `H`.
fn is_append(prepared: &PreparedCandidate) -> bool {
    prepared
        .candidate()
        .mutations
        .iter()
        .any(|mutation| match mutation {
            Mutation::Put { address, .. } => journal_tag(&address.key) == Some(b'H'),
            _ => false,
        })
}
fn decision_name(decision: &Decision) -> &'static str {
    match decision {
        Decision::Applied(_) => "Applied",
        Decision::ConditionConflict => "ConditionConflict",
        Decision::TimeGuardFailed { .. } => "TimeGuardFailed",
        Decision::OpIdConflict => "OpIdConflict",
        Decision::Fenced => "Fenced",
        Decision::Stale => "Stale",
    }
}

impl Mem {
    fn new() -> Self {
        Self {
            state: Mutex::default(),
            mode: Mutex::new(Mode::Forward),
            journal: OnceLock::new(),
            unitcp_commits: AtomicUsize::new(0),
            appended_in_window: AtomicUsize::new(0),
            conflicts: AtomicUsize::new(0),
            original_reads: AtomicUsize::new(0),
            seen: Mutex::default(),
            decisions: Mutex::default(),
            appenders: Mutex::default(),
            append_delay: Mutex::new(None),
            appends_applied: AtomicUsize::new(0),
            compete: Mutex::new(None),
            max_rows: Mutex::new(None),
        }
    }
    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
    /// Overwrite the original frame `prepared` pins with `R(1)`'s bytes, before it is applied.
    fn replace_pinned_original(&self, prepared: &PreparedCandidate) {
        let pinned = prepared
            .candidate()
            .predicates
            .iter()
            .find(|predicate| journal_tag(&predicate.address.key) == Some(b'R'))
            .expect("a selection pins its original frame")
            .address
            .clone();
        let mut state = self.state.lock().unwrap();
        let first = state
            .rows
            .iter()
            .find(|(at, _)| at.key == journal_key(b'R', 1))
            .map(|(_, value)| value.clone())
            .expect("the first original frame");
        assert_ne!(pinned.key, journal_key(b'R', 1));
        state.rows.insert(pinned, first);
    }
    fn apply(&self, prepared: &PreparedCandidate) -> Decision {
        let mut state = self.state.lock().unwrap();
        let candidate = prepared.candidate();
        if let Some(digest) = state.receipts.get(&candidate.id.operation) {
            return if *digest == prepared.fingerprint() {
                Decision::Applied(candidate.result.clone())
            } else {
                Decision::OpIdConflict
            };
        }
        let root_raw = row(&state, &control_address(control::DATASET_KEY.to_vec())).unwrap();
        let root = control::Dataset::decode(root_raw.expose(&crate::seal::lend())).unwrap();
        let writer_raw = row(
            &state,
            &control_address(control::writer_key(candidate.id.writer).to_vec()),
        )
        .unwrap();
        let writer = control::Writer::decode(writer_raw.expose(&crate::seal::lend())).unwrap();
        if root.writer_epoch != candidate.id.writer_epoch
            || !writer.admits(candidate.id.execution_epoch)
        {
            return Decision::Fenced;
        }
        for predicate in &candidate.predicates {
            let found = row(&state, &predicate.address);
            if !match &predicate.expected {
                ExpectedValue::Absent => found.is_none(),
                ExpectedValue::Exact(value) => found.as_ref() == Some(value),
            } {
                return Decision::ConditionConflict;
            }
        }
        for mutation in &candidate.mutations {
            match mutation {
                Mutation::Put { address, value } => {
                    state.rows.insert(address.clone(), value.clone());
                }
                Mutation::Delete(address) => {
                    state.rows.remove(address);
                }
                Mutation::DeleteRange { .. } => panic!("no range deletion here"),
            }
        }
        state
            .receipts
            .insert(candidate.id.operation, prepared.fingerprint());
        Decision::Applied(candidate.result.clone())
    }
    /// One injected request-path append, staged and confirmed on the shared
    /// node journal from another task.
    fn inject(&self) -> tokio::sync::oneshot::Receiver<()> {
        let journal = self.journal.get().expect("journal attached").clone();
        let (landed, receiver) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let run = journal
                .stage_run(&[Entry::new(RecordClass::Transaction, INJECTED.to_vec())])
                .expect("stage the injected append");
            journal
                .confirm(&run)
                .await
                .expect("the injected append lands");
            let _ = landed.send(());
        });
        self.appenders.lock().unwrap().push(task);
        receiver
    }
}

impl PersistenceBackend for Mem {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: busbar_contract::abi::sdk::store::v4::slot::PHYSICAL_VERSION,
            durability: Durability::Local,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        let originals = request
            .addresses
            .iter()
            .filter(|address| journal_tag(&address.key) == Some(b'R'))
            .count();
        self.original_reads.fetch_add(originals, Ordering::SeqCst);
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [3; 16],
                    unix_seconds: 10,
                },
                values: request
                    .addresses
                    .iter()
                    .map(|address| row(&state, address))
                    .collect(),
            })
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            let rows = state
                .rows
                .iter()
                .filter(|(at, _)| {
                    at.namespace == request.namespace.0 && at.key.starts_with(&request.prefix)
                })
                .map(|(at, value)| (at.clone(), value.clone()))
                .collect();
            Ok(Page {
                generation: 0,
                rows,
                next: None,
            })
        })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async {
            Ok(ClockObservation {
                authority: [3; 16],
                unix_seconds: 10,
            })
        })
    }
    fn commit(
        &self,
        prepared: PreparedCandidate,
        _key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        Box::pin(async move {
            if is_recovery(&prepared) && *self.mode.lock().unwrap() == Mode::TamperRecovery {
                self.set_mode(Mode::Forward);
                self.replace_pinned_original(&prepared);
            }
            if !is_unitcp(&prepared) {
                let decision = self.apply(&prepared);
                if is_append(&prepared) && matches!(decision, Decision::Applied(_)) {
                    self.appends_applied.fetch_add(1, Ordering::SeqCst);
                    let delay = *self.append_delay.lock().unwrap();
                    if let Some(delay) = delay {
                        tokio::time::sleep(delay).await;
                    }
                }
                return Ok(decision);
            }
            let head = prepared
                .candidate()
                .predicates
                .iter()
                .find(|predicate| journal_tag(&predicate.address.key) == Some(b'H'))
                .map(|predicate| match &predicate.expected {
                    ExpectedValue::Absent => Vec::new(),
                    ExpectedValue::Exact(value) => value.expose(&crate::seal::lend()).clone(),
                })
                .expect("a unit checkpoint selection pins the node journal head");
            self.seen.lock().unwrap().push(Seen {
                operation: prepared.candidate().id.operation,
                head,
            });
            self.unitcp_commits.fetch_add(1, Ordering::SeqCst);
            let rows = prepared.candidate().mutations.len();
            if self.max_rows.lock().unwrap().is_some_and(|max| rows > max) {
                return Err(busbar_contract::persistence::Failure::Refused);
            }
            if rows > 1 {
                let competing = self.compete.lock().unwrap().take();
                if let Some(id) = competing {
                    let address = prepared
                        .candidate()
                        .mutations
                        .iter()
                        .find_map(|mutation| match mutation {
                            Mutation::Put { address, .. } if address.key.ends_with(&id) => {
                                Some(address.clone())
                            }
                            _ => None,
                        })
                        .expect("the competing checkpoint is in the batch");
                    self.state
                        .lock()
                        .unwrap()
                        .rows
                        .insert(address, Secret::new(b"another candidate's head".to_vec()));
                }
            }
            let mode = *self.mode.lock().unwrap();
            match mode {
                // `TamperRecovery` acts on the next recovery selection only (above).
                Mode::Forward | Mode::TamperRecovery => {}
                Mode::AppendInWindow => {
                    let landed = self.inject();
                    if tokio::time::timeout(Duration::from_millis(300), landed)
                        .await
                        .is_ok()
                    {
                        self.appended_in_window.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Mode::Park => {
                    self.set_mode(Mode::Forward);
                    std::future::pending::<()>().await;
                }
                Mode::Tamper => {
                    self.set_mode(Mode::Forward);
                    let pinned = prepared
                        .candidate()
                        .predicates
                        .iter()
                        .find(|predicate| journal_tag(&predicate.address.key) == Some(b'R'))
                        .expect("a selection pins its original frame")
                        .address
                        .clone();
                    let mut state = self.state.lock().unwrap();
                    let first = state
                        .rows
                        .iter()
                        .find(|(at, _)| at.key == journal_key(b'R', 1))
                        .map(|(_, value)| value.clone())
                        .expect("the first original frame");
                    assert_ne!(pinned.key, journal_key(b'R', 1));
                    state.rows.insert(pinned, first);
                }
            }
            let decision = self.apply(&prepared);
            if matches!(decision, Decision::ConditionConflict) {
                self.conflicts.fetch_add(1, Ordering::SeqCst);
            }
            self.decisions
                .lock()
                .unwrap()
                .push(decision_name(&decision));
            Ok(decision)
        })
    }
}

struct Signer(AuditSigningKey);
#[async_trait::async_trait]
impl UnitCheckpointAudit for Signer {
    fn keys(&self) -> AuditKeySet {
        let mut keys = AuditKeySet::new();
        keys.insert(AuditVerifyingKey::from_hex(&self.0.public_key_hex()).unwrap());
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

struct Fixture {
    backend: Arc<Mem>,
    journal: Arc<RuntimeJournal>,
    evidence: Arc<UnitCheckpointEvidence>,
    sink: StoreUnitCheckpoints,
}
async fn fixture() -> Fixture {
    fixture_with(64).await
}
/// A fixture whose store reads and stages up to `scan_items` items per call.
async fn fixture_with(scan_items: usize) -> Fixture {
    let backend = Arc::new(Mem::new());
    let store = Arc::new(
        CoreStore::attach(
            backend.clone(),
            WriterAuthority {
                writer_epoch: 2,
                writer: [1; 16],
                execution_epoch: 3,
            },
            Limits {
                pending_operations: 64,
                conflict_retries: 1,
                scan_items,
                scan_bytes: 1024 * 1024,
            },
        )
        .await
        .unwrap(),
    );
    let journal = RuntimeJournal::open(
        store,
        NODE,
        BufferBudget {
            records: 1024,
            bytes: 4 * 1024 * 1024,
        },
    )
    .await
    .unwrap();
    assert!(backend.journal.set(journal.clone()).is_ok());
    let evidence = Arc::new(UnitCheckpointEvidence::new(
        journal.clone(),
        crate::teller::Kernel::new().durability_token(),
    ));
    let sink = StoreUnitCheckpoints::new(
        evidence.clone(),
        Arc::new(Signer(AuditSigningKey::from_seed(&[0x27; 32]))),
    );
    Fixture {
        backend,
        journal,
        evidence,
        sink,
    }
}

fn terminal_event() -> RecoveryEvent {
    RecoveryEvent {
        operation_id: [0x2c; 16],
        revision: 0,
        previous_event: None,
        kind: RecoveryKind::Usage,
        body_fingerprint: [2; 32],
        state: RecoveryState::Intent,
        first_sent_at_ms: Some(1000),
        payload: b"{}".to_vec(),
    }
}
/// Revision 1 is running; revision 2 is terminal.
fn unit(revision: u64) -> UnitCheckpoint {
    let terminal = revision >= 2;
    UnitCheckpoint {
        id: [0xa2; 16],
        revision,
        unit: 17,
        principal: "race-principal".into(),
        group: String::new(),
        arrived: 1_700_000_000,
        lane: "race-lane".into(),
        provider: Some("race".into()),
        era_at: 42,
        era_entry: None,
        units: BTreeMap::from([(
            "work".into(),
            Count::parse(if terminal { "0.25" } else { "0.125" }).unwrap(),
        )]),
        targets: vec![UnitTarget {
            bucket: "race-principal".into(),
            window: 0,
            group: None,
        }],
        metered: true,
        ended: terminal,
        terminal: terminal.then(|| vec![terminal_event()]),
        audit: Some(b"{}".to_vec()),
        measurement: None,
        unread: None,
    }
}
fn selected_revision(backend: &Mem) -> Option<u64> {
    let state = backend.state.lock().unwrap();
    let (_, raw) = state
        .rows
        .iter()
        .find(|(at, _)| at.key.starts_with(UNITCP))?;
    let head: serde_json::Value = serde_json::from_slice(raw.expose(&crate::seal::lend())).unwrap();
    head["revision"].as_u64()
}
fn selected_raw(backend: &Mem) -> Option<Secret<Vec<u8>>> {
    let state = backend.state.lock().unwrap();
    state
        .rows
        .iter()
        .find(|(at, _)| at.key.starts_with(UNITCP))
        .map(|(_, raw)| raw.clone())
}
async fn bounded<T>(test: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), test)
        .await
        .expect("no hang")
}

/// WHO: the usage flusher persisting and settling one running unit while
/// request-path audit appends land on the same node journal.
/// DOES: every persist/remove selects on its first call, with exactly one
/// selection candidate, no condition conflict, and no append landing between
/// the proof and the selection.
/// WHY: a lost selection retains the single pending slot and stalls every
/// later checkpoint until the next tick, so `/admin/usage` lags seconds behind
/// served requests.
#[tokio::test]
async fn selection_is_not_lost_to_a_concurrent_append() {
    bounded(async {
        let fixture = fixture().await;
        let backend = &fixture.backend;
        backend.set_mode(Mode::AppendInWindow);
        let before = fixture.journal.next_seq();
        for (call, step) in ["persist 1", "persist 2", "remove 2"].iter().enumerate() {
            let commits = backend.unitcp_commits.load(Ordering::SeqCst);
            let result = match call {
                0 => fixture.sink.persist(&unit(1)).await,
                1 => fixture.sink.persist(&unit(2)).await,
                _ => fixture.sink.remove(&unit(2)).await,
            };
            assert!(
                result.is_ok(),
                "{step} must select on its first call: {:?}",
                result.err().map(|e| e.0)
            );
            assert_eq!(
                backend.unitcp_commits.load(Ordering::SeqCst),
                commits + 1,
                "{step} submits exactly one selection candidate"
            );
            assert_eq!(backend.conflicts.load(Ordering::SeqCst), 0, "{step}");
            assert_eq!(
                backend.appended_in_window.load(Ordering::SeqCst),
                0,
                "{step}: no append may land between the proof and the selection"
            );
        }
        let appenders = std::mem::take(&mut *backend.appenders.lock().unwrap());
        assert_eq!(appenders.len(), 3);
        for appender in appenders {
            appender.await.unwrap();
        }
        fixture.journal.flush().await.unwrap();
        let injected = fixture
            .journal
            .read_records(BufferBudget {
                records: 64,
                bytes: 1024 * 1024,
            })
            .await
            .unwrap()
            .into_iter()
            .filter(|record| record.class == RecordClass::Transaction && record.body == INJECTED)
            .count();
        assert_eq!(injected, 3, "every injected append landed exactly once");
        // Two checkpoint originals plus the three injected appends.
        assert_eq!(fixture.journal.next_seq(), before + 5);
        assert_eq!(selected_revision(backend), None, "terminal custody removed");
    })
    .await;
}

/// WHO: the usage flusher on a node journal that has grown.
/// DOES: a persist or remove reads at most one original frame (the selected
/// checkpoint's own), whatever the journal length.
/// WHY: proving and locating by replaying the whole journal per checkpoint
/// makes settle time grow with uptime and widens the race window.
#[tokio::test]
async fn live_proof_does_not_replay_history() {
    bounded(async {
        let fixture = fixture().await;
        let backend = &fixture.backend;
        fixture.sink.persist(&unit(1)).await.unwrap();
        for _ in 0..50 {
            let run = fixture
                .journal
                .stage_run(&[Entry::new(RecordClass::Transaction, INJECTED.to_vec())])
                .unwrap();
            fixture.journal.confirm(&run).await.unwrap();
        }
        backend.original_reads.store(0, Ordering::SeqCst);
        fixture.sink.persist(&unit(2)).await.unwrap();
        let persisted = backend.original_reads.swap(0, Ordering::SeqCst);
        assert!(
            persisted <= 1,
            "persist read {persisted} original frames; at most the selected one"
        );
        fixture.sink.remove(&unit(2)).await.unwrap();
        let removed = backend.original_reads.swap(0, Ordering::SeqCst);
        assert!(
            removed <= 1,
            "remove read {removed} original frames; at most the selected one"
        );
        assert_eq!(selected_revision(backend), None);
    })
    .await;
}

/// Drop a persist while its selection is parked in the backend.
async fn cancel_parked_persist(fixture: &Fixture, snapshot: &UnitCheckpoint) {
    fixture.backend.set_mode(Mode::Park);
    tokio::select! {
        result = fixture.sink.persist(snapshot) => {
            panic!("the parked selection must not return: {:?}", result.err().map(|e| e.0))
        }
        _ = async {
            while fixture.backend.seen.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        } => {}
    }
    assert_eq!(fixture.backend.seen.lock().unwrap().len(), 1);
}

/// WHO: the usage flusher re-driving a checkpoint selection whose crossing was
/// cancelled (timeout, abort) while another service appended.
/// DOES: the proof is retained before any native claim, so the re-drive
/// presents the exact same attempt (same operation id, same head predicate).
/// (SHUTDOWN-HANG F2.2, 8.4(c), owner ruling 2026-11-16 "Re-select, after
/// authority check") With the head moved, that re-drive's condition conflict is
/// a definitive no-effect: our authority is intact, so the same staged original
/// is re-selected once under a new operation id against the current head, and
/// nothing is staged twice.
/// WHY: re-proving against the moved head on the re-drive would change the claim
/// digest for the same operation id and wedge it as corruption; never
/// re-selecting held the single slot, and every later checkpoint, for ever.
#[tokio::test]
async fn cancelled_selection_resumes_exact_attempt() {
    bounded(async {
        let fixture = fixture().await;
        cancel_parked_persist(&fixture, &unit(1)).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            let run = fixture
                .journal
                .stage_run(&[Entry::new(RecordClass::Transaction, INJECTED.to_vec())])
                .unwrap();
            fixture.journal.confirm(&run).await.unwrap();
        })
        .await
        .expect("a cancelled selection releases the journal's publication driver");
        let staged = fixture.journal.next_seq();
        let resolved = fixture.sink.persist(&unit(1)).await;
        assert!(resolved.is_ok(), "{:?}", resolved.err().map(|e| e.0));
        let seen = fixture.backend.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 3, "the re-drive, then one re-select");
        assert_eq!(seen[1], seen[0], "the re-drive presents the exact attempt");
        assert_ne!(seen[2].operation, seen[0].operation, "a new operation id");
        assert_ne!(
            seen[2].head, seen[0].head,
            "the re-select pins the current head"
        );
        assert_eq!(
            fixture.backend.decisions.lock().unwrap().clone(),
            vec!["ConditionConflict", "Applied"]
        );
        assert_eq!(
            fixture.journal.next_seq(),
            staged,
            "the same staged original is re-selected"
        );
        assert_eq!(selected_revision(&fixture.backend), Some(1));
    })
    .await;
}

/// WHO: the usage flusher re-driving a cancelled selection whose head did not
/// move. DOES: the exact retained attempt applies once. WHY: a cancelled
/// selection that can still apply must apply.
#[tokio::test]
async fn cancelled_selection_without_append_applies() {
    bounded(async {
        let fixture = fixture().await;
        cancel_parked_persist(&fixture, &unit(1)).await;
        fixture.sink.persist(&unit(1)).await.unwrap();
        let seen = fixture.backend.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1], seen[0]);
        assert_eq!(selected_revision(&fixture.backend), Some(1));
        let decisions = fixture.backend.decisions.lock().unwrap().clone();
        assert_eq!(
            decisions,
            vec!["Applied"],
            "the parked attempt never landed"
        );
    })
    .await;
}

/// WHO: the usage flusher when an original frame no longer holds the bytes
/// the runtime located. DOES: the selection fails closed, the selected row is
/// unchanged, and the refusal names corruption. WHY: a located frame is only
/// trusted through the native byte predicate; a mismatch is never selected and
/// never reported as an ordinary moved head.
#[tokio::test]
async fn locator_mismatch_fails_closed() {
    bounded(async {
        let fixture = fixture().await;
        fixture.sink.persist(&unit(1)).await.unwrap();
        let selected = selected_raw(&fixture.backend).expect("revision 1 selected");
        fixture.backend.set_mode(Mode::Tamper);
        let refused = fixture.sink.persist(&unit(2)).await.unwrap_err().0;
        assert!(refused.contains("Corrupt"), "{refused}");
        assert_eq!(selected_raw(&fixture.backend), Some(selected));
        assert_eq!(fixture.backend.conflicts.load(Ordering::SeqCst), 1);
    })
    .await;
}

/// Rewrite this node's original at `ordinal` self-consistently: a valid frame at the same
/// sequence, with its own chain hash recomputed, that is not the bytes this process sealed.
fn rewrite_original(backend: &Mem, ordinal: u64) {
    let mut state = backend.state.lock().unwrap();
    let (address, value) = state
        .rows
        .iter()
        .find(|(at, _)| at.key == journal_key(b'R', ordinal))
        .map(|(at, value)| (at.clone(), value.clone()))
        .expect("the original frame");
    let mut record =
        busbar_kernel_wal::JournalRecord::decode(value.expose(&crate::seal::lend())).unwrap();
    record.wall += 1;
    record.hash = record.digest_of_chain();
    state.rows.insert(address, Secret::new(record.encode()));
}

/// The sealed audit line of unit 17, incarnation 7, as the root seals a terminal unit's line.
fn audit_line() -> busbar_kernel_audit::AuditRecord {
    use busbar_contract::caps::{Audit as AuditStep, KernelSeal, Origin, OriginKind, Outcome};
    use busbar_kernel_audit::record::{
        AuditChain, AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage,
        What,
    };
    let mut chain = AuditChain::new()
        .signing_with(AuditSigningKey::from_seed(&[0x5a; 32]))
        .sealing_as(NODE);
    let inputs = AuditInputs {
        subject: Subject::PrincipalId("race-principal".into()),
        what: What {
            unit_key: busbar_contract::caps::UnitKey::new(17),
            incarnation: 7,
            op_class: OpClassId::new("chat.completion"),
            destination: None,
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 1_700_000_000,
        mono: 5,
        origin: Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client),
        outcome: OutcomeFacts {
            unit_end: Outcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines: Vec::new(),
            tier_bp: 10_000,
            fee_count: 0,
            rate_card_version: None,
            bucket_chain_ref: String::new(),
        },
        controls: Controls::default(),
        correlation_label: None,
        unit: busbar_kernel_audit::UnitFacts::default(),
    };
    busbar_kernel_audit::record::Audit::seal(
        &mut chain,
        inputs,
        &busbar_contract::caps::Pass::<AuditStep>::mint(&crate::seal::acquire()),
    )
}

/// One request-path append on the shared journal, confirmed.
async fn append_one(journal: &RuntimeJournal) {
    let run = journal
        .stage_run(&[Entry::new(RecordClass::Transaction, INJECTED.to_vec())])
        .unwrap();
    journal.confirm(&run).await.unwrap();
}

/// WHO: unit checkpoint custody confirming its custody while request-path appends commit as groups.
/// DOES: (SHUTDOWN-HANG 8.16) a confirmation never waits for the publication driver; while a
/// pinned group is in flight, a head the store has already moved to the group's end is accepted as
/// this owner's own; under 8 appenders with a delayed append reply, at most 1% of confirmations
/// fall back to the driver and none is refused.
/// WHY: confirmations serialised on the append lane capped the flusher at ~150 items/s, and a head
/// moved by our own in-flight group was misreported as lost authority.
#[tokio::test]
async fn confirm_with_accepts_a_pinned_group_head() {
    bounded(async {
        let fixture = fixture().await;
        let backend = fixture.backend.clone();
        append_one(&fixture.journal).await;
        *backend.append_delay.lock().unwrap() = Some(Duration::from_millis(400));
        let applied = backend.appends_applied.load(Ordering::SeqCst);
        let journal = fixture.journal.clone();
        let held = tokio::spawn(async move { append_one(&journal).await });
        while backend.appends_applied.load(Ordering::SeqCst) == applied {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(
            !fixture.journal.driver_is_free(),
            "the held append keeps the publication driver"
        );
        tokio::time::timeout(
            Duration::from_millis(200),
            fixture.journal.confirm_with(&[]),
        )
        .await
        .expect("a confirmation never waits for the publication driver")
        .expect("the in-flight group's head is this owner's own");
        held.await.unwrap();
        fixture.journal.confirm_with(&[]).await.unwrap();

        *backend.append_delay.lock().unwrap() = Some(Duration::from_millis(5));
        let mut appenders = Vec::new();
        for _ in 0..8 {
            let journal = fixture.journal.clone();
            appenders.push(tokio::spawn(async move {
                for _ in 0..20 {
                    append_one(&journal).await;
                }
            }));
        }
        let mut confirmations = 0u64;
        while confirmations < 200 || appenders.iter().any(|a| !a.is_finished()) {
            fixture
                .journal
                .confirm_with(&[])
                .await
                .expect("an own group never reads as lost authority");
            confirmations += 1;
            tokio::task::yield_now().await;
        }
        for appender in appenders {
            appender.await.unwrap();
        }
        let fallbacks = fixture.journal.lane_fallbacks();
        assert!(
            fallbacks * 100 <= confirmations,
            "{fallbacks} of {confirmations} confirmations fell back to the driver"
        );
    })
    .await;
}

/// WHO: the flusher removing a terminal unit whose audit line this process sealed.
/// DOES: (SHUTDOWN-HANG F1a, 8.3, 8.5b) the line is read by the hint carried from its append: one
/// original read and no journal replay, whatever the journal length; a self-consistent rewrite of
/// that original is refused against the carried hash.
/// WHY: a full-journal replay per terminal unit made each shutdown drain cost O(N²) in requests.
#[tokio::test]
async fn a_terminal_audit_line_is_read_once_by_its_carried_hint() {
    bounded(async {
        let fixture = fixture().await;
        let audit = audit_line();
        let run = fixture
            .journal
            .stage_run(&[Entry::new(
                RecordClass::Transaction,
                busbar_kernel_audit::journal_body(&audit).unwrap(),
            )
            .at(audit.wall, audit.mono)])
            .unwrap();
        fixture.journal.confirm(&run).await.unwrap();
        let hint = run.carried().next().expect("one original");
        for _ in 0..50 {
            append_one(&fixture.journal).await;
        }
        fixture.backend.original_reads.store(0, Ordering::SeqCst);
        let replays = crate::persistence::journal::replays_on_this_thread();
        let found = fixture
            .evidence
            .find_audit_at(hint)
            .await
            .expect("the hinted line is found");
        assert_eq!(found, audit);
        let reads = fixture.backend.original_reads.load(Ordering::SeqCst);
        assert!(reads <= 1, "the lookup read {reads} original frames");
        assert_eq!(
            crate::persistence::journal::replays_on_this_thread(),
            replays,
            "no journal replay"
        );
        let ordinal = fixture
            .journal
            .locate(&fixture.journal.verified().unwrap(), hint.seq)
            .unwrap();
        rewrite_original(&fixture.backend, ordinal);
        let refused = fixture.evidence.find_audit_at(hint).await.unwrap_err().0;
        assert!(refused.contains("carried"), "{refused}");
    })
    .await;
}

/// WHO: unit checkpoint custody through one unit's life.
/// DOES: (SHUTDOWN-HANG 8.3) P's append confirmation carries the checkpoint original's sequence
/// and hash, a later revision replaces it, and R's applied delete pops it.
/// WHY: own originals are evidence from their append; nothing carried may outlive custody.
#[tokio::test]
async fn carried_checkpoint_evidence_follows_its_selection() {
    bounded(async {
        let fixture = fixture().await;
        let id = unit(1).id;
        let seq = fixture.journal.next_seq();
        fixture.sink.persist(&unit(1)).await.unwrap();
        let first = fixture
            .sink
            .carried(&id)
            .expect("P's append confirmation carries its original");
        assert_eq!(first.seq, seq);
        append_one(&fixture.journal).await;
        fixture.sink.persist(&unit(2)).await.unwrap();
        let second = fixture.sink.carried(&id).expect("the terminal revision");
        assert!(second.seq > first.seq + 1, "{second:?} after {first:?}");
        fixture.sink.remove(&unit(2)).await.unwrap();
        assert_eq!(
            fixture.sink.carried(&id),
            None,
            "R pops the carried evidence"
        );
        assert_eq!(selected_revision(&fixture.backend), None);
    })
    .await;
}

/// WHO: unit checkpoint custody when its own selected original was rewritten in the store with a
/// self-consistent frame (same sequence, valid hash, H untouched).
/// DOES: (SHUTDOWN-HANG 8.5b) the next persist refuses with the carried-evidence mismatch and
/// selects nothing.
/// WHY: the checkpoint signature covers the body only; without the carried hash a rewritten own
/// original passed as evidence.
#[tokio::test]
async fn a_rewritten_checkpoint_original_is_refused_against_carried_evidence() {
    bounded(async {
        let fixture = fixture().await;
        let seq = fixture.journal.next_seq();
        fixture.sink.persist(&unit(1)).await.unwrap();
        let ordinal = fixture
            .journal
            .locate(&fixture.journal.verified().unwrap(), seq)
            .unwrap();
        rewrite_original(&fixture.backend, ordinal);
        let refused = fixture.sink.persist(&unit(2)).await.unwrap_err().0;
        assert!(refused.contains("carried"), "{refused}");
        assert_eq!(selected_revision(&fixture.backend), Some(1));
    })
    .await;
}

/// WHO: usage recovery selecting an operation's Intent while one of its own originals no longer
/// holds the bytes it sealed, with the selection row unchanged.
/// DOES: (SHUTDOWN-HANG F2.1, 8.4) the no-effect is classified from one read of the selection
/// row: unchanged and custody ours, so it names the changed original; the staged original is kept
/// and never re-staged.
/// WHY: an unchanged row was reported as a missing selection or as another candidate's win.
#[tokio::test]
async fn an_unchanged_row_no_effect_names_the_changed_original() {
    bounded(async {
        let fixture = fixture().await;
        append_one(&fixture.journal).await;
        let recovery = crate::governance::persistence::recovery::StoreRecovery::new(
            fixture.journal.clone(),
            crate::teller::Kernel::new().durability_token(),
        )
        .unwrap();
        fixture.backend.set_mode(Mode::TamperRecovery);
        let refused =
            crate::governance::recovery::RecoverySink::persist(&recovery, &terminal_event())
                .await
                .unwrap_err()
                .to_string();
        assert!(
            !refused.contains("another recovery candidate won"),
            "{refused}"
        );
        assert!(refused.contains("differs"), "{refused}");
        let staged = fixture.journal.next_seq();
        let _ =
            crate::governance::recovery::RecoverySink::persist(&recovery, &terminal_event()).await;
        assert_eq!(
            fixture.journal.next_seq(),
            staged,
            "the kept candidate is never staged twice"
        );
    })
    .await;
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl Logs {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}
/// Runs `test` on a current-thread runtime with every log line captured.
fn logged(test: impl std::future::Future<Output = ()>) -> Logs {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(test)
    });
    logs
}
/// `snapshot` as checkpoint `n` of a batch: its own id and unit.
fn numbered(mut snapshot: UnitCheckpoint, n: u8) -> UnitCheckpoint {
    snapshot.id = [n; 16];
    snapshot.unit = 1_000 + u64::from(n);
    snapshot
}
/// Running-unit head rows in the store, whoever wrote them.
fn heads(backend: &Mem) -> usize {
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .keys()
        .filter(|at| at.key.starts_with(UNITCP))
        .count()
}

/// WHO: the settlement flusher's phase P over one batch of 128 checkpoints.
/// DOES: (SHUTDOWN-HANG 8.9) the batch is one selection CAS. With one competing selector in it,
/// the batch bisects: 127 commit and the bad one reports "another candidate won", in at most 14
/// extra crossings. With a store refusing candidates over 32 rows, the batch size halves twice,
/// `UNIT_FLUSH_BATCH_REDUCED` (BUSBAR-8031) is raised once, and every item commits.
/// WHY: one crossing per item bounds a drain's settlement rate by store latency (§1.7), and one
/// bad item must never fail its siblings.
#[test]
fn batch_bisects_and_reduces() {
    let logs = logged(bounded(async {
        let batch: Vec<UnitCheckpoint> = (1..=128u8).map(|n| numbered(unit(1), n)).collect();

        let fixture = fixture_with(256).await;
        *fixture.backend.compete.lock().unwrap() = Some(batch[37].id);
        let results = fixture.sink.persist_batch(&batch).await;
        let crossings = fixture.backend.unitcp_commits.load(Ordering::SeqCst);
        assert!(
            crossings <= 15,
            "one CAS for the batch plus at most 14 for the bisect, not {crossings}"
        );
        for (at, result) in results.iter().enumerate() {
            match result {
                Err(refused) if at == 37 => {
                    assert!(refused.0.contains("another candidate won"), "{}", refused.0)
                }
                Ok(()) if at != 37 => {}
                other => panic!("item {at}: {:?}", other.as_ref().err().map(|e| &e.0)),
            }
        }
        assert_eq!(
            heads(&fixture.backend),
            128,
            "127 selected, plus the competitor's"
        );

        let fixture = fixture_with(256).await;
        *fixture.backend.max_rows.lock().unwrap() = Some(32);
        let results = fixture.sink.persist_batch(&batch).await;
        for (at, result) in results.iter().enumerate() {
            assert!(
                result.is_ok(),
                "item {at}: {:?}",
                result.as_ref().err().map(|e| &e.0)
            );
        }
        assert_eq!(heads(&fixture.backend), 128);
        assert_eq!(
            fixture.backend.unitcp_commits.load(Ordering::SeqCst),
            6,
            "128 and 64 refused, then four batches of 32"
        );
    }));
    let text = logs.text();
    assert_eq!(text.matches("BUSBAR-8031").count(), 1, "{text}");
}

/// WHO: the settlement flusher driving 50 terminal checkpoints through P and R as batches.
/// DOES: (SHUTDOWN-HANG 8.3) P is one selection CAS and carries each original's sealed sequence
/// and hash; R is one delete CAS, after which nothing is carried and no head row is left.
/// WHY: own originals are evidence from their append, and nothing carried outlives custody.
#[tokio::test]
async fn a_batch_carries_its_originals_through_p_and_pops_them_in_r() {
    bounded(async {
        let fixture = fixture_with(256).await;
        let batch: Vec<UnitCheckpoint> = (1..=50u8).map(|n| numbered(unit(2), n)).collect();
        let first = fixture.journal.next_seq();
        for result in fixture.sink.persist_batch(&batch).await {
            assert!(result.is_ok(), "{:?}", result.err().map(|e| e.0));
        }
        assert_eq!(fixture.backend.unitcp_commits.load(Ordering::SeqCst), 1);
        for (at, snapshot) in batch.iter().enumerate() {
            let carried = fixture
                .sink
                .carried(&snapshot.id)
                .expect("P carries its original");
            assert_eq!(carried.seq, first + at as u64);
        }
        let removals: Vec<UnitRemoval<'_>> = batch
            .iter()
            .map(|snapshot| UnitRemoval {
                snapshot,
                audit: None,
            })
            .collect();
        for result in fixture.sink.remove_batch(&removals).await {
            assert!(result.is_ok(), "{:?}", result.err().map(|e| e.0));
        }
        assert_eq!(fixture.backend.unitcp_commits.load(Ordering::SeqCst), 2);
        for snapshot in &batch {
            assert_eq!(fixture.sink.carried(&snapshot.id), None);
        }
        assert_eq!(heads(&fixture.backend), 0);
    })
    .await;
}
