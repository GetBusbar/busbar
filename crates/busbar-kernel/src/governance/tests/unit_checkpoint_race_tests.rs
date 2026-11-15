// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Running-unit checkpoint selection against a node journal that other services
//! keep appending to (UPG-A27c). An interposed memory backend injects a real
//! journal append while a unit checkpoint selection is in flight, counts
//! original-frame reads, parks a selection, or rewrites an original frame.

use super::recovery::{RecoveryEvent, RecoveryKind, RecoveryState};
use super::unit_checkpoint::{UnitCheckpoint, UnitCheckpointSink, UnitTarget};
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
        }
    }
    fn set_mode(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
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
            if !is_unitcp(&prepared) {
                return Ok(self.apply(&prepared));
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
            let mode = *self.mode.lock().unwrap();
            match mode {
                Mode::Forward => {}
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
    fn sign_checkpoint(&self, body: &[u8]) -> RecordStoreResult<Vec<u8>> {
        Ok(self.0.sign_checkpoint_body(body))
    }
    async fn confirm(&self, _: &UnitCheckpoint) -> RecordStoreResult<()> {
        Ok(())
    }
    async fn recover(&self, _: &UnitCheckpoint) -> RecordStoreResult<()> {
        Ok(())
    }
}

struct Fixture {
    backend: Arc<Mem>,
    journal: Arc<RuntimeJournal>,
    sink: StoreUnitCheckpoints,
}
async fn fixture() -> Fixture {
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
                scan_items: 64,
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
        evidence,
        Arc::new(Signer(AuditSigningKey::from_seed(&[0x27; 32]))),
    );
    Fixture {
        backend,
        journal,
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
        units: {
            let mut units = BTreeMap::new();
            units.insert(
                "work".to_owned(),
                Count::parse(if terminal { "0.25" } else { "0.125" }).unwrap(),
            );
            units
        },
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
/// presents the exact same attempt (same operation id, same head predicate);
/// with the head moved the attempt stays retained for reconciliation.
/// WHY: re-proving against the moved head would change the claim digest for
/// the same operation id and wedge it as corruption.
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
        let refused = fixture.sink.persist(&unit(1)).await.unwrap_err().0;
        let seen = fixture.backend.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[1], seen[0], "the re-drive presents the exact attempt");
        assert!(
            refused.contains("running money native custody remains unresolved"),
            "{refused}"
        );
        assert!(
            !refused.contains("Corrupt") && !refused.contains("OperationConflict"),
            "{refused}"
        );
        let again = fixture.sink.persist(&unit(1)).await.unwrap_err().0;
        assert!(
            again.contains("running money native custody remains unresolved"),
            "{again}"
        );
        assert_eq!(
            fixture.backend.seen.lock().unwrap().len(),
            2,
            "a reconciling attempt is not resubmitted"
        );
        assert_eq!(selected_revision(&fixture.backend), None);
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
