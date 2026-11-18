// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::import_target::r0::{Access, Commit, Outcome};
use busbar_contract::persistence::{BackendInfo, Call, ClockObservation, Durability, Page, Scan};
use futures::FutureExt;
use std::time::Duration;
use std::{collections::BTreeMap, sync::Mutex};

/// One evaluated verdict, as a slot row records it.
#[derive(Clone, Copy)]
enum Verdict {
    Applied,
    Conflict,
    Time(u64),
}
/// (writer, slot) → (seq, fingerprint, verdict): STORE-TRANSACTIONS §2.5.
type SlotRows = BTreeMap<([u8; 16], u32), (u64, [u8; 32], Verdict)>;
/// One-shot hook the mock `commit` runs on the locked state before anything else.
type BeforeCommit = Box<dyn FnOnce(&mut Native) + Send>;
#[derive(Default)]
struct Native {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    slots: SlotRows,
    applied: usize,
    sends: Vec<[u8; 32]>,
    lose_reply: bool,
    /// Lose the reply of the next evaluated send, whatever its verdict.
    lose_any: bool,
    hold_reply: bool,
    now: u64,
    commit_now: Option<u64>,
    unknown_before: bool,
    /// One-shot reply, taken after the send is recorded and before the receipt lookup.
    force: Option<Result<Decision, Failure>>,
    /// One-shot write applied between a caller's read and its commit.
    before_commit: Option<BeforeCommit>,
}
#[derive(Default)]
struct Backend(Mutex<Native>);
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: busbar_contract::persistence::PHYSICAL_VERSION,
            durability: Durability::Local,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let native = self.0.lock().unwrap();
            let observed_at = ClockObservation {
                authority: [3; 16],
                unix_seconds: native.now,
            };
            if request.time.is_some_and(|guard| !guard.permits(native.now)) {
                return Ok(ReadResult::TimeGuardFailed { observed_at });
            }
            Ok(ReadResult::Values {
                observed_at,
                values: request
                    .addresses
                    .iter()
                    .map(|key| native.rows.get(key).cloned())
                    .collect(),
            })
        })
    }
    fn scan(&self, _: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async { panic!("startup must not discover grants by scanning business records") })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { panic!("writer identities must not come from wall time") })
    }
    fn commit(
        &self,
        prepared: PreparedCandidate,
        key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        Box::pin(async move {
            // The native Store adapter checks declared control effects before sending.
            control::admit(&prepared)?;
            let (decision, hold) = {
                let mut native = self.0.lock().unwrap();
                if let Some(apply) = native.before_commit.take() {
                    apply(&mut native);
                }
                let digest = prepared.fingerprint();
                native.sends.push(digest);
                if let Some(reply) = native.force.take() {
                    return reply;
                }
                let candidate = prepared.candidate();
                if std::mem::take(&mut native.unknown_before) {
                    return Err(Failure::Unknown);
                }
                let (slot, seq) = key.wire();
                let row = (candidate.id.writer, slot);
                let observed = |native: &Native, now: u64| ClockObservation {
                    authority: [3; 16],
                    unix_seconds: if now == 0 { native.now } else { now },
                };
                if !key.is_self_fenced() {
                    if let Some(&(recorded, fingerprint, verdict)) = native.slots.get(&row) {
                        if seq < recorded {
                            return Ok(Decision::Stale);
                        }
                        if seq == recorded {
                            if fingerprint != digest {
                                return Ok(Decision::OpIdConflict);
                            }
                            return Ok(match verdict {
                                Verdict::Applied => Decision::Applied(Secret::new(Vec::new())),
                                Verdict::Conflict => Decision::ConditionConflict,
                                Verdict::Time(now) => Decision::TimeGuardFailed {
                                    observed_at: observed(&native, now),
                                },
                            });
                        }
                    }
                }
                let seal = crate::seal::lend();
                if let Some(now) = native.commit_now.take() {
                    native.now = now;
                }
                let fenced = if !native.rows.contains_key(&root_address()) {
                    // Records in the reserved import set do not count (MIGRATE-ON-BOOT seam).
                    native
                        .rows
                        .keys()
                        .any(|a| control::counts_toward_empty(NamespaceId(a.namespace)))
                        || !native.slots.is_empty()
                        || !control::initialization(&prepared, self.info().dataset)
                } else {
                    let root = native
                        .rows
                        .get(&root_address())
                        .and_then(|v| control::Dataset::decode(v.expose(&seal)))
                        .unwrap();
                    let writer = native
                        .rows
                        .get(&writer_address(candidate.id.writer))
                        .and_then(|v| control::Writer::decode(v.expose(&seal)));
                    root.writer_epoch != candidate.id.writer_epoch
                        || !writer.is_some_and(|w| w.admits(candidate.id.execution_epoch))
                };
                let verdict = if fenced {
                    None
                } else if candidate
                    .time
                    .is_some_and(|guard| !guard.permits(native.now))
                {
                    Some(Verdict::Time(native.now))
                } else if candidate.predicates.iter().any(|predicate| {
                    let value = native.rows.get(&predicate.address);
                    !match &predicate.expected {
                        ExpectedValue::Absent => value.is_none(),
                        ExpectedValue::Exact(expected) => value == Some(expected),
                    }
                }) {
                    Some(Verdict::Conflict)
                } else {
                    for mutation in &candidate.mutations {
                        let (address, value) = match mutation {
                            Mutation::Put { address, value } => (address, value),
                            Mutation::Delete(address) => {
                                native.rows.remove(address);
                                continue;
                            }
                            Mutation::DeleteRange {
                                namespace,
                                prefix,
                                exact_key_length,
                            } => {
                                assert_eq!(*namespace, control::SLOT_NS);
                                assert_eq!(*exact_key_length, 20);
                                let closed: [u8; 16] = prefix.as_slice().try_into().unwrap();
                                native.slots.retain(|(writer, _), _| *writer != closed);
                                continue;
                            }
                        };
                        native.rows.insert(address.clone(), value.clone());
                    }
                    native.applied += 1;
                    Some(Verdict::Applied)
                };
                let decision = match verdict {
                    None => Decision::Fenced,
                    Some(verdict) => {
                        if !key.is_self_fenced() {
                            native.slots.insert(row, (seq, digest, verdict));
                        }
                        match verdict {
                            Verdict::Applied => Decision::Applied(Secret::new(Vec::new())),
                            Verdict::Conflict => Decision::ConditionConflict,
                            Verdict::Time(now) => Decision::TimeGuardFailed {
                                observed_at: observed(&native, now),
                            },
                        }
                    }
                };
                if std::mem::take(&mut native.lose_any) {
                    return Err(Failure::Unknown);
                }
                if matches!(decision, Decision::Applied(_)) {
                    if std::mem::take(&mut native.lose_reply) {
                        return Err(Failure::Unknown);
                    }
                    (decision, std::mem::take(&mut native.hold_reply))
                } else {
                    (decision, false)
                }
            };
            if hold {
                std::future::pending::<()>().await;
            }
            Ok(decision)
        })
    }
}
fn limits() -> Limits {
    Limits {
        pending_operations: 4,
        conflict_retries: 2,
        scan_items: 20,
        scan_bytes: 4096,
    }
}
fn startup(backend: &Arc<Backend>, create: bool) -> Startup {
    Startup::new(backend.clone(), limits(), create).unwrap()
}
async fn admitted(startup: &mut Startup) -> Arc<CoreStore> {
    for _ in 0..8 {
        if startup.advance().await.unwrap() == Progress::Admitted {
            return startup.store().unwrap();
        }
    }
    panic!("startup did not finish bounded phases")
}

/// The diagnostics emitted on this thread while `future` runs, as the fmt layer prints them.
async fn capture_diagnostics<T>(future: impl std::future::Future<Output = T>) -> (T, String) {
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    let out = future.await;
    drop(guard);
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    (out, text)
}

fn banner(diagnostic: &crate::diagnostics::Diagnostic) -> String {
    format!("diag={}", diagnostic.banner())
}

fn birth_of(backend: &Backend) -> Birth {
    let native = backend.0.lock().unwrap();
    Birth::decode(
        native.rows[&first_start::address()].expose(&crate::seal::lend()),
        DatasetId([1; 16]),
    )
    .unwrap()
}

fn writer_row(backend: &Backend, writer: [u8; 16]) -> control::Writer {
    let native = backend.0.lock().unwrap();
    control::Writer::decode(native.rows[&writer_address(writer)].expose(&crate::seal::lend()))
        .unwrap()
}

/// A successor over an unpublished birth record whose owner's writer row is open. It must
/// wait, change nothing, and take over only at the window computed from the record it sees.
async fn admitted_after_stall(backend: &Arc<Backend>, prior: [u8; 16]) -> Arc<CoreStore> {
    let snapshot = || {
        let native = backend.0.lock().unwrap();
        (native.rows.clone(), native.sends.len(), native.slots.len())
    };
    let before = snapshot();
    let birth = birth_of(backend);
    assert_eq!(
        birth.owner,
        Some(prior),
        "the record is not the prior owner's"
    );
    assert!(!birth.published, "the record is already published");
    let window = stall_window(&birth);
    assert_eq!(
        window,
        FIRST_START_STALL + READY_STEP * u32::try_from(birth.done_len()).unwrap()
    );
    let mut successor = startup(backend, false);
    assert_eq!(
        successor.advance().await.unwrap(),
        Progress::Pending,
        "first observation"
    );
    assert!(snapshot() == before, "the first observation wrote");
    tokio::time::advance(window / 2).await;
    assert_eq!(
        successor.advance().await.unwrap(),
        Progress::Pending,
        "half the window"
    );
    assert!(snapshot() == before, "half the window wrote");
    tokio::time::advance(window - window / 2 - Duration::from_millis(1)).await;
    assert_eq!(
        successor.advance().await.unwrap(),
        Progress::Pending,
        "1 ms before the window"
    );
    assert!(snapshot() == before, "1 ms before the window wrote");
    tokio::time::advance(Duration::from_millis(1)).await;
    let (store, log) = capture_diagnostics(admitted(&mut successor)).await;
    assert!(
        !writer_row(backend, prior).admits(1),
        "the prior owner is not retired"
    );
    assert_eq!(
        birth_of(backend).owner,
        Some(store.authority().unwrap().writer),
        "the successor does not own the record"
    );
    assert_eq!(
        log.matches(&banner(&FIRST_START_TAKEOVER)).count(),
        1,
        "{log}"
    );
    assert!(log.contains(&writer_hex(&prior)), "{log}");
    store
}

/// A: Initialize, Register, Admitted, then dropped with its writer row open (a crash). B is a
/// fresh Startup advanced to the window, so its next advance submits the takeover Register.
async fn takeover_built(backend: &Arc<Backend>) -> ([u8; 16], Startup) {
    let owner = admitted(&mut startup(backend, true))
        .await
        .first_start()
        .unwrap()
        .owner();
    let mut b = startup(backend, false);
    assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    tokio::time::advance(FIRST_START_STALL).await;
    let sends = backend.0.lock().unwrap().sends.len();
    assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
    assert!(matches!(b.phase, Phase::Register(.., Some(_))));
    assert_eq!(
        backend.0.lock().unwrap().sends.len(),
        sends,
        "built, not sent"
    );
    (owner, b)
}

fn initial_binding(instance: &str, digest: u8) -> first_start::Binding {
    first_start::Binding {
        instance: instance.into(),
        digest: [digest; 32],
    }
}

fn delayed_initial_write(store: &CoreStore) -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: store.next_id().unwrap(),
        codec: CANDIDATE_VERSION,
        predicates: Vec::new(),
        mutations: vec![Mutation::Put {
            address: Address {
                namespace: [9; 16],
                key: b"initial-state".to_vec(),
            },
            value: Secret::new(b"incurred-state".to_vec()),
        }],
        time: None,
        result: Secret::new(Vec::new()),
    })
    .unwrap()
}

fn host_initialization(value: &[u8]) -> (Vec<Predicate>, Vec<Mutation>) {
    let address = Address {
        namespace: [8; 16],
        key: b"host-initial-state".to_vec(),
    };
    (
        vec![Predicate {
            address: address.clone(),
            expected: ExpectedValue::Absent,
        }],
        vec![Mutation::Put {
            address,
            value: Secret::new(value.to_vec()),
        }],
    )
}

#[tokio::test(start_paused = true)]
async fn first_start_host_initialization_is_atomic_and_replay_is_read_only() {
    let backend = Arc::new(Backend::default());
    let store = admitted(&mut startup(&backend, true)).await;
    let proof = store.first_start().unwrap();
    let before = proof.initialization_witness().await.unwrap();
    let (mut predicates, mutations) = host_initialization(b"initial");
    predicates[0].expected = ExpectedValue::Exact(Secret::new(b"missing".to_vec()));
    assert_eq!(
        proof
            .initialize_host(initial_binding("host", 1), predicates, mutations)
            .await,
        Err(Error::Conflict)
    );
    // Neither the consumption marker nor the host row can survive a failed condition.
    {
        let native = backend.0.lock().unwrap();
        assert_eq!(
            native.rows[&first_start::address()].expose(&crate::seal::lend()),
            &before
        );
        assert!(!native.rows.keys().any(|a| a.namespace == [8; 16]));
    }
    // A fresh process reconciles the definite conflict without repurposing its candidate.
    let store = admitted_after_stall(&backend, proof.owner()).await;
    let proof = store.first_start().unwrap();
    let (predicates, mutations) = host_initialization(b"initial");
    assert_eq!(
        proof
            .initialize_host(initial_binding("host", 1), predicates, mutations)
            .await,
        Ok(Progress::Advanced)
    );
    let after = proof.initialization_witness().await.unwrap();
    assert_ne!(before, after);
    let sends = backend.0.lock().unwrap().sends.len();
    let (predicates, mutations) = host_initialization(b"replacement");
    assert_eq!(
        proof
            .initialize_host(initial_binding("host", 1), predicates, mutations)
            .await,
        Ok(Progress::Advanced)
    );
    assert_eq!(backend.0.lock().unwrap().sends.len(), sends);
    let native = backend.0.lock().unwrap();
    let address = Address {
        namespace: [8; 16],
        key: b"host-initial-state".to_vec(),
    };
    assert_eq!(
        native.rows[&address].expose(&crate::seal::lend()),
        b"initial"
    );
    assert!(String::from_utf8(after).unwrap().contains("initialized"));
}

#[tokio::test]
async fn first_start_host_unknown_retains_complete_candidate_and_stable_witness() {
    for lost_after in [false, true] {
        let backend = Arc::new(Backend::default());
        let store = admitted(&mut startup(&backend, true)).await;
        let proof = store.first_start().unwrap();
        let before = proof.initialization_witness().await.unwrap();
        assert!(!proof.host_initialization_pending("host").await);
        {
            let mut native = backend.0.lock().unwrap();
            native.unknown_before = !lost_after;
            native.lose_reply = lost_after;
        }
        let (predicates, mutations) = host_initialization(b"initial");
        assert_eq!(
            proof
                .initialize_host(initial_binding("host", 1), predicates, mutations)
                .await,
            Ok(Progress::Pending)
        );
        assert!(proof.host_initialization_pending("host").await);
        assert!(!proof.host_initialization_pending("other").await);
        let fingerprint = *backend.0.lock().unwrap().sends.last().unwrap();
        assert_eq!(proof.initialization_witness().await.unwrap(), before);
        let (predicates, mutations) = host_initialization(b"initial");
        assert_eq!(
            proof
                .initialize_host(initial_binding("host", 2), predicates, mutations)
                .await,
            Err(Error::Authority)
        );
        let (predicates, mutations) = host_initialization(b"changed");
        assert_eq!(
            proof
                .initialize_host(initial_binding("host", 1), predicates, mutations)
                .await,
            Err(Error::Authority)
        );
        let (mut predicates, mutations) = host_initialization(b"initial");
        predicates[0].expected = ExpectedValue::Exact(Secret::new(b"changed".to_vec()));
        assert_eq!(
            proof
                .initialize_host(initial_binding("host", 1), predicates, mutations)
                .await,
            Err(Error::Authority)
        );
        assert_eq!(proof.freeze(Vec::new()).await, Err(Error::Authority));
        let (predicates, mutations) = host_initialization(b"initial");
        assert_eq!(
            proof
                .initialize_host(initial_binding("host", 1), predicates, mutations)
                .await,
            Ok(Progress::Advanced)
        );
        assert_eq!(
            *backend.0.lock().unwrap().sends.last().unwrap(),
            fingerprint
        );
        assert!(!proof.host_initialization_pending("host").await);
        assert_ne!(proof.initialization_witness().await.unwrap(), before);
    }
}

#[tokio::test(start_paused = true)]
async fn first_start_host_initialization_takeover_fences_stale_completion() {
    let backend = Arc::new(Backend::default());
    let store = admitted(&mut startup(&backend, true)).await;
    let prior = store.first_start().unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    let (predicates, mutations) = host_initialization(b"initial");
    assert_eq!(
        prior
            .initialize_host(initial_binding("host", 1), predicates, mutations)
            .await,
        Ok(Progress::Pending)
    );
    let successor = admitted_after_stall(&backend, prior.owner()).await;
    let current = successor.first_start().unwrap();
    assert_eq!(prior.initialization_witness().await, Err(Error::Authority));
    let (predicates, mutations) = host_initialization(b"initial");
    assert_eq!(
        prior
            .initialize_host(initial_binding("host", 1), predicates, mutations)
            .await,
        // The successor superseded the exact birth witness: audited Reconcile (section 2.3 c).
        Ok(Progress::Reconcile)
    );
    let (predicates, mutations) = host_initialization(b"initial");
    assert_eq!(
        current
            .initialize_host(initial_binding("host", 1), predicates, mutations)
            .await,
        Ok(Progress::Advanced)
    );
    let (predicates, mutations) = host_initialization(b"initial");
    assert_eq!(
        current
            .initialize_host(initial_binding("host", 2), predicates, mutations)
            .await,
        Err(Error::Authority)
    );
    current.freeze(Vec::new()).await.unwrap();
    let (predicates, mutations) = host_initialization(b"new");
    assert_eq!(
        current
            .initialize_host(initial_binding("another", 1), predicates, mutations)
            .await,
        Err(Error::Authority)
    );
    current.publish().await.unwrap();
    assert_eq!(
        current.initialization_witness().await,
        Err(Error::Authority)
    );
    let (predicates, mutations) = host_initialization(b"initial");
    assert_eq!(
        current
            .initialize_host(initial_binding("host", 1), predicates, mutations)
            .await,
        Err(Error::Authority)
    );
}

#[tokio::test(start_paused = true)]
async fn first_start_before_plan_freeze_can_resume_but_fences_delayed_old_writes() {
    let backend = Arc::new(Backend::default());
    let first = admitted(&mut startup(&backend, true)).await;
    let prior = first.first_start().unwrap();
    let delayed = delayed_initial_write(&first);
    // A crash before the plan exists has issued no plane initialization authority.
    assert!(!prior.permits("one").await.unwrap());
    let second = admitted_after_stall(&backend, prior.owner()).await;
    let current = second.first_start().unwrap();
    assert_eq!(
        current
            .freeze(vec![initial_binding("one", 2)])
            .await
            .unwrap(),
        Progress::Advanced
    );
    assert!(current.permits("one").await.unwrap());
    assert!(!current.permits("unrelated").await.unwrap());
    assert!(matches!(
        backend
            .commit(
                delayed,
                busbar_contract::persistence::CommitKey::slotted(
                    65_535,
                    1,
                    &busbar_contract::caps::SlotSeal::acquire_for_tests()
                )
                .unwrap()
            )
            .await
            .unwrap(),
        Decision::Fenced
    ));
    assert_eq!(
        prior.freeze(vec![initial_binding("one", 1)]).await,
        // A self-fenced FENCED on a first send is final (section 2.3).
        Err(Error::Authority)
    );
    assert!(!prior.permits("one").await.unwrap());
    assert!(!prior.published().await);
    assert!(current.permits("one").await.unwrap());
    assert!(!backend
        .0
        .lock()
        .unwrap()
        .rows
        .keys()
        .any(|a| a.namespace == [9; 16]));
}

#[tokio::test(start_paused = true)]
async fn first_start_frozen_plan_and_native_initialization_survive_crash_exactly() {
    let backend = Arc::new(Backend::default());
    let first = admitted(&mut startup(&backend, true)).await;
    let prior = first.first_start().unwrap();
    let plan = vec![initial_binding("one", 1), initial_binding("two", 2)];
    assert_eq!(
        prior.freeze(plan.clone()).await.unwrap(),
        Progress::Advanced
    );
    // Native initialization effects and quota/barrier state remain intact through
    // takeover. Successor authority is never permission to reconstruct counters.
    assert!(matches!(
        backend
            .commit(
                delayed_initial_write(&first),
                busbar_contract::persistence::CommitKey::slotted(
                    65_535,
                    1,
                    &busbar_contract::caps::SlotSeal::acquire_for_tests()
                )
                .unwrap()
            )
            .await
            .unwrap(),
        Decision::Applied(_)
    ));
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(prior.complete("one").await.unwrap(), Progress::Pending);
    let second = admitted_after_stall(&backend, prior.owner()).await;
    let current = second.first_start().unwrap();
    assert_eq!(
        current
            .freeze(vec![initial_binding("one", 8), initial_binding("two", 2)])
            .await,
        Err(Error::Authority)
    );
    assert_eq!(
        current.freeze(plan.clone()).await.unwrap(),
        Progress::Advanced
    );
    assert!(
        !current.permits("one").await.unwrap(),
        "confirmed per-instance Done cannot regrant"
    );
    assert!(current.permits("two").await.unwrap());
    // A late replay can correctly acknowledge old effects; only the final current
    // owner CAS grants publication, so that acknowledgment cannot revive the owner.
    // The successor superseded the exact birth witness, so the late replay is an
    // audited Reconcile (section 2.3 c) and the held attempt blocks any other change.
    assert_eq!(prior.complete("one").await.unwrap(), Progress::Reconcile);
    assert_eq!(prior.complete("two").await, Err(Error::Authority));
    assert!(!prior.permits("two").await.unwrap());
    assert!(!prior.published().await);
    assert!(current.permits("two").await.unwrap());
    assert_eq!(current.complete("one").await.unwrap(), Progress::Advanced);
    assert_eq!(current.complete("two").await.unwrap(), Progress::Advanced);
    assert_eq!(current.publish().await.unwrap(), Progress::Advanced);
    assert!(!current.permits("two").await.unwrap());
    let third = admitted(&mut startup(&backend, false)).await;
    assert!(
        third.first_start().is_none(),
        "completed birth proof grants no new process authority"
    );
    let native = backend.0.lock().unwrap();
    assert_eq!(
        native.rows[&Address {
            namespace: [9; 16],
            key: b"initial-state".to_vec()
        }]
            .expose(&crate::seal::lend()),
        b"incurred-state"
    );
}

#[tokio::test]
async fn first_start_unknown_plan_freeze_retains_exact_candidate_and_missing_proof_never_grants() {
    let backend = Arc::new(Backend::default());
    let first = admitted(&mut startup(&backend, true)).await;
    let proof = first.first_start().unwrap();
    let plan = vec![initial_binding("one", 1)];
    backend.0.lock().unwrap().unknown_before = true;
    assert_eq!(proof.freeze(plan.clone()).await.unwrap(), Progress::Pending);
    let sent = *backend.0.lock().unwrap().sends.last().unwrap();
    assert!(!proof.permits("one").await.unwrap());
    assert_eq!(
        proof.freeze(vec![initial_binding("one", 2)]).await,
        Err(Error::Authority)
    );
    assert_eq!(proof.freeze(plan).await.unwrap(), Progress::Advanced);
    assert_eq!(*backend.0.lock().unwrap().sends.last().unwrap(), sent);
    assert!(proof.permits("one").await.unwrap());
    // An older current-format namespace without the new native birth marker is
    // retained data, even when all plugin business rows happen to be absent.
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .remove(&first_start::address());
    let retained = admitted(&mut startup(&backend, false)).await;
    assert!(retained.first_start().is_none());
}

#[tokio::test(start_paused = true)]
async fn first_start_late_applied_ready_cannot_publish_after_owner_takeover() {
    let backend = Arc::new(Backend::default());
    let first = admitted(&mut startup(&backend, true)).await;
    let prior = first.first_start().unwrap();
    let plan = vec![initial_binding("one", 1)];
    prior.freeze(plan.clone()).await.unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(prior.complete("one").await.unwrap(), Progress::Pending);
    let successor = admitted_after_stall(&backend, prior.owner()).await;
    let current = successor.first_start().unwrap();
    current.freeze(plan).await.unwrap();
    // The successor superseded the exact birth witness: audited Reconcile (section 2.3 c).
    assert_eq!(prior.complete("one").await.unwrap(), Progress::Reconcile);
    assert_eq!(
        prior.publish().await,
        Err(Error::Authority),
        "an unresolved READY never grants publication"
    );
    assert!(!prior.permits("one").await.unwrap());
    assert!(!prior.published().await);
    assert!(!current.published().await);
    assert!(
        !current.permits("one").await.unwrap(),
        "the current owner's Done entry remains closed"
    );
    assert_eq!(current.publish().await.unwrap(), Progress::Advanced);
}

#[tokio::test]
async fn first_start_entitlement_is_exact_caller_scoped_and_ends_at_confirmed_ready() {
    use crate::{
        host_record_bootstrap::ENTITLEMENT,
        host_services::{InstanceFacts, KernelServices},
    };
    use busbar_contract::{abi::mechanism::KindCode, services::Caller};
    let backend = Arc::new(Backend::default());
    let store = admitted(&mut startup(&backend, true)).await;
    let proof = store.first_start().unwrap();
    proof.freeze(vec![initial_binding("one", 1)]).await.unwrap();
    let mut host = KernelServices::new();
    host = host.with_persistence(store);
    host.admit(&"one".into(), InstanceFacts::default())
        .await
        .unwrap();
    let caller = Caller::for_test(Arc::from("one"), KindCode::Plane);
    host.bind_native_record_bootstrap(&caller).await.unwrap();
    assert!(host.entitled(&caller, None, ENTITLEMENT));
    assert!(host.entitled(&caller.clone(), None, ENTITLEMENT));
    let replacement = Caller::for_test(Arc::from("one"), KindCode::Plane);
    assert!(!host.entitled(&replacement, None, ENTITLEMENT));
    assert!(!host.entitled(&caller, None, "record-quota-bootstrap:forged"));
    assert!(host
        .admit(&"one".into(), InstanceFacts::default())
        .await
        .is_err());
    proof.complete("one").await.unwrap();
    host.revoke_native_record_bootstrap(&caller).unwrap();
    assert!(!host.entitled(&caller, None, ENTITLEMENT));
    host.bind_native_record_bootstrap(&caller).await.unwrap();
    assert!(
        !host.entitled(&caller, None, ENTITLEMENT),
        "per-instance Done cannot regrant even before global publication"
    );
    proof.publish().await.unwrap();
    host.admit(&"one".into(), InstanceFacts::default())
        .await
        .unwrap();
    host.bind_native_record_bootstrap(&replacement)
        .await
        .unwrap();
    assert!(
        !host.entitled(&replacement, None, ENTITLEMENT),
        "reload never inherits initial authority"
    );
}

#[tokio::test]
async fn startup_reopen_uses_new_writer_and_retirement_is_durable() {
    let backend = Arc::new(Backend::default());
    let mut first = startup(&backend, true);
    let a = admitted(&mut first).await;
    let proof = a.first_start().unwrap();
    assert_eq!(proof.freeze(Vec::new()).await.unwrap(), Progress::Advanced);
    assert_eq!(proof.publish().await.unwrap(), Progress::Advanced);
    let mut second = startup(&backend, false);
    let b = admitted(&mut second).await;
    assert_ne!(a.authority().unwrap().writer, b.authority().unwrap().writer);
    assert_eq!(a.authority().unwrap().execution_epoch, 1);
    let before = backend.0.lock().unwrap().sends.len();
    first.begin_retirement().unwrap();
    assert!(first.store().is_none());
    assert!(matches!(a.next_id(), Err(AccessError::Closed)));
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(first.advance().await.unwrap(), Progress::Pending);
    assert_eq!(first.advance().await.unwrap(), Progress::Retired);
    let native = backend.0.lock().unwrap();
    assert_eq!(native.sends[before], native.sends[before + 1]);
    let seal = crate::seal::lend();
    let retired = control::Writer::decode(
        native.rows[&writer_address(a.authority().unwrap().writer)].expose(&seal),
    )
    .unwrap();
    assert!(!retired.admits(1));
    let active = control::Writer::decode(
        native.rows[&writer_address(b.authority().unwrap().writer)].expose(&seal),
    )
    .unwrap();
    assert!(active.admits(1));
}

#[tokio::test]
async fn startup_lost_bootstrap_and_cancelled_registration_replay_exactly() {
    let backend = Arc::new(Backend::default());
    let mut start = startup(&backend, true);
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(start.advance().await.unwrap(), Progress::Pending);
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    {
        let native = backend.0.lock().unwrap();
        assert_eq!(native.sends[0], native.sends[1]);
    }
    assert!(matches!(start.phase, Phase::Inspect));
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    assert!(matches!(start.phase, Phase::Register(..)));
    backend.0.lock().unwrap().hold_reply = true;
    assert!(start.advance().now_or_never().is_none());
    assert!(start.store().is_none());
    let store = admitted(&mut start).await;
    let native = backend.0.lock().unwrap();
    // DES-264 §3.2 (86f2c543e0): the last commit opens generation 0; the two before it are the
    // cancelled registration and its exact replay.
    let opened = native.sends.len() - 1;
    assert_eq!(native.sends[opened - 2], native.sends[opened - 1]);
    assert_eq!(
        native
            .rows
            .keys()
            .filter(|a| a.namespace == control::NAMESPACE.0 && a.key.first() == Some(&b'w'))
            .count(),
        2
    );
    assert_ne!(store.authority().unwrap().writer, [0; 16]);
}

#[tokio::test]
async fn fresh_initialization_never_exposes_authority_without_its_manifest() {
    for interruption in ["before", "lost", "cancelled"] {
        let backend = Arc::new(Backend::default());
        let mut start = startup(&backend, true);
        assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
        let Phase::Initialize(attempt) = &start.phase else {
            panic!("one retained initialization")
        };
        let candidate = attempt.candidate();
        assert_eq!(candidate.candidate().mutations.len(), 5);
        assert!(control::initialization(candidate, backend.info().dataset));
        {
            let mut native = backend.0.lock().unwrap();
            native.unknown_before = interruption == "before";
            native.lose_reply = interruption == "lost";
            native.hold_reply = interruption == "cancelled";
        }
        if interruption == "cancelled" {
            assert!(start.advance().now_or_never().is_none());
        } else {
            assert_eq!(start.advance().await.unwrap(), Progress::Pending);
        }
        assert!(start.store().is_none());
        {
            let native = backend.0.lock().unwrap();
            assert_eq!(
                native.rows.contains_key(&root_address()),
                native.rows.contains_key(&manifest_address())
            );
            assert_eq!(
                native.rows.len(),
                if interruption == "before" { 0 } else { 5 }
            );
        }
        assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
        assert!(
            matches!(start.phase, Phase::Inspect),
            "Applied goes directly to inspection"
        );
        {
            let native = backend.0.lock().unwrap();
            assert_eq!(native.sends.len(), 2);
            assert_eq!(
                native.sends[0], native.sends[1],
                "retry retains the complete original candidate"
            );
            assert_eq!(native.applied, 1, "no separate format publication commit");
            assert_eq!(native.rows.len(), 5);
            assert!(native.rows.contains_key(&root_address()));
            assert!(native.rows.contains_key(&manifest_address()));
            assert!(native.rows.contains_key(&first_start::address()));
        }
        // A process lost after the initialization commit can reopen the complete
        // current format instead of inheriting a ROOT-only intermediate state.
        drop(start);
        let mut reopened = startup(&backend, false);
        admitted(&mut reopened).await;
        assert_eq!(
            backend.0.lock().unwrap().applied,
            3,
            "only initialization, new-writer registration and generation 0's open (DES-264 §3.2)"
        );
    }
}

#[tokio::test]
async fn startup_unknown_formats_and_partial_initialization_never_write() {
    let backend = Arc::new(Backend::default());
    admitted(&mut startup(&backend, true)).await;
    let original = backend.0.lock().unwrap().rows[&manifest_address()].clone();
    for offset in [0, 8, 12, 16, 20, 72] {
        let mut changed = original.expose(&crate::seal::lend()).clone();
        changed[offset] ^= 0x40;
        backend
            .0
            .lock()
            .unwrap()
            .rows
            .insert(manifest_address(), Secret::new(changed));
        let before = backend.0.lock().unwrap().sends.len();
        assert_eq!(
            startup(&backend, true).advance().await,
            Err(Error::UnsupportedFormat)
        );
        assert_eq!(backend.0.lock().unwrap().sends.len(), before);
    }
    backend.0.lock().unwrap().rows.remove(&manifest_address());
    let before = backend.0.lock().unwrap().sends.len();
    assert_eq!(
        startup(&backend, true).advance().await,
        Err(Error::IncompleteInitialization)
    );
    assert_eq!(backend.0.lock().unwrap().sends.len(), before);
}

#[tokio::test]
async fn startup_absent_markers_do_not_prove_empty_and_create_is_explicit() {
    let backend = Arc::new(Backend::default());
    assert_eq!(
        startup(&backend, false).advance().await,
        Err(Error::InitializationNotAllowed)
    );
    assert!(backend.0.lock().unwrap().sends.is_empty());
    let address = Address {
        namespace: [9; 16],
        key: b"existing".to_vec(),
    };
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .insert(address.clone(), Secret::new(b"preserve".to_vec()));
    let mut start = startup(&backend, true);
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    // Every store answers FENCED to Initialize on a non-empty dataset (section 2.6); the
    // re-inspect finds no dataset root and refuses as before.
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    assert_eq!(start.advance().await, Err(Error::Backend(Failure::Refused)));
    let native = backend.0.lock().unwrap();
    assert_eq!(native.rows.len(), 1);
    assert_eq!(
        native.rows[&address].expose(&crate::seal::lend()),
        b"preserve"
    );
}

#[tokio::test]
async fn startup_retirement_cannot_discard_uncertain_business_work() {
    let backend = Arc::new(Backend::default());
    let mut start = startup(&backend, true);
    let store = admitted(&mut start).await;
    let candidate = PreparedCandidate::new(Candidate {
        id: store.next_id().unwrap(),
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![Mutation::Put {
            address: Address {
                namespace: [7; 16],
                key: vec![1],
            },
            value: Secret::new(vec![2]),
        }],
        time: None,
        result: Secret::new(vec![]),
    })
    .unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    let pending = store.submit(candidate).await.unwrap();
    assert!(matches!(pending.result, SubmitResult::Uncertain));
    assert_eq!(start.begin_retirement(), Err(Error::PendingWork));
    assert!(matches!(store.next_id(), Err(AccessError::Closed)));
    assert!(matches!(
        store.retry(pending.id).await.unwrap().result,
        SubmitResult::Decided(_)
    ));
    start.begin_retirement().unwrap();
    assert_eq!(start.advance().await.unwrap(), Progress::Retired);
}

#[tokio::test]
async fn claims_expiry_is_inclusive_and_owner_kind_scoped() {
    use crate::persistence::claims::{Claims, Outcome};
    let backend = Arc::new(Backend::default());
    let store = admitted(&mut startup(&backend, true)).await;
    backend.0.lock().unwrap().now = 10;
    let claims = Claims::authorized(&store, "caller-a", "proof");
    assert_eq!(claims.redeem("token", 10).await.unwrap(), Outcome::Claimed);
    assert_eq!(
        claims.redeem("token", 10).await.unwrap(),
        Outcome::AlreadyClaimed
    );
    assert_eq!(
        Claims::authorized(&store, "caller-b", "proof")
            .redeem("token", 10)
            .await
            .unwrap(),
        Outcome::Claimed
    );
    assert_eq!(
        Claims::authorized(&store, "caller-a", "other")
            .redeem("token", 10)
            .await
            .unwrap(),
        Outcome::Claimed
    );
    backend.0.lock().unwrap().now = 11;
    assert_eq!(claims.redeem("token", 20).await.unwrap(), Outcome::Claimed);
    assert_eq!(
        claims.redeem("token", 30).await.unwrap(),
        Outcome::AlreadyClaimed
    );
    assert_eq!(claims.redeem("past", 10).await.unwrap(), Outcome::Expired);
    backend.0.lock().unwrap().now = u64::MAX;
    assert_eq!(
        claims.redeem("last", u64::MAX).await.unwrap(),
        Outcome::Claimed
    );
    assert_eq!(
        claims.redeem("last", u64::MAX).await.unwrap(),
        Outcome::AlreadyClaimed
    );
}

#[tokio::test]
async fn claims_queued_expiry_and_clock_rewind_cannot_consume_outside_interval() {
    use crate::persistence::claims::{Claims, Outcome};
    let backend = Arc::new(Backend::default());
    let store = admitted(&mut startup(&backend, true)).await;
    let claims = Claims::authorized(&store, "caller", "proof");
    backend.0.lock().unwrap().now = 10;
    let count = backend.0.lock().unwrap().rows.len();
    backend.0.lock().unwrap().commit_now = Some(11);
    assert_eq!(claims.redeem("queued", 10).await.unwrap(), Outcome::Expired);
    assert_eq!(backend.0.lock().unwrap().rows.len(), count);
    backend.0.lock().unwrap().now = 10;
    assert_eq!(claims.redeem("old", 10).await.unwrap(), Outcome::Claimed);
    backend.0.lock().unwrap().now = 11;
    backend.0.lock().unwrap().commit_now = Some(10);
    assert_eq!(
        claims.redeem("old", 20).await.unwrap(),
        Outcome::AlreadyClaimed
    );
    backend.0.lock().unwrap().now = 11;
    assert_eq!(claims.redeem("old", 20).await.unwrap(), Outcome::Claimed);
}

#[tokio::test]
async fn claims_lost_reply_replays_and_an_unevaluated_send_expires_on_retry() {
    use crate::persistence::claims::{Claims, Outcome};
    let backend = Arc::new(Backend::default());
    let store = admitted(&mut startup(&backend, true)).await;
    let claims = Claims::authorized(&store, "caller", "proof");
    backend.0.lock().unwrap().now = 10;
    backend.0.lock().unwrap().lose_reply = true;
    let Outcome::Pending(pending) = claims.redeem("applied", 10).await.unwrap() else {
        panic!("expected retained claim")
    };
    backend.0.lock().unwrap().now = 11;
    assert_eq!(claims.retry(pending).await.unwrap(), Outcome::Claimed);
    backend.0.lock().unwrap().unknown_before = true;
    let Outcome::Pending(pending) = claims.redeem("unresolved", 20).await.unwrap() else {
        panic!("expected retained claim")
    };
    backend.0.lock().unwrap().now = 21;
    // The first send was never evaluated, so the equal-seq retry is the slot row's
    // single evaluation: a consistent time-guard refusal is final (section 2.3).
    assert_eq!(claims.retry(pending).await.unwrap(), Outcome::Expired);
    assert!(store.stop_admission().unwrap().is_empty());
}

fn business(store: &CoreStore, key: u8) -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: store.next_id().unwrap(),
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![Mutation::Put {
            address: Address {
                namespace: [7; 16],
                key: vec![key],
            },
            value: Secret::new(vec![key]),
        }],
        time: None,
        result: Secret::new(vec![]),
    })
    .unwrap()
}

fn writer_fence(backend: &Backend, store: &CoreStore) -> control::Writer {
    control::Writer::decode(
        backend.0.lock().unwrap().rows[&writer_address(store.authority().unwrap().writer)]
            .expose(&crate::seal::lend()),
    )
    .unwrap()
}

#[tokio::test]
async fn live_roll_serves_new_epoch_while_old_unknown_blocks_retirement() {
    let backend = Arc::new(Backend::default());
    let mut start = startup(&backend, true);
    let store = admitted(&mut start).await;
    let old = business(&store, 1);
    let stale = business(&store, 2);
    backend.0.lock().unwrap().unknown_before = true;
    let old_pending = store.submit(old.clone()).await.unwrap();
    assert!(matches!(old_pending.result, SubmitResult::Uncertain));
    start.begin_epoch_roll().unwrap();
    assert_eq!(start.begin_epoch_roll(), Err(Error::NotAdmitted));
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    assert!(Arc::ptr_eq(&store, &start.store().unwrap()));
    assert_eq!(store.authority().unwrap().execution_epoch, 2);
    let sends = backend.0.lock().unwrap().sends.len();
    assert!(matches!(
        store.submit(stale).await,
        Err(AccessError::Authority)
    ));
    assert_eq!(backend.0.lock().unwrap().sends.len(), sends);
    assert!(matches!(
        store.submit(business(&store, 3)).await.unwrap().result,
        SubmitResult::Decided(_)
    ));
    assert_eq!(start.advance().await.unwrap(), Progress::Draining);
    assert_eq!(writer_fence(&backend, &store).retired_through, 0);
    assert!(matches!(
        store.retry(old_pending.id).await.unwrap().result,
        SubmitResult::Decided(_)
    ));
    assert_eq!(
        *backend.0.lock().unwrap().sends.last().unwrap(),
        old.fingerprint()
    );
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    assert_eq!(writer_fence(&backend, &store).retired_through, 0);
    assert_eq!(start.advance().await.unwrap(), Progress::Admitted);
    assert_eq!(
        writer_fence(&backend, &store),
        control::Writer {
            retired_through: 1,
            admitted_through: 2
        }
    );
    assert!(Arc::ptr_eq(&store, &start.store().unwrap()));
}

#[tokio::test]
async fn live_roll_cancelled_or_lost_grant_and_retirement_replay_exactly() {
    for cancel in [false, true] {
        let backend = Arc::new(Backend::default());
        let mut start = startup(&backend, true);
        let store = admitted(&mut start).await;
        start.begin_epoch_roll().unwrap();
        for grant in [true, false] {
            let before = backend.0.lock().unwrap().sends.len();
            {
                let mut native = backend.0.lock().unwrap();
                native.hold_reply = cancel;
                native.lose_reply = !cancel;
            }
            if cancel {
                assert!(start.advance().now_or_never().is_none());
            } else {
                assert_eq!(start.advance().await.unwrap(), Progress::Pending);
            }
            assert!(Arc::ptr_eq(&store, &start.store().unwrap()));
            assert_eq!(
                store.authority().unwrap().execution_epoch,
                if grant { 1 } else { 2 }
            );
            assert_eq!(
                start.advance().await.unwrap(),
                if grant {
                    Progress::Advanced
                } else {
                    Progress::Admitted
                }
            );
            {
                let native = backend.0.lock().unwrap();
                assert_eq!(native.sends[before], native.sends[before + 1]);
            }
            if grant {
                assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
            }
        }
        assert_eq!(writer_fence(&backend, &store).retired_through, 1);
    }
}

#[tokio::test]
async fn live_roll_shutdown_uses_current_fence_and_never_reopens_admission() {
    let backend = Arc::new(Backend::default());
    let mut start = startup(&backend, true);
    let store = admitted(&mut start).await;
    for epoch in 2..=3 {
        start.begin_epoch_roll().unwrap();
        assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
        assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
        assert_eq!(start.advance().await.unwrap(), Progress::Admitted);
        assert_eq!(store.authority().unwrap().execution_epoch, epoch);
    }
    // Even a shutdown that races an already prepared grant cannot be reopened.
    start.begin_epoch_roll().unwrap();
    assert!(store.stop_admission().unwrap().is_empty());
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    assert!(matches!(store.next_id(), Err(AccessError::Closed)));
    assert_eq!(start.advance().await.unwrap(), Progress::Advanced);
    assert_eq!(start.advance().await.unwrap(), Progress::Admitted);
    start.begin_retirement().unwrap();
    assert_eq!(start.advance().await.unwrap(), Progress::Retired);
    assert_eq!(
        writer_fence(&backend, &store),
        control::Writer {
            retired_through: 4,
            admitted_through: 4
        }
    );
}

#[tokio::test]
async fn live_roll_conflict_and_expired_authority_are_not_admission() {
    for expired in [false, true] {
        let backend = Arc::new(Backend::default());
        let mut start = startup(&backend, true);
        let store = admitted(&mut start).await;
        start.begin_epoch_roll().unwrap();
        let Phase::Grant(session, _, _, _) = &start.phase else {
            panic!("grant")
        };
        let writer = if expired {
            session.manifest.registrar.writer
        } else {
            store.authority().unwrap().writer
        };
        backend.0.lock().unwrap().rows.insert(
            writer_address(writer),
            Secret::new(
                control::Writer {
                    retired_through: 1,
                    admitted_through: 1,
                }
                .encode()
                .unwrap()
                .to_vec(),
            ),
        );
        assert_eq!(
            start.advance().await,
            if expired {
                // A FENCED self-fenced first send is final (section 2.3).
                Err(Error::Authority)
            } else {
                Err(Error::Conflict)
            }
        );
        assert_eq!(store.authority().unwrap().execution_epoch, 1);
        assert!(Arc::ptr_eq(&store, &start.store().unwrap()));
        assert_eq!(start.begin_epoch_roll(), Err(Error::NotAdmitted));
    }
}

#[tokio::test]
async fn live_roll_epoch_exhaustion_is_explicit_and_does_not_send() {
    let backend = Arc::new(Backend::default());
    let mut start = startup(&backend, true);
    let store = admitted(&mut start).await;
    let authority = WriterAuthority {
        execution_epoch: u64::MAX,
        ..store.authority().unwrap()
    };
    let writer = control::Writer {
        retired_through: u64::MAX - 1,
        admitted_through: u64::MAX,
    };
    backend.0.lock().unwrap().rows.insert(
        writer_address(authority.writer),
        Secret::new(writer.encode().unwrap().to_vec()),
    );
    let store = Arc::new(
        CoreStore::attach(backend.clone(), authority, limits())
            .await
            .unwrap(),
    );
    let Phase::Admitted(session) = &mut start.phase else {
        panic!("admitted")
    };
    session.writer = writer;
    session.store = store.clone();
    let before = backend.0.lock().unwrap().sends.len();
    assert_eq!(start.begin_epoch_roll(), Err(Error::EpochExhausted));
    assert_eq!(backend.0.lock().unwrap().sends.len(), before);
    assert!(Arc::ptr_eq(&store, &start.store().unwrap()));
    start.begin_retirement().unwrap();
    assert_eq!(start.advance().await.unwrap(), Progress::Retired);
}

fn writer_rows(backend: &Backend) -> usize {
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .keys()
        .filter(|address| {
            address.namespace == control::NAMESPACE.0
                && matches!(
                    control::Key::decode(&address.key),
                    Some(control::Key::Writer(_))
                )
        })
        .count()
}

async fn finish_first_start(store: &CoreStore) {
    let first = store.first_start().expect("first-start owner");
    assert_eq!(first.freeze(Vec::new()).await, Ok(Progress::Advanced));
    assert_eq!(first.publish().await, Ok(Progress::Advanced));
    assert!(first.published().await);
}

/// 8.2: a lost reply on Initialize, then on Register: the retry is answered
/// FENCED/CONDITION_CONFLICT and the readback finds this attempt's own writer row.
#[tokio::test]
async fn lost_initialize_and_register_replies_resolve_by_readback() {
    let backend = Arc::new(Backend::default());
    let mut start = startup(&backend, true);
    assert_eq!(start.advance().await, Ok(Progress::Advanced));
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(start.advance().await, Ok(Progress::Pending));
    assert_eq!(
        start.advance().await,
        Ok(Progress::Advanced),
        "FENCED → readback → Applied"
    );
    assert!(matches!(start.phase, Phase::Inspect));
    assert_eq!(start.advance().await, Ok(Progress::Advanced));
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(start.advance().await, Ok(Progress::Pending));
    assert_eq!(
        start.advance().await,
        Ok(Progress::Advanced),
        "CONFLICT → readback → Applied"
    );
    assert_eq!(start.advance().await, Ok(Progress::Admitted));
    finish_first_start(&start.store().unwrap()).await;
}

/// 8.2: a lost reply on a writer transition (retirement) resolves by its (E) witness.
#[tokio::test]
async fn lost_writer_transition_reply_resolves_by_readback() {
    let backend = Arc::new(Backend::default());
    let mut start = startup(&backend, true);
    let store = admitted(&mut start).await;
    finish_first_start(&store).await;
    start.begin_retirement().unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(start.advance().await, Ok(Progress::Pending));
    assert_eq!(start.advance().await, Ok(Progress::Retired));
}

async fn initialized_only(backend: &Arc<Backend>) {
    let mut first = startup(backend, true);
    assert_eq!(first.advance().await, Ok(Progress::Advanced));
    assert_eq!(first.advance().await, Ok(Progress::Advanced));
    assert!(matches!(first.phase, Phase::Inspect));
}

#[tokio::test]
async fn first_register_native_fences_are_satisfied_by_declared_initialize_effects() {
    let backend = Arc::new(Backend::default());
    initialized_only(&backend).await;
    let mut start = startup(&backend, false);
    assert_eq!(start.advance().await, Ok(Progress::Advanced));
    let Phase::Register(_, _, _, attempt, _) = &start.phase else {
        panic!("first Register retained before submission")
    };
    assert_eq!(control::admit(attempt.candidate()), Ok(()));
    {
        let native = backend.0.lock().unwrap();
        let fences = control::fences(attempt.candidate());
        assert_eq!(fences.len(), 2);
        for fence in fences {
            let ExpectedValue::Exact(expected) = fence.expected else {
                panic!("Register requires exact root and epoch fences")
            };
            assert_eq!(
                native.rows.get(&fence.address),
                Some(&expected),
                "Initialize must declare every row needed by the first Register fence"
            );
        }
    }
    assert_eq!(start.advance().await, Ok(Progress::Advanced));
    assert_eq!(start.advance().await, Ok(Progress::Admitted));
}

/// 8.2b: racing initializers, plain and with the loser's reply lost. The loser
/// resolves its lost attempt definitively and re-inspects. Under FIRST-START-TAKEOVER it
/// never refuses: over the winner's live first start it waits (`Pending`) and writes
/// nothing; over a still-unowned record its Register loses to the winner's and then it
/// waits. The winner's writer row is untouched and it finishes first start.
#[tokio::test]
async fn racing_initializers_loser_waits_and_winner_finishes() {
    for lose in [false, true] {
        for loser_reinspects_before_winner_registers in [true, false] {
            let backend = Arc::new(Backend::default());
            let mut a = startup(&backend, true);
            let mut b = startup(&backend, true);
            assert_eq!(a.advance().await, Ok(Progress::Advanced));
            assert_eq!(b.advance().await, Ok(Progress::Advanced));
            assert_eq!(b.advance().await, Ok(Progress::Advanced), "B initializes");
            if !loser_reinspects_before_winner_registers {
                assert_eq!(b.advance().await, Ok(Progress::Advanced));
                assert_eq!(b.advance().await, Ok(Progress::Advanced), "B registers");
            }
            if lose {
                backend.0.lock().unwrap().lose_any = true;
                assert_eq!(a.advance().await, Ok(Progress::Pending));
            }
            assert_eq!(
                a.advance().await,
                Ok(Progress::Advanced),
                "A resolves Fenced"
            );
            let rows = writer_rows(&backend);
            let sends = backend.0.lock().unwrap().sends.len();
            let store = if loser_reinspects_before_winner_registers {
                // The record is unowned: A builds a Register, sends nothing, and loses it
                // to B's; then A waits on B's live first start.
                assert_eq!(a.advance().await, Ok(Progress::Advanced), "A builds");
                assert_eq!(
                    backend.0.lock().unwrap().sends.len(),
                    sends,
                    "built, not sent"
                );
                let store = admitted(&mut b).await;
                assert_eq!(a.advance().await, Ok(Progress::Advanced), "A loses");
                assert!(matches!(a.phase, Phase::Inspect));
                let rows = writer_rows(&backend);
                assert_eq!(a.advance().await, Ok(Progress::Pending));
                assert_eq!(writer_rows(&backend), rows, "A wrote nothing");
                store
            } else {
                assert_eq!(a.advance().await, Ok(Progress::Pending));
                assert_eq!(writer_rows(&backend), rows, "A wrote nothing");
                assert_eq!(
                    backend.0.lock().unwrap().sends.len(),
                    sends,
                    "A built no candidate"
                );
                admitted(&mut b).await
            };
            assert!(a.waiting_on().is_some());
            let winner = store.authority().unwrap().writer;
            assert!(writer_row(&backend, winner).admits(1));
            finish_first_start(&store).await;
            assert!(writer_row(&backend, winner).admits(1));
        }
    }
}

/// 8.2b winner-late: B's Initialize applies but its reply is lost; A's is FENCED
/// and A builds a Register over the unowned birth record without sending it; B's retry
/// reads back Applied, inspects the unowned record and registers retiring nobody. A's
/// Register then loses and A waits on B (FIRST-START-TAKEOVER).
#[tokio::test]
async fn racing_initializers_winner_late_registers_retiring_nobody() {
    let backend = Arc::new(Backend::default());
    let mut a = startup(&backend, true);
    let mut b = startup(&backend, true);
    assert_eq!(a.advance().await, Ok(Progress::Advanced));
    assert_eq!(b.advance().await, Ok(Progress::Advanced));
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(
        b.advance().await,
        Ok(Progress::Pending),
        "B applied, reply lost"
    );
    assert_eq!(a.advance().await, Ok(Progress::Advanced), "A is FENCED");
    let sends = backend.0.lock().unwrap().sends.len();
    assert_eq!(a.advance().await, Ok(Progress::Advanced), "A builds");
    assert_eq!(
        backend.0.lock().unwrap().sends.len(),
        sends,
        "built, not sent"
    );
    let rows = writer_rows(&backend);
    let store = admitted(&mut b).await;
    assert_eq!(writer_rows(&backend), rows + 1, "only B's new writer");
    assert_eq!(a.advance().await, Ok(Progress::Advanced), "A loses");
    assert_eq!(a.advance().await, Ok(Progress::Pending), "A waits on B");
    assert_eq!(writer_rows(&backend), rows + 1, "A wrote nothing");
    let seal = crate::seal::lend();
    for (address, value) in &backend.0.lock().unwrap().rows {
        if address.namespace == control::NAMESPACE.0
            && matches!(
                control::Key::decode(&address.key),
                Some(control::Key::Writer(_))
            )
        {
            let writer = control::Writer::decode(value.expose(&seal)).unwrap();
            assert!(writer.admits(1), "nobody was retired");
        }
    }
    finish_first_start(&store).await;
}

/// 8.2c: racing Register on first start. B registers; A's reply is lost; A's retry
/// is a CONDITION_CONFLICT the readback proves final (W absent, birth predicate
/// failed, no-ABA); A re-inspects and waits on B's live first start (FIRST-START-TAKEOVER),
/// writing nothing, and B is not retired.
#[tokio::test]
async fn racing_register_loser_waits_and_winner_is_not_retired() {
    let backend = Arc::new(Backend::default());
    initialized_only(&backend).await;
    let mut a = startup(&backend, false);
    let mut b = startup(&backend, false);
    assert_eq!(a.advance().await, Ok(Progress::Advanced));
    assert_eq!(b.advance().await, Ok(Progress::Advanced));
    assert_eq!(b.advance().await, Ok(Progress::Advanced), "B registers");
    backend.0.lock().unwrap().lose_any = true;
    assert_eq!(a.advance().await, Ok(Progress::Pending));
    assert_eq!(
        a.advance().await,
        Ok(Progress::Advanced),
        "readback: ConditionConflict"
    );
    let rows = writer_rows(&backend);
    assert_eq!(a.advance().await, Ok(Progress::Pending));
    assert_eq!(writer_rows(&backend), rows, "A wrote nothing");
    let store = admitted(&mut b).await;
    let winner = store.authority().unwrap().writer;
    assert!(writer_row(&backend, winner).admits(1));
    finish_first_start(&store).await;
}

/// Repeated CAS losses on a published dataset stay bounded by `conflict_retries`.
#[tokio::test]
async fn losses_are_bounded_by_conflict_retries() {
    let backend = Arc::new(Backend::default());
    let mut start = startup(&backend, true);
    start.lost = limits().conflict_retries;
    assert_eq!(start.lose(), Err(Error::Conflict));
}

#[test]
fn pending_operations_above_max_slots_are_invalid_limits() {
    let backend = Arc::new(Backend::default());
    assert!(matches!(
        Startup::new(
            backend,
            Limits {
                pending_operations: MAX_SLOTS as usize + 1,
                ..limits()
            },
            true
        ),
        Err(Error::Access(AccessError::InvalidLimits))
    ));
}

// ---- FIRST-START-TAKEOVER (§8) ------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn t3_crashed_owner_is_taken_over_after_the_window_and_audited_once() {
    let backend = Arc::new(Backend::default());
    let owner = admitted(&mut startup(&backend, true))
        .await
        .first_start()
        .unwrap()
        .owner();
    let mut b = startup(&backend, false);
    assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    tokio::time::advance(Duration::from_secs(89)).await;
    assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    let waiting = b.waiting_on().unwrap();
    assert_eq!(waiting.owner, owner);
    assert_eq!(waiting.window, FIRST_START_STALL);
    assert_eq!(waiting.since_change, Duration::from_secs(89));
    assert!(writer_row(&backend, owner).admits(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    let (store, log) = capture_diagnostics(admitted(&mut b)).await;
    assert!(b.waiting_on().is_none());
    assert!(!writer_row(&backend, owner).admits(1));
    let writer = store.authority().unwrap().writer;
    assert_eq!(birth_of(&backend).owner, Some(writer));
    assert_eq!(
        log.matches(&banner(&FIRST_START_TAKEOVER)).count(),
        1,
        "{log}"
    );
    assert!(
        log.contains(&format!("previous={}", writer_hex(&owner))),
        "{log}"
    );
    assert!(
        log.contains(&format!("new_writer={}", writer_hex(&writer))),
        "{log}"
    );
    assert!(
        !log.contains(&banner(&FIRST_START_TAKEOVER_UNCONFIRMED)),
        "{log}"
    );
}

#[tokio::test(start_paused = true)]
async fn t3_restart_resets_the_window() {
    let backend = Arc::new(Backend::default());
    let owner = admitted(&mut startup(&backend, true))
        .await
        .first_start()
        .unwrap()
        .owner();
    let mut b = startup(&backend, false);
    assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    drop(b);
    let mut restarted = startup(&backend, false);
    assert_eq!(restarted.advance().await.unwrap(), Progress::Pending);
    tokio::time::advance(Duration::from_secs(89)).await;
    assert_eq!(restarted.advance().await.unwrap(), Progress::Pending);
    assert!(writer_row(&backend, owner).admits(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    admitted(&mut restarted).await;
    assert!(!writer_row(&backend, owner).admits(1));
}

#[tokio::test(start_paused = true)]
async fn t1_live_owner_is_never_retired_and_the_waiter_registers_after_publication() {
    let backend = Arc::new(Backend::default());
    let a = admitted(&mut startup(&backend, true)).await;
    let proof = a.first_start().unwrap();
    let mut b = startup(&backend, false);
    let before = writer_row(&backend, proof.owner());
    for _ in 0..100 {
        assert_eq!(b.advance().await.unwrap(), Progress::Pending);
        assert_eq!(writer_row(&backend, proof.owner()), before);
        tokio::time::advance(Duration::from_millis(250)).await;
    }
    assert_eq!(
        proof.freeze(vec![initial_binding("one", 1)]).await,
        Ok(Progress::Advanced)
    );
    assert_eq!(proof.complete("one").await, Ok(Progress::Advanced));
    assert_eq!(proof.publish().await, Ok(Progress::Advanced));
    let store = admitted(&mut b).await;
    assert!(store.first_start().is_none());
    assert!(writer_row(&backend, proof.owner()).admits(1));
}

#[tokio::test(start_paused = true)]
async fn t4_stuck_owner_is_fenced_after_takeover() {
    let backend = Arc::new(Backend::default());
    let a = admitted(&mut startup(&backend, true)).await;
    let prior = a.first_start().unwrap();
    let birth = backend.0.lock().unwrap().rows[&first_start::address()].clone();
    let successor = admitted_after_stall(&backend, prior.owner()).await;
    assert!(successor.first_start().is_some());
    let taken = backend.0.lock().unwrap().rows[&first_start::address()].clone();
    assert_ne!(taken, birth);
    assert_eq!(
        prior.freeze(vec![initial_binding("one", 1)]).await,
        // A self-fenced FENCED on a first send is final (STORE-TRANSACTIONS section 2.3).
        Err(Error::Authority)
    );
    assert!(!prior.permits("one").await.unwrap());
    assert_eq!(
        backend.0.lock().unwrap().rows[&first_start::address()],
        taken
    );
}

#[tokio::test(start_paused = true)]
async fn t5_late_progress_makes_the_takeover_lose_and_the_waiter_waits_again() {
    let backend = Arc::new(Backend::default());
    let a = admitted(&mut startup(&backend, true)).await;
    let proof = a.first_start().unwrap();
    let mut b = startup(&backend, false);
    let ((), log) = capture_diagnostics(async {
        assert_eq!(b.advance().await.unwrap(), Progress::Pending);
        tokio::time::advance(FIRST_START_STALL).await;
        assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
        assert!(matches!(b.phase, Phase::Register(.., Some(_))));
        assert_eq!(
            proof.freeze(vec![initial_binding("one", 1)]).await,
            Ok(Progress::Advanced)
        );
        assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
        assert!(matches!(b.phase, Phase::Inspect));
        assert_eq!(b.lost, 1);
        assert_eq!(b.advance().await.unwrap(), Progress::Pending);
        assert_eq!(b.waiting_on().unwrap().since_change, Duration::ZERO);
    })
    .await;
    assert!(!log.contains(&banner(&FIRST_START_TAKEOVER)), "{log}");
    assert!(writer_row(&backend, proof.owner()).admits(1));
    assert_eq!(birth_of(&backend).owner, Some(proof.owner()));
}

#[tokio::test(start_paused = true)]
async fn t6_two_waiters_one_takeover_audited_once() {
    let backend = Arc::new(Backend::default());
    let owner = admitted(&mut startup(&backend, true))
        .await
        .first_start()
        .unwrap()
        .owner();
    let mut b = startup(&backend, false);
    let mut c = startup(&backend, false);
    let (store, log) = capture_diagnostics(async {
        assert_eq!(b.advance().await.unwrap(), Progress::Pending);
        assert_eq!(c.advance().await.unwrap(), Progress::Pending);
        tokio::time::advance(FIRST_START_STALL).await;
        assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
        assert_eq!(c.advance().await.unwrap(), Progress::Advanced);
        assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
        assert_eq!(c.advance().await.unwrap(), Progress::Advanced);
        assert!(matches!(c.phase, Phase::Inspect));
        assert_eq!(c.advance().await.unwrap(), Progress::Pending);
        admitted(&mut b).await
    })
    .await;
    let writer = store.authority().unwrap().writer;
    assert_eq!(birth_of(&backend).owner, Some(writer));
    assert_eq!(c.waiting_on().unwrap().owner, writer);
    assert!(writer_row(&backend, writer).admits(1));
    assert!(!writer_row(&backend, owner).admits(1));
    assert_eq!(
        log.matches(&banner(&FIRST_START_TAKEOVER)).count(),
        1,
        "{log}"
    );
    assert!(
        log.contains(&format!("new_writer={}", writer_hex(&writer))),
        "{log}"
    );
}

#[tokio::test(start_paused = true)]
async fn t8_lost_register_race_on_an_unowned_record_waits_then_registers() {
    let backend = Arc::new(Backend::default());
    let mut a = startup(&backend, true);
    assert_eq!(a.advance().await.unwrap(), Progress::Advanced);
    assert_eq!(a.advance().await.unwrap(), Progress::Advanced);
    let mut b = startup(&backend, false);
    let mut c = startup(&backend, false);
    assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
    assert_eq!(c.advance().await.unwrap(), Progress::Advanced);
    assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
    assert_eq!(c.advance().await.unwrap(), Progress::Advanced);
    assert!(matches!(c.phase, Phase::Inspect));
    assert_eq!(c.advance().await.unwrap(), Progress::Pending);
    let store = admitted(&mut b).await;
    let proof = store.first_start().unwrap();
    proof.freeze(Vec::new()).await.unwrap();
    proof.publish().await.unwrap();
    let late = admitted(&mut c).await;
    assert!(late.first_start().is_none());
    assert!(writer_row(&backend, proof.owner()).admits(1));
}

#[tokio::test(start_paused = true)]
async fn t8_decided_register_losses_are_bounded() {
    let backend = Arc::new(Backend::default());
    admitted(&mut startup(&backend, true)).await;
    let mut b = Startup::new(
        backend.clone(),
        Limits {
            conflict_retries: 16,
            ..limits()
        },
        false,
    )
    .unwrap();
    for loss in 1..=17 {
        // The record is owned by a live writer: wait out the window, then lose the Register.
        assert_eq!(b.advance().await.unwrap(), Progress::Pending);
        tokio::time::advance(FIRST_START_STALL).await;
        assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
        backend.0.lock().unwrap().force = Some(Ok(Decision::ConditionConflict));
        let result = b.advance().await;
        if loss <= 16 {
            assert_eq!(result, Ok(Progress::Advanced), "loss {loss}");
            // A forced loss changed nothing, so the same bytes are seen again: drop the stall.
            b.stall = None;
        } else {
            assert_eq!(result, Err(Error::Conflict));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn t9_window_grows_with_planes_done_and_the_probe_floor_covers_it() {
    assert_eq!(first_start_probe_floor(0), Duration::from_secs(200));
    assert_eq!(first_start_probe_floor(7), Duration::from_secs(935));
    let backend = Arc::new(Backend::default());
    let a = admitted(&mut startup(&backend, true)).await;
    let proof = a.first_start().unwrap();
    let plan = vec![initial_binding("one", 1), initial_binding("two", 2)];
    proof.freeze(plan).await.unwrap();
    proof.complete("one").await.unwrap();
    assert_eq!(stall_window(&birth_of(&backend)), Duration::from_secs(125));
    proof.complete("two").await.unwrap();
    assert_eq!(stall_window(&birth_of(&backend)), Duration::from_secs(160));
    let mut b = startup(&backend, false);
    assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    tokio::time::advance(Duration::from_secs(159)).await;
    assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    tokio::time::advance(Duration::from_secs(1)).await;
    let store = admitted(&mut b).await;
    let current = store.first_start().unwrap();
    assert_eq!(current.complete("one").await, Ok(Progress::Advanced));
    assert_eq!(current.publish().await, Ok(Progress::Advanced));
}

#[tokio::test(start_paused = true)]
async fn t11_abandon_variants_in_the_mock() {
    // An uncertain step does not block the hand-over.
    let backend = Arc::new(Backend::default());
    let a = admitted(&mut startup(&backend, true)).await;
    let proof = a.first_start().unwrap();
    proof.freeze(vec![initial_binding("one", 1)]).await.unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(proof.complete("one").await, Ok(Progress::Pending));
    assert_eq!(proof.abandon().await, Ok(first_start::Abandoned::Retired));
    let row = writer_row(&backend, proof.owner());
    assert!(row.retired_through == row.admitted_through);
    let mut b = startup(&backend, false);
    assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
    admitted(&mut b).await;

    // Taken over first: nothing written.
    let backend = Arc::new(Backend::default());
    let a = admitted(&mut startup(&backend, true)).await;
    let prior = a.first_start().unwrap();
    let successor = admitted_after_stall(&backend, prior.owner()).await;
    let (rows, sends) = {
        let native = backend.0.lock().unwrap();
        (native.rows.clone(), native.sends.len())
    };
    assert_eq!(
        prior.abandon().await,
        Ok(first_start::Abandoned::NotAdmitted)
    );
    {
        let native = backend.0.lock().unwrap();
        assert!(native.rows == rows);
        assert_eq!(native.sends.len(), sends);
    }
    let current = successor.first_start().unwrap();
    assert!(writer_row(&backend, current.owner()).admits(1));
}

#[tokio::test(start_paused = true)]
async fn t11_abandon_race_with_a_takeover_writes_nothing() {
    let backend = Arc::new(Backend::default());
    let a = admitted(&mut startup(&backend, true)).await;
    let proof = a.first_start().unwrap();
    let mut b = startup(&backend, false);
    assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    tokio::time::advance(FIRST_START_STALL).await;
    assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
    let before = backend.0.lock().unwrap().rows.clone();
    assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
    let sends = {
        let mut native = backend.0.lock().unwrap();
        let after = std::mem::replace(&mut native.rows, before);
        native.before_commit = Some(Box::new(move |n: &mut Native| n.rows = after));
        native.sends.len()
    };
    assert_eq!(
        proof.abandon().await,
        Ok(first_start::Abandoned::NotAdmitted)
    );
    assert_eq!(backend.0.lock().unwrap().sends.len(), sends + 1);
    assert!(!writer_row(&backend, proof.owner()).admits(1));
    let store = admitted(&mut b).await;
    assert_eq!(
        birth_of(&backend).owner,
        Some(store.authority().unwrap().writer)
    );
}

#[tokio::test(start_paused = true)]
async fn t11_abandon_retries_once_when_only_the_manifest_moved() {
    let backend = Arc::new(Backend::default());
    let a = admitted(&mut startup(&backend, true)).await;
    let proof = a.first_start().unwrap();
    let sends = {
        let mut native = backend.0.lock().unwrap();
        native.before_commit = Some(Box::new(|n: &mut Native| {
            let seal = crate::seal::lend();
            let mut manifest = Manifest::decode(n.rows[&manifest_address()].expose(&seal)).unwrap();
            manifest.registrar.execution_epoch += 1;
            let registrar = writer_address(manifest.registrar.writer);
            let row = control::Writer::decode(n.rows[&registrar].expose(&seal)).unwrap();
            let moved = control::Writer {
                admitted_through: 2,
                ..row
            };
            n.rows
                .insert(manifest_address(), Secret::new(manifest.encode().to_vec()));
            n.rows
                .insert(registrar, Secret::new(moved.encode().unwrap().to_vec()));
        }));
        native.sends.len()
    };
    assert_eq!(proof.abandon().await, Ok(first_start::Abandoned::Retired));
    assert_eq!(backend.0.lock().unwrap().sends.len(), sends + 2);
    assert!(!writer_row(&backend, proof.owner()).admits(1));
}

#[tokio::test(start_paused = true)]
async fn t15_lost_takeover_reply_replayed_as_applied_is_audited_once() {
    let backend = Arc::new(Backend::default());
    let (owner, mut b) = takeover_built(&backend).await;
    let n = backend.0.lock().unwrap().sends.len();
    backend.0.lock().unwrap().lose_reply = true;
    let (store, log) = capture_diagnostics(async {
        assert_eq!(b.advance().await.unwrap(), Progress::Pending);
        assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
        assert!(matches!(b.phase, Phase::Attach(..)));
        admitted(&mut b).await
    })
    .await;
    {
        let native = backend.0.lock().unwrap();
        assert_eq!(native.sends[n], native.sends[n + 1]);
    }
    let writer = store.authority().unwrap().writer;
    assert_eq!(
        log.matches(&banner(&FIRST_START_TAKEOVER)).count(),
        1,
        "{log}"
    );
    assert!(
        log.contains(&format!("previous={}", writer_hex(&owner))),
        "{log}"
    );
    assert!(
        log.contains(&format!("new_writer={}", writer_hex(&writer))),
        "{log}"
    );
    assert!(
        !log.contains(&banner(&FIRST_START_TAKEOVER_UNCONFIRMED)),
        "{log}"
    );
    assert!(!writer_row(&backend, owner).admits(1));
    assert_eq!(birth_of(&backend).owner, Some(writer));
}

#[tokio::test(start_paused = true)]
async fn t15_takeover_with_an_unknown_outcome_is_unconfirmed() {
    for lost_first in [false, true] {
        let backend = Arc::new(Backend::default());
        let (owner, mut b) = takeover_built(&backend).await;
        let (result, log) = capture_diagnostics(async {
            if lost_first {
                backend.0.lock().unwrap().lose_reply = true;
                assert_eq!(b.advance().await.unwrap(), Progress::Pending);
            }
            // A STALE answer to a self-fenced Register cannot be resolved by readback:
            // the outcome is unknown (STORE-TRANSACTIONS slot invariant).
            backend.0.lock().unwrap().force = Some(Ok(Decision::Stale));
            b.advance().await
        })
        .await;
        assert_eq!(result, Ok(Progress::Reconcile), "lost first: {lost_first}");
        assert_eq!(
            log.matches(&banner(&FIRST_START_TAKEOVER_UNCONFIRMED))
                .count(),
            1,
            "{log}"
        );
        assert!(log.contains("outcome unknown"), "{log}");
        assert!(log.contains(&writer_hex(&owner)), "{log}");
        assert!(!log.contains(&banner(&FIRST_START_TAKEOVER)), "{log}");
    }
}

#[tokio::test(start_paused = true)]
async fn t15_refused_takeover_is_unconfirmed_and_writes_nothing() {
    for (forced, expected) in [
        (Ok(Decision::OpIdConflict), Error::Authority),
        (Err(Failure::Refused), Error::Backend(Failure::Refused)),
    ] {
        let backend = Arc::new(Backend::default());
        let (owner, mut b) = takeover_built(&backend).await;
        let (rows, slots) = {
            let native = backend.0.lock().unwrap();
            (native.rows.clone(), native.slots.len())
        };
        backend.0.lock().unwrap().force = Some(forced);
        let (result, log) = capture_diagnostics(b.advance()).await;
        assert_eq!(result, Err(expected));
        assert_eq!(
            log.matches(&banner(&FIRST_START_TAKEOVER_UNCONFIRMED))
                .count(),
            1,
            "{log}"
        );
        assert!(log.contains(&format!("refused: {expected:?}")), "{log}");
        assert!(!log.contains(&banner(&FIRST_START_TAKEOVER)), "{log}");
        let native = backend.0.lock().unwrap();
        assert!(native.rows == rows);
        assert_eq!(native.slots.len(), slots);
        drop(native);
        assert!(writer_row(&backend, owner).admits(1));
    }
}

const IMPORT_SUMMARY: &[u8] = &[0];

/// A slotted key on one fixed queue slot; `seq` must grow per writer.
fn slot_key(seq: u64) -> busbar_contract::persistence::CommitKey {
    busbar_contract::persistence::CommitKey::slotted(
        65_535,
        seq,
        &busbar_contract::caps::SlotSeal::acquire_for_tests(),
    )
    .unwrap()
}

fn import_address(key: &[u8]) -> Address {
    Address {
        namespace: control::IMPORT_NAMESPACE.0,
        key: key.to_vec(),
    }
}

/// One R0 page as MIGRATE commits it under the owner's authority: `SUMMARY` and core's R0
/// progress row, each under an exact predicate. `last` deletes both and the remaining row.
fn r0_page(
    store: &CoreStore,
    backend: &Backend,
    consumed: u8,
    fold: bool,
    last: bool,
) -> PreparedCandidate {
    let native = backend.0.lock().unwrap();
    let seal = crate::seal::lend();
    let summary = import_address(IMPORT_SUMMARY);
    let progress = first_start::r0_progress_address();
    let summary_now = native.rows[&summary].expose(&seal).clone();
    let progress_now = native.rows.get(&progress).map(|v| v.expose(&seal).clone());
    let pages = progress_now
        .as_deref()
        .and_then(first_start::R0Progress::decode)
        .map_or(0, |p| p.pages);
    let mut predicates = vec![exact(summary.clone(), summary_now)];
    predicates.push(match progress_now {
        Some(value) => exact(progress.clone(), value),
        None => Predicate {
            address: progress.clone(),
            expected: ExpectedValue::Absent,
        },
    });
    let mutations = if last {
        vec![
            Mutation::Delete(progress),
            Mutation::Delete(summary),
            Mutation::Delete(import_address(b"row")),
        ]
    } else {
        let mut mutations = vec![Mutation::Put {
            address: progress,
            value: Secret::new(
                first_start::R0Progress {
                    version: 1,
                    pages: pages + 1,
                    cursor: Vec::new(),
                }
                .encode()
                .unwrap(),
            ),
        }];
        if fold {
            mutations.push(Mutation::Put {
                address: summary,
                value: Secret::new(vec![consumed]),
            });
        }
        mutations
    };
    drop(native);
    PreparedCandidate::new(Candidate {
        id: store.next_id().unwrap(),
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(Vec::new()),
    })
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn t16_an_importing_owner_is_never_taken_over() {
    for fold in [true, false] {
        let backend = Arc::new(Backend::default());
        {
            let mut native = backend.0.lock().unwrap();
            native
                .rows
                .insert(import_address(IMPORT_SUMMARY), Secret::new(vec![0]));
            native
                .rows
                .insert(import_address(b"row"), Secret::new(b"1.5.5".to_vec()));
        }
        let a = admitted(&mut startup(&backend, true)).await;
        let proof = a.first_start().unwrap();
        let birth = backend.0.lock().unwrap().rows[&first_start::address()].clone();
        let writer = writer_row(&backend, proof.owner());
        let mut b = startup(&backend, false);
        let mut page = 0u8;
        for step in 0..2400u32 {
            if step > 0 && step.is_multiple_of(240) {
                page += 1;
                let decision = backend
                    .commit(
                        r0_page(&a, &backend, page, fold, false),
                        slot_key(u64::from(page)),
                    )
                    .await
                    .unwrap();
                assert!(matches!(decision, Decision::Applied(_)), "page {page}");
                proof.note_r0_commit();
            }
            let sends = backend.0.lock().unwrap().sends.len();
            assert_eq!(b.advance().await.unwrap(), Progress::Pending, "step {step}");
            assert_eq!(
                backend.0.lock().unwrap().sends.len(),
                sends,
                "B built a candidate"
            );
            tokio::time::advance(Duration::from_millis(250)).await;
        }
        assert!(matches!(
            backend
                .commit(
                    r0_page(&a, &backend, page + 1, fold, true),
                    slot_key(u64::from(page) + 1),
                )
                .await
                .unwrap(),
            Decision::Applied(_)
        ));
        assert!(!backend
            .0
            .lock()
            .unwrap()
            .rows
            .keys()
            .any(|k| k.namespace == control::IMPORT_NAMESPACE.0
                || *k == first_start::r0_progress_address()));
        assert_eq!(
            backend.0.lock().unwrap().rows[&first_start::address()],
            birth
        );
        assert_eq!(writer_row(&backend, proof.owner()), writer);
        proof.freeze(Vec::new()).await.unwrap();
        proof.publish().await.unwrap();
        let store = admitted(&mut b).await;
        assert!(store.first_start().is_none());
        assert!(writer_row(&backend, proof.owner()).admits(1));
    }
}

#[tokio::test(start_paused = true)]
async fn t16_a_page_racing_the_takeover_makes_it_lose() {
    let backend = Arc::new(Backend::default());
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .insert(import_address(IMPORT_SUMMARY), Secret::new(vec![0]));
    let a = admitted(&mut startup(&backend, true)).await;
    let proof = a.first_start().unwrap();
    let mut b = startup(&backend, false);
    let ((), log) = capture_diagnostics(async {
        assert_eq!(b.advance().await.unwrap(), Progress::Pending);
        tokio::time::advance(FIRST_START_STALL).await;
        assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
        assert!(matches!(
            backend
                .commit(r0_page(&a, &backend, 1, true, false), slot_key(1))
                .await
                .unwrap(),
            Decision::Applied(_)
        ));
        assert_eq!(b.advance().await.unwrap(), Progress::Advanced);
        assert_eq!(b.lost, 1);
        assert_eq!(b.advance().await.unwrap(), Progress::Pending);
    })
    .await;
    assert!(!log.contains(&banner(&FIRST_START_TAKEOVER)), "{log}");
    assert!(writer_row(&backend, proof.owner()).admits(1));
}

#[tokio::test(start_paused = true)]
async fn t18_the_slow_step_check_measures_each_r0_gap() {
    for slow in [false, true] {
        let backend = Arc::new(Backend::default());
        let a = admitted(&mut startup(&backend, true)).await;
        let fs = a.first_start().unwrap();
        let ((), log) = capture_diagnostics(async {
            for page in 0..4 {
                let gap = if slow && page == 2 { 50 } else { 40 };
                tokio::time::advance(Duration::from_secs(gap)).await;
                fs.note_r0_commit();
            }
            tokio::time::advance(Duration::from_secs(40)).await;
            fs.freeze(Vec::new()).await.unwrap();
        })
        .await;
        let slow_steps = log
            .matches(&banner(&crate::diagnostics::FIRST_START_SLOW_STEP))
            .count();
        if slow {
            assert_eq!(slow_steps, 1, "{log}");
            assert!(log.contains("r0-commit"), "{log}");
        } else {
            assert_eq!(slow_steps, 0, "{log}");
        }
    }
}

#[test]
fn r0_progress_row_has_a_fixed_layout_and_refuses_anything_else() {
    let row = first_start::R0Progress {
        version: 1,
        pages: 7,
        cursor: b"cursor".to_vec(),
    };
    let bytes = row.encode().unwrap();
    assert_eq!(&bytes[..8], b"bbr0prg1");
    assert_eq!(bytes.len(), 24 + 6);
    assert_eq!(first_start::R0Progress::decode(&bytes), Some(row.clone()));
    let mut wrong = bytes.clone();
    wrong[0] ^= 1;
    assert_eq!(first_start::R0Progress::decode(&wrong), None);
    let mut version = bytes.clone();
    version[8] = 2;
    assert_eq!(first_start::R0Progress::decode(&version), None);
    assert_eq!(
        first_start::R0Progress::decode(&bytes[..bytes.len() - 1]),
        None
    );
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(first_start::R0Progress::decode(&long), None);
    assert_eq!(first_start::R0Progress { version: 2, ..row }.encode(), None);
}

// ---- #319 r4 §5: record-format admission -----------------------------------------------------

/// #319 r4 §5: a Current manifest beside a record-format step cursor is contradictory evidence (a
/// step under way whose flip did not delete its cursor, or a cursor written without its tail).
/// Admission refuses it before any write; it never ignores or deletes the cursor.
#[tokio::test]
async fn a_current_manifest_with_a_migration_cursor_is_refused() {
    let backend = Arc::new(Backend::default());
    admitted(&mut startup(&backend, true)).await;
    let cursor = Address {
        namespace: witness::FORMAT_NAMESPACE.0,
        key: b"step".to_vec(),
    };
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .insert(cursor.clone(), Secret::new(b"leftover".to_vec()));
    let before = backend.0.lock().unwrap().sends.len();
    assert_eq!(
        startup(&backend, false).advance().await,
        Err(Error::Corrupt)
    );
    assert_eq!(backend.0.lock().unwrap().sends.len(), before);
    assert!(backend.0.lock().unwrap().rows.contains_key(&cursor));
}

// #319 r4 §5-§9 over the seam: a synthetic step 0 -> 1 (the kernel writes format 1), never a
// production step.
struct ZeroToOne;
impl FormatChain for ZeroToOne {
    fn has_step(&self, from: u32) -> bool {
        from == 0
    }
    fn initial_cursor(&self, from: u32) -> Option<Vec<u8>> {
        (from == 0).then(|| b"cursor@0".to_vec())
    }
}

fn converting(backend: &Arc<Backend>) -> Startup {
    startup(backend, false).with_format_chain(Arc::new(ZeroToOne))
}

fn row(backend: &Backend, address: &Address) -> Option<Vec<u8>> {
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .get(address)
        .map(|value| value.expose(&crate::seal::lend()).clone())
}

fn dataset_epoch(backend: &Backend) -> u64 {
    control::Dataset::decode(&row(backend, &root_address()).unwrap())
        .unwrap()
        .writer_epoch
}

/// Rewrite the manifest's four format copies, keeping its registrar.
fn set_format(backend: &Backend, format: u32) {
    let mut bytes = row(backend, &manifest_address()).unwrap();
    for at in [8, 12, 16, 20] {
        bytes[at..at + 4].copy_from_slice(&format.to_le_bytes());
    }
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .insert(manifest_address(), Secret::new(bytes));
}

/// A dataset at the synthetic older format 0 with its first start published away (absent), and
/// a process admitted under the old epoch that may still try to write.
async fn format_zero(backend: &Arc<Backend>) -> Arc<CoreStore> {
    let old = admitted(&mut startup(backend, true)).await;
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .remove(&first_start::address());
    set_format(backend, 0);
    old
}

/// Advance until `want`, within a few bounded steps.
async fn until(startup: &mut Startup, want: Progress) {
    for _ in 0..6 {
        if startup.advance().await.unwrap() == want {
            return;
        }
    }
    panic!("startup did not reach {want:?}");
}

/// One business row, as any old-epoch writer would put it.
fn old_write() -> Commit {
    Commit {
        put: vec![(
            Address {
                namespace: [7; 16],
                key: vec![9],
            },
            busbar_contract::secure::SecureVec::from(vec![9]),
        )],
        ..Commit::default()
    }
}

fn secure(bytes: Vec<u8>) -> busbar_contract::secure::SecureVec {
    busbar_contract::secure::SecureVec::from(bytes)
}

/// #319 r4 §5-§6: an older format this chain converts is opened in one transaction: the dataset
/// epoch advances (every old-epoch writer is fenced at its next commit, reported as a fence and
/// never as a refusal a smaller page could pass), the manifest names a fresh owner with the tail,
/// and the step's cursor exists. No ordinary store is handed out while the tail is nonzero.
#[tokio::test]
async fn an_older_format_is_opened_atomically_and_fences_the_old_epoch() {
    let backend = Arc::new(Backend::default());
    let old = format_zero(&backend).await;
    assert_eq!(dataset_epoch(&backend), 1);
    let mut converting = converting(&backend);
    until(&mut converting, Progress::Migrate).await;
    assert!(converting.store().is_none());
    let owner = converting.migration().unwrap();
    assert_eq!((owner.format(), owner.migrating_to()), (0, 1));
    assert_eq!(dataset_epoch(&backend), 2);
    let manifest = row(&backend, &manifest_address()).unwrap();
    assert_eq!(manifest, owner.manifest_bytes());
    assert_eq!(
        classify(&manifest, |f| f == 0),
        Format::Migrating { from: 0, to: 1 }
    );
    let registrar = Manifest::identities(&manifest).unwrap().registrar;
    assert_eq!((registrar.writer_epoch, registrar.execution_epoch), (2, 1));
    assert!(writer_row(&backend, registrar.writer).admits(1));
    assert_eq!(row(&backend, &cursor_address()), Some(b"cursor@0".to_vec()));
    // The process admitted under epoch 1 is fenced; its row never lands.
    assert_eq!(
        Access::new(old.clone()).commit(old_write()).await,
        Ok(Outcome::Fenced)
    );
    assert_eq!(
        row(
            &backend,
            &Address {
                namespace: [7; 16],
                key: vec![9]
            }
        ),
        None
    );
}

/// #319 r4 §6: the opening's reply is lost after it applied. The same attempt is sent again, is
/// fenced by the epoch it advanced, and its fresh owner's writer row resolves it as applied: one
/// opening, one owner, never a second transition.
#[tokio::test]
async fn a_lost_opening_reply_resolves_by_its_owner_witness() {
    let backend = Arc::new(Backend::default());
    format_zero(&backend).await;
    let mut converting = converting(&backend);
    assert_eq!(converting.advance().await.unwrap(), Progress::Advanced);
    let applied = {
        let mut native = backend.0.lock().unwrap();
        native.lose_reply = true;
        native.applied
    };
    assert_eq!(converting.advance().await.unwrap(), Progress::Pending);
    until(&mut converting, Progress::Migrate).await;
    assert_eq!(backend.0.lock().unwrap().applied, applied + 1);
    assert_eq!(dataset_epoch(&backend), 2);
    let registrar = Manifest::identities(&row(&backend, &manifest_address()).unwrap())
        .unwrap()
        .registrar;
    assert_eq!(
        converting.migration().unwrap().manifest_bytes().to_vec(),
        Manifest {
            dataset: DatasetId([1; 16]),
            registrar,
            format: RECORD_FORMAT,
        }
        .encode_at(0, 1)
        .to_vec()
    );
}

/// #319 r4 §7, §9: the owner commits pages under its own authority, then the final publication
/// advances the epoch past it, names a fresh registrar and the Current manifest and deletes the
/// cursor, atomically. Reinspection then admits ordinarily, and the finished owner is fenced.
#[tokio::test]
async fn the_final_publication_admits_ordinarily_and_fences_the_owner() {
    let backend = Arc::new(Backend::default());
    format_zero(&backend).await;
    let mut converting = converting(&backend);
    until(&mut converting, Progress::Migrate).await;
    let owner = converting.migration().unwrap();
    let manifest = owner.manifest_bytes().to_vec();
    let page = Commit {
        expect: vec![
            (manifest_address(), Some(secure(manifest.clone()))),
            (cursor_address(), Some(secure(b"cursor@0".to_vec()))),
        ],
        put: vec![(cursor_address(), secure(b"cursor@end".to_vec()))],
        ..Commit::default()
    };
    assert_eq!(owner.access().commit(page).await, Ok(Outcome::Applied));
    // The completion may not write the manifest itself: the publication does.
    let rogue = Commit {
        put: vec![(manifest_address(), secure(manifest.clone()))],
        ..Commit::default()
    };
    assert!(owner.finalize(rogue, RECORD_FORMAT).await.is_err());
    let completion = || Commit {
        expect: vec![
            (manifest_address(), Some(secure(manifest.clone()))),
            (cursor_address(), Some(secure(b"cursor@end".to_vec()))),
        ],
        delete: vec![cursor_address()],
        ..Commit::default()
    };
    assert_eq!(
        owner.finalize(completion(), RECORD_FORMAT).await,
        Ok(Outcome::Applied)
    );
    assert_eq!(dataset_epoch(&backend), 3);
    assert_eq!(row(&backend, &cursor_address()), None);
    let published = row(&backend, &manifest_address()).unwrap();
    assert_eq!(classify(&published, |_| false), Format::Current);
    let registrar = Manifest::identities(&published).unwrap().registrar;
    assert_eq!(registrar.writer_epoch, 3);
    assert!(writer_row(&backend, registrar.writer).admits(1));
    // A second publication of the same completion cannot apply: the owner is fenced.
    assert_eq!(
        owner.finalize(completion(), RECORD_FORMAT).await,
        Ok(Outcome::Fenced)
    );
    converting.migration_finished().unwrap();
    let store = admitted(&mut converting).await;
    let process = store.authority().unwrap();
    assert_eq!(process.writer_epoch, 3);
    assert_ne!(process.writer, registrar.writer);
    assert_eq!(
        owner.access().commit(old_write()).await,
        Ok(Outcome::Fenced)
    );
}

/// #319 r4 §8: another process's conversion is watched, not adopted. Only after its whole tuple
/// stays unchanged for the window is it claimed, in one transaction that advances the epoch and
/// installs a fresh owner; a page by the old owner within the window resets the wait; once
/// claimed, the old owner is fenced.
#[tokio::test(start_paused = true)]
async fn a_stalled_conversion_is_claimed_after_the_window_and_its_owner_fenced() {
    let backend = Arc::new(Backend::default());
    format_zero(&backend).await;
    let mut first = converting(&backend);
    until(&mut first, Progress::Migrate).await;
    let stalled = first.migration().unwrap();
    let manifest = stalled.manifest_bytes().to_vec();
    drop(first);
    let mut next = converting(&backend);
    assert_eq!(next.advance().await.unwrap(), Progress::Pending);
    let waiting = next.waiting_on().unwrap();
    assert!(waiting.migrating);
    assert_eq!(waiting.window, FIRST_START_STALL);
    tokio::time::advance(Duration::from_secs(60)).await;
    // The owner still progresses: its page changes the cursor, so the window starts again.
    let page = Commit {
        expect: vec![
            (manifest_address(), Some(secure(manifest.clone()))),
            (cursor_address(), Some(secure(b"cursor@0".to_vec()))),
        ],
        put: vec![(cursor_address(), secure(b"cursor@1".to_vec()))],
        ..Commit::default()
    };
    assert_eq!(stalled.access().commit(page).await, Ok(Outcome::Applied));
    assert_eq!(next.advance().await.unwrap(), Progress::Pending);
    tokio::time::advance(Duration::from_secs(89)).await;
    assert_eq!(next.advance().await.unwrap(), Progress::Pending);
    assert_eq!(dataset_epoch(&backend), 2);
    tokio::time::advance(Duration::from_secs(1)).await;
    until(&mut next, Progress::Migrate).await;
    assert_eq!(dataset_epoch(&backend), 3);
    let claimed = next.migration().unwrap();
    assert_eq!((claimed.format(), claimed.migrating_to()), (0, 1));
    assert_eq!(row(&backend, &cursor_address()), Some(b"cursor@1".to_vec()));
    assert_eq!(
        stalled.access().commit(old_write()).await,
        Ok(Outcome::Fenced)
    );
}

/// #319 r4 §5: an older format with a first start still pending is refused (first-start and
/// format takeover never both acquire the dataset), and without a chain an older format is refused
/// as before; neither writes.
#[tokio::test]
async fn an_older_format_with_a_pending_first_start_or_no_chain_is_refused() {
    let backend = Arc::new(Backend::default());
    admitted(&mut startup(&backend, true)).await;
    set_format(&backend, 0);
    let before = backend.0.lock().unwrap().sends.len();
    assert_eq!(
        converting(&backend).advance().await,
        Err(Error::IncompleteInitialization)
    );
    assert_eq!(
        startup(&backend, false).advance().await,
        Err(Error::UnsupportedFormat)
    );
    assert_eq!(backend.0.lock().unwrap().sends.len(), before);
}

/// #319 r4 §7.1: a backend refusal of a send with no earlier uncertainty is reported as one a
/// smaller candidate may pass; the facade's shared `NoEffect(Refused)` does not erase that.
#[tokio::test]
async fn a_backend_refusal_is_reported_as_resizable() {
    let backend = Arc::new(Backend::default());
    let store = admitted(&mut startup(&backend, true)).await;
    backend.0.lock().unwrap().force = Some(Err(Failure::Refused));
    assert_eq!(
        Access::new(store).commit(old_write()).await,
        Ok(Outcome::Refused)
    );
}
