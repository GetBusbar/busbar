// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::persistence::{BackendInfo, Call, ClockObservation, Durability, Page, Scan};
use futures::FutureExt;
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct Native {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: Vec<(AttemptId, [u8; 32])>,
    sends: Vec<[u8; 32]>,
    lose_reply: bool,
    hold_reply: bool,
    now: u64,
    commit_now: Option<u64>,
    unknown_before: bool,
}
#[derive(Default)]
struct Backend(Mutex<Native>);
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
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
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let hold = {
                let mut native = self.0.lock().unwrap();
                let digest = prepared.fingerprint();
                native.sends.push(digest);
                let candidate = prepared.candidate();
                if let Some((_, prior)) = native.receipts.iter().find(|(id, _)| id == &candidate.id)
                {
                    return Ok(if *prior == digest {
                        Decision::Applied(candidate.result.clone())
                    } else {
                        Decision::OpIdConflict
                    });
                }
                let seal = crate::seal::lend();
                if std::mem::take(&mut native.unknown_before) {
                    return Err(Failure::Unknown);
                }
                if let Some(now) = native.commit_now.take() {
                    native.now = now;
                }
                if !native.rows.contains_key(&root_address()) {
                    if !native.rows.is_empty()
                        || !native.receipts.is_empty()
                        || !control::initialization(candidate, self.info().dataset)
                    {
                        return Err(Failure::Refused);
                    }
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
                    if root.writer_epoch != candidate.id.writer_epoch
                        || !writer.is_some_and(|w| w.admits(candidate.id.execution_epoch))
                    {
                        return Ok(Decision::ExpiredUnknown);
                    }
                }
                if candidate
                    .time
                    .is_some_and(|guard| !guard.permits(native.now))
                {
                    return Ok(Decision::TimeGuardFailed {
                        observed_at: ClockObservation {
                            authority: [3; 16],
                            unix_seconds: native.now,
                        },
                    });
                }
                for predicate in &candidate.predicates {
                    let value = native.rows.get(&predicate.address);
                    let matches = match &predicate.expected {
                        ExpectedValue::Absent => value.is_none(),
                        ExpectedValue::Exact(expected) => value == Some(expected),
                    };
                    if !matches {
                        return Ok(Decision::ConditionConflict);
                    }
                }
                for mutation in &candidate.mutations {
                    let Mutation::Put { address, value } = mutation else {
                        panic!("unexpected startup mutation")
                    };
                    native.rows.insert(address.clone(), value.clone());
                }
                native.receipts.push((candidate.id, digest));
                if std::mem::take(&mut native.lose_reply) {
                    return Err(Failure::Unknown);
                }
                std::mem::take(&mut native.hold_reply)
            };
            if hold {
                std::future::pending::<()>().await;
            }
            Ok(Decision::Applied(prepared.candidate().result.clone()))
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

#[tokio::test]
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
    let store = admitted(&mut startup(&backend, false)).await;
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

#[tokio::test]
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
    let successor = admitted(&mut startup(&backend, false)).await;
    let current = successor.first_start().unwrap();
    assert_eq!(prior.initialization_witness().await, Err(Error::Authority));
    let (predicates, mutations) = host_initialization(b"initial");
    assert_eq!(
        prior
            .initialize_host(initial_binding("host", 1), predicates, mutations)
            .await,
        Err(Error::Authority)
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

#[tokio::test]
async fn first_start_before_plan_freeze_can_resume_but_fences_delayed_old_writes() {
    let backend = Arc::new(Backend::default());
    let first = admitted(&mut startup(&backend, true)).await;
    let prior = first.first_start().unwrap();
    let delayed = delayed_initial_write(&first);
    // A crash before the plan exists has issued no plane initialization authority.
    assert!(!prior.permits("one").await.unwrap());
    let second = admitted(&mut startup(&backend, false)).await;
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
        backend.commit(delayed).await.unwrap(),
        Decision::ExpiredUnknown
    ));
    assert_eq!(
        prior.freeze(vec![initial_binding("one", 1)]).await,
        Ok(Progress::Reconcile)
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

#[tokio::test]
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
        backend.commit(delayed_initial_write(&first)).await.unwrap(),
        Decision::Applied(_)
    ));
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(prior.complete("one").await.unwrap(), Progress::Pending);
    let second = admitted(&mut startup(&backend, false)).await;
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
    assert_eq!(prior.complete("one").await.unwrap(), Progress::Advanced);
    assert_eq!(prior.complete("two").await, Ok(Progress::Reconcile));
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

#[tokio::test]
async fn first_start_late_applied_ready_cannot_publish_after_owner_takeover() {
    let backend = Arc::new(Backend::default());
    let first = admitted(&mut startup(&backend, true)).await;
    let prior = first.first_start().unwrap();
    let plan = vec![initial_binding("one", 1)];
    prior.freeze(plan.clone()).await.unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(prior.complete("one").await.unwrap(), Progress::Pending);
    let successor = admitted(&mut startup(&backend, false)).await;
    let current = successor.first_start().unwrap();
    current.freeze(plan).await.unwrap();
    assert_eq!(prior.complete("one").await.unwrap(), Progress::Advanced);
    assert_eq!(
        prior.publish().await,
        Ok(Progress::Reconcile),
        "late Applied proves old effects, never current publication ownership"
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
    let host = KernelServices::new();
    assert!(host.attach_persistence(store));
    host.admit("one", InstanceFacts::default()).await.unwrap();
    let caller = Caller {
        instance: Arc::from("one"),
        plugin: Arc::from("protocol"),
        kind: KindCode::Plane,
    };
    host.bind_native_record_bootstrap(&caller).await.unwrap();
    assert!(host.entitled(&caller, None, ENTITLEMENT));
    assert!(host.entitled(&caller.clone(), None, ENTITLEMENT));
    let replacement = Caller {
        instance: Arc::from("one"),
        plugin: Arc::from("protocol"),
        kind: KindCode::Plane,
    };
    assert!(!host.entitled(&replacement, None, ENTITLEMENT));
    assert!(!host.entitled(&caller, None, "record-quota-bootstrap:forged"));
    assert!(host.admit("one", InstanceFacts::default()).await.is_err());
    proof.complete("one").await.unwrap();
    host.revoke_native_record_bootstrap(&caller).unwrap();
    assert!(!host.entitled(&caller, None, ENTITLEMENT));
    host.bind_native_record_bootstrap(&caller).await.unwrap();
    assert!(
        !host.entitled(&caller, None, ENTITLEMENT),
        "per-instance Done cannot regrant even before global publication"
    );
    proof.publish().await.unwrap();
    host.admit("one", InstanceFacts::default()).await.unwrap();
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
    assert_eq!(
        native.sends[native.sends.len() - 2],
        native.sends[native.sends.len() - 1]
    );
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
        assert_eq!(candidate.candidate().mutations.len(), 4);
        assert!(control::initialization(
            candidate.candidate(),
            backend.info().dataset
        ));
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
                if interruption == "before" { 0 } else { 4 }
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
            assert_eq!(
                native.receipts.len(),
                1,
                "no separate format publication commit"
            );
            assert_eq!(native.rows.len(), 4);
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
            backend.0.lock().unwrap().receipts.len(),
            2,
            "only initialization and new-writer registration"
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
async fn claims_lost_reply_replays_after_expiry_without_reclassifying_unknown() {
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
    assert!(matches!(
        claims.retry(pending).await.unwrap(),
        Outcome::Reconcile(_)
    ));
    assert_eq!(store.stop_admission().unwrap().len(), 1);
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
                Ok(Progress::Reconcile)
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
