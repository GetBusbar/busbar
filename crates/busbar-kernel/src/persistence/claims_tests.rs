// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::facade::{Limits, WriterAuthority};
use busbar_contract::persistence::{
    control, AttemptId, BackendInfo, Call, ClockObservation, DatasetId, Durability, Page,
    PersistenceBackend,
};
use futures::FutureExt;
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct Native {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: Vec<(AttemptId, [u8; 32])>,
    sends: Vec<[u8; 32]>,
    scans: usize,
    now: u64,
    commit_now: Option<u64>,
    replace: Option<(Address, Secret<Vec<u8>>)>,
    unknown_before: bool,
    lose_reply: bool,
    hold_reply: bool,
    wrong_clock: bool,
    bad_cursor: bool,
    /// Answer a read whose TimeGuard no longer holds with TimeGuardFailed,
    /// as a native store does.
    honour_read_time: bool,
}

#[derive(Default)]
struct Backend(Mutex<Native>);

impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: busbar_contract::abi::sdk::store::v4::slot::PHYSICAL_VERSION,
            durability: Durability::Ephemeral,
        }
    }

    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let native = self.0.lock().unwrap();
            if native.honour_read_time && request.time.is_some_and(|time| !time.permits(native.now))
            {
                return Ok(ReadResult::TimeGuardFailed {
                    observed_at: ClockObservation {
                        authority: [3; 16],
                        unix_seconds: native.now,
                    },
                });
            }
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: if native.wrong_clock { [9; 16] } else { [3; 16] },
                    unix_seconds: native.now,
                },
                values: request
                    .addresses
                    .iter()
                    .map(|address| {
                        if address.namespace == control::NAMESPACE.0 {
                            Some(Secret::new(if address.key == control::DATASET_KEY {
                                control::Dataset {
                                    id: self.info().dataset,
                                    writer_epoch: 1,
                                }
                                .encode()
                                .unwrap()
                                .to_vec()
                            } else {
                                assert_eq!(address.key, control::writer_key([4; 16]));
                                control::Writer {
                                    retired_through: 0,
                                    admitted_through: 1,
                                }
                                .encode()
                                .unwrap()
                                .to_vec()
                            }))
                        } else {
                            native.rows.get(address).cloned()
                        }
                    })
                    .collect(),
            })
        })
    }

    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            let mut native = self.0.lock().unwrap();
            native.scans += 1;
            assert_eq!(request.generation, None);
            assert!(request.allow_change);
            let mut rows = Vec::new();
            let mut bytes = 0;
            let mut more = false;
            for (address, value) in &native.rows {
                if address.namespace != request.namespace.0
                    || !address.key.starts_with(&request.prefix)
                    || request
                        .after
                        .as_ref()
                        .is_some_and(|after| &address.key <= after)
                {
                    continue;
                }
                let size = address.key.len() + value.expose(&crate::seal::lend()).len();
                if rows.len() == request.max_items || bytes + size > request.max_bytes {
                    more = true;
                    break;
                }
                bytes += size;
                rows.push((address.clone(), value.clone()));
            }
            let next = if native.bad_cursor {
                Some(vec![0])
            } else if more {
                Some(
                    rows.last()
                        .expect("test page budget fits one claim")
                        .0
                        .key
                        .clone(),
                )
            } else {
                None
            };
            Ok(Page {
                generation: native.scans as u64,
                rows,
                next,
            })
        })
    }

    fn commit(
        &self,
        prepared: PreparedCandidate,
        _key: busbar_contract::persistence::CommitKey,
    ) -> Call<'_, Decision> {
        Box::pin(async move {
            let hold = {
                let mut native = self.0.lock().unwrap();
                let candidate = prepared.candidate();
                let fingerprint = prepared.fingerprint();
                native.sends.push(fingerprint);
                if let Some((_, prior)) = native.receipts.iter().find(|(id, _)| id == &candidate.id)
                {
                    return Ok(if prior == &fingerprint {
                        Decision::Applied(candidate.result.clone())
                    } else {
                        Decision::OpIdConflict
                    });
                }
                if std::mem::take(&mut native.unknown_before) {
                    return Err(Failure::Unknown);
                }
                if let Some(now) = native.commit_now.take() {
                    native.now = now;
                }
                if let Some((address, value)) = native.replace.take() {
                    native.rows.insert(address, value);
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
                    let matches = match &predicate.expected {
                        ExpectedValue::Absent => !native.rows.contains_key(&predicate.address),
                        ExpectedValue::Exact(expected) => {
                            native.rows.get(&predicate.address) == Some(expected)
                        }
                    };
                    if !matches {
                        return Ok(Decision::ConditionConflict);
                    }
                }
                for mutation in &candidate.mutations {
                    match mutation {
                        Mutation::Delete(address) => {
                            native.rows.remove(address);
                        }
                        Mutation::Put { address, value } => {
                            native.rows.insert(address.clone(), value.clone());
                        }
                        _ => panic!("unexpected claim mutation"),
                    }
                }
                native.receipts.push((candidate.id, fingerprint));
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

    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { panic!("sweep requires coherent READ time, not a separate CLOCK") })
    }
}

fn value(expiry: u64) -> Secret<Vec<u8>> {
    let mut encoded = vec![1];
    encoded.extend_from_slice(&expiry.to_be_bytes());
    Secret::new(encoded)
}

async fn fixture(items: usize, bytes: usize) -> (Arc<Backend>, CoreStore) {
    let backend = Arc::new(Backend::default());
    backend.0.lock().unwrap().now = 100;
    let store = CoreStore::attach(
        backend.clone(),
        WriterAuthority {
            writer_epoch: 1,
            writer: [4; 16],
            execution_epoch: 1,
        },
        Limits {
            pending_operations: 4,
            conflict_retries: 2,
            scan_items: items,
            scan_bytes: bytes,
        },
    )
    .await
    .unwrap();
    (backend, store)
}

fn insert(backend: &Backend, claims: &Claims<'_>, token: &str, expiry: u64) -> Address {
    let address = claims.address(token).unwrap();
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .insert(address.clone(), value(expiry));
    address
}

#[tokio::test]
async fn sweep_preserves_inclusive_expiry_maximum_and_other_scopes() {
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    let expired = insert(&backend, &claims, "expired", 99);
    insert(&backend, &claims, "boundary", 100);
    insert(&backend, &claims, "maximum", u64::MAX);
    insert(
        &backend,
        &Claims::authorized(&store, "other", "kind"),
        "expired",
        1,
    );
    insert(
        &backend,
        &Claims::authorized(&store, "owner", "other"),
        "expired",
        1,
    );
    let mut sweep = claims.sweep().unwrap();
    assert_eq!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 3,
            deleted: 1,
            complete: true
        }
    );
    assert_eq!(sweep.advance().await.unwrap(), SweepOutcome::Complete);
    let native = backend.0.lock().unwrap();
    assert!(!native.rows.contains_key(&expired));
    assert_eq!(native.rows.len(), 4);
    assert_eq!(native.scans, 1);
}

#[tokio::test]
async fn sweep_advances_past_live_rows_and_revisits_inserts_on_next_pass() {
    let (backend, store) = fixture(2, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    for token in ["b", "c"] {
        insert(&backend, &claims, token, 100);
    }
    for token in ["e", "f", "g"] {
        insert(&backend, &claims, token, 99);
    }
    let mut sweep = claims.sweep().unwrap();
    assert_eq!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 2,
            deleted: 0,
            complete: false
        }
    );
    let behind = insert(&backend, &claims, "a", 1);
    let ahead = insert(&backend, &claims, "d", 1);
    assert_eq!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 2,
            deleted: 2,
            complete: false
        }
    );
    assert_eq!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 2,
            deleted: 2,
            complete: true
        }
    );
    assert!(!backend.0.lock().unwrap().rows.contains_key(&ahead));
    assert!(backend.0.lock().unwrap().rows.contains_key(&behind));
    assert_eq!(backend.0.lock().unwrap().scans, 3);
    assert_eq!(
        claims.sweep().unwrap().advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 2,
            deleted: 1,
            complete: false
        }
    );
    assert!(!backend.0.lock().unwrap().rows.contains_key(&behind));
}

#[tokio::test]
async fn sweep_obeys_byte_budget_and_refuses_malformed_cursor_or_clock() {
    let (backend, store) = fixture(20, 65).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    for token in ["a", "b"] {
        insert(&backend, &claims, token, 1);
    }
    assert_eq!(
        claims.sweep().unwrap().advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 1,
            deleted: 1,
            complete: false
        }
    );
    backend.0.lock().unwrap().bad_cursor = true;
    assert_eq!(claims.sweep().unwrap().advance().await, Err(Error::Corrupt));
    backend.0.lock().unwrap().bad_cursor = false;
    backend.0.lock().unwrap().wrong_clock = true;
    assert_eq!(claims.sweep().unwrap().advance().await, Err(Error::Corrupt));
    assert_eq!(backend.0.lock().unwrap().sends.len(), 1);
}

#[tokio::test]
async fn sweep_conflict_never_deletes_concurrently_reclaimed_value() {
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    let address = insert(&backend, &claims, "token", 99);
    backend.0.lock().unwrap().replace = Some((address.clone(), value(200)));
    assert_eq!(
        claims.sweep().unwrap().advance().await.unwrap(),
        SweepOutcome::Contended
    );
    assert_eq!(
        backend.0.lock().unwrap().rows.get(&address),
        Some(&value(200))
    );
}

#[tokio::test]
async fn sweep_clock_rewind_refuses_at_native_commit() {
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    let address = insert(&backend, &claims, "token", 99);
    backend.0.lock().unwrap().commit_now = Some(99);
    assert_eq!(
        claims.sweep().unwrap().advance().await.unwrap(),
        SweepOutcome::ClockRewound
    );
    assert!(backend.0.lock().unwrap().rows.contains_key(&address));
}

#[tokio::test]
async fn sweep_lost_reply_replays_receipt_without_deleting_new_claim() {
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    let address = insert(&backend, &claims, "token", 99);
    backend.0.lock().unwrap().lose_reply = true;
    let mut sweep = claims.sweep().unwrap();
    assert!(matches!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Pending(_)
    ));
    insert(&backend, &claims, "token", 200);
    backend.0.lock().unwrap().now = 1;
    assert_eq!(store.stop_admission().unwrap().len(), 1);
    assert_eq!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 1,
            deleted: 1,
            complete: true
        }
    );
    let native = backend.0.lock().unwrap();
    assert_eq!(native.scans, 1);
    assert_eq!(native.sends[0], native.sends[1]);
    assert_eq!(native.rows.get(&address), Some(&value(200)));
}

#[tokio::test]
async fn sweep_unknown_then_rewind_resolves_from_the_slotted_retry() {
    // STORE-TRANSACTIONS section 2.3: an equal-seq slotted retry is the slot row's single
    // evaluation, so a consistent time-guard refusal after an unevaluated send is final.
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    let address = insert(&backend, &claims, "token", 99);
    backend.0.lock().unwrap().unknown_before = true;
    let mut sweep = claims.sweep().unwrap();
    assert!(matches!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Pending(_)
    ));
    backend.0.lock().unwrap().now = 99;
    assert_eq!(sweep.advance().await.unwrap(), SweepOutcome::ClockRewound);
    let native = backend.0.lock().unwrap();
    assert_eq!(native.scans, 1);
    assert_eq!(native.sends.len(), 2);
    assert_eq!(native.sends[0], native.sends[1]);
    assert!(native.rows.contains_key(&address));
}

#[tokio::test]
async fn sweep_cancellation_keeps_cursor_and_exact_pending_candidate() {
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    insert(&backend, &claims, "token", 99);
    backend.0.lock().unwrap().hold_reply = true;
    let mut sweep = claims.sweep().unwrap();
    assert!(sweep.advance().now_or_never().is_none());
    assert_eq!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 1,
            deleted: 1,
            complete: true
        }
    );
    let native = backend.0.lock().unwrap();
    assert_eq!(native.scans, 1);
    assert_eq!(native.sends[0], native.sends[1]);
}

#[tokio::test]
async fn redeem_cancellation_rediscovers_original_attempt_before_reading_again() {
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    backend.0.lock().unwrap().hold_reply = true;
    assert!(claims.redeem("token", 200).now_or_never().is_none());
    // The committed row now exists, but retry must resolve the original attempt
    // as Claimed rather than misreporting AlreadyClaimed from a new observation.
    assert_eq!(claims.redeem("token", 200).await.unwrap(), Outcome::Claimed);
    let native = backend.0.lock().unwrap();
    assert_eq!(native.sends.len(), 2);
    assert_eq!(native.sends[0], native.sends[1]);
}

#[tokio::test]
async fn shutdown_redeem_rediscovers_cancelled_attempt_but_refuses_new_claims() {
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    backend.0.lock().unwrap().hold_reply = true;
    assert!(claims.redeem("token", 200).now_or_never().is_none());
    assert_eq!(store.stop_admission().unwrap().len(), 1);
    assert_eq!(claims.redeem("token", 200).await.unwrap(), Outcome::Claimed);
    assert_eq!(
        claims.redeem("new-token", 200).await.unwrap_err(),
        Error::Access(AccessError::Closed)
    );
    let native = backend.0.lock().unwrap();
    assert_eq!(native.sends.len(), 2);
    assert_eq!(native.sends[0], native.sends[1]);
}

#[tokio::test]
async fn registered_scopes_rotate_and_retain_cancelled_pages_without_store_cycles() {
    let (backend, store) = fixture(20, 4096).await;
    let store = Arc::new(store);
    let weak = Arc::downgrade(&store);
    insert(
        &backend,
        &Claims::authorized(&store, "owner", "first"),
        "expired",
        99,
    );
    insert(
        &backend,
        &Claims::authorized(&store, "owner", "second"),
        "expired",
        99,
    );
    store.register_claim_scope("owner", "first").unwrap();
    store.register_claim_scope("owner", "first").unwrap();
    store.register_claim_scope("owner", "second").unwrap();
    backend.0.lock().unwrap().hold_reply = true;
    assert!(store.sweep_claim_scope().now_or_never().is_none());
    assert_eq!(
        store.sweep_claim_scope().await.unwrap(),
        Some(SweepOutcome::Page {
            scanned: 1,
            deleted: 1,
            complete: true
        })
    );
    assert_eq!(
        store.sweep_claim_scope().await.unwrap(),
        Some(SweepOutcome::Page {
            scanned: 1,
            deleted: 1,
            complete: true
        })
    );
    {
        let native = backend.0.lock().unwrap();
        assert_eq!(native.scans, 2);
        assert_eq!(native.sends.len(), 3);
        assert_eq!(native.sends[0], native.sends[2]);
    }
    drop(store);
    assert!(
        weak.upgrade().is_none(),
        "maintenance must not own an Arc back to its attachment"
    );
}

fn scans(backend: &Backend) -> usize {
    backend.0.lock().unwrap().scans
}

/// Advance the local monotonic clock and the store clock together.
async fn tick(backend: &Backend, seconds: u64) {
    tokio::time::advance(std::time::Duration::from_secs(seconds)).await;
    backend.0.lock().unwrap().now += seconds;
}

#[tokio::test(start_paused = true)]
async fn idle_claim_scope_rests_after_complete_pass() {
    let (backend, store) = fixture(20, 4096).await;
    store.register_claim_scope("owner", "idle").unwrap();
    for _ in 0..120 {
        store.sweep_claim_scope().await.unwrap();
        tick(&backend, 1).await;
    }
    assert!(
        scans(&backend) <= 3,
        "an empty scope rests between passes: {} scans in 120 s",
        scans(&backend)
    );
}

#[tokio::test(start_paused = true)]
async fn rest_honours_earliest_expiry() {
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    let soon = insert(&backend, &claims, "soon", 103);
    let later = insert(&backend, &claims, "later", 130);
    store.register_claim_scope("owner", "kind").unwrap();
    assert_eq!(
        store.sweep_claim_scope().await.unwrap(),
        Some(SweepOutcome::Page {
            scanned: 2,
            deleted: 0,
            complete: true
        })
    );
    assert_eq!(scans(&backend), 1);
    for _ in 0..3 {
        tick(&backend, 1).await;
        assert_eq!(store.sweep_claim_scope().await.unwrap(), None);
    }
    assert_eq!(scans(&backend), 1, "no scan before the earliest expiry");
    tick(&backend, 1).await;
    assert_eq!(
        store.sweep_claim_scope().await.unwrap(),
        Some(SweepOutcome::Page {
            scanned: 2,
            deleted: 1,
            complete: true
        })
    );
    assert_eq!(scans(&backend), 2);
    assert!(!backend.0.lock().unwrap().rows.contains_key(&soon));
    assert!(backend.0.lock().unwrap().rows.contains_key(&later));
    for _ in 0..26 {
        tick(&backend, 1).await;
        assert_eq!(store.sweep_claim_scope().await.unwrap(), None);
    }
    assert_eq!(
        scans(&backend),
        2,
        "the next pass waits for the +30 s expiry"
    );
    tick(&backend, 1).await;
    store.sweep_claim_scope().await.unwrap();
    assert_eq!(scans(&backend), 3);
}

#[tokio::test(start_paused = true)]
async fn late_sweep_never_redeems_lapsed_claim() {
    let (backend, store) = fixture(20, 4096).await;
    backend.0.lock().unwrap().honour_read_time = true;
    let claims = Claims::authorized(&store, "owner", "kind");
    store.register_claim_scope("owner", "kind").unwrap();
    assert_eq!(
        store.sweep_claim_scope().await.unwrap(),
        Some(SweepOutcome::Complete)
    );
    // The scope rests; a claim lapsing in 2 s is written into it.
    assert_eq!(claims.redeem("token", 102).await.unwrap(), Outcome::Claimed);
    tick(&backend, 5).await;
    assert_eq!(store.sweep_claim_scope().await.unwrap(), None);
    assert_eq!(scans(&backend), 1);
    assert_eq!(
        claims.redeem("lapsed", 102).await.unwrap(),
        Outcome::Expired,
        "redeem enforces lapse by its own TimeGuard, whatever the sweep timing"
    );
    let address = claims.address("token").unwrap();
    for _ in 0..55 {
        tick(&backend, 1).await;
        store.sweep_claim_scope().await.unwrap();
    }
    assert!(
        !backend.0.lock().unwrap().rows.contains_key(&address),
        "the lapsed row is deleted within the maximum rest"
    );
}

#[tokio::test(start_paused = true)]
async fn rest_is_not_store_time() {
    let (backend, store) = fixture(20, 4096).await;
    backend.0.lock().unwrap().now = 1_000_000_000;
    let claims = Claims::authorized(&store, "owner", "kind");
    insert(&backend, &claims, "far", 1_000_000_000 + 1_000_000);
    store.register_claim_scope("owner", "kind").unwrap();
    store.sweep_claim_scope().await.unwrap();
    assert_eq!(scans(&backend), 1);
    tick(&backend, 59).await;
    assert_eq!(store.sweep_claim_scope().await.unwrap(), None);
    assert_eq!(scans(&backend), 1);
    tick(&backend, 1).await;
    store.sweep_claim_scope().await.unwrap();
    assert_eq!(
        scans(&backend),
        2,
        "the rest is capped by the maximum, not by store seconds"
    );
}

/// 8.7: a sweep tick on a full slot queue gets Overloaded and keeps its prepared
/// page unregistered; once a slot frees, the next tick submits and completes.
#[tokio::test]
async fn sweep_on_a_full_queue_is_overloaded_then_completes_next_tick() {
    use busbar_contract::persistence::{Candidate, Mutation, CANDIDATE_VERSION};
    let (backend, store) = fixture(20, 4096).await;
    let claims = Claims::authorized(&store, "owner", "kind");
    let address = insert(&backend, &claims, "token", 99);
    let mut held = Vec::new();
    for n in 0..4u8 {
        backend.0.lock().unwrap().unknown_before = true;
        let candidate = PreparedCandidate::new(Candidate {
            id: store.next_id().unwrap(),
            codec: CANDIDATE_VERSION,
            predicates: vec![],
            mutations: vec![Mutation::Put {
                address: Address {
                    namespace: [7; 16],
                    key: vec![n],
                },
                value: Secret::new(vec![n]),
            }],
            time: None,
            result: Secret::new(vec![]),
        })
        .unwrap();
        held.push(store.submit(candidate).await.unwrap().id);
    }
    let mut sweep = claims.sweep().unwrap();
    assert!(matches!(
        sweep.advance().await,
        Err(Error::Access(
            crate::persistence::facade::AccessError::Overloaded
        ))
    ));
    assert!(store.exhausted());
    assert!(matches!(
        store.retry(held[0]).await.unwrap().result,
        crate::persistence::commit::SubmitResult::Decided(_)
    ));
    assert_eq!(
        sweep.advance().await.unwrap(),
        SweepOutcome::Page {
            scanned: 1,
            deleted: 1,
            complete: true
        }
    );
    assert!(!backend.0.lock().unwrap().rows.contains_key(&address));
}
