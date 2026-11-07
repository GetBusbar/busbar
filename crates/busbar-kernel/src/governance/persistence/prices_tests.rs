// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::facade::{Limits, WriterAuthority};
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Durability, PersistenceBackend, control,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

#[derive(Default)]
pub(crate) struct State {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
    pub(crate) sent: Vec<PreparedCandidate>,
    generations: HashMap<[u8; 16], u64>,
}
#[derive(Default)]
pub(crate) struct Backend {
    pub(crate) state: Mutex<State>,
    pub(crate) lose_reply: AtomicBool,
    pub(crate) hang: AtomicBool,
    lose_call: std::sync::atomic::AtomicUsize,
}
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
            let state = self.state.lock().unwrap();
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [3; 16],
                    unix_seconds: 10,
                },
                values: request
                    .addresses
                    .iter()
                    .map(|at| {
                        if at.namespace == control::GENERATION_NAMESPACE.0 {
                            let namespace: [u8; 16] = at.key.as_slice().try_into().unwrap();
                            state
                                .generations
                                .get(&namespace)
                                .map(|v| Secret::new(v.to_le_bytes().to_vec()))
                        } else if at.namespace == control::NAMESPACE.0 {
                            let bytes = if at.key == control::DATASET_KEY {
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
                            Some(Secret::new(bytes))
                        } else {
                            state.rows.get(at).cloned()
                        }
                    })
                    .collect(),
            })
        })
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> Call<'_, busbar_contract::persistence::Page> {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            let generation = state
                .generations
                .get(&request.namespace.0)
                .copied()
                .unwrap_or(0);
            if request.generation.is_some_and(|n| n != generation) {
                return Err(Failure::StaleScan);
            }
            let seal = crate::seal::lend();
            let mut bytes = 0;
            let mut rows = Vec::new();
            let mut more = false;
            for (at, value) in &state.rows {
                if at.namespace != request.namespace.0
                    || !at.key.starts_with(&request.prefix)
                    || request.after.as_ref().is_some_and(|key| key >= &at.key)
                {
                    continue;
                }
                bytes += at.key.len() + value.expose(&seal).len();
                if rows.len() == request.max_items || bytes > request.max_bytes {
                    more = true;
                    break;
                }
                rows.push((at.clone(), value.clone()));
            }
            Ok(busbar_contract::persistence::Page {
                generation,
                next: if more {
                    rows.last().map(|(at, _)| at.key.clone())
                } else {
                    None
                },
                rows,
            })
        })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        self.state.lock().unwrap().sent.push(prepared.clone());
        Box::pin(async move {
            if self.hang.load(Ordering::SeqCst) {
                std::future::pending::<()>().await;
            }
            let mut state = self.state.lock().unwrap();
            let candidate = prepared.candidate();
            if let Some(digest) = state.receipts.get(&candidate.id.operation) {
                return Ok(if *digest == prepared.fingerprint() {
                    Decision::Applied(candidate.result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            for predicate in &candidate.predicates {
                let generated;
                let found = if predicate.address.namespace == control::GENERATION_NAMESPACE.0 {
                    let namespace: [u8; 16] = predicate.address.key.as_slice().try_into().unwrap();
                    generated = state
                        .generations
                        .get(&namespace)
                        .map(|v| Secret::new(v.to_le_bytes().to_vec()));
                    generated.as_ref()
                } else {
                    state.rows.get(&predicate.address)
                };
                let matches = match &predicate.expected {
                    ExpectedValue::Absent => found.is_none(),
                    ExpectedValue::Exact(bytes) => found == Some(bytes),
                };
                if !matches {
                    return Ok(Decision::ConditionConflict);
                }
            }
            let mut changed = BTreeSet::new();
            for mutation in &candidate.mutations {
                match mutation {
                    Mutation::Put { address, value } => {
                        changed.insert(address.namespace);
                        state.rows.insert(address.clone(), value.clone());
                    }
                    Mutation::Delete(at) => {
                        changed.insert(at.namespace);
                        state.rows.remove(at);
                    }
                    Mutation::DeleteRange {
                        namespace,
                        prefix,
                        exact_key_length,
                    } => {
                        changed.insert(namespace.0);
                        state.rows.retain(|at, _| {
                            !(at.namespace == namespace.0
                                && at.key.starts_with(prefix)
                                && at.key.len() as u64 == *exact_key_length)
                        });
                    }
                }
            }
            for namespace in changed {
                *state.generations.entry(namespace).or_default() += 1;
            }
            state
                .receipts
                .insert(candidate.id.operation, prepared.fingerprint());
            let call_number = state.sent.len();
            if self.lose_reply.swap(false, Ordering::SeqCst)
                || self
                    .lose_call
                    .compare_exchange(call_number, 0, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
            {
                return Err(Failure::Unknown);
            }
            Ok(Decision::Applied(candidate.result.clone()))
        })
    }
}
pub(crate) async fn attach(backend: Arc<Backend>) -> CoreStore {
    CoreStore::attach(
        backend,
        WriterAuthority {
            writer_epoch: 2,
            writer: [4; 16],
            execution_epoch: 3,
        },
        Limits {
            pending_operations: 16,
            conflict_retries: 2,
            scan_items: 2,
            scan_bytes: 32768,
        },
    )
    .await
    .unwrap()
}
fn key(time: u64) -> EntryKey {
    EntryKey::new(time, [5; 8], 0)
}
fn entry(time: u64, base: Option<EntryKey>) -> StoredEntry {
    StoredEntry {
        key: key(time),
        effective_from: if base.is_none() { 0 } else { time },
        effective_until: None,
        appended_at: time,
        author: if base.is_none() {
            EntryAuthor::Opening {}
        } else {
            EntryAuthor::Change
        },
        actor: "reload by operator".into(),
        base,
        writer: 42,
        set_fields: vec!["per_request_fee".into()],
        card: CardFields {
            per_request_fee: time as i64,
            ..CardFields::default()
        },
        correction: Some(vec![0, 128, 255, 1]),
    }
}
async fn applied(prices: &Prices<'_>, mut plan: PricePlan) {
    assert_eq!(prices.submit(&mut plan).await.unwrap(), Outcome::Applied);
}
async fn opening(prices: &Prices<'_>) {
    applied(prices, prices.prepare(entry(1, None), true).await.unwrap()).await;
    applied(
        prices,
        prices
            .authorize_activation(key(1), Activation { effective_from: 0 })
            .await
            .unwrap(),
    )
    .await;
    applied(prices, prices.activate(key(1)).await.unwrap()).await;
}

#[tokio::test]
async fn unknown_keeps_exact_operation_and_never_grants_publication() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let prices = store.prices();
    opening(&prices).await;
    applied(
        &prices,
        prices.prepare(entry(2, Some(key(1))), true).await.unwrap(),
    )
    .await;
    applied(
        &prices,
        prices
            .authorize_activation(
                key(2),
                Activation {
                    effective_from: 100,
                },
            )
            .await
            .unwrap(),
    )
    .await;
    let mut plan = prices.activate(key(2)).await.unwrap();
    let fingerprint = plan.candidate.fingerprint();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(matches!(
        prices.submit(&mut plan).await.unwrap(),
        Outcome::Pending(_)
    ));
    assert!(plan.publication().is_none());
    assert!(plan.pending_id().is_some());
    assert_eq!(prices.submit(&mut plan).await.unwrap(), Outcome::Applied);
    assert_eq!(plan.publication().unwrap().entry, entry(2, Some(key(1))));
    assert_eq!(
        plan.publication()
            .unwrap()
            .activation
            .unwrap()
            .effective_from,
        100
    );
    let state = backend.state.lock().unwrap();
    let sent = &state.sent;
    assert_eq!(sent[sent.len() - 2].fingerprint(), fingerprint);
    assert_eq!(sent[sent.len() - 1].fingerprint(), fingerprint);
    assert_eq!(
        sent[sent.len() - 2].candidate().id,
        sent[sent.len() - 1].candidate().id
    );
}

#[tokio::test]
async fn restart_retains_activation_and_retirement_boundaries_and_provenance() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let prices = store.prices();
    opening(&prices).await;
    let original = entry(2, Some(key(1)));
    applied(
        &prices,
        prices.prepare(original.clone(), true).await.unwrap(),
    )
    .await;
    applied(
        &prices,
        prices
            .authorize_activation(
                key(2),
                Activation {
                    effective_from: 200,
                },
            )
            .await
            .unwrap(),
    )
    .await;
    let restarted = attach(backend.clone()).await;
    let recovered = restarted.prices().snapshot().await.unwrap();
    assert_eq!(recovered.entries.len(), 1);
    assert_eq!(recovered.intents[&key(2)].entry, original);
    assert_eq!(recovered.intents[&key(2)].phase, Phase::Activating);
    assert_eq!(
        recovered.intents[&key(2)]
            .activation
            .unwrap()
            .effective_from,
        200
    );
    assert!(matches!(
        restarted.prices().authorize_retirement(key(2)).await,
        Err(Error::WrongPhase)
    ));
    applied(
        &restarted.prices(),
        restarted.prices().activate(key(2)).await.unwrap(),
    )
    .await;
    applied(
        &restarted.prices(),
        restarted
            .prices()
            .prepare(entry(3, Some(key(2))), true)
            .await
            .unwrap(),
    )
    .await;
    backend.lose_reply.store(true, Ordering::SeqCst);
    let mut retirement = restarted
        .prices()
        .authorize_retirement(key(3))
        .await
        .unwrap();
    assert!(matches!(
        restarted.prices().submit(&mut retirement).await.unwrap(),
        Outcome::Pending(_)
    ));
    assert!(matches!(
        restarted
            .prices()
            .authorize_activation(
                key(3),
                Activation {
                    effective_from: 300
                }
            )
            .await,
        Err(Error::WrongPhase)
    ));
    assert_eq!(
        restarted.prices().snapshot().await.unwrap().intents[&key(3)].phase,
        Phase::Retiring
    );
    assert_eq!(
        restarted.prices().submit(&mut retirement).await.unwrap(),
        Outcome::Applied
    );
    applied(
        &restarted.prices(),
        restarted.prices().retire(key(3)).await.unwrap(),
    )
    .await;
    let recovered = restarted.prices().snapshot().await.unwrap();
    assert!(!recovered.entries.contains_key(&key(3)));
    assert_eq!(recovered.intents[&key(3)].phase, Phase::Retired);
}

#[tokio::test]
async fn competing_heads_conflict_and_actual_base_is_preserved() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let prices = store.prices();
    opening(&prices).await;
    for n in [2, 3] {
        applied(
            &prices,
            prices.prepare(entry(n, Some(key(1))), true).await.unwrap(),
        )
        .await;
        applied(
            &prices,
            prices
                .authorize_activation(
                    key(n),
                    Activation {
                        effective_from: n * 100,
                    },
                )
                .await
                .unwrap(),
        )
        .await;
    }
    let mut first = prices.activate(key(2)).await.unwrap();
    let mut second = prices.activate(key(3)).await.unwrap();
    assert_eq!(prices.submit(&mut first).await.unwrap(), Outcome::Applied);
    assert_eq!(prices.submit(&mut second).await.unwrap(), Outcome::Conflict);
    assert!(second.publication().is_none());
    // A definitive conflict permits planning against the new head. Provenance
    // still names this node's actual predecessor, not the fleet's newest card.
    applied(&prices, prices.activate(key(3)).await.unwrap()).await;
    assert_eq!(
        prices.snapshot().await.unwrap().entries[&key(3)].base,
        Some(key(1))
    );
    let mut next = prices.prepare(entry(4, Some(key(1))), true).await.unwrap();
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(at(b'E', Some(key(1))), Secret::new(entry(99, None).value()));
    assert_eq!(prices.submit(&mut next).await.unwrap(), Outcome::Conflict);
}

#[tokio::test]
async fn strict_restart_refuses_unknown_metadata_and_missing_body() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    opening(&store.prices()).await;
    let status_address = at(b'S', Some(key(1)));
    let original = backend.state.lock().unwrap().rows[&status_address].clone();
    let mut value: serde_json::Value = decode(&original).unwrap();
    value["unexpected"] = serde_json::json!(true);
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(status_address.clone(), encode(&value).unwrap());
    assert!(matches!(
        store.prices().snapshot().await,
        Err(Error::Corrupt)
    ));
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(status_address, original);
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .remove(&at(b'E', Some(key(1))));
    assert!(matches!(
        store.prices().snapshot().await,
        Err(Error::Corrupt)
    ));
}

#[tokio::test]
async fn raw_price_records_exceed_legacy_limit_and_keep_signed_envelope() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend).await;
    let mut original = entry(1, None);
    original.actor = "a".repeat(2048);
    original.correction = Some((0..4096).map(|i| i as u8).collect());
    let mut plan = store
        .prices()
        .prepare(original.clone(), false)
        .await
        .unwrap();
    assert!(plan.publication().is_none());
    assert_eq!(
        store.prices().submit(&mut plan).await.unwrap(),
        Outcome::Applied
    );
    assert_eq!(plan.publication().unwrap().entry, original);
    assert_eq!(
        store.prices().snapshot().await.unwrap().entries[&key(1)],
        original
    );
}

#[tokio::test]
async fn cancellation_retains_native_candidate_before_crossing() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let mut plan = store.prices().prepare(entry(1, None), false).await.unwrap();
    backend.hang.store(true, Ordering::SeqCst);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            store.prices().submit(&mut plan)
        )
        .await
        .is_err()
    );
    let id = plan.pending_id().unwrap();
    assert!(plan.publication().is_none());
    backend.hang.store(false, Ordering::SeqCst);
    assert_eq!(
        store.prices().submit(&mut plan).await.unwrap(),
        Outcome::Applied
    );
    let sent = &backend.state.lock().unwrap().sent;
    assert_eq!(sent[0].candidate().id.operation, id.0);
    assert_eq!(sent[0].fingerprint(), sent[1].fingerprint());
}

#[tokio::test]
async fn historical_projection_uses_cutover_bounded_amendments_and_node_ownership() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend).await;
    let prices = store.prices();
    opening(&prices).await;
    let mut foreign = entry(2, Some(key(1)));
    foreign.writer = 43;
    applied(&prices, prices.prepare(foreign, true).await.unwrap()).await;
    applied(
        &prices,
        prices
            .authorize_activation(
                key(2),
                Activation {
                    effective_from: 200,
                },
            )
            .await
            .unwrap(),
    )
    .await;
    applied(&prices, prices.activate(key(2)).await.unwrap()).await;
    let mut amendment = entry(3, Some(key(1)));
    amendment.author = EntryAuthor::Amend {
        reason: "ab".repeat(32),
    };
    amendment.effective_from = 50;
    amendment.effective_until = Some(75);
    applied(&prices, prices.prepare(amendment, false).await.unwrap()).await;
    let snapshot = prices.snapshot().await.unwrap();
    let convert = |card: &CardFields| RateCard::absent(card.per_request_fee);
    let fleet = snapshot.history(convert);
    assert_eq!(fleet.current().entry_at(49).unwrap().key(), key(1));
    assert_eq!(fleet.current().entry_at(50).unwrap().key(), key(3));
    assert_eq!(fleet.current().entry_at(74).unwrap().key(), key(3));
    assert_eq!(fleet.current().entry_at(75).unwrap().key(), key(1));
    assert_eq!(fleet.current().entry_at(199).unwrap().key(), key(1));
    assert_eq!(fleet.current().entry_at(200).unwrap().key(), key(2));
    let node = snapshot.node_history(42, Some(key(1)), convert);
    assert_eq!(node.current().entry_at(200).unwrap().key(), key(1));
    assert_eq!(node.current().entry_at(50).unwrap().key(), key(3));
}

#[tokio::test]
async fn void_is_future_only_and_retains_audit_without_deleting_entry() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend).await;
    let prices = store.prices();
    opening(&prices).await;
    applied(
        &prices,
        prices.prepare(entry(2, Some(key(1))), true).await.unwrap(),
    )
    .await;
    applied(
        &prices,
        prices
            .authorize_activation(
                key(2),
                Activation {
                    effective_from: 200,
                },
            )
            .await
            .unwrap(),
    )
    .await;
    applied(&prices, prices.activate(key(2)).await.unwrap()).await;
    let record = VoidRecord {
        voided: key(2).hex(),
        voider: 42,
        at_ms: 100,
        actor: "operator".into(),
        why: "void".into(),
    };
    assert!(matches!(
        prices.void(record.clone(), 200).await,
        Err(Error::WrongPhase)
    ));
    applied(&prices, prices.void(record.clone(), 100).await.unwrap()).await;
    let snapshot = prices.snapshot().await.unwrap();
    assert_eq!(snapshot.voids, vec![record]);
    assert!(snapshot.entries.contains_key(&key(2)));
    let history = snapshot.history(|card| RateCard::absent(card.per_request_fee));
    assert_eq!(history.current().entry_at(200).unwrap().key(), key(1));
}

fn runtime_rates(card: &CardFields) -> RateCard {
    RateCard::absent(card.per_request_fee)
}
async fn runtime_book(backend: Arc<Backend>) -> (Arc<CoreStore>, Arc<runtime::CardStore>) {
    let store = Arc::new(attach(backend).await);
    let book = runtime::CardStore::new(store.clone(), 42, runtime_rates).unwrap();
    book.boot(
        &CardFields {
            per_request_fee: 1,
            ..CardFields::default()
        },
        "original boot",
        Vec::new(),
    )
    .await
    .unwrap();
    (store, book)
}

#[tokio::test]
async fn runtime_activation_unknown_and_rescan_cannot_publish_before_generation_commit() {
    let backend = Arc::new(Backend::default());
    let (store, book) = runtime_book(backend.clone()).await;
    let original = book.own().unwrap().0;
    let card = CardFields {
        per_request_fee: 2,
        ..CardFields::default()
    };
    let prepared = book
        .prepare(&card, "reload by original operator")
        .await
        .unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(prepared.confirm_activation().await.is_err());
    let sent = backend.state.lock().unwrap().sent.last().unwrap().clone();
    assert_eq!(book.own().unwrap().0, original);
    book.rescan(None).await.unwrap();
    assert_eq!(book.history().unwrap().len(), 1);
    let prepared = book
        .prepare(&card, "retry must not rewrite actor")
        .await
        .unwrap();
    let replay = backend.state.lock().unwrap().sent.last().unwrap().clone();
    assert_eq!(sent.fingerprint(), replay.fingerprint());
    assert_eq!(sent.candidate().id, replay.candidate().id);
    let confirmed = prepared.confirm_activation().await.unwrap();
    book.rescan(None).await.unwrap();
    assert_eq!(book.own().unwrap().0, original);
    assert_eq!(book.history().unwrap().len(), 1);
    let key = confirmed.commit();
    assert_eq!(book.own().unwrap(), (key, card));
    assert_eq!(
        book.entry(&key).unwrap().actor,
        "reload by original operator"
    );
    let snapshot = store.prices().snapshot().await.unwrap();
    assert_eq!(snapshot.intents[&key].phase, Phase::Active);
    assert!(snapshot.activations.contains_key(&key));
}

#[tokio::test]
async fn runtime_uncertain_retirement_finishes_before_superseding_original() {
    let backend = Arc::new(Backend::default());
    let (store, book) = runtime_book(backend.clone()).await;
    let rejected = CardFields {
        per_request_fee: 2,
        ..CardFields::default()
    };
    drop(
        book.prepare(&rejected, "original inert preparation")
            .await
            .unwrap(),
    );
    let retired = book.pending().unwrap();
    let replacement = CardFields {
        per_request_fee: 3,
        ..CardFields::default()
    };
    assert!(book.prepare(&replacement, "ordinary apply").await.is_err());
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(
        book.prepare_recovery(&replacement, "explicit reload")
            .await
            .is_err()
    );
    let original = backend.state.lock().unwrap().sent.last().unwrap().clone();
    // Retrying the old values must resolve retirement rather than activate them.
    assert!(book.prepare(&rejected, "old values retried").await.is_err());
    let replay = backend.state.lock().unwrap().sent.last().unwrap().clone();
    assert_eq!(original.fingerprint(), replay.fingerprint());
    assert_eq!(original.candidate().id, replay.candidate().id);
    let prepared = book
        .prepare_recovery(&replacement, "explicit reload")
        .await
        .unwrap();
    prepared.confirm_activation().await.unwrap().commit();
    let snapshot = store.prices().snapshot().await.unwrap();
    assert_eq!(snapshot.intents[&retired].phase, Phase::Retired);
    assert_eq!(
        snapshot.intents[&retired].entry.actor,
        "original inert preparation"
    );
    assert!(!snapshot.activations.contains_key(&retired));
    assert!(!snapshot.entries.contains_key(&retired));
    assert_eq!(book.own().unwrap().1, replacement);
}

#[tokio::test]
async fn runtime_cancellation_retries_the_exact_native_plan_and_keeps_provenance() {
    let backend = Arc::new(Backend::default());
    let (_, book) = runtime_book(backend.clone()).await;
    let original = book.own().unwrap().0;
    let card = CardFields {
        per_request_fee: 4,
        ..CardFields::default()
    };
    backend.hang.store(true, Ordering::SeqCst);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(10),
            book.prepare(&card, "cancelled original actor")
        )
        .await
        .is_err()
    );
    let held = backend.state.lock().unwrap().sent.last().unwrap().clone();
    backend.hang.store(false, Ordering::SeqCst);
    let prepared = book.prepare(&card, "retry actor").await.unwrap();
    let replay = backend.state.lock().unwrap().sent.last().unwrap().clone();
    assert_eq!(held.fingerprint(), replay.fingerprint());
    assert_eq!(held.candidate().id, replay.candidate().id);
    assert_eq!(book.own().unwrap().0, original);
    let key = prepared.confirm_activation().await.unwrap().commit();
    assert_eq!(book.entry(&key).unwrap().actor, "cancelled original actor");
}

#[tokio::test]
async fn runtime_unknown_final_activation_stays_private_until_its_applied_receipt() {
    let backend = Arc::new(Backend::default());
    let (store, book) = runtime_book(backend.clone()).await;
    let original = book.own().unwrap().0;
    let card = CardFields {
        per_request_fee: 5,
        ..CardFields::default()
    };
    let prepared = book
        .prepare(&card, "final activation original")
        .await
        .unwrap();
    let activation_call = backend.state.lock().unwrap().sent.len() + 2;
    backend.lose_call.store(activation_call, Ordering::SeqCst);
    assert!(prepared.confirm_activation().await.is_err());
    let unknown = backend.state.lock().unwrap().sent.last().unwrap().clone();
    let key = book.pending().unwrap();
    assert_eq!(
        store.prices().snapshot().await.unwrap().intents[&key].phase,
        Phase::Active
    );
    book.rescan(None).await.unwrap();
    assert_eq!(book.own().unwrap().0, original);
    assert_eq!(book.history().unwrap().len(), 1);
    let prepared = book.prepare(&card, "retry").await.unwrap();
    let replay = backend.state.lock().unwrap().sent.last().unwrap().clone();
    assert_eq!(unknown.fingerprint(), replay.fingerprint());
    assert_eq!(unknown.candidate().id, replay.candidate().id);
    let confirmed = prepared.confirm_activation().await.unwrap();
    assert_eq!(book.own().unwrap().0, original);
    assert_eq!(confirmed.commit(), key);
    assert_eq!(book.own().unwrap().1, card);
}

#[tokio::test]
async fn runtime_unknown_void_readback_does_not_publish_or_rewrite_its_original() {
    let backend = Arc::new(Backend::default());
    let (store, book) = runtime_book(backend.clone()).await;
    let base = book.own().unwrap().0;
    let time = crate::store::now_ms() + 60_000;
    let mut future = entry(time, Some(base));
    future.card.per_request_fee = 7;
    let key = future.key;
    applied(
        &store.prices(),
        store.prices().prepare(future, false).await.unwrap(),
    )
    .await;
    book.rescan(None).await.unwrap();
    assert_eq!(
        book.history()
            .unwrap()
            .current()
            .entry_at(time)
            .unwrap()
            .key(),
        key
    );
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(book.void(key, "original void actor").await.is_err());
    let unknown = backend.state.lock().unwrap().sent.last().unwrap().clone();
    book.rescan(None).await.unwrap();
    assert_eq!(
        book.history()
            .unwrap()
            .current()
            .entry_at(time)
            .unwrap()
            .key(),
        key
    );
    book.void(key, "retry must keep actor").await.unwrap();
    let replay = backend.state.lock().unwrap().sent.last().unwrap().clone();
    assert_eq!(unknown.fingerprint(), replay.fingerprint());
    assert_eq!(unknown.candidate().id, replay.candidate().id);
    assert_ne!(
        book.history()
            .unwrap()
            .current()
            .entry_at(time)
            .unwrap()
            .key(),
        key
    );
    assert_eq!(
        store.prices().snapshot().await.unwrap().voids[0].actor,
        "original void actor"
    );
}

#[tokio::test]
async fn runtime_serving_boot_refuses_historical_import_without_writing() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let book = runtime::CardStore::new(store, 42, runtime_rates).unwrap();
    let historical = entry(1, None);
    assert!(
        book.boot(&historical.card, "serving boot", vec![historical.clone()])
            .await
            .is_err()
    );
    assert!(backend.state.lock().unwrap().sent.is_empty());
    assert!(book.history().is_none());
    assert!(!book.is_loaded());
}

#[tokio::test]
async fn runtime_boot_keeps_unknown_original_across_an_interrupted_wait() {
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let book = runtime::CardStore::new(store, 42, runtime_rates).unwrap();
    let card = CardFields {
        per_request_fee: 7,
        ..Default::default()
    };
    backend.lose_reply.store(true, Ordering::SeqCst);
    let boot = book.boot(&card, "original boot", Vec::new());
    tokio::pin!(boot);
    assert!(futures::poll!(&mut boot).is_pending());
    let original = backend.state.lock().unwrap().sent.last().unwrap().clone();
    let key = book.pending().expect("boot retains the original candidate");
    assert!(
        book.history().is_none_or(|history| history.len() == 0),
        "an unknown original grants no publication"
    );
    boot.await.unwrap();
    let sent = backend.state.lock().unwrap().sent.clone();
    assert!(sent.len() >= 2);
    assert_eq!(sent[1].candidate().id, original.candidate().id);
    assert_eq!(sent[1].fingerprint(), original.fingerprint());
    assert_eq!(book.own().unwrap().0, key);
    assert_eq!(book.entries().len(), 1);
    assert!(book.pending().is_none());
    book.stop_background().await.unwrap();
}
