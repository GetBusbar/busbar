// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::facade::{Limits, WriterAuthority};
use busbar_contract::persistence::{
    control, BackendInfo, Call, ClockObservation, DatasetId, Durability, PersistenceBackend,
};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

#[derive(Default)]
struct State {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: HashMap<[u8; 16], [u8; 32]>,
    sent: Vec<PreparedCandidate>,
    generations: HashMap<[u8; 16], u64>,
}
#[derive(Default)]
struct Backend {
    state: Mutex<State>,
    lose_reply: AtomicBool,
    hang: AtomicBool,
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
            if self.lose_reply.swap(false, Ordering::SeqCst) {
                return Err(Failure::Unknown);
            }
            Ok(Decision::Applied(candidate.result.clone()))
        })
    }
}
async fn attach(backend: Arc<Backend>) -> CoreStore {
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
fn declarations() -> [Collection<'static>; 3] {
    [
        Collection {
            kind: "root",
            mode: Mode::Upsert,
            retention: Retention::TerminalOnly,
            parent: None,
        },
        Collection {
            kind: "child",
            mode: Mode::Upsert,
            retention: Retention::Age,
            parent: Some("root"),
        },
        Collection {
            kind: "leaf",
            mode: Mode::Append,
            retention: Retention::Age,
            parent: Some("child"),
        },
    ]
}
fn row(kind: &str, id: &str, parent: Option<&str>, seq: u64, terminal: bool) -> PlaneRecord {
    PlaneRecord {
        kind: kind.into(),
        id: id.into(),
        parent: parent.map(str::to_owned),
        seq,
        ts: 10,
        disposition: if terminal {
            PlaneDisposition::Terminal
        } else {
            PlaneDisposition::Active
        },
        body: vec![0, 255, 128, 3],
    }
}
#[tokio::test]
async fn opaque_envelopes_replay_fork_retention_and_recursive_cascade() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let history = History::authorized(&store, "owner", declarations()).unwrap();
    let mut root = row("root", "r", None, 0, false);
    root.body = vec![255; 12000];
    let child = row("child", "c", Some("r"), 0, false);
    let leaf = row("leaf", "l", Some("c"), 1, false);
    assert_eq!(
        history.upsert(child.view()).await,
        Err(Error::MissingParent)
    );
    assert_eq!(history.upsert(root.view()).await.unwrap(), Outcome::Applied);
    assert_eq!(history.get("root", "r").await.unwrap(), Some(root.clone()));
    assert_eq!(
        history.upsert(child.view()).await.unwrap(),
        Outcome::Applied
    );
    assert_eq!(history.append(leaf.view()).await.unwrap(), Outcome::Applied);
    assert_eq!(history.append(leaf.view()).await.unwrap(), Outcome::Applied);
    let mut divergent = leaf.clone();
    divergent.body.push(1);
    assert_eq!(history.append(divergent.view()).await, Err(Error::Fork));
    assert_eq!(history.parents("leaf").await.unwrap(), vec!["c"]);
    assert_eq!(
        history
            .list("leaf", &PlaneSelector::Parent("c".into()))
            .await
            .unwrap(),
        vec![leaf.clone()]
    );
    assert_eq!(
        history.purge("root", 20).await.unwrap(),
        (Outcome::Applied, 0)
    );
    root.disposition = PlaneDisposition::Terminal;
    history.upsert(root.view()).await.unwrap();
    let before = backend.state.lock().unwrap().sent.len();
    assert_eq!(
        history.purge("root", 20).await.unwrap(),
        (Outcome::Applied, 1)
    );
    assert_eq!(backend.state.lock().unwrap().sent.len(), before + 1);
    assert!(history.get("child", "c").await.unwrap().is_none());
    assert!(history
        .list("leaf", &PlaneSelector::All)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(history.append(leaf.view()).await, Err(Error::MissingParent));
    let other = History::authorized(&store, "other", declarations()).unwrap();
    assert_ne!(
        history.address("root", "r", b'M', 0).unwrap().key,
        other.address("root", "r", b'M', 0).unwrap().key
    );
    assert!(other.get("root", "r").await.unwrap().is_none());
}
#[tokio::test]
async fn parent_life_and_scan_guards_reject_delete_recreate_aba() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let history = History::authorized(&store, "owner", declarations()).unwrap();
    let root = row("root", "r", None, 0, false);
    history.upsert(root.view()).await.unwrap();
    let mut stale_append = Plan::new(&store);
    let first = history
        .observe(&mut stale_append, "root", "r")
        .await
        .unwrap()
        .life
        .unwrap();
    let child = row("child", "c", Some("r"), 0, false);
    history
        .observe(&mut stale_append, "child", "c")
        .await
        .unwrap();
    stale_append.put(
        history.address("child", "c", b'M', 0).unwrap(),
        encode(&Metadata::new(child.view(), Some(first.serial))).unwrap(),
    );
    stale_append.put(
        history.address("child", "c", b'B', 0).unwrap(),
        Secret::new(child.body.clone()),
    );
    history.delete("root", "r").await.unwrap();
    history.upsert(root.view()).await.unwrap();
    let mut fresh = Plan::new(&store);
    assert!(
        history
            .observe(&mut fresh, "root", "r")
            .await
            .unwrap()
            .life
            .unwrap()
            .serial
            > first.serial
    );
    assert_eq!(stale_append.submit().await.unwrap(), Outcome::Conflict);
    assert!(history.get("child", "c").await.unwrap().is_none());
    // A delete planned before child creation must also lose its comparison.
    let mut stale_delete = Plan::new(&store);
    history
        .cascade(&mut stale_delete, vec![("root".into(), "r".into())])
        .await
        .unwrap();
    history.upsert(child.view()).await.unwrap();
    assert_eq!(stale_delete.submit().await.unwrap(), Outcome::Conflict);
    assert!(history.get("child", "c").await.unwrap().is_some());
}
#[tokio::test]
async fn unknown_retains_candidate_without_replanning_and_binary_metadata_is_strict() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let history = History::authorized(&store, "owner", declarations()).unwrap();
    let root = row("root", "r", None, 0, false);
    backend.lose_reply.store(true, Ordering::SeqCst);
    let Outcome::Pending(id) = history.upsert(root.view()).await.unwrap() else {
        panic!("unknown must retain custody");
    };
    assert_eq!(history.retry(id).await.unwrap(), Outcome::Applied);
    assert_eq!(history.get("root", "r").await.unwrap(), Some(root));
    {
        let state = backend.state.lock().unwrap();
        assert_eq!(state.sent.len(), 2);
        assert_eq!(state.sent[0].fingerprint(), state.sent[1].fingerprint());
    }
    let at = history.address("root", "r", b'M', 0).unwrap();
    {
        let mut state = backend.state.lock().unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(state.rows[&at].expose(&crate::seal::lend())).unwrap();
        value["record"]["unexpected"] = true.into();
        state
            .rows
            .insert(at, Secret::new(serde_json::to_vec(&value).unwrap()));
    }
    assert_eq!(history.get("root", "r").await, Err(Error::Corrupt));
}
#[tokio::test]
async fn independent_append_orders_sequences_and_deletes_chain() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let history = History::authorized(
        &store,
        "owner",
        [Collection {
            kind: "events",
            mode: Mode::Append,
            retention: Retention::Age,
            parent: None,
        }],
    )
    .unwrap();
    for seq in [5, 2, 9, 1] {
        history
            .append(row("events", "event", Some("chain"), seq, false).view())
            .await
            .unwrap();
    }
    assert_eq!(
        history
            .list("events", &PlaneSelector::All)
            .await
            .unwrap()
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>(),
        vec![1, 2, 5, 9]
    );
    assert_eq!(
        history.purge("events", 11).await.unwrap(),
        (Outcome::Applied, 4)
    );
    assert!(history.parents("events").await.unwrap().is_empty());
}
fn audit_row(seq: u64, prev: &str) -> AuditRecord {
    let mut record = AuditRecord {
        seq,
        ts: 2,
        action: "read".into(),
        resource: "resource".into(),
        outcome: "applied".into(),
        principal: "principal".into(),
        prev_hash: prev.into(),
        hash: String::new(),
    };
    let framed = crate::audit::stream_registry::StreamRecord::from_parts(
        String::new(),
        seq,
        prev.into(),
        String::new(),
        crate::audit::auditlog::audit_suffix(
            record.ts,
            &record.action,
            &record.resource,
            &record.outcome,
            &record.principal,
        ),
        crate::audit::Framing::PipeSeparated,
        false,
    );
    record.hash = crate::audit::digest(&framed);
    record
}
#[tokio::test]
async fn audit_reuses_published_recipe_replays_refuses_forks_and_pages_tail() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let audit = Audit::authorized(&store, "lineage");
    let mut expected = Vec::new();
    for seq in [1, 2, 4, 8, 10] {
        let record = audit_row(
            seq,
            expected
                .last()
                .map(|r: &AuditRecord| r.hash.as_str())
                .unwrap_or(""),
        );
        assert_eq!(audit.append(&record).await.unwrap(), Outcome::Applied);
        expected.push(record);
    }
    assert_eq!(audit.append(&expected[0]).await.unwrap(), Outcome::Applied);
    let fork = audit_row(1, "other");
    assert_eq!(audit.append(&fork).await, Err(Error::Fork));
    let mut invalid = expected[0].clone();
    invalid.action.push('x');
    assert_eq!(audit.append(&invalid).await, Err(Error::Corrupt));
    assert_eq!(audit.list().await.unwrap(), expected);
    assert_eq!(audit.list_tail(2).await.unwrap(), expected[3..]);
    assert!(audit.list_tail(0).await.unwrap().is_empty());
    assert!(Audit::authorized(&store, "different")
        .list()
        .await
        .unwrap()
        .is_empty());
}
#[tokio::test]
async fn declarations_require_explicit_valid_upsert_parents() {
    let store = attach(Arc::new(Backend::default())).await;
    let mut bad = declarations();
    bad[0].parent = Some("child");
    assert!(matches!(
        History::authorized(&store, "owner", bad),
        Err(Error::Invalid)
    ));
    let mut bad = declarations();
    bad[1].parent = Some("missing");
    assert!(matches!(
        History::authorized(&store, "owner", bad),
        Err(Error::Unauthorized)
    ));
    let mut bad = declarations();
    bad[0].parent = Some("leaf");
    assert!(matches!(
        History::authorized(&store, "owner", bad),
        Err(Error::Invalid)
    ));
}

#[tokio::test]
async fn durable_declarations_refuse_omitted_relationships_mode_and_retention_rebinding() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let history = History::authorized(&store, "owner", declarations()).unwrap();
    assert!(history.get("root", "r").await.unwrap().is_none());
    assert!(backend.state.lock().unwrap().sent.is_empty());
    let root = row("root", "r", None, 0, false);
    let child = row("child", "c", Some("r"), 0, false);
    history.upsert(root.view()).await.unwrap();
    history.upsert(child.view()).await.unwrap();
    let before = backend.state.lock().unwrap().sent.len();
    let omitted = History::authorized(&store, "owner", [declarations()[0]]).unwrap();
    assert_eq!(omitted.delete("root", "r").await, Err(Error::Unauthorized));
    let mut changed = declarations();
    changed[2].mode = Mode::Upsert;
    assert_eq!(
        History::authorized(&store, "owner", changed)
            .unwrap()
            .get("root", "r")
            .await,
        Err(Error::Unauthorized)
    );
    let mut changed = declarations();
    changed[0].retention = Retention::Age;
    assert_eq!(
        History::authorized(&store, "owner", changed)
            .unwrap()
            .purge("root", 20)
            .await,
        Err(Error::Unauthorized)
    );
    assert_eq!(backend.state.lock().unwrap().sent.len(), before);
    let mut reordered = declarations();
    reordered.reverse();
    assert_eq!(
        History::authorized(&store, "owner", reordered)
            .unwrap()
            .get("child", "c")
            .await
            .unwrap(),
        Some(child)
    );
    // Data without its declaration descriptor is corruption, never a chance to
    // authorize a narrower graph or reinterpret an existing collection.
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .retain(|at, _| at.key.first() != Some(&b'D'));
    assert_eq!(history.get("root", "r").await, Err(Error::Corrupt));
}

#[tokio::test]
async fn fresh_snapshot_migration_uses_exact_live_history_rows_and_owner_authorization() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let history = History::authorized(&store, "owner", declarations()).unwrap();
    for (record, parent_life) in [
        (row("root", "r", None, 0, false), None),
        (row("child", "c", Some("r"), 0, false), Some(1)),
        (row("leaf", "l", Some("c"), 1, true), Some(1)),
    ] {
        let imported = migration_rows("owner", declarations(), record.view(), parent_life).unwrap();
        let result = if record.kind == "leaf" {
            history.append(record.view()).await
        } else {
            history.upsert(record.view()).await
        };
        assert_eq!(result.unwrap(), Outcome::Applied);
        let native = backend.state.lock().unwrap();
        for (address, value) in imported {
            assert_eq!(native.rows.get(&address), Some(&value));
            assert!(migration_authorizes("owner", declarations(), &address));
            assert!(!migration_authorizes("other", declarations(), &address));
            let mut changed = address;
            changed.namespace = [255; 16];
            assert!(!migration_authorizes("owner", declarations(), &changed));
        }
    }
}

#[tokio::test]
async fn logical_append_cancellation_resolves_original_plan_after_shutdown() {
    use futures::FutureExt;
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let declarations = [Collection {
        kind: "events",
        mode: Mode::Append,
        retention: Retention::Age,
        parent: None,
    }];
    let history = History::authorized(&store, "owner", declarations).unwrap();
    let record = row("events", "event", Some("stream"), 1, false);
    backend.hang.store(true, Ordering::SeqCst);
    assert!(history
        .append_with_id([42; 16], record.view())
        .now_or_never()
        .is_none());
    let mut changed = record.clone();
    changed.body.push(9);
    assert_eq!(
        history
            .append_with_id([42; 16], changed.view())
            .await
            .unwrap(),
        Outcome::OpIdConflict
    );
    assert_eq!(store.stop_admission().unwrap().len(), 1);
    backend.hang.store(false, Ordering::SeqCst);
    assert_eq!(
        history
            .append_with_id([42; 16], record.view())
            .await
            .unwrap(),
        Outcome::Applied
    );
    let native = backend.state.lock().unwrap();
    assert_eq!(native.sent.len(), 2);
    assert_eq!(native.sent[0].fingerprint(), native.sent[1].fingerprint());
}

#[tokio::test]
async fn historical_native_sequence_and_timestamp_preserve_full_unsigned_range() {
    let backend = Arc::new(Backend::default());
    let store = attach(backend.clone()).await;
    let declarations = [Collection {
        kind: "events",
        mode: Mode::Append,
        retention: Retention::Age,
        parent: None,
    }];
    let history = History::authorized(&store, "owner", declarations).unwrap();
    let mut original = row("events", "event", Some("stream"), u64::MAX, false);
    original.ts = u64::MAX;
    let imported = migration_rows("owner", declarations, original.view(), None).unwrap();
    backend.state.lock().unwrap().rows.extend(imported);
    assert_eq!(
        history.list("events", &PlaneSelector::All).await.unwrap(),
        vec![original]
    );
}
