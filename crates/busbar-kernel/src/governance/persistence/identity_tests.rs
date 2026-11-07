// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::persistence::facade::{Limits, WriterAuthority};
use busbar_contract::persistence::{
    control, BackendInfo, Call, ClockObservation, DatasetId, Durability, Page, PersistenceBackend,
    Scan,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

type Receipt = ([u8; 32], Secret<Vec<u8>>);

#[derive(Default)]
struct State {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    generation: u64,
    sends: usize,
    reads: usize,
    unknown: bool,
    conflicts: usize,
    receipts: HashMap<[u8; 16], Receipt>,
    fingerprints: Vec<[u8; 32]>,
}
#[derive(Default)]
struct Backend {
    state: Mutex<State>,
    hang: AtomicBool,
}
impl Backend {
    fn now(&self) -> ClockObservation {
        ClockObservation {
            authority: [3; 16],
            unix_seconds: 1234,
        }
    }
}
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: Durability::Ephemeral,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            state.reads += 1;
            let values = request
                .addresses
                .iter()
                .map(|at| {
                    if at.namespace == control::NAMESPACE.0 {
                        let value = if at.key == control::DATASET_KEY {
                            control::Dataset {
                                id: self.info().dataset,
                                writer_epoch: 1,
                            }
                            .encode()
                            .unwrap()
                            .to_vec()
                        } else {
                            control::Writer {
                                retired_through: 0,
                                admitted_through: 1,
                            }
                            .encode()
                            .unwrap()
                            .to_vec()
                        };
                        Some(Secret::new(value))
                    } else {
                        state.rows.get(at).cloned()
                    }
                })
                .collect();
            Ok(ReadResult::Values {
                observed_at: self.now(),
                values,
            })
        })
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            if request.after.is_some() && request.generation.is_none() && !request.allow_change {
                return Err(Failure::Refused);
            }
            let state = self.state.lock().unwrap();
            if request.generation.is_some_and(|g| g != state.generation) {
                return Err(Failure::StaleScan);
            }
            let mut rows = Vec::new();
            let mut bytes = 0usize;
            let mut next = None;
            let seal = crate::seal::lend();
            for (at, value) in state.rows.iter().filter(|(at, _)| {
                at.namespace == request.namespace.0
                    && at.key.starts_with(&request.prefix)
                    && request.after.as_ref().is_none_or(|a| &at.key > a)
            }) {
                let size = at.key.len() + value.expose(&seal).len();
                if rows.len() == request.max_items || bytes + size > request.max_bytes {
                    if rows.is_empty() {
                        return Err(Failure::Overloaded);
                    }
                    next = rows
                        .last()
                        .map(|(at, _): &(Address, Secret<Vec<u8>>)| at.key.clone());
                    break;
                }
                bytes += size;
                rows.push((at.clone(), value.clone()));
            }
            Ok(Page {
                generation: state.generation,
                rows,
                next,
            })
        })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Ok(self.now()) })
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            if self.hang.load(Ordering::Acquire) {
                {
                    let mut state = self.state.lock().unwrap();
                    state.sends += 1;
                    state.fingerprints.push(prepared.fingerprint());
                }
                return futures::future::pending().await;
            }
            let mut state = self.state.lock().unwrap();
            state.sends += 1;
            state.fingerprints.push(prepared.fingerprint());
            if let Some((fingerprint, result)) =
                state.receipts.get(&prepared.candidate().id.operation)
            {
                return Ok(if *fingerprint == prepared.fingerprint() {
                    Decision::Applied(result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            if state.conflicts > 0 {
                state.conflicts -= 1;
                return Ok(Decision::ConditionConflict);
            }
            let candidate = prepared.candidate();
            let seal = crate::seal::lend();
            for predicate in &candidate.predicates {
                let actual = state.rows.get(&predicate.address).map(|v| v.expose(&seal));
                let expected = match &predicate.expected {
                    ExpectedValue::Absent => None,
                    ExpectedValue::Exact(v) => Some(v.expose(&seal)),
                };
                if actual != expected {
                    return Ok(Decision::ConditionConflict);
                }
            }
            for mutation in &candidate.mutations {
                match mutation {
                    Mutation::Put { address, value } => {
                        state.rows.insert(address.clone(), value.clone());
                    }
                    Mutation::Delete(at) => {
                        state.rows.remove(at);
                    }
                    Mutation::DeleteRange { .. } => panic!("identity uses point writes"),
                }
            }
            state.generation += 1;
            state.receipts.insert(
                candidate.id.operation,
                (prepared.fingerprint(), candidate.result.clone()),
            );
            if state.unknown {
                state.unknown = false;
                return Err(Failure::Unknown);
            }
            Ok(Decision::Applied(candidate.result.clone()))
        })
    }
}
async fn setup() -> (Arc<Backend>, CoreStore) {
    let backend = Arc::new(Backend::default());
    let store = CoreStore::attach(
        backend.clone(),
        WriterAuthority {
            writer_epoch: 1,
            writer: [4; 16],
            execution_epoch: 1,
        },
        Limits {
            pending_operations: 16,
            conflict_retries: 2,
            scan_items: 2,
            scan_bytes: 100_000,
        },
    )
    .await
    .unwrap();
    (backend, store)
}
fn key() -> VirtualKey {
    VirtualKey {
        id: "owner".into(),
        name: "attribution".into(),
        generation_hash: "generation".into(),
        enabled: true,
        created_at: 7,
        ..Default::default()
    }
}
fn credential(id: &str, public_id: &str) -> CredentialSecret {
    CredentialSecret {
        meta: CredentialMeta {
            id: id.into(),
            key_id: "owner".into(),
            kind: "signing".into(),
            slot: 0,
            public_id: public_id.into(),
            secret_form: SecretForm::Recoverable,
            created_at: 7,
            updated_at: 7,
            expires_at: None,
            revoked_at: None,
            revoke_reason: None,
            revision: 0,
        },
        secret: "v1:aead:opaque:unchanged:envelope".into(),
    }
}
#[tokio::test]
async fn atomic_mint_revoke_replacement_retains_hydration_tombstone_and_frees_public_handle() {
    let (backend, store) = setup().await;
    let identity = store.identity();
    let first = credential("first", "public-first");
    identity
        .put_key_with_credential(&key(), &first)
        .await
        .unwrap();
    assert_eq!(backend.state.lock().unwrap().sends, 1);
    let hydrated = identity.list_credentials_since(0).await.unwrap();
    assert_eq!(hydrated[0].secret, first.secret);
    let revision = hydrated[0].meta.revision;
    let mut duplicate = credential("duplicate", "public-first");
    duplicate.meta.slot = 1;
    assert!(identity.put_credential(&duplicate).await.is_err());
    duplicate.meta.public_id = "different-public".into();
    duplicate.meta.slot = 2;
    assert!(identity.put_credential(&duplicate).await.is_err());
    identity.revoke_credential("first", "rotate").await.unwrap();
    let second = credential("second", "public-second");
    identity.put_credential(&second).await.unwrap();
    assert!(identity.put_credential(&first).await.is_err());
    let delta = identity.list_credentials_since(revision).await.unwrap();
    assert_eq!(delta.len(), 2);
    assert_eq!(delta[0].meta.id, "first");
    assert!(delta[0].secret.is_empty());
    assert_eq!(delta[0].meta.revoked_at, Some(1234));
    assert_eq!(identity.list_credentials("owner").await.unwrap().len(), 1);
    let mut third = credential("third", "public-first");
    third.meta.slot = 1;
    identity.put_credential(&third).await.unwrap();
    identity.delete_key("owner").await.unwrap();
    let deleted = identity.get_key("owner").await.unwrap().unwrap();
    assert_eq!(deleted.name, "attribution");
    assert_eq!(deleted.deleted_at, Some(1234));
    assert!(!deleted.enabled);
    assert!(identity.list_credentials("owner").await.unwrap().is_empty());
    assert!(identity
        .list_credentials_since(0)
        .await
        .unwrap()
        .iter()
        .all(|c| c.secret.is_empty() && c.meta.revoked_at.is_some()));
    assert!(identity.put_key(&key()).await.is_err());
    identity.delete_key("owner").await.unwrap();
    assert!(identity.delete_key("missing").await.is_err());
    assert!(identity.revoke_credential("missing", "typo").await.is_err());
}
#[tokio::test]
async fn stale_rewrap_and_stale_slot_mint_cannot_cross_revocation_or_competing_mint() {
    let (_, store) = setup().await;
    let identity = store.identity();
    identity
        .put_key_with_credential(&key(), &credential("first", "public"))
        .await
        .unwrap();
    let expected = identity.list_credentials_since(0).await.unwrap().remove(0);
    let mut tx = Tx::start(&store).await.unwrap();
    identity
        .plan(&mut tx, &Change::Rewrap(&expected, "replacement"))
        .await
        .unwrap();
    identity.revoke_credential("first", "revoke").await.unwrap();
    assert!(matches!(tx.commit().await, Err(Error::Conflict)));
    assert!(!identity
        .rewrap_credential(&expected, "replacement")
        .await
        .unwrap());
    let second = credential("second", "second-public");
    let mut tx = Tx::start(&store).await.unwrap();
    identity
        .plan(&mut tx, &Change::PutCredential(&second, None))
        .await
        .unwrap();
    identity
        .put_credential(&credential("third", "third-public"))
        .await
        .unwrap();
    assert!(matches!(tx.commit().await, Err(Error::Conflict)));
    assert_eq!(
        identity.list_credentials("owner").await.unwrap()[0].id,
        "third"
    );
}
#[tokio::test]
async fn unknown_retains_identity_without_replanning_and_conflicts_are_bounded() {
    let (backend, store) = setup().await;
    backend.state.lock().unwrap().unknown = true;
    let error = store
        .identity()
        .put_key(&key())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("retained operation"));
    assert_eq!(backend.state.lock().unwrap().sends, 1);
    assert_eq!(store.stop_admission().unwrap().len(), 1);
    let (backend, store) = setup().await;
    backend.state.lock().unwrap().conflicts = 20;
    assert!(store
        .identity()
        .put_key(&key())
        .await
        .unwrap_err()
        .to_string()
        .contains("retry budget"));
    assert_eq!(backend.state.lock().unwrap().sends, 3);
}
#[tokio::test]
async fn exact_rewrap_cas_and_strict_versioned_records_preserve_scope_semantics() {
    let (backend, store) = setup().await;
    let mut key = key();
    key.allowed_scopes = Some(vec![busbar_contract::records::ScopeRef {
        kind: "agent".into(),
        value: "worker".into(),
    }]);
    store
        .identity()
        .put_key_with_credential(&key, &credential("first", "public"))
        .await
        .unwrap();
    assert_eq!(
        store
            .identity()
            .get_key("owner")
            .await
            .unwrap()
            .unwrap()
            .allowed_scopes,
        key.allowed_scopes
    );
    let expected = store
        .identity()
        .list_credentials_since(0)
        .await
        .unwrap()
        .remove(0);
    assert!(store
        .identity()
        .rewrap_credential(&expected, "new-envelope")
        .await
        .unwrap());
    assert!(!store
        .identity()
        .rewrap_credential(&expected, "stale-envelope")
        .await
        .unwrap());
    let at = row(b'K', "owner").unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&encode(&key).unwrap()).unwrap();
    value["record"]["future_field"] = serde_json::json!([]);
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(at.clone(), Secret::new(serde_json::to_vec(&value).unwrap()));
    assert!(store.identity().get_key("owner").await.is_err());
    value["record"]
        .as_object_mut()
        .unwrap()
        .remove("future_field");
    value["version"] = 2.into();
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(at, Secret::new(serde_json::to_vec(&value).unwrap()));
    assert!(store.identity().get_key("owner").await.is_err());
}
#[test]
fn framing_is_injective_and_not_limited_to_plane_keys() {
    assert_ne!(
        keys::framed(b'K', &[b"a/b", b"c"]).unwrap(),
        keys::framed(b'K', &[b"a", b"b/c"]).unwrap()
    );
    let long = vec![42; 1024];
    let encoded = keys::framed(b'K', &[&long]).unwrap();
    assert_eq!(
        keys::components(&encoded, b'K').unwrap(),
        vec![long.as_slice()]
    );
}

#[tokio::test]
async fn multi_page_lists_and_cascade_exceed_page_limit_without_truncation() {
    let (_, store) = setup().await;
    let identity = store.identity();
    for n in 0..5 {
        let mut owner = key();
        owner.id = format!("owner-{n}");
        identity.put_key(&owner).await.unwrap();
    }
    assert_eq!(identity.list_keys().await.unwrap().len(), 5);
    assert_eq!(identity.list_keys_since(0).await.unwrap().len(), 5);
    identity.put_key(&key()).await.unwrap();
    for n in 0..5 {
        let mut secret = credential(&format!("credential-{n}"), &format!("public-{n}"));
        secret.meta.kind = format!("kind-{n}");
        identity.put_credential(&secret).await.unwrap();
    }
    assert_eq!(identity.list_credentials("owner").await.unwrap().len(), 5);
    let before = identity.list_credentials_since(0).await.unwrap();
    assert_eq!(before.len(), 5);
    let cursor = before.last().unwrap().meta.revision;
    identity.delete_key("owner").await.unwrap();
    assert!(identity.list_credentials("owner").await.unwrap().is_empty());
    let changed = identity.list_credentials_since(cursor).await.unwrap();
    assert_eq!(changed.len(), 5);
    assert!(changed
        .iter()
        .all(|secret| secret.secret.is_empty() && secret.meta.revoked_at.is_some()));
    let tx = Tx::start(&store).await.unwrap();
    identity.add_denylist("subject", "reason").await.unwrap();
    assert!(matches!(tx.key("missing").await, Err(Error::Conflict)));
    assert_eq!(identity.list_denylist().await.unwrap(), ["subject"]);
}

#[tokio::test]
async fn native_identity_runtime_confirms_before_publishing_and_hydrates_without_legacy_reads() {
    use crate::governance::{signing::TokenSigner, GovState, NewKeySpec};
    let (backend, store) = setup().await;
    let core = Arc::new(store);
    let gov = GovState::new_with_core(
        core.clone(),
        None,
        Some(TokenSigner::from_secret_bytes(&[7; 32], "test")),
    )
    .await
    .unwrap();
    let (minted, token) = gov
        .mint_signed_async(NewKeySpec::default(), u64::MAX, 1234)
        .await
        .unwrap();
    assert!(gov.lookup_by_sub(&minted.id).is_some());
    assert!(gov
        .verify_token(token.expose(&crate::seal::lend()), 1234, None)
        .is_some());
    let rotated = gov
        .rotate_key_outcome_async(&minted.id, u64::MAX)
        .await
        .unwrap()
        .unwrap();
    assert!(gov
        .verify_token(token.expose(&crate::seal::lend()), 1234, None)
        .is_none());
    assert!(gov
        .verify_token(rotated.token.expose(&crate::seal::lend()), 1234, None)
        .is_some());
    backend.state.lock().unwrap().unknown = true;
    assert!(gov
        .update_key_outcome_async(&minted.id, Some(false), None)
        .await
        .is_err());
    assert!(
        gov.lookup_by_sub(&minted.id).unwrap().enabled,
        "an unknown update cannot publish its projected delta"
    );
    gov.refresh_async().await.unwrap();
    let (independent, _) = gov
        .mint_signed_async(NewKeySpec::default(), u64::MAX, 1234)
        .await
        .unwrap();
    assert!(
        gov.lookup_by_sub(&independent.id).is_some(),
        "a disjoint confirmed identity remains publishable while another key is unresolved"
    );
    assert!(
        !gov.lookup_by_sub(&minted.id).unwrap().enabled,
        "refresh publishes the canonical state only after original receipt settlement"
    );
}

#[tokio::test]
async fn native_identity_snapshot_preserves_tombstone_and_confidential_destruction() {
    let (_, store) = setup().await;
    store
        .identity()
        .put_key_with_credential(&key(), &credential("first", "public"))
        .await
        .unwrap();
    store
        .identity()
        .add_denylist("owner", "test")
        .await
        .unwrap();
    store.identity().delete_key("owner").await.unwrap();
    let snapshot = store.identity().snapshot().await.unwrap();
    assert_eq!(snapshot.denied, ["owner"]);
    assert_eq!(snapshot.keys.len(), 1);
    assert!(snapshot.keys[0].deleted_at.is_some());
    assert_eq!(snapshot.credentials.len(), 1);
    assert!(snapshot.credentials[0].secret.is_empty());
    assert!(snapshot.credentials[0].meta.revoked_at.is_some());
}

#[tokio::test]
async fn native_self_issue_reuses_binding_and_refresh_atomically_tombstones_previous() {
    use crate::governance::{signing::TokenSigner, GovState};
    let (backend, store) = setup().await;
    let core = Arc::new(store);
    let gov = GovState::new_with_core(
        core.clone(),
        None,
        Some(TokenSigner::from_secret_bytes(&[7; 32], "test")),
    )
    .await
    .unwrap();
    let (first, first_token) = gov
        .issue_self("sam", "corp", None, u64::MAX, 1234)
        .await
        .unwrap();
    let (again, _) = gov
        .issue_self("sam", "corp", None, u64::MAX, 1235)
        .await
        .unwrap();
    assert_eq!(first.id, again.id);
    let sends = backend.state.lock().unwrap().sends;
    let (next, next_token) = gov
        .refresh_self("sam", "corp", None, u64::MAX, 1236)
        .await
        .unwrap();
    assert_ne!(first.id, next.id);
    assert_eq!(
        backend.state.lock().unwrap().sends,
        sends + 1,
        "self refresh must use one atomic replacement transaction"
    );
    assert!(core
        .identity()
        .get_key(&first.id)
        .await
        .unwrap()
        .unwrap()
        .deleted_at
        .is_some());
    assert!(gov.verify_token(&first_token, 1236, None).is_none());
    assert!(gov.verify_token(&next_token, 1236, None).is_some());
    assert_eq!(
        core.identity()
            .list_keys()
            .await
            .unwrap()
            .iter()
            .filter(|key| key.deleted_at.is_none())
            .count(),
        1
    );
}

#[tokio::test]
async fn native_identity_publication_keeps_tombstone_revision_across_full_reload() {
    let (_, store) = setup().await;
    let core = Arc::new(store);
    let initial = core.identity().compare_key(None, &key()).await.unwrap();
    let before = initial.keys[0].clone();
    let gov = crate::governance::GovState::new_with_core(core.clone(), None, None)
        .await
        .unwrap();
    let mut updated = before.clone();
    updated.name = "older confirmed change".into();
    let older = core
        .identity()
        .compare_key(Some(&before), &updated)
        .await
        .unwrap();
    let tombstone = core.identity().delete_key(&before.id).await.unwrap();
    gov.publish_identity(tombstone);
    gov.refresh_async().await.unwrap();
    gov.publish_identity(older);
    gov.publish_identity(initial);
    assert!(
        gov.lookup_by_sub(&before.id).is_none(),
        "neither delayed delta can resurrect the tombstone after a full reload"
    );
}

#[tokio::test]
async fn native_identity_publication_cannot_restore_superseded_slot_owner() {
    let (_, store) = setup().await;
    let core = Arc::new(store);
    let initial = core
        .identity()
        .put_key_with_credential(&key(), &credential("old", "public"))
        .await
        .unwrap();
    let gov = crate::governance::GovState::new_with_core(core.clone(), None, None)
        .await
        .unwrap();
    let revoked = core
        .identity()
        .revoke_credential("old", "replace")
        .await
        .unwrap();
    let replacement = core
        .identity()
        .put_credential(&credential("new", "public"))
        .await
        .unwrap();
    gov.publish_identity(replacement);
    gov.publish_identity(initial);
    gov.publish_identity(revoked);
    assert_eq!(
        gov.lookup_credential("signing", "public")
            .unwrap()
            .1
            .meta
            .id,
        "new"
    );
}

#[tokio::test]
async fn native_credential_read_refuses_parent_expiry_at_exact_boundary_without_io() {
    let (backend, store) = setup().await;
    let mut parent = key();
    parent.expires_at = Some(2000);
    let keys = crate::governance::at_rest::AtRestKeys::new(&[7; 32], None);
    let mut row = credential("first", "public");
    row.secret = keys.seal(&row.meta, b"sealed-test-secret").unwrap();
    store
        .identity()
        .put_key_with_credential(&parent, &row)
        .await
        .unwrap();
    let gov = crate::governance::GovState::new_with_core(Arc::new(store), None, None)
        .await
        .unwrap();
    gov.set_at_rest_keys(Some(keys));
    let reads = backend.state.lock().unwrap().reads;
    let (secret, live) = gov.credential_secret("signing", "public", 1999);
    assert_eq!(secret.expose(&crate::seal::lend()), "sealed-test-secret");
    assert!(
        live,
        "the sealed credential is live before its parent key expires"
    );
    assert!(
        !gov.credential_secret("signing", "public", 2000).1,
        "parent expiry is inclusive"
    );
    assert!(!gov.credential_secret("signing", "public", 2001).1);
    assert_eq!(
        backend.state.lock().unwrap().reads,
        reads,
        "credential liveness remains an in-memory decision"
    );
}

#[tokio::test]
async fn rewrap_settlement_replays_original_receipt_without_new_envelope_or_revision() {
    let (backend, store) = setup().await;
    store
        .identity()
        .put_key_with_credential(&key(), &credential("first", "public"))
        .await
        .unwrap();
    let expected = store
        .identity()
        .list_credentials_since(0)
        .await
        .unwrap()
        .remove(0);
    backend.state.lock().unwrap().unknown = true;
    assert!(store
        .identity()
        .rewrap_committed(&expected, "exact-new-envelope")
        .await
        .is_err());
    let (generation, fingerprint) = {
        let state = backend.state.lock().unwrap();
        (state.generation, *state.fingerprints.last().unwrap())
    };
    assert!(store.identity().snapshot().await.is_err());
    store.stop_admission().unwrap();
    store.identity().settle_pending().await.unwrap();
    let snapshot = store.identity().snapshot().await.unwrap();
    assert_eq!(snapshot.credentials[0].secret, "exact-new-envelope");
    let state = backend.state.lock().unwrap();
    assert_eq!(
        state.generation, generation,
        "receipt replay must not rewrite or bump revision"
    );
    assert_eq!(state.fingerprints.last(), Some(&fingerprint));
    assert_eq!(store.pending_operations().unwrap(), 0);
}

#[tokio::test]
async fn identity_settlement_skips_active_and_foreign_attempts_and_keeps_cancelled_custody() {
    use futures::FutureExt;
    let (backend, store) = setup().await;
    backend.hang.store(true, Ordering::Release);
    let key = key();
    let identity = store.identity();
    let mut operation = Box::pin(identity.put_key(&key));
    assert!(operation.as_mut().now_or_never().is_none());
    assert!(
        identity.settle_pending().await.is_err(),
        "active caller retains its decision"
    );
    assert_eq!(backend.state.lock().unwrap().sends, 1);
    drop(operation);
    backend.hang.store(false, Ordering::Release);
    store.stop_admission().unwrap();
    identity.settle_pending().await.unwrap();
    {
        let state = backend.state.lock().unwrap();
        assert_eq!(state.fingerprints.len(), 2);
        assert_eq!(state.fingerprints[0], state.fingerprints[1]);
    }
    assert_eq!(identity.get_key(&key.id).await.unwrap().unwrap().id, key.id);

    let (backend, store) = setup().await;
    backend.state.lock().unwrap().unknown = true;
    let foreign = PreparedCandidate::new(Candidate {
        id: store.next_id().unwrap(),
        codec: CANDIDATE_VERSION,
        time: None,
        predicates: vec![],
        mutations: vec![Mutation::Put {
            address: row(b'X', "foreign-owner").unwrap(),
            value: Secret::new(vec![1]),
        }],
        result: Secret::new(vec![]),
    })
    .unwrap();
    assert!(matches!(
        store.submit(foreign).await.unwrap().result,
        SubmitResult::Uncertain
    ));
    let sends = backend.state.lock().unwrap().sends;
    store.identity().settle_pending().await.unwrap();
    assert_eq!(
        backend.state.lock().unwrap().sends,
        sends,
        "sharing identity namespace never makes another owner's candidate settleable"
    );
    assert_eq!(store.pending_operations().unwrap(), 1);
    assert!(
        store.identity().snapshot().await.is_err(),
        "foreign uncertainty still blocks snapshot publication"
    );
}
