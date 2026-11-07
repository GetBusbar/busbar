// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, Decision, Durability, Page, Scan,
};
use busbar_contract::plugin::TestKernelSeal;
use std::{collections::BTreeMap, sync::Mutex};

#[derive(Default)]
struct Backend {
    rows: Mutex<BTreeMap<Address, Secret<Vec<u8>>>>,
    // Replace the live manifest just after its read, proving generation pinning.
    replace: Mutex<Option<(Address, Secret<Vec<u8>>)>>,
}
impl Backend {
    fn apply(&self, candidate: &PreparedCandidate) {
        for mutation in &candidate.candidate().mutations {
            if let Mutation::Put { address, value } = mutation {
                self.rows
                    .lock()
                    .unwrap()
                    .insert(address.clone(), value.clone());
            }
        }
    }
}
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: object().dataset,
            atomic_domain: [1; 16],
            clock_authority: [2; 16],
            physical_version: 1,
            durability: Durability::Ephemeral,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        let values = request
            .addresses
            .iter()
            .map(|address| self.rows.lock().unwrap().get(address).cloned())
            .collect();
        if request
            .addresses
            .first()
            .is_some_and(|address| address.key[0] == b'm')
        {
            if let Some((address, value)) = self.replace.lock().unwrap().take() {
                self.rows.lock().unwrap().insert(address, value);
            }
        }
        Box::pin(async move {
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [2; 16],
                    unix_seconds: 1,
                },
                values,
            })
        })
    }
    fn scan(&self, _: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
    fn commit(&self, _: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async { Err(Failure::Refused) })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { Err(Failure::Unavailable) })
    }
}
fn object() -> ObjectId {
    ObjectId {
        dataset: DatasetId([1; 16]),
        namespace: NamespaceId([2; 16]),
        owner: [3; 16],
        object: [4; 16],
    }
}
fn attempt() -> AttemptId {
    AttemptId {
        dataset: object().dataset,
        writer_epoch: 1,
        writer: [5; 16],
        execution_epoch: 1,
        operation: [6; 16],
    }
}
fn candidate() -> Candidate {
    Candidate {
        id: attempt(),
        codec: CANDIDATE_VERSION,
        predicates: vec![],
        mutations: vec![],
        time: None,
        result: Secret::default(),
    }
}
fn prepare(bytes: Vec<u8>, generation: u8) -> PreparedObject {
    PreparedObject::prepare_non_secret(
        object(),
        [generation; 16],
        &Secret::new(bytes),
        usize::MAX,
        &TestKernelSeal,
    )
    .unwrap()
}
fn upload(backend: &Backend, prepared: &PreparedObject) {
    if prepared.manifest.chunk_count > 0 {
        backend.apply(
            &prepared
                .chunk_candidate(
                    attempt(),
                    0..prepared.manifest.chunk_count,
                    usize::MAX,
                    &TestKernelSeal,
                )
                .unwrap(),
        );
    }
}
async fn publish(backend: &Backend, prepared: &PreparedObject) {
    let verified = prepared
        .verify(backend, 7, usize::MAX, &TestKernelSeal)
        .await
        .unwrap();
    let mut candidate = candidate();
    verified
        .append_publication(&mut candidate, ExpectedValue::Absent, usize::MAX)
        .unwrap();
    backend.apply(&PreparedCandidate::new(candidate).unwrap());
}
#[tokio::test]
async fn unpublished_chunks_are_invisible_and_large_object_roundtrips() {
    let backend = Backend::default();
    let bytes: Vec<_> = (0..CHUNK_BYTES * 101 + 713)
        .map(|i| (i % 251) as u8)
        .collect();
    let prepared = prepare(bytes.clone(), 7);
    let batch = prepared
        .chunk_candidate(attempt(), 0..102, 9_000_000, &TestKernelSeal)
        .unwrap();
    assert_eq!(batch.candidate().predicates.len(), 102);
    assert!(batch.candidate().result.expose(&TestKernelSeal).is_empty());
    backend.apply(&batch);
    assert!(
        read_non_secret(object(), &backend, 13, 9_000_000, &TestKernelSeal)
            .await
            .unwrap()
            .is_none()
    );
    publish(&backend, &prepared).await;
    let verified = read_non_secret(object(), &backend, 13, 9_000_000, &TestKernelSeal)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(verified.bytes().expose(&TestKernelSeal), &bytes);
    assert!(!format!("{verified:?}").contains("0, 1, 2, 3"));
}
#[tokio::test]
async fn referenced_missing_truncated_and_wrong_digest_refuse() {
    for replacement in [None, Some(vec![1; 512]), Some(vec![9; 1000])] {
        let backend = Backend::default();
        let prepared = prepare(vec![1; 1000], 7);
        upload(&backend, &prepared);
        publish(&backend, &prepared).await;
        let address = object().address(Some(([7; 16], 0))).unwrap();
        match replacement {
            Some(bytes) => {
                backend
                    .rows
                    .lock()
                    .unwrap()
                    .insert(address, Secret::new(bytes));
            }
            None => {
                backend.rows.lock().unwrap().remove(&address);
            }
        }
        assert!(matches!(
            read_non_secret(object(), &backend, 1, 1_000_000, &TestKernelSeal).await,
            Err(ObjectError::Corrupt)
        ));
        assert!(matches!(
            prepared
                .verify(&backend, 1, 1_000_000, &TestKernelSeal)
                .await,
            Err(ObjectError::Corrupt)
        ));
    }
}
#[tokio::test]
async fn manifest_generation_is_pinned_through_batched_reads() {
    let backend = Backend::default();
    let old = prepare(vec![1; CHUNK_BYTES * 3 + 9], 7);
    let new = prepare(vec![2; CHUNK_BYTES * 3 + 9], 8);
    upload(&backend, &old);
    upload(&backend, &new);
    publish(&backend, &old).await;
    *backend.replace.lock().unwrap() = Some((
        object().address(None).unwrap(),
        Secret::new(new.manifest.encode().to_vec()),
    ));
    let read = read_non_secret(object(), &backend, 1, 1_000_000, &TestKernelSeal)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        read.bytes().expose(&TestKernelSeal),
        old.bytes.expose(&TestKernelSeal)
    );
    let read = read_non_secret(object(), &backend, 1, 1_000_000, &TestKernelSeal)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        read.bytes().expose(&TestKernelSeal),
        new.bytes.expose(&TestKernelSeal)
    );
}
#[tokio::test]
async fn empty_and_invalid_manifests_and_budgets() {
    let backend = Backend::default();
    let empty = prepare(vec![], 7);
    publish(&backend, &empty).await;
    assert!(
        read_non_secret(object(), &backend, 1, 1000, &TestKernelSeal)
            .await
            .unwrap()
            .unwrap()
            .bytes()
            .expose(&TestKernelSeal)
            .is_empty()
    );
    let mut wrong_count = empty.manifest.encode().to_vec();
    wrong_count[32] = 1;
    let mut zero_generation = empty.manifest.encode().to_vec();
    zero_generation[8..24].fill(0);
    for bytes in [
        vec![],
        vec![0; 72],
        empty.manifest.encode()[..71].to_vec(),
        [empty.manifest.encode().as_slice(), &[0]].concat(),
        wrong_count,
        zero_generation,
    ] {
        backend
            .rows
            .lock()
            .unwrap()
            .insert(object().address(None).unwrap(), Secret::new(bytes));
        assert!(matches!(
            read_non_secret(object(), &backend, 1, 1000, &TestKernelSeal).await,
            Err(ObjectError::Corrupt)
        ));
    }
    assert!(matches!(
        PreparedObject::prepare_non_secret(
            object(),
            [7; 16],
            &Secret::new(vec![1; 513]),
            512,
            &TestKernelSeal
        ),
        Err(ObjectError::Budget)
    ));
    let prepared = prepare(vec![1; 513], 7);
    assert!(matches!(
        prepared.chunk_candidate(attempt(), 0..1, 512, &TestKernelSeal),
        Err(ObjectError::Budget)
    ));
    assert!(matches!(
        prepared.verify(&backend, 1, 512, &TestKernelSeal).await,
        Err(ObjectError::Budget)
    ));
    let mut candidate = candidate();
    let verified = empty
        .verify(&backend, 1, 1000, &TestKernelSeal)
        .await
        .unwrap();
    assert!(matches!(
        verified.append_publication(&mut candidate, ExpectedValue::Absent, 0),
        Err(ObjectError::Budget)
    ));
    assert!(candidate.predicates.is_empty() && candidate.mutations.is_empty());
}
