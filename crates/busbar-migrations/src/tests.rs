// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use async_trait::async_trait;
use busbar_contract::{persistence::*, Secret};
use busbar_kernel::persistence::facade::WriterAuthority;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Native {
    rows: BTreeMap<Address, Secret<Vec<u8>>>,
    receipts: Vec<(AttemptId, [u8; 32])>,
    sends: Vec<[u8; 32]>,
    candidates: Vec<PreparedCandidate>,
    lose_reply: bool,
    lose_writer_reply: Option<Id>,
    uncertain_without_effect: Option<Id>,
    fail_read_after_commit: bool,
    failed_reads: usize,
    reject: bool,
}
#[derive(Default)]
struct Backend(Mutex<Native>);
impl PersistenceBackend for Backend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            dataset: DatasetId([2; 16]),
            atomic_domain: [3; 16],
            clock_authority: [4; 16],
            physical_version: 1,
            durability: Durability::Local,
        }
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        Box::pin(async move {
            let mut inner = self.0.lock().unwrap();
            if inner.failed_reads != 0 {
                inner.failed_reads -= 1;
                return Err(Failure::Unknown);
            }
            Ok(ReadResult::Values {
                observed_at: ClockObservation {
                    authority: [4; 16],
                    unix_seconds: 1,
                },
                values: request
                    .addresses
                    .iter()
                    .map(|a| inner.rows.get(a).cloned())
                    .collect(),
            })
        })
    }
    fn scan(&self, _: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async { panic!("no unbounded target scans") })
    }
    fn clock(&self, _: DatasetId) -> Call<'_, ClockObservation> {
        Box::pin(async { panic!("no client clock") })
    }
    fn commit(&self, prepared: PreparedCandidate) -> Call<'_, Decision> {
        Box::pin(async move {
            let mut inner = self.0.lock().unwrap();
            let candidate = prepared.candidate();
            let digest = prepared.fingerprint();
            inner.sends.push(digest);
            inner.candidates.push(prepared.clone());
            if let Some((_, fingerprint)) =
                inner.receipts.iter().find(|(id, _)| *id == candidate.id)
            {
                return Ok(if *fingerprint == digest {
                    Decision::Applied(candidate.result.clone())
                } else {
                    Decision::OpIdConflict
                });
            }
            let root_address = Address {
                namespace: control::NAMESPACE.0,
                key: control::DATASET_KEY.to_vec(),
            };
            if let Some(root) = inner.rows.get(&root_address) {
                let root = control::Dataset::decode(root.expose(&crate::seal::lend())).unwrap();
                if root.writer_epoch != candidate.id.writer_epoch {
                    return Ok(Decision::ExpiredUnknown);
                }
                let writer = inner
                    .rows
                    .get(
                        &busbar_kernel::persistence::import_target::target::writer_address(
                            candidate.id.writer,
                        ),
                    )
                    .and_then(|value| control::Writer::decode(value.expose(&crate::seal::lend())));
                if !writer.is_some_and(|writer| writer.admits(candidate.id.execution_epoch)) {
                    return Ok(Decision::ExpiredUnknown);
                }
            }
            if inner.reject {
                return Ok(Decision::ConditionConflict);
            }
            for predicate in &candidate.predicates {
                let actual = inner.rows.get(&predicate.address);
                if !match &predicate.expected {
                    ExpectedValue::Absent => actual.is_none(),
                    ExpectedValue::Exact(expected) => actual == Some(expected),
                } {
                    return Ok(Decision::ConditionConflict);
                }
            }
            if inner.uncertain_without_effect == Some(candidate.id.writer) {
                inner.uncertain_without_effect = None;
                return Err(Failure::Unknown);
            }
            let mut changed = BTreeSet::new();
            for mutation in &candidate.mutations {
                match mutation {
                    Mutation::Put { address, value } => {
                        inner.rows.insert(address.clone(), value.clone());
                        changed.insert(address.namespace);
                    }
                    Mutation::Delete(address) => {
                        inner.rows.remove(address);
                        changed.insert(address.namespace);
                    }
                    _ => panic!("unsupported test mutation"),
                }
            }
            for namespace in changed {
                let address = Address {
                    namespace: control::GENERATION_NAMESPACE.0,
                    key: namespace.to_vec(),
                };
                let previous = inner.rows.get(&address).map_or(0, |value| {
                    u64::from_le_bytes(
                        value
                            .expose(&crate::seal::lend())
                            .as_slice()
                            .try_into()
                            .unwrap(),
                    )
                });
                inner
                    .rows
                    .insert(address, Secret::new((previous + 1).to_le_bytes().to_vec()));
            }
            inner.receipts.push((candidate.id, digest));
            if std::mem::take(&mut inner.fail_read_after_commit) {
                inner.failed_reads += 1;
            }
            let lose_writer = inner.lose_writer_reply == Some(candidate.id.writer);
            if lose_writer {
                inner.lose_writer_reply = None;
            }
            if std::mem::take(&mut inner.lose_reply) || lose_writer {
                return Err(Failure::Unknown);
            }
            Ok(Decision::Applied(candidate.result.clone()))
        })
    }
}

struct Custody(Mutex<Option<(Id, Secret<Vec<u8>>)>>, Arc<Backend>);
#[async_trait]
impl IntentStore for Custody {
    async fn reconcile(&self, _: Id) -> Result<ReconciliationProgress, Error> {
        Err(Error::MissingCapability)
    }
    async fn pending(&self, _: Id) -> Result<bool, Error> {
        Ok(self.0.lock().unwrap().is_some())
    }
    async fn persist(
        &self,
        migration: Id,
        operation: Id,
        snapshot: &Secret<Vec<u8>>,
    ) -> Result<(), Error> {
        let mut inner = self.0.lock().unwrap();
        if let Some((id, bytes)) = &*inner {
            if *id != operation || bytes != snapshot {
                return Err(Error::Conflict);
            }
        } else {
            *inner = Some((operation, snapshot.clone()));
        }
        self.1 .0.lock().unwrap().rows.insert(
            super::intent::guard_address(migration),
            Secret::new(super::intent::open_guard(migration, operation)),
        );
        Ok(())
    }
    async fn clear(&self, migration: Id, operation: Id, _: &IntentResolution) -> Result<(), Error> {
        let mut inner = self.0.lock().unwrap();
        if inner.as_ref().is_some_and(|(id, _)| *id != operation) {
            return Err(Error::Conflict);
        }
        *inner = None;
        self.1 .0.lock().unwrap().rows.insert(
            super::intent::guard_address(migration),
            Secret::new(Vec::new()),
        );
        Ok(())
    }
}

struct Reader(Identity);
#[async_trait]
impl SourceReader for Reader {
    async fn identify(&self) -> Result<Identity, Error> {
        Ok(self.0.clone())
    }
    async fn page(
        &self,
        snapshot: &SnapshotEvidence,
        family: &Family,
        after: u64,
        _: Bounds,
    ) -> Result<SourcePage, Error> {
        Ok(SourcePage {
            snapshot: snapshot.snapshot,
            family: family.id,
            after,
            next: after + 1,
            complete: after == 1,
            records: vec![Record {
                key: vec![after as u8],
                value: Secret::new(vec![42]),
                preserve_exact: true,
            }],
        })
    }
}
struct CopyTransform(Edge);
impl Transform for CopyTransform {
    fn edge(&self) -> &Edge {
        &self.0
    }
    fn authorize(&self, family: &Family, address: &Address) -> bool {
        address.namespace == family.target_namespace
    }
    fn transform(
        &self,
        family: &Family,
        records: &[Record],
        _: Bounds,
    ) -> Result<Vec<TargetRow>, Error> {
        Ok(records
            .iter()
            .enumerate()
            .map(|(index, r)| TargetRow {
                address: Address {
                    namespace: family.target_namespace,
                    key: r.key.clone(),
                },
                value: r.value.clone(),
                preserved_source: Some(index as u32),
            })
            .collect())
    }
}
struct Verify;
#[async_trait]
impl Verifier for Verify {
    async fn target_offline(&self, _: &Identity, _: WriterAuthority) -> Result<(), Error> {
        Ok(())
    }
    async fn fence(&self, source: &Identity) -> Result<FenceEvidence, Error> {
        Ok(FenceEvidence {
            native_upgrade: None,
            source: source.dataset,
            native_anchor_digest: [42; 32],
            archive_digest: source.artifact_digest,
            enforcement_digest: [1; 32],
            sender_quiescence_attestation: [2; 32],
            backend_quiescence_attestation: [3; 32],
        })
    }
    async fn snapshot(
        &self,
        source: &Identity,
        _: &FenceEvidence,
    ) -> Result<SnapshotEvidence, Error> {
        Ok(SnapshotEvidence {
            source: source.dataset,
            snapshot: [6; 16],
            content_digest: [7; 32],
            coverage_digest: [8; 32],
        })
    }
    async fn target_step(&self, manifest: &Manifest, _: Bounds) -> Result<Verification, Error> {
        Ok(Verification {
            partial: None,
            cursor: 1,
            complete: true,
            debt_write_blocks_digest: [9; 32],
            families: manifest
                .checkpoints
                .iter()
                .map(|cp| VerifiedFamily {
                    family: cp.family,
                    source_count: cp.source_count,
                    target_count: cp.target_count,
                    source_digest: cp.source_digest,
                    target_digest: cp.target_digest,
                    decoded_invariants_digest: [10; 32],
                    source_coverage_digest: [11; 32],
                })
                .collect(),
        })
    }
    async fn retirement_permitted(&self, _: &Manifest) -> Result<Digest32, Error> {
        Ok([12; 32])
    }
}
fn identity(dataset: u8, logical: u32) -> Identity {
    Identity {
        dataset: [dataset; 16],
        format: Format {
            owner: if dataset == 2 {
                CORE_FORMAT_OWNER
            } else {
                [1; 16]
            },
            logical,
            physical: 1,
            codec: 1,
        },
        artifact_digest: [2; 32],
        schema_digest: [3; 32],
        product_release: [1, 5, 5],
    }
}
fn fixture() -> (Arc<Registry>, Manifest) {
    let source = identity(1, 0);
    let target = identity(2, 1);
    let edge = Edge {
        id: [4; 16],
        source: source.format,
        target: target.format,
        code_digest: [5; 32],
        preconditions_digest: [6; 32],
        verification_rule_digest: [7; 32],
        bounds: Bounds {
            items: 2,
            bytes: 1024,
        },
        families: vec![Family {
            id: [8; 16],
            source_schema: 1,
            target_schema: 1,
            target_namespace: [9; 16],
        }],
    };
    let registry = Arc::new(Registry::new(vec![edge]).unwrap());
    let plan = registry.plan([10; 16], source, target, &[[4; 16]]).unwrap();
    (registry, plan)
}
fn authority() -> WriterAuthority {
    WriterAuthority {
        writer: [11; 16],
        writer_epoch: 1,
        execution_epoch: 1,
    }
}
fn services(plan: &Manifest, custody: Arc<Custody>) -> Services {
    Services {
        source: Arc::new(Reader(plan.source.clone())),
        transform: Arc::new(CopyTransform(plan.edges[0].clone())),
        verifier: Arc::new(Verify),
        activation: None,
        intent: custody,
    }
}
async fn offline_backend() -> Arc<Backend> {
    let backend = Arc::new(Backend::default());
    let mut bootstrap = TargetBootstrap::new(backend.clone(), authority(), [90; 16]).unwrap();
    assert_eq!(bootstrap.advance().await, Ok(BootstrapProgress::Advanced));
    assert_eq!(bootstrap.advance().await, Ok(BootstrapProgress::Ready));
    backend.0.lock().unwrap().sends.clear();
    backend
}
async fn start() -> (
    Coordinator,
    Arc<Backend>,
    Arc<Custody>,
    Manifest,
    Arc<Registry>,
) {
    let (registry, plan) = fixture();
    let backend = offline_backend().await;
    let custody = Arc::new(Custody(Mutex::new(None), backend.clone()));
    let coordinator = Coordinator::start(
        plan.clone(),
        registry.clone(),
        backend.clone(),
        authority(),
        services(&plan, custody.clone()),
    )
    .await
    .unwrap();
    (coordinator, backend, custody, plan, registry)
}
async fn copying(coordinator: &mut Coordinator) {
    for _ in 0..5 {
        assert_eq!(coordinator.advance().await.unwrap(), Progress::Advanced);
    }
    assert_eq!(coordinator.manifest().state, State::Copying);
}

#[test]
fn manifest_refuses_version_unknown_fields_and_changed_edge() {
    let (registry, plan) = fixture();
    let mut changed = plan.clone();
    changed.edges[0].code_digest = [99; 32];
    assert_eq!(changed.validate(&registry), Err(Error::EdgeMismatch));
    changed = plan.clone();
    changed.version = 99;
    assert_eq!(changed.validate(&registry), Err(Error::UnsupportedVersion));
    changed = plan.clone();
    changed.state = State::Activated;
    assert_eq!(changed.validate(&registry), Err(Error::InvalidState));
    let mut json = serde_json::to_value(&plan).unwrap();
    json["sql"] = serde_json::json!("DROP TABLE source");
    assert_eq!(
        Manifest::decode(&serde_json::to_vec(&json).unwrap(), &registry),
        Err(Error::InvalidManifest)
    );
    assert_eq!(
        Manifest::decode(&plan.encode(&registry).unwrap(), &registry).unwrap(),
        plan
    );
}

#[tokio::test]
async fn admission_binds_actual_source_and_transform() {
    let (registry, plan) = fixture();
    let backend = offline_backend().await;
    let custody = Arc::new(Custody(Mutex::new(None), backend.clone()));
    let mut svc = services(&plan, custody.clone());
    let mut other = plan.source.clone();
    other.schema_digest = [88; 32];
    svc.source = Arc::new(Reader(other));
    assert!(matches!(
        Coordinator::start(
            plan.clone(),
            registry.clone(),
            backend.clone(),
            authority(),
            svc
        )
        .await,
        Err(Error::IdentityMismatch)
    ));
    let mut svc = services(&plan, custody);
    let mut edge = plan.edges[0].clone();
    edge.code_digest = [88; 32];
    svc.transform = Arc::new(CopyTransform(edge));
    assert!(matches!(
        Coordinator::start(plan, registry, backend.clone(), authority(), svc).await,
        Err(Error::EdgeMismatch)
    ));
    assert!(backend.0.lock().unwrap().sends.is_empty());
}

#[tokio::test]
async fn unknown_copy_retains_exact_candidate_and_atomic_checkpoint() {
    let (mut coordinator, backend, custody, _, registry) = start().await;
    copying(&mut coordinator).await;
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(coordinator.advance().await.unwrap(), Progress::Pending);
    let operation = coordinator.pending_operation().unwrap();
    assert_eq!(coordinator.manifest().checkpoints[0].source_count, 0);
    assert!(custody
        .pending(coordinator.manifest().migration)
        .await
        .unwrap());
    let durable = status(
        backend.as_ref(),
        coordinator.manifest().migration,
        &registry,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(durable.checkpoints[0].source_count, 1);
    assert!(backend.0.lock().unwrap().rows.contains_key(&Address {
        namespace: [9; 16],
        key: vec![0]
    }));
    assert_eq!(coordinator.advance().await.unwrap(), Progress::Advanced);
    assert_eq!(coordinator.manifest().checkpoints[0].source_count, 1);
    let native = backend.0.lock().unwrap();
    let sends = &native.sends;
    assert_eq!(sends[sends.len() - 1], sends[sends.len() - 2]);
    assert_eq!(
        native
            .receipts
            .iter()
            .filter(|(id, _)| *id == operation)
            .count(),
        1
    );
}

#[tokio::test]
async fn conflict_commits_neither_page_nor_checkpoint() {
    let (mut coordinator, backend, _, _, registry) = start().await;
    copying(&mut coordinator).await;
    backend.0.lock().unwrap().reject = true;
    assert_eq!(coordinator.advance().await, Err(Error::Conflict));
    assert_eq!(
        status(
            backend.as_ref(),
            coordinator.manifest().migration,
            &registry
        )
        .await
        .unwrap()
        .unwrap()
        .checkpoints[0]
            .source_count,
        0
    );
    assert!(!backend.0.lock().unwrap().rows.contains_key(&Address {
        namespace: [9; 16],
        key: vec![0]
    }));
}

#[tokio::test]
async fn crash_with_pending_intent_refuses_new_operation() {
    let (mut coordinator, backend, custody, plan, registry) = start().await;
    copying(&mut coordinator).await;
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(coordinator.advance().await.unwrap(), Progress::Pending);
    drop(coordinator);
    let before = backend.0.lock().unwrap().sends.len();
    assert!(matches!(
        Coordinator::resume(
            &plan,
            registry,
            backend.clone(),
            authority(),
            services(&plan, custody)
        )
        .await,
        Err(Error::ReconciliationRequired)
    ));
    assert_eq!(backend.0.lock().unwrap().sends.len(), before);
}

#[tokio::test]
async fn resumes_every_confirmed_stage_and_refuses_missing_activation() {
    let (mut coordinator, backend, custody, plan, registry) = start().await;
    for _ in 0..8 {
        coordinator.advance().await.unwrap();
        let state = coordinator.manifest().state;
        drop(coordinator);
        coordinator = Coordinator::resume(
            &plan,
            registry.clone(),
            backend.clone(),
            authority(),
            services(&plan, custody.clone()),
        )
        .await
        .unwrap();
        assert_eq!(coordinator.manifest().state, state);
    }
    assert_eq!(coordinator.manifest().state, State::TargetVerified);
    assert_eq!(coordinator.advance().await, Err(Error::MissingCapability));
    assert!(coordinator.pending_operation().is_none());
    let mut wrong = plan.clone();
    wrong.source.artifact_digest = [88; 32];
    assert!(matches!(
        Coordinator::resume(
            &wrong,
            registry,
            backend,
            authority(),
            services(&plan, custody)
        )
        .await,
        Err(Error::IdentityMismatch)
    ));
}

struct RekeyTransform {
    edge: Edge,
    corrupt: bool,
}
impl Transform for RekeyTransform {
    fn edge(&self) -> &Edge {
        &self.edge
    }
    fn authorize(&self, family: &Family, address: &Address) -> bool {
        address.namespace == family.target_namespace
    }
    fn transform(
        &self,
        family: &Family,
        records: &[Record],
        _: Bounds,
    ) -> Result<Vec<TargetRow>, Error> {
        Ok(records
            .iter()
            .enumerate()
            .map(|(index, record)| TargetRow {
                address: Address {
                    namespace: family.target_namespace,
                    key: [b"canonical/".as_slice(), &record.key].concat(),
                },
                value: if self.corrupt {
                    Secret::new(vec![43])
                } else {
                    record.value.clone()
                },
                preserved_source: Some(index as u32),
            })
            .collect())
    }
}

#[tokio::test]
async fn original_ciphertext_can_be_rekeyed_but_not_rewritten() {
    for corrupt in [false, true] {
        let (registry, plan) = fixture();
        let backend = offline_backend().await;
        let custody = Arc::new(Custody(Mutex::new(None), backend.clone()));
        let mut svc = services(&plan, custody);
        svc.transform = Arc::new(RekeyTransform {
            edge: plan.edges[0].clone(),
            corrupt,
        });
        let mut coordinator = Coordinator::start(plan, registry, backend.clone(), authority(), svc)
            .await
            .unwrap();
        copying(&mut coordinator).await;
        let before = backend.0.lock().unwrap().sends.len();
        let result = coordinator.advance().await;
        if corrupt {
            assert_eq!(result, Err(Error::Verification));
            assert_eq!(backend.0.lock().unwrap().sends.len(), before);
        } else {
            assert_eq!(result, Ok(Progress::Advanced));
            assert!(backend.0.lock().unwrap().rows.contains_key(&Address {
                namespace: [9; 16],
                key: b"canonical/\0".to_vec()
            }));
        }
    }
}

#[tokio::test]
async fn oversized_source_page_never_creates_a_target_attempt() {
    let (_, original) = fixture();
    let mut edge = original.edges[0].clone();
    edge.bounds.bytes = 1;
    let registry = Arc::new(Registry::new(vec![edge]).unwrap());
    let plan = registry
        .plan(
            original.migration,
            original.source,
            original.target,
            &[[4; 16]],
        )
        .unwrap();
    let backend = offline_backend().await;
    let custody = Arc::new(Custody(Mutex::new(None), backend.clone()));
    let mut coordinator = Coordinator::start(
        plan.clone(),
        registry,
        backend.clone(),
        authority(),
        services(&plan, custody),
    )
    .await
    .unwrap();
    copying(&mut coordinator).await;
    let before = backend.0.lock().unwrap().sends.len();
    assert_eq!(coordinator.advance().await, Err(Error::Bounds));
    assert_eq!(backend.0.lock().unwrap().sends.len(), before);
    assert!(coordinator.pending_operation().is_none());
}

#[tokio::test]
async fn activation_unknown_replays_old_identity_then_retirement_uses_successor_epoch() {
    let (mut coordinator, backend, custody, plan, registry) = start().await;
    backend.0.lock().unwrap().rows.insert(
        Address {
            namespace: control::NAMESPACE.0,
            key: control::DATASET_KEY.to_vec(),
        },
        Secret::new(
            control::Dataset {
                id: DatasetId(plan.target.dataset),
                writer_epoch: 1,
            }
            .encode()
            .unwrap()
            .to_vec(),
        ),
    );
    backend.0.lock().unwrap().rows.insert(
        busbar_kernel::persistence::import_target::target::writer_address(authority().writer),
        Secret::new(
            control::Writer {
                retired_through: 0,
                admitted_through: 1,
            }
            .encode()
            .unwrap()
            .to_vec(),
        ),
    );
    for _ in 0..8 {
        coordinator.advance().await.unwrap();
    }
    drop(coordinator);
    let mut svc = services(&plan, custody.clone());
    svc.activation = Some(Arc::new(CoreActivation::new(backend.clone())));
    let mut coordinator =
        Coordinator::resume(&plan, registry.clone(), backend.clone(), authority(), svc)
            .await
            .unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(coordinator.advance().await, Ok(Progress::Pending));
    assert_eq!(coordinator.manifest().state, State::TargetVerified);
    assert_eq!(
        status(backend.as_ref(), plan.migration, &registry)
            .await
            .unwrap()
            .unwrap()
            .state,
        State::Activated
    );
    assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
    assert_eq!(coordinator.manifest().state, State::Activated);
    drop(coordinator);
    let successor = authority();
    let mut coordinator = Coordinator::resume(
        &plan,
        registry.clone(),
        backend.clone(),
        successor,
        services(&plan, custody.clone()),
    )
    .await
    .unwrap();
    assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
    assert_eq!(coordinator.manifest().state, State::Retired);
    drop(coordinator);
    let mut coordinator = Coordinator::resume(
        &plan,
        registry,
        backend,
        successor,
        services(&plan, custody),
    )
    .await
    .unwrap();
    assert_eq!(coordinator.advance().await, Ok(Progress::Complete));
}

#[tokio::test]
async fn offline_bootstrap_retains_unknown_and_resumes_without_publishing_format() {
    let backend = Arc::new(Backend::default());
    let mut bootstrap = TargetBootstrap::new(backend.clone(), authority(), [90; 16]).unwrap();
    assert_eq!(bootstrap.advance().await, Ok(BootstrapProgress::Advanced));
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(bootstrap.advance().await, Ok(BootstrapProgress::Pending));
    assert_eq!(bootstrap.advance().await, Ok(BootstrapProgress::Ready));
    {
        let native = backend.0.lock().unwrap();
        assert_eq!(native.sends[0], native.sends[1]);
        assert!(!native
            .rows
            .contains_key(&busbar_kernel::persistence::import_target::target::manifest_address()));
    }
    let mut restart = TargetBootstrap::new(backend.clone(), authority(), [90; 16]).unwrap();
    assert_eq!(restart.advance().await, Ok(BootstrapProgress::Ready));
    let mut wrong = TargetBootstrap::new(
        backend,
        WriterAuthority {
            writer: [66; 16],
            ..authority()
        },
        [90; 16],
    )
    .unwrap();
    assert_eq!(wrong.advance().await, Err(Error::InvalidState));
}

#[tokio::test]
async fn core_activation_rejects_serving_target_and_writer_retirement() {
    let (mut coordinator, backend, _, plan, _) = start().await;
    let mut bootstrap = TargetBootstrap::new(backend.clone(), authority(), [90; 16]).unwrap();
    assert_eq!(bootstrap.advance().await, Ok(BootstrapProgress::Ready));
    for _ in 0..8 {
        coordinator.advance().await.unwrap();
    }
    let activation = CoreActivation::new(backend.clone());
    let change = activation
        .prepare(coordinator.manifest(), authority())
        .await
        .unwrap();
    assert_eq!(change.mutations.len(), 2);
    assert_eq!(change.predicates.len(), 3);
    backend.0.lock().unwrap().rows.insert(
        busbar_kernel::persistence::import_target::target::manifest_address(),
        Secret::new(vec![1]),
    );
    assert!(matches!(
        activation
            .prepare(coordinator.manifest(), authority())
            .await,
        Err(Error::Conflict)
    ));
    backend
        .0
        .lock()
        .unwrap()
        .rows
        .remove(&busbar_kernel::persistence::import_target::target::manifest_address());
    backend.0.lock().unwrap().rows.insert(
        busbar_kernel::persistence::import_target::target::writer_address(authority().writer),
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
    assert!(matches!(
        activation
            .prepare(coordinator.manifest(), authority())
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(plan.target.format.logical, 1);
}

#[tokio::test]
async fn copying_conflicts_if_serving_format_is_concurrently_published() {
    let (mut coordinator, backend, _, _, _) = start().await;
    copying(&mut coordinator).await;
    backend.0.lock().unwrap().rows.insert(
        busbar_kernel::persistence::import_target::target::manifest_address(),
        Secret::new(vec![1]),
    );
    assert_eq!(coordinator.advance().await, Err(Error::Conflict));
    assert_eq!(coordinator.manifest().checkpoints[0].source_count, 0);
    assert!(!backend.0.lock().unwrap().rows.contains_key(&Address {
        namespace: [9; 16],
        key: vec![0]
    }));
}

#[test]
fn registry_refuses_format_control_and_checkpoint_target_namespaces() {
    let (_, plan) = fixture();
    for namespace in [
        busbar_kernel::persistence::import_target::target::manifest_address().namespace,
        control::NAMESPACE.0,
        control::GENERATION_NAMESPACE.0,
        *b"busbar.migrate1\0",
    ] {
        let mut edge = plan.edges[0].clone();
        edge.families[0].target_namespace = namespace;
        assert!(matches!(
            Registry::new(vec![edge]),
            Err(Error::InvalidManifest)
        ));
    }
}

#[tokio::test]
async fn normal_startup_cannot_admit_copying_target() {
    let (mut coordinator, backend, _, _, _) = start().await;
    copying(&mut coordinator).await;
    let mut startup = busbar_kernel::persistence::startup::Startup::new(
        backend,
        busbar_kernel::persistence::facade::Limits {
            pending_operations: 8,
            conflict_retries: 1,
            scan_items: 8,
            scan_bytes: 4096,
        },
        true,
    )
    .unwrap();
    assert_eq!(
        startup.advance().await,
        Err(busbar_kernel::persistence::startup::Error::IncompleteInitialization)
    );
    assert!(startup.store().is_none());
}

#[tokio::test]
async fn live_activation_uses_successor_epoch_without_restarting_coordinator() {
    let (mut coordinator, backend, custody, plan, registry) = start().await;
    for _ in 0..8 {
        coordinator.advance().await.unwrap();
    }
    drop(coordinator);
    let mut svc = services(&plan, custody);
    svc.activation = Some(Arc::new(CoreActivation::new(backend.clone())));
    let mut coordinator = Coordinator::resume(&plan, registry, backend, authority(), svc)
        .await
        .unwrap();
    assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
    assert_eq!(coordinator.manifest().state, State::Activated);
    assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
    assert_eq!(coordinator.manifest().state, State::Retired);
}

async fn store_intent(backend: Arc<Backend>, migration: Id) -> Arc<StoreIntent> {
    let mut registration =
        ColdWriterRegistration::new(backend.clone(), migration, authority(), [88; 16], [91; 16])
            .unwrap();
    assert_eq!(
        registration.advance().await,
        Ok(BootstrapProgress::Advanced)
    );
    assert_eq!(registration.advance().await, Ok(BootstrapProgress::Ready));
    Arc::new(
        StoreIntent::open(backend, migration, 64 * 1024)
            .await
            .unwrap(),
    )
}

fn intent_candidate(migration: Id, operation: Id) -> PreparedCandidate {
    let target = Address {
        namespace: [9; 16],
        key: operation.to_vec(),
    };
    super::witness::attach(
        Candidate {
            id: AttemptId {
                dataset: DatasetId([2; 16]),
                writer_epoch: 1,
                writer: authority().writer,
                execution_epoch: 1,
                operation,
            },
            codec: CANDIDATE_VERSION,
            predicates: vec![
                Predicate {
                    address: super::intent::guard_address(migration),
                    expected: ExpectedValue::Exact(Secret::new(super::intent::open_guard(
                        migration, operation,
                    ))),
                },
                Predicate {
                    address: target.clone(),
                    expected: ExpectedValue::Absent,
                },
            ],
            mutations: vec![Mutation::Put {
                address: target,
                value: Secret::new(vec![42]),
            }],
            time: None,
            result: Secret::new(Vec::new()),
        },
        migration,
    )
    .unwrap()
}

#[tokio::test]
async fn durable_intent_read_resolves_lost_reply_and_closed_guard_fences_delayed_writes() {
    let backend = offline_backend().await;
    let migration = [10; 16];
    let owner = store_intent(backend.clone(), migration).await;
    let candidate = intent_candidate(migration, [22; 16]);
    let snapshot = busbar_kernel::persistence::import_target::candidate_codec::encode(
        &candidate,
        64 * 1024,
        &crate::seal::lend(),
    )
    .unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    owner.persist(migration, [22; 16], &snapshot).await.unwrap();
    assert!(owner.pending(migration).await.unwrap());
    let old_journal_put = backend.0.lock().unwrap().candidates.last().unwrap().clone();
    let restored = StoreIntent::open(backend.clone(), migration, 64 * 1024)
        .await
        .unwrap();
    let outstanding = restored.outstanding(migration).await.unwrap().unwrap();
    assert_eq!(outstanding.candidate, snapshot);
    assert_eq!(outstanding.fingerprint, candidate.fingerprint());
    assert_eq!(outstanding.prepared_at.unix_seconds, 1);
    assert_eq!(outstanding.replay_deadline, 86401);
    assert!(matches!(
        backend.commit(candidate.clone()).await.unwrap(),
        Decision::Applied(_)
    ));
    let resolution = IntentResolution {
        applied_result: None,
        fingerprint: candidate.fingerprint(),
        kind: super::coordinator::ResolutionKind::Applied,
    };
    backend.0.lock().unwrap().lose_reply = true;
    owner.clear(migration, [22; 16], &resolution).await.unwrap();
    assert!(!owner.pending(migration).await.unwrap());
    assert!(owner.outstanding(migration).await.unwrap().is_none());
    {
        let mut native = backend.0.lock().unwrap();
        let payload = native
            .rows
            .iter()
            .find(|(address, _)| {
                address.namespace == super::intent::NAMESPACE && address.key[0] == b'p'
            })
            .unwrap()
            .1;
        assert_eq!(payload.expose(&crate::seal::lend()).len(), 160);
        native.receipts.retain(|(id, _)| {
            *id != candidate.candidate().id && *id != old_journal_put.candidate().id
        });
    }
    assert!(matches!(
        backend.commit(candidate).await.unwrap(),
        Decision::ConditionConflict
    ));
    assert!(matches!(
        backend.commit(old_journal_put).await.unwrap(),
        Decision::ConditionConflict
    ));
    assert!(!restored.pending(migration).await.unwrap());
}

#[tokio::test]
async fn durable_intent_failed_readback_keeps_original_journal_attempt() {
    let backend = offline_backend().await;
    let migration = [10; 16];
    let owner = store_intent(backend.clone(), migration).await;
    let candidate = intent_candidate(migration, [23; 16]);
    let snapshot = busbar_kernel::persistence::import_target::candidate_codec::encode(
        &candidate,
        64 * 1024,
        &crate::seal::lend(),
    )
    .unwrap();
    {
        let mut native = backend.0.lock().unwrap();
        native.lose_reply = true;
        native.fail_read_after_commit = true;
    }
    assert_eq!(
        owner.persist(migration, [23; 16], &snapshot).await,
        Err(Error::Backend(Failure::Unknown))
    );
    assert!(owner.pending(migration).await.unwrap());
    let sends = backend.0.lock().unwrap().sends.len();
    owner.persist(migration, [23; 16], &snapshot).await.unwrap();
    assert_eq!(backend.0.lock().unwrap().sends.len(), sends);
    assert_eq!(
        owner
            .outstanding(migration)
            .await
            .unwrap()
            .unwrap()
            .candidate,
        snapshot
    );
}

#[tokio::test]
async fn durable_intent_blocks_restart_and_reopens_cold_writer_after_activation() {
    let (registry, plan) = fixture();
    let backend = offline_backend().await;
    let owner = store_intent(backend.clone(), plan.migration).await;
    let fixture_custody = Arc::new(Custody(Mutex::new(None), backend.clone()));
    let mut svc = services(&plan, fixture_custody.clone());
    svc.intent = owner.clone();
    svc.activation = Some(Arc::new(CoreActivation::new(backend.clone())));
    let mut coordinator = Coordinator::start(
        plan.clone(),
        registry.clone(),
        backend.clone(),
        authority(),
        svc,
    )
    .await
    .unwrap();
    for _ in 0..8 {
        coordinator.advance().await.unwrap();
    }
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
    assert_eq!(coordinator.manifest().state, State::Activated);
    drop(coordinator);
    let reopened = Arc::new(
        StoreIntent::open(backend.clone(), plan.migration, 64 * 1024)
            .await
            .unwrap(),
    );
    let mut svc = services(&plan, fixture_custody);
    svc.intent = reopened;
    let mut coordinator = Coordinator::resume(&plan, registry, backend, authority(), svc)
        .await
        .unwrap();
    assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
    assert_eq!(coordinator.manifest().state, State::Retired);
}

#[tokio::test]
async fn durable_active_intent_refuses_coordinator_restart_and_cold_admission_is_explicit() {
    let (registry, plan) = fixture();
    let backend = offline_backend().await;
    assert!(matches!(
        StoreIntent::open(backend.clone(), plan.migration, 64 * 1024).await,
        Err(Error::FenceRequired)
    ));
    let owner = store_intent(backend.clone(), plan.migration).await;
    let mut svc = services(&plan, Arc::new(Custody(Mutex::new(None), backend.clone())));
    svc.intent = owner.clone();
    let mut coordinator = Coordinator::start(
        plan.clone(),
        registry.clone(),
        backend.clone(),
        authority(),
        svc.clone(),
    )
    .await
    .unwrap();
    coordinator.advance().await.unwrap();
    drop(coordinator);
    let candidate = intent_candidate(plan.migration, [24; 16]);
    let snapshot = busbar_kernel::persistence::import_target::candidate_codec::encode(
        &candidate,
        64 * 1024,
        &crate::seal::lend(),
    )
    .unwrap();
    owner
        .persist(plan.migration, [24; 16], &snapshot)
        .await
        .unwrap();
    svc.intent = Arc::new(
        StoreIntent::open(backend.clone(), plan.migration, 64 * 1024)
            .await
            .unwrap(),
    );
    assert!(matches!(
        Coordinator::resume(&plan, registry, backend.clone(), authority(), svc).await,
        Err(Error::ReconciliationRequired)
    ));
    backend.0.lock().unwrap().rows.insert(
        busbar_kernel::persistence::import_target::target::writer_address([88; 16]),
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
    assert!(matches!(
        StoreIntent::open(backend, plan.migration, 64 * 1024).await,
        Err(Error::FenceRequired)
    ));
}

struct PartitionTransform {
    edge: Edge,
    bad: bool,
}
impl Transform for PartitionTransform {
    fn edge(&self) -> &Edge {
        &self.edge
    }
    fn authorize(&self, _: &Family, address: &Address) -> bool {
        address.key.len() == 2
            && address.key[0] == b'p'
            && address.namespace == [address.key[1] + 32; 16]
    }
    fn transform(
        &self,
        _: &Family,
        records: &[Record],
        _: Bounds,
    ) -> Result<Vec<TargetRow>, Error> {
        Ok(records
            .iter()
            .enumerate()
            .map(|(index, row)| TargetRow {
                address: Address {
                    namespace: [row.key[0] + 32; 16],
                    key: vec![if self.bad { b'x' } else { b'p' }, row.key[0]],
                },
                value: row.value.clone(),
                preserved_source: Some(index as u32),
            })
            .collect())
    }
}

#[tokio::test]
async fn transform_address_class_allows_partitions_and_rejects_wrong_key_framing() {
    for bad in [false, true] {
        let (registry, plan) = fixture();
        let backend = offline_backend().await;
        let mut svc = services(&plan, Arc::new(Custody(Mutex::new(None), backend.clone())));
        svc.transform = Arc::new(PartitionTransform {
            edge: plan.edges[0].clone(),
            bad,
        });
        let mut coordinator = Coordinator::start(plan, registry, backend.clone(), authority(), svc)
            .await
            .unwrap();
        copying(&mut coordinator).await;
        let before = backend.0.lock().unwrap().sends.len();
        if bad {
            assert_eq!(coordinator.advance().await, Err(Error::Verification));
            assert_eq!(backend.0.lock().unwrap().sends.len(), before);
        } else {
            assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
            assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
            assert!(backend.0.lock().unwrap().rows.contains_key(&Address {
                namespace: [32; 16],
                key: vec![b'p', 0]
            }));
            assert!(backend.0.lock().unwrap().rows.contains_key(&Address {
                namespace: [33; 16],
                key: vec![b'p', 1]
            }));
        }
    }
}

#[test]
fn bootstrap_identities_depend_on_frozen_plan_and_ignore_reported_progress() {
    let (registry, plan) = fixture();
    let original = BootstrapIds::for_plan(&plan, &registry).unwrap();
    let mut report = plan.clone();
    report.state = State::Identified;
    let resumed = BootstrapIds::for_plan(&report, &registry).unwrap();
    assert_eq!(original.authority, resumed.authority);
    assert_eq!(original.initialize_operation, resumed.initialize_operation);
    assert_eq!(original.cold_writer, resumed.cold_writer);
    assert_eq!(
        original.cold_registration_operation,
        resumed.cold_registration_operation
    );
    assert_ne!(original.cold_writer, original.authority.writer);
    report.migration = [25; 16];
    assert_ne!(
        original.authority,
        BootstrapIds::for_plan(&report, &registry)
            .unwrap()
            .authority
    );
}

#[tokio::test]
async fn fenced_recovery_resolves_receipt_or_immutable_witness_and_grants_successor() {
    for collect_receipt in [false, true] {
        let (registry, plan) = fixture();
        let backend = offline_backend().await;
        let owner = store_intent(backend.clone(), plan.migration).await;
        let mut svc = services(&plan, Arc::new(Custody(Mutex::new(None), backend.clone())));
        svc.intent = owner;
        let mut coordinator = Coordinator::start(
            plan.clone(),
            registry.clone(),
            backend.clone(),
            authority(),
            svc.clone(),
        )
        .await
        .unwrap();
        copying(&mut coordinator).await;
        backend.0.lock().unwrap().lose_writer_reply = Some(authority().writer);
        assert_eq!(coordinator.advance().await, Ok(Progress::Pending));
        assert_eq!(coordinator.manifest().checkpoints[0].source_count, 0);
        drop(coordinator);
        if collect_receipt {
            let mut native = backend.0.lock().unwrap();
            let id = native.candidates.last().unwrap().candidate().id;
            native.receipts.retain(|(receipt, _)| *receipt != id);
        }
        let recovered = Arc::new(
            StoreIntent::open(backend.clone(), plan.migration, 64 * 1024)
                .await
                .unwrap(),
        );
        assert_eq!(
            recovered.reconcile(plan.migration).await,
            Ok(ReconciliationProgress::Advanced)
        );
        assert_eq!(
            recovered.reconcile(plan.migration).await,
            Ok(ReconciliationProgress::Advanced)
        );
        // Crash after closing the intent but before granting a new epoch.
        drop(recovered);
        let recovered = Arc::new(
            StoreIntent::open(backend.clone(), plan.migration, 64 * 1024)
                .await
                .unwrap(),
        );
        assert_eq!(
            recovered.reconcile(plan.migration).await,
            Ok(ReconciliationProgress::Advanced)
        );
        assert_eq!(
            recovered.reconcile(plan.migration).await,
            Ok(ReconciliationProgress::Resolved)
        );
        svc.intent = recovered;
        let mut coordinator =
            Coordinator::resume(&plan, registry, backend.clone(), authority(), svc)
                .await
                .unwrap();
        assert_eq!(coordinator.manifest().checkpoints[0].source_count, 1);
        assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
        assert_eq!(coordinator.manifest().checkpoints[0].source_count, 2);
        let native = backend.0.lock().unwrap();
        let writer = control::Writer::decode(
            native.rows[&busbar_kernel::persistence::import_target::target::writer_address(
                authority().writer,
            )]
                .expose(&crate::seal::lend()),
        )
        .unwrap();
        assert_eq!(
            writer,
            control::Writer {
                retired_through: 1,
                admitted_through: 2
            }
        );
    }
}

#[tokio::test]
async fn fenced_recovery_missing_witness_keeps_debt_and_never_first_executes() {
    let backend = offline_backend().await;
    let migration = [10; 16];
    let owner = store_intent(backend.clone(), migration).await;
    let candidate = intent_candidate(migration, [26; 16]);
    let snapshot = busbar_kernel::persistence::import_target::candidate_codec::encode(
        &candidate,
        64 * 1024,
        &crate::seal::lend(),
    )
    .unwrap();
    owner.persist(migration, [26; 16], &snapshot).await.unwrap();
    drop(owner);
    let owner = StoreIntent::open(backend.clone(), migration, 64 * 1024)
        .await
        .unwrap();
    assert_eq!(
        owner.reconcile(migration).await,
        Ok(ReconciliationProgress::Advanced)
    );
    assert_eq!(
        owner.reconcile(migration).await,
        Ok(ReconciliationProgress::Unresolved)
    );
    assert!(owner.pending(migration).await.unwrap());
    assert!(matches!(
        backend.commit(candidate).await.unwrap(),
        Decision::ExpiredUnknown
    ));
    assert!(!backend.0.lock().unwrap().rows.contains_key(&Address {
        namespace: [9; 16],
        key: vec![26; 16]
    }));
}

#[tokio::test]
async fn activation_recovery_uses_root_fence_and_preserves_live_registrar() {
    let (registry, plan) = fixture();
    let backend = offline_backend().await;
    let owner = store_intent(backend.clone(), plan.migration).await;
    let mut svc = services(&plan, Arc::new(Custody(Mutex::new(None), backend.clone())));
    svc.intent = owner;
    svc.activation = Some(Arc::new(CoreActivation::new(backend.clone())));
    let mut coordinator = Coordinator::start(
        plan.clone(),
        registry.clone(),
        backend.clone(),
        authority(),
        svc.clone(),
    )
    .await
    .unwrap();
    for _ in 0..8 {
        coordinator.advance().await.unwrap();
    }
    backend.0.lock().unwrap().lose_writer_reply = Some(authority().writer);
    assert_eq!(coordinator.advance().await, Ok(Progress::Pending));
    drop(coordinator);
    let recovered = Arc::new(
        StoreIntent::open(backend.clone(), plan.migration, 64 * 1024)
            .await
            .unwrap(),
    );
    assert_eq!(
        recovered.reconcile(plan.migration).await,
        Ok(ReconciliationProgress::Advanced)
    );
    assert_eq!(
        recovered.reconcile(plan.migration).await,
        Ok(ReconciliationProgress::Resolved)
    );
    let proof = recovered
        .confirmed_checkpoint(plan.migration)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proof.phase,
        busbar_contract::persistence::lifecycle::CompletionPhase::Activation
    );
    assert_eq!(proof.attempt.writer, authority().writer);
    let native_marker =
        busbar_contract::persistence::lifecycle::completion_marker_address(plan.migration);
    let marker = backend.0.lock().unwrap().rows[&native_marker].clone();
    let marker = busbar_contract::persistence::lifecycle::codec::decode_completion_marker(
        marker.expose(&crate::seal::lend()),
        busbar_contract::persistence::lifecycle::Bounds {
            items: 16,
            bytes: 4096,
        },
    )
    .unwrap();
    assert_eq!(marker.phase, proof.phase);
    assert_eq!(
        marker.checkpoint_value_digest,
        proof.checkpoint_value_digest
    );
    {
        let native = backend.0.lock().unwrap();
        let registrar = control::Writer::decode(
            native.rows[&busbar_kernel::persistence::import_target::target::writer_address(
                authority().writer,
            )]
                .expose(&crate::seal::lend()),
        )
        .unwrap();
        assert!(registrar.admits(1));
    }
    svc.intent = recovered.clone();
    let mut coordinator = Coordinator::resume(&plan, registry, backend, authority(), svc)
        .await
        .unwrap();
    assert_eq!(coordinator.manifest().state, State::Activated);
    assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
    assert_eq!(coordinator.manifest().state, State::Retired);
    let activation = recovered
        .confirmed_checkpoint_phase(
            plan.migration,
            busbar_contract::persistence::lifecycle::CompletionPhase::Activation,
        )
        .await
        .unwrap()
        .unwrap();
    let complete = recovered
        .confirmed_checkpoint_phase(
            plan.migration,
            busbar_contract::persistence::lifecycle::CompletionPhase::Complete,
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(activation.attempt, proof.attempt);
    assert_ne!(activation.attempt, complete.attempt);
    assert_ne!(
        activation.checkpoint_value_digest,
        complete.checkpoint_value_digest
    );
}

#[tokio::test]
async fn copy_reuses_only_identical_destination_bytes_and_never_repairs_collisions() {
    for value in [42, 43] {
        let (mut coordinator, backend, _, _, _) = start().await;
        copying(&mut coordinator).await;
        let address = Address {
            namespace: [9; 16],
            key: vec![0],
        };
        backend
            .0
            .lock()
            .unwrap()
            .rows
            .insert(address.clone(), Secret::new(vec![value]));
        if value == 42 {
            assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
            assert_eq!(coordinator.manifest().checkpoints[0].target_count, 1);
        } else {
            let before = backend.0.lock().unwrap().sends.len();
            assert_eq!(coordinator.advance().await, Err(Error::Verification));
            assert_eq!(backend.0.lock().unwrap().sends.len(), before);
            assert_eq!(coordinator.manifest().checkpoints[0].target_count, 0);
        }
        assert_eq!(
            backend.0.lock().unwrap().rows[&address],
            Secret::new(vec![value])
        );
    }
}

#[tokio::test]
async fn fenced_no_effect_requires_unchanged_native_generation_and_prior_checkpoint() {
    for changed_generation in [false, true] {
        let (registry, plan) = fixture();
        let backend = offline_backend().await;
        let owner = store_intent(backend.clone(), plan.migration).await;
        let mut svc = services(&plan, Arc::new(Custody(Mutex::new(None), backend.clone())));
        svc.intent = owner;
        let mut coordinator = Coordinator::start(
            plan.clone(),
            registry.clone(),
            backend.clone(),
            authority(),
            svc.clone(),
        )
        .await
        .unwrap();
        copying(&mut coordinator).await;
        backend.0.lock().unwrap().uncertain_without_effect = Some(authority().writer);
        assert_eq!(coordinator.advance().await, Ok(Progress::Pending));
        drop(coordinator);
        if changed_generation {
            let external = PreparedCandidate::new(Candidate {
                id: AttemptId {
                    dataset: DatasetId([2; 16]),
                    writer_epoch: 1,
                    writer: authority().writer,
                    execution_epoch: 1,
                    operation: [97; 16],
                },
                codec: CANDIDATE_VERSION,
                predicates: vec![],
                mutations: vec![Mutation::Put {
                    address: Address {
                        namespace: super::coordinator::NAMESPACE,
                        key: b"unrelated".to_vec(),
                    },
                    value: Secret::new(vec![1]),
                }],
                time: None,
                result: Secret::new(Vec::new()),
            })
            .unwrap();
            assert!(matches!(
                backend.commit(external).await.unwrap(),
                Decision::Applied(_)
            ));
        }
        let recovered = Arc::new(
            StoreIntent::open(backend.clone(), plan.migration, 64 * 1024)
                .await
                .unwrap(),
        );
        assert_eq!(
            recovered.reconcile(plan.migration).await,
            Ok(ReconciliationProgress::Advanced)
        );
        if changed_generation {
            assert_eq!(
                recovered.reconcile(plan.migration).await,
                Ok(ReconciliationProgress::Unresolved)
            );
            assert!(recovered.pending(plan.migration).await.unwrap());
        } else {
            assert_eq!(
                recovered.reconcile(plan.migration).await,
                Ok(ReconciliationProgress::Advanced)
            );
            assert_eq!(
                recovered.reconcile(plan.migration).await,
                Ok(ReconciliationProgress::Advanced)
            );
            assert_eq!(
                recovered.reconcile(plan.migration).await,
                Ok(ReconciliationProgress::Resolved)
            );
            svc.intent = recovered;
            let mut coordinator =
                Coordinator::resume(&plan, registry, backend.clone(), authority(), svc)
                    .await
                    .unwrap();
            assert_eq!(coordinator.manifest().checkpoints[0].source_count, 0);
            assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
            assert_eq!(coordinator.manifest().checkpoints[0].source_count, 1);
        }
    }
}

struct LiveFixtureProbe;
#[async_trait]
impl SourceFenceProbe for LiveFixtureProbe {
    fn implementation_digest(&self) -> [u8; 32] {
        [77; 32]
    }
    async fn verify(
        &self,
        request: &busbar_contract::persistence::source_fence::ProbeRequest,
    ) -> Result<busbar_contract::persistence::source_fence::ProbeReply, Error> {
        use busbar_contract::persistence::source_fence as wire;
        Ok(wire::ProbeReply {
            version: wire::VERSION,
            request_sha256: request.digest().unwrap(),
            native_anchor_sha256: request.native_anchor_sha256,
            archive_sha256: request.archive_sha256,
            writer_inventory_sha256: wire::writer_inventory_digest(&request.old_writers).unwrap(),
            enforcement_policy_sha256: [7; 32],
            observation_sha256: busbar_contract::abi::sdk::digest::sha256(&request.challenge),
        })
    }
}
struct ExactFixtureReadback(Edge);
impl NativeReadback for ExactFixtureReadback {
    fn edge(&self) -> &Edge {
        &self.0
    }
    fn verify(
        &self,
        _: &Identity,
        family: &Family,
        records: &[Record],
        _: Bounds,
        values: &[(Address, Secret<Vec<u8>>)],
    ) -> Result<[u8; 32], Error> {
        if records.len() != values.len()
            || records
                .iter()
                .zip(values)
                .any(|(record, (address, value))| {
                    address.namespace != family.target_namespace
                        || address.key != record.key
                        || value != &record.value
                })
        {
            return Err(Error::Verification);
        }
        Ok(busbar_contract::abi::sdk::digest::sha256(
            b"fixture exact protected row readback",
        ))
    }
}
struct NoFixtureRecovery;
#[async_trait]
impl TargetRecoveryProbe for NoFixtureRecovery {
    async fn verify_reopened_hydrated(&self, _: &Identity) -> Result<[u8; 32], Error> {
        Err(Error::MissingCapability)
    }
}
fn readback_services(plan: &Manifest, backend: Arc<Backend>) -> Services {
    use busbar_contract::persistence::{archive, source_fence as wire};
    let writers = vec!["fixture legacy writer".to_owned()];
    let inventory = wire::writer_inventory_digest(&writers).unwrap();
    let attestation = |kind, epoch| wire::Attestation {
        version: wire::VERSION,
        kind,
        epoch: [epoch; 16],
        native_anchor_sha256: [42; 32],
        archive_sha256: plan.source.artifact_digest,
        writer_inventory_sha256: inventory,
        quiesced: true,
        actor: "fixture operator".into(),
        reason: "unit source snapshot".into(),
    };
    let header = archive::Header {
        owner: plan.source.format.owner,
        physical: plan.source.format.physical,
        catalogue_digest: [9; 32],
        native_anchor_digest: [42; 32],
        capture: Some(wire::CaptureFence {
            writer_inventory_sha256: inventory,
            enforcement_policy_sha256: [7; 32],
            prefence_observation_sha256: [8; 32],
        }),
        tables: vec![],
    };
    let summary = archive::Summary {
        rows: 2,
        bytes: 256,
        digest: plan.source.artifact_digest,
        catalogue_digest: [9; 32],
        layout_digest: plan.source.schema_digest,
        content_digest: [4; 32],
        post_observation_sha256: Some([5; 32]),
    };
    let fence = Arc::new(
        NativeSourceFence::new(
            plan.source.clone(),
            &header,
            summary,
            writers,
            &attestation(wire::Quiescence::Sender, 1),
            &attestation(wire::Quiescence::Backend, 2),
            Arc::new(LiveFixtureProbe),
        )
        .unwrap(),
    );
    let source = Arc::new(Reader(plan.source.clone()));
    let transform = Arc::new(CopyTransform(plan.edges[0].clone()));
    let snapshot = SnapshotEvidence {
        source: plan.source.dataset,
        snapshot: [6; 16],
        content_digest: plan.source.artifact_digest,
        coverage_digest: [8; 32],
    };
    let verifier = Arc::new(
        ArchiveVerifier::new(
            backend.clone(),
            source.clone(),
            transform.clone(),
            Arc::new(ExactFixtureReadback(plan.edges[0].clone())),
            fence,
            snapshot,
            Arc::new(NoFixtureRecovery),
        )
        .unwrap(),
    );
    Services {
        source,
        transform,
        verifier,
        activation: None,
        intent: Arc::new(Custody(Mutex::new(None), backend)),
    }
}

#[tokio::test]
async fn bounded_native_readback_resumes_persisted_partial_family() {
    let (registry, plan) = fixture();
    let backend = offline_backend().await;
    let mut coordinator = Coordinator::start(
        plan.clone(),
        registry.clone(),
        backend.clone(),
        authority(),
        readback_services(&plan, backend.clone()),
    )
    .await
    .unwrap();
    for _ in 0..8 {
        coordinator.advance().await.unwrap();
    }
    assert_eq!(coordinator.manifest().state, State::Copying);
    let verification = coordinator.manifest().verification.as_ref().unwrap();
    assert_eq!(verification.partial.as_ref().unwrap().after, 1);
    assert!(verification.families.is_empty());
    drop(coordinator);
    let mut coordinator = Coordinator::resume(
        &plan,
        registry,
        backend.clone(),
        authority(),
        readback_services(&plan, backend),
    )
    .await
    .unwrap();
    assert_eq!(coordinator.advance().await, Ok(Progress::Advanced));
    assert_eq!(coordinator.manifest().state, State::TargetVerified);
    let verification = coordinator.manifest().verification.as_ref().unwrap();
    assert!(verification.complete);
    assert!(verification.partial.is_none());
    assert_eq!(verification.families[0].source_count, 2);
}

#[tokio::test]
async fn native_readback_rejects_changed_value_without_advancing_checkpoint() {
    let (registry, plan) = fixture();
    let backend = offline_backend().await;
    let mut coordinator = Coordinator::start(
        plan.clone(),
        registry,
        backend.clone(),
        authority(),
        readback_services(&plan, backend.clone()),
    )
    .await
    .unwrap();
    for _ in 0..7 {
        coordinator.advance().await.unwrap();
    }
    backend.0.lock().unwrap().rows.insert(
        Address {
            namespace: [9; 16],
            key: vec![0],
        },
        Secret::new(vec![43]),
    );
    let before = backend.0.lock().unwrap().sends.len();
    assert_eq!(coordinator.advance().await, Err(Error::Verification));
    assert_eq!(backend.0.lock().unwrap().sends.len(), before);
    assert!(coordinator.manifest().verification.is_none());
}

#[tokio::test]
async fn document_checkpoints_retain_unknown_and_discover_before_new_custody() {
    use busbar_kernel::persistence::import_target::target;
    let backend = offline_backend().await;
    backend.0.lock().unwrap().rows.insert(
        target::manifest_address(),
        Secret::new(
            target::FormatRecord {
                dataset: backend.info().dataset,
                registrar: authority(),
            }
            .encode()
            .to_vec(),
        ),
    );
    let custody = Arc::new(Custody(Mutex::new(None), backend.clone()));
    let migration = [73; 16];
    let scope = [74; 32];
    let protected = Secret::new(b"protected original document inventory".to_vec());
    let checkpoints = documents::StoreCheckpoints::new(
        backend.clone(),
        authority(),
        custody.clone(),
        scope,
        64 * 1024,
    )
    .unwrap();
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(
        checkpoints.confirm(migration, &protected).await,
        Err(Error::IntentPending)
    );
    assert!(checkpoints.has_pending());
    let changed = Secret::new(b"different protected original".to_vec());
    assert_eq!(
        checkpoints.confirm(migration, &changed).await,
        Err(Error::Conflict)
    );
    assert_eq!(
        checkpoints.confirm(migration, &protected).await.unwrap(),
        protected
    );
    {
        let inner = backend.0.lock().unwrap();
        assert_eq!(inner.sends.len(), 2);
        assert_eq!(inner.sends[0], inner.sends[1]);
    }
    drop(checkpoints);
    let discovered = documents::StoreCheckpoints::discover(backend.clone(), scope, 64 * 1024)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(discovered.migration, migration);
    assert_eq!(discovered.protected, protected);
    let checkpoints =
        documents::StoreCheckpoints::new(backend.clone(), authority(), custody, scope, 64 * 1024)
            .unwrap();
    assert_eq!(
        checkpoints.load(migration).await.unwrap(),
        Some(protected.clone())
    );
    backend.0.lock().unwrap().lose_reply = true;
    assert_eq!(
        checkpoints.complete(migration, &protected).await,
        Err(Error::IntentPending)
    );
    // Complete and locator deletion were one native commit even though its reply was lost.
    assert!(
        documents::StoreCheckpoints::discover(backend.clone(), scope, 64 * 1024)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        checkpoints.complete(migration, &protected).await.unwrap(),
        protected
    );
    assert_eq!(checkpoints.load(migration).await.unwrap(), Some(protected));
}
