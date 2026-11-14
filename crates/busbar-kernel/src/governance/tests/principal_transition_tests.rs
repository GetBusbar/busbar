// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use super::{guard_native as guard, pending_guard_native as pending_guard};
use crate::config::{overlay::OverlayStore, GroupCfg};
use crate::governance::{binding_marker, signing::TokenSigner, GovState};
use crate::host_record_bootstrap::StoreWitness;
use crate::persistence::facade::{CoreStore, PendingId};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, DatasetId, Decision as NativeDecision, Failure, Page,
    PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::records::{MeteringDelta, ModelTokens};
use busbar_contract::records::{UsageLedger, VirtualKey};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

const TEST_INSTANCE: &str = "test.principal-transition-fixture";
fn test_witness_binding() -> super::WitnessBinding {
    super::WitnessBinding {
        instance: TEST_INSTANCE.into(),
        private: true,
        source_scope: super::WitnessScope::Unscoped,
    }
}
struct TestRows(Arc<CoreStore>);
impl TestRows {
    fn owner(&self, schema: RecordSchemaId) -> crate::persistence::scoped::ScopedStore {
        crate::persistence::scoped::ScopedStore::host_private(
            self.0.clone(),
            if schema == super::SCHEMA {
                super::NATIVE_INSTANCE
            } else {
                TEST_INSTANCE
            },
            [schema.as_str().to_string()],
        )
        .unwrap()
    }
    async fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), String> {
        match self
            .owner(schema)
            .put(
                schema.as_str(),
                key,
                busbar_contract::Secret::new(value.as_slice().to_vec()),
            )
            .await
            .map_err(|e| format!("{e:?}"))?
        {
            crate::persistence::scoped::Outcome::Applied => Ok(()),
            other => Err(format!("fixture write was not applied: {other:?}")),
        }
    }
    async fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        self.owner(schema)
            .get(schema.as_str(), key)
            .await
            .map_err(|e| format!("{e:?}"))?
            .map(|value| {
                RecordBytes::new(value.expose(&crate::seal::lend()).clone())
                    .map_err(|_| "fixture record bound".into())
            })
            .transpose()
    }
}
async fn read_head(rows: &TestRows) -> Result<Option<(super::Head, Vec<u8>)>, String> {
    super::read_head(&super::native_receipt_snapshot(&rows.0).await?)
}
async fn snapshot_body(rows: &TestRows, prefix: &[u8], length: usize) -> Result<Vec<u8>, String> {
    super::read_body(
        &super::native_receipt_snapshot(&rows.0).await?,
        prefix,
        length,
    )
}
async fn consume_bootstrap(
    receipt: crate::host_record_bootstrap::ColdRecordReceipt,
    expected: &str,
    rows: &TestRows,
) -> Result<crate::host_record_bootstrap::Bootstrap, &'static str> {
    crate::host_record_bootstrap::Bootstrap::consume(
        receipt,
        expected,
        &rows.0,
        |schema, key, value| {
            super::witness_address(schema, key, value, None).map_err(|_| "unbound witness")
        },
    )
    .await
}

const NOW: u64 = 1_700_000_000;
const OLD: &str = "historic-subject";
const NEW: &str = "opaque-format:issuer:historic-subject";
fn sha() -> String {
    "a".repeat(64)
}
fn signer() -> TokenSigner {
    TokenSigner::from_secret_bytes(&[37; 32], "transition-test")
}

struct Fixture {
    store: Arc<CoreStore>,
    backend: Arc<UnknownUsage>,
    overlay: Arc<OverlayStore>,
    groups: BTreeMap<String, GroupCfg>,
}
impl Fixture {
    async fn new() -> Self {
        let backend = Arc::new(UnknownUsage {
            inner: crate::real_store::native_backend().await,
            fail: AtomicBool::new(false),
            fail_key: AtomicBool::new(false),
            pending: Mutex::new(None),
        });
        let store = crate::real_store::core_over(backend.clone()).await;
        let overlay = OverlayStore::from_core(store.clone()).unwrap();
        let groups=serde_yaml::from_str::<BTreeMap<String,GroupCfg>>("user:historic-subject:\n  parent: shared\n  limits:\n    - { requests: 9, per: total }\n    - { tokens: 10, per: hour }\n    - { budget: 100, per: day }\n    - { requests: 20, per: month, pool: opaque/a }\nshared:\n  limits:\n    - { requests: 100, per: total }\n").unwrap();
        let witness = RecordBytes::new(b"test owns this newly opened namespace".to_vec()).unwrap();
        TestRows(store.clone())
            .record_put(
                RecordSchemaId::new("test.principal-witness"),
                b"namespace",
                &witness,
            )
            .await
            .unwrap();
        let key = VirtualKey {
            id: "vk_retained".into(),
            generation_hash: binding_marker("vk_retained", "3"),
            enabled: true,
            group: Some(group(OLD)),
            idp_subject: Some(OLD.into()),
            idp_provider: Some("identity".into()),
            binding_mode: Some(crate::governance::SELF_KEY_BINDING_MODE.into()),
            ..Default::default()
        };
        store.identity().put_key(&key).await.unwrap();
        let fixture = Self {
            store,
            backend,
            overlay,
            groups,
        };
        for (source, _, window, _) in addresses(&fixture.spec(), &fixture.groups, NOW).unwrap() {
            fixture
                .store
                .ledger()
                .put_usage(&source, window, &raw())
                .await
                .unwrap();
        }
        fixture
            .store
            .ledger()
            .put_usage(
                "group:shared@total",
                0,
                &UsageLedger {
                    requests: 73,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        fixture
    }
    fn spec(&self) -> Specification {
        Specification {
            witness_binding: Some(test_witness_binding()),
            version: 2,
            id: "operator-approved-cutover".into(),
            bindings: vec![Binding {
                old_principal: OLD.into(),
                new_principal: NEW.into(),
                provider: "identity".into(),
                historical_provenance_sha256: sha(),
                old_product_sha256: sha(),
            }],
            role_bindings_before: Default::default(),
            role_dispositions: Vec::new(),
            rotations: Vec::new(),
            unaffected: Vec::new(),
            complete_legacy_inventory_sha256: sha(),
            requirements: vec![
                Requirement {
                    provider: "identity".into(),
                    plugin: "test.auth".into(),
                    domain_sha256: sha(),
                    format: "opaque-format".into(),
                    product_sha256: sha(),
                    settings_sha256: sha(),
                },
                Requirement {
                    provider: "operator-token".into(),
                    plugin: "test.static-token".into(),
                    format: String::new(),
                    domain_sha256: String::new(),
                    product_sha256: String::new(),
                    settings_sha256: sha(),
                },
            ],
            store_config_sha256: sha(),
            effective_config_sha256: sha(),
            witness: StoreWitness {
                schema: "test.principal-witness".into(),
                key_hex: hex::encode(b"namespace"),
                value_hex: hex::encode(b"test owns this newly opened namespace"),
            },
            cutover: NOW,
        }
    }
    async fn plan(&self) -> Plan {
        prepare(self.spec(), self.store.clone(), self.groups.clone(), None)
            .await
            .unwrap()
    }
    fn attest(&self, plan: &Plan, epoch: u8) -> ColdAttestation {
        ColdAttestation {
            version: 1,
            epoch: hex::encode([epoch; 16]),
            plan_sha256: digest(&plan.authoring(&crate::seal::acquire())).unwrap(),
            sender_quiesced: true,
            backend_quiesced: true,
            recovery_and_corrections_settled: true,
            actor: "isolated test namespace owner".into(),
            reason: "all test calls returned; no background producer exists".into(),
        }
    }
    async fn apply(&self, plan: &Plan) {
        apply(
            plan,
            &self.attest(plan, 1),
            self.store.clone(),
            &self.overlay,
            NOW,
            &sha(),
        )
        .await
        .unwrap();
    }
    async fn gov(&self) -> GovState {
        let g = GovState::new_with_core(self.store.clone(), None, Some(signer()))
            .await
            .unwrap();
        g.install_transition_self_holds(
            guard(self.store.clone(), &sha(), &self.spec().requirements)
                .await
                .unwrap(),
        );
        g
    }
}
fn next_artifact(f: &Fixture, plan: &Plan) -> super::Reauthorization {
    let mut requirements = plan.specification.requirements.clone();
    requirements[0].product_sha256 = "b".repeat(64);
    super::Reauthorization {
        witness_binding: Some(test_witness_binding()),
        version: 2,
        baseline_sha256: digest(&plan.authoring(&crate::seal::acquire())).unwrap(),
        previous_requirements_sha256: digest(&plan.specification.requirements).unwrap(),
        requirements,
        identity_outputs_unchanged: true,
        continuity_evidence_sha256: sha(),
        witness: f.spec().witness,
        attestation: f.attest(plan, 9),
    }
}

fn raw() -> UsageLedger {
    UsageLedger {
        requests: 9,
        billable_requests: 7,
        models: vec![ModelTokens {
            scale: 6,
            model: "opaque:model".into(),
            usage_units: BTreeMap::from([
                ("input".into(), 10_000_001),
                ("custom:class".into(), 9_007_199_254_740_993),
            ]),
        }],
    }
}

#[tokio::test]
async fn cold_principal_transition_preserves_raw_budget_and_self_key_identity() {
    let f = Fixture::new().await;
    let before = f
        .store
        .identity()
        .get_key("vk_retained")
        .await
        .unwrap()
        .unwrap();
    let token = signer().mint(&before.id, NOW + 3600, Some("3"));
    let plan = f.plan().await;
    f.apply(&plan).await;
    let gov = f.gov().await;
    let retained = gov.verify_token(&token, NOW, None).unwrap();
    assert_eq!(retained.id, before.id);
    assert_eq!(retained.generation_hash, before.generation_hash);
    assert_eq!(retained.group.as_deref(), Some(group(NEW).as_str()));
    assert_eq!(
        gov.issue_self(NEW, "identity", None, NOW + 3600, NOW)
            .await
            .unwrap()
            .0
            .id,
        before.id
    );
    for c in &plan.carry {
        assert_eq!(
            f.store
                .ledger()
                .get_usage(&c.destination, c.window)
                .await
                .unwrap(),
            c.raw
        );
        assert_eq!(
            f.store
                .ledger()
                .get_usage(&c.source, c.window)
                .await
                .unwrap(),
            c.raw
        );
    }
    assert_eq!(
        f.store
            .ledger()
            .get_usage("group:shared@total", 0)
            .await
            .unwrap()
            .requests,
        73
    );
    let mut groups = f.groups.clone();
    groups.insert(group(NEW), groups[&group(OLD)].clone());
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &groups);
    gov.hydrate_budgets_async(&cost, NOW).await.unwrap();
    assert!(
        gov.try_admit(&cost, &retained, "", NOW).is_err(),
        "copied exhausted request quota must reject"
    );
}

#[tokio::test]
async fn cold_principal_transition_carries_disabled_and_revoked_self_holds() {
    for revoked in [false, true] {
        let f = Fixture::new().await;
        let mut key = f
            .store
            .identity()
            .get_key("vk_retained")
            .await
            .unwrap()
            .unwrap();
        if revoked {
            f.store
                .identity()
                .add_denylist(&key.id, "operator revoked")
                .await
                .unwrap();
        } else {
            key.enabled = false;
            f.store.identity().put_key(&key).await.unwrap();
        }
        let plan = f.plan().await;
        f.apply(&plan).await;
        for _restart in 0..2 {
            let gov = f.gov().await;
            assert!(!gov.self_mint_holds.load(Ordering::Relaxed));
            assert!(matches!(
                gov.issue_self(NEW, "identity", None, NOW + 60, NOW).await,
                Err(crate::governance::SelfMintError::Refused(
                    crate::governance::SelfMintRefusal::Disabled
                ))
            ));
            assert!(matches!(
                gov.refresh_self(NEW, "identity", None, NOW + 60, NOW).await,
                Err(crate::governance::SelfMintError::Refused(
                    crate::governance::SelfMintRefusal::Disabled
                ))
            ));
            assert!(gov
                .issue_self("independent-B", "identity", None, NOW + 60, NOW)
                .await
                .is_ok());
        }
        let after = f
            .store
            .identity()
            .get_key("vk_retained")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.enabled, key.enabled);
        assert_eq!(after.generation_hash, key.generation_hash);
        if revoked {
            assert!(f
                .store
                .identity()
                .list_denylist()
                .await
                .unwrap()
                .contains(&key.id));
        }
        let mut rotated_admin = plan.specification.requirements.clone();
        rotated_admin[1].settings_sha256 = "e".repeat(64);
        let holds = guard(f.store.clone(), &sha(), &rotated_admin)
            .await
            .unwrap();
        assert!(
            holds.contains(NEW),
            "unrelated static-token rotation must retain tracked denial"
        );
        rotated_admin.pop();
        assert_eq!(
            holds,
            guard(f.store.clone(), &sha(), &rotated_admin)
                .await
                .unwrap(),
            "removing an unrelated unmarked provider does not remove tracked holds"
        );
        let mut tracked_unmarked = rotated_admin.clone();
        tracked_unmarked[0].format.clear();
        assert!(guard(f.store.clone(), &sha(), &tracked_unmarked)
            .await
            .is_err());
        let mut authorization = next_artifact(&f, &plan);
        authorization.requirements[1].settings_sha256 = "e".repeat(64);
        super::reauthorize(
            &authorization,
            f.store.clone(),
            &sha(),
            &authorization.requirements,
        )
        .await
        .unwrap();
        let reloaded = GovState::new_with_core(f.store.clone(), None, Some(signer()))
            .await
            .unwrap();
        reloaded.install_transition_self_holds(
            guard(f.store.clone(), &sha(), &authorization.requirements)
                .await
                .unwrap(),
        );
        assert!(matches!(
            reloaded
                .issue_self(NEW, "identity", None, NOW + 60, NOW)
                .await,
            Err(crate::governance::SelfMintError::Refused(
                crate::governance::SelfMintRefusal::Disabled
            ))
        ));
        for carry in &plan.carry {
            assert_eq!(
                f.store
                    .ledger()
                    .get_usage(&carry.destination, carry.window)
                    .await
                    .unwrap(),
                carry.raw
            );
        }
    }
    // A normal successful SELF refresh leaves a tombstone. It must not silently become a
    // permanent subject-level hold, and a live row alone cannot prove the deletion's cause.
    let rotated = Fixture::new().await;
    let live = GovState::new_with_core(rotated.store.clone(), None, Some(signer()))
        .await
        .unwrap();
    let (successor, token) = live
        .refresh_self(OLD, "identity", None, NOW + 3600, NOW)
        .await
        .unwrap();
    drop(live);
    let retired = rotated
        .store
        .identity()
        .get_key("vk_retained")
        .await
        .unwrap()
        .unwrap();
    let successor = rotated
        .store
        .identity()
        .get_key(&successor.id)
        .await
        .unwrap()
        .unwrap();
    assert!(retired.deleted_at.is_some());
    let error = prepare(
        rotated.spec(),
        rotated.store.clone(),
        rotated.groups.clone(),
        None,
    )
    .await
    .unwrap_err();
    assert!(error.contains("rotation versus revocation"));
    assert!(read_head(&TestRows(rotated.store.clone()))
        .await
        .unwrap()
        .is_none());
    let mut spec = rotated.spec();
    spec.rotations.push(super::RotationDisposition {
        retired_key_id: retired.id.clone(),
        successor_key_id: successor.id.clone(),
        retired_key_sha256: digest(&retired).unwrap(),
        successor_key_sha256: digest(&successor).unwrap(),
        evidence_sha256: sha(),
    });
    let plan = prepare(spec, rotated.store.clone(), rotated.groups.clone(), None)
        .await
        .unwrap();
    rotated.apply(&plan).await;
    let resumed = rotated.gov().await;
    assert_eq!(
        resumed.verify_token(&token, NOW, None).unwrap().id,
        successor.id
    );
    assert_eq!(
        resumed
            .issue_self(NEW, "identity", None, NOW + 60, NOW)
            .await
            .unwrap()
            .0
            .id,
        successor.id
    );
    assert_eq!(
        rotated
            .store
            .identity()
            .get_key(&retired.id)
            .await
            .unwrap()
            .unwrap(),
        retired,
        "rotation tombstone remains historical evidence"
    );
}

struct UnknownUsage {
    inner: Arc<dyn PersistenceBackend>,
    fail: AtomicBool,
    fail_key: AtomicBool,
    pending: Mutex<Option<PendingId>>,
}
impl PersistenceBackend for UnknownUsage {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.inner.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        self.inner.scan(request)
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.inner.clock(dataset)
    }
    fn commit(&self, candidate: PreparedCandidate) -> Call<'_, NativeDecision> {
        Box::pin(async move {
            let fail_key = self.fail_key.load(Ordering::SeqCst);
            let target = candidate.candidate().mutations.iter().any(|mutation| {
                let busbar_contract::persistence::Mutation::Put { address, .. } = mutation else {
                    return false;
                };
                if fail_key {
                    address.namespace == crate::governance::persistence::identity::NAMESPACE.0
                        && address.key.first() == Some(&b'K')
                } else {
                    address.key.first() == Some(&b'U')
                }
            });
            let id = PendingId(candidate.candidate().id.operation);
            let result = self.inner.commit(candidate).await?;
            if target
                && self.fail.swap(false, Ordering::SeqCst)
                && matches!(result, NativeDecision::Applied(_))
            {
                *self.pending.lock().unwrap() = Some(id);
                return Err(Failure::Unknown);
            }
            Ok(result)
        })
    }
}

struct ArmedFault {
    core: Arc<CoreStore>,
    backend: Arc<UnknownUsage>,
}
impl Fixture {
    fn fault(&self, fail_key: bool) -> ArmedFault {
        self.backend.fail_key.store(fail_key, Ordering::SeqCst);
        self.backend.fail.store(true, Ordering::SeqCst);
        ArmedFault {
            core: self.store.clone(),
            backend: self.backend.clone(),
        }
    }
}
impl ArmedFault {
    async fn apply(
        &self,
        plan: &Plan,
        attestation: &ColdAttestation,
        overlay: &OverlayStore,
        now: u64,
        effective: &str,
    ) -> Result<(), String> {
        let result = super::apply(
            plan,
            attestation,
            self.core.clone(),
            overlay,
            now,
            effective,
        )
        .await;
        // Model the test operator's externally settled backend before obtaining
        // another attestation: replay exactly the retained native attempt first.
        let pending = self.backend.pending.lock().unwrap().take();
        if let Some(pending) = pending {
            assert!(matches!(self.core.retry(pending).await.unwrap().result,
                crate::persistence::commit::SubmitResult::Decided(decision) if matches!(*decision, NativeDecision::Applied(_))));
        }
        result
    }
}

#[tokio::test]
async fn cold_principal_transition_pending_or_unknown_outcome_refuses_serving() {
    for fail_key in [false, true] {
        let f = Fixture::new().await;
        let plan = f.plan().await;
        let attestation = f.attest(&plan, 1);
        let fault = f.fault(fail_key);
        assert!(fault
            .apply(&plan, &attestation, &f.overlay, NOW, &sha())
            .await
            .is_err());
        assert_eq!(
            f.store
                .ledger()
                .get_usage(&plan.carry[0].destination, plan.carry[0].window)
                .await
                .unwrap(),
            plan.carry[0].raw,
            "unknown reply may have committed"
        );
        assert!(guard(f.store.clone(), &sha(), &[]).await.is_err());
        assert!(pending_guard(f.store.clone()).await.is_err());
        let authorization = next_artifact(&f, &plan);
        assert!(
            super::reauthorize(
                &authorization,
                f.store.clone(),
                &sha(),
                &authorization.requirements
            )
            .await
            .is_err(),
            "reauthorization cannot release a pending migration"
        );
        assert!(apply(
            &plan,
            &attestation,
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha()
        )
        .await
        .unwrap_err()
        .contains("already consumed"));
        let mut changed: Plan = serde_json::from_value(
            serde_json::to_value(plan.authoring(&crate::seal::acquire())).unwrap(),
        )
        .unwrap();
        changed.specification.id.push('x');
        assert!(apply(
            &changed,
            &f.attest(&changed, 2),
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha()
        )
        .await
        .is_err());
        apply(
            &plan,
            &f.attest(&plan, 2),
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha(),
        )
        .await
        .unwrap();
        verify(&plan, f.store.clone(), &f.overlay, NOW)
            .await
            .unwrap();
        for c in &plan.carry {
            assert_eq!(
                f.store
                    .ledger()
                    .get_usage(&c.destination, c.window)
                    .await
                    .unwrap(),
                c.raw
            );
        }
    }
}

#[tokio::test]
async fn cold_principal_transition_rejects_ambiguous_or_conflicting_mapping_before_write() {
    let f = Fixture::new().await;
    for variant in 0..5 {
        let mut spec = f.spec();
        match variant {
            0 => spec.bindings.push(spec.bindings[0].clone()),
            1 => spec.bindings[0].new_principal = "x".repeat(252),
            2 => spec.bindings[0].historical_provenance_sha256.clear(),
            3 => spec.bindings[0].provider = "other".into(),
            _ => spec.complete_legacy_inventory_sha256.clear(),
        }
        assert!(prepare(spec, f.store.clone(), f.groups.clone(), None)
            .await
            .is_err());
        assert!(read_head(&TestRows(f.store.clone()))
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            f.store
                .identity()
                .get_key("vk_retained")
                .await
                .unwrap()
                .unwrap()
                .idp_subject
                .as_deref(),
            Some(OLD)
        );
    }
    for state in 0..4 {
        let mut observed = Fixture::new().await;
        let other = VirtualKey {
            id: "vk_omitted_B".into(),
            generation_hash: binding_marker("vk_omitted_B", "0"),
            enabled: state != 1,
            group: Some(group("omitted-B")),
            idp_subject: Some("omitted-B".into()),
            idp_provider: Some("identity".into()),
            binding_mode: Some(crate::governance::SELF_KEY_BINDING_MODE.into()),
            ..Default::default()
        };
        observed.store.identity().put_key(&other).await.unwrap();
        if state == 2 {
            observed
                .store
                .identity()
                .add_denylist(&other.id, "revoked B")
                .await
                .unwrap();
        }
        if state == 3 {
            observed
                .store
                .identity()
                .delete_key(&other.id)
                .await
                .unwrap();
        }
        observed
            .groups
            .insert(group("omitted-B"), observed.groups[&group(OLD)].clone());
        let before = observed.store.identity().list_keys().await.unwrap();
        let error = prepare(
            observed.spec(),
            observed.store.clone(),
            observed.groups.clone(),
            None,
        )
        .await
        .unwrap_err();
        assert!(
            error.contains("omitted"),
            "unmapped observed B must fail even with a syntactically valid complete-inventory digest: {error}"
        );
        assert_eq!(observed.store.identity().list_keys().await.unwrap(), before);
        assert!(read_head(&TestRows(observed.store.clone()))
            .await
            .unwrap()
            .is_none());
    }
    let mut orphan = Fixture::new().await;
    orphan
        .groups
        .insert(group("orphan-B"), orphan.groups[&group(OLD)].clone());
    assert!(prepare(
        orphan.spec(),
        orphan.store.clone(),
        orphan.groups.clone(),
        None
    )
    .await
    .unwrap_err()
    .contains("omitted"));
    f.store.ledger().put_usage(NEW, 0, &raw()).await.unwrap();
    assert!(prepare(f.spec(), f.store.clone(), f.groups.clone(), None)
        .await
        .is_err());
    assert!(f.overlay.read_required_async().await.unwrap().is_none());
}

#[tokio::test]
async fn cold_principal_transition_does_not_rewrite_history_or_replay_old_secrets() {
    let f = Fixture::new().await;
    let delta: MeteringDelta = serde_json::from_value(serde_json::json!({
        "scale":6,"key_id":"vk_retained","bucket":NOW / 86400 * 86400,
        "model":"historical:model","provider":"historical-provider",
        "tokens_input":10_000_001,"tokens_output":3,"tokens_cache_read":0,"tokens_cache_write":0,
        "requests":9,"billable_requests":7,"key_group_at_use":group(OLD),
        "pricing_version":"original-era","priced_from_ms":9001,
        "usage_units":{"opaque:class":9007199254740993u64}
    }))
    .unwrap();
    f.store.ledger().add_metering(&delta).await.unwrap();
    let metering_before = f.store.ledger().list_metering(delta.bucket).await.unwrap();
    let history=RecordBytes::new(br#"{"actor":"historic-subject","secret":"old-once-secret","group":"user:historic-subject"}"#.to_vec()).unwrap();
    for schema in [
        "test.historical-audit",
        "test.old-admin-replay",
        "test.metering-history",
    ] {
        TestRows(f.store.clone())
            .record_put(RecordSchemaId::new(schema), OLD.as_bytes(), &history)
            .await
            .unwrap();
    }
    let plan = f.plan().await;
    f.apply(&plan).await;
    assert_eq!(
        f.store.ledger().list_metering(delta.bucket).await.unwrap(),
        metering_before,
        "carried enforcement baseline must not become billable traffic"
    );
    for schema in [
        "test.historical-audit",
        "test.old-admin-replay",
        "test.metering-history",
    ] {
        assert_eq!(
            TestRows(f.store.clone())
                .record_get(RecordSchemaId::new(schema), OLD.as_bytes())
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            history.as_slice()
        );
        assert!(TestRows(f.store.clone())
            .record_get(RecordSchemaId::new(schema), NEW.as_bytes())
            .await
            .unwrap()
            .is_none());
    }
}

#[tokio::test]
async fn cold_principal_transition_enumerates_exact_scoped_windows_and_eras() {
    let f = Fixture::new().await;
    let plan = f.plan().await;
    for period in ["total", "hour", "day", "month"] {
        let pairs: Vec<_> = plan.carry.iter().filter(|c| c.period == period).collect();
        assert!(pairs.len() >= 2);
        for c in &pairs {
            assert_eq!(c.window, crate::governance::budget_window(period, NOW));
        }
    }
    assert!(plan
        .carry
        .iter()
        .any(|c| c.source == "group:user:historic-subject@month#pool:opaque/a"));
    assert!(plan.carry.iter().any(|c| c.source
        == crate::governance::era_bucket("group:user:historic-subject@month#pool:opaque/a")));
    let before = f.store.identity().list_keys().await.unwrap();
    assert!(apply(
        &plan,
        &f.attest(&plan, 1),
        f.store.clone(),
        &f.overlay,
        NOW + 3600,
        &sha()
    )
    .await
    .unwrap_err()
    .contains("window"));
    assert_eq!(f.store.identity().list_keys().await.unwrap(), before);
    assert!(read_head(&TestRows(f.store.clone()))
        .await
        .unwrap()
        .is_none());
    // Unrelated configurations without a format requirement still boot. Active changed formats
    // cannot use an empty key scan as a fresh-namespace claim.
    assert!(guard(f.store.clone(), &sha(), &[]).await.is_ok());
    assert!(guard(f.store.clone(), &sha(), &f.spec().requirements)
        .await
        .is_err());
    let mut unsupported = f.groups.clone();
    unsupported.get_mut(&group(OLD)).unwrap().limits[3]
        .scope
        .as_mut()
        .unwrap()
        .kind = "agent".into();
    let error = prepare(f.spec(), f.store.clone(), unsupported, None)
        .await
        .unwrap_err();
    assert!(error.contains("lossless"));
    assert!(read_head(&TestRows(f.store.clone()))
        .await
        .unwrap()
        .is_none());

    // A pending transition crosses an hour/day/month. Resume SAME immutable plan under a new
    // quiescence receipt; capture and carry exact new active windows, including nonzero usage.
    let rolled = Fixture::new().await;
    let rolled_plan = rolled.plan().await;
    let fault = rolled.fault(false);
    assert!(fault
        .apply(
            &rolled_plan,
            &rolled.attest(&rolled_plan, 1),
            &rolled.overlay,
            NOW,
            &sha()
        )
        .await
        .is_err());
    let later = NOW + 40 * 86400;
    let active = addresses(
        &rolled_plan.specification,
        &rolled_plan.groups_before,
        later,
    )
    .unwrap();
    for (source, _, window, _) in &active {
        if !rolled_plan
            .carry
            .iter()
            .any(|carry| carry.source == *source && carry.window == *window)
        {
            rolled
                .store
                .ledger()
                .put_usage(source, *window, &raw())
                .await
                .unwrap();
        }
    }
    assert!(pending_guard(rolled.store.clone()).await.is_err());
    // A second lost reply after the rollover journal commits must also resume idempotently.
    let fault = rolled.fault(false);
    assert!(fault
        .apply(
            &rolled_plan,
            &rolled.attest(&rolled_plan, 2),
            &rolled.overlay,
            later,
            &sha()
        )
        .await
        .is_err());
    assert!(pending_guard(rolled.store.clone()).await.is_err());
    apply(
        &rolled_plan,
        &rolled.attest(&rolled_plan, 3),
        rolled.store.clone(),
        &rolled.overlay,
        later,
        &sha(),
    )
    .await
    .unwrap();
    verify(&rolled_plan, rolled.store.clone(), &rolled.overlay, later)
        .await
        .unwrap();
    for (source, destination, window, _) in active {
        assert_eq!(
            rolled
                .store
                .ledger()
                .get_usage(&destination, window)
                .await
                .unwrap(),
            rolled
                .store
                .ledger()
                .get_usage(&source, window)
                .await
                .unwrap()
        );
    }
    for carry in &rolled_plan.carry {
        assert_eq!(
            rolled
                .store
                .ledger()
                .get_usage(&carry.source, carry.window)
                .await
                .unwrap(),
            carry.raw
        );
        assert_eq!(
            rolled
                .store
                .ledger()
                .get_usage(&carry.destination, carry.window)
                .await
                .unwrap(),
            carry.raw
        );
    }
    let (head, _) = read_head(&TestRows(rolled.store.clone()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        head.plan_sha256,
        digest(&rolled_plan.authoring(&crate::seal::acquire())).unwrap()
    );
    assert!(head.rollover.is_some());
    assert!(!head.extra_carry.is_empty());

    let fresh = crate::real_store::core().await;
    let rows = TestRows(fresh.clone());
    rows.record_put(
        RecordSchemaId::new("test.creation"),
        b"fresh",
        &RecordBytes::new(b"external-provisioner-owned-new-namespace".to_vec()).unwrap(),
    )
    .await
    .unwrap();
    let required = f.spec().requirements;
    assert!(
        guard(fresh.clone(), &sha(), &required).await.is_err(),
        "empty key scan establishes no baseline"
    );
    let receipt = super::FreshNamespace {
        witness_binding: Some(test_witness_binding()),
        version: 2,
        store_config_sha256: sha(),
        requirements: required.clone(),
        ephemeral_instance: false,
        exclusive_instance: false,
        witness: Some(StoreWitness {
            schema: "test.creation".into(),
            key_hex: hex::encode(b"fresh"),
            value_hex: hex::encode(b"external-provisioner-owned-new-namespace"),
        }),
        creation_evidence_sha256: sha(),
        newly_created_namespace: true,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "test namespace provisioner".into(),
        reason: "fresh actual Store; witness is the only completed setup write".into(),
    };
    super::initialize_fresh(&receipt, fresh.clone(), &sha(), &required)
        .await
        .unwrap();
    assert!(guard(fresh.clone(), &sha(), &required)
        .await
        .unwrap()
        .is_empty());
    let mut changed = required.clone();
    changed[0].provider = "renamed-provider".into();
    assert!(guard(fresh.clone(), &sha(), &changed).await.is_err());
    let mut removed = required.clone();
    removed[0].format.clear();
    assert!(guard(fresh.clone(), &sha(), &removed).await.is_err());
    assert!(guard(fresh.clone(), &sha(), &[]).await.is_err());
    let mut unrelated = required.clone();
    unrelated[1].settings_sha256 = "e".repeat(64);
    unrelated[1].provider = "renamed-unrelated-admin-token".into();
    assert!(guard(fresh.clone(), &sha(), &unrelated).await.is_ok());
    unrelated.pop();
    assert!(guard(fresh.clone(), &sha(), &unrelated).await.is_ok());
    let mut added_marked = required.clone();
    added_marked[1].format = "another-format".into();
    added_marked[1].domain_sha256 = sha();
    assert!(
        guard(fresh.clone(), &sha(), &added_marked).await.is_err(),
        "every current marked domain requires a matching receipt"
    );
    let baseline = digest(&receipt).unwrap();
    let mut next = required.clone();
    next[0].product_sha256 = "b".repeat(64);
    next[0].settings_sha256 = "c".repeat(64);
    assert!(
        guard(fresh.clone(), &sha(), &next).await.is_ok(),
        "ordinary artifact/non-domain settings updates preserve identity"
    );
    let mut domain_change = next.clone();
    domain_change[0].domain_sha256 = "d".repeat(64);
    assert!(guard(fresh.clone(), &sha(), &domain_change).await.is_err());
    let mut plugin_change = next.clone();
    plugin_change[0].plugin = "other.auth".into();
    assert!(guard(fresh.clone(), &sha(), &plugin_change).await.is_err());
    let mut authorization = super::Reauthorization {
        witness_binding: Some(test_witness_binding()),
        version: 2,
        baseline_sha256: baseline.clone(),
        previous_requirements_sha256: digest(&required).unwrap(),
        requirements: next.clone(),
        identity_outputs_unchanged: true,
        continuity_evidence_sha256: sha(),
        witness: StoreWitness {
            schema: "test.creation".into(),
            key_hex: hex::encode(b"fresh"),
            value_hex: hex::encode(b"external-provisioner-owned-new-namespace"),
        },
        attestation: ColdAttestation {
            version: 1,
            epoch: hex::encode([19u8; 16]),
            plan_sha256: baseline,
            sender_quiesced: true,
            backend_quiesced: true,
            recovery_and_corrections_settled: true,
            actor: "operator".into(),
            reason: "audited new artifact preserves all principal outputs".into(),
        },
    };
    authorization.identity_outputs_unchanged = false;
    assert!(
        super::reauthorize(&authorization, fresh.clone(), &sha(), &next)
            .await
            .is_err()
    );
    authorization.identity_outputs_unchanged = true;
    authorization.requirements = changed.clone();
    assert!(
        super::reauthorize(&authorization, fresh.clone(), &sha(), &changed)
            .await
            .is_err()
    );
    authorization.requirements = next.clone();
    authorization.previous_requirements_sha256 = "b".repeat(64);
    assert!(
        super::reauthorize(&authorization, fresh.clone(), &sha(), &next)
            .await
            .is_err()
    );
    authorization.previous_requirements_sha256 = digest(&required).unwrap();
    authorization.witness.value_hex = hex::encode(b"wrong namespace");
    assert!(
        super::reauthorize(&authorization, fresh.clone(), &sha(), &next)
            .await
            .is_err()
    );
    authorization.witness.value_hex = hex::encode(b"external-provisioner-owned-new-namespace");
    // A definitive condition conflict consumes the op ID; changing the body requires a fresh
    // receipt identity, represented here by a new operator quiescence epoch.
    authorization.attestation.epoch = hex::encode([20u8; 16]);
    super::reauthorize(&authorization, fresh.clone(), &sha(), &next)
        .await
        .unwrap();
    assert!(guard(fresh.clone(), &sha(), &next).await.is_ok());
    assert!(guard(fresh.clone(), &sha(), &required).await.is_ok());
    assert!(
        super::initialize_fresh(&receipt, fresh.clone(), &sha(), &required)
            .await
            .is_err(),
        "baseline must not overwrite retained state"
    );
}

#[test]
fn principal_domain_metadata_is_strict_non_secret_and_only_tracks_identity_fields() {
    use serde_json::json;
    let schema = json!({super::DOMAIN_ANNOTATION: [
        {"pointer":"/issuer", "required":true},
        {"pointer":"/audience", "required":true},
        {"pointer":"/client_id", "required":false}
    ]});
    let settings = json!({"issuer":"exact issuer", "audience":"exact audience", "ttl":5});
    let fingerprint = |s: &serde_json::Value| {
        super::domain_fingerprint(
            &schema,
            &crate::config::secret::test_settings_value(s),
            &["client_secret".into()],
        )
    };
    let before = fingerprint(&settings).unwrap();
    let mut next = settings.clone();
    next["ttl"] = json!(60);
    next["client_id"] = serde_json::Value::Null;
    assert_eq!(before, fingerprint(&next).unwrap());
    for field in ["issuer", "audience", "client_id"] {
        let mut changed = settings.clone();
        changed[field] = json!("different");
        assert_ne!(before, fingerprint(&changed).unwrap());
    }
    for field in ["issuer", "audience"] {
        let mut changed = settings.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(fingerprint(&changed).is_err());
        changed[field] = serde_json::Value::Null;
        assert!(fingerprint(&changed).is_err());
    }
    for declaration in [
        json!([]),
        json!([{"pointer":"/issuer"}]),
        json!([{"pointer":"issuer","required":true}]),
        json!([{"pointer":"/bad~2escape","required":false}]),
        json!([{"pointer":"/issuer","required":true,"extra":1}]),
        json!([{"pointer":"/issuer","required":true},{"pointer":"/issuer","required":false}]),
    ] {
        assert!(super::domain_fingerprint(
            &json!({super::DOMAIN_ANNOTATION: declaration}),
            &crate::config::secret::test_settings_value(&settings),
            &[]
        )
        .is_err());
    }
    assert!(super::domain_fingerprint(
        &json!({}),
        &crate::config::secret::test_settings_value(&settings),
        &[]
    )
    .is_err());
    let mut reordered = schema.clone();
    reordered[super::DOMAIN_ANNOTATION]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_ne!(
        before,
        super::domain_fingerprint(
            &reordered,
            &crate::config::secret::test_settings_value(&settings),
            &[]
        )
        .unwrap()
    );
    for (pointer, secret) in [
        ("/issuer", "issuer"),
        ("/issuer/name", "issuer"),
        ("/issuer", "issuer.name"),
        ("/issuers/0/name", "issuers.*.name"),
        ("/a~1b/~0name", "a/b.~name"),
    ] {
        let declaration = json!({super::DOMAIN_ANNOTATION:[{"pointer":pointer,"required":false}]});
        assert!(super::domain_fingerprint(
            &declaration,
            &crate::config::secret::test_settings_value(&settings),
            &[secret.into()]
        )
        .is_err());
    }
    let mut unresolved = settings.clone();
    unresolved["issuer"] = json!({"module":"fixture-source","settings":{"slot":"ISSUER"}});
    assert!(fingerprint(&unresolved).is_err());
    unresolved["issuer"] =
        json!({"nested":[{"module":"fixture-source","settings":{"slot":"ISSUER"}}]});
    assert!(fingerprint(&unresolved).is_err());
}

#[test]
fn principal_digests_canonicalize_nested_objects_even_with_preserve_order() {
    let store_a: serde_json::Value = serde_json::from_str(
        r#"{"module":"opaque-store","settings":{"z":1,"nested":{"b":2,"a":1}}}"#,
    )
    .unwrap();
    let store_b: serde_json::Value = serde_json::from_str(
        r#"{"settings":{"nested":{"a":1,"b":2},"z":1},"module":"opaque-store"}"#,
    )
    .unwrap();
    let authoring_seal = crate::seal::acquire();
    let typed: Option<crate::config::StoreCfg> = serde_json::from_value(store_a.clone()).unwrap();
    assert_eq!(
        super::store_fingerprint(&typed.as_ref().map(|store| store.authoring(&authoring_seal)))
            .unwrap(),
        super::store_fingerprint(&store_b).unwrap()
    );
    assert_eq!(
        super::store_fingerprint(&store_a).unwrap(),
        super::store_fingerprint(&store_b).unwrap()
    );
    // Parsing retains opposite insertion order when the assembled product enables preserve_order.
    let a: serde_json::Value =
        serde_json::from_str(r#"{"z":[{"b":2,"a":1}],"a":{"d":4,"c":3}}"#).unwrap();
    let b: serde_json::Value =
        serde_json::from_str(r#"{"a":{"c":3,"d":4},"z":[{"a":1,"b":2}]}"#).unwrap();
    assert_eq!(
        super::canonical_bytes(&a).unwrap(),
        super::canonical_bytes(&b).unwrap()
    );
    assert_eq!(digest(&a).unwrap(), digest(&b).unwrap());
    let schema =
        serde_json::json!({super::DOMAIN_ANNOTATION:[{"pointer":"/domain","required":true}]});
    assert_eq!(
        super::domain_fingerprint(
            &schema,
            &crate::config::secret::test_settings_value(&serde_json::json!({"domain":a})),
            &[]
        )
        .unwrap(),
        super::domain_fingerprint(
            &schema,
            &crate::config::secret::test_settings_value(&serde_json::json!({"domain":b})),
            &[]
        )
        .unwrap()
    );
}

fn creation_receipt(f: &Fixture, requirements: Vec<Requirement>) -> super::FreshNamespace {
    super::FreshNamespace {
        witness_binding: Some(test_witness_binding()),
        version: 2,
        store_config_sha256: sha(),
        requirements,
        witness: Some(f.spec().witness),
        ephemeral_instance: false,
        exclusive_instance: false,
        creation_evidence_sha256: sha(),
        newly_created_namespace: true,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "fixture namespace creator".into(),
        reason: "this test exclusively created this namespace and its setup records".into(),
    }
}

#[tokio::test]
async fn completed_baseline_and_migration_support_attested_successors_without_losing_history_or_holds(
) {
    for migrated in [false, true] {
        let f = Fixture::new().await;
        let mut key = f
            .store
            .identity()
            .get_key("vk_retained")
            .await
            .unwrap()
            .unwrap();
        key.enabled = false;
        f.store.identity().put_key(&key).await.unwrap();
        let mut groups = f.groups.clone();
        let (from, to, overlay) = if migrated {
            let mut retired = key.clone();
            retired.id = "vk_historical_tombstone".into();
            retired.deleted_at = Some(NOW - 5);
            f.store.identity().put_key(&retired).await.unwrap();
            let first = f.plan().await;
            f.apply(&first).await;
            let overlay = super::after_overlay(&first).unwrap();
            groups.extend(overlay.groups.clone());
            // The immutable hold must survive even if a later operator re-enables this row.
            let mut live = f
                .store
                .identity()
                .get_key("vk_retained")
                .await
                .unwrap()
                .unwrap();
            live.enabled = true;
            f.store.identity().put_key(&live).await.unwrap();
            (
                NEW,
                "opaque-format:second-domain:historic-subject",
                Some(overlay),
            )
        } else {
            let receipt = creation_receipt(&f, f.spec().requirements);
            super::initialize_fresh(&receipt, f.store.clone(), &sha(), &receipt.requirements)
                .await
                .unwrap();
            (OLD, NEW, None)
        };
        let rows = TestRows(f.store.clone());
        let (old_head, old_bytes) = read_head(&rows).await.unwrap().unwrap();
        let old_body = snapshot_body(
            &rows,
            &super::body_prefix(&old_head.plan_sha256),
            old_head.length,
        )
        .await
        .unwrap();
        let old_digest = super::receipt_head_digest(f.store.clone())
            .await
            .unwrap()
            .unwrap();
        let mut spec = f.spec();
        spec.id = "explicit-next-identity-domain".into();
        spec.bindings[0].old_principal = from.into();
        spec.bindings[0].new_principal = to.into();
        spec.requirements[0].domain_sha256 = "b".repeat(64);
        assert!(guard(f.store.clone(), &sha(), &spec.requirements)
            .await
            .is_err());
        let mut plan = prepare(spec, f.store.clone(), groups, overlay)
            .await
            .unwrap();
        assert_eq!(plan.previous.as_ref().unwrap().head_sha256, old_digest);
        let original = plan.previous.as_ref().unwrap().head_sha256.clone();
        plan.previous.as_mut().unwrap().head_sha256 = "f".repeat(64);
        assert!(
            super::check(&plan, f.store.clone(), &f.overlay, NOW, &sha())
                .await
                .is_err()
        );
        assert_eq!(read_head(&rows).await.unwrap().unwrap().1, old_bytes);
        plan.previous.as_mut().unwrap().head_sha256 = original;
        let lost = f.fault(false);
        assert!(lost
            .apply(&plan, &f.attest(&plan, 31), &f.overlay, NOW, &sha())
            .await
            .is_err());
        assert!(pending_guard(f.store.clone()).await.is_err());
        assert!(guard(f.store.clone(), &sha(), &[]).await.is_err());
        assert!(prepare(f.spec(), f.store.clone(), f.groups.clone(), None)
            .await
            .is_err());
        assert_eq!(
            rows.record_get(super::SCHEMA, format!("ancestor:{old_digest}").as_bytes())
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            old_bytes
        );
        assert_eq!(
            snapshot_body(
                &rows,
                &super::body_prefix(&old_head.plan_sha256),
                old_head.length
            )
            .await
            .unwrap(),
            old_body
        );
        apply(
            &plan,
            &f.attest(&plan, 32),
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha(),
        )
        .await
        .unwrap();
        verify(&plan, f.store.clone(), &f.overlay, NOW)
            .await
            .unwrap();
        let held = guard(f.store.clone(), &sha(), &plan.specification.requirements)
            .await
            .unwrap();
        assert!(held.contains(to));
        if migrated {
            assert!(held.contains(NEW));
        }
        let gov = GovState::new_with_core(f.store.clone(), None, Some(signer()))
            .await
            .unwrap();
        gov.install_transition_self_holds(held);
        assert!(gov
            .issue_self(to, "identity", None, NOW + 60, NOW)
            .await
            .is_err());
        let after = f
            .store
            .identity()
            .get_key("vk_retained")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after.idp_subject.as_deref(), Some(to));
        assert_eq!(after.generation_hash, key.generation_hash);
        for carry in &plan.carry {
            assert_eq!(
                f.store
                    .ledger()
                    .get_usage(&carry.destination, carry.window)
                    .await
                    .unwrap(),
                carry.raw
            );
            assert_eq!(
                f.store
                    .ledger()
                    .get_usage(&carry.source, carry.window)
                    .await
                    .unwrap(),
                carry.raw
            );
        }
        assert_eq!(
            f.store
                .ledger()
                .get_usage("group:shared@total", 0)
                .await
                .unwrap()
                .requests,
            73
        );
        let (final_head, _) = read_head(&rows).await.unwrap().unwrap();
        assert_eq!(final_head.depth, 2);
        assert_eq!(
            snapshot_body(
                &rows,
                &super::body_prefix(&old_head.plan_sha256),
                old_head.length
            )
            .await
            .unwrap(),
            old_body
        );
        assert_eq!(
            rows.record_get(super::SCHEMA, format!("ancestor:{old_digest}").as_bytes())
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
            old_bytes
        );
    }
}

#[tokio::test]
async fn unrelated_retained_self_group_requires_exact_unaffected_provenance_and_stays_unchanged() {
    let mut f = Fixture::new().await;
    let principal = "unrelated-static-subject";
    let name = group(principal);
    let mut key = f
        .store
        .identity()
        .get_key("vk_retained")
        .await
        .unwrap()
        .unwrap();
    key.id = "vk_unrelated_static".into();
    key.idp_subject = Some(principal.into());
    key.idp_provider = Some("operator-token".into());
    key.group = Some(name.clone());
    f.store.identity().put_key(&key).await.unwrap();
    let key = f.store.identity().get_key(&key.id).await.unwrap().unwrap();
    f.groups.insert(name.clone(), f.groups[&group(OLD)].clone());
    let unrelated_usage = "group:user:unrelated-static-subject@total";
    f.store
        .ledger()
        .put_usage(unrelated_usage, 0, &raw())
        .await
        .unwrap();
    assert!(prepare(f.spec(), f.store.clone(), f.groups.clone(), None)
        .await
        .is_err());
    let mut spec = f.spec();
    spec.unaffected.push(super::UnaffectedPrincipal {
        principal: principal.into(),
        provider: "operator-token".into(),
        requirement_sha256: digest(&spec.requirements[1]).unwrap(),
        keys_sha256: digest(&vec![&key]).unwrap(),
        group_sha256: digest(&f.groups.get(&name)).unwrap(),
        provenance_sha256: sha(),
    });
    spec.unaffected[0].provenance_sha256.clear();
    assert!(prepare(
        serde_json::from_value(serde_json::to_value(&spec).unwrap()).unwrap(),
        f.store.clone(),
        f.groups.clone(),
        None
    )
    .await
    .is_err());
    spec.unaffected[0].provenance_sha256 = sha();
    spec.unaffected[0].keys_sha256 = "f".repeat(64);
    assert!(prepare(
        serde_json::from_value(serde_json::to_value(&spec).unwrap()).unwrap(),
        f.store.clone(),
        f.groups.clone(),
        None
    )
    .await
    .is_err());
    spec.unaffected[0].keys_sha256 = digest(&vec![&key]).unwrap();
    let plan = prepare(spec, f.store.clone(), f.groups.clone(), None)
        .await
        .unwrap();
    let mut forged: Plan = serde_json::from_value(
        serde_json::to_value(plan.authoring(&crate::seal::acquire())).unwrap(),
    )
    .unwrap();
    forged.specification.unaffected[0].provider = "identity".into();
    assert!(super::validate_plan(&forged).is_err());
    forged = serde_json::from_value(
        serde_json::to_value(plan.authoring(&crate::seal::acquire())).unwrap(),
    )
    .unwrap();
    forged
        .groups_before
        .insert(group("orphan"), GroupCfg::default());
    assert!(super::validate_plan(&forged).is_err());
    f.apply(&plan).await;
    assert_eq!(
        f.store.identity().get_key(&key.id).await.unwrap().unwrap(),
        key
    );
    assert_eq!(
        f.store
            .ledger()
            .get_usage(unrelated_usage, 0)
            .await
            .unwrap(),
        raw()
    );
    assert_eq!(super::after_overlay(&plan).unwrap().groups.get(&name), None);
}

#[tokio::test]
async fn explicit_ephemeral_creation_requires_attestation_durability_and_absent_head() {
    let f = Fixture::new().await;
    let mut receipt = creation_receipt(&f, f.spec().requirements);
    receipt.witness = None;
    assert!(
        super::initialize_fresh(&receipt, f.store.clone(), &sha(), &receipt.requirements)
            .await
            .is_err()
    );
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .await
    .is_err());
    receipt.ephemeral_instance = true;
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .await
    .is_err());
    receipt.exclusive_instance = true;
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        false
    )
    .await
    .is_err());
    receipt.newly_created_namespace = false;
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .await
    .is_err());
    assert!(read_head(&TestRows(f.store.clone()))
        .await
        .unwrap()
        .is_none());
    receipt.newly_created_namespace = true;
    super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true,
    )
    .await
    .unwrap();
    assert!(guard(f.store.clone(), &sha(), &receipt.requirements)
        .await
        .is_ok());
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .await
    .is_err());
    let reloaded = crate::real_store::core().await;
    assert!(
        guard(reloaded, &sha(), &receipt.requirements)
            .await
            .is_err(),
        "a new instance does not inherit the explicit creation claim"
    );
}

#[tokio::test]
async fn ephemeral_creation_cannot_replace_a_pending_transition() {
    let f = Fixture::new().await;
    let plan = f.plan().await;
    let lost = f.fault(false);
    assert!(lost
        .apply(&plan, &f.attest(&plan, 55), &f.overlay, NOW, &sha())
        .await
        .is_err());
    let before = read_head(&TestRows(f.store.clone()))
        .await
        .unwrap()
        .unwrap()
        .1;
    let mut receipt = creation_receipt(&f, f.spec().requirements);
    receipt.witness = None;
    receipt.ephemeral_instance = true;
    receipt.exclusive_instance = true;
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .await
    .is_err());
    assert_eq!(
        read_head(&TestRows(f.store.clone()))
            .await
            .unwrap()
            .unwrap()
            .1,
        before
    );
    assert!(pending_guard(f.store.clone()).await.is_err());
}

#[tokio::test]
async fn successor_rejects_omitted_predecessor_hold_without_any_key_or_group() {
    let f = Fixture::new().await;
    let old_b = "denied-without-retained-record";
    let second_b = "opaque-format:first-domain:denied-without-record";
    let third_b = "opaque-format:second-domain:denied-without-record";
    f.store
        .identity()
        .add_denylist(old_b, "historical principal revocation")
        .await
        .unwrap();
    let mut spec = f.spec();
    let mut b = spec.bindings[0].clone();
    b.old_principal = old_b.into();
    b.new_principal = second_b.into();
    spec.bindings.push(b);
    let first = prepare(spec, f.store.clone(), f.groups.clone(), None)
        .await
        .unwrap();
    f.apply(&first).await;
    assert!(
        guard(f.store.clone(), &sha(), &first.specification.requirements)
            .await
            .unwrap()
            .contains(second_b)
    );
    assert!(f
        .store
        .identity()
        .list_keys()
        .await
        .unwrap()
        .iter()
        .all(|key| key.idp_subject.as_deref() != Some(second_b)));
    let overlay = super::after_overlay(&first).unwrap();
    let mut groups = f.groups.clone();
    groups.extend(overlay.groups.clone());
    let before = read_head(&TestRows(f.store.clone()))
        .await
        .unwrap()
        .unwrap()
        .1;
    let mut next = f.spec();
    next.requirements[0].domain_sha256 = "b".repeat(64);
    next.bindings[0].old_principal = NEW.into();
    next.bindings[0].new_principal = "opaque-format:second-domain:historic-subject".into();
    let partial = serde_json::from_value(serde_json::to_value(&next).unwrap()).unwrap();
    assert!(
        prepare(
            partial,
            f.store.clone(),
            groups.clone(),
            Some(overlay.clone())
        )
        .await
        .is_err(),
        "known keyless predecessor hold B must not be omitted from a changed domain"
    );
    assert_eq!(
        read_head(&TestRows(f.store.clone()))
            .await
            .unwrap()
            .unwrap()
            .1,
        before
    );
    let mut b = next.bindings[0].clone();
    b.old_principal = second_b.into();
    b.new_principal = third_b.into();
    next.bindings.push(b);
    let second = prepare(next, f.store.clone(), groups, Some(overlay))
        .await
        .unwrap();
    apply(
        &second,
        &f.attest(&second, 61),
        f.store.clone(),
        &f.overlay,
        NOW,
        &sha(),
    )
    .await
    .unwrap();
    let held = guard(f.store.clone(), &sha(), &second.specification.requirements)
        .await
        .unwrap();
    assert!(held.contains(second_b));
    assert!(held.contains(third_b));
    let gov = GovState::new_with_core(f.store.clone(), None, Some(signer()))
        .await
        .unwrap();
    gov.install_transition_self_holds(held);
    assert!(gov
        .issue_self(third_b, "identity", None, NOW + 60, NOW)
        .await
        .is_err());
    assert!(gov
        .refresh_self(third_b, "identity", None, NOW + 60, NOW)
        .await
        .is_err());
    assert!(!gov.self_mint_holds.load(Ordering::Relaxed));
}

#[tokio::test]
async fn successor_rejects_unaffected_tombstone_as_automatically_migrated_history() {
    let f = Fixture::new().await;
    let b = VirtualKey {
        id: "vk_unaffected_tombstone_b".into(),
        enabled: false,
        deleted_at: Some(NOW - 5),
        idp_provider: Some("operator-token".into()),
        idp_subject: Some("old-static-b".into()),
        group: None,
        ..Default::default()
    };
    f.store.identity().put_key(&b).await.unwrap();
    let b = f.store.identity().get_key(&b.id).await.unwrap().unwrap();
    let mut spec = f.spec();
    spec.unaffected.push(super::UnaffectedPrincipal {
        principal: "old-static-b".into(),
        provider: "operator-token".into(),
        requirement_sha256: digest(&spec.requirements[1]).unwrap(),
        keys_sha256: digest(&vec![&b]).unwrap(),
        group_sha256: digest(&Option::<GroupCfg>::None).unwrap(),
        provenance_sha256: sha(),
    });
    let first = prepare(spec, f.store.clone(), f.groups.clone(), None)
        .await
        .unwrap();
    f.apply(&first).await;
    let overlay = super::after_overlay(&first).unwrap();
    let mut groups = f.groups.clone();
    groups.extend(overlay.groups.clone());
    let c = VirtualKey {
        id: "vk_new_static_c".into(),
        enabled: true,
        idp_provider: Some("operator-token".into()),
        idp_subject: Some("old-static-c".into()),
        group: None,
        ..Default::default()
    };
    f.store.identity().put_key(&c).await.unwrap();
    let a = f
        .store
        .identity()
        .get_key("vk_retained")
        .await
        .unwrap()
        .unwrap();
    let mut next = f.spec();
    next.requirements[1].format = "opaque-static-v2".into();
    next.requirements[1].domain_sha256 = "b".repeat(64);
    next.requirements[1].product_sha256 = sha();
    next.bindings[0].provider = "operator-token".into();
    next.bindings[0].old_principal = "old-static-c".into();
    next.bindings[0].new_principal = "opaque-static-v2:c".into();
    next.unaffected.push(super::UnaffectedPrincipal {
        principal: NEW.into(),
        provider: "identity".into(),
        requirement_sha256: digest(&next.requirements[0]).unwrap(),
        keys_sha256: digest(&vec![&a]).unwrap(),
        group_sha256: digest(&groups.get(&group(NEW))).unwrap(),
        provenance_sha256: sha(),
    });
    let before = read_head(&TestRows(f.store.clone()))
        .await
        .unwrap()
        .unwrap()
        .1;
    let partial = serde_json::from_value(serde_json::to_value(&next).unwrap()).unwrap();
    assert!(
        prepare(
            partial,
            f.store.clone(),
            groups.clone(),
            Some(overlay.clone())
        )
        .await
        .is_err(),
        "a previously unaffected tombstone was never migrated and cannot bypass current inventory coverage"
    );
    assert_eq!(
        read_head(&TestRows(f.store.clone()))
            .await
            .unwrap()
            .unwrap()
            .1,
        before
    );
    let mut mapping = next.bindings[0].clone();
    mapping.old_principal = "old-static-b".into();
    mapping.new_principal = "opaque-static-v2:b".into();
    next.bindings.push(mapping);
    let second = prepare(next, f.store.clone(), groups, Some(overlay))
        .await
        .unwrap();
    apply(
        &second,
        &f.attest(&second, 62),
        f.store.clone(),
        &f.overlay,
        NOW,
        &sha(),
    )
    .await
    .unwrap();
    assert_eq!(f.store.identity().get_key(&b.id).await.unwrap().unwrap(), b);
    let held = guard(f.store.clone(), &sha(), &second.specification.requirements)
        .await
        .unwrap();
    assert!(held.contains("opaque-static-v2:b"));
    let gov = GovState::new_with_core(f.store.clone(), None, Some(signer()))
        .await
        .unwrap();
    gov.install_transition_self_holds(held);
    assert!(gov
        .issue_self("opaque-static-v2:b", "operator-token", None, NOW + 60, NOW)
        .await
        .is_err());
}

fn role_inventory(spec: &mut Specification) {
    spec.role_bindings_before = serde_json::from_value(serde_json::json!({
        "identity": {
            "github:org/old-name": {"allowed_pools": [], "group": "shared",
                "admin_scope": "read-only", "verbs": ["get_keys"], "allowed_tools": []},
            "github:never-asserted-user": {"admin_scope": "full"}
        },
        "operator-token": {"operator": {"allowed_pools": null, "admin_scope": "full"}}
    }))
    .unwrap();
    spec.role_dispositions = vec![
        super::RoleDisposition {
            provider: "identity".into(),
            old_role: "github:org/old-name".into(),
            new_role: Some("github-v2:aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbQ:org:42".into()),
            historical_provenance_sha256: sha(),
            old_product_sha256: sha(),
        },
        super::RoleDisposition {
            provider: "identity".into(),
            old_role: "github:never-asserted-user".into(),
            new_role: None,
            historical_provenance_sha256: sha(),
            old_product_sha256: sha(),
        },
    ];
}

#[tokio::test]
async fn cold_principal_transition_role_policy_is_lossless_fenced_and_restart_replayable() {
    let f = Fixture::new().await;
    let mut spec = f.spec();
    role_inventory(&mut spec);
    let before = spec.role_bindings_before.clone();
    let new = spec.role_dispositions[0].new_role.clone().unwrap();
    let prior_patch = serde_json::json!({"$stages": [
        {"set": {"/auth": {"role_bindings": before, "default": "none"}}},
        {"set": {"/listen": "127.0.0.1:8080"}}
    ]});
    let mut overlay = crate::config::overlay::OverlayDoc::default();
    overlay.version = crate::config::overlay::OVERLAY_VERSION;
    overlay.document_patch = Some(serde_json::from_value(prior_patch).unwrap());
    crate::config::overlay::write_async(&f.overlay, &overlay)
        .await
        .unwrap();
    let plan = prepare(spec, f.store.clone(), f.groups.clone(), Some(overlay))
        .await
        .unwrap();
    f.apply(&plan).await;
    // A completed retry verifies rather than duplicating the policy/usage carry.
    f.apply(&plan).await;
    verify(&plan, f.store.clone(), &f.overlay, NOW)
        .await
        .unwrap();
    let after = f.overlay.read_required_async().await.unwrap().unwrap();
    let mut document = serde_yaml::from_str("auth: {}\nlisten: old\n").unwrap();
    after
        .document_patch
        .as_ref()
        .unwrap()
        .apply_to(&mut document)
        .unwrap();
    let document = serde_json::to_value(document).unwrap();
    let roles: crate::config::RoleBindings =
        serde_json::from_value(document["auth"]["role_bindings"].clone()).unwrap();
    assert_eq!(
        roles["identity"][&new],
        before["identity"]["github:org/old-name"]
    );
    assert!(!roles["identity"].contains_key("github:org/old-name"));
    assert!(!roles["identity"].contains_key("github:never-asserted-user"));
    assert_eq!(roles["operator-token"], before["operator-token"]);
    assert_eq!(document["listen"], "127.0.0.1:8080");
    assert_eq!(document["auth"]["default"], "none");
    for cell in &plan.carry {
        assert_eq!(
            f.store
                .ledger()
                .get_usage(&cell.destination, cell.window)
                .await
                .unwrap(),
            cell.raw
        );
    }
}

#[tokio::test]
async fn cold_principal_transition_role_policy_refuses_missing_proof_and_collisions_before_write() {
    let f = Fixture::new().await;
    let mut spec = f.spec();
    role_inventory(&mut spec);
    assert!(super::role_bindings_after(&spec).is_ok());
    let second = spec.role_dispositions.pop().unwrap();
    assert!(super::role_bindings_after(&spec).is_err());
    spec.role_dispositions.push(second);
    spec.role_dispositions[0]
        .historical_provenance_sha256
        .clear();
    assert!(super::role_bindings_after(&spec).is_err());
    spec.role_dispositions[0].historical_provenance_sha256 = sha();
    spec.role_dispositions[1].new_role = spec.role_dispositions[0].new_role.clone();
    assert!(super::role_bindings_after(&spec).is_err());
    spec.role_dispositions[1].new_role = None;
    let destination = spec.role_dispositions[0].new_role.clone().unwrap();
    spec.role_bindings_before
        .get_mut("identity")
        .unwrap()
        .insert(destination, Default::default());
    assert!(super::role_bindings_after(&spec).is_err());
    assert!(f.overlay.read_required_async().await.unwrap().is_none());
    assert!(read_head(&TestRows(f.store.clone()))
        .await
        .unwrap()
        .is_none());
}

fn fresh_record_creation_receipt() -> super::FreshNamespace {
    super::FreshNamespace {
        witness_binding: None,
        version: 1,
        store_config_sha256: sha(),
        requirements: vec![],
        witness: None,
        ephemeral_instance: true,
        exclusive_instance: true,
        creation_evidence_sha256: sha(),
        newly_created_namespace: true,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "exclusive test Store owner".into(),
        reason: "newly created test Store with no senders and settled backend".into(),
    }
}

#[tokio::test]
async fn fresh_record_bootstrap_refuses_durable_unattested_existing_and_wrong_store() {
    let store = crate::real_store::core().await;
    let mut receipt = fresh_record_creation_receipt();
    assert!(super::initialize_ephemeral_with_record_bootstrap(
        &receipt,
        store.clone(),
        &sha(),
        &[],
        false,
        "a2a",
        &sha()
    )
    .await
    .is_err());
    receipt.newly_created_namespace = false;
    assert!(super::initialize_ephemeral_with_record_bootstrap(
        &receipt,
        store.clone(),
        &sha(),
        &[],
        true,
        "a2a",
        &sha()
    )
    .await
    .is_err());
    receipt.newly_created_namespace = true;
    receipt.backend_quiesced = false;
    assert!(super::initialize_ephemeral_with_record_bootstrap(
        &receipt,
        store.clone(),
        &sha(),
        &[],
        true,
        "a2a",
        &sha()
    )
    .await
    .is_err());
    receipt.backend_quiesced = true;
    assert!(super::initialize_ephemeral_with_record_bootstrap(
        &receipt,
        store.clone(),
        &sha(),
        &[],
        true,
        "",
        &sha()
    )
    .await
    .is_err());
    assert!(read_head(&TestRows(store.clone())).await.unwrap().is_none());
    let bootstrap = super::initialize_ephemeral_with_record_bootstrap(
        &receipt,
        store.clone(),
        &sha(),
        &[],
        true,
        "a2a",
        &sha(),
    )
    .await
    .unwrap();
    assert!(super::initialize_ephemeral_with_record_bootstrap(
        &receipt,
        store.clone(),
        &sha(),
        &[],
        true,
        "a2a",
        &sha()
    )
    .await
    .is_err());
    let other = crate::real_store::core().await;
    assert!(consume_bootstrap(bootstrap, &sha(), &TestRows(other))
        .await
        .is_err());
}

#[tokio::test]
async fn fresh_record_bootstrap_consumes_real_baseline_witness_once_and_scopes_caller() {
    let store = crate::real_store::core().await;
    let receipt = fresh_record_creation_receipt();
    let bootstrap = super::initialize_ephemeral_with_record_bootstrap(
        &receipt,
        store.clone(),
        &sha(),
        &[],
        true,
        "a2a",
        &sha(),
    )
    .await
    .unwrap();
    let replay = serde_json::from_value(serde_json::to_value(&bootstrap).unwrap()).unwrap();
    let mut grant = consume_bootstrap(bootstrap, &sha(), &TestRows(store.clone()))
        .await
        .unwrap();
    assert!(consume_bootstrap(replay, &sha(), &TestRows(store))
        .await
        .is_err());
    let caller = busbar_contract::services::Caller::for_test(
        Arc::from("a2a"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    );
    assert!(!grant.accepts(&caller));
    grant.bind_caller(&caller).unwrap();
    assert!(grant.accepts(&caller));
    let replacement = busbar_contract::services::Caller::for_test(
        Arc::from("a2a"),
        busbar_contract::abi::mechanism::KindCode::Plane,
    );
    assert!(!grant.accepts(&replacement));
}

#[tokio::test]
async fn native_guard_validates_exact_baseline_and_refuses_missing_or_changed_identity_domains() {
    use crate::persistence::scoped::{
        Mutation as NativeMutation, Request as NativeRequest, ScopedStore,
    };
    let core = crate::real_store::core().await;
    let requirements = vec![Requirement {
        provider: "corp".into(),
        plugin: "auth-corp".into(),
        format: "principal-v2".into(),
        domain_sha256: "a".repeat(64),
        product_sha256: "b".repeat(64),
        settings_sha256: "c".repeat(64),
    }];
    let binding = "d".repeat(64);
    assert!(guard_native(core.clone(), &binding, &requirements)
        .await
        .is_err());
    assert!(guard_native(core.clone(), &binding, &[])
        .await
        .unwrap()
        .is_empty());
    let receipt = FreshNamespace {
        witness_binding: None,
        version: 1,
        store_config_sha256: binding.clone(),
        requirements: requirements.clone(),
        witness: None,
        ephemeral_instance: true,
        exclusive_instance: true,
        creation_evidence_sha256: "e".repeat(64),
        newly_created_namespace: true,
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "test".into(),
        reason: "fresh".into(),
    };
    let body = serde_json::to_vec(&receipt).unwrap();
    let plan_sha256 = digest(&receipt).unwrap();
    let head = Head {
        version: 1,
        plan_sha256: plan_sha256.clone(),
        length: body.len(),
        fresh: true,
        complete: true,
        previous: None,
        authorization: None,
        rollover: None,
        retired_keys: Default::default(),
        historical_groups: Default::default(),
        depth: 0,
        extra_carry: Vec::new(),
        store_config_sha256: String::new(),
        requirements: Vec::new(),
        holds: Default::default(),
        held_principals: Default::default(),
    };
    let mut mutations = chunks(&body_prefix(&plan_sha256), &body)
        .unwrap()
        .into_iter()
        .map(|mutation| {
            let Mutation::Put { schema, key, value } = mutation else {
                panic!("body chunks only put")
            };
            NativeMutation::Put {
                schema,
                key,
                value: busbar_contract::Secret::new(value),
            }
        })
        .collect::<Vec<_>>();
    mutations.push(NativeMutation::Put {
        schema: SCHEMA.as_str().into(),
        key: HEAD.to_vec(),
        value: busbar_contract::Secret::new(serde_json::to_vec(&head).unwrap()),
    });
    let rows =
        ScopedStore::host_private(core.clone(), NATIVE_INSTANCE, [SCHEMA.as_str().to_string()])
            .unwrap();
    assert!(matches!(
        rows.conditional_native(&NativeRequest {
            op_id: [91; 16],
            predicates: Vec::new(),
            mutations,
        })
        .await
        .unwrap(),
        crate::persistence::scoped::Outcome::Applied
    ));
    assert!(guard_native(core.clone(), &binding, &requirements)
        .await
        .unwrap()
        .is_empty());
    assert!(guard_native(core.clone(), &"f".repeat(64), &requirements)
        .await
        .is_err());
    let mut changed = requirements;
    changed[0].domain_sha256 = "0".repeat(64);
    assert!(guard_native(core, &binding, &changed).await.is_err());
}

#[tokio::test]
async fn native_startup_initializes_principal_baseline_once_and_preserves_it_after_restart() {
    let backend = crate::real_store::native_backend().await;
    let core = crate::real_store::core_over(backend.clone()).await;
    let required = vec![Requirement {
        provider: "corp".into(),
        plugin: "auth-corp".into(),
        format: "principal-v2".into(),
        domain_sha256: "a".repeat(64),
        product_sha256: "b".repeat(64),
        settings_sha256: "c".repeat(64),
    }];
    let store = "d".repeat(64);
    assert!(guard_native(core.clone(), &store, &required).await.is_err());
    assert!(guard_startup_native(core.clone(), &store, &required)
        .await
        .unwrap()
        .is_empty());
    let first = native_receipt_snapshot(&core).await.unwrap();
    let (_, head) = super::read_head(&first).unwrap().unwrap();
    assert!(guard_startup_native(core.clone(), &store, &required)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        super::read_head(&native_receipt_snapshot(&core).await.unwrap())
            .unwrap()
            .unwrap()
            .1,
        head
    );
    let mut changed = required.clone();
    changed[0].domain_sha256 = "e".repeat(64);
    assert!(guard_startup_native(core.clone(), &store, &changed)
        .await
        .is_err());
    let proof = core.first_start().unwrap();
    assert_eq!(
        proof.freeze(Vec::new()).await.unwrap(),
        crate::persistence::startup::Progress::Advanced
    );
    assert_eq!(
        proof.publish().await.unwrap(),
        crate::persistence::startup::Progress::Advanced
    );
    let reopened = crate::real_store::core_over(backend).await;
    assert!(reopened.first_start().is_none());
    assert!(guard_startup_native(reopened.clone(), &store, &required)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        super::read_head(&native_receipt_snapshot(&reopened).await.unwrap())
            .unwrap()
            .unwrap()
            .1,
        head
    );
    assert!(guard_startup_native(reopened, &store, &changed)
        .await
        .is_err());
}

#[tokio::test]
async fn native_startup_does_not_infer_principal_freshness_from_missing_records() {
    let backend = crate::real_store::native_backend().await;
    let core = crate::real_store::core_over(backend.clone()).await;
    let proof = core.first_start().unwrap();
    proof.freeze(Vec::new()).await.unwrap();
    proof.publish().await.unwrap();
    let reopened = crate::real_store::core_over(backend).await;
    assert!(reopened.first_start().is_none());
    let required = vec![Requirement {
        provider: "corp".into(),
        plugin: "auth-corp".into(),
        format: "principal-v2".into(),
        domain_sha256: "a".repeat(64),
        product_sha256: "b".repeat(64),
        settings_sha256: "c".repeat(64),
    }];
    assert!(
        guard_startup_native(reopened.clone(), &"d".repeat(64), &required)
            .await
            .is_err()
    );
    assert!(
        super::read_head(&native_receipt_snapshot(&reopened).await.unwrap())
            .unwrap()
            .is_none()
    );
}

#[test]
fn linked_product_digest_hashes_the_running_image() {
    let path = std::env::current_exe().expect("test binary path");
    let expected = hex::encode(Sha256::digest(
        std::fs::read(path).expect("test binary bytes"),
    ));
    assert_eq!(executable_sha256().expect("running image digest"), expected);
}
