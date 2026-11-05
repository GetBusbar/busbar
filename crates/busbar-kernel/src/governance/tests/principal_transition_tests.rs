// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    addresses, apply, digest, group, guard, pending_guard, prepare, read_head, verify, Binding,
    ColdAttestation, Plan, Requirement, Specification,
};
use crate::config::{overlay::OverlayStore, GroupCfg};
use crate::governance::{binding_marker, signing::TokenSigner, GovState};
use crate::host_record_bootstrap::StoreWitness;
use crate::host_records::{RecordRows, StoreRows};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    MeteringDelta, MeteringRow, ModelTokens, RecordStoreError, RecordStoreResult,
};
use busbar_contract::records::{RecordStore, UsageLedger, VirtualKey};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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
    store: Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    overlay: Arc<OverlayStore>,
    groups: BTreeMap<String, GroupCfg>,
}
impl Fixture {
    fn new() -> Self {
        let store = crate::real_store::store();
        let overlay = OverlayStore::new(store.clone()).unwrap();
        let groups=serde_yaml::from_str::<BTreeMap<String,GroupCfg>>("user:historic-subject:\n  parent: shared\n  limits:\n    - { requests: 9, per: total }\n    - { tokens: 10, per: hour }\n    - { budget: 100, per: day }\n    - { requests: 20, per: month, pool: opaque/a }\nshared:\n  limits:\n    - { requests: 100, per: total }\n").unwrap();
        let witness = RecordBytes::new(b"test owns this newly opened namespace".to_vec()).unwrap();
        StoreRows(store.clone())
            .record_put(
                RecordSchemaId::new("test.principal-witness"),
                b"namespace",
                &witness,
            )
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
        store.put_key(&key).unwrap();
        let fixture = Self {
            store,
            overlay,
            groups,
        };
        for (source, _, window, _) in addresses(&fixture.spec(), &fixture.groups, NOW).unwrap() {
            fixture.store.put_usage(&source, window, &raw()).unwrap();
        }
        fixture
            .store
            .put_usage(
                "group:shared@total",
                0,
                &UsageLedger {
                    requests: 73,
                    ..Default::default()
                },
            )
            .unwrap();
        fixture
    }
    fn spec(&self) -> Specification {
        Specification {
            version: 1,
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
    fn plan(&self) -> Plan {
        prepare(
            self.spec(),
            self.store.as_ref(),
            self.store.clone(),
            self.groups.clone(),
            None,
        )
        .unwrap()
    }
    fn attest(&self, plan: &Plan, epoch: u8) -> ColdAttestation {
        ColdAttestation {
            version: 1,
            epoch: hex::encode([epoch; 16]),
            plan_sha256: digest(plan).unwrap(),
            sender_quiesced: true,
            backend_quiesced: true,
            recovery_and_corrections_settled: true,
            actor: "isolated test namespace owner".into(),
            reason: "all test calls returned; no background producer exists".into(),
        }
    }
    fn apply(&self, plan: &Plan) {
        apply(
            plan,
            &self.attest(plan, 1),
            self.store.as_ref(),
            self.store.clone(),
            &self.overlay,
            NOW,
            &sha(),
        )
        .unwrap();
    }
    fn gov(&self) -> GovState {
        let g = GovState::new_with_signer(self.store.clone(), None, Some(signer())).unwrap();
        g.install_transition_self_holds(
            guard(self.store.clone(), &sha(), &self.spec().requirements).unwrap(),
        );
        g
    }
}
fn next_artifact(f: &Fixture, plan: &Plan) -> super::Reauthorization {
    let mut requirements = plan.specification.requirements.clone();
    requirements[0].product_sha256 = "b".repeat(64);
    super::Reauthorization {
        version: 1,
        baseline_sha256: digest(plan).unwrap(),
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

#[test]
fn cold_principal_transition_preserves_raw_budget_and_self_key_identity() {
    let f = Fixture::new();
    let before = f.store.get_key("vk_retained").unwrap().unwrap();
    let token = signer().mint(&before.id, NOW + 3600, Some("3"));
    let plan = f.plan();
    f.apply(&plan);
    let gov = f.gov();
    let retained = gov.verify_token(&token, NOW, None).unwrap();
    assert_eq!(retained.id, before.id);
    assert_eq!(retained.generation_hash, before.generation_hash);
    assert_eq!(retained.group.as_deref(), Some(group(NEW).as_str()));
    assert_eq!(
        gov.issue_self(NEW, "identity", None, NOW + 3600, NOW)
            .unwrap()
            .0
            .id,
        before.id
    );
    for c in &plan.carry {
        assert_eq!(f.store.get_usage(&c.destination, c.window).unwrap(), c.raw);
        assert_eq!(f.store.get_usage(&c.source, c.window).unwrap(), c.raw);
    }
    assert_eq!(
        f.store.get_usage("group:shared@total", 0).unwrap().requests,
        73
    );
    let mut groups = f.groups.clone();
    groups.insert(group(NEW), groups[&group(OLD)].clone());
    let cost = crate::cost::CostModel::resolve_parts(None, 0, &groups);
    gov.hydrate_budgets(&cost, NOW).unwrap();
    assert!(
        gov.try_admit(&cost, &retained, "", NOW).is_err(),
        "copied exhausted request quota must reject"
    );
}

#[test]
fn cold_principal_transition_carries_disabled_and_revoked_self_holds() {
    for revoked in [false, true] {
        let f = Fixture::new();
        let mut key = f.store.get_key("vk_retained").unwrap().unwrap();
        if revoked {
            f.store.add_denylist(&key.id, "operator revoked").unwrap();
        } else {
            key.enabled = false;
            f.store.put_key(&key).unwrap();
        }
        let plan = f.plan();
        f.apply(&plan);
        for _restart in 0..2 {
            let gov = f.gov();
            assert!(!gov.self_mint_holds.load(Ordering::Relaxed));
            assert!(matches!(
                gov.issue_self(NEW, "identity", None, NOW + 60, NOW),
                Err(crate::governance::SelfMintError::Refused(
                    crate::governance::SelfMintRefusal::Disabled
                ))
            ));
            assert!(matches!(
                gov.refresh_self(NEW, "identity", None, NOW + 60, NOW),
                Err(crate::governance::SelfMintError::Refused(
                    crate::governance::SelfMintRefusal::Disabled
                ))
            ));
            assert!(gov
                .issue_self("independent-B", "identity", None, NOW + 60, NOW)
                .is_ok());
        }
        let after = f.store.get_key("vk_retained").unwrap().unwrap();
        assert_eq!(after.enabled, key.enabled);
        assert_eq!(after.generation_hash, key.generation_hash);
        if revoked {
            assert!(f.store.list_denylist().unwrap().contains(&key.id));
        }
        let mut rotated_admin = plan.specification.requirements.clone();
        rotated_admin[1].settings_sha256 = "e".repeat(64);
        let holds = guard(f.store.clone(), &sha(), &rotated_admin).unwrap();
        assert!(
            holds.contains(NEW),
            "unrelated static-token rotation must retain tracked denial"
        );
        rotated_admin.pop();
        assert_eq!(
            holds,
            guard(f.store.clone(), &sha(), &rotated_admin).unwrap(),
            "removing an unrelated unmarked provider does not remove tracked holds"
        );
        let mut tracked_unmarked = rotated_admin.clone();
        tracked_unmarked[0].format.clear();
        assert!(guard(f.store.clone(), &sha(), &tracked_unmarked).is_err());
        let mut authorization = next_artifact(&f, &plan);
        authorization.requirements[1].settings_sha256 = "e".repeat(64);
        super::reauthorize(
            &authorization,
            f.store.clone(),
            &sha(),
            &authorization.requirements,
        )
        .unwrap();
        let reloaded = GovState::new_with_signer(f.store.clone(), None, Some(signer())).unwrap();
        reloaded.install_transition_self_holds(
            guard(f.store.clone(), &sha(), &authorization.requirements).unwrap(),
        );
        assert!(matches!(
            reloaded.issue_self(NEW, "identity", None, NOW + 60, NOW),
            Err(crate::governance::SelfMintError::Refused(
                crate::governance::SelfMintRefusal::Disabled
            ))
        ));
        for carry in &plan.carry {
            assert_eq!(
                f.store.get_usage(&carry.destination, carry.window).unwrap(),
                carry.raw
            );
        }
    }
    // A normal successful SELF refresh leaves a tombstone. It must not silently become a
    // permanent subject-level hold, and a live row alone cannot prove the deletion's cause.
    let rotated = Fixture::new();
    let live = GovState::new_with_signer(rotated.store.clone(), None, Some(signer())).unwrap();
    let (successor, token) = live
        .refresh_self(OLD, "identity", None, NOW + 3600, NOW)
        .unwrap();
    drop(live);
    let retired = rotated.store.get_key("vk_retained").unwrap().unwrap();
    let successor = rotated.store.get_key(&successor.id).unwrap().unwrap();
    assert!(retired.deleted_at.is_some());
    let error = prepare(
        rotated.spec(),
        rotated.store.as_ref(),
        rotated.store.clone(),
        rotated.groups.clone(),
        None,
    )
    .unwrap_err();
    assert!(error.contains("rotation versus revocation"));
    assert!(read_head(&StoreRows(rotated.store.clone()))
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
    let plan = prepare(
        spec,
        rotated.store.as_ref(),
        rotated.store.clone(),
        rotated.groups.clone(),
        None,
    )
    .unwrap();
    rotated.apply(&plan);
    let resumed = rotated.gov();
    assert_eq!(
        resumed.verify_token(&token, NOW, None).unwrap().id,
        successor.id
    );
    assert_eq!(
        resumed
            .issue_self(NEW, "identity", None, NOW + 60, NOW)
            .unwrap()
            .0
            .id,
        successor.id
    );
    assert_eq!(
        rotated.store.get_key(&retired.id).unwrap().unwrap(),
        retired,
        "rotation tombstone remains historical evidence"
    );
}

struct UnknownUsage {
    inner: Arc<busbar_plugin_loader::store_v3::LoadedStore>,
    fail: AtomicBool,
    fail_key: bool,
}
impl RecordStore for UnknownUsage {
    fn put_key(&self, k: &VirtualKey) -> RecordStoreResult<()> {
        self.inner.put_key(k)?;
        if self.fail_key && self.fail.swap(false, Ordering::SeqCst) {
            Err(RecordStoreError(
                "injected lost key reply AFTER actual Store commit".into(),
            ))
        } else {
            Ok(())
        }
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, b: &str, w: u64) -> RecordStoreResult<UsageLedger> {
        self.inner.get_usage(b, w)
    }
    fn put_usage(&self, b: &str, w: u64, l: &UsageLedger) -> RecordStoreResult<()> {
        self.inner.put_usage(b, w, l)?;
        if !self.fail_key && self.fail.swap(false, Ordering::SeqCst) {
            Err(RecordStoreError(
                "injected lost reply AFTER actual Store commit".into(),
            ))
        } else {
            Ok(())
        }
    }
    fn add_metering(&self, d: &MeteringDelta) -> RecordStoreResult<()> {
        self.inner.add_metering(d)
    }
    fn list_metering(&self, b: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(b)
    }
    fn list_denylist(&self) -> RecordStoreResult<Vec<String>> {
        self.inner.list_denylist()
    }
}

#[test]
fn cold_principal_transition_pending_or_unknown_outcome_refuses_serving() {
    for fail_key in [false, true] {
        let f = Fixture::new();
        let plan = f.plan();
        let attestation = f.attest(&plan, 1);
        let fault = UnknownUsage {
            inner: f.store.clone(),
            fail: AtomicBool::new(true),
            fail_key,
        };
        assert!(apply(
            &plan,
            &attestation,
            &fault,
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha()
        )
        .is_err());
        assert_eq!(
            f.store
                .get_usage(&plan.carry[0].destination, plan.carry[0].window)
                .unwrap(),
            plan.carry[0].raw,
            "unknown reply may have committed"
        );
        assert!(guard(f.store.clone(), &sha(), &[]).is_err());
        assert!(pending_guard(f.store.clone()).is_err());
        let authorization = next_artifact(&f, &plan);
        assert!(
            super::reauthorize(
                &authorization,
                f.store.clone(),
                &sha(),
                &authorization.requirements
            )
            .is_err(),
            "reauthorization cannot release a pending migration"
        );
        assert!(apply(
            &plan,
            &attestation,
            f.store.as_ref(),
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha()
        )
        .unwrap_err()
        .contains("already consumed"));
        let mut changed: Plan =
            serde_json::from_value(serde_json::to_value(&plan).unwrap()).unwrap();
        changed.specification.id.push('x');
        assert!(apply(
            &changed,
            &f.attest(&changed, 2),
            f.store.as_ref(),
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha()
        )
        .is_err());
        apply(
            &plan,
            &f.attest(&plan, 2),
            f.store.as_ref(),
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha(),
        )
        .unwrap();
        verify(&plan, f.store.as_ref(), f.store.clone(), &f.overlay, NOW).unwrap();
        for c in &plan.carry {
            assert_eq!(f.store.get_usage(&c.destination, c.window).unwrap(), c.raw);
        }
    }
}

#[test]
fn cold_principal_transition_rejects_ambiguous_or_conflicting_mapping_before_write() {
    let f = Fixture::new();
    for variant in 0..5 {
        let mut spec = f.spec();
        match variant {
            0 => spec.bindings.push(spec.bindings[0].clone()),
            1 => spec.bindings[0].new_principal = "x".repeat(252),
            2 => spec.bindings[0].historical_provenance_sha256.clear(),
            3 => spec.bindings[0].provider = "other".into(),
            _ => spec.complete_legacy_inventory_sha256.clear(),
        }
        assert!(prepare(
            spec,
            f.store.as_ref(),
            f.store.clone(),
            f.groups.clone(),
            None
        )
        .is_err());
        assert!(read_head(&StoreRows(f.store.clone())).unwrap().is_none());
        assert_eq!(
            f.store
                .get_key("vk_retained")
                .unwrap()
                .unwrap()
                .idp_subject
                .as_deref(),
            Some(OLD)
        );
    }
    for state in 0..4 {
        let mut observed = Fixture::new();
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
        observed.store.put_key(&other).unwrap();
        if state == 2 {
            observed.store.add_denylist(&other.id, "revoked B").unwrap();
        }
        if state == 3 {
            observed.store.delete_key(&other.id).unwrap();
        }
        observed
            .groups
            .insert(group("omitted-B"), observed.groups[&group(OLD)].clone());
        let before = observed.store.list_keys().unwrap();
        let error = prepare(
            observed.spec(),
            observed.store.as_ref(),
            observed.store.clone(),
            observed.groups.clone(),
            None,
        )
        .unwrap_err();
        assert!(error.contains("omitted"), "unmapped observed B must fail even with a syntactically valid complete-inventory digest: {error}");
        assert_eq!(observed.store.list_keys().unwrap(), before);
        assert!(read_head(&StoreRows(observed.store.clone()))
            .unwrap()
            .is_none());
    }
    let mut orphan = Fixture::new();
    orphan
        .groups
        .insert(group("orphan-B"), orphan.groups[&group(OLD)].clone());
    assert!(prepare(
        orphan.spec(),
        orphan.store.as_ref(),
        orphan.store.clone(),
        orphan.groups.clone(),
        None
    )
    .unwrap_err()
    .contains("omitted"));
    f.store.put_usage(NEW, 0, &raw()).unwrap();
    assert!(prepare(
        f.spec(),
        f.store.as_ref(),
        f.store.clone(),
        f.groups.clone(),
        None
    )
    .is_err());
    assert!(f.overlay.read_required().unwrap().is_none());
}

#[test]
fn cold_principal_transition_does_not_rewrite_history_or_replay_old_secrets() {
    let f = Fixture::new();
    let delta: MeteringDelta = serde_json::from_value(serde_json::json!({
        "scale":6,"key_id":"vk_retained","bucket":NOW / 86400 * 86400,
        "model":"historical:model","provider":"historical-provider",
        "tokens_input":10_000_001,"tokens_output":3,"tokens_cache_read":0,"tokens_cache_write":0,
        "requests":9,"billable_requests":7,"key_group_at_use":group(OLD),
        "pricing_version":"original-era","priced_from_ms":9001,
        "usage_units":{"opaque:class":9007199254740993u64}
    }))
    .unwrap();
    f.store.add_metering(&delta).unwrap();
    let metering_before = f.store.list_metering(delta.bucket).unwrap();
    let history=RecordBytes::new(br#"{"actor":"historic-subject","secret":"old-once-secret","group":"user:historic-subject"}"#.to_vec()).unwrap();
    for schema in [
        "test.historical-audit",
        "test.old-admin-replay",
        "test.metering-history",
    ] {
        StoreRows(f.store.clone())
            .record_put(RecordSchemaId::new(schema), OLD.as_bytes(), &history)
            .unwrap();
    }
    let plan = f.plan();
    f.apply(&plan);
    assert_eq!(
        f.store.list_metering(delta.bucket).unwrap(),
        metering_before,
        "carried enforcement baseline must not become billable traffic"
    );
    for schema in [
        "test.historical-audit",
        "test.old-admin-replay",
        "test.metering-history",
    ] {
        assert_eq!(
            StoreRows(f.store.clone())
                .record_get(RecordSchemaId::new(schema), OLD.as_bytes())
                .unwrap()
                .unwrap()
                .as_slice(),
            history.as_slice()
        );
        assert!(StoreRows(f.store.clone())
            .record_get(RecordSchemaId::new(schema), NEW.as_bytes())
            .unwrap()
            .is_none());
    }
}

#[test]
fn cold_principal_transition_enumerates_exact_scoped_windows_and_eras() {
    let f = Fixture::new();
    let plan = f.plan();
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
    let before = f.store.list_keys().unwrap();
    assert!(apply(
        &plan,
        &f.attest(&plan, 1),
        f.store.as_ref(),
        f.store.clone(),
        &f.overlay,
        NOW + 3600,
        &sha()
    )
    .unwrap_err()
    .contains("window"));
    assert_eq!(f.store.list_keys().unwrap(), before);
    assert!(read_head(&StoreRows(f.store.clone())).unwrap().is_none());
    // Unrelated configurations without a format requirement still boot. Active changed formats
    // cannot use an empty key scan as a fresh-namespace claim.
    assert!(guard(f.store.clone(), &sha(), &[]).is_ok());
    assert!(guard(f.store.clone(), &sha(), &f.spec().requirements).is_err());
    let mut unsupported = f.groups.clone();
    unsupported.get_mut(&group(OLD)).unwrap().limits[3]
        .scope
        .as_mut()
        .unwrap()
        .kind = "agent".into();
    let error = prepare(
        f.spec(),
        f.store.as_ref(),
        f.store.clone(),
        unsupported,
        None,
    )
    .unwrap_err();
    assert!(error.contains("lossless"));
    assert!(read_head(&StoreRows(f.store.clone())).unwrap().is_none());

    // A pending transition crosses an hour/day/month. Resume SAME immutable plan under a new
    // quiescence receipt; capture and carry exact new active windows, including nonzero usage.
    let rolled = Fixture::new();
    let rolled_plan = rolled.plan();
    let fault = UnknownUsage {
        inner: rolled.store.clone(),
        fail: AtomicBool::new(true),
        fail_key: false,
    };
    assert!(apply(
        &rolled_plan,
        &rolled.attest(&rolled_plan, 1),
        &fault,
        rolled.store.clone(),
        &rolled.overlay,
        NOW,
        &sha()
    )
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
            rolled.store.put_usage(source, *window, &raw()).unwrap();
        }
    }
    assert!(pending_guard(rolled.store.clone()).is_err());
    // A second lost reply after the rollover journal commits must also resume idempotently.
    let fault = UnknownUsage {
        inner: rolled.store.clone(),
        fail: AtomicBool::new(true),
        fail_key: false,
    };
    assert!(apply(
        &rolled_plan,
        &rolled.attest(&rolled_plan, 2),
        &fault,
        rolled.store.clone(),
        &rolled.overlay,
        later,
        &sha()
    )
    .is_err());
    assert!(pending_guard(rolled.store.clone()).is_err());
    apply(
        &rolled_plan,
        &rolled.attest(&rolled_plan, 3),
        rolled.store.as_ref(),
        rolled.store.clone(),
        &rolled.overlay,
        later,
        &sha(),
    )
    .unwrap();
    verify(
        &rolled_plan,
        rolled.store.as_ref(),
        rolled.store.clone(),
        &rolled.overlay,
        later,
    )
    .unwrap();
    for (source, destination, window, _) in active {
        assert_eq!(
            rolled.store.get_usage(&destination, window).unwrap(),
            rolled.store.get_usage(&source, window).unwrap()
        );
    }
    for carry in &rolled_plan.carry {
        assert_eq!(
            rolled.store.get_usage(&carry.source, carry.window).unwrap(),
            carry.raw
        );
        assert_eq!(
            rolled
                .store
                .get_usage(&carry.destination, carry.window)
                .unwrap(),
            carry.raw
        );
    }
    let (head, _) = read_head(&StoreRows(rolled.store.clone()))
        .unwrap()
        .unwrap();
    assert_eq!(head.plan_sha256, digest(&rolled_plan).unwrap());
    assert!(head.rollover.is_some());
    assert!(!head.extra_carry.is_empty());

    let fresh = crate::real_store::store();
    let rows = StoreRows(fresh.clone());
    rows.record_put(
        RecordSchemaId::new("test.creation"),
        b"fresh",
        &RecordBytes::new(b"external-provisioner-owned-new-namespace".to_vec()).unwrap(),
    )
    .unwrap();
    let required = f.spec().requirements;
    assert!(
        guard(fresh.clone(), &sha(), &required).is_err(),
        "empty key scan establishes no baseline"
    );
    let receipt = super::FreshNamespace {
        version: 1,
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
    super::initialize_fresh(&receipt, fresh.clone(), &sha(), &required).unwrap();
    assert!(guard(fresh.clone(), &sha(), &required).unwrap().is_empty());
    let mut changed = required.clone();
    changed[0].provider = "renamed-provider".into();
    assert!(guard(fresh.clone(), &sha(), &changed).is_err());
    let mut removed = required.clone();
    removed[0].format.clear();
    assert!(guard(fresh.clone(), &sha(), &removed).is_err());
    assert!(guard(fresh.clone(), &sha(), &[]).is_err());
    let mut unrelated = required.clone();
    unrelated[1].settings_sha256 = "e".repeat(64);
    unrelated[1].provider = "renamed-unrelated-admin-token".into();
    assert!(guard(fresh.clone(), &sha(), &unrelated).is_ok());
    unrelated.pop();
    assert!(guard(fresh.clone(), &sha(), &unrelated).is_ok());
    let mut added_marked = required.clone();
    added_marked[1].format = "another-format".into();
    added_marked[1].domain_sha256 = sha();
    assert!(
        guard(fresh.clone(), &sha(), &added_marked).is_err(),
        "every current marked domain requires a matching receipt"
    );
    let baseline = digest(&receipt).unwrap();
    let mut next = required.clone();
    next[0].product_sha256 = "b".repeat(64);
    next[0].settings_sha256 = "c".repeat(64);
    assert!(
        guard(fresh.clone(), &sha(), &next).is_ok(),
        "ordinary artifact/non-domain settings updates preserve identity"
    );
    let mut domain_change = next.clone();
    domain_change[0].domain_sha256 = "d".repeat(64);
    assert!(guard(fresh.clone(), &sha(), &domain_change).is_err());
    let mut plugin_change = next.clone();
    plugin_change[0].plugin = "other.auth".into();
    assert!(guard(fresh.clone(), &sha(), &plugin_change).is_err());
    let mut authorization = super::Reauthorization {
        version: 1,
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
    assert!(super::reauthorize(&authorization, fresh.clone(), &sha(), &next).is_err());
    authorization.identity_outputs_unchanged = true;
    authorization.requirements = changed.clone();
    assert!(super::reauthorize(&authorization, fresh.clone(), &sha(), &changed).is_err());
    authorization.requirements = next.clone();
    authorization.previous_requirements_sha256 = "b".repeat(64);
    assert!(super::reauthorize(&authorization, fresh.clone(), &sha(), &next).is_err());
    authorization.previous_requirements_sha256 = digest(&required).unwrap();
    authorization.witness.value_hex = hex::encode(b"wrong namespace");
    assert!(super::reauthorize(&authorization, fresh.clone(), &sha(), &next).is_err());
    authorization.witness.value_hex = hex::encode(b"external-provisioner-owned-new-namespace");
    // A definitive condition conflict consumes the op ID; changing the body requires a fresh
    // receipt identity, represented here by a new operator quiescence epoch.
    authorization.attestation.epoch = hex::encode([20u8; 16]);
    super::reauthorize(&authorization, fresh.clone(), &sha(), &next).unwrap();
    assert!(guard(fresh.clone(), &sha(), &next).is_ok());
    assert!(guard(fresh.clone(), &sha(), &required).is_ok());
    assert!(
        super::initialize_fresh(&receipt, fresh.clone(), &sha(), &required).is_err(),
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
    let fingerprint =
        |s: &serde_json::Value| super::domain_fingerprint(&schema, s, &["client_secret".into()]);
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
            &settings,
            &[]
        )
        .is_err());
    }
    assert!(super::domain_fingerprint(&json!({}), &settings, &[]).is_err());
    let mut reordered = schema.clone();
    reordered[super::DOMAIN_ANNOTATION]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_ne!(
        before,
        super::domain_fingerprint(&reordered, &settings, &[]).unwrap()
    );
    for (pointer, secret) in [
        ("/issuer", "issuer"),
        ("/issuer/name", "issuer"),
        ("/issuer", "issuer.name"),
        ("/issuers/0/name", "issuers.*.name"),
        ("/a~1b/~0name", "a/b.~name"),
    ] {
        let declaration = json!({super::DOMAIN_ANNOTATION:[{"pointer":pointer,"required":false}]});
        assert!(super::domain_fingerprint(&declaration, &settings, &[secret.into()]).is_err());
    }
    let mut unresolved = settings.clone();
    unresolved["issuer"] = json!({"env":"ISSUER"});
    assert!(fingerprint(&unresolved).is_err());
    unresolved["issuer"] = json!({"nested":[{"env":"ISSUER"}]});
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
    let typed: Option<crate::config::StoreCfg> = serde_json::from_value(store_a.clone()).unwrap();
    assert_eq!(
        super::store_fingerprint(&typed).unwrap(),
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
        super::domain_fingerprint(&schema, &serde_json::json!({"domain":a}), &[]).unwrap(),
        super::domain_fingerprint(&schema, &serde_json::json!({"domain":b}), &[]).unwrap()
    );
}

fn creation_receipt(f: &Fixture, requirements: Vec<Requirement>) -> super::FreshNamespace {
    super::FreshNamespace {
        version: 1,
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

#[test]
fn completed_baseline_and_migration_support_attested_successors_without_losing_history_or_holds() {
    for migrated in [false, true] {
        let f = Fixture::new();
        let mut key = f.store.get_key("vk_retained").unwrap().unwrap();
        key.enabled = false;
        f.store.put_key(&key).unwrap();
        let mut groups = f.groups.clone();
        let (from, to, overlay) = if migrated {
            let mut retired = key.clone();
            retired.id = "vk_historical_tombstone".into();
            retired.deleted_at = Some(NOW - 5);
            f.store.put_key(&retired).unwrap();
            let first = f.plan();
            f.apply(&first);
            let overlay = super::after_overlay(&first).unwrap();
            groups.extend(overlay.groups.clone());
            // The immutable hold must survive even if a later operator re-enables this row.
            let mut live = f.store.get_key("vk_retained").unwrap().unwrap();
            live.enabled = true;
            f.store.put_key(&live).unwrap();
            (
                NEW,
                "opaque-format:second-domain:historic-subject",
                Some(overlay),
            )
        } else {
            let receipt = creation_receipt(&f, f.spec().requirements);
            super::initialize_fresh(&receipt, f.store.clone(), &sha(), &receipt.requirements)
                .unwrap();
            (OLD, NEW, None)
        };
        let rows = StoreRows(f.store.clone());
        let (old_head, old_bytes) = read_head(&rows).unwrap().unwrap();
        let old_body = super::read_body(
            &rows,
            &super::body_prefix(&old_head.plan_sha256),
            old_head.length,
        )
        .unwrap();
        let old_digest = super::receipt_head_digest(f.store.clone())
            .unwrap()
            .unwrap();
        let mut spec = f.spec();
        spec.id = "explicit-next-identity-domain".into();
        spec.bindings[0].old_principal = from.into();
        spec.bindings[0].new_principal = to.into();
        spec.requirements[0].domain_sha256 = "b".repeat(64);
        assert!(guard(f.store.clone(), &sha(), &spec.requirements).is_err());
        let mut plan = prepare(spec, f.store.as_ref(), f.store.clone(), groups, overlay).unwrap();
        assert_eq!(plan.previous.as_ref().unwrap().head_sha256, old_digest);
        let original = plan.previous.as_ref().unwrap().head_sha256.clone();
        plan.previous.as_mut().unwrap().head_sha256 = "f".repeat(64);
        assert!(super::check(
            &plan,
            f.store.as_ref(),
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha()
        )
        .is_err());
        assert_eq!(read_head(&rows).unwrap().unwrap().1, old_bytes);
        plan.previous.as_mut().unwrap().head_sha256 = original;
        let lost = UnknownUsage {
            inner: f.store.clone(),
            fail: AtomicBool::new(true),
            fail_key: false,
        };
        assert!(apply(
            &plan,
            &f.attest(&plan, 31),
            &lost,
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha()
        )
        .is_err());
        assert!(pending_guard(f.store.clone()).is_err());
        assert!(guard(f.store.clone(), &sha(), &[]).is_err());
        assert!(prepare(
            f.spec(),
            f.store.as_ref(),
            f.store.clone(),
            f.groups.clone(),
            None
        )
        .is_err());
        assert_eq!(
            rows.record_get(super::SCHEMA, format!("ancestor:{old_digest}").as_bytes())
                .unwrap()
                .unwrap()
                .as_slice(),
            old_bytes
        );
        assert_eq!(
            super::read_body(
                &rows,
                &super::body_prefix(&old_head.plan_sha256),
                old_head.length
            )
            .unwrap(),
            old_body
        );
        apply(
            &plan,
            &f.attest(&plan, 32),
            f.store.as_ref(),
            f.store.clone(),
            &f.overlay,
            NOW,
            &sha(),
        )
        .unwrap();
        verify(&plan, f.store.as_ref(), f.store.clone(), &f.overlay, NOW).unwrap();
        let held = guard(f.store.clone(), &sha(), &plan.specification.requirements).unwrap();
        assert!(held.contains(to));
        if migrated {
            assert!(held.contains(NEW));
        }
        let gov = GovState::new_with_signer(f.store.clone(), None, Some(signer())).unwrap();
        gov.install_transition_self_holds(held);
        assert!(gov.issue_self(to, "identity", None, NOW + 60, NOW).is_err());
        let after = f.store.get_key("vk_retained").unwrap().unwrap();
        assert_eq!(after.idp_subject.as_deref(), Some(to));
        assert_eq!(after.generation_hash, key.generation_hash);
        for carry in &plan.carry {
            assert_eq!(
                f.store.get_usage(&carry.destination, carry.window).unwrap(),
                carry.raw
            );
            assert_eq!(
                f.store.get_usage(&carry.source, carry.window).unwrap(),
                carry.raw
            );
        }
        assert_eq!(
            f.store.get_usage("group:shared@total", 0).unwrap().requests,
            73
        );
        let (final_head, _) = read_head(&rows).unwrap().unwrap();
        assert_eq!(final_head.depth, 2);
        assert_eq!(
            super::read_body(
                &rows,
                &super::body_prefix(&old_head.plan_sha256),
                old_head.length
            )
            .unwrap(),
            old_body
        );
        assert_eq!(
            rows.record_get(super::SCHEMA, format!("ancestor:{old_digest}").as_bytes())
                .unwrap()
                .unwrap()
                .as_slice(),
            old_bytes
        );
    }
}

#[test]
fn unrelated_retained_self_group_requires_exact_unaffected_provenance_and_stays_unchanged() {
    let mut f = Fixture::new();
    let principal = "unrelated-static-subject";
    let name = group(principal);
    let mut key = f.store.get_key("vk_retained").unwrap().unwrap();
    key.id = "vk_unrelated_static".into();
    key.idp_subject = Some(principal.into());
    key.idp_provider = Some("operator-token".into());
    key.group = Some(name.clone());
    f.store.put_key(&key).unwrap();
    let key = f.store.get_key(&key.id).unwrap().unwrap();
    f.groups.insert(name.clone(), f.groups[&group(OLD)].clone());
    let unrelated_usage = "group:user:unrelated-static-subject@total";
    f.store.put_usage(unrelated_usage, 0, &raw()).unwrap();
    assert!(prepare(
        f.spec(),
        f.store.as_ref(),
        f.store.clone(),
        f.groups.clone(),
        None
    )
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
        f.store.as_ref(),
        f.store.clone(),
        f.groups.clone(),
        None
    )
    .is_err());
    spec.unaffected[0].provenance_sha256 = sha();
    spec.unaffected[0].keys_sha256 = "f".repeat(64);
    assert!(prepare(
        serde_json::from_value(serde_json::to_value(&spec).unwrap()).unwrap(),
        f.store.as_ref(),
        f.store.clone(),
        f.groups.clone(),
        None
    )
    .is_err());
    spec.unaffected[0].keys_sha256 = digest(&vec![&key]).unwrap();
    let plan = prepare(
        spec,
        f.store.as_ref(),
        f.store.clone(),
        f.groups.clone(),
        None,
    )
    .unwrap();
    let mut forged: Plan = serde_json::from_value(serde_json::to_value(&plan).unwrap()).unwrap();
    forged.specification.unaffected[0].provider = "identity".into();
    assert!(super::validate_plan(&forged).is_err());
    forged = serde_json::from_value(serde_json::to_value(&plan).unwrap()).unwrap();
    forged
        .groups_before
        .insert(group("orphan"), GroupCfg::default());
    assert!(super::validate_plan(&forged).is_err());
    f.apply(&plan);
    assert_eq!(f.store.get_key(&key.id).unwrap().unwrap(), key);
    assert_eq!(f.store.get_usage(unrelated_usage, 0).unwrap(), raw());
    assert_eq!(super::after_overlay(&plan).unwrap().groups.get(&name), None);
}

#[test]
fn explicit_ephemeral_creation_requires_attestation_durability_and_absent_head() {
    let f = Fixture::new();
    let mut receipt = creation_receipt(&f, f.spec().requirements);
    receipt.witness = None;
    assert!(
        super::initialize_fresh(&receipt, f.store.clone(), &sha(), &receipt.requirements).is_err()
    );
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .is_err());
    receipt.ephemeral_instance = true;
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .is_err());
    receipt.exclusive_instance = true;
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        false
    )
    .is_err());
    receipt.newly_created_namespace = false;
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .is_err());
    assert!(read_head(&StoreRows(f.store.clone())).unwrap().is_none());
    receipt.newly_created_namespace = true;
    super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true,
    )
    .unwrap();
    assert!(guard(f.store.clone(), &sha(), &receipt.requirements).is_ok());
    assert!(super::initialize_ephemeral_fresh(
        &receipt,
        f.store.clone(),
        &sha(),
        &receipt.requirements,
        true
    )
    .is_err());
    let reloaded = crate::real_store::store();
    assert!(
        guard(reloaded, &sha(), &receipt.requirements).is_err(),
        "a new instance does not inherit the explicit creation claim"
    );
}

#[test]
fn ephemeral_creation_cannot_replace_a_pending_transition() {
    let f = Fixture::new();
    let plan = f.plan();
    let lost = UnknownUsage {
        inner: f.store.clone(),
        fail: AtomicBool::new(true),
        fail_key: false,
    };
    assert!(apply(
        &plan,
        &f.attest(&plan, 55),
        &lost,
        f.store.clone(),
        &f.overlay,
        NOW,
        &sha()
    )
    .is_err());
    let before = read_head(&StoreRows(f.store.clone())).unwrap().unwrap().1;
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
    .is_err());
    assert_eq!(
        read_head(&StoreRows(f.store.clone())).unwrap().unwrap().1,
        before
    );
    assert!(pending_guard(f.store.clone()).is_err());
}

#[test]
fn successor_rejects_omitted_predecessor_hold_without_any_key_or_group() {
    let f = Fixture::new();
    let old_b = "denied-without-retained-record";
    let second_b = "opaque-format:first-domain:denied-without-record";
    let third_b = "opaque-format:second-domain:denied-without-record";
    f.store
        .add_denylist(old_b, "historical principal revocation")
        .unwrap();
    let mut spec = f.spec();
    let mut b = spec.bindings[0].clone();
    b.old_principal = old_b.into();
    b.new_principal = second_b.into();
    spec.bindings.push(b);
    let first = prepare(
        spec,
        f.store.as_ref(),
        f.store.clone(),
        f.groups.clone(),
        None,
    )
    .unwrap();
    f.apply(&first);
    assert!(
        guard(f.store.clone(), &sha(), &first.specification.requirements)
            .unwrap()
            .contains(second_b)
    );
    assert!(f
        .store
        .list_keys()
        .unwrap()
        .iter()
        .all(|key| key.idp_subject.as_deref() != Some(second_b)));
    let overlay = super::after_overlay(&first).unwrap();
    let mut groups = f.groups.clone();
    groups.extend(overlay.groups.clone());
    let before = read_head(&StoreRows(f.store.clone())).unwrap().unwrap().1;
    let mut next = f.spec();
    next.requirements[0].domain_sha256 = "b".repeat(64);
    next.bindings[0].old_principal = NEW.into();
    next.bindings[0].new_principal = "opaque-format:second-domain:historic-subject".into();
    let partial = serde_json::from_value(serde_json::to_value(&next).unwrap()).unwrap();
    assert!(
        prepare(
            partial,
            f.store.as_ref(),
            f.store.clone(),
            groups.clone(),
            Some(overlay.clone())
        )
        .is_err(),
        "known keyless predecessor hold B must not be omitted from a changed domain"
    );
    assert_eq!(
        read_head(&StoreRows(f.store.clone())).unwrap().unwrap().1,
        before
    );
    let mut b = next.bindings[0].clone();
    b.old_principal = second_b.into();
    b.new_principal = third_b.into();
    next.bindings.push(b);
    let second = prepare(
        next,
        f.store.as_ref(),
        f.store.clone(),
        groups,
        Some(overlay),
    )
    .unwrap();
    apply(
        &second,
        &f.attest(&second, 61),
        f.store.as_ref(),
        f.store.clone(),
        &f.overlay,
        NOW,
        &sha(),
    )
    .unwrap();
    let held = guard(f.store.clone(), &sha(), &second.specification.requirements).unwrap();
    assert!(held.contains(second_b));
    assert!(held.contains(third_b));
    let gov = GovState::new_with_signer(f.store.clone(), None, Some(signer())).unwrap();
    gov.install_transition_self_holds(held);
    assert!(gov
        .issue_self(third_b, "identity", None, NOW + 60, NOW)
        .is_err());
    assert!(gov
        .refresh_self(third_b, "identity", None, NOW + 60, NOW)
        .is_err());
    assert!(!gov.self_mint_holds.load(Ordering::Relaxed));
}

#[test]
fn successor_rejects_unaffected_tombstone_as_automatically_migrated_history() {
    let f = Fixture::new();
    let b = VirtualKey {
        id: "vk_unaffected_tombstone_b".into(),
        enabled: false,
        deleted_at: Some(NOW - 5),
        idp_provider: Some("operator-token".into()),
        idp_subject: Some("old-static-b".into()),
        group: None,
        ..Default::default()
    };
    f.store.put_key(&b).unwrap();
    let b = f.store.get_key(&b.id).unwrap().unwrap();
    let mut spec = f.spec();
    spec.unaffected.push(super::UnaffectedPrincipal {
        principal: "old-static-b".into(),
        provider: "operator-token".into(),
        requirement_sha256: digest(&spec.requirements[1]).unwrap(),
        keys_sha256: digest(&vec![&b]).unwrap(),
        group_sha256: digest(&Option::<GroupCfg>::None).unwrap(),
        provenance_sha256: sha(),
    });
    let first = prepare(
        spec,
        f.store.as_ref(),
        f.store.clone(),
        f.groups.clone(),
        None,
    )
    .unwrap();
    f.apply(&first);
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
    f.store.put_key(&c).unwrap();
    let a = f.store.get_key("vk_retained").unwrap().unwrap();
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
    let before = read_head(&StoreRows(f.store.clone())).unwrap().unwrap().1;
    let partial = serde_json::from_value(serde_json::to_value(&next).unwrap()).unwrap();
    assert!(prepare(partial, f.store.as_ref(), f.store.clone(), groups.clone(), Some(overlay.clone())).is_err(),
        "a previously unaffected tombstone was never migrated and cannot bypass current inventory coverage");
    assert_eq!(
        read_head(&StoreRows(f.store.clone())).unwrap().unwrap().1,
        before
    );
    let mut mapping = next.bindings[0].clone();
    mapping.old_principal = "old-static-b".into();
    mapping.new_principal = "opaque-static-v2:b".into();
    next.bindings.push(mapping);
    let second = prepare(
        next,
        f.store.as_ref(),
        f.store.clone(),
        groups,
        Some(overlay),
    )
    .unwrap();
    apply(
        &second,
        &f.attest(&second, 62),
        f.store.as_ref(),
        f.store.clone(),
        &f.overlay,
        NOW,
        &sha(),
    )
    .unwrap();
    assert_eq!(f.store.get_key(&b.id).unwrap().unwrap(), b);
    let held = guard(f.store.clone(), &sha(), &second.specification.requirements).unwrap();
    assert!(held.contains("opaque-static-v2:b"));
    let gov = GovState::new_with_signer(f.store.clone(), None, Some(signer())).unwrap();
    gov.install_transition_self_holds(held);
    assert!(gov
        .issue_self("opaque-static-v2:b", "operator-token", None, NOW + 60, NOW)
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

#[test]
fn cold_principal_transition_role_policy_is_lossless_fenced_and_restart_replayable() {
    let f = Fixture::new();
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
    f.overlay.update(|doc| *doc = overlay.clone()).unwrap();
    let plan = prepare(
        spec,
        f.store.as_ref(),
        f.store.clone(),
        f.groups.clone(),
        Some(overlay),
    )
    .unwrap();
    f.apply(&plan);
    // A completed retry verifies rather than duplicating the policy/usage carry.
    f.apply(&plan);
    verify(&plan, f.store.as_ref(), f.store.clone(), &f.overlay, NOW).unwrap();
    let after = f.overlay.read_required().unwrap().unwrap();
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
            f.store.get_usage(&cell.destination, cell.window).unwrap(),
            cell.raw
        );
    }
}

#[test]
fn cold_principal_transition_role_policy_refuses_missing_proof_and_collisions_before_write() {
    let f = Fixture::new();
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
    assert!(f.overlay.read_required().unwrap().is_none());
    assert!(read_head(&StoreRows(f.store.clone())).unwrap().is_none());
}
