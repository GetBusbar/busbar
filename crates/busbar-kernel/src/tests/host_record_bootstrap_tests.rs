// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_records::StoreRows;
use crate::host_services::{AdmitRefused, InstanceFacts, KernelServices};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::kinds::RecordBytes;

const WITNESS: RecordSchemaId = RecordSchemaId::new("test.cold-store-witness");
const ROW: RecordSchemaId = RecordSchemaId::new("test.cold-task");

struct Fixture {
    rows: Arc<StoreRows>,
    instance: String,
    epoch: String,
    witness_key: Vec<u8>,
    witness_value: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        // Unique namespace and witness, owned only by this test. No background producer or old
        // namespace exists. The single setup write is definitively acknowledged before attesting.
        let mut epoch = [0u8; 16];
        getrandom::fill(&mut epoch).unwrap();
        let epoch = hex::encode(epoch);
        let rows = Arc::new(StoreRows(crate::real_store::store()));
        let witness_key = epoch.as_bytes().to_vec();
        let witness_value = format!("owned fresh store {epoch}").into_bytes();
        rows.record_put(
            WITNESS,
            &witness_key,
            &RecordBytes::new(witness_value.clone()).unwrap(),
        )
        .unwrap();
        Self {
            instance: format!("cold-{epoch}"),
            rows,
            epoch,
            witness_key,
            witness_value,
        }
    }

    fn receipt(&self) -> ColdRecordReceipt {
        ColdRecordReceipt {
            version: 1,
            epoch: self.epoch.clone(),
            instance: self.instance.clone(),
            namespace_hex: hex::encode(record_key(&self.instance, &[])),
            store_config_sha256: "test-owned-store-fingerprint".into(),
            store_witness: StoreWitness {
                schema: WITNESS.as_str().into(),
                key_hex: hex::encode(&self.witness_key),
                value_hex: hex::encode(&self.witness_value),
            },
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "targeted test owns unique namespace".into(),
            reason: "no old workers; the only setup write is acknowledged".into(),
        }
    }

    fn host(&self) -> KernelServices {
        KernelServices::new().with_records(self.rows.clone())
    }

    fn arm(&self, host: &KernelServices) -> Result<(), &'static str> {
        host.arm_record_bootstrap(self.receipt(), "test-owned-store-fingerprint")
    }

    fn caller(&self) -> Caller {
        Caller {
            instance: Arc::from(self.instance.as_str()),
            plugin: Arc::from("test-plane"),
            kind: KindCode::Plane,
        }
    }
}

fn facts() -> InstanceFacts {
    InstanceFacts {
        record_kinds: vec![ROW],
        conditional_record_kinds: vec![0],
        scope_kinds: vec!["record-quota-bootstrap".into()],
        ..InstanceFacts::default()
    }
}

#[test]
fn cold_receipt_allows_repeated_callbacks_only_for_its_first_caller_generation() {
    let fixture = Fixture::new();
    let host = fixture.host();
    fixture.arm(&host).unwrap();
    let caller = fixture.caller();
    host.bind_record_bootstrap_caller(&caller).unwrap();
    host.admit(&fixture.instance, facts()).unwrap();
    assert!(host.entitled(&caller, None, ENTITLEMENT));
    assert!(host.entitled(&caller.clone(), None, ENTITLEMENT));
    assert_eq!(host.record_kind(&caller, 0), Some(ROW));
    let replacement = fixture.caller();
    assert!(host.bind_record_bootstrap_caller(&replacement).is_err());
    assert!(!host.entitled(&replacement, None, ENTITLEMENT));
    assert_eq!(
        host.record_kind(&replacement, 0),
        None,
        "a second generation cannot write under the old facts"
    );
    assert!(matches!(
        host.admit(&fixture.instance, facts()),
        Err(AdmitRefused::BootstrapHeld { .. })
    ));
    assert!(
        host.entitled(&caller, None, ENTITLEMENT),
        "rejected reload did not damage ongoing bootstrap"
    );
    host.admit("other-instance", facts()).unwrap();
    let other = Caller {
        instance: Arc::from("other-instance"),
        ..fixture.caller()
    };
    assert!(!host.entitled(&other, None, ENTITLEMENT));
    assert!(!host.entitled(&caller, None, "record-quota-bootstrap:forged"));
}

#[test]
fn ordinary_declared_scope_never_grants_bootstrap_and_hot_arm_is_refused() {
    let fixture = Fixture::new();
    let host = fixture.host();
    host.admit(&fixture.instance, facts()).unwrap();
    assert!(!host.entitled(&fixture.caller(), None, ENTITLEMENT));
    assert!(
        fixture.arm(&host).is_err(),
        "admission is irreversible evidence this host is not cold"
    );
    assert!(!host.entitled(&fixture.caller(), None, ENTITLEMENT));
}

#[test]
fn wrong_store_namespace_and_missing_quiescence_do_not_consume_receipt() {
    let fixture = Fixture::new();
    let host = fixture.host();
    assert!(host
        .arm_record_bootstrap(fixture.receipt(), "another-store")
        .is_err());
    for which in 0..4 {
        let mut receipt = fixture.receipt();
        match which {
            0 => receipt.sender_quiesced = false,
            1 => receipt.backend_quiesced = false,
            2 => receipt.namespace_hex = hex::encode(record_key("other", &[])),
            _ => receipt.store_witness.value_hex = hex::encode(b"another backing store"),
        }
        assert!(host
            .arm_record_bootstrap(receipt, "test-owned-store-fingerprint")
            .is_err());
    }
    fixture.arm(&host).unwrap();
}

#[test]
fn consumed_epoch_cannot_be_reused_after_restart_or_under_another_instance() {
    let fixture = Fixture::new();
    let host = fixture.host();
    fixture.arm(&host).unwrap();
    drop(host); // No producer or pending write survives this owned test generation.
    let next = fixture.host();
    assert!(fixture.arm(&next).is_err());
    let mut receipt = fixture.receipt();
    receipt.instance = "other-instance".into();
    receipt.namespace_hex = hex::encode(record_key(&receipt.instance, &[]));
    assert!(next
        .arm_record_bootstrap(receipt, "test-owned-store-fingerprint")
        .is_err());
    let mut renewed = fixture.receipt();
    let mut epoch = [0u8; 16];
    getrandom::fill(&mut epoch).unwrap();
    renewed.epoch = hex::encode(epoch);
    next.arm_record_bootstrap(renewed, "test-owned-store-fingerprint")
        .unwrap();
    let caller = fixture.caller();
    next.bind_record_bootstrap_caller(&caller).unwrap();
    next.admit(&fixture.instance, facts()).unwrap();
    assert!(
        next.entitled(&caller, None, ENTITLEMENT),
        "fresh attestation resumes interrupted cold migration"
    );
}

#[test]
fn plugins_cannot_declare_consumed_receipts() {
    let host = KernelServices::new();
    assert!(matches!(
        host.admit(
            "forger",
            InstanceFacts {
                record_kinds: vec![RECEIPT_SCHEMA],
                ..InstanceFacts::default()
            }
        ),
        Err(AdmitRefused::KindReserved { .. })
    ));
}

struct LoseConsumptionReply(Arc<StoreRows>);

impl RecordRows for LoseConsumptionReply {
    fn supports_record_transaction(&self) -> bool {
        true
    }

    fn record_transaction(
        &self,
        request: &Request,
    ) -> Result<Decision, busbar_contract::store_calls::StoreFailure> {
        let decision = self.0.record_transaction(request)?;
        assert_eq!(decision, Decision::Applied);
        Err(busbar_contract::store_calls::StoreFailure::Failed(
            "receipt committed but reply lost".into(),
        ))
    }

    fn record_put(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
        value: &RecordBytes,
    ) -> Result<(), busbar_contract::kinds::StoreError> {
        self.0.record_put(schema, key, value)
    }

    fn record_get(
        &self,
        schema: RecordSchemaId,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, busbar_contract::kinds::StoreError> {
        self.0.record_get(schema, key)
    }

    fn record_scan(
        &self,
        schema: RecordSchemaId,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, busbar_contract::kinds::StoreError> {
        self.0.record_scan(schema, prefix, limit)
    }

    fn claim(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> Result<bool, busbar_contract::kinds::StoreError> {
        self.0.claim(kind, token, expires_at, now)
    }
}

#[test]
fn indeterminate_consumption_never_grants_and_its_epoch_cannot_replay() {
    let fixture = Fixture::new();
    let host =
        KernelServices::new().with_records(Arc::new(LoseConsumptionReply(fixture.rows.clone())));
    assert!(fixture.arm(&host).is_err());
    host.admit(&fixture.instance, facts()).unwrap();
    assert!(!host.entitled(&fixture.caller(), None, ENTITLEMENT));
    drop(host);
    let restarted = fixture.host();
    assert!(
        fixture.arm(&restarted).is_err(),
        "durably consumed despite lost reply"
    );
}

#[test]
fn receipt_does_not_admit_an_unbound_generation() {
    let fixture = Fixture::new();
    let host = fixture.host();
    fixture.arm(&host).unwrap();
    assert!(matches!(
        host.admit(&fixture.instance, facts()),
        Err(AdmitRefused::BootstrapHeld { .. })
    ));
    assert!(!host.entitled(&fixture.caller(), None, ENTITLEMENT));
    let caller = fixture.caller();
    host.bind_record_bootstrap_caller(&caller).unwrap();
    host.admit(&fixture.instance, facts()).unwrap();
    assert!(host.entitled(&caller, None, ENTITLEMENT));
}
