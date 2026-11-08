// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_services::{AdmitRefused, InstanceFacts, KernelServices};
use crate::persistence::{
    facade::CoreStore,
    host_records::tests::{attach, Backend},
    scoped::{migration_address, ScopedStore},
};
use busbar_contract::abi::mechanism::KindCode;
use std::sync::{atomic::Ordering, Arc};

trait TestAdmission {
    fn admit_sync(&self, instance: &str, facts: InstanceFacts) -> Result<(), AdmitRefused>;
}
impl TestAdmission for KernelServices {
    fn admit_sync(&self, instance: &str, facts: InstanceFacts) -> Result<(), AdmitRefused> {
        futures::FutureExt::now_or_never(self.admit(instance, facts))
            .expect("in-memory admission is ready")
    }
}

const WITNESS: RecordSchemaId = RecordSchemaId::new("test.cold-store-witness");
const ROW: RecordSchemaId = RecordSchemaId::new("test.cold-task");

struct Fixture {
    store: Arc<CoreStore>,
    backend: Arc<Backend>,
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
        let backend = Arc::new(Backend::default());
        let store =
            Arc::new(futures::FutureExt::now_or_never(attach(Arc::clone(&backend))).unwrap());
        let witness_key = epoch.as_bytes().to_vec();
        let witness_value = format!("owned fresh store {epoch}").into_bytes();
        let rows = ScopedStore::host_private(
            Arc::clone(&store),
            "bootstrap-witness",
            [WITNESS.as_str().to_string()],
        )
        .unwrap();
        assert_eq!(
            futures::FutureExt::now_or_never(rows.put(
                WITNESS.as_str(),
                &witness_key,
                Secret::new(witness_value.clone())
            ))
            .unwrap()
            .unwrap(),
            crate::persistence::scoped::Outcome::Applied
        );
        Self {
            instance: format!("cold-{epoch}"),
            store,
            backend,
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
        let host = KernelServices::new();
        assert!(host.attach_persistence(Arc::clone(&self.store)));
        host
    }
    fn arm_receipt(
        &self,
        host: &KernelServices,
        receipt: ColdRecordReceipt,
        fingerprint: &str,
    ) -> Result<(), &'static str> {
        futures::FutureExt::now_or_never(host.arm_record_bootstrap(
            receipt,
            fingerprint,
            |schema, key, value| {
                if schema != WITNESS.as_str()
                    || key != self.witness_key.as_slice()
                    || value != self.witness_value.as_slice()
                {
                    return Err("unknown bootstrap witness binding");
                }
                migration_address(true, "bootstrap-witness", schema, key)
                    .map_err(|_| "invalid bootstrap witness binding")
            },
        ))
        .expect("native bootstrap fixture is ready")
    }
    fn arm(&self, host: &KernelServices) -> Result<(), &'static str> {
        self.arm_receipt(host, self.receipt(), "test-owned-store-fingerprint")
    }

    fn caller(&self) -> Caller {
        Caller::for_test(Arc::from(self.instance.as_str()), KindCode::Plane)
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
    host.admit_sync(&fixture.instance, facts()).unwrap();
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
        host.admit_sync(&fixture.instance, facts()),
        Err(AdmitRefused::BootstrapHeld { .. })
    ));
    assert!(
        host.entitled(&caller, None, ENTITLEMENT),
        "rejected reload did not damage ongoing bootstrap"
    );
    host.admit_sync("other-instance", facts()).unwrap();
    let other = Caller::for_test(Arc::from("other-instance"), (fixture.caller()).kind());
    assert!(!host.entitled(&other, None, ENTITLEMENT));
    assert!(!host.entitled(&caller, None, "record-quota-bootstrap:forged"));
}

#[test]
fn ordinary_declared_scope_never_grants_bootstrap_and_hot_arm_is_refused() {
    let fixture = Fixture::new();
    let host = fixture.host();
    host.admit_sync(&fixture.instance, facts()).unwrap();
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
    assert!(fixture
        .arm_receipt(&host, fixture.receipt(), "another-store")
        .is_err());
    for which in 0..4 {
        let mut receipt = fixture.receipt();
        match which {
            0 => receipt.sender_quiesced = false,
            1 => receipt.backend_quiesced = false,
            2 => receipt.namespace_hex = hex::encode(record_key("other", &[])),
            _ => receipt.store_witness.value_hex = hex::encode(b"another backing store"),
        }
        assert!(fixture
            .arm_receipt(&host, receipt, "test-owned-store-fingerprint")
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
    assert!(fixture
        .arm_receipt(&next, receipt, "test-owned-store-fingerprint")
        .is_err());
    let mut renewed = fixture.receipt();
    let mut epoch = [0u8; 16];
    getrandom::fill(&mut epoch).unwrap();
    renewed.epoch = hex::encode(epoch);
    fixture
        .arm_receipt(&next, renewed, "test-owned-store-fingerprint")
        .unwrap();
    let caller = fixture.caller();
    next.bind_record_bootstrap_caller(&caller).unwrap();
    next.admit_sync(&fixture.instance, facts()).unwrap();
    assert!(
        next.entitled(&caller, None, ENTITLEMENT),
        "fresh attestation resumes interrupted cold migration"
    );
}

#[test]
fn plugins_cannot_declare_consumed_receipts() {
    let host = KernelServices::new();
    assert!(matches!(
        host.admit_sync(
            "forger",
            InstanceFacts {
                record_kinds: vec![RECEIPT_SCHEMA],
                ..InstanceFacts::default()
            }
        ),
        Err(AdmitRefused::KindReserved { .. })
    ));
}

#[test]
fn indeterminate_consumption_never_grants_and_its_epoch_cannot_replay() {
    let fixture = Fixture::new();
    let host = fixture.host();
    fixture.backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(fixture.arm(&host).is_err());
    host.admit_sync(&fixture.instance, facts()).unwrap();
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
        host.admit_sync(&fixture.instance, facts()),
        Err(AdmitRefused::BootstrapHeld { .. })
    ));
    assert!(!host.entitled(&fixture.caller(), None, ENTITLEMENT));
    let caller = fixture.caller();
    host.bind_record_bootstrap_caller(&caller).unwrap();
    host.admit_sync(&fixture.instance, facts()).unwrap();
    assert!(host.entitled(&caller, None, ENTITLEMENT));
}

fn native_receipt(instance: &str, epoch: [u8; 16]) -> ColdRecordReceipt {
    ColdRecordReceipt {
        version: 1,
        epoch: hex::encode(epoch),
        instance: instance.into(),
        namespace_hex: hex::encode(record_key(instance, &[])),
        store_config_sha256: "native-store".into(),
        store_witness: StoreWitness {
            schema: WITNESS.as_str().into(),
            key_hex: hex::encode(b"old-witness"),
            value_hex: hex::encode(b"public witness"),
        },
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "native fixture owner".into(),
        reason: "fresh exclusively owned backend".into(),
    }
}

#[tokio::test]
async fn native_bootstrap_pairs_exact_imported_witness_with_global_epoch_across_instances() {
    use crate::persistence::{
        host_records::tests::{attach, Backend},
        scoped::{migration_address, ScopedStore},
    };
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let rows = ScopedStore::host_private(
        Arc::clone(&store),
        "witness-owner",
        [WITNESS.as_str().to_string()],
    )
    .unwrap();
    rows.put(
        WITNESS.as_str(),
        b"old-witness",
        Secret::new(b"public witness".to_vec()),
    )
    .await
    .unwrap();
    let address =
        migration_address(true, "witness-owner", WITNESS.as_str(), b"old-witness").unwrap();
    let resolve = |schema: &str, key: &[u8], value: &[u8]| {
        if schema == WITNESS.as_str() && key == b"old-witness" && value == b"public witness" {
            Ok(address.clone())
        } else {
            Err("unregistered witness binding")
        }
    };
    let grant = Bootstrap::consume(
        native_receipt("first", [77; 16]),
        "native-store",
        &store,
        resolve,
    )
    .await
    .unwrap();
    assert_eq!(grant.instance, "first");
    assert!(Bootstrap::consume(
        native_receipt("second", [77; 16]),
        "native-store",
        &store,
        resolve
    )
    .await
    .is_err());
    assert!(Bootstrap::consume(
        native_receipt("second", [78; 16]),
        "native-store",
        &store,
        |_, _, _| Err("unregistered witness binding")
    )
    .await
    .is_err());
    let global = migration_receipt_address(&[77; 16]).unwrap();
    assert!(migration_receipt_authorizes(&global));
    assert!(!migration_receipt_authorizes(&address));
}

#[tokio::test]
async fn native_bootstrap_unknown_grants_nothing_and_retains_original_attempt() {
    use crate::persistence::{
        host_records::tests::{attach, Backend},
        scoped::{migration_address, ScopedStore},
    };
    use std::sync::{atomic::Ordering, Arc};
    let backend = Arc::new(Backend::default());
    let store = Arc::new(attach(backend.clone()).await);
    let rows = ScopedStore::host_private(
        Arc::clone(&store),
        "witness-owner",
        [WITNESS.as_str().to_string()],
    )
    .unwrap();
    rows.put(
        WITNESS.as_str(),
        b"old-witness",
        Secret::new(b"public witness".to_vec()),
    )
    .await
    .unwrap();
    let address =
        migration_address(true, "witness-owner", WITNESS.as_str(), b"old-witness").unwrap();
    backend.lose_reply.store(true, Ordering::SeqCst);
    assert!(Bootstrap::consume(
        native_receipt("first", [79; 16]),
        "native-store",
        &store,
        |_, _, _| Ok(address.clone())
    )
    .await
    .is_err());
    let pending = store.stop_admission().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(
        matches!(store.retry(pending[0]).await.unwrap().result,SubmitResult::Decided(decision) if matches!(decision.as_ref(),NativeDecision::Applied(_)))
    );
}
