// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::{keyset_of, DurabilityConfig, Scratch};
use busbar_kernel::persistence::{
    facade::CoreStore,
    journal::runtime::{BufferBudget, RuntimeJournal},
};
use busbar_kernel_audit::{AuditChain, AuditRecord};
use std::{path::Path, sync::Arc};
const NOW: u64 = 1_700_000_000;
fn token() -> Grant<DurableWrite> {
    crate::root::kernel::new_kernel().durability_token()
}
fn budget() -> BufferBudget {
    BufferBudget {
        records: 4096,
        bytes: 8 * 1024 * 1024,
    }
}
async fn node(core: Arc<CoreStore>, data_dir: Option<&Path>) -> Durability {
    let journal = RuntimeJournal::open(core, 7, budget())
        .await
        .expect("native node journal opens");
    crate::root::durability::build_on_store(
        &DurabilityConfig {
            data_dir: data_dir.map(Path::to_path_buf),
        },
        7,
        journal,
        None,
        budget(),
    )
    .await
    .expect("the native book opens")
}
async fn boot(
    core: &Arc<CoreStore>,
    dir: &Path,
) -> (Durability, Result<KeysetSource, KeysetError>) {
    let mut durability = node(core.clone(), Some(dir)).await;
    let identity = BootIdentity::new(core.clone()).unwrap();
    let bound = bind(&mut durability, &identity, &token(), StepName::Meter, NOW).await;
    (durability, bound)
}
async fn put_seed(core: &Arc<CoreStore>, value: &[u8]) {
    use busbar_kernel::persistence::{
        boot_identity::{INSTANCE, KEYSET_SCHEMA},
        scoped::{Outcome, ScopedStore},
    };
    let records =
        ScopedStore::host_private(core.clone(), INSTANCE, [KEYSET_SCHEMA.into()]).unwrap();
    assert!(matches!(
        records
            .put(
                KEYSET_SCHEMA,
                b"deployment",
                busbar_contract::Secret::new(value.to_vec())
            )
            .await
            .unwrap(),
        Outcome::Applied
    ));
}
async fn drained(book: &Durability) {
    book.journal.flush().await.expect("original runs confirm");
}

async fn seal(durability: &mut Durability) -> AuditRecord {
    use busbar_contract::caps::{OriginKind, Outcome, UnitKey};
    use busbar_kernel_audit::{
        AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage, What,
    };
    let inputs = AuditInputs {
        subject: Subject::PrincipalId("pseudonym-1".to_string()),
        what: What {
            unit_key: UnitKey::new(1),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: None,
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: NOW + 1,
        mono: 1,
        origin: crate::root::kernel::new_kernel().origin(OriginKind::Client),
        outcome: OutcomeFacts {
            unit_end: Outcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines: Vec::new(),
            tier_bp: 10_000,
            fee_count: 0,
            rate_card_version: Some([1; 20]),
            bucket_chain_ref: String::new(),
        },
        controls: Controls::default(),
        correlation_label: None,
    };
    let (record, original) = durability
        .stage_unit(
            inputs,
            busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel()),
            &token(),
        )
        .expect("the original audit record is staged");
    durability
        .journal
        .confirm(&original)
        .await
        .expect("the node confirms its original record");
    record
}

fn verifies(record: &AuditRecord, keys: &busbar_kernel_audit::AuditKeySet) -> bool {
    record
        .key_id
        .as_deref()
        .and_then(|id| keys.get(id))
        .is_some_and(|key| AuditChain::verify_signature(record, key).is_ok())
}

#[tokio::test]
async fn an_ephemeral_node_verifies_its_own_boots_signatures() {
    let mut first = node(crate::root::real_store::core().await, None).await;
    assert!(
        first.record.signing_key_id().is_none(),
        "a book is built keyless"
    );
    assert_eq!(
        bind_ephemeral(&mut first).expect("an ephemeral keyset mints"),
        KeysetSource::Ephemeral
    );
    let key_id = first
        .record
        .signing_key_id()
        .expect("the chain now signs")
        .to_string();
    let record = seal(&mut first).await;
    assert!(record.signature.is_some(), "the record is signed");
    assert!(
        verifies(&record, &keyset_of(&first.record)),
        "the node's own keyset verifies its own boot's record"
    );

    let mut second = node(crate::root::real_store::core().await, None).await;
    bind_ephemeral(&mut second).expect("an ephemeral keyset mints");
    assert_ne!(
        second.record.signing_key_id(),
        Some(key_id.as_str()),
        "every ephemeral boot mints its own key"
    );
    assert!(
        !verifies(&record, &keyset_of(&second.record)),
        "another boot's keyset cannot vouch for this record"
    );
}

#[tokio::test]
async fn the_first_boot_with_a_data_dir_keeps_its_keyset_in_the_store_and_seals_a_bootstrap() {
    let slots = crate::root::real_store::core().await;
    let dir = Scratch::new("keyset-mint");
    let (durability, bound) = boot(&slots, &dir.0).await;
    assert_eq!(bound, Ok(KeysetSource::Stored));
    let records = durability.chain().await.unwrap().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].class, RecordClass::Bootstrap);
    let seed = BootIdentity::new(slots.clone())
        .unwrap()
        .stored_keyset()
        .await
        .unwrap()
        .unwrap();
    let stored = AuditSigningKey::from_hex_seed(&seed).unwrap();
    assert_eq!(
        bootstrap_fingerprint(&records[0].body),
        Some(fingerprint_of_signer(&stored))
    );
    assert_eq!(durability.record.signing_key_id(), Some(stored.key_id()));
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[tokio::test]
async fn a_restart_with_the_data_dir_signs_with_the_same_store_key() {
    let slots = crate::root::real_store::core().await;
    let dir = Scratch::new("keyset-restart");
    let (mut first, bound) = boot(&slots, &dir.0).await;
    bound.unwrap();
    let record = seal(&mut first).await;
    let key_id = first.record.signing_key_id().map(str::to_string);
    drained(&first).await;
    drop(first);
    let (mut second, bound) = boot(&slots, &dir.0).await;
    assert_eq!(bound, Ok(KeysetSource::Stored));
    assert_eq!(second.record.signing_key_id().map(str::to_string), key_id);
    assert!(verifies(&record, &keyset_of(&second.record)));
    assert_eq!(
        second
            .chain()
            .await
            .unwrap()
            .unwrap()
            .iter()
            .filter(|r| r.class == RecordClass::Bootstrap)
            .count(),
        1
    );
    let next = seal(&mut second).await;
    assert_eq!(next.prev_hash, record.hash);
    assert_eq!(next.seq, record.seq + 1);
    assert_eq!(next.what.incarnation, record.what.incarnation + 1);
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[tokio::test]
async fn keyset_missing_refuses_in_its_exact_words_when_the_store_key_is_gone() {
    let slots = crate::root::real_store::core().await;
    let dir = Scratch::new("keyset-missing");
    let (first, bound) = boot(&slots, &dir.0).await;
    bound.unwrap();
    let fingerprint = sealed_fingerprint(&first).await.unwrap().unwrap();
    drained(&first).await;
    let records = first.chain().await.unwrap().unwrap();
    drop(first);

    let restored = crate::root::real_store::core().await;
    let restored_journal = RuntimeJournal::open(restored.clone(), 7, budget())
        .await
        .unwrap();
    for record in &records {
        let entry = Entry::new(record.class, record.body.clone())
            .at(record.wall, record.mono)
            .under(record.lease_epoch, record.policy_epoch);
        let original = restored_journal.stage_run(&[entry]).unwrap();
        assert_eq!(
            original.records()[0].body,
            record.encode(),
            "restore preserves the actual Bootstrap frame"
        );
        restored_journal.confirm(&original).await.unwrap();
    }
    let (second, bound) = boot(&restored, &dir.0).await;
    assert_eq!(bound, Err(KeysetError::StoreMissing { fingerprint }));
    assert_eq!(
        bound.unwrap_err().to_string(),
        format!(
            "KeysetMissing: the journal the configured store keeps holds a Bootstrap sealing keyset fingerprint {}, and the store does not yield that fingerprint. Restore the store's deployment keyset, or boot against a store that holds it",
            hex::encode(fingerprint),
        )
    );
    assert!(second.record.signing_key_id().is_none());
    assert!(BootIdentity::new(restored.clone())
        .unwrap()
        .stored_keyset()
        .await
        .unwrap()
        .is_none());
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[tokio::test]
async fn keyset_missing_refuses_a_store_holding_another_key() {
    let slots = crate::root::real_store::core().await;
    let dir = Scratch::new("keyset-other");
    let (first, bound) = boot(&slots, &dir.0).await;
    bound.unwrap();
    drained(&first).await;
    drop(first);
    put_seed(&slots, "11".repeat(32).as_bytes()).await;
    let (_, bound) = boot(&slots, &dir.0).await;
    assert!(
        matches!(bound, Err(KeysetError::StoreMissing { .. })),
        "{bound:?}"
    );
}

#[tokio::test]
async fn helpers_never_cache_a_keyset_with_or_without_a_data_dir() {
    let dir = Scratch::new("keyset-helper");
    for path in [None, Some(dir.0.as_path())] {
        let core = crate::root::real_store::core().await;
        let mut durability = node(core.clone(), path).await;
        assert_eq!(bind_ephemeral(&mut durability), Ok(KeysetSource::Ephemeral));
        assert!(BootIdentity::new(core)
            .unwrap()
            .stored_keyset()
            .await
            .unwrap()
            .is_none());
        assert_eq!(durability.journal.next_seq(), 1);
    }
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[tokio::test]
async fn a_stored_keyset_with_no_bootstrap_is_adopted_and_a_legacy_cache_is_untouched() {
    let slots = crate::root::real_store::core().await;
    let dir = Scratch::new("keyset-adopt");
    let seed = "22".repeat(32);
    let legacy = "33".repeat(32);
    let file = dir.0.join("deployment-keyset");
    std::fs::write(&file, legacy.as_bytes()).unwrap();
    put_seed(&slots, seed.as_bytes()).await;
    let expected = AuditSigningKey::from_hex_seed(&seed).unwrap();
    let (durability, bound) = boot(&slots, &dir.0).await;
    assert_eq!(bound, Ok(KeysetSource::Stored));
    assert_eq!(durability.record.signing_key_id(), Some(expected.key_id()));
    assert_eq!(
        sealed_fingerprint(&durability).await,
        Ok(Some(fingerprint_of_signer(&expected)))
    );
    assert_eq!(std::fs::read(&file).unwrap(), legacy.as_bytes());
}
