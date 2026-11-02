// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::{build_with_cards, keyset_of, DurabilityConfig, Scratch};
use busbar_kernel_audit::{AuditChain, AuditRecord};
use busbar_kernel_wal::NullShipper;

const NOW: u64 = 1_700_000_000;

fn token() -> Grant<DurableWrite> {
    crate::root::kernel::new_kernel().durability_token()
}

fn node(data_dir: Option<&Path>) -> Durability {
    build_with_cards(
        &DurabilityConfig {
            data_dir: data_dir.map(Path::to_path_buf),
        },
        0,
        Box::new(NullShipper::new()),
        None,
    )
    .expect("the book opens")
}

fn boot(
    slots: &crate::root::store_double::RecordSlots,
    dir: &Path,
) -> (Durability, Result<KeysetSource, KeysetError>) {
    let lane = crate::root::durability::JournalLane::start(slots.calls(), "test-store").unwrap();
    let mut durability = crate::root::durability::build_on_store(
        &DurabilityConfig {
            data_dir: Some(dir.to_path_buf()),
        },
        7,
        lane,
        None,
    )
    .unwrap();
    let bound = bind(&mut durability, Some(dir), &token(), StepName::Meter, NOW);
    (durability, bound)
}

fn drained(book: &Durability) {
    assert!(book
        .lane()
        .unwrap()
        .drain(std::time::Duration::from_secs(5)));
}

fn seal(durability: &mut Durability) -> AuditRecord {
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
        origin: busbar_kernel_testkit::test_support::tokens::origin(OriginKind::Client),
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
            rate_card_version: 1,
            bucket_chain_ref: String::new(),
        },
        controls: Controls::default(),
        correlation_label: None,
    };
    durability
        .seal_unit(
            inputs,
            busbar_kernel_testkit::test_support::tokens::pass(),
            &token(),
        )
        .expect("the node seals");
    durability
        .audit_records
        .last()
        .cloned()
        .expect("the record is cached")
}

fn verifies(record: &AuditRecord, keys: &busbar_kernel_audit::AuditKeySet) -> bool {
    record
        .key_id
        .as_deref()
        .and_then(|id| keys.get(id))
        .is_some_and(|key| AuditChain::verify_signature(record, key).is_ok())
}

#[test]
fn an_ephemeral_node_verifies_its_own_boots_signatures() {
    let mut first = node(None);
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
    let record = seal(&mut first);
    assert!(record.signature.is_some(), "the record is signed");
    assert!(
        verifies(&record, &keyset_of(&first.record)),
        "the node's own keyset verifies its own boot's record"
    );

    let mut second = node(None);
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

#[test]
fn the_first_boot_with_a_data_dir_keeps_its_keyset_in_the_store_and_seals_a_bootstrap() {
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = Scratch::new("keyset-mint");
    let (durability, bound) = boot(&slots, &dir.0);
    assert_eq!(bound, Ok(KeysetSource::Stored));
    let records = durability.chain().unwrap().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].class, RecordClass::Bootstrap);
    let seed = crate::root::durability::stored_keyset(slots.calls().as_ref())
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

#[test]
fn a_restart_with_the_data_dir_signs_with_the_same_store_key() {
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = Scratch::new("keyset-restart");
    let (mut first, bound) = boot(&slots, &dir.0);
    bound.unwrap();
    let record = seal(&mut first);
    let key_id = first.record.signing_key_id().map(str::to_string);
    drained(&first);
    drop(first);
    let (mut second, bound) = boot(&slots, &dir.0);
    assert_eq!(bound, Ok(KeysetSource::Stored));
    assert_eq!(second.record.signing_key_id().map(str::to_string), key_id);
    assert!(verifies(&record, &keyset_of(&second.record)));
    assert_eq!(
        second
            .chain()
            .unwrap()
            .unwrap()
            .iter()
            .filter(|r| r.class == RecordClass::Bootstrap)
            .count(),
        1
    );
    let next = seal(&mut second);
    assert_eq!(next.prev_hash, record.hash);
    assert_eq!(next.seq, record.seq + 1);
    assert_eq!(next.what.incarnation, record.what.incarnation + 1);
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn keyset_missing_refuses_in_its_exact_words_when_the_store_key_is_gone() {
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = Scratch::new("keyset-missing");
    let (first, bound) = boot(&slots, &dir.0);
    bound.unwrap();
    let fingerprint = sealed_fingerprint(&first).unwrap().unwrap();
    drained(&first);
    let records = crate::root::durability::read_chain(slots.calls().as_ref(), 7).unwrap();
    drop(first);

    let restored = crate::root::store_double::RecordSlots::new();
    let lane =
        crate::root::durability::JournalLane::start(restored.calls(), "restored-store").unwrap();
    lane.shipper().ship(&records).unwrap();
    assert!(lane.drain(std::time::Duration::from_secs(5)));
    let (second, bound) = boot(&restored, &dir.0);
    assert_eq!(bound, Err(KeysetError::StoreMissing { fingerprint }));
    assert_eq!(bound.unwrap_err().to_string(), format!(
        "KeysetMissing: the journal the configured store keeps holds a Bootstrap sealing keyset fingerprint {}, and the store does not yield that fingerprint. Restore the store's deployment keyset, or boot against a store that holds it",
        hex::encode(fingerprint),
    ));
    assert!(second.record.signing_key_id().is_none());
    assert!(
        crate::root::durability::stored_keyset(restored.calls().as_ref())
            .unwrap()
            .is_none()
    );
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn keyset_missing_refuses_a_store_holding_another_key() {
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = Scratch::new("keyset-other");
    let (first, bound) = boot(&slots, &dir.0);
    bound.unwrap();
    drained(&first);
    drop(first);
    slots.put_row(
        "busbar.keyset.v1",
        b"deployment",
        "11".repeat(32).as_bytes(),
    );
    let (_, bound) = boot(&slots, &dir.0);
    assert!(
        matches!(bound, Err(KeysetError::StoreMissing { .. })),
        "{bound:?}"
    );
}

#[test]
fn helpers_never_cache_a_keyset_with_or_without_a_data_dir() {
    let dir = Scratch::new("keyset-helper");
    for path in [None, Some(dir.0.as_path())] {
        let mut durability = node(path);
        assert_eq!(
            bind(&mut durability, path, &token(), StepName::Meter, NOW),
            Ok(KeysetSource::Ephemeral)
        );
        assert!(!durability.keeps_chain());
        assert_eq!(durability.journal.next_seq(), 1);
    }
    assert_eq!(std::fs::read_dir(&dir.0).unwrap().count(), 0);
}

#[test]
fn a_stored_keyset_with_no_bootstrap_is_adopted_and_a_legacy_cache_is_untouched() {
    let slots = crate::root::store_double::RecordSlots::new();
    let dir = Scratch::new("keyset-adopt");
    let seed = "22".repeat(32);
    let legacy = "33".repeat(32);
    let file = dir.0.join("deployment-keyset");
    std::fs::write(&file, legacy.as_bytes()).unwrap();
    slots.put_row("busbar.keyset.v1", b"deployment", seed.as_bytes());
    let expected = AuditSigningKey::from_hex_seed(&seed).unwrap();
    let (durability, bound) = boot(&slots, &dir.0);
    assert_eq!(bound, Ok(KeysetSource::Stored));
    assert_eq!(durability.record.signing_key_id(), Some(expected.key_id()));
    assert_eq!(
        sealed_fingerprint(&durability),
        Ok(Some(fingerprint_of_signer(&expected)))
    );
    assert_eq!(std::fs::read(&file).unwrap(), legacy.as_bytes());
}
