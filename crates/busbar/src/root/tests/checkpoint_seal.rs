// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The checkpoint sealer (OWNER Q71(3); ARCHITECTURE.md §4.7): the cadence's two constants, the
//! audit keyset bound to the ledger's sign and verify seams, and each seal refusal in its own words.

use super::*;
use busbar_contract::caps::KernelSeal;
use busbar_kernel_audit::AuditSigningKey;
use busbar_kernel_ledger::legacy::RecordingRows;
use busbar_kernel_wal::NullShipper;

fn token() -> Grant<DurableWrite> {
    Grant::<DurableWrite>::mint(&KernelSeal::acquire_for_kernel())
}

fn node(cfg: &DurabilityConfig) -> Durability {
    build_priced(
        cfg,
        3,
        Box::new(NullShipper::new()),
        Box::new(RecordingRows::new()),
        Box::new(|| None),
    )
    .expect("the book opens")
}

fn memory_node() -> Durability {
    node(&DurabilityConfig { data_dir: None })
}

fn signing(durability: &mut Durability, seed: u8) {
    durability.record = AuditChain::new().signing_with(AuditSigningKey::from_seed(&[seed; 32]));
}

/// One serving append: an idempotency claim, which reports back through the cadence check.
fn append(durability: &mut Durability, token: &Grant<DurableWrite>, n: u64) {
    let key = TotalsKey::new(
        BucketId::new("vk_seal"),
        CapDimension::NanoUnits,
        BucketScope::All,
    );
    let at = Settling {
        key: &key,
        window: 86_400,
        durability: token,
        step: StepName::Admit,
        stamp: PostingStamp {
            rate_card_version: 0,
            wall: 1_700_000_000,
            mono: n,
        },
    };
    let _ = durability.journal_claim(&at, &format!("claim-{n}"));
}

const NOW: u64 = 1_700_000_000;

/// THE TWO CONSTANTS, whichever first: ten thousand records, or sixty seconds with a change.
#[test]
fn the_cadence_is_ten_thousand_entries_or_sixty_seconds_whichever_first() {
    assert_eq!(CHECKPOINT_ENTRIES, 10_000);
    assert_eq!(CHECKPOINT_INTERVAL_SECS, 60);
    let cadence = Cadence::starting(100, NOW, 1);
    assert!(!cadence.due(100 + 9_999, NOW), "9,999 records is not due");
    assert!(
        cadence.due(100 + 10_000, NOW),
        "10,000 records is due at once"
    );
    assert!(!cadence.due(101, NOW + 59), "one record at 59 s is not due");
    assert!(cadence.due(101, NOW + 60), "one record at 60 s is due");
    assert!(
        !cadence.due(100, NOW + 3_600),
        "nothing journaled since the last seal is never due: checkpoints only on change"
    );
}

/// THE ENTRY HALF, on the serving path: the 10,000th append after arming seals, the 9,999th does
/// not, and the seal is on the journal as a Checkpoint record.
#[test]
fn the_ten_thousandth_serving_append_seals_a_checkpoint_onto_the_journal() {
    let token = token();
    let mut durability = memory_node();
    durability.arm_checkpoints(busbar_substrate_values::store::now());
    for n in 0..CHECKPOINT_ENTRIES - 1 {
        append(&mut durability, &token, n);
    }
    assert!(
        durability.checkpoints.is_empty(),
        "9,999 records seal nothing"
    );
    append(&mut durability, &token, CHECKPOINT_ENTRIES);
    assert_eq!(durability.checkpoints.len(), 1, "the 10,000th record seals");
    assert_eq!(durability.checkpoints[0].checkpoint_seq, 1);
    assert_eq!(
        durability.checkpoints[0].store_seq_high_water, CHECKPOINT_ENTRIES,
        "the seal covers every record before it (the journal numbers from one)"
    );
    assert_eq!(durability.checkpoints[0].heads.len(), 1);
    assert_eq!(
        durability.checkpoints[0].heads[0].node_seq,
        CHECKPOINT_ENTRIES
    );
    let cadence = durability.cadence().expect("armed");
    assert_eq!(cadence.next_checkpoint_seq(), 2);
}

/// THE INTERVAL HALF: sixty seconds after arming, one record is due; with nothing new it is not.
///
/// Armed on the process clock, because the serving append checks the cadence on that clock too.
#[test]
fn the_interval_seals_a_changed_book_and_never_an_unchanged_one() {
    let token = token();
    let mut durability = memory_node();
    let armed = busbar_substrate_values::store::now();
    durability.arm_checkpoints(armed);
    assert!(
        durability
            .seal_if_due(&token, StepName::Meter, armed + 600)
            .is_none(),
        "an unchanged book is not sealed however long it waits"
    );
    append(&mut durability, &token, 1);
    assert!(
        durability.checkpoints.is_empty(),
        "one record seals nothing at once"
    );
    assert!(durability
        .seal_if_due(&token, StepName::Meter, armed + 59)
        .is_none());
    let sealed = durability
        .seal_if_due(&token, StepName::Meter, armed + 60)
        .expect("due")
        .expect("sealed");
    assert_eq!(sealed.wall, armed + 60);
    assert_eq!(durability.checkpoints, vec![sealed]);
    let replayed = durability
        .journal
        .replay()
        .expect("reads back")
        .expect("verifies");
    assert!(replayed.iter().any(|r| r.class == RecordClass::Checkpoint));
    assert!(
        durability
            .seal_if_due(&token, StepName::Meter, armed + 600)
            .is_none(),
        "the checkpoint's own record is not a change to seal"
    );
}

/// An unarmed book seals nothing on its own, whatever it journals.
#[test]
fn an_unarmed_book_never_seals() {
    let token = token();
    let mut durability = memory_node();
    assert!(durability.cadence().is_none());
    assert!(durability
        .seal_if_due(&token, StepName::Meter, NOW + 3_600)
        .is_none());
    append(&mut durability, &token, 1);
    assert!(durability.checkpoints.is_empty());
}

/// ONE KEYSET (Q71(3)): the chain's key signs the checkpoint, and the audit keyset verifies it.
#[test]
fn a_checkpoint_the_chain_signed_verifies_against_the_audit_keyset() {
    let token = token();
    let mut durability = memory_node();
    signing(&mut durability, 7);
    let sealed = durability
        .seal_checkpoint(&token, StepName::Meter, NOW)
        .expect("sealed");
    assert!(sealed.signature.is_some(), "a chain with a key signs");
    let keys = KeySetVerifier::new(keyset_of(&durability.record));
    assert_eq!(sealed.verify_seal(&keys), Ok(()));
}

/// Each refusal in its own words: UNSIGNED, EDITED, and a signature the keyset rejects.
#[test]
fn each_seal_refusal_says_which_it_was() {
    let token = token();

    let mut unsigned_node = memory_node();
    let unsigned = unsigned_node
        .seal_checkpoint(&token, StepName::Meter, NOW)
        .expect("a chain with no key seals unsigned rather than failing");
    assert!(unsigned.signature.is_none());
    let refusal = unsigned
        .verify_seal(&KeySetVerifier::new(keyset_of(&unsigned_node.record)))
        .expect_err("unsigned");
    assert_eq!(
        refusal.to_string(),
        "checkpoint 1 carries no signature — no key in the keyset can vouch for it"
    );

    let mut signed_node = memory_node();
    signing(&mut signed_node, 7);
    let signed = signed_node
        .seal_checkpoint(&token, StepName::Meter, NOW)
        .expect("sealed");
    let keys = KeySetVerifier::new(keyset_of(&signed_node.record));

    let mut edited = signed.clone();
    edited.wall += 1;
    assert_eq!(
        edited.verify_seal(&keys).expect_err("edited").to_string(),
        "checkpoint 1 does not hash to its own figures — it was EDITED after it was sealed"
    );

    let mut stranger = memory_node();
    signing(&mut stranger, 9);
    let others = KeySetVerifier::new(keyset_of(&stranger.record));
    assert_eq!(
        signed
            .verify_seal(&others)
            .expect_err("wrong key")
            .to_string(),
        "checkpoint 1's signature does not verify against the keyset: the signature does not \
         verify against this key"
    );
}

/// A chain with no key hands the ledger no signer, so a seal is never refused for want of one.
#[test]
fn a_chain_with_no_key_offers_no_signer() {
    assert!(ChainSecret::of(&AuditChain::new()).is_none());
    let keyed = AuditChain::new().signing_with(AuditSigningKey::from_seed(&[7; 32]));
    let secret = ChainSecret::of(&keyed).expect("a keyed chain signs");
    let signature = secret.sign(b"body").expect("signs");
    assert_eq!(signature.bytes().len(), 64);
}

/// Numbering survives a restart: a rebuilt book continues after the highest checkpoint its chain
/// carries, so no two checkpoints ever share a sequence number.
#[test]
fn checkpoint_numbering_continues_across_a_restart() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-checkpoint-seal-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let cfg = DurabilityConfig {
        data_dir: Some(dir.clone()),
    };
    let token = token();
    {
        let mut durability = node(&cfg);
        durability.arm_checkpoints(NOW);
        for seq in [1, 2] {
            let sealed = durability
                .seal_checkpoint(&token, StepName::Meter, NOW)
                .expect("sealed");
            assert_eq!(sealed.checkpoint_seq, seq);
        }
    }
    let mut again = node(&cfg);
    again.arm_checkpoints(NOW);
    let next = again.cadence().expect("armed").next_checkpoint_seq();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(next, 3);
}
