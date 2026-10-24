// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The checkpoint sealer (OWNER Q71(3); BUSBAR-1.6.0.md THE DESIGN, §7): the cadence's two constants, the
//! audit keyset bound to the ledger's sign and verify seams, and each seal refusal in its own words.

use super::*;
// All but the signing key are used only by the `root-admin` test below.
#[cfg_attr(not(feature = "root-admin"), allow(unused_imports))]
use busbar_kernel_audit::{
    AuditInputs, AuditSigningKey, Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage,
    What,
};
use busbar_kernel_ledger::{
    checkpoint::{AnchoredHead, CheckpointAnchor},
    legacy::RecordingRows,
};
use busbar_kernel_wal::NullShipper;

fn token() -> Grant<DurableWrite> {
    busbar_kernel::test_support::tokens::grant::<DurableWrite>()
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
    durability.arm_checkpoints(busbar_kernel::store::now());
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
    let armed = busbar_kernel::store::now();
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
    assert_eq!(durability.checkpoints, vec![sealed.head()]);
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

/// THE RING (architect ruling 2026-09-26, "checkpoint retention"): the node holds the latest 1,024
/// seals; the 1,025th evicts the OLDEST, and every seal is still on the journal.
#[test]
fn the_checkpoint_ring_holds_the_latest_1024_and_evicts_the_oldest_at_1025() {
    use super::super::CHECKPOINT_RING;
    assert_eq!(CHECKPOINT_RING, 1_024);
    let token = token();
    let mut durability = memory_node();
    for n in 0..1_024u64 {
        durability
            .seal_checkpoint(&token, StepName::Meter, NOW + n)
            .expect("the seal goes down");
    }
    assert_eq!(
        durability.checkpoints.len(),
        1_024,
        "1,024 seals are all held"
    );
    assert_eq!(durability.checkpoints[0].checkpoint_seq, 1);

    durability
        .seal_checkpoint(&token, StepName::Meter, NOW + 1_024)
        .expect("the 1,025th seal goes down");
    assert_eq!(
        durability.checkpoints.len(),
        1_024,
        "the 1,025th seal must evict one: the ring is bounded"
    );
    assert_eq!(
        durability.checkpoints[0].checkpoint_seq, 2,
        "the OLDEST seal (checkpoint 1) is the one evicted"
    );
    assert_eq!(
        durability.checkpoints[1_023].checkpoint_seq, 1_025,
        "the newest seal is held"
    );
    assert_eq!(
        durability.journal.next_seq(),
        1_026,
        "the journal is the durable record: it took every seal, the evicted one included"
    );
}

/// N SEALS HOLD NO COPY OF THE BOOK BEYOND ONE RESIDENT SEALED COPY (Q128 kernel-ledger HIGH 1,
/// ARCHITECT ruling A1): the node keeps one live book, the deltas not yet sealed, and one resident
/// sealed copy (the newest kept seal, which the retirement measures against), however many seals it
/// has made. RED before the ruling: the
/// ring kept a full copy of the book per seal, so fifty seals of an eight-balance book held four
/// hundred balances.
#[test]
fn n_seals_hold_no_copy_of_the_book_beyond_one_in_flight() {
    let token = token();
    let mut durability = memory_node();
    for n in 0..8u64 {
        let key = TotalsKey::new(
            BucketId::new(format!("vk_bound_{n}")),
            CapDimension::NanoUnits,
            BucketScope::All,
        );
        durability.ledger.book_mut().entry(key, 86_400).settled = 1;
    }
    let book = durability.ledger.book().len();
    assert_eq!(book, 8);
    for n in 0..50u64 {
        durability
            .seal_checkpoint(&token, StepName::Meter, NOW + n)
            .expect("the seal goes down");
    }
    assert!(
        durability.sealed_balances_held() <= book,
        "fifty seals hold {} sealed balances beside a live book of {book}: one resident sealed \
         copy at most",
        durability.sealed_balances_held()
    );
}

/// **EVERY SEAL BOUNDS THE BOOK** at 1.5.5's thirty-one-day horizon. A window the last kept seal
/// holds, past the horizon, leaves the book and the dual-write rows before the next seal, so that
/// seal no longer carries it; a window inside the horizon and the all-time window are untouched,
/// and the books still verify clean against the new seal. Before this, no production path retired
/// a window, and every seal cloned every window the node had ever settled into.
#[test]
fn a_seal_retires_the_windows_past_the_horizon_the_last_seal_holds() {
    use busbar_kernel_ledger::totals::{ALL_TIME_WINDOW, WINDOW_RETENTION_SECS};

    let token = token();
    let rows = RecordingRows::new();
    let mut durability = build_priced(
        &DurabilityConfig { data_dir: None },
        3,
        Box::new(NullShipper::new()),
        Box::new(rows.clone()),
        Box::new(|| None),
    )
    .expect("the book opens");
    let key = TotalsKey::new(
        BucketId::new("vk_retire"),
        CapDimension::NanoUnits,
        BucketScope::All,
    );
    let old = 86_400;
    let today = NOW / 86_400 * 86_400;
    for window in [ALL_TIME_WINDOW, old, today] {
        durability.ledger.record_hold_opened(&key, window, 100);
        durability.ledger.replay_post(
            &key,
            window,
            "vk_retire",
            Figures {
                reserved: 100,
                settled: 60,
                fee_count: 1,
            },
        );
    }
    let inside = |book: &busbar_kernel_ledger::totals::Book| -> Vec<_> {
        book.iter()
            .filter(|((_, window), _)| *window != old)
            .map(|(at, figures)| (at.clone(), *figures))
            .collect()
    };
    let before = inside(durability.ledger.book());
    assert!(old.saturating_add(WINDOW_RETENTION_SECS) <= NOW);

    // The first seal has no seal before it, so it retires nothing and holds every window.
    let first = durability
        .seal_checkpoint(&token, StepName::Meter, NOW)
        .expect("the seal goes down");
    assert!(first.totals.contains_key(&(key.clone(), old)));
    assert_eq!(durability.ledger.book().len(), 3);

    // The next one retires what the first holds past the horizon, and seals without it.
    let second = durability
        .seal_checkpoint(&token, StepName::Meter, NOW + 1)
        .expect("the seal goes down");
    assert!(!second.totals.contains_key(&(key.clone(), old)));
    assert_eq!(durability.ledger.book().get(&key, old), Totals::zero());
    assert!(rows.written().iter().all(|row| row.window_start != old));
    assert_eq!(rows.written().len(), 2, "the rows inside the horizon stay");
    assert_eq!(
        inside(durability.ledger.book()),
        before,
        "every balance inside the horizon is unchanged"
    );
    assert!(
        busbar_kernel_ledger::verify::verify(&second, &durability.ledger.book().snapshot(), None)
            .is_empty(),
        "the books verify clean against the seal that no longer holds the retired window"
    );
}

/// U12: A REWOUND CHECKPOINT IS A `/verify` FINDING. Two checkpoints are sealed and the second is
/// anchored; the ring is then rewound to the first (what a node restored from an older copy of its
/// own state holds). `GET /admin/verify` compares the anchored head with the checkpoint it verifies
/// against and reports that they differ. With the anchor passed as `None` (before U12) the rewound
/// book verified clean against the older checkpoint.
#[cfg(feature = "root-admin")]
#[test]
fn verify_reports_a_rewound_checkpoint_against_the_anchored_head() {
    use crate::root::units_admin::{LegacyRowsRead, NodeLedger};
    let token = token();
    let node_book = crate::root::durability::node_book();
    let book = std::sync::Arc::clone(&node_book.durability);
    let legacy: std::sync::Arc<dyn LegacyRowsRead> = node_book.rows.clone();
    let view = NodeLedger::new(std::sync::Arc::clone(&book), legacy);
    let verify = || {
        String::from_utf8(
            crate::root::units_admin::bound::verify_effect(&view, None)
                .expect("verify answers")
                .body,
        )
        .expect("utf-8")
    };
    {
        let mut durability = book.lock().expect("unpoisoned");
        durability.arm_checkpoints(NOW);
        for _ in 0..2 {
            durability
                .seal_checkpoint(&token, StepName::Meter, NOW)
                .expect("sealed");
        }
    }
    let clean = verify();
    assert!(
        clean.contains(r#""ok":true"#) && !clean.contains("the anchor holds"),
        "a book at its anchored head verifies clean: {clean}"
    );
    book.lock().expect("unpoisoned").checkpoints.pop();
    let rewound = verify();
    assert!(
        rewound.contains("the anchor holds checkpoint 2, not 1")
            && rewound.contains(r#""ok":false"#),
        "a checkpoint rewound behind the anchored head must be a finding: {rewound}"
    );
}

/// U12: THE ANCHOR IS SEEDED FROM THE CHAIN AT BOOT. A node that restarts over its own journal holds
/// the last checkpoint that journal anchored, not an empty head.
#[test]
fn the_anchor_is_seeded_from_the_chain_at_boot() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-anchor-seed-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    let cfg = DurabilityConfig {
        data_dir: Some(dir.clone()),
    };
    let token = token();
    let second = {
        let mut durability = node(&cfg);
        durability.arm_checkpoints(NOW);
        let _first = durability
            .seal_checkpoint(&token, StepName::Meter, NOW)
            .expect("sealed");
        durability
            .seal_checkpoint(&token, StepName::Meter, NOW)
            .expect("sealed")
    };
    let again = node(&cfg);
    let head = again.anchor.head().expect("reads");
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        head,
        Some(AnchoredHead {
            checkpoint_seq: second.checkpoint_seq,
            body_hash: second.body_hash,
        }),
        "the restarted node's anchor holds the chain's last checkpoint"
    );
}

/// WHAT THE BOOT RECONCILIATION FOUND IS A `/verify` FINDING. A node that booted over a journal it
/// could not wholly read serves on (a corrupt journal does not stop the boot) and logs the finding;
/// `GET /admin/verify` names it too, and is not `ok`.
#[cfg(feature = "root-admin")]
#[test]
fn verify_names_what_the_boot_reconciliation_found() {
    use crate::root::units_admin::{LegacyRowsRead, NodeLedger};
    let node_book = crate::root::durability::node_book();
    let legacy: std::sync::Arc<dyn LegacyRowsRead> = node_book.rows.clone();
    let view = NodeLedger::new(std::sync::Arc::clone(&node_book.durability), legacy);
    let verify = || {
        String::from_utf8(
            crate::root::units_admin::bound::verify_effect(&view, None)
                .expect("verify answers")
                .body,
        )
        .expect("utf-8")
    };
    assert!(verify().contains(r#""ok":true"#));
    node_book
        .durability
        .lock()
        .expect("unpoisoned")
        .restart_findings
        .push(JournalDisagreement::Unreadable(
            "the journal does not verify: a forged record".to_string(),
        ));
    let body = verify();
    assert!(
        body.contains("restart: ")
            && body.contains("a forged record")
            && body.contains(r#""ok":false"#),
        "a boot finding must be a /verify finding: {body}"
    );
}

/// A RETAINED AUDIT RECORD EDITED AFTER IT WAS SEALED IS A `GET /admin/verify` FINDING: the walk of
/// the fixed audit chain the node holds runs on every verify, and the answer is `ok: false`.
#[cfg(feature = "root-admin")]
#[test]
fn verify_names_a_tampered_retained_audit_record() {
    use crate::root::units_admin::{LegacyRowsRead, NodeLedger};
    let node_book = crate::root::durability::node_book();
    let legacy: std::sync::Arc<dyn LegacyRowsRead> = node_book.rows.clone();
    let view = NodeLedger::new(std::sync::Arc::clone(&node_book.durability), legacy);
    let verify = || {
        String::from_utf8(
            crate::root::units_admin::bound::verify_effect(&view, None)
                .expect("verify answers")
                .body,
        )
        .expect("utf-8")
    };
    {
        let mut durability = node_book.durability.lock().expect("unpoisoned");
        let token = busbar_kernel::teller::Kernel::new().durability_token();
        for unit in 1..=2 {
            let inputs = AuditInputs {
                subject: Subject::PrincipalId(format!("p-{unit}")),
                what: What {
                    unit_key: busbar_contract::UnitKey::new(unit),
                    incarnation: 0,
                    op_class: OpClassId::new("chat"),
                    destination: None,
                    parent: None,
                    pre_hook_head: None,
                    post_hook_head: None,
                },
                wall: 1_700_000_000,
                mono: unit,
                origin: busbar_kernel::test_support::tokens::origin(
                    busbar_contract::caps::OriginKind::Client,
                ),
                outcome: OutcomeFacts {
                    unit_end: busbar_contract::caps::Outcome::Completed,
                    step: None,
                    finish: FinishClass::Complete,
                    hook_failed: false,
                    emission_delta: 0,
                    stale_policy: false,
                },
                usage: Usage {
                    lines: Vec::new(),
                    tier_bp: 10_000,
                    fee_count: 1,
                    rate_card_version: 0,
                    bucket_chain_ref: String::new(),
                },
                controls: Controls::default(),
                correlation_label: None,
            };
            let pass = busbar_kernel::test_support::tokens::pass();
            durability.seal_unit(inputs, pass, &token).expect("sealed");
        }
    }
    assert!(verify().contains(r#""ok":true"#), "{}", verify());
    node_book
        .durability
        .lock()
        .expect("unpoisoned")
        .audit_records[0]
        .usage
        .fee_count = 9;
    let body = verify();
    assert!(
        body.contains("audit chain: ") && body.contains(r#""ok":false"#),
        "a tampered retained record must be a /verify finding: {body}"
    );
}

/// A CHECKPOINT OUT OF STEP WITH THE CHAIN IS A RESTART FINDING (self-attesting). The chain seals
/// checkpoints 1 and 2; a later record then carries checkpoint 1 again — a checkpoint put back after
/// a newer one was sealed. The boot's step check (the chain's newest checkpoint record against the
/// anchor it seeds at the highest-numbered one) names it, and says it is self-attesting.
#[test]
fn a_checkpoint_out_of_step_with_the_chain_is_a_restart_finding() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-anchor-step-{}-{:?}",
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
        let first = durability
            .seal_checkpoint(&token, StepName::Meter, NOW)
            .expect("sealed");
        let _second = durability
            .seal_checkpoint(&token, StepName::Meter, NOW)
            .expect("sealed");
        assert!(node_findings(&durability).is_empty());
        durability
            .journal
            .append(
                &token,
                StepName::Meter,
                &[busbar_kernel_wal::Entry::new(
                    busbar_kernel_wal::RecordClass::Checkpoint,
                    crate::root::durability::checkpoint_body(&first),
                )],
            )
            .expect("appended");
    }
    let again = node(&cfg);
    let _ = std::fs::remove_dir_all(&dir);
    let findings = node_findings(&again);
    assert!(
        findings
            .iter()
            .any(|f| f.contains("self-attesting") && f.contains("out of step")),
        "{findings:?}"
    );
}

fn node_findings(durability: &Durability) -> Vec<String> {
    durability
        .restart_findings
        .iter()
        .map(ToString::to_string)
        .collect()
}
