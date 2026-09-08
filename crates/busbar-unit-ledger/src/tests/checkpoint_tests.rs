// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checkpoints: sealing, signing, anchoring, and the verification that closes a window.

use std::collections::BTreeMap;

use busbar_unit_cost::HistorySeq;

use crate::checkpoint::{
    AnchorError, ChainHead, Checkpoint, CheckpointAnchor, CheckpointSecret, SelfAttestingAnchor,
    SignError, Signature,
};
use crate::settle::Ledger;
use crate::totals::{Totals, TotalsKey, WindowStart};
use crate::verify::{sequences_are_monotonic, verify, AllWindowsOpen, Finding, WindowState};

use super::fixtures::{hold, key, ledger_token, usage};

/// A signer that stamps the digest of what it was given, so a test can tell one body from another.
struct StampSigner;

impl CheckpointSecret for StampSigner {
    fn sign(&self, body: &[u8]) -> Result<Signature, SignError> {
        Ok(Signature::new(crate::digest::sha256(body).to_vec()))
    }
}

struct NoKey;

impl CheckpointSecret for NoKey {
    fn sign(&self, _body: &[u8]) -> Result<Signature, SignError> {
        Err(SignError::KeyUnavailable("under test".into()))
    }
}

fn book_with_a_settlement() -> Ledger {
    let mut ledger = Ledger::new();
    let token = ledger_token();
    let k = key("b");
    ledger.record_draw(&k, 1, 1_000);
    ledger.record_hold_opened(&k, 1, 600);
    ledger.record_slice_spent(&k, 1, 600);
    let _ = ledger.settle(&k, 1, hold("a", 600), 450, &usage("tokens", 450), &token);
    ledger
}

fn seal(ledger: &Ledger, seq: u64) -> Checkpoint {
    Checkpoint::seal(
        seq,
        1,
        1_700_000_000,
        vec![ChainHead {
            node: 1,
            node_seq: 10,
            hash: [7u8; 32],
        }],
        ledger.book().snapshot(),
        5,
        99,
        Some(&StampSigner),
    )
    .unwrap()
}

#[test]
fn a_sealed_checkpoint_hashes_to_its_own_figures() {
    let checkpoint = seal(&book_with_a_settlement(), 1);
    assert!(checkpoint.body_hash_verifies());
    assert!(checkpoint.signature.is_some());
}

#[test]
fn editing_a_sealed_figure_is_caught() {
    let mut checkpoint = seal(&book_with_a_settlement(), 1);
    let entry = checkpoint
        .totals
        .get_mut(&(key("b"), 1 as WindowStart))
        .unwrap();
    entry.settled += 1;
    assert!(!checkpoint.body_hash_verifies());
    let findings = verify(&checkpoint, &BTreeMap::new(), &AllWindowsOpen);
    assert!(findings
        .iter()
        .any(|f| matches!(f, Finding::CheckpointEdited { .. })));
}

#[test]
fn the_head_order_does_not_change_the_body() {
    let ledger = book_with_a_settlement();
    let heads_one = vec![
        ChainHead {
            node: 2,
            node_seq: 5,
            hash: [1u8; 32],
        },
        ChainHead {
            node: 1,
            node_seq: 9,
            hash: [2u8; 32],
        },
    ];
    let mut heads_two = heads_one.clone();
    heads_two.reverse();
    let seal_with = |heads: Vec<ChainHead>| {
        Checkpoint::seal(
            1,
            1,
            10,
            heads,
            ledger.book().snapshot(),
            0,
            0,
            Some(&StampSigner),
        )
        .unwrap()
    };
    assert_eq!(
        seal_with(heads_one).body_hash,
        seal_with(heads_two).body_hash,
        "two nodes collecting the same heads in a different order must seal the same body"
    );
}

#[test]
fn a_checkpoint_can_be_sealed_without_a_signer_and_says_so() {
    let checkpoint = Checkpoint::seal(1, 1, 10, Vec::new(), BTreeMap::new(), 0, 0, None).unwrap();
    assert!(checkpoint.signature.is_none());
    assert!(checkpoint.body_hash_verifies());
}

#[test]
fn a_signer_without_a_key_refuses_rather_than_sealing_something_unsigned() {
    let err = Checkpoint::seal(1, 1, 10, Vec::new(), BTreeMap::new(), 0, 0, Some(&NoKey));
    assert!(matches!(err, Err(SignError::KeyUnavailable(_))));
}

#[test]
fn the_local_anchor_admits_it_is_self_attesting() {
    // The honest label. A node that files its own signatures where it can rewrite them has proved
    // nothing, and the type says so rather than leaving an operator to work it out.
    let mut anchor = SelfAttestingAnchor::new();
    assert!(anchor.is_self_attesting());
    let checkpoint = seal(&book_with_a_settlement(), 4);
    anchor.anchor(&checkpoint).unwrap();
    let head = anchor.head().unwrap().unwrap();
    assert_eq!(head.checkpoint_seq, 4);
    assert_eq!(head.body_hash, checkpoint.body_hash);
}

/// The threshold comparison, at the boundary in both directions.
///
/// The COUNTING itself is the caller's: `AnchorState::consecutive_failures` is a plain field with
/// no incrementing method on this crate's side, so what this crate can be held to is the comparison
/// and nothing else. Named accordingly rather than claiming the count is checked here.
#[test]
fn the_alarm_threshold_is_reached_at_the_count_and_not_before() {
    use crate::checkpoint::AnchorState;
    let fresh = AnchorState::default();
    assert_eq!(fresh.consecutive_failures, 0);
    assert!(
        !fresh.should_alarm(1),
        "a sink that has not failed does not alarm"
    );
    assert!(
        fresh.should_alarm(0),
        "a threshold of nothing is reached by nothing"
    );

    let mut state = AnchorState::default();
    for _ in 0..3 {
        state.consecutive_failures += 1;
    }
    assert!(
        !state.should_alarm(4),
        "one short of the threshold is quiet"
    );
    assert!(state.should_alarm(3), "the threshold itself alarms");
    assert!(state.should_alarm(2), "and anything past it");

    // The read-back failure is a DISTINCT fact from an unreachable sink, and its text is what an
    // operator is handed. Previously this variant was constructed and discarded, which asserted
    // nothing at all: a sink that silently returned a different checkpoint could be reported with
    // the "not usable" wording and nobody would look for a rewrite.
    assert_ne!(
        AnchorError::ReadBackDiffers,
        AnchorError::Unavailable("anything".into())
    );
    assert_eq!(
        AnchorError::ReadBackDiffers.to_string(),
        "the anchor sink read back something other than what was written"
    );
}

#[test]
fn verification_closes_the_window_when_the_books_balance_and_opens_it_when_they_do_not() {
    let ledger = book_with_a_settlement();
    let checkpoint = seal(&ledger, 1);

    // Nothing has happened since: the delta is zero, which balances.
    assert!(verify(&checkpoint, &ledger.book().snapshot(), &AllWindowsOpen).is_empty());

    // More work, properly recorded: still balances.
    let mut ledger = ledger;
    let token = ledger_token();
    let k = key("b");
    ledger.record_hold_opened(&k, 1, 200);
    ledger.record_slice_spent(&k, 1, 200);
    let _ = ledger.settle(&k, 1, hold("a", 200), 200, &usage("tokens", 200), &token);
    assert!(verify(&checkpoint, &ledger.book().snapshot(), &AllWindowsOpen).is_empty());

    // One figure edited by hand: does not.
    ledger.book_mut().entry(k.clone(), 1).settled += 5;
    let findings = verify(&checkpoint, &ledger.book().snapshot(), &AllWindowsOpen);
    assert_eq!(findings.len(), 1);
    match &findings[0] {
        Finding::Imbalanced(i) => assert_eq!(i.residual.amount(), 5),
        other => panic!("expected an imbalance, got {other}"),
    }
}

#[test]
fn a_closed_window_that_keeps_posting_is_reported_as_such() {
    struct EverythingClosed;
    impl WindowState for EverythingClosed {
        fn is_open(&self, _key: &TotalsKey, _window: WindowStart) -> bool {
            false
        }
    }
    let ledger = book_with_a_settlement();
    let checkpoint = seal(&ledger, 1);
    let mut ledger = ledger;
    ledger.book_mut().entry(key("b"), 1).settled += 25;

    let findings = verify(&checkpoint, &ledger.book().snapshot(), &EverythingClosed);
    match findings.as_slice() {
        [Finding::ClosedWindowMoved(c)] => assert_eq!(c.moved, 25),
        other => panic!("expected one closed-window finding, got {other:?}"),
    }
}

/// A window the book retired is NOT a window whose money went missing.
///
/// Retiring a sealed window is the ordinary way a book stays bounded — the figures were signed and
/// shipped, and the book stopped being the record of them. Measured against the zeros a retired key
/// reads back as, the answer depends on figures that have nothing to do with the question: silence
/// when the sealed balance happens to balance from zero, an imbalance the size of the whole balance
/// when it does not. This fixture gets the first of those, which is the worse one — a balance can
/// leave the book and the verifier says nothing at all. Named, it says what happened, and the other
/// way a balance leaves a book is that somebody removed it.
#[test]
fn a_balance_the_book_retired_is_named_as_retired_and_not_as_an_imbalance() {
    let mut ledger = book_with_a_settlement();
    let checkpoint = seal(&ledger, 1);
    assert!(verify(&checkpoint, &ledger.book().snapshot(), &AllWindowsOpen).is_empty());

    // The window is sealed, so the book lets it go.
    assert_eq!(ledger.book_mut().retain_from(2), 1);
    let findings = verify(&checkpoint, &ledger.book().snapshot(), &AllWindowsOpen);
    match findings.as_slice() {
        [Finding::Retired { key: k, window }] => {
            assert_eq!(k, &key("b"));
            assert_eq!(*window, 1 as WindowStart);
        }
        other => panic!("expected one retirement, got {other:?}"),
    }
    assert!(
        findings[0].to_string().contains("no longer in the book"),
        "the finding says what happened: {}",
        findings[0]
    );

    // And a closed window is answered the same way: what is gone is gone, not gone and unbalanced.
    struct EverythingClosed;
    impl WindowState for EverythingClosed {
        fn is_open(&self, _key: &TotalsKey, _window: WindowStart) -> bool {
            false
        }
    }
    let closed = verify(&checkpoint, &ledger.book().snapshot(), &EverythingClosed);
    assert!(matches!(closed.as_slice(), [Finding::Retired { .. }]));
}

#[test]
fn a_balance_that_appeared_after_the_checkpoint_is_still_checked() {
    // A key that was not in the checkpoint is measured from zeros, so a brand-new balance cannot
    // hide by simply not having existed at sealing time.
    let checkpoint = Checkpoint::seal(1, 1, 10, Vec::new(), BTreeMap::new(), 0, 0, None).unwrap();
    let mut now = BTreeMap::new();
    now.insert(
        (key("new"), 1 as WindowStart),
        Totals {
            settled: 100,
            ..Totals::zero()
        },
    );
    let findings = verify(&checkpoint, &now, &AllWindowsOpen);
    assert_eq!(findings.len(), 1, "a new unbalanced key must be found");
}

#[test]
fn a_node_sequence_that_goes_backwards_is_found() {
    let ledger = book_with_a_settlement();
    let earlier = seal(&ledger, 1);
    let mut later = seal(&ledger, 2);
    later.heads[0].node_seq = 3;
    let findings = sequences_are_monotonic(&earlier, &later);
    match findings.as_slice() {
        [Finding::SequenceNotMonotonic { node, was, now }] => {
            assert_eq!((*node, *was, *now), (1, 10, 3));
        }
        other => panic!("expected one sequence finding, got {other:?}"),
    }
    assert!(sequences_are_monotonic(&earlier, &earlier).is_empty());
}

/// A checkpoint sealed before the history existed keeps its own bytes, forever.
///
/// This is the compatibility claim, stated as arithmetic rather than as a promise: the body a
/// pre-history deployment digested carries no snapshot field at all, so the digest over it is the
/// digest it always was. Every checkpoint already sealed and already anchored still verifies.
#[test]
fn a_checkpoint_sealed_before_the_history_still_verifies_under_its_own_encoding() {
    let checkpoint = seal(&book_with_a_settlement(), 1);
    assert_eq!(checkpoint.history_seq, None);
    assert!(checkpoint.body_hash_verifies());
    // And the bytes are literally the old ones: nothing named `history_seq` is in them.
    let body = checkpoint.signed_body();
    let field = b"history_seq";
    assert!(
        !body.windows(field.len()).any(|w| w == field),
        "a pre-history body must not grow a field it never had"
    );
}

/// A checkpoint sealed AS OF a snapshot carries it, and the digest covers it.
///
/// The figures a checkpoint seals are a materialised view of a lookup, so on their own they say
/// what the totals were without saying what they were true of. The number has to be inside the
/// signature or it is a claim anybody could swap afterwards.
#[test]
fn a_checkpoint_sealed_as_of_a_snapshot_carries_it_and_the_digest_covers_it() {
    let ledger = book_with_a_settlement();
    let cut = |seq: u64| {
        Checkpoint::seal_as_of(
            1,
            1,
            1_700_000_000,
            vec![ChainHead {
                node: 1,
                node_seq: 10,
                hash: [7u8; 32],
            }],
            ledger.book().snapshot(),
            5,
            99,
            HistorySeq(seq),
            Some(&StampSigner),
        )
        .unwrap()
    };

    let at_seven = cut(7);
    assert_eq!(at_seven.history_seq, Some(HistorySeq(7)));
    assert!(at_seven.body_hash_verifies());

    // The same totals at a different snapshot are a different body and a different signature. If
    // they were not, "these totals, at that history" would be a sentence the digest did not cover.
    let at_eight = cut(8);
    assert_ne!(at_seven.body_hash, at_eight.body_hash);
    assert_ne!(at_seven.signature, at_eight.signature);

    // And a snapshot swapped after sealing is caught, exactly as an edited figure is.
    let mut tampered = at_seven.clone();
    tampered.history_seq = Some(HistorySeq(8));
    assert!(!tampered.body_hash_verifies());

    // The pre-history body and the at-a-snapshot body are different bodies, so a checkpoint that
    // named a history cannot be read back as one that did not.
    assert_ne!(seal(&ledger, 1).body_hash, cut(0).body_hash);
}

/// The body is re-encoded deterministically with the heads sorted, snapshot or no snapshot.
///
/// The property the module already had, re-asserted across the new field: two verifiers holding the
/// same checkpoint produce the same bytes whatever order they received the heads in, and a
/// signature that depended on iteration order would verify only on the machine that made it.
#[test]
fn the_body_re_encodes_deterministically_with_the_heads_sorted_at_a_snapshot_too() {
    let ledger = book_with_a_settlement();
    let one_way = vec![
        ChainHead {
            node: 2,
            node_seq: 5,
            hash: [1u8; 32],
        },
        ChainHead {
            node: 1,
            node_seq: 9,
            hash: [2u8; 32],
        },
    ];
    // The SAME two heads, collected in the other order — which is what two nodes gathering the same
    // facts actually differ by.
    let other_way: Vec<ChainHead> = one_way.iter().rev().cloned().collect();
    let cut = |heads: Vec<ChainHead>| {
        Checkpoint::seal_as_of(
            1,
            1,
            10,
            heads,
            ledger.book().snapshot(),
            0,
            0,
            HistorySeq(3),
            Some(&StampSigner),
        )
        .unwrap()
    };
    let one = cut(one_way);
    let two = cut(other_way);
    assert_eq!(one.body_hash, two.body_hash);
    assert_eq!(one.signed_body(), two.signed_body());
    assert!(one.body_hash_verifies() && two.body_hash_verifies());

    // Re-encoding twice is the same bytes twice, which is what makes a verifier's answer stable.
    assert_eq!(one.signed_body(), one.signed_body());

    // And a checkpoint whose heads were stored out of order still verifies, because the encoder
    // sorts before it digests rather than trusting the order it was handed.
    let mut shuffled = one.clone();
    shuffled.heads.reverse();
    assert!(shuffled.body_hash_verifies());
}
