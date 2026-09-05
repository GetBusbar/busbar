// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checkpoints: sealing, signing, anchoring, and the verification that closes a window.

use std::collections::BTreeMap;

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
    ledger.settle(&k, 1, hold("a", 600), &usage("tokens", 450), &token);
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

#[test]
fn consecutive_anchor_failures_are_counted_so_they_can_be_alarmed_on() {
    use crate::checkpoint::AnchorState;
    let mut state = AnchorState::default();
    for _ in 0..3 {
        state.consecutive_failures += 1;
    }
    assert!(!state.should_alarm(4));
    assert!(state.should_alarm(3));
    let _ = AnchorError::ReadBackDiffers;
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
    ledger.settle(&k, 1, hold("a", 200), &usage("tokens", 200), &token);
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
