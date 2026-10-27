// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checkpoints: sealing, signing, anchoring, and the verification measured from one.

use std::collections::BTreeMap;

use crate::checkpoint::{
    AnchorError, ChainHead, Checkpoint, CheckpointSecret, SignError, Signature,
};
use crate::totals::{Totals, WindowStart};
use crate::verify::{sequences_are_monotonic, verify, Finding};

use super::fixtures::key;

struct NoKey;

impl CheckpointSecret for NoKey {
    fn sign(&self, _body: &[u8]) -> Result<Signature, SignError> {
        Err(SignError::KeyUnavailable("under test".into()))
    }
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

/// An anchor sink that read back something else is a DISTINCT failure from an unreachable one.
///
/// (A consecutive-failure counter, `AnchorState`, and its threshold check had no production
/// construction site and are deleted with the half of this test that pinned the threshold.)
#[test]
fn a_read_back_that_differs_is_its_own_anchor_failure() {
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
    let findings = verify(&checkpoint, &now, None);
    assert_eq!(findings.len(), 1, "a new unbalanced key must be found");
}

fn sealed_with_fees(fee_count: u64) -> Checkpoint {
    let mut totals = BTreeMap::new();
    totals.insert(
        (key("b"), 1 as WindowStart),
        Totals {
            settled: 500,
            fee_count,
            ..Totals::zero()
        },
    );
    Checkpoint::seal(1, 1, 10, Vec::new(), totals, 0, 0, None).unwrap()
}

/// **EVERY SEALED FIGURE IS UNDER THE DIGEST, THE FEE COUNT INCLUDED** (RED arm).
///
/// The fee count was sealed beside the figures and left out of the body, so editing it after the
/// seal still verified: a checkpoint could be made to say a window billed any number of requests
/// and the digest would vouch for it. Now an edited count is an edited checkpoint.
#[test]
fn an_edited_fee_count_is_an_edited_checkpoint() {
    let mut checkpoint = sealed_with_fees(3);
    assert!(checkpoint.body_hash_verifies());
    let cell = checkpoint
        .totals
        .get_mut(&(key("b"), 1 as WindowStart))
        .expect("the sealed row");
    cell.fee_count = 4;
    assert!(
        !checkpoint.body_hash_verifies(),
        "a fee count edited after sealing must fail the digest"
    );
    // And a count edited down to nothing: the field's absence is not a way round it.
    let mut zeroed = sealed_with_fees(3);
    zeroed
        .totals
        .get_mut(&(key("b"), 1 as WindowStart))
        .expect("the sealed row")
        .fee_count = 0;
    assert!(!zeroed.body_hash_verifies());
}

/// A checkpoint that seals no fee count keeps the exact bytes it always had, so every body sealed
/// before the count joined the digest still hashes to its own stored digest.
#[test]
fn a_checkpoint_with_no_fee_count_keeps_its_bytes() {
    let none = sealed_with_fees(0);
    let some = sealed_with_fees(2);
    let tail = |body: &[u8]| body.windows(b"fee_count".len()).any(|w| w == b"fee_count");
    assert!(!tail(&none.signed_body()), "no fee count, no framed field");
    assert!(tail(&some.signed_body()), "a fee count is framed by name");
    assert!(none.signed_body().len() < some.signed_body().len());
    assert_ne!(none.body_hash, some.body_hash);
}

fn sealed_with_heads(checkpoint_seq: u64, heads: Vec<ChainHead>) -> Checkpoint {
    Checkpoint::seal(checkpoint_seq, 1, 10, heads, BTreeMap::new(), 0, 0, None)
        .expect("an unsigned checkpoint seals")
}

fn head(node: u64, node_seq: u64, hash_byte: u8) -> ChainHead {
    ChainHead {
        node,
        node_seq,
        hash: [hash_byte; 32],
    }
}

/// A node whose chain head the earlier checkpoint held and the newer one does not is a chain that
/// was REMOVED. Walking only the newer checkpoint's heads never met it, so a vanished chain passed.
#[test]
fn a_chain_head_that_vanished_between_two_checkpoints_is_found() {
    let earlier = sealed_with_heads(1, vec![head(1, 10, 1), head(2, 7, 2)]);
    let newer = sealed_with_heads(2, vec![head(1, 12, 3)]);
    let findings = sequences_are_monotonic(&earlier, &newer);
    assert_eq!(
        findings,
        vec![Finding::ChainHeadRemoved { node: 2, was: 7 }]
    );
    assert!(findings[0].to_string().contains("REMOVED"));
}

/// A head at the same sequence with a different hash is an entry REWRITTEN in place; the sequence
/// alone cannot see it. An idle node — same sequence, same hash — and a chain that began between the
/// two seals are both ordinary and find nothing.
#[test]
fn a_chain_head_rewritten_at_the_same_sequence_is_found() {
    let earlier = sealed_with_heads(1, vec![head(1, 10, 1)]);
    let rewritten = sealed_with_heads(2, vec![head(1, 10, 9)]);
    assert_eq!(
        sequences_are_monotonic(&earlier, &rewritten),
        vec![Finding::ChainHeadRewritten {
            node: 1,
            node_seq: 10
        }]
    );

    let idle = sealed_with_heads(2, vec![head(1, 10, 1)]);
    assert!(sequences_are_monotonic(&earlier, &idle).is_empty());
    let grown = sealed_with_heads(2, vec![head(1, 11, 4), head(3, 1, 5)]);
    assert!(sequences_are_monotonic(&earlier, &grown).is_empty());
    let backwards = sealed_with_heads(2, vec![head(1, 9, 1)]);
    assert_eq!(
        sequences_are_monotonic(&earlier, &backwards),
        vec![Finding::SequenceNotMonotonic {
            node: 1,
            was: 10,
            now: 9
        }]
    );
}
