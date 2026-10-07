// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Checkpoints: sealing, signing, anchoring, and the verification that closes a window.

use std::collections::BTreeMap;

use crate::checkpoint::{AnchorError, Checkpoint, CheckpointSecret, SignError, Signature};
use crate::totals::{Totals, WindowStart};
use crate::verify::{verify, AllWindowsOpen};

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
    let findings = verify(&checkpoint, &now, &AllWindowsOpen, None);
    assert_eq!(findings.len(), 1, "a new unbalanced key must be found");
}

/// **THE SEAL AND THE VERIFY SHARE ONE PREIMAGE AND ONE DIGEST (item 438).**
///
/// The seal used to encode its own body from its arguments and hash it, while the verify re-encoded
/// from the checkpoint's fields and hashed that: two encoder calls and two digest calls for one
/// preimage, which is exactly the drift `digest.rs` warns about. Now both go through
/// `body_digest` over `signed_body`, and this counts the call sites so a second one cannot return.
#[test]
fn the_seal_and_the_verify_share_one_preimage_and_one_digest() {
    let source = include_str!("../checkpoint.rs");
    let calls = |needle: &str| {
        source
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .filter(|l| l.contains(needle) && !l.contains(&format!("fn {needle}")))
            .count()
    };
    assert_eq!(calls("encode_body("), 1, "one encoder call: signed_body");
    assert_eq!(calls("digest::sha256("), 1, "one digest call: body_digest");
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
