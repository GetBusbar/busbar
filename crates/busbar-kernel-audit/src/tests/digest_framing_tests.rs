// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMING IS THE EVIDENCE.
//!
//! An audit digest exists to make one claim: these bytes are the mutation that happened, and no
//! other. That claim is only as strong as the map from fields to preimage being INJECTIVE — two
//! different mutations must never produce one preimage. A separator join is not injective whenever
//! a field can contain the separator, because a bar the caller put inside one field moves the
//! boundary the join relies on.
//!
//! [`crate::record::AuditRecord`], the fixed record, is [`Framing::LengthPrefixed`]. Every field in
//! it can hold arbitrary caller-influenced text, so the boundary is made unforgeable. The properties
//! the framing owes are stated here as tests rather than as prose:
//!
//! 1. **A bar moved between two caller-named fields changes the digest**, on the record's own
//!    digest path.
//! 2. **Every field carries its own length**, checked on the preimage bytes themselves rather than
//!    inferred from a digest agreeing with itself.

use busbar_contract::caps::{
    Audit as AuditStep, KernelSeal, Origin, OriginKind, Outcome, Pass, UnitKey,
};

use crate::digest::{Digest, Framing};
use crate::record::{
    Audit, AuditChain, AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts, QuantitySource,
    Subject, Usage, UsageLine, What,
};

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

/// One set of record inputs, with the two caller-named text fields under the test's control.
fn record_inputs(op_class: &str, destination: &str) -> AuditInputs {
    AuditInputs {
        subject: Subject::PrincipalId("pseudonym-1".into()),
        what: What {
            unit_key: UnitKey::new(1),
            incarnation: 0,
            op_class: OpClassId::new(op_class),
            destination: Some(destination.into()),
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 1_700_000_000,
        mono: 1_000,
        origin: Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client),
        outcome: OutcomeFacts {
            unit_end: Outcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines: vec![UsageLine {
                class: busbar_contract::caps::MeterClassId::new("tokens_out"),
                quantity: 120,
                source: QuantitySource::Locator {
                    direction: busbar_contract::ClassDirection::Response,
                    ptr: busbar_contract::caps::LocatorPtr::new("/usage/output_tokens"),
                },
                estimated: false,
            }],
            tier_bp: 9_000,
            fee_count: 1,
            rate_card_version: 3,
            bucket_chain_ref: "chain:free>paid".into(),
        },
        controls: Controls {
            hold_ref: None,
            settle_ref: None,
            slice_ref: None,
            lease_ref: None,
            lease_epoch: 0,
            policy_epoch: 0,
            hooks_applied: Vec::new(),
            replayed: false,
            children: Vec::new(),
        },
        correlation_label: None,
    }
}

/// THE NEW RECORD'S OWN FIELDS SEPARATE, ON THE RECORD'S OWN DIGEST PATH.
///
/// A test on the canonicaliser alone is not enough. This one goes through the thing a
/// deployment actually verifies with — [`AuditChain::digest_of`] — because a framing that were
/// correct in isolation and mis-wired at the record would still let the log agree with a lie. The
/// operation class and the destination are adjacent caller-named text fields, which is exactly the
/// adjacency a separator join cannot defend: `("a|b", "c")` and `("a", "b|c")` join to the same
/// `a|b|c` and must not digest the same.
#[test]
fn a_bar_moved_between_two_caller_named_fields_of_the_new_record_changes_its_digest() {
    let mut chain = AuditChain::new();
    let left = chain.seal(record_inputs("chat.completion|upstream-a", "eu"), &token());

    let mut chain = AuditChain::new();
    let right = chain.seal(record_inputs("chat.completion", "upstream-a|eu"), &token());

    assert_ne!(
        AuditChain::digest_of(&left),
        AuditChain::digest_of(&right),
        "moving a bar between the operation class and the destination did not change the digest"
    );

    // And the digest each record carries is the one its own fields produce, so a record re-sealed
    // with the other's digest does not verify.
    let mut forged = right.clone();
    forged.hash = left.hash.clone();
    assert_ne!(
        AuditChain::digest_of(&forged),
        forged.hash,
        "a record re-sealed with a different record's digest verified"
    );
}

/// THE LENGTH WORD IS REALLY THERE, ON THE PREIMAGE BYTES.
///
/// Checked on the canonicaliser's own buffer rather than through a digest, because a digest that
/// merely agrees with itself would agree just as happily under a framing that omitted the lengths.
/// Each field must appear as a big-endian eight-byte length followed by exactly that many bytes,
/// and the buffer must end exactly at the last field -- no padding, no separator.
#[test]
fn every_field_of_a_length_framed_preimage_is_preceded_by_its_own_eight_byte_length() {
    let mut d = Digest::new(Framing::LengthPrefixed);
    d.text("").text("a").text("bar|inside").num(u64::MAX);

    let buf = d.bytes().to_vec();
    let mut at = 0usize;
    let mut fields: Vec<Vec<u8>> = Vec::new();
    while at < buf.len() {
        assert!(
            at + 8 <= buf.len(),
            "the buffer ended inside a length word at offset {at}"
        );
        let len = u64::from_be_bytes(buf[at..at + 8].try_into().unwrap()) as usize;
        at += 8;
        assert!(
            at + len <= buf.len(),
            "a length word at offset {at} claimed {len} bytes the buffer does not hold"
        );
        fields.push(buf[at..at + len].to_vec());
        at += len;
    }
    assert_eq!(
        at,
        buf.len(),
        "the preimage did not end on a field boundary"
    );
    assert_eq!(
        fields,
        vec![
            b"".to_vec(),
            b"a".to_vec(),
            b"bar|inside".to_vec(),
            u64::MAX.to_be_bytes().to_vec(),
        ],
        "the framed fields are not the fields that were fed in"
    );

    // An integer is its eight-byte big-endian form, NOT its decimal text: the two framings disagree
    // about that, and a number that framed as text would be one a caller's digits could imitate.
    let mut as_num = Digest::new(Framing::LengthPrefixed);
    as_num.num(7);
    let mut as_text = Digest::new(Framing::LengthPrefixed);
    as_text.text("7");
    assert_ne!(
        as_num.bytes(),
        as_text.bytes(),
        "an integer framed as its decimal text"
    );
}
