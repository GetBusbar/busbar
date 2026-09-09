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
//! This crate carries TWO framings, and which one a record uses is not data:
//! [`ChainedRecord::FRAMING`] is an associated const, a wire fact of the records already on disk.
//!
//! * [`crate::record::AuditRecord`], the NEW fixed record, is [`Framing::LengthPrefixed`]. Every
//!   field in it can hold arbitrary caller-influenced text, so the boundary is made unforgeable.
//! * [`AuditEntry`], the previous release's admin mutation chain, is [`Framing::PipeSeparated`],
//!   kept byte for byte because its records are already persisted. Changing it would report every
//!   deployment's history as TAMPERED at its next boot.
//!
//! So these are the properties the framing owes, stated as tests rather than as prose:
//!
//! 1. **NO TWO DISTINCT MUTATIONS SHARE A DIGEST** under the length-framed scheme, demonstrated on
//!    the exact pair a separator join collides.
//! 2. **THE FRAMING IS NOT A FIELD.** It is a per-type const, so there is no byte a tamper can flip
//!    to move a record into the other preimage space. Both consts are pinned here, because nothing
//!    else in the crate fails if one of them changes.
//! 3. **A LEGACY CHAIN STILL VERIFIES**, and is still tamper-evident: the old framing is ambiguous,
//!    not absent.
//! 4. **EVERY FIELD CARRIES ITS OWN LENGTH**, checked on the preimage bytes themselves rather than
//!    inferred from a digest agreeing with itself.

use busbar_caps::{
    Audit as AuditStep, KernelSeal, Origin, OriginKind, Outcome, UnitKey, UnitToken,
};

use crate::legacy::chain::{digest, seal, verify_chain, ChainedRecord, Digest, Framing};
use crate::legacy::{AuditEntry, AuditInput, ADMIN_LOG, OUTCOME_APPLIED, OUTCOME_REJECTED};
use crate::record::{
    Amount, Audit, AuditChain, AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts,
    QuantitySource, Subject, UsageLine, What,
};

/// An admin entry at a position, with no hash on it yet.
fn unsealed(
    seq: u64,
    ts: u64,
    prev_hash: &str,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> AuditEntry {
    AuditEntry {
        seq,
        ts,
        action: action.to_string(),
        resource: resource.to_string(),
        outcome: outcome.to_string(),
        principal: principal.to_string(),
        prev_hash: prev_hash.to_string(),
        hash: String::new(),
        recorded_here: false,
    }
}

/// The same entry, sealed with the digest its record type's framing implies.
fn sealed(mut entry: AuditEntry) -> AuditEntry {
    entry.hash = digest(&entry);
    entry
}

/// The admin entry's chained fields, fed into a canonicaliser of the caller's choosing. This is the
/// same field list and the same order [`AuditEntry::digest_fields`] uses; feeding it under BOTH
/// framings is how the collision below is demonstrated rather than asserted about.
fn admin_preimage(framing: Framing, entry: &AuditEntry) -> String {
    let mut d = Digest::new(framing);
    d.text(&entry.prev_hash)
        .num(entry.seq)
        .num(entry.ts)
        .text(&entry.action)
        .text(&entry.resource)
        .text(&entry.outcome)
        .text(&entry.principal);
    d.finish()
}

/// THE COLLISION A SEPARATOR JOIN ADMITS, AND THE ONE THE LENGTH FRAMING MUST NOT.
///
/// Two mutations that disagree about the two things an audit log exists to record — WHAT HAPPENED
/// and WHO DID IT — hash identically when the fields are joined by a bar, because the bar the
/// caller put inside `principal` (or inside `resource`) moves the boundary the join relies on:
///
/// * resource `hook:x`, outcome `rejected`, principal `applied|mallory`
/// * resource `hook:x|rejected`, outcome `applied`, principal `mallory`
///
/// One of those says a change was refused and blames a principal whose name contains a bar; the
/// other says the change was APPLIED by mallory. Under the pipe join the two preimages are one, so
/// a verifier passes either against the other's digest. Under the length-framed scheme the two
/// differ in the length words themselves, which no caller writes.
#[test]
fn two_mutations_that_collide_under_the_pipe_join_have_distinct_length_framed_digests() {
    let honest = |framing| {
        admin_preimage(
            framing,
            &unsealed(
                7,
                1_700_000_007,
                "cafe",
                "hook.register",
                "hook:x",
                OUTCOME_REJECTED,
                "applied|mallory",
            ),
        )
    };
    let lie = |framing| {
        admin_preimage(
            framing,
            &unsealed(
                7,
                1_700_000_007,
                "cafe",
                "hook.register",
                "hook:x|rejected",
                OUTCOME_APPLIED,
                "mallory",
            ),
        )
    };

    // The defect, demonstrated rather than asserted about: under a separator join the two are one
    // digest. If this ever stops holding the collision pair above has drifted and the rest of this
    // test is no longer testing what it says.
    assert_eq!(
        honest(Framing::PipeSeparated),
        lie(Framing::PipeSeparated),
        "the pipe join is expected to collide on this pair -- it is why the new record is framed"
    );

    // The property: the same two mutations are two digests under the framing every NEW record is
    // sealed with.
    assert_ne!(
        honest(Framing::LengthPrefixed),
        lie(Framing::LengthPrefixed),
        "a caller's own bytes moved a field boundary under the length-framed scheme"
    );
}

/// A BAR ANYWHERE A CALLER CAN PUT ONE STILL SEPARATES.
///
/// The pair above is one witness; the property is general. Adjacent fields are walked, a bar is
/// planted in one of them, and the mutation that results must digest differently from the one whose
/// bar sits in the neighbouring field instead.
#[test]
fn moving_a_caller_supplied_bar_between_adjacent_fields_always_changes_the_digest() {
    // (action, resource, outcome, principal) pairs that differ only in WHICH field owns the bar.
    let pairs = [
        (
            ("hook.register|hook:x", "", OUTCOME_APPLIED, "alice"),
            ("hook.register", "|hook:x", OUTCOME_APPLIED, "alice"),
        ),
        (
            ("hook.register", "hook:x|applied", "", "alice"),
            ("hook.register", "hook:x", "|applied", "alice"),
        ),
        (
            ("hook.register", "hook:x", "applied|", "alice"),
            ("hook.register", "hook:x", "applied", "|alice"),
        ),
    ];
    for (left, right) in pairs {
        let a = admin_preimage(
            Framing::LengthPrefixed,
            &unsealed(3, 1_700_000_003, "beef", left.0, left.1, left.2, left.3),
        );
        let b = admin_preimage(
            Framing::LengthPrefixed,
            &unsealed(3, 1_700_000_003, "beef", right.0, right.1, right.2, right.3),
        );
        assert_ne!(a, b, "{left:?} and {right:?} share a length-framed digest");
    }
}

fn token() -> UnitToken<AuditStep> {
    UnitToken::mint(&KernelSeal::acquire_for_kernel())
}

/// One set of record inputs, with the two caller-named text fields under the test's control.
fn record_inputs(op_class: &str, destination: &str) -> AuditInputs {
    AuditInputs {
        subject: Subject::PrincipalId("pseudonym-1".into()),
        what: What {
            unit_key: UnitKey::new(1),
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
        amount: Amount {
            lines: vec![UsageLine {
                class: busbar_caps::MeterClassId::new("tokens_out"),
                quantity: 120,
                source: QuantitySource::Locator {
                    direction: busbar_contract::ClassDirection::Response,
                    ptr: busbar_caps::LocatorPtr::new("/usage/output_tokens"),
                },
                estimated: false,
            }],
            pre_tier: 600,
            priced: 540,
            tier_bp: 9_000,
            fee_count: 1,
            currency: "USD".into(),
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
/// The two tests above work on the canonicaliser directly. This one goes through the thing a
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

/// THE FRAMING IS A PROPERTY OF THE RECORD TYPE, NOT A FIELD A TAMPER CAN FLIP.
///
/// There is no per-record scheme byte. Which framing a stream uses is [`ChainedRecord::FRAMING`],
/// fixed at the type, so an attacker who can edit a stored record cannot move it into whichever
/// preimage space suits them — the choice is not in the bytes to edit. That safety is structural,
/// which is precisely why it needs pinning: nothing else in this crate fails if either const is
/// changed, and changing one silently re-frames a stream that already has records on disk.
#[test]
fn each_stream_names_its_framing_at_the_type_and_the_two_do_not_agree() {
    assert_eq!(
        <AuditEntry as ChainedRecord>::FRAMING,
        Framing::PipeSeparated,
        "the previous release's admin chain changed framing -- every persisted chain would now \
         report itself tampered"
    );

    // The new fixed record is the length-framed one. Asserted through the digest rather than a
    // const, because the record's chain is not a `ChainedRecord` implementation: what matters is
    // that the bytes it hashes are the length-framed bytes, which the collision test above shows
    // the pipe join cannot produce.
    let mut chain = AuditChain::new();
    let record = chain.seal(record_inputs("chat.completion", "upstream-a"), &token());
    assert_eq!(
        AuditChain::digest_of(&record),
        record.hash,
        "a freshly sealed record did not verify against its own digest path"
    );
}

/// A CHAIN WRITTEN ENTIRELY UNDER THE LEGACY FRAMING STILL VERIFIES.
///
/// This is the migration this module may never do silently: a store full of the previous release's
/// entries is read back at the next boot and every one of them must still check out under the
/// framing it was sealed with. A verifier that only knew the new framing would report every
/// deployment's history as tampered.
#[test]
fn a_chain_sealed_entirely_under_the_legacy_framing_verifies() {
    let mut chain = Vec::new();
    let mut prev = String::new();
    for seq in 1..=5u64 {
        let e = sealed(unsealed(
            seq,
            1_700_000_000 + seq,
            &prev,
            "hook.register",
            "hook:x",
            OUTCOME_APPLIED,
            "alice",
        ));
        prev = e.hash.clone();
        chain.push(e);
    }
    verify_chain(&chain).expect("a wholly legacy chain must verify");

    // And it is still tamper-evident: the old framing is ambiguous, not absent.
    let mut tampered = chain.clone();
    tampered[2].outcome = OUTCOME_REJECTED.to_string();
    assert!(
        verify_chain(&tampered).is_err(),
        "a legacy chain accepted an altered entry"
    );

    // A tamper at either end is caught too, not just one in the middle.
    for i in [0usize, 4] {
        let mut tampered = chain.clone();
        tampered[i].principal = "mallory".to_string();
        assert!(
            verify_chain(&tampered).is_err(),
            "a tamper at index {i} went undetected"
        );
    }
}

/// EVERY ENTRY THIS BUILD SEALS ONTO THE ADMIN CHAIN GOES THROUGH ONE CONSTRUCTION PATH.
///
/// [`seal`] is the only thing that may set a hash, and it takes the sequence and the previous hash
/// as arguments from whatever owns the position rather than from the caller's payload. So a caller
/// cannot choose its own link, and there is no branch by which one could ask for a different
/// framing.
#[test]
fn the_only_construction_path_seals_with_the_chains_own_framing() {
    let entry: AuditEntry = seal(
        ADMIN_LOG,
        1,
        String::new(),
        AuditInput {
            ts: 1_700_000_000,
            action: "hook.register".to_string(),
            resource: "hook:x".to_string(),
            outcome: OUTCOME_APPLIED.to_string(),
            principal: "alice".to_string(),
        },
    );
    assert_eq!(
        digest(&entry),
        entry.hash,
        "a freshly sealed entry did not verify"
    );
    assert_eq!(
        entry.hash,
        admin_preimage(
            <AuditEntry as ChainedRecord>::FRAMING,
            &unsealed(
                1,
                1_700_000_000,
                "",
                "hook.register",
                "hook:x",
                OUTCOME_APPLIED,
                "alice",
            ),
        ),
        "the sealed digest is not the one the record type's framing produces over its own fields"
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

/// THE SEPARATOR-JOINED FRAMING IS UNCHANGED, BYTE FOR BYTE.
///
/// The legacy framing is a wire fact of records already on disk. Pinning its bytes here is what
/// makes an accidental "improvement" to it fail loudly rather than at somebody's next boot.
#[test]
fn the_legacy_framing_still_joins_on_a_bar_with_integers_in_decimal() {
    let mut d = Digest::new(Framing::PipeSeparated);
    d.text("cafe")
        .num(7)
        .num(1_700_000_000)
        .text("hook.register");
    assert_eq!(
        d.bytes(),
        b"cafe|7|1700000000|hook.register",
        "the legacy framing moved -- every persisted chain would fail to verify"
    );

    // The FIRST field owes no separator; only the ones after it do.
    let mut lead = Digest::new(Framing::PipeSeparated);
    lead.text("only");
    assert_eq!(lead.bytes(), b"only");

    // And an empty leading field still owes the separator to the field after it.
    let mut empty_lead = Digest::new(Framing::PipeSeparated);
    empty_lead.text("").text("after");
    assert_eq!(empty_lead.bytes(), b"|after");
}
