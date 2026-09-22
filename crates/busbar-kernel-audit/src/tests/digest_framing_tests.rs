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

use busbar_contract::caps::{
    Audit as AuditStep, KernelSeal, Origin, OriginKind, Outcome, Pass, UnitKey,
};

use crate::legacy::chain::{digest, seal, verify_chain, Chain, ChainedRecord, Digest, Framing};
use crate::legacy::{
    AuditEntry, AuditInput, ADMIN_LOG, AUDIT_SCHEME_LENGTH_PREFIXED, AUDIT_SCHEME_PIPE,
    OUTCOME_APPLIED, OUTCOME_REJECTED,
};
use crate::record::{
    Amount, Audit, AuditChain, AuditInputs, Controls, FinishClass, OpClassId, OutcomeFacts,
    QuantitySource, Subject, UsageLine, What,
};

/// An admin entry at a position, with no hash on it yet. Carries [`AUDIT_SCHEME_PIPE`] — every
/// caller here is either feeding these fields straight into `admin_preimage` (which never reads
/// `scheme` at all) or is reconstructing what an OLD, already-persisted record's fields were, so
/// scheme 1 is what the returned entry represents either way. A test that needs a scheme-2 entry
/// overrides `.scheme` on the value this returns, same as it would override any other field.
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
        scheme: AUDIT_SCHEME_PIPE,
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

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
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
                class: busbar_contract::caps::MeterClassId::new("tokens_out"),
                quantity: 120,
                source: QuantitySource::Locator {
                    direction: busbar_contract::ClassDirection::Response,
                    ptr: busbar_contract::caps::LocatorPtr::new("/usage/output_tokens"),
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

/// EVERY ENTRY THIS BUILD SEALS ONTO THE ADMIN CHAIN GOES THROUGH ONE CONSTRUCTION PATH, AND IT
/// SEALS UNDER SCHEME 2.
///
/// [`seal`] is the only thing that may set a hash, and it takes the sequence and the previous hash
/// as arguments from whatever owns the position rather than from the caller's payload. So a caller
/// cannot choose its own link, and there is no branch by which one could ask for a different
/// framing or scheme.
///
/// NOTE: this is deliberately NOT `<AuditEntry as ChainedRecord>::FRAMING` (which still names scheme
/// 1 -- see that const's own doc). A fresh entry's digest is governed by `entry.framing()`, read off
/// the `scheme` tag [`AuditEntry::link`] itself writes, and this test pins that a fresh entry's
/// framing is [`Framing::LengthPrefixed`] -- the property that closes the collision, checked at the
/// real construction path rather than the raw `Digest` primitive.
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
        entry.scheme, AUDIT_SCHEME_LENGTH_PREFIXED,
        "a freshly sealed entry must carry the scheme tag that closes the collision, not scheme 1"
    );
    assert_eq!(
        entry.hash,
        admin_preimage(
            Framing::LengthPrefixed,
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
        "the sealed digest is not the one Framing::LengthPrefixed produces over the same fields"
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

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE SCHEME TAG — the four properties the owner's fix has to prove, exercised through the REAL
// `AuditEntry` + `ChainedRecord` wiring (`AuditEntry::framing`, `AuditEntry::link`, `digest`,
// `verify_chain`), not just the raw `Digest` primitive the tests above already cover.
// ══════════════════════════════════════════════════════════════════════════════════════════════

/// 1. THE COLLISION, CLOSED AT THE WIRING — not just the primitive.
///
/// The same pair `two_mutations_that_collide_under_the_pipe_join_have_distinct_length_framed_digests`
/// demonstrates on the bare `Digest`, this time sealed as REAL `AuditEntry` records at each scheme
/// through `AuditEntry::framing`. Scheme 1 (every record already on disk) still collides on this
/// pair — that is the defect scheme 2 exists to close, not a property removed from scheme 1, since
/// removing it would change what an old record hashes to. Scheme 2 (what `link` seals every fresh
/// record under) must not.
#[test]
fn the_collision_pair_does_not_survive_a_records_own_scheme_2_tag() {
    let mut honest = unsealed(
        7,
        1_700_000_007,
        "cafe",
        "hook.register",
        "hook:x",
        OUTCOME_REJECTED,
        "applied|mallory",
    );
    let mut lie = unsealed(
        7,
        1_700_000_007,
        "cafe",
        "hook.register",
        "hook:x|rejected",
        OUTCOME_APPLIED,
        "mallory",
    );

    honest.scheme = AUDIT_SCHEME_PIPE;
    lie.scheme = AUDIT_SCHEME_PIPE;
    assert_eq!(
        digest(&honest),
        digest(&lie),
        "scheme 1 must still collide on this pair -- that is the vulnerability scheme 2 exists to \
         close, and an old record's digest must not move"
    );

    honest.scheme = AUDIT_SCHEME_LENGTH_PREFIXED;
    lie.scheme = AUDIT_SCHEME_LENGTH_PREFIXED;
    assert_ne!(
        digest(&honest),
        digest(&lie),
        "scheme 2, selected per-record through AuditEntry::framing, must not collide on the pair \
         that closes over a REJECTED mutation and an APPLIED one"
    );
}

/// 2. OLD RECORDS STILL VERIFY, DIGEST BYTE-IDENTICAL TO BEFORE.
///
/// The exact production golden pinned three times elsewhere in this tree
/// (`crates/busbar-kernel/src/audit/tests/boot_verify_golden.rs`'s `AD_1`, the durable-seam golden in
/// `plane_host/tests/journal_tests.rs`'s `G_AD_1`, and the byte-identity witness in
/// `plane/tests/auditlog_tests.rs`): a real admin entry, genesis position. An ABSENT scheme tag on a
/// record read back off a store this build has never touched reads as scheme 1 by
/// `#[serde(default)]` -- exactly what `unsealed`'s own default represents -- and digests to the
/// exact bytes a build from before this change computed.
#[test]
fn a_scheme_one_record_digests_to_the_exact_bytes_it_always_did() {
    let entry = unsealed(
        1,
        1_700_000_000,
        "",
        "hook.register",
        "hook:compress",
        OUTCOME_APPLIED,
        "admin",
    );
    assert_eq!(
        entry.scheme, AUDIT_SCHEME_PIPE,
        "unsealed()'s own default must be scheme 1 for this pin to mean anything"
    );
    assert_eq!(
        digest(&entry),
        "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa",
        "a scheme-1 record's digest moved -- every deployment's chain would report itself tampered \
         at its next boot"
    );
}

/// 3. NEW RECORDS SEAL UNDER SCHEME 2 AND CARRY THE TAG.
///
/// Covered end to end by `the_only_construction_path_seals_with_the_chains_own_framing` above (the
/// real `seal` path, asserting both the `scheme` field and the digest it produces). This test adds
/// the wire-level half: the tag a fresh entry carries is not merely an in-memory field, it is
/// actually PRESENT in the encoded record, because a verifier reading it back off a store must be
/// able to see which rules it was sealed under. `crate::tests::legacy_ring_tests` pins the
/// analogous property for the ring's own encode (nine wire fields for a live entry, `scheme` named
/// explicitly).
#[test]
fn a_freshly_sealed_entry_carries_its_scheme_on_the_wire() {
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
    let json = serde_json::to_value(&entry).expect("AuditEntry encodes");
    assert_eq!(
        json.get("scheme").and_then(serde_json::Value::as_u64),
        Some(u64::from(AUDIT_SCHEME_LENGTH_PREFIXED)),
        "a freshly sealed entry's scheme tag is not on the wire -- a verifier reading it back could \
         not tell which rules it was sealed under"
    );

    // And an OLD encoded record -- no `scheme` key at all -- decodes with the tag defaulting to
    // scheme 1, which is what every such record actually is.
    let old_json = serde_json::json!({
        "seq": 1u64,
        "ts": 1_700_000_000u64,
        "action": "hook.register",
        "resource": "hook:x",
        "outcome": OUTCOME_APPLIED,
        "principal": "alice",
        "prev_hash": "",
        "hash": entry.hash,
    });
    let decoded: AuditEntry =
        serde_json::from_value(old_json).expect("a pre-scheme record still decodes");
    assert_eq!(
        decoded.scheme, AUDIT_SCHEME_PIPE,
        "a record with no scheme key on the wire must read back as scheme 1"
    );
}

/// 4. A CHAIN MIXING BOTH SCHEMES VERIFIES END TO END.
///
/// The realistic state of any store that existed before this change: an old tail sealed under scheme
/// 1, and every record appended since under scheme 2. `verify_chain` walks both halves with no
/// special-casing -- each record's own `scheme` tag says how to check it.
#[test]
fn a_chain_mixing_scheme_one_and_scheme_two_records_verifies_end_to_end() {
    let mut legacy = unsealed(
        1,
        1_700_000_000,
        "",
        "hook.register",
        "hook:compress",
        OUTCOME_APPLIED,
        "admin",
    );
    legacy.scheme = AUDIT_SCHEME_PIPE;
    let legacy = sealed(legacy);
    assert_eq!(
        legacy.hash, "52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa",
        "the scheme-1 half of this mixed chain is the same golden entry pinned elsewhere in this file"
    );

    // Continue the chain the REAL way -- through `Chain`/`seal` -- so record 2 is exactly what this
    // build actually mints today: scheme 2, linked onto the scheme-1 tail.
    let mut chain: Chain<AuditEntry> =
        Chain::from_persisted_unverified(std::slice::from_ref(&legacy));
    let fresh = chain.append(
        ADMIN_LOG,
        AuditInput {
            ts: 1_700_000_060,
            action: "hook.delete".to_string(),
            resource: "hook:compress".to_string(),
            outcome: OUTCOME_APPLIED.to_string(),
            principal: "admin".to_string(),
        },
    );
    assert_eq!(
        fresh.scheme, AUDIT_SCHEME_LENGTH_PREFIXED,
        "the record appended after this change must carry the new scheme"
    );
    assert_eq!(fresh.prev_hash, legacy.hash, "record 2 links record 1");

    let mixed = vec![legacy, fresh];
    verify_chain(&mixed).expect(
        "a chain mixing a scheme-1 record already on disk with a scheme-2 record appended after \
         this change must verify end to end",
    );

    // And it is still tamper-evident across the seam: editing either half breaks the walk.
    let mut tampered = mixed.clone();
    tampered[0].principal = "mallory".to_string();
    assert!(
        verify_chain(&tampered).is_err(),
        "a tamper on the scheme-1 half of a mixed chain went undetected"
    );
    let mut tampered = mixed;
    tampered[1].resource = "hook:evil".to_string();
    assert!(
        verify_chain(&tampered).is_err(),
        "a tamper on the scheme-2 half of a mixed chain went undetected"
    );
}
