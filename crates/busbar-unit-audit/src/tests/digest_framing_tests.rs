// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FRAMING IS THE EVIDENCE.
//!
//! An audit digest exists to make one claim: these bytes are the mutation that happened, and no
//! other. That claim is only as strong as the map from fields to preimage being INJECTIVE — two
//! different mutations must never produce one preimage. The legacy pipe join was not injective,
//! because `resource` and `principal` are free text a caller hands in and a bar inside either moved
//! the field boundaries.
//!
//! So these are the properties the framing owes, stated as tests rather than as prose:
//!
//! 1. **NO TWO DISTINCT MUTATIONS SHARE A DIGEST.** Demonstrated on the exact pair the legacy
//!    framing collides, which must separate under the new one.
//! 2. **THE VERSION IS INSIDE WHAT IS SIGNED.** An entry relabelled from one scheme to the other
//!    stops verifying, so a chain cannot be walked backwards into the ambiguous framing.
//! 3. **A LEGACY CHAIN STILL VERIFIES**, and a chain that CROSSES the upgrade verifies as one
//!    chain, each entry under its own framing.
//! 4. **EVERY FIELD CARRIES ITS OWN LENGTH**, checked on the preimage bytes themselves rather than
//!    inferred from a digest agreeing with itself.

use crate::legacy::chain::{digest, seal, verify_chain, Digest, Framing};
use crate::legacy::entry::{DIGEST_SCHEME_LEGACY_PIPE, DIGEST_SCHEME_LEN_PREFIXED};
use crate::legacy::{AuditEntry, AuditInput, ADMIN_LOG, OUTCOME_APPLIED, OUTCOME_REJECTED};

/// Build an entry at a position under a chosen scheme, sealed with the digest that scheme implies.
fn sealed_under(
    scheme: u8,
    seq: u64,
    prev_hash: &str,
    action: &str,
    resource: &str,
    outcome: &str,
    principal: &str,
) -> AuditEntry {
    let mut entry = AuditEntry {
        seq,
        ts: 1_700_000_000 + seq,
        action: action.to_string(),
        resource: resource.to_string(),
        outcome: outcome.to_string(),
        principal: principal.to_string(),
        prev_hash: prev_hash.to_string(),
        hash: String::new(),
        digest_scheme: scheme,
        recorded_here: false,
    };
    entry.hash = digest(&entry);
    entry
}

/// THE COLLISION THE LEGACY FRAMING ADMITS, AND THE ONE THE NEW FRAMING MUST NOT.
///
/// Two mutations that disagree about the two things an audit log exists to record — WHAT HAPPENED
/// and WHO DID IT — hash identically when the fields are joined by a bar, because the bar the
/// caller put inside `principal` (or inside `resource`) moves the boundary the join relies on:
///
/// * resource `hook:x`, outcome `rejected`, principal `applied|mallory`
/// * resource `hook:x|rejected`, outcome `applied`, principal `mallory`
///
/// One of those says a change was refused and blames a principal whose name contains a bar; the
/// other says the change was APPLIED by mallory. Under the pipe join the chain verifier passes
/// either against the other's digest, so the log agrees with the lie. Under the length-framed
/// scheme the two preimages differ in the length words themselves, which no caller writes.
#[test]
fn two_admin_mutations_that_collide_under_the_pipe_join_have_distinct_length_framed_digests() {
    let honest = |scheme| {
        sealed_under(
            scheme,
            7,
            "cafe",
            "hook.register",
            "hook:x",
            OUTCOME_REJECTED,
            "applied|mallory",
        )
    };
    let lie = |scheme| {
        sealed_under(
            scheme,
            7,
            "cafe",
            "hook.register",
            "hook:x|rejected",
            OUTCOME_APPLIED,
            "mallory",
        )
    };

    // The defect, demonstrated rather than asserted about: under the legacy framing the two are one
    // digest. If this ever stops holding the collision pair above has drifted and the rest of this
    // test is no longer testing what it says.
    assert_eq!(
        honest(DIGEST_SCHEME_LEGACY_PIPE).hash,
        lie(DIGEST_SCHEME_LEGACY_PIPE).hash,
        "the pipe join is expected to collide on this pair -- it is why the framing was replaced"
    );

    // The property: the same two mutations are two digests under the framing every new entry is
    // sealed with.
    assert_ne!(
        honest(DIGEST_SCHEME_LEN_PREFIXED).hash,
        lie(DIGEST_SCHEME_LEN_PREFIXED).hash,
        "a caller's own bytes moved a field boundary under the length-framed scheme"
    );

    // And the digest each entry carries is the one its own framing produces, so the verifier
    // separates them too: the honest record's digest must not verify the lie.
    let mut forged = lie(DIGEST_SCHEME_LEN_PREFIXED);
    forged.hash = honest(DIGEST_SCHEME_LEN_PREFIXED).hash.clone();
    assert_ne!(
        digest(&forged),
        forged.hash,
        "an entry re-sealed with a different mutation's digest verified"
    );
}

/// A BAR ANYWHERE A CALLER CAN PUT ONE STILL SEPARATES.
///
/// The pair above is one witness; the property is general. Every field a caller supplies is walked,
/// a bar is planted in it, and the mutation that results must digest differently from the one whose
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
        let a = sealed_under(
            DIGEST_SCHEME_LEN_PREFIXED,
            3,
            "beef",
            left.0,
            left.1,
            left.2,
            left.3,
        );
        let b = sealed_under(
            DIGEST_SCHEME_LEN_PREFIXED,
            3,
            "beef",
            right.0,
            right.1,
            right.2,
            right.3,
        );
        assert_ne!(
            a.hash, b.hash,
            "{left:?} and {right:?} share a length-framed digest"
        );
    }
}

/// THE SCHEME TAG IS INSIDE THE PREIMAGE, NOT BESIDE IT.
///
/// Relabelling an entry's `digest_scheme` must not be a way to get it verified under the other
/// framing: if the version merely SELECTED a framing without entering the bytes, an attacker who
/// could flip the byte could move a record into whichever preimage space suited them.
#[test]
fn an_entry_relabelled_into_the_other_scheme_stops_verifying() {
    let modern = sealed_under(
        DIGEST_SCHEME_LEN_PREFIXED,
        4,
        "d00d",
        "key.rotate",
        "key:9",
        OUTCOME_APPLIED,
        "alice",
    );
    let mut downgraded = modern.clone();
    downgraded.digest_scheme = DIGEST_SCHEME_LEGACY_PIPE;
    assert_ne!(
        digest(&downgraded),
        downgraded.hash,
        "a scheme 2 entry relabelled as scheme 1 still verified"
    );

    let legacy = sealed_under(
        DIGEST_SCHEME_LEGACY_PIPE,
        4,
        "d00d",
        "key.rotate",
        "key:9",
        OUTCOME_APPLIED,
        "alice",
    );
    let mut upgraded = legacy.clone();
    upgraded.digest_scheme = DIGEST_SCHEME_LEN_PREFIXED;
    assert_ne!(
        digest(&upgraded),
        upgraded.hash,
        "a scheme 1 entry relabelled as scheme 2 still verified"
    );

    // The two spaces are disjoint even for identical field values.
    assert_ne!(
        modern.hash, legacy.hash,
        "the two schemes produced one digest for one set of fields"
    );
}

/// A CHAIN WRITTEN ENTIRELY BEFORE THE UPGRADE STILL VERIFIES.
///
/// This is the migration this module may never do silently: a store full of 1.5.5 entries is read
/// back at the next boot and every one of them must still check out under the framing it was sealed
/// with. A verifier that only knew the new framing would report every deployment's history as
/// tampered.
#[test]
fn a_chain_sealed_entirely_under_the_legacy_framing_verifies() {
    let mut chain = Vec::new();
    let mut prev = String::new();
    for seq in 1..=5u64 {
        let e = sealed_under(
            DIGEST_SCHEME_LEGACY_PIPE,
            seq,
            &prev,
            "hook.register",
            "hook:x",
            OUTCOME_APPLIED,
            "alice",
        );
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
}

/// ONE CHAIN, TWO FRAMINGS, ACROSS THE UPGRADE BOUNDARY.
///
/// A node that upgrades mid-life has legacy entries linked to modern ones in a single sequence. The
/// per-entry scheme is what makes that verifiable without asking anyone to choose between keeping
/// their history and being safe, so a mixed chain is not a degraded case — it is the expected shape
/// of every upgraded deployment's log, and it must verify as one chain.
#[test]
fn a_chain_that_crosses_the_framing_upgrade_verifies_as_one_chain() {
    let mut chain = Vec::new();
    let mut prev = String::new();
    for seq in 1..=6u64 {
        // The first three predate the upgrade, the last three postdate it.
        let scheme = if seq <= 3 {
            DIGEST_SCHEME_LEGACY_PIPE
        } else {
            DIGEST_SCHEME_LEN_PREFIXED
        };
        let e = sealed_under(
            scheme,
            seq,
            &prev,
            "hook.register",
            "hook:x",
            OUTCOME_APPLIED,
            "alice",
        );
        prev = e.hash.clone();
        chain.push(e);
    }
    verify_chain(&chain).expect("a chain spanning the upgrade must verify as one chain");

    // The boundary is real: the entries either side were sealed under different framings.
    assert_eq!(chain[2].digest_scheme, DIGEST_SCHEME_LEGACY_PIPE);
    assert_eq!(chain[3].digest_scheme, DIGEST_SCHEME_LEN_PREFIXED);

    // A tamper on EITHER side of the boundary is still caught -- the mixed chain does not verify
    // vacuously on the half whose framing the verifier was not expecting.
    for i in [1usize, 4] {
        let mut tampered = chain.clone();
        tampered[i].principal = "mallory".to_string();
        assert!(
            verify_chain(&tampered).is_err(),
            "a tamper at index {i} of a mixed chain went undetected"
        );
    }
}

/// EVERY ENTRY THIS BUILD SEALS IS SEALED UNDER THE INJECTIVE FRAMING.
///
/// There is exactly one construction path and it has no branch, which is what stops a caller
/// reintroducing the ambiguous framing by asking for it.
#[test]
fn the_only_construction_path_seals_under_the_length_framed_scheme() {
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
        entry.digest_scheme, DIGEST_SCHEME_LEN_PREFIXED,
        "a freshly sealed entry did not name the injective framing"
    );
    assert_eq!(
        digest(&entry),
        entry.hash,
        "a freshly sealed entry did not verify"
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
