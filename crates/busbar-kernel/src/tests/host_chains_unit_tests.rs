// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's half of a plane record chain (`host_chains.rs`): the declaration, the stored body, and
//! the verified read, over GENUINE pre-change bytes.
//!
//! THE FROZEN PER-TASK CHAIN below is the one a plane's task store sealed before this ABI (its
//! pipe-joined `prev|task|seq|ts|kind|context|principal|agent|state` digest), byte for byte: the
//! hashes are the ones that store persisted, never regenerated. Declared pipe-separated with its
//! scope digested, the host's framing recomputes them. DO NOT regenerate these bytes to make a
//! failing test pass.

use super::*;

const SCOPE: &str = "task-1";
const SUFFIX_1: &[u8] = b"|1700000000|task.submitted|ctx-1|vk_alice|planner|submitted";
const HASH_1: &str = "1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1";
const SUFFIX_2: &[u8] = b"|1700000060|task.working|ctx-1|vk_alice|planner|working";
const HASH_2: &str = "6059096fd763aa3293489637e995f70ca396752aa2313d7d4a05105883fe7e19";

const PIPE_SCOPED: ChainFraming = ChainFraming {
    framing: Framing::PipeSeparated,
    digests_scope: true,
};

const EV: RecordSchemaId = RecordSchemaId::new("ev");

fn frozen(seq: u64, prev: &str, hash: &str, suffix: &[u8]) -> PlaneJournalRecord {
    PlaneJournalRecord::from_parts(
        SCOPE.to_string(),
        seq,
        prev.to_string(),
        hash.to_string(),
        suffix.to_vec(),
        Framing::PipeSeparated,
        true,
    )
}

/// The frozen chain as the store would hold it: `(chain key, stored body)`.
fn stored() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (
            chain_key(SCOPE.as_bytes(), 1),
            encode(&frozen(1, "", HASH_1, SUFFIX_1)).unwrap(),
        ),
        (
            chain_key(SCOPE.as_bytes(), 2),
            encode(&frozen(2, HASH_1, HASH_2, SUFFIX_2)).unwrap(),
        ),
    ]
}

/// Ported from the plane engine's chain golden (`chain_golden.rs`, the frozen chain recomputing
/// from its own bytes).
/// The host's prelude (`prev`, then the scope, then the sequence, pipe-joined, the genesis's empty
/// `prev` still owing its `|`) joined to the plane's own bytes recomputes each frozen digest.
#[test]
fn the_frozen_per_task_chain_recomputes_from_its_own_bytes() {
    let (e1, e2) = (
        frozen(1, "", HASH_1, SUFFIX_1),
        frozen(2, HASH_1, HASH_2, SUFFIX_2),
    );
    assert_eq!(crate::audit::digest(&e1), HASH_1, "genesis digest drifted");
    assert_eq!(crate::audit::digest(&e2), HASH_2, "tail digest drifted");
    verify_chain(&[e1, e2]).expect("the frozen chain must verify");
}

/// Ported from the plane engine's chain golden (`chain_golden.rs`, a boot restore of the frozen
/// chain reporting no tamper).
/// Stored and read back through the host's verified read, the frozen chain announces no break and
/// answers both records with the plane's own bytes.
#[test]
fn a_read_of_the_frozen_chain_reports_no_tamper() {
    assert_eq!(
        verified("inst", EV, stored(), PIPE_SCOPED),
        vec![
            (chain_key(SCOPE.as_bytes(), 1), SUFFIX_1.to_vec()),
            (chain_key(SCOPE.as_bytes(), 2), SUFFIX_2.to_vec()),
        ],
        "a persisted chain reported TAMPERED means the host's framing drifted"
    );
}

/// Ported from the plane engine's chain golden (`chain_golden.rs`, one undecodable record not
/// dropping the others on restore).
/// One undecodable record wedged between the two frozen ones is skipped (and reported), the others
/// still answered, and they still verify: no break is announced.
#[test]
fn one_undecodable_record_does_not_drop_the_others() {
    let mut rows = stored();
    rows[1].0 = chain_key(SCOPE.as_bytes(), 3);
    rows.push((chain_key(SCOPE.as_bytes(), 2), b"{not an event".to_vec()));
    let read = verified("inst", EV, rows, PIPE_SCOPED);
    assert_eq!(
        read,
        vec![
            (chain_key(SCOPE.as_bytes(), 1), SUFFIX_1.to_vec()),
            (chain_key(SCOPE.as_bytes(), 3), SUFFIX_2.to_vec()),
        ],
        "the undecodable record is skipped, the surviving chain intact"
    );
}

/// Ported from the plane engine's task store tests (`taskstore_tests.rs`, the verifier detecting a
/// tampered link in the persisted chain).
/// The frozen chain verified untouched; one field of its second record rewritten in the store, the
/// read names the chain, the record, and the kind of break.
#[test]
fn the_verifier_detects_a_tampered_link_in_the_persisted_chain() {
    let mut rows = stored();
    assert_eq!(verified("inst", EV, rows.clone(), PIPE_SCOPED).len(), 2);
    let edited = encode(&frozen(
        2,
        HASH_1,
        HASH_2,
        b"|1700000060|task.working|ctx-1|vk_alice|attacker-agent|working",
    ))
    .unwrap();
    rows[1].1 = edited;
    let read = verified("inst", EV, rows, PIPE_SCOPED);
    assert_eq!(read[0].0, SCOPE.as_bytes(), "the broken chain is named");
    let words = String::from_utf8(read[0].1.clone()).unwrap();
    assert!(
        words.contains("seq 2"),
        "the verifier names WHICH record: {words}"
    );
    assert!(words.contains("EDITED"), "an in-place edit: {words}");
    assert_eq!(read.len(), 3, "and both records are still answered");
}

/// A link spliced out of order is a link break, not a digest one.
#[test]
fn a_relinked_record_is_a_link_break() {
    let mut rows = stored();
    rows[1].1 = encode(&frozen(2, HASH_2, HASH_2, SUFFIX_2)).unwrap();
    let read = verified("inst", EV, rows, PIPE_SCOPED);
    let words = String::from_utf8(read[0].1.clone()).unwrap();
    assert!(words.contains("prev_hash"), "{words}");
}

/// The stored body round-trips, and a body of another layout is no record.
#[test]
fn a_stored_body_round_trips_and_a_foreign_one_is_none() {
    let r = frozen(2, HASH_1, HASH_2, SUFFIX_2);
    let body = encode(&r).unwrap();
    assert!(body.len() <= CHAIN_OVERHEAD + SUFFIX_2.len());
    let back = decode(SCOPE, &body, PIPE_SCOPED).unwrap();
    assert_eq!(
        (back.seq(), back.prev_hash(), back.hash(), back.content()),
        (2, HASH_1, HASH_2, SUFFIX_2)
    );
    let mut foreign = body.clone();
    foreign[0] = 2;
    assert!(decode(SCOPE, &foreign, PIPE_SCOPED).is_none());
    assert!(decode(SCOPE, &body[..20], PIPE_SCOPED).is_none());
    assert!(decode(SCOPE, b"", PIPE_SCOPED).is_none());
}

/// The declaration maps to the framing it names; a code this build does not know is none.
#[test]
fn the_declaration_names_its_framing() {
    let chain = |framing, flags| RecordChain {
        kind: 0,
        framing,
        flags,
        _reserved: 0,
    };
    assert_eq!(
        ChainFraming::of(&chain(CHAIN_PIPE_SEPARATED, CHAIN_DIGESTS_SCOPE)),
        Some(PIPE_SCOPED)
    );
    assert_eq!(
        ChainFraming::of(&chain(CHAIN_LENGTH_PREFIXED, 0)),
        Some(ChainFraming {
            framing: Framing::LengthPrefixed,
            digests_scope: false,
        })
    );
    assert_eq!(ChainFraming::of(&chain(0, 0)), None);
    assert_eq!(ChainFraming::of(&chain(CHAIN_PIPE_SEPARATED, 2)), None);
}

/// A scope is UTF-8, not empty, and never shaped like a listed record's key.
#[test]
fn a_scope_is_never_a_record_key() {
    assert_eq!(scope_of(b"a11ce/t1"), Some("a11ce/t1"));
    assert_eq!(scope_of(b""), None);
    assert_eq!(scope_of(b"\xff"), None);
    assert_eq!(scope_of(&chain_key(b"t1", 1)), None);
}
