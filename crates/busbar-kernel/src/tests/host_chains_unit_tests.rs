// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's half of a plane record chain (`host_chains.rs`): the declaration, the stored body, and
//! the verified read.
//!
//! The chain these tests read is sealed by the ONE chain mechanism in the framing a plane's task
//! chain declares (length-prefixed, its scope digested). The frozen pipe-joined chain a plane's task
//! store sealed before this ABI is not shipped: the ABI declares the
//! length-prefixed framing, so the goldens that pinned those pipe-joined bytes are retired.

use super::*;

const SCOPE: &str = "a11ce/task-1";

/// Length-prefixed own bytes of one event: `ts`, then the text fields.
fn own(ts: u64, fields: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    field(&ts.to_be_bytes());
    for f in fields {
        field(f.as_bytes());
    }
    out
}

fn own_1() -> Vec<u8> {
    own(
        1_700_000_000,
        &["task.submitted", "ctx-1", "a11ce", "planner", "submitted"],
    )
}

fn own_2() -> Vec<u8> {
    own(
        1_700_000_060,
        &["task.working", "ctx-1", "a11ce", "planner", "working"],
    )
}

const LP_SCOPED: ChainFraming = ChainFraming {
    framing: Framing::LengthPrefixed,
    digests_scope: true,
};

const EV: RecordSchemaId = RecordSchemaId::new("ev");

/// Two records sealed by the chain mechanism, as the flush seals them.
fn sealed() -> (StreamRecord, StreamRecord) {
    let mut chain = Chain::<StreamRecord>::new();
    let input = |b: Vec<u8>| StreamInput::new(b, Framing::LengthPrefixed, true);
    let e1 = chain.append(SCOPE, input(own_1()));
    let e2 = chain.append(SCOPE, input(own_2()));
    (e1, e2)
}

/// The sealed chain as the store would hold it: `(chain key, stored body)`.
fn stored() -> Vec<(Vec<u8>, Vec<u8>)> {
    let (e1, e2) = sealed();
    vec![
        (chain_key(SCOPE.as_bytes(), 1), encode(&e1).unwrap()),
        (chain_key(SCOPE.as_bytes(), 2), encode(&e2).unwrap()),
    ]
}

/// The digest the host seals is the length-prefixed prelude (`prev`, the scope, the sequence as
/// eight big-endian bytes, each after its length) joined to the plane's own bytes.
#[test]
fn the_host_seals_the_length_prefixed_prelude_and_the_planes_bytes() {
    let (e1, e2) = sealed();
    let expect = |prev: &str, seq: u64, own: &[u8]| {
        let mut input = Vec::new();
        let seq = seq.to_be_bytes();
        for f in [prev.as_bytes(), SCOPE.as_bytes(), &seq[..]] {
            input.extend_from_slice(&(f.len() as u64).to_be_bytes());
            input.extend_from_slice(f);
        }
        input.extend_from_slice(own);
        busbar_contract::redacted::sha256_hex(&input)
    };
    assert_eq!(e1.hash(), expect("", 1, &own_1()));
    assert_eq!(e2.hash(), expect(e1.hash(), 2, &own_2()));
    verify_chain(&[e1, e2]).expect("the sealed chain verifies");
}

/// Ported from the plane engine's chain golden (`chain_golden.rs`, a boot restore of the chain
/// reporting no tamper), over a sealed chain (B1 ruling 1). Stored and read back through the host's
/// verified read, the chain announces no break and answers both records with the plane's bytes.
#[test]
fn a_read_of_a_sealed_chain_reports_no_tamper() {
    assert_eq!(
        verified("inst", EV, stored(), LP_SCOPED),
        vec![
            (chain_key(SCOPE.as_bytes(), 1), own_1()),
            (chain_key(SCOPE.as_bytes(), 2), own_2()),
        ],
        "a persisted chain reported TAMPERED means the host's framing drifted"
    );
}

/// Ported from the plane engine's chain golden (`chain_golden.rs`, one undecodable record not
/// dropping the others on restore). One undecodable record wedged between the two sealed ones is
/// skipped (and reported), the others still answered, and they still verify.
#[test]
fn one_undecodable_record_does_not_drop_the_others() {
    let mut rows = stored();
    rows[1].0 = chain_key(SCOPE.as_bytes(), 3);
    rows.push((chain_key(SCOPE.as_bytes(), 2), b"{not an event".to_vec()));
    assert_eq!(
        verified("inst", EV, rows, LP_SCOPED),
        vec![
            (chain_key(SCOPE.as_bytes(), 1), own_1()),
            (chain_key(SCOPE.as_bytes(), 3), own_2()),
        ],
        "the undecodable record is skipped, the surviving chain intact"
    );
}

/// Ported from the plane engine's task store tests (`taskstore_tests.rs`, the verifier detecting a
/// tampered link in the persisted chain). One field of the second record rewritten in the store,
/// the read names the chain, the record, and the kind of break.
#[test]
fn the_verifier_detects_a_tampered_link_in_the_persisted_chain() {
    let mut rows = stored();
    let (_, e2) = sealed();
    let edited = StreamRecord::from_parts(
        SCOPE.into(),
        2,
        e2.prev_hash().into(),
        e2.hash().into(),
        own(
            1_700_000_060,
            &[
                "task.working",
                "ctx-1",
                "a11ce",
                "attacker-agent",
                "working",
            ],
        ),
        Framing::LengthPrefixed,
        true,
    );
    rows[1].1 = encode(&edited).unwrap();
    let read = verified("inst", EV, rows, LP_SCOPED);
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
    let (_, e2) = sealed();
    let relinked = StreamRecord::from_parts(
        SCOPE.into(),
        2,
        e2.hash().into(),
        e2.hash().into(),
        own_2(),
        Framing::LengthPrefixed,
        true,
    );
    rows[1].1 = encode(&relinked).unwrap();
    let read = verified("inst", EV, rows, LP_SCOPED);
    let words = String::from_utf8(read[0].1.clone()).unwrap();
    assert!(words.contains("prev_hash"), "{words}");
}

/// The stored body round-trips, and a body of another layout is no record.
#[test]
fn a_stored_body_round_trips_and_a_foreign_one_is_none() {
    let (e1, e2) = sealed();
    let body = encode(&e2).unwrap();
    assert!(body.len() <= CHAIN_OVERHEAD + own_2().len());
    let back = decode(SCOPE, &body, LP_SCOPED).unwrap();
    assert_eq!(
        (back.seq(), back.prev_hash(), back.hash(), back.content()),
        (2, e1.hash(), e2.hash(), own_2().as_slice())
    );
    let mut foreign = body.clone();
    foreign[0] = 2;
    assert!(decode(SCOPE, &foreign, LP_SCOPED).is_none());
    assert!(decode(SCOPE, &body[..20], LP_SCOPED).is_none());
    assert!(decode(SCOPE, b"", LP_SCOPED).is_none());
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
        ChainFraming::of(&chain(CHAIN_LENGTH_PREFIXED, CHAIN_DIGESTS_SCOPE)),
        Some(LP_SCOPED)
    );
    assert_eq!(
        ChainFraming::of(&chain(CHAIN_PIPE_SEPARATED, 0)),
        Some(ChainFraming {
            framing: Framing::PipeSeparated,
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
