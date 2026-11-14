// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

use crate::record_rows_fixture::Rows as RetryRows;

/// Fixture adapter: one ordinary chained write through the production write-behind's native
/// flush (`prepare_ordinary_async` and a conditional publication) over the fixture's CoreStore.
impl ChainBook {
    fn append(
        &self,
        rows: &RetryRows,
        instance: &Arc<str>,
        schema: RecordSchemaId,
        scope: &str,
        content: &[u8],
        f: ChainFraming,
    ) -> Result<(), &'static str> {
        let value = RecordBytes::new(content.to_vec()).map_err(|_| CHAIN_RECORD_TOO_LARGE)?;
        let batcher = Arc::new(crate::host_records::WriteBehind::default());
        let pending = crate::host_records::PendingRecords::default();
        let answer = Arc::new(Mutex::new(None));
        let into = Arc::clone(&answer);
        batcher.push_native_with(|| crate::host_records::Write {
            instance: Arc::clone(instance),
            schema,
            key: scope.as_bytes().to_vec(),
            value,
            seq: 0,
            owed: crate::host_records::Owed::new(Box::new(move |took| {
                *into.lock().unwrap() = Some(took);
            })),
            chain: Some(f),
        });
        futures::FutureExt::now_or_never(batcher.flush_native(&pending, &rows.store(), self))
            .expect("the native in-memory fixture finishes in one poll");
        let took = answer.lock().unwrap().take();
        took.unwrap_or(Err(WRITE_FAILED))
    }
}

#[test]
fn a_mismatched_body_sequence_cannot_reposition_before_an_occupied_key() {
    let rows = RetryRows::default();
    let book = ChainBook::default();
    let instance = Arc::from("inst");
    let (record, _) = sealed();
    let body = RecordBytes::new(encode(&record).unwrap()).unwrap();
    rows.record_put(
        EV,
        &record_key(&instance, &chain_key(SCOPE.as_bytes(), 9)),
        &body,
    )
    .unwrap();
    book.append(&rows, &instance, EV, SCOPE, b"after mismatch", LP_SCOPED)
        .unwrap();
    let next = rows
        .record_get(EV, &record_key(&instance, &chain_key(SCOPE.as_bytes(), 10)))
        .unwrap()
        .expect("continue beyond the occupied key");
    let next = decode(SCOPE, next.as_slice(), LP_SCOPED).unwrap();
    assert_eq!(next.seq(), 10);
    assert_eq!(next.prev_hash(), record.hash());
    assert_eq!(rows.record_scan(EV, b"", u32::MAX).unwrap().len(), 2);
}

const SCOPE: &str = "a11ce/task-1";

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

fn sealed() -> (StreamRecord, StreamRecord) {
    let mut chain = Chain::<StreamRecord>::new();
    let input = |b: Vec<u8>| StreamInput::new(b, Framing::LengthPrefixed, true);
    let e1 = chain.append(SCOPE, input(own_1()));
    let e2 = chain.append(SCOPE, input(own_2()));
    (e1, e2)
}

fn stored() -> Vec<(Vec<u8>, Vec<u8>)> {
    let (e1, e2) = sealed();
    vec![
        (chain_key(SCOPE.as_bytes(), 1), encode(&e1).unwrap()),
        (chain_key(SCOPE.as_bytes(), 2), encode(&e2).unwrap()),
    ]
}

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

#[test]
fn a_stored_body_round_trips_and_a_foreign_one_is_none() {
    let (e1, e2) = sealed();
    let body = encode(&e2).unwrap();
    assert!(body.len() <= CHAIN_OVERHEAD + own_2().len());
    let back = decode(SCOPE, &body, LP_SCOPED).unwrap();
    assert_eq!(
        (
            back.seq(),
            back.prev_hash(),
            back.hash(),
            back.content.as_slice()
        ),
        (2, e1.hash(), e2.hash(), own_2().as_slice())
    );
    let mut foreign = body.clone();
    foreign[0] = 2;
    assert!(decode(SCOPE, &foreign, LP_SCOPED).is_none());
    assert!(decode(SCOPE, &body[..20], LP_SCOPED).is_none());
    assert!(decode(SCOPE, b"", LP_SCOPED).is_none());
}

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

#[test]
fn a_scope_is_never_a_record_key() {
    assert_eq!(scope_of(b"a11ce/t1"), Some("a11ce/t1"));
    assert_eq!(scope_of(b""), None);
    assert_eq!(scope_of(b"\xff"), None);
    assert_eq!(scope_of(&chain_key(b"t1", 1)), None);
}
