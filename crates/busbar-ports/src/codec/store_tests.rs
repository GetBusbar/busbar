// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-A5: the store request encoders and answer decoders over the wire records, and the slot namespace pin.

use busbar_contract::persistence::control;
use busbar_contract::persistence::{
    Address, AttemptId, BackendInfo, Candidate, ClockObservation, CommitKey, DatasetId, Decision,
    Durability, ExpectedValue, Mutation, NamespaceId, Predicate, PreparedCandidate, Read,
    ReadResult, Scan, TimeGuard, CANDIDATE_VERSION,
};
use busbar_contract::Secret;
use busbar_plugin_abi::kinds::store::plumbing::{decode_commit, CommitSlot};
use busbar_plugin_abi::kinds::store::store as wire;
use busbar_plugin_abi::records::{RecErr, Records, Reply, Writer};

use super::*;

fn address(space: u8, key: &[u8]) -> Address {
    Address {
        namespace: [space; 16],
        key: key.to_vec(),
    }
}

fn prepared() -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: DatasetId([1; 16]),
            writer_epoch: 1,
            writer: [2; 16],
            execution_epoch: 1,
            operation: [3; 16],
        },
        codec: CANDIDATE_VERSION,
        predicates: vec![
            Predicate {
                address: address(5, b"a"),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: address(5, b"c"),
                expected: ExpectedValue::Exact(Secret::new(b"old".to_vec())),
            },
        ],
        mutations: vec![
            Mutation::Put {
                address: address(5, b"a"),
                value: Secret::new(b"new".to_vec()),
            },
            Mutation::Delete(address(5, b"b")),
            Mutation::DeleteRange {
                namespace: NamespaceId([6; 16]),
                prefix: b"p".to_vec(),
                exact_key_length: 4,
            },
        ],
        time: Some(TimeGuard {
            not_before: Some(10),
            before: None,
        }),
        result: Secret::new(b"res".to_vec()),
    })
    .unwrap()
}

fn key() -> CommitKey {
    CommitKey::slotted(4, 9, &busbar_contract::caps::SlotSeal::acquire_for_tests()).unwrap()
}

#[test]
fn the_slot_namespace_is_the_one_the_store_kind_pins() {
    assert_eq!(control::SLOT_NS.0, wire::SLOT_NS);
    assert_eq!(&wire::SLOT_NS, b"busbar.slot.v1\0\0");
    assert_eq!(wire::MAX_SLOTS, busbar_contract::persistence::MAX_SLOTS);
    assert_eq!(
        wire::SLOT_SELF_FENCED,
        busbar_contract::persistence::SLOT_SELF_FENCED
    );
}

#[test]
fn a_candidate_encodes_to_the_records_the_store_decodes() {
    let c = prepared();
    let mut w = Reply::new();
    encode_candidate(&mut w, &c, &key(), &busbar_contract::plugin::TestKernelSeal).unwrap();
    let got = decode_commit(Records::new(w.as_bytes())).unwrap();
    assert_eq!(got.head.slot, CommitSlot::Slotted { slot: 4, seq: 9 });
    assert_eq!(got.head.id.dataset, [1; 16]);
    assert_eq!(got.head.id.writer, [2; 16]);
    assert_eq!(got.head.id.operation, [3; 16]);
    assert_eq!(got.head.id.writer_epoch, 1);
    assert_eq!(got.head.codec, wire::CODEC_VERSION);
    assert_eq!(got.head.guard.flags, wire::TIME_NOT_BEFORE);
    assert_eq!(got.head.guard.not_before, 10);
    let fences = control::fences(&c);
    assert_eq!(got.head.fences.len(), fences.len());
    assert_eq!(got.head.fences[0].namespace, fences[0].address.namespace);
    assert_eq!(got.head.fences[0].key, fences[0].address.key.as_slice());
    assert_eq!(got.predicates.len(), 2);
    assert_eq!(got.predicates[0].tag, wire::PREDICATE_ABSENT);
    assert_eq!(got.predicates[0].expected, b"");
    assert_eq!(got.predicates[1].tag, wire::PREDICATE_EXACT);
    assert_eq!(got.predicates[1].key, b"c");
    assert_eq!(got.predicates[1].expected, b"old");
    assert_eq!(got.mutations.len(), 3);
    assert_eq!(got.mutations[0].tag, wire::MUTATION_PUT);
    assert_eq!(got.mutations[0].key, b"a");
    assert_eq!(got.mutations[0].value, b"new");
    assert_eq!(got.mutations[1].tag, wire::MUTATION_DELETE);
    assert_eq!(got.mutations[2].tag, wire::MUTATION_DELETE_RANGE);
    assert_eq!(got.mutations[2].key, b"p");
    assert_eq!(got.mutations[2].exact_length, 4);
    assert_eq!(got.result, b"res");
}

#[test]
fn a_read_request_is_a_head_then_one_address_per_key() {
    let read = Read {
        dataset: DatasetId([1; 16]),
        addresses: vec![address(5, b"k1"), address(6, b"")],
        time: Some(TimeGuard {
            not_before: Some(7),
            before: Some(9),
        }),
    };
    let mut w = Reply::new();
    encode_read(&mut w, &read).unwrap();
    let mut recs = Records::new(w.as_bytes());
    let head = recs.next().unwrap().unwrap();
    assert_eq!(head.tag, wire::tag::READ_HEAD);
    let head = head.pod::<wire::ReadHead>().unwrap();
    assert_eq!(head.dataset, [1; 16]);
    assert_eq!(head.guard.flags, wire::TIME_NOT_BEFORE | wire::TIME_BEFORE);
    assert_eq!((head.guard.not_before, head.guard.before), (7, 9));
    let first = recs.next().unwrap().unwrap();
    assert_eq!(first.tag, wire::tag::ADDRESS);
    let (rec, tail) = first.pod_tail::<wire::AddressRec>().unwrap();
    assert_eq!((rec.namespace, tail), ([5; 16], &b"k1"[..]));
    let second = recs.next().unwrap().unwrap();
    assert_eq!(second.pod_tail::<wire::AddressRec>().unwrap().1, b"");
    assert!(recs.next().is_none());
}

#[test]
fn an_unguarded_read_carries_a_zero_guard() {
    let read = Read {
        dataset: DatasetId([1; 16]),
        addresses: vec![],
        time: None,
    };
    let mut w = Reply::new();
    encode_read(&mut w, &read).unwrap();
    let head = Records::new(w.as_bytes()).next().unwrap().unwrap();
    let head = head.pod::<wire::ReadHead>().unwrap();
    assert_eq!(head.guard.flags, 0);
    assert_eq!((head.guard.not_before, head.guard.before), (0, 0));
}

#[test]
fn a_scan_request_carries_after_only_with_its_flag() {
    let scan = |after: Option<Vec<u8>>, generation: Option<u64>, allow_change: bool| Scan {
        dataset: DatasetId([1; 16]),
        namespace: NamespaceId([2; 16]),
        prefix: b"pre".to_vec(),
        after,
        generation,
        allow_change,
        max_items: 50,
        max_bytes: 4096,
    };
    let mut w = Reply::new();
    encode_scan(&mut w, &scan(None, None, false)).unwrap();
    let recs: Vec<_> = Records::new(w.as_bytes()).map(Result::unwrap).collect();
    assert_eq!(recs.len(), 2);
    let head = recs[0].pod::<wire::ScanHead>().unwrap();
    assert_eq!(head.flags, 0);
    assert_eq!((head.max_rows, head.max_bytes), (50, 4096));
    assert_eq!((head.dataset, head.namespace), ([1; 16], [2; 16]));
    assert_eq!(recs[1].tag, wire::tag::SCAN_PREFIX);
    assert_eq!(recs[1].body, b"pre");

    let mut w = Reply::new();
    encode_scan(&mut w, &scan(Some(b"cur".to_vec()), Some(8), true)).unwrap();
    let recs: Vec<_> = Records::new(w.as_bytes()).map(Result::unwrap).collect();
    assert_eq!(recs.len(), 3);
    let head = recs[0].pod::<wire::ScanHead>().unwrap();
    assert_eq!(
        head.flags,
        wire::SCAN_FLAG_AFTER | wire::SCAN_FLAG_GENERATION | wire::SCAN_FLAG_ALLOW_CHANGE
    );
    assert_eq!(head.generation, 8);
    assert_eq!(recs[2].tag, wire::tag::SCAN_AFTER);
    assert_eq!(recs[2].body, b"cur");
}

#[test]
fn the_clock_request_is_the_dataset_in_one_record() {
    let mut w = Reply::new();
    encode_dataset(&mut w, &DatasetId([9; 16])).unwrap();
    let recs: Vec<_> = Records::new(w.as_bytes()).map(Result::unwrap).collect();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].tag, wire::tag::CLOCK);
    assert_eq!(recs[0].body, &[9u8; 16][..]);
}

fn read_done(code: u32, observed_at: u64, authority: [u8; 16]) -> Reply {
    let mut w = Reply::new();
    let done = wire::ReadDone {
        code,
        _r: 0,
        observed_at,
        authority,
    };
    w.put_pod(wire::tag::READ_DONE, &done).unwrap();
    w
}

fn value(w: &mut Reply, found: u32, bytes: &[u8]) {
    let rec = wire::ValueRec { found, _r: 0 };
    w.put_pod_tail(wire::tag::VALUE, &rec, bytes).unwrap();
}

#[test]
fn a_read_answer_keeps_absent_distinct_from_empty() {
    let mut w = read_done(wire::READ_VALUES, 77, [4; 16]);
    value(&mut w, 1, b"one");
    value(&mut w, 0, b"");
    value(&mut w, 1, b"");
    let got = read_values(Records::new(w.as_bytes()), 3).unwrap();
    let ReadResult::Values {
        observed_at,
        values,
    } = got
    else {
        panic!("values expected");
    };
    assert_eq!(observed_at.unix_seconds, 77);
    assert_eq!(observed_at.authority, [4; 16]);
    assert_eq!(values.len(), 3);
    assert!(values[1].is_none());
    assert_eq!(
        values[2].as_ref().map(|v| v == &Secret::new(Vec::new())),
        Some(true)
    );
    assert!(values[0].is_some());
}

#[test]
fn a_failed_time_guard_answers_no_values() {
    let w = read_done(wire::READ_TIME_GUARD_FAILED, 5, [4; 16]);
    let got = read_values(Records::new(w.as_bytes()), 2).unwrap();
    assert!(
        matches!(got, ReadResult::TimeGuardFailed { observed_at } if observed_at.unix_seconds == 5)
    );
    let mut w = read_done(wire::READ_TIME_GUARD_FAILED, 5, [4; 16]);
    value(&mut w, 0, b"");
    assert!(read_values(Records::new(w.as_bytes()), 1).is_err());
}

#[test]
fn a_read_answer_with_the_wrong_value_count_or_shape_is_refused() {
    let mut w = read_done(wire::READ_VALUES, 1, [4; 16]);
    value(&mut w, 1, b"x");
    assert!(read_values(Records::new(w.as_bytes()), 2).is_err());
    assert!(read_values(Records::new(w.as_bytes()), 0).is_err());
    let mut w = read_done(wire::READ_VALUES, 1, [4; 16]);
    value(&mut w, 0, b"tail on an absent value");
    assert!(read_values(Records::new(w.as_bytes()), 1).is_err());
    let mut w = read_done(wire::READ_VALUES, 1, [4; 16]);
    value(&mut w, 2, b"");
    assert!(read_values(Records::new(w.as_bytes()), 1).is_err());
    let w = read_done(0, 1, [4; 16]);
    assert!(read_values(Records::new(w.as_bytes()), 0).is_err());
    let w = read_done(wire::READ_VALUES, 1, [0; 16]);
    assert!(read_values(Records::new(w.as_bytes()), 0).is_err());
}

fn scan_done(code: u32, continuation: u32, generation: u64) -> Reply {
    let mut w = Reply::new();
    let done = wire::ScanDone {
        code,
        continuation,
        generation,
    };
    w.put_pod(wire::tag::SCAN_DONE, &done).unwrap();
    w
}

fn row(w: &mut Reply, key: &[u8], value: &[u8]) {
    let rec = wire::RowRec {
        key_len: key.len() as u32,
        _r: 0,
    };
    w.put_pod_tail(wire::tag::ROW, &rec, &[key, value].concat())
        .unwrap();
}

#[test]
fn a_scan_page_is_ordered_rows_and_a_continuation_that_names_the_last_key() {
    let mut w = scan_done(wire::SCAN_PAGE, wire::SCAN_CONTINUE, 12);
    row(&mut w, b"a", b"1");
    row(&mut w, b"b", b"");
    w.put(wire::tag::NEXT, b"b").unwrap();
    let ScanOutcome::Page(page) = scan_outcome(Records::new(w.as_bytes()), [8; 16]).unwrap() else {
        panic!("page expected");
    };
    assert_eq!(page.generation, 12);
    assert_eq!(page.rows.len(), 2);
    assert_eq!(page.rows[0].0.namespace, [8; 16]);
    assert_eq!(page.rows[0].0.key, b"a");
    assert_eq!(page.next.as_deref(), Some(&b"b"[..]));

    let mut w = scan_done(wire::SCAN_PAGE, wire::SCAN_EXHAUSTED, 3);
    row(&mut w, b"z", b"v");
    let ScanOutcome::Page(page) = scan_outcome(Records::new(w.as_bytes()), [8; 16]).unwrap() else {
        panic!("page expected");
    };
    assert!(page.next.is_none());
}

#[test]
fn a_malformed_scan_page_is_refused() {
    let bad = |build: &dyn Fn(&mut Reply)| {
        let mut w = scan_done(wire::SCAN_PAGE, wire::SCAN_CONTINUE, 1);
        build(&mut w);
        scan_outcome(Records::new(w.as_bytes()), [8; 16]).is_err()
    };
    assert!(bad(&|_| {}));
    assert!(bad(&|w| {
        row(w, b"a", b"");
        w.put(wire::tag::NEXT, b"other").unwrap();
    }));
    assert!(bad(&|w| {
        row(w, b"b", b"");
        row(w, b"a", b"");
        w.put(wire::tag::NEXT, b"a").unwrap();
    }));
    assert!(bad(&|w| {
        row(w, b"a", b"");
        row(w, b"a", b"");
        w.put(wire::tag::NEXT, b"a").unwrap();
    }));
    let mut w = scan_done(wire::SCAN_PAGE, wire::SCAN_EXHAUSTED, 1);
    row(&mut w, b"a", b"");
    w.put(wire::tag::NEXT, b"a").unwrap();
    assert!(scan_outcome(Records::new(w.as_bytes()), [8; 16]).is_err());
    let w = scan_done(9, wire::SCAN_EXHAUSTED, 1);
    assert!(scan_outcome(Records::new(w.as_bytes()), [8; 16]).is_err());
}

#[test]
fn a_stale_continued_scan_is_an_outcome_with_no_rows() {
    let w = scan_done(wire::SCAN_STALE, wire::SCAN_EXHAUSTED, 4);
    assert!(matches!(
        scan_outcome(Records::new(w.as_bytes()), [8; 16]),
        Ok(ScanOutcome::Stale)
    ));
    let mut w = scan_done(wire::SCAN_STALE, wire::SCAN_EXHAUSTED, 4);
    row(&mut w, b"a", b"");
    assert!(scan_outcome(Records::new(w.as_bytes()), [8; 16]).is_err());
}

fn committed(code: u32) -> Reply {
    let mut w = Reply::new();
    let rec = wire::Committed {
        code,
        _r: 0,
        observed_at: 21,
        authority: [6; 16],
    };
    w.put_pod(wire::tag::COMMITTED, &rec).unwrap();
    w
}

#[test]
fn committed_codes_one_to_six_map_to_the_decisions() {
    let decide = |code| decision(Records::new(committed(code).as_bytes()));
    assert!(matches!(decide(1), Ok(Decision::Applied(_))));
    assert!(matches!(decide(2), Ok(Decision::ConditionConflict)));
    let at = ClockObservation {
        authority: [6; 16],
        unix_seconds: 21,
    };
    assert!(matches!(
        decide(3),
        Ok(Decision::TimeGuardFailed { observed_at }) if observed_at == at
    ));
    assert!(matches!(decide(4), Ok(Decision::OpIdConflict)));
    assert!(matches!(decide(5), Ok(Decision::Fenced)));
    assert!(matches!(decide(6), Ok(Decision::Stale)));
    assert_eq!(decide(0).err(), Some(RecErr::Size));
    assert_eq!(decide(7).err(), Some(RecErr::Size));
}

#[test]
fn a_commit_answer_is_exactly_one_committed_record() {
    let mut w = committed(1);
    w.put(wire::tag::RESULT, b"echoed").unwrap();
    assert!(decision(Records::new(w.as_bytes())).is_err());
    let empty = Reply::new();
    assert!(decision(Records::new(empty.as_bytes())).is_err());
    let mut twice = committed(1);
    let again = wire::Committed {
        code: 1,
        _r: 0,
        observed_at: 21,
        authority: [6; 16],
    };
    twice.put_pod(wire::tag::COMMITTED, &again).unwrap();
    assert!(decision(Records::new(twice.as_bytes())).is_err());
}

#[test]
fn a_clock_answer_is_one_record_with_a_registered_authority() {
    let mut w = Reply::new();
    let rec = wire::ClockRec {
        observed_at: 31,
        authority: [2; 16],
    };
    w.put_pod(wire::tag::CLOCK, &rec).unwrap();
    let got = clock(Records::new(w.as_bytes())).unwrap();
    assert_eq!((got.unix_seconds, got.authority), (31, [2; 16]));
    let mut w = Reply::new();
    let rec = wire::ClockRec {
        observed_at: 31,
        authority: [0; 16],
    };
    w.put_pod(wire::tag::CLOCK, &rec).unwrap();
    assert!(clock(Records::new(w.as_bytes())).is_err());
    assert!(clock(Records::new(Reply::new().as_bytes())).is_err());
}

fn info_reply(durability: u32) -> Reply {
    let mut w = Reply::new();
    let rec = wire::InfoRec {
        dataset: [1; 16],
        atomic_domain: [2; 16],
        clock_authority: [3; 16],
        physical_version: 3,
        durability,
    };
    w.put_pod(wire::tag::INFO, &rec).unwrap();
    w
}

#[test]
fn info_maps_field_for_field_and_refuses_an_unknown_durability() {
    let got: BackendInfo = info(Records::new(info_reply(wire::DUR_LOCAL).as_bytes())).unwrap();
    assert_eq!(got.dataset, DatasetId([1; 16]));
    assert_eq!(got.atomic_domain, [2; 16]);
    assert_eq!(got.clock_authority, [3; 16]);
    assert_eq!(got.physical_version, 3);
    assert_eq!(got.durability, Durability::Local);
    let eph = info(Records::new(info_reply(wire::DUR_EPHEMERAL).as_bytes())).unwrap();
    assert_eq!(eph.durability, Durability::Ephemeral);
    let quorum = info(Records::new(info_reply(wire::DUR_QUORUM).as_bytes())).unwrap();
    assert_eq!(quorum.durability, Durability::Quorum);
    for bad in [0, 4, u32::MAX] {
        assert_eq!(
            info(Records::new(info_reply(bad).as_bytes())).err(),
            Some(RecErr::Size)
        );
    }
    let mut two = info_reply(wire::DUR_LOCAL);
    let again = wire::InfoRec {
        dataset: [1; 16],
        atomic_domain: [2; 16],
        clock_authority: [3; 16],
        physical_version: 3,
        durability: wire::DUR_LOCAL,
    };
    two.put_pod(wire::tag::INFO, &again).unwrap();
    assert!(info(Records::new(two.as_bytes())).is_err());
}
