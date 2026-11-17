// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-A5 red: the shared store plumbing (Decision 299 §2.4) over the wire constants.

use zerocopy::IntoBytes;

use super::plumbing::*;
use super::store as wire;
use crate::records::{RecErr, Records, Reply, Writer};

const W: [u8; 16] = [7; 16];

fn ns(n: u8) -> [u8; 16] {
    [n; 16]
}

fn head(slot: u32, seq: u64) -> wire::CandHead {
    wire::CandHead {
        id: wire::AttemptId {
            dataset: ns(1),
            writer: W,
            operation: ns(3),
            writer_epoch: 1,
            execution_epoch: 1,
        },
        codec: wire::CODEC_VERSION,
        slot,
        seq,
        guard: wire::TimeGuard {
            flags: 0,
            _r: 0,
            not_before: 0,
            before: 0,
        },
    }
}

fn cond(w: &mut Reply, tag: u16, space: [u8; 16], kind: u32, key: &[u8], expected: &[u8]) {
    let rec = wire::PredicateRec {
        namespace: space,
        tag: kind,
        key_len: key.len() as u32,
    };
    let tail = [key, expected].concat();
    w.put_pod_tail(tag, &rec, &tail).unwrap();
}

fn mutation(w: &mut Reply, space: [u8; 16], kind: u32, key: &[u8], value: &[u8], exact: u64) {
    let rec = wire::MutationRec {
        namespace: space,
        tag: kind,
        key_len: key.len() as u32,
        exact_length: exact,
    };
    let tail = [key, value].concat();
    w.put_pod_tail(wire::tag::MUTATION, &rec, &tail).unwrap();
}

fn base(slot: u32, seq: u64) -> Reply {
    let mut w = Reply::new();
    w.put_pod(wire::tag::CAND_HEAD, &head(slot, seq)).unwrap();
    w
}

fn finish(mut w: Reply) -> Reply {
    w.put(wire::tag::RESULT, b"result").unwrap();
    w
}

fn fault(w: Reply) -> Option<CommitErr> {
    let legacy = decode_commit(Records::new(w.as_bytes())).err();
    assert_eq!(
        try_decode_commit(Records::new(w.as_bytes())).err(),
        legacy.map(PrepareErr::Commit),
        "fallible and legacy decoding must reject the same wire records"
    );
    legacy
}

#[test]
fn verdicts_are_the_wire_codes_and_unknown_is_corrupt() {
    assert_eq!(Verdict::Applied.code(), wire::COMMIT_APPLIED);
    assert_eq!(Verdict::Conflict.code(), wire::COMMIT_CONDITION_CONFLICT);
    assert_eq!(Verdict::TimeGuard.code(), wire::COMMIT_TIME_GUARD_FAILED);
    for code in [1, 2, 3] {
        assert_eq!(Verdict::from_u8(code).unwrap().to_u8(), code);
    }
    for code in [0, 4, 5, 6, 255] {
        assert_eq!(Verdict::from_u8(code), Err(Corrupt));
    }
}

#[test]
fn packed_slot_rows_round_trip_and_refuse_corruption() {
    let row = SlotRow {
        seq: u64::MAX - 1,
        fp: [7; 32],
        verdict: Verdict::TimeGuard,
        observed: 1_700_000_000,
    };
    let bytes = row.encode_packed();
    assert_eq!(&bytes[..4], b"BVS1");
    assert_eq!(SlotRow::decode_packed(&bytes), Ok(row));
    assert_eq!(
        SlotRow::decode_packed(&bytes[..PACKED_LEN - 1]),
        Err(Corrupt)
    );
    let mut bad = bytes;
    bad[0] = b'X';
    assert_eq!(SlotRow::decode_packed(&bad), Err(Corrupt));
    bad = bytes;
    bad[44] = 9;
    assert_eq!(SlotRow::decode_packed(&bad), Err(Corrupt));
}

#[test]
fn a_replay_answers_the_recorded_verdict_at_its_original_time() {
    let row = SlotRow {
        seq: 4,
        fp: [1; 32],
        verdict: Verdict::TimeGuard,
        observed: 99,
    };
    let answer = row.replay(ns(5));
    assert_eq!(answer.code, wire::COMMIT_TIME_GUARD_FAILED);
    assert_eq!(answer.observed_at, 99);
    assert_eq!(answer.authority, ns(5));
    assert_eq!(answer.as_bytes().len(), 32);
}

#[test]
fn a_slot_row_judges_a_send_by_sequence_then_fingerprint() {
    let row = SlotRow {
        seq: 5,
        fp: [1; 32],
        verdict: Verdict::Applied,
        observed: 1,
    };
    assert_eq!(judge(None, 1, &[1; 32]), Judgement::Fresh);
    assert_eq!(judge(Some(&row), 6, &[9; 32]), Judgement::Fresh);
    assert_eq!(judge(Some(&row), 5, &[1; 32]), Judgement::Replay);
    assert_eq!(judge(Some(&row), 5, &[2; 32]), Judgement::OpIdConflict);
    assert_eq!(judge(Some(&row), 4, &[1; 32]), Judgement::Stale);
}

#[test]
fn holds_compares_absent_and_exact_and_nothing_else() {
    assert!(holds(wire::PREDICATE_ABSENT, b"", None));
    assert!(!holds(wire::PREDICATE_ABSENT, b"", Some(b"")));
    assert!(holds(wire::PREDICATE_EXACT, b"v", Some(b"v")));
    assert!(holds(wire::PREDICATE_EXACT, b"", Some(b"")));
    assert!(!holds(wire::PREDICATE_EXACT, b"v", Some(b"w")));
    assert!(!holds(wire::PREDICATE_EXACT, b"v", None));
    assert!(!holds(0, b"", None));
    assert!(!holds(3, b"", None));
}

#[test]
fn prelude_order_is_one_byte_ordered_set_exclusive_if_mutated() {
    let (a, b, c) = (ns(3), ns(1), ns(2));
    let got = prelude_order([
        (&a, &b"k"[..], Use::Condition),
        (&b, &b"k"[..], Use::Read),
        (&c, &b"k"[..], Use::Condition),
        (&c, &b"j"[..], Use::Mutation),
        (&a, &b"z"[..], Use::Condition),
    ]);
    assert_eq!(got, vec![(b, false), (c, true), (a, false)]);
}

#[test]
fn a_generation_condition_locks_the_namespace_it_names() {
    let (generation, named) = (wire::GENERATION_NS, ns(9));
    let got = prelude_order([(&generation, &named[..], Use::Condition)]);
    assert_eq!(got, vec![(named, false)]);
    // A read of the same address is not matched: it locks the generation namespace itself.
    let got = prelude_order([(&generation, &named[..], Use::Read)]);
    assert_eq!(got, vec![(generation, false)]);
}

#[test]
fn a_slotted_commit_decodes_its_head_fences_predicates_and_mutations() {
    let mut w = base(3, 2);
    cond(
        &mut w,
        wire::tag::FENCE,
        ns(4),
        wire::PREDICATE_EXACT,
        b"root",
        b"BSE1",
    );
    cond(
        &mut w,
        wire::tag::PREDICATE,
        ns(5),
        wire::PREDICATE_ABSENT,
        b"a",
        b"",
    );
    cond(
        &mut w,
        wire::tag::PREDICATE,
        ns(5),
        wire::PREDICATE_EXACT,
        b"b",
        b"x",
    );
    mutation(&mut w, ns(5), wire::MUTATION_PUT, b"a", b"value", 0);
    mutation(&mut w, ns(5), wire::MUTATION_DELETE, b"b", b"", 0);
    mutation(&mut w, ns(6), wire::MUTATION_DELETE_RANGE, b"pre", b"", 8);
    let w = finish(w);
    let got = decode_commit(Records::new(w.as_bytes())).unwrap();
    assert_eq!(got.head.slot, CommitSlot::Slotted { slot: 3, seq: 2 });
    assert_eq!(got.head.id.writer, W);
    assert_eq!(got.head.codec, wire::CODEC_VERSION);
    assert_eq!(got.head.fences.len(), 1);
    assert_eq!(got.head.fences[0].expected, b"BSE1");
    assert_eq!(got.predicates.len(), 2);
    assert_eq!(got.predicates[0].expected, b"");
    assert_eq!(got.predicates[1].key, b"b");
    assert_eq!(got.mutations.len(), 3);
    assert_eq!(got.mutations[0].value, b"value");
    assert_eq!(got.mutations[2].exact_length, 8);
    assert_eq!(got.result, b"result");
}

#[test]
fn a_self_fenced_head_has_slot_max_and_seq_zero() {
    let mut w = base(wire::SLOT_SELF_FENCED, 0);
    mutation(&mut w, ns(5), wire::MUTATION_PUT, b"a", b"v", 0);
    let w = finish(w);
    let got = decode_commit(Records::new(w.as_bytes())).unwrap();
    assert_eq!(got.head.slot, CommitSlot::SelfFenced);
}

#[test]
fn any_other_slot_and_seq_is_refused() {
    for (slot, seq) in [
        (0, 0),
        (wire::MAX_SLOTS, 1),
        (wire::SLOT_SELF_FENCED, 1),
        (wire::MAX_SLOTS - 1, 0),
    ] {
        assert_eq!(fault(finish(base(slot, seq))), Some(CommitErr::Refused));
    }
    assert!(fault(finish(base(wire::MAX_SLOTS - 1, 1))).is_none());
}

#[test]
fn g2_faults_a_slot_namespace_mutation_other_than_the_writers_range() {
    let delete_range = |prefix: &[u8], exact: u64| {
        let mut w = base(0, 1);
        mutation(
            &mut w,
            wire::SLOT_NS,
            wire::MUTATION_DELETE_RANGE,
            prefix,
            b"",
            exact,
        );
        fault(finish(w))
    };
    assert_eq!(delete_range(&W, 20), None);
    assert!(matches!(delete_range(&W, 19), Some(CommitErr::Fault(_))));
    assert!(matches!(
        delete_range(&W[..8], 20),
        Some(CommitErr::Fault(_))
    ));
    assert!(matches!(delete_range(b"", 20), Some(CommitErr::Fault(_))));
    for kind in [wire::MUTATION_PUT, wire::MUTATION_DELETE] {
        let mut w = base(0, 1);
        mutation(
            &mut w,
            wire::SLOT_NS,
            kind,
            &[W.as_slice(), &[0; 4]].concat(),
            b"v",
            0,
        );
        assert!(matches!(fault(finish(w)), Some(CommitErr::Fault(_))));
    }
}

#[test]
fn g2_faults_a_generation_mutation_and_a_generation_condition_off_16_bytes() {
    for kind in [
        wire::MUTATION_PUT,
        wire::MUTATION_DELETE,
        wire::MUTATION_DELETE_RANGE,
    ] {
        let mut w = base(0, 1);
        mutation(&mut w, wire::GENERATION_NS, kind, &ns(2), b"", 0);
        assert!(matches!(fault(finish(w)), Some(CommitErr::Fault(_))));
    }
    for tag in [wire::tag::FENCE, wire::tag::PREDICATE] {
        for key in [&b""[..], &[1; 15][..], &[1; 17][..]] {
            let mut w = base(0, 1);
            cond(
                &mut w,
                tag,
                wire::GENERATION_NS,
                wire::PREDICATE_ABSENT,
                key,
                b"",
            );
            assert!(matches!(fault(finish(w)), Some(CommitErr::Fault(_))));
        }
        let mut w = base(0, 1);
        cond(
            &mut w,
            tag,
            wire::GENERATION_NS,
            wire::PREDICATE_ABSENT,
            &ns(2),
            b"",
        );
        assert_eq!(fault(finish(w)), None);
    }
}

#[test]
fn an_unknown_condition_or_mutation_code_and_a_misplaced_record_fault() {
    let mut w = base(0, 1);
    cond(&mut w, wire::tag::PREDICATE, ns(5), 3, b"k", b"");
    assert!(matches!(
        fault(finish(w)),
        Some(CommitErr::Fault(RecErr::Size))
    ));

    let mut w = base(0, 1);
    mutation(&mut w, ns(5), 9, b"k", b"", 0);
    assert!(matches!(
        fault(finish(w)),
        Some(CommitErr::Fault(RecErr::Size))
    ));

    // A FENCE after a PREDICATE, and a candidate with no RESULT, are out of order.
    let mut w = base(0, 1);
    cond(
        &mut w,
        wire::tag::PREDICATE,
        ns(5),
        wire::PREDICATE_ABSENT,
        b"k",
        b"",
    );
    cond(
        &mut w,
        wire::tag::FENCE,
        ns(5),
        wire::PREDICATE_ABSENT,
        b"j",
        b"",
    );
    assert!(matches!(
        fault(finish(w)),
        Some(CommitErr::Fault(RecErr::Unknown(_)))
    ));
    assert!(matches!(fault(base(0, 1)), Some(CommitErr::Fault(_))));

    // A mutation with a non-zero exact length that is not a range.
    let mut w = base(0, 1);
    mutation(&mut w, ns(5), wire::MUTATION_PUT, b"k", b"v", 4);
    assert!(matches!(
        fault(finish(w)),
        Some(CommitErr::Fault(RecErr::Size))
    ));
}

#[test]
fn the_slot_pins_equal_the_documented_bytes() {
    assert_eq!(&wire::SLOT_NS, b"busbar.slot.v1\0\0");
    assert_eq!(&wire::GENERATION_NS, b"busbar.scan.v1\0\0");
    assert_eq!(RECEIPT_ERA_VERSION, 1);
    assert!(RECEIPT_ERA_REFUSAL.starts_with("pre-release receipt-era"));
}

#[test]
fn fallible_decode_preserves_wire_views_and_rejects_each_metadata_allocation() {
    let mut bytes = base(0, 1);
    cond(
        &mut bytes,
        wire::tag::FENCE,
        ns(4),
        wire::PREDICATE_EXACT,
        b"f",
        b"guard",
    );
    cond(
        &mut bytes,
        wire::tag::PREDICATE,
        ns(5),
        wire::PREDICATE_ABSENT,
        b"p",
        b"",
    );
    mutation(&mut bytes, ns(5), wire::MUTATION_PUT, b"k", b"payload", 0);
    let bytes = finish(bytes);
    let parsed = try_decode_commit(Records::new(bytes.as_bytes())).unwrap();
    assert_eq!(parsed.head.fences[0].expected, b"guard");
    assert_eq!(parsed.predicates[0].key, b"p");
    assert_eq!(parsed.mutations[0].value, b"payload");
    assert_eq!(parsed.result, b"result");
    for allocation in 0..3 {
        with_allocation_failure(AllocationSite::Metadata, allocation, || {
            assert_eq!(
                try_decode_commit(Records::new(bytes.as_bytes())).err(),
                Some(PrepareErr::Allocation)
            );
        });
    }
    assert!(try_decode_commit(Records::new(bytes.as_bytes())).is_ok());
}

#[test]
fn fallible_decode_parses_the_current_record_before_reserving_it() {
    let mut bytes = base(0, 1);
    cond(&mut bytes, wire::tag::PREDICATE, ns(5), 99, b"p", b"");
    let bytes = finish(bytes);
    with_allocation_failure(AllocationSite::Metadata, 0, || {
        assert_eq!(
            try_decode_commit(Records::new(bytes.as_bytes())).err(),
            Some(PrepareErr::Commit(CommitErr::Fault(RecErr::Size)))
        );
    });
    for (slot, seq) in [(0, 0), (wire::MAX_SLOTS, 1), (wire::SLOT_SELF_FENCED, 1)] {
        let bytes = finish(base(slot, seq));
        assert_eq!(
            try_decode_commit(Records::new(bytes.as_bytes())).err(),
            Some(PrepareErr::Commit(CommitErr::Refused))
        );
    }
}

#[test]
fn fallible_namespace_plan_keeps_lock_order_and_mutation_only_generations() {
    let (a, b) = (ns(3), ns(1));
    let items = [
        (&a, b"k".as_slice(), Use::Condition),
        (&b, b"k".as_slice(), Use::Mutation),
        (&wire::GENERATION_NS, a.as_slice(), Use::Condition),
        (&b, b"j".as_slice(), Use::Mutation),
        (&wire::SLOT_NS, W.as_slice(), Use::Mutation),
    ];
    let plan = try_prelude_order(items).unwrap();
    assert_eq!(plan, prelude_order(items));
    let mut expected = vec![b, wire::SLOT_NS];
    expected.sort();
    assert_eq!(
        plan.iter()
            .filter_map(|(ns, exclusive)| exclusive.then_some(*ns))
            .collect::<Vec<_>>(),
        expected
    );
    with_allocation_failure(AllocationSite::Metadata, 0, || {
        assert!(try_prelude_order(items).is_err())
    });
}

#[test]
fn row_encoder_discards_dirty_scratch_and_reuses_only_empty_custody() {
    let mut scratch = crate::secure::SecureVec::from(b"prior secret".as_slice());
    let mut out = Reply::new();
    for (key, value) in [
        (b"key".as_slice(), b"value".as_slice()),
        (b"".as_slice(), b"".as_slice()),
    ] {
        write_row(&mut out, &mut scratch, key, value).unwrap();
        assert!(scratch.is_empty());
    }
    let mut records = Records::new(out.as_bytes());
    let first = records.next_rec().unwrap().unwrap();
    assert_eq!(first.tag, wire::tag::ROW);
    let (head, tail) = first.pod_tail::<wire::RowRec>().unwrap();
    assert_eq!(head.key_len, 3);
    assert_eq!(head._r, 0);
    assert_eq!(tail, b"keyvalue");
    let empty = records.next_rec().unwrap().unwrap();
    assert_eq!(empty.pod_tail::<wire::RowRec>().unwrap().1, b"");
    assert!(records.next_rec().is_none());
}

#[test]
fn row_allocation_failure_clears_dirty_input_and_emits_nothing() {
    let mut scratch = crate::secure::SecureVec::from(b"dirty".as_slice());
    let mut out = Reply::new();
    with_allocation_failure(AllocationSite::Row, 0, || {
        assert!(matches!(
            write_row(&mut out, &mut scratch, b"key", &[7; 4096]),
            Err(RowErr::Allocation)
        ));
    });
    assert!(scratch.is_empty());
    assert!(out.as_bytes().is_empty());
    write_row(&mut out, &mut scratch, b"key", b"value").unwrap();
}

struct FailingRowWriter(bool);
impl Writer for FailingRowWriter {
    fn put_parts(&mut self, _: u16, _: &[&[u8]]) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_pod_nested<T: crate::records::Pod>(
        &mut self,
        _: u16,
        _: &T,
        _: impl FnOnce(&mut crate::records::Nested<'_>) -> Result<(), crate::records::Full>,
    ) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_u32s(
        &mut self,
        _: u16,
        _: impl FnOnce(&mut crate::records::U32s<'_>) -> Result<(), crate::records::Full>,
    ) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put(&mut self, _: u16, _: &[u8]) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_u32s(
        &mut self,
        _: u16,
        _: impl FnOnce(&mut crate::records::U32s<'_>) -> Result<(), crate::records::Full>,
    ) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_pod<T: crate::records::Pod>(
        &mut self,
        _: u16,
        _: &T,
    ) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_pod_tail<T: crate::records::Pod>(
        &mut self,
        _: u16,
        _: &T,
        tail: &[u8],
    ) -> Result<(), crate::records::Full> {
        assert_eq!(tail, b"keyvalue");
        assert!(!self.0, "writer panic after observing the assembled row");
        Err(crate::records::Full)
    }
    fn put_text(&mut self, _: u16, _: &str) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_pair(&mut self, _: u16, _: &str, _: &[u8]) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_fact(&mut self, _: u32, _: u64) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_fact_text(&mut self, _: u32, _: &str) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_metric(
        &mut self,
        _: u32,
        _: u32,
        _: f64,
        _: &[&str],
    ) -> Result<(), crate::records::Full> {
        unreachable!()
    }
    fn put_nested(
        &mut self,
        _: u16,
        _: impl FnOnce(&mut crate::records::Nested<'_>) -> Result<(), crate::records::Full>,
    ) -> Result<(), crate::records::Full> {
        unreachable!()
    }
}

#[test]
fn row_full_and_writer_panic_leave_reusable_empty_scratch() {
    let mut scratch = crate::secure::SecureVec::from(b"old".as_slice());
    assert!(matches!(
        write_row(&mut FailingRowWriter(false), &mut scratch, b"key", b"value"),
        Err(RowErr::Full(_))
    ));
    assert!(scratch.is_empty());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = write_row(&mut FailingRowWriter(true), &mut scratch, b"key", b"value");
    }));
    assert!(panic.is_err());
    assert!(scratch.is_empty());
    write_row(&mut Reply::new(), &mut scratch, b"next", b"row").unwrap();
    assert!(scratch.is_empty());
}

#[test]
fn row_size_checks_do_not_require_constructing_oversized_slices() {
    assert_eq!(row_shape(0, 0).unwrap(), (0, 0));
    assert_eq!(row_shape(3, 5).unwrap(), (3, 8));
    assert!(matches!(row_shape(1, usize::MAX), Err(RowErr::Size)));
    if let Some(too_long) = (u32::MAX as usize).checked_add(1) {
        assert!(matches!(row_shape(too_long, 0), Err(RowErr::Size)));
    }
}
