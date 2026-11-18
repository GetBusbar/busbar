// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The journal codec the store journal borrows: the fixed record, the chain over it, the body
//! fields, and the quarantine note an already written journal can carry.

use crate::journal::{JOURNAL_MAGIC, JOURNAL_VERSION};
use crate::{
    body_digest, decode_run, verify_journal as verify, BodyReader, BodyWriter, Entry, JournalBreak,
    JournalBreakKind, JournalRecord, QuarantineNote, Record, RecordClass, JOURNAL_HEADER_BYTES,
    QUARANTINE_BODY_TAG,
};

/// Chain `entry` onto `prev` as record `node_seq` of `node`, the way the store journal seals.
fn seal(node: u64, node_seq: u64, prev: [u8; 32], entry: Entry) -> JournalRecord {
    let mut record = JournalRecord {
        class: entry.class,
        node,
        node_seq,
        lease_epoch: entry.lease_epoch,
        policy_epoch: entry.policy_epoch,
        wall: entry.wall,
        mono: entry.mono,
        body_hash: body_digest(&entry.body),
        body: entry.body,
        prev_hash: prev,
        hash: [0u8; 32],
    };
    record.hash = record.digest_of_chain();
    record
}

/// `entries` chained for `node`, numbered from `first`, linked onto `prev`.
fn chain(node: u64, first: u64, prev: [u8; 32], entries: Vec<Entry>) -> Vec<JournalRecord> {
    let mut head = prev;
    entries
        .into_iter()
        .zip(first..)
        .map(|(entry, seq)| {
            let record = seal(node, seq, head, entry);
            head = record.hash;
            record
        })
        .collect()
}

fn entries(class: RecordClass, n: usize, tag: u8) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            Entry::new(class, vec![tag, i as u8, 0xAB]).at(1_700_000_000 + i as u64, i as u64 * 7)
        })
        .collect()
}

/// Fourteen classes, each pinned to its byte. The set is the contract's.
#[test]
fn every_class_is_pinned_to_its_byte() {
    use RecordClass::*;
    let all = [
        Transaction,
        Access,
        Slice,
        Lease,
        Policy,
        Checkpoint,
        Reconciliation,
        Migration,
        Bootstrap,
        Purge,
        Load,
        ChainBreak,
        StoreRestore,
        FleetOutage,
    ];
    for (code, class) in (1u8..).zip(all) {
        assert_eq!(class.code(), code);
        assert_eq!(RecordClass::from_code(code), Some(class));
    }
    assert_eq!(RecordClass::Transaction.code(), 1);
    assert_eq!(RecordClass::Checkpoint.code(), 6);
    assert_eq!(RecordClass::Migration.code(), 8);
    assert_eq!(RecordClass::ChainBreak.code(), 12);
    assert_eq!(RecordClass::FleetOutage.code(), 14);
    assert_eq!(RecordClass::from_code(0), None);
    assert_eq!(RecordClass::from_code(15), None);
}

/// The reading half of a body gives back exactly what the writing half put down, field by field,
/// and a short or lying body is an answer, not a panic.
#[test]
fn a_body_reads_back_what_was_written() {
    let mut body = BodyWriter::new();
    body.text("hold.open");
    body.num(7);
    body.figure(-42);
    body.bytes(&[1, 2, 3]);
    let bytes = body.finish();

    let mut read = BodyReader::new(&bytes);
    assert_eq!(read.text(), Some("hold.open"));
    assert_eq!(read.num(), Some(7));
    assert_eq!(read.figure(), Some(-42));
    assert_eq!(read.bytes(), Some(&[1u8, 2, 3][..]));
    assert!(read.is_done());
    assert_eq!(
        read.num(),
        None,
        "reading past the end is an answer, not a panic"
    );

    let mut short = BodyReader::new(&bytes[..bytes.len() - 1]);
    assert_eq!(short.text(), Some("hold.open"));
    assert_eq!(short.num(), Some(7));
    assert_eq!(short.figure(), Some(-42));
    assert_eq!(short.bytes(), None);

    let claim = u64::MAX.to_le_bytes();
    let mut lying = BodyReader::new(&claim);
    assert_eq!(lying.text(), None);
}

#[test]
fn the_record_header_is_fixed() {
    assert_eq!(JOURNAL_HEADER_BYTES, 160);
    assert_eq!(JOURNAL_MAGIC, *b"BJRN");
    assert_eq!(JOURNAL_VERSION, 1);

    let record = seal(
        7,
        1,
        [0u8; 32],
        Entry::new(RecordClass::Transaction, b"a body".to_vec())
            .at(1_700_000_000, 42)
            .under(3, 5),
    );
    let bytes = record.encode();

    assert_eq!(bytes.len(), JOURNAL_HEADER_BYTES + 6);
    assert_eq!(&bytes[0..4], b"BJRN");
    assert_eq!(u16::from_le_bytes([bytes[4], bytes[5]]), 1);
    assert_eq!(bytes[6], RecordClass::Transaction.code());
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 7);
    assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bytes[24..32].try_into().unwrap()), 3);
    assert_eq!(u64::from_le_bytes(bytes[32..40].try_into().unwrap()), 5);
    assert_eq!(
        u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
        1_700_000_000
    );
    assert_eq!(u64::from_le_bytes(bytes[48..56].try_into().unwrap()), 42);
    assert_eq!(u32::from_le_bytes(bytes[56..60].try_into().unwrap()), 6);
    assert_eq!(&bytes[JOURNAL_HEADER_BYTES..], b"a body");

    assert_eq!(JournalRecord::decode(&bytes).expect("decodes"), record);
}

/// `encodes_as` answers exactly what `encode() == bytes` answers: yes for the record's own bytes,
/// and no for every single changed byte, every truncation and an extension, header and body alike.
#[test]
fn a_record_is_compared_with_bytes_exactly_as_its_encoding_is() {
    for body in [Vec::new(), b"a body".to_vec(), vec![0xA5; 513]] {
        let record = seal(
            7,
            1,
            [9u8; 32],
            Entry::new(RecordClass::Transaction, body)
                .at(1_700_000_000, 42)
                .under(3, 5),
        );
        let bytes = record.encode();
        assert!(record.encodes_as(&bytes));
        for at in 0..bytes.len() {
            let mut changed = bytes.clone();
            changed[at] ^= 0x01;
            assert!(!record.encodes_as(&changed), "changed byte {at}");
            assert_eq!(
                record.encodes_as(&changed),
                record.encode() == changed,
                "changed byte {at}"
            );
        }
        for len in 0..bytes.len() {
            assert!(!record.encodes_as(&bytes[..len]), "truncated to {len}");
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(!record.encodes_as(&longer));
    }
}

#[test]
fn one_chain_carries_every_unit() {
    let mut run = Vec::new();
    let mut head = [0u8; 32];
    for class in [
        RecordClass::Transaction,
        RecordClass::Checkpoint,
        RecordClass::Migration,
        RecordClass::Access,
    ] {
        let next = chain(
            1,
            run.len() as u64 + 1,
            head,
            entries(class, 2, class.code()),
        );
        head = next.last().expect("a record").hash;
        run.extend(next);
    }

    let stored: Vec<Record> = run
        .iter()
        .map(|r| Record::new(r.node, r.node_seq, r.encode()))
        .collect();
    let replayed = decode_run(&stored).expect("the stored run decodes");
    verify(&replayed).expect("and verifies");
    assert_eq!(replayed, run);
    assert_eq!(replayed[0].class, RecordClass::Transaction);
    assert_eq!(replayed[2].class, RecordClass::Checkpoint);
    assert_eq!(replayed[4].class, RecordClass::Migration);
    assert_eq!(replayed[6].class, RecordClass::Access);
    let seqs: Vec<u64> = replayed.iter().map(|r| r.node_seq).collect();
    assert_eq!(seqs, (1..=8).collect::<Vec<u64>>());

    let mut torn = stored.clone();
    torn[3].body.truncate(JOURNAL_HEADER_BYTES - 1);
    assert_eq!(
        decode_run(&torn).expect_err("a short record is not a record"),
        JournalBreak {
            at_index: 4,
            kind: JournalBreakKind::NotARecord,
        }
    );
}

#[test]
fn chain_verification_catches_a_mutated_body() {
    let mut run = chain(2, 1, [0u8; 32], entries(RecordClass::Transaction, 5, 1));
    assert!(verify(&run).is_ok());

    run[2].body[0] ^= 0xFF;
    let broken = verify(&run).expect_err("an edited body must not verify");
    assert_eq!(broken.at_index, 3);
    assert_eq!(broken.kind, JournalBreakKind::BodyDigestMismatch);
}

#[test]
fn chain_verification_catches_a_mutated_header() {
    let mut run = chain(2, 1, [0u8; 32], entries(RecordClass::Transaction, 4, 1));
    run[1].class = RecordClass::Access;
    let broken = verify(&run).expect_err("an edited class must not verify");
    assert_eq!(broken.at_index, 2);
    assert_eq!(broken.kind, JournalBreakKind::ChainDigestMismatch);

    let mut run = chain(2, 5, [9u8; 32], entries(RecordClass::Transaction, 4, 2));
    run[3].wall += 600;
    assert_eq!(
        verify(&run)
            .expect_err("an edited clock must not verify")
            .kind,
        JournalBreakKind::ChainDigestMismatch
    );
}

#[test]
fn chain_verification_catches_a_gap_in_the_numbering() {
    let first = chain(5, 1, [0u8; 32], entries(RecordClass::Transaction, 3, 1));
    let head = first.last().expect("a record").hash;
    let after = chain(5, 6, head, entries(RecordClass::Transaction, 2, 2));
    assert_eq!(after[0].node_seq, 6, "the fixture really did skip two");

    let mut run = first.clone();
    run.extend(after);
    let broken = verify(&run).expect_err("a skipped identity must not verify");
    assert_eq!(
        broken.kind,
        JournalBreakKind::SequenceMismatch {
            expected: 4,
            found: 6
        },
        "the break names the number that was owed and the one that arrived"
    );
    assert_eq!(broken.at_index, 4, "reported at the record that jumped");

    verify(&first).expect("everything up to the gap is sound");
}

#[test]
fn chain_verification_catches_a_removed_record() {
    let mut run = chain(2, 1, [0u8; 32], entries(RecordClass::Transaction, 5, 1));
    run.remove(2);
    let broken = verify(&run).expect_err("a removed record must not verify");
    assert_eq!(broken.at_index, 3);
    assert_eq!(broken.kind, JournalBreakKind::LinkMismatch);
}

/// A `journal-quarantine` ChainBreak body naming the hole between `before` and `after`, in the
/// field order the old engine's encoder wrote.
fn quarantine_body(before: Option<(u64, u64)>, after: Option<(u64, u64)>) -> Vec<u8> {
    let mut body = BodyWriter::new();
    body.text(QUARANTINE_BODY_TAG)
        .text("")
        .num(0)
        .num(0)
        .num(0)
        .num(1)
        .text("in-process")
        .num(0)
        .num(1);
    let (has_before, before) = before.map_or((0, (0, 0)), |id| (1, id));
    let (has_after, after) = after.map_or((0, (0, 0)), |id| (1, id));
    body.num(has_before)
        .num(before.0)
        .num(before.1)
        .num(has_after)
        .num(after.0)
        .num(after.1);
    body.finish()
}

/// Records 1..=4 of node 3, with record 2 gone, then a ChainBreak at 5 carrying `note`.
fn holed_run(note: Vec<u8>) -> Vec<JournalRecord> {
    let mut run = chain(3, 1, [0u8; 32], entries(RecordClass::Load, 4, 1));
    run.remove(1);
    let head = run.last().expect("a record").hash;
    run.push(seal(3, 5, head, Entry::new(RecordClass::ChainBreak, note)));
    run
}

/// The bridge rule: a chain crosses only the hole a quarantine note on it names, anchored on the
/// record it names as kept before the hole.
#[test]
fn verify_crosses_only_the_hole_a_quarantine_note_names() {
    verify(&holed_run(quarantine_body(Some((3, 1)), Some((3, 3)))))
        .expect("the named hole is crossed");

    let mut unnamed = holed_run(quarantine_body(Some((3, 1)), Some((3, 3))));
    unnamed.pop();
    assert_eq!(
        verify(&unnamed).expect_err("a hole no note names breaks the chain"),
        JournalBreak {
            at_index: 2,
            kind: JournalBreakKind::LinkMismatch,
        }
    );

    for (before, after) in [
        (Some((3, 2)), Some((3, 3))),
        (Some((3, 1)), Some((3, 4))),
        (None, Some((3, 3))),
    ] {
        assert_eq!(
            verify(&holed_run(quarantine_body(before, after)))
                .expect_err("a note anchored on the wrong record crosses nothing")
                .at_index,
            2,
            "{before:?} -> {after:?}"
        );
    }

    let mut plain = BodyWriter::new();
    plain.text("operator-break");
    assert_eq!(
        verify(&holed_run(plain.finish()))
            .expect_err("a ChainBreak that is not a quarantine note crosses nothing")
            .at_index,
        2
    );
}

/// A hole at the tail, with nothing kept after it, is crossed by the note that seals the hole:
/// the note links onto the last record kept before it.
#[test]
fn verify_crosses_a_tail_hole_the_note_anchors() {
    let mut run = chain(3, 1, [0u8; 32], entries(RecordClass::Load, 3, 1));
    let head = run.last().expect("a record").hash;
    run.push(seal(
        3,
        5,
        head,
        Entry::new(RecordClass::ChainBreak, quarantine_body(Some((3, 3)), None)),
    ));
    verify(&run).expect("number four stays taken, and the chain verifies across it");
}

/// The bytes of one `journal-quarantine` body as the 1.6.0 engine wrote them: tag, segment file,
/// segment, offset, damage offset, byte count, where it was kept, when, how many identities, then
/// the hole (has-before, before, has-after, after).
const GOLDEN_QUARANTINE_BODY: &str = concat!(
    "12000000000000006a6f75726e616c2d71756172616e74696e65000000000000",
    "0000030000000000000000040000000000000006000000000000000200000000",
    "00000a00000000000000696e2d70726f636573730068e5cf8b01000002000000",
    "0000000001000000000000000700000000000000040000000000000001000000",
    "0000000007000000000000000600000000000000",
);

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

/// Journals already written carry this layout, so the reader is pinned to the bytes.
#[test]
fn a_written_quarantine_body_reads_back_byte_for_byte() {
    let golden = unhex(GOLDEN_QUARANTINE_BODY);
    assert_eq!(golden.len(), 148);
    let note = QuarantineNote::read(&golden).expect("a quarantine body");
    assert_eq!(note.segment, 3);
    assert_eq!(note.offset, 1024);
    let bridge = note.bridge.expect("it names a hole");
    assert_eq!(bridge.before, (7, 4));
    assert_eq!(bridge.after, Some((7, 6)));

    assert_eq!(
        QuarantineNote::read(&golden[..golden.len() - 1])
            .expect("the fixed fields are whole")
            .bridge,
        None,
        "a cut hole names no bridge"
    );
    let mut other = golden.clone();
    other[8] ^= 0x20;
    assert!(
        QuarantineNote::read(&other).is_none(),
        "another tag is not a quarantine note"
    );
}
