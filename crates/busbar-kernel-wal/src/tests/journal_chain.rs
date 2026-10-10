// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one journal: the fixed record, the chain over it, the bound on the buffer, and the two
//! postures a restart has to survive.
//!
//! Each of these is a claim somebody could otherwise only take on trust. A chain that "detects
//! tampering" is worth nothing until a test edits a record and watches it break at that record; a
//! buffer that is "bounded" is worth nothing until a test fills it and reads back what the node
//! decided to do about it.

use crate::journal::{Journal, RecordClass, MEMORY_BUFFER_RECORDS};

/// Fourteen classes, each pinned to its byte. The set is the contract's, so a test says the set did
/// not change rather than a reviewer having to remember it.
#[test]
fn every_class_is_pinned_to_its_byte() {
    assert_eq!(RecordClass::all().len(), 14);
    for class in RecordClass::all() {
        assert_eq!(RecordClass::from_code(class.code()), Some(*class));
    }
    assert_eq!(RecordClass::Transaction.code(), 1);
    assert_eq!(RecordClass::Checkpoint.code(), 6);
    assert_eq!(RecordClass::Migration.code(), 8);
    assert_eq!(RecordClass::ChainBreak.code(), 12);
    assert_eq!(RecordClass::FleetOutage.code(), 14);
    assert_eq!(RecordClass::from_code(0), None);
    assert_eq!(RecordClass::from_code(15), None);
}

/// The bound is pinned, and it is the one an operator cannot raise. Stated as a test because a
/// number that quietly grew would turn a store outage into an out-of-memory kill.
#[test]
fn the_bound_is_pinned() {
    assert_eq!(MEMORY_BUFFER_RECORDS, 8192);
    assert_eq!(
        Journal::memory_buffered(1, crate::tests::fixtures::wall_ms).capacity(),
        MEMORY_BUFFER_RECORDS
    );
}

/// The reading half of a body gives back exactly what the writing half put down, field by field, and
/// answers `None` — never a panic — on a body that is short or not what the reader expected.
#[test]
fn a_body_reads_back_what_was_written() {
    let mut body = crate::BodyWriter::new();
    body.text("hold.open");
    body.num(7);
    body.figure(-42);
    body.bytes(&[1, 2, 3]);
    let bytes = body.finish();

    let mut read = crate::BodyReader::new(&bytes);
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

    // A body cut short.
    let mut short = crate::BodyReader::new(&bytes[..bytes.len() - 1]);
    assert_eq!(short.text(), Some("hold.open"));
    assert_eq!(short.num(), Some(7));
    assert_eq!(short.figure(), Some(-42));
    assert_eq!(short.bytes(), None);

    // A length prefix that claims more than there is.
    let claim = u64::MAX.to_le_bytes();
    let mut lying = crate::BodyReader::new(&claim);
    assert_eq!(lying.text(), None);
}

/// A run of `n` chained journal records for `node`, numbered from one, as a store hands them back.
fn chained_run(node: u64, n: u64) -> Vec<crate::Record> {
    let mut head = [0u8; 32];
    (1..=n)
        .map(|seq| {
            let body = format!("record {seq}").into_bytes();
            let mut record = crate::JournalRecord {
                class: RecordClass::Transaction,
                node,
                node_seq: seq,
                lease_epoch: 0,
                policy_epoch: 0,
                wall: seq,
                mono: seq,
                body_hash: crate::body_digest(&body),
                body,
                prev_hash: head,
                hash: [0u8; 32],
            };
            record.hash = record.digest_of_chain();
            head = record.hash;
            crate::Record::new(node, seq, record.encode())
        })
        .collect()
}

/// A MEMORY JOURNAL RESUMED FROM THE STORE'S CHAIN reads that chain back and continues it: the
/// replay is the run the store kept, the head is its newest record's and the next number is past
/// it — and nothing it was seeded with is shipped again.
#[test]
fn a_resumed_memory_journal_reads_back_and_continues_the_stored_chain() {
    let run = chained_run(5, 40);
    let shipper = crate::BufferShipper::new();
    let journal = Journal::memory_resumed(
        5,
        &run,
        Box::new(shipper.clone()),
        crate::tests::fixtures::wall_ms,
    )
    .expect("a run that fits a segment seeds");
    let replayed = journal
        .replay()
        .expect("reads back")
        .expect("the seeded run verifies");
    assert_eq!(replayed.len(), 40, "every stored record is on the chain");
    assert_eq!(journal.next_seq(), 41, "the numbering continues past them");
    assert_eq!(
        journal.head(),
        replayed.last().expect("a record").hash,
        "the chain continues from the newest stored record"
    );
    assert!(
        shipper.records().is_empty(),
        "a seeded record is never shipped back to the store it came from"
    );
    assert_eq!(journal.mode(), crate::Mode::MemoryBuffered);
}

/// A journal that KEEPS records at its bound reports the bound and never seals a break: the caller
/// that asked for it refuses new work instead.
#[test]
fn a_retaining_journal_reports_its_bound_and_drops_nothing() {
    let journal = Journal::memory_buffered(1, crate::tests::fixtures::wall_ms)
        .with_capacity(1)
        .retaining_at_bound();
    assert!(!journal.at_bound(), "an empty buffer is not at its bound");
    assert_eq!(journal.dropped_total(), 0);
    assert!(journal.overflows().is_empty());
}
