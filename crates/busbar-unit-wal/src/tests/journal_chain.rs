// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one journal: the fixed record, the chain over it, the bound on the buffer, and the two
//! postures a restart has to survive.
//!
//! Each of these is a claim somebody could otherwise only take on trust. A chain that "detects
//! tampering" is worth nothing until a test edits a record and watches it break at that record; a
//! buffer that is "bounded" is worth nothing until a test fills it and reads back what the node
//! decided to do about it.

use busbar_caps::StepName;

use crate::journal::{
    decode_run, tail_of, verify, Entry, Journal, JournalBreakKind, JournalRecord, RecordClass,
    JOURNAL_HEADER_BYTES, JOURNAL_MAGIC, JOURNAL_VERSION, MEMORY_BUFFER_RECORDS,
    OVERFLOW_HISTORY_RECORDS,
};
use crate::ship::{BufferShipper, NullShipper, ShipError, Shipper};
use crate::wal::{Mode, Wal};

use super::fixtures::{durability_token, TempDir};

/// A store that will not take anything. What a memory-buffered node's durability failure looks like
/// from the log's side, and the only way to make the buffer grow at all.
#[derive(Debug, Default)]
struct RefusingShipper;

impl Shipper for RefusingShipper {
    fn ship(&mut self, _records: &[crate::record::Record]) -> Result<(), ShipError> {
        Err(ShipError::Unavailable("the store is not answering".into()))
    }
}

fn entries(class: RecordClass, n: usize, tag: u8) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            Entry::new(class, vec![tag, i as u8, 0xAB]).at(1_700_000_000 + i as u64, i as u64 * 7)
        })
        .collect()
}

/// The header is a fixed table of offsets, and a build that moved one would be a build that reads
/// every record already written at the wrong place. Pinned as numbers rather than as a `size_of`,
/// because the claim is about the MEDIUM and not about this compiler's layout.
#[test]
fn the_record_header_is_fixed() {
    assert_eq!(JOURNAL_HEADER_BYTES, 160);
    assert_eq!(JOURNAL_MAGIC, *b"BJRN");
    assert_eq!(JOURNAL_VERSION, 1);

    let mut journal = Journal::memory_buffered(7);
    let token = durability_token();
    let ack = journal
        .append(
            &token,
            StepName::Meter,
            &[Entry::new(RecordClass::Transaction, b"a body".to_vec())
                .at(1_700_000_000, 42)
                .under(3, 5)],
        )
        .expect("a memory-buffered journal that ships nowhere cannot fail");
    let bytes = ack.sealed[0].encode();

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

    // And it comes back exactly as it went down.
    assert_eq!(
        JournalRecord::decode(&bytes).expect("decodes"),
        ack.sealed[0]
    );
}

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

/// Every unit's records go on ONE chain, in the order they were sealed, and the run verifies.
#[test]
fn one_chain_carries_every_unit() {
    let mut journal = Journal::memory_buffered(1);
    let token = durability_token();
    for class in [
        RecordClass::Transaction,
        RecordClass::Checkpoint,
        RecordClass::Migration,
        RecordClass::Access,
    ] {
        journal
            .append(&token, StepName::Meter, &entries(class, 2, class.code()))
            .expect("ships nowhere");
    }

    let replayed = journal
        .replay()
        .expect("the log reads back")
        .expect("and verifies");
    assert_eq!(replayed.len(), 8);
    assert_eq!(replayed[0].class, RecordClass::Transaction);
    assert_eq!(replayed[2].class, RecordClass::Checkpoint);
    assert_eq!(replayed[4].class, RecordClass::Migration);
    assert_eq!(replayed[6].class, RecordClass::Access);
    // One numbering across all four, which is what "one journal" means in practice.
    let seqs: Vec<u64> = replayed.iter().map(|r| r.node_seq).collect();
    assert_eq!(seqs, (1..=8).collect::<Vec<u64>>());
    assert_eq!(replayed.last().expect("a record").hash, journal.head());
}

/// The chain catches a record whose BODY was edited, at that record.
#[test]
fn chain_verification_catches_a_mutated_body() {
    let mut journal = Journal::memory_buffered(2);
    let token = durability_token();
    let ack = journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 5, 1),
        )
        .expect("ships nowhere");
    let mut run = ack.sealed;
    assert!(verify(&run).is_ok());

    run[2].body[0] ^= 0xFF;
    let broken = verify(&run).expect_err("an edited body must not verify");
    assert_eq!(broken.at_index, 3);
    assert_eq!(broken.kind, JournalBreakKind::BodyDigestMismatch);
}

/// And a record whose HEADER was edited — which is why the chain hash covers the whole fixed header
/// and not only the identity and the two digests.
#[test]
fn chain_verification_catches_a_mutated_header() {
    let mut journal = Journal::memory_buffered(2);
    let token = durability_token();
    let mut run = journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 4, 1),
        )
        .expect("ships nowhere")
        .sealed;

    // Re-classing a settlement as an access would be the interesting edit: same money, different
    // story about what it was.
    run[1].class = RecordClass::Access;
    let broken = verify(&run).expect_err("an edited class must not verify");
    assert_eq!(broken.at_index, 2);
    assert_eq!(broken.kind, JournalBreakKind::ChainDigestMismatch);

    // The same for a moved clock, which is how a record is made to look like it happened elsewhen.
    let mut run = journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 4, 2),
        )
        .expect("ships nowhere")
        .sealed;
    run[3].wall += 600;
    assert_eq!(
        verify(&run)
            .expect_err("an edited clock must not verify")
            .kind,
        JournalBreakKind::ChainDigestMismatch
    );
}

/// A record REMOVED from the middle breaks the link rather than passing as a shorter history.
#[test]
fn chain_verification_catches_a_removed_record() {
    let mut journal = Journal::memory_buffered(2);
    let token = durability_token();
    let mut run = journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 5, 1),
        )
        .expect("ships nowhere")
        .sealed;
    run.remove(2);
    let broken = verify(&run).expect_err("a removed record must not verify");
    assert_eq!(broken.at_index, 3);
    assert_eq!(broken.kind, JournalBreakKind::LinkMismatch);
}

/// A memory-buffered journal writes nothing to any disk. The same claim the log makes, made again at
/// this level because the journal is what a unit now talks to and a caller reading only this module
/// should not have to go and check.
#[test]
fn without_a_data_dir_the_journal_creates_no_file() {
    let dir = TempDir::new("journal-no-disk");
    assert!(dir.walk().is_empty());
    let cwd_before = std::fs::read_dir(".")
        .map(|e| e.flatten().count())
        .unwrap_or(0);

    let shipper = BufferShipper::new();
    let mut journal = Journal::memory_buffered_to(3, Box::new(shipper.clone()));
    assert_eq!(journal.mode(), Mode::MemoryBuffered);
    let token = durability_token();
    for round in 0..6 {
        journal
            .append(
                &token,
                StepName::Meter,
                &entries(RecordClass::Transaction, 4, round),
            )
            .expect("the store takes it");
    }

    assert!(
        dir.walk().is_empty(),
        "a journal with no data directory put something on a disk: {:?}",
        dir.walk()
    );
    assert_eq!(
        cwd_before,
        std::fs::read_dir(".")
            .map(|e| e.flatten().count())
            .unwrap_or(0),
        "something appeared in the working directory"
    );
    assert_eq!(shipper.records().len(), 24);
}

/// A restart without a data directory loses nothing that was SHIPPED. What the store acknowledged
/// is what exists, so the chain resumes from the store's own copy and the next record links onto it.
#[test]
fn a_restart_without_a_data_dir_loses_nothing_that_was_shipped() {
    let shipper = BufferShipper::new();
    let token = durability_token();

    let (head_before, next_before) = {
        let mut journal = Journal::memory_buffered_to(9, Box::new(shipper.clone()));
        for round in 0..3 {
            journal
                .append(
                    &token,
                    StepName::Meter,
                    &entries(RecordClass::Transaction, 3, round),
                )
                .expect("the store takes it");
        }
        (journal.head(), journal.next_seq())
    };

    // The node is gone. Everything it had is what the store took.
    let shipped = decode_run(&shipper.records()).expect("the shipped bytes are journal records");
    assert_eq!(shipped.len(), 9);
    verify(&shipped).expect("what the store holds is a chain that verifies");
    let (head, next_seq) = tail_of(&shipped, 9).expect("this node's own tail");
    assert_eq!(head, head_before, "the store's head is the node's head");
    assert_eq!(next_seq, next_before);

    // And a node coming back up continues that chain rather than starting a second one.
    let mut restarted = Journal::resuming(
        Wal::memory_buffered_to(Box::new(shipper.clone())),
        9,
        head,
        next_seq,
    );
    let ack = restarted
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Checkpoint, 1, 9),
        )
        .expect("the store takes it");
    assert_eq!(ack.sealed[0].prev_hash, head_before);
    assert_eq!(ack.sealed[0].node_seq, 10);

    let whole = decode_run(&shipper.records()).expect("still journal records");
    verify(&whole).expect("the chain across the restart verifies end to end");
    assert_eq!(whole.len(), 10);
}

/// With a data directory the journal replays to the same head it had before the restart, off its own
/// segments and with no store involved at all.
#[test]
fn with_a_data_dir_the_journal_replays_to_the_same_head() {
    let dir = TempDir::new("journal-on-disk");
    let inner = dir.path().join("journal");
    let token = durability_token();

    let (head_before, next_before) = {
        let mut journal = Journal::in_directory(5, &inner, Box::new(NullShipper::new()))
            .expect("the directory is writable");
        assert_eq!(journal.mode(), Mode::OnDisk);
        for round in 0..4 {
            journal
                .append(
                    &token,
                    StepName::Meter,
                    &entries(RecordClass::Transaction, 3, round),
                )
                .expect("the disk takes it");
        }
        (journal.head(), journal.next_seq())
    };

    let reopened = Journal::in_directory(5, &inner, Box::new(NullShipper::new()))
        .expect("the journal reopens onto what it wrote");
    assert_eq!(
        reopened.head(),
        head_before,
        "the head moved across a restart"
    );
    assert_eq!(reopened.next_seq(), next_before);
    let replayed = reopened
        .replay()
        .expect("the segments read back")
        .expect("and verify");
    assert_eq!(replayed.len(), 12);
    assert_eq!(replayed.last().expect("a record").hash, head_before);
}

/// The buffer is bounded, and reaching the bound is a DECISION with a record for it — never a silent
/// drop, and never a refusal.
#[test]
fn a_full_buffer_seals_a_chain_break_rather_than_dropping_silently() {
    let mut journal = Journal::memory_buffered_to(4, Box::new(RefusingShipper)).with_capacity(4);
    assert_eq!(journal.capacity(), 4);
    let token = durability_token();

    // The store refuses, so the batch is retained. That is the buffer filling.
    journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 3, 1),
        )
        .expect_err("a store that refuses is a durability loss on a node with no data directory");
    assert_eq!(journal.buffered(), 3);
    assert!(
        journal.overflows().is_empty(),
        "the bound is not reached yet"
    );

    // Three more would make six against a bound of four, so two of the oldest go.
    journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 3, 2),
        )
        .expect_err("the store is still refusing");

    let overflows = journal.overflows();
    assert_eq!(overflows.len(), 1, "the bound was reached exactly once");
    assert_eq!(overflows[0].dropped, 2);
    assert_eq!(overflows[0].first, (4, 1), "the OLDEST go, not the newest");
    assert_eq!(overflows[0].last, (4, 2));

    // And the loss is on the chain, as the class the contract already has for it.
    let on_the_medium =
        decode_run(&journal.log().read_back().expect("readable").records).expect("journal records");
    let breaks: Vec<&JournalRecord> = on_the_medium
        .iter()
        .filter(|r| r.class == RecordClass::ChainBreak)
        .collect();
    assert_eq!(breaks.len(), 1, "one break record for one overflow");
    assert_eq!(
        breaks[0].body,
        overflows[0].body(),
        "the break names how many went and which"
    );
    assert_eq!(breaks[0].node_seq, overflows[0].chain_break_seq);
}

/// The overflow history is a window plus a running total, not one entry per overflowing append.
///
/// Once the buffer is full EVERY append overflows, so an unbounded history is a per-request memory
/// cost for the whole length of a store outage — growth that starts precisely when the node is
/// already degraded. The detail the window forgets is not lost: it is in the sealed `ChainBreak`
/// record, which is where it was always the durable answer.
#[test]
fn overflow_history_is_a_window_while_the_dropped_total_keeps_rising() {
    let mut journal = Journal::memory_buffered_to(4, Box::new(RefusingShipper)).with_capacity(4);
    let token = durability_token();

    for round in 0..80u8 {
        journal
            .append(
                &token,
                StepName::Meter,
                &entries(RecordClass::Transaction, 2, round),
            )
            .expect_err("the store refuses every time");
    }

    assert!(
        journal.overflows().len() <= OVERFLOW_HISTORY_RECORDS,
        "the history is a window, got {} entries",
        journal.overflows().len()
    );
    assert!(
        journal.overflows_seen() > OVERFLOW_HISTORY_RECORDS,
        "the run has to pass the window for the bound to mean anything"
    );
    assert!(
        journal.dropped_total() >= 100,
        "the running total keeps counting past the window, got {}",
        journal.dropped_total()
    );
    let window: Vec<u64> = journal
        .overflows()
        .iter()
        .map(|o| o.chain_break_seq)
        .collect();
    assert!(
        window.windows(2).all(|p| p[0] < p[1]),
        "the window reads oldest first"
    );
    assert!(
        window.first().is_some_and(|&seq| seq > 20),
        "the window keeps the NEWEST overflows, not the first ones the run made"
    );

    // And the durable side is untouched: a break is still sealed for every single overflow.
    let on_the_medium =
        decode_run(&journal.log().read_back().expect("readable").records).expect("journal records");
    let breaks: Vec<&JournalRecord> = on_the_medium
        .iter()
        .filter(|r| r.class == RecordClass::ChainBreak)
        .collect();
    assert_eq!(
        breaks.len(),
        journal.overflows_seen(),
        "one sealed ChainBreak per overflow, however few of them the history still names"
    );
}

/// The bound is pinned, and it is the one an operator cannot raise. Stated as a test because a
/// number that quietly grew would turn a store outage into an out-of-memory kill.
#[test]
fn the_bound_is_pinned() {
    assert_eq!(MEMORY_BUFFER_RECORDS, 8192);
    assert_eq!(
        Journal::memory_buffered(1).capacity(),
        MEMORY_BUFFER_RECORDS
    );
}
