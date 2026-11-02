// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::StepName;

use busbar_kernel_wal::journal::{
    decode_run, tail_of, verify, Entry, Journal, JournalBreakKind, JournalRecord, RecordClass,
    JOURNAL_HEADER_BYTES, JOURNAL_MAGIC, JOURNAL_VERSION, OVERFLOW_HISTORY_RECORDS,
};
use busbar_kernel_wal::ship::NullShipper;
use busbar_kernel_wal::wal::{Mode, Wal};

use super::fixtures::{durability_token, KeepingShipper, RefusingShipper, TempDir};

fn entries(class: RecordClass, n: usize, tag: u8) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            Entry::new(class, vec![tag, i as u8, 0xAB]).at(1_700_000_000 + i as u64, i as u64 * 7)
        })
        .collect()
}

#[test]
fn the_record_header_is_fixed() {
    assert_eq!(JOURNAL_HEADER_BYTES, 160);
    assert_eq!(JOURNAL_MAGIC, *b"BJRN");
    assert_eq!(JOURNAL_VERSION, 1);

    let mut journal =
        Journal::memory_buffered_to(7, Box::new(NullShipper::new()), super::fixtures::wall_ms);
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

    assert_eq!(
        JournalRecord::decode(&bytes).expect("decodes"),
        ack.sealed[0]
    );
}

#[test]
fn one_chain_carries_every_unit() {
    let mut journal =
        Journal::memory_buffered_to(1, Box::new(NullShipper::new()), super::fixtures::wall_ms);
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

    let seqs: Vec<u64> = replayed.iter().map(|r| r.node_seq).collect();
    assert_eq!(seqs, (1..=8).collect::<Vec<u64>>());
    assert_eq!(replayed.last().expect("a record").hash, journal.head());
}

#[test]
fn chain_verification_catches_a_mutated_body() {
    let mut journal =
        Journal::memory_buffered_to(2, Box::new(NullShipper::new()), super::fixtures::wall_ms);
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

#[test]
fn chain_verification_catches_a_mutated_header() {
    let mut journal =
        Journal::memory_buffered_to(2, Box::new(NullShipper::new()), super::fixtures::wall_ms);
    let token = durability_token();
    let mut run = journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 4, 1),
        )
        .expect("ships nowhere")
        .sealed;

    run[1].class = RecordClass::Access;
    let broken = verify(&run).expect_err("an edited class must not verify");
    assert_eq!(broken.at_index, 2);
    assert_eq!(broken.kind, JournalBreakKind::ChainDigestMismatch);

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

#[test]
fn chain_verification_catches_a_gap_in_the_numbering() {
    let token = durability_token();

    let mut journal =
        Journal::memory_buffered_to(5, Box::new(NullShipper::new()), super::fixtures::wall_ms);
    let first = journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 3, 1),
        )
        .expect("the store takes it")
        .sealed;
    assert_eq!(journal.next_seq(), 4, "the log ended on three");

    let mut head = journal.head();
    let after: Vec<JournalRecord> = entries(RecordClass::Transaction, 2, 2)
        .into_iter()
        .zip(6u64..)
        .map(|(entry, node_seq)| {
            let mut record = JournalRecord {
                class: entry.class,
                node: 5,
                node_seq,
                lease_epoch: entry.lease_epoch,
                policy_epoch: entry.policy_epoch,
                wall: entry.wall,
                mono: entry.mono,
                body_hash: busbar_kernel_wal::journal::body_digest(&entry.body),
                body: entry.body,
                prev_hash: head,
                hash: [0u8; 32],
            };
            record.hash = record.digest_of_chain();
            head = record.hash;
            record
        })
        .collect();
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

    assert_ne!(broken.kind, JournalBreakKind::LinkMismatch);
    assert_ne!(broken.kind, JournalBreakKind::BodyDigestMismatch);
    assert_ne!(broken.kind, JournalBreakKind::ChainDigestMismatch);

    verify(&first).expect("everything up to the gap is sound");
}

#[test]
fn chain_verification_catches_a_removed_record() {
    let mut journal =
        Journal::memory_buffered_to(2, Box::new(NullShipper::new()), super::fixtures::wall_ms);
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

#[test]
fn without_a_data_dir_the_journal_creates_no_file() {
    super::no_disk_tests::in_empty_working_directory(
        concat!(
            module_path!(),
            "::without_a_data_dir_the_journal_creates_no_file"
        ),
        || {
            let shipper = KeepingShipper::new();
            let mut journal =
                Journal::memory_buffered_to(3, Box::new(shipper.clone()), super::fixtures::wall_ms);
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

            assert_eq!(shipper.records().len(), 24);
        },
    );
}

#[test]
fn without_a_data_dir_what_the_store_took_is_the_chain_to_the_nodes_head() {
    let shipper = KeepingShipper::new();
    let token = durability_token();

    let (head_before, next_before) = {
        let mut journal =
            Journal::memory_buffered_to(9, Box::new(shipper.clone()), super::fixtures::wall_ms);
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

    let shipped = decode_run(&shipper.records()).expect("the shipped bytes are journal records");
    assert_eq!(shipped.len(), 9);
    verify(&shipped).expect("what the store holds is a chain that verifies");
    let (head, next_seq) = tail_of(&shipped, 9).expect("this node's own tail");
    assert_eq!(head, head_before, "the store's head is the node's head");
    assert_eq!(next_seq, next_before);
}

#[test]
fn with_a_data_dir_the_journal_replays_to_the_same_head() {
    let dir = TempDir::new("journal-on-disk");
    let inner = dir.path().join("journal");
    let token = durability_token();

    let (head_before, next_before) = {
        let mut journal = Journal::in_directory(
            5,
            &inner,
            Box::new(NullShipper::new()),
            super::fixtures::wall_ms,
        )
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

    let reopened = Journal::in_directory(
        5,
        &inner,
        Box::new(NullShipper::new()),
        super::fixtures::wall_ms,
    )
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

#[test]
fn a_full_buffer_seals_a_chain_break_rather_than_dropping_silently() {
    let mut journal =
        Journal::memory_buffered_to(4, Box::new(RefusingShipper), super::fixtures::wall_ms)
            .with_capacity(4);
    assert_eq!(journal.capacity(), 4);
    let token = durability_token();

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

    journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 3, 2),
        )
        .expect_err("the store is still refusing");

    assert!(
        journal.buffered() <= journal.capacity(),
        "the bound counts every record the buffer holds, the break record included: {} held against a bound of {}",
        journal.buffered(),
        journal.capacity()
    );

    let overflows = journal.overflows();
    assert_eq!(overflows.len(), 1, "the bound was reached exactly once");
    assert_eq!(overflows[0].dropped, 3);
    assert_eq!(overflows[0].first, (4, 1), "the OLDEST go, not the newest");
    assert_eq!(overflows[0].last, (4, 3));

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

#[test]
fn the_overflow_break_is_dated_so_a_retention_pass_does_not_delete_the_evidence() {
    let mut journal =
        Journal::memory_buffered_to(4, Box::new(RefusingShipper), super::fixtures::wall_ms)
            .with_capacity(4);
    let token = durability_token();

    journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 3, 1),
        )
        .expect_err("a store that refuses is a durability loss on a node with no data directory");

    let batch = entries(RecordClass::Transaction, 3, 2);
    let batch_wall = batch
        .iter()
        .map(|e| e.wall)
        .max()
        .expect("a non-empty batch");
    let batch_mono = batch
        .iter()
        .map(|e| e.mono)
        .max()
        .expect("a non-empty batch");
    journal
        .append(&token, StepName::Meter, &batch)
        .expect_err("the store is still refusing");

    let on_the_medium =
        decode_run(&journal.log().read_back().expect("readable").records).expect("journal records");
    let brk = on_the_medium
        .iter()
        .find(|r| r.class == RecordClass::ChainBreak)
        .expect("the overflow sealed a break");

    let cutoff = batch_wall - 1_000_000;
    assert!(
        cutoff > 0,
        "the cutoff has to be a real window, not epoch 0"
    );
    let survivors: Vec<&JournalRecord> =
        on_the_medium.iter().filter(|r| r.wall >= cutoff).collect();

    assert!(
        survivors
            .iter()
            .any(|r| r.class == RecordClass::ChainBreak),
        "the break that records the drop must survive a retention cutoff older than the batch that \
         caused it — a break left at `wall: 0` is older than every positive cutoff, so the FIRST \
         sweep deletes the one record saying entries were lost"
    );

    assert_eq!(
        brk.wall, batch_wall,
        "the break takes the appending batch's own wall clock"
    );
    assert_eq!(brk.mono, batch_mono, "and its monotonic clock too");
}

#[test]
fn a_batch_bigger_than_the_capacity_still_seals_a_chain_break() {
    let mut journal =
        Journal::memory_buffered_to(4, Box::new(RefusingShipper), super::fixtures::wall_ms)
            .with_capacity(4);
    let token = durability_token();

    journal
        .append(
            &token,
            StepName::Meter,
            &entries(RecordClass::Transaction, 6, 9),
        )
        .expect_err("the store refuses");

    let overflows = journal.overflows();
    assert_eq!(
        overflows.len(),
        1,
        "an oversized batch reaches the bound on its own"
    );
    assert_eq!(overflows[0].dropped, 0, "nothing was buffered yet to evict");

    let on_the_medium =
        decode_run(&journal.log().read_back().expect("readable").records).expect("journal records");
    let breaks: Vec<&JournalRecord> = on_the_medium
        .iter()
        .filter(|r| r.class == RecordClass::ChainBreak)
        .collect();
    assert_eq!(
        breaks.len(),
        1,
        "the oversized batch still seals a break, not none"
    );
    assert_eq!(breaks[0].body, overflows[0].body());
}

#[test]
fn overflow_history_is_a_window_while_the_dropped_total_keeps_rising() {
    let mut journal =
        Journal::memory_buffered_to(4, Box::new(RefusingShipper), super::fixtures::wall_ms)
            .with_capacity(4);
    let token = durability_token();

    for round in 0..80u8 {
        journal
            .append(
                &token,
                StepName::Meter,
                &entries(RecordClass::Transaction, 2, round),
            )
            .expect_err("the store refuses every time");
        assert!(
            journal.buffered() <= journal.capacity(),
            "round {round} left {} records buffered against a bound of {}",
            journal.buffered(),
            journal.capacity()
        );
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

#[test]
fn a_tail_this_build_cannot_read_does_not_make_the_next_record_vanish() {
    use busbar_kernel_wal::backend::MemoryFactory;
    use busbar_kernel_wal::record::{Record, FRAME_BYTES};

    const NODE: u64 = 6;
    const CEILING: u64 = 64 * FRAME_BYTES as u64;
    let token = durability_token();
    let factory = MemoryFactory::retaining();
    let open = |factory: &MemoryFactory| {
        Wal::with_parts(
            Box::new(factory.clone()),
            Box::new(NullShipper::new()),
            Mode::OnDisk,
            CEILING,
            super::fixtures::wall_ms,
        )
        .expect("a memory segment cannot fail to open")
    };

    {
        let mut log = open(&factory);
        log.append_batch(
            &token,
            StepName::Meter,
            &[
                Record::new(
                    NODE,
                    1,
                    b"a record of a layout this build does not read".to_vec(),
                ),
                Record::new(NODE, 2, b"and the one after it".to_vec()),
            ],
        )
        .expect("the medium is healthy");
    }

    let log = open(&factory);
    assert_eq!(
        log.recovered().len(),
        2,
        "the fixture is only interesting if the log recovered a tail it seeded its marks from"
    );
    let mut journal = Journal::over(log, NODE);

    let ack = journal
        .append(
            &token,
            StepName::Meter,
            &[Entry::new(
                RecordClass::Transaction,
                b"a settlement".to_vec(),
            )],
        )
        .expect("a healthy medium takes the append");
    assert_eq!(
        ack.batch.appended, 1,
        "the journal reported a sealed record the log never wrote"
    );

    let sealed = &ack.sealed[0];
    let on_the_medium = journal
        .log()
        .read_back()
        .expect("the segment reads back")
        .records;
    assert!(
        on_the_medium
            .iter()
            .any(|r| r.identity() == sealed.identity() && r.body == sealed.encode()),
        "the record the journal sealed is not on the medium: identity {:?} collided with the tail",
        sealed.identity()
    );
}
