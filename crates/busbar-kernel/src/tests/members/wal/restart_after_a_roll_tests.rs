// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::caps::StepName;

use busbar_kernel_wal::backend::{DirectoryFactory, MemoryFactory, SegmentFactory as _};
use busbar_kernel_wal::journal::{decode_run, verify, Entry, Journal, JournalRecord, RecordClass};
use busbar_kernel_wal::record::{Record, FRAME_BYTES};
use busbar_kernel_wal::recover::scan;
use busbar_kernel_wal::segment::Segment;
use busbar_kernel_wal::ship::NullShipper;
use busbar_kernel_wal::wal::{Mode, Wal};

use super::fixtures::{durability_token, TempDir};

const CEILING: u64 = 64 * FRAME_BYTES as u64;

const NODE: u64 = 9;

fn write(journal: &mut Journal, n: usize, tag: u8) {
    let token = durability_token();
    for i in 0..n {
        journal
            .append(
                &token,
                StepName::Meter,
                &[Entry::new(RecordClass::Transaction, vec![tag, i as u8])],
            )
            .expect("a healthy backing takes every append");
    }
}

fn whole_log(segments: Vec<Box<dyn busbar_kernel_wal::backend::SegmentBackend>>) -> Vec<Record> {
    let mut records = Vec::new();
    for backend in segments {
        let segment = Segment::open_at(backend, 0, 0, CEILING).expect("a segment opens");
        records.extend(scan(&segment).expect("a segment reads back").records);
    }
    records
}

fn verified_chain(records: &[Record]) -> Vec<JournalRecord> {
    let decoded = decode_run(records).expect("every record in the log is a journal record");
    verify(&decoded).expect("the chain links end to end across the restart");
    decoded
}

fn assert_no_identity_reuse(records: &[Record]) {
    let mut seen = std::collections::HashSet::new();
    for record in records {
        assert!(
            seen.insert(record.identity()),
            "identity {:?} appears twice in the log",
            record.identity()
        );
    }
}

fn assert_resumed(before: ([u8; 32], u64, usize), resumed: ([u8; 32], u64), whole: &[Record]) {
    let (head_before, next_seq_before, count_before) = before;
    assert_eq!(
        resumed.1, next_seq_before,
        "the restart resumed at the number the log actually ended on"
    );
    assert_eq!(
        resumed.0, head_before,
        "the restart resumed from the head the log actually ended on"
    );
    assert!(
        whole.len() > count_before,
        "the appends after the restart are in the log"
    );
    assert_no_identity_reuse(whole);
    let chain = verified_chain(whole);
    assert_eq!(chain.len(), whole.len());
    for (i, record) in chain.iter().enumerate() {
        assert_eq!(
            record.node_seq,
            i as u64 + 1,
            "the chain is numbered without a gap or a repeat across the restart"
        );
    }
}

#[test]
fn a_file_backed_restart_after_a_roll_resumes_at_the_end_of_the_log() {
    let dir = TempDir::in_build_dir("restart-after-a-roll");

    let mut journal = Journal::over(open_over_dir(dir.path()), NODE);
    write(&mut journal, 400, 0x11);
    assert!(
        journal.log().segments_used() > 1,
        "the run has to cross a roll for this to be the restart it claims to be"
    );
    let before = (journal.head(), journal.next_seq(), 400);
    drop(journal);

    let mut reopened = Journal::over(open_over_dir(dir.path()), NODE);
    let resumed = (reopened.head(), reopened.next_seq());
    write(&mut reopened, 40, 0x22);

    let mut factory = DirectoryFactory::new(dir.path()).expect("the directory is still there");
    let highest = factory
        .highest_index()
        .expect("the directory lists")
        .expect("a log that has written has segments");
    let segments = (0..=highest)
        .map(|i| factory.open(i).expect("every segment opens"))
        .collect();
    assert_resumed(before, resumed, &whole_log(segments));
}

#[test]
fn a_memory_backed_restart_after_a_roll_resumes_at_the_end_of_the_log() {
    let factory = MemoryFactory::retaining();

    let mut journal = Journal::over(open_over_memory(&factory), NODE);
    write(&mut journal, 400, 0x11);
    assert!(
        journal.log().segments_used() > 1,
        "the run has to cross a roll for this to be the restart it claims to be"
    );
    let before = (journal.head(), journal.next_seq(), 400);
    drop(journal);

    let mut reopened = Journal::over(open_over_memory(&factory), NODE);
    let resumed = (reopened.head(), reopened.next_seq());
    write(&mut reopened, 40, 0x22);

    let mut listing = factory.clone();
    let highest = listing
        .highest_index()
        .expect("the map answers")
        .expect("a log that has written has segments");
    let segments = (0..=highest)
        .map(|i| listing.open(i).expect("every segment opens"))
        .collect();
    assert_resumed(before, resumed, &whole_log(segments));
}

#[test]
fn a_restart_steps_back_over_a_segment_a_roll_opened_and_never_wrote_to() {
    let dir = TempDir::in_build_dir("roll-then-crash");

    let mut journal = Journal::over(open_over_dir(dir.path()), NODE);
    write(&mut journal, 400, 0x11);
    let before = (journal.head(), journal.next_seq(), 400);
    let last = journal.log().segments_used();
    drop(journal);

    let mut factory = DirectoryFactory::new(dir.path()).expect("the directory is there");
    drop(factory.open(last).expect("the next segment is created"));
    assert!(factory.segment_path(last).exists());

    let mut reopened = Journal::over(open_over_dir(dir.path()), NODE);
    let resumed = (reopened.head(), reopened.next_seq());
    write(&mut reopened, 10, 0x22);

    let highest = factory
        .highest_index()
        .expect("the directory lists")
        .expect("a log that has written has segments");
    let segments = (0..=highest)
        .map(|i| factory.open(i).expect("every segment opens"))
        .collect();
    assert_resumed(before, resumed, &whole_log(segments));
}

#[test]
fn a_file_backed_restart_after_a_roll_replays_every_segment_oldest_first() {
    let dir = TempDir::in_build_dir("replay-after-a-roll");

    let mut journal = Journal::over(open_over_dir(dir.path()), NODE);
    write(&mut journal, 400, 0x11);
    assert!(
        journal.log().segments_used() > 1,
        "the run has to cross a roll for this to be the restart it claims to be"
    );
    drop(journal);

    let mut reopened = Journal::over(open_over_dir(dir.path()), NODE);
    write(&mut reopened, 40, 0x22);
    let chain = reopened
        .replay()
        .expect("the log reads back")
        .expect("the chain verifies end to end");
    assert_eq!(
        chain.len(),
        440,
        "every record written before and after the restart, in every segment"
    );
    for (i, record) in chain.iter().enumerate() {
        assert_eq!(record.node_seq, i as u64 + 1, "oldest segment first");
    }
    assert_eq!(
        chain[0].body,
        vec![0x11, 0],
        "the first record of segment zero"
    );
}

#[test]
fn a_memory_backed_replay_after_a_roll_reads_every_resident_segment() {
    let factory = MemoryFactory::retaining();
    let mut journal = Journal::over(open_over_memory(&factory), NODE);
    write(&mut journal, 400, 0x11);
    assert!(journal.log().segments_used() > 1);
    let chain = journal
        .replay()
        .expect("the log reads back")
        .expect("the chain verifies end to end");
    assert_eq!(chain.len(), 400);
    assert_eq!(chain[0].node_seq, 1);
}

fn open_over_dir(dir: &std::path::Path) -> Wal {
    let factory = DirectoryFactory::new(dir).expect("the data directory opens");
    Wal::with_parts(
        Box::new(factory),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        CEILING,
        super::fixtures::wall_ms,
    )
    .expect("the log opens over its data directory")
}

fn open_over_memory(factory: &MemoryFactory) -> Wal {
    Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(NullShipper::new()),
        Mode::MemoryBuffered,
        CEILING,
        super::fixtures::wall_ms,
    )
    .expect("a memory segment cannot fail to open")
}
