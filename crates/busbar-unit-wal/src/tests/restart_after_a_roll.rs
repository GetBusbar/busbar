// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a restart resumes from once the log has rolled past its first segment.
//!
//! Every other battery in this crate rolls IN PROCESS, where the marks and the chain head are still
//! in memory and nothing has to be read back to know where the log ends. That is the one shape a
//! production restart never has. A node that has been up long enough to fill a segment and is then
//! restarted has to find the end of its log on the medium, and if it finds the end of the FIRST
//! segment instead it resumes in the middle of its own history: the numbers it takes next are
//! numbers it has already used, and a store that deduplicates on `(node, node_seq)` silently drops
//! everything the node writes after the restart.
//!
//! So the assertions here are about identity and linkage across the whole log, not about the last
//! segment: every `(node, node_seq)` appears once, and the chain read end to end verifies.

use busbar_caps::StepName;

use crate::backend::{DirectoryFactory, MemoryFactory, SegmentFactory as _};
use crate::journal::{decode_run, verify, Entry, Journal, JournalRecord, RecordClass};
use crate::record::{Record, FRAME_BYTES};
use crate::recover::scan;
use crate::segment::Segment;
use crate::ship::NullShipper;
use crate::wal::{Mode, Wal};

use super::fixtures::{durability_token, TempDir};

/// Small enough that a few hundred records roll the log several times.
const CEILING: u64 = 64 * FRAME_BYTES as u64;

/// The node the journal writes as.
const NODE: u64 = 9;

/// Append `n` entries, one per call, so the run crosses a roll at an arbitrary point rather than at
/// a batch boundary the test chose.
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

/// Every record in the log, oldest segment first — which is what "the chain" means once the log has
/// more than one segment and no single segment holds all of it.
fn whole_log(segments: Vec<Box<dyn crate::backend::SegmentBackend>>) -> Vec<Record> {
    let mut records = Vec::new();
    for backend in segments {
        let segment = Segment::open_at(backend, 0, 0, CEILING).expect("a segment opens");
        records.extend(scan(&segment).expect("a segment reads back").records);
    }
    records
}

/// The chain, decoded and verified end to end. A restart that resumed in the wrong segment shows up
/// here as a break, because the record it wrote first links to a head from the middle of the log.
fn verified_chain(records: &[Record]) -> Vec<JournalRecord> {
    let decoded = decode_run(records).expect("every record in the log is a journal record");
    verify(&decoded).expect("the chain links end to end across the restart");
    decoded
}

/// No identity is used twice, anywhere in the log. This is the property the store depends on: a
/// second record under a number some earlier record already carries is not stored, it is dropped as
/// a duplicate, and the settlement it recorded is gone without an error anywhere.
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

/// The assertions both backings share: the restart continued the chain instead of forking it.
///
/// `before` is where the first journal left the log; `resumed` is what the second one made of it
/// the moment it opened, before it had written anything of its own.
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

/// A restart of an on-disk node whose log has rolled resumes at the end of the log.
///
/// The FILE backing on purpose: the in-memory ones let a test hold the same factory across the
/// restart, which is a convenience a real restart does not have. Here the second log is handed
/// nothing but the directory, exactly as a node is handed nothing but its data directory, and
/// everything it knows it has to read off the disk.
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

/// The same claim on the memory backing, where the factory outlives the log the way a data
/// directory outlives a process.
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

/// A crash between a roll and the first commit into the segment it opened leaves a real but empty
/// newest segment. Resuming there would find no tail at all and start the chain over from genesis,
/// which is the same fork by a different route.
#[test]
fn a_restart_steps_back_over_a_segment_a_roll_opened_and_never_wrote_to() {
    let dir = TempDir::in_build_dir("roll-then-crash");

    let mut journal = Journal::over(open_over_dir(dir.path()), NODE);
    write(&mut journal, 400, 0x11);
    let before = (journal.head(), journal.next_seq(), 400);
    let last = journal.log().segments_used();
    drop(journal);

    // What the roll would have left behind: the next segment's file, present and empty.
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

fn open_over_dir(dir: &std::path::Path) -> Wal {
    let factory = DirectoryFactory::new(dir).expect("the data directory opens");
    Wal::with_parts(
        Box::new(factory),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        CEILING,
    )
    .expect("the log opens over its data directory")
}

fn open_over_memory(factory: &MemoryFactory) -> Wal {
    Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(NullShipper::new()),
        Mode::MemoryBuffered,
        CEILING,
    )
    .expect("a memory segment cannot fail to open")
}
