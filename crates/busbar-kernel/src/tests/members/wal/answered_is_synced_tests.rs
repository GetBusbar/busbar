// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WRITE-BEFORE-ANSWER GATE: every record the journal acknowledged is on the medium as of the
//! last completed sync, so a crash right after the answer loses nothing that was answered.
//!
//! A real disk keeps written-but-unsynced bytes in the page cache, and `kill -9` does not lose
//! them, so a kill test over a real directory cannot tell an append that synced from one that only
//! wrote. The backing here keeps two images per segment: what was WRITTEN, and what was there at the
//! last completed `sync` (what a power cut leaves). After every acknowledged append the test cuts
//! the power, reopens a journal over only the synced images and replays it: every record any `Ok`
//! has carried must be there, byte for byte, and the chain must verify.
//!
//! This holds for any way of committing. A group commit that answered a waiter before the sync
//! covering its record would leave that record only in the written image, and this test reports it.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{Arc, Mutex};

use busbar_kernel_wal::backend::{MemoryFactory, MemorySegment, SegmentBackend, SegmentFactory};
use busbar_kernel_wal::journal::{Entry, Journal, RecordClass};
use busbar_kernel_wal::record::FRAME_BYTES;
use busbar_kernel_wal::ship::NullShipper;
use busbar_kernel_wal::wal::{Mode, Wal};

use super::fixtures::{durability_token, wall_ms, METER};

/// The node every record is written as.
const NODE: u64 = 7;

/// A small segment ceiling, so the run rolls through several segments.
const CEILING: u64 = 24 * FRAME_BYTES as u64;

/// What a power cut leaves: each segment's bytes as of its last completed sync.
type Synced = Arc<Mutex<BTreeMap<u64, Vec<u8>>>>;

/// The segments whose sync has failed once. Shared by every backing the factory hands out, so a
/// segment reopened under the same index stays failed.
type Failed = Arc<Mutex<std::collections::HashSet<u64>>>;

/// A memory backing that copies its bytes to the synced image only when a sync completes, and can
/// be told to fail its next sync.
///
/// AFTER A FAILED SYNC THE SEGMENT'S SYNCED IMAGE IS FROZEN. A kernel may drop the dirty pages of a
/// file whose fsync returned EIO and report the next fsync as a success ("fsyncgate"), so nothing
/// written to that segment before or after the failure counts as durable. A later `sync` answers
/// `Ok` and snapshots nothing. A log that kept the failed batch on the poisoned segment, or marked it
/// written instead of rewriting it on a fresh one, loses it here.
struct PowerCutBackend {
    index: u64,
    written: MemorySegment,
    synced: Synced,
    fail_next_sync: Arc<Mutex<bool>>,
    failed: Failed,
}

impl SegmentBackend for PowerCutBackend {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        self.written.write_all_at(offset, bytes)
    }

    fn sync(&mut self) -> io::Result<()> {
        if std::mem::take(&mut *self.fail_next_sync.lock().unwrap()) {
            self.failed.lock().unwrap().insert(self.index);
            return Err(io::Error::other("simulated EIO at the sync point"));
        }
        if self.failed.lock().unwrap().contains(&self.index) {
            return Ok(());
        }
        self.synced
            .lock()
            .unwrap()
            .insert(self.index, self.written.snapshot());
        Ok(())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.written.read_at(offset, buf)
    }

    fn len(&self) -> io::Result<u64> {
        self.written.len()
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.written.set_len(len)
    }
}

/// Hands out [`PowerCutBackend`]s over one written image and one synced image.
#[derive(Clone)]
struct PowerCutFactory {
    written: MemoryFactory,
    synced: Synced,
    fail_next_sync: Arc<Mutex<bool>>,
    failed: Failed,
}

impl PowerCutFactory {
    fn new() -> Self {
        PowerCutFactory {
            written: MemoryFactory::retaining(),
            synced: Arc::default(),
            fail_next_sync: Arc::default(),
            failed: Arc::default(),
        }
    }

    /// Cut the power: a fresh factory holding, for every segment the log created, only the bytes
    /// its last completed sync covered. A segment created but never synced comes back empty.
    fn after_power_cut(&self, created: u64) -> MemoryFactory {
        let image = MemoryFactory::retaining();
        let synced = self.synced.lock().unwrap();
        for index in 0..created {
            *image.segment_bytes(index).lock().unwrap() =
                synced.get(&index).cloned().unwrap_or_default();
        }
        image
    }
}

impl SegmentFactory for PowerCutFactory {
    fn open(&mut self, index: u64) -> io::Result<Box<dyn SegmentBackend>> {
        Ok(Box::new(PowerCutBackend {
            index,
            written: MemorySegment::over(self.written.segment_bytes(index)),
            synced: Arc::clone(&self.synced),
            fail_next_sync: Arc::clone(&self.fail_next_sync),
            failed: Arc::clone(&self.failed),
        }))
    }

    fn highest_index(&self) -> io::Result<Option<u64>> {
        self.written.highest_index()
    }

    fn existing(&self, index: u64) -> io::Result<Option<Box<dyn SegmentBackend>>> {
        self.written.existing(index)
    }

    fn is_durable(&self) -> bool {
        true
    }

    fn segment_file(&self, _index: u64) -> Option<std::path::PathBuf> {
        None
    }

    fn quarantine(
        &mut self,
        index: u64,
        offset: u64,
        unix_ms: u64,
        bytes: &[u8],
    ) -> io::Result<Option<std::path::PathBuf>> {
        self.written.quarantine(index, offset, unix_ms, bytes)
    }
}

fn journal_over(factory: Box<dyn SegmentFactory>) -> Journal {
    let wal = Wal::with_parts(
        factory,
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        CEILING,
        wall_ms,
    )
    .expect("a memory segment opens");
    Journal::over(wal, NODE)
}

/// One batch of `n` entries, each body naming the batch and its place in it. Bodies vary in length
/// so some records span more than one frame.
fn batch(round: u64, n: u64) -> Vec<Entry> {
    (0..n)
        .map(|i| {
            let len = 40 + ((round * 131 + i * 17) % 900) as usize;
            let body: Vec<u8> = (0..len)
                .map(|b| ((round as usize * 7 + i as usize + b) % 251) as u8)
                .collect();
            Entry::new(RecordClass::Transaction, body).at(round, i)
        })
        .collect()
}

/// Cut the power now and assert every answered record is on what is left, and the chain verifies.
fn assert_power_cut_keeps(
    factory: &PowerCutFactory,
    created: u64,
    answered: &HashMap<u64, Vec<u8>>,
    round: u64,
) {
    let survivor = journal_over(Box::new(factory.after_power_cut(created)));
    let replayed = survivor
        .replay()
        .expect("the synced image reads back")
        .unwrap_or_else(|e| panic!("round {round}: the synced image does not verify: {e:?}"));
    let on_medium: HashMap<u64, &Vec<u8>> = replayed
        .iter()
        .filter(|r| r.node == NODE)
        .map(|r| (r.node_seq, &r.body))
        .collect();
    for (seq, body) in answered {
        assert_eq!(
            on_medium.get(seq).copied(),
            Some(body),
            "round {round}: record {seq} was answered Ok but a power cut right after the answer \
             lost it: the append answered before the sync that covers it"
        );
    }
}

/// Every append that answers `Ok` has been synced: a power cut right after any answer keeps every
/// record answered so far, across segment rolls and group commits of one to four records.
#[test]
fn a_power_cut_right_after_any_answer_loses_nothing_answered() {
    let token = durability_token();
    let factory = PowerCutFactory::new();
    let mut journal = journal_over(Box::new(factory.clone()));
    let mut answered: HashMap<u64, Vec<u8>> = HashMap::new();
    for round in 1..=120u64 {
        let ack = journal
            .append(&token, METER, &batch(round, 1 + round % 4))
            .expect("a healthy medium takes every batch");
        for record in &ack.sealed {
            answered.insert(record.node_seq, record.body.clone());
        }
        assert_power_cut_keeps(&factory, journal.log().segments_used(), &answered, round);
    }
    assert!(
        journal.log().segments_used() > 3,
        "the run rolled through several segments"
    );
}

/// The same with a failing medium: an append whose sync fails answers a loss, not `Ok`, and every
/// record that WAS answered `Ok` survives a power cut — including the failed batch once a later
/// append writes it again and answers for it.
#[test]
fn a_failed_sync_answers_no_ok_and_every_ok_survives_a_power_cut() {
    let token = durability_token();
    let factory = PowerCutFactory::new();
    let mut journal = journal_over(Box::new(factory.clone()));
    let mut answered: HashMap<u64, Vec<u8>> = HashMap::new();
    let mut lost: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut failures = 0;
    for round in 1..=90u64 {
        let entries = batch(round, 1 + round % 3);
        let fail = round % 7 == 0;
        if fail {
            *factory.fail_next_sync.lock().unwrap() = true;
        }
        let next = journal.next_seq();
        match journal.append(&token, METER, &entries) {
            Ok(ack) => {
                assert!(!fail, "round {round}: a failed sync must not answer Ok");
                for record in &ack.sealed {
                    answered.insert(record.node_seq, record.body.clone());
                }
                // A retained batch is written ahead of this one, so this Ok answers for it too.
                answered.extend(std::mem::take(&mut lost));
            }
            Err(_) => {
                assert!(fail, "round {round}: a healthy medium answered a loss");
                failures += 1;
                for (i, entry) in entries.iter().enumerate() {
                    lost.insert(next + i as u64, entry.body.clone());
                }
            }
        }
        assert_power_cut_keeps(&factory, journal.log().segments_used(), &answered, round);
    }
    assert!(failures >= 10, "the run exercised the failure arm");
}
