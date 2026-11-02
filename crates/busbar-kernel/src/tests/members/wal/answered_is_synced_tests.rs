// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::{Arc, Mutex};

use busbar_kernel_wal::backend::{MemoryFactory, MemorySegment, SegmentBackend, SegmentFactory};
use busbar_kernel_wal::journal::{Entry, Journal, RecordClass};
use busbar_kernel_wal::record::FRAME_BYTES;
use busbar_kernel_wal::ship::NullShipper;
use busbar_kernel_wal::wal::{Mode, Wal};

use super::fixtures::{durability_token, wall_ms, METER};

const NODE: u64 = 7;

const CEILING: u64 = 24 * FRAME_BYTES as u64;

type Synced = Arc<Mutex<BTreeMap<u64, Vec<u8>>>>;

type Failed = Arc<Mutex<std::collections::HashSet<u64>>>;

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
