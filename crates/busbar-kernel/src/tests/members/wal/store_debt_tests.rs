// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! On a data directory the store is catch-up work, and catch-up work that is given up on is a hole
//! in the store's copy of the chain.
//!
//! The log keeps what the store has not taken in a bounded queue, because a store that is down for
//! an hour must not be answered by exhausting the node's memory. The records past that bound are on
//! the medium either way; what the bound may cost is memory, never the store's copy of them. When
//! the store answers again, every record it was owed reaches it, once each, in the order written.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::caps::StepName;
use busbar_kernel_wal::backend::MemoryFactory;
use busbar_kernel_wal::record::{Record, FRAME_BYTES};
use busbar_kernel_wal::ship::{ShipError, Shipper};
use busbar_kernel_wal::wal::{Mode, Wal, STORE_BACKLOG_RECORDS};

use super::fixtures::durability_token;

/// A store that refuses while `down` is set and keeps everything it takes.
#[derive(Clone, Default)]
struct Store {
    down: Arc<AtomicBool>,
    taken: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl Shipper<Record> for Store {
    fn ship(&mut self, records: &[Record]) -> Result<(), ShipError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(ShipError::Unavailable("under test".into()));
        }
        self.taken
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend(records.iter().map(Record::identity));
        Ok(())
    }
}

/// RED before the fix: past the bound the oldest records left the queue and were only counted, so
/// the store, once it answered, never received them.
#[test]
fn an_on_disk_store_outage_longer_than_the_queue_still_reaches_the_store_whole() {
    const NODE: u64 = 7;
    const BATCH: u64 = 100;
    let store = Store::default();
    store.down.store(true, Ordering::SeqCst);
    // A small segment, so the outage spans several of them and the catch-up reads across a roll.
    let mut wal = Wal::with_parts(
        Box::new(MemoryFactory::retaining()),
        Box::new(store.clone()),
        Mode::OnDisk,
        1024 * FRAME_BYTES as u64,
        super::fixtures::wall_ms,
    )
    .expect("a memory segment opens");
    let token = durability_token();

    let mut written = 0u64;
    while written < STORE_BACKLOG_RECORDS as u64 + 3 * BATCH {
        let batch: Vec<Record> = (written + 1..=written + BATCH)
            .map(|seq| Record::new(NODE, seq, vec![seq as u8; 24]))
            .collect();
        wal.append_batch(&token, StepName::Meter, &batch)
            .expect("the medium is healthy; only the store is not");
        written += BATCH;
    }
    assert!(
        wal.owed_to_store().len() <= STORE_BACKLOG_RECORDS,
        "the queue in memory stays bounded, got {}",
        wal.owed_to_store().len()
    );
    assert!(wal.segments_used() > 1, "the outage spans a roll");
    assert!(store.taken.lock().unwrap().is_empty());

    // The store answers again, and the next commit settles the whole debt.
    store.down.store(false, Ordering::SeqCst);
    let last = Record::new(NODE, written + 1, b"after the outage".to_vec());
    wal.append_batch(&token, StepName::Meter, &[last])
        .expect("a healthy commit");
    written += 1;

    let taken = store.taken.lock().unwrap().clone();
    let expected: Vec<(u64, u64)> = (1..=written).map(|seq| (NODE, seq)).collect();
    assert_eq!(
        taken.len(),
        expected.len(),
        "every record written reaches the store, each once"
    );
    assert_eq!(taken, expected, "in the order written");
    assert!(wal.owed_to_store().is_empty(), "and nothing is owed after");
}

/// Write `count` records numbered from `from` as one commit each.
fn commit_each(wal: &mut Wal, from: u64, count: u64) {
    let token = durability_token();
    for seq in from..from + count {
        wal.append_batch(
            &token,
            StepName::Meter,
            &[Record::new(RESTART_NODE, seq, vec![seq as u8; 24])],
        )
        .expect("the medium is healthy; only the store is not");
    }
}

/// The node the restart batteries write as.
const RESTART_NODE: u64 = 11;

/// A log over `factory` on a disk, shipping to `store`.
fn on_disk(factory: &MemoryFactory, store: &Store) -> Wal {
    Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(store.clone()),
        Mode::OnDisk,
        256 * FRAME_BYTES as u64,
        super::fixtures::wall_ms,
    )
    .expect("a memory segment opens")
}

/// RED before the fix: the store's debt lived only in the process, so a node restarted during a
/// store outage opened with nothing owed, and the records the store never took never reached it.
/// (BUSBAR-1.6.0.md section 7: the journal is the record and the store keeps its copy; on a disk
/// the store is catch-up work, and catch-up work forgotten at a restart is a hole in that copy.)
#[test]
fn a_restart_during_an_on_disk_store_outage_still_owes_the_store_every_record() {
    let factory = MemoryFactory::retaining();
    let store = Store::default();
    store.down.store(true, Ordering::SeqCst);
    {
        let mut wal = on_disk(&factory, &store);
        // Past one segment, so the debt the restart owes is read across a roll.
        commit_each(&mut wal, 1, 300);
        assert!(store.taken.lock().unwrap().is_empty());
    }
    // The process ends; the store comes back; the node restarts over the same medium.
    store.down.store(false, Ordering::SeqCst);
    let mut wal = on_disk(&factory, &store);
    commit_each(&mut wal, 301, 1);

    let mut taken = store.taken.lock().unwrap().clone();
    taken.sort_unstable();
    taken.dedup();
    let expected: Vec<(u64, u64)> = (1..=301).map(|seq| (RESTART_NODE, seq)).collect();
    assert_eq!(
        taken, expected,
        "every record written before the restart reaches the store, and the new one after them"
    );
    assert!(wal.owed_to_store().is_empty(), "and nothing is owed after");
}

/// GREEN twin: a store that took every record before the restart loses nothing and gains no
/// identity it did not have. The restart re-offers the log once, in the order written, and the
/// store's put is an idempotent upsert keyed on the identity, so the re-offer is the same records.
#[test]
fn a_restart_over_a_store_that_took_everything_offers_the_same_records_in_order() {
    let factory = MemoryFactory::retaining();
    let store = Store::default();
    {
        let mut wal = on_disk(&factory, &store);
        commit_each(&mut wal, 1, 300);
    }
    let before: Vec<(u64, u64)> = store.taken.lock().unwrap().clone();
    let expected: Vec<(u64, u64)> = (1..=300).map(|seq| (RESTART_NODE, seq)).collect();
    assert_eq!(
        before, expected,
        "a healthy store took each record once, in order"
    );

    let wal = on_disk(&factory, &store);
    let after = store.taken.lock().unwrap().clone();
    assert_eq!(
        &after[before.len()..],
        expected.as_slice(),
        "the restart re-offers the whole log once, oldest first, at open"
    );
    assert!(
        !wal.owes_store_from_medium(),
        "and owes nothing once the store took it"
    );
    assert_eq!(
        wal.store_debt_on_medium(),
        0,
        "and left nothing on the medium past the bound"
    );
}

/// GREEN twin: a fresh log owes the store nothing at open and ships nothing until it commits.
#[test]
fn a_fresh_on_disk_log_owes_the_store_nothing_at_open() {
    let factory = MemoryFactory::retaining();
    let store = Store::default();
    let wal = on_disk(&factory, &store);
    assert!(!wal.owes_store_from_medium());
    assert!(store.taken.lock().unwrap().is_empty());
}
