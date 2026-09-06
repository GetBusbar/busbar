// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What happens when the medium says no.
//!
//! A write error and a full volume are the same event to this crate: a durable write that was
//! observed to fail. The segment is closed, the caller is handed a durability loss, and the batch
//! that failed goes to a fresh segment with the batch after it — in that order, so the log reads
//! back in the order records were written.

use crate::record::FRAME_BYTES;
use crate::wal::{Mode, Wal};

use super::fixtures::{durability_token, records, Fault, FaultyFactory};

const CEILING: u64 = 256 * FRAME_BYTES as u64;

fn wal_with_faults() -> (
    Wal,
    super::fixtures::FaultSwitch,
    crate::backend::MemoryFactory,
) {
    let (factory, switch, memory) = FaultyFactory::new();
    let wal = Wal::with_parts(
        Box::new(factory),
        Box::new(crate::ship::NullShipper::new()),
        Mode::OnDisk,
        CEILING,
    )
    .unwrap();
    (wal, switch, memory)
}

#[test]
fn an_error_at_the_sync_point_poisons_the_segment() {
    for fault in [Fault::SyncEio, Fault::SyncEnospc] {
        let (mut wal, switch, _memory) = wal_with_faults();
        let token = durability_token();
        switch.arm(fault);
        let batch = records(1, 1, 2, 40);
        let lost = wal
            .append_batch(&token, busbar_caps::StepName::Meter, &batch)
            .expect_err("a failed sync must be reported as a lost durable write");
        assert_eq!(lost.step(), busbar_caps::StepName::Meter);
        assert!(wal.is_poisoned(), "{fault:?} did not poison the segment");
        assert_eq!(wal.owed(), batch.as_slice());
    }
}

#[test]
fn an_error_at_the_write_itself_poisons_the_segment_too() {
    let (mut wal, switch, _memory) = wal_with_faults();
    let token = durability_token();
    switch.arm(Fault::WriteEio);
    let batch = records(1, 1, 1, 40);
    wal.append_batch(&token, busbar_caps::StepName::Admit, &batch)
        .expect_err("a failed write is a lost durable write");
    assert!(wal.is_poisoned());
}

#[test]
fn batches_n_and_n_plus_one_are_re_appended_to_a_fresh_segment_in_order() {
    let (mut wal, switch, _memory) = wal_with_faults();
    let token = durability_token();

    // Batch n-1 lands.
    let earlier = records(1, 1, 2, 40);
    wal.append_batch(&token, busbar_caps::StepName::Meter, &earlier)
        .unwrap();
    let first_segment = wal.segments_used();

    // Batch n is lost at the sync point.
    switch.arm(Fault::SyncEio);
    let n = records(1, 3, 2, 40);
    wal.append_batch(&token, busbar_caps::StepName::Meter, &n)
        .expect_err("the sync was armed to fail");
    assert!(wal.is_poisoned());

    // Batch n+1 arrives; the log rolls, writes n, then n+1.
    let n_plus_one = records(1, 5, 2, 40);
    let ack = wal
        .append_batch(&token, busbar_caps::StepName::Meter, &n_plus_one)
        .expect("the fresh segment takes both batches");
    assert!(ack.replayed_lost_batch);
    assert_eq!(ack.appended, 4, "both batches, no duplicates");
    assert!(wal.segments_used() > first_segment, "the log rolled");
    assert!(wal.owed().is_empty());
    assert!(!wal.is_poisoned());

    let back = wal.read_back().unwrap().records;
    let mut expected = n.clone();
    expected.extend(n_plus_one.clone());
    assert_eq!(
        back, expected,
        "n before n+1, in the order they were written"
    );
}

#[test]
fn re_appending_a_batch_that_is_already_in_the_log_writes_nothing_twice() {
    let (mut wal, _switch, _memory) = wal_with_faults();
    let token = durability_token();
    let batch = records(2, 1, 3, 40);

    let first = wal
        .append_batch(&token, busbar_caps::StepName::Meter, &batch)
        .unwrap();
    assert_eq!(first.appended, 3);
    assert_eq!(first.already_present, 0);

    let again = wal
        .append_batch(&token, busbar_caps::StepName::Meter, &batch)
        .unwrap();
    assert_eq!(
        again.appended, 0,
        "a re-offer is not an error, it is a no-op"
    );
    assert_eq!(again.already_present, 3);
    assert_eq!(again.durable_end, first.durable_end);

    // Overlapping: the batch names four records, two of which the log already holds.
    let overlapping = records(2, 2, 4, 40);
    let third = wal
        .append_batch(&token, busbar_caps::StepName::Meter, &overlapping)
        .unwrap();
    assert_eq!(third.appended, 2);
    assert_eq!(third.already_present, 2);
    assert_eq!(wal.read_back().unwrap().records.len(), 5);
}

#[test]
fn a_group_commit_costs_one_sync_however_many_records_are_in_it() {
    let (mut wal, switch, _memory) = wal_with_faults();
    let token = durability_token();
    let before = switch.syncs();
    wal.append_batch(
        &token,
        busbar_caps::StepName::Meter,
        &records(9, 1, 16, 300),
    )
    .unwrap();
    assert_eq!(
        switch.syncs() - before,
        1,
        "sixteen records in one batch must cost exactly one sync"
    );
}

#[test]
fn a_poisoned_segment_never_takes_another_write() {
    let (mut wal, switch, _memory) = wal_with_faults();
    let token = durability_token();
    switch.arm(Fault::SyncEio);
    wal.append_batch(&token, busbar_caps::StepName::Meter, &records(1, 1, 1, 10))
        .expect_err("armed");
    // The switch is one-shot, so the disk is healthy again — but the segment stays closed and the
    // log moves on rather than writing more bytes into a region of unknown state.
    let segment_before = wal.read_back().unwrap();
    let ack = wal
        .append_batch(&token, busbar_caps::StepName::Meter, &records(1, 2, 1, 10))
        .unwrap();
    assert!(ack.segment > 0, "the write went to a fresh segment");
    let _ = segment_before;
}

/// What the store is owed on disk is a QUEUE WITH A BOUND, not a list that grows for as long as the
/// outage lasts. What it gives up on is counted, and those records are still in the segments.
#[test]
fn the_on_disk_catch_up_queue_is_bounded_and_says_what_it_gave_up_on() {
    struct Refuses;
    impl crate::ship::Shipper for Refuses {
        fn ship(
            &mut self,
            _records: &[crate::record::Record],
        ) -> Result<(), crate::ship::ShipError> {
            Err(crate::ship::ShipError::Unavailable("under test".into()))
        }
    }
    let (factory, _switch, _memory) = FaultyFactory::new();
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(Refuses),
        Mode::OnDisk,
        u64::MAX / 2,
    )
    .unwrap();
    let token = durability_token();

    let bound = crate::wal::STORE_BACKLOG_RECORDS;
    let mut written = 0u64;
    while written < bound as u64 + 200 {
        let batch = records(1, written + 1, 100, 8);
        wal.append_batch(&token, busbar_caps::StepName::Meter, &batch)
            .expect("the medium is healthy; only the store is not");
        written += 100;
    }

    assert!(
        wal.owed_to_store().len() <= bound,
        "the catch-up queue is bounded, got {}",
        wal.owed_to_store().len()
    );
    assert!(
        wal.store_debt_dropped() > 0,
        "and it says how much of the catch-up it gave up on"
    );
    assert_eq!(
        wal.read_back().unwrap().records.len() as u64,
        written,
        "nothing was dropped from the medium, only from the offer to the store"
    );
}

#[test]
fn a_store_that_refuses_a_memory_buffered_batch_is_a_durability_loss() {
    // With no data directory the store IS the durability, so its refusal is the loss.
    struct Refuses;
    impl crate::ship::Shipper for Refuses {
        fn ship(
            &mut self,
            _records: &[crate::record::Record],
        ) -> Result<(), crate::ship::ShipError> {
            Err(crate::ship::ShipError::Unavailable("under test".into()))
        }
    }
    let mut wal = Wal::memory_buffered_to(Box::new(Refuses));
    let token = durability_token();
    let batch = records(1, 1, 2, 20);
    wal.append_batch(&token, busbar_caps::StepName::Meter, &batch)
        .expect_err("a store that will not take the batch has not made it durable");
    assert_eq!(wal.owed(), batch.as_slice());
}

/// A store that refuses once and then accepts. It keeps everything it took, so a test can say
/// exactly what reached it and how many times.
#[derive(Default)]
struct RefusesOnce {
    refusals_left: usize,
    taken: std::sync::Arc<std::sync::Mutex<Vec<crate::record::Record>>>,
}

impl RefusesOnce {
    fn new(
        refusals: usize,
    ) -> (
        Self,
        std::sync::Arc<std::sync::Mutex<Vec<crate::record::Record>>>,
    ) {
        let taken = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        (
            RefusesOnce {
                refusals_left: refusals,
                taken: taken.clone(),
            },
            taken,
        )
    }
}

impl crate::ship::Shipper for RefusesOnce {
    fn ship(&mut self, records: &[crate::record::Record]) -> Result<(), crate::ship::ShipError> {
        if self.refusals_left > 0 {
            self.refusals_left -= 1;
            return Err(crate::ship::ShipError::Unavailable("under test".into()));
        }
        self.taken
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .extend_from_slice(records);
        Ok(())
    }
}

/// A refusal on a node with a data directory does not fail the commit — and it does not throw the
/// batch away either.
///
/// The contract on the seam is that an error means the batch is STILL OWED and will be offered
/// again. Discarding the answer honours neither half: the commit is fine, and the store never hears
/// about those records again.
#[test]
fn an_on_disk_batch_the_store_refused_is_offered_again_rather_than_discarded() {
    let (shipper, taken) = RefusesOnce::new(1);
    let (factory, _switch, _memory) = FaultyFactory::new();
    let mut wal =
        Wal::with_parts(Box::new(factory), Box::new(shipper), Mode::OnDisk, CEILING).unwrap();
    let token = durability_token();

    let refused = records(1, 1, 2, 20);
    wal.append_batch(&token, busbar_caps::StepName::Meter, &refused)
        .expect("the bytes are on the medium; the store can catch up later");
    assert!(
        taken.lock().unwrap().is_empty(),
        "the store refused, so it holds nothing yet"
    );
    assert_eq!(
        wal.owed_to_store().len(),
        2,
        "and the log knows it still owes them"
    );

    // The next commit re-offers what is owed, in order, and the store takes the lot.
    let next = records(1, 3, 1, 20);
    wal.append_batch(&token, busbar_caps::StepName::Meter, &next)
        .expect("a commit on a healthy disk");
    let mut expected = refused.clone();
    expected.extend(next.clone());
    assert_eq!(
        *taken.lock().unwrap(),
        expected,
        "each record reaches the store exactly once, oldest first"
    );
    assert!(wal.owed_to_store().is_empty());

    // And the medium holds each record once: a re-offer to the store is not a second write.
    assert_eq!(wal.read_back().unwrap().records, expected);
}

/// A memory-buffered node whose store refused once must not end up with the batch on its own buffer
/// twice.
///
/// The refusal is a durability loss and the batch is retained, so it is offered again on the next
/// append. If the retry appends those records to the segment a second time the chain reads back with
/// a repeated run — which the journal's own verification reports as tampering, from nothing worse
/// than a store that was briefly unavailable.
#[test]
fn a_memory_buffered_retry_after_a_refusal_does_not_write_the_records_twice() {
    use crate::journal::{Entry, Journal, RecordClass};

    let (shipper, taken) = RefusesOnce::new(1);
    let mut journal = Journal::memory_buffered_to(4, Box::new(shipper));
    let token = durability_token();

    let first: Vec<Entry> = (0..2)
        .map(|i| Entry::new(RecordClass::Transaction, vec![i as u8; 8]))
        .collect();
    journal
        .append(&token, busbar_caps::StepName::Meter, &first)
        .expect_err("a store that will not take the batch has not made it durable");
    assert_eq!(journal.buffered(), 2, "the batch is still owed");

    let second = vec![Entry::new(RecordClass::Transaction, vec![9u8; 8])];
    journal
        .append(&token, busbar_caps::StepName::Meter, &second)
        .expect("the store is answering again");
    assert_eq!(journal.buffered(), 0);

    let replayed = journal
        .replay()
        .expect("the buffer reads back")
        .expect("and verifies: a transient refusal is not tampering");
    assert_eq!(
        replayed.iter().map(|r| r.node_seq).collect::<Vec<u64>>(),
        vec![1, 2, 3],
        "each record is on the chain exactly once"
    );
    assert_eq!(
        taken.lock().unwrap().len(),
        3,
        "and the store ends up with all three, each once"
    );
}

#[test]
fn a_store_that_refuses_an_on_disk_batch_does_not_fail_the_commit() {
    // With a data directory the local log is the record and shipping is catch-up work.
    struct Refuses;
    impl crate::ship::Shipper for Refuses {
        fn ship(
            &mut self,
            _records: &[crate::record::Record],
        ) -> Result<(), crate::ship::ShipError> {
            Err(crate::ship::ShipError::Unavailable("under test".into()))
        }
    }
    let (factory, _switch, _memory) = FaultyFactory::new();
    let mut wal =
        Wal::with_parts(Box::new(factory), Box::new(Refuses), Mode::OnDisk, CEILING).unwrap();
    let token = durability_token();
    wal.append_batch(&token, busbar_caps::StepName::Meter, &records(1, 1, 2, 20))
        .expect("the bytes are on the medium; the store can catch up later");
}
