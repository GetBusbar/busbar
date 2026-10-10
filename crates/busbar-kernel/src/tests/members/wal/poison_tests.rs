// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What happens when the medium says no.
//!
//! A write error and a full volume are the same event to this crate: a durable write that was
//! observed to fail. The segment is closed, the caller is handed a durability loss, and the batch
//! that failed goes to a fresh segment with the batch after it — in that order, so the log reads
//! back in the order records were written.

use busbar_kernel_wal::record::FRAME_BYTES;
use busbar_kernel_wal::wal::{Mode, Wal};

use super::fixtures::{durability_token, records, Fault, FaultyFactory};

const CEILING: u64 = 256 * FRAME_BYTES as u64;

fn wal_with_faults() -> (
    Wal,
    super::fixtures::FaultSwitch,
    busbar_kernel_wal::backend::MemoryFactory,
) {
    let (factory, switch, memory) = FaultyFactory::new();
    let wal = Wal::with_parts(
        Box::new(factory),
        Box::new(busbar_kernel_wal::ship::NullShipper::new()),
        Mode::OnDisk,
        CEILING,
        super::fixtures::wall_ms,
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
            .append_batch(&token, busbar_contract::caps::StepName::Meter, &batch)
            .expect_err("a failed sync must be reported as a lost durable write");
        assert_eq!(lost.step(), busbar_contract::caps::StepName::Meter);
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
    wal.append_batch(&token, busbar_contract::caps::StepName::Admit, &batch)
        .expect_err("a failed write is a lost durable write");
    assert!(wal.is_poisoned());
}

#[test]
fn batches_n_and_n_plus_one_are_re_appended_to_a_fresh_segment_in_order() {
    let (mut wal, switch, _memory) = wal_with_faults();
    let token = durability_token();

    // Batch n-1 lands.
    let earlier = records(1, 1, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &earlier)
        .unwrap();
    let first_segment = wal.segments_used();

    // Batch n is lost at the sync point.
    switch.arm(Fault::SyncEio);
    let n = records(1, 3, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &n)
        .expect_err("the sync was armed to fail");
    assert!(wal.is_poisoned());

    // Batch n+1 arrives; the log rolls, writes n, then n+1.
    let n_plus_one = records(1, 5, 2, 40);
    let ack = wal
        .append_batch(&token, busbar_contract::caps::StepName::Meter, &n_plus_one)
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

/// The batch a poisoned segment lost can sit WHOLE in two segments: its bytes reached the poisoned
/// one before the sync failed, and the roll wrote it again on the fresh one. Reading the whole log
/// back hands it over once, in the place it was first written, with what came before the poison.
#[test]
fn reading_back_across_a_poison_roll_returns_each_record_once_oldest_first() {
    let (mut wal, switch, memory) = wal_with_faults();
    let token = durability_token();
    // The poisoned segment stays resident, the way a data directory keeps its file.
    let _segment_zero = memory.segment_bytes(0);

    let earlier = records(1, 1, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &earlier)
        .unwrap();
    switch.arm(Fault::SyncEio);
    let n = records(1, 3, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &n)
        .expect_err("the sync was armed to fail");
    let n_plus_one = records(1, 5, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &n_plus_one)
        .expect("the fresh segment takes both batches");
    assert!(wal.segments_used() > 1, "the log rolled");

    let mut expected = earlier;
    expected.extend(n);
    expected.extend(n_plus_one);
    assert_eq!(
        wal.read_back().unwrap().records,
        expected,
        "the whole log, each record once, oldest first"
    );
}

#[test]
fn re_appending_a_batch_that_is_already_in_the_log_writes_nothing_twice() {
    let (mut wal, _switch, _memory) = wal_with_faults();
    let token = durability_token();
    let batch = records(2, 1, 3, 40);

    let first = wal
        .append_batch(&token, busbar_contract::caps::StepName::Meter, &batch)
        .unwrap();
    assert_eq!(first.appended, 3);
    assert_eq!(first.already_present, 0);

    let again = wal
        .append_batch(&token, busbar_contract::caps::StepName::Meter, &batch)
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
        .append_batch(&token, busbar_contract::caps::StepName::Meter, &overlapping)
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
        busbar_contract::caps::StepName::Meter,
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
    let (mut wal, switch, memory) = wal_with_faults();
    let token = durability_token();
    // A batch that lands first, so the poisoned segment holds bytes once the failed batch is cut
    // off it: the region the claim is about.
    wal.append_batch(
        &token,
        busbar_contract::caps::StepName::Meter,
        &records(1, 1, 1, 10),
    )
    .unwrap();
    switch.arm(Fault::SyncEio);
    wal.append_batch(
        &token,
        busbar_contract::caps::StepName::Meter,
        &records(1, 2, 1, 10),
    )
    .expect_err("armed");

    // The poisoned segment's own bytes, held by a strong reference so they survive the roll that
    // follows. A fresh segment NUMBER is not the claim: the claim is that the segment that lost a
    // sync receives no further writes, and only the bytes can say that. Reading them back through
    // `wal.read_back()` afterwards would read the NEW segment, which is why the factory is asked.
    let poisoned_bytes = memory.segment_bytes(0);
    let before = poisoned_bytes.lock().unwrap().clone();
    assert!(
        !before.is_empty(),
        "the fixture is only interesting if the poisoned segment holds bytes"
    );

    // The switch is one-shot, so the disk is healthy again — but the segment stays closed and the
    // log moves on rather than writing more bytes into a segment that lost a sync.
    let ack = wal
        .append_batch(
            &token,
            busbar_contract::caps::StepName::Meter,
            &records(1, 3, 1, 10),
        )
        .unwrap();
    assert!(ack.segment > 0, "the write went to a fresh segment");
    assert_eq!(
        *poisoned_bytes.lock().unwrap(),
        before,
        "the poisoned segment took another write"
    );
}

/// A log over memory that keeps every segment, as a data directory keeps its files, so a second log
/// opened over the same memory is a restart.
fn restartable_wal_with_faults() -> (
    Wal,
    super::fixtures::FaultSwitch,
    busbar_kernel_wal::backend::MemoryFactory,
) {
    let (factory, switch, memory) = FaultyFactory::retaining();
    let wal = Wal::with_parts(
        Box::new(factory),
        Box::new(busbar_kernel_wal::ship::NullShipper::new()),
        Mode::OnDisk,
        CEILING,
        super::fixtures::wall_ms,
    )
    .unwrap();
    (wal, switch, memory)
}

fn restart(memory: &busbar_kernel_wal::backend::MemoryFactory) -> Wal {
    Wal::with_parts(
        Box::new(memory.clone()),
        Box::new(busbar_kernel_wal::ship::NullShipper::new()),
        Mode::OnDisk,
        CEILING,
        super::fixtures::wall_ms,
    )
    .unwrap()
}

/// **A BATCH THE CALLER WAS TOLD WAS LOST DOES NOT COME BACK AT A RESTART** (Q128 kernel-wal 3).
///
/// After a write error the failed batch's pages can still be readable — here they are, in the
/// memory the failing disk wrote them to — without ever having reached the medium. A restart that
/// read them would put on the book records the caller was told were lost, and chain the next ones
/// onto records that are on no disk. So the failed batch is cut off its segment when it is lost.
/// RED before the fix: the poison was an in-memory flag, the bytes stayed, and the restart
/// recovered the lost batch as the tail of the log.
#[test]
fn a_batch_reported_lost_does_not_come_back_at_a_restart() {
    let (mut wal, switch, memory) = restartable_wal_with_faults();
    let token = durability_token();

    let landed = records(1, 1, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &landed)
        .unwrap();
    switch.arm(Fault::SyncEio);
    let lost = records(1, 3, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &lost)
        .expect_err("the sync was armed to fail");
    drop(wal);

    let restarted = restart(&memory);
    assert_eq!(
        restarted.recovered(),
        landed.as_slice(),
        "the restart's tail is what was acknowledged, not the batch reported lost"
    );
    assert!(
        !restarted.holds(1, 3),
        "the lost batch's identities are free"
    );
}

/// **A RESTART NEVER APPENDS TO THE SEGMENT THAT LOST A SYNC** (Q128 kernel-wal 3).
///
/// Poison was a flag in the process that saw the sync fail, and the roll away from the poisoned
/// segment waited for the next append; a restart before it opened the same segment unpoisoned and
/// appended to it. Now the next segment is opened the moment the sync fails, and a restart appends
/// to the newest segment even when its tail is read from the one below. RED before the fix: the
/// restart appended into segment zero.
#[test]
fn a_restart_never_appends_to_the_segment_that_lost_a_sync() {
    let (mut wal, switch, memory) = restartable_wal_with_faults();
    let token = durability_token();
    let segment_zero = memory.segment_bytes(0);

    let landed = records(1, 1, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &landed)
        .unwrap();
    switch.arm(Fault::SyncEio);
    wal.append_batch(
        &token,
        busbar_contract::caps::StepName::Meter,
        &records(1, 3, 2, 40),
    )
    .expect_err("the sync was armed to fail");
    drop(wal);

    let mut restarted = restart(&memory);
    let before = segment_zero.lock().unwrap().clone();
    let after_restart = records(1, 3, 2, 40);
    let ack = restarted
        .append_batch(
            &token,
            busbar_contract::caps::StepName::Meter,
            &after_restart,
        )
        .expect("a healthy disk takes the append");
    assert_eq!(ack.segment, 1, "the append went to the segment after it");
    assert_eq!(
        *segment_zero.lock().unwrap(),
        before,
        "the segment that lost a sync took a write after the restart"
    );
    let mut expected = landed;
    expected.extend(after_restart);
    assert_eq!(restarted.read_back().unwrap().records, expected);
}

/// **A ROLL THAT CANNOT OPEN THE NEXT SEGMENT KEEPS THE BATCH IT WAS HANDED** (Q128 kernel-wal 4).
///
/// The journal chains a batch before the log takes it. When the segment that lost a sync cannot be
/// replaced — a full volume, no descriptors left — every other failure arm retains the batch for
/// the retry; this one returned before it, so the records were on no medium and in no queue, and
/// once the disk recovered the next record linked onto a head that was never written. RED before
/// the fix: `owed()` held only the earlier lost batch.
#[test]
fn a_roll_that_cannot_open_the_next_segment_keeps_the_batch_it_was_handed() {
    let (mut wal, switch, _memory) = wal_with_faults();
    let token = durability_token();

    // The volume is full: the sync fails, and no segment can be opened to move to.
    switch.refuse_new_segments(true);
    switch.arm(Fault::SyncEio);
    let n = records(1, 1, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &n)
        .expect_err("the sync was armed to fail");

    let n_plus_one = records(1, 3, 2, 40);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &n_plus_one)
        .expect_err("no segment can be opened to roll to");
    let mut owed = n.clone();
    owed.extend(n_plus_one.clone());
    assert_eq!(
        wal.owed(),
        owed.as_slice(),
        "both batches are retained, in order"
    );

    switch.refuse_new_segments(false);
    let n_plus_two = records(1, 5, 1, 40);
    let ack = wal
        .append_batch(&token, busbar_contract::caps::StepName::Meter, &n_plus_two)
        .expect("the disk has room again");
    assert_eq!(ack.appended, 5, "all three batches, each once");
    assert!(wal.owed().is_empty());
    owed.extend(n_plus_two);
    assert_eq!(wal.read_back().unwrap().records, owed);
}

/// The same, at the journal: a failed roll leaves no hole in the chain. RED before the fix: the
/// record sealed into the refused batch was never written, and the chain read back broke at the
/// record after it.
#[test]
fn a_failed_roll_leaves_no_hole_in_the_chain() {
    use busbar_kernel_wal::journal::{Entry, Journal, RecordClass};

    let (wal, switch, memory) = wal_with_faults();
    // The first segment stays resident, the way a data directory keeps its file, so the chain read
    // back is the whole log.
    let _segment_zero = memory.segment_bytes(0);
    let mut journal = Journal::over(wal, 4);
    let token = durability_token();
    let entry = |tag: u8| [Entry::new(RecordClass::Transaction, vec![tag; 8])];

    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &entry(1))
        .expect("a healthy disk");
    switch.refuse_new_segments(true);
    switch.arm(Fault::SyncEio);
    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &entry(2))
        .expect_err("the sync was armed to fail");
    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &entry(3))
        .expect_err("no segment can be opened to roll to");
    switch.refuse_new_segments(false);
    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &entry(4))
        .expect("the disk has room again");

    let chain = journal
        .replay()
        .expect("the log reads back")
        .expect("and the chain verifies: nothing sealed was dropped");
    assert_eq!(
        chain.iter().map(|r| r.node_seq).collect::<Vec<u64>>(),
        vec![1, 2, 3, 4]
    );
}

/// A journal that RETAINS at its bound keeps a failed roll's batch past that bound: the batch a
/// failed roll keeps and the records a full lane keeps are the one retained batch, and a retaining
/// journal never forgets from it to make room (H3's `retaining_at_bound`, Q128 kernel-wal 4).
#[test]
fn a_retaining_journal_keeps_a_failed_rolls_batch_past_its_bound() {
    use busbar_kernel_wal::journal::{Entry, Journal, RecordClass};

    let (wal, switch, memory) = wal_with_faults();
    let _segment_zero = memory.segment_bytes(0);
    let mut journal = Journal::over(wal, 4)
        .with_capacity(1)
        .retaining_at_bound();
    let token = durability_token();
    let entry = |tag: u8| [Entry::new(RecordClass::Transaction, vec![tag; 8])];

    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &entry(1))
        .expect("a healthy disk");
    switch.refuse_new_segments(true);
    switch.arm(Fault::SyncEio);
    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &entry(2))
        .expect_err("the sync was armed to fail");
    let ack = journal.append(&token, busbar_contract::caps::StepName::Meter, &entry(3));
    assert!(ack.is_err(), "no segment can be opened to roll to");
    assert!(journal.at_bound(), "two records owed against a bound of one");
    assert_eq!(journal.buffered(), 2, "both batches are retained");
    assert_eq!(journal.dropped_total(), 0, "nothing was forgotten");
    assert!(journal.overflows().is_empty(), "no break was sealed");

    switch.refuse_new_segments(false);
    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &entry(4))
        .expect("the disk has room again");
    assert_eq!(journal.buffered(), 0);
    let chain = journal
        .replay()
        .expect("the log reads back")
        .expect("and the chain verifies");
    assert_eq!(
        chain.iter().map(|r| r.node_seq).collect::<Vec<u64>>(),
        vec![1, 2, 3, 4]
    );
}

/// What the store is owed on disk is a QUEUE WITH A BOUND, not a list that grows for as long as the
/// outage lasts. What it gives up on is counted, and those records are still in the segments.
#[test]
fn the_on_disk_catch_up_queue_is_bounded_and_says_what_it_gave_up_on() {
    struct Refuses;
    impl busbar_kernel_wal::ship::Shipper<busbar_kernel_wal::record::Record> for Refuses {
        fn ship(
            &mut self,
            _records: &[busbar_kernel_wal::record::Record],
        ) -> Result<(), busbar_kernel_wal::ship::ShipError> {
            Err(busbar_kernel_wal::ship::ShipError::Unavailable(
                "under test".into(),
            ))
        }
    }
    let (factory, _switch, _memory) = FaultyFactory::new();
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(Refuses),
        Mode::OnDisk,
        u64::MAX / 2,
        super::fixtures::wall_ms,
    )
    .unwrap();
    let token = durability_token();

    let bound = busbar_kernel_wal::wal::STORE_BACKLOG_RECORDS;
    let mut written = 0u64;
    while written < bound as u64 + 200 {
        let batch = records(1, written + 1, 100, 8);
        wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &batch)
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
    impl busbar_kernel_wal::ship::Shipper<busbar_kernel_wal::record::Record> for Refuses {
        fn ship(
            &mut self,
            _records: &[busbar_kernel_wal::record::Record],
        ) -> Result<(), busbar_kernel_wal::ship::ShipError> {
            Err(busbar_kernel_wal::ship::ShipError::Unavailable(
                "under test".into(),
            ))
        }
    }
    let mut wal = Wal::memory_buffered_to(Box::new(Refuses), super::fixtures::wall_ms);
    let token = durability_token();
    let batch = records(1, 1, 2, 20);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &batch)
        .expect_err("a store that will not take the batch has not made it durable");
    assert_eq!(wal.owed(), batch.as_slice());
}

/// A store that refuses once and then accepts. It keeps everything it took, so a test can say
/// exactly what reached it and how many times.
#[derive(Default)]
struct RefusesOnce {
    refusals_left: usize,
    taken: std::sync::Arc<std::sync::Mutex<Vec<busbar_kernel_wal::record::Record>>>,
}

impl RefusesOnce {
    fn new(
        refusals: usize,
    ) -> (
        Self,
        std::sync::Arc<std::sync::Mutex<Vec<busbar_kernel_wal::record::Record>>>,
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

impl busbar_kernel_wal::ship::Shipper<busbar_kernel_wal::record::Record> for RefusesOnce {
    fn ship(
        &mut self,
        records: &[busbar_kernel_wal::record::Record],
    ) -> Result<(), busbar_kernel_wal::ship::ShipError> {
        if self.refusals_left > 0 {
            self.refusals_left -= 1;
            return Err(busbar_kernel_wal::ship::ShipError::Unavailable(
                "under test".into(),
            ));
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
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(shipper),
        Mode::OnDisk,
        CEILING,
        super::fixtures::wall_ms,
    )
    .unwrap();
    let token = durability_token();

    let refused = records(1, 1, 2, 20);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &refused)
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
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &next)
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
    use busbar_kernel_wal::journal::{Entry, Journal, RecordClass};

    let (shipper, taken) = RefusesOnce::new(1);
    let mut journal = Journal::memory_buffered_to(4, Box::new(shipper), super::fixtures::wall_ms);
    let token = durability_token();

    let first: Vec<Entry> = (0..2)
        .map(|i| Entry::new(RecordClass::Transaction, vec![i as u8; 8]))
        .collect();
    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &first)
        .expect_err("a store that will not take the batch has not made it durable");
    assert_eq!(journal.buffered(), 2, "the batch is still owed");

    let second = vec![Entry::new(RecordClass::Transaction, vec![9u8; 8])];
    journal
        .append(&token, busbar_contract::caps::StepName::Meter, &second)
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
    impl busbar_kernel_wal::ship::Shipper<busbar_kernel_wal::record::Record> for Refuses {
        fn ship(
            &mut self,
            _records: &[busbar_kernel_wal::record::Record],
        ) -> Result<(), busbar_kernel_wal::ship::ShipError> {
            Err(busbar_kernel_wal::ship::ShipError::Unavailable(
                "under test".into(),
            ))
        }
    }
    let (factory, _switch, _memory) = FaultyFactory::new();
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(Refuses),
        Mode::OnDisk,
        CEILING,
        super::fixtures::wall_ms,
    )
    .unwrap();
    let token = durability_token();
    wal.append_batch(
        &token,
        busbar_contract::caps::StepName::Meter,
        &records(1, 1, 2, 20),
    )
    .expect("the bytes are on the medium; the store can catch up later");
}
