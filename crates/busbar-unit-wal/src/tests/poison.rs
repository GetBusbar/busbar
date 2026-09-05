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
