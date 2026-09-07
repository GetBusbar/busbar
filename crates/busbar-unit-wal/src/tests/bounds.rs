// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the log is allowed to keep in memory while it stays correct.
//!
//! A bound is worth nothing until a test runs past it and reads back what the node decided to hold
//! on to. A node that answers correctly for a week and is killed by the allocator on the eighth day
//! answered incorrectly.

use busbar_caps::StepName;

use crate::backend::MemoryFactory;
use crate::record::FRAME_BYTES;
use crate::ship::NullShipper;
use crate::wal::{Mode, Wal};

use super::fixtures::{durability_token, records, FaultyFactory};

/// Small enough that a run of a few thousand records rolls the log many times over.
const CEILING: u64 = 256 * FRAME_BYTES as u64;

/// The idempotence check is a bound, not a ledger of everything the process ever wrote.
///
/// The identity space is `(node, node_seq)` and a writer numbers its own records upward, so what the
/// log has to remember is one mark per node — not one entry per record. A set that grew per record
/// would cost a running node roughly a gigabyte a day at a very ordinary rate, on a product that
/// otherwise measures its footprint in megabytes.
#[test]
fn the_idempotence_check_costs_one_mark_per_node_not_one_entry_per_record() {
    let (factory, _switch, _memory) = FaultyFactory::new();
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        CEILING,
    )
    .unwrap();
    let token = durability_token();

    let mut seq = 1u64;
    for _ in 0..200 {
        let batch = records(1, seq, 16, 300);
        seq += 16;
        wal.append_batch(&token, StepName::Meter, &batch)
            .expect("a healthy disk takes every batch");
    }

    assert!(
        wal.segments_used() > 1,
        "the run has to cross a roll for this to be the bound it claims to be"
    );
    assert!(
        wal.tracked_identities() <= 64,
        "3200 records must not cost 3200 remembered identities, got {}",
        wal.tracked_identities()
    );
}

/// A node with no data directory holds ONE segment's bytes, however many it has rolled through.
///
/// The memory backing is the whole of such a node's storage, so a factory that kept a reference to
/// every segment it ever opened would turn a long-running node into a process whose footprint grows
/// by a segment's ceiling on every roll — sixty-four megabytes at a time in production, and never
/// released, because nothing above it ever asks for those bytes again. The record bound above governs
/// what the log will HOLD for a store; this one governs what it leaves behind after it has moved on.
#[test]
fn a_memory_backed_log_keeps_only_the_segment_it_is_writing_to() {
    let factory = MemoryFactory::new();
    let mut wal = Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(NullShipper::new()),
        Mode::MemoryBuffered,
        CEILING,
    )
    .unwrap();
    let token = durability_token();

    let mut seq = 1u64;
    for _ in 0..200 {
        let batch = records(1, seq, 16, 300);
        seq += 16;
        wal.append_batch(&token, StepName::Meter, &batch)
            .expect("a memory backing takes every batch");
    }

    assert!(
        wal.segments_used() > 4,
        "the run has to roll several times for this to be the bound it claims to be, got {}",
        wal.segments_used()
    );
    assert_eq!(
        factory.segment_count(),
        1,
        "only the segment being written to is still resident, after {} rolls",
        wal.segments_used() - 1
    );

    // And the one that is resident is the one the log is actually writing to: a bound that held by
    // dropping the LIVE segment would pass the count above and lose the log.
    let ack = wal
        .append_batch(&token, StepName::Meter, &records(2, 1, 1, 300))
        .expect("the live segment still takes a batch");
    assert_eq!(ack.appended, 1);
    assert_eq!(factory.segment_count(), 1);
}

/// Bounding the check must not weaken it: an identity the log already holds is still passed over,
/// including one written into a segment the log has long since rolled past.
#[test]
fn a_bounded_idempotence_check_still_suppresses_a_re_offer_from_a_rolled_segment() {
    let (factory, _switch, _memory) = FaultyFactory::new();
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        CEILING,
    )
    .unwrap();
    let token = durability_token();

    let first = records(1, 1, 4, 300);
    wal.append_batch(&token, StepName::Meter, &first)
        .expect("the first batch lands");

    let mut seq = 5u64;
    for _ in 0..200 {
        let batch = records(1, seq, 16, 300);
        seq += 16;
        wal.append_batch(&token, StepName::Meter, &batch)
            .expect("a healthy disk takes every batch");
    }
    assert!(wal.segments_used() > 1, "the first batch is behind a roll");

    let again = wal
        .append_batch(&token, StepName::Meter, &first)
        .expect("a re-offer is not an error");
    assert_eq!(
        again.appended, 0,
        "nothing is written twice, however many segments ago it went in"
    );
    assert_eq!(again.already_present, 4);
    assert!(wal.holds(1, 1), "the log still says it holds the identity");
}

/// A NUMBER BELOW THE MARK THAT WAS NEVER WRITTEN IS ABSENT, AND HAS TO READ AS ABSENT.
///
/// The idempotence check is a high-water mark plus a window of the holes below it, and the mark on
/// its own gets exactly one thing wrong: a number under it that nothing ever wrote. Without the
/// window that number reads as present, so the record offered under it is passed over and the ack
/// says `appended: 0` — a record accepted, reported as a duplicate, and on no medium anywhere.
///
/// The window's other end is already covered (a hole that has fallen out of it reads as present, on
/// purpose, because passing over a record is the safe direction). What was not covered is the end
/// that matters more: while the hole is still IN the window, the log has to admit it does not hold
/// it, and has to take the record.
#[test]
fn a_hole_still_inside_the_window_reads_as_absent_and_the_record_is_taken() {
    let (factory, _switch, _memory) = FaultyFactory::new();
    let mut wal = Wal::with_parts(
        Box::new(factory),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        CEILING,
    )
    .unwrap();
    let token = durability_token();

    // A writer that skips: the log's mark for node 1 jumps to 5 without 1..=4 ever being written.
    wal.append_batch(&token, StepName::Meter, &records(1, 5, 1, 40))
        .expect("the first record lands");
    assert!(wal.holds(1, 5), "what was written is held");
    assert!(
        !wal.holds(1, 3),
        "a number below the mark that nothing wrote is not held, and the mark alone cannot say so"
    );

    // And the log has to prove it by taking the record rather than passing it over as a duplicate.
    let ack = wal
        .append_batch(&token, StepName::Meter, &records(1, 3, 1, 40))
        .expect("the skipped number is still free");
    assert_eq!(
        ack.appended, 1,
        "a record under a number nothing wrote was passed over as a duplicate and never landed"
    );
    assert_eq!(ack.already_present, 0);
    assert!(wal.holds(1, 3), "and now it is held");
}
