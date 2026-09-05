// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Kill the node at every durability point there is.
//!
//! There is no interesting subset of the byte offsets a crash can stop at, so none is chosen: the
//! battery writes a run of records, truncates the segment at EVERY offset from zero to the end,
//! recovers, and asserts the recovered records are exactly the longest complete prefix of what was
//! written. A special case in the scan shows up here as the one offset the loop fails on.

use crate::backend::{MemoryFactory, SegmentFactory as _};
use crate::record::{Record, FRAME_BYTES};
use crate::recover::recover_and_truncate;
use crate::segment::Segment;

use super::fixtures::{durability_token, records};

/// A ceiling small enough that the space a segment claims ahead of its writes stays in the
/// kilobytes. The rule under test is about frame boundaries, not about how large a segment can get.
const TEST_CEILING: u64 = 256 * FRAME_BYTES as u64;

/// Write `written` into a fresh memory segment and return exactly the committed bytes — not the
/// claimed-ahead zeros after them, which are not part of what a crash can tear.
fn lay_down(written: &[Record]) -> Vec<u8> {
    let mut factory = MemoryFactory::new();
    let mut wal = crate::wal::Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(crate::ship::NullShipper::new()),
        crate::wal::Mode::OnDisk,
        TEST_CEILING,
    )
    .unwrap();
    let token = durability_token();
    let ack = wal
        .append_batch(&token, busbar_caps::StepName::Meter, written)
        .unwrap();
    drop(wal);
    let backend = factory.open(0).unwrap();
    let mut bytes = vec![0u8; usize::try_from(ack.durable_end).unwrap()];
    let n = backend.read_at(0, &mut bytes).unwrap();
    assert_eq!(n, bytes.len());
    bytes
}

/// Recover from exactly these bytes, cutting whatever does not verify.
fn recover_from(bytes: &[u8]) -> Vec<Record> {
    let shared = crate::backend::SharedBytes::new(std::sync::Mutex::new(bytes.to_vec()));
    let backend = Box::new(crate::backend::MemorySegment::over(shared));
    let mut segment = Segment::open_at(backend, 0, 0, TEST_CEILING).unwrap();
    recover_and_truncate(&mut segment).unwrap().records
}

/// How many whole records survive a cut at `offset`, given the frame count of each record.
fn expected_prefix(written: &[Record], offset: usize) -> usize {
    let mut end = 0usize;
    let mut kept = 0usize;
    for record in written {
        end += record.frame_count() * FRAME_BYTES;
        if end <= offset {
            kept += 1;
        } else {
            break;
        }
    }
    kept
}

#[test]
fn a_cut_at_every_byte_offset_recovers_the_longest_complete_prefix() {
    // Bodies chosen so the run mixes single-frame records with two- and three-frame ones: the rule
    // is about RECORDS, and a run of uniform single-frame records would never exercise it.
    let mut written = Vec::new();
    for (i, body_len) in [0usize, 10, 415, 416, 417, 900, 1000]
        .into_iter()
        .enumerate()
    {
        written.push(Record::new(
            7,
            100 + i as u64,
            vec![(i + 1) as u8; body_len],
        ));
    }
    let bytes = lay_down(&written);
    assert!(!bytes.is_empty());

    for offset in 0..=bytes.len() {
        let recovered = recover_from(&bytes[..offset]);
        let expected = expected_prefix(&written, offset);
        assert_eq!(
            recovered.len(),
            expected,
            "a cut at byte {offset} of {} kept {} records, expected {expected}",
            bytes.len(),
            recovered.len()
        );
        assert_eq!(
            recovered,
            written[..expected].to_vec(),
            "the records recovered after a cut at byte {offset} are not the ones written"
        );
    }
}

#[test]
fn a_cut_mid_record_drops_the_whole_record_not_a_short_one() {
    // One record that needs three frames. A cut after two of them must produce nothing: a truncated
    // body would be a fact the recovery path invented.
    let written = vec![Record::new(1, 1, vec![9u8; 1000])];
    assert_eq!(written[0].frame_count(), 3);
    let bytes = lay_down(&written);
    assert_eq!(bytes.len(), 3 * FRAME_BYTES);

    for offset in 0..3 * FRAME_BYTES {
        assert!(
            recover_from(&bytes[..offset]).is_empty(),
            "a cut at byte {offset} produced a record from an incomplete one"
        );
    }
    assert_eq!(recover_from(&bytes), written);
}

#[test]
fn a_single_flipped_byte_anywhere_stops_the_scan_at_that_record() {
    let written = records(3, 1, 4, 200);
    let bytes = lay_down(&written);
    for offset in 0..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[offset] ^= 0xFF;
        let recovered = recover_from(&damaged);
        let record_index = offset / FRAME_BYTES;
        assert_eq!(
            recovered.len(),
            record_index,
            "flipping byte {offset} should leave the {record_index} records before it"
        );
        assert_eq!(recovered, written[..record_index].to_vec());
    }
}

#[test]
fn recovery_cuts_the_backing_so_the_next_append_lands_on_a_boundary() {
    let written = records(5, 1, 3, 100);
    let bytes = lay_down(&written);
    // Stop one byte into the third record's frame.
    let torn = &bytes[..2 * FRAME_BYTES + 1];
    let shared = crate::backend::SharedBytes::new(std::sync::Mutex::new(torn.to_vec()));
    let backend = Box::new(crate::backend::MemorySegment::over(shared.clone()));
    let mut segment = Segment::open_at(backend, 0, 0, TEST_CEILING).unwrap();
    let recovered = recover_and_truncate(&mut segment).unwrap();

    assert_eq!(recovered.records.len(), 2);
    assert!(recovered.was_torn());
    assert_eq!(recovered.durable_end, 2 * FRAME_BYTES as u64);
    assert_eq!(recovered.discarded_bytes, 1);
    assert_eq!(shared.lock().unwrap().len(), 2 * FRAME_BYTES);
    assert_eq!(segment.write_offset(), 2 * FRAME_BYTES as u64);
}

#[test]
fn a_restart_replays_to_the_recovered_head_and_appends_after_it() {
    let mut factory = MemoryFactory::new();
    let token = durability_token();
    let first = records(1, 1, 3, 50);
    {
        let mut wal = crate::wal::Wal::with_parts(
            Box::new(factory.clone()),
            Box::new(crate::ship::NullShipper::new()),
            crate::wal::Mode::OnDisk,
            TEST_CEILING,
        )
        .unwrap();
        wal.append_batch(&token, busbar_caps::StepName::Meter, &first)
            .unwrap();
    }
    // Tear the tail: lose the last frame and one byte of the one before it.
    {
        let shared = factory.segment_bytes(0);
        let mut held = shared.lock().unwrap();
        let keep = 2 * FRAME_BYTES - 1;
        held.truncate(keep);
    }
    let mut wal = crate::wal::Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(crate::ship::NullShipper::new()),
        crate::wal::Mode::OnDisk,
        TEST_CEILING,
    )
    .unwrap();
    assert_eq!(wal.recovered(), &first[..1]);

    let second = records(1, 2, 2, 50);
    wal.append_batch(&token, busbar_caps::StepName::Meter, &second)
        .unwrap();
    let back = wal.read_back().unwrap();
    assert_eq!(
        back.records,
        [first[0].clone(), second[0].clone(), second[1].clone()]
    );
    let _ = factory.open(0);
}
