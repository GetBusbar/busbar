// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel_wal::backend::{MemoryFactory, SegmentFactory as _};
use busbar_kernel_wal::record::{Record, FRAME_BYTES};
use busbar_kernel_wal::recover::recover_and_truncate;
use busbar_kernel_wal::segment::Segment;

use super::fixtures::{durability_token, records};

const TEST_CEILING: u64 = 256 * FRAME_BYTES as u64;

fn lay_down(written: &[Record]) -> Vec<u8> {
    let mut factory = MemoryFactory::retaining();
    let mut wal = busbar_kernel_wal::wal::Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(busbar_kernel_wal::ship::NullShipper::new()),
        busbar_kernel_wal::wal::Mode::OnDisk,
        TEST_CEILING,
        super::fixtures::wall_ms,
    )
    .unwrap();
    let token = durability_token();
    let ack = wal
        .append_batch(&token, busbar_contract::caps::StepName::Meter, written)
        .unwrap();
    drop(wal);
    let backend = factory.open(0).unwrap();
    let mut bytes = vec![0u8; usize::try_from(ack.durable_end).unwrap()];
    let n = backend.read_at(0, &mut bytes).unwrap();
    assert_eq!(n, bytes.len());
    bytes
}

fn recover_from(bytes: &[u8]) -> Vec<Record> {
    let shared =
        busbar_kernel_wal::backend::SharedBytes::new(std::sync::Mutex::new(bytes.to_vec()));
    let backend = Box::new(busbar_kernel_wal::backend::MemorySegment::over(shared));
    let mut segment = Segment::open_at(backend, 0, 0, TEST_CEILING).unwrap();
    recover_and_truncate(
        &mut segment,
        &mut MemoryFactory::new(),
        super::fixtures::wall_ms,
    )
    .unwrap()
    .records
}

fn lay_down_commits(commits: &[Vec<Record>]) -> Vec<u8> {
    let mut factory = MemoryFactory::retaining();
    let mut wal = busbar_kernel_wal::wal::Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(busbar_kernel_wal::ship::NullShipper::new()),
        busbar_kernel_wal::wal::Mode::OnDisk,
        TEST_CEILING,
        super::fixtures::wall_ms,
    )
    .unwrap();
    let token = durability_token();
    let mut end = 0;
    for commit in commits {
        end = wal
            .append_batch(&token, busbar_contract::caps::StepName::Meter, commit)
            .unwrap()
            .durable_end;
    }
    drop(wal);
    let backend = factory.open(0).unwrap();
    let mut bytes = vec![0u8; usize::try_from(end).unwrap()];
    let n = backend.read_at(0, &mut bytes).unwrap();
    assert_eq!(n, bytes.len());
    bytes
}

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
fn a_zero_padded_tear_at_every_byte_offset_is_torn_never_corrupt() {
    let mut first = Vec::new();
    let mut second = Vec::new();
    for (i, body_len) in [0usize, 10, 415, 416, 417, 900, 1000]
        .into_iter()
        .enumerate()
    {
        let record = Record::new(7, 100 + i as u64, vec![(i + 1) as u8; body_len]);
        if i < 3 {
            first.push(record);
        } else {
            second.push(record);
        }
    }
    let bytes = lay_down_commits(&[first.clone(), second.clone()]);
    let mut written = first;
    written.extend(second);

    let claimed = bytes.len() + 4 * FRAME_BYTES;

    for stop in 0..=bytes.len() {
        let mut torn = bytes[..stop].to_vec();
        torn.resize(claimed, 0);
        let shared = busbar_kernel_wal::backend::SharedBytes::new(std::sync::Mutex::new(torn));
        let backend = Box::new(busbar_kernel_wal::backend::MemorySegment::over(shared));
        let mut segment = Segment::open_at(backend, 0, 0, TEST_CEILING).unwrap();
        let mut sink = MemoryFactory::new();
        let recovered =
            recover_and_truncate(&mut segment, &mut sink, super::fixtures::wall_ms).unwrap();
        let expected = expected_prefix(&written, stop);
        assert!(
            !recovered.was_corrupt(),
            "a write that stopped at byte {stop} of {} read as corruption: {:?}",
            bytes.len(),
            recovered.verdict
        );
        assert!(
            recovered.quarantined.is_empty() && sink.quarantined().is_empty(),
            "a write that stopped at byte {stop} was quarantined"
        );
        assert_eq!(
            recovered.records,
            written[..expected].to_vec(),
            "the records recovered after a stop at byte {stop} are not the longest complete prefix"
        );
    }
}

#[test]
fn a_cut_mid_record_drops_the_whole_record_not_a_short_one() {
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
fn a_single_flipped_byte_anywhere_sets_aside_that_record_and_no_other() {
    let written = records(3, 1, 4, 200);
    let bytes = lay_down(&written);
    for offset in 0..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[offset] ^= 0xFF;
        let recovered = recover_from(&damaged);
        let record_index = offset / FRAME_BYTES;
        let mut kept = written.clone();
        kept.remove(record_index);
        assert_eq!(
            recovered, kept,
            "flipping byte {offset} should set aside record {record_index} alone"
        );
    }
}

#[test]
fn recovery_cuts_the_backing_so_the_next_append_lands_on_a_boundary() {
    let written = records(5, 1, 3, 100);
    let bytes = lay_down(&written);

    let torn = &bytes[..2 * FRAME_BYTES + 1];
    let shared = busbar_kernel_wal::backend::SharedBytes::new(std::sync::Mutex::new(torn.to_vec()));
    let backend = Box::new(busbar_kernel_wal::backend::MemorySegment::over(
        shared.clone(),
    ));
    let mut segment = Segment::open_at(backend, 0, 0, TEST_CEILING).unwrap();
    let mut sink = MemoryFactory::new();
    let recovered =
        recover_and_truncate(&mut segment, &mut sink, super::fixtures::wall_ms).unwrap();

    assert_eq!(recovered.records.len(), 2);
    assert!(recovered.was_torn());
    assert_eq!(recovered.durable_end, 2 * FRAME_BYTES as u64);
    assert_eq!(recovered.discarded_bytes, 1);
    assert_eq!(shared.lock().unwrap().len(), 2 * FRAME_BYTES);
    assert_eq!(segment.write_offset(), 2 * FRAME_BYTES as u64);

    assert!(recovered.quarantined.is_empty());
    assert!(sink.quarantined().is_empty());
}

#[test]
fn a_restart_replays_to_the_recovered_head_and_appends_after_it() {
    let mut factory = MemoryFactory::retaining();
    let token = durability_token();
    let first = records(1, 1, 3, 50);
    {
        let mut wal = busbar_kernel_wal::wal::Wal::with_parts(
            Box::new(factory.clone()),
            Box::new(busbar_kernel_wal::ship::NullShipper::new()),
            busbar_kernel_wal::wal::Mode::OnDisk,
            TEST_CEILING,
            super::fixtures::wall_ms,
        )
        .unwrap();
        wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &first)
            .unwrap();
    }

    {
        let shared = factory.segment_bytes(0);
        let mut held = shared.lock().unwrap();
        let keep = 2 * FRAME_BYTES - 1;
        held.truncate(keep);
    }
    let mut wal = busbar_kernel_wal::wal::Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(busbar_kernel_wal::ship::NullShipper::new()),
        busbar_kernel_wal::wal::Mode::OnDisk,
        TEST_CEILING,
        super::fixtures::wall_ms,
    )
    .unwrap();
    assert_eq!(wal.recovered(), &first[..1]);

    let second = records(1, 2, 2, 50);
    wal.append_batch(&token, busbar_contract::caps::StepName::Meter, &second)
        .unwrap();
    let back = wal.read_back().unwrap();
    assert_eq!(
        back.records,
        [first[0].clone(), second[0].clone(), second[1].clone()]
    );
    let _ = factory.open(0);
}
