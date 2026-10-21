// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A frame whose header does not check names its record UNVERIFIED, and an unverified number must
//! not move the node's numbering past what the set-aside bytes could have held.
//!
//! Recovery marks every identity in a quarantined remainder as taken, so a number a store may
//! already hold is never handed out again. A whole frame whose header was altered is read as its
//! bytes now stand, and the altered byte may be the sequence number itself: taken at its word, one
//! damaged frame moves the node's mark to any value at all. At the top of the range the journal's
//! next number saturates, every record after it is sealed under the same identity the log already
//! holds, and the log passes each one over as a duplicate while the append answers `Ok`.

use crate::backend::MemoryFactory;
use crate::journal::Journal;
use crate::record::{Record, FRAME_BYTES};
use crate::ship::NullShipper;
use crate::wal::{Mode, Wal};

/// The node the damaged log was written by.
const NODE: u64 = 3;

/// Lay four single-frame records of `NODE`, numbered 1 to 4, into segment 0 of `factory` as one
/// group commit puts them down, then overwrite the last frame's sequence number with `seq` and
/// leave its header check and digest as they were: a whole frame altered after it was written.
fn lay_down_with_altered_seq(factory: &MemoryFactory, seq: u64) {
    let mut bytes = Vec::new();
    for n in 1..=4u64 {
        for frame in Record::new(NODE, n, vec![n as u8; 200]).encode_in_commit(n == 1) {
            bytes.extend_from_slice(&frame);
        }
    }
    let last = 3 * FRAME_BYTES;
    bytes[last + 16..last + 24].copy_from_slice(&seq.to_le_bytes());
    *factory
        .segment_bytes(0)
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = bytes;
}

fn reopen(factory: &MemoryFactory) -> Wal {
    Wal::with_parts(
        Box::new(factory.clone()),
        Box::new(NullShipper::new()),
        Mode::OnDisk,
        64 * FRAME_BYTES as u64,
        crate::tests::fixtures::wall_ms,
    )
    .expect("a memory segment opens")
}

/// RED before the fix: the altered number became the node's mark, so the next free number was
/// `u64::MAX` and the journal over the log numbered every record after it there.
#[test]
fn an_altered_sequence_number_in_a_set_aside_frame_does_not_move_the_numbering() {
    let factory = MemoryFactory::retaining();
    lay_down_with_altered_seq(&factory, u64::MAX - 1);
    let wal = reopen(&factory);

    assert_eq!(wal.recovered().len(), 3, "the verified prefix is kept");
    assert_eq!(
        wal.quarantined().len(),
        1,
        "the altered frame is set aside, loudly"
    );
    assert!(
        wal.next_free_seq(NODE) <= 5,
        "one set-aside record moves the numbering by one at most, got {}",
        wal.next_free_seq(NODE)
    );
    assert!(
        wal.next_free_seq(NODE) >= 5,
        "the set-aside record's own number is never handed out again, got {}",
        wal.next_free_seq(NODE)
    );

    let journal = Journal::over(wal, NODE);
    assert_eq!(
        journal.next_seq(),
        5,
        "the journal numbers on from the record it set aside"
    );
}

/// A header altered somewhere other than the number keeps the number it carried, and that number
/// stays taken: the record was acknowledged, and a store may hold it.
#[test]
fn a_set_aside_frame_whose_number_is_in_reach_keeps_it_taken() {
    let factory = MemoryFactory::retaining();
    // The number the frame was written with, unchanged; the payload length byte is what changed.
    lay_down_with_altered_seq(&factory, 4);
    {
        let bytes = factory.segment_bytes(0);
        let mut bytes = bytes.lock().unwrap_or_else(|e| e.into_inner());
        bytes[3 * FRAME_BYTES + 33] ^= 0x40;
    }
    let wal = reopen(&factory);
    assert_eq!(wal.quarantined().len(), 1);
    assert_eq!(wal.next_free_seq(NODE), 5);
}
