// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the log is allowed to keep in memory while it stays correct.
//!
//! A bound is worth nothing until a test runs past it and reads back what the node decided to hold
//! on to. A node that answers correctly for a week and is killed by the allocator on the eighth day
//! answered incorrectly.

use busbar_caps::StepName;

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
