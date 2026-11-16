// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §3.6.2 (MR-5): the predecessor sealer's own rules that need no second process.

use std::sync::Arc;

use busbar_kernel_audit::{BreakReason, TailItem, WalkOutcome};

use super::{budget_break, run, SealerDone};
use crate::root::durability::tests::{audit_inputs, audit_pass, token, NativeFixture};

/// A walk that keeps more lines than its budget without an anchor stops with a `budget` break over
/// exactly the walked range, never a restart page.
#[tokio::test]
async fn a_walk_over_budget_is_a_budget_break_over_the_walked_range() {
    let fixture = NativeFixture::new(71).await;
    let mut book = fixture.book().await;
    for unit in 1..=5u64 {
        book.stage_line(audit_inputs(unit), audit_pass(), &token())
            .unwrap();
    }
    let items: Vec<TailItem> = book
        .audit_records()
        .iter()
        .enumerate()
        .map(|(i, record)| TailItem::Line {
            record: record.clone(),
            node_seq: 100 + i as u64,
        })
        .collect();
    let WalkOutcome::Break(at) = budget_break(&items[1..]) else {
        panic!("a budget break");
    };
    assert_eq!(at.reason, BreakReason::Budget);
    assert_eq!((at.last_good, at.unsealed_from, at.unsealed_to), (1, 2, 5));
    assert_eq!((at.journal_from, at.journal_to), (101, 104));
    book.journal.flush().await.unwrap();
}

/// With no deployment key or Bootstrap handle (a keyless book) the task seals nothing and runs
/// only SHUTDOWN-HANG F5; a stop flag already set ends it before F5.
#[tokio::test]
async fn a_keyless_task_seals_nothing_and_stops_at_the_flag() {
    let fixture = NativeFixture::new(72).await;
    let fence = busbar_kernel::persistence::boot_identity::PredecessorFence::new(
        Arc::clone(&fixture.core),
        "predecessor-test-host",
    )
    .unwrap();
    let (stop_tx, stop) = tokio::sync::watch::channel(false);
    stop_tx.send(true).unwrap();
    let done = run(fence, None, None, stop).await;
    assert_eq!(done, SealerDone::default());
}
