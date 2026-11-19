// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The flusher's pull of the cores' audit state (design 2, A1, A3, A5, A8).

use super::*;
use crate::root::durability::audit::tests::inputs;

fn at_mono(unit: u64, mono: u64) -> AuditInputs {
    let mut line = inputs(unit);
    line.mono = mono;
    line
}

#[test]
fn a_pull_takes_every_core_in_monotonic_order() {
    let flusher = CoreFlusher::default();
    let first = flusher.core();
    let second = flusher.core();
    first.records().append(at_mono(1, 30));
    second.records().append(at_mono(2, 10));
    first.records().append(at_mono(3, 20));
    let pulled = flusher.pull();
    let order: Vec<u64> = pulled.lines.iter().map(|(_, line)| line.mono).collect();
    assert_eq!(order, [10, 20, 30]);
    assert_eq!(pulled.cores.len(), 2);
    assert_eq!(first.records().held(), 0);
    assert_eq!(second.records().held(), 0);
    assert!(
        flusher.pull().lines.is_empty(),
        "a pull takes each line once"
    );
}

#[test]
fn a_core_whose_loop_ended_is_pulled_once_more_then_released() {
    let flusher = CoreFlusher::default();
    let core = flusher.core();
    core.records().append(at_mono(1, 1));
    let weak = Arc::downgrade(&core);
    drop(core);
    let pulled = flusher.pull();
    assert_eq!(
        pulled.lines.len(),
        1,
        "a line handed over before the loop ended is not lost"
    );
    drop(pulled);
    assert!(weak.upgrade().is_none(), "the pull released the core");
    assert!(flusher.cores.lock().unwrap().is_empty());
}

#[test]
fn refusal_counts_merge_across_cores_by_listener_reason_and_status() {
    let flusher = CoreFlusher::default();
    let first = flusher.core();
    let second = flusher.core();
    for _ in 0..1000 {
        first.count_refusal(
            "public",
            StepName::Authenticate,
            ReasonCode::Unauthenticated,
            401,
        );
    }
    second.count_refusal(
        "public",
        StepName::Authenticate,
        ReasonCode::Unauthenticated,
        401,
    );
    second.count_refusal("public", StepName::Route, ReasonCode::NoDestination, 404);
    let pulled = flusher.pull();
    assert_eq!(
        pulled.refusals.len(),
        2,
        "one entry per (listener, reason, status)"
    );
    let unauthenticated = pulled
        .refusals
        .iter()
        .find(|count| count.reason == ReasonCode::Unauthenticated)
        .unwrap();
    assert_eq!(unauthenticated.count, 1001);
    assert!(first.refusals_held().is_empty());
}

#[test]
fn a_carried_pull_comes_back_before_anything_newer() {
    let flusher = CoreFlusher::default();
    let core = flusher.core();
    core.records().append(at_mono(1, 5));
    let pulled = flusher.pull();
    flusher.carry(pulled);
    core.records().append(at_mono(2, 6));
    let again = flusher.pull();
    let units: Vec<u64> = again.lines.iter().map(|(_, line)| line.mono).collect();
    assert_eq!(units, [5, 6]);
}

#[test]
fn the_flusher_is_judged_stalled_only_after_it_started_and_by_age() {
    let flusher = CoreFlusher::default();
    let now = Instant::now();
    assert!(
        !flusher.stalled(now + STALL_LIMIT * 10),
        "never started: not judged"
    );
    flusher.started(now);
    // The age is kept in whole milliseconds: judge a few either side of the limit.
    assert!(!flusher.stalled(now + STALL_LIMIT - Duration::from_millis(5)));
    assert!(flusher.stalled(now + STALL_LIMIT + Duration::from_millis(5)));
    flusher.good(now + STALL_LIMIT);
    assert!(!flusher.stalled(now + STALL_LIMIT + Duration::from_millis(5)));
}

/// BUSBAR-2060: the journal's buffer fills during one pull, so it refuses the third line. That
/// refusal is not sticky (the next flush stages again), so a later flush that commits must not
/// settle the third line's waiter unless the third line is in the journal.
#[tokio::test]
async fn a_line_the_journal_refused_mid_pull_is_kept_and_its_waiter_released_only_by_its_commit() {
    use busbar_kernel::persistence::journal::{BufferBudget, RuntimeJournal};
    use busbar_kernel_wal::{Entry, RecordClass};
    let budget = BufferBudget {
        records: 3,
        bytes: 1024 * 1024,
    };
    let history = BufferBudget {
        records: 64,
        bytes: 1024 * 1024,
    };
    let faults = crate::root::store_double::NativeFaults::open().await;
    let store = crate::root::real_store::core_over(faults).await;
    let journal = RuntimeJournal::open(store, 883, budget).await.unwrap();
    let book = crate::root::durability::node_book(journal.clone(), history)
        .await
        .unwrap()
        .durability;
    let node = Arc::new(crate::root::plane_node::Node::new());
    node.bind_book(book);
    let core = node.core_audit();
    let before = journal.read_records(history).await.unwrap().len();
    // One record already held: room for two of the three lines.
    journal
        .stage_run(&[Entry::new(RecordClass::Load, vec![1])])
        .unwrap();
    let tickets: Vec<_> = (1..=3)
        .map(|unit| core.records().append(at_mono(unit, unit)))
        .collect();

    assert!(
        node.flush_cores().await.is_err(),
        "the third stage is refused"
    );
    assert!(!core.records().is_committed(tickets[2]));
    // The buffer drained with that flush: the refusal is gone, and the next flush stages again.
    assert!(journal.refuses_staging().is_none());
    node.flush_cores().await.unwrap();

    let audit_lines = journal.read_records(history).await.unwrap().len() - before - 1;
    assert!(core.records().is_committed(tickets[2]));
    assert_eq!(
        audit_lines, 3,
        "a waiter released as committed has its line in the journal"
    );
}

/// BUSBAR-2060, the chain half. Keeping the refused line means linking it a second time: it was
/// linked once over the tail it was refused on, unlinked (`Linked::unlink`), carried, and linked
/// again at whatever position was next. After that the node's chain must still be ONE chain:
/// it verifies link by link, the three units appear once each and in their monotonic order, and
/// no position is skipped or used twice. Two more refusals in a row (the journal still full on
/// the next flush) must not change that: a line may be handed back any number of times.
#[tokio::test]
async fn a_line_handed_back_by_the_journal_is_sealed_once_in_order_on_one_verifiable_chain() {
    use busbar_kernel::persistence::journal::{BufferBudget, RuntimeJournal};
    use busbar_kernel_wal::{Entry, RecordClass};
    let budget = BufferBudget {
        records: 3,
        bytes: 1024 * 1024,
    };
    let history = BufferBudget {
        records: 64,
        bytes: 1024 * 1024,
    };
    let faults = crate::root::store_double::NativeFaults::open().await;
    let store = crate::root::real_store::core_over(faults).await;
    let journal = RuntimeJournal::open(store, 884, budget).await.unwrap();
    let book = crate::root::durability::node_book(journal.clone(), history)
        .await
        .unwrap()
        .durability;
    let node = Arc::new(crate::root::plane_node::Node::new());
    node.bind_book(Arc::clone(&book));
    let core = node.core_audit();
    let sealed = || -> Vec<(u64, u64)> {
        book.lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .audit_records()
            .iter()
            .map(|record| (record.seq, record.what.unit_key.get()))
            .collect()
    };
    let first_seq = sealed().last().map_or(1, |(seq, _)| seq + 1);

    // One record already held: room for two of the three lines.
    journal
        .stage_run(&[Entry::new(RecordClass::Load, vec![1])])
        .unwrap();
    let tickets: Vec<_> = (1..=3)
        .map(|unit| core.records().append(at_mono(unit, unit)))
        .collect();
    assert!(
        node.flush_cores().await.is_err(),
        "the third stage is refused"
    );
    assert_eq!(
        sealed()
            .iter()
            .filter(|(seq, _)| *seq >= first_seq)
            .map(|(_, unit)| *unit)
            .collect::<Vec<_>>(),
        [1, 2],
        "the refused line took no position: the chain holds the two lines that staged"
    );

    // The journal is filled again before the next flush: the kept line is refused a second time
    // and handed back a second time, and a line that arrived meanwhile waits behind it.
    for filler in 2..=4u8 {
        journal
            .stage_run(&[Entry::new(RecordClass::Load, vec![filler])])
            .unwrap();
    }
    let late = core.records().append(at_mono(4, 4));
    assert!(
        node.flush_cores().await.is_err(),
        "the kept line is refused again while the journal is full"
    );
    assert!(!core.records().is_committed(tickets[2]));
    assert!(!core.records().is_committed(late));

    // The journal's own driver drains it (a flush the flusher refused before staging does not).
    journal.flush().await.unwrap();
    node.flush_cores().await.unwrap();
    assert!(core.records().is_committed(tickets[2]));
    assert!(core.records().is_committed(late));

    let ours: Vec<(u64, u64)> = sealed()
        .into_iter()
        .filter(|(seq, _)| *seq >= first_seq)
        .collect();
    assert_eq!(
        ours,
        [
            (first_seq, 1),
            (first_seq + 1, 2),
            (first_seq + 2, 3),
            (first_seq + 3, 4),
        ],
        "each unit is sealed once, in monotonic order, at consecutive positions"
    );
    let held = book.lock().unwrap_or_else(|poison| poison.into_inner());
    busbar_kernel_audit::AuditChain::verify_window(held.audit_records())
        .expect("the chain verifies link by link after a line was handed back twice");
}
