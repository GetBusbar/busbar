// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE SHUTDOWN TAIL (audit busbar-src #1; ruling H2 U10; BUSBAR-1.6.0.md THE DESIGN, §7): it
//! returns only once the journal records queued for the configured store have reached it, and both
//! of the process's tails — the listener path's and the line-serve mode's — are this one function.

use busbar_contract::caps::{DurableWrite, StepName};
use busbar_kernel_ledger::legacy::RecordingRows;
use busbar_kernel_wal::{Entry, Record, RecordClass};

use super::*;
use crate::root::durability::{build_on_store, read_chain, DurabilityConfig, JournalLane};
use crate::root::kernel::PinnedHistory;
use crate::root::store_double::RecordSlots;

/// The node the test book is built as.
const NODE: u64 = 31;

/// How long the store refuses before it recovers: long enough that a tail which does not wait has
/// returned well before, short enough to sit far inside [`RECORD_DRAIN`].
const OUTAGE: std::time::Duration = std::time::Duration::from_millis(300);

/// How long a test waits on the lane outside the tail.
const WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// No dated history: the test book prices nothing.
fn no_history() -> Option<PinnedHistory> {
    None
}

/// A book over `slots` with no data directory (the production boot's shape for a child process
/// with no disk), and a handle on the same lane its journal ships through.
fn store_book(slots: &RecordSlots) -> (Arc<Mutex<Durability>>, JournalLane) {
    store_book_bounded(slots, busbar_kernel_wal::MEMORY_BUFFER_RECORDS)
}

/// [`store_book`], its lane to the store bounded at `capacity` records.
fn store_book_bounded(
    slots: &RecordSlots,
    capacity: usize,
) -> (Arc<Mutex<Durability>>, JournalLane) {
    let lane =
        JournalLane::with_capacity(slots.calls(), "test-store", capacity).expect("the lane starts");
    let durability = build_on_store(
        &DurabilityConfig { data_dir: None },
        NODE,
        lane.clone(),
        Box::new(RecordingRows::new()),
        Box::new(no_history),
        None,
    )
    .expect("the store reads back");
    (Arc::new(Mutex::new(durability)), lane)
}

/// **THE SHUTDOWN TAIL DRAINS THE JOURNAL'S LANE BEFORE IT RETURNS.** Journal records wait in the
/// lane while the store refuses; the store recovers a moment into the tail. The tail returns only
/// once the store took every one of them, so the process that exits right after it (the line-serve
/// mode's `std::process::exit`) leaves nothing queued.
///
/// RED before the fix: there was no shared tail (`root::shutdown` did not exist), and the line-serve
/// mode's own tail flushed the budget and metering write-behind and exited, never touching the
/// lane: the records it held at stdin EOF were lost with the process.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_shutdown_tail_drains_the_journal_lane_before_it_returns() {
    let slots = RecordSlots::new();
    let (book, lane) = store_book(&slots);
    slots.refuse(true);
    let before = slots.puts();
    let queued: Vec<Record> = (1..=4)
        .map(|seq| Record::new(NODE + 1, seq, vec![7u8; 24]))
        .collect();
    lane.shipper()
        .ship(&queued)
        .expect("a refusing store does not refuse the hand-off: the lane has room");
    assert!(lane.pending() > 0, "the records wait for the store");

    let recovers = {
        let slots = slots.clone();
        std::thread::spawn(move || {
            std::thread::sleep(OUTAGE);
            slots.refuse(false);
        })
    };
    let late = LateServices::new();
    tail(None, &late, Some(&book)).await;

    assert_eq!(
        lane.pending(),
        0,
        "the tail returned with journal records still queued for the store"
    );
    assert!(
        slots.puts() >= before + queued.len(),
        "every queued record reached the store before the tail returned"
    );
    recovers.join().expect("the recovery thread");
}

/// **THE SHUTDOWN TAIL HANDS THE STORE WHAT THE JOURNAL HELD BACK, TOO** (audit root r4 B-6;
/// BUSBAR-1.6.0.md THE DESIGN §7, l.991-998: the kernel writes exactly what it is told, one sealed
/// line per unit; `root::shutdown`'s docs: what the caller was answered for has to reach the store
/// before the process is gone). The lane is full while the store refuses, so the journal's last
/// records were turned away and are retained by the journal, outside the lane. The store recovers a
/// moment into the tail. The tail returns only once those records reached the store as well.
///
/// RED before the fix: the tail drained only the lane's queue and never re-offered the journal's
/// retained batch, so the process exited with settled records the store never saw.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn the_shutdown_tail_hands_the_store_what_the_journal_held_back() {
    let slots = RecordSlots::new();
    let (book, lane) = store_book_bounded(&slots, 4);
    assert!(lane.drain(WAIT), "the boot's records reach the store");
    slots.refuse(true);
    let token = busbar_kernel::test_support::tokens::grant::<DurableWrite>();
    let written = {
        let mut durability = book.lock().expect("the book");
        // Past the lane's bound: the lane holds four, the journal retains the rest.
        for _ in 0..6 {
            let _ = durability.journal.append(
                &token,
                StepName::Meter,
                &[Entry::new(RecordClass::Load, Vec::new())],
            );
        }
        assert!(
            durability.journal.buffered() > 0,
            "the journal holds back what the full lane turned away"
        );
        durability.journal.next_seq() - 1
    };

    let recovers = {
        let slots = slots.clone();
        std::thread::spawn(move || {
            std::thread::sleep(OUTAGE);
            slots.refuse(false);
        })
    };
    let late = LateServices::new();
    tail(None, &late, Some(&book)).await;

    assert_eq!(
        book.lock().expect("the book").journal.buffered(),
        0,
        "the tail returned with records the journal still held back from the store"
    );
    assert_eq!(lane.pending(), 0, "the tail returned with records queued");
    assert_eq!(
        read_chain(slots.calls().as_ref(), NODE)
            .expect("the store reads back")
            .len() as u64,
        written,
        "every record the journal sealed reached the store before the tail returned"
    );
    recovers.join().expect("the recovery thread");
}

/// **BOTH TAILS ARE THE ONE TAIL.** `main.rs` calls [`tail`] from the line-serve branch, before its
/// `std::process::exit`, and from the listener path's end; and it spells none of the tail's steps
/// itself, so neither path can again carry a shorter list than the other.
///
/// RED before the fix: the line-serve branch flushed the budget and metering write-behind inline
/// and exited without draining the plane records or the journal lane; the listener path spelled
/// its own longer list.
#[test]
fn the_line_serve_tail_and_the_listener_tail_are_the_one_shutdown_tail() {
    let main = include_str!("../../main.rs");
    let call = "root::shutdown::tail(";
    assert_eq!(
        main.matches(call).count(),
        2,
        "main.rs runs the shutdown tail once per tail: the line-serve branch and the listener path"
    );
    let served = main
        .find("serve_lines(")
        .expect("main.rs serves the line-serve mode");
    let exit = served
        + main[served..]
            .find("std::process::exit(code)")
            .expect("the line-serve branch exits with the loop's code");
    assert!(
        main[served..exit].contains(call),
        "the line-serve branch exits without running the shutdown tail"
    );
    assert!(
        main[exit..].contains(call),
        "the listener path ends without running the shutdown tail"
    );
    for step in [
        "flush_budgets(",
        "flush_metering(",
        "drain_records(",
        "RECORD_DRAIN",
    ] {
        assert!(
            !main.contains(step),
            "main.rs spells the shutdown step `{step}` itself instead of running the one tail"
        );
    }
}
