// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-WATCH-CHURN (ABI-MIN3-INTERFACE §14): Watchdog registration churn, alignment and the full table (rounds 12,
//! 17, 24).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_plugin_abi::host::{enter, full_total, init, leave, live, WatchWord, WATCH_CAP};

/// Three table-fulls of threads, each making one entry and exiting: every exit releases its word (else the
/// table fills after 1,024 and later entries run unwatched, counted in `full_total`), and the word table never
/// grows. Words own their 128-byte line pair (round 17).
#[test]
fn thread_churn_leaves_the_table_at_baseline() {
    assert_eq!(core::mem::align_of::<WatchWord>(), 128);
    assert_eq!(core::mem::size_of::<WatchWord>(), 128);
    init();
    let full_before = full_total();
    for _ in 0..(3 * WATCH_CAP / 32) {
        let batch: Vec<_> = (0..32)
            .map(|i| {
                std::thread::spawn(move || {
                    enter(i, 0);
                    leave();
                })
            })
            .collect();
        for thread in batch {
            thread.join().expect("thread");
        }
    }
    assert_eq!(
        full_total(),
        full_before,
        "no entry found the table full: every exit released its word"
    );
    assert!(
        live() < WATCH_CAP,
        "registrations are back near the baseline, never the whole table"
    );
}

#[test]
#[ignore = "owner: W1-L2"]
fn a_full_table_entry_is_still_attributed_and_scrubbed() {
    todo!("owner: W1-L2 (C-WATCH-CHURN)")
}
