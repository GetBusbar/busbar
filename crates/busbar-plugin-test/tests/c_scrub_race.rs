// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCRUB-RACE (ABI-MIN3-INTERFACE §14 round 8): two threads register different slots of one instance 10,000
//! times each in a barrier loop; after every round both values are scrubbed by `text`. W1-H0's (merged); the
//! `forget` race is its crate test (`busbar-plugin-abi` host_side::scrub tests).
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use std::sync::{Arc, Barrier};

use busbar_plugin_abi::host_side::scrub::Scrub;

const ROUNDS: usize = 10_000;

fn value(slot: u32, round: usize) -> String {
    format!("slot{slot}-round{round:05}-secret")
}

#[test]
fn both_slots_are_masked_after_every_round() {
    let scrub = Arc::new(Scrub::new());
    let barrier = Arc::new(Barrier::new(3));
    let writers: Vec<_> = [10u32, 11]
        .into_iter()
        .map(|slot| {
            let (scrub, barrier) = (Arc::clone(&scrub), Arc::clone(&barrier));
            std::thread::spawn(move || {
                for round in 0..ROUNDS {
                    scrub.register(slot, &[value(slot, round).as_bytes()]);
                    barrier.wait();
                    barrier.wait();
                }
            })
        })
        .collect();
    for round in 0..ROUNDS {
        barrier.wait();
        for slot in [10u32, 11] {
            let secret = value(slot, round);
            let shown = scrub.text(&format!("leak {secret}"));
            assert!(
                !shown.contains(&secret),
                "round {round}: slot {slot} unmasked"
            );
        }
        barrier.wait();
    }
    for writer in writers {
        writer.join().expect("writer");
    }
}
