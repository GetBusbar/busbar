// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCRUB-RETIRE (ABI-MIN3-INTERFACE §14 round 17): readers never take the lock or free a snapshot while a
//! writer rebuilds. The `Drop for Snap` thread record and the reader-side free count are W1-H0's crate test
//! (counting build, `busbar-plugin-abi` host_side::scrub tests); this is its public shape: 16 readers of
//! `fail_text` see a stable secret masked on every read while a 17th thread re-registers a changing value.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};
use std::sync::Arc;

use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};

const STABLE: &str = "stable-secret-XYZ123";
const LINE: &str = "token stable-secret-XYZ123 rejected";

#[test]
fn readers_see_the_stable_secret_masked_while_a_writer_rebuilds() {
    let scrub = Arc::new(Scrub::new());
    scrub.register(1, &[STABLE.as_bytes()]);
    let stop = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..16)
        .map(|_| {
            let (scrub, stop) = (Arc::clone(&scrub), Arc::clone(&stop));
            std::thread::spawn(move || {
                let mut reads = 0u64;
                loop {
                    assert!(!fail_text(&scrub, LINE).contains(STABLE));
                    reads += 1;
                    if stop.load(Relaxed) {
                        return reads;
                    }
                }
            })
        })
        .collect();
    for round in 0..2_000u32 {
        let value = format!("rotating-{round:06}-value");
        scrub.register(2, &[value.as_bytes()]);
    }
    stop.store(true, Relaxed);
    for reader in readers {
        assert!(reader.join().expect("reader") > 0);
    }
}
