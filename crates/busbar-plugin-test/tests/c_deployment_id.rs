// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-DEPLOYMENT-ID (ABI-MIN3-INTERFACE §14 rounds 28, 29). Arm (e), never torn, is W1-H0's (merged). (a) and (d)
//! need the kernel's boot identity (K9 owns boot.rs in wave 1); (c) is a C-PANIC-HOST injection arm (W1-H1); (f),
//! the 2a/2b re-check, is the registry's (W1-L2). (b), the C fixture's `bb_host.deployment`, runs in
//! busbar-secret-c's CI.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use std::sync::{Arc, Barrier};

use busbar_plugin_abi::host_side::host_vt::{set_deployment, vt};

const ID: [u8; 16] = *b"deployment-id-16";

#[test]
fn every_read_is_all_zero_or_exactly_the_id() {
    let start = Arc::new(Barrier::new(9));
    let readers: Vec<_> = (0..8)
        .map(|_| {
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                for _ in 0..125_000 {
                    let read = vt::deployment().0;
                    assert!(read == [0; 16] || read == ID, "torn: {read:?}");
                }
            })
        })
        .collect();
    start.wait();
    set_deployment(ID);
    for reader in readers {
        reader.join().expect("reader");
    }
    assert_eq!(vt::deployment().0, ID);
}

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): boot does not yet open the planes, stores and hooks through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10)"]
fn step_2b_reads_none_and_2c_reads_the_stored_id() {
    todo!("owner: W1-K9 (C-DEPLOYMENT-ID)")
}

#[test]
#[ignore = "owner: W1-H1 (blocked: entry::guard, GetBusbar/busbar#272)"]
fn the_conformance_injection_answers_all_zero_without_unwinding() {
    todo!("owner: W1-H1 (C-DEPLOYMENT-ID)")
}

#[test]
#[ignore = "owner: W1-K9; blocked (re-checked on dev 2026-11-16): boot does not yet open the planes, stores and hooks through the MIN-3 Registry (min3_boot configured(), OUTSTANDING rows 7 to 10)"]
fn the_id_never_equals_a_run_of_the_keyset_seed() {
    todo!("owner: W1-K9 (C-DEPLOYMENT-ID)")
}

#[test]
#[ignore = "owner: W1-L2; blocked (re-checked on dev 2026-11-16): no test constructor for Registry<N> (Needs impl, ConfigBinder, Ceilings, a static Host) and no second-identity MIN-3 fixture image exist in busbar-plugin-test on dev"]
fn the_2a_and_2b_recheck_sees_the_id_before_any_2c_open() {
    todo!("owner: W1-L2 (C-DEPLOYMENT-ID)")
}
