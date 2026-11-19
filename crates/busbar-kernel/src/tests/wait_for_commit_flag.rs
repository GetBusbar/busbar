// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `advanced.wait_for_commit` is a field of the generation a request was admitted under: reading
//! it is a field load and a branch, no lock, no lookup, no clone (owner: "make the flag check
//! itself ns").

use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use crate::state::App;

fn generation(wait_for_commit: Option<bool>) -> Arc<App> {
    let base = crate::inbound::native::tests::app();
    let mut next = (*base).clone();
    next.limits = wait_for_commit.map(|wait_for_commit| crate::config::LimitsResolved {
        wait_for_commit,
        ..Default::default()
    });
    Arc::new(next)
}

#[test]
fn the_flag_is_the_generations_and_off_without_resolved_limits() {
    assert!(!generation(None).wait_for_commit());
    assert!(!generation(Some(false)).wait_for_commit());
    assert!(generation(Some(true)).wait_for_commit());
}

#[test]
fn an_admitted_request_keeps_its_generations_flag_when_the_next_one_differs() {
    let admitted = generation(Some(false));
    let held = Arc::clone(&admitted);
    let _next = generation(Some(true));
    assert!(
        !held.wait_for_commit(),
        "a request never sees the flag flip mid-flight"
    );
}

/// Prints nanoseconds per check for the flag and for a plain `bool` branch. Asserts only that the
/// flag check is not slower than a plain branch by more than an order of magnitude, so a loaded
/// build machine does not fail it; the printed figures are the measurement.
#[test]
fn the_flag_check_costs_what_a_plain_branch_costs() {
    const N: u32 = 20_000_000;
    let app = generation(Some(true));
    let plain = Box::new(true);
    let mut taken = 0u64;
    let started = Instant::now();
    for _ in 0..N {
        if black_box(&*app).wait_for_commit() {
            taken += 1;
        }
    }
    let flag = started.elapsed();
    let started = Instant::now();
    for _ in 0..N {
        if *black_box(&*plain) {
            taken += 1;
        }
    }
    let branch = started.elapsed();
    assert_eq!(taken, 2 * u64::from(N));
    let per = |d: std::time::Duration| d.as_secs_f64() * 1e9 / f64::from(N);
    println!(
        "MEASURE wait_for_commit flag {:.3} ns/check, plain bool branch {:.3} ns/check",
        per(flag),
        per(branch)
    );
    assert!(per(flag) < per(branch) * 10.0 + 1.0);
}
