// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCRUB-HIT (ABI-MIN3-INTERFACE §14 rounds 5, 7, 18, 19): one register per value change. The scrub-set arm
//! (rotation keeps the previous generation, a second rotation drops the oldest, an unchanged value is not a
//! rotation) is W1-H0's (merged); the custody arms are W1-K2's (registration on the miss path, publish order).
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::host_side::scrub::Scrub;

const V1: &str = "alpha-7Q2x-secret";
const V2: &str = "bravo-9K4m-secret";
const V3: &str = "charlie-3T8p-secret";

fn masked(scrub: &Scrub, value: &str) -> bool {
    !scrub
        .text(&format!("token {value} rejected"))
        .contains(value)
}

#[test]
fn rotations_keep_one_previous_generation_and_a_repeat_is_not_a_rotation() {
    let scrub = Scrub::new();
    scrub.register(4, &[V1.as_bytes()]);
    scrub.register(4, &[V2.as_bytes()]);
    assert!(masked(&scrub, V1) && masked(&scrub, V2));
    scrub.register(4, &[V3.as_bytes()]);
    assert!(!masked(&scrub, V1), "the oldest generation is dropped");
    assert!(masked(&scrub, V2) && masked(&scrub, V3));
    scrub.register(4, &[V3.as_bytes()]);
    assert!(
        masked(&scrub, V2),
        "the same value again does not shift the slot"
    );
    scrub.forget(4);
    assert!(!masked(&scrub, V3) && !masked(&scrub, V2));
}

#[test]
#[ignore = "owner: W1-K2"]
fn ten_thousand_secret_needs_on_one_handle_register_once() {
    todo!("owner: W1-K2 (C-SCRUB-HIT)")
}

#[test]
#[ignore = "owner: W1-K2"]
fn two_instances_each_register_on_their_first_resolve() {
    todo!("owner: W1-K2 (C-SCRUB-HIT)")
}

#[test]
#[ignore = "owner: W1-K2"]
fn a_publish_waits_for_register_and_the_publish_first_control_is_red() {
    todo!("owner: W1-K2 (C-SCRUB-HIT)")
}
