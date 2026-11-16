// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-FAIL-FACTS (ABI-MIN3-INTERFACE §14): FAIL then exactly the stated FACTs, the bytes zeroed, and each adapter's
//! `PortError::Failed` facts (round 21).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-A3"]
fn the_shim_writes_fail_then_its_facts() {
    todo!("owner: W1-A3 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-H1"]
fn hand_written_bad_fact_answers_fault() {
    todo!("owner: W1-H1 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L3"]
fn store_adapter_maps_the_facts() {
    todo!("owner: W1-L3 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L4"]
fn secret_adapter_maps_the_facts() {
    todo!("owner: W1-L4 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L5"]
fn auth_adapter_maps_the_facts() {
    todo!("owner: W1-L5 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L6"]
fn hook_adapter_maps_the_facts() {
    todo!("owner: W1-L6 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L7"]
fn export_adapter_maps_the_facts() {
    todo!("owner: W1-L7 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-L8"]
fn plane_admin_maps_the_facts() {
    todo!("owner: W1-L8 (C-FAIL-FACTS)")
}

#[test]
#[ignore = "owner: W1-K3"]
fn retry_policy_honours_retry_after() {
    todo!("owner: W1-K3 (C-FAIL-FACTS)")
}
