// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OBSERVE (ABI-MIN3-INTERFACE §14): OBS_SCOPE, ATTACH, OBSERVE and OBS_PENDING rules.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "re-checked 2026-11-16: busbar-plugin-test does depend on busbar-kernel, but partial kernel cover (plane_driver/tests/port_observations_tests.rs:185-354 CREATE/FINAL/CLOSE, ATTACH by another scope refused; port_intents_tests.rs:1792 P_OBSERVED) leaves clauses uncovered: OBS_PENDING is only asserted distinct from OBS_REFUSED (port_observations_tests.rs:350), never driven from StoreError::Pending or the receipt-encode path (port_observations.rs:178,:252,:270), OBSERVE-after-durable-write order is untested, and USAGE for an observed class is not dropped and audited (plane_usage_double appears only in a doc comment, plugin-abi kinds/plane.rs:235). OUTSTANDING row 5 (K8A tail)"]
fn observation_scope_attach_and_pending_rules() {
    todo!("owner: W1-K8A (C-OBSERVE)")
}
