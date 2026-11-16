// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-OUTBOUND-STYLE (ABI-MIN3-INTERFACE §14): Deferred `{"$style": ..}` bindings resolve to the one declaring
//! fixture (one process since MIGRATE-ON-BOOT r42).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: $style resolution is busbar-migrate styles.rs plus the busbar bin boot (kernel_application tests); no declaring-fixture boot path reachable from this crate; owner W1-K9"]
fn deferred_styles_resolve_to_one_declaring_fixture() {
    todo!("owner: W1-K9 (C-OUTBOUND-STYLE)")
}
