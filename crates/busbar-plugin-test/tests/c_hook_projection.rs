// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-HOOK-PROJECTION (ABI-MIN3-INTERFACE §14): Hook views from a golden 1.5.5 decision; S_STAGE and S_STAGE_MODEL
//! (round 17). The hook-webrequest golden runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8 + hook-webrequest P; blocked (re-checked on dev 2026-11-16): hooks are not wired into min3_boot (OUTSTANDING row 8, W2-SW-HOOK), the golden 1.5.5 decision and the byte-equal projection are hook-webrequest's P suite, and the ranking clause needs a hook-ranking fixture; the view builder (plugin-loader hook_door/port.rs) stays private (not widened for a test), its encoding unit-tested in plugin-loader encode/hook.rs"]
fn hook_views_round_trip_the_golden_decision() {
    todo!("blocked: the view builder (plugin-loader hook_door/port.rs C_HAS_* and S_STAGE* code) is private to HookDoor; encoding is unit-tested in plugin-loader encode/hook.rs; the hook-webrequest golden runs in its repo (C-HOOK-PROJECTION)")
}
