// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PUBLIC-URL (ABI-MIN3-INTERFACE §14): `public_url` written at D_PUBLIC_URL_PATH only (§12.7; K7 with L2).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: D_PUBLIC_URL_PATH write-path enforcement is in the kernel boot (K7 with L2) with no public entry reachable from this crate"]
fn public_url_at_its_declared_path_only() {
    todo!("owner: W1-K7 (C-PUBLIC-URL)")
}
