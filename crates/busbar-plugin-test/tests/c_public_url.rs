// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PUBLIC-URL (ABI-MIN3-INTERFACE §14): `public_url` written at D_PUBLIC_URL_PATH only (§12.7; K7 with L2).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K7 + W1-L2; blocked (re-checked on dev 2026-11-16): compares plane-a2a, plane-mcp and plane-streaming outputs with their repos' goldens on MIN-3 planes (min3_boot and plane serving, OUTSTANDING rows 3, 7-10); the registry's write at D_PUBLIC_URL_PATH needs a plane fixture declaring it through the suites Harness (booted-fixture work, not a relocation)"]
fn public_url_at_its_declared_path_only() {
    todo!("owner: W1-K7 (C-PUBLIC-URL)")
}
