// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-AUTHORITY (ABI-MIN3-INTERFACE §14): An h2 request with `:authority` and no `host` reaches
//! `verify`/`verify_io` with `authority` set.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8B; re-checked 2026-11-16, W2-SW-AUTH: the encode half is on dev (plugin-loader encode/auth.rs:108 writes Q_AUTHORITY, tested in encode/auth.rs) but nothing in the kernel builds an AuthIn from a parsed request (the only AuthIn constructors are plugin-loader adapters/auth.rs decoders and test code), so :authority never reaches verify on the live path until the auth switch-over (draft MR !2481); the SigV4 verification clause also needs the auth-sigv4 image"]
fn an_h2_authority_reaches_verify() {
    todo!("owner: W1-K8B (C-AUTHORITY)")
}
