// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-CRED-CACHE (ABI-MIN3-INTERFACE §14): The credential cache (§12.2; K2 + K3 + K6), arms (a)-(m). The auth-oauth
//! image arms are on #217.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K6; re-checked 2026-11-16, W2-SW-AUTH: the cache is on dev (busbar-kernel custody/cred.rs, with the single-flight, refresh-ahead, failure-window, cap and max-hold rules unit-tested in custody/cred_tests.rs) but nothing outside tests constructs a CredCache or calls auth_bindings::upstream_credential (no production caller; the live outbound path predates the AuthPort), so the end-to-end arms wait on the auth switch-over (draft MR !2481); (h), (l) and (m) also need the auth-oauth and auth-header images and a counting allocator"]
fn credential_cache_core_arms() {
    todo!("owner: W1-K6 (C-CRED-CACHE)")
}
