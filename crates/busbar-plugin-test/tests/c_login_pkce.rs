// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LOGIN-PKCE (ABI-MIN3-INTERFACE §14): Core mints the PKCE challenge, verifier and nonce once
//! (`busbar-core-oauth2::pkce`; K8 + K10). The auth plugins' arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: busbar-core-oauth2 has no pkce module on dev (no minting functions; hosted_login does not mint L_CODE_CHALLENGE)"]
fn core_mints_pkce_once() {
    todo!("blocked: busbar-core-oauth2 has no pkce module on dev (no minting functions; hosted_login does not mint L_CODE_CHALLENGE) (C-LOGIN-PKCE)")
}
