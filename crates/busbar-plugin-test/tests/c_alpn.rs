// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ALPN (ABI-MIN3-INTERFACE §14): ALPN offers per role and per instance setting.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L9; blocked (re-checked on dev 2026-11-16): the transport-http fixture image lives in the plugin repo, not in core; core has only the adapter-level cache arm"]
fn alpn_offers_per_role() {
    todo!("owner: W1-L9 (C-ALPN)")
}
