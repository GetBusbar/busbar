// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PLANE-CHAIN (ABI-MIN3-INTERFACE §14): LK_CHAIN appends, paged lookups and break detection (K5 + K8). The
//! plane P arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: PluginRecords append/chain need a kernel store backend and plane driver LOOKUP(LK_CHAIN); covered in-crate by busbar-kernel plugin_records tests (a_chain_appends_in_order_and_reads_back_in_pages, a_tampered_entry_breaks_the_chain_there, a_missing_tail_entry_breaks_at_len)"]
fn chain_appends_lookups_and_breaks() {
    todo!("owner: W1-K8A (C-PLANE-CHAIN)")
}
