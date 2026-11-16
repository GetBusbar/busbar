// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PLANE-CHAIN (ABI-MIN3-INTERFACE §14): LK_CHAIN appends, paged lookups and break detection (K5 + K8). The
//! plane P arms run in their repos.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K5 + W1-K8; blocked (re-checked on dev 2026-11-16): the K5 half runs as busbar_kernel::plugin_records::tests::{a_chain_appends_in_order_and_reads_back_in_pages, a_tampered_entry_breaks_the_chain_there, a_missing_tail_entry_breaks_at_len, stored_frames_are_the_kernel_chain_frames, two_instances_chains_with_one_name_are_separate, ttl_zero_never_expires_and_a_ttl_is_clamped_to_the_maximum} (250 and 10 entries); the K8 half (STORE/LOOKUP LK_CHAIN through the plane port, 1,000 entries in pages of 100, ttl_s != 0 and in-COMMIT refusals) needs MIN-3 plane serving (OUTSTANDING rows 3, 5), and a2a's health clause is plane-a2a's P suite"]
fn chain_appends_lookups_and_breaks() {
    todo!("owner: W1-K8A (C-PLANE-CHAIN)")
}
