// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-POOL-KEY (ABI-MIN3-INTERFACE §14): Conn pool keys (rounds 4 and 11; C1's suite).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-C1A"]
fn sni_cert_or_trust_alone_never_share_a_conn() {
    todo!("owner: W1-C1A (C-POOL-KEY)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn a_constant_hasher_never_reuses_another_dests_conn() {
    todo!("owner: W1-C1A (C-POOL-KEY)")
}

#[test]
#[ignore = "owner: W1-C1A"]
fn pool_key_has_no_u64_hash_and_production_uses_random_state() {
    todo!("owner: W1-C1A (C-POOL-KEY)")
}
