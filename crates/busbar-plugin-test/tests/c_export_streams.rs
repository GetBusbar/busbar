// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EXPORT-STREAMS (ABI-MIN3-INTERFACE §14): Export streams (round 28). (a)'s one-definition source check is
//! W1-X1's job.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-L7"]
fn the_const_block_matches_export_stream() {
    todo!("owner: W1-L7 (C-EXPORT-STREAMS)")
}

#[test]
#[ignore = "owner: W1-L7"]
fn bad_d_streams_bodies_are_describe_invalid() {
    todo!("owner: W1-L7 (C-EXPORT-STREAMS)")
}

#[test]
#[ignore = "owner: W1-K8C"]
fn stream_routing_and_refusals() {
    todo!("owner: W1-K8C (C-EXPORT-STREAMS)")
}
