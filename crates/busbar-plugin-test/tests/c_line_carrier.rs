// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LINE-CARRIER (ABI-MIN3-INTERFACE §14): The line carrier (§12.23).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8A; blocked (re-checked on dev 2026-11-16): needs a MIN-3 plane fixture declaring ROUTE_LINE, served through root::serve_lines::serve_lines_over over a MemIo pair, and plane-mcp's 1.5.5 transcripts; crates/busbar has no such fixture (the arm moves there: crates/busbar is a bin crate, so nothing can depend on it) and MIN-3 plane serving waits on the K8A tail and K10 (OUTSTANDING rows 3, 5). Clause (e) runs as busbar::root::serve_lines::tests::the_one_line_plane_is_bound_and_two_are_refused_naming_both"]
fn the_line_carrier() {
    todo!("blocked: serve_lines_over is pub(crate) in the busbar bin crate (root/serve_lines.rs) and needs a plane-mcp fixture; unreachable from busbar-plugin-test (C-LINE-CARRIER)")
}
