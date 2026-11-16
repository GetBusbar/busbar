// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-LINE-CARRIER (ABI-MIN3-INTERFACE §14): The line carrier (§12.23).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "blocked: serve_lines_over is pub(crate) in the busbar bin crate (root/serve_lines.rs) and needs a plane-mcp fixture; unreachable from busbar-plugin-test"]
fn the_line_carrier() {
    todo!("blocked: serve_lines_over is pub(crate) in the busbar bin crate (root/serve_lines.rs) and needs a plane-mcp fixture; unreachable from busbar-plugin-test (C-LINE-CARRIER)")
}
