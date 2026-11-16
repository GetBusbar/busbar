// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-APPEND (ABI-MIN3-INTERFACE §14): File-sink appends (§12.21).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

#[test]
#[ignore = "owner: W1-K8C; re-checked 2026-11-16: the kernel has the delivery ids, custody counting and per-instance breaker cell (busbar-kernel export/delivery.rs, unit-tested in export/tests/delivery_tests.rs) but no export pump and no DiskSink (no DiskSink or ExportPump type in busbar-kernel or busbar; plugin-loader ports/export.rs:68 only names it), so the booted arm waits on open MR !2645 (W1-K8C + W2-SW-EXPORT, OUTSTANDING rows 4 and 9)"]
fn file_sink_appends() {
    todo!("owner: W1-K8C (C-APPEND)")
}
