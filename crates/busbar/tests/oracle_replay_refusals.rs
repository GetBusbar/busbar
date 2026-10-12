// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ORACLE NEVER READS "NOTHING JUDGED" AS A VERDICT (2026-10-07, row 86). A filtered replay
//! handed `--filter` (record's flag; replay selects with `--id-filter`) exited 2 from the engine's
//! argument parser, and the fence and dated-baseline sections then printed their own rows, which
//! read like a verdict over the selected cells. `bin/oracle replay-refusal-selftest` drives a copy
//! of the shim with a stub engine: `--filter` is refused by name before the engine runs, an engine
//! argument refusal stops the replay, a report that compared zero owed cells is refused, and a
//! replay that judged cells answers the engine's verdict.

use std::path::Path;
use std::process::Command;

#[test]
fn a_replay_that_judged_nothing_is_refused_never_read_as_a_verdict() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("bash")
        .arg(root.join("bin/oracle"))
        .arg("replay-refusal-selftest")
        .current_dir(&root)
        .output()
        .expect("bash runs the shim");
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
