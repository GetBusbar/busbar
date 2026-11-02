// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
