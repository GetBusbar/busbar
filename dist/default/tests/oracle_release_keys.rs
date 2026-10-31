// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JUDGE IS VERIFIED AGAINST BUSBAR-RELEASE'S TRUSTED RELEASE KEY: the owner's 2026-10-28 key,
//! and no other. The earlier key busbar-release-2026-10-09 (private half lived in GitHub) is refused
//! (owner ruling 2026-10-28). A `.sig` by a listed key verifies; one by any other key is refused.
//! `bin/oracle release-key-selftest` drives each case.

use std::path::Path;
use std::process::Command;

#[test]
fn the_judge_verifies_with_the_trusted_release_keys_and_no_other() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = Command::new("bash")
        .arg(root.join("bin/oracle"))
        .arg("release-key-selftest")
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
