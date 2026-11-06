// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! GitHub is a public source mirror. Executable Actions must not return.

use crate::walk;

#[test]
fn public_mirror_has_no_github_actions() {
    let root = walk::repo();
    for relative in [".github/workflows", ".github/actions"] {
        assert!(
            !root.join(relative).exists(),
            "{relative} must remain absent: GitHub Actions is retired"
        );
    }
}
