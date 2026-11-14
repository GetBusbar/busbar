// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared support for the architecture checks (CORE-ARCHITECTURE-DIET §5 and §7).

pub mod scan;

use std::path::Path;
use std::process::Command;

/// `git` in the workspace, or `None` when it fails.
pub fn git(root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// The revision the ratchet compares against: the merge base with the target branch.
///
/// In a merge-request pipeline the qualifier fetches the current `dev` head, so `FETCH_HEAD` is
/// an ancestor of the candidate and is the base. On `dev` itself the base is the first parent,
/// which covers the whole merged change. `BUSBAR_LOC_BASE` names a base explicitly.
pub fn base_revision(root: &Path) -> Option<String> {
    let head = git(root, &["rev-parse", "HEAD"])?;
    let mut candidates = Vec::new();
    if let Ok(explicit) = std::env::var("BUSBAR_LOC_BASE") {
        candidates.push(explicit);
    }
    candidates.extend(
        ["FETCH_HEAD", "refs/remotes/origin/dev", "refs/heads/dev"]
            .into_iter()
            .map(str::to_string),
    );
    for candidate in candidates {
        let Some(commit) = git(
            root,
            &[
                "rev-parse",
                "--verify",
                "-q",
                &format!("{candidate}^{{commit}}"),
            ],
        ) else {
            continue;
        };
        if let Some(base) = git(root, &["merge-base", "HEAD", &commit]) {
            if base != head {
                return Some(base);
            }
        }
    }
    git(root, &["rev-parse", "--verify", "-q", "HEAD^1"])
}

/// A tracked file as it was at `revision`, or `None` when it did not exist there.
pub fn file_at(root: &Path, revision: &str, path: &str) -> Option<String> {
    git(root, &["show", &format!("{revision}:{path}")])
}
