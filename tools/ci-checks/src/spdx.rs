// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `spdx-headers` (#277): every tracked source file carries `SPDX-License-Identifier: Apache-2.0`
//! in its first lines, and none names another licence. The tree is Apache-2.0 (LICENSE); a file
//! without the identifier is invisible to licence scanners and a file naming another one contradicts
//! LICENSE. In scope: every tracked `.rs` file, and the migration corpus (`tests/migration-corpus/`
//! YAML snapshots, which once carried the pre-relicence AGPL header).

use std::path::Path;
use std::process::Command;

use crate::Outcome;

/// The tag a header carries.
const TAG: &str = "SPDX-License-Identifier:";
/// The identifier every in-scope file names.
const WANT: &str = "Apache-2.0";
/// How far down a file the header may sit (a shebang and a blank line may be above it).
const HEAD_LINES: usize = 5;

/// Whether a repo-relative path is a source file the rule covers.
pub(crate) fn in_scope(path: &str) -> bool {
    path.ends_with(".rs")
        || (path.starts_with("tests/migration-corpus/")
            && (path.ends_with(".yaml") || path.ends_with(".yml")))
}

/// The finding for one file's text, if its header is missing or names another licence.
pub(crate) fn header_finding(path: &str, text: &str) -> Option<String> {
    let mut found = false;
    for line in text.lines().take(HEAD_LINES) {
        if let Some((_, id)) = line.split_once(TAG) {
            found = true;
            let id = id
                .trim()
                .trim_end_matches("*/")
                .trim_end_matches("-->")
                .trim();
            if id != WANT {
                return Some(format!(
                    "{path}: names `{id}`, but the tree is {WANT} (LICENSE; #277)"
                ));
            }
        }
    }
    (!found).then(|| format!("{path}: no `{TAG} {WANT}` in the first {HEAD_LINES} lines (#277)"))
}

pub(crate) fn spdx_headers(root: &Path) -> Outcome {
    let listed = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .map_err(|error| format!("git ls-files: {error}"))?;
    if !listed.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&listed.stderr).trim()
        ));
    }
    let mut findings = Vec::new();
    let mut checked = 0usize;
    for raw in listed.stdout.split(|byte| *byte == 0) {
        let Ok(path) = std::str::from_utf8(raw) else {
            findings.push(format!(
                "{}: a tracked path that is not UTF-8",
                String::from_utf8_lossy(raw)
            ));
            continue;
        };
        if !in_scope(path) {
            continue;
        }
        let file = root.join(path);
        let bytes = std::fs::read(&file).map_err(|error| format!("{path}: {error}"))?;
        checked += 1;
        findings.extend(header_finding(path, &String::from_utf8_lossy(&bytes)));
    }
    if checked == 0 {
        return Err("no tracked source file found: is this a git checkout?".to_owned());
    }
    Ok(findings)
}
