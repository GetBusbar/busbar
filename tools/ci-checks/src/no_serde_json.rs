// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `no-serde-json` (DEP-3, SERDE-JSON-EXIT §4 MR 6/7, #162): JSON is sonic-rs through
//! `busbar_contract::json`, so no first-party Rust file under `crates/`, `dist/`, `tools/` or
//! `testing/` names the `serde_json` crate (production and tests alike), and no first-party manifest
//! there depends on it. A third-party crate may still pull serde_json in; cargo-deny's `wrappers`
//! row governs that, not this check.
//!
//! The old ABI that wave 3 deletes still names it. Those paths are listed, with the wave-3 task that
//! deletes or rewrites each, in `ci/serde-json-w3.allow`. The list only shrinks: an entry under
//! which no file names serde_json any more is itself a finding, so the line goes with the code.
//!
//! The scan reads tokens, not text: a comment, a doc comment or a string literal that spells
//! `serde_json` (a test fixture's `$serde_json::private::Number` key) is not a use. A file that does
//! not lex is scanned line by line instead, so it is never skipped.

use std::path::{Path, PathBuf};
use std::str::FromStr;

use proc_macro2::{TokenStream, TokenTree};

use super::{rel, sorted_entries, Outcome};

/// The allowlist of wave-3 paths, relative to the repository root.
pub(crate) const ALLOW_FILE: &str = "ci/serde-json-w3.allow";

/// The trees scanned for first-party code.
const ROOTS: [&str; 4] = ["crates", "dist", "tools", "testing"];

/// The crate name the check refuses.
const CRATE: &str = "serde_json";

pub(crate) fn no_serde_json(root: &Path) -> Outcome {
    let allow_text = std::fs::read_to_string(root.join(ALLOW_FILE))
        .map_err(|error| format!("{ALLOW_FILE}: {error}"))?;
    let allow = allow_entries(&allow_text);
    let mut files = Vec::new();
    for dir in ROOTS {
        let dir = root.join(dir);
        if dir.is_dir() {
            first_party_files(&dir, &mut files)?;
        }
    }
    let mut findings = Vec::new();
    let mut used = vec![false; allow.len()];
    for file in files {
        let path = rel(root, &file);
        let text = std::fs::read_to_string(&file).map_err(|error| format!("{path}: {error}"))?;
        let lines = if file.extension().is_some_and(|ext| ext == "rs") {
            rust_uses(&text)
        } else {
            manifest_uses(&text)
        };
        if lines.is_empty() {
            continue;
        }
        if let Some(at) = allow.iter().position(|entry| covers(entry, &path)) {
            used[at] = true;
            continue;
        }
        for line in lines {
            findings.push(format!(
                "{path}:{line}: names serde_json; JSON is busbar_contract::json (sonic-rs, DEP-3)"
            ));
        }
    }
    for (entry, used) in allow.iter().zip(used) {
        if !used {
            findings.push(format!(
                "{ALLOW_FILE}: `{entry}` names no file that uses serde_json any more; delete the line"
            ));
        }
    }
    Ok(findings)
}

/// The allowlist's path prefixes: one per line, `#` starts a comment.
pub(crate) fn allow_entries(text: &str) -> Vec<String> {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or_default().trim())
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Whether an allowlist entry covers a repository path: the file itself, or a directory entry
/// (ending in `/`) above it.
pub(crate) fn covers(entry: &str, path: &str) -> bool {
    if entry.ends_with('/') {
        path.starts_with(entry)
    } else {
        path == entry
    }
}

/// Every `.rs` file and `Cargo.toml` under `dir`, in path order, skipping build output.
fn first_party_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for path in sorted_entries(dir)? {
        if path.is_dir() {
            if !path.file_name().is_some_and(|name| name == "target") {
                first_party_files(&path, out)?;
            }
        } else if path.extension().is_some_and(|ext| ext == "rs")
            || path.file_name().is_some_and(|name| name == "Cargo.toml")
        {
            out.push(path);
        }
    }
    Ok(())
}

/// The lines of a Rust source on which the `serde_json` identifier appears as code.
pub(crate) fn rust_uses(text: &str) -> Vec<usize> {
    let mut lines = Vec::new();
    match TokenStream::from_str(text) {
        Ok(tokens) => idents(tokens, &mut lines),
        Err(_) => {
            for (index, line) in text.lines().enumerate() {
                let code = line.trim_start();
                if !code.starts_with("//") && code.contains(CRATE) {
                    lines.push(index + 1);
                }
            }
        }
    }
    lines.dedup();
    lines
}

fn idents(tokens: TokenStream, lines: &mut Vec<usize>) {
    for token in tokens {
        match token {
            TokenTree::Ident(ident) if ident == CRATE => lines.push(ident.span().start().line),
            TokenTree::Group(group) => idents(group.stream(), lines),
            _ => {}
        }
    }
}

/// The lines of a manifest that declare a `serde_json` dependency (`serde_json = ...`,
/// `serde_json.workspace = true`, or a `[dependencies.serde_json]` table).
pub(crate) fn manifest_uses(text: &str) -> Vec<usize> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| {
            let line = line.trim_start();
            let key = line
                .strip_prefix('[')
                .map_or(line, |table| table.rsplit('.').next().unwrap_or(table));
            key.strip_prefix(CRATE).is_some_and(|rest| {
                let rest = rest.trim_start();
                rest.starts_with('=') || rest.starts_with('.') || rest.starts_with(']')
            })
        })
        .map(|(index, _)| index + 1)
        .collect()
}

#[cfg(test)]
#[path = "no_serde_json_tests.rs"]
mod no_serde_json_tests;
