// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The backend pin travels with the commit (ABI promise: a published core commit is consumable by an
//! out-of-tree plugin with no `[patch]`).
//!
//! busbar-crypto names busbar-crypto-backend by core's git URL at an exact `rev`. Core's own roots patch
//! that URL to the path crate, so core always builds the backend of its own tree. A plugin pinned to a
//! core commit P (`.busbar-ref`) has no such patch: it builds P's facade against the backend at that
//! `rev`. The two agree only when the `rev`'s `crates/busbar-crypto-backend` tree is the tree at P.
//! At 787645cd49 they did not (the rev predated the backend API the facade calls), and every plugin
//! pinned there failed to compile busbar-contract.
//!
//! A commit cannot name itself, so a backend change takes two commits: the change, then the bump of
//! `rev` to a commit that carries it (after a merge that changes the backend, the merge). This test
//! makes the second commit mandatory: the tree at `rev` must equal this commit's, the same equality
//! busbar-release's plugin-checks check 3 asks from the plugin side. In a shallow clone it fetches
//! `rev` from `origin` (without touching FETCH_HEAD), as a plugin's cargo would.

use std::path::{Path, PathBuf};
use std::process::Command;

const BACKEND: &str = "crates/busbar-crypto-backend";
const CORE_URL: &str = "https://github.com/GetBusbar/busbar";

fn here() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn root() -> PathBuf {
    here().join("../..")
}

/// `git -C <root> <args>`: stdout on success, else the exit status and stderr.
fn git(args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root())
        .args(args)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(format!(
            "git {}: {}: {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// The value of `key = "..."` in one inline-table manifest row.
fn field<'a>(row: &'a str, key: &str) -> Option<&'a str> {
    let at = row.find(&format!("{key} = \""))? + key.len() + 4;
    let rest = &row[at..];
    Some(&rest[..rest.find('"')?])
}

/// The backend row of busbar-crypto's `[dependencies]`.
fn backend_row(manifest: &str) -> String {
    let mut section = "";
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line;
        } else if section == "[dependencies]" && line.starts_with("busbar-crypto-backend ") {
            return line.to_string();
        }
    }
    panic!("crates/busbar-crypto/Cargo.toml [dependencies] names no busbar-crypto-backend");
}

#[test]
fn backend_rev_carries_this_commits_backend() {
    let manifest = std::fs::read_to_string(here().join("Cargo.toml")).unwrap();
    let row = backend_row(&manifest);
    assert_eq!(
        field(&row, "git"),
        Some(CORE_URL),
        "the backend is named by core's URL, the one core's roots patch to {BACKEND}: {row}"
    );
    for moving in ["branch", "tag"] {
        assert!(
            field(&row, moving).is_none(),
            "the backend is named by an exact rev, not a {moving}: a {moving} resolves to whatever it \
             points at when a lock is refreshed, not to the consumer's .busbar-ref: {row}"
        );
    }
    let rev = field(&row, "rev").unwrap_or_else(|| panic!("the backend names no rev: {row}"));
    assert!(
        rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit()),
        "the backend rev is a full commit id: {rev}"
    );

    git(&["rev-parse", "--git-dir"])
        .unwrap_or_else(|e| panic!("this guard reads core's git history: {e}"));
    let want = git(&["rev-parse", &format!("HEAD:{BACKEND}")]).unwrap();
    let commit = format!("{rev}^{{commit}}");
    if git(&["cat-file", "-e", &commit]).is_err() {
        // `--no-write-fetch-head`: the architecture tests read FETCH_HEAD as their base candidate.
        git(&[
            "fetch",
            "-q",
            "--no-tags",
            "--no-write-fetch-head",
            "--depth=1",
            "origin",
            rev,
        ])
        .unwrap_or_else(|e| {
            panic!(
                "the backend rev {rev} cannot be fetched from origin, so no plugin can resolve it: {e}"
            )
        });
    }
    let have = git(&["rev-parse", &format!("{rev}:{BACKEND}")])
        .unwrap_or_else(|e| panic!("the backend rev {rev} has no {BACKEND}: {e}"));
    let changed = git(&["diff", "--stat", rev, "HEAD", "--", BACKEND]).unwrap_or_default();
    assert_eq!(
        have, want,
        "crates/busbar-crypto/Cargo.toml pins busbar-crypto-backend at {rev}, whose {BACKEND} tree is \
         {have}; this commit's is {want}. A plugin pinned to this commit would build the facade against \
         the backend at {rev}. Set rev to a commit that carries this commit's backend (after a backend \
         change lands, the next commit bumps rev to it).\n{changed}"
    );
}
