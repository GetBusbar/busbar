// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! ONE ORACLE, ONE PIN: the shadow oracle is the Rust `busbar-oracle` engine named by
//! `testing/shadow-oracle/oracle-rust.pin`, and its `mock` subcommand is the one upstream far end.
//! A second pin file or a Python mock upstream reappearing means two judges (or two far ends) can
//! drift, so either one fails here (docs/design/1.6.0-TODO.md, the stock-take defect "oracle.pin and
//! the mock-upstream Python path").

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

/// Every file under `dir`, skipping build output and VCS metadata.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if p.is_dir() {
            if !matches!(name.as_ref(), "target" | ".git" | "node_modules" | ".lk") {
                walk(&p, out);
            }
        } else {
            out.push(p);
        }
    }
}

fn all_files() -> Vec<PathBuf> {
    let mut v = Vec::new();
    walk(&repo_root(), &mut v);
    v
}

#[test]
fn the_oracle_has_exactly_one_pin_file() {
    let pins: Vec<String> = all_files()
        .iter()
        .filter(|p| p.extension().is_some_and(|e| e == "pin"))
        .filter(|p| {
            p.parent()
                .is_some_and(|d| d.ends_with("testing/shadow-oracle"))
        })
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        pins,
        ["oracle-rust.pin"],
        "testing/shadow-oracle must hold exactly one pin, oracle-rust.pin"
    );
}

#[test]
fn no_python_mock_upstream_exists() {
    let bad: Vec<_> = all_files()
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "py"))
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .contains("mock-upstream")
        })
        .collect();
    assert!(
        bad.is_empty(),
        "an upstream mock is the oracle engine's `mock` subcommand, never a .py: {bad:?}"
    );
}
