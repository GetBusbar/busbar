// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2-SW-AUTH done check: auth runs on the MIN-3 path only (`ports::auth`, `adapters::auth`, the kernel
//! auth chain), so the old auth ABI is gone from the tree. Two arms: the files that carried it no longer
//! exist, and no Rust or manifest line outside a comment names it.

use std::path::{Path, PathBuf};

/// The files and directories the switch-over deletes (WBS W2-SW-AUTH row).
const DELETED: &[&str] = &[
    "crates/busbar-contract/src/abi/auth",
    "crates/busbar-contract/src/abi/sdk/auth_door.rs",
    "crates/busbar-contract/src/abi/sdk/auth_kit.rs",
    "crates/busbar-contract/src/abi/sdk/auth_outbound.rs",
    "crates/busbar-contract/src/abi/sdk/tests/auth_door_tests.rs",
    "crates/busbar-contract/src/abi/sdk/tests/auth_kit_tests.rs",
    "crates/busbar-contract/src/abi/sdk/tests/auth_outbound_tests.rs",
    "crates/busbar-contract/src/auth_calls.rs",
    "crates/busbar-contract/src/auth_calls",
    "crates/plugin-loader/src/dispatch/kinds/auth.rs",
    "crates/plugin-loader/src/auth_door.rs",
    "crates/plugin-loader/src/auth_axis.rs",
    "crates/plugin-loader/src/auth_login.rs",
    "crates/plugin-loader/src/cold/auth_door.rs",
    "crates/plugin-loader/src/cold/auth_axis.rs",
    "crates/plugin-loader/src/tests/auth_door_tests.rs",
    "crates/plugin-loader/src/tests/auth_axis_tests.rs",
    "crates/plugin-loader/tests/fixtures/neutral_auth_door.rs",
];

/// Names only the old auth ABI uses. The MIN-3 auth kind is `busbar_plugin_abi::kinds::auth` and the loader's
/// `ports::auth` / `adapters::auth`, none of which contains these.
const NAMES: &[&str] = &[
    "busbar_contract::abi::auth",
    "crate::abi::auth",
    "auth_calls",
    "sdk::auth_door",
    "sdk::auth_kit",
    "sdk::auth_outbound",
    "dispatch::auth_outbound",
    "dispatch::kinds::auth",
    "::auth_door",
    "::auth_axis",
    "::auth_login",
    "mod auth_door",
    "mod auth_axis",
    "mod auth_login",
    "mod auth_outbound",
    "mod auth_kit",
    "neutral_auth_door",
    "AuthAxis",
    "AuthCalls",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs" || e == "toml") {
            out.push(path);
        }
    }
}

#[test]
fn the_old_auth_abi_files_are_deleted() {
    let root = root();
    let left: Vec<&str> = DELETED
        .iter()
        .copied()
        .filter(|p| root.join(p).exists())
        .collect();
    assert!(
        left.is_empty(),
        "old auth ABI files still present: {left:#?}"
    );
}

#[test]
fn no_old_auth_abi_reference() {
    let root = root();
    let this = Path::new(file!())
        .file_name()
        .expect("this file's name")
        .to_owned();
    let mut files = Vec::new();
    for top in ["crates", "tools", "testing", "dist"] {
        walk(&root.join(top), &mut files);
    }
    let mut hits = Vec::new();
    for file in files {
        if file.file_name() == Some(this.as_os_str()) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//")
                || code.starts_with('#')
                || code.starts_with("/*")
                || code.starts_with('*')
            {
                continue;
            }
            if let Some(name) = NAMES.iter().find(|name| code.contains(*name)) {
                let rel = file.strip_prefix(&root).unwrap_or(&file);
                hits.push(format!("{}:{}: {name}", rel.display(), n + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "{} line(s) still name the old auth ABI:\n{}",
        hits.len(),
        hits.join("\n")
    );
}
