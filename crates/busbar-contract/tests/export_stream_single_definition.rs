// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-EXPORT-STREAMS (a), as a source check: the workspace holds exactly one definition of the
//! export-stream vocabulary, and it lives in `busbar_contract::export_stream`.

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn export_stream_has_exactly_one_definition_in_export_stream_rs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Built at run time so this file does not match its own search.
    let needle = format!("pub enum {}", "ExportStream");
    let mut files = Vec::new();
    for top in ["crates", "tools", "dist"] {
        rust_files(&root.join(top), &mut files);
    }
    let mut found: Vec<String> = files
        .iter()
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|t| t.lines().any(|l| l.trim_start().starts_with(&needle)))
                .unwrap_or(false)
        })
        .map(|p| {
            p.strip_prefix(&root)
                .unwrap_or(p)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        ["crates/busbar-contract/src/export_stream.rs".to_string()],
        "ExportStream must be defined exactly once, in crates/busbar-contract/src/export_stream.rs"
    );
}
