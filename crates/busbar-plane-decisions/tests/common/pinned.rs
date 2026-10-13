// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PINNED SIBLING PLANES (ARCHITECT row 106 (A)): a plane that left the tree for its own repo is
//! still a sibling. The root pins it as a git row; cargo resolves its checkout. Shared by this
//! crate's `invariance.rs` and `purity.rs`.

use std::path::Path;

/// The root manifest's pinned plane rows, `(package, rev)`: each `[workspace.dependencies]` row
/// naming a `git` source whose package is a plane (`busbar-plane-<key>`, the kind's own naming rule;
/// never its `-plugin` cdylib twin), each held to resolve in `cargo metadata`.
pub fn pinned_planes(crates_dir: &Path) -> Vec<(String, String)> {
    let root = crates_dir.parent().expect("crates/ sits in the workspace");
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("the root Cargo.toml");
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut inside = false;
    for raw in manifest.lines() {
        let t = raw.trim();
        if t.starts_with('[') {
            inside = t == "[workspace.dependencies]";
            continue;
        }
        let Some((key, spec)) = t.split_once('=').filter(|_| inside && !t.starts_with('#')) else {
            continue;
        };
        let field = |name: &str| {
            spec.split_once(&format!("{name} = \""))
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(v, _)| v.to_string())
        };
        let name = field("package").unwrap_or_else(|| key.trim().to_string());
        if spec.contains("git =")
            && name.starts_with("busbar-plane-")
            && !name.ends_with("-plugin")
            && !rows.iter().any(|(n, _)| *n == name)
        {
            rows.push((name, field("rev").unwrap_or_default()));
        }
    }
    if rows.is_empty() {
        return rows;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata failed; the pinned planes {rows:?} cannot be resolved"
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata JSON");
    for (name, rev) in &rows {
        let resolved = meta["packages"].as_array().is_some_and(|ps| {
            ps.iter().any(|p| {
                p["name"] == name.as_str()
                    && p["source"].as_str().is_some_and(|s| s.starts_with("git+"))
            })
        });
        assert!(
            resolved,
            "the pinned plane `{name}` at {rev} does not resolve in cargo metadata"
        );
    }
    rows
}
