// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PINNED PLANES, FOR THE TESTS THAT READ THE TREE OFF DISK (ARCHITECT row 106 (A),
//! condition 5).
//!
//! A plane crate that left this tree for its own repo (`GetBusbar/busbar-plane-<key>`) comes back as
//! a `git` row of the root `[workspace.dependencies]`, pinned at one rev, and cargo fetches its
//! checkout for the rev `Cargo.lock` pins. The xtask gates read it through their context's base
//! layer, laid at `crates/<package>`; a test here that reads the filesystem resolves the same
//! directory through this module, so a plane that left is read exactly as when it lived here.
//! Nothing is written into the tree: the bytes are read where cargo keeps them (spec #39, plugin
//! source never re-enters busbar).
//!
//! Generic over the plane KIND: a pinned row is a plane when its package is `busbar-plane-<key>`
//! and not the `-plugin` cdylib twin, the kind's own naming rule; no plane instance is named here.
//! FAILS CLOSED: a pinned plane cargo does not resolve panics, naming the package and its rev.

use std::path::{Path, PathBuf};

/// The kind prefix every plane package carries.
const PLANE_PREFIX: &str = "busbar-plane-";

/// The `-plugin` cdylib twin's suffix: a plugin repo's packaging crate, never the plane itself.
const TWIN_SUFFIX: &str = "-plugin";

/// The root manifest's pinned plane rows: `(package, rev)` for each `[workspace.dependencies]` row
/// naming a `git` source whose package is a plane.
pub fn pinned_rows(root: &Path) -> Vec<(String, String)> {
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).expect("the root Cargo.toml");
    let mut rows: Vec<(String, String)> = Vec::new();
    let mut inside = false;
    for raw in manifest.lines() {
        let t = raw.trim();
        if t.starts_with('[') {
            inside = t == "[workspace.dependencies]";
            continue;
        }
        if !inside || t.starts_with('#') {
            continue;
        }
        let Some((key, spec)) = t.split_once('=') else {
            continue;
        };
        if !spec.contains("git =") {
            continue;
        }
        let field = |name: &str| {
            spec.split_once(&format!("{name} = \""))
                .and_then(|(_, rest)| rest.split_once('"'))
                .map(|(v, _)| v.to_string())
        };
        let name = field("package").unwrap_or_else(|| key.trim().to_string());
        if !name.starts_with(PLANE_PREFIX)
            || name.ends_with(TWIN_SUFFIX)
            || rows.iter().any(|(n, _)| *n == name)
        {
            continue;
        }
        rows.push((name, field("rev").unwrap_or_else(|| "<no rev>".to_string())));
    }
    rows
}

/// Every pinned plane's checkout directory, as `cargo metadata` resolves it: `(package, dir)`.
///
/// # Panics
/// `cargo metadata` does not answer, or a pinned plane does not resolve to a `git` package (named,
/// with its rev).
pub fn pinned_dirs(root: &Path) -> Vec<(String, PathBuf)> {
    let rows = pinned_rows(root);
    if rows.is_empty() {
        return Vec::new();
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let out = std::process::Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .output()
        .unwrap_or_else(|e| {
            panic!("cargo metadata does not run ({e}); the pinned planes {rows:?} cannot be read")
        });
    assert!(
        out.status.success(),
        "cargo metadata failed; the pinned planes {rows:?} cannot be read: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("cargo metadata answers JSON");
    let packages = meta["packages"]
        .as_array()
        .expect("cargo metadata lists packages");
    rows.iter()
        .map(|(name, rev)| {
            let dir = packages
                .iter()
                .find(|p| {
                    p["name"] == name.as_str()
                        && p["source"].as_str().is_some_and(|s| s.starts_with("git+"))
                })
                .and_then(|p| p["manifest_path"].as_str())
                .and_then(|m| Path::new(m).parent())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| {
                    panic!("the pinned plane `{name}` at {rev} does not resolve in cargo metadata")
                });
            (name.clone(), dir)
        })
        .collect()
}

/// Where `rel` (a repo-relative path) is read: the tree's own file, or, under `crates/<package>/`
/// of a pinned plane no crate on disk is, that plane's checkout.
pub fn resolve(root: &Path, rel: &str) -> PathBuf {
    let on_disk = root.join(rel);
    if on_disk.exists() {
        return on_disk;
    }
    let Some(rest) = rel.strip_prefix("crates/") else {
        return on_disk;
    };
    let (package, inner) = rest.split_once('/').unwrap_or((rest, ""));
    if !package.starts_with(PLANE_PREFIX) || root.join("crates").join(package).exists() {
        return on_disk;
    }
    match pinned_dirs(root).into_iter().find(|(n, _)| n == package) {
        Some((_, dir)) if inner.is_empty() => dir,
        Some((_, dir)) => dir.join(inner),
        None => on_disk,
    }
}
