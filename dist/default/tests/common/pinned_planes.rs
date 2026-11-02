// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::{Path, PathBuf};

const PLANE_PREFIX: &str = "busbar-plane-";

const TWIN_SUFFIX: &str = "-plugin";

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
    let plane = package.strip_suffix(TWIN_SUFFIX).unwrap_or(package);
    let Some((_, dir)) = pinned_dirs(root).into_iter().find(|(n, _)| n == plane) else {
        return on_disk;
    };
    let dir = if plane == package {
        dir
    } else {
        match twin_dir(&dir, package) {
            Some(twin) => twin,
            None => return on_disk,
        }
    };
    if inner.is_empty() {
        dir
    } else {
        dir.join(inner)
    }
}

fn twin_dir(plane_dir: &Path, twin: &str) -> Option<PathBuf> {
    let workspace = plane_dir.ancestors().skip(1).find(|d| {
        std::fs::read_to_string(d.join("Cargo.toml"))
            .is_ok_and(|t| t.lines().any(|l| l.trim() == "[workspace]"))
    })?;
    let named = format!("name = \"{twin}\"");
    std::fs::read_dir(workspace)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|d| {
            std::fs::read_to_string(d.join("Cargo.toml"))
                .is_ok_and(|t| t.lines().any(|l| l.trim() == named))
        })
}
