// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `test-seal` FEATURE MAY NEVER REACH A RELEASE BUILD.

use std::path::{Path, PathBuf};

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("busbar-contract lives two levels under the workspace root")
        .to_path_buf()
}

/// Every `Cargo.toml` in the workspace, skipping build output and any vendored tree.
fn manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name == "vendor" || name == "node_modules" {
                continue;
            }
            manifests(&path, out);
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// Which table a manifest line sits under, tracked by the last `[header]` seen.
fn section_of(lines: &[&str], idx: usize) -> String {
    lines[..=idx]
        .iter()
        .rev()
        .find_map(|l| {
            let t = l.trim();
            (t.starts_with('[') && t.ends_with(']')).then(|| t.to_string())
        })
        .unwrap_or_else(|| "<no section>".to_string())
}

/// A section that is dev-only: `[dev-dependencies]`, `[dev-dependencies.x]`, and the

fn is_dev_section(section: &str) -> bool {
    let inner = section.trim_start_matches('[').trim_end_matches(']');
    inner
        .split('.')
        .any(|seg| seg.trim_matches(|c| c == '\'' || c == '"') == "dev-dependencies")
}

/// Every line of one manifest's `text` naming `feature` outside a dev-only table, and how many dev

fn offenders_in(feature: &str, text: &str, own: bool, label: &str) -> (Vec<String>, usize) {
    let mut offenders = Vec::new();
    let mut dev_edges = 0usize;
    let lines: Vec<&str> = text.lines().collect();
    for (n, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains(feature) {
            continue;
        }
        let section = section_of(&lines, n);
        if own && section == "[features]" {
            let key = trimmed.split('=').next().unwrap_or_default().trim();
            let value = trimmed.split_once('=').map(|(_, v)| v).unwrap_or_default();
            if key == feature && !value.contains(feature) {
                continue;
            }
        }
        if is_dev_section(&section) {
            dev_edges += 1;
            continue;
        }
        offenders.push(format!(
            "{label}:{} under {} -> {}",
            n + 1,
            section,
            trimmed
        ));
    }
    (offenders, dev_edges)
}

/// Every manifest line naming `feature` outside a dev-only table, and how many dev edges name it.
fn edges_of(feature: &str, found: &[PathBuf], root: &Path) -> (Vec<String>, usize) {
    let own_manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let mut offenders = Vec::new();
    let mut dev_edges = 0usize;
    for manifest in found {
        let Ok(text) = std::fs::read_to_string(manifest) else {
            continue;
        };
        if !text.contains(feature) {
            continue;
        }
        let label = manifest
            .strip_prefix(root)
            .unwrap_or(manifest.as_path())
            .display()
            .to_string();
        let (o, d) = offenders_in(feature, &text, *manifest == own_manifest, &label);
        offenders.extend(o);
        dev_edges += d;
    }
    (offenders, dev_edges)
}

#[test]
fn the_test_seal_feature_is_named_only_on_dev_dependency_edges() {
    let root = workspace_root();
    let mut found = Vec::new();
    manifests(&root, &mut found);
    assert!(
        found.len() > 10,
        "manifest walk found only {} Cargo.toml files under {} — the walk is broken, and a broken \
         walk would pass this test while checking nothing",
        found.len(),
        root.display()
    );

    let (offenders, dev_edges) = edges_of("test-seal", &found, &root);

    assert!(
        offenders.is_empty(),
        "`test-seal` is enabled outside [dev-dependencies]. That compiles \
         `plugin::TestKernelSeal` — an implementor of the SEALED `KernelSeal` trait — into a \
         RELEASE build, which re-opens the #65 forgery for every crate in the graph. Move these to \
         [dev-dependencies] or drop them:\n  {}",
        offenders.join("\n  ")
    );

    assert!(
        dev_edges > 0,
        "no crate enables `test-seal` on a dev edge, so this test just proved nothing. Either the \
         fixtures stopped using `plugin::TestKernelSeal` (then delete the feature and this test) \
         or the scan stopped matching (then fix the scan)."
    );
}

/// RED PLANTS for the dev-edge scan the rules above run: each manifest below turns `test-seal` on

#[test]
fn the_dev_edge_scan_refuses_every_non_dev_edge() {
    const F: &str = "test-seal";
    let pin = r#"busbar-contract = { git = "https://github.com/GetBusbar/busbar", rev = "0", features = ["test-seal"] }"#;

    let (o, d) = offenders_in(F, &format!("[dev-dependencies]\n{pin}\n"), false, "plant");
    assert!(o.is_empty(), "{o:?}");
    assert_eq!(d, 1);

    let (o, _) = offenders_in(
        F,
        "[dev-dependencies.busbar-contract]\nfeatures = [\"test-seal\"]\n",
        false,
        "plant",
    );
    assert!(o.is_empty(), "{o:?}");
    let (o, _) = offenders_in(
        F,
        &format!("[target.'cfg(unix)'.dev-dependencies]\n{pin}\n"),
        false,
        "plant",
    );
    assert!(o.is_empty(), "{o:?}");

    let (o, _) = offenders_in(F, "[features]\ntest-seal = []\n", true, "own");
    assert!(o.is_empty(), "{o:?}");

    for planted in [
        format!("[dependencies]\n{pin}\n"),
        "[dependencies.busbar-contract]\nfeatures = [\"test-seal\"]\n".to_string(),
        format!("[build-dependencies]\n{pin}\n"),
        format!("[target.'cfg(unix)'.dependencies]\n{pin}\n"),
        "[features]\ndefault = [\"busbar-contract/test-seal\"]\n".to_string(),
        "[features]\ngates = [\"busbar-contract/test-seal\"]\n".to_string(),
        format!("[workspace.dependencies]\n{pin}\n"),
    ] {
        let (o, _) = offenders_in(F, &planted, false, "plant");
        assert_eq!(o.len(), 1, "not refused:\n{planted}");
    }

    for planted in [
        "[features]\ndefault = [\"test-seal\"]\ntest-seal = []\n",
        "[features]\ntest-seal = []\ntest-seal = [\"test-seal\"]\n",
    ] {
        let (o, _) = offenders_in(F, planted, true, "own");
        assert_eq!(o.len(), 1, "not refused:\n{planted}");
    }
}
