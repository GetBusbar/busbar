// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST-ONLY FEATURES MAY NEVER REACH A RELEASE BUILD: `test-seal`, `test-support`, `abi-scan`
//! (the contract's and the loader's) and the facade's `kernel-parity` (SDK-SAFE-TEST-HOST §10.6, T-GUARD).
//!
//! The walk covers root-workspace members only: a directory whose `Cargo.toml` declares its own
//! `[workspace]` (`tools/plugin-bench`, `tools/system-hammer`, `dist/default`) is a separate build and is
//! skipped, so the bench's deliberate `test-support` never false-reds. `dist/default`, the shipped
//! build's workspace, is scanned by name. The facade (`crates/busbar-plugin-test`) is the one named
//! exception: its normal dependencies carry the features by design. What the shipped `busbar` binary
//! resolves is asserted by the `cargo tree` step in busbar-release `ci/core.yml`.

use std::path::{Path, PathBuf};

/// The features that are test-only everywhere. A `[features]` entry whose key is one of these only
/// composes test-only features, so defining or forwarding it is not an enabling edge.
const GUARDED: [&str; 5] = [
    "test-seal",
    "test-support",
    "abi-scan",
    "kernel-parity",
    "stage-probe",
];

/// The facade's manifest, relative to the workspace root.
const FACADE: &str = "crates/busbar-plugin-test/Cargo.toml";

/// The workspace root, from this crate's manifest directory.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("busbar-contract lives two levels under the workspace root")
        .to_path_buf()
}

/// Whether a manifest's text declares its own `[workspace]` (a separate build).
fn declares_workspace(text: &str) -> bool {
    text.lines().any(|l| {
        let t = l.trim();
        t == "[workspace]" || t.starts_with("[workspace.")
    })
}

/// Every `Cargo.toml` of a root-workspace member, skipping build output, vendored trees and any
/// directory that declares its own `[workspace]`.
fn manifests(dir: &Path, root: &Path, out: &mut Vec<PathBuf>) {
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
            if path != root {
                if let Ok(text) = std::fs::read_to_string(path.join("Cargo.toml")) {
                    if declares_workspace(&text) {
                        continue;
                    }
                }
            }
            manifests(&path, root, out);
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
/// `[target.'cfg(..)'.dev-dependencies]` forms.
fn is_dev_section(section: &str) -> bool {
    let inner = section.trim_start_matches('[').trim_end_matches(']');
    inner
        .split('.')
        .any(|seg| seg.trim_matches(|c| c == '\'' || c == '"') == "dev-dependencies")
}

/// Every line of one manifest's `text` naming `feature` outside a dev-only table, and how many dev
/// edges name it. A `[features]` entry whose key is itself a guarded feature is a definition (or a
/// forward gated by that key), not an enabling edge, unless its value names the key itself.
fn offenders_in(feature: &str, text: &str, label: &str) -> (Vec<String>, usize) {
    let mut offenders = Vec::new();
    let mut dev_edges = 0usize;
    let lines: Vec<&str> = text.lines().collect();
    for (n, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || !trimmed.contains(feature) {
            continue;
        }
        let section = section_of(&lines, n);
        if section == "[features]" {
            let key = trimmed.split('=').next().unwrap_or_default().trim();
            let value = trimmed.split_once('=').map(|(_, v)| v).unwrap_or_default();
            let names_itself = value
                .split([',', '[', ']'])
                .any(|item| item.trim().trim_matches('"') == key);
            if GUARDED.contains(&key) && !names_itself {
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

/// The path of `manifest` relative to the workspace root, `/`-separated.
fn label_of(manifest: &Path, root: &Path) -> String {
    manifest
        .strip_prefix(root)
        .unwrap_or(manifest)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Every manifest line naming `feature` outside a dev-only table, and how many dev edges name it.
/// `facade_exempt` leaves the facade's own manifest out of the offenders: its normal dependencies
/// carry the test-only features by design.
fn edges_of(
    feature: &str,
    found: &[PathBuf],
    root: &Path,
    facade_exempt: bool,
) -> (Vec<String>, usize) {
    let mut offenders = Vec::new();
    let mut dev_edges = 0usize;
    for manifest in found {
        let Ok(text) = std::fs::read_to_string(manifest) else {
            continue;
        };
        if !text.contains(feature) {
            continue;
        }
        let label = label_of(manifest, root);
        let (o, d) = offenders_in(feature, &text, &label);
        if !(facade_exempt && label == FACADE) {
            offenders.extend(o);
        }
        dev_edges += d;
    }
    (offenders, dev_edges)
}

/// The root-workspace member manifests, plus `dist/default`'s (the shipped build's workspace).
fn scanned() -> (PathBuf, Vec<PathBuf>) {
    let root = workspace_root();
    let mut found = Vec::new();
    manifests(&root, &root, &mut found);
    assert!(
        found.len() > 10,
        "manifest walk found only {} Cargo.toml files under {} — the walk is broken, and a broken \
         walk would pass this test while checking nothing",
        found.len(),
        root.display()
    );
    assert!(
        !found
            .iter()
            .any(|m| label_of(m, &root).starts_with("tools/plugin-bench/")),
        "the walk entered tools/plugin-bench, a separate workspace: it would false-red on its \
         deliberate `test-support`"
    );
    found.push(root.join("dist/default/Cargo.toml"));
    (root, found)
}

#[test]
fn the_test_seal_feature_is_named_only_on_dev_dependency_edges() {
    let (root, found) = scanned();
    let (offenders, dev_edges) = edges_of("test-seal", &found, &root, false);

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

/// `test-support` and `abi-scan` open test-only items (`#[cfg(any(test, feature = "test-support"))]`)
/// in the contract and the loader. Only dev edges may enable them, and the facade's normal edges.
#[test]
fn test_support_and_abi_scan_are_named_only_on_dev_edges_or_the_facade() {
    let (root, found) = scanned();
    for feature in ["test-support", "abi-scan"] {
        let (offenders, dev_edges) = edges_of(feature, &found, &root, true);
        assert!(
            offenders.is_empty(),
            "`{feature}` is enabled outside [dev-dependencies] (the facade `{FACADE}` excepted), which \
             compiles test-only items into a release build. Move these to [dev-dependencies] or \
             drop them:\n  {}",
            offenders.join("\n  ")
        );
        if feature == "test-support" {
            assert!(
                dev_edges > 0,
                "no crate enables `test-support` on a dev edge: the scan stopped matching"
            );
        }
    }
    let facade = std::fs::read_to_string(root.join(FACADE)).expect("the facade manifest exists");
    assert!(
        facade.contains("test-support") && facade.contains("abi-scan"),
        "the facade no longer carries `test-support` and `abi-scan`: the named exception is stale"
    );
}

/// `kernel-parity` (the facade's raw-handle feature) is enabled by exactly one manifest:
/// `dist/default`'s `[dev-dependencies]`. No root-workspace member names it but the facade defining it.
#[test]
fn kernel_parity_is_enabled_only_by_dist_default_dev_dependencies() {
    let (root, found) = scanned();
    let mut offenders = Vec::new();
    for manifest in &found {
        let label = label_of(manifest, &root);
        if label == FACADE {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(manifest) else {
            continue;
        };
        if label == "dist/default/Cargo.toml" {
            offenders.extend(offenders_in("kernel-parity", &text, &label).0);
        } else {
            for (n, line) in text.lines().enumerate() {
                if !line.trim().starts_with('#') && line.contains("kernel-parity") {
                    offenders.push(format!("{label}:{} -> {}", n + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "`kernel-parity` is enabled somewhere other than dist/default's [dev-dependencies]; it hands a \
         test the raw `PlaneCalls` handle:\n  {}",
        offenders.join("\n  ")
    );
}

/// RED PLANTS for the dev-edge scan the rules above run: each manifest below turns a guarded feature
/// on somewhere a release build would see it.
#[test]
fn the_dev_edge_scan_refuses_every_non_dev_edge() {
    for f in GUARDED {
        let pin = format!(
            r#"busbar-contract = {{ git = "https://github.com/GetBusbar/busbar", rev = "0", features = ["{f}"] }}"#
        );

        let (o, d) = offenders_in(f, &format!("[dev-dependencies]\n{pin}\n"), "plant");
        assert!(o.is_empty(), "{o:?}");
        assert_eq!(d, 1);

        let (o, _) = offenders_in(
            f,
            &format!("[dev-dependencies.busbar-contract]\nfeatures = [\"{f}\"]\n"),
            "plant",
        );
        assert!(o.is_empty(), "{o:?}");
        let (o, _) = offenders_in(
            f,
            &format!("[target.'cfg(unix)'.dev-dependencies]\n{pin}\n"),
            "plant",
        );
        assert!(o.is_empty(), "{o:?}");

        // Defining the feature, or forwarding it from itself, enables nothing.
        let (o, _) = offenders_in(f, &format!("[features]\n{f} = []\n"), "own");
        assert!(o.is_empty(), "{o:?}");
        let (o, _) = offenders_in(
            f,
            &format!("[features]\n{f} = [\"busbar-contract/{f}\"]\n"),
            "own",
        );
        assert!(o.is_empty(), "{o:?}");

        for planted in [
            format!("[dependencies]\n{pin}\n"),
            format!("[dependencies.busbar-contract]\nfeatures = [\"{f}\"]\n"),
            format!("[build-dependencies]\n{pin}\n"),
            format!("[target.'cfg(unix)'.dependencies]\n{pin}\n"),
            format!("[features]\ndefault = [\"busbar-contract/{f}\"]\n"),
            format!("[features]\ngates = [\"busbar-contract/{f}\"]\n"),
            format!("[workspace.dependencies]\n{pin}\n"),
            format!("[features]\ndefault = [\"{f}\"]\n{f} = []\n"),
            format!("[features]\n{f} = []\n{f} = [\"{f}\"]\n"),
        ] {
            let (o, _) = offenders_in(f, &planted, "plant");
            assert_eq!(o.len(), 1, "not refused:\n{planted}");
        }
    }
}

/// A manifest that declares its own `[workspace]` is a separate build, so the walk leaves it out.
#[test]
fn a_separate_workspace_is_not_walked() {
    assert!(declares_workspace(
        "[package]\nname = \"x\"\n\n[workspace]\n"
    ));
    assert!(declares_workspace("[workspace.dependencies]\n"));
    assert!(!declares_workspace(
        "[package]\nname = \"x\"\n[dependencies]\n"
    ));
}

/// THE `stage-probe` COUNTERS MAY NEVER REACH A RELEASE BUILD EITHER (SINGLE-PATH §8): the same
/// dev-edge scan, for the single-path count probes.
#[test]
fn the_stage_probe_feature_is_named_only_on_dev_dependency_edges() {
    let (root, found) = scanned();
    let (offenders, dev_edges) = edges_of("stage-probe", &found, &root, false);

    assert!(
        offenders.is_empty(),
        "`stage-probe` is enabled outside [dev-dependencies], which puts the single-path count \
         probes into a release build. Move these to [dev-dependencies] or drop them:\n  {}",
        offenders.join("\n  ")
    );
    assert!(
        dev_edges > 0,
        "no crate enables `stage-probe` on a dev edge, so the single-path count tests prove \
         nothing. Either delete the feature and this test or fix the scan."
    );
}
