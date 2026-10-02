// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `test-seal` FEATURE MAY NEVER REACH A RELEASE BUILD.
//!
//! #65 sealed [`busbar_contract::plugin::KernelSeal`]: the supertrait that closes it lives in a
//! `pub(crate)` module, so no crate outside this one can implement it. That is a compiler
//! guarantee and the `compile_fail` fixture on the trait proves it.
//!
//! The one deliberate exception is `plugin::TestKernelSeal`, gated on the `test-seal` feature,
//! which exists because a PLANE crate may not name [`busbar_contract::caps`] (ARCHITECTURE section
//! 1.2, asserted from the inside by each plane's own `purity` test) and therefore cannot mint a
//! real capability token for its own fixtures. `qa/construction.toml`'s `kernel-seal-impls` rule
//! named both the gap and the remedy: *"their test seals cannot move onto a token until the
//! contract offers a seal a plane is allowed to name"*.
//!
//! An exception that anything could switch on would put the forgery straight back. Cargo features
//! are ADDITIVE and unify across a build graph, so a single non-dev edge declaring
//! `features = ["test-seal"]` would compile `TestKernelSeal` into the release artifact and hand
//! every crate in the workspace a seal it never had to earn. This test is what stops that being a
//! thing anyone can do quietly: the feature may be named ONLY under `[dev-dependencies]` (or
//! `[dev-dependencies.busbar-contract]`), never under `[dependencies]`, `[build-dependencies]` or
//! a `[target.*]` table of either.
//!
//! This is a source scan, and unlike the scan it replaces it is guarding an exception rather than
//! standing in for a type-system rule that does not exist: the trait is genuinely sealed either
//! way, and what is checked here is only whether the ONE escape hatch stayed dev-only.

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
/// `[target.'cfg(..)'.dev-dependencies]` forms.
fn is_dev_section(section: &str) -> bool {
    let inner = section.trim_start_matches('[').trim_end_matches(']');
    inner
        .split('.')
        .any(|seg| seg.trim_matches(|c| c == '\'' || c == '"') == "dev-dependencies")
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

    // This crate's own manifest DECLARES the feature (`test-seal = []` under `[features]`); that is
    // the definition, not an edge that turns it on.
    let own_manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

    let mut offenders = Vec::new();
    let mut dev_edges = 0usize;
    for manifest in &found {
        let Ok(text) = std::fs::read_to_string(manifest) else {
            continue;
        };
        if !text.contains("test-seal") {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || !trimmed.contains("test-seal") {
                continue;
            }
            let section = section_of(&lines, n);
            if *manifest == own_manifest && section == "[features]" {
                continue;
            }
            if is_dev_section(&section) {
                dev_edges += 1;
                continue;
            }
            offenders.push(format!(
                "{}:{} under {} -> {}",
                manifest
                    .strip_prefix(&root)
                    .unwrap_or(manifest.as_path())
                    .display(),
                n + 1,
                section,
                trimmed
            ));
        }
    }

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
