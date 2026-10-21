// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATOR SURFACE'S TESTS LINK NO PLUGIN (THE DESIGN §1, BUSBAR-1.6.0.md l.179-181: "Kernel
//! tests use kind-neutral doubles ... The one place a plugin name appears is the composition root's
//! manifest: its `Cargo.toml` dependency, its feature and its linked row. The cleanliness crates
//! (§8) obey the same rule.").
//!
//! This crate's manifest names the kernel's crates and third-party libraries, and nothing that is a
//! plugin: no plugin crate as a dependency of any kind, no metadata table listing plugins to link
//! into the tests, no feature forwarding into a plugin, and no build script generating a table of
//! them. Its unit tests run against the kernel's kind-neutral doubles; a cell that asserts a real
//! plane's behaviour lives in the composition root's tests, where the plugins are linked.

/// The workspace crates a cleanliness crate's manifest may name: the kernel's and the contract.
fn kind_neutral(dep: &str) -> bool {
    dep == "busbar-kernel" || dep == "busbar-contract" || dep.starts_with("busbar-kernel-")
}

/// Every `busbar-*` crate the manifest names in a dependency table, with the table.
fn busbar_dependencies(manifest: &str) -> Vec<(String, String)> {
    let mut table = String::new();
    let mut out = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            table = code.to_string();
            continue;
        }
        if !table.ends_with("dependencies]") {
            continue;
        }
        if let Some((name, _)) = code.split_once('=') {
            let name = name.trim();
            if name.starts_with("busbar-") {
                out.push((table.clone(), name.to_string()));
            }
        }
    }
    out
}

/// RED while the manifest named a plane crate and the operator-auth plugin as dev-dependencies,
/// listed them as `[package.metadata.busbar]` rows a build script turned into linked tables, and
/// forwarded a feature into the plane.
#[test]
fn the_admin_crates_manifest_names_no_plugin() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("the manifest reads");
    let deps = busbar_dependencies(&manifest);
    assert!(
        deps.iter().any(|(_, d)| d == "busbar-kernel"),
        "the manifest scan found no kernel dependency: it reads nothing"
    );
    let plugins: Vec<&(String, String)> = deps.iter().filter(|(_, d)| !kind_neutral(d)).collect();
    assert!(
        plugins.is_empty(),
        "the cleanliness crate's manifest names a plugin crate: {plugins:?}"
    );
    assert!(
        !manifest.contains("[package.metadata.busbar]"),
        "the manifest lists plugins for a build script to link into the tests"
    );
    assert!(
        !dir.join("build.rs").exists(),
        "a build script generates a linked-plugin table for the tests"
    );
    let forwards: Vec<&str> = manifest
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .filter(|l| {
            l.split('"')
                .skip(1)
                .step_by(2)
                .filter_map(|f| f.split_once('/'))
                .any(|(krate, _)| krate.starts_with("busbar-") && !kind_neutral(krate))
        })
        .collect();
    assert!(
        forwards.is_empty(),
        "a feature forwards into a plugin crate: {forwards:?}"
    );
}

/// The scan reads dependency tables and only those, and tells the kernel's crates from a plugin's.
#[test]
fn the_manifest_scan_reads_dependency_tables() {
    let manifest = "[package]\nname = \"busbar-x\"\n[dependencies]\nbusbar-kernel = { path = \"k\" }\n[dev-dependencies]\nbusbar-plane-x = { path = \"p\" }\nserde = \"1\"\n[features]\nbusbar-y = []\n";
    let deps = busbar_dependencies(manifest);
    assert_eq!(
        deps,
        vec![
            ("[dependencies]".to_string(), "busbar-kernel".to_string()),
            (
                "[dev-dependencies]".to_string(),
                "busbar-plane-x".to_string()
            ),
        ]
    );
    assert!(kind_neutral("busbar-kernel-ledger"));
    assert!(!kind_neutral("busbar-plane-x"));
}
