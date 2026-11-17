// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SOURCE-TREE CHECKS (CORE-ARCHITECTURE-DIET). `arch/escapes.rs` holds A8 and A7.
//!
//! Size is judged by bloat, waste and slowness, never by a line budget (owner ruling 2026-11-15:
//! "drop size limites it arbitrary. the only rule is that we dont have bloat waste or slowness").
//! What stays is what a number cannot argue with: no source file no Cargo target reaches, no
//! generated production code outside the frozen list in `arch/source-tree.json`, test-only crates
//! only as dev-dependencies, and the lib's workspace dependencies written down exactly in
//! `arch/layering.json` (they grow only through its `allowed_additions`). The check parses sources
//! only; it never builds core.

mod arch;

use std::collections::BTreeSet;
use std::path::Path;

use arch::scan;
use serde::Deserialize;

const TREE: &str = "crates/busbar-kernel/tests/arch/source-tree.json";
const LAYERING: &str = "crates/busbar-kernel/tests/arch/layering.json";

#[derive(Deserialize)]
struct SourceTree {
    version: u32,
    #[serde(default)]
    test_only: Vec<String>,
    #[serde(default)]
    generated: Vec<String>,
}

#[derive(Deserialize)]
struct Layering {
    version: u32,
    lib: String,
    lib_workspace_deps: Vec<String>,
    #[serde(default)]
    allowed_additions: Vec<String>,
}

fn parse<T: for<'de> Deserialize<'de>>(name: &str, text: &str) -> T {
    sonic_rs::from_str(text).unwrap_or_else(|error| panic!("{name}: {error}"))
}

fn read(root: &Path, name: &str) -> String {
    std::fs::read_to_string(root.join(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
}

#[test]
fn the_source_tree_holds_no_dead_or_generated_code_and_its_layering() {
    let mut workspace = scan::load();
    let root = workspace.root.clone();
    let tree: SourceTree = parse(TREE, &read(&root, TREE));
    let layering: Layering = parse(LAYERING, &read(&root, LAYERING));
    let mut failures = Vec::new();

    assert_eq!(tree.version, 1, "{TREE}: unknown version");
    assert_eq!(layering.version, 1, "{LAYERING}: unknown version");

    let test_only: BTreeSet<String> = tree.test_only.iter().cloned().collect();
    workspace.walk(&test_only);
    let (_, generated) = workspace.count();

    // Test-only crates are dev-dependencies only.
    for package in &workspace.packages {
        for dependency in &package.dependencies {
            if test_only.contains(&dependency.name) && dependency.kind.as_deref() != Some("dev") {
                failures.push(format!(
                    "{} takes the test-only crate {} as a non-dev dependency",
                    package.name, dependency.name
                ));
            }
        }
    }

    // No unreachable source file.
    for path in workspace.unreachable() {
        failures.push(format!(
            "unreachable file: {} is under src/ but no Cargo target reaches it; delete it",
            workspace.relative(&path)
        ));
    }

    // No generated production code outside the frozen list.
    let sites: BTreeSet<String> = generated
        .iter()
        .map(|site| format!("{}:{}", workspace.relative(&site.file), site.line))
        .collect();
    for site in &sites {
        if !tree.generated.contains(site) {
            failures.push(format!(
                "generated code: {site} includes a non-literal path in production code; check \
                 what it reaches and add it to {TREE} only with the owner's approval"
            ));
        }
    }
    for site in &tree.generated {
        if !sites.contains(site) {
            failures.push(format!(
                "generated list: {site} is no longer a generated include; remove it from {TREE}"
            ));
        }
    }

    // The dependency-set guard (§5): the lib's workspace dependencies, written down exactly.
    let lib_deps: BTreeSet<String> = workspace
        .packages
        .iter()
        .find(|package| package.name == layering.lib)
        .map(|lib| {
            lib.dependencies
                .iter()
                .filter(|dependency| dependency.kind.is_none())
                .filter(|dependency| {
                    workspace
                        .packages
                        .iter()
                        .any(|package| package.name == dependency.name)
                })
                .map(|dependency| dependency.name.clone())
                .collect()
        })
        .unwrap_or_default();
    let declared: BTreeSet<String> = layering.lib_workspace_deps.iter().cloned().collect();
    if lib_deps != declared {
        failures.push(format!(
            "{LAYERING}: lib_workspace_deps must be exactly {lib_deps:?}"
        ));
    }
    match arch::base_revision(&root) {
        None => failures.push(
            "no base revision: the dependency-set guard needs Git history (set BUSBAR_LOC_BASE)"
                .to_string(),
        ),
        Some(base) => {
            println!("layering base: {base}");
            let base_layering: Option<Layering> =
                arch::file_at(&root, &base, LAYERING).map(|text| parse(LAYERING, &text));
            if let Some(base_layering) = &base_layering {
                for added in lib_deps
                    .iter()
                    .filter(|name| !base_layering.lib_workspace_deps.contains(*name))
                {
                    if !layering.allowed_additions.contains(added) {
                        failures.push(format!(
                            "dependency-set guard: {} gained the workspace dependency {added}, \
                             which is not in {LAYERING} allowed_additions",
                            layering.lib
                        ));
                    }
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "source-tree checks ({}):\n{}",
        scan::METHOD,
        failures.join("\n")
    );
}

/// What reads the live secret axis as a grammar: the set the last admission published, whatever
/// generation is serving or building (SECRET-SHORTHAND-BOOT §3.1, §3.4).
const LIVE_AXIS_GRAMMAR: &[&str] = &[
    "admitted_sugars(",
    "grammar::admitted(",
    "catalog_admitted",
    "SecretAxis::sugars(&crate::root::native_secrets::NATIVE",
];

/// The production sites that may: process-lifetime machinery past admission that holds no
/// generation of its own. The connector's admission authority is issued once per process-lifetime
/// table; plane-bound fills, door section references and export sinks are judged by the plane and
/// export machinery. The grammar pin makes the axis equal the generation's grammar on every word a
/// generation uses, except during a build, and there is no per-generation secret axis
/// (SECRET-SHORTHAND-BOOT OQ3). `config/secret.rs` defines the one accessor.
const LIVE_AXIS_ALLOWED: &[(&str, &str)] = &[
    (
        "crates/busbar/src/root/connector.rs",
        "SecretAxis::sugars(&crate::root::native_secrets::NATIVE",
    ),
    (
        "crates/busbar-kernel/src/config/secret.rs",
        "admitted_sugars(",
    ),
    (
        "crates/busbar-kernel/src/config/filled.rs",
        "admitted_sugars(",
    ),
    (
        "crates/busbar-kernel/src/off_path/plane_door.rs",
        "admitted_sugars(",
    ),
    (
        "crates/busbar-kernel/src/off_path/export.rs",
        "admitted_sugars(",
    ),
];

/// SECRET-SHORTHAND-BOOT §3.4 (MR-B3): every reader takes the grammar of the read or generation it
/// serves, passed explicitly: an admin request body its own phase 1, a generation's settings,
/// fills, hooks, exports and plane sections that generation's grammar. None reads what the last
/// admission left on the live secret axis, which during a build already holds the candidate's set.
#[test]
fn generation_sites_never_read_the_live_axis_as_their_grammar() {
    let mut workspace = scan::load();
    let root = workspace.root.clone();
    let tree: SourceTree = parse(TREE, &read(&root, TREE));
    let test_only: BTreeSet<String> = tree.test_only.iter().cloned().collect();
    workspace.walk(&test_only);
    let mut found = Vec::new();
    for (path, reached) in &workspace.files {
        if !reached.production {
            continue;
        }
        let Ok(source) = std::fs::read_to_string(path) else {
            continue;
        };
        let parsed = scan::Parsed::new(&source);
        // Production lines only (test and doc ranges excluded), comments cut, whitespace removed:
        // a call rustfmt splits over lines reads as one.
        let code: String = source
            .lines()
            .enumerate()
            .filter(|(index, _)| !parsed.excluded(index + 1))
            .map(|(_, line)| line.split("//").next().unwrap_or_default())
            .flat_map(str::chars)
            .filter(|c| !c.is_whitespace())
            .collect();
        let relative = workspace.relative(path);
        for needle in LIVE_AXIS_GRAMMAR {
            let allowed = LIVE_AXIS_ALLOWED
                .iter()
                .any(|(file, what)| relative == *file && what == needle);
            if !allowed && code.contains(needle) {
                found.push(format!("{relative}: {needle}"));
            }
        }
    }
    assert!(
        found.is_empty(),
        "production code reads the live secret axis as a grammar; pass the read's or the \
         generation's grammar instead:\n{}",
        found.join("\n")
    );
}
