// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// THE ORACLE'S BUILD SCRIPT (busbar-release planning/design/ORACLE-FIRST.md). The oracle files are
// dist/default's own tests, compiled here by path with no plugin crate. They read what dist/default's
// build script (crates/busbar/build.rs) gave them, and this script gives them the same, from the same
// tables and core's own generator (src/linked_gen.rs):
//   * every `linked_*` cfg and BUSBAR_LINKED_AXES / BUSBAR_LINKED_SECTIONS / BUSBAR_ENABLED_FEATURES, from
//     the bundled set's tables in Cargo.toml (dist/default's, verbatim). The bundled plugins are loaded
//     from packages, not linked, so their crates are stated as the product's dependencies for the
//     generator only: the cfgs come out exactly as the product build's, the same cells apply, and a
//     plugin that lags FAILS its cells instead of compiling them out;
//   * `BUSBAR_DOOR_BLACKBOX`: each plane door's black-box case directory (`crate=dir;` rows), in the plugin source ci/qa.yml
//     fetched at the package's commit (BUSBAR_ORACLE_SOURCES/<repo>). A source it did not fetch leaves the
//     directory empty, and plane_blackbox fails naming that plane;
//   * `cfg(oracle_lookup)`: the shared helper (test_plugins.rs) then defines `token_verifier`, the
//     token-verifying cdylib lookup the shared credentials helper calls (oidc's own test source in dist/default), as a lookup only: the cdylib
//     ci/qa.yml copied into the test profile directory. No plugin source is compiled.

use std::path::{Path, PathBuf};

// The generator is core's own source (crates/busbar/src/linked_gen.rs), reached as a build-dependency (this script writes no Rust output).
use busbar_linked_gen::*;

/// `<sources>/<repo>/<crate dir>/tests/blackbox` when that crate is the plane door the bundled table
/// names (its own `links` row, as crates/busbar/build.rs holds the door's metadata to be its own).
fn oracle_blackbox_dir(sources: &Path, krate: &str) -> Option<String> {
    let dir = sources
        .join(krate)
        .join(krate.strip_prefix("busbar-").unwrap_or(krate));
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).ok()?;
    let links = format!("busbar-door-cells-{krate}");
    let name = metadata_value(&manifest, "package", "name");
    if name.as_deref() != Some(krate)
        || metadata_value(&manifest, "package", "links").as_deref() != Some(links.as_str())
    {
        println!(
            "cargo::warning={}: not {krate}'s door crate (name {name:?}, links must be {links})",
            dir.display()
        );
        return None;
    }
    let cases = dir.join("tests/blackbox");
    println!("cargo:rerun-if-changed={}", cases.display());
    cases.is_dir().then(|| cases.display().to_string())
}

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=../../crates/busbar/src");
    println!("cargo:rerun-if-env-changed=BUSBAR_ORACLE_SOURCES");
    let manifest = std::fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    let linked = metadata_map(&manifest, "package.metadata.busbar.linked");
    let product = format!(
        "{manifest}\n[dependencies]\n{}",
        linked
            .iter()
            .map(|(_, krate)| format!("{krate} = \"bundled\"\n"))
            .collect::<String>()
    );

    let always_on: Vec<String> = metadata_map(&product, "package.metadata.busbar.always-on")
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let enabled = |feature: &str| {
        let var = format!("CARGO_FEATURE_{}", feature.to_uppercase().replace('-', "_"));
        always_on.iter().any(|k| k == feature) || std::env::var_os(var).is_some()
    };

    let cfgs = build_cfgs(&product, &enabled);
    println!("cargo::rustc-check-cfg=cfg(door_rig)");
    for (cfg, on) in &cfgs {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
        if *on {
            println!("cargo::rustc-cfg={cfg}");
        }
    }
    let axes: Vec<&str> = cfgs
        .iter()
        .filter(|(cfg, on)| *on && cfg.starts_with("linked_axis_"))
        .map(|(cfg, _)| cfg.as_str())
        .collect();
    println!("cargo:rustc-env=BUSBAR_LINKED_AXES={}", axes.join(" "));
    let sections: Vec<String> = metadata_map(&product, "package.metadata.busbar.linked-section")
        .into_iter()
        .filter(|(feature, _)| enabled(feature))
        .map(|(_, section)| section)
        .collect();
    println!(
        "cargo:rustc-env=BUSBAR_LINKED_SECTIONS={}",
        sections.join(" ")
    );
    let on: Vec<String> = always_on
        .iter()
        .cloned()
        .chain(declared_features(&product))
        .filter(|f| enabled(f))
        .collect();
    println!("cargo:rustc-env=BUSBAR_ENABLED_FEATURES={}", on.join(" "));

    let sources = std::env::var_os("BUSBAR_ORACLE_SOURCES").map(PathBuf::from);
    let axes_table = metadata_map(&product, "package.metadata.busbar.linked-axes");
    let mut rows = String::new();
    for (feature, krate) in &linked {
        let door = axes_table
            .iter()
            .any(|(f, a)| f == feature && a.split_whitespace().any(|axis| axis == PLANE_DOOR_AXIS));
        if !(door && enabled(feature)) {
            continue;
        }
        let dir = sources
            .as_deref()
            .and_then(|s| oracle_blackbox_dir(s, krate))
            .unwrap_or_default();
        if dir.is_empty() {
            println!("cargo::warning={krate}: no black-box case directory (BUSBAR_ORACLE_SOURCES)");
        }
        rows.push_str(&format!("{krate}={dir};"));
    }
    println!("cargo:rustc-env=BUSBAR_DOOR_BLACKBOX={rows}");
    println!("cargo::rustc-check-cfg=cfg(oracle_lookup)");
    println!("cargo::rustc-cfg=oracle_lookup");
}
