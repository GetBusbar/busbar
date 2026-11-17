// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// BUILD-PROVENANCE STAMP. This build script bakes the OPTIMIZATION POSTURE of the binary into it at
// compile time, so `busbar --build-info` / `busbar --version` can self-report exactly how it was
// built. It exists because of a real incident: a ~20% throughput gap between two releases was
// eventually traced mostly to a BUILD-CONFIG mismatch — a binary built WITHOUT PGO (or without the
// release profile) masquerading as a code regression. A binary that says `pgo=false` / `profile=debug`
// out loud makes the build configuration visible when diagnosing a regression.
//
// WHAT CARGO ACTUALLY EXPOSES to a build script (the honest surface):
//   * PROFILE                 -> "release" | "debug"          (the profile in force)
//   * OPT_LEVEL               -> "0".."3" | "s" | "z"         (the resolved opt-level)
//   * TARGET                  -> the target triple
//   * DEBUG                   -> debuginfo level (NOT debug-assertions)
//   * CARGO_ENCODED_RUSTFLAGS -> the \x1f-separated rustc flags (carries -Cprofile-use for PGO and
//                                -Ctarget-cpu when set via RUSTFLAGS)
// `lto` and the profile-table `debug-assertions` are NOT exposed to build scripts by cargo. So:
//   * debug-assertions is reported by main.rs at runtime via `cfg!(debug_assertions)` (compiled with
//     the binary's own profile — the reliable source), and
//   * profile-table `lto` is reported as unknown here, since no build-time API reveals it.
// Production Cargo builds use scripts/build-provenance-gate.sh as a rustc wrapper. It replaces
// the unverified receipt defaults only on the final dist/default executable compiler invocation,
// using resolved rustc argv for LTO/codegen units and Git source identity at that invocation.
// PGO IS DETECTED ONE WAY, AND ONLY ONE: the `-Cprofile-use` flag appearing in
// CARGO_ENCODED_RUSTFLAGS, the effective compiler flags, is the sole PGO source.
// An environment hint cannot attest that profile data reached the compiler.
// A plain release build without -Cprofile-use therefore reports pgo=false.
//
//
//
//
//
//
//
// The derivation itself lives in src/build_stamp.rs, `include!`d below and mounted by main.rs under
// `#[cfg(test)]`, so the functions that decide what the stamp says are unit-testable rather than
// reachable only through a release build.
//
// THE LINKED TABLES. This script also writes `$OUT_DIR/linked.rs`, which `main.rs` includes: the
// plugins this build links (one table per registration axis) and the root units it composes, read
// out of the manifest's `[package.metadata.busbar.*]` tables and filtered by the enabled cargo
// features — plus a `linked_*` cfg per root-bound seam some enabled entry drives. The generator is
// src/linked_gen.rs, `include!`d below and by the test that judges `main.rs` against the same tables
// (tests/composition_root_names_no_linked_plugin.rs), so what it decides is asserted there.

use std::env;

include!("src/build_stamp.rs");
include!("src/linked_gen.rs");

#[path = "src/link_policy.rs"]
mod link_policy;

#[path = "src/test_source_gen.rs"]
mod test_source_gen;

fn main() {
    println!("cargo:rerun-if-env-changed=BUSBAR_PGO");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");

    println!("cargo:rerun-if-env-changed=BUSBAR_PROVENANCE_SOURCE");
    let manifest = std::fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    let core = core_dir(&manifest);
    println!(
        "cargo:rerun-if-changed={}",
        core.join("src/test_source_gen.rs").display()
    );
    println!("cargo:rerun-if-changed={}", core.join("build.rs").display());
    println!(
        "cargo:rerun-if-changed={}",
        core.join("src/build_stamp.rs").display()
    );

    println!("cargo:rustc-env=BUSBAR_CORE_DIR={}", core.display());

    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    let opt_level = env::var("OPT_LEVEL").unwrap_or_else(|_| "unknown".into());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    for argument in link_policy::arguments(&target) {
        println!("cargo:rustc-link-arg={argument}");
    }
    println!(
        "cargo:rerun-if-changed={}",
        core.join("src/link_policy.rs").display()
    );
    let encoded_flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let flags: Vec<&str> = encoded_flags
        .split('\u{1f}')
        .filter(|s| !s.is_empty())
        .collect();

    let pgo = pgo_from_flags(&flags);

    let target_cpu = flag_value(&flags, "target-cpu").unwrap_or_else(|| "default".into());

    let target_features = flag_value(&flags, "target-feature").unwrap_or_else(|| "default".into());

    let lto = flag_value(&flags, "lto").unwrap_or_else(|| "(profile-table)".into());

    for key in [
        "CODEGEN_UNITS",
        "RECEIPT",
        "PACKAGE",
        "MANIFEST",
        "SOURCE_COMMIT",
        "SOURCE_CLEAN",
    ] {
        println!("cargo:rustc-env=BUSBAR_BUILD_{key}=unverified");
    }

    println!("cargo:rustc-env=BUSBAR_BUILD_PROFILE={profile}");
    println!("cargo:rustc-env=BUSBAR_BUILD_OPT_LEVEL={opt_level}");
    println!("cargo:rustc-env=BUSBAR_BUILD_TARGET={target}");
    println!("cargo:rustc-env=BUSBAR_BUILD_TARGET_CPU={target_cpu}");
    println!("cargo:rustc-env=BUSBAR_BUILD_TARGET_FEATURES={target_features}");
    println!("cargo:rustc-env=BUSBAR_BUILD_LTO={lto}");
    println!(
        "cargo:rustc-env=BUSBAR_BUILD_PGO={}",
        if pgo { "true" } else { "false" }
    );

    println!("cargo:rerun-if-changed=Cargo.toml");
    println!(
        "cargo:rerun-if-changed={}",
        core.join("src/linked_gen.rs").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        core.join("src/manifest_rows.rs").display()
    );
    let always_on: Vec<String> = metadata_map(&manifest, "package.metadata.busbar.always-on")
        .into_iter()
        .map(|(key, _)| key)
        .collect();
    let enabled = |feature: &str| {
        let var = format!("CARGO_FEATURE_{}", feature.to_uppercase().replace('-', "_"));
        always_on.iter().any(|k| k == feature) || env::var_os(var).is_some()
    };
    let (source, _) = linked_source(&manifest, &enabled);
    let out = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("linked.rs");
    std::fs::write(out, source).expect("write linked.rs");

    let cfgs = build_cfgs(&manifest, &enabled);
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
    let sections: Vec<String> = metadata_map(&manifest, "package.metadata.busbar.linked-section")
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
        .chain(declared_features(&manifest))
        .filter(|f| enabled(f))
        .collect();
    println!("cargo:rustc-env=BUSBAR_ENABLED_FEATURES={}", on.join(" "));

    let out = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"))
        .join("linked_plane_doors.rs");
    std::fs::write(out, linked_plane_doors_source(&manifest, &enabled))
        .expect("write linked_plane_doors.rs");
    std::fs::write(
        std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"))
            .join("linked_native_images.rs"),
        linked_native_images_source(&manifest, &enabled),
    )
    .expect("write linked_native_images.rs");

    let words = driver_words_source(&manifest, &enabled);
    let out_dir = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("driver_words.rs"), words).expect("write driver_words.rs");

    let (wires, wires_off) = linked_transports_source(&manifest, &enabled);
    let out_dir = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("linked_transports.rs"), wires)
        .expect("write linked_transports.rs");
    std::fs::write(out_dir.join("linked_transports_off.rs"), wires_off)
        .expect("write linked_transports_off.rs");

    let out = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"))
        .join("source_scan_needles.rs");
    std::fs::write(out, source_scan_needles_source(&manifest, &enabled))
        .expect("write source_scan_needles.rs");

    let (cells, cells_files, rig) = door_cells_source(&manifest, &enabled);

    println!("cargo::rustc-check-cfg=cfg(door_rig)");
    if rig {
        println!("cargo::rustc-cfg=door_rig");
    }
    let out_dir = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(out_dir.join("door_cells.rs"), cells).expect("write door_cells.rs");
    let test_owners = test_source_gen::Owners::load(&manifest);
    std::fs::write(
        out_dir.join("root_test_sources.rs"),
        test_sources_source(&manifest, &test_owners, "root-test-sources", "root", false),
    )
    .expect("write root_test_sources.rs");
    std::fs::write(
        out_dir.join("common_test_sources.rs"),
        test_sources_source(
            &manifest,
            &test_owners,
            "test-common-sources",
            "common",
            true,
        ),
    )
    .expect("write common_test_sources.rs");
    std::fs::write(
        out_dir.join("context_test_sources.rs"),
        context_test_sources_source(&manifest, &test_owners),
    )
    .expect("write context_test_sources.rs");
    println!("cargo:rustc-env=BUSBAR_DOOR_BLACKBOX={cells_files}");
    println!("cargo::rustc-check-cfg=cfg(oracle_lookup)");

    let out =
        std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("test_linked.rs");
    std::fs::write(out, test_linked_source(&manifest)).expect("write test_linked.rs");
    let out = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"))
        .join("test_linked_secrets.rs");
    std::fs::write(out, test_linked_secrets_source(&manifest))
        .expect("write test_linked_secrets.rs");
    let out = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"))
        .join("test_operator_auth.rs");
    std::fs::write(out, test_operator_auth_source(&manifest)).expect("write test_operator_auth.rs");
}

fn core_dir(manifest: &str) -> std::path::PathBuf {
    let here = std::path::PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    match metadata_value(manifest, "package.metadata.busbar.core", "dir") {
        Some(dir) => here.join(dir).canonicalize().expect("core dir"),
        None => here,
    }
}

fn test_operator_auth_source(manifest: &str) -> String {
    let idents: Vec<String> = test_linked_list(manifest, "operator-auth")
        .iter()
        .map(|c| c.replace('-', "_"))
        .collect();
    let mut out = String::from("// @generated by build.rs from Cargo.toml metadata.\n");
    for id in &idents {
        out.push_str(&format!("extern crate {id} as _;\n"));
    }
    out.push_str("macro_rules! for_each_operator_auth_row {\n    ($f:expr) => {{\n");
    for id in &idents {
        out.push_str(&format!("        ($f)({id}::door);\n"));
    }
    out.push_str("    }};\n}\n");
    out
}

fn test_linked_source(manifest: &str) -> String {
    let doors: Vec<String> = test_linked_list(manifest, "planes")
        .iter()
        .map(|c| c.replace('-', "_"))
        .collect();
    let mut out = String::from("// @generated by build.rs from Cargo.toml metadata.\n");
    for id in &doors {
        out.push_str(&format!("extern crate {id} as _;\n"));
    }
    out.push_str(
        "static TEST_LINKED_DOORS: &[(&str, ::busbar_contract::abi::mechanism::door::DoorFn)] = &[\n",
    );

    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    for id in &doors {
        let module = entries
            .iter()
            .map(|(_, module)| module)
            .find(|module| *module == id || module.starts_with(&format!("{id}::")))
            .cloned()
            .unwrap_or_else(|| format!("{id}::plane_door"));
        out.push_str(&format!("    ({id:?}, {module}::door),\n"));
    }

    out.push_str("];\n");
    out
}

/// The test-linked secret sources (`[package.metadata.busbar.test-linked] secrets`), each with the
/// door its `linked-entry` names and the declares item its row's `linked-declares` names: the same
/// rows the root links on its secret axis.
fn test_linked_secrets_source(manifest: &str) -> String {
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    let rows = metadata_map(manifest, "package.metadata.busbar.linked");
    let declares = metadata_map(manifest, "package.metadata.busbar.linked-declares");
    let mut out = String::from("// @generated by build.rs from Cargo.toml metadata.\n");
    let mut table = String::from(
        "static TEST_LINKED_SECRETS: &[(::busbar_contract::abi::mechanism::door::DoorFn, \
         ::std::option::Option<&str>)] = &[\n",
    );
    for krate in test_linked_list(manifest, "secrets") {
        let id = krate.replace('-', "_");
        out.push_str(&format!("extern crate {id} as _;\n"));
        let module = match entries.iter().find(|(name, _)| *name == krate) {
            Some((_, module)) => module.clone(),
            None => id,
        };
        let declared = rows
            .iter()
            .filter(|(_, name)| *name == krate)
            .find_map(|(feature, _)| declares.iter().find(|(row, _)| row == feature));
        let declared = match declared {
            Some((_, item)) => format!("::std::option::Option::Some({item})"),
            None => "::std::option::Option::None".to_string(),
        };
        table.push_str(&format!("    ({module}::door, {declared}),\n"));
    }
    table.push_str("];\n");
    out.push_str(&table);
    out
}

fn test_linked_list(manifest: &str, key: &str) -> Vec<String> {
    let header = "[package.metadata.busbar.test-linked]";
    let (mut in_table, mut collecting, mut body) = (false, false, String::new());
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if !collecting && code.starts_with('[') {
            in_table = code == header;
            continue;
        }
        if collecting {
            body.push_str(code);
        } else if in_table {
            if let Some((k, v)) = code.split_once('=') {
                if k.trim() == key {
                    collecting = true;
                    body.push_str(v.trim());
                }
            }
        }
        if collecting && body.contains(']') {
            break;
        }
    }
    if !collecting {
        return Vec::new();
    }
    let list: Vec<String> = body
        .trim()
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().trim_matches('"').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert!(
        !list.is_empty(),
        "Cargo.toml: `{key}` under `{header}` is empty"
    );
    list
}

// Owners declare source-only test paths in package metadata, without exporting
// test helpers through a production plugin library.
fn test_sources_source(
    manifest: &str,
    owners: &test_source_gen::Owners,
    table: &str,
    source: &str,
    reexport: bool,
) -> String {
    let mut out = format!("// @generated from package.metadata.busbar.{table}.\n");
    for (module, krate) in metadata_map(manifest, &format!("package.metadata.busbar.{table}")) {
        out.push_str(&owners.module(&krate, source, &module));
        if reexport {
            out.push_str(&format!("pub use {module}::*;\n"));
        }
    }
    out
}

// The same source-owner boundary can mount tests beneath private host modules.
// Context names are assembly data. Assemblies must account for every mounted context;
// neutral core builds do not acquire source owners merely by mounting a context.
fn context_test_sources_source(manifest: &str, owners: &test_source_gen::Owners) -> String {
    let mut out = String::from("// @generated from package.metadata.busbar.test-source-contexts.\nmacro_rules! owner_test_sources {\n");
    for (context, owner) in metadata_map(manifest, "package.metadata.busbar.test-source-contexts") {
        test_source_gen::identifier(&context);
        out.push_str(&format!(
            "    ({context}) => {{ {} }};\n",
            owners.context(&owner, &context)
        ));
    }
    if metadata_value(manifest, "package.metadata.busbar.core", "dir").is_some() {
        out.push_str(
            "    ($context:ident) => { compile_error!(concat!(\"missing assembly test source context: \", stringify!($context))); };\n",
        );
    } else {
        out.push_str("    ($context:ident) => {};\n");
    }
    out.push_str("}\n");
    out
}

fn door_cells_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> (String, String, bool) {
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let mut out = String::from(
        "// @generated by build.rs from Cargo.toml `[package.metadata.busbar.linked]` and each plane \
         door's `links` metadata.\n",
    );
    let mut driven: Vec<String> = Vec::new();
    let mut configs: Vec<String> = Vec::new();

    let mut blackbox: Vec<String> = Vec::new();
    let mut rig = false;
    for (feature, krate) in metadata_map(manifest, "package.metadata.busbar.linked") {
        let is_door = axes
            .iter()
            .any(|(f, a)| *f == feature && a.split_whitespace().any(|x| x == PLANE_DOOR_AXIS));
        if !(enabled(&feature) && is_door) {
            continue;
        }

        let box_var = format!(
            "DEP_{}_BLACKBOX",
            door_cells_links(&krate).to_uppercase().replace('-', "_")
        );
        println!("cargo:rerun-if-env-changed={box_var}");

        let dir = env::var(&box_var).unwrap_or_default();
        if !dir.is_empty() {
            println!("cargo:rerun-if-changed={dir}");
        }
        blackbox.push(format!("{krate}={dir};"));
        let var = format!(
            "DEP_{}_CELLS",
            door_cells_links(&krate).to_uppercase().replace('-', "_")
        );
        println!("cargo:rerun-if-env-changed={var}");
        let Ok(at) = env::var(&var) else {
            continue;
        };
        println!("cargo:rerun-if-changed={at}");
        if let Err(e) = cells_are_the_crates_own(&krate, &at) {
            panic!("{var}: {e}");
        }
        rig |= std::fs::read_to_string(&at).is_ok_and(|text| text.contains("door_rig"));
        let module = ident(&feature);
        out.push_str(&format!("#[path = {at:?}]\npub(crate) mod {module};\n"));
        driven.push(format!(".chain({module}::secret_source_driven())"));
        configs.push(format!("        {module}::minimal_valid_config(),\n"));
    }
    out.push_str(&format!(
        "/// The Statement names the door planes' own root cells drive through the secret-source scan.\n\
         pub(crate) fn door_cells_secret_driven() -> Vec<String> {{\n    \
         std::iter::empty::<String>(){}.collect()\n}}\n",
        driven.concat()
    ));

    out.push_str(&format!(
        "/// Minimal sections supplied by the linked plane test owners.\n\
         pub(crate) fn door_cells_minimal_configs() -> Vec<(&'static str, ::serde_json::Value)> {{\n    vec![\n{}    ]\n}}\n",
        configs.concat()
    ));

    (out, blackbox.concat(), rig)
}

fn source_scan_needles_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> String {
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let features = declared_features(manifest);
    let required = required_deps(manifest);
    let mut out = String::from(
        "// @generated from each linked source owner's test metadata.\n\
         const SOURCE_SCAN_NEEDLES: &[&str] = &[\n",
    );
    for (feature, krate) in metadata_map(manifest, "package.metadata.busbar.linked") {
        let is_source = axes
            .iter()
            .any(|(f, a)| *f == feature && a.split_whitespace().any(|axis| axis == SECRET_AXIS));
        let always = !features.contains(&feature) && required.contains(&krate);
        if !is_source || !(enabled(&feature) || always) {
            continue;
        }
        let links = format!("busbar-source-scan-{krate}");
        let var = format!(
            "DEP_{}_SOURCE_SCAN_NEEDLES",
            links.to_uppercase().replace('-', "_")
        );
        println!("cargo:rerun-if-env-changed={var}");
        let at = match env::var(&var) {
            Ok(at) => at,
            Err(_) if !enabled("test-harness") => continue,
            Err(e) => panic!(
                "{krate}: source-scan owner metadata is required under test-harness ({var}): {e}"
            ),
        };
        if let Err(e) =
            metadata_is_the_crates_own(&krate, &at, "tests/source_scan_needles.json", &links)
        {
            panic!("{var}: {e}");
        }
        println!("cargo:rerun-if-changed={at}");
        out.push_str(&format!("    include_str!({at:?}),\n"));
    }
    out.push_str("];\n");
    out
}

fn cells_are_the_crates_own(krate: &str, at: &str) -> Result<(), String> {
    metadata_is_the_crates_own(krate, at, "tests/root/mod.rs", &door_cells_links(krate))
}

fn metadata_is_the_crates_own(
    krate: &str,
    at: &str,
    relative: &str,
    want_links: &str,
) -> Result<(), String> {
    use std::path::{Component, Path};
    let path = Path::new(at);
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        || !path.ends_with(relative)
    {
        return Err(format!(
            "`{at}` is not `<{krate}'s manifest dir>/{relative}`"
        ));
    }
    let dir = path
        .ancestors()
        .nth(Path::new(relative).components().count())
        .ok_or_else(|| format!("`{at}` has no crate directory"))?;
    let canonical_dir = dir.canonicalize().map_err(|e| format!("`{at}`: {e}"))?;
    let canonical_path = path.canonicalize().map_err(|e| format!("`{at}`: {e}"))?;
    if canonical_path != canonical_dir.join(relative) {
        return Err(format!("`{at}` leaves {krate}'s own metadata path"));
    }
    println!(
        "cargo:rerun-if-changed={}",
        dir.join("Cargo.toml").display()
    );
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml"))
        .map_err(|e| format!("`{at}`: {}: {e}", dir.join("Cargo.toml").display()))?;
    let (mut name, mut links, mut in_package) = (None, None, false);
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if let (true, Some((k, v))) = (in_package, line.split_once('=')) {
            let v = v.trim().trim_matches('"').to_string();
            match k.trim() {
                "name" => name = Some(v),
                "links" => links = Some(v),
                _ => {}
            }
        }
    }
    if name.as_deref() == Some(krate) && links.as_deref() == Some(want_links) {
        Ok(())
    } else {
        Err(format!(
            "`{at}` is not {krate}'s own metadata: {} names package {name:?}, links {links:?}",
            dir.join("Cargo.toml").display()
        ))
    }
}

fn door_cells_links(krate: &str) -> String {
    format!("busbar-door-cells-{krate}")
}

fn driver_words_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> String {
    let head =
        "// @generated by build.rs from Cargo.toml `[package.metadata.busbar.driver-proofs]`.\n";
    let rows: Vec<(String, String)> =
        metadata_map(manifest, "package.metadata.busbar.driver-proofs")
            .into_iter()
            .filter(|(feature, _)| enabled(feature))
            .collect();
    let mut words = String::from(head);
    match rows.as_slice() {
        [] => words.push_str("pub(crate) const DRIVER_WORDS: &str = \"\";\n"),
        [(feature, krate)] => {
            let var = format!(
                "DEP_{}_DRIVER",
                door_cells_links(krate).to_uppercase().replace('-', "_")
            );
            println!("cargo:rerun-if-env-changed={var}");
            let at = std::path::PathBuf::from(env::var(&var).unwrap_or_else(|_| {
                panic!("driver-proofs row `{feature}`: `{krate}` states no `driver=` under its links name ({var})")
            }));
            words.push_str(&format!(
                "pub(crate) const DRIVER_WORDS: &str = include_str!({:?});\n",
                at.join("words.txt").display().to_string()
            ));
        }
        _ => {
            words.push_str("compile_error!(\"more than one driver-proofs row is enabled; a build proves one door\");\n");
            words.push_str("pub(crate) const DRIVER_WORDS: &str = \"\";\n");
        }
    }
    words
}

fn linked_native_images_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> String {
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    let mut out = String::from(
        "// @generated from the same MIN-3 image rows as the composition root.\n\
         pub(crate) static LINKED_NATIVE_IMAGES: &[fn() -> Result<\
         ::busbar_plugin_loader::admit::Admitted, \
         ::busbar_plugin_loader::refusal::Refusal>] = &[\n",
    );
    for (feature, krate) in metadata_map(manifest, "package.metadata.busbar.linked") {
        if !enabled(&feature)
            || !axes.iter().any(|(key, list)| {
                *key == feature && list.split_whitespace().any(|axis| axis == MIN3_AXIS)
            })
        {
            continue;
        }
        let entry = entries
            .iter()
            .find(|(key, _)| *key == feature)
            .or_else(|| entries.iter().find(|(key, _)| *key == krate))
            .map_or_else(|| ident(&krate), |(_, path)| path.clone());
        out.push_str(&format!(
            "    || ::busbar_plugin_loader::admit::admit_linked(&{entry}::PLUGIN),\n"
        ));
    }
    out.push_str("];\n");
    out
}

fn linked_plane_doors_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> String {
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    let mut out = String::from(
        "// @generated by build.rs from Cargo.toml `[package.metadata.busbar.linked]`.\n\
         pub(crate) static LINKED_PLANE_DOORS: &[::busbar_contract::abi::mechanism::door::DoorFn] = &[\n",
    );
    for (feature, krate) in metadata_map(manifest, "package.metadata.busbar.linked") {
        let is_door = axes
            .iter()
            .any(|(f, a)| *f == feature && a.split_whitespace().any(|x| x == "plane-door"));
        if !(enabled(&feature) && is_door) {
            continue;
        }
        let entry = entries
            .iter()
            .find(|(k, _)| *k == feature)
            .or_else(|| entries.iter().find(|(k, _)| *k == krate))
            .map_or_else(|| format!("{}::linked", ident(&krate)), |(_, e)| e.clone());
        if !entry.starts_with("crate::") {
            out.push_str(&format!("    ::{entry}::door,\n"));
        }
    }
    out.push_str("];\n");
    out
}

fn linked_transports_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> (String, String) {
    let features = declared_features(manifest);
    let required = required_deps(manifest);
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    let mut rows = String::new();
    let mut door_claims = String::new();
    let mut off = 0;
    for (key, krate) in metadata_map(manifest, "package.metadata.busbar.linked") {
        let is_wire = axes
            .iter()
            .any(|(f, a)| *f == key && a.split_whitespace().any(|x| x == "transport"));
        if !is_wire {
            continue;
        }
        let always = !features.contains(&key) && required.contains(&krate);
        if !(enabled(&key) || always) {
            off += 1;
            continue;
        }
        let entry = entries
            .iter()
            .find(|(k, _)| *k == key)
            .or_else(|| entries.iter().find(|(k, _)| *k == krate))
            .map(|(_, path)| path.clone())
            .unwrap_or_else(|| format!("{}::linked", ident(&krate)));
        let door_fn = format!("::{entry}::door");
        let door = axes
            .iter()
            .any(|(f, a)| *f == key && a.split_whitespace().any(|x| x == DOOR_AXIS));
        let n = door_claims.matches("fn __door_claims_").count();

        assert!(
            door,
            "Cargo.toml: `{key}` is on the transport axis but not the `{DOOR_AXIS}` axis; a \
             transport is linked only as its memory-ABI door"
        );

        door_claims.push_str(&format!(
            "fn __door_claims_{n}() -> Vec<&'static str> {{\n    \
             self::__busbar_doors::claims_of({door_fn})\n}}\n"
        ));
        rows.push_str(&format!(
            "        __linked_wire({door_fn}, __door_claims_{n}),\n"
        ));
    }
    // Each includer (a dist/default integration test) reads only part of a row: its key, its
    // layers or its claims. A row is therefore a tuple, so no named field a test does not read is
    // left dead in it; the off count is its own file, included only by the test that reads it.
    let mut source = format!(
        "// @generated by build.rs from Cargo.toml `[package.metadata.busbar.linked]` (the transport axis).\n\
         /// One linked wire: (its registry key, the layers it declares, read off its door's\n\
         /// Statement, every scheme its entry claims (its own first)).\n\
         pub(crate) type LinkedWire = (&'static str, Vec<&'static str>, fn() -> Vec<&'static str>);\n\
         fn __linked_wire(\n    \
             door: ::busbar_contract::abi::mechanism::door::DoorFn,\n    \
             claims: fn() -> Vec<&'static str>,\n\
         ) -> LinkedWire {{\n    \
             let facts = self::__busbar_doors::row_facts(door);\n    \
             (facts.key, facts.composes_over, claims)\n\
         }}\n\
         /// Every wire this build links, in manifest order, read off the doors on first use.\n\
         pub(crate) static LINKED_TRANSPORTS: ::std::sync::LazyLock<Vec<LinkedWire>> =\n    \
             ::std::sync::LazyLock::new(|| vec![\n{rows}    ]);\n"
    );
    source.push_str(&door_claims);
    source.push_str(
        "/// The connector's transport adapter, shared with the running product.\n\
         use busbar_core_connector::doors as __busbar_doors;\n",
    );
    let off = format!(
        "// @generated by build.rs from Cargo.toml `[package.metadata.busbar.linked]` (the transport axis).\n\
         /// The transport rows the manifest declares that this build does not link.\n\
         pub(crate) const LINKED_TRANSPORTS_OFF: usize = {off};\n"
    );
    (source, off)
}

#[cfg(test)]
mod test_source_context_tests {
    use super::context_test_sources_source;

    #[test]
    fn missing_assembly_context_refuses_compilation_but_neutral_core_stays_independent() {
        let base = std::env::var_os("BUSBAR_TEST_TMP")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let directory = base.join(format!("source-context-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        let compile = |manifest: &str, invocation: &str, fixture: &str| {
            let input = directory.join("context.rs");
            std::fs::write(
                &input,
                format!(
                    "{fixture}\n{}\n{invocation}\nfn main() {{}}\n",
                    context_test_sources_source(manifest)
                ),
            )
            .unwrap();
            std::process::Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
                .arg("--edition=2021")
                .arg("--crate-name=source_context")
                .arg(&input)
                .arg("-o")
                .arg(directory.join("context"))
                .output()
                .expect("compile the generated test source context")
        };
        let assembly = "[package.metadata.busbar.core]\ndir = \"../../crates/busbar\"\n";
        let missing = compile(assembly, "owner_test_sources!(omitted_context);", "");
        let error = String::from_utf8_lossy(&missing.stderr);
        assert!(
            !missing.status.success(),
            "an omitted assembly context compiled"
        );
        assert!(
            error.contains("missing assembly test source context: omitted_context"),
            "{error}"
        );
        let neutral = compile("", "owner_test_sources!(omitted_context);", "");
        assert!(
            neutral.status.success(),
            "{}",
            String::from_utf8_lossy(&neutral.stderr)
        );
        let declared = compile(
            &format!("{assembly}[package.metadata.busbar.test-source-contexts]\nknown_context = \"fixture-owner\"\n"),
            "owner_test_sources!(known_context); const _: u8 = OWNER_WITNESS;",
            r#"extern crate self as fixture_owner;
                #[macro_export]
                macro_rules! __busbar_context_tests {
                    (known_context, "fixture-owner") => { const OWNER_WITNESS: u8 = 1; };
                }"#,
        );
        assert!(
            declared.status.success(),
            "{}",
            String::from_utf8_lossy(&declared.stderr)
        );
    }
}
