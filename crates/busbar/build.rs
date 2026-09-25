// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// BUILD-PROVENANCE STAMP. This build script bakes the OPTIMIZATION POSTURE of the binary into it at
// compile time, so `busbar --build-info` / `busbar --version` can self-report exactly how it was
// built. It exists because of a real incident: a ~20% throughput gap between two releases was
// eventually traced mostly to a BUILD-CONFIG mismatch — a binary built WITHOUT PGO (or without the
// release profile) masquerading as a code regression. A binary that says `pgo=false` / `profile=debug`
// out loud makes that class of mistake impossible to misdiagnose, and a CI assertion over these
// values (see scripts/profile-lock.sh + the build-provenance gate in ci.yml) makes it impossible to
// SHIP a mis-built binary green.
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
//   * `lto = "fat"` on [profile.release] is enforced by scripts/profile-lock.sh (a source-level check
//     over the workspace Cargo.toml), since no build-time API reveals it.
// PGO IS DETECTED ONE WAY, AND ONLY ONE: the `-Cprofile-use` flag appearing in
// CARGO_ENCODED_RUSTFLAGS — the flags cargo ACTUALLY applied. It used to be an OR with an explicit
// `BUSBAR_PGO=1` env var, described here as "belt and suspenders"; that description went stale.
// scripts/pgo-build.sh (see its note above the optimized build) stopped exporting BUSBAR_PGO
// precisely so the stamp would be the COMPILER's account of what it was given rather than a build
// script's account of what it meant to send, and no shipping path has set it since. What was left
// was an escape hatch nothing used and nothing validated: `BUSBAR_PGO=1 cargo build --release`
// produced a binary self-reporting `pgo=true` with no profile data anywhere near it, which is
// EXACTLY the misdiagnosis this whole file exists to make impossible. A plain
// `cargo build --release` carries no -Cprofile-use, so it reports `pgo=false` — the whole point.
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

fn main() {
    // Re-run when the PGO signal or the rustflags change, so the stamp never goes stale.
    println!("cargo:rerun-if-env-changed=BUSBAR_PGO");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    println!("cargo:rerun-if-changed=build.rs");

    let profile = env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
    let opt_level = env::var("OPT_LEVEL").unwrap_or_else(|_| "unknown".into());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    let encoded_flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let flags: Vec<&str> = encoded_flags
        .split('\u{1f}')
        .filter(|s| !s.is_empty())
        .collect();

    // PGO: the presence of -Cprofile-use in the rustflags cargo applied, and nothing else.
    let pgo = pgo_from_flags(&flags);

    // target-cpu, if pinned via RUSTFLAGS (`-Ctarget-cpu=<x>` or `target-cpu=<x>`); else the rustc
    // default for the target.
    let target_cpu = flag_value(&flags, "target-cpu").unwrap_or_else(|| "default".into());

    // target-feature, if pinned via RUSTFLAGS (`-Ctarget-feature=<list>`); else the rustc default
    // feature set for the target, reported as `default`. The default arm64 Linux release raises
    // its ISA floor with `+lse` here (native atomics, armv8.1+); the armv8.0-compatible variant
    // carries no flag and honestly reports `default` — which is how the two arm64 artifacts stay
    // tellable-apart from the binary alone (`busbar --build-info`), the same misdiagnosis-proofing
    // the pgo field exists for. NOTE: the value must never contain spaces (it is one token of the
    // space-separated stamp line); rustc feature lists are comma-separated, so they never do.
    let target_features = flag_value(&flags, "target-feature").unwrap_or_else(|| "default".into());

    // lto is not exposed to build scripts; surface what CAN be seen (a -Clto flag if any) and defer
    // the profile-table `lto = "fat"` guarantee to scripts/profile-lock.sh. Reported honestly as
    // "(profile-table; see Cargo.toml)" when governed by the profile rather than a flag.
    let lto = flag_value(&flags, "lto").unwrap_or_else(|| "(profile-table)".into());

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

    // THE LINKED TABLES (see src/linked_gen.rs): which plugins this build links, read as data out of
    // the manifest and filtered by the cargo features cargo enabled for this build.
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=src/linked_gen.rs");
    let manifest = std::fs::read_to_string("Cargo.toml").expect("read Cargo.toml");
    let enabled = |feature: &str| {
        let var = format!("CARGO_FEATURE_{}", feature.to_uppercase().replace('-', "_"));
        env::var_os(var).is_some()
    };
    let (source, cfgs) = linked_source(&manifest, &enabled);
    let out = std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("linked.rs");
    std::fs::write(out, source).expect("write linked.rs");
    // The root-bound seams some enabled entry drives: the root binds each under its cfg.
    for cfg in seam_cfgs() {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
    }
    for cfg in cfgs {
        println!("cargo::rustc-cfg={cfg}");
    }
    // THE LINKED-AXIS CFGS: `linked_axis_<axis>` for every registration axis some ENABLED linked row
    // carries (`[package.metadata.busbar.linked-axes]`, filtered by the cargo features on). A test
    // that needs "a linked plane serves this axis" gates on the axis, read out of the same table the
    // root folds, instead of on the feature name that spells one plugin.
    for cfg in linked_axis_cfgs(&manifest, &enabled).1 {
        println!("cargo::rustc-check-cfg=cfg({cfg})");
    }
    for cfg in linked_axis_cfgs(&manifest, &enabled).0 {
        println!("cargo::rustc-cfg={cfg}");
    }
    // `BUSBAR_ENABLED_FEATURES`: the cargo features this build enabled, space-separated — so a test
    // that maps a manifest row to "is it compiled into this build" reads the answer as data rather
    // than spelling a `cfg(feature = "...")` per plugin.
    let on: Vec<String> = declared_features(&manifest)
        .into_iter()
        .filter(|f| enabled(f))
        .collect();
    println!("cargo:rustc-env=BUSBAR_ENABLED_FEATURES={}", on.join(" "));
    // `linked_every_plane`: EVERY linked row carrying the `plane` axis is enabled — the "every plane
    // compiled in" shape a test about unmounted-but-present planes needs, read off the same table.
    println!("cargo::rustc-check-cfg=cfg(linked_every_plane)");
    let every_plane = metadata_map(&manifest, "package.metadata.busbar.linked-axes")
        .iter()
        .filter(|(_, axes)| axes.split_whitespace().any(|a| a == "plane"))
        .all(|(feature, _)| enabled(feature));
    if every_plane {
        println!("cargo::rustc-cfg=linked_every_plane");
    }

    // THE LINKED PLANE ROWS FOR THE INTEGRATION TESTS (tests only include it): each enabled linked
    // plane crate's registry row, assembled from its `linked` entry exactly as the root assembles it,
    // so a test reasons over the real rows without naming a plane crate.
    let out =
        std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("linked_planes.rs");
    std::fs::write(out, linked_planes_source(&manifest, &enabled)).expect("write linked_planes.rs");

    // THE SERVED-LEG WITNESS TABLE (test builds only include it): each enabled linked plane's
    // `testkit::SERVED`, read as data out of `[package.metadata.busbar.served-witness]`, so the root's
    // rider tests drive every served plane through the real kernel-loop runner without naming one.
    let out =
        std::path::PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR")).join("served_witness.rs");
    std::fs::write(out, served_witness_source(&manifest, &enabled))
        .expect("write served_witness.rs");
}

/// `static SERVED_WITNESSES` over `<crate>::testkit::SERVED` for every
/// `[package.metadata.busbar.served-witness]` row whose cargo feature is enabled, in manifest order.
/// A build with the feature off has no row, exactly as it has no served leg for that plane.
fn served_witness_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> String {
    let mut out = String::from(
        "// @generated by build.rs from Cargo.toml `[package.metadata.busbar.served-witness]`.\n\
         /// One served-leg witness: drive the served path, assert, return the units it served.\n\
         pub(crate) type ServedWitness =\n    fn() -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = u64>>>;\n\
         pub(crate) static SERVED_WITNESSES: &[(&str, &[(&str, ServedWitness)])] = &[\n",
    );
    for (feature, krate) in metadata_map(manifest, "package.metadata.busbar.served-witness") {
        if enabled(&feature) {
            out.push_str(&format!("    {}::testkit::SERVED,\n", ident(&krate)));
        }
    }
    out.push_str("];\n");
    out
}

/// `(set, declared)`: the `linked_axis_<axis>` cfgs of every axis an enabled linked row carries
/// (the `plane` axis included), and every such cfg any axis could produce (for `rustc-check-cfg`).
fn linked_axis_cfgs(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> (Vec<String>, Vec<String>) {
    let cfg_of = |axis: &str| format!("linked_axis_{}", axis.replace('-', "_"));
    let mut declared: Vec<String> = vec![cfg_of("plane")];
    declared.extend(AXES.iter().map(|(axis, _, _)| cfg_of(axis)));
    let mut set: Vec<String> = Vec::new();
    for (feature, axes) in metadata_map(manifest, "package.metadata.busbar.linked-axes") {
        if !enabled(&feature) {
            continue;
        }
        for axis in axes.split_whitespace() {
            let cfg = cfg_of(axis);
            if declared.contains(&cfg) && !set.contains(&cfg) {
                set.push(cfg);
            }
        }
    }
    (set, declared)
}

/// `static LINKED_PLANES` — `PlaneDecl::assemble(<crate>::linked::PLANE_DECLARATION,
/// <crate>::linked::PLANE_HOOKS)` for every enabled `[package.metadata.busbar.linked]` row whose
/// axes carry `plane` and whose entry module is the crate's own `linked` (a root-module entry is not
/// reachable from an integration test), in manifest order.
fn linked_planes_source(manifest: &str, enabled: &dyn Fn(&str) -> bool) -> String {
    let axes = metadata_map(manifest, "package.metadata.busbar.linked-axes");
    let entries = metadata_map(manifest, "package.metadata.busbar.linked-entry");
    let mut out = String::from(
        "// @generated by build.rs from Cargo.toml `[package.metadata.busbar.linked]`.\n\
         pub(crate) static LINKED_PLANES: &[::busbar_kernel::plane::registry::PlaneDecl] = &[\n",
    );
    for (feature, krate) in metadata_map(manifest, "package.metadata.busbar.linked") {
        let is_plane = axes
            .iter()
            .any(|(f, a)| *f == feature && a.split_whitespace().any(|x| x == "plane"));
        let own_entry = !entries.iter().any(|(k, _)| *k == krate);
        if enabled(&feature) && is_plane && own_entry {
            let id = ident(&krate);
            out.push_str(&format!(
                "    ::busbar_kernel::plane::registry::PlaneDecl::assemble(\n        \
                 ::{id}::linked::PLANE_DECLARATION,\n        ::{id}::linked::PLANE_HOOKS,\n    ),\n"
            ));
        }
    }
    out.push_str("];\n");
    out
}
