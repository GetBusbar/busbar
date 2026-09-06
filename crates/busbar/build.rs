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

use std::env;

include!("src/build_stamp.rs");

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
    // `-Clto=`, with the `-C` — not a bare `lto=`. The bare form matches ANY flag whose text happens
    // to contain those four characters (`-Cllvm-args=…lto=…`, a `-Cprofile-use` path under a
    // directory named `lto=fat`), and the value it then reports is whatever followed that
    // coincidence. A stamp that can be wrong about the build it describes is worse than one that
    // says it does not know, and the whole reason this field exists is a misdiagnosis.
    let lto = flag_value(&flags, "-Clto")
        .map(|value| sanitized(&value))
        .unwrap_or_else(|| "(profile-table)".into());

    // EVERY VALUE BELOW THAT CAME OUT OF `RUSTFLAGS` IS SANITISED FIRST. A `cargo:` directive is
    // line-oriented and cargo reads whatever the build script prints, so a rustflag carrying a
    // newline would end the directive early and let the rest of its own text be read as a FRESH
    // directive — a `RUSTFLAGS` value choosing this crate's link flags, its rerun-if triggers or any
    // other `cargo:` key. The stamp is a self-report of how the binary was built and nothing more;
    // it has no business being an instruction channel.
    let target_cpu = sanitized(&target_cpu);
    let target_features = sanitized(&target_features);

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
}

/// One `RUSTFLAGS`-derived value, safe to put after `cargo:rustc-env=NAME=`.
///
/// Two rules, and both are about the line rather than about the value's meaning. Anything that could
/// END the directive — a newline, a carriage return, the `\x1f` the flags arrive separated by — is
/// dropped, because everything after it would be read by cargo as a directive of its own. A space is
/// dropped for a different reason: the stamp is one space-separated line, so a value containing one
/// would split into two fields and every reader downstream would parse the wrong thing. An empty
/// result reads as the honest `default` rather than as a name nothing wrote.
fn sanitized(value: &str) -> String {
    let kept: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    if kept.is_empty() {
        "default".to_string()
    } else {
        kept
    }
}
