// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One shared guard for every "load a real cdylib fixture over the ABI" test in this crate.
//!
//! Before this module existed, six call sites (`hook_plugin_path`, `store_fixture_cdylib`,
//! `store_fixture_plugin_path`, `secret_example_plugin_path`, `export_example_plugin_path` x2)
//! each carried their own ~25-line copy of "find the built cdylib, then decide whether its
//! absence is a silent skip or a hard failure" -- and the copies had drifted: `hook_plugin_path`
//! gated on bare `CI`, `store_fixture_cdylib` gated on `CI && DEV_GATE`, for reasons that were
//! real (see [`FixtureClass`]) but undocumented in one place, so the divergence read as an
//! accident rather than a decision.
//!
//! There are exactly two fixture classes in this crate, and the gate is a property of the class,
//! not of the individual test file:
//!
//!  - [`FixtureClass::InTree`]: a workspace-member cdylib (`store-example-plugin`,
//!    `secret-example-plugin`, `export-example-plugin`, `hook-test-plugin`) that a plain
//!    `cargo test --workspace` -- what `ci.yml`'s `check` job runs -- always builds. Its absence
//!    under `CI` is a broken pipeline, never a local-iteration skip.
//!  - [`FixtureClass::Sibling`]: a cdylib built from an external sibling checkout (e.g.
//!    `../store-sqlite`) that only the loader-mechanism job provides
//!    (`scripts/qa-gate-run.sh loader`, which checks the sibling out, builds it, then sets
//!    `DEV_GATE=1` before running `cargo test -p busbar-plugin-loader`). `ci.yml` never checks
//!    the sibling out but DOES run under `CI=true` (GitHub Actions sets that for every job), so
//!    gating a sibling fixture on bare `CI` would turn ci.yml red for a fixture it never had a
//!    chance to build. Gating on `DEV_GATE` instead keeps ci.yml green while still hard-failing
//!    the one job that actually has the fixture.

use std::path::{Path, PathBuf};

/// Which build pipeline is responsible for producing the fixture, and therefore which env var
/// marks the job where its absence must be a hard failure rather than a silent skip.
pub(crate) enum FixtureClass {
    /// Built in-workspace by a plain `cargo test --workspace`.
    InTree,
    /// Built from a sibling checkout of `repo`, only present under the loader-mechanism job.
    Sibling { repo: &'static str },
}

/// Locate `crate_name`'s cdylib under `class`, then apply the class's gate: `None` while
/// ungated, or a hard panic naming `coverage` once the responsible job should have built it.
pub(crate) fn locate(crate_name: &str, class: FixtureClass, coverage: &str) -> Option<PathBuf> {
    let candidate = match &class {
        FixtureClass::InTree => locate_in_tree(crate_name),
        FixtureClass::Sibling { repo } => locate_sibling(repo, crate_name),
    };
    let gated = match class {
        FixtureClass::InTree => std::env::var_os("CI").is_some(),
        FixtureClass::Sibling { .. } => std::env::var_os("DEV_GATE").is_some(),
    };
    if candidate.is_none() && gated {
        panic!(
            "fixture cdylib for `{crate_name}` is not built: refusing to silently skip {coverage}"
        );
    }
    candidate
}

/// Print the one-line local-iteration skip notice. The single call site every fixture-gated test
/// shares, so the wording (and the fact that it goes to stderr, not stdout) can't drift per file.
pub(crate) fn note_skip(what: &str) {
    eprintln!("skip: {what} cdylib not built (run under --workspace)");
}

/// The sibling-checkout counterpart of [`note_skip`]: names the sibling repo and the exact build
/// command that produces the fixture, since "run under --workspace" doesn't apply to it.
pub(crate) fn note_skip_sibling(crate_pkg: &str, repo: &str) {
    eprintln!(
        "skip: {crate_pkg} cdylib not built (run `cargo build --release -p {crate_pkg}` in a \
         sibling ../{repo} checkout)"
    );
}

/// Checks BOTH the "uplifted" `<profile_dir>/<name>` copy (only refreshed when `[lib]` is a ROOT
/// build target, e.g. `cargo build --all-targets`) and the raw `<profile_dir>/deps/<name>`
/// compiler output (refreshed on every build that recompiles the lib). A SCOPED
/// `cargo test -p busbar-plugin-loader` does not uplift the cdylib to the top-level profile dir,
/// only to `target/deps`, so checking only `profile_dir` would find nothing even though the
/// cdylib really was built.
fn locate_in_tree(crate_name: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let profile_dir = exe.parent()?.parent()?;
    let name = crate::plugin_library_filename(crate_name);
    let uplifted = profile_dir.join(&name);
    let raw = profile_dir.join("deps").join(&name);
    [uplifted, raw]
        .into_iter()
        .filter_map(|p| {
            std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .map(|mtime| (p, mtime))
        })
        .max_by_key(|(_, mtime)| *mtime)
        .map(|(p, _)| p)
}

fn locate_sibling(repo: &str, crate_name: &str) -> Option<PathBuf> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")); // .../busbarAI/crates/plugin-loader
    let sibling_root = manifest_dir.join("../../..").join(repo); // sibling of busbarAI
    let name = crate::plugin_library_filename(crate_name);
    let candidate = sibling_root.join("target/release").join(&name);
    candidate.exists().then_some(candidate)
}
