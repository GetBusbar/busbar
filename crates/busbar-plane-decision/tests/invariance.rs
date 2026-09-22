//! This plane is the same plane everywhere it is compiled.
//!
//! Mirrors `busbar-plane-a2a`/`busbar-plane-mcp`'s own `invariance.rs`, and mirrors it exactly now:
//! the ONE deliberate difference it used to carry — this manifest named the legacy plugin-facing
//! crate for `UpstreamCreds`, which its pure siblings never did — is gone, and that crate has
//! joined the forbidden list rather than the allowed one. The exception was not free. It depends on
//! `sha2`, so the manifest edge put `sha2 -> cpufeatures -> libc` in a pure plane's closure, which
//! the transitive source denylist bans outright, and this was the only plane of the five with such
//! an edge (1 occurrence against 0 for the other four). `UpstreamCreds` moved to
//! `busbar_contract::config::UpstreamCreds` verbatim, the same route `ModelCfg` took out of
//! `busbar-substrate`/`busbar-kernel` (DECISIONS #40/#38), so both reserved model-serving shapes
//! now arrive from the crate a plugin may name and the manifest names exactly one busbar crate. The
//! forbidden list is that crate, `busbar-core`, `busbar-caps`, `busbar-kernel`, `busbar-unit-*`,
//! and the sibling PLANE crates (naming another plane would be a plane reading another plane's
//! private surface, never legitimate for any plane).
//!
//! `the_manifest_names_only_what_this_plane_may_name` was RED for as long as this manifest named
//! `busbar-kernel`, and it is GREEN now because the manifest does not. The edge existed for ONE
//! file — `src/registry.rs`, a `PlaneDecl` constant declared against a FUTURE root registration
//! that never arrived — and that file was deleted, not relocated: nothing outside this crate ever
//! named `PLANE_DECL`, and the binary does not even depend on this crate. This test is the #40
//! witness for that closure, so it must never be relaxed to keep it green; if `busbar-kernel`
//! returns to the manifest, this is the line that is supposed to fail.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn manifest() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the manifest is readable")
}

fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    for entry in std::fs::read_dir(dir)
        .expect("the source directory is readable")
        .flatten()
    {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}

/// The manifest declares no features at all.
#[test]
fn the_crate_declares_no_features() {
    let manifest = manifest();
    assert!(
        !manifest.contains("[features]"),
        "the plane declares cargo features, so it is not one plane"
    );
    assert!(
        !manifest.contains("optional = true"),
        "an optional dependency is a feature by another name"
    );
}

/// No item on the surface is behind a conditional-compilation attribute (test modules exempted).
#[test]
fn no_item_is_conditionally_compiled() {
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            let line = line.trim_start();
            if line.starts_with("#[cfg(test)]") {
                continue;
            }
            if line.starts_with("#[cfg(") || line.starts_with("#![cfg(") {
                offenders.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "conditionally compiled items: {offenders:?}"
    );
}

/// The crate carries the two lint gates the design requires of a plugin.
#[test]
fn the_crate_forbids_unsafe_and_undocumented_items() {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("the root is readable");
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    assert!(lib.contains("#![deny(missing_docs)]"));
}

/// No source file contains the word the lint gate forbids.
#[test]
fn the_source_contains_no_unsafe_block() {
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//") {
                continue;
            }
            if line.contains("unsafe ") {
                offenders.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "unsafe code on the surface: {offenders:?}"
    );
}

/// The manifest names only the contract (which holds both explicitly-ruled model-serving config
/// types, `ModelCfg` and `UpstreamCreds`) and the serializer — never a genuinely kernel-side crate,
/// never the legacy plugin-facing one, never a sibling plane.
#[test]
fn the_manifest_names_only_what_this_plane_may_name() {
    let manifest = manifest();
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("the manifest has a dependency section");
    for line in deps.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let name = line.split_whitespace().next().unwrap_or_default();
        for forbidden in [
            // The edge this plane alone had, and the one that reached banned source. It is a ban,
            // not an exception, since `UpstreamCreds` moved to `busbar-contract`.
            "busbar-api",
            "busbar-core",
            "busbar-caps",
            "busbar-kernel",
            "busbar-unit-",
            "busbar-plane-llm",
            "busbar-plane-mcp",
            "busbar-plane-a2a",
            "busbar-plane-streaming",
            "busbar-admin",
        ] {
            assert!(
                !name.starts_with(forbidden),
                "the plane depends on {name}, which is kernel-side or a sibling plane"
            );
        }
    }
}

/// The comments cite the design in words, not in section numbers or binding identifiers.
#[test]
fn the_comments_cite_the_design_in_words() {
    let mut offenders = Vec::new();
    let mut check = |path: &Path, text: &str| {
        for (n, line) in text.lines().enumerate() {
            if line.contains('\u{a7}') {
                offenders.push(format!("{}:{}: section sign", path.display(), n + 1));
            }
        }
    };
    walk(&src_dir(), &mut check);
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"),
        &mut check,
    );
    assert!(
        offenders.is_empty(),
        "the source cites the design by section-sign rather than in words: {offenders:?}"
    );
}
