//! The dependency seam the crate root describes, checked rather than described.
//!
//! `src/lib.rs`'s header is this crate's own purity argument and it is falsifiable by design — it
//! names its own proof. It went unrun, and drifted into three false claims at once: a dependency on
//! `busbar-voice` that does not exist, a `default-features = false` on a line that does not exist,
//! and `async-trait` said to be "never part of this crate's build" while the manifest names it
//! directly. The edge is also INVERTED from what the header described: `busbar-voice` depends on
//! this crate, not the reverse.
//!
//! So this file is the promised proof, in the shape the header cites: the top level of
//! `cargo tree -p busbar-plane-voice` — every direct edge of this crate, enumerated and pinned — read
//! off the manifests themselves. A claim in that header that stops being true stops compiling green.

use std::path::{Path, PathBuf};

/// This crate's own manifest directory.
fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The dependency names one `[dependencies]`-shaped table of a manifest declares, in file order.
///
/// A hand-rolled reader rather than a TOML dependency: the shape being read is one flat table of
/// `name = ...` lines, and a test that proved the seam by adding a crate to the closure it is
/// policing would be answering its own question.
fn dependency_lines(manifest: &str, table: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            inside = trimmed == table;
            continue;
        }
        if !inside || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        out.push((name.trim().to_string(), value.trim().to_string()));
    }
    out
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} is readable: {e}", path.display()))
}

/// The top level of `cargo tree -p busbar-plane-voice`: five direct edges, and exactly these five.
///
/// Pinned as a set rather than asserted about one at a time, because the failure the header's claims
/// were guarding against is an edge ARRIVING — an async runtime, a transport, a composition root —
/// not one of the five leaving.
#[test]
fn the_crate_names_five_direct_dependencies_and_no_others() {
    const EXPECTED: &[&str] = &[
        "busbar-contract",
        "busbar-voice-codec",
        "serde_json",
        "bytes",
        "async-trait",
    ];
    let manifest = read(&manifest_dir().join("Cargo.toml"));
    let named: Vec<String> = dependency_lines(&manifest, "[dependencies]")
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        named, EXPECTED,
        "the crate root's dependency-seam header enumerates this crate's direct edges; it and the \
         manifest have to be the same list"
    );
}

/// `busbar-voice` is not one of them, and neither is an async runtime.
///
/// The header once claimed this crate depends on `busbar-voice` with `default-features = false` to
/// fence off its `runtime` feature. There is no such edge and no such flag: what this crate names is
/// `busbar-voice-codec`, the pure half that was split out precisely so a pure kind could name it.
#[test]
fn the_retiring_crate_and_every_async_runtime_are_outside_this_crate_s_direct_edges() {
    const FORBIDDEN: &[&str] = &["busbar-voice", "tokio", "futures", "axum", "hyper"];
    let manifest = read(&manifest_dir().join("Cargo.toml"));
    for table in [
        "[dependencies]",
        "[dev-dependencies]",
        "[build-dependencies]",
    ] {
        for (name, value) in dependency_lines(&manifest, table) {
            assert!(
                !FORBIDDEN.contains(&name.as_str()),
                "{table} names {name}, which a pure plane's closure may not reach"
            );
            assert!(
                !value.contains("default-features"),
                "{table}'s {name} carries a default-features flag; the header states there is none"
            );
        }
    }
}

/// The edge runs the OTHER WAY: the retiring crate depends on this one.
///
/// This is the dependency inversion that lets a plane crate stay pure while the legacy runtime
/// consumes its ports (`governed`, `tools`). The header used to describe the reverse, which is the
/// direction that makes the crate look LESS pure than it is while reading as though it were more.
#[test]
fn the_retiring_crate_is_the_one_that_depends_on_this_plane() {
    let voice = manifest_dir()
        .parent()
        .expect("the crates directory")
        .join("busbar-voice/Cargo.toml");
    let manifest = read(&voice);
    let named: Vec<String> = dependency_lines(&manifest, "[dependencies]")
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert!(
        named.iter().any(|n| n == "busbar-plane-voice"),
        "busbar-voice is the crate that names busbar-plane-voice, not the reverse: {named:?}"
    );
}
