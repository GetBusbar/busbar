//! This plane is the same plane everywhere it is compiled.
//!
//! A plane compiled two ways is two planes, and the kernel would have no way to tell which one it
//! registered. The contract crate holds itself to that rule and asserts it; this is the same
//! assertion, one crate over, for the same reason.

use std::path::{Path, PathBuf};

/// The crate's own source directory.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The crate's own manifest.
fn manifest() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the manifest is readable")
}

/// Walk every source file, handing each to a reader.
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

/// No item on the surface is behind a conditional-compilation attribute.
///
/// Test modules are exempt, because a test module is not on the surface: it is compiled only when
/// the tests are, and the kernel never sees it.
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

/// The manifest names the contract, the codec and the serializer, and nothing kernel-side.
#[test]
fn the_manifest_names_only_what_a_plane_may_name() {
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
            "busbar-core",
            "busbar-substrate",
            "busbar-caps",
            "busbar-kernel",
            "busbar-unit-",
            "busbar-plane-llm",
            "busbar-plane-mcp",
        ] {
            assert!(
                !name.starts_with(forbidden),
                "the plane depends on {name}, which is kernel-side"
            );
        }
    }
}

/// The comments cite the design in words, not in section numbers or binding identifiers.
///
/// A section number in a comment is a cross-reference that rots the first time the document is
/// renumbered, and the design says as much: cite the section in words.
#[test]
fn the_comments_cite_the_design_in_words() {
    let mut offenders = Vec::new();
    let mut check = |path: &Path, text: &str| {
        for (n, line) in text.lines().enumerate() {
            if line.contains('\u{a7}') {
                offenders.push(format!("{}:{}: section sign", path.display(), n + 1));
            }
            let bytes = line.as_bytes();
            for i in 0..bytes.len().saturating_sub(4) {
                if bytes[i] == b'P'
                    && bytes[i + 1] == b'B'
                    && bytes[i + 2] == b'-'
                    && bytes[i + 3].is_ascii_digit()
                {
                    offenders.push(format!("{}:{}: binding identifier", path.display(), n + 1));
                }
            }
        }
    };
    walk(&src_dir(), &mut check);
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests"),
        &mut check,
    );
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    check(&manifest_path, &manifest());
    assert!(
        offenders.is_empty(),
        "the source cites the design by number rather than in words: {offenders:?}"
    );
}
