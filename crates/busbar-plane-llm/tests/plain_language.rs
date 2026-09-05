//! The crate says what it means, in words, and names nothing it may not name.
//!
//! Copied in shape from the contract crate's own scan, because the properties are the same ones and
//! a second mechanism for the same rule would be a second rule. Four things are checked: the crate
//! declares no features, it carries the two lint gates a plane is required to carry, its source
//! names no kernel-side crate, and its comments cite the design in prose rather than by number.
//!
//! The last one is worth stating plainly: a section number in a comment is a cross-reference that
//! goes stale the first time the document is renumbered, and a stale cross-reference is worse than
//! none, because a reader trusts it.

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

/// The manifest declares no features at all.
///
/// A plane compiled two ways is two planes, and the registry has no way to tell which one it holds.
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

/// No item is behind a conditional-compilation attribute.
#[test]
fn no_item_is_conditionally_compiled() {
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            let line = line.trim_start();
            if line.starts_with("#[cfg(") || line.starts_with("#![cfg(") {
                offenders.push(format!("{}:{}", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "conditionally compiled items in a plane: {offenders:?}"
    );
}

/// The crate carries the two lint gates a plane is required to carry.
#[test]
fn the_crate_forbids_unsafe_and_undocumented_items() {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("the root is readable");
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    assert!(lib.contains("#![deny(missing_docs)]"));
}

/// The source names no crate a plane's manifest may not name.
///
/// The kernel, the capability crate and the units are all on the far side of the contract from a
/// plane. Naming one would be a plane reaching back into core, which is the one direction the whole
/// architecture forbids.
#[test]
fn the_source_names_no_kernel_side_crate() {
    let forbidden = [
        "busbar_caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_core",
        "busbar_transport",
        "plane_host",
    ];
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            for name in forbidden {
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the plane names kernel-side crates in code: {offenders:?}"
    );
}

/// The manifest names only the contract, the codecs and reviewed third-party crates.
#[test]
fn the_manifest_names_only_what_a_plane_may_name() {
    let manifest = manifest();
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("the manifest has a dependency section");
    let allowed = ["busbar-contract", "busbar-llm"];
    for line in deps.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        let name = line.split_whitespace().next().unwrap_or_default();
        if name.starts_with("busbar") {
            assert!(
                allowed.contains(&name),
                "the plane depends on the workspace crate {name}, which a plane may not name"
            );
        }
    }
}

/// The comments cite the design in words, not in section numbers or binding identifiers.
#[test]
fn the_doc_comments_cite_the_design_in_words() {
    let mut offenders = Vec::new();
    let mut check = |path: &Path, text: &str| {
        for (n, line) in text.lines().enumerate() {
            if line.contains('\u{a7}') {
                offenders.push(format!("{}:{}: section sign", path.display(), n + 1));
            }
            // A parity-binding identifier is a two-letter prefix, a hyphen and digits.
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
    assert!(
        offenders.is_empty(),
        "the source cites the design by number rather than in words: {offenders:?}"
    );
}

/// Walk every source file under a directory.
fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    let entries = std::fs::read_dir(dir).expect("the directory is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("a source file is readable");
            f(&path, &text);
        }
    }
}
