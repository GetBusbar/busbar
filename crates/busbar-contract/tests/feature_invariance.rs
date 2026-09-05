//! The contract is the same surface everywhere it is compiled.
//!
//! The core-to-plugin section of the design requires the contract to be feature-invariant, and the
//! honesty table lists a gate scan as the mechanism. This is that scan, run as a test so it fails
//! in the same place a compile error would: the crate declares no cargo features, and no item on
//! its surface is behind a conditional-compilation attribute.
//!
//! The property matters because a feature-gated contract is not one contract. A plugin built with
//! a feature on and a kernel built with it off would agree at the manifest and disagree at the
//! call, and nothing in between would notice.

use std::path::{Path, PathBuf};

/// The crate's own source directory.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The manifest declares no features at all.
#[test]
fn the_crate_declares_no_features() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("the manifest is readable");
    assert!(
        !manifest.contains("[features]"),
        "the contract declares cargo features, so it is not one surface"
    );
    assert!(
        !manifest.contains("optional = true"),
        "an optional dependency is a feature by another name"
    );
}

/// No item on the surface is behind a conditional-compilation attribute.
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
        "conditionally compiled items on the contract surface: {offenders:?}"
    );
}

/// The crate carries the two lint gates the design requires of it.
#[test]
fn the_crate_forbids_unsafe_and_undocumented_items() {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("the root is readable");
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    assert!(lib.contains("#![deny(missing_docs)]"));
}

/// The crate names no other crate of the workspace.
///
/// This is the manifest allow-list, asserted from the inside: the contract has to stand alone, so
/// a dependency on the kernel, on the capability crate, on a unit, on a plane or on a transport is
/// a failure here rather than a discovery later.
#[test]
fn the_contract_stands_alone() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("the manifest is readable");
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
        assert!(
            !name.starts_with("busbar"),
            "the contract depends on {name}, so it does not stand alone"
        );
        assert!(
            !line.contains("path ="),
            "the contract depends on a workspace crate: {line}"
        );
    }
}

/// The source names no crate a plugin manifest may not name.
#[test]
fn the_source_names_no_kernel_side_crate() {
    let forbidden = [
        "busbar_caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_plane",
        "busbar_transport",
        "busbar_substrate",
        "busbar_core",
    ];
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for name in forbidden {
            // A mention inside a doc comment is a reference by name, which the design allows;
            // a use of the identifier in code is not.
            for (n, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || trimmed.starts_with("//!") {
                    continue;
                }
                if line.contains(name) {
                    offenders.push(format!("{}:{}: {name}", path.display(), n + 1));
                }
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "the contract names kernel-side crates in code: {offenders:?}"
    );
}

/// The doc comments cite the design in words, not in section numbers or binding identifiers.
///
/// A section number in a comment is a cross-reference that rots the first time the document is
/// renumbered, and the design says as much: cite the section in words.
#[test]
fn the_doc_comments_cite_the_design_in_words() {
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if line.contains('§') {
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
    });
    assert!(
        offenders.is_empty(),
        "the source cites the design by number rather than in words: {offenders:?}"
    );
}

/// Walk every source file under a directory.
fn walk(dir: &Path, f: &mut impl FnMut(&Path, &str)) {
    let entries = std::fs::read_dir(dir).expect("the source directory is readable");
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
