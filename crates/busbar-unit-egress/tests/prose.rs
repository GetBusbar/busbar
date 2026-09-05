//! The unit says what it means in words, and names only what it is allowed to name.
//!
//! Two properties, both scanned from the source rather than trusted to review, in the same shape
//! the contract crate scans its own.
//!
//! A section number or a binding identifier in a comment is a cross-reference that rots the first
//! time the document is renumbered, and it tells a reader nothing they could act on. The design
//! asks for the sentence instead, so this test asks for it too.
//!
//! The dependency list is the other half. This unit is allowed to name the contract and the
//! capability crate and nothing else in the workspace: everything else it needs — the breaker, the
//! egress-auth unit, the journal, the permit store — enters through a trait the integrator binds,
//! and a direct dependency on one of those crates would quietly turn a seam into a coupling.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn manifest() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("the manifest is readable")
}

#[test]
fn the_source_cites_the_design_in_words() {
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if line.contains('§') {
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
    });
    assert!(
        offenders.is_empty(),
        "the source cites the design by number rather than in words: {offenders:?}"
    );
}

#[test]
fn the_crate_carries_its_two_lint_gates() {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("the root is readable");
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    assert!(lib.contains("#![deny(missing_docs)]"));
}

#[test]
fn the_unit_names_only_the_contract_and_the_capability_crate() {
    let manifest = manifest();
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("the manifest has a dependency section");
    let allowed = ["busbar-caps", "busbar-contract"];
    for line in deps.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // The next manifest section — `[dev-dependencies]` and beyond are a different
            // concern (test-only bindings that prove a seam is implementable, not a production
            // coupling); this check is about what the unit's OWN code is allowed to name.
            break;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line.split_whitespace().next().unwrap_or_default();
        if name.starts_with("busbar") {
            assert!(
                allowed.contains(&name),
                "the egress unit depends on {name}, which is another unit's crate"
            );
        }
    }
}

#[test]
fn the_crate_declares_no_features() {
    let manifest = manifest();
    assert!(
        !manifest.contains("[features]"),
        "a feature-gated unit is not one unit"
    );
    assert!(
        !manifest.contains("optional = true"),
        "an optional dependency is a feature by another name"
    );
}

#[test]
fn every_seam_the_integrator_binds_says_so() {
    // The marker is how a reader tells "this is bound elsewhere" from "this is unfinished". Each
    // trait the integrator has to implement carries one, so the list of work is readable off the
    // source rather than out of a hand-off note.
    let ports =
        std::fs::read_to_string(src_dir().join("ports.rs")).expect("the ports are readable");
    for seam in [
        "pub trait Breaker",
        "pub trait Capacity",
        "pub trait EgressAuth",
        "pub trait Journal",
        "pub trait Clock",
        "pub trait Telemetry",
    ] {
        let at = ports
            .find(seam)
            .unwrap_or_else(|| panic!("the {seam} seam is declared"));
        let preamble = &ports[at.saturating_sub(1200)..at];
        assert!(
            preamble.contains("// contract:"),
            "the {seam} seam does not say that the integrator binds it"
        );
    }
}

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
