//! The breaker unit understands no protocol (THE DESIGN §1: "Nothing in the kernel parses or
//! understands a protocol"; Law 1: no plugin instance is named in core logic).
//!
//! The unit reads facts only: the transport's fault reading, the kernel's fact that no answer came,
//! and a stated wait in seconds. A header read, a date parser, an HTTP status ladder, one vendor's
//! status number or one dialect's error code belongs to the transport or the plane that owns it,
//! so none of them may appear in this crate's production source or in its dependency list.
//! Scanned from the source, so a second normalizer cannot come back in by review oversight.

use std::path::{Path, PathBuf};

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every production source file of the crate (`src/**/*.rs` outside `src/tests`).
fn production_sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        let entries = std::fs::read_dir(dir).expect("the source directory is readable");
        for entry in entries {
            let path = entry.expect("a directory entry is readable").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("a source file is readable");
                out.push((path, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(&crate_dir().join("src"), &mut out);
    out
}

#[test]
fn the_unit_source_reads_no_header_and_classifies_no_status() {
    // Positive control: the scan reaches the unit's own classifier, so an empty offender list
    // means the files were read, not that none were found.
    let sources = production_sources();
    assert!(
        sources.iter().any(|(p, _)| p.ends_with("classify.rs")),
        "the scan must reach src/classify.rs; it read {:?}",
        sources.iter().map(|(p, _)| p.clone()).collect::<Vec<_>>()
    );
    let forbidden = [
        ("httpdate", "an HTTP-date parser"),
        ("HeaderMap", "an HTTP header map"),
        ("http::header", "an HTTP header name"),
        ("http_status", "an HTTP status ladder"),
        ("529", "one vendor's overload status"),
        ("PROVIDER_CODE_CONTEXT_LENGTH", "one dialect's error code"),
        ("mod normalize", "the retired engines' normalizer"),
    ];
    let mut offenders = Vec::new();
    for (path, text) in &sources {
        for (n, line) in text.lines().enumerate() {
            for (needle, what) in forbidden {
                if line.contains(needle) {
                    offenders.push(format!("{}:{}: {what} (`{needle}`)", path.display(), n + 1));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "the breaker unit understands a protocol: {offenders:#?}"
    );
}

#[test]
fn the_unit_depends_on_no_date_parser() {
    let manifest = std::fs::read_to_string(crate_dir().join("Cargo.toml"))
        .expect("the manifest is readable");
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("the manifest has a dependency section");
    let deps = deps.split("\n[").next().unwrap_or(deps);
    assert!(
        deps.contains("busbar-contract"),
        "positive control: the dependency section names the contract: {deps}"
    );
    let named: Vec<&str> = deps
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| l.starts_with("httpdate") || l.starts_with("http "))
        .collect();
    assert!(
        named.is_empty(),
        "the breaker unit depends on an HTTP parsing crate: {named:?}"
    );
}
