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
//!
//! TWO EXEMPTIONS, and neither is on the plugin-visible surface of a release build.
//!
//! 1. The transport-facing half folded in from `busbar-contract-transport` (DECISIONS #38) carries
//!    the two NEUTRAL capability features `dispatch`/`runtime`, which gate the in-tree-only
//!    transport-axis enum (`transport::transport`). That axis is not on the wire (its derive carries
//!    no `Serialize`/`repr`) and no plugin manifest names it — transports are in-tree and never
//!    dynamically loaded — so the "plugin and kernel disagree" hazard does not reach it.
//!
//! 2. `test-seal` (#65, item 112), the contract's ONE dev-only seam. #65 sealed
//!    `plugin::KernelSeal`, so only this crate can implement it; a plane or a transport may not name
//!    `caps` (each asserts it in its own purity test) and may not take a dev edge onto the kernel
//!    (`kind-isolation:test-deps` refuses a plane/transport -> kernel edge as not-allowed), so its
//!    harness has no other legal way to present a seal. `plugin::TestKernelSeal` and its two impls
//!    in `caps/token.rs` are that seal. The hazard this file exists for — a plugin and the kernel
//!    disagreeing at the call — needs the item to exist in a shipped build, and it does not:
//!    `tests/test_seal_is_dev_only.rs` fails if any non-dev dependency edge anywhere in the
//!    workspace enables the feature, which is the guard this exemption rests on.
//!
//! The exemption is as narrow as it can be written. The feature must be named exactly `test-seal`
//! and be EMPTY (`[]`: it may switch on no dependency and no other feature). Its conditional items
//! must be spelled `#[cfg(feature = "test-seal")]` exactly — no `any(...)`/`all(...)` composition —
//! and the item under each one must be one of [`TEST_SEAL_ITEMS`], in the file that list names.
//! Any other feature, any non-empty `test-seal`, and any other item behind `test-seal` stays RED;
//! the `*_red_*` tests below plant each of those and require the finding.

use std::path::{Path, PathBuf};

/// The crate's own source directory.
fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// The two NEUTRAL transport-axis capability features folded in with `busbar-contract-transport`
/// (DECISIONS #38). Both are empty and gate only the in-tree, wire-inert transport axis.
const NEUTRAL_TRANSPORT_FEATURES: [&str; 2] = ["dispatch", "runtime"];

/// The dev-only seal feature (#65, item 112). Empty, and enabled by `[dev-dependencies]` edges only
/// (`tests/test_seal_is_dev_only.rs`).
const TEST_SEAL_FEATURE: &str = "test-seal";

/// The one attribute spelling the `test-seal` exemption accepts.
const TEST_SEAL_CFG: &str = "#[cfg(feature = \"test-seal\")]";

/// Every item `test-seal` may gate: `(file under src/, the item's first line)`. The type and its two
/// sealed-trait impls, and nothing else.
const TEST_SEAL_ITEMS: [(&str, &str); 3] = [
    ("plugin.rs", "pub struct TestKernelSeal;"),
    (
        "caps/token.rs",
        "impl crate::plugin::sealed::KernelSealed for crate::plugin::TestKernelSeal {}",
    ),
    (
        "caps/token.rs",
        "impl crate::plugin::KernelSeal for crate::plugin::TestKernelSeal {",
    ),
];

/// Every finding against the manifest's `[features]` table and optional dependencies.
fn feature_findings(manifest: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(section) = manifest.split("[features]").nth(1) {
        for line in section.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                break; // next section
            }
            let key = line.split('=').next().unwrap_or_default().trim();
            let value = line.split('=').nth(1).unwrap_or_default().trim();
            if !(NEUTRAL_TRANSPORT_FEATURES.contains(&key) || key == TEST_SEAL_FEATURE) {
                out.push(format!(
                    "the contract declares feature {key:?} beyond the neutral transport-axis gates \
                     and the dev-only `test-seal`, so its plugin-visible surface is not one surface"
                ));
            } else if value != "[]" {
                out.push(format!(
                    "the exempt feature {key:?} must stay empty, got {value:?}"
                ));
            }
        }
    }
    if manifest.contains("optional = true") {
        out.push("an optional dependency is a feature by another name".to_string());
    }
    out
}

/// Every conditionally compiled item in `(path relative to src/, text)` that no exemption covers.
fn cfg_findings(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (rel, text) in files {
        let lines: Vec<&str> = text.lines().collect();
        for (n, raw) in lines.iter().enumerate() {
            let line = raw.trim_start();
            if !(line.starts_with("#[cfg(") || line.starts_with("#![cfg(")) {
                continue;
            }
            // Test-only compilation never reaches the shipped surface.
            if line.starts_with("#[cfg(test)]") || line.starts_with("#![cfg(test)]") {
                continue;
            }
            // The two neutral transport-axis capability gates are exempt.
            if NEUTRAL_TRANSPORT_FEATURES
                .iter()
                .any(|feat| line.contains(&format!("feature = \"{feat}\"")))
            {
                continue;
            }
            // The dev-only seal: this exact attribute, over one of the named items, in its file.
            if line.trim_end() == TEST_SEAL_CFG {
                let item = lines[n + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("#["))
                    .unwrap_or_default();
                if TEST_SEAL_ITEMS
                    .iter()
                    .any(|(file, first)| rel == file && item == *first)
                {
                    continue;
                }
            }
            out.push(format!("{rel}:{}", n + 1));
        }
    }
    out
}

/// Every `.rs` under `src/`, as `(path relative to src/ with `/` separators, text)`.
fn src_files() -> Vec<(String, String)> {
    let root = src_dir();
    let mut files = Vec::new();
    walk(&root, &mut |path, text| {
        let rel = path
            .strip_prefix(&root)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        files.push((rel, text.to_string()));
    });
    files
}

/// The manifest declares no features beyond the two neutral transport-axis capability gates and the
/// dev-only `test-seal`, each empty, and no optional dependencies.
#[test]
fn the_crate_declares_no_features() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("the manifest is readable");
    let findings = feature_findings(&manifest);
    assert!(findings.is_empty(), "{findings:?}");
}

/// No item on the PLUGIN-VISIBLE surface is behind a conditional-compilation attribute. The only
/// conditionals allowed are the two neutral transport-axis capability gates, test-only `cfg(test)`,
/// and `test-seal` over exactly [`TEST_SEAL_ITEMS`] (see the module header).
#[test]
fn no_item_is_conditionally_compiled() {
    let offenders = cfg_findings(&src_files());
    assert!(
        offenders.is_empty(),
        "conditionally compiled items on the contract surface: {offenders:?}"
    );
}

/// The `test-seal` exemption is not vacuous: every item it names is really in the tree, behind the
/// exact attribute. A renamed or moved item would otherwise leave an exemption that covers nothing
/// and silently excuses the next item to take the name.
#[test]
fn every_test_seal_item_is_present_behind_its_attribute() {
    let files = src_files();
    for (file, first) in TEST_SEAL_ITEMS {
        let (_, text) = files
            .iter()
            .find(|(rel, _)| rel == file)
            .unwrap_or_else(|| panic!("src/{file} is missing"));
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let at = lines
            .iter()
            .position(|l| *l == first)
            .unwrap_or_else(|| panic!("src/{file} no longer carries `{first}`"));
        let attr = lines[..at]
            .iter()
            .rev()
            .take_while(|l| l.starts_with("#["))
            .any(|l| *l == TEST_SEAL_CFG);
        assert!(
            attr,
            "src/{file}: `{first}` is not behind `{TEST_SEAL_CFG}`"
        );
    }
}

/// RED: a feature beyond the three exemptions is refused.
#[test]
fn an_extra_feature_is_red() {
    let m = "[features]\ndispatch = []\nruntime = []\ntest-seal = []\ntest-seal-2 = []\n";
    assert_eq!(feature_findings(m).len(), 1, "{:?}", feature_findings(m));
    assert!(feature_findings("[features]\ntest-seal = []\n").is_empty());
}

/// RED: a `test-seal` that switches on anything is refused — the exemption is for an EMPTY feature.
#[test]
fn a_non_empty_test_seal_is_red() {
    for m in [
        "[features]\ntest-seal = [\"runtime\"]\n",
        "[features]\ntest-seal = [\"dep:serde_json\"]\n",
    ] {
        assert_eq!(
            feature_findings(m).len(),
            1,
            "{m}: {:?}",
            feature_findings(m)
        );
    }
}

/// RED: `test-seal` over any item but the three named ones, in any file but its own, or in any
/// spelling but the exact one, is refused.
#[test]
fn test_seal_over_another_item_is_red() {
    let plant = |rel: &str, text: &str| cfg_findings(&[(rel.to_string(), text.to_string())]);
    // The named item, in its file: exempt.
    assert!(plant(
        "plugin.rs",
        "#[cfg(feature = \"test-seal\")]\n#[derive(Debug)]\npub struct TestKernelSeal;\n"
    )
    .is_empty());
    // Another item behind the same attribute.
    assert_eq!(
        plant(
            "plugin.rs",
            "#[cfg(feature = \"test-seal\")]\npub fn helper() {}\n"
        )
        .len(),
        1
    );
    // The named item, in the wrong file.
    assert_eq!(
        plant(
            "dest.rs",
            "#[cfg(feature = \"test-seal\")]\npub struct TestKernelSeal;\n"
        )
        .len(),
        1
    );
    // A composed spelling that would also compile it somewhere else.
    assert_eq!(
        plant(
            "plugin.rs",
            "#[cfg(any(debug_assertions, feature = \"test-seal\"))]\npub struct TestKernelSeal;\n"
        )
        .len(),
        1
    );
    // Some other feature entirely.
    assert_eq!(
        plant(
            "plugin.rs",
            "#[cfg(feature = \"extra\")]\npub struct TestKernelSeal;\n"
        )
        .len(),
        1
    );
}

/// The crate carries the two lint gates the design requires of it.
#[test]
fn the_crate_forbids_unsafe_and_undocumented_items() {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("the root is readable");
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    assert!(lib.contains("#![deny(missing_docs)]"));
}

/// The crates that sit BELOW the contract, and may therefore be named by it.
///
/// `busbar-grammar` is the contract's own surface split out under its own ceiling rather than a
/// dependency in the ordinary sense: it names nothing itself, it is re-exported here, and a plugin
/// that reaches it reaches it through this crate. Anything else is a layering violation.
/// (`busbar-contract-transport` used to sit here too; DECISIONS #38 folded it into the `transport`
/// module, so it is no longer a dependency at all.)
const BELOW_THE_CONTRACT: [&str; 1] = ["busbar-grammar"];

/// The crate names no other crate of the workspace except the ones below it.
///
/// This is the manifest allow-list, asserted from the inside: the contract has to stand alone
/// against everything ABOVE it, so a dependency on the kernel, on the capability crate, on a unit,
/// on a plane or on a transport is a failure here rather than a discovery later.
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
        if BELOW_THE_CONTRACT.contains(&name) {
            continue;
        }
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
        "busbar_contract::caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_plane",
        "busbar_transport",
        "busbar_substrate",
        "busbar_kernel",
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
