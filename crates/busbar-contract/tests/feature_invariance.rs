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
//!    in `caps/token.rs` are that seal (also compiled for this crate's own `cfg(test)`, where the
//!    `Secret<T>` cell presents it), and `KernelSeal::acquire_for_kernel` is the tests' minter
//!    of the concrete seal (#65: a release build's only seal is the kernel's own). The hazard this
//!    file exists for — a plugin and the kernel disagreeing at the call — needs the item to exist in a shipped build, and it does not:
//!    `tests/test_seal_is_dev_only.rs` fails if any non-dev dependency edge anywhere in the
//!    workspace enables the feature, which is the guard this exemption rests on.
//!
//! The exemption is as narrow as it can be written. The feature must be named exactly `test-seal`
//! and be EMPTY (`[]`: it may switch on no dependency and no other feature). The minter must be
//! spelled `#[cfg(feature = "test-seal")]` exactly ([`TEST_SEAL_ITEMS`]); the seal type and its two
//! impls exactly `#[cfg(any(test, feature = "test-seal"))]` ([`TEST_SEAL_TYPE_ITEMS`]) — no other
//! composition — each in the file its list names.
//! Any other feature, any non-empty `test-seal`, and any other item behind `test-seal` stays RED;
//! the `*_red_*` tests below plant each of those and require the finding.
//!
//! 3. The TEST KIT (Locked Decision #33, "there is NO testkit"): `pub mod testkit;` in `lib.rs`,
//!    and the plugin test support `pub mod test_support;` in `abi/sdk/mod.rs` (the all-zero ABI
//!    structs and the Statement reader a plugin's tests drive its door with, no `unsafe`), each
//!    behind exactly [`TESTKIT_CFG`] — this crate's own `cfg(test)`, or the same dev-only
//!    `test-seal` feature a plugin's `[dev-dependencies]` edge already enables. No new feature, so
//!    the surface a plugin compiles against in a release build has neither in it at all.
//!
//! 4. The SHARED HOST-SERVICES DOUBLE (busbar #476 follow-up): `pub mod double;` in `services.rs`,
//!    behind exactly [`SERVICES_DOUBLE_CFG`] — this crate's own `cfg(test)`, or the dev-only, EMPTY
//!    `services-double` feature a plugin's `[dev-dependencies]` edge enables
//!    (`tests/test_seal_is_dev_only.rs` refuses any other edge). It is a `HostServices` test
//!    double, the host's trait and not the plugin ABI, so a release build carries none of it.
//!
//! 5. The COUNTING ALLOCATOR (ARCHITECT ruling 2026-10-21): `pub mod alloc_counter;` in `lib.rs`,
//!    behind exactly [`ALLOC_COUNTER_CFG`] — this crate's own `cfg(test)`, or the dev-only, EMPTY
//!    `alloc-counter` feature a plugin's `[dev-dependencies]` edge enables
//!    (`tests/test_seal_is_dev_only.rs` refuses any other edge and any `default` naming it). Plugin
//!    crate roots keep the literal `#![forbid(unsafe_code)]`, so the `GlobalAlloc` impl their
//!    allocation gates install lives here. Its `#[allow(unsafe_code)]` is the unsafe policy's
//!    second and last sanctioned site, over [`ALLOC_COUNTER_IMPL`] alone (see
//!    [`unsafe_findings`]).

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

/// The one attribute spelling the `test-seal` exemption accepts for the minter.
const TEST_SEAL_CFG: &str = "#[cfg(feature = \"test-seal\")]";

/// The one attribute the test seal TYPE and its two sealed-trait impls carry: this crate's own unit
/// tests (the `Secret<T>` cell presents the seal; `cargo test -p busbar-contract` turns no feature on,
/// so a feature-only type is absent there and the cell does not compile) or the dev-only feature.
/// `cfg(test)` never reaches a shipped build, so this is no wider than [`TEST_SEAL_CFG`] in a release.
const TEST_SEAL_TYPE_CFG: &str = "#[cfg(any(test, feature = \"test-seal\"))]";

/// The items [`TEST_SEAL_TYPE_CFG`] gates: the type and its two sealed-trait impls. The minter
/// `acquire_for_kernel` is NOT among them: it stays behind [`TEST_SEAL_CFG`] alone.
const TEST_SEAL_TYPE_ITEMS: [(&str, &str); 3] = [
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

/// The one attribute the test kit's module declaration may carry: the crate's own tests, or the
/// dev-only seal feature. Nothing else may be spelled this way.
const TESTKIT_CFG: &str = "#[cfg(any(test, feature = \"test-seal\"))]";

/// The two items [`TESTKIT_CFG`] may gate: `(file under src/, the item's first line)`. The test kit,
/// and the plugin test support (it holds `unsafe`, so it lives under `abi/`).
const TESTKIT_ITEMS: [(&str, &str); 2] = [
    ("lib.rs", "pub mod testkit;"),
    ("abi/sdk/mod.rs", "pub mod test_support;"),
];

/// The dev-only shared host-services double's feature. Empty, and enabled by `[dev-dependencies]`
/// edges only (`tests/test_seal_is_dev_only.rs`).
const SERVICES_DOUBLE_FEATURE: &str = "services-double";

/// The one attribute the shared double's module declaration may carry.
const SERVICES_DOUBLE_CFG: &str = "#[cfg(any(test, feature = \"services-double\"))]";

/// The one item [`SERVICES_DOUBLE_CFG`] may gate: `(file under src/, the item's first line)`.
const SERVICES_DOUBLE_ITEM: (&str, &str) = ("services.rs", "pub mod double;");

/// The dev-only counting allocator's feature. Empty, never in `default`, and enabled by
/// `[dev-dependencies]` edges only (`tests/test_seal_is_dev_only.rs`).
const ALLOC_COUNTER_FEATURE: &str = "alloc-counter";

/// The one attribute the counting allocator's module declaration may carry.
const ALLOC_COUNTER_CFG: &str = "#[cfg(any(test, feature = \"alloc-counter\"))]";

/// The one item [`ALLOC_COUNTER_CFG`] may gate: `(file under src/, the item's first line)`.
const ALLOC_COUNTER_ITEM: (&str, &str) = ("lib.rs", "pub mod alloc_counter;");

/// The one item outside `abi/` an `#[allow(unsafe_code)]` may sit over, and the only place outside
/// `abi/` an `unsafe` token may appear (between this line and the block's closing `}`):
/// `(file under src/, the item's first line)`. The allocator impl, not its module.
const ALLOC_COUNTER_IMPL: (&str, &str) =
    ("alloc_counter.rs", "unsafe impl GlobalAlloc for Counting {");

/// Every item `test-seal` alone may gate: `(file under src/, the item's first line)`. The tests'
/// seal minter `KernelSeal::acquire_for_kernel` (#65, ARCHITECT ruling 2026-10-14: the release seal
/// reaches the kernel through its own symbol, so the minter is dev-only), and nothing else.
const TEST_SEAL_ITEMS: [(&str, &str); 1] =
    [("caps/token.rs", "pub fn acquire_for_kernel() -> Self {")];

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
            if !(NEUTRAL_TRANSPORT_FEATURES.contains(&key)
                || key == TEST_SEAL_FEATURE
                || key == SERVICES_DOUBLE_FEATURE
                || key == ALLOC_COUNTER_FEATURE)
            {
                out.push(format!(
                    "the contract declares feature {key:?} beyond the neutral transport-axis gates \
                     and the dev-only `test-seal`, `services-double` and `alloc-counter`, so its \
                     plugin-visible surface is not one surface"
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
            // The test kit's and the test support's declarations: this exact attribute, over one of
            // those two items, in its own file.
            if line.trim_end() == TESTKIT_CFG {
                let item = lines[n + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("#["))
                    .unwrap_or_default();
                if TESTKIT_ITEMS
                    .iter()
                    .any(|(file, first)| rel == file && item == *first)
                {
                    continue;
                }
            }
            // The test seal type and its two impls: this exact attribute, over one of those items.
            if line.trim_end() == TEST_SEAL_TYPE_CFG {
                let item = lines[n + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("#["))
                    .unwrap_or_default();
                if TEST_SEAL_TYPE_ITEMS
                    .iter()
                    .any(|(file, first)| rel == file && item == *first)
                {
                    continue;
                }
            }
            // The shared host-services double: this exact attribute, over that one item, in
            // services.rs.
            if line.trim_end() == SERVICES_DOUBLE_CFG {
                let item = lines[n + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("#["))
                    .unwrap_or_default();
                if rel == SERVICES_DOUBLE_ITEM.0 && item == SERVICES_DOUBLE_ITEM.1 {
                    continue;
                }
            }
            // The counting allocator: this exact attribute, over that one item, in lib.rs.
            if line.trim_end() == ALLOC_COUNTER_CFG {
                let item = lines[n + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("#["))
                    .unwrap_or_default();
                if rel == ALLOC_COUNTER_ITEM.0 && item == ALLOC_COUNTER_ITEM.1 {
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
/// dev-only `test-seal` and `services-double`, each empty, and no optional dependencies.
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
/// and `test-seal` over exactly [`TEST_SEAL_ITEMS`] and [`TEST_SEAL_TYPE_ITEMS`] (see the module
/// header).
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
    let gated = TEST_SEAL_ITEMS
        .iter()
        .map(|item| (item, TEST_SEAL_CFG))
        .chain(
            TEST_SEAL_TYPE_ITEMS
                .iter()
                .map(|item| (item, TEST_SEAL_TYPE_CFG)),
        );
    for (&(file, first), cfg) in gated {
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
            .any(|l| *l == cfg);
        assert!(attr, "src/{file}: `{first}` is not behind `{cfg}`");
    }
}

/// Locked Decision #33: the test kit is not in a release build, nor is the plugin test support.
/// Each declaration carries exactly [`TESTKIT_CFG`]; an ungated `pub mod testkit;` or
/// `pub mod test_support;` (shipping in every build) is RED here.
#[test]
fn the_testkit_is_behind_its_test_only_attribute() {
    let files = src_files();
    for (file, first) in TESTKIT_ITEMS {
        let (_, text) = files
            .iter()
            .find(|(rel, _)| rel == file)
            .unwrap_or_else(|| panic!("src/{file} is present"));
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let at = lines
            .iter()
            .position(|l| *l == first)
            .unwrap_or_else(|| panic!("src/{file} still declares `{first}`"));
        assert!(
            lines[..at]
                .iter()
                .rev()
                .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
                .any(|l| *l == TESTKIT_CFG),
            "src/{file}: `{first}` is not behind `{TESTKIT_CFG}`, so it ships in every build"
        );
    }
}

/// The shared host-services double is not in a release build: its declaration carries exactly
/// [`SERVICES_DOUBLE_CFG`]; an ungated `pub mod double;` (the double shipping in every build) is
/// RED here.
#[test]
fn the_services_double_is_behind_its_test_only_attribute() {
    let files = src_files();
    let (_, text) = files
        .iter()
        .find(|(rel, _)| rel == SERVICES_DOUBLE_ITEM.0)
        .expect("src/services.rs is present");
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let at = lines
        .iter()
        .position(|l| *l == SERVICES_DOUBLE_ITEM.1)
        .expect("src/services.rs still declares the shared double");
    assert!(
        lines[..at]
            .iter()
            .rev()
            .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
            .any(|l| *l == SERVICES_DOUBLE_CFG),
        "src/services.rs: `{}` is not behind `{SERVICES_DOUBLE_CFG}`, so the double ships in every \
         build",
        SERVICES_DOUBLE_ITEM.1
    );
}

/// RED: the shared double's attribute over any other item, in any other file, or spelled any
/// other way, is refused; a non-empty `services-double` is refused.
#[test]
fn the_services_double_attribute_over_another_item_is_red() {
    let plant = |rel: &str, text: String| cfg_findings(&[(rel.to_string(), text)]);
    let right =
        format!("{SERVICES_DOUBLE_CFG}\n#[path = \"services_double.rs\"]\npub mod double;\n");
    assert!(plant("services.rs", right.clone()).is_empty());
    assert_eq!(plant("lib.rs", right).len(), 1);
    let other = format!("{SERVICES_DOUBLE_CFG}\npub fn shipped_only_sometimes() {{}}\n");
    assert_eq!(plant("services.rs", other).len(), 1);
    let composed =
        "#[cfg(any(debug_assertions, feature = \"services-double\"))]\npub mod double;\n";
    assert_eq!(plant("services.rs", composed.to_string()).len(), 1);
    assert!(feature_findings("[features]\nservices-double = []\n").is_empty());
    assert_eq!(
        feature_findings("[features]\nservices-double = [\"runtime\"]\n").len(),
        1
    );
}

/// RED: the test kit's attribute over any other item, or in any other file, is refused.
#[test]
fn the_testkit_attribute_over_another_item_is_red() {
    let planted = format!("{TESTKIT_CFG}\npub fn shipped_only_sometimes() {{}}\n");
    assert_eq!(
        cfg_findings(&[("lib.rs".to_string(), planted.clone())]).len(),
        1
    );
    let moved = format!("{TESTKIT_CFG}\npub mod testkit;\n");
    assert_eq!(cfg_findings(&[("plugin.rs".to_string(), moved)]).len(), 1);
    let right = format!("{TESTKIT_CFG}\npub mod testkit;\n");
    assert!(cfg_findings(&[("lib.rs".to_string(), right)]).is_empty());
    // The plugin test support: its own file only, and the kit's file holds no second item.
    let support = format!("{TESTKIT_CFG}\npub mod test_support;\n");
    assert!(cfg_findings(&[("abi/sdk/mod.rs".to_string(), support.clone())]).is_empty());
    assert_eq!(
        cfg_findings(&[("lib.rs".to_string(), support.clone())]).len(),
        1
    );
    assert_eq!(
        cfg_findings(&[("abi/mod.rs".to_string(), support)]).len(),
        1
    );
    let other = format!("{TESTKIT_CFG}\npub mod testkit;\n");
    assert_eq!(
        cfg_findings(&[("abi/sdk/mod.rs".to_string(), other)]).len(),
        1
    );
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

/// RED: `test-seal` over any item but the four named ones, in any file but its own, or in any
/// spelling but the exact one that item takes, is refused.
#[test]
fn test_seal_over_another_item_is_red() {
    let plant = |rel: &str, text: &str| cfg_findings(&[(rel.to_string(), text.to_string())]);
    // The named items, in their files, each behind its own attribute: exempt.
    assert!(plant(
        "plugin.rs",
        "#[cfg(any(test, feature = \"test-seal\"))]\n#[derive(Debug)]\npub struct TestKernelSeal;\n"
    )
    .is_empty());
    assert!(plant(
        "caps/token.rs",
        "#[cfg(feature = \"test-seal\")]\npub fn acquire_for_kernel() -> Self {\n"
    )
    .is_empty());
    // The minter may not take the type's wider attribute: a seal minted in every `cfg(test)` build.
    assert_eq!(
        plant(
            "caps/token.rs",
            "#[cfg(any(test, feature = \"test-seal\"))]\npub fn acquire_for_kernel() -> Self {\n"
        )
        .len(),
        1
    );
    // Another item behind the type's attribute.
    assert_eq!(
        plant(
            "plugin.rs",
            "#[cfg(any(test, feature = \"test-seal\"))]\npub fn helper() {}\n"
        )
        .len(),
        1
    );
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

/// The crate carries the two lint gates the design requires of it: `unsafe` is denied crate-wide
/// and undocumented items are denied.
///
/// UNSAFE POLICY after the #84 merge. The plugin C ABI and its SDK folded in as ONE module,
/// `abi`, and that module IS the FFI boundary: `#[repr(C)]` declarations a `'static` must be `Sync`
/// to hold, sized-struct reads over a peer's pointer, the export boundary, and the one set of frozen
/// `#[no_mangle]` door symbols (defined once so two plugins linked into one image never define them
/// twice). A crate-level `forbid` cannot be lifted for one module, so the crate DENIES `unsafe_code`
/// and exactly ONE `#[allow(unsafe_code)]` exists — on `pub mod abi;` — and no `unsafe` token appears
/// in any source file outside `src/abi/`. Every module that was unsafe-free under `forbid` is still
/// unsafe-free, now by this scan plus the crate-level `deny`.
///
/// ONE MORE SITE (ARCHITECT ruling 2026-10-21): the test-only counting allocator's
/// `unsafe impl GlobalAlloc` ([`ALLOC_COUNTER_IMPL`]) carries the second and last allow, over that
/// impl block alone; the rest of `alloc_counter.rs` stays under the crate's `deny`.
#[test]
fn the_crate_denies_unsafe_outside_the_abi_and_undocumented_items() {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("the root is readable");
    assert!(lib.contains("#![deny(unsafe_code)]"));
    assert!(lib.contains("#![deny(missing_docs)]"));
    let findings = unsafe_findings(&src_files());
    assert!(findings.is_empty(), "{findings:?}");
}

/// Every breach of the unsafe policy in `(path relative to src/, text)`: an `allow(unsafe_code)`
/// anywhere but over `pub mod abi;` in `lib.rs` or over [`ALLOC_COUNTER_IMPL`] in its file, more
/// than one allow at either site, an `unsafe` token outside `abi/` and outside that one impl block,
/// or a crate-level `allow`/`warn` that would re-open the whole crate.
fn unsafe_findings(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let mut abi_allows = 0;
    let mut alloc_allows = 0;
    let mut allows = 0;
    for (rel, text) in files {
        let lines: Vec<&str> = text.lines().collect();
        // The allocator impl block: from its first line to the first line that is `}` alone.
        let mut in_alloc_impl = false;
        for (n, raw) in lines.iter().enumerate() {
            let line = raw.trim_start();
            if rel == ALLOC_COUNTER_IMPL.0 && raw.trim_end() == ALLOC_COUNTER_IMPL.1 {
                in_alloc_impl = true;
            }
            let inside_impl = in_alloc_impl;
            if in_alloc_impl && raw.trim_end() == "}" {
                in_alloc_impl = false;
            }
            if line.starts_with("//") {
                continue;
            }
            // An attribute is read WHOLE: one that spans lines (`#[allow(\n    unsafe_code)]`) is
            // joined to its closing `]` and read without whitespace, and the item it sits over is
            // the first line after that.
            let (attr, attr_end) = if line.starts_with("#[") || line.starts_with("#![") {
                attribute_at(&lines, n)
            } else {
                (String::new(), n)
            };
            if attr.starts_with("#![")
                && attr.contains("unsafe_code")
                && !attr.starts_with("#![deny(unsafe_code)]")
                && !attr.starts_with("#![forbid(unsafe_code)]")
            {
                out.push(format!(
                    "{rel}:{}: a crate- or module-level unsafe_code attribute other than deny or forbid",
                    n + 1
                ));
            }
            if attr.starts_with("#[") && attr.contains("allow(") && attr.contains("unsafe_code") {
                allows += 1;
                let item = lines[attr_end + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.starts_with("#[") && !l.starts_with("//"))
                    .unwrap_or_default();
                if rel == "lib.rs" && item == "pub mod abi;" {
                    abi_allows += 1;
                } else if rel == ALLOC_COUNTER_IMPL.0 && item == ALLOC_COUNTER_IMPL.1 {
                    alloc_allows += 1;
                } else {
                    out.push(format!("{rel}:{}: allow(unsafe_code) over `{item}`", n + 1));
                }
            }
            if !rel.starts_with("abi/") && !inside_impl && has_unsafe_token(line) {
                out.push(format!(
                    "{rel}:{}: unsafe outside the abi module and the counting allocator's impl",
                    n + 1
                ));
            }
        }
    }
    if abi_allows > 1 {
        out.push(format!(
            "{abi_allows} allow(unsafe_code) attributes over `pub mod abi;`; exactly one is permitted"
        ));
    }
    if alloc_allows > 1 {
        out.push(format!(
            "{alloc_allows} allow(unsafe_code) attributes over the counting allocator's impl; \
             exactly one is permitted"
        ));
    }
    // THE TOTAL, beside the per-site counts: two allows in the whole crate, one per sanctioned site.
    if allows > 2 {
        out.push(format!(
            "{allows} allow(unsafe_code) attributes in all; exactly two are permitted"
        ));
    }
    out
}

/// The attribute that opens on line `n`, joined across lines up to its balancing `]` and with
/// every whitespace character removed, and the index of the line it closes on.
fn attribute_at(lines: &[&str], n: usize) -> (String, usize) {
    let mut joined = String::new();
    let mut depth = 0i32;
    for (at, l) in lines.iter().enumerate().skip(n) {
        let code = l.split("//").next().unwrap_or_default();
        for c in code.chars() {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                _ => {}
            }
            if !c.is_whitespace() {
                joined.push(c);
            }
        }
        if depth <= 0 {
            return (joined, at);
        }
    }
    (joined, lines.len().saturating_sub(1))
}

/// True when `line` holds the `unsafe` keyword as a whole word (not inside `unsafe_code`).
fn has_unsafe_token(line: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(at) = line[from..].find("unsafe") {
        let start = from + at;
        let end = start + "unsafe".len();
        let before =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let after =
            end == bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if before && after {
            return true;
        }
        from = end;
    }
    false
}

/// RED: the unsafe policy refuses an `unsafe` block outside `abi/`, a second allow, an allow over any
/// other module, and a crate-level re-opening; the one sanctioned allow and `abi/` unsafe pass.
#[test]
fn an_unsafe_site_outside_the_abi_is_red() {
    let plant = |rel: &str, text: &str| unsafe_findings(&[(rel.to_string(), text.to_string())]);
    assert!(plant(
        "lib.rs",
        "#![deny(unsafe_code)]\n#[allow(unsafe_code)]\npub mod abi;\n"
    )
    .is_empty());
    assert!(plant("abi/hot/decl.rs", "unsafe impl Sync for PlaneDecl {}\n").is_empty());
    assert!(plant(
        "dest.rs",
        "// an unsafe word in a comment\n#[deny(unsafe_code)]\nfn f() {}\n"
    )
    .is_empty());
    assert_eq!(plant("dest.rs", "fn f() { unsafe { g() } }\n").len(), 1);
    assert_eq!(
        plant("lib.rs", "#[allow(unsafe_code)]\npub mod dest;\n").len(),
        1
    );
    assert_eq!(plant("lib.rs", "#![allow(unsafe_code)]\n").len(), 1);
    // A third allow, beside the two sanctioned ones: red per site (over `mod inner;`) AND red on
    // the total (three in all).
    let three = unsafe_findings(&[
        (
            "lib.rs".to_string(),
            "#[allow(unsafe_code)]\npub mod abi;\n".to_string(),
        ),
        (
            "alloc_counter.rs".to_string(),
            "#[allow(unsafe_code)]\nunsafe impl GlobalAlloc for Counting {\n}\n".to_string(),
        ),
        (
            "abi/mod.rs".to_string(),
            "#[allow(unsafe_code)]\nmod inner;\n".to_string(),
        ),
    ]);
    assert_eq!(three.len(), 2, "{three:?}");
    // The two sanctioned sites alone are green.
    let sanctioned = unsafe_findings(&[
        (
            "lib.rs".to_string(),
            "#[allow(unsafe_code)]\npub mod abi;\n".to_string(),
        ),
        (
            "alloc_counter.rs".to_string(),
            "#[allow(unsafe_code)]\nunsafe impl GlobalAlloc for Counting {\n}\n".to_string(),
        ),
    ]);
    assert!(sanctioned.is_empty(), "{sanctioned:?}");
}

/// RED: an attribute split across lines is read whole. A multi-line `#[allow(\n unsafe_code)]`
/// over a `#[no_mangle]` item, and a multi-line crate-level `#![allow(...)]`, are refused like
/// their one-line spellings; the sanctioned allow split across lines still counts toward the total.
#[test]
fn a_multi_line_unsafe_code_attribute_is_red() {
    let plant = |rel: &str, text: &str| unsafe_findings(&[(rel.to_string(), text.to_string())]);
    let split = "#[allow(\n    unsafe_code\n)]\n#[no_mangle]\npub extern \"C\" fn exported() {}\n";
    let found = plant("dest.rs", split);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("pub extern"), "{found:?}");
    assert_eq!(plant("lib.rs", "#![allow(\n    unsafe_code\n)]\n").len(), 1);
    assert_eq!(
        plant(
            "lib.rs",
            "#![cfg_attr(\n    test,\n    allow(unsafe_code)\n)]\n"
        )
        .len(),
        1
    );
    // Split across lines over the sanctioned module: still the sanctioned site, still counted.
    assert!(plant("lib.rs", "#[allow(\n    unsafe_code\n)]\npub mod abi;\n").is_empty());
    let over = unsafe_findings(&[
        (
            "lib.rs".to_string(),
            "#[allow(\n    unsafe_code,\n)]\npub mod abi;\n".to_string(),
        ),
        (
            "alloc_counter.rs".to_string(),
            "#[allow(unsafe_code)]\nunsafe impl GlobalAlloc for Counting {\n}\n".to_string(),
        ),
        (
            "dest.rs".to_string(),
            "#[allow(\n    unsafe_code\n)]\n#[no_mangle]\npub extern \"C\" fn exported() {}\n"
                .to_string(),
        ),
    ]);
    assert_eq!(over.len(), 2, "{over:?}");
}

/// The counting allocator's unsafe exemption is the impl block and nothing wider. GREEN: the one
/// allow over the impl, with `unsafe` inside the block. RED: the allow lifted to the module
/// declaration or over another item, `unsafe` in the same file outside the block, the impl in
/// another file, and a second allow on the impl.
#[test]
fn the_counting_allocator_unsafe_exemption_is_its_impl_alone() {
    let plant = |rel: &str, text: &str| unsafe_findings(&[(rel.to_string(), text.to_string())]);
    let right = "use std::alloc::GlobalAlloc;\n\
                 #[allow(unsafe_code)] // REVIEWED, TEST ONLY\n\
                 // SAFETY: forwards.\n\
                 unsafe impl GlobalAlloc for Counting {\n    \
                 unsafe fn alloc(&self, l: Layout) -> *mut u8 { unsafe { System.alloc(l) } }\n\
                 }\n\
                 pub fn allocations() -> u64 { 0 }\n";
    assert!(
        plant("alloc_counter.rs", right).is_empty(),
        "{:?}",
        plant("alloc_counter.rs", right)
    );
    // The allow lifted to the module declaration.
    assert_eq!(
        plant("lib.rs", "#[allow(unsafe_code)]\npub mod alloc_counter;\n").len(),
        1
    );
    // `unsafe` in the module but outside the impl block.
    let outside = format!("{right}pub fn peek() -> u8 {{ unsafe {{ *P }} }}\n");
    assert_eq!(plant("alloc_counter.rs", &outside).len(), 1);
    // The allow over another item in the same file.
    assert_eq!(
        plant(
            "alloc_counter.rs",
            "#[allow(unsafe_code)]\npub fn reset() -> u64 { 0 }\n"
        )
        .len(),
        1
    );
    // The same impl in another file: both the allow and its unsafe tokens are refused.
    assert_eq!(
        plant("dest.rs", right).len(),
        3,
        "{:?}",
        plant("dest.rs", right)
    );
    // A second allow on the impl.
    let doubled = right.replacen(
        "#[allow(unsafe_code)] // REVIEWED, TEST ONLY\n",
        "#[allow(unsafe_code)]\n#[allow(unsafe_code)] // REVIEWED, TEST ONLY\n",
        1,
    );
    assert_eq!(
        plant("alloc_counter.rs", &doubled).len(),
        1,
        "{:?}",
        plant("alloc_counter.rs", &doubled)
    );
}

/// The counting allocator is not in a release build: its declaration carries exactly
/// [`ALLOC_COUNTER_CFG`]. RED: an ungated `pub mod alloc_counter;`, the attribute over another
/// item or in another file, a composed spelling, and a non-empty `alloc-counter`.
#[test]
fn the_alloc_counter_is_behind_its_test_only_attribute() {
    let files = src_files();
    let (_, text) = files
        .iter()
        .find(|(rel, _)| rel == ALLOC_COUNTER_ITEM.0)
        .expect("src/lib.rs is present");
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let at = lines
        .iter()
        .position(|l| *l == ALLOC_COUNTER_ITEM.1)
        .expect("src/lib.rs still declares the counting allocator");
    assert!(
        lines[..at]
            .iter()
            .rev()
            .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
            .any(|l| *l == ALLOC_COUNTER_CFG),
        "src/lib.rs: `{}` is not behind `{ALLOC_COUNTER_CFG}`, so the allocator ships in every build",
        ALLOC_COUNTER_ITEM.1
    );

    let plant = |rel: &str, text: String| cfg_findings(&[(rel.to_string(), text)]);
    let right = format!("{ALLOC_COUNTER_CFG}\npub mod alloc_counter;\n");
    assert!(plant("lib.rs", right.clone()).is_empty());
    assert_eq!(plant("services.rs", right).len(), 1);
    let other = format!("{ALLOC_COUNTER_CFG}\npub fn shipped_only_sometimes() {{}}\n");
    assert_eq!(plant("lib.rs", other).len(), 1);
    let composed =
        "#[cfg(any(debug_assertions, feature = \"alloc-counter\"))]\npub mod alloc_counter;\n";
    assert_eq!(plant("lib.rs", composed.to_string()).len(), 1);
    let bare = "#[cfg(feature = \"alloc-counter\")]\npub mod alloc_counter;\n";
    assert_eq!(plant("lib.rs", bare.to_string()).len(), 1);
    assert!(feature_findings("[features]\nalloc-counter = []\n").is_empty());
    assert_eq!(
        feature_findings("[features]\nalloc-counter = [\"dep:serde_json\"]\n").len(),
        1
    );
    // A `default` naming it is a feature beyond the exemptions.
    assert_eq!(
        feature_findings("[features]\ndefault = [\"alloc-counter\"]\nalloc-counter = []\n").len(),
        1
    );
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
///
/// A crate is NAMED in code as a path (`busbar_kernel::x`) or in a `use`/`extern crate`. The frozen
/// C symbol names the plugin ABI carries (`busbar_plane_decl`, `busbar_transport_decl` — the names a
/// loader `dlsym`s, #84: a published layout) share a prefix with two crate families but are not
/// paths, so the scan reads the whole identifier and asks whether it is used as one.
#[test]
fn the_source_names_no_kernel_side_crate() {
    let mut offenders = Vec::new();
    walk(&src_dir(), &mut |path, text| {
        for hit in kernel_side_names(text) {
            offenders.push(format!("{}:{hit}", path.display()));
        }
    });
    assert!(
        offenders.is_empty(),
        "the contract names kernel-side crates in code: {offenders:?}"
    );
}

/// Every `line: name` in `text` where code names a kernel-side crate.
fn kernel_side_names(text: &str) -> Vec<String> {
    const FORBIDDEN: [&str; 6] = [
        "busbar_contract::caps",
        "busbar_kernel",
        "busbar_unit",
        "busbar_plane",
        "busbar_transport",
        "busbar_substrate",
    ];
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        // A mention inside a doc comment is a reference by name, which the design allows; a use of
        // the identifier in code is not.
        if trimmed.starts_with("//") {
            continue;
        }
        let names_crates = trimmed.starts_with("use ")
            || trimmed.starts_with("pub use ")
            || trimmed.starts_with("extern crate ");
        for name in FORBIDDEN {
            let mut from = 0;
            while let Some(at) = line[from..].find(name) {
                let start = from + at;
                // The whole identifier this occurrence begins.
                let end = start
                    + line[start..]
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
                        .unwrap_or(line.len() - start);
                let ident = &line[start..end];
                if name.contains("::") || ident.contains("::") || names_crates {
                    out.push(format!("{}: {name}", n + 1));
                    break;
                }
                from = end.max(start + 1);
            }
        }
    }
    out
}

/// RED: a path into a kernel-side crate, a `use` of one, and the literal capability path are named;
/// the frozen door symbol names the ABI publishes are not.
#[test]
fn a_kernel_side_crate_path_is_red() {
    assert_eq!(
        kernel_side_names("let x = busbar_kernel::run();\n").len(),
        1
    );
    assert_eq!(
        kernel_side_names("    busbar_plane_planted::decl()\n").len(),
        1
    );
    assert_eq!(
        kernel_side_names("use busbar_transport_planted;\n").len(),
        1
    );
    assert_eq!(
        kernel_side_names("use busbar_contract::caps::Pass;\n").len(),
        1
    );
    assert!(kernel_side_names("pub const D: &[u8] = b\"busbar_plane_decl\\0\";\n").is_empty());
    assert!(
        kernel_side_names("pub unsafe extern \"C-unwind\" fn busbar_transport_decl() {}\n")
            .is_empty()
    );
    assert!(kernel_side_names("// busbar_kernel::run in a comment\n").is_empty());
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

/// THE CONTRACT HOLDS SHAPES AND MACRO DEFINITIONS ONLY (#83; ARCHITECT F6 queue (4)). Logging is
/// a HOST SERVICE: the contract declares the shape of the host log call and nothing it compiles may
/// print, write to a standard stream, or install a global `tracing`/`log` dispatcher. Code inside a
/// `macro_rules!` body runs in the PLUGIN, so it is not contract code. Test-only code
/// (`#[cfg(test)]` items, `src/**/tests/`) is not shipped and is not scanned.
const OUTPUT_SITES: [&str; 13] = [
    "eprintln!",
    "eprint!",
    "println!",
    "print!",
    "dbg!",
    "io::stderr",
    "io::stdout",
    "io::Write",
    "set_global_default",
    "set_default(",
    "set_logger",
    "set_boxed_logger",
    "set_global_logger",
];

/// The ONE exempt site, `(file under src/, the trimmed line)`: the contract's always-compiled test
/// double (`testkit`, #83a O8 / ARCHITECT SD-3 queue (4)) makes callsite interest permanent with a
/// record-nothing global default, which only a plugin's own TESTS ever reach.
const OUTPUT_EXEMPT: [(&str, &str); 1] = [(
    "testkit/warn_capture.rs",
    "let _ = tracing::subscriber::set_global_default(Interested);",
)];

/// `text` with every comment and every string/char literal blanked to spaces (newlines kept), so
/// a scan sees code only.
fn code_only(text: &str) -> Vec<char> {
    let c: Vec<char> = text.chars().collect();
    let mut out = c.clone();
    let blank = |out: &mut Vec<char>, from: usize, to: usize| {
        for ch in out.iter_mut().take(to.min(c.len())).skip(from) {
            if *ch != '\n' {
                *ch = ' ';
            }
        }
    };
    let mut i = 0;
    while i < c.len() {
        let next = c.get(i + 1).copied();
        if c[i] == '/' && next == Some('/') {
            let end = (i..c.len()).find(|&j| c[j] == '\n').unwrap_or(c.len());
            blank(&mut out, i, end);
            i = end;
        } else if c[i] == '/' && next == Some('*') {
            let (mut depth, mut j) = (0usize, i);
            while j < c.len() {
                if c[j] == '/' && c.get(j + 1) == Some(&'*') {
                    depth += 1;
                    j += 2;
                } else if c[j] == '*' && c.get(j + 1) == Some(&'/') {
                    depth -= 1;
                    j += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if c[i] == 'r'
            && (next == Some('"') || next == Some('#'))
            && (i == 0 || !(c[i - 1].is_alphanumeric() || c[i - 1] == '_'))
        {
            let hashes = c[i + 1..].iter().take_while(|&&h| h == '#').count();
            if c.get(i + 1 + hashes) != Some(&'"') {
                i += 1;
                continue;
            }
            let close: String = std::iter::once('"')
                .chain("#".repeat(hashes).chars())
                .collect();
            let body = i + 2 + hashes;
            let rest: String = c[body..].iter().collect();
            let end = rest.find(&close).map_or(c.len(), |at| {
                body + rest[..at].chars().count() + close.len()
            });
            blank(&mut out, i, end);
            i = end;
        } else if c[i] == '"' {
            let mut j = i + 1;
            while j < c.len() && c[j] != '"' {
                j += if c[j] == '\\' { 2 } else { 1 };
            }
            blank(&mut out, i, j + 1);
            i = j + 1;
        } else if c[i] == '\'' {
            // A char literal (`'x'`, `'\n'`, `'\u{..}'`); anything else is a lifetime.
            let end = if next == Some('\\') {
                (i + 2..c.len()).find(|&j| c[j] == '\'')
            } else if c.get(i + 2) == Some(&'\'') {
                Some(i + 2)
            } else {
                None
            };
            match end {
                Some(e) => {
                    blank(&mut out, i, e + 1);
                    i = e + 1;
                }
                None => i += 1,
            }
        } else {
            i += 1;
        }
    }
    out
}

/// The index one past the delimiter group opening at `open` (`{`/`(`/`[`), in blanked code.
fn close_of(c: &[char], open: usize) -> usize {
    let mut depth = 0usize;
    for (j, ch) in c.iter().enumerate().skip(open) {
        match ch {
            '{' | '(' | '[' => depth += 1,
            '}' | ')' | ']' => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
    }
    c.len()
}

/// Blank every `macro_rules!` body (it expands in the plugin) and every `#[cfg(test)]` item.
fn contract_code(text: &str) -> String {
    let mut c = code_only(text);
    let s: String = c.iter().collect();
    let mut cut = Vec::new();
    for (at, _) in s.match_indices("macro_rules!") {
        let at = s[..at].chars().count();
        if let Some(open) = (at..c.len()).find(|&j| matches!(c[j], '{' | '(' | '[')) {
            cut.push((at, close_of(&c, open)));
        }
    }
    if s.trim_start().starts_with("#![cfg(test)]") {
        cut.push((0, c.len()));
    }
    for (at, _) in s.match_indices("#[cfg(test)]") {
        let from = s[..at].chars().count();
        let mut j = from + "#[cfg(test)]".len();
        let end = loop {
            match c.get(j) {
                None => break c.len(),
                Some('[') | Some('(') => j = close_of(&c, j),
                Some(';') => break j + 1,
                Some('{') => break close_of(&c, j),
                Some(_) => j += 1,
            }
        };
        cut.push((from, end));
    }
    for (from, to) in cut {
        for ch in c.iter_mut().take(to).skip(from) {
            if *ch != '\n' {
                *ch = ' ';
            }
        }
    }
    c.into_iter().collect()
}

/// Every print, standard-stream write or global dispatcher install in contract code, as
/// `file:line: site`, over `(path relative to src/, text)`.
fn output_findings(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (rel, text) in files {
        if rel.starts_with("tests/") || rel.contains("/tests/") {
            continue;
        }
        let raw: Vec<&str> = text.lines().collect();
        for (n, line) in contract_code(text).lines().enumerate() {
            let exempt = OUTPUT_EXEMPT
                .iter()
                .any(|(f, l)| rel == f && raw.get(n).map(|r| r.trim()) == Some(*l));
            if exempt {
                continue;
            }
            let hit = OUTPUT_SITES.iter().find(|site| {
                line.match_indices(**site).any(|(at, _)| {
                    let before = line[..at].chars().next_back();
                    !before.is_some_and(|b| b.is_alphanumeric() || b == '_')
                })
            });
            if let Some(site) = hit {
                out.push(format!("{rel}:{}: {site}", n + 1));
            }
        }
    }
    out
}

/// The contract prints nothing, writes to no standard stream and installs no global dispatcher: a
/// plugin's log records go to the host's sink or drop.
#[test]
fn the_contract_prints_nothing_and_installs_no_dispatcher() {
    let findings = output_findings(&src_files());
    assert!(
        findings.is_empty(),
        "contract code emits output of its own (logging is a host service): {findings:?}"
    );
}

/// The one output exemption is not vacuous: its line is really in its file.
#[test]
fn the_output_exemption_is_present() {
    let files = src_files();
    for (file, line) in OUTPUT_EXEMPT {
        let (_, text) = files
            .iter()
            .find(|(rel, _)| rel == file)
            .unwrap_or_else(|| panic!("src/{file} is missing"));
        assert!(
            text.lines().any(|l| l.trim() == line),
            "src/{file} no longer carries `{line}`"
        );
    }
}

/// RED: an `eprintln!` fallback, a standard-stream write and a global dispatcher install in contract
/// code are each refused; the same text inside a `macro_rules!` body, a `#[cfg(test)]` item, a test
/// file, a comment or a string is not contract code, and the one exempt testkit line passes.
#[test]
fn a_print_a_stream_write_or_a_dispatcher_install_in_contract_code_is_red() {
    let plant = |rel: &str, text: &str| output_findings(&[(rel.to_string(), text.to_string())]);
    let sdk = "abi/sdk/mod.rs";
    for planted in [
        "pub fn log(msg: &str) {\n    if raw == 0 {\n        eprintln!(\"[busbar-plugin] {msg}\");\n        return;\n    }\n}\n",
        "pub fn log(msg: &str) { let _ = std::io::stderr().write_all(msg.as_bytes()); }\n",
        "use std::io::Write;\n",
        "fn f() { print!(\"x\"); }\n",
        "fn install() {\n    let _ = tracing::subscriber::set_global_default(Forwarder);\n}\n",
        "fn install() { let _g = tracing::dispatcher::set_default(&d); }\n",
    ] {
        assert_eq!(plant(sdk, planted).len(), 1, "{planted}: {:?}", plant(sdk, planted));
    }
    // Not contract code: a macro body (it expands in the plugin), a cfg(test) item, a test file, a
    // comment, a string literal.
    assert!(plant(
        sdk,
        "#[macro_export]\nmacro_rules! export_plugin {\n    () => {\n        let _ = tc::dispatcher::set_global_default(d); // '{'\n    };\n}\npub fn after() {}\n"
    )
    .is_empty());
    assert!(plant(
        "abi/mod.rs",
        "#[cfg(test)]\nmod probe {\n    fn f() { eprintln!(\"{}\", '}'); }\n}\n#[cfg(test)]\n#[path = \"tests/x.rs\"]\nmod tests;\n"
    )
    .is_empty());
    assert!(plant(
        "abi/sdk/tests/lib_tests.rs",
        "fn f() { eprintln!(\"x\"); }\n"
    )
    .is_empty());
    assert!(plant(sdk, "// eprintln! in a comment\nconst S: &str = \"println!\";\nconst R: &str = r#\"io::stderr\"#;\n").is_empty());
    // After a macro or a cfg(test) item, contract code is scanned again.
    assert_eq!(
        plant(
            sdk,
            "macro_rules! m { () => {} }\n#[cfg(test)]\nfn t() {}\nfn f() { eprintln!(\"x\"); }\n"
        )
        .len(),
        1
    );
    // The exempt testkit line passes; any other install in the testkit is red.
    let (file, line) = OUTPUT_EXEMPT[0];
    assert!(plant(file, &format!("fn f() {{\n    {line}\n}}\n")).is_empty());
    assert_eq!(
        plant(
            file,
            "fn f() { let _ = tracing::subscriber::set_global_default(Other); }\n"
        )
        .len(),
        1
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
