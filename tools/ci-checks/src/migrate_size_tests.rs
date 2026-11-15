// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Red (sz1) of MIGRATE-ON-BOOT r42 §7, the `migrate-size` job's own tests. Sizes are printed,
//! never gated (R-SIZE/Δ2 voids the numbers); separation and anchors are gated.

use crate::migrate_size::{
    anchors_missing, bin_findings, counted_lines, dockerfile_findings, forbidden_deps,
    gateway_bytes, gateway_prefixes, linked_crates, overlay_word_sites, parse_bloat,
    separation_deps, BYTE_GATE, LINE_GATE,
};
use crate::repo_root;

const KB: u64 = 1024;

fn bloat(entries: &[(&str, u64)]) -> Vec<(String, u64)> {
    let body: Vec<String> = entries
        .iter()
        .map(|(name, size)| format!(r#"{{"crate":"x","name":"{name}","size":{size}}}"#))
        .collect();
    let json = format!(r#"{{"file-size":1,"functions":[{}]}}"#, body.join(","));
    parse_bloat(&json).expect("cargo bloat json parses")
}

const DIST: &str = r#"
[package.metadata.busbar.always-on]
plane-llm-door = "busbar-plane-llm"

[package.metadata.busbar.linked]
store-memory = "busbar-store-memory"
fixture = "fixture-plugin"
auth-oauth = "busbar-auth-oauth"

[package.metadata.busbar.core]
dir = "../../crates/busbar"
"#;

const DIST_LOCK: &str = r#"
[[package]]
name = "busbar-plane-llm"
version = "1.6.0"

[[package]]
name = "fixture-plugin"
version = "0.0.0"
"#;

/// The bloat parser reads names with quotes, braces and `<` in them, in any key order.
#[test]
fn bloat_json_names_and_sizes_are_read_in_any_key_order() {
    let json = r#"{"functions":[{"size":7,"crate":null,"name":"a::{{closure}}<\"q\">"},{"name":"b","size":9}],"x":1}"#;
    assert_eq!(
        parse_bloat(json).expect("parses"),
        vec![("a::{{closure}}<\"q\">".to_owned(), 7), ("b".to_owned(), 9)]
    );
    assert!(parse_bloat("{}").is_err());
}

/// (1) A 310 KB fn in `busbar_migrate` fails the byte gate; the same fn in a non-migrator module
/// of `busbar` is not counted. The gate is printed, not enforced.
#[test]
fn a_310kb_fn_counts_in_the_migrator_and_not_elsewhere() {
    let prefixes = gateway_prefixes(DIST, DIST_LOCK);
    let inside = bloat(&[("busbar_migrate::big", 310 * KB)]);
    let outside = bloat(&[("busbar::root::other::big", 310 * KB)]);
    assert!(gateway_bytes(&inside, &prefixes) > BYTE_GATE);
    assert_eq!(gateway_bytes(&outside, &prefixes), 0);
}

/// A symbol matching two prefixes is counted once.
#[test]
fn a_symbol_matching_two_prefixes_is_counted_once() {
    let prefixes = gateway_prefixes(DIST, DIST_LOCK);
    let both = bloat(&[("busbar_migrate::x::busbar::root::migrate::y", 100)]);
    assert_eq!(gateway_bytes(&both, &prefixes), 100);
}

/// (2) The line count: 5,000 counted lines pass, the 5,001st exceeds. Blank and comment lines are
/// not counted.
#[test]
fn the_line_count_skips_blank_and_comment_lines() {
    let body = "fn a() {}\n".repeat(LINE_GATE);
    assert_eq!(counted_lines(&body), LINE_GATE);
    let over = format!("{body}fn b() {{}}\n\n// note\n");
    assert_eq!(counted_lines(&over), LINE_GATE + 1);
}

/// (3)/(3b) Each gateway anchor must be a symbol in `cargo bloat`: a stripped build or a renamed
/// module finds none and each is named; `plan` does not match `planned`.
#[test]
fn a_missing_anchor_symbol_is_named_and_a_present_one_is_not() {
    let all = bloat(&[
        ("busbar_migrate::plan", 10),
        ("busbar::root::migrate::run", 10),
        ("busbar_kernel::persistence::startup::Manifest::decode", 10),
        ("plugin_loader::dispatch::migrate::settings_migration", 10),
        ("busbar_contract::abi::sdk::migrate::read_answer", 10),
    ]);
    assert!(anchors_missing(&all).is_empty());
    let renamed = bloat(&[
        ("busbar_migrate::planned", 10),
        ("busbar_kernel::persistence::startup::Manifest::decode", 10),
        ("plugin_loader::dispatch::migrate::settings_migration", 10),
        ("busbar_contract::abi::sdk::migrate::read_answer", 10),
    ]);
    let missing = anchors_missing(&renamed);
    assert_eq!(missing.len(), 2, "{missing:?}");
    assert!(missing.iter().any(|m| m.contains("busbar::root::migrate::run")));
    assert!(missing.iter().all(|m| m.contains("anchor not found")));
    assert_eq!(anchors_missing(&[]).len(), 5);
}

/// (3d) Linked plugins are counted from the manifest: the fixture row adds its `migrate::` prefix,
/// removing the row drops it with no other edit, a crate not in the lock adds nothing, and a fn
/// outside `migrate` is not counted.
#[test]
fn linked_plugin_migrate_code_is_counted_from_the_manifest() {
    let with_row = gateway_prefixes(DIST, DIST_LOCK);
    assert!(with_row.contains(&"fixture_plugin::migrate::".to_owned()));
    assert!(with_row.contains(&"busbar_plane_llm::migrate::".to_owned()));
    // busbar-auth-oauth is a row but the release build does not resolve it here.
    assert!(!with_row.iter().any(|p| p.starts_with("busbar_auth_oauth")));
    let fns = bloat(&[
        ("fixture_plugin::migrate::big", 310 * KB),
        ("fixture_plugin::other::big", 310 * KB),
    ]);
    assert_eq!(gateway_bytes(&fns, &with_row), 310 * KB);
    let without_row = gateway_prefixes(&DIST.replace("fixture = \"fixture-plugin\"\n", ""), DIST_LOCK);
    assert_eq!(gateway_bytes(&fns, &without_row), 0);
    // A linked crate with no migrate module adds 0.
    let none = bloat(&[("busbar_plane_llm::lib::f", 50)]);
    assert_eq!(gateway_bytes(&none, &with_row), 0);
}

const LOCK: &str = r#"
[[package]]
name = "busbar-migrate"
version = "1.6.0"
dependencies = [
 "busbar-contract",
 "extra",
]

[[package]]
name = "busbar-contract"
version = "1.6.0"
dependencies = [
 "sha2",
]

[[package]]
name = "extra"
version = "1.0.0"
dependencies = [
 "deep 2.0.0",
]

[[package]]
name = "deep"
version = "2.0.0"
dependencies = [
 "postcard",
]
"#;

/// (4) A forbidden crate anywhere beneath `busbar-migrate` fails separation; the shared contract
/// facade is the allowed edge and is not entered. Adding `plugin-loader` directly fails too.
#[test]
fn a_forbidden_dependency_beneath_the_migrator_fails_separation() {
    let forbidden = forbidden_deps(&linked_crates(DIST));
    let findings = separation_deps(LOCK, &forbidden);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].contains("postcard"), "{findings:?}");
    let direct = LOCK.replace(" \"extra\",\n", " \"extra\",\n \"busbar-plugin-loader\",\n");
    assert!(separation_deps(&direct, &forbidden)
        .iter()
        .any(|f| f.contains("busbar-plugin-loader")));
    let linked = LOCK.replace(" \"extra\",\n", " \"extra\",\n \"busbar-plane-llm\",\n");
    assert!(separation_deps(&linked, &forbidden)
        .iter()
        .any(|f| f.contains("busbar-plane-llm")));
    let clean = LOCK.replace(" \"postcard\",\n", "");
    assert!(separation_deps(&clean, &forbidden).is_empty());
}

/// (4) The real lock: `busbar-migrate` reaches no forbidden crate.
#[test]
fn the_real_migrator_has_no_forbidden_dependency() {
    let root = repo_root();
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("root lock");
    let dist = std::fs::read_to_string(root.join("dist/default/Cargo.toml")).expect("dist manifest");
    let findings = separation_deps(&lock, &forbidden_deps(&linked_crates(&dist)));
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// (5) A `[[bin]] busbar-migrate`, a `src/main.rs` beside the migrate crate, or a second
/// Dockerfile binary fails.
#[test]
fn a_migrate_binary_fails_separation() {
    let bin = "[package]\nname = \"x\"\n\n[[bin]]\nname = \"busbar-migrate\"\npath = \"src/main.rs\"\n";
    assert_eq!(bin_findings("crates/x/Cargo.toml", bin).len(), 1);
    let other = "[[bin]]\nname = \"busbar\"\npath = \"src/main.rs\"\n";
    assert!(bin_findings("crates/x/Cargo.toml", other).is_empty());
    let one = "COPY binaries/${TARGETARCH}/busbar /busbar\nCOPY providers.yaml /etc/p.yaml\n";
    assert!(dockerfile_findings(one).is_empty());
    let two = format!("{one}COPY binaries/${{TARGETARCH}}/busbar-migrate /busbar-migrate\n");
    assert!(!dockerfile_findings(&two).is_empty());
}

/// (r17) The overlay words occur in no production source outside `crates/busbar-migrate`: a
/// literal, a doc comment and an identifier are found; test code is not.
#[test]
fn the_overlay_words_are_found_in_production_text_and_not_in_tests() {
    let source = r#"
const NAME: &str = "BUSBAR_CONFIG_OVERLAY";
/// the busbar-overlay.json file
fn f() {}
const DEFAULT_OVERLAY_FILENAME: &str = "x";
#[cfg(test)]
mod tests { const T: &str = "busbar-overlay.json"; }
"#;
    assert_eq!(overlay_word_sites(source), vec![2, 3, 5]);
    assert!(overlay_word_sites("const OK: &str = \"overlay\";").is_empty());
}
