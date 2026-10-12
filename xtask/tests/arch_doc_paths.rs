//! docs/architecture.md names only repository paths that exist, so a deleted crate cannot
//! linger in the prose (the 1.5.5 text kept 14 `crates/busbar-core/src` paths after that crate
//! was gone).

use std::path::Path;

const ROOTS: &[&str] = &[
    "crates/", "docs/", "xtask/", "scripts/", "qa/", "conformance/", "tests/",
];

/// Every backticked token that begins with a repository root, trimmed of trailing punctuation.
fn named_paths(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .filter(|t| ROOTS.iter().any(|r| t.starts_with(r)) && !t.contains(' '))
        .map(|t| t.trim_end_matches(['.', ',', ';', ':']).to_string())
        .collect()
}

fn missing(text: &str, root: &Path) -> Vec<String> {
    named_paths(text)
        .into_iter()
        .filter(|p| !root.join(p).exists())
        .collect()
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

#[test]
fn architecture_md_names_only_paths_that_exist() {
    let text = std::fs::read_to_string(repo_root().join("docs/architecture.md")).unwrap();
    assert!(!named_paths(&text).is_empty(), "the scan found no paths: the gate is blind");
    assert_eq!(missing(&text, repo_root()), Vec::<String>::new());
}

#[test]
fn architecture_md_has_no_stale_core_crate_or_three_planes() {
    let text = std::fs::read_to_string(repo_root().join("docs/architecture.md")).unwrap();
    assert!(!text.contains("crates/busbar-core/"));
    assert!(!text.to_lowercase().contains("three planes"));
}

/// RED arm: a path to a crate that is gone is caught.
#[test]
fn a_planted_stale_path_is_refused() {
    let planted = "see `crates/busbar-core/src/router.rs` and `docs/architecture.md`.";
    assert_eq!(
        missing(planted, repo_root()),
        vec!["crates/busbar-core/src/router.rs".to_string()]
    );
}
