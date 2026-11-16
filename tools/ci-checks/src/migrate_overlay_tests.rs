// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    docs, docs_findings, hook_keys, separation, word_sites, HOOK_KEY, ONE_BOOT, ROLLBACK, WORDS,
};
use crate::repo_root;

/// (f2) the real tree: no production source outside crates/busbar-migrate names the 1.5.5
/// overlay's variable, file name or constant.
#[test]
fn no_production_source_outside_the_helper_names_the_1_5_5_overlay() {
    let findings = separation(&repo_root()).expect("the crates tree scans");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// (f2) planted: a `"BUSBAR_CONFIG_OVERLAY"` literal, the default file name in a format string,
/// the constant as an identifier and in a doc comment are found; a plain comment and test code
/// are not.
#[test]
fn a_planted_overlay_name_is_found_and_test_code_is_not() {
    let source = r#"
// a plain comment naming BUSBAR_CONFIG_OVERLAY is not source an operator or a boot reads
const VAR: &str = "BUSBAR_CONFIG_OVERLAY";
fn path(dir: &str) -> String { format!("{dir}/busbar-overlay.json") }
use kernel::config::overlay::DEFAULT_OVERLAY_FILENAME;
/// Reads `BUSBAR_CONFIG_OVERLAY`.
fn documented() {}
#[cfg(test)]
mod tests { const T: &str = "BUSBAR_CONFIG_OVERLAY"; }
"#;
    let lines: Vec<usize> = word_sites(source, &WORDS, true)
        .into_iter()
        .map(|(line, _)| line)
        .collect();
    assert_eq!(lines, vec![3, 4, 5, 6]);
    assert!(word_sites("const OK: &str = \"config.yaml\";\n", &WORDS, true).is_empty());
}

/// (n4)(4) the real tree: `global_hooks` is a literal of the overlay-hook pass alone.
#[test]
fn only_the_overlay_hook_pass_names_the_global_hooks_key() {
    let findings = hook_keys(&repo_root()).expect("busbar-migrate scans");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// (n4)(4) planted: a `"global_hooks"` literal is found; a doc comment naming the key is not a
/// literal.
#[test]
fn a_planted_global_hooks_literal_is_found() {
    let source = "/// Folds `global_hooks`.\nfn fold() { let _ = map.get(\"global_hooks\"); }\n";
    let lines: Vec<usize> = word_sites(source, &[HOOK_KEY], false)
        .into_iter()
        .map(|(line, _)| line)
        .collect();
    assert_eq!(lines, vec![2]);
}

/// (f2), (o7) the real page carries the one-boot sentence and the F-first rollback, and says no
/// stamped boot refuses an overlay.
#[test]
fn the_upgrade_page_says_the_overlay_is_checked_on_one_boot() {
    let findings = docs(&repo_root()).expect("the page reads");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// (f2), (o7) planted: a page without the sentences, or with one saying serving refuses an
/// overlay, fails.
#[test]
fn a_page_that_says_a_stamped_boot_refuses_an_overlay_fails() {
    let good = format!("Read the line. {ONE_BOOT}. Roll back: remove P, then {ROLLBACK}.\n");
    assert!(
        docs_findings(&good).is_empty(),
        "{:?}",
        docs_findings(&good)
    );
    assert_eq!(docs_findings("nothing here\n").len(), 2);
    let bad = format!(
        "{good}After the upgrade, serving refuses to start while the overlay file holds settings.\n"
    );
    let findings = docs_findings(&bad);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].contains("serving refuses"), "{findings:?}");
}
