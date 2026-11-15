// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::path::Path;

use super::{crypto_graph, no_getrandom, repo_root, scan_source, seam_only_reached};

/// The real tree: core's feature-resolved graph builds ring, sha2 and ed25519-dalek only beneath
/// the seam.
#[test]
fn the_root_graph_builds_seam_only_crypto_beneath_busbar_crypto_alone() {
    let findings = crypto_graph(&repo_root()).expect("cargo tree resolves the root workspace");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

/// The real tree: no first-party production code outside the seam names getrandom.
#[test]
fn no_first_party_code_names_getrandom_outside_the_seam() {
    let findings = no_getrandom(&repo_root()).expect("the crates tree scans");
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}

#[test]
fn production_getrandom_sites_are_found_and_test_code_is_not() {
    let source = r#"
use getrandom::fill;
// getrandom::fill in a comment
const DOC: &str = "getrandom::fill";
fn production(buf: &mut [u8]) { getrandom::fill(buf).ok(); }
fn in_macro() { println!("{:?}", getrandom::u64()); }
#[cfg(test)]
mod tests { fn helper() { getrandom::fill(&mut [0; 4]).ok(); } }
#[test]
fn a_test() { getrandom::fill(&mut [0; 4]).ok(); }
#[cfg(all(test, unix))]
fn unix_test_helper() { getrandom::fill(&mut [0; 4]).ok(); }
#[cfg(any(test, feature = "test-support"))]
fn feature_helper() { getrandom::fill(&mut [0; 4]).ok(); }
fn other_crate() { my::getrandom::fill(); getrandom(); }
extern crate getrandom;
"#;
    let scan = scan_source(Path::new("/r/crates/x/src/lib.rs"), source);
    let lines: Vec<usize> = scan.hits.iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [2, 5, 6, 14, 16]);
}

#[test]
fn a_whole_file_under_cfg_test_is_test_code() {
    let scan = scan_source(
        Path::new("/r/crates/x/src/lib.rs"),
        "#![cfg(test)]\nfn helper() { getrandom::fill(&mut [0; 4]).ok(); }\n",
    );
    assert!(scan.hits.is_empty());
}

#[test]
fn a_file_syn_cannot_parse_is_scanned_by_line() {
    let scan = scan_source(
        Path::new("/r/crates/x/src/lib.rs"),
        "fn broken( {\n// getrandom::fill\n    getrandom::fill(buf);\n",
    );
    let lines: Vec<usize> = scan.hits.iter().map(|(line, _)| *line).collect();
    assert_eq!(lines, [3]);
}

#[test]
fn module_files_declared_under_cfg_test_are_test_code() {
    let scan = scan_source(
        Path::new("/r/crates/x/src/engine.rs"),
        "#[cfg(test)]\nmod tests;\nmod live;\n#[cfg(test)]\n#[path = \"engine_more.rs\"]\nmod more;\n\
         #[cfg(test)]\nmod inline { mod deep; }\n",
    );
    let covered = |file: &str| {
        scan.test_modules
            .iter()
            .any(|module| module.covers(Path::new(file)))
    };
    assert!(covered("/r/crates/x/src/engine/tests.rs"));
    assert!(covered("/r/crates/x/src/engine/tests/mod.rs"));
    assert!(covered("/r/crates/x/src/engine/tests/cases.rs"));
    assert!(covered("/r/crates/x/src/engine_more.rs"));
    assert!(covered("/r/crates/x/src/engine/inline/deep.rs"));
    assert!(!covered("/r/crates/x/src/engine/live.rs"));
    assert!(!covered("/r/crates/x/src/engine.rs"));
}

const TREE: &str = "0app v1.0.0 (/r/app)\n1reqwest v0.12.28\n2rustls v0.23.46\n3ring v0.17.14\n\
                    3aws-lc-rs v1.16.0\n1tokio v1.53.3\n2ring v0.17.14 (*)\n\n0other v1.0.0 (/r/other)\n\
                    1sha2-like v0.1.0\n";

#[test]
fn seam_only_crypto_built_outside_the_seam_is_named_with_its_path() {
    assert_eq!(
        seam_only_reached(TREE),
        ["ring v0.17.14 is built outside busbar-crypto*: app -> reqwest -> rustls -> ring"]
    );
}

#[test]
fn a_graph_without_seam_only_crypto_is_clean() {
    let clean = TREE
        .replace("3ring v0.17.14\n", "")
        .replace("2ring v0.17.14 (*)\n", "");
    assert!(seam_only_reached(&clean).is_empty());
}
