// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R131 on synthetic trees: what it flags, and what it leaves alone.

use super::{r131, Finding, Rule};
use std::path::{Path, PathBuf};

/// A scratch tree, removed on drop.
struct Tree(PathBuf);

impl Tree {
    fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!("r131-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (path, src) in files {
            let p = root.join(path);
            std::fs::create_dir_all(p.parent().expect("a parent")).expect("mkdir");
            std::fs::write(&p, src).expect("write");
        }
        Self(root)
    }

    fn findings(&self) -> Vec<(String, Rule)> {
        let root = self.0.canonicalize().expect("the tree");
        r131(&self.0)
            .into_iter()
            .map(|Finding { file, rule, .. }| (rel(&root, &file), rule))
            .collect()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rel(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

const UNSAFE_FN: &str = "fn f() { unsafe { g() } }\n";

#[test]
fn an_unsafe_token_in_a_tests_file_is_flagged() {
    let t = Tree::new("tests-dir", &[("c/tests/a.rs", UNSAFE_FN)]);
    assert_eq!(t.findings(), [("c/tests/a.rs".to_string(), Rule::Unsafe)]);
}

#[test]
fn an_unsafe_token_inside_a_macro_rules_body_is_flagged() {
    let t = Tree::new(
        "macro",
        &[(
            "c/tests/m.rs",
            "macro_rules! m { () => { unsafe { core::hint::unreachable_unchecked() } }; }\n",
        )],
    );
    assert_eq!(t.findings(), [("c/tests/m.rs".to_string(), Rule::Unsafe)]);
}

#[test]
fn an_out_of_line_cfg_test_module_is_test_reachable() {
    let t = Tree::new(
        "out-of-line",
        &[
            ("c/src/lib.rs", "#[cfg(test)]\nmod x;\nmod y;\n"),
            ("c/src/x.rs", UNSAFE_FN),
            ("c/src/y.rs", UNSAFE_FN),
        ],
    );
    assert_eq!(
        t.findings(),
        [("c/src/x.rs".to_string(), Rule::Unsafe)],
        "only the test-only module is test code; y.rs is production"
    );
}

#[test]
fn a_path_attribute_is_followed_from_a_test_gated_module() {
    let t = Tree::new(
        "path",
        &[
            (
                "c/src/lib.rs",
                "pub mod a;\n#[cfg(any(test, feature = \"test-support\"))]\npub mod support;\n",
            ),
            (
                "c/src/a.rs",
                "#[cfg(test)]\n#[path = \"checks/a_checks.rs\"]\nmod checks;\n",
            ),
            ("c/src/checks/a_checks.rs", UNSAFE_FN),
            ("c/src/support.rs", UNSAFE_FN),
        ],
    );
    assert_eq!(
        t.findings(),
        [
            ("c/src/checks/a_checks.rs".to_string(), Rule::Unsafe),
            ("c/src/support.rs".to_string(), Rule::Unsafe),
        ]
    );
}

#[test]
fn the_boundary_and_production_code_are_not_flagged() {
    let t = Tree::new(
        "boundary",
        &[
            (
                "busbar-contract/src/lib.rs",
                "pub mod abi;\n#[cfg(not(test))]\nmod live;\n",
            ),
            ("busbar-contract/src/live.rs", UNSAFE_FN),
            (
                "busbar-contract/tests/clean.rs",
                "// unsafe in a comment\nconst S: &str = \"unsafe { }\";\nconst R: &str = r#\"unsafe\"#;\n",
            ),
            (
                "busbar-contract/src/abi/mod.rs",
                "#[cfg(any(test, feature = \"test-support\"))]\npub mod sdk;\n",
            ),
            ("busbar-contract/src/abi/sdk/mod.rs", "pub mod test_support;\n"),
            ("busbar-contract/src/abi/sdk/test_support/mod.rs", UNSAFE_FN),
        ],
    );
    assert_eq!(t.findings(), Vec::<(String, Rule)>::new());
}

#[test]
fn the_raw_back_doors_are_flagged_in_a_test_file() {
    let t = Tree::new(
        "back-doors",
        &[(
            "c/tests/b.rs",
            "fn f() {\n    let mut fr = Frame::new(i, o);\n    let row = LinkedRow::of_raw(d);\n}\n",
        )],
    );
    assert_eq!(
        t.findings(),
        [
            ("c/tests/b.rs".to_string(), Rule::BackDoor),
            ("c/tests/b.rs".to_string(), Rule::BackDoor),
        ]
    );
}

#[test]
fn dependency_sources_under_a_repository_local_cargo_home_are_not_scanned() {
    // CI keeps CARGO_HOME inside the checkout (`.cargo-home`, so the runner can cache it): the registry and
    // git checkouts under it are third-party crates, not this repository's test-reachable code.
    let t = Tree::new(
        "cargo-home",
        &[
            (".cargo-home/git/checkouts/dep-1/abc/tests/a.rs", UNSAFE_FN),
            (
                ".cargo-home/registry/src/index/dep-2/src/lib.rs",
                "#[cfg(test)]\nmod t;\n",
            ),
            (".cargo-home/registry/src/index/dep-2/src/t.rs", UNSAFE_FN),
            (".cargo/registry/src/index/dep-3/tests/b.rs", UNSAFE_FN),
            ("c/tests/a.rs", UNSAFE_FN),
        ],
    );
    assert_eq!(t.findings(), [("c/tests/a.rs".to_string(), Rule::Unsafe)]);
}
