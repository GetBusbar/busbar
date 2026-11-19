// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R131 `test-unsafe-outside-boundary` over the kernel's in-src test modules (SDK-SAFE-TEST-HOST
//! §7 MR 7, package S2-STH-7). Every test-reachable file under `crates/busbar-kernel/src/` is
//! scanned, except `config/tests/**`, the W3-D-CONTRACT handoff files, and the files listed in
//! [`LEFT_OUT`], each with the row it waits for. The kernel's `tests/` tree is S2-STH-3A's.

use std::path::Path;

use busbar_plugin_test::abi_scan::r131;

const SRC: &str = "crates/busbar-kernel/src/";

/// Directories not in the path list (package scope).
const LEFT_OUT_DIRS: &[&str] = &["crates/busbar-kernel/src/config/tests/"];

const HANDOFF: &str = "W3-D-CONTRACT handoff (WBS rule 13)";

/// Files not in R131's path list, relative to the repository root, each with why.
const LEFT_OUT: &[(&str, &str)] = &[
    // W3-D-CONTRACT's rule-13 serial handoff files in the kernel's src tree.
    ("crates/busbar-kernel/src/tests/host_services_tests.rs", HANDOFF),
    ("crates/busbar-kernel/src/tests/trust_native.rs", HANDOFF),
    ("crates/busbar-kernel/src/tests/trust_rule_tests.rs", HANDOFF),
    ("crates/busbar-kernel/src/tests/trust_verify_tests.rs", HANDOFF),
    ("crates/busbar-kernel/src/tests/trust_ordering_tests.rs", HANDOFF),
    ("crates/busbar-kernel/src/tests/trust_sight_ordering_tests.rs", HANDOFF),
    ("crates/busbar-kernel/src/host_work/tests/host_work_tests.rs", HANDOFF),
    // Rows not built.
    (
        "crates/busbar-kernel/src/plane_driver/tests/retirement_tests.rs",
        "reads the far end's state mutex from inside a 'static effect callback through an AtomicPtr: needs a scoped-borrow probe row (or the far end's state behind an Arc)",
    ),
];

fn repository() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

#[test]
fn r131_holds_over_the_kernels_in_src_test_modules() {
    let repo = repository();
    let mut found = Vec::new();
    for f in r131(&repo.join("crates/busbar-kernel")) {
        let rel = f
            .file
            .strip_prefix(&repo)
            .unwrap_or(&f.file)
            .to_string_lossy()
            .replace('\\', "/");
        let left_out = LEFT_OUT.iter().any(|(path, _)| *path == rel)
            || LEFT_OUT_DIRS.iter().any(|dir| rel.starts_with(dir));
        if rel.starts_with(SRC) && !left_out {
            found.push(format!("{rel}:{}: {:?}: {}", f.line, f.rule, f.what));
        }
    }
    assert!(
        found.is_empty(),
        "{} R131 finding(s) in the path list:\n{}",
        found.len(),
        found.join("\n")
    );
}

#[test]
fn every_left_out_file_exists_and_states_its_reason() {
    let repo = repository();
    for (path, why) in LEFT_OUT {
        assert!(repo.join(path).is_file(), "{path} is gone: drop its row");
        assert!(!why.is_empty(), "{path} has no reason");
    }
    for dir in LEFT_OUT_DIRS {
        assert!(repo.join(dir).is_dir(), "{dir} is gone: drop its row");
    }
}
