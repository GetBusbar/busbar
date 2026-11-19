// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R131 `test-unsafe-outside-boundary` over the connector's in-src test modules
//! (SDK-SAFE-TEST-HOST §7 MR 6, package S2-STH-6): every test-reachable file under
//! `crates/busbar-core-connector/src/` that is a test module (`src/tests/**`, `*_tests.rs`,
//! `src/tls/tests.rs`), except the files listed in [`LEFT_OUT`], each with the row it waits for.

use std::path::Path;

use busbar_plugin_test::abi_scan::r131;

const CRATE: &str = "crates/busbar-core-connector";

const DOOR_DOUBLE: &str = "hand-written transport door double over the host's raw loans: needs the HostView row and the FramerSink writers (design 3.3, not built)";

/// Files not in R131's path list, relative to the repository root, each with why.
const LEFT_OUT: &[(&str, &str)] = &[
    (
        "crates/busbar-core-connector/src/tests/support_lib.rs",
        "owns the unsafe GlobalAlloc wipe and allocation probes (Q24: the /proc/self/mem canary scan replaces them; row not built) and the FramerSink writers pieces_on_lanes and writable_on_lane (FramerSink writer row, not built)",
    ),
    ("crates/busbar-core-connector/src/tests/framed_stream_tests.rs", DOOR_DOUBLE),
    ("crates/busbar-core-connector/src/tests/listen_tests.rs", DOOR_DOUBLE),
];

fn repository() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

/// The package owns the connector's in-src test modules, not its production files or test kit.
fn is_test_module(rel: &str) -> bool {
    rel.starts_with(&format!("{CRATE}/src/"))
        && (rel.contains("/src/tests/")
            || rel.ends_with("_tests.rs")
            || rel.ends_with("/tls/tests.rs"))
}

#[test]
fn r131_holds_over_the_connector_in_src_test_modules() {
    let repo = repository();
    let mut found = Vec::new();
    for f in r131(&repo.join(CRATE)) {
        let rel = f
            .file
            .strip_prefix(&repo)
            .unwrap_or(&f.file)
            .to_string_lossy()
            .replace('\\', "/");
        if is_test_module(&rel) && !LEFT_OUT.iter().any(|(path, _)| *path == rel) {
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
}
