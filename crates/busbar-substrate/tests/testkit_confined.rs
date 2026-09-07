// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MECHANICAL PREVENTION for "a testkit seam cannot be installed in a non-test build": `pub mod
//! testkit` in `src/lib.rs` must stay gated by `#[cfg(any(test, feature = "test-support"))]` — the
//! same predicate that keeps `dep:rcgen`/`dep:reqwest`/`dep:tracing-subscriber` optional in
//! `Cargo.toml` — so a shipped binary (no `test-support`, not compiled as a test) never links the
//! fixture host, engine kits or loopback HTTP doubles under `src/testkit/`.
//!
//! This crate's own `cargo test -p busbar-substrate` run cannot observe the negative case directly:
//! `cfg(test)` is live for the crate's *own* unit tests, so `busbar_substrate::testkit` compiles in
//! from inside the lib. But THIS file is an external integration-test binary; cargo links it against
//! the crate's NORMAL (non-`cfg(test)`) rlib, so `testkit` is reachable from here if and only if the
//! `test-support` feature is enabled for the test run. Rather than pin that (accidentally correct,
//! feature-set-dependent) reachability, this test pins the source text the reachability rests on: the
//! declaration in `lib.rs` carries exactly the guarding `#[cfg]`, so no future edit can widen or drop
//! it without failing this test RED first.

use std::path::Path;

fn lib_rs_src() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

#[test]
fn testkit_module_is_declared_pub_mod_exactly_once() {
    let src = lib_rs_src();
    let count = src
        .lines()
        .filter(|l| l.trim() == "pub mod testkit;")
        .count();
    assert_eq!(
        count, 1,
        "expected exactly one `pub mod testkit;` declaration in src/lib.rs; found {count}. If \
         testkit moved or was re-declared, this gate needs to move with it — do not just delete it."
    );
}

#[test]
fn testkit_declaration_is_immediately_preceded_by_its_test_only_cfg_gate() {
    let src = lib_rs_src();
    let lines: Vec<&str> = src.lines().collect();
    let decl_line = lines
        .iter()
        .position(|l| l.trim() == "pub mod testkit;")
        .expect("testkit_module_is_declared_pub_mod_exactly_once already asserts this exists");

    // Walk upward past any doc/line comments straight to the nearest non-comment line: that line
    // must be the exact cfg gate. A blank line, an unrelated attribute, or a widened predicate
    // (e.g. `cfg(test)` alone, or `not(feature = "test-support")`) all fail this.
    let mut i = decl_line;
    let gate_line = loop {
        assert!(i > 0, "walked off the top of lib.rs without finding a non-comment line above `pub mod testkit;`");
        i -= 1;
        let trimmed = lines[i].trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        break trimmed;
    };

    assert_eq!(
        gate_line, r#"#[cfg(any(test, feature = "test-support"))]"#,
        "the line immediately above `pub mod testkit;` (past comments) must be exactly this cfg \
         gate — a shipped, non-test build must never compile testkit in. Found: {gate_line:?}"
    );
}
