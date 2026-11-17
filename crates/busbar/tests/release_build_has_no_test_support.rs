// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §9 test 31, `release_build_has_no_test_support`: in the feature set a release
//! build of `busbar` resolves, `busbar-kernel-audit`'s `test-support` feature is off, so the §3.2
//! legacy per-line signing builder cannot reach production.
//!
//! Cargo resolves the release graph's features over normal and build edges only (resolver 2 keeps
//! dev-dependency features out of a non-test build), for every target platform. The check asks
//! Cargo for exactly that graph (`cargo tree -e normal,build,features`), reading `cargo
//! metadata`'s resolution with dev edges excluded. Red: any dependency edge outside
//! `dev-dependencies` that enables the feature.

use std::path::Path;
use std::process::Command;

#[test]
fn release_build_has_no_test_support() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = Command::new(env!("CARGO"))
        .args(["tree", "--manifest-path"])
        .arg(&manifest)
        .args([
            "--package",
            "busbar",
            "--edges",
            "normal,build,features",
            "--target",
            "all",
            "--invert",
            "busbar-kernel-audit",
            "--prefix",
            "none",
            "--format",
            "{p} {f}",
            "--no-dedupe",
            "--locked",
        ])
        .output()
        .expect("run cargo tree");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8(output.stdout).expect("cargo tree prints UTF-8");
    assert!(
        tree.lines()
            .any(|line| line.starts_with("busbar-kernel-audit ")),
        "the release graph reaches busbar-kernel-audit:\n{tree}"
    );
    // The package line lists its enabled features (`{f}`), and each enabled feature is also a
    // `busbar-kernel-audit feature "<name>"` node: neither may name `test-support`.
    let enabled: Vec<&str> = tree
        .lines()
        .filter(|line| line.starts_with("busbar-kernel-audit") && line.contains("test-support"))
        .collect();
    assert!(
        enabled.is_empty(),
        "a non-dev dependency edge enables busbar-kernel-audit/test-support in the release \
         graph:\n{tree}"
    );
}
