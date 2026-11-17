// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R131 `test-unsafe-outside-boundary` over the composition root's, the plugin loader's and the
//! default distribution's integration tests (SDK-SAFE-TEST-HOST §7 MR 3, package S2-STH-3B). Every
//! test-reachable file under `crates/busbar/tests/`, `crates/plugin-loader/tests/` and
//! `dist/default/tests/` is scanned, except the files listed in [`LEFT_OUT`], each with the reason
//! it is not in the path list yet.

use std::path::Path;

use busbar_plugin_test::abi_scan::r131;

/// The crate directories (relative to the repository root) whose `tests/` trees this lane owns.
const CRATES: &[&str] = &["crates/busbar", "crates/plugin-loader", "dist/default"];

const HAND_FIXTURE: &str =
    "hand-written raw-ABI fixture door of the loader's in-src dispatch tests (STH 4a/4b; W3 deletes dispatch/**)";
const PLANE_DRIVER: &str =
    "drives the plane driver through dispatch::Frame over a hand-written plane door: needs the HostView row (not built); W3-D-CONTRACT deletes the driver";

/// Files not in R131's path list, relative to the repository root, each with why.
const LEFT_OUT: &[(&str, &str)] = &[
    (
        "crates/plugin-loader/tests/streaming_media.rs",
        "forges a Statement and plane tail to test the loader's Plane::context: needs the statement/kind-tail forging rows (Gaps 3 and 4, not built)",
    ),
    ("crates/plugin-loader/tests/fixtures/dispatch_test_plugin.rs", HAND_FIXTURE),
    (
        "crates/plugin-loader/tests/fixtures/hook_door_plugin.rs",
        "forges a Door with an untailed Statement (Door::__from_parts): needs the injected-tail mutant row (Gap 4, not built)",
    ),
    ("crates/plugin-loader/tests/fixtures/log_witness_plugin.rs", HAND_FIXTURE),
    ("crates/plugin-loader/tests/fixtures/neutral_frame_door.rs", HAND_FIXTURE),
    (
        "crates/plugin-loader/tests/fixtures/neutral_plane_plugin.rs",
        "calls the host's raw connector identity service from inside the plugin: needs the scripted-connections row (Gap 2, not built)",
    ),
    (
        "dist/default/tests/canary/abi.rs",
        "needs the Recorder row (design §3.4, not built)",
    ),
    (
        "dist/default/tests/canary/recorder.rs",
        "needs the Recorder row (design §3.4, not built)",
    ),
    (
        "dist/default/tests/cli_validate.rs",
        "write_stated_store renders a hand-built Statement with a forged kind ABI: needs a rendering-of-a-mutant row (not built)",
    ),
    (
        "dist/default/tests/door_ready_alloc.rs",
        "counts allocations around Frame calls of the plane fixture door: needs the HostView row (not built)",
    ),
    ("dist/default/tests/fixtures/plane_driver_test_plane.rs", PLANE_DRIVER),
    ("dist/default/tests/plane_driver.rs", PLANE_DRIVER),
    ("dist/default/tests/plane_forged_context.rs", PLANE_DRIVER),
    ("dist/default/tests/plane_rider.rs", PLANE_DRIVER),
];

fn repository() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

#[test]
fn r131_holds_over_the_busbar_loader_and_default_distribution_integration_tests() {
    let repo = repository();
    let mut found = Vec::new();
    for name in CRATES {
        for f in r131(&repo.join(name)) {
            let rel = f
                .file
                .strip_prefix(&repo)
                .unwrap_or(&f.file)
                .to_string_lossy()
                .replace('\\', "/");
            let in_tests = rel.starts_with(&format!("{name}/tests/"));
            if in_tests && !LEFT_OUT.iter().any(|(path, _)| *path == rel) {
                found.push(format!("{rel}:{}: {:?}: {}", f.line, f.rule, f.what));
            }
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
