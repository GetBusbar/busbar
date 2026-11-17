// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R131 `test-unsafe-outside-boundary` over the kernel's and the contract's integration tests
//! (SDK-SAFE-TEST-HOST §7 MR 3, package S2-STH-3A). Every test-reachable file under
//! `crates/busbar-kernel/tests/` and `crates/busbar-contract/tests/` is scanned, except the files
//! listed in [`LEFT_OUT`], each with the reason it is not in the path list yet.

use std::path::Path;

use busbar_plugin_test::abi_scan::r131;

/// The crates whose `tests/` trees this lane owns.
const CRATES: &[&str] = &["busbar-kernel", "busbar-contract"];

/// Files not in R131's path list, relative to `crates/`, each with why.
const LEFT_OUT: &[(&str, &str)] = &[
    // W3-D-CONTRACT's rule-13 serial handoff files (WBS rule 13): not ported, not deleted now.
    (
        "busbar-contract/tests/architecture_surface.rs",
        "W3-D-CONTRACT handoff (WBS rule 13)",
    ),
    (
        "busbar-contract/tests/layout_golden.rs",
        "W3-D-CONTRACT handoff (WBS rule 13)",
    ),
    (
        "busbar-kernel/tests/loader_host_contracts.rs",
        "W3-D-CONTRACT handoff (WBS rule 13)",
    ),
    (
        "busbar-kernel/tests/plane_driver.rs",
        "W3-D-CONTRACT handoff (WBS rule 13)",
    ),
    (
        "busbar-kernel/tests/support/plane_driver_actual.rs",
        "W3-D-CONTRACT handoff (WBS rule 13)",
    ),
    // Modules of the plane_driver suite above; they swap an ops slot and read raw host-trait
    // arguments, which needs the HostView and swapped-slot rows (not built).
    (
        "busbar-kernel/tests/support/plane_driver_completion_retirement.rs",
        "plane_driver suite: needs HostView and a swapped ops slot (not built)",
    ),
    (
        "busbar-kernel/tests/support/plane_driver_session_input_cases.rs",
        "plane_driver suite: needs HostView (not built)",
    ),
    (
        "busbar-kernel/tests/support/plane_driver_unbilled_cases.rs",
        "plane_driver suite: needs HostView and a swapped ops slot (not built)",
    ),
    // Tests of contract abi/**, which MIN-3 W3-D-CONTRACT deletes (AGREED:52): not ported, not deleted now.
    (
        "busbar-contract/tests/abi_versions.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    (
        "busbar-contract/tests/auth_answer_validators.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    (
        "busbar-contract/tests/common_measurements.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    (
        "busbar-contract/tests/fixtures/sdk_door_plugin.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    (
        "busbar-contract/tests/plane_class_parents.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    (
        "busbar-contract/tests/plane_streaming_media.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    (
        "busbar-contract/tests/sdk_door_cdylib.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    (
        "busbar-contract/tests/sdk_hyper.rs",
        "abi/** (W3-D-CONTRACT deletes it); also needs Watch::block (!2305)",
    ),
    (
        "busbar-contract/tests/sdk_hyper_field_block.rs",
        "abi/** (W3-D-CONTRACT deletes it); also needs Watch::armed_here (!2305)",
    ),
    (
        "busbar-contract/tests/signing_gate_reader.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    (
        "busbar-contract/tests/zero_declarations.rs",
        "abi/** (W3-D-CONTRACT deletes it)",
    ),
    // Port waits for the plugin-facing rows of core MR !2305 (Watch::armed_here and ::block, cpu::thread_ns).
    (
        "busbar-contract/tests/bounded_allocations.rs",
        "needs Watch::armed_here (!2305)",
    ),
];

#[test]
fn r131_holds_over_the_kernel_and_contract_integration_tests() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut found = Vec::new();
    for name in CRATES {
        let root = crates.join(name).canonicalize().expect("the crate");
        let parent = root.parent().expect("crates/").to_path_buf();
        for f in r131(&root) {
            let rel = f
                .file
                .strip_prefix(&parent)
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
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for (path, why) in LEFT_OUT {
        assert!(crates.join(path).is_file(), "{path} is gone: drop its row");
        assert!(!why.is_empty(), "{path} has no reason");
    }
}
