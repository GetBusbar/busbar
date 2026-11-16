// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-HEADER (ABI-MIN3-INTERFACE §14): The C header: static asserts, the C fixture's admit arm, the arena arm and
//! the full-table nested arm (rounds 11, 20, 22). The secret-c arm runs in its repo.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

// W1-A13: the generator, the compiler step, the C fixture, its C host and the cc job script live with the header
// (busbar-plugin-abi/tests/c_header/); the cc job runs these arms on every CI target with its own CC.
#[path = "../../busbar-plugin-abi/tests/c_header/asserts.rs"]
mod asserts;
#[path = "../../busbar-plugin-abi/tests/c_header/cc.rs"]
pub(crate) mod cc;

/// One `_Static_assert` per size, alignment, offset and constant, read from the Rust items, compiles with the
/// header under `cc -std=c11 -Wall -Werror`; so does the C fixture, built from the header alone.
#[test]
fn the_static_asserts_compile_with_the_header() {
    let file = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("c_header_asserts.c");
    std::fs::write(&file, asserts::generate()).expect("the assert file is written");
    cc::cc(
        "c_header_asserts.o",
        &[file.to_str().expect("a UTF-8 path")],
        false,
    );
    cc::cc("c_header_fixture.o", &["fixture.c"], false);
}

#[test]
#[ignore = "owner: W1-L1"]
fn the_c_fixture_admits_and_runs_every_entry() {
    todo!("owner: W1-L1 (C-HEADER)")
}

#[test]
#[ignore = "owner: W1-H1 (blocked: entry::guard, GetBusbar/busbar#272)"]
fn arena_outputs_never_overlap_and_are_zero_after_the_entry() {
    todo!("owner: W1-H1 (C-HEADER)")
}

#[test]
#[ignore = "owner: W1-H1 (blocked: entry::guard, GetBusbar/busbar#272)"]
fn the_full_table_nested_arm() {
    todo!("owner: W1-H1 (C-HEADER)")
}
