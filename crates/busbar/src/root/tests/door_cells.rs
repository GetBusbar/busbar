// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' OWN ROOT CELLS, HELD TO THE ROSTER (ARCHITECT ruling on #464). The cells are each
//! plane crate's `tests/root/mod.rs`, compiled into this serve module from the path the crate states
//! under its `links` name (`$OUT_DIR/door_cells.rs`); the composition root names no plane.
//!
//! - Every linked plane door states its cells: a door whose crate states none fails here, naming the
//!   crate (`DOOR_CELLS_MISSING`) — a root leg is never skipped.

/// Every plane door the build links states its root cells; `Err` names each crate that states none.
fn every_door_states_its_cells(missing: &[&str]) -> Result<(), String> {
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "the linked plane door crates {missing:?} state no root cells (a `links = \
         \"busbar-door-cells-<crate>\"` row whose `build.rs` prints `cargo::metadata=cells=<its \
         tests/root/mod.rs>`): their root legs cannot run"
    ))
}

/// THE ROSTER: every plane door this build links states its root cells, at a file that exists.
#[test]
fn every_linked_plane_door_states_its_root_cells() {
    every_door_states_its_cells(super::DOOR_CELLS_MISSING).unwrap_or_else(|e| panic!("{e}"));
    for &(krate, at, _, _) in super::DOOR_CELLS {
        assert!(
            std::path::Path::new(at).is_file(),
            "`{krate}` states its cells at {at}, which is no file"
        );
    }
}

/// A DOOR WHOSE CRATE STATES NO CELLS IS REFUSED, NAMING IT — the RED of the no-silent-skip rule.
#[test]
fn a_plane_door_stating_no_cells_fails_naming_its_crate() {
    every_door_states_its_cells(&[]).expect("every door states its cells");
    let refusal = every_door_states_its_cells(&["plane-without-cells"])
        .expect_err("a door with no cells is never skipped");
    assert!(refusal.contains("plane-without-cells"), "{refusal}");
}
