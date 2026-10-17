// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMMITTED METHOD INVENTORY IS CHECKED, NOT TRUSTED (audit XA1 HIGH 5; Law 8, BUSBAR-1.6.0.md
//! l.2068-2069: "Where a roster of instances must exist, it is derived from the instances' own
//! declarations; a roster maintained by hand is a defect with a date on it").
//!
//! `qa/method-inventory.json` is the roster `crates/busbar/tests/method_coverage.rs` owes cells
//! against. Deleting the rows of an unimplemented method removed its owed cells with nothing red:
//! `method-inventory --check` was run by nothing, and its in-tree drift test returned early,
//! SKIPPED, whenever the rmcp source was not already in the cargo registry, which no build of this
//! workspace puts there. These cases hold the three things that make the roster a derivation:
//!
//! * THE CHECK IS A REGISTERED GATE, so `cargo xtask gate --all` and the per-gate self-test run it.
//! * THE SOURCES ARE OBTAINED, NEVER SKIPPED: the unplanted tree checks clean (exit 0).
//! * A HAND EDIT IS DRIFT, AND DRIFT EXITS 1.

use xtask::ctx::{Ctx, Overlay};
use xtask::gates;
use xtask::method_inventory;

fn workspace() -> Ctx {
    Ctx::workspace().expect("the workspace opens with its pinned planes")
}

fn check(cx: &Ctx) -> i32 {
    method_inventory::main(cx, &["--check".to_string()])
}

#[test]
fn the_method_inventory_check_is_a_registered_gate() {
    assert!(
        gates::find("method-inventory").is_some(),
        "no registered gate runs `method-inventory --check`, so nothing in `cargo xtask gate --all` \
         or the self-test battery notices a hand-edited qa/method-inventory.json"
    );
}

#[test]
fn the_committed_inventory_checks_clean_from_sources_obtained_not_skipped() {
    assert_eq!(
        check(&workspace()),
        0,
        "`cargo xtask method-inventory --check` over the unplanted tree must derive the inventory \
         from its pinned sources and find it equal to the committed file"
    );
}

#[test]
fn a_hand_edited_inventory_is_drift_and_exits_1() {
    let cx = workspace();
    let committed = cx
        .read(method_inventory::OUT)
        .expect("the committed inventory reads");
    let edited = committed.replacen(
        "\"method\": \"completion/complete\"",
        "\"method\": \"completion/complete-by-hand\"",
        1,
    );
    assert_ne!(edited, committed, "the hand edit found its target");
    let mut ov = Overlay::new();
    ov.set(method_inventory::OUT, edited);
    assert_eq!(
        check(&cx.with_overlay(ov)),
        1,
        "a hand-edited qa/method-inventory.json is drift against a fresh derivation: exit 1"
    );
}
