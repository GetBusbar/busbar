// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::ledger::Status;

/// ITEM 219: a manifest OUTSIDE `crates/` and `xtask/` that depends on xtask reds the reverse
/// row. `fuzz/Cargo.toml` is one of three tracked manifests the old three-root walk never read.
#[test]
fn a_manifest_outside_the_workspace_roots_depending_on_xtask_is_red() {
    let cx = Ctx::workspace().expect("workspace context");
    let text = cx
        .read("fuzz/Cargo.toml")
        .expect("fuzz/Cargo.toml is tracked");
    let mut ov = Overlay::new();
    ov.set(
        "fuzz/Cargo.toml",
        format!("{text}\n[dev-dependencies]\nxtask = {{ path = \"../xtask\" }}\n"),
    );
    let row = rule_reverse(&cx.with_overlay(ov));
    assert_eq!(row.status, Status::Fail, "{}", row.detail);
    assert!(row.detail.contains("fuzz/Cargo.toml"), "{}", row.detail);
    let clean = rule_reverse(&cx);
    assert_eq!(clean.status, Status::Pass, "{}", clean.detail);
}

/// ITEM 219: the floors sit near the populations they guard, not 5-20x beneath them. A floor
/// under a fifth of what it guards cannot tell a narrowed walk from a whole one.
#[test]
fn the_walk_floors_guard_most_of_their_populations() {
    let cx = Ctx::workspace().expect("workspace context");
    let src = cx
        .walk(&WalkSpec::new(["xtask/src"]).ext("rs").allow_empty())
        .expect("xtask/src walk")
        .len();
    let manifests = cx
        .walk(&WalkSpec::new(["."]).ext("toml").allow_empty())
        .expect("tree walk")
        .iter()
        .filter(|f| f.rel_str() == "Cargo.toml" || f.rel_str().ends_with("/Cargo.toml"))
        .count();
    assert!(
        SRC_FLOOR * 4 >= src * 3 && SRC_FLOOR <= src,
        "SRC_FLOOR {SRC_FLOOR} against {src} files: a floor must guard at least three quarters \
         of its population and never exceed it"
    );
    assert!(
        MANIFEST_FLOOR * 4 >= manifests * 3 && MANIFEST_FLOOR <= manifests,
        "MANIFEST_FLOOR {MANIFEST_FLOOR} against {manifests} manifests"
    );
}
