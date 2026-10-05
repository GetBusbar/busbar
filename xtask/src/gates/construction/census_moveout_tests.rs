// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE ACCEPTED WAY DOWN for a `[gate.census.plugin_kinds]` floor: a plugin crate MOVED OUT
//! (TODO PATH TO DEV-GREEN P5), pinned back as a git dependency at an exact rev. Every other drop
//! stays RED.

use std::collections::BTreeMap;

use super::{deleted_plane_crates, glob_matches, lowered_floors, moved_out};

const ROOT: &str = "[workspace.dependencies]\n\
    busbar-x-moved = { git = \"https://example.invalid/busbar-x-moved\", rev = \"0123abc\" }\n\
    busbar-x-branch = { git = \"https://example.invalid/busbar-x-branch\", branch = \"dev\" }\n\
    busbar-x-path = { path = \"crates/busbar-x-path\" }\n";

fn package(dir: &str) -> Option<String> {
    dir.strip_prefix("crates/").map(str::to_string)
}

const DOC: &str = "[gate.census]\nplane_crates = 4\n\n[gate.census.plugin_kinds]\nx = 4\n";

fn doc(s: &str) -> crate::toml_doc::Document {
    crate::toml_doc::parse_str(s).expect("the fixture parses")
}

#[test]
fn a_crate_pinned_back_as_a_git_dependency_at_a_rev_moved_out() {
    assert_eq!(
        moved_out(&["crates/busbar-x-moved".into()], package, ROOT),
        Some(1)
    );
}

/// RED: a crate that left the tree with NO pinned git dependency (deleted, or pulled by branch or
/// path) did not move out, and neither did a set with one such crate in it.
#[test]
fn a_drop_with_no_pinned_git_dependency_is_not_a_move_out() {
    for gone in [
        "crates/busbar-x-gone",
        "crates/busbar-x-branch",
        "crates/busbar-x-path",
    ] {
        assert_eq!(moved_out(&[gone.into()], package, ROOT), None, "{gone}");
    }
    assert_eq!(
        moved_out(
            &[
                "crates/busbar-x-moved".into(),
                "crates/busbar-x-gone".into()
            ],
            package,
            ROOT
        ),
        None
    );
    assert_eq!(moved_out(&[], package, ROOT), None);
}

/// RED: the floor drop is refused unless a move-out covers it, and only by as many crates as moved.
#[test]
fn a_floor_drop_is_accepted_only_up_to_the_crates_that_moved_out() {
    let now = doc(&DOC.replace("x = 4", "x = 3"));
    let base = doc(DOC);
    let none = BTreeMap::new();
    assert_eq!(lowered_floors(&now, &base, "abc1234", &none).len(), 1);
    let one: BTreeMap<String, i64> = [("plugin_kinds.x".to_string(), 1)].into();
    assert!(lowered_floors(&now, &base, "abc1234", &one).is_empty());
    let two_down = doc(&DOC.replace("x = 4", "x = 2"));
    let out = lowered_floors(&two_down, &base, "abc1234", &one);
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
        out[0].contains("plugin_kinds.x: the floor itself went 4 -> 2"),
        "{out:?}"
    );
    // A move-out of one kind excuses no other key.
    let other = doc(&DOC.replace("plane_crates = 4", "plane_crates = 3"));
    assert_eq!(lowered_floors(&other, &base, "abc1234", &one).len(), 1);
}

#[test]
fn a_kind_glob_matches_one_directory_level() {
    assert!(glob_matches(
        "crates/busbar-transport-*",
        "crates/busbar-transport-ws"
    ));
    assert!(glob_matches("crates/hook*", "crates/hook-test-plugin"));
    assert!(glob_matches(
        "crates/busbar-plane-llm",
        "crates/busbar-plane-llm"
    ));
    assert!(!glob_matches(
        "crates/busbar-transport-*",
        "crates/busbar-transport-ws/src"
    ));
    assert!(!glob_matches("crates/store-*", "crates/busbar-store-x"));
}

/// The `plane_crates` floor's way down (ARCHITECT 2026-10-05): a legacy plane crate the base listed
/// and this tree does not counts only when it was deleted under `[gate.census.deleted]`.
#[test]
fn a_plane_crate_deleted_under_the_ledger_excuses_its_floor_drop() {
    let base: Vec<String> = ["busbar-llm", "busbar-voice"].map(String::from).to_vec();
    let now: Vec<String> = vec!["busbar-llm".into()];
    assert_eq!(
        deleted_plane_crates(&base, &now, |d| d == "crates/busbar-voice"),
        Some(1)
    );
    let mut moved = BTreeMap::new();
    moved.insert("plane_crates".to_string(), 1);
    assert!(lowered_floors(
        &doc("[gate.census]\nplane_crates = 3\n"),
        &doc("[gate.census]\nplane_crates = 4\n"),
        "base",
        &moved
    )
    .is_empty());
}

/// RED: a plane crate that left the list without a ledger row excuses nothing, and neither does a
/// list that lost nothing.
#[test]
fn an_unlisted_plane_crate_drop_stays_red() {
    let base: Vec<String> = ["busbar-llm", "busbar-voice"].map(String::from).to_vec();
    let now: Vec<String> = vec!["busbar-llm".into()];
    assert_eq!(deleted_plane_crates(&base, &now, |_| false), None);
    assert_eq!(deleted_plane_crates(&base, &base, |_| true), None);
    assert!(!lowered_floors(
        &doc("[gate.census]\nplane_crates = 3\n"),
        &doc("[gate.census]\nplane_crates = 4\n"),
        "base",
        &BTreeMap::new()
    )
    .is_empty());
}
