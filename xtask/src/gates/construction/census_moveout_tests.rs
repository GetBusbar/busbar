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

/// No rename rows.
fn none() -> BTreeMap<String, String> {
    BTreeMap::new()
}

/// The census ledger's rename row `busbar-x-old -> busbar-x-moved`.
fn renamed() -> BTreeMap<String, String> {
    [("busbar-x-old".to_string(), "busbar-x-moved".to_string())].into()
}

fn doc(s: &str) -> crate::toml_doc::Document {
    crate::toml_doc::parse_str(s).expect("the fixture parses")
}

#[test]
fn a_crate_pinned_back_as_a_git_dependency_at_a_rev_moved_out() {
    assert_eq!(
        moved_out(&["crates/busbar-x-moved".into()], package, ROOT, &none()),
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
        assert_eq!(
            moved_out(&[gone.into()], package, ROOT, &none()),
            None,
            "{gone}"
        );
    }
    assert_eq!(
        moved_out(
            &[
                "crates/busbar-x-moved".into(),
                "crates/busbar-x-gone".into()
            ],
            package,
            ROOT,
            &none()
        ),
        None
    );
    assert_eq!(moved_out(&[], package, ROOT, &none()), None);
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

/// RED (ARCHITECT 2026-10-03, Q-L7B2-CENSUS): a crate whose package name changed with the move is
/// NOT a move-out on the pin alone. `crates/busbar-x-old` left the tree, and the root pins
/// `busbar-x-moved` at a rev, but with no rename row nothing says the new crate is the old one.
#[test]
fn a_renamed_move_with_no_rename_row_stays_red() {
    assert_eq!(
        moved_out(&["crates/busbar-x-old".into()], package, ROOT, &none()),
        None
    );
    // And so the floor drop it would have excused is still refused.
    let now = doc(&DOC.replace("x = 4", "x = 3"));
    let out = lowered_floors(&now, &doc(DOC), "abc1234", &BTreeMap::new());
    assert_eq!(out.len(), 1, "{out:?}");
    assert!(
        out[0].contains("plugin_kinds.x: the floor itself went 4 -> 3"),
        "{out:?}"
    );
}

/// RED: a rename row is not enough either. The row names `busbar-x-old -> busbar-x-branch`, and
/// the root pulls the new name by branch, not at a rev — the move is unproven. Nor does a row for
/// one crate excuse another.
#[test]
fn a_rename_row_without_a_pin_under_the_new_name_stays_red() {
    let to_branch: BTreeMap<String, String> =
        [("busbar-x-old".to_string(), "busbar-x-branch".to_string())].into();
    assert_eq!(
        moved_out(&["crates/busbar-x-old".into()], package, ROOT, &to_branch),
        None
    );
    let to_absent: BTreeMap<String, String> =
        [("busbar-x-old".to_string(), "busbar-x-absent".to_string())].into();
    assert_eq!(
        moved_out(&["crates/busbar-x-old".into()], package, ROOT, &to_absent),
        None
    );
    assert_eq!(
        moved_out(&["crates/busbar-x-other".into()], package, ROOT, &renamed()),
        None
    );
}

/// GREEN: BOTH halves — the rename row AND the git pin at a rev under the new name — make the
/// renamed crate a move-out.
#[test]
fn a_renamed_move_with_its_row_and_its_pin_moved_out() {
    assert_eq!(
        moved_out(&["crates/busbar-x-old".into()], package, ROOT, &renamed()),
        Some(1)
    );
}
