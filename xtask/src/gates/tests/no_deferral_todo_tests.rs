// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{close_todo_item, discover, markers_in, markers_memo, todo_item_open};
use crate::ctx::{Ctx, Overlay};

/// A TODO in the committed shape: numbered items before and after the KERNEL<>PLUGINS table,
/// whose step numbers overlap theirs, plus an `ITEM <n>` heading.
const TODO_DOC: &str = "\
# THE PLAN
## PHASE 4
| # | item | exit |
|---|---|---|
| 36 | a work item that shares step 36's number | x |
| ~~41~~ | a superseded item | x |
## KERNEL<>PLUGINS — the migration
| # | Step | Depends on | Gate | Status |
|---|---|---|---|---|
| C0 | CAP: `llm\\|*\\|x` | – | | open |
| 5 | BOOT-LOOP | 1 | | **PARTLY LANDED.** steps 1-2 landed |
| 36 | Delete the engine | 33 | perf | open. **BLOCKED** half |
| 37 | FLEET | 2 | | done |
| 38 | postgres | 3 | | **LANDED** at abc |
| ~~39~~ | struck | 21 | | open |
### LANDED
| commit | what | feeds step |
| a2312c5cc | fixture | 5 |
## KERNEL: A DIFFERENT SECTION
| 40 | not a KP step | x |
## ITEM 572 — `oauth-as` 0.9.3 → 1.0.0
## ~~ITEM 573~~ — struck
";

/// THE MEMOISED MARKERS ARE THE FULL LEX'S, on the real tree and on planted ones: every
/// discovered file's markers through the memo (cold, then warm) equal [`markers_in`] over the
/// same bytes, and a planted file whose bytes change after the real tree filled the memo is
/// lexed fresh — under the same path, so a memo keyed on the path alone would answer wrong.
#[test]
fn the_memoised_markers_are_the_full_lex_on_planted_trees() {
    let base = Ctx::workspace().expect("the workspace opens");
    let real = discover(&base).expect("discovery reads the real tree");
    let (rel, text) = real.last().cloned().expect("discovery found a file");
    let planted = |extra: &str| {
        let mut ov = Overlay::new();
        ov.set(&rel, format!("{text}{extra}"));
        ov
    };
    let plants = [
        Overlay::new(),
        planted("\npub fn planted() -> u8 { todo!() }\n"),
        planted("\n// FIXME: a second planted marker\npub fn other() -> u8 { 1 }\n"),
    ];
    let mut any = 0usize;
    for (i, ov) in plants.into_iter().enumerate() {
        let cx = base.with_overlay(ov);
        for (path, body) in discover(&cx).expect("discovery reads the planted tree") {
            let full = markers_in(&path, &body);
            any += full.len();
            assert_eq!(
                *markers_memo(&path, &body),
                full,
                "plant {i}: {path} (cold)"
            );
            assert_eq!(
                *markers_memo(&path, &body),
                full,
                "plant {i}: {path} (warm)"
            );
        }
    }
    assert!(any > 0, "no marker anywhere, so nothing was compared");
}

#[test]
fn kp_steps_resolve_inside_their_section_only() {
    assert_eq!(todo_item_open(TODO_DOC, "KP-36"), Some(true));
    assert_eq!(todo_item_open(TODO_DOC, "KP-C0"), Some(true));
    // PARTLY LANDED is open; done / LANDED / struck are closed.
    assert_eq!(todo_item_open(TODO_DOC, "KP-5"), Some(true));
    assert_eq!(todo_item_open(TODO_DOC, "KP-37"), Some(false));
    assert_eq!(todo_item_open(TODO_DOC, "KP-38"), Some(false));
    assert_eq!(todo_item_open(TODO_DOC, "KP-39"), Some(false));
    // `## KERNEL: …` is another section; its row 40 is not a step.
    assert_eq!(todo_item_open(TODO_DOC, "KP-40"), None);
    assert_eq!(todo_item_open(TODO_DOC, "KP-999"), None);
}

#[test]
fn items_resolve_outside_the_kp_table_and_by_heading() {
    assert_eq!(todo_item_open(TODO_DOC, "ITEM-36"), Some(true));
    assert_eq!(todo_item_open(TODO_DOC, "ITEM-41"), Some(false));
    assert_eq!(todo_item_open(TODO_DOC, "ITEM-572"), Some(true));
    assert_eq!(todo_item_open(TODO_DOC, "ITEM-573"), Some(false));
    // Step 37 is a KP row, never an item; `ITEM-57` is not a prefix match of 572.
    assert_eq!(todo_item_open(TODO_DOC, "ITEM-37"), None);
    assert_eq!(todo_item_open(TODO_DOC, "ITEM-57"), None);
    assert_eq!(todo_item_open(TODO_DOC, "ITEM-40"), Some(true));
}

#[test]
fn unprefixed_ids_name_nothing() {
    // The retired TRACKER ids, and a bare number that would be ambiguous between the spaces.
    for id in ["H5", "N1", "36", "C0"] {
        assert_eq!(todo_item_open(TODO_DOC, id), None, "{id}");
    }
}

#[test]
fn the_expired_plant_closes_exactly_the_named_item() {
    for id in ["KP-36", "KP-C0", "KP-5", "ITEM-36", "ITEM-572"] {
        let closed = close_todo_item(TODO_DOC, id).expect(id);
        assert_eq!(todo_item_open(&closed, id), Some(false), "{id}");
        // Nothing else moved: the other space's same number is still open.
        let other = if id.starts_with("KP-") {
            id.replacen("KP-", "ITEM-", 1)
        } else {
            id.replacen("ITEM-", "KP-", 1)
        };
        assert_eq!(
            todo_item_open(&closed, &other),
            todo_item_open(TODO_DOC, &other),
            "{id} closed {other} too"
        );
    }
    // Already closed, or absent: nothing to close.
    assert_eq!(close_todo_item(TODO_DOC, "KP-37"), None);
    assert_eq!(close_todo_item(TODO_DOC, "ITEM-99999"), None);
}

#[test]
fn a_cfg_any_test_module_is_production_code_not_scaffolding() {
    use super::any_test_with_other;
    assert!(any_test_with_other("#[cfg(any(test, feature = \"x\"))]"));
    assert!(any_test_with_other("#[cfg(any(feature = \"x\", test))]"));
    assert!(any_test_with_other(
        "#[cfg(all(unix, any(test, debug_assertions)))]"
    ));
    assert!(!any_test_with_other("#[cfg(any(test))]"));
    assert!(!any_test_with_other("#[cfg(all(test, unix))]"));
    assert!(!any_test_with_other("#[cfg(test)]"));
    let planted = "#[cfg(any(test, feature = \"x\"))]\nmod m {\n    fn f() { todo!() }\n}\n";
    assert!(
        !markers_in("crates/x/src/lib.rs", planted).is_empty(),
        "a todo!() in a cfg(any(test, feature)) module must be counted"
    );
}
