// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::ledger::Status;

fn cx() -> Ctx {
    Ctx::workspace().expect("workspace context")
}

fn status_of(v: &Verdict, id: &str) -> Status {
    v.rows
        .iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("{id} was not emitted"))
        .status
}

/// The committed locks clear every row, and every floor is armed at exactly what the lock holds
/// (a floor below the count is a floor that lets the next trim through unseen).
#[test]
fn the_committed_locks_are_green_and_every_floor_is_armed_at_its_count() {
    let cx = cx();
    let v = FieldInventoryGate.run(&cx);
    for id in FieldInventoryGate.owed() {
        assert_eq!(status_of(&v, &id), Status::Pass, "{id}");
    }
    let locks = wire_lock::committed(&cx).expect("locks");
    for (d, l) in DIALECTS.iter().zip(&locks) {
        for (dir, paths) in &l.dirs {
            let floor = PAIR_FLOORS
                .iter()
                .find(|(n, x, _)| *n == d.name && x == dir)
                .map(|(_, _, f)| *f);
            assert_eq!(floor, Some(paths.len()), "{}/{dir}", d.name);
        }
    }
}

/// A trimmed direction is caught by the floor and by nothing that reads it as well-formed.
#[test]
fn a_direction_trimmed_below_its_floor_reds_both_directions_only() {
    let cx = cx();
    let trimmed = cx.with_overlay(edit(&cx, "gemini", &|l| {
        if let Some(r) = l.dirs.get_mut("response") {
            let keep = r.keys().next().cloned();
            r.retain(|k, _| Some(k) == keep.as_ref());
        }
    }));
    let v = FieldInventoryGate.run(&trimmed);
    assert_eq!(status_of(&v, ROW_PROVENANCE), Status::Pass);
    assert_eq!(status_of(&v, ROW_BOTH_DIRECTIONS), Status::Fail);
}

/// A re-pinned spec whose lock was not regenerated is red on provenance, naming the command.
#[test]
fn a_repinned_spec_without_a_regenerated_lock_is_refused() {
    let cx = cx();
    let tsv = cx.read(wire_lock::spec::DIGESTS).expect("tsv");
    let pin = wire_lock::spec::pins(&cx).expect("pins")["bedrock"]
        .sha256
        .clone();
    let mut ov = Overlay::new();
    ov.set(wire_lock::spec::DIGESTS, tsv.replace(&pin, &"f".repeat(64)));
    let v = FieldInventoryGate.run(&cx.with_overlay(ov));
    assert_eq!(status_of(&v, ROW_PROVENANCE), Status::Fail);
    assert_eq!(status_of(&v, ROW_REGISTRATION), Status::Pass);
}

/// A lock in any layout but its canonical render is refused by the canonical row, and the
/// whitespace-shaped duplicate check alone reads nothing in it.
#[test]
fn a_reformatted_lock_is_refused_as_non_canonical() {
    let cx = cx();
    let path = wire_lock::lock_path("cohere");
    let text = cx.read(&path).expect("lock");
    let mut ov = Overlay::new();
    ov.set(&path, text.replace("\n    \"", "\n      \""));
    let v = FieldInventoryGate.run(&cx.with_overlay(ov));
    assert_eq!(status_of(&v, ROW_CANONICAL_FORM), Status::Fail);
    assert_eq!(status_of(&v, ROW_PROVENANCE), Status::Pass);
}

/// A duplicated path key is not the canonical render of anything: the canonical row reds on it
/// even where the duplicate check's line shape does not match.
#[test]
fn a_duplicated_path_in_a_reformatted_lock_is_still_refused() {
    let cx = cx();
    let path = wire_lock::lock_path("cohere");
    let text = cx.read(&path).expect("lock");
    let doubled = text
        .replacen(
            "    \"model\": ",
            "    \"model\": {\"type\":\"string\"},\n    \"model\": ",
            1,
        )
        .replace("\n    \"", "\n\t\"");
    let mut ov = Overlay::new();
    ov.set(&path, doubled);
    let v = FieldInventoryGate.run(&cx.with_overlay(ov));
    assert_eq!(status_of(&v, ROW_NO_DUPLICATE_FIELDS), Status::Pass);
    assert_eq!(status_of(&v, ROW_CANONICAL_FORM), Status::Fail);
}

/// A floor row naming a pair the register does not declare is a finding.
#[test]
fn an_orphan_floor_row_is_refused() {
    let mut floors = PAIR_FLOORS.to_vec();
    assert!(orphan_floors(&floors).is_empty());
    floors.push(("openai", "bogus", 1));
    floors.push(("retired", "request", 1));
    assert_eq!(orphan_floors(&floors).len(), 2);
}
