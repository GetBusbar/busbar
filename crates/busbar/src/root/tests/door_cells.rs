// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR PLANES' OWN ROOT CELLS, HELD TO THE ROSTER AND TO THE LEDGER (ARCHITECT ruling on #464,
//! applied to every door plane's root leg; coordinator ruling, Law 0 root lane). The cells are each
//! plane crate's `tests/root/mod.rs`, compiled into this serve module from the path the crate states
//! under its `links` name (`$OUT_DIR/door_cells.rs`); the composition root names no plane.
//!
//! - Every linked plane door states its cells: a door whose crate states none fails here, naming the
//!   crate (`DOOR_CELLS_MISSING`) — a root leg is never skipped.
//! - Every door's not-applicable cells are the ledger's own: its `NOT_APPLICABLE`
//!   `(capability, column, reason)` set equals the root-leg cells `qa/capability-equality.json`
//!   marks not applicable on its `COLUMNS`, reason for reason. A plane opts out of nothing the ledger
//!   says it has, and the ledger excuses nothing the plane does not state.

use std::collections::BTreeSet;

use serde_json::Value;

/// The capability-equality ledger the door cells answer to.
const LEDGER: &str = include_str!("../../../../../qa/capability-equality.json");

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

/// The root-leg cells `ledger` marks not applicable on `columns`, as `(capability, column, reason)`.
fn ledger_not_applicable(
    ledger: &Value,
    columns: &[&str],
) -> Result<BTreeSet<(String, String, String)>, String> {
    let cells = ledger
        .get("cells")
        .and_then(Value::as_array)
        .ok_or("the ledger has no `cells`")?;
    let mut out = BTreeSet::new();
    for cell in cells {
        let Some(column) = cell.get("plane").and_then(Value::as_str) else {
            continue;
        };
        if !columns.contains(&column)
            || cell.pointer("/root/state").and_then(Value::as_str) != Some("not-applicable")
        {
            continue;
        }
        let capability = cell
            .get("capability")
            .and_then(Value::as_str)
            .ok_or("a ledger cell names no capability")?;
        let reason = cell
            .get("reason")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("the ledger's `{capability}` x `{column}` states no reason"))?;
        out.insert((
            capability.to_string(),
            column.to_string(),
            reason.to_string(),
        ));
    }
    Ok(out)
}

/// `krate`'s declared not-applicable cells equal the ledger's on its columns; `Err` names every
/// cell the two disagree on, each way.
fn not_applicable_agrees(
    krate: &str,
    columns: &[&str],
    declared: &[(&str, &str, &str)],
    ledger: &Value,
) -> Result<(), String> {
    let ledger = ledger_not_applicable(ledger, columns)?;
    let declared: BTreeSet<(String, String, String)> = declared
        .iter()
        .map(|(c, col, r)| ((*c).to_string(), (*col).to_string(), (*r).to_string()))
        .collect();
    let undeclared: Vec<_> = ledger.difference(&declared).collect();
    let unbacked: Vec<_> = declared.difference(&ledger).collect();
    if undeclared.is_empty() && unbacked.is_empty() {
        return Ok(());
    }
    Err(format!(
        "`{krate}`'s not-applicable root cells disagree with the ledger: the ledger excuses \
         {undeclared:?} which the plane does not state, and the plane states {unbacked:?} which \
         the ledger does not excuse"
    ))
}

/// THE ROSTER: every plane door this build links states its root cells. RED until each linked
/// plane's crate states them; no door is skipped.
#[test]
fn every_linked_plane_door_states_its_root_cells() {
    every_door_states_its_cells(super::DOOR_CELLS_MISSING).unwrap_or_else(|e| panic!("{e}"));
}

/// THE LEDGER: every door's not-applicable root cells are the ledger's, reason for reason.
#[test]
fn every_door_planes_not_applicable_cells_are_the_ledgers() {
    let ledger: Value = serde_json::from_str(LEDGER).expect("the ledger is JSON");
    for &(krate, columns, declared) in super::DOOR_CELLS {
        not_applicable_agrees(krate, columns, declared, &ledger).unwrap_or_else(|e| panic!("{e}"));
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

/// NOT APPLICABLE IS NEVER A FREE PASS: a plane's set agrees only when it IS the ledger's — a cell
/// the ledger excuses but the plane does not state, a cell the plane states but the ledger does not
/// excuse (a capability the ledger says it has), and the same cell for another reason are refused.
#[test]
fn a_planes_not_applicable_cells_must_equal_the_ledgers() {
    let ledger: Value = serde_json::json!({ "cells": [
        { "capability": "net-guard", "plane": "p-client", "state": "not-applicable",
          "reason": "it dials nothing", "root": { "state": "not-applicable", "leg": "root-p" } },
        { "capability": "breaker-trip", "plane": "p-client", "state": "proven", "test": "x::y",
          "root": { "state": "proven", "leg": "root-p", "test": "x::y" } },
        { "capability": "net-guard", "plane": "q-client", "state": "not-applicable",
          "reason": "another plane's", "root": { "state": "not-applicable", "leg": "root-q" } },
    ]});
    let columns = ["p-client"];
    not_applicable_agrees(
        "p",
        &columns,
        &[("net-guard", "p-client", "it dials nothing")],
        &ledger,
    )
    .expect("the ledger's own set agrees");
    let refusal = not_applicable_agrees("p", &columns, &[], &ledger)
        .expect_err("a cell the ledger excuses and the plane does not state");
    assert!(refusal.contains("net-guard"), "{refusal}");
    not_applicable_agrees(
        "p",
        &columns,
        &[
            ("net-guard", "p-client", "it dials nothing"),
            ("breaker-trip", "p-client", "it dials nothing"),
        ],
        &ledger,
    )
    .expect_err("a capability the ledger says the plane has");
    not_applicable_agrees(
        "p",
        &columns,
        &[("net-guard", "p-client", "another reason")],
        &ledger,
    )
    .expect_err("the same cell for another reason");
}
