// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `testing/shadow-oracle/cells.json` is the upgrade tests' corpus and its source of truth (#439: there is no
//! generator; the file is edited by hand). This is its validator: schema, unique ids, every reference a cell
//! makes resolves, every 1.5.5 recording belongs to a cell, and the counts the file states are the counts of its
//! cells. It reads the checked-in files, so a hand edit that breaks one of these fails CI.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use busbar_contract::json::{self, JsonContainerTrait, JsonValueTrait, Value};

use crate::repo_root;

const PLANES: [&str; 4] = ["a2a", "core", "llm", "mcp"];
const DRIVERS: [&str; 5] = ["capture", "concurrent", "exec", "http", "script"];
const MODES: [&str; 3] = ["boot", "cli", "validate"];

fn data() -> PathBuf {
    repo_root().join("testing/shadow-oracle")
}

fn read(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    json::parse_value(text.as_bytes()).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn cells(root: &Value) -> &[Value] {
    root.get("cells")
        .and_then(|c| c.as_array())
        .map(|a| a.as_slice())
        .expect("cells.json has a `cells` array")
}

fn text<'a>(cell: &'a Value, key: &str) -> Option<&'a str> {
    cell.get(key).and_then(|v| v.as_str())
}

fn id(cell: &Value) -> &str {
    text(cell, "id").expect("every cell has a string id")
}

/// The recording file stem of a cell id: `|` is `__`, anything outside `[A-Za-z0-9._-]` is `_`.
fn stem(id: &str) -> String {
    id.replace('|', "__")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn count_of(node: Option<&Value>) -> Option<usize> {
    node.and_then(|n| n.as_u64())
        .and_then(|n| usize::try_from(n).ok())
}

#[test]
fn every_cell_has_the_required_fields_and_a_known_plane_and_driver() {
    let root = read(&data().join("cells.json"));
    let mut bad = Vec::new();
    for cell in cells(&root) {
        let id = text(cell, "id").unwrap_or("<no id>");
        for key in ["id", "plane", "outcome", "why"] {
            if text(cell, key).is_none_or(str::is_empty) {
                bad.push(format!("{id}: `{key}` is missing or empty"));
            }
        }
        if let Some(plane) = text(cell, "plane") {
            if !PLANES.contains(&plane) {
                bad.push(format!("{id}: unknown plane `{plane}`"));
            }
        }
        if let Some(driver) = text(cell, "driver") {
            if !DRIVERS.contains(&driver) {
                bad.push(format!("{id}: unknown driver `{driver}`"));
            }
        }
        if text(cell, "driver") == Some("exec") {
            let exec = cell.get("exec");
            if exec
                .and_then(|e| e.get("args"))
                .and_then(|a| a.as_array())
                .is_none()
            {
                bad.push(format!("{id}: an exec cell carries `exec.args`"));
            }
            match exec.and_then(|e| e.get("mode")).and_then(|m| m.as_str()) {
                Some(mode) if MODES.contains(&mode) => {}
                other => bad.push(format!("{id}: exec.mode {other:?} is not one of {MODES:?}")),
            }
        }
    }
    assert!(bad.is_empty(), "cells.json schema:\n{}", bad.join("\n"));
}

#[test]
fn cell_ids_are_unique_and_each_maps_to_its_own_recording_name() {
    let root = read(&data().join("cells.json"));
    let mut ids = BTreeSet::new();
    let mut stems: BTreeMap<String, String> = BTreeMap::new();
    let mut bad = Vec::new();
    for cell in cells(&root) {
        let id = id(cell);
        if !ids.insert(id.to_owned()) {
            bad.push(format!("duplicate id {id}"));
        }
        if let Some(other) = stems.insert(stem(id), id.to_owned()) {
            if other != id {
                bad.push(format!("{id} and {other} share one recording name"));
            }
        }
    }
    assert!(bad.is_empty(), "cells.json ids:\n{}", bad.join("\n"));
}

#[test]
fn every_reference_a_cell_makes_resolves() {
    let data = data();
    let root = read(&data.join("cells.json"));
    let mutations: BTreeSet<String> = read(&data.join("fixtures/boot-mutations.json"))
        .get("mutations")
        .and_then(|m| m.as_array())
        .expect("boot-mutations.json has `mutations`")
        .iter()
        .filter_map(|m| text(m, "id").map(str::to_owned))
        .collect();
    let mut bad = Vec::new();
    for cell in cells(&root) {
        let id = id(cell);
        if let Some(name) = cell.get("script").and_then(|s| text(s, "name")) {
            if !data.join("scripts").join(name).is_file() {
                bad.push(format!("{id}: script {name} is not in scripts/"));
            }
        }
        let Some(config) = cell.get("exec").and_then(|e| text(e, "config")) else {
            continue;
        };
        if let Some(rest) = config.strip_prefix("mutation:") {
            if !mutations.contains(rest) {
                bad.push(format!(
                    "{id}: mutation {rest} is not in boot-mutations.json"
                ));
            }
        } else if let Some(path) = config
            .strip_prefix("corpus:")
            .or_else(|| config.strip_prefix("migrated:"))
        {
            if !repo_root().join(path).is_file() {
                bad.push(format!("{id}: corpus file {path} does not exist"));
            }
        } else if !matches!(config, "baseline" | "missing") {
            bad.push(format!("{id}: unknown exec.config `{config}`"));
        }
    }
    assert!(bad.is_empty(), "cells.json references:\n{}", bad.join("\n"));
}

#[test]
fn every_recording_belongs_to_a_cell() {
    let data = data();
    let root = read(&data.join("cells.json"));
    let stems: BTreeSet<String> = cells(&root).iter().map(|c| stem(id(c))).collect();
    let dir = data.join("golden/1.5.5/cells");
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    let mut bad = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if !stems.contains(stem) {
            bad.push(format!(
                "{}: no cell has this id",
                dir.join(&name).display()
            ));
        }
    }
    assert!(bad.is_empty(), "orphan recordings:\n{}", bad.join("\n"));
}

#[test]
fn the_counts_the_file_states_are_the_counts_of_its_cells() {
    let root = read(&data().join("cells.json"));
    let counts = root.get("counts").expect("cells.json has `counts`");
    let all = cells(&root);
    assert_eq!(
        count_of(counts.get("total")),
        Some(all.len()),
        "counts.total"
    );
    let mut by_plane: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_family: BTreeMap<&str, usize> = BTreeMap::new();
    for cell in all {
        let plane = text(cell, "plane").unwrap_or("");
        *by_plane.entry(plane).or_default() += 1;
        // A protocol cell names no family: its family is its plane.
        *by_family
            .entry(text(cell, "family").unwrap_or(plane))
            .or_default() += 1;
    }
    for (name, want) in [("by_plane", &by_plane), ("by_family", &by_family)] {
        let stated = counts
            .get(name)
            .and_then(|o| o.as_object())
            .unwrap_or_else(|| panic!("counts.{name} is an object"));
        let stated: BTreeMap<&str, usize> = stated
            .iter()
            .map(|(k, v)| (k, count_of(Some(v)).expect("a count")))
            .collect();
        assert_eq!(&stated, want, "counts.{name}");
    }
}
