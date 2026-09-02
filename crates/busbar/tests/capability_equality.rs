// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EQUALITY GATE. Every cell of `core capability x protocol plane` is `proven` (naming a test
//! that this gate verifies exists), `missing` (the pinned work queue), or `not-applicable` (with a
//! one-line argument) -- and a matrix that drifts from that pin FAILS THE BUILD.
//!
//! Owner's ruling, recorded repeatedly and slipped repeatedly, which is the whole reason this is a
//! gate and not another paragraph:
//!
//! > *"breakers, hooks, auditing -- list all the core functionality. outside should ONLY BE Auth,
//! > Store, Protocols, i.e. Plugins. Any plugin gets all functionality. LLM == MCP == A2A -- just
//! > different protocols not different pathway through engine at all."*
//!
//! And, on being told this was already recorded: *"its been recorded before hence my concern.
//! i keep repeating."* Prose here has a measured half-life of days; the mechanisms that have held
//! are machine gates (PLANE_LEDGER, `pinned_missing_set_is_exact`, the hygiene lints). This file is
//! that mechanism for the equality doctrine, modelled on
//! `crates/busbar/tests/method_coverage.rs` -- the house oracle pattern.
//!
//! ## The three states, and what each one costs
//!
//! | state | claim | enforced how |
//! |---|---|---|
//! | `proven` | a named test exercises the capability ON that plane | the file must exist, the fn must be in it, and the file must live in a test location. A proven cell whose test vanishes or is renamed is RED. |
//! | `missing` | the capability does not reach the plane, or nothing proves it does | allowed, pinned, and NAMED on every umbrella run (`scripts/capability-equality-summary.py`, wired into `scripts/full-gate.sh`). Closing a cell without flipping the pin leaves the queue lying, and the review that lands the closing test is expected to flip it in the same commit. |
//! | `not-applicable` | the plane is not owed this capability | only WITH an argument long enough to actually argue. N/A is a claim, not an escape; an unexplained absent cell is the failure mode this gate exists to prevent, so there is no way to express one. |
//!
//! The matrix is EXACT: every capability x plane pair appears exactly once, no hole, no duplicate,
//! no cell naming a capability or plane the header does not declare. That is the "computed ==
//! pinned" half -- the cross product is computed from the declared axes and the pinned cells must
//! tile it.
//!
//! ## Why it is allowed to be red-in-the-ledger and green-in-CI
//!
//! Same honest-ledger pattern as `qa/method-coverage.missing`: the missing set IS the work queue
//! for wiring the non-LLM planes into the core capabilities (the breaker/failover audit,
//! `design/breaker-all-planes-audit.md`, is the evidence base). Green means "the pin matches
//! reality"; it never means "no gap". The gap is printed, by name, on every full-gate run.
//!
//! **Never weaken this gate to make it green. Never delete a capability to shrink the queue.**

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The doctrine's plane list, verbatim: three protocols, and the two bidirectional ones counted in
/// both directions. A matrix missing a plane is not a smaller matrix, it is a different claim.
const PLANES: [&str; 5] = [
    "llm",
    "mcp-client",
    "mcp-server",
    "a2a-client",
    "a2a-server",
];

/// M0 TOTALITY CROSS-CHECK — a SEPARATE axis from the pinned directional `PLANES` above.
///
/// `PLANES` is the owner's doctrine, pinned verbatim in
/// [`the_gates_own_constants_are_the_doctrines`]; it is deliberately NOT derived from the workspace
/// (the two bidirectional protocols are counted in both directions, so the axis is 5 wide over 3
/// protocols). This map runs the OTHER direction: it names, per workspace PLANE CRATE, the ledger
/// columns that crate answers to. The cross-check below fails loudly if any plane crate the tree
/// carries maps to ZERO columns — a plane that reaches the workspace and then answers to nothing is
/// tracked by no cell, the silent hole the whole file exists to refuse.
///
/// `voice` (busbar-voice, Plane 4) is a skeleton crate not yet split into client/server directions;
/// it is pinned here to its own pending [`VOICE_PENDING_COLUMN`] so the ledger already names it the
/// day it lands. Every OTHER mapped column must be a real declared ledger plane.
const PLANE_CRATE_LEDGER_COLUMNS: &[(&str, &[&str])] = &[
    ("llm", &["llm"]),
    ("mcp", &["mcp-client", "mcp-server"]),
    ("a2a", &["a2a-client", "a2a-server"]),
    ("voice", &[VOICE_PENDING_COLUMN]),
];

/// Voice's column does not yet exist in the directional ledger (the crate is a skeleton); it is
/// pinned as a pending identity so the totality check has a non-empty answer for voice today.
const VOICE_PENDING_COLUMN: &str = "voice";

/// Floor on the capability axis. Sized below today's real number (13) so an ordinary addition does
/// not trip it, and well above zero so a file that quietly lost its rows cannot report equality of
/// nothing.
const MIN_CAPABILITIES: usize = 12;

/// Floor on proven cells. A matrix where nothing is proven is a matrix nobody filled from the tree;
/// today's honest count is well above this.
const MIN_PROVEN: usize = 20;

/// An n/a "argument" shorter than this is a label, not an argument.
const MIN_NA_REASON: usize = 60;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// What the verifier concluded. `missing` keeps the ids so the caller can print the queue.
#[derive(Debug, Default, PartialEq, Eq)]
struct Summary {
    proven: usize,
    missing: Vec<String>,
    not_applicable: usize,
    per_plane_missing: BTreeMap<String, usize>,
}

/// THE ONE VERDICT. Both the real gate and the self-tests below drive this exact function -- a
/// self-test that exercised a copy would prove the copy (the same reason `structure-lint.sh
/// --selftest` runs the real `scan_rule`).
///
/// `required_planes` / `min_capabilities` are parameters so the self-tests can plant a small
/// fixture matrix; [`the_gates_own_constants_are_the_doctrines`] pins the real constants.
fn verify(
    doc: &serde_json::Value,
    root: &Path,
    required_planes: &[&str],
    min_capabilities: usize,
) -> Result<Summary, String> {
    let capabilities: BTreeSet<String> = doc["capabilities"]
        .as_object()
        .ok_or("`capabilities` must be an object of name -> one-line definition")?
        .keys()
        .cloned()
        .collect();
    let planes: BTreeSet<String> = doc["planes"]
        .as_object()
        .ok_or("`planes` must be an object of name -> one-line definition")?
        .keys()
        .cloned()
        .collect();

    if capabilities.len() < min_capabilities {
        return Err(format!(
            "only {} capabilities declared (floor {min_capabilities}). This gate refuses to pass \
             vacuously -- a matrix that lost its rows would report equality of nothing.",
            capabilities.len()
        ));
    }
    for p in required_planes {
        if !planes.contains(*p) {
            return Err(format!(
                "plane `{p}` is not declared. The doctrine's planes are {required_planes:?}; a \
                 matrix missing one is not a smaller matrix, it is a different claim."
            ));
        }
    }
    for p in &planes {
        if !required_planes.contains(&p.as_str()) {
            return Err(format!(
                "plane `{p}` is declared but is not one of the doctrine's planes \
                 {required_planes:?}. Add it to the doctrine (this test) and fill its whole \
                 column, or delete it."
            ));
        }
    }
    for (name, def) in doc["capabilities"].as_object().unwrap() {
        if def.as_str().is_none_or(|d| d.trim().len() < 20) {
            return Err(format!(
                "capability `{name}` has no real one-line definition; an undefined capability \
                 cannot be argued about, only gestured at."
            ));
        }
    }

    let cells = doc["cells"].as_array().ok_or("`cells` must be an array")?;

    let mut seen: BTreeSet<(String, String)> = BTreeSet::new();
    let mut out = Summary::default();
    for p in &planes {
        out.per_plane_missing.insert(p.clone(), 0);
    }

    for cell in cells {
        let cap = cell["capability"]
            .as_str()
            .ok_or("a cell has no `capability`")?;
        let plane = cell["plane"].as_str().ok_or("a cell has no `plane`")?;
        let id = format!("{cap}\u{d7}{plane}"); // U+00D7 MULTIPLICATION SIGN, the matrix's own glyph
        if !capabilities.contains(cap) {
            return Err(format!(
                "cell `{id}` names capability `{cap}` which is not declared in `capabilities`. \
                 An undeclared row is how a capability gets tracked nowhere."
            ));
        }
        if !planes.contains(plane) {
            return Err(format!(
                "cell `{id}` names plane `{plane}` which is not declared in `planes`."
            ));
        }
        if !seen.insert((cap.to_string(), plane.to_string())) {
            return Err(format!(
                "cell `{id}` appears twice. Two answers for one cell is no answer."
            ));
        }
        match cell["state"].as_str() {
            Some("proven") => {
                let test = cell["test"].as_str().ok_or_else(|| {
                    format!(
                        "cell `{id}` is `proven` but names no `test`. Proven means an instrument \
                         was watched; name it as `<repo-relative file>::<test fn>`."
                    )
                })?;
                let (file, func) = test.split_once("::").ok_or_else(|| {
                    format!("cell `{id}`: `test` must be `<repo-relative file>::<test fn>`, got {test:?}")
                })?;
                if !(file.contains("/tests/") || file.ends_with("_tests.rs")) {
                    return Err(format!(
                        "cell `{id}`: {file} is not a test location (`.../tests/...` or \
                         `*_tests.rs`). Evidence must be a test, not a pointer at production code."
                    ));
                }
                let path = root.join(file);
                let src = std::fs::read_to_string(&path).map_err(|e| {
                    format!(
                        "cell `{id}` is `proven` by {test}, but {file} cannot be read ({e}). \
                         A proven cell whose evidence vanished has REGRESSED: either restore the \
                         test or flip the cell to `missing` -- in the same commit, so the queue \
                         tells the truth."
                    )
                })?;
                let sig = format!("fn {func}(");
                if !src.contains(&sig) {
                    return Err(format!(
                        "cell `{id}` is `proven` by {test}, but no `fn {func}(` exists in {file}. \
                         The named instrument is gone or renamed; a claim that outlives its \
                         evidence is exactly the drift this gate exists to stop. Restore or rename \
                         the reference, or flip the cell to `missing`."
                    ));
                }
                out.proven += 1;
            }
            Some("missing") => {
                out.missing.push(id.clone());
                *out.per_plane_missing.get_mut(plane).unwrap() += 1;
            }
            Some("not-applicable") => {
                let reason = cell["reason"].as_str().unwrap_or("");
                if reason.trim().len() < MIN_NA_REASON {
                    return Err(format!(
                        "cell `{id}` is `not-applicable` with reason {reason:?}. N/A is a CLAIM, \
                         not an escape -- it needs a one-line argument (>= {MIN_NA_REASON} chars) a \
                         reviewer could disagree with. An unexplained absent cell is \
                         indistinguishable from an oversight, which is the failure mode."
                    ));
                }
                out.not_applicable += 1;
            }
            other => {
                return Err(format!(
                    "cell `{id}` has state {other:?}. A cell is `proven`, `missing`, or \
                     `not-applicable`; there is no fourth state, deliberately."
                ));
            }
        }
    }

    // The cross product is EXACT: the pinned cells must tile computed capabilities x planes.
    for cap in &capabilities {
        for plane in &planes {
            if !seen.contains(&(cap.clone(), plane.clone())) {
                return Err(format!(
                    "cell `{cap}\u{d7}{plane}` is ABSENT from the matrix. An absent cell and a \
                     considered-and-inapplicable cell look identical on the page; that is the \
                     silent omission this gate exists to catch. Add it as `proven`, `missing`, or \
                     `not-applicable` with an argument."
                ));
            }
        }
    }
    out.missing.sort();
    Ok(out)
}

fn real_doc() -> serde_json::Value {
    let p = repo_root().join("qa/capability-equality.json");
    serde_json::from_str(
        &std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display())),
    )
    .expect("qa/capability-equality.json parses")
}

// ---------------------------------------------------------------------------
// 1. The gate: the pinned matrix is exact, honest, and every proof exists.
// ---------------------------------------------------------------------------

#[test]
fn pinned_equality_matrix_is_exact_and_every_proof_exists() {
    let summary = verify(&real_doc(), &repo_root(), &PLANES, MIN_CAPABILITIES)
        .unwrap_or_else(|e| panic!("qa/capability-equality.json: {e}"));

    assert!(
        summary.proven >= MIN_PROVEN,
        "only {} proven cells (floor {MIN_PROVEN}). A matrix where almost nothing is proven was \
         not filled from the tree; fill it honestly, cell by cell.",
        summary.proven
    );

    // The named gap -- same honest-ledger shape as qa/method-coverage.missing. Green while the pin
    // matches reality; the umbrella (scripts/full-gate.sh) prints this list on every run.
    println!(
        "EQUALITY: {} cells missing ({} proven, {} n/a) -- {}",
        summary.missing.len(),
        summary.proven,
        summary.not_applicable,
        summary.missing.join(", ")
    );
}

/// The constants above ARE the doctrine; a refactor that widened `verify`'s parameters must not be
/// able to quietly narrow what the real gate demands.
#[test]
fn the_gates_own_constants_are_the_doctrines() {
    assert_eq!(
        PLANES,
        [
            "llm",
            "mcp-client",
            "mcp-server",
            "a2a-client",
            "a2a-server"
        ],
        "the plane list is the owner's ruling (LLM == MCP == A2A, both directions of the \
         bidirectional two); changing it is a doctrine change, not a refactor"
    );
    const {
        assert!(MIN_CAPABILITIES >= 12 && MIN_PROVEN >= 20 && MIN_NA_REASON >= 60);
    }
}

/// Read the ONE list of plane keys (`scripts/plane-keys.sh`, the same source the shell gates read)
/// so this test enumerates the workspace plane crates from the tree's single source, not a second
/// hand-kept copy. A plane added there is enumerated here with no edit.
fn plane_keys_from_single_source(root: &Path) -> Vec<String> {
    let p = root.join("scripts/plane-keys.sh");
    let src = std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read the single source of plane keys {}: {e}",
            p.display()
        )
    });
    for line in src.lines() {
        if let Some(rest) = line.trim().strip_prefix("PLANE_KEYS=") {
            return rest
                .trim()
                .trim_matches('"')
                .split_whitespace()
                .map(str::to_string)
                .collect();
        }
    }
    panic!("scripts/plane-keys.sh declares no `PLANE_KEYS=...` line");
}

/// M0 TOTALITY CROSS-CHECK. Enumerate the workspace PLANE CRATES from the single source and assert
/// each maps to >= 1 ledger column. This is the reverse of the pinned matrix: the matrix proves no
/// declared cell is a lie; this proves no plane crate the tree carries is tracked by NOTHING. Voice
/// arriving as a skeleton with no directional column is exactly the hole it catches — pinned here to
/// its pending column so the check is honest-green today and RED the moment a plane crate joins the
/// workspace with no row in `PLANE_CRATE_LEDGER_COLUMNS`.
#[test]
fn every_workspace_plane_crate_maps_to_at_least_one_ledger_column() {
    let root = repo_root();
    let ledger_columns: BTreeSet<String> = real_doc()["planes"]
        .as_object()
        .expect("`planes` is an object")
        .keys()
        .cloned()
        .collect();
    let map: BTreeMap<&str, &[&str]> = PLANE_CRATE_LEDGER_COLUMNS.iter().copied().collect();

    let mut unmapped: Vec<String> = Vec::new();
    for key in plane_keys_from_single_source(&root) {
        // The single source names this plane; the crate must exist, or source and tree disagree.
        let crate_dir = root.join(format!("crates/busbar-{key}"));
        assert!(
            crate_dir.is_dir(),
            "scripts/plane-keys.sh names plane `{key}` but crates/busbar-{key} does not exist; the \
             single source and the tree disagree — fix one."
        );
        match map.get(key.as_str()) {
            Some(cols) if !cols.is_empty() => {
                // Every mapped column must be a real ledger plane, EXCEPT voice's pending column
                // (the crate is a skeleton; its directional identity is not yet in the ledger).
                for &col in *cols {
                    if col == VOICE_PENDING_COLUMN {
                        continue;
                    }
                    assert!(
                        ledger_columns.contains(col),
                        "plane crate busbar-{key} maps to column `{col}`, which is not a declared \
                         ledger plane {ledger_columns:?}. Fix the map or the ledger."
                    );
                }
            }
            _ => unmapped.push(key),
        }
    }
    assert!(
        unmapped.is_empty(),
        "workspace plane crate(s) {unmapped:?} map to ZERO ledger columns. A plane crate that \
         reaches the workspace and answers to no column is tracked by nothing — add its columns to \
         PLANE_CRATE_LEDGER_COLUMNS (voice is pinned to its own pending column as the pattern)."
    );

    println!(
        "TOTALITY: {} workspace plane crate(s) all map to >= 1 ledger column",
        PLANE_CRATE_LEDGER_COLUMNS.len()
    );
}

// ---------------------------------------------------------------------------
// 2. SELF-TEST: the gate is proven to FIRE, on fixtures, through the REAL `verify`.
//    House rule: a gate that cannot fail is worse than none.
// ---------------------------------------------------------------------------

/// A small well-formed matrix (2 capabilities x 2 planes) whose one proven cell points at a fixture
/// test file this helper plants on disk. Each red case below breaks exactly one thing.
fn fixture(root: &Path) -> serde_json::Value {
    let tests_dir = root.join("crates/x/tests");
    std::fs::create_dir_all(&tests_dir).expect("fixture tests dir");
    std::fs::write(
        tests_dir.join("real_tests.rs"),
        "#[test]\nfn the_named_instrument() {}\n",
    )
    .expect("fixture test file");
    serde_json::json!({
        "capabilities": {
            "cap-a": "a capability defined at argument length for the fixture",
            "cap-b": "another capability defined at argument length for the fixture"
        },
        "planes": { "p1": "first fixture plane", "p2": "second fixture plane" },
        "cells": [
            { "capability": "cap-a", "plane": "p1", "state": "proven",
              "test": "crates/x/tests/real_tests.rs::the_named_instrument" },
            { "capability": "cap-a", "plane": "p2", "state": "missing" },
            { "capability": "cap-b", "plane": "p1", "state": "not-applicable",
              "reason": "a fixture argument that is long enough to be an actual argument a reviewer could disagree with" },
            { "capability": "cap-b", "plane": "p2", "state": "missing" }
        ]
    })
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-capability-equality-selftest-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("selftest scratch dir");
    d
}

#[test]
fn selftest_green_fixture_passes_and_counts_honestly() {
    let root = scratch("green");
    let s = verify(&fixture(&root), &root, &["p1", "p2"], 2).expect("the green fixture verifies");
    assert_eq!(s.proven, 1);
    assert_eq!(s.missing, vec!["cap-a\u{d7}p2", "cap-b\u{d7}p2"]);
    assert_eq!(s.not_applicable, 1);
    assert_eq!(s.per_plane_missing["p2"], 2);
    let _ = std::fs::remove_dir_all(&root);
}

/// (a) A proven cell whose named test VANISHES must turn the gate red -- this is the regression
/// case, and it is the single most important firing mode: a claim outliving its evidence.
#[test]
fn selftest_a_proven_cell_whose_named_test_vanished_is_red() {
    // The fn is renamed out from under the claim.
    let root = scratch("vanish-fn");
    let doc = fixture(&root);
    std::fs::write(
        root.join("crates/x/tests/real_tests.rs"),
        "#[test]\nfn renamed_out_from_under_the_claim() {}\n",
    )
    .unwrap();
    let err = verify(&doc, &root, &["p1", "p2"], 2).expect_err("a vanished test fn must be red");
    assert!(
        err.contains("the_named_instrument") && err.contains("gone or renamed"),
        "the error must name the vanished instrument; got: {err}"
    );

    // The whole file is deleted.
    let root2 = scratch("vanish-file");
    let doc2 = fixture(&root2);
    std::fs::remove_file(root2.join("crates/x/tests/real_tests.rs")).unwrap();
    let err2 =
        verify(&doc2, &root2, &["p1", "p2"], 2).expect_err("a deleted test file must be red");
    assert!(
        err2.contains("REGRESSED"),
        "the error must say the cell regressed; got: {err2}"
    );

    // And evidence pointing at NON-test code is refused even if it exists.
    let root3 = scratch("not-a-test");
    let mut doc3 = fixture(&root3);
    std::fs::create_dir_all(root3.join("crates/x/src")).unwrap();
    std::fs::write(
        root3.join("crates/x/src/lib.rs"),
        "pub fn the_named_instrument() {}\n",
    )
    .unwrap();
    doc3["cells"][0]["test"] = "crates/x/src/lib.rs::the_named_instrument".into();
    let err3 = verify(&doc3, &root3, &["p1", "p2"], 2)
        .expect_err("production code is not evidence of a watched instrument");
    assert!(err3.contains("not a test location"), "got: {err3}");

    for r in [root, root2, root3] {
        let _ = std::fs::remove_dir_all(&r);
    }
}

/// (b) A pinned file that disagrees with the computed cross product -- a hole, a duplicate, or a
/// cell naming an undeclared axis -- must be red. An absent cell and a considered cell look
/// identical on the page; only the computation tells them apart.
#[test]
fn selftest_b_pin_disagreeing_with_computed_cross_product_is_red() {
    // A HOLE: one cell silently absent.
    let root = scratch("hole");
    let mut doc = fixture(&root);
    doc["cells"].as_array_mut().unwrap().pop();
    let err = verify(&doc, &root, &["p1", "p2"], 2).expect_err("a hole in the matrix must be red");
    assert!(
        err.contains("cap-b\u{d7}p2") && err.contains("ABSENT"),
        "the error must name the absent cell; got: {err}"
    );

    // A DUPLICATE: two answers for one cell.
    let root2 = scratch("dup");
    let mut doc2 = fixture(&root2);
    let dup = doc2["cells"][1].clone();
    doc2["cells"].as_array_mut().unwrap().push(dup);
    let err2 = verify(&doc2, &root2, &["p1", "p2"], 2).expect_err("a duplicate cell must be red");
    assert!(err2.contains("appears twice"), "got: {err2}");

    // AN UNDECLARED PLANE: a cell for a column the header does not own.
    let root3 = scratch("undeclared");
    let mut doc3 = fixture(&root3);
    doc3["cells"][1]["plane"] = "p9".into();
    let err3 =
        verify(&doc3, &root3, &["p1", "p2"], 2).expect_err("an undeclared plane must be red");
    assert!(err3.contains("p9"), "got: {err3}");

    // A FOURTH STATE: `partially` is not a state, here or in method-coverage.
    let root4 = scratch("fourth-state");
    let mut doc4 = fixture(&root4);
    doc4["cells"][1]["state"] = "partially".into();
    let err4 = verify(&doc4, &root4, &["p1", "p2"], 2).expect_err("a fourth state must be red");
    assert!(err4.contains("no fourth state"), "got: {err4}");

    for r in [root, root2, root3, root4] {
        let _ = std::fs::remove_dir_all(&r);
    }
}

/// (c) An n/a cell with no argument (or a token one) must be red. N/A is a claim.
#[test]
fn selftest_c_na_cell_without_an_argument_is_red() {
    let root = scratch("na-empty");
    let mut doc = fixture(&root);
    doc["cells"][2]["reason"] = "".into();
    let err = verify(&doc, &root, &["p1", "p2"], 2).expect_err("an argument-free n/a must be red");
    assert!(err.contains("not an escape"), "got: {err}");

    let root2 = scratch("na-token");
    let mut doc2 = fixture(&root2);
    doc2["cells"][2]["reason"] = "does not apply".into();
    let err2 = verify(&doc2, &root2, &["p1", "p2"], 2).expect_err("a token n/a label must be red");
    assert!(err2.contains("not an escape"), "got: {err2}");

    // And an n/a with a REAL argument still passes -- the gate must move in both directions or it
    // is decorative.
    let root3 = scratch("na-ok");
    let doc3 = fixture(&root3);
    verify(&doc3, &root3, &["p1", "p2"], 2).expect("a properly argued n/a is legitimate");

    for r in [root, root2, root3] {
        let _ = std::fs::remove_dir_all(&r);
    }
}
