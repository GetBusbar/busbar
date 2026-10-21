// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 4-PLANE BEHAVIOURAL ISOMORPHISM GATE (Assertion I2 of
//! docs/design/BUSBAR-1.6.0.md THE DESIGN, §1).
//!
//! Owner's ruling, recorded and slipped repeatedly, which is why this is a gate and not a paragraph:
//!
//! > every plane is the same pathway through the engine; only the protocol differs.
//!
//! The structural half of isomorphism (Assertion I1) is enforced by the type system already: every
//! plane crate constructs the SAME registry `PlaneDecl`, naming every field or failing to compile.
//! What is NOT type-checked is the SEMANTIC half: whether each `None` hook is a legitimate capability
//! difference or a silent gap. This test fills that hole. It REFLECTS THE ACTUAL Some/None of the
//! installed `&'static PlaneDecl` values (it does not re-read a ledger to decide the matrix — the
//! whole point, per Risk 2), and for every hook field where one plane is `Some` while a sibling is
//! `None`, it FORBIDS the `None` unless it is declared in `qa/plane-hook-isomorphism.allow` AND the
//! declared capability maps to a real cell in `qa/capability-equality.json` for that plane's ledger
//! column(s). An undeclared asymmetric `None` is RED (a plane quietly not doing what a sibling does,
//! nobody having decided that is correct); a declared row that is NOT actually an asymmetric `None` on
//! the live decls is also RED (a stale exemption). Over- and under-count both fail.
//!
//! ## What is reflected, and what is not
//!
//! The installed planes are the ones the composition root links on the `plane` axis and pushes
//! through `install_planes`; a plane served through its door alone installs no PlaneDecl. That axis
//! is EMPTY today (the doctrine cell below holds it so): every plane is a door plane. The cells that
//! reflected the live decls were gated on `linked_axis_plane`, a cfg no linked row sets, so they never
//! ran; they are deleted with the allowlist only they read (status row 82, D2; Law 10). The fixture
//! self-tests keep `verify` proven, so a row returning to the plane axis is a doctrine change made with
//! its cells, not an empty gate.
//!
//! Modelled on `crates/busbar/tests/capability_equality.rs` -- the house oracle pattern: one `verify`
//! fn drives both the real gate and the fixture self-tests, so a self-test proves the REAL gate fires.

mod common;

use busbar_kernel::plane_driver::row::PlaneDecl;
use std::collections::{BTreeMap, BTreeSet};
/// THE PINNED HOOK-FIELD SET — every `Option<…>` capability hook on the registry `PlaneDecl`, each
/// paired with the extractor that reads its Some/None off a live decl. This is the "small pinned map"
/// the design requires; its length is floor-checked ([`MIN_HOOK_FIELDS`]) so it cannot silently shrink
/// to prove nothing. A hook added to `PlaneDecl` that is not added here is invisible to this gate — the
/// same inherent limit `capability_equality.rs`'s pinned axes carry; the floor keeps the set honest.
#[allow(clippy::type_complexity)]
const HOOK_FIELDS: &[(&str, fn(&PlaneDecl) -> bool)] = &[
    ("routes", |d| d.routes.is_some()),
    ("admin_routes", |d| d.admin_routes.is_some()),
    ("openapi", |d| d.openapi.is_some()),
    // NOTE: `openapi_schemas` is `#[cfg(feature = "openapi-schema")]`-gated on PlaneDecl, so it is
    // genuinely ABSENT from the default build this test runs in. Reflecting it would make the hook set
    // feature-conditional, so it is deliberately not in this set.
    ("hydrate", |d| d.hydrate.is_some()),
    ("start", |d| d.start.is_some()),
    ("config_validate", |d| d.config_validate.is_some()),
    ("registry_contains", |d| d.registry_contains.is_some()),
    ("reresolve_gates", |d| d.reresolve_gates.is_some()),
    ("retain_verify_gates", |d| d.retain_verify_gates.is_some()),
    ("default_section", |d| d.default_section.is_some()),
    ("on_swap", |d| d.on_swap.is_some()),
    ("parse_endpoint", |d| d.parse_endpoint.is_some()),
    ("lower_endpoint", |d| d.lower_endpoint.is_some()),
    ("build_runtime", |d| d.build_runtime.is_some()),
    ("card_signing_domain", |d| d.card_signing_domain.is_some()),
    ("card_kid_prefix", |d| d.card_kid_prefix.is_some()),
];

/// Floor on the reflected hook set (sized below today's 17 so an ordinary addition does not trip it,
/// well above zero so a set that quietly lost its rows cannot report isomorphism of nothing).
const MIN_HOOK_FIELDS: usize = 15;

/// The doctrine map: each INSTALLED plane crate key → the directional ledger column(s) it answers to
/// in `qa/capability-equality.json`. The bidirectional protocols count in both directions. Pinned
/// (not derived) for the same reason `capability_equality.rs` pins its axes: it is the owner's ruling.
fn plane_ledger_columns() -> Vec<(&'static str, &'static [&'static str])> {
    common::doctrine_rows("installed")
        .into_iter()
        .map(|r| {
            let cols: &'static [&'static str] = Box::leak(r[1..].to_vec().into_boxed_slice());
            (r[0], cols)
        })
        .collect()
}

/// The Some/None matrix: `field -> (plane -> is_some)`. Computed from the live decls.
type Matrix = BTreeMap<String, BTreeMap<String, bool>>;

#[derive(Debug, Default, PartialEq, Eq)]
struct Summary {
    /// Every `(field, plane)` where the plane is `None` and a sibling is `Some`.
    asymmetric_nones: BTreeSet<(String, String)>,
    /// The asymmetric `None`s that a declared, ledger-anchored allowlist row accounts for.
    declared: usize,
}

/// THE ONE VERDICT. Both the real gate and the self-tests drive this exact function over DATA
/// (matrix + ledger + allowlist as `serde_json::Value`), so a self-test that plants a fixture matrix
/// proves the REAL join, not a copy of it.
fn verify(
    matrix: &Matrix,
    ledger: &serde_json::Value,
    allow: &serde_json::Value,
    columns: &BTreeMap<&str, &[&str]>,
    min_hook_fields: usize,
    min_asymmetries: usize,
) -> Result<Summary, String> {
    verify_scoped(
        matrix,
        ledger,
        allow,
        columns,
        min_hook_fields,
        min_asymmetries,
        true,
    )
}

/// [`verify`], told whether EVERY plane is linked into this build. With the whole roster the
/// staleness check is exact. With part of it, an allowlist row can only be judged for a plane that
/// is linked, and only on the one question the part can answer: the plane that row says is `None`
/// now FILLS the hook. A row for an unlinked plane, or one whose `Some` sibling is not linked here,
/// is not stale — it is unobservable in this build.
fn verify_scoped(
    matrix: &Matrix,
    ledger: &serde_json::Value,
    allow: &serde_json::Value,
    columns: &BTreeMap<&str, &[&str]>,
    min_hook_fields: usize,
    min_asymmetries: usize,
    every_plane_linked: bool,
) -> Result<Summary, String> {
    if matrix.len() < min_hook_fields {
        return Err(format!(
            "only {} hook fields reflected (floor {min_hook_fields}). A matrix that lost its rows \
             would report isomorphism of nothing.",
            matrix.len()
        ));
    }

    let ledger_caps: BTreeSet<String> = ledger["capabilities"]
        .as_object()
        .ok_or("qa/capability-equality.json: `capabilities` must be an object")?
        .keys()
        .cloned()
        .collect();
    // The set of (capability, plane-column) cells the ledger declares — totality makes this the whole
    // cross product, but we READ it rather than assume it, so a hole in the ledger is caught here too.
    let mut ledger_cells: BTreeSet<(String, String)> = BTreeSet::new();
    for cell in ledger["cells"]
        .as_array()
        .ok_or("qa/capability-equality.json: `cells` must be an array")?
    {
        let cap = cell["capability"]
            .as_str()
            .ok_or("a ledger cell has no `capability`")?;
        let plane = cell["plane"]
            .as_str()
            .ok_or("a ledger cell has no `plane`")?;
        ledger_cells.insert((cap.to_string(), plane.to_string()));
    }

    // (1) Compute the asymmetric-None set straight off the reflected matrix.
    let mut asymmetric_nones: BTreeSet<(String, String)> = BTreeSet::new();
    for (field, row) in matrix {
        let any_some = row.values().any(|&s| s);
        if !any_some {
            continue; // all-None (or all-Some) is symmetric — no asymmetry to account for.
        }
        for (plane, &is_some) in row {
            if !is_some {
                asymmetric_nones.insert((field.clone(), plane.clone()));
            }
        }
    }

    // (2) Load the declared allowlist rows and validate each against the ledger + the live matrix.
    let rows = allow["asymmetries"]
        .as_array()
        .ok_or("qa/plane-hook-isomorphism.allow: `asymmetries` must be an array")?;
    if rows.len() < min_asymmetries {
        return Err(format!(
            "only {} allowlist rows (floor {min_asymmetries}); an allowlist gutted to nothing cannot \
             account for a decl set that has asymmetries.",
            rows.len()
        ));
    }

    let mut declared_set: BTreeSet<(String, String)> = BTreeSet::new();
    for row in rows {
        let field = row["field"]
            .as_str()
            .ok_or("an allowlist row has no `field`")?;
        let capability = row["capability"]
            .as_str()
            .ok_or_else(|| format!("allowlist row for `{field}` has no `capability`"))?;
        let reason = row["reason"].as_str().unwrap_or("");
        if reason.trim().len() < 40 {
            return Err(format!(
                "allowlist row `{field}` has reason {reason:?}: an accepted asymmetry needs a real \
                 one-line argument (>= 40 chars) a reviewer could disagree with, not a label."
            ));
        }
        if !matrix.contains_key(field) {
            return Err(format!(
                "allowlist row names hook `{field}`, which is not a reflected PlaneDecl hook \
                 {:?}. Fix the field name or add the hook to HOOK_FIELDS.",
                matrix.keys().collect::<Vec<_>>()
            ));
        }
        if !ledger_caps.contains(capability) {
            return Err(format!(
                "allowlist row `{field}` names capability `{capability}`, which is not declared in \
                 qa/capability-equality.json. An asymmetry must map to a REAL ledger capability."
            ));
        }
        let planes_none = row["planes_none"]
            .as_array()
            .ok_or_else(|| format!("allowlist row `{field}` has no `planes_none` array"))?;
        for p in planes_none {
            let plane = p.as_str().ok_or_else(|| {
                format!("allowlist row `{field}`: a `planes_none` entry is not a string")
            })?;
            let cols = columns.get(plane).ok_or_else(|| {
                format!(
                    "allowlist row `{field}` names plane `{plane}`, which is not an installed plane \
                     {:?}.",
                    columns.keys().collect::<Vec<_>>()
                )
            })?;
            // The asymmetry MUST map to a real cell for EACH of the plane's ledger columns.
            for &col in *cols {
                if !ledger_cells.contains(&(capability.to_string(), col.to_string())) {
                    return Err(format!(
                        "allowlist row `{field}` for plane `{plane}` maps to capability \
                         `{capability}`, but qa/capability-equality.json has no cell \
                         `{capability}×{col}`. The asymmetry maps to no ledger cell."
                    ));
                }
            }
            if !declared_set.insert((field.to_string(), plane.to_string())) {
                return Err(format!(
                    "allowlist row declares `{field}`/`{plane}` twice; two answers for one cell is \
                     no answer."
                ));
            }
        }
    }

    // (3) EXACTNESS both ways: every actual asymmetric None must be declared, and every declared
    //     row must be an actual asymmetric None (no stale exemption).
    let undeclared: Vec<String> = asymmetric_nones
        .iter()
        .filter(|c| !declared_set.contains(*c))
        .map(|(f, p)| format!("{f}×{p}"))
        .collect();
    if !undeclared.is_empty() {
        return Err(format!(
            "UNDECLARED asymmetric None(s): {}. A plane is `None` on a hook a sibling fills, with no \
             qa/plane-hook-isomorphism.allow row accounting for it. Either wire the hook, or declare \
             the difference with a ledger-anchored argument.",
            undeclared.join(", ")
        ));
    }
    let stale: Vec<String> = declared_set
        .iter()
        .filter(|c| !asymmetric_nones.contains(*c))
        .filter(|(f, p)| {
            every_plane_linked || matrix.get(f).and_then(|row| row.get(p)).copied() == Some(true)
        })
        .map(|(f, p)| format!("{f}×{p}"))
        .collect();
    if !stale.is_empty() {
        return Err(format!(
            "STALE allowlist row(s): {}. These declare an asymmetric None that no longer exists on \
             the live decls (the hook was wired, or the sibling's Some went away). Drop the row so \
             the allowlist matches the decls.",
            stale.join(", ")
        ));
    }

    Ok(Summary {
        declared: declared_set.len(),
        asymmetric_nones,
    })
}

// ---------------------------------------------------------------------------
// 1. THE GATE: the live decls' asymmetries are all declared, ledger-anchored, and exact.
// ---------------------------------------------------------------------------

/// Root-proven cells per `(leg, column)` — the unit the root-leg assertion above names.
fn proven_per_leg_column(ledger: &serde_json::Value) -> BTreeMap<(String, String), usize> {
    let mut out: BTreeMap<(String, String), usize> = BTreeMap::new();
    for cell in ledger["cells"].as_array().expect("`cells` is an array") {
        let r = &cell["root"];
        if r["state"].as_str() == Some("proven") {
            if let (Some(leg), Some(col)) = (r["leg"].as_str(), cell["plane"].as_str()) {
                *out.entry((leg.to_string(), col.to_string())).or_default() += 1;
            }
        }
    }
    out
}

/// The tally is per COLUMN: a leg proving seven client-column cells and no server-column cell has a
/// dead server column, and the per-leg count of seven must not stand in for it.
#[test]
fn selftest_a_column_whose_root_proofs_are_all_gone_counts_zero_under_a_leg_that_proves_others() {
    let ledger = serde_json::json!({
        "cells": [
            { "capability": "c1", "plane": "p-client", "root": { "state": "proven", "leg": "root-p" } },
            { "capability": "c2", "plane": "p-client", "root": { "state": "proven", "leg": "root-p" } },
            { "capability": "c1", "plane": "p-server", "root": { "state": "none", "leg": "root-p" } }
        ]
    });
    let tally = proven_per_leg_column(&ledger);
    assert_eq!(
        tally.get(&("root-p".to_string(), "p-client".to_string())),
        Some(&2)
    );
    assert_eq!(
        tally.get(&("root-p".to_string(), "p-server".to_string())),
        None,
        "the server column has no root proof, whatever its leg proves on the client column"
    );
}

/// I1 / floor guard: the reflected hook set and the doctrine constants cannot silently shrink.
#[test]
fn the_reflected_hook_set_and_constants_are_the_doctrine() {
    assert!(
        HOOK_FIELDS.len() >= MIN_HOOK_FIELDS,
        "the reflected hook set shrank below the floor"
    );
    const {
        assert!(MIN_HOOK_FIELDS >= 15);
    }
    // The doctrine's installed-plane axis, verbatim: EMPTY. P3 DEL-MCP (ARCHITECT 2026-10-05) and the
    // door flips after it each took a plane off it, and the deletion of the model plane's retired
    // engine crate (DEV-GREEN row 83, coordinator ruling 2026-10-18) took the last: every plane is
    // served through its memory-ABI door alone and installs no PlaneDecl from a linked entry.
    let keys: Vec<&str> = plane_ledger_columns().iter().map(|(k, _)| *k).collect();
    assert!(
        keys.is_empty(),
        "the installed-plane axis is the owner's ruling; changing it is a doctrine change: {keys:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. SELF-TEST: the gate is proven to FIRE, on fixtures, through the REAL `verify`.
//    House rule: a gate that cannot fail is worse than none.
// ---------------------------------------------------------------------------

/// A tiny fixture: 15 hook fields (to clear the floor) over 2 planes, exactly one asymmetric None
/// (`h0`: p_a Some, p_b None). A minimal ledger declaring the referenced capability for both planes'
/// columns, and an allowlist that (by default) accounts for the one asymmetry.
fn fixtures() -> (
    Matrix,
    serde_json::Value,
    serde_json::Value,
    BTreeMap<&'static str, &'static [&'static str]>,
) {
    let mut matrix: Matrix = BTreeMap::new();
    for i in 0..15 {
        let mut row = BTreeMap::new();
        // h0 is the only asymmetry: p_a=Some, p_b=None. Every other hook is symmetric (both Some).
        let (a, b) = if i == 0 { (true, false) } else { (true, true) };
        row.insert("p_a".to_string(), a);
        row.insert("p_b".to_string(), b);
        matrix.insert(format!("h{i}"), row);
    }
    let ledger = serde_json::json!({
        "capabilities": { "cap-x": "a fixture capability defined at argument length for the test" },
        "planes": { "pa-col": "fixture", "pb-col": "fixture" },
        "cells": [
            { "capability": "cap-x", "plane": "pa-col", "state": "proven", "test": "x" },
            { "capability": "cap-x", "plane": "pb-col", "state": "missing" }
        ]
    });
    let allow = serde_json::json!({
        "asymmetries": [
            { "field": "h0", "planes_none": ["p_b"], "capability": "cap-x",
              "reason": "a fixture argument long enough to be an actual reviewable argument here" }
        ]
    });
    let mut columns: BTreeMap<&'static str, &'static [&'static str]> = BTreeMap::new();
    columns.insert("p_a", &["pa-col"]);
    columns.insert("p_b", &["pb-col"]);
    (matrix, ledger, allow, columns)
}

#[test]
fn selftest_green_fixture_passes_and_counts_the_one_asymmetry() {
    let (m, ledger, allow, cols) = fixtures();
    let s = verify(&m, &ledger, &allow, &cols, 15, 1).expect("the green fixture verifies");
    assert_eq!(s.asymmetric_nones.len(), 1);
    assert_eq!(s.declared, 1);
}

#[test]
fn selftest_undeclared_asymmetric_none_is_red() {
    // Drop the only allowlist row: the h0/p_b asymmetry is now undeclared → RED.
    let (m, ledger, mut allow, cols) = fixtures();
    allow["asymmetries"] = serde_json::json!([]);
    let err = verify(&m, &ledger, &allow, &cols, 15, 0)
        .expect_err("an undeclared asymmetric None must be red");
    assert!(
        err.contains("UNDECLARED") && err.contains("h0×p_b"),
        "got: {err}"
    );
}

/// PART OF THE ROSTER LINKED: a row whose `Some` sibling is not linked is unobservable, not stale —
/// while a row whose own plane now FILLS the hook is still RED. The whole-roster verdict on the same
/// matrix stays exact.
#[test]
fn selftest_a_partial_roster_scopes_staleness_to_what_it_can_observe() {
    let (full, ledger, allow, cols) = fixtures();
    // Only `p_b` linked: its `h0` None has no linked `Some` sibling to be asymmetric against.
    let mut part: Matrix = BTreeMap::new();
    for (field, row) in &full {
        let mut r = BTreeMap::new();
        r.insert("p_b".to_string(), row["p_b"]);
        part.insert(field.clone(), r);
    }
    verify_scoped(&part, &ledger, &allow, &cols, 15, 1, false)
        .expect("a row whose sibling is not linked is unobservable in a partial build, not stale");
    let err = verify_scoped(&part, &ledger, &allow, &cols, 15, 1, true)
        .expect_err("with the whole roster claimed, the same row is stale");
    assert!(
        err.contains("STALE") && err.contains("h0×p_b"),
        "got: {err}"
    );
    // A row declaring `p_b` None on a hook `p_b` FILLS is stale in any build.
    let mut allow_filled = allow.clone();
    allow_filled["asymmetries"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "field": "h1", "planes_none": ["p_b"], "capability": "cap-x",
            "reason": "a fixture argument long enough to be an actual reviewable argument here"
        }));
    let err = verify_scoped(&part, &ledger, &allow_filled, &cols, 15, 1, false).expect_err(
        "a plane that fills the hook it is declared None on is stale in a partial build",
    );
    assert!(
        err.contains("STALE") && err.contains("h1×p_b"),
        "got: {err}"
    );
}

#[test]
fn selftest_stale_allowlist_row_is_red() {
    // Declare an asymmetry that does not exist (h1 is symmetric) → stale row → RED.
    let (m, ledger, mut allow, cols) = fixtures();
    allow["asymmetries"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "field": "h1", "planes_none": ["p_b"], "capability": "cap-x",
            "reason": "a fixture argument long enough to be an actual reviewable argument here"
        }));
    let err =
        verify(&m, &ledger, &allow, &cols, 15, 1).expect_err("a stale allowlist row must be red");
    assert!(
        err.contains("STALE") && err.contains("h1×p_b"),
        "got: {err}"
    );
}

#[test]
fn selftest_asymmetry_mapping_to_no_ledger_cell_is_red() {
    // Point the row at a capability the ledger does not declare → the asymmetry maps to no cell → RED.
    let (m, ledger, mut allow, cols) = fixtures();
    allow["asymmetries"][0]["capability"] = "cap-absent".into();
    let err = verify(&m, &ledger, &allow, &cols, 15, 1)
        .expect_err("an asymmetry mapping to a non-existent capability must be red");
    assert!(
        err.contains("not declared in qa/capability-equality.json"),
        "got: {err}"
    );
}

#[test]
fn selftest_a_token_reason_is_red() {
    let (m, ledger, mut allow, cols) = fixtures();
    allow["asymmetries"][0]["reason"] = "n/a".into();
    let err = verify(&m, &ledger, &allow, &cols, 15, 1).expect_err("a token reason must be red");
    assert!(err.contains("real"), "got: {err}");
}
