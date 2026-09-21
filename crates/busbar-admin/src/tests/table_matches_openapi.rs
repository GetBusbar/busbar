// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The derivation artifact: proves [`crate::verb::LEGACY_VERBS`] matches
//! `testing/shadow-oracle/fixtures/openapi-1.5.5.json` byte-for-byte — same 49 paths, same 66
//! operations, same required scope for each (PB-62). Fails the build (not just the test) intent:
//! an operation missing from the table, an extra operation in the table, or a scope disagreement
//! are each a distinct assertion failure naming the offending path+method, so a drift is never
//! reported as a single opaque "mismatch".
//!
//! `serde_json` is a dev-dependency ONLY for this file — see the crate-level doc.

use crate::verb::{LegacyVerbRow, VerbScope, LEGACY_VERBS};
use std::collections::BTreeSet;

const FIXTURE: &str = include_str!("../../../../testing/shadow-oracle/fixtures/openapi-1.5.5.json");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FixtureOp {
    method: String,
    path: String,
    scope: String,
    operation_id: String,
}

/// The operations the COMMITTED fixture names, with the scope the fixture itself carries.
///
/// The scope is READ OUT of `x-busbar-required-scope`, not recomputed here. It used to be derived
/// by a hand-transcribed second copy of `verb::scope_for`'s rule — which meant the comparison below
/// ran rule-copy-A against rule-copy-B and could not see a disagreement between the table and the
/// artifact it is derived from. A corrected fixture row (say `plugins/inspect` becoming `full`)
/// was then invisible: the test recomputed `read-only`, matched the table's `read-only`, and passed
/// while the shipped table served a mutating POST to a read-only credential.
fn fixture_ops() -> Vec<FixtureOp> {
    let doc: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let paths = doc["paths"]
        .as_object()
        .expect("fixture has a paths object");
    let mut ops = Vec::new();
    for (path, methods) in paths {
        let methods = methods.as_object().expect("each path is a method map");
        for (method, op) in methods {
            let m = method.to_uppercase();
            if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&m.as_str()) {
                continue;
            }
            let scope = op["x-busbar-required-scope"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "the fixture operation {m} {path} carries no `x-busbar-required-scope`; \
                         the scope is read from the artifact, never inferred"
                    )
                })
                .to_string();
            let operation_id = op["operationId"]
                .as_str()
                .unwrap_or_else(|| {
                    panic!(
                        "the fixture operation {m} {path} carries no `operationId`; the id is \
                         read from the artifact, never inferred"
                    )
                })
                .to_string();
            ops.push(FixtureOp {
                method: m,
                path: path.clone(),
                scope,
                operation_id,
            });
        }
    }
    ops
}

fn table_ops() -> Vec<FixtureOp> {
    LEGACY_VERBS
        .iter()
        .map(|r: &LegacyVerbRow| FixtureOp {
            method: r.method.to_string(),
            path: r.path.to_string(),
            scope: r.scope.as_str().to_string(),
            operation_id: r.operation_id.to_string(),
        })
        .collect()
}

/// Every fixture operation declares a scope, and it is one of the two the table can express.
///
/// Stated separately so that a fixture row losing the key, or growing a third spelling, is reported
/// as what it is rather than as a mismatch against the table.
#[test]
fn every_fixture_operation_declares_a_scope_the_table_can_express() {
    let ops = fixture_ops();
    assert_eq!(ops.len(), 66, "the loop has to have something to check");
    for op in &ops {
        assert!(
            op.scope == "read-only" || op.scope == "full",
            "{} {} declares an unknown scope `{}`",
            op.method,
            op.path,
            op.scope
        );
    }
    // Both scopes are actually present, so a fixture that collapsed to one value everywhere — which
    // would make the comparison below pass against an equally collapsed table — is caught here.
    assert!(ops.iter().any(|o| o.scope == "read-only"));
    assert!(ops.iter().any(|o| o.scope == "full"));
}

#[test]
fn fixture_has_49_paths_and_66_operations() {
    let doc: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
    let paths = doc["paths"].as_object().unwrap();
    assert_eq!(paths.len(), 49, "the architecture document pins 49 paths");
    assert_eq!(
        fixture_ops().len(),
        66,
        "the architecture document pins 66 operations"
    );
}

#[test]
fn table_has_no_more_and_no_fewer_rows_than_the_fixture() {
    assert_eq!(
        LEGACY_VERBS.len(),
        66,
        "LEGACY_VERBS must carry exactly the 66 mechanically-derived operations"
    );
}

#[test]
fn every_fixture_operation_is_in_the_table_with_the_same_scope() {
    let fixture: BTreeSet<_> = fixture_ops().into_iter().collect();
    let table: BTreeSet<_> = table_ops().into_iter().collect();

    let missing: Vec<_> = fixture.difference(&table).collect();
    assert!(
        missing.is_empty(),
        "openapi-1.5.5.json names an operation the table is missing (or whose scope the table \
         gets wrong): {missing:?}"
    );
    let extra: Vec<_> = table.difference(&fixture).collect();
    assert!(
        extra.is_empty(),
        "the table names an operation (or a scope) not in openapi-1.5.5.json: {extra:?}"
    );
}

/// `verb.rs:74-76` justifies carrying `operation_id` at all as existing "so the conformance test
/// can report a mismatch by the name an operator would recognise" — but nothing compared it to the
/// fixture's `operationId` before this. `every_fixture_operation_is_in_the_table_with_the_same_
/// scope`'s set-diff now also catches a divergent id (it is part of `FixtureOp`), but reports it as
/// a whole row missing/extra on both sides; this case is the one that reports it BY NAME, keyed on
/// (method, path), which is the property the field was added for.
#[test]
fn every_operations_id_matches_the_fixtures_operation_id() {
    let fixture: std::collections::BTreeMap<(String, String), String> = fixture_ops()
        .into_iter()
        .map(|op| ((op.method, op.path), op.operation_id))
        .collect();
    for row in LEGACY_VERBS {
        let key = (row.method.to_string(), row.path.to_string());
        let expected = fixture
            .get(&key)
            .unwrap_or_else(|| panic!("{} {} is in the table but not the fixture", key.0, key.1));
        assert_eq!(
            row.operation_id, expected,
            "{} {}: the table's operation_id must match the fixture's operationId",
            key.0, key.1
        );
    }
}

#[test]
fn no_duplicate_operation_ids_in_the_table() {
    let mut ids: Vec<_> = LEGACY_VERBS.iter().map(|r| r.operation_id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(
        before,
        ids.len(),
        "every legacy operation id must be unique"
    );
}

/// The dry-run carve-out is not hand-transcribed a second time anywhere this test can reach: the
/// set asserted here is DERIVED from `LEGACY_VERBS` itself (method `POST` and scope `ReadOnly`),
/// then checked against the fixture's own column, so the two can never silently drift out of step
/// the way a second literal copy of the same two paths could.
#[test]
fn table_derived_read_only_post_paths_match_the_fixture_column() {
    let table_read_only_posts: BTreeSet<&str> = LEGACY_VERBS
        .iter()
        .filter(|r| r.method == "POST" && r.scope == VerbScope::ReadOnly)
        .map(|r| r.path)
        .collect();

    let fixture_read_only_posts: BTreeSet<String> = fixture_ops()
        .into_iter()
        .filter(|op| op.method == "POST" && op.scope == "read-only")
        .map(|op| op.path)
        .collect();
    let fixture_read_only_posts: BTreeSet<&str> =
        fixture_read_only_posts.iter().map(String::as_str).collect();

    assert_eq!(
        table_read_only_posts, fixture_read_only_posts,
        "the table's read-only POST paths, derived from LEGACY_VERBS, must be exactly the \
         fixture's dry-run carve-out"
    );
    assert_eq!(
        table_read_only_posts.len(),
        2,
        "1.5.5 names exactly two stateless dry-run POSTs"
    );
}

#[test]
fn scope_split_is_34_read_only_32_full() {
    let read_only = LEGACY_VERBS
        .iter()
        .filter(|r| r.scope == VerbScope::ReadOnly)
        .count();
    let full = LEGACY_VERBS
        .iter()
        .filter(|r| r.scope == VerbScope::Full)
        .count();
    assert_eq!(
        read_only, 34,
        "34 read-only operations, per the architecture document"
    );
    assert_eq!(
        full, 32,
        "32 full operations, per the architecture document"
    );
}
