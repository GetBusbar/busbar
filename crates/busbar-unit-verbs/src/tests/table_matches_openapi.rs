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
    scope: &'static str,
}

fn fixture_ops() -> Vec<FixtureOp> {
    let doc: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture is valid JSON");
    let paths = doc["paths"].as_object().expect("fixture has a paths object");
    let mut ops = Vec::new();
    for (path, methods) in paths {
        let methods = methods.as_object().expect("each path is a method map");
        for (method, _op) in methods {
            let m = method.to_uppercase();
            if !["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&m.as_str()) {
                continue;
            }
            // Reproduce 1.5.5's `required_scope` exactly: every read is `read-only`; the two
            // stateless dry-run POSTs are `read-only`; everything else is `full`.
            let is_read = m == "GET" || m == "HEAD";
            let is_dry_run_post =
                path == "/api/v1/admin/config/validate" || path == "/api/v1/admin/plugins/inspect";
            let scope = if is_read || is_dry_run_post { "read-only" } else { "full" };
            ops.push(FixtureOp {
                method: m,
                path: path.clone(),
                scope,
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
            scope: r.scope.as_str(),
        })
        .collect()
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

#[test]
fn no_duplicate_operation_ids_in_the_table() {
    let mut ids: Vec<_> = LEGACY_VERBS.iter().map(|r| r.operation_id).collect();
    let before = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(before, ids.len(), "every legacy operation id must be unique");
}

#[test]
fn scope_split_is_34_read_only_32_full() {
    let read_only = LEGACY_VERBS
        .iter()
        .filter(|r| r.scope == VerbScope::ReadOnly)
        .count();
    let full = LEGACY_VERBS.iter().filter(|r| r.scope == VerbScope::Full).count();
    assert_eq!(read_only, 34, "34 read-only operations, per the architecture document");
    assert_eq!(full, 32, "32 full operations, per the architecture document");
}
