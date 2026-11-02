// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::verb::{VerbRow, VerbScope, LEGACY_VERBS};
use std::collections::BTreeSet;

const FIXTURE: &str = include_str!("../../../../testing/shadow-oracle/fixtures/openapi-1.5.5.json");

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FixtureOp {
    method: String,
    path: String,
    scope: String,
}

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
        .map(|r: &VerbRow| FixtureOp {
            method: r.method.to_string(),
            path: r.path.to_string(),
            scope: r.scope.as_str().to_string(),
        })
        .collect()
}

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
