// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `POST /api/v1/admin/config/rollback` on the real binary (docs/admin-api.md): a retained
//! version's hook surface is restored as a NEW version, re-validated against current reality and
//! audited like any other config mutation; an unknown version is `404`, audited as rejected,
//! leaving the running config as it was.

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;
mod e2e_support;

use e2e_support::{closed_port, Deployment, Node, Reply};
use serde_json::json;

/// The running hook surface: each hook's name and `timeout_ms`, sorted by name.
fn running_hooks(node: &Node) -> Vec<(String, u64)> {
    let reply = node.operator("GET", "/api/v1/admin/hooks", None);
    assert_eq!(reply.status, 200, "the hooks read: {}", reply.text());
    let mut hooks: Vec<(String, u64)> = reply.json()["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a hooks page has items: {}", reply.text()))
        .iter()
        .map(|hook| {
            (
                hook["name"].as_str().expect("a hook has a name").to_owned(),
                hook["timeout_ms"].as_u64().expect("a hook has a timeout"),
            )
        })
        .collect();
    hooks.sort();
    hooks
}

/// The outcomes of the `config.rollback` audit rows naming `resource`, newest first.
fn rollback_audit(node: &Node, resource: &str) -> Vec<String> {
    let reply = node.operator(
        "GET",
        &format!("/api/v1/admin/audit?action=config.rollback&resource={resource}"),
        None,
    );
    assert_eq!(reply.status, 200, "the audit read: {}", reply.text());
    reply.json()["items"]
        .as_array()
        .unwrap_or_else(|| panic!("an audit page has items: {}", reply.text()))
        .iter()
        .map(|row| {
            row["outcome"]
                .as_str()
                .expect("an audit row has an outcome")
                .to_owned()
        })
        .collect()
}

fn rollback(node: &Node, version: u64) -> Reply {
    node.operator(
        "POST",
        "/api/v1/admin/config/rollback",
        Some(&json!({ "version": version })),
    )
}

fn version_of(reply: &Reply, field: &str) -> u64 {
    let body = reply.json();
    body[field]
        .as_u64()
        .unwrap_or_else(|| panic!("the answer states `{field}`: {body}"))
}

#[test]
fn config_rollback_restores_a_retained_version_and_refuses_an_unknown_one() {
    // No hooks: at this head a node defining any webrequest hook refuses to boot (BUSBAR-9007
    // "reserved hook lost its admitted descriptor", NEEDS.tsv E-ROLLBACK), so the restored hook
    // surface is the empty one; the version, history and audit facts are asserted in full.
    let node = Deployment::new("config-rollback")
        .provider(
            "mock",
            "openai",
            &format!("http://127.0.0.1:{}", closed_port()),
        )
        .section("models:\n  test-model:\n    provider: mock\n")
        .section("pools:\n  e2e:\n    members:\n      - { model: test-model }\n")
        .boot();
    let v0: Vec<(String, u64)> = Vec::new();
    assert_eq!(running_hooks(&node), v0, "v0's hook surface");

    // v1: a reload from disk.
    let reply = node.operator("POST", "/api/v1/admin/config/reload", None);
    assert_eq!(reply.status, 200, "the reload applies: {}", reply.text());
    assert_eq!(version_of(&reply, "config_version"), 1);

    // Roll back to the boot version: a NEW version serving v0's hook surface, audited.
    let restored = rollback(&node, 0);
    assert_eq!(
        restored.status,
        200,
        "a retained version is restored: {}",
        restored.text()
    );
    assert_eq!(version_of(&restored, "restored_version"), 0);
    assert_eq!(
        version_of(&restored, "config_version"),
        2,
        "a rollback is a new version; history is append-only"
    );
    assert_eq!(
        running_hooks(&node),
        v0,
        "the running config serves the restored version's hook surface"
    );
    assert_eq!(
        rollback_audit(&node, "config:v0"),
        ["applied"],
        "the rollback is audited as applied"
    );
    let history = node.operator("GET", "/api/v1/admin/config/versions", None);
    assert_eq!(history.status, 200, "{}", history.text());
    assert!(
        history.text().contains("config.rollback to v0"),
        "the rollback is recorded in the version history: {}",
        history.text()
    );

    // A version this process never recorded is refused, audited, and changes nothing.
    let unknown = rollback(&node, 424_242);
    assert_eq!(
        unknown.status,
        404,
        "an unknown version: {}",
        unknown.text()
    );
    assert_eq!(rollback_audit(&node, "config:v424242"), ["rejected"]);
    let after = node.operator("GET", "/api/v1/admin/config/versions", None);
    assert!(
        !after.text().contains("config.rollback to v424242"),
        "a refused rollback records no version: {}",
        after.text()
    );
}
