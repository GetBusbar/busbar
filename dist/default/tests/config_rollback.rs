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

use e2e_support::{closed_port, Deployment, Node, Reply, WEBREQUEST_HOOK_IMAGE};
use serde_json::json;

/// One gate definition asking nobody (it is never asked: no request is sent).
fn gate(name: &str, target: &str) -> String {
    format!(
        "  {name}:\n    module: webrequest\n    kind: gate\n    prompt: ro\n    \
         timeout_ms: 2000\n    on_error: reject\n    settings: {{ url: \"{target}\" }}\n"
    )
}

/// Rename a hook everywhere in the node's `config.yaml` (its definition and any attachment; the
/// boot may have rewritten the file into the 1.6 shape) and reload it: one new version from disk.
fn reload_renaming(node: &Node, from: &str, to: &str) -> u64 {
    let path = node.config_path();
    let text = std::fs::read_to_string(&path).expect("read config.yaml");
    assert!(text.contains(from), "config.yaml names `{from}`: {text}");
    std::fs::write(&path, text.replace(from, to)).expect("rewrite config.yaml");
    let reply = node.operator("POST", "/api/v1/admin/config/reload", None);
    assert_eq!(reply.status, 200, "the reload applies: {}", reply.text());
    reply.json()["config_version"]
        .as_u64()
        .unwrap_or_else(|| panic!("a reload states its version: {}", reply.text()))
}

/// The hook names the running config serves, sorted.
fn running_hooks(node: &Node) -> Vec<String> {
    let reply = node.operator("GET", "/api/v1/admin/hooks", None);
    assert_eq!(reply.status, 200, "the hooks read: {}", reply.text());
    let mut names: Vec<String> = reply.json()["items"]
        .as_array()
        .unwrap_or_else(|| panic!("a hooks page has items: {}", reply.text()))
        .iter()
        .map(|hook| hook["name"].as_str().expect("a hook has a name").to_owned())
        .collect();
    names.sort();
    names
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

fn history(node: &Node) -> String {
    let versions = node.operator("GET", "/api/v1/admin/config/versions", None);
    assert_eq!(versions.status, 200, "{}", versions.text());
    versions.text()
}

#[test]
fn config_rollback_restores_a_retained_version_and_refuses_an_unknown_one() {
    let target = format!("http://127.0.0.1:{}/decide", closed_port());
    let node = Deployment::new("config-rollback")
        .provider(
            "mock",
            "openai",
            &format!("http://127.0.0.1:{}", closed_port()),
        )
        .section("models:\n  test-model:\n    provider: mock\n")
        .plugin("hook", WEBREQUEST_HOOK_IMAGE)
        .section(&format!(
            "hooks:\n{}{}",
            gate("rbalpha", &target),
            gate("rbkeep", &target)
        ))
        .section("pools:\n  e2e:\n    members:\n      - { model: test-model }\n")
        .boot();
    assert_eq!(running_hooks(&node), ["rbalpha", "rbkeep"], "v0's hooks");

    // v1: the unattached hook is renamed on disk and reloaded.
    assert_eq!(reload_renaming(&node, "rbalpha", "rbbeta"), 1);
    assert_eq!(running_hooks(&node), ["rbbeta", "rbkeep"], "v1's hooks");

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
        ["rbalpha", "rbkeep"],
        "the running config serves the restored version's hooks"
    );
    assert_eq!(
        rollback_audit(&node, "config:v0"),
        ["applied"],
        "the rollback is audited as applied"
    );
    assert!(
        history(&node).contains("config.rollback to v0"),
        "the rollback is recorded in the version history"
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
    assert_eq!(
        running_hooks(&node),
        ["rbalpha", "rbkeep"],
        "a refused rollback changes nothing"
    );
}
