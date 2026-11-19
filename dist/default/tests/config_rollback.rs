// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `POST /api/v1/admin/config/rollback` on the real binary (docs/admin-api.md): a retained
//! version's hook surface is restored as a NEW version, re-validated against current reality and
//! audited like any other config mutation; an unknown version is `404` and a target that no
//! longer validates is `400`, both audited as rejected and both leaving the running config as it
//! was.

#![cfg(unix)]
#![cfg(linked_section_pools)]

mod common;
mod e2e_support;

use e2e_support::{closed_port, Deployment, Node, WEBREQUEST_HOOK_IMAGE};
use serde_json::{json, Value};

/// The `hooks:` definition map: one never-attached gate per name, asking nobody.
fn hooks(names: &[&str]) -> String {
    let target = format!("http://127.0.0.1:{}/decide", closed_port());
    let mut yaml = String::from("hooks:\n");
    for name in names {
        yaml.push_str(&format!(
            "  {name}:\n    module: webrequest\n    kind: gate\n    prompt: ro\n    \
             timeout_ms: 2000\n    on_error: reject\n    settings: {{ url: \"{target}\" }}\n"
        ));
    }
    yaml
}

/// The pool `e2e` over `test-model`, attaching `attached` when given.
fn pools(attached: Option<&str>) -> String {
    let mut yaml = String::from("pools:\n  e2e:\n    members:\n      - { model: test-model }\n");
    if let Some(hook) = attached {
        yaml.push_str(&format!("    hooks: [{hook}]\n"));
    }
    yaml
}

/// Replace the tail of the node's `config.yaml` and reload it: one new version from disk.
fn reload_onto(node: &Node, old_tail: &str, new_tail: &str) -> u64 {
    let path = node.config_path();
    let text = std::fs::read_to_string(&path).expect("read config.yaml");
    assert!(
        text.ends_with(old_tail),
        "config.yaml ends with the sections this test wrote: {text}"
    );
    let rewritten = format!("{}{new_tail}", &text[..text.len() - old_tail.len()]);
    std::fs::write(&path, rewritten).expect("rewrite config.yaml");
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

/// The `config.rollback` audit rows naming `resource`, newest first: their outcomes.
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

fn rollback(node: &Node, version: u64) -> e2e_support::Reply {
    node.operator(
        "POST",
        "/api/v1/admin/config/rollback",
        Some(&json!({ "version": version })),
    )
}

fn version_of(reply: &e2e_support::Reply, field: &str) -> u64 {
    let body: Value = reply.json();
    body[field]
        .as_u64()
        .unwrap_or_else(|| panic!("the answer states `{field}`: {body}"))
}

#[test]
fn config_rollback_restores_a_retained_version_and_refuses_unknown_or_invalid_targets() {
    let boot_tail = format!("{}{}", hooks(&["first"]), pools(None));
    let node = Deployment::new("config-rollback")
        .provider(
            "mock",
            "openai",
            &format!("http://127.0.0.1:{}", closed_port()),
        )
        .section("models:\n  test-model:\n    provider: mock\n")
        .plugin("hook", WEBREQUEST_HOOK_IMAGE)
        .section(&boot_tail)
        .boot();
    assert_eq!(running_hooks(&node), ["first"], "v0 serves its own hooks");

    // v1: the hook surface moves on.
    let v1_tail = format!("{}{}", hooks(&["second"]), pools(None));
    let v1 = reload_onto(&node, &boot_tail, &v1_tail);
    assert_eq!(v1, 1, "the first reload is version 1");
    assert_eq!(running_hooks(&node), ["second"], "v1 serves its own hooks");

    // Roll back to the boot version: a NEW version serving v0's hook surface, audited.
    let restored = rollback(&node, 0);
    assert_eq!(
        restored.status,
        200,
        "a retained version is restored: {}",
        restored.text()
    );
    assert_eq!(version_of(&restored, "restored_version"), 0);
    let v2 = version_of(&restored, "config_version");
    assert_eq!(v2, 2, "a rollback is a new version; history is append-only");
    assert_eq!(
        running_hooks(&node),
        ["first"],
        "the running config is the restored version's"
    );
    assert_eq!(
        rollback_audit(&node, "config:v0"),
        ["applied"],
        "the rollback is audited as applied"
    );
    let versions = node.operator("GET", "/api/v1/admin/config/versions", None);
    assert_eq!(versions.status, 200, "{}", versions.text());
    assert!(
        versions.text().contains("config.rollback to v0"),
        "the rollback is recorded in the version history: {}",
        versions.text()
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
        ["first"],
        "a refused rollback changes nothing"
    );

    // v3: the disk config attaches `second` to the pool. Restoring v2's surface (`first` only)
    // would leave the pool naming a hook that no longer exists: re-validation refuses it.
    let v3_tail = format!("{}{}", hooks(&["second"]), pools(Some("second")));
    let v3 = reload_onto(&node, &v1_tail, &v3_tail);
    assert_eq!(v3, 3);
    let invalid = rollback(&node, 2);
    assert_eq!(
        invalid.status,
        400,
        "a target that no longer validates is refused: {}",
        invalid.text()
    );
    assert_eq!(rollback_audit(&node, "config:v2"), ["rejected"]);
    assert_eq!(
        running_hooks(&node),
        ["second"],
        "a refused rollback leaves the running config as it was"
    );
    let info = node.operator("GET", "/api/v1/admin/config/versions", None);
    assert!(
        !info.text().contains("config.rollback to v2"),
        "a refused rollback records no version: {}",
        info.text()
    );
}
