// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The trust surface's derivations: the digest, the observation, the state, the changes queue and
//! the views.

use serde_json::json;

use super::*;

fn def(doc: Value) -> McpServerDefCfg {
    serde_json::from_value(doc).expect("a registration")
}

fn schema() -> Value {
    json!({ "type": "object", "properties": { "path": { "type": "string" } } })
}

fn rooted(hash: &str) -> McpServerDefCfg {
    def(json!({
        "url": "https://fs.example/rpc",
        "pin": { "mechanism": "pinned_pubkey", "key": "sha256/K=" },
        "tools_allow": { "read": { "schema_hash": hash }, "write": {} }
    }))
}

fn seen(tools: Value) -> Sighting {
    Sighting::Seen(observe(&json!({ "tools": tools })).expect("a tool list"))
}

/// The digest frames its three parts and reads the schema canonically: key order is not drift, a
/// changed description or schema is.
#[test]
fn the_digest_frames_its_parts_and_reads_the_schema_canonically() {
    let a = tool_digest("read", "reads", &json!({"a": 1, "b": [true, null]}));
    let b = tool_digest("read", "reads", &json!({"b": [true, null], "a": 1}));
    assert_eq!(a, b, "key order is not drift");
    assert!(a.starts_with("sha256:") && a.len() == 7 + 64, "{a}");
    assert_ne!(
        a,
        tool_digest("read", "reads!", &json!({"a": 1, "b": [true, null]}))
    );
    assert_ne!(
        a,
        tool_digest("rea", "dreads", &json!({"a": 1, "b": [true, null]}))
    );
    assert_eq!(
        canonical_json(&json!({"z": {"y": 1, "x": "q\""}, "a": []})),
        r#"{"a":[],"z":{"x":"q\"","y":1}}"#
    );
}

/// A tool list is strict about names and defaults the optional fields, which are hashed at their
/// default.
#[test]
fn an_observation_is_read_strictly() {
    assert!(observe(&json!({})).is_err());
    assert!(observe(&json!({ "tools": [ { "description": "x" } ] })).is_err());
    assert!(observe(&json!({ "tools": [ { "name": " " } ] })).is_err());
    let obs = observe(&json!({ "tools": [ { "name": "read" } ] })).unwrap();
    assert_eq!(
        obs.capabilities["read"],
        tool_digest("read", "", &json!({}))
    );
}

/// The state, in precedence order, and the changes queue on each axis.
#[test]
fn the_state_is_derived_from_the_approval_and_the_last_sighting() {
    let digest = tool_digest("read", "reads a file", &schema());
    let def = rooted(&digest);
    assert_eq!(
        state(&Approval::of(&def), &Sighting::Never),
        State::Approved
    );
    let good =
        seen(json!([{ "name": "read", "description": "reads a file", "inputSchema": schema() }]));
    assert_eq!(state(&Approval::of(&def), &good), State::Approved);
    let pulled = seen(json!([
        { "name": "read", "description": "reads a file", "inputSchema": { "type": "object" } },
        { "name": "extra" }
    ]));
    assert_eq!(state(&Approval::of(&def), &pulled), State::Quarantined);
    let d = drift(&Approval::of(&def), &pulled);
    assert_eq!(
        (d.changed, d.added, d.removed),
        (vec!["read".to_string()], vec!["extra".to_string()], vec![])
    );
    let failed = Sighting::Failed("down".to_string());
    assert_eq!(state(&Approval::of(&def), &failed), State::Error);
    let unpinned = def_unpinned();
    assert_eq!(state(&Approval::of(&unpinned), &good), State::Pending);
}

fn def_unpinned() -> McpServerDefCfg {
    def(json!({
        "url": "https://fs.example/rpc",
        "pin": { "mechanism": "unpinned" },
        "tools_allow": { "read": { "schema_hash": "sha256:aa" } }
    }))
}

/// The views name every field the served engine's did, in its order.
#[test]
fn the_views_render_the_served_engines_fields_in_its_order() {
    let digest = tool_digest("read", "reads a file", &schema());
    let def = rooted(&digest);
    let good =
        seen(json!([{ "name": "read", "description": "reads a file", "inputSchema": schema() }]));
    let view: Value = serde_json::from_str(&trust_view("fs", &def, &good)).unwrap();
    assert_eq!(
        view,
        json!({
            "name": "fs", "state": "approved", "pin_mechanism": "pinned_pubkey",
            "pin_changed": false, "added": [], "changed": [], "removed": [],
            "observed_tools": 1, "failure": null,
            "capabilities": [
                { "tool": "read", "status": "approved", "approved_digest": digest },
                { "tool": "write", "status": "pending", "approved_digest": null }
            ]
        })
    );
    assert!(trust_view("fs", &def, &good).starts_with(r#"{"name":"fs","state":"approved","#));
    let health: Value = serde_json::from_str(&health_view("fs", &def, &Sighting::Never)).unwrap();
    assert_eq!(
        health,
        json!({ "name": "fs", "state": "approved", "serving": true, "contacted": false,
                "failure": null, "observed_tools": 0 })
    );
    assert_ne!(catalogue_hash(&Observation::default()), "");
}
