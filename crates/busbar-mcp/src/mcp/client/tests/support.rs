// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared fixtures for the MCP client tests.
//!
//! One place to build a caller, a server registration and a tool, so a test that means to vary ONE
//! thing varies one thing. The alternative — each test hand-building a `VirtualKey` — is how two
//! tests end up asserting the same property against two different principals and nobody notices
//! that one of them was a wildcard.

use crate::mcp::client::catalogue::{ServerCatalogue, ToolDef, TransportPin};
use crate::mcp::client::identity::{ServerId, ToolKey};
use busbar_api::{ScopeRef, VirtualKey};

/// A server id that is known-good, so a test asserting something else does not fail on a name.
pub(super) fn sid(id: &str) -> ServerId {
    ServerId::new(id).expect("test server id must be valid")
}

pub(super) fn tkey(server: &str, tool: &str) -> ToolKey {
    ToolKey::new(sid(server), tool).expect("test tool key must be valid")
}

/// A tool definition with a controllable description and schema.
pub(super) fn tool(name: &str, description: &str, schema: serde_json::Value) -> ToolDef {
    ToolDef {
        name: name.to_string(),
        description: description.to_string(),
        input_schema: schema,
    }
}

/// A plain one-string-argument tool.
pub(super) fn simple_tool(name: &str, description: &str) -> ToolDef {
    tool(
        name,
        description,
        serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}}),
    )
}

/// A key with an EXPLICIT scope list. `allowed_scopes: Some(..)` is exhaustive across kinds, so this
/// is the shape every grant-sensitive test wants: what is not listed is not granted.
pub(super) fn key_with_scopes(id: &str, scopes: Vec<ScopeRef>) -> VirtualKey {
    let mut k = key_wildcard(id);
    k.allowed_scopes = Some(scopes);
    k
}

/// A key with NO scope restriction. `None` means every scope of every kind — the most permissive
/// principal the store can express, and therefore the one an adversarial test should use when it
/// wants the GRANT not to be the reason something was refused.
pub(super) fn key_wildcard(id: &str) -> VirtualKey {
    VirtualKey {
        id: id.to_string(),
        generation_hash: String::new(),
        name: id.to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: None,
        labels: std::collections::BTreeMap::new(),
        expires_at: None,
        deleted_at: None,
        revision: 0,
        ..Default::default()
    }
}

/// A server catalogue that is APPROVED and serving `tools`, with `pin` locked.
///
/// Built by driving the REAL lifecycle (`observe` then `approve`) rather than by constructing an
/// approved state directly. A fixture that fabricates the end state is a fixture that can disagree
/// with the machine it is standing in for, and the drift tests below are precisely about that
/// machine.
pub(super) fn approved_server(id: &str, tools: Vec<ToolDef>) -> ServerCatalogue {
    let mut sc = ServerCatalogue::registered(sid(id));
    let pin = TransportPin::cert_spki(&format!("sha256/{id}-pin"));
    sc.observe(Some(pin), tools);
    sc.approval
        .approve(&sc.sighting, None)
        .expect("approve captured pin");
    sc
}
