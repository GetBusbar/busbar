// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECT / REFRESH PATH itself: what it parses, what it records, what it refuses, and the
//! approval round trip that keeps an operator's decision from evaporating at the next config apply.
//!
//! The end-to-end proof that a drifted schema stops a call lives beside this file in
//! `drift_dispatch_tests.rs`. This one covers the parts that are not visible from there: the wire
//! parse, the failure recording, the credential refusal, and the overlay projection.

use super::connect_support::{approved_hash, mcp_cfg, server_cfg, wire_tool, Peer};
use crate::mcp::client::catalogue::CatalogueCache;
use crate::mcp::connect::{changes, overlay_patch, parse_tool_list, refresh};
use crate::test_support::TestApp;
use std::sync::Arc;

const DESCRIPTION: &str = "reads a file from disk";

fn schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": { "path": { "type": "string" } } })
}

/// The wire parse takes what an MCP server actually sends.
#[test]
fn a_tools_list_result_parses_into_definitions() {
    let parsed = parse_tool_list(&serde_json::json!({
        "tools": [
            { "name": "read", "description": DESCRIPTION, "inputSchema": schema() },
            { "name": "write" },
        ]
    }))
    .expect("a well-formed result parses");
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].name, "read");
    assert_eq!(parsed[0].description, DESCRIPTION);
    // The DEFAULTS go into the identity rather than being excused from it: an upstream that later
    // supplies a description it had omitted has changed the tool, and a parse that treated an absent
    // field as "not part of the identity" would let exactly that change through unnoticed.
    assert_eq!(parsed[1].description, "");
    assert_eq!(parsed[1].input_schema, serde_json::json!({}));
}

/// A result that is not a tool list is REFUSED rather than adopted as an empty one. Adopting it
/// would be `removed` drift for every approved tool, which reads as an alarm about the upstream when
/// the actual fault is that this was not a tool list at all.
#[test]
fn a_result_that_is_not_a_tool_list_is_refused() {
    assert!(parse_tool_list(&serde_json::json!({ "content": [] })).is_err());
    assert!(
        parse_tool_list(&serde_json::json!({ "tools": [{ "description": "no name" }] })).is_err()
    );
    assert!(parse_tool_list(&serde_json::json!({ "tools": [{ "name": "  " }] })).is_err());
}

/// A REFRESH RECORDS WHAT IT SAW, and the digests it records are re-hashed from the definitions
/// rather than adopted from anything the upstream supplied.
#[tokio::test]
async fn a_refresh_records_the_observation_it_re_hashed() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let cache = Arc::new(CatalogueCache::new());
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server(
            "fs",
            server_cfg(
                &peer,
                &[("read", Some(approved_hash("read", DESCRIPTION, schema())))],
            ),
        )
        .with_mcp_sightings(cache.clone())
        .build();
    let entry = app.mcp_catalogue.server("fs").unwrap().clone();

    let report = refresh(&app.mcp_pool, &cache, &entry).await.unwrap();

    assert_eq!(report.observed, 1);
    assert_eq!(report.failure, None);
    assert_eq!(report.state_word(), "approved");
    assert_eq!(
        peer.methods(),
        vec!["tools/list".to_string()],
        "a refresh asks for a tool list and nothing else"
    );
    // The same facts, read back with no contact at all.
    let derived = changes(&cache, &entry);
    assert_eq!(derived.state, report.state);
    assert!(derived.drift.is_empty());
    assert_eq!(derived.observed, 1);
}

/// AN UNREACHABLE UPSTREAM IS RECORDED AS A FAILURE, not dropped. Leaving the previous observation
/// in place would let a server that stopped answering keep serving on the strength of the last time
/// it did.
#[tokio::test]
async fn a_failed_refresh_is_recorded_and_demotes_the_server() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let cache = Arc::new(CatalogueCache::new());
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server(
            "fs",
            server_cfg(
                &peer,
                &[("read", Some(approved_hash("read", DESCRIPTION, schema())))],
            ),
        )
        .with_mcp_sightings(cache.clone())
        .build();
    let entry = app.mcp_catalogue.server("fs").unwrap().clone();
    refresh(&app.mcp_pool, &cache, &entry).await.unwrap();
    assert_eq!(changes(&cache, &entry).state_word(), "approved");

    peer.fail_list(-32001);
    let report = refresh(&app.mcp_pool, &cache, &entry).await.unwrap();

    assert_eq!(report.state_word(), "error");
    assert!(
        report
            .failure
            .as_deref()
            .unwrap_or_default()
            .contains("-32001"),
        "the operator is told what the upstream said: {report:?}"
    );
    assert_eq!(
        changes(&cache, &entry).state_word(),
        "error",
        "and the failure is what a later read sees, not the successful observation before it"
    );
}

/// `passthrough` REFUSES an operator-driven refresh rather than substituting busbar's own
/// credential. The whole meaning of that mode is that the credential belongs to a caller, and a
/// refresh has no caller.
#[tokio::test]
async fn a_passthrough_server_refuses_an_operator_driven_refresh() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let cache = Arc::new(CatalogueCache::new());
    let mut cfg = server_cfg(
        &peer,
        &[("read", Some(approved_hash("read", DESCRIPTION, schema())))],
    );
    cfg.upstream_credentials = Some(crate::auth::UpstreamCreds::Passthrough);
    let app = TestApp::new()
        .mcp(&mcp_cfg())
        .mcp_server("fs", cfg)
        .with_mcp_sightings(cache.clone())
        .build();
    let entry = app.mcp_catalogue.server("fs").unwrap().clone();

    let refusal = refresh(&app.mcp_pool, &cache, &entry)
        .await
        .expect_err("a passthrough refresh has no caller credential to send");

    assert!(
        refusal.to_string().contains("passthrough"),
        "the refusal names the posture that caused it: {refusal}"
    );
    assert!(
        peer.methods().is_empty(),
        "and it refuses BEFORE any network I/O, so a misconfiguration cannot generate traffic"
    );
}

/// THE ROUND TRIP. An approval projects onto exactly the two config fields the build reads back —
/// `pin.key` and `tools_allow[].schema_hash` — so an approval worked through the changes queue
/// survives the next config apply instead of evaporating.
#[test]
fn an_approval_projects_onto_the_config_fields_the_build_reads_back() {
    use crate::mcp::client::catalogue::TransportPin;
    use crate::trust::{Approval, Observation, Sighting};

    let mut approval: Approval<TransportPin> = Approval::declared(
        TransportPin::declared("cert_spki", "sha256/OLD="),
        Default::default(),
    );
    let observation = Sighting::Seen(Observation {
        pin: Some(TransportPin::declared("cert_spki", "sha256/OLD=")),
        capabilities: [("read".to_string(), "sha256:aaa".to_string())]
            .into_iter()
            .collect(),
    });
    // THE TRANSITIONS ARE THE LIFECYCLE'S. Nothing in the projection decides anything.
    approval.approve(&observation, None).unwrap();
    approval.reject_capability("write");

    let patch = overlay_patch("fs", &approval);

    assert_eq!(
        patch.pointer("/tools/servers/fs/pin/key").unwrap(),
        "sha256/OLD=",
        "the locked pin lands on the field the declared-pin reader reads: {patch}"
    );
    assert_eq!(
        patch
            .pointer("/tools/servers/fs/tools_allow/read/schema_hash")
            .unwrap(),
        "sha256:aaa",
        "the approved digest lands on the field `server_entry` reads: {patch}"
    );
    assert!(
        patch
            .pointer("/tools/servers/fs/tools_allow/write/schema_hash")
            .unwrap()
            .is_null(),
        "a REJECTED capability projects as no approved hash, which the build reads as `pending` — \
         allowed, inspectable, and not serving: {patch}"
    );
}

/// AND THE ROUND TRIP CLOSES: feeding the projection back through the config grammar rebuilds an
/// approval that serves the same digest. A projection that wrote a field the build does not read is
/// a projection that loses the operator's decision silently, which is the failure this asserts
/// against rather than describes.
#[test]
fn the_projected_approval_rebuilds_into_the_same_dispatch_answer() {
    use crate::mcp::client::catalogue::TransportPin;
    use crate::trust::{Approval, Observation, Sighting};

    let mut approval: Approval<TransportPin> = Approval::declared(
        TransportPin::declared("cert_spki", "sha256/PEER="),
        Default::default(),
    );
    approval
        .approve(
            &Sighting::Seen(Observation {
                pin: Some(TransportPin::declared("cert_spki", "sha256/PEER=")),
                capabilities: [("read".to_string(), "sha256:aaa".to_string())]
                    .into_iter()
                    .collect(),
            }),
            None,
        )
        .unwrap();
    let patch = overlay_patch("fs", &approval);

    // Rebuild a registration carrying exactly what the projection wrote.
    let mut cfg: crate::mcp::config::McpServerDefCfg = serde_json::from_value(serde_json::json!({
        "url": "https://upstream.example.com/mcp",
        "pin": {
            "mechanism": "cert_spki",
            "key": patch.pointer("/tools/servers/fs/pin/key").unwrap(),
        },
        "tools_allow": {
            "read": {
                "schema_hash": patch
                    .pointer("/tools/servers/fs/tools_allow/read/schema_hash")
                    .unwrap(),
            }
        },
    }))
    .expect("the projection must be valid `tools:` config");
    cfg.allow_private = true;

    let mut servers = indexmap::IndexMap::new();
    servers.insert("fs".to_string(), cfg);
    let catalogue = crate::mcp::catalogue::Catalogue::build(&crate::mcp::config::ToolsCfg {
        servers,
        ..Default::default()
    });
    let rebuilt = catalogue.server("fs").expect("the server rebuilds");

    assert!(
        rebuilt.approval.serves("read", "sha256:aaa"),
        "the rebuilt approval serves the digest the original approved — the round trip is closed"
    );
    assert!(
        !rebuilt.approval.serves("read", "sha256:bbb"),
        "and refuses any other, so the round trip did not widen anything"
    );
}
