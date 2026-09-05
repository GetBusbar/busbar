// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HONEST DEGRADE, MADE TRUE FOR MCP: `cert_spki`/`mtls` are pins that are actually checked.
//!
//! Until this file existed, `crate::mcp::client::catalogue::TransportPin::cert_spki`/`mtls` were
//! `#[allow(dead_code)]`: `crate::mcp::connect::refresh` fed `ServerCatalogue::observe` the pin the
//! OPERATOR DECLARED, under the module comment's own name for it — "the observed identity" — so a
//! `cert_spki`-pinned registration's sighting always agreed with its approval BY CONSTRUCTION.
//! `busbar_substrate::trust::Approval::drift`'s `pin_changed` check (`self.pin != obs.pin`) could
//! never fire: the two sides of that comparison were read from the same field. An operator who
//! configured `cert_spki` believed the upstream's certificate was pinned; the upstream's certificate
//! was never once compared to anything.
//!
//! Every test here drives a REAL TLS HANDSHAKE — through `crate::mcp::client::transport::HttpTransport`,
//! the production wire — against `busbar_substrate::egress::fixtures::spawn_tls`, a real `rustls` server
//! on a real loopback socket. The one throw-away CA these hops trust
//! (`crate::mcp::client::transport::test_ca::TEST_CA`) exists because MCP has no config-shaped way to name
//! a private CA for a registration yet (unlike A2A's `client_identity:` path); see that module for
//! why one CA correctly serves both the matching and the mismatched case below.

use busbar_substrate::egress::fixtures::{spawn_tls, CannedResponse, ClientAuth, TlsServerSpec};
use std::sync::Arc;

use crate::mcp::client::catalogue::CatalogueCache;
use crate::mcp::client::transport::test_ca::TEST_CA;
use crate::mcp::config::{McpPinMechanism, McpServerDefCfg, ServerPinCfg, ToolAllowCfg};
use crate::mcp::connect::{
    connect_support::{approved_hash, mcp_cfg},
    refresh,
};
use crate::mcp::test_engine::*;
use crate::testkit::TestAppMcpExt;

const TOOL_NAME: &str = "read";
const DESCRIPTION: &str = "reads a file from disk";

fn schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": { "path": { "type": "string" } } })
}

/// The `tools/list` JSON-RPC RESULT the fixture answers with, correlated to
/// `crate::mcp::connect::REFRESH_REQUEST_ID` (`1`) — the fixed id every operator-driven refresh
/// sends, which is what lets one canned response serve every test below.
fn tools_list_body() -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [{ "name": TOOL_NAME, "description": DESCRIPTION, "inputSchema": schema() }]
        }
    })
    .to_string()
}

/// A REAL TLS peer serving the one `tools/list` answer, over the certificate every test-build hop
/// trusts (`TEST_CA`). Kept alive by the caller for as long as a refresh may still reach it.
fn tls_peer() -> busbar_substrate::egress::fixtures::TlsFixture {
    spawn_tls(TlsServerSpec {
        cert_chain_pem: TEST_CA.leaf_pem.clone(),
        key_pem: TEST_CA.leaf_key_pem.clone(),
        client_auth: ClientAuth::None,
        response: CannedResponse::ok(&tools_list_body()),
        max_requests_per_connection: 4,
    })
}

/// A registration pointed at a REAL TLS peer, pinned under `mechanism` to `key`.
///
/// Mirrors `connect::connect_support::server_cfg`, parameterised on the two fields that battery
/// fixes: this one is about what the mechanism does with a certificate that is REALLY there,
/// not about the capability axis that fixture's plaintext peer covers.
fn server_cfg(url: String, mechanism: McpPinMechanism, key: &str) -> McpServerDefCfg {
    let mut allow = indexmap::IndexMap::new();
    allow.insert(
        TOOL_NAME.to_string(),
        ToolAllowCfg {
            schema_hash: Some(approved_hash(TOOL_NAME, DESCRIPTION, schema())),
            description: None,
            input_schema: None,
            ask_caller: Vec::new(),
            ..ToolAllowCfg::default()
        },
    );
    McpServerDefCfg {
        command: None,
        args: Vec::new(),
        env: Default::default(),
        cwd: None,
        verify_ttl: None,
        timeout: None,
        url,
        pin: ServerPinCfg {
            mechanism,
            key: Some(key.to_string()),
        },
        tools_allow: allow,
        prompts_allow: indexmap::IndexMap::new(),
        resources_allow: indexmap::IndexMap::new(),
        resource_templates_allow: Default::default(),
        transport: None,
        aud: None,
        grants: crate::mcp::config::ServerRequestGrants::default(),
        roots: Vec::new(),
        sampling: None,
        max_input_required_rounds: None,
        max_caller_ask_rounds: None,
        // The peer is on loopback, which every fail-closed default refuses until an operator says
        // the estate is internal.
        allow_private: true,
        token_exchange: None,
        upstream_credentials: None,
        hooks: Vec::new(),
    }
}

async fn refresh_against(
    mechanism: McpPinMechanism,
    key: &str,
) -> crate::mcp::connect::ConnectReport {
    metrics_init();
    let peer = tls_peer();
    let url = format!("https://127.0.0.1:{}/mcp", peer.addr.port());
    let cache = Arc::new(CatalogueCache::new());
    let app = test_app()
        .mcp(&mcp_cfg())
        .mcp_server("fs", server_cfg(url, mechanism, key))
        .with_mcp_sightings(cache.clone())
        .build();
    let entry = crate::mcp::runtime(&app)
        .catalogue
        .server("fs")
        .unwrap()
        .clone();
    let report = refresh(&crate::mcp::runtime(&app).pool, &cache, &entry)
        .await
        .unwrap();
    drop(peer);
    report
}

// ══ `cert_spki`: THE PIN IS COMPARED AGAINST WHAT THE HOP ACTUALLY PRESENTED ═══════════════════

/// THE GREEN HALF: an operator who correctly copied the endpoint's SPKI into `pin.key:` gets an
/// `approved` registration, because the observed certificate now genuinely matches it.
#[tokio::test]
async fn a_cert_spki_pin_matching_the_served_certificate_is_approved() {
    let report = refresh_against(McpPinMechanism::CertSpki, &TEST_CA.expected_pin).await;
    assert_eq!(
        report.failure, None,
        "the fetch itself must succeed: {report:?}"
    );
    assert_eq!(
        report.state_word(),
        "approved",
        "the served certificate's SPKI is exactly the pinned one: {report:?}"
    );
    assert!(
        report.drift.is_empty(),
        "nothing disagreed with the approval: {:?}",
        report.drift
    );
}

/// THE RED HALF, AND THE ONE THIS FILE EXISTS TO PROVE: a `cert_spki` pin that does NOT match the
/// certificate the hop actually received.
///
/// BEFORE `connect::observed_pin` existed, `refresh` fed `ServerCatalogue::observe` the DECLARED
/// pin as its own "observation" — so this exact registration, against this exact TLS peer, would
/// have compared `elsewhere`'s value to itself and reported `approved`. The upstream's real
/// certificate was never read for this purpose at all: `TransportPin::cert_spki`/`mtls` were
/// `#[allow(dead_code)]` because nothing ever called them. This test is the proof that changed:
/// the sighting now carries what the socket actually presented, and it disagrees with what the
/// operator wrote down.
#[tokio::test]
async fn a_cert_spki_pin_mismatched_against_the_served_certificate_is_quarantined() {
    let wrong_pin = "sha256/NOT-THE-SERVED-KEY=";
    assert_ne!(
        wrong_pin, TEST_CA.expected_pin,
        "the fixture's own guard: the test must pin something the peer does NOT present"
    );
    let report = refresh_against(McpPinMechanism::CertSpki, wrong_pin).await;
    assert_eq!(
        report.failure, None,
        "the TLS handshake and the fetch both succeed; the mismatch is a TRUST decision, not a \
         network failure: {report:?}"
    );
    assert_eq!(
        report.state_word(),
        "quarantined",
        "a certificate that is not the pinned one must demote the registration, not silently \
         serve under it: {report:?}"
    );
    assert!(
        report.drift.pin_changed,
        "the changes queue must name the axis that moved: {:?}",
        report.drift
    );
}

// ══ `mtls`: THE SAME PEER-IDENTITY CHECK, UNDER THE OPERATOR'S OTHER WORD FOR IT ═══════════════
//
// MCP has no `client_identity:` grammar yet (see `TransportPin::mtls`'s own doc), so `mtls`
// degrades to exactly the `cert_spki` check today. These two mirror the pair above under that
// mechanism, so `TransportPin::mtls` is proven wired rather than merely uncommented.

#[tokio::test]
async fn an_mtls_pin_matching_the_served_certificate_is_approved() {
    let report = refresh_against(McpPinMechanism::Mtls, &TEST_CA.expected_pin).await;
    assert_eq!(report.state_word(), "approved", "{report:?}");
}

#[tokio::test]
async fn an_mtls_pin_mismatched_against_the_served_certificate_is_quarantined() {
    let report = refresh_against(McpPinMechanism::Mtls, "sha256/SOMEBODY-ELSES-KEY=").await;
    assert_eq!(report.state_word(), "quarantined", "{report:?}");
    assert!(report.drift.pin_changed, "{:?}", report.drift);
}
