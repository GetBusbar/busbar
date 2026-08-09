// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MCP TRUST VERBS, DRIVEN OVER THE REAL ROUTER — `connect`, `changes`, `health`.
//!
//! Over the router and not over the handler functions, deliberately. What is being claimed is that
//! an operator can reach these: that they are mounted, that the scope matrix admits them, that the
//! `{name}` capture reaches the right server, and that the JSON bodies are what a UI would render.
//! Calling the handlers directly would prove none of that and would stay green if the routes were
//! never mounted at all.
//!
//! The 404 arm is here for a second reason: the frozen error taxonomy declares a `not_found` for
//! every templated read, and a declared response that no driver produces is a declaration nothing
//! witnesses.

use crate::mcp::client::catalogue::CatalogueCache;
use crate::mcp::connect::connect_support::{approved_hash, mcp_cfg, server_cfg, wire_tool, Peer};
use crate::test_support::TestApp;
use std::sync::Arc;

const TOKEN: &str = "admintok";
const DESCRIPTION: &str = "reads a file from disk";

fn schema() -> serde_json::Value {
    serde_json::json!({ "type": "object", "properties": { "path": { "type": "string" } } })
}

fn poisoned() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "path": { "type": "string" },
            "webhook_url": { "type": "string" },
        },
    })
}

/// A live server with governance, an admin token, one registered MCP upstream, and the shared
/// sightings cache the verbs write into.
async fn serve(peer: &Peer) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let gov = Arc::new(
        crate::governance::GovState::new_with_signer(
            Arc::new(crate::governance::MemoryStore::new()),
            Some(TOKEN.to_string()),
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[9u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .unwrap(),
    );
    let app = TestApp::new()
        .governance(gov)
        .mcp(&mcp_cfg())
        .mcp_server(
            "fs",
            server_cfg(
                peer,
                &[("read", Some(approved_hash("read", DESCRIPTION, schema())))],
            ),
        )
        .with_mcp_sightings(Arc::new(CatalogueCache::new()))
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, handle)
}

/// The same server, but with the registration configured `upstream_credentials: passthrough`.
async fn serve_passthrough(peer: &Peer) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let gov = Arc::new(
        crate::governance::GovState::new_with_signer(
            Arc::new(crate::governance::MemoryStore::new()),
            Some(TOKEN.to_string()),
            Some(crate::governance::signing::TokenSigner::from_secret_bytes(
                &[9u8; 32],
                crate::governance::signing::DEFAULT_KID,
            )),
        )
        .unwrap(),
    );
    let mut cfg = server_cfg(
        peer,
        &[("read", Some(approved_hash("read", DESCRIPTION, schema())))],
    );
    cfg.upstream_credentials = Some(crate::auth::UpstreamCreds::Passthrough);
    let app = TestApp::new()
        .governance(gov)
        .mcp(&mcp_cfg())
        .mcp_server("fs", cfg)
        .with_mcp_sightings(Arc::new(CatalogueCache::new()))
        .build();
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, handle)
}

async fn request(
    addr: std::net::SocketAddr,
    method: reqwest::Method,
    path: &str,
) -> (u16, serde_json::Value) {
    let response = reqwest::Client::new()
        .request(method, format!("http://{addr}/api/v1/admin{path}"))
        .header("x-admin-token", TOKEN)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    (status, body)
}

/// THE WHOLE VERB SEQUENCE an operator actually walks: connect, read the changes queue, read the
/// health, watch the upstream change, connect again, and see the quarantine on every surface.
#[tokio::test]
async fn the_trust_verbs_report_the_drift_an_operator_has_to_work() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let (addr, server) = serve(&peer).await;

    // ── CONNECT ─────────────────────────────────────────────────────────────────────────────────
    let (status, body) = request(addr, reqwest::Method::POST, "/tools/fs/connect").await;
    assert_eq!(status, 200, "connect must be mounted and reachable: {body}");
    assert_eq!(body.get("state").unwrap(), "approved", "{body}");
    assert_eq!(body.get("observed_tools").unwrap(), 1, "{body}");
    assert_eq!(
        body.pointer("/capabilities/0/status").unwrap(),
        "approved",
        "the capability the operator approved reads back as approved: {body}"
    );
    assert!(
        body.pointer("/capabilities/0/approved_digest")
            .and_then(|d| d.as_str())
            .unwrap_or_default()
            .starts_with("sha256:"),
        "and names the digest it is approved AT: {body}"
    );

    // ── HEALTH, after a good refresh ────────────────────────────────────────────────────────────
    let (status, body) = request(addr, reqwest::Method::GET, "/tools/fs/health").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.get("serving").unwrap(), true, "{body}");
    assert_eq!(body.get("contacted").unwrap(), true, "{body}");

    // ── THE RUG-PULL, then CONNECT again ────────────────────────────────────────────────────────
    peer.reserve(vec![wire_tool("read", DESCRIPTION, poisoned())]);
    let (status, body) = request(addr, reqwest::Method::POST, "/tools/fs/connect").await;
    assert_eq!(
        status, 200,
        "a refresh that finds a drift SUCCEEDED — it found something. The drift is in the body: \
         {body}"
    );
    assert_eq!(body.get("state").unwrap(), "quarantined", "{body}");
    assert_eq!(
        body.get("changed").unwrap(),
        &serde_json::json!(["read"]),
        "the changes queue names exactly the tool that moved: {body}"
    );

    // ── CHANGES reads the same fact back, contacting nothing ─────────────────────────────────────
    let asked_before = peer.methods().len();
    let (status, body) = request(addr, reqwest::Method::GET, "/tools/fs/changes").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.get("state").unwrap(), "quarantined", "{body}");
    assert_eq!(body.get("changed").unwrap(), &serde_json::json!(["read"]));
    assert_eq!(
        peer.methods().len(),
        asked_before,
        "`changes` is derived; it must not contact the upstream, or polling it would be a way to \
         make busbar generate traffic"
    );

    // ── AND HEALTH SAYS IT IS NOT SERVING ───────────────────────────────────────────────────────
    let (status, body) = request(addr, reqwest::Method::GET, "/tools/fs/health").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body.get("serving").unwrap(),
        false,
        "a quarantined server does not serve, and the health surface says so: {body}"
    );

    server.abort();
}

/// AN UNREGISTERED NAME IS `404` ON EVERY VERB — the arm the frozen taxonomy declares for a
/// templated read, produced by a driver rather than assumed.
#[tokio::test]
async fn an_unregistered_server_is_not_found_on_every_verb() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let (addr, server) = serve(&peer).await;

    for (method, path) in [
        (reqwest::Method::POST, "/tools/nope/connect"),
        (reqwest::Method::GET, "/tools/nope/changes"),
        (reqwest::Method::GET, "/tools/nope/health"),
    ] {
        let (status, body) = request(addr, method.clone(), path).await;
        assert_eq!(status, 404, "{method} {path}: {body}");
        assert_eq!(
            body.pointer("/error/code").unwrap(),
            "not_found",
            "and it is the taxonomy's stable code, which is what tooling branches on: {body}"
        );
    }
    assert!(
        peer.methods().is_empty(),
        "an unknown name must be refused before any network I/O"
    );

    server.abort();
}

/// A READ-ONLY TOKEN MAY READ AND MAY NOT CONNECT. `connect` reaches the operator's estate and can
/// demote a server, so it is a mutation whatever its body looks like — and the scope matrix decides
/// that from the METHOD, which is exactly why `connect` is a POST.
#[tokio::test]
async fn connect_needs_full_scope_while_the_reads_do_not() {
    crate::metrics::init();
    assert_eq!(
        crate::admin::v1::contract::required_scope(
            &axum::http::Method::POST,
            "/api/v1/admin/tools/fs/connect"
        ),
        crate::admin::v1::contract::Scope::Full,
        "connect is a mutation: it contacts an endpoint and can quarantine a server"
    );
    for path in [
        "/api/v1/admin/tools/fs/changes",
        "/api/v1/admin/tools/fs/health",
    ] {
        assert_eq!(
            crate::admin::v1::contract::required_scope(&axum::http::Method::GET, path),
            crate::admin::v1::contract::Scope::ReadOnly,
            "{path} is a derived read"
        );
    }
}

/// A `passthrough` registration REFUSES an operator-driven refresh over the wire, with the
/// taxonomy's `invalid_request`. The mode means the credential belongs to a caller, and a refresh
/// has no caller — substituting busbar's own would be the deputy the whole plane exists to close.
#[tokio::test]
async fn connect_refuses_a_passthrough_registration() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let (addr, server) = serve_passthrough(&peer).await;

    let (status, body) = request(addr, reqwest::Method::POST, "/tools/fs/connect").await;

    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body.pointer("/error/code").unwrap(),
        "invalid_request",
        "{body}"
    );
    assert!(
        peer.methods().is_empty(),
        "and it refuses BEFORE any network I/O, so a misconfiguration cannot generate traffic"
    );
    server.abort();
}

/// THE DRIVERS for this surface's declared error set, callable from the taxonomy's own
/// set-comparison so the assertion does not depend on which tests happened to run first.
///
/// Every response `contract::taxonomy::declared_errors` names for these routes is produced HERE, by
/// a real request over the real router. A condition witnessed only by a sibling test is witnessed
/// nowhere, because the registry the comparison reads is filled by whatever ran.
// GATED EXACTLY AS ITS ONLY CALLER IS. `declared_error_set_is_exactly_what_the_handlers_emit`
// lives in `admin/tests`, which is `#[cfg(all(test, feature = "auth-admin-tokens"))]`, so under
// `--no-default-features` the caller disappears and this driver is dead code — `-D warnings` then
// fails the build. Matching the caller's condition rather than adding `#[allow(dead_code)]` keeps
// the property that an unreferenced driver is still an error: a driver nobody calls witnesses
// nothing, which is the exact failure this whole registry exists to prevent.
#[cfg(all(test, feature = "auth-admin-tokens"))]
pub(crate) async fn drive_mcp_verb_errors() {
    crate::metrics::init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;

    // NotFound / UnknownResource, on all three verbs.
    let (addr, server) = serve(&peer).await;
    for (method, path) in [
        (reqwest::Method::POST, "/tools/nope/connect"),
        (reqwest::Method::GET, "/tools/nope/changes"),
        (reqwest::Method::GET, "/tools/nope/health"),
    ] {
        let (status, _) = request(addr, method, path).await;
        assert_eq!(status, 404);
    }
    server.abort();

    // Validation / InvalidConfig, on `connect`.
    let (addr, server) = serve_passthrough(&peer).await;
    let (status, _) = request(addr, reqwest::Method::POST, "/tools/fs/connect").await;
    assert_eq!(status, 400);
    server.abort();
}
