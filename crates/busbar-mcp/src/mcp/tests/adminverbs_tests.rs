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
use crate::mcp::test_engine::*;
use crate::testkit::TestAppMcpExt;
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
async fn serve(
    peer: &Peer,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<CatalogueCache>,
) {
    let gov = engine()
        .governance(
            Arc::new(busbar_store_memory::MemoryStore::new()),
            Some(TOKEN.to_string()),
            Some(
                busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_substrate::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap();
    let sightings = Arc::new(CatalogueCache::new());
    let app = test_app()
        .governance(gov)
        .mcp(&mcp_cfg())
        .mcp_server(
            "fs",
            server_cfg(
                peer,
                &[("read", Some(approved_hash("read", DESCRIPTION, schema())))],
            ),
        )
        .with_mcp_sightings(Arc::clone(&sightings))
        .build();
    let router = build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, handle, sightings)
}

/// The same server, but with the registration configured `upstream_credentials: passthrough`.
async fn serve_passthrough(peer: &Peer) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let gov = engine()
        .governance(
            Arc::new(busbar_store_memory::MemoryStore::new()),
            Some(TOKEN.to_string()),
            Some(
                busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_substrate::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap();
    let mut cfg = server_cfg(
        peer,
        &[("read", Some(approved_hash("read", DESCRIPTION, schema())))],
    );
    cfg.upstream_credentials = Some(busbar_api::UpstreamCreds::Passthrough);
    let app = test_app()
        .governance(gov)
        .mcp(&mcp_cfg())
        .mcp_server("fs", cfg)
        .with_mcp_sightings(Arc::new(CatalogueCache::new()))
        .build();
    let router = build_router(app);
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
    metrics_init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let (addr, server, _sightings) = serve(&peer).await;

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
    metrics_init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let (addr, server, _sightings) = serve(&peer).await;

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
    metrics_init();
    assert_eq!(
        engine().admin_required_scope(&axum::http::Method::POST, "/api/v1/admin/tools/fs/connect"),
        busbar_substrate::testkit::engine_kit::AdminScope::Full,
        "connect is a mutation: it contacts an endpoint and can quarantine a server"
    );
    for path in [
        "/api/v1/admin/tools/fs/changes",
        "/api/v1/admin/tools/fs/health",
    ] {
        assert_eq!(
            engine().admin_required_scope(&axum::http::Method::GET, path),
            busbar_substrate::testkit::engine_kit::AdminScope::ReadOnly,
            "{path} is a derived read"
        );
    }
}

/// A `passthrough` registration REFUSES an operator-driven refresh over the wire, with the
/// taxonomy's `invalid_request`. The mode means the credential belongs to a caller, and a refresh
/// has no caller — substituting busbar's own would be the deputy the whole plane exists to close.
#[tokio::test]
async fn connect_refuses_a_passthrough_registration() {
    metrics_init();
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
// No cfg of its own: this whole module is gated on `auth-admin-tokens` at its include site in
// `adminverbs.rs`, for the same reason its only caller in `admin/tests` is. Adding a second gate
// here would imply the two conditions could differ, and they cannot — if this module compiles,
// the caller does too.
pub async fn drive_mcp_verb_errors() {
    metrics_init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;

    // NotFound / UnknownResource, on all three verbs.
    let (addr, server, _sightings) = serve(&peer).await;
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

/// AN OPERATOR'S CONNECT RESETS THE UNATTENDED CLOCK. The sweep re-checks a registration when its
/// ledger says `NeverChecked` or the `verify_ttl:` lapsed, and `connect` takes EXACTLY the
/// observation the sweep takes — same fetch, same re-hash, same `demotion::settle`. It used to
/// take everything about that observation EXCEPT the ledger stamp, so a registration an operator
/// had just looked at was still `NeverChecked` to the timer and was re-fetched on the sweep's very
/// next tick — a second contact the operator's look should have satisfied, landing at a moment
/// nobody chose. One observation, two actors, one set of books.
#[tokio::test]
async fn a_connect_stamps_the_ledger_so_the_sweep_is_not_still_due() {
    use crate::mcp::client::identity::ServerId;
    use busbar_substrate::trust::reverify::{due, Due, Policy};

    metrics_init();
    let peer = Peer::start(vec![wire_tool("read", DESCRIPTION, schema())]).await;
    let (addr, server, sightings) = serve(&peer).await;

    // The control: before any look, the timer's answer is NeverChecked — due now.
    let fresh = sightings
        .load()
        .server(&ServerId::new("fs").unwrap())
        .map(|s| s.ledger.clone())
        .unwrap_or_default();
    let policy = Policy {
        ttl_ms: 3_600_000,
        recovery_backoff_ms: 0,
    };
    let now = busbar_substrate::store::now_ms();
    assert_eq!(
        due(&fresh, &policy, now, false),
        Due::NeverChecked,
        "an unlooked-at registration is due, which is the fail-closed default"
    );

    let (status, body) = request(addr, reqwest::Method::POST, "/tools/fs/connect").await;
    assert_eq!(status, 200, "{body}");

    let stamped = sightings
        .load()
        .server(&ServerId::new("fs").unwrap())
        .map(|s| s.ledger.clone())
        .expect("the connect observed the server, so the cache has an entry");
    assert_eq!(
        due(&stamped, &policy, busbar_substrate::store::now_ms(), false),
        Due::No,
        "the operator just looked; the unattended timer must not immediately look again \
         (ledger: {stamped:?})"
    );

    server.abort();
}
