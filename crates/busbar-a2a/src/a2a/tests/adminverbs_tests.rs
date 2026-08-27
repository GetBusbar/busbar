// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE A2A TRUST VERBS, DRIVEN OVER THE REAL ROUTER — `connect` and `approve`.
//!
//! Over the router and not over the handler functions, for the reason the MCP plane's sibling file
//! gives: what is being claimed is that an OPERATOR can reach these. Calling
//! [`crate::a2a::verbs::connect`] directly proves the decision and proves nothing about whether a
//! deployment has any way to take it — which is exactly the defect this file exists to close. Every
//! A2A unit test in the tree passed while the receiving plane could not be lifted out of `Pending`
//! by any sequence of operator actions.
//!
//! The whole sequence is here once, end to end, because the claim is a SEQUENCE: a registration
//! born `Pending` is previewed, the fingerprint a human saw is echoed back, and only then does the
//! agent serve. Each half alone would leave the other unproven.

use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

use crate::a2a::config::{AgentDefCfg, AgentPinCfg, PinMechanism};
use crate::a2a::jws::ED25519_SPKI_PREFIX;
use busbar_core::test_support::TestApp;

const TOKEN: &str = "admintok";
const STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn spki_base64(k: &SigningKey) -> String {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(k.verifying_key().as_bytes());
    STD.encode(der)
}

fn a_card(skill: &str) -> Value {
    json!({
        "protocolVersion": "0.3.0",
        "name": "echo",
        "url": "https://echo.example/agent",
        "skills": [{ "id": skill, "name": "Echo", "description": "echoes what it is sent" }]
    })
}

fn signed_by(k: &SigningKey, card: Value) -> Value {
    let mut card = card;
    let protected = crate::a2a::jws::B64URL.encode(br#"{"alg":"EdDSA","kid":"vendor-2026"}"#);
    let payload = crate::a2a::jws::B64URL.encode(
        crate::a2a::card::signing_payload(&card)
            .expect("payload")
            .as_bytes(),
    );
    let sig = k.sign(format!("{protected}.{payload}").as_bytes());
    card.as_object_mut().expect("object").insert(
        "signatures".to_string(),
        json!([{ "protected": protected, "signature": crate::a2a::jws::B64URL.encode(sig.to_bytes()) }]),
    );
    card
}

/// A LOOPBACK AGENT serving a signed card at the canonical well-known path.
///
/// Plain `http://` on `127.0.0.1`, which is the shape a hermetic rig has and which the card fetch
/// refuses outright unless the operator has said `allow_private: true` out loud. The registration
/// below says it; that is the second half of this file's subject.
async fn agent_endpoint(card: Value) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let body = serde_json::to_string(&card).expect("serialize");
    let router = axum::Router::new().route(
        crate::a2a::card::WELL_KNOWN_CARD_PATH,
        axum::routing::get(move || {
            let body = body.clone();
            async move {
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, handle)
}

fn agent_cfg(url: &str, allow_private: bool) -> AgentDefCfg {
    AgentDefCfg {
        url: url.to_string(),
        pin: AgentPinCfg {
            mechanism: PinMechanism::JwsIssuerKey,
            key: Some(spki_base64(&key())),
            fingerprint: None,
        },
        reverify_ttl: None,
        recovery_backoff: None,
        protocol_version: None,
        allow_private,
        client_identity: None,
        upstream_credentials: None,
        upstream_credential: None,
        egress_scopes: Vec::new(),
        hooks: Vec::new(),
    }
}

/// A live busbar with governance, an admin token and one registered — therefore `Pending` — agent.
///
/// Hands back the PLANE as well as the address. The admin verbs' own answers are one surface, and
/// the question the 503 was actually about is a different one: is the registration DELEGABLE, which
/// is what `a2a::inbound::authorize` and `relay::LiveGate` ask on every inbound request. A test that
/// only read the verb's own response body would prove the verb agrees with itself.
async fn serve(
    def: AgentDefCfg,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<crate::a2a::plane::A2aPlane>,
) {
    let gov = Arc::new(
        busbar_core::governance::GovState::new_with_signer(
            Arc::new(busbar_core::governance::MemoryStore::new()),
            Some(TOKEN.to_string()),
            Some(
                busbar_substrate::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_substrate::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap(),
    );
    let app = TestApp::new()
        .governance(gov)
        .agent_def("echo", def)
        .build();
    let plane = crate::a2a::runtime_arc(&app).expect("an `agents:` section is an A2A plane");
    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (addr, handle, plane)
}

/// Whether the LIVE registry would let this agent carry traffic — the exact predicate behind the
/// `503 … is not serving (Pending)` an operator saw.
fn delegable(plane: &crate::a2a::plane::A2aPlane) -> bool {
    plane.with_registrations(|regs| {
        regs.iter()
            .any(|r| r.agent_id == "echo" && r.is_delegable())
    })
}

async fn request(
    addr: std::net::SocketAddr,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut req = reqwest::Client::new()
        .request(method, format!("http://{addr}/api/v1/admin{path}"))
        .header("x-admin-token", TOKEN);
    if let Some(b) = body {
        req = req.json(&b);
    }
    let response = req.send().await.unwrap();
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap_or_default();
    (status, body)
}

/// THE WHOLE SEQUENCE AN OPERATOR WALKS, and the one that had no path through it: a registration
/// born `Pending`, previewed, approved against the fingerprint the preview showed, and serving.
#[tokio::test]
async fn an_operator_can_take_a_registration_out_of_pending() {
    busbar_core::metrics::init();
    let k = key();
    let (agent, agent_task) = agent_endpoint(signed_by(&k, a_card("echo"))).await;
    let (addr, server, plane) = serve(agent_cfg(&format!("http://{agent}/agent"), true)).await;

    assert!(
        !delegable(&plane),
        "THE STARTING POINT, asserted rather than assumed: a registration lowered from `agents:` is \
         `Pending` and carries no traffic. This is the state busbar shipped in with no way out of it."
    );

    // ── CONNECT: a preview. It reports a fingerprint and it grants nothing. ─────────────────────
    let (status, body) = request(addr, reqwest::Method::POST, "/agents/echo/connect", None).await;
    assert_eq!(status, 200, "connect must be mounted and reachable: {body}");
    assert_eq!(
        body.get("state").unwrap(),
        "pending",
        "a preview NEVER reports approved: {body}"
    );
    let fingerprint = body
        .get("fingerprint")
        .and_then(|f| f.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        !fingerprint.is_empty(),
        "the preview must surface the fingerprint a human is being asked to approve: {body}"
    );
    assert!(
        !delegable(&plane),
        "and a PREVIEW MOVED NOTHING. `connect` fetching a card an operator has not approved must \
         not put the agent into service, or the preview would be the grant."
    );

    // ── APPROVE against the fingerprint the human just read. ────────────────────────────────────
    let (status, body) = request(
        addr,
        reqwest::Method::POST,
        "/agents/echo/approve",
        Some(json!({ "fingerprint": fingerprint })),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body.get("state").unwrap(),
        "approved",
        "and NOW the registration serves: {body}"
    );
    assert!(
        delegable(&plane),
        "AND THE LIVE REGISTRY AGREES — this is the predicate `inbound::authorize` and \
         `relay::LiveGate` ask on every request, and the one that was answering \
         `503 … is not serving (Pending)` for every fronted agent in every deployment."
    );
    // AND THE SERVED CARD IS WARM. `delegable` is the TRUST axis; the CATALOGUE axis is a second
    // gate that excludes an agent with no cached card (`Excluded::NoCachedCard`), so an approved
    // registration whose card was never cached is still absent from every caller's catalogue,
    // answers `503` on `/a2a/agents/{id}`, and refuses every delegation. The deleted re-verification
    // sweep used to cache that first card on its first tick; verify-on-call has no tick, so `approve`
    // caches the exact document it just verified. Without that, this is the state the A2A conformance
    // battery failed on — approved, delegable, and serving nothing.
    assert!(
        plane.with_registrations(|regs| regs
            .iter()
            .any(|r| r.agent_id == "echo" && r.cached_card.is_some())),
        "approve must cache the document it verified, or the agent is delegable on the trust axis \
         yet excluded from every catalogue for want of a card"
    );

    server.abort();
    agent_task.abort();
}

/// APPROVE REFUSES A FINGERPRINT THE OPERATOR DID NOT SEE. The echo is the whole trust root: an
/// approve that accepted whatever the endpoint currently serves would be trust-on-first-use with a
/// button on it.
#[tokio::test]
async fn approve_refuses_a_fingerprint_that_is_not_the_one_being_served() {
    busbar_core::metrics::init();
    let k = key();
    let (agent, agent_task) = agent_endpoint(signed_by(&k, a_card("echo"))).await;
    let (addr, server, plane) = serve(agent_cfg(&format!("http://{agent}/agent"), true)).await;

    let (status, body) = request(
        addr,
        reqwest::Method::POST,
        "/agents/echo/approve",
        Some(json!({ "fingerprint": "sha256:0000000000000000000000000000000000000000000000000000000000000000" })),
    )
    .await;
    assert_eq!(status, 400, "{body}");
    assert_eq!(
        body.pointer("/error/code").unwrap(),
        "invalid_request",
        "{body}"
    );

    // AND THE REGISTRATION IS STILL PENDING: a refused approval must not have moved anything.
    let (status, body) = request(addr, reqwest::Method::POST, "/agents/echo/connect", None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body.get("state").unwrap(), "pending", "{body}");
    assert!(
        !delegable(&plane),
        "a refused approval must leave the registry exactly where it was"
    );

    server.abort();
    agent_task.abort();
}

/// AN `unpinned` REGISTRATION IS INSPECTABLE AND NEVER APPROVABLE. The A2A plane's one local rule
/// about what its artifact means, reachable now that there is a surface that could have broken it.
#[tokio::test]
async fn an_unpinned_registration_cannot_be_approved() {
    busbar_core::metrics::init();
    let (agent, agent_task) = agent_endpoint(a_card("echo")).await;
    let mut def = agent_cfg(&format!("http://{agent}/agent"), true);
    def.pin = AgentPinCfg {
        mechanism: PinMechanism::Unpinned,
        key: None,
        fingerprint: None,
    };
    let (addr, server, _plane) = serve(def).await;

    let (status, body) = request(addr, reqwest::Method::POST, "/agents/echo/connect", None).await;
    assert_eq!(status, 200, "it is inspectable: {body}");
    let fingerprint = body
        .get("fingerprint")
        .and_then(|f| f.as_str())
        .unwrap_or_default()
        .to_string();

    let (status, body) = request(
        addr,
        reqwest::Method::POST,
        "/agents/echo/approve",
        Some(json!({ "fingerprint": fingerprint })),
    )
    .await;
    assert_eq!(status, 400, "and it is never approvable: {body}");

    server.abort();
    agent_task.abort();
}

/// A LOOPBACK BACKEND WITHOUT THE OPT-IN IS STILL REFUSED. `allow_private` is the operator saying
/// so out loud; absent it, the SSRF guard's answer does not change because an admin verb asked.
#[tokio::test]
async fn a_loopback_backend_is_refused_without_the_opt_in() {
    busbar_core::metrics::init();
    let k = key();
    let (agent, agent_task) = agent_endpoint(signed_by(&k, a_card("echo"))).await;
    let (addr, server, _plane) = serve(agent_cfg(&format!("http://{agent}/agent"), false)).await;

    let (status, body) = request(addr, reqwest::Method::POST, "/agents/echo/connect", None).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        body.get("state").unwrap(),
        "error",
        "a refused fetch is a FAILED CONTACT, recorded as one: {body}"
    );
    assert!(
        body.get("failure")
            .and_then(|f| f.as_str())
            .unwrap_or_default()
            .contains("allow_private"),
        "and the refusal names the knob that would permit it: {body}"
    );

    server.abort();
    agent_task.abort();
}

/// AN UNREGISTERED NAME IS `404` ON BOTH VERBS — the arm the frozen taxonomy declares, produced by
/// a driver rather than assumed.
#[tokio::test]
async fn an_unregistered_agent_is_not_found_on_every_verb() {
    busbar_core::metrics::init();
    let (addr, server, _plane) = serve(agent_cfg("https://echo.example/agent", false)).await;

    for (method, path, body) in [
        (reqwest::Method::POST, "/agents/nope/connect", None),
        (
            reqwest::Method::POST,
            "/agents/nope/approve",
            Some(json!({ "fingerprint": "sha256:abc" })),
        ),
    ] {
        let (status, got) = request(addr, method.clone(), path, body).await;
        assert_eq!(status, 404, "{method} {path}: {got}");
        assert_eq!(
            got.pointer("/error/code").unwrap(),
            "not_found",
            "and it is the taxonomy's stable code, which is what tooling branches on: {got}"
        );
    }

    server.abort();
}

/// BOTH VERBS NEED FULL SCOPE. `connect` reaches an operator-named endpoint and `approve` moves a
/// registration into service; the scope matrix decides that from the METHOD, which is why both are
/// POSTs.
#[tokio::test]
async fn the_trust_verbs_need_full_scope() {
    busbar_core::metrics::init();
    for path in [
        "/api/v1/admin/agents/echo/connect",
        "/api/v1/admin/agents/echo/approve",
    ] {
        assert_eq!(
            busbar_core::admin::v1::contract::required_scope(&axum::http::Method::POST, path),
            busbar_core::admin::v1::contract::Scope::Full,
            "{path} is a mutation"
        );
    }
}

/// THE DRIVERS for this surface's declared error set, callable from the taxonomy's own
/// set-comparison so the assertion does not depend on which tests happened to run first.
// No cfg of its own: this whole module is gated on `auth-admin-tokens` at its include site in
// `adminverbs.rs`, exactly as the MCP plane's sibling is.
pub(crate) async fn drive_a2a_verb_errors() {
    busbar_core::metrics::init();
    let k = key();
    let (agent, agent_task) = agent_endpoint(signed_by(&k, a_card("echo"))).await;
    let (addr, server, _plane) = serve(agent_cfg(&format!("http://{agent}/agent"), true)).await;

    // NotFound / UnknownResource, on both verbs.
    let (status, _) = request(addr, reqwest::Method::POST, "/agents/nope/connect", None).await;
    assert_eq!(status, 404);
    let (status, _) = request(
        addr,
        reqwest::Method::POST,
        "/agents/nope/approve",
        Some(json!({ "fingerprint": "sha256:abc" })),
    )
    .await;
    assert_eq!(status, 404);

    // Validation / MalformedBody, on `approve`.
    let (status, _) = request(
        addr,
        reqwest::Method::POST,
        "/agents/echo/approve",
        Some(json!({ "nope": true })),
    )
    .await;
    assert_eq!(status, 400);

    // Validation / InvalidConfig, on `approve`: a fingerprint that is not the one being served.
    let (status, _) = request(
        addr,
        reqwest::Method::POST,
        "/agents/echo/approve",
        Some(json!({ "fingerprint": "sha256:not-the-one" })),
    )
    .await;
    assert_eq!(status, 400);

    server.abort();
    agent_task.abort();
}
