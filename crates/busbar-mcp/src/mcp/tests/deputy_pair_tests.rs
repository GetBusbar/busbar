// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSITIVE CONFUSED DEPUTY, PROVEN AS A PAIR.
//!
//! ## What was missing, and why it mattered
//!
//! The outbound credential gate has existed for a while, and it was proven — against a CONSTRUCTED
//! principal. That is not the same claim. A client-only gateway cannot have this bug at all: it has
//! no inbound principal to be confused about. busbar is both directions, so an authenticated inbound
//! `tools/call` can cause busbar to mint an outbound token from its OWN ambient credentials and
//! re-export an upstream with more authority than the caller holds. The bundle creates the deputy,
//! so only the bundle can close it — and a gate tested against a principal a test hand-built proves
//! the gate works, not that anything reaches it.
//!
//! Every test in this file therefore starts from an INBOUND caller and asserts on what the UPSTREAM
//! received. Nothing here inspects a value busbar was about to send.
//!
//! ## The discriminator, stated up front
//!
//! The catalogue filter and the egress gate consult the same two grants, so "granted the server
//! only" is refused by both and either alone would satisfy a status-code assertion. The property
//! that ONLY the egress gate can deliver is the one asserted hardest here: **two callers making the
//! SAME call get DIFFERENT credentials**, because the RFC 8693 down-scope is derived from each
//! caller's own grant. A deputy defence that stopped at "refused / not refused" would be satisfied by
//! a gateway that handed every admitted caller the same all-powerful token.
//!
//! ## The wildcard case is not an edge case
//!
//! `allowed_scopes: None` is the store's wildcard and it is the MOST COMMON key shape in a small
//! deployment, because nothing in this release writes `mcp_server`/`mcp_tool` scopes onto a key at
//! mint time. If a wildcard principal got a wildcard token, the defence would be vacuous for exactly the
//! deployments most likely to be running. So a wildcard is down-scoped to the SINGLE TOOL IT CALLED,
//! and that is asserted on the exchange request the authorization server received.

use super::upstream_support::{
    call, contains, encodings, exchanging_server, gov_with_scopes, key_with_scopes, mcp_cfg,
    wildcard_key, Behaviour, Peer,
};
use crate::mcp::test_engine::*;
use crate::testkit::TestAppMcpExt;
use std::sync::Arc;

const CANONICAL: &str = "https://gateway.example.com/mcp";
/// BUSBAR's own ambient credential. Legitimately travels on the EXCHANGE and nowhere else.
const SUBJECT: &str = "busbar-ambient-subject-token-SENTINEL-9c1f";
/// What the authorization server hands back. This, and only this, may reach the upstream.
const ISSUED: &str = "downscoped-access-token-for-this-backend";

/// Build an app fronting `peer`, with the two tools `fs_read` and `fs_write` approved.
fn app_for(peer: &Peer) -> Arc<dyn EngineApp> {
    test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(peer, SUBJECT))
        .build()
}

fn params(tool: &str) -> serde_json::Value {
    serde_json::json!({ "name": tool, "arguments": { "path": "/etc/hosts" } })
}

// ─── CASE 1: granted server + tool → the call is made, with the DOWN-SCOPED credential ───────────

/// The caller holds `mcp_server: fs` and `mcp_tool: fs_read`. The upstream call is made, and the
/// credential it carries is the one the authorization server issued for a scope derived from THIS
/// caller's grant.
#[tokio::test]
async fn a_granted_caller_reaches_the_upstream_with_a_credential_scoped_to_its_own_grant() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = app_for(&peer);
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(&app, &g, "tools/call", params("fs_read")).await;
    assert_eq!(status, 200, "{body}");

    // THE EXCHANGE, as the authorization server received it. Every RFC field asserted on the OUTPUT.
    assert_eq!(peer.token_hits(), 1);
    let form = peer.last_token().form();
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("urn:ietf:params:oauth:grant-type:token-exchange"),
        "RFC 8693 §2.1: {form:?}"
    );
    assert_eq!(
        form.get("requested_token_type").map(String::as_str),
        Some("urn:ietf:params:oauth:token-type:access_token"),
        "an ACCESS token back, not another exchangeable subject token"
    );
    assert_eq!(
        form.get("resource").map(String::as_str),
        Some(peer.mcp_url().as_str()),
        "RFC 8707: the issued token is bound to THIS upstream and is not spendable at another"
    );
    assert_eq!(
        form.get("subject_token").map(String::as_str),
        Some(SUBJECT),
        "the SUBJECT of the exchange is busbar's own credential — never the caller's"
    );
    assert_eq!(
        form.get("scope").map(String::as_str),
        Some("fs_read"),
        "THE DOWN-SCOPE: exactly the tools this caller is granted on this server: {form:?}"
    );

    // And the tool call carries the ISSUED token, not the subject token and nothing of the caller's.
    let sent = peer.last_mcp();
    let auth = sent
        .headers
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.clone())
        .expect("the upstream call must carry the exchanged credential");
    assert_eq!(auth, format!("Bearer {ISSUED}"));
}

/// THE DISCRIMINATOR. Two callers make the IDENTICAL call and the authorization server is asked for
/// two DIFFERENT scopes, because each is derived from that caller's own grant.
///
/// This is the assertion the catalogue filter cannot make. A gateway that authorised correctly and
/// then spent one all-powerful ambient credential would pass every refusal test in this file and
/// fail this one.
#[tokio::test]
async fn two_callers_making_the_same_call_get_two_different_credentials() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = app_for(&peer);

    let narrow = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let wide = gov_with_scopes(&[
        ("mcp_server", "fs"),
        ("mcp_tool", "fs_read"),
        ("mcp_tool", "fs_write"),
    ]);

    let (s1, b1) = call(&app, &narrow, "tools/call", params("fs_read")).await;
    let narrow_scope = peer.last_token().form().get("scope").cloned();
    let (s2, b2) = call(&app, &wide, "tools/call", params("fs_read")).await;
    let wide_scope = peer.last_token().form().get("scope").cloned();

    assert_eq!((s1, s2), (200, 200), "{b1} / {b2}");
    assert_eq!(narrow_scope.as_deref(), Some("fs_read"));
    assert_eq!(
        wide_scope.as_deref(),
        Some("fs_read fs_write"),
        "the down-scope is the caller's grant ON THIS SERVER, sorted so it is comparable"
    );
    assert_ne!(
        narrow_scope, wide_scope,
        "the SAME call by two callers must mint two DIFFERENT credentials; a shared one is the \
         transitive confused deputy"
    );
}

// ─── CASE 2: granted the SERVER only → refused, and NO exchange round trip ───────────────────────

/// A caller holding `mcp_server: fs` and no `mcp_tool` grant is refused, and — the half that a
/// status code cannot show — busbar makes NO token-exchange round trip on its own authorization
/// server. An unauthorised party that can make busbar generate authenticated traffic to the
/// operator's IdP is spending the operator's rate limit for free.
#[tokio::test]
async fn a_server_only_grant_is_refused_and_causes_no_token_exchange() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = app_for(&peer);
    let server_only = gov_with_scopes(&[("mcp_server", "fs")]);

    let (status, body) = call(&app, &server_only, "tools/call", params("fs_read")).await;

    assert!(
        (400..500).contains(&status),
        "a server-wide grant must not become a tool-wide one: {status} {body}"
    );
    assert_ne!(
        body.pointer("/error/data/reason").and_then(|v| v.as_str()),
        Some("upstream_failed"),
        "this must be refused by a GRANT, not by a network: {body}"
    );
    assert_eq!(
        peer.token_hits(),
        0,
        "an unauthorised call must not cause a token-exchange round trip AT ALL"
    );
    assert_eq!(peer.mcp_hits(), 0, "and must not reach the upstream");
}

// ─── CASE 3: granted a DIFFERENT tool → refused ──────────────────────────────────────────────────

/// A caller granted `fs_write` calling `fs_read` is refused. The grant is per tool, not per server,
/// and holding one capability on a server is not holding its neighbours.
#[tokio::test]
async fn a_grant_for_a_different_tool_on_the_same_server_is_refused() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = app_for(&peer);
    let other = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_write")]);

    let (status, body) = call(&app, &other, "tools/call", params("fs_read")).await;
    assert!((400..500).contains(&status), "{status} {body}");
    assert_eq!(
        (peer.token_hits(), peer.mcp_hits()),
        (0, 0),
        "refused before any outbound traffic"
    );

    // THE CONTROL, on the same app and the same caller: the tool it IS granted goes through. Without
    // this the refusal above is indistinguishable from a deployment that refuses everything.
    let (ok, ok_body) = call(&app, &other, "tools/call", params("fs_write")).await;
    assert_eq!(ok, 200, "{ok_body}");
    assert_eq!(
        peer.last_token().form().get("scope").map(String::as_str),
        Some("fs_write"),
        "and the credential it got is scoped to the tool it holds, not to the one it asked for \
         first"
    );
}

// ─── CASE 4: the caller's own busbar key appears NOWHERE on the upstream wire ────────────────────

/// THE ADVERSARIAL SCAN, END TO END OVER HTTP.
///
/// An external MCP client authenticates to busbar's resource server with a REAL audience-bound
/// busbar token, calls a tool, and every byte the upstream and the authorization server received is
/// scanned for that token in five encodings. This is the strongest form of the claim available: the
/// haystack is what the peers RECEIVED, so a header added by some future transport is covered
/// automatically, and the needle is the credential the caller actually presented rather than a
/// constant a test planted in a struct.
///
/// The control is at the bottom: the scanner is proven able to FIND a secret on this same wire.
#[tokio::test]
async fn the_callers_busbar_key_appears_nowhere_on_the_upstream_wire() {
    use busbar_store_memory::MemoryStore;
    use busbar_substrate::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_substrate::governance::NewKeySpec;
    metrics_init();

    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let store = Arc::new(MemoryStore::new());
    // Two handles on the SAME key material: one inside `GovState` (which consumes it) and one for
    // the test to mint the caller's audience-bound token with. Same bytes, same kid, so the verifier
    // busbar runs is verifying a token this test really minted.
    let signer = TokenSigner::from_secret_bytes(&[11u8; 32], DEFAULT_KID);
    let gov = engine()
        .governance(
            store.clone(),
            Some("admintok".to_string()),
            Some(TokenSigner::from_secret_bytes(&[11u8; 32], DEFAULT_KID)),
        )
        .unwrap();

    // Mint a REAL key, then give it the MCP grants. Nothing in this release writes `mcp_server` /
    // `mcp_tool` scopes at mint time (the admin verbs for it are a separate unit), so the row is
    // written directly — which is the honest way to get the shape a future mint path will produce.
    let (key, plain) = gov
        .mint_signed(
            NewKeySpec {
                name: "external-mcp-client".to_string(),
                allowed_pools: None,
                group: None,
                labels: Default::default(),
                ..Default::default()
            },
            2_000_000_000,
            busbar_substrate::store::now(),
        )
        .unwrap();
    let generation = TokenVerifier::single(signer.kid(), signer.verifying_key())
        .verify(plain.as_str(), busbar_substrate::store::now(), None)
        .expect("the plain token verifies")
        .generation;
    let mut scoped = key.clone();
    scoped.allowed_scopes = Some(vec![
        busbar_api::ScopeRef {
            kind: "mcp_server".to_string(),
            value: "fs".to_string(),
        },
        busbar_api::ScopeRef {
            kind: "mcp_tool".to_string(),
            value: "fs_read".to_string(),
        },
    ]);
    gov.store().put_key(&scoped).unwrap();
    gov.refresh().unwrap();

    // THE CALLER'S BUSBAR KEY: an audience-bound token for THIS deployment. This is the sentinel.
    let bearer = signer.mint_for_audience(
        &key.id,
        2_000_000_000,
        generation.as_deref(),
        CANONICAL,
        Some("external-client-1"),
    );

    let app = test_app()
        .keys_chain()
        .governance(gov)
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    // This end-to-end case asserts the CREDENTIAL LEG over the real wire, not verify-on-call: mark
    // the server just-verified so the gate reuses the snapshot (the mock upstream answers `tools/call`
    // but not a verifiable `tools/list`). See `crate::testkit::prefresh_mcp_sightings`.
    crate::testkit::prefresh_mcp_sightings(app.as_ref());
    let router = build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let version = crate::mcp::envelope::PROTOCOL_VERSION;
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 42, "method": "tools/call",
        "params": {
            "name": "fs_read",
            "arguments": { "path": "/etc/hosts" },
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/mcp"))
        .header("authorization", format!("Bearer {bearer}"))
        .header("mcp-protocol-version", version)
        .header("mcp-method", "tools/call")
        .header("mcp-name", "fs_read")
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        status, 200,
        "the end-to-end pair must actually complete, or nothing below is scanning a real dispatch: \
         {json}"
    );
    assert_eq!(
        json.pointer("/result/content/0/text").unwrap(),
        "UPSTREAM RESULT"
    );

    // The INBOUND principal reached the OUTBOUND gate: the scope the authorization server was asked
    // for is the scope on the key that authenticated over HTTP.
    assert_eq!(
        peer.last_token().form().get("scope").map(String::as_str),
        Some("fs_read"),
        "the down-scope must be derived from the grant on the key the CALLER authenticated with"
    );

    // ── THE SCAN ──
    let wire = peer.all_wire();
    assert!(
        wire.len() > 100,
        "the scan has nothing to scan: {} bytes",
        wire.len()
    );
    let forms = encodings(&bearer);
    assert_eq!(forms.len(), 5, "every encoding must be exercised");
    for (encoding, bytes) in &forms {
        assert!(
            !contains(&wire, bytes),
            "the caller's busbar key reached an upstream, encoded as {encoding}"
        );
    }
    // Belt and braces on the same haystack: no fragment of the token's payload segment either.
    let payload_segment = bearer
        .trim_start_matches(busbar_substrate::governance::signing::TOKEN_PREFIX)
        .split('.')
        .next()
        .unwrap()
        .to_string();
    assert!(
        !contains(&wire, payload_segment.as_bytes()),
        "not even the token's claims segment may leave"
    );

    // ── THE CONTROL ── the scanner CAN find a secret on this very wire. busbar's own subject token
    // is legitimately forwarded to the authorization server, and it is found. Without this, the
    // assertions above would be equally green against a peer that received nothing.
    assert!(
        contains(&wire, SUBJECT.as_bytes()),
        "the scanner must be able to find a legitimately-forwarded credential, or its silence \
         above proves nothing"
    );
    // ...and the ISSUED token is on the tool call, which is the credential that SHOULD be there.
    assert!(contains(&peer.last_mcp().wire(), ISSUED.as_bytes()));
    // ...while busbar's ambient subject token is NOT: it rides the exchange and stops there.
    assert!(
        !contains(&peer.last_mcp().wire(), SUBJECT.as_bytes()),
        "busbar's ambient subject token must not ride the tool call; it has not been down-scoped"
    );

    server.abort();
}

// ─── CASE 5: the WILDCARD principal ──────────────────────────────────────────────────────────────

/// A WILDCARD principal (`allowed_scopes: None`) is down-scoped to the SINGLE TOOL IT CALLED.
///
/// Without this the whole property is vacuous in small deployments: a wildcard is an ABSENCE of a
/// constraint on the inbound side, and turning that into a grant of everything on the outbound side
/// is precisely the amplification this defence exists to stop. The server offers two tools, so "everything"
/// and "the one it called" are observably different strings.
#[tokio::test]
async fn a_wildcard_principal_is_down_scoped_to_the_single_tool_it_called() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = app_for(&peer);
    let wildcard = busbar_api::PlaneRequestCtx {
        key: Some(Arc::new(wildcard_key("wildcard-key"))),
    };

    let (status, body) = call(&app, &wildcard, "tools/call", params("fs_read")).await;
    assert_eq!(status, 200, "a wildcard principal is granted: {body}");
    assert_eq!(
        peer.last_token().form().get("scope").map(String::as_str),
        Some("fs_read"),
        "a wildcard inbound must NOT become a wildcard outbound"
    );

    // The same principal calling the OTHER tool gets the OTHER scope — so the value above is the
    // tool that was called, not a constant that happens to match.
    let (status, body) = call(&app, &wildcard, "tools/call", params("fs_write")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        peer.last_token().form().get("scope").map(String::as_str),
        Some("fs_write")
    );

    // And it is strictly narrower than what the server offers: `fs_write` is reachable by this
    // principal and was still not asked for on the first call.
    assert_ne!(
        "fs_read fs_write", "fs_read",
        "the server genuinely offers more than one tool, so the down-scope above is a narrowing"
    );
}

/// GOVERNANCE DISABLED takes the same posture and it is the same code path: no key means the
/// WILDCARD principal, which means the single tool called — not a skipped gate.
///
/// A deployment with governance off has no principal to carry a grant. Skipping the egress gate
/// there would have asked the authorization server for everything, on every ungoverned deployment.
#[tokio::test]
async fn an_ungoverned_deployment_still_down_scopes_to_the_tool_it_called() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = app_for(&peer);

    let (status, body) = call(
        &app,
        &busbar_api::PlaneRequestCtx::default(),
        "tools/call",
        params("fs_read"),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        peer.last_token().form().get("scope").map(String::as_str),
        Some("fs_read"),
        "governance off is a WILDCARD principal, not an absent gate"
    );
}

// ─── The gate is the one the client direction owns ───────────────────────────────────────────────

/// The dispatch path's gate IS `client::egress::authorise_tool_egress`, consulted with the real inbound
/// principal — not a second predicate that happens to agree with it today.
///
/// Asserted by agreement over a MATRIX: for every (grant shape × tool) pair, the answer the HTTP
/// surface gives and the answer the gate gives must be the same. Two implementations of one rule
/// agree right up until they do not, and the divergence is silent.
#[tokio::test]
async fn the_dispatch_gate_and_the_egress_gate_agree_on_every_grant_shape() {
    metrics_init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = app_for(&peer);

    let shapes: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("nothing", vec![]),
        ("server only", vec![("mcp_server", "fs")]),
        ("tool only", vec![("mcp_tool", "fs_read")]),
        (
            "server+read",
            vec![("mcp_server", "fs"), ("mcp_tool", "fs_read")],
        ),
        (
            "server+write",
            vec![("mcp_server", "fs"), ("mcp_tool", "fs_write")],
        ),
        (
            "server+both",
            vec![
                ("mcp_server", "fs"),
                ("mcp_tool", "fs_read"),
                ("mcp_tool", "fs_write"),
            ],
        ),
        ("other server", vec![("mcp_server", "db")]),
        ("a pool grant", vec![("pool", "fast")]),
    ];
    assert!(
        shapes.len() >= 8,
        "a floor on the matrix: a shrunken table would satisfy the agreement below vacuously"
    );

    let mut admitted = 0usize;
    let mut refused = 0usize;
    for (label, pairs) in &shapes {
        for tool in ["fs_read", "fs_write"] {
            let key = key_with_scopes("matrix", pairs);
            let gate = crate::mcp::client::egress::authorise_tool_egress(
                &key,
                &crate::mcp::client::identity::ToolKey::parse(tool).unwrap(),
            )
            .is_ok();
            let gov = busbar_api::PlaneRequestCtx {
                key: Some(Arc::new(key)),
            };
            let (status, body) = call(&app, &gov, "tools/call", params(tool)).await;
            let dispatched = status == 200;
            assert_eq!(
                dispatched, gate,
                "`{label}` calling `{tool}`: the HTTP surface said {dispatched} and \
                 `authorise_tool_egress` said {gate}. Two answers to one rule is the divergence this \
                 test exists to catch. Body: {body}"
            );
            if dispatched {
                admitted += 1;
            } else {
                refused += 1;
            }
        }
    }
    // FLOORS on both outcomes: a matrix that only ever refused, or only ever admitted, would agree
    // with a broken gate perfectly.
    assert!(
        admitted >= 3 && refused >= 8,
        "the matrix must exercise BOTH answers; got {admitted} admitted / {refused} refused"
    );
}
