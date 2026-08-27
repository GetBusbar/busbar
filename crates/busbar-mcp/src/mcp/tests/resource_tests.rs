// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OAuth 2.1 resource-server surface: the RFC 9728 metadata document, and the RFC 6750 `401`
//! challenge that points a credential-less client at it.
//!
//! ## Why this is the part worth testing hardest
//!
//! Nothing else tests it. The official MCP conformance suite has ZERO server-side auth scenarios —
//! its `auth/*` scenarios are all client-side, and its `authorization` subcommand tests a
//! third-party authorization server rather than a resource server. So `401` + `WWW-Authenticate`,
//! the protected-resource metadata document, and RFC 8707 audience rejection are covered by nothing
//! in the ecosystem. That makes this the one area where writing our own tests strictly beats
//! adopting somebody else's, and it is also the area where a silent regression would be invisible
//! until an agent could not log in.
//!
//! Every test here runs against a CLOSED chain (`keys_chain` + governance), because the whole
//! question is what an unauthenticated caller receives.

use crate::mcp::McpCfg;
use crate::testkit::TestAppMcpExt;
use busbar_core::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const ISSUER: &str = "https://login.example.com";
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";

async fn serve() -> (String, tokio::task::JoinHandle<()>) {
    use busbar_core::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_core::governance::{GovState, MemoryStore};
    use std::sync::Arc;

    busbar_core::metrics::init();
    let gov = Arc::new(
        GovState::new_with_signer(
            Arc::new(MemoryStore::new()),
            Some("admintok".to_string()),
            Some(TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID)),
        )
        .unwrap(),
    );
    let app = TestApp::new()
        .keys_chain()
        .governance(gov)
        .mcp(&McpCfg {
            canonical_uri: CANONICAL.to_string(),
            authorization_servers: vec![ISSUER.to_string()],
            scopes_supported: vec!["mcp:tools:list".to_string(), "mcp:tools:call".to_string()],
            allowed_origins: Vec::new(),
        })
        .build();
    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

/// THE DISCOVERY LOOP, end to end, as a client with no prior configuration walks it.
///
/// This is one test rather than three because the value is in the JOIN: the URL in the challenge
/// must be the URL that serves the document, and the `resource` in the document must be the audience
/// the verifier enforces. Three separate tests would each pass while the three values disagreed,
/// which is precisely the failure that makes every correctly-behaved client in the world obtain a
/// token this server then refuses.
#[tokio::test]
async fn a_credential_less_client_can_walk_from_the_401_to_the_metadata_document() {
    let (base, h) = serve().await;
    let client = reqwest::Client::new();

    // Step 1: connect with no credential.
    let resp = client
        .post(format!("{base}/mcp"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .expect("a 401 from an OAuth resource server MUST carry a challenge")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        challenge.starts_with("Bearer "),
        "the challenge scheme must be Bearer: {challenge}"
    );
    assert!(
        !challenge.contains("error="),
        "no credential was presented, so RFC 6750 §3.1 says the challenge omits `error` — \
         `invalid_token` would tell the client its token was bad when it had none: {challenge}"
    );

    // Step 2: follow `resource_metadata` out of the challenge. The client reads the URL from the
    // header rather than reconstructing it, which is the point of the parameter existing.
    let url = challenge
        .split("resource_metadata=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("the challenge must carry a resource_metadata parameter");
    assert!(
        url.ends_with(METADATA_PATH),
        "RFC 9728 §3.1 inserts the well-known prefix BEFORE the resource path; got {url}"
    );

    // The absolute URL points at THIS deployment's canonical origin, and the document is served at
    // the path it names — fetched through the served router, so the assertion is about the mounted
    // surface rather than about a string.
    let doc: serde_json::Value = client
        .get(format!("{base}{METADATA_PATH}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Step 3: the document says what to ask for, and it is the exact value the verifier compares
    // against.
    assert_eq!(doc["resource"], CANONICAL);
    assert_eq!(doc["authorization_servers"], serde_json::json!([ISSUER]));
    assert_eq!(
        doc["bearer_methods_supported"],
        serde_json::json!(["header"]),
        "a token in a query string lands in access logs, proxy logs and Referer headers; the \
         document must say header-only rather than leave a client to discover it by rejection"
    );
    assert_eq!(
        doc["scopes_supported"],
        serde_json::json!(["mcp:tools:list", "mcp:tools:call"])
    );
    h.abort();
}

/// The metadata document is READABLE WITHOUT CREDENTIALS, on a deployment whose chain is otherwise
/// closed. It must be: every caller who needs it is by definition one that does not have a token
/// yet, so requiring one is a discovery loop with no entrance.
#[tokio::test]
async fn the_metadata_document_is_public_on_an_otherwise_closed_deployment() {
    let (base, h) = serve().await;
    let client = reqwest::Client::new();
    // Control: the same deployment refuses an unauthenticated request everywhere else, so the 200
    // below is a property of this route rather than of an open server.
    assert_eq!(
        client
            .get(format!("{base}/stats"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401,
        "the deployment must otherwise be closed, or this test asserts nothing"
    );
    let resp = client
        .get(format!("{base}{METADATA_PATH}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json")));
    h.abort();
}

/// The openness is EXACT. `/.well-known/` is not a prefix that grants anything: a free pass matching
/// a prefix would hand one to every path beneath it, which is the discipline the core route table
/// exists to hold. Every near miss below takes the normal bar.
#[tokio::test]
async fn the_public_metadata_route_is_an_exact_path_and_grants_no_neighbours() {
    let (base, h) = serve().await;
    let client = reqwest::Client::new();
    for near in [
        "/.well-known",
        "/.well-known/",
        "/.well-known/oauth-protected-resource",
        "/.well-known/oauth-protected-resource/",
        "/.well-known/oauth-protected-resource/mcp/",
        "/.well-known/oauth-protected-resource/mcpx",
        "/.well-known/oauth-protected-resource/mcp/../../stats",
        "/.well-known/oauth-authorization-server",
        "/.WELL-KNOWN/OAUTH-PROTECTED-RESOURCE/MCP",
    ] {
        let status = client
            .get(format!("{base}{near}"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16();
        assert_ne!(
            status, 200,
            "`{near}` is not the declared-open metadata path and must not be served as it"
        );
    }
    h.abort();
}

/// THE CONFUSED-DEPUTY TEST, and the only one in this file whose subject is core rather than the
/// protocol.
///
/// The chain here is the TEST OIDC STAND-IN, which identifies any non-empty credential and asks
/// nothing about audience — which is not a weakness of the fixture, it is what the plugin ABI makes
/// every real auth plugin: `AuthOutcome` has no shape for "and it was minted for you". So this app
/// WOULD admit the foreign token if core did not refuse it first, and that is what makes the
/// assertion load-bearing. Run the same case against a keys-only chain and it passes whether or not
/// the audience is ever checked, because a keys chain refuses a non-busbar token for an unrelated
/// reason.
///
/// The token below is one an operator's IdP legitimately issued and correctly signed — for their
/// wiki. Nothing about it is malformed. It is simply not ours.
#[tokio::test]
async fn a_token_minted_for_another_resource_is_refused_even_when_the_chain_would_admit_it() {
    use base64::Engine as _;
    busbar_core::metrics::init();
    let app = TestApp::new()
        .idp_chain()
        .mcp(&McpCfg {
            canonical_uri: CANONICAL.to_string(),
            authorization_servers: vec![ISSUER.to_string()],
            scopes_supported: Vec::new(),
            allowed_origins: Vec::new(),
        })
        .build();
    let router = busbar_core::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let b64 = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    let jwt = |claims: &str| {
        format!(
            "{}.{}.{}",
            b64(br#"{"alg":"RS256"}"#),
            b64(claims.as_bytes()),
            b64(b"sig")
        )
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion":
                    crate::mcp::envelope::PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let call = |tok: String| {
        let client = client.clone();
        let body = body.clone();
        async move {
            client
                .post(format!("http://{addr}/mcp"))
                .header("authorization", format!("Bearer {tok}"))
                .header(
                    "mcp-protocol-version",
                    crate::mcp::envelope::PROTOCOL_VERSION,
                )
                .header("mcp-method", "tools/list")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // THE CONTROL, and it comes first because without it the refusals below prove only that this
    // deployment refuses everything. A token naming THIS resource is admitted and reaches the MCP
    // handler, which answers `tools/list` with the (empty, on this deployment) grant-scoped
    // catalogue. It used to answer 404/-32601 because no method was implemented; the assertion moved
    // with the surface, and it is still the same control.
    let ours = call(jwt(&format!(r#"{{"aud":"{CANONICAL}","sub":"alice"}}"#))).await;
    assert_eq!(
        ours.status().as_u16(),
        200,
        "a token minted for this resource must be admitted and reach the MCP handler — without \
         this the refusals below are indistinguishable from a closed door"
    );

    // The refusals. Every one is a token the operator's IdP would happily vouch for.
    for (label, claims) in [
        (
            "minted for the operator's wiki",
            r#"{"aud":"https://wiki.example.com","sub":"alice"}"#.to_string(),
        ),
        (
            "an audience array that does not include us",
            r#"{"aud":["https://wiki.example.com","https://ci.example.com"]}"#.to_string(),
        ),
        ("no audience at all", r#"{"sub":"alice"}"#.to_string()),
        (
            "a near miss on our own canonical URI",
            format!(r#"{{"aud":"{CANONICAL}-staging"}}"#),
        ),
    ] {
        let resp = call(jwt(&claims)).await;
        assert_eq!(
            resp.status().as_u16(),
            401,
            "a token {label} must be refused: the chain vouches for the signature, and only core \
             can say it was not minted for us"
        );
        let challenge = resp
            .headers()
            .get("www-authenticate")
            .expect("the refusal must carry a challenge")
            .to_str()
            .unwrap();
        assert!(
            challenge.contains("error=\"invalid_token\""),
            "a token {label} was presented and failed, which is `invalid_token`, not a bare \
             challenge: {challenge}"
        );
        assert!(challenge.contains("resource_metadata="));
    }

    // An OPAQUE reference token: nothing to read, so nothing can establish it was minted for us.
    // The honest answer to "I cannot tell" on a confused-deputy defence is refusal.
    let opaque = call("0f6d2a9c-3b1e-4f77-9a2e-8c5d1e0b7a44".to_string()).await;
    assert_eq!(
        opaque.status().as_u16(),
        401,
        "an opaque token carries no audience and must not be admitted on an audience-bound plane"
    );
    h.abort();
}

/// The challenge is built, not formatted: a value carrying a quote, a backslash or a control
/// character must not be able to terminate the quoted-string and rewrite the rest of the header.
/// Operator config rather than caller input, so this is defence in depth — and it costs one
/// function.
#[test]
fn challenge_values_cannot_escape_their_quoted_string() {
    use busbar_core::auth::challenge::{www_authenticate, ChallengeError};
    let hostile = "https://h.example/\"x\\y\r\nInjected: yes";
    let v = www_authenticate(ChallengeError::InvalidToken, hostile, None, None);
    assert!(
        !v.contains('\r') && !v.contains('\n'),
        "a control character must never survive into a header value: {v}"
    );
    assert!(
        v.contains("\\\"x\\\\y"),
        "the quote and backslash must be escaped rather than dropped, so the value a client reads \
         back is the value the operator configured: {v}"
    );
    // Exactly one quoted-string per parameter: an unbalanced count means one of them terminated
    // early and the rest of the header is being read as something it is not.
    assert_eq!(
        v.matches("=\"").count(),
        v.match_indices('"').count() / 2,
        "every parameter must open and close exactly one quoted-string: {v}"
    );
}

/// `insufficient_scope` is a `403`, never a `401`, and it carries the metadata URL like every other
/// challenge. Re-authenticating cannot fix a grant that does not cover the request, so answering
/// `401` would send the client round a loop that cannot terminate.
#[test]
fn insufficient_scope_is_a_403_and_still_names_the_metadata() {
    use busbar_core::auth::challenge::{refuse, ChallengeError};
    let resp = refuse(
        ChallengeError::InsufficientScope,
        "https://h.example/.well-known/oauth-protected-resource/mcp",
        "nope",
        Some("mcp:tools:call"),
    );
    assert_eq!(resp.status().as_u16(), 403);
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(challenge.contains("error=\"insufficient_scope\""));
    assert!(challenge.contains("scope=\"mcp:tools:call\""));
    assert!(challenge.contains("resource_metadata="));
}
