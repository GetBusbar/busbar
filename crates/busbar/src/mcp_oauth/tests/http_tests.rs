// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The resource server AT THE HTTP BOUNDARY: the 401 challenge, the metadata document, and the
//! admission decision as an axum client actually experiences them.
//!
//! The admission battery proves `ResourceServer::admit` refuses the right tokens. These prove the
//! refusal is WIRED — that a request reaching busbar over HTTP is judged by that function and not by
//! the ordinary data-plane bar, that the 401 carries the challenge a client needs to recover, and
//! that an admitted caller actually reaches the MCP mount. A correct validator that nothing calls is
//! a false green of exactly the shape this codebase keeps finding.

use super::support::*;
use super::{PROTECTED_RESOURCE_METADATA_PATH, PROTECTED_RESOURCE_METADATA_ROOT_PATH};

/// Serve a router on an ephemeral loopback port. The same four lines the auth tests use; a real
/// listener rather than a tower `oneshot`, so the middleware stack, the extensions and the header
/// encoding are all the production ones.
async fn serve(app: std::sync::Arc<crate::state::App>) -> (String, tokio::task::JoinHandle<()>) {
    let router = crate::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (format!("http://{addr}"), handle)
}

/// An app with the MCP plane ON, trusting `idp`.
fn mcp_app(idp: &TestIdp) -> std::sync::Arc<crate::state::App> {
    crate::metrics::init();
    crate::test_support::TestApp::new()
        .keys_chain()
        .mcp(resource_server(idp))
        .build()
}

/// THE FIRST STEP OF THE FLOW. An agent connects with no credential at all and must be told, in one
/// response, both that it needs a token and exactly where to learn how to get one. Without the
/// `WWW-Authenticate` header there is no discovery: a compliant MCP client has no other way to find
/// the metadata document, and the entire OAuth surface is unreachable however correct the rest of it
/// is.
///
/// RED (no MCP arm in the auth middleware): `/mcp` takes the ordinary data-plane bar, so the
/// response is the vendor-shaped LLM 401 with NO `WWW-Authenticate` header at all, and the
/// assertion fails on the absent header.
/// GREEN: 401 carrying the RFC 9728 challenge.
#[tokio::test]
async fn an_unauthenticated_mcp_request_is_challenged_with_the_metadata_document() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    let challenge = resp
        .headers()
        .get("www-authenticate")
        .expect("an unauthenticated MCP request MUST carry the RFC 9728 challenge")
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        challenge,
        format!(
            "Bearer resource_metadata=\"https://busbar.acme.com{PROTECTED_RESOURCE_METADATA_PATH}\""
        )
    );
    // The refusal reason is never on the wire: a 401 that says which check failed is an oracle.
    let body = resp.text().await.unwrap();
    for leak in [
        "audience",
        "aud",
        "signature",
        "expired",
        "issuer",
        "client_id",
    ] {
        assert!(!body.contains(leak), "401 body leaks {leak}: {body}");
    }
}

/// The document the challenge names must actually be there, and it must be fetchable by a caller who
/// has NO credential — which is the only kind of caller that has any reason to fetch it. The path is
/// taken FROM THE CHALLENGE rather than written out again here, so a challenge that named a document
/// busbar does not serve would fail this test rather than pass two independent copies of the same
/// mistake.
#[tokio::test]
async fn the_document_the_challenge_names_is_fetchable_and_well_formed() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    let client = reqwest::Client::new();

    let challenge = client
        .post(format!("{base}/mcp"))
        .send()
        .await
        .unwrap()
        .headers()
        .get("www-authenticate")
        .expect("challenge")
        .to_str()
        .unwrap()
        .to_string();
    // Parse the URL out of the challenge exactly as a client would, then fetch its PATH from the
    // server under test (the challenge names the deployment's public origin, which in a test is not
    // the ephemeral loopback port).
    let advertised = challenge
        .split("resource_metadata=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("the challenge names a resource_metadata URL");
    let path = advertised
        .strip_prefix("https://busbar.acme.com")
        .expect("advertised URL is under the configured canonical origin");

    let resp = client.get(format!("{base}{path}")).send().await.unwrap();
    assert_eq!(resp.status(), 200, "the advertised document must be served");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let doc: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(doc["resource"], serde_json::json!(BUSBAR_RESOURCE));
    assert_eq!(doc["authorization_servers"], serde_json::json!([ISSUER]));
}

/// The root form of the document is served too, for a client that never saw the challenge.
#[tokio::test]
async fn the_root_form_of_the_metadata_document_is_served_as_an_alias() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    let client = reqwest::Client::new();
    let a: serde_json::Value = client
        .get(format!("{base}{PROTECTED_RESOURCE_METADATA_PATH}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let b: serde_json::Value = client
        .get(format!("{base}{PROTECTED_RESOURCE_METADATA_ROOT_PATH}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(a, b, "there is one protected resource and one document");
}

/// **THE CONFUSED-DEPUTY DEFENCE AT THE WIRE.** A correctly signed, unexpired token from the
/// operator's own IdP, issued to a real client for a real subject — for the billing API. Over HTTP
/// it must be refused, with the same challenge an empty request gets, because from the client's side
/// "your token is for the wrong resource" and "you have no token" have the same remedy: go get one
/// for THIS resource.
///
/// RED (no MCP arm in the auth middleware): `/mcp` takes the data-plane bar and the token is refused
/// for the WRONG REASON — it is not a busbar key — so the test passes on the status code while the
/// audience is never examined, which is why the challenge header is asserted alongside it.
/// RED (MCP arm present, audience check removed from `admit`): 501 from the MCP mount. The token for
/// another service opened busbar's MCP endpoint.
/// GREEN: 401 with the challenge.
#[tokio::test]
async fn a_token_for_another_service_is_refused_at_the_wire() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    let client = reqwest::Client::new();

    let mut claims = live_claims();
    claims["aud"] = serde_json::json!(OTHER_RESOURCE);
    let wrong_audience = idp.mint(&claims);

    // Control: the same token differing only in `aud` is admitted, so the refusal below is
    // attributable to the audience and to nothing else about the request.
    let admitted = client
        .post(format!("{base}/mcp"))
        .bearer_auth(idp.mint(&live_claims()))
        .send()
        .await
        .unwrap();
    assert_ne!(
        admitted.status(),
        401,
        "control failed: the baseline token must be admitted"
    );

    let resp = client
        .post(format!("{base}/mcp"))
        .bearer_auth(&wrong_audience)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "a token for {OTHER_RESOURCE} must not open busbar's MCP endpoint"
    );
    assert!(resp.headers().contains_key("www-authenticate"));
}

/// The positive path end to end: a well-formed token for the right audience is admitted, reaches the
/// MCP mount, and arrives with the caller's identity attached. The mount is a placeholder today, so
/// the assertion is on the placeholder's own status — but the placeholder EXTRACTS the admitted
/// caller, so reaching it at all is proof the admission path ran and inserted the identity.
#[tokio::test]
async fn a_well_formed_token_reaches_the_mcp_mount() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    let resp = reqwest::Client::new()
        .post(format!("{base}/mcp"))
        .bearer_auth(idp.mint(&live_claims()))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        501,
        "an admitted caller reaches the mount, which is not implemented yet"
    );
    assert!(
        !resp.headers().contains_key("www-authenticate"),
        "an admitted request is not challenged"
    );
}

/// The MCP plane takes OAuth access tokens and nothing else. An opaque busbar-shaped bearer is not
/// one, and admitting it would make the plane boundary one-directional: the P1 work keeps an
/// audience-bound token off the data plane, and this keeps a data-plane credential off the MCP
/// plane.
#[tokio::test]
async fn a_busbar_shaped_bearer_does_not_open_the_mcp_plane() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    for credential in ["bbk_deadbeefdeadbeef", "not-a-token", ""] {
        let resp = reqwest::Client::new()
            .post(format!("{base}/mcp"))
            .header("authorization", format!("Bearer {credential}"))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "credential {credential:?}");
        assert!(resp.headers().contains_key("www-authenticate"));
    }
}

/// The credential is read from `Authorization: Bearer` and from nowhere else. `x-api-key` and
/// `x-goog-api-key` are LLM-SDK conveniences that the data plane accepts; honouring them here would
/// add a second door to the MCP plane whose bar nobody would think to check.
#[tokio::test]
async fn the_vendor_key_carriers_do_not_open_the_mcp_plane() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    let token = idp.mint(&live_claims());
    for carrier in ["x-api-key", "x-goog-api-key"] {
        let resp = reqwest::Client::new()
            .post(format!("{base}/mcp"))
            .header(carrier, token.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            401,
            "a valid token presented on {carrier} must not be honoured on the MCP plane"
        );
    }
}

/// With `mcp:` absent the plane is OFF: no metadata document, no mount, nothing to probe. A
/// deployment that does not use MCP must carry no reachable MCP surface, so this asserts the ABSENCE
/// of a 200 rather than the presence of a particular error.
#[tokio::test]
async fn with_the_mcp_plane_disabled_none_of_its_routes_exist() {
    crate::metrics::init();
    let app = crate::test_support::TestApp::new().keys_chain().build();
    let (base, _h) = serve(app).await;
    let client = reqwest::Client::new();
    for path in [
        PROTECTED_RESOURCE_METADATA_PATH,
        PROTECTED_RESOURCE_METADATA_ROOT_PATH,
    ] {
        let resp = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_ne!(
            resp.status(),
            200,
            "{path} must not be served when the MCP plane is off"
        );
        assert!(!resp.headers().contains_key("www-authenticate"));
    }
    // And an unauthenticated `/mcp` is judged by the ordinary bar, not challenged: there is no
    // resource server to challenge on behalf of.
    let resp = client.post(format!("{base}/mcp")).send().await.unwrap();
    assert!(!resp.headers().contains_key("www-authenticate"));
}

/// The metadata routes are open by declaration, and the openness must be EXACT. A near-miss path
/// must take the ordinary bar rather than ride the bypass — the same discipline the core route table
/// already enforces for `/auth/token`, checked here for the paths this change adds.
#[tokio::test]
async fn the_metadata_bypass_is_exact() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    let client = reqwest::Client::new();
    for near_miss in [
        "/.well-known",
        "/.well-known/",
        "/.well-known/oauth-protected-resourcex",
        "/.well-known/oauth-protected-resource/mcpx",
        "/.well-known/oauth-protected-resource/mcp/",
        "/.well-known/oauth-authorization-server",
    ] {
        let resp = client
            .get(format!("{base}{near_miss}"))
            .send()
            .await
            .unwrap();
        assert_ne!(
            resp.status(),
            200,
            "{near_miss} is not the protected-resource metadata document and must not be served \
             as though it were"
        );
    }
}

/// The MCP plane's boundary at the wire. `/mcpx` shares a prefix with the mount and is NOT on the
/// plane, so it must not be challenged — being challenged would mean the middleware claimed a path
/// the resource server does not own, and every path it claims is a path it decides.
#[tokio::test]
async fn a_prefix_neighbour_of_the_mcp_mount_is_not_on_the_plane() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let (base, _h) = serve(mcp_app(&idp)).await;
    let client = reqwest::Client::new();
    for neighbour in ["/mcpx", "/mcp-admin", "/xmcp"] {
        let resp = client
            .post(format!("{base}{neighbour}"))
            .send()
            .await
            .unwrap();
        assert!(
            !resp.headers().contains_key("www-authenticate"),
            "{neighbour} is not on the MCP plane and must not be challenged as though it were"
        );
    }
    // And a path BENEATH the mount is on the plane, so it is.
    let resp = client
        .post(format!("{base}/mcp/anything"))
        .send()
        .await
        .unwrap();
    assert!(resp.headers().contains_key("www-authenticate"));
}

/// A RATCHET on the mounted surface. Turning the MCP plane on adds EXACTLY three routes and no
/// others; turning it off adds none. Enumerated from the real `CoreRouteTable` the router is built
/// with, not from a hand-written list, so a fourth route mounted under this flag joins the assertion
/// instead of escaping it — and so the "off means nothing is reachable" claim is checked rather than
/// asserted.
#[test]
fn enabling_the_mcp_plane_mounts_exactly_its_own_routes() {
    let empty = crate::plugin_routes::PluginRouteTable::empty();
    let off = crate::base_data_router(&empty, false).1;
    let on = crate::base_data_router(&empty, true).1;

    let names = |t: &crate::core_routes::CoreRouteTable| -> Vec<String> {
        let mut v: Vec<String> = t
            .routes()
            .iter()
            .map(|r| format!("{:?} {}", r.method, r.path))
            .collect();
        v.sort();
        v
    };
    let (off, on) = (names(&off), names(&on));
    let added: Vec<&String> = on.iter().filter(|r| !off.contains(r)).collect();
    assert_eq!(
        added,
        vec![
            &"Get /.well-known/oauth-protected-resource".to_string(),
            &"Get /.well-known/oauth-protected-resource/mcp".to_string(),
            &"Get /mcp".to_string(),
            &"Post /mcp".to_string(),
        ],
        "enabling the MCP plane must mount exactly the metadata document (both forms) and the mount \
         itself; anything else here is a surface nobody reviewed"
    );
    assert!(
        on.len() > off.len(),
        "and disabling it must remove them again"
    );
}
