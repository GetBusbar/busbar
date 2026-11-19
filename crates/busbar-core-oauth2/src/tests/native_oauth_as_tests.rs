// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The authorization server's public endpoints as the NATIVE data listener serves them: a core
//! route declared `RouteAuth::None` is completed public (`CompletingPhysicalRequest::complete_public`)
//! and answered from the request the listener captured (`ChargedRequestSnapshot`), projected back to
//! HTTP by `HttpProjection::from_snapshot` with the snapshot's own body. Each request here is made
//! exactly that way and handed to what the mounted route runs (`routes::forward`: the plane's
//! `handle`). Registration (RFC 7591), a client ID metadata document client (CIMD) and the token
//! endpoint are served; PKCE, the exact redirect and the registration ceiling still refuse.

use std::sync::Arc;

use busbar_kernel::inbound::http_projection::HttpProjection;
use busbar_kernel::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission, RequestLease};
use oauth_as::client::ClientId;
use serde_json as json;

use crate::config::OauthAsCfg;

const ISSUER: &str = "https://as.example.com";
const SCOPE: &str = "read";
const REDIRECT_URI: &str = "http://127.0.0.1:9999/cb";
const VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const CIMD_CLIENT_ID: &str = "https://client.example/oauth-client";

async fn plane() -> Arc<crate::plane::AsPlane> {
    let config = OauthAsCfg {
        issuer: ISSUER.into(),
        default_grant: vec![SCOPE.into()],
        ..Default::default()
    };
    let block = busbar_contract::yaml::to_value(
        config.authoring(&busbar_kernel::test_hooks::tokens::seal()),
    )
    .expect("owner config serializes");
    crate::plane::seam_build::<crate::NoConnections>(
        block,
        Vec::new(),
        Vec::new(),
        None,
        crate::testkit::memory_store().await,
        crate::testkit::ADMIN_ORIGIN.to_string(),
    )
    .await
    .expect("the owner seam builds over the store")
    .downcast::<crate::plane::AsPlane>()
    .unwrap_or_else(|_| panic!("the owner seam returns its plane"))
}

/// One request as the native listener holds it: captured whole under a data lease, then projected
/// back to HTTP with the snapshot's own body (`PhysicalPublicExecution::http_response`). The lease
/// is returned with it: the snapshot's bytes are charged to it for the request's life.
fn native(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (RequestLease, http::Request<axum::body::Body>) {
    let budget = ProcessAdmission::with_limits(4, 1 << 20, 0);
    let lease = budget
        .try_enter(AdmissionClass::Data)
        .expect("a data lease under an empty budget");
    let fields: Vec<(&str, &[u8])> = headers
        .iter()
        .map(|(name, value)| (*name, value.as_bytes()))
        .collect();
    let snapshot = ChargedRequestSnapshot::capture(
        SnapshotInput {
            method,
            path,
            query: query.unwrap_or_default(),
            query_present: query.is_some(),
            authority: "as.example.com",
            headers: fields.iter().copied(),
            peer: "192.0.2.7:50000",
            tls_peer_cert: &[],
            body,
            now_s: 0,
        },
        &lease,
    )
    .expect("the request is captured");
    let request = HttpProjection::from_snapshot(Arc::clone(&snapshot))
        .expect("the snapshot projects")
        .into_request(axum::body::Body::from(snapshot.body_bytes()));
    (lease, request)
}

/// What the mounted route answers the native request: the plane's own `handle`, as `forward` runs it.
async fn served(
    plane: &crate::plane::AsPlane,
    (lease, request): (RequestLease, http::Request<axum::body::Body>),
) -> (u16, json::Value) {
    let response = plane.handle(request).await;
    drop(lease);
    let status = response.status().as_u16();
    let bytes = response.into_body().into_bytes();
    let value = json::from_slice(&bytes).unwrap_or(json::Value::Null);
    (status, value)
}

fn form(pairs: &[(&str, &str)]) -> Vec<u8> {
    form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs)
        .finish()
        .into_bytes()
}

/// A code for `client_id` approved by the operator, with PKCE S256 over [`VERIFIER`].
async fn approved_code(plane: &crate::plane::AsPlane, client_id: &str) -> String {
    let request = oauth_as::authorization::AuthorizationRequest::from_pairs([
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", REDIRECT_URI),
        ("code_challenge", CHALLENGE),
        ("code_challenge_method", "S256"),
    ]);
    let validated = plane
        .server()
        .validate_authorization_request(&request)
        .await
        .expect("the request validates");
    plane
        .server()
        .issue_authorization_code(oauth_as::server::UserApproval::granted(
            &validated,
            "busbar-operator",
        ))
        .await
        .expect("the approved request mints a code")
        .code
}

/// The token endpoint, over the native projection, for an authorization code.
async fn exchange(
    plane: &crate::plane::AsPlane,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    verifier: Option<&str>,
) -> (u16, json::Value) {
    let mut pairs = vec![
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];
    if let Some(verifier) = verifier {
        pairs.push(("code_verifier", verifier));
    }
    let body = form(&pairs);
    served(
        plane,
        native(
            "POST",
            plane.identity().token_path(),
            None,
            &[("content-type", "application/x-www-form-urlencoded")],
            &body,
        ),
    )
    .await
}

async fn register(plane: &crate::plane::AsPlane, document: &json::Value) -> (u16, json::Value) {
    let body = document.to_string();
    served(
        plane,
        native(
            "POST",
            plane.identity().register_path(),
            None,
            &[("content-type", "application/json")],
            body.as_bytes(),
        ),
    )
    .await
}

#[tokio::test]
async fn native_oauth_as_serves_metadata_registration_and_the_token_endpoint() {
    crate::testkit::install_test_seam();
    let plane = plane().await;

    let (status, metadata) = served(
        &plane,
        native("GET", plane.identity().metadata_path(), None, &[], b""),
    )
    .await;
    assert_eq!(status, 200, "RFC 8414 metadata is served: {metadata}");
    assert_eq!(metadata["issuer"], ISSUER);
    assert_eq!(
        metadata["code_challenge_methods_supported"],
        json::json!(["S256"]),
        "OAuth 2.1 s4.1.1: PKCE S256 is the one method advertised"
    );
    assert!(
        metadata["registration_endpoint"].is_string(),
        "RFC 7591 registration is advertised: {metadata}"
    );

    let (status, registered) = register(
        &plane,
        &json::json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code", "refresh_token"],
            "client_name": "an agent",
        }),
    )
    .await;
    assert_eq!(status, 201, "a registration is admitted: {registered}");
    let client_id = registered["client_id"]
        .as_str()
        .expect("the registration answers its client_id")
        .to_string();

    let code = approved_code(&plane, &client_id).await;
    let (status, token) = exchange(&plane, &client_id, &code, REDIRECT_URI, Some(VERIFIER)).await;
    assert_eq!(
        status, 200,
        "the code exchanges at the token endpoint: {token}"
    );
    let access = token["access_token"]
        .as_str()
        .expect("the token response carries an access token");
    let live = plane
        .server()
        .introspect(access)
        .await
        .expect("introspection answers")
        .expect("the token just minted is live");
    assert_eq!(live.client_id.as_str(), client_id);
}

#[tokio::test]
async fn native_oauth_as_admits_a_metadata_document_client_at_the_token_endpoint() {
    crate::testkit::install_test_seam();
    let plane = plane().await;
    plane
        .server()
        .store()
        .set_fetcher(Arc::new(DocumentHost(json::json!({
            "client_id": CIMD_CLIENT_ID,
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "client_name": "an agent",
            "scope": SCOPE,
        }))));
    let code = approved_code(&plane, CIMD_CLIENT_ID).await;
    let (status, token) =
        exchange(&plane, CIMD_CLIENT_ID, &code, REDIRECT_URI, Some(VERIFIER)).await;
    assert_eq!(
        status, 200,
        "the metadata document client exchanges its code: {token}"
    );
    let live = plane
        .server()
        .introspect(token["access_token"].as_str().expect("an access token"))
        .await
        .expect("introspection answers")
        .expect("the token just minted is live");
    assert_eq!(
        live.client_id,
        ClientId::new(CIMD_CLIENT_ID),
        "the document's URL is the client's identity, verbatim"
    );
}

#[tokio::test]
async fn native_oauth_as_still_refuses_what_oauth_2_1_refuses() {
    crate::testkit::install_test_seam();
    let plane = plane().await;
    let (status, registered) = register(
        &plane,
        &json::json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "client_name": "an agent",
        }),
    )
    .await;
    assert_eq!(status, 201, "{registered}");
    let client_id = registered["client_id"]
        .as_str()
        .expect("client_id")
        .to_string();

    // OAuth 2.1 s4.1.3: a code issued with a challenge is never exchanged without its verifier.
    let code = approved_code(&plane, &client_id).await;
    let (status, refused) = exchange(&plane, &client_id, &code, REDIRECT_URI, None).await;
    assert_eq!(status, 400, "no code_verifier: {refused}");
    let code = approved_code(&plane, &client_id).await;
    let (status, refused) = exchange(
        &plane,
        &client_id,
        &code,
        REDIRECT_URI,
        Some("a-verifier-that-is-not-the-one-the-challenge-was-made-from-at-all"),
    )
    .await;
    assert_eq!(status, 400, "a wrong code_verifier: {refused}");

    // OAuth 2.1 s4.1.3: the redirect_uri is the one the code was issued for, compared exactly.
    let code = approved_code(&plane, &client_id).await;
    let (status, refused) = exchange(
        &plane,
        &client_id,
        &code,
        "http://127.0.0.1:9999/cb/",
        Some(VERIFIER),
    )
    .await;
    assert_eq!(
        status, 400,
        "a redirect_uri that is not the exact one: {refused}"
    );

    // The registration ceiling: a self-registered client may ask for no scope beyond default_grant.
    let (status, refused) = register(
        &plane,
        &json::json!({
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "client_name": "an agent",
            "scope": "read admin",
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "a scope over the ceiling is refused: {refused}"
    );
}

struct DocumentHost(json::Value);

impl crate::cimd::CimdFetch for DocumentHost {
    fn fetch<'a>(
        &'a self,
        url: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send + 'a>>
    {
        Box::pin(async move {
            if url == CIMD_CLIENT_ID {
                Ok(json::to_vec(&self.0).expect("the document serialises"))
            } else {
                Err(format!("no document at `{url}`"))
            }
        })
    }
}
