// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EPHEMERAL-SECRET MINT, SERVED — the browser `ek_` pass with a composed provider credential.
//!
//! Two halves, both load-bearing:
//!
//!  1. THE COMPOSITION SEAM. The composition root hands the plane a provider ORIGIN and the secret
//!     REFERENCE the deployment already declared for that provider, plus the deployment's own secret
//!     resolver. The plane resolves the reference through that seam and composes the endpoint — so a
//!     deployment's realtime credential arrives the same way every other provider key does, and the
//!     `streams:` grammar gains no credential field.
//!  2. THE SERVED MINT. With a provider composed, the mint pass no longer answers "no provider
//!     composed": it dials the provider's client-secrets endpoint under busbar's OWN key and answers
//!     `200` with the browser-facing ephemeral token shape (`value` + `expires_at_unix`).
//!
//! RED before the wiring: nothing composed a provider, so the mint route answered `501` on every
//! deployment and the real key never had a way in.

use crate::mount::{
    compose_provider, composed_provider_base_url, open_governed, provider_composed, GovernedOpen,
    Ingress, ProviderEndpoint,
};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::testkit::fixture_host::FixtureHost;
use std::sync::{Arc, Mutex};

/// The provider key busbar holds server-side — the value the loopback provider must be dialed with.
const PROVIDER_KEY: &str = "sk-realtime-key-held-server-side";
/// The browser-facing ephemeral secret the provider mints back.
const EK_VALUE: &str = "ek_browser_secret_2f4c";
/// The absolute expiry the provider stamps on that secret.
const EK_EXPIRES_AT: u64 = 1_780_000_600;

/// A loopback "provider" for `POST /v1/realtime/client_secrets`: it RECORDS the `Authorization` it was
/// dialed with and answers the provider's own client-secret document.
async fn spawn_client_secrets_provider(seen: Arc<Mutex<Option<String>>>) -> std::net::SocketAddr {
    async fn client_secrets(
        axum::extract::State(seen): axum::extract::State<Arc<Mutex<Option<String>>>>,
        headers: axum::http::HeaderMap,
    ) -> axum::response::Response {
        *seen.lock().unwrap() = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                serde_json::json!({ "value": EK_VALUE, "expires_at": EK_EXPIRES_AT }).to_string(),
            ))
            .unwrap()
    }
    let app = axum::Router::new()
        .route(
            "/v1/realtime/client_secrets",
            axum::routing::post(client_secrets),
        )
        .with_state(seen);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// A stand-in for the deployment's secret resolver: it answers one reference with one credential and
/// refuses everything else, so the test can tell "resolved through the seam" from "guessed".
struct OneSecretResolver {
    expect: busbar_api::SecretRef,
    value: String,
}

impl busbar_api::SecretResolve for OneSecretResolver {
    fn resolve(&self, secret: &busbar_api::SecretRef) -> Result<Vec<u8>, String> {
        self.resolve_string(secret).map(String::into_bytes)
    }
    fn resolve_string(&self, secret: &busbar_api::SecretRef) -> Result<String, String> {
        if secret == &self.expect {
            Ok(self.value.clone())
        } else {
            Err("no such secret reference in this deployment".to_string())
        }
    }
}

fn runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    )
}

#[tokio::test]
async fn a_composed_provider_credential_makes_the_mint_pass_serve_the_browser_token() {
    let seen_auth: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let addr = spawn_client_secrets_provider(Arc::clone(&seen_auth)).await;
    let host = FixtureHost::new().into_host();
    let rt = runtime();
    let provider = ProviderEndpoint {
        base_url: format!("http://{addr}"),
        api_key: PROVIDER_KEY.to_string(),
    };

    let resp = open_governed(GovernedOpen {
        rt: &rt,
        host,
        provider: Some(&provider),
        ingress: Ingress::Mint,
        owner: "acct-mint".to_string(),
        call_id: "call-mint".to_string(),
        vkey: None,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 7,
    })
    .await;

    assert_eq!(
        resp.status(),
        axum::http::StatusCode::OK,
        "with a provider credential composed, the mint pass serves rather than reporting no provider"
    );
    // The browser-facing payload: the ephemeral secret and its absolute expiry, and NOT the real key.
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["value"], EK_VALUE, "the browser gets the ek_ secret");
    assert_eq!(
        json["expires_at_unix"], EK_EXPIRES_AT,
        "the browser gets the secret's absolute expiry"
    );
    assert!(
        !String::from_utf8_lossy(&body).contains(PROVIDER_KEY),
        "the real provider key must never appear in the browser payload"
    );
    // The provider hop authenticated with busbar's OWN key, held server-side.
    assert_eq!(
        seen_auth.lock().unwrap().as_deref(),
        Some(format!("Bearer {PROVIDER_KEY}").as_str()),
        "the mint dials the provider under busbar's own credential"
    );
}

#[test]
fn the_composition_root_composes_the_provider_through_the_deployments_secret_resolver() {
    let reference = busbar_api::SecretRef::env("REALTIME_PROVIDER_KEY");
    let resolver = OneSecretResolver {
        expect: reference.clone(),
        value: PROVIDER_KEY.to_string(),
    };

    // A reference this deployment does NOT declare fails closed with the resolver's own message, and
    // composes nothing — an unresolvable credential must never become an empty one.
    let unknown = busbar_api::SecretRef::env("NOT_DECLARED_HERE");
    assert!(
        compose_provider("https://api.example.com", &unknown, &resolver).is_err(),
        "an unresolvable reference composes nothing"
    );
    assert!(
        !provider_composed(),
        "a failed resolve leaves the plane with no provider"
    );

    // The declared reference resolves through the seam and composes the endpoint the mint / SDP
    // passes read.
    assert_eq!(
        compose_provider("https://api.example.com", &reference, &resolver),
        Ok(true),
        "the declared provider credential composes"
    );
    assert!(
        provider_composed(),
        "the mint / SDP passes now have an endpoint"
    );
    assert_eq!(
        composed_provider_base_url(),
        Some("https://api.example.com"),
        "the composed origin is the one the deployment declared"
    );

    // Set-once: a second compose does not silently swap the deployment's credential.
    assert_eq!(
        compose_provider("https://other.example.com", &reference, &resolver),
        Ok(false),
        "the first composed endpoint stands"
    );
    assert_eq!(
        composed_provider_base_url(),
        Some("https://api.example.com"),
        "a second compose leaves the first endpoint in place"
    );
}
