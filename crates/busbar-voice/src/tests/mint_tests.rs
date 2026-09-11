// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EPHEMERAL-SECRET MINT, SERVED — the browser `ek_` pass with a composed provider credential.
//!
//! Two halves, both load-bearing:
//!
//!  1. THE COMPOSITION SEAM. The plane's own `build` is handed the deployment's model→upstream
//!     catalog and looks up the model ITS OWN section pins, so a deployment's realtime credential
//!     arrives the same way every other provider key does, on the slot of the generation that
//!     resolved it, and the `streams:` grammar gains no credential field.
//!  2. THE SERVED MINT. With a provider composed, the mint pass no longer answers "no provider
//!     composed": it dials the provider's client-secrets endpoint under busbar's OWN key and answers
//!     `200` with the browser-facing ephemeral token shape (`value` + `expires_at_unix`).
//!
//! RED before the wiring: nothing composed a provider, so the mint route answered `501` on every
//! deployment and the real key never had a way in.

use crate::mount::{open_governed, GovernedOpen, Ingress, ProviderEndpoint, VoiceMount as Door};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane::registry::{ResolvedUpstream, UpstreamCatalog};

/// The operator posture a node is built from — the section this declaration carries, spelled once.
type Posture = crate::config::StreamsCfg;
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

/// THE DEPLOYMENT'S MODEL→UPSTREAM CATALOG as the composition hands one to a plane's `build`: the
/// declared models, each with the origin and RESOLVED credential of the upstream serving it. A model
/// this deployment does not declare answers `Ok(None)`; one wired to an undeclared credential
/// reference answers `Err`, which is the fail-closed shape the real catalog gives a reference the
/// deployment's own resolver refuses.
struct Catalog(Vec<(&'static str, &'static str, &'static str)>);

impl UpstreamCatalog for Catalog {
    fn upstream_for_model(&self, model: &str) -> Result<Option<ResolvedUpstream>, String> {
        match self.0.iter().find(|(m, _, _)| *m == model) {
            None => Ok(None),
            Some((_, _, "")) => Err("no such credential reference in this deployment".to_string()),
            Some((_, base_url, api_key)) => Ok(Some(ResolvedUpstream {
                base_url: (*base_url).to_string(),
                api_key: (*api_key).to_string(),
            })),
        }
    }
}

/// ONE NODE, built the way the composition builds one: this deployment's own posture (pinning
/// `model`, or nothing) and this deployment's catalog, through the plane's own `build`.
fn node(model: Option<&str>, catalog: &Catalog) -> Arc<Door> {
    let mut written = Posture::default();
    written.session.model = model.map(str::to_string);
    crate::mount::mount_tests::slot_from(
        &[(crate::PLANE_DECL.config_section, &written)],
        Some("https://gw.example.com"),
        Some(catalog),
        &[],
        None,
    )
    .expect("a deployment with a receiving origin mounts")
    .downcast::<Door>()
    .expect("the slot this plane builds is its own mount")
}

/// TWO NODES BUILT IN ONE PROCESS, each pinning its own model, EACH DIAL THEIR OWN UPSTREAM.
///
/// RED before this seam: the endpoint was a process-wide set-once cell the root wrote AFTER the slot
/// was built, so the second node in a process read the FIRST node's origin and credential — measured,
/// `Some("https://a.example.com")` where the node's own configuration said `b`. A deployment could not
/// tell, because both nodes booted clean and both dialed something.
///
/// The fact is a fact of the generation that resolved it, so it rides that generation's slot: each
/// node's `build` looks its OWN section's model up in the deployment's catalog, and neither node can
/// reach the other's answer because neither answer is anywhere but on a slot.
#[test]
fn two_nodes_built_in_one_process_each_dial_their_own_provider() {
    let catalog = Catalog(vec![
        ("model-a", "https://a.example.com", "key-a"),
        ("model-b", "https://b.example.com", "key-b"),
    ]);

    let a = node(Some("model-a"), &catalog);
    let b = node(Some("model-b"), &catalog);

    assert_eq!(
        a.provider().map(|p| p.base_url.as_str()),
        Some("https://a.example.com"),
        "the first node dials the upstream serving the model its own section pinned"
    );
    assert_eq!(
        b.provider().map(|p| p.base_url.as_str()),
        Some("https://b.example.com"),
        "and the second dials ITS own, not whichever was resolved first in this process"
    );
    assert_eq!(
        b.provider().map(|p| p.api_key.as_str()),
        Some("key-b"),
        "credential and origin move together — no node dials one origin under another's key"
    );
    // The second dialect reads its own field, so a deployment cannot silently point one dialect's
    // traffic at the other's credential — and it is still this node's own entry, not the other's.
    assert_eq!(
        b.gemini_provider.as_ref().map(|p| p.base_url.as_str()),
        Some("https://b.example.com"),
        "the second-dialect endpoint is this generation's too"
    );
}

/// THE THREE WAYS A NODE RESOLVES NOTHING, and none of them is a dial with an empty credential.
///
/// A posture that pins no model asks the catalog nothing; a model this deployment does not declare
/// answers nothing; and a declared model whose credential reference will not resolve FAILS CLOSED —
/// the plane says so in its own words and composes nothing, so the mint / SDP passes keep answering
/// "governed, but no provider composed" rather than dialing under an empty key.
#[test]
fn a_node_that_resolves_no_provider_composes_none_rather_than_an_empty_credential() {
    let catalog = Catalog(vec![
        ("model-a", "https://a.example.com", "key-a"),
        // Declared here, but wired to a reference this deployment's resolver refuses.
        ("model-refused", "https://a.example.com", ""),
    ]);
    for (model, why) in [
        (None, "a posture that pins no model resolves nothing"),
        (
            Some("model-absent"),
            "a model this deployment does not declare resolves nothing",
        ),
        (
            Some("model-refused"),
            "a declared model whose credential will not resolve fails closed",
        ),
    ] {
        assert!(node(model, &catalog).provider().is_none(), "{why}");
    }
}

/// A NODE BUILT WITH NO CATALOG BEHIND IT resolves nothing and still mounts — the honest answer for a
/// context with no deployment catalog in it, and byte-identically what an uncomposed deployment got.
#[test]
fn a_node_built_with_no_catalog_resolves_no_provider_and_still_mounts() {
    let mut written = Posture::default();
    written.session.model = Some("model-a".to_string());
    let mount = crate::mount::mount_tests::slot_from(
        &[(crate::PLANE_DECL.config_section, &written)],
        Some("https://gw.example.com"),
        None,
        &[],
        None,
    )
    .expect("a deployment with a receiving origin mounts")
    .downcast::<Door>()
    .expect("the slot this plane builds is its own mount");
    assert!(
        mount.provider().is_none(),
        "no catalog is no upstream, not an empty one"
    );
}
