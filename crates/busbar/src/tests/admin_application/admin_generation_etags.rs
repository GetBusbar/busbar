// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 section 6 over the real root: ETags on every GET, `If-Match` against the durable
//! generation, `Idempotency-Key` replay on any mutation, and `GET /operations/{key}`.

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json;

const CHILD: &str = "BUSBAR_ADMIN_GENERATION_CHILD";
const WITNESS: &str = "actual root generation assertions completed";

struct Served {
    addr: std::net::SocketAddr,
    handle: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
    client: reqwest::Client,
    app: Arc<busbar_kernel::state::App>,
}

impl Served {
    fn url(&self, path: &str) -> String {
        format!("http://{}/api/v1/admin{path}", self.addr)
    }
    fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.client
            .get(self.url(path))
            .header("x-admin-token", "admintok")
    }
    fn send(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        self.client
            .request(method, self.url(path))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    }
    fn finish(self) {
        self.handle.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn serve(name: &str, require_if_match: bool) -> Served {
    serve_with_effect(name, require_if_match, None).await
}

async fn serve_with_effect(
    name: &str,
    require_if_match: bool,
    effect: Option<axum::Router>,
) -> Served {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(name);
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([5u8; 32])).unwrap();
    std::fs::write(&operator_token, "admintok").unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {}, "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key },
                  "policy": { "require_if_match": require_if_match } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["plugins"] = crate::root::test_plugins::config_document(
        &crate::root::test_plugins::trusted_config(&directory),
    );
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["groups"] = serde_json::json!({"team":{"limits":[{"budget":20000,"per":"month"}]}});
    let config_path = directory.join("config.json");
    let providers_path = directory.join("providers.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&document).unwrap()).unwrap();
    std::fs::write(&providers_path, b"{}").unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .unwrap();
    let config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Fixture {
        backend: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .unwrap();
    let anchor = crate::root::real_store::core_over(anchor).await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone()).unwrap();
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (Some(config_path), Some(providers_path)),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .unwrap();
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module).await.unwrap();
    limits.keep().await.unwrap();
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = crate::root::real_store::hydrated(Arc::new(app)).await;
    let router = match effect {
        Some(router) => busbar_core_admin::test_support::with_idempotency(router, app.clone()),
        None => busbar_kernel::build_router(app.clone()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Served {
        addr,
        handle,
        dir: directory,
        client: reqwest::Client::new(),
        app,
    }
}

#[tokio::test]
async fn failed_reply_after_effect_is_replayed_without_a_second_effect() {
    isolated!(CHILD, WITNESS, witness = "generation");
    use std::sync::atomic::{AtomicUsize, Ordering};

    let effects = Arc::new(AtomicUsize::new(0));
    let handler_effects = effects.clone();
    let router = axum::Router::new().route(
        "/api/v1/admin/counted-effect/{status}",
        axum::routing::post(
            move |axum::extract::Path(status): axum::extract::Path<u16>| {
                let effects = handler_effects.clone();
                async move {
                    effects.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        [("content-type", "application/json")],
                        r#"{"effect":"applied","receipt":"retained"}"#,
                    )
                }
            },
        ),
    );
    let s = serve_with_effect("failed-reply-retained", false, Some(router)).await;
    for (index, status) in [500, 503, 429].into_iter().enumerate() {
        let path = format!("/counted-effect/{status}");
        let key = format!("failed-reply-{status}");
        let first = s
            .send(reqwest::Method::POST, &path)
            .header("idempotency-key", &key)
            .body("original")
            .send()
            .await
            .unwrap();
        assert_eq!(first.status().as_u16(), status);
        let content_type = first.headers()["content-type"].clone();
        let body = first.bytes().await.unwrap();
        let retry = s
            .send(reqwest::Method::POST, &path)
            .header("idempotency-key", &key)
            .body("original")
            .send()
            .await
            .unwrap();
        assert_eq!(retry.status().as_u16(), status);
        assert_eq!(retry.headers().get("idempotent-replayed").unwrap(), "true");
        assert_eq!(retry.headers()["content-type"], content_type);
        assert_eq!(retry.bytes().await.unwrap(), body);
        assert_eq!(effects.load(Ordering::SeqCst), index + 1);
        let mismatch = s
            .send(reqwest::Method::POST, &path)
            .header("idempotency-key", &key)
            .body("different")
            .send()
            .await
            .unwrap();
        assert_eq!(mismatch.status().as_u16(), 409);
        let mismatch: serde_json::Value = mismatch.json().await.unwrap();
        assert_eq!(mismatch["error"]["reason"], "idempotency_mismatch");
        assert_eq!(effects.load(Ordering::SeqCst), index + 1);
    }
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn every_get_has_etag_and_304() {
    isolated!(CHILD, WITNESS, witness = "generation");
    let s = serve("every-get-has-etag", false).await;
    for path in [
        "/info",
        "/kinds/core/instances",
        "/hooks",
        "/groups",
        "/config",
        "/auth",
    ] {
        let first = s.get(path).send().await.unwrap();
        assert_eq!(first.status().as_u16(), 200, "{path}");
        let etag = first
            .headers()
            .get("etag")
            .unwrap_or_else(|| panic!("{path} carries an ETag"))
            .to_str()
            .unwrap()
            .to_string();
        let again = s
            .get(path)
            .header("if-none-match", &etag)
            .send()
            .await
            .unwrap();
        // /info carries live counters; every other read is stable between the two calls.
        if path != "/info" {
            assert_eq!(again.status().as_u16(), 304, "{path} answers If-None-Match");
        }
    }
    let config = s.get("/groups").send().await.unwrap();
    let etag = config.headers()["etag"].to_str().unwrap().to_string();
    assert!(
        etag.starts_with("\"dep_"),
        "config ETag is deployment.generation: {etag}"
    );
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn generation_etag_moves_on_write_and_if_match_guards() {
    isolated!(CHILD, WITNESS, witness = "generation");
    let s = serve("generation-if-match", false).await;
    let before = s.get("/groups").send().await.unwrap();
    let etag = before.headers()["etag"].to_str().unwrap().to_string();
    let body = json::json!({"name": "user:ann", "config": {"parent": "team"}}).to_string();
    let wrote = s
        .send(reqwest::Method::POST, "/groups")
        .body(body)
        .send()
        .await
        .unwrap();
    assert!(wrote.status().is_success(), "{}", wrote.status());
    let after = s.get("/groups").send().await.unwrap();
    let moved = after.headers()["etag"].to_str().unwrap().to_string();
    assert_ne!(etag, moved, "a publication moves the generation");
    let stale = s
        .send(reqwest::Method::DELETE, "/overlay/groups")
        .header("if-match", &etag)
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409);
    let body = json::parse_value(&stale.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["reason"], "stale_if_match");
    let unquoted = s
        .send(reqwest::Method::DELETE, "/overlay/groups")
        .header("if-match", "7")
        .send()
        .await
        .unwrap();
    assert_eq!(unquoted.status().as_u16(), 400);
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn require_if_match_428() {
    isolated!(CHILD, WITNESS, witness = "generation");
    let s = serve("require-if-match", true).await;
    let refused = s
        .send(reqwest::Method::DELETE, "/overlay/groups")
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status().as_u16(), 428);
    let body = json::parse_value(&refused.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert_eq!(body["error"]["reason"], "if_match_required");
    let etag = s.get("/groups").send().await.unwrap().headers()["etag"]
        .to_str()
        .unwrap()
        .to_string();
    let allowed = s
        .send(reqwest::Method::DELETE, "/overlay/groups")
        .header("if-match", etag)
        .send()
        .await
        .unwrap();
    assert!(allowed.status().is_success(), "{}", allowed.status());
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn idempotent_replay_every_mutation() {
    isolated!(CHILD, WITNESS, witness = "generation");
    let s = serve("idempotent-replay", false).await;
    let body = json::json!({"name": "user:zed", "config": {"parent": "team"}}).to_string();
    let first = s
        .send(reqwest::Method::POST, "/groups")
        .header("idempotency-key", "grp-1")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert!(first.status().is_success(), "{}", first.status());
    assert!(first.headers().get("idempotent-replayed").is_none());
    let first_status = first.status();
    let first_body = first.bytes().await.unwrap();
    let replay = s
        .send(reqwest::Method::POST, "/groups")
        .header("idempotency-key", "grp-1")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), first_status);
    assert_eq!(replay.headers()["idempotent-replayed"], "true");
    assert_eq!(replay.bytes().await.unwrap(), first_body);
    let different = s
        .send(reqwest::Method::POST, "/groups")
        .header("idempotency-key", "grp-1")
        .body(json::json!({"name": "user:other", "config": {"parent": "team"}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(different.status().as_u16(), 409);
    let refusal = json::parse_value(&different.bytes().await.unwrap()).unwrap();
    assert_eq!(refusal["error"]["reason"], "idempotency_mismatch");
    let operation = s
        .get("/operations/grp-1")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let operation = json::parse_value(&operation).unwrap();
    assert_eq!(operation["state"], "applied");
    assert_eq!(operation["idempotency_key"], "grp-1");
    let missing = s.get("/operations/never-sent").send().await.unwrap();
    assert_eq!(missing.status().as_u16(), 404);
    s.finish();
    println!("{WITNESS}");
}

fn unknown_effect_request(body: &'static str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/api/v1/admin/unknown-effect")
        .header("idempotency-key", "unknown-effect")
        .body(axum::body::Body::from(body))
        .unwrap()
}

fn unknown_effect_query_request(
    query: &str,
    body: &'static str,
) -> axum::http::Request<axum::body::Body> {
    let mut request = unknown_effect_request(body);
    *request.uri_mut() = format!("/api/v1/admin/unknown-effect?{query}")
        .parse()
        .unwrap();
    request
}

#[tokio::test]
async fn unreadable_retained_intent_refuses_without_an_effect() {
    isolated!(CHILD, WITNESS, witness = "generation");
    use busbar_core_admin::idempotency::durable::{self, Settled};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;

    let s = serve("unknown-effect-unreadable-intent", false).await;
    let store = durable::scoped_store(
        s.app
            .governance
            .as_ref()
            .unwrap()
            .core_store_handle()
            .unwrap(),
    )
    .unwrap();
    let key = ("anonymous".into(), "op:unknown-effect".into());
    let now = busbar_kernel::store::now();
    let claim = durable::claim_held(&store, &key, now).await.unwrap();
    durable::settle(&store, &claim, now, &Settled::Retained(vec![255]))
        .await
        .unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let handler_effects = effects.clone();
    let effect = axum::Router::new().route(
        "/api/v1/admin/unknown-effect",
        axum::routing::post(move || {
            let effects = handler_effects.clone();
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }),
    );
    let response = busbar_core_admin::test_support::with_idempotency(effect, s.app.clone())
        .oneshot(unknown_effect_request("original"))
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn unreadable_reply_retains_the_effect_across_router_reconstruction() {
    isolated!(CHILD, WITNESS, witness = "generation");
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;

    let effects = Arc::new(AtomicUsize::new(0));
    let handler_effects = effects.clone();
    let effect = axum::Router::new().route(
        "/api/v1/admin/unknown-effect",
        axum::routing::post(move || {
            let effects = handler_effects.clone();
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                // A successful handler reply that cannot fit the middleware's response buffer.
                axum::body::Body::from(vec![b'x'; 16 * 1024 * 1024 + 1])
            }
        }),
    );
    let s = serve("unknown-effect-collection", false).await;
    let first = busbar_core_admin::test_support::with_idempotency(effect.clone(), s.app.clone())
        .oneshot(unknown_effect_query_request("marker=", "original"))
        .await
        .unwrap();
    assert_eq!(first.status().as_u16(), 500);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let rebuilt = busbar_core_admin::test_support::with_idempotency(effect, s.app.clone());
    let retry = rebuilt
        .clone()
        .oneshot(unknown_effect_query_request("marker=", "original"))
        .await
        .unwrap();
    assert_eq!(retry.status().as_u16(), 409);
    assert_eq!(retry.headers()["retry-after"], "1");
    let refusal: serde_json::Value = json::from_slice(
        &axum::body::to_bytes(retry.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(refusal["error"]["reason"], "idempotency_in_flight");
    let collision = rebuilt
        .clone()
        .oneshot(unknown_effect_query_request("marker", "=original"))
        .await
        .unwrap();
    assert_eq!(collision.status().as_u16(), 409);
    let refusal: serde_json::Value = json::from_slice(
        &axum::body::to_bytes(collision.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(refusal["error"]["reason"], "idempotency_mismatch");
    let mismatch = rebuilt
        .clone()
        .oneshot(unknown_effect_query_request("marker=", "different"))
        .await
        .unwrap();
    assert_eq!(mismatch.status().as_u16(), 409);
    let refusal: serde_json::Value = json::from_slice(
        &axum::body::to_bytes(mismatch.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(refusal["error"]["reason"], "idempotency_mismatch");
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let operation = rebuilt
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/admin/operations/unknown-effect")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(operation.status().as_u16(), 200);
    let operation: serde_json::Value = json::from_slice(
        &axum::body::to_bytes(operation.into_body(), 16 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(operation["state"], "in_flight");
    assert!(operation["response"].is_null());
    assert_eq!(operation["request_sha256"].as_str().unwrap().len(), 64);
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn cancellation_after_dispatch_keeps_the_original_action_excluded() {
    isolated!(CHILD, WITNESS, witness = "generation");
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;

    let effects = Arc::new(AtomicUsize::new(0));
    let started = Arc::new(tokio::sync::Notify::new());
    let handler_effects = effects.clone();
    let handler_started = started.clone();
    let effect = axum::Router::new().route(
        "/api/v1/admin/unknown-effect",
        axum::routing::post(move || {
            let effects = handler_effects.clone();
            let started = handler_started.clone();
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                std::future::pending::<()>().await;
                axum::http::StatusCode::OK
            }
        }),
    );
    let s = serve("unknown-effect-cancellation", false).await;
    let router = busbar_core_admin::test_support::with_idempotency(effect.clone(), s.app.clone());
    let first = tokio::spawn(router.clone().oneshot(unknown_effect_request("original")));
    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .expect("the first handler crossed the durable intent boundary");
    let concurrent = router
        .oneshot(unknown_effect_request("original"))
        .await
        .unwrap();
    assert_eq!(concurrent.status().as_u16(), 409);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    let rebuilt = busbar_core_admin::test_support::with_idempotency(effect, s.app.clone());
    let retry = rebuilt
        .oneshot(unknown_effect_request("original"))
        .await
        .unwrap();
    assert_eq!(retry.status().as_u16(), 409);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn idempotency_binding_keeps_query_and_body_boundaries() {
    isolated!(CHILD, WITNESS, witness = "generation");
    let s = serve("idempotent-request-framing", false).await;
    let body = json::json!({"name": "user:framed", "config": {"parent": "team"}}).to_string();
    let first = s
        .send(reqwest::Method::POST, "/groups?marker=")
        .header("idempotency-key", "framed-request")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert!(first.status().is_success(), "{}", first.status());
    let first_status = first.status();
    let first_body = first.bytes().await.unwrap();

    // Both requests concatenate to the same method/path/query/body bytes without framing.
    let different = s
        .send(reqwest::Method::POST, "/groups?marker")
        .header("idempotency-key", "framed-request")
        .body(format!("={body}"))
        .send()
        .await
        .unwrap();
    assert_eq!(different.status().as_u16(), 409);
    assert!(different.headers().get("idempotent-replayed").is_none());
    let refusal = json::parse_value(&different.bytes().await.unwrap()).unwrap();
    assert_eq!(refusal["error"]["reason"], "idempotency_mismatch");

    let replay = s
        .send(reqwest::Method::POST, "/groups?marker=")
        .header("idempotency-key", "framed-request")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), first_status);
    assert_eq!(replay.headers()["idempotent-replayed"], "true");
    assert_eq!(replay.bytes().await.unwrap(), first_body);
    s.finish();
    println!("{WITNESS}");
}

#[tokio::test]
async fn unsupported_answer_binding_layout_never_replays_or_dispatches() {
    isolated!(CHILD, WITNESS, witness = "generation");
    use busbar_core_admin::idempotency::durable::{self, Settled};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tower::ServiceExt as _;

    let s = serve("unsupported-answer-layout", false).await;
    let scoped = durable::scoped_store(
        s.app
            .governance
            .as_ref()
            .unwrap()
            .core_store_handle()
            .unwrap(),
    )
    .unwrap();
    let now = busbar_kernel::store::now();
    let key = ("anonymous".into(), "op:unknown-effect".into());
    let claim = durable::claim(&scoped, &key, now).await.unwrap();
    // Layout1 did not distinguish framed from ambiguous concatenated fingerprints.
    let mut old = vec![1];
    old.extend_from_slice(&200u16.to_be_bytes());
    old.extend_from_slice(&now.to_be_bytes());
    old.extend_from_slice(&0u64.to_be_bytes());
    old.extend_from_slice(&[0; 32]);
    old.push(0);
    old.extend_from_slice(b"old answer");
    durable::settle(&scoped, &claim, now, &Settled::Answer(old))
        .await
        .unwrap();
    let effects = Arc::new(AtomicUsize::new(0));
    let handler_effects = effects.clone();
    let effect = axum::Router::new().route(
        "/api/v1/admin/unknown-effect",
        axum::routing::post(move || {
            let effects = handler_effects.clone();
            async move {
                effects.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        }),
    );
    let response = busbar_core_admin::test_support::with_idempotency(effect, s.app.clone())
        .oneshot(unknown_effect_request("original"))
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(effects.load(Ordering::SeqCst), 0);
    s.finish();
    println!("{WITNESS}");
}
