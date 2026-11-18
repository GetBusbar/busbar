// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use crate::test_common as common;
use busbar_contract::json::JsonValueTrait as _;
use std::io::Write;
use std::sync::{Arc, Mutex};

const AUDIENCE: &str = "api://auth-self-groups";

/// One presentation: its name, the headers it carries, and the 4032 reason it must be refused with.
type Case = (&'static str, Vec<(&'static str, String)>, &'static str);

/// What a deployment with no `oauth_as` answers for any DPoP-bound or DPoP-scheme presentation.
const UNVERIFIABLE: &str = "This deployment does not verify DPoP proofs, so a DPoP-bound or \
                            DPoP-scheme presentation cannot be accepted (RFC 9449). Present an \
                            unbound bearer token.";

/// The actual product, with an actual OIDC chain and Store, and no authorization server.
async fn no_authorization_server(tag: &str) -> Arc<busbar_kernel::state::App> {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "auth-dpop-no-as-{tag}-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC product exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "corp", true);
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([9u8; 32]))
        .expect("write the actual configured signing key");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": {
            "corp": { "module": oidc_module, "settings": common::credentials::settings(AUDIENCE) }
        },
        "auth": {
            "chain": ["corp"], "signing_key": { "file": signing },
            "key_ttl": "1h",
            "role_bindings": { "corp": { "eng": { "group": "team" } } }
        },
        "groups": { "team": { "child_default": { "limits": [{ "budget": 500, "per": "month" }] } } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
    }), &crate::root::boot::axis_test_grammar())
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store bootstraps its config authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional config records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay.clone()),
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let app = Arc::new(app);
    assert!(
        app.oauth_as.is_none(),
        "precondition: no actual authorization server is configured"
    );
    app
}

async fn answer(
    router: &axum::Router,
    method: &str,
    uri: &str,
    headers: &[(&str, String)],
) -> (u16, String) {
    let mut request = axum::http::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tower::ServiceExt::oneshot(
            router.clone(),
            request.body(axum::body::Body::empty()).unwrap(),
        ),
    )
    .await
    .expect("the actual request is bounded")
    .unwrap();
    let status = response.status().as_u16();
    let bytes = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), 64 * 1024),
    )
    .await
    .expect("the actual body is bounded")
    .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[derive(Clone, Default)]
struct Buf(Arc<Mutex<Vec<u8>>>);

impl Write for Buf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Buf {
    fn take(&self) -> String {
        String::from_utf8(std::mem::take(&mut *self.0.lock().unwrap())).unwrap()
    }
}

/// Capture this (current-thread) test's diagnostics for as long as the guard lives.
fn capture() -> (Buf, tracing::subscriber::DefaultGuard) {
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    (buf, guard)
}

fn assert_refused_record(text: &str, surface: &str, reason: &str, case: &str) {
    assert!(
        text.lines().any(|line| line.contains("diag=BUSBAR-4032")
            && line.contains(&format!("surface={surface}"))
            && line.contains(&format!("reason={reason}"))),
        "{case}: BUSBAR-4032 surface={surface} reason={reason} is recorded; got: {text:?}"
    );
}

fn bound_token(jkt: serde_json::Value) -> String {
    common::credentials::token_with_claims(
        "alice",
        &["eng"],
        AUDIENCE,
        serde_json::json!({ "cnf": { "jkt": jkt } }),
    )
}

#[tokio::test]
async fn without_an_authorization_server_a_dpop_presentation_is_refused_and_explained() {
    let app = no_authorization_server("presentation").await;
    let token = common::credentials::token_for("alice", &["eng"], AUDIENCE);
    let router = busbar_kernel::build_router(app);
    let (absent_status, absent_body) = answer(&router, "GET", "/stats", &[]).await;
    assert_eq!(absent_status, 401, "the actual chain requires a credential");
    let (buf, _guard) = capture();
    let (presented_status, presented_body) = answer(
        &router,
        "GET",
        "/stats",
        &[
            ("authorization", format!("DPoP {token}")),
            ("dpop", "a.b.c".to_owned()),
        ],
    )
    .await;
    assert_eq!(presented_status, 401, "a DPoP presentation is refused");
    assert!(
        presented_body.contains(UNVERIFIABLE),
        "the refusal explains itself: {presented_body}"
    );
    assert_ne!(
        presented_body, absent_body,
        "a refused DPoP presentation is not answered as an absent credential"
    );
    assert_refused_record(&buf.take(), "door", "unverifiable", "DPoP scheme");
    let (genuine, _) = answer(
        &router,
        "GET",
        "/stats",
        &[("authorization", format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(
        genuine, 200,
        "a genuinely signed unbound OIDC bearer is admitted"
    );
    let anonymous = answer(&router, "POST", "/auth/token", &[]).await;
    assert_eq!(
        (anonymous.0, anonymous.1.as_str()),
        (401, r#"{"error":"not authenticated"}"#)
    );
}

#[tokio::test]
async fn without_an_authorization_server_a_dpop_bound_token_is_refused_at_the_door() {
    let app = no_authorization_server("door").await;
    let router = busbar_kernel::build_router(app);
    let unbound = common::credentials::token_for("alice", &["eng"], AUDIENCE);
    let (precondition, _) =
        answer(&router, "GET", "/stats", &[("x-api-key", unbound.clone())]).await;
    assert_eq!(
        precondition, 200,
        "precondition: x-api-key carries a credential here"
    );
    let bound = bound_token(serde_json::json!(
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    ));
    let cases: Vec<Case> = vec![
        (
            "bound bearer",
            vec![("authorization", format!("Bearer {bound}"))],
            "bound_bearer",
        ),
        (
            "bound x-api-key",
            vec![("x-api-key", bound.clone())],
            "bound_bearer",
        ),
        (
            "hidden behind an unbound bearer",
            vec![
                ("authorization", format!("Bearer {unbound}")),
                ("x-api-key", bound.clone()),
            ],
            "bound_bearer",
        ),
        (
            "second x-api-key occurrence",
            vec![("x-api-key", unbound.clone()), ("x-api-key", bound.clone())],
            "bound_bearer",
        ),
        (
            "malformed numeric jkt",
            vec![(
                "authorization",
                format!("Bearer {}", bound_token(serde_json::json!(123))),
            )],
            "bound_bearer",
        ),
        (
            "malformed object jkt",
            vec![("x-api-key", bound_token(serde_json::json!({})))],
            "bound_bearer",
        ),
        (
            "DPoP scheme with a bound x-api-key",
            vec![
                ("authorization", "DPoP anything".to_owned()),
                ("x-api-key", bound.clone()),
            ],
            "unverifiable",
        ),
        (
            "DPoP scheme with an unbound x-api-key",
            vec![
                ("authorization", "DPoP anything".to_owned()),
                ("x-api-key", unbound.clone()),
            ],
            "unverifiable",
        ),
        (
            "DPoP scheme alone",
            vec![("authorization", format!("DPoP {bound}"))],
            "unverifiable",
        ),
    ];
    let (buf, _guard) = capture();
    for (case, headers, reason) in cases {
        let (status, body) = answer(&router, "GET", "/stats", &headers).await;
        assert_eq!(status, 401, "{case}: refused");
        assert!(body.contains(UNVERIFIABLE), "{case}: explained: {body}");
        assert_refused_record(&buf.take(), "door", reason, case);
    }
}

#[tokio::test]
async fn without_an_authorization_server_a_dpop_bound_token_is_never_exchanged() {
    let app = no_authorization_server("exchange").await;
    let gov = app.governance.clone().expect("governance mints keys here");
    let router = busbar_kernel::build_router(app);
    let bound = bound_token(serde_json::json!(
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    ));
    let refused = serde_json::json!({
        "error": "sender_constrained",
        "error_description": UNVERIFIABLE,
    });
    let cases: Vec<Case> = vec![
        (
            "bound bearer",
            vec![("authorization", format!("Bearer {bound}"))],
            "bound_bearer",
        ),
        (
            "bound x-api-key",
            vec![("x-api-key", bound.clone())],
            "bound_bearer",
        ),
        (
            "DPoP scheme with a bound x-api-key",
            vec![
                ("authorization", "DPoP x".to_owned()),
                ("x-api-key", bound.clone()),
            ],
            "unverifiable",
        ),
        (
            "malformed jkt",
            vec![(
                "authorization",
                format!("Bearer {}", bound_token(serde_json::json!(123))),
            )],
            "bound_bearer",
        ),
    ];
    let (buf, _guard) = capture();
    for (case, headers, reason) in cases {
        let (status, body) = answer(&router, "POST", "/auth/token", &headers).await;
        assert_eq!(
            (
                status,
                serde_json::from_str::<serde_json::Value>(&body).ok()
            ),
            (401, Some(refused.clone())),
            "{case}: refused and explained"
        );
        assert_refused_record(&buf.take(), "exchange", reason, case);
        assert!(
            gov.all_keys_async().await.unwrap().is_empty(),
            "{case}: no key is minted"
        );
    }
    let unbound = common::credentials::token_for("alice", &["eng"], AUDIENCE);
    let (status, body) = answer(
        &router,
        "POST",
        "/auth/token",
        &[("authorization", format!("Bearer {unbound}"))],
    )
    .await;
    assert_eq!(status, 200, "an unbound IdP token still exchanges: {body}");
    assert_eq!(gov.all_keys_async().await.unwrap().len(), 1);
}

#[tokio::test]
async fn a_dpop_bound_line_session_credential_is_refused_and_explained() {
    let app = no_authorization_server("session").await;
    let mut with_as = (*app).clone();
    with_as.oauth_as = Some(Arc::new(()));
    let env = crate::root::serve::lines::env_credential("mcp", "stdio");
    let bound = bound_token(serde_json::json!(
        "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    ));
    let unbound = common::credentials::token_for("alice", &["eng"], AUDIENCE);
    for app in [app, Arc::new(with_as)] {
        let configured = app.oauth_as.is_some();
        let (buf, guard) = capture();
        let refused = crate::root::serve::lines::session(
            app.clone(),
            "mcp",
            "stdio",
            Some(AUDIENCE),
            Some(&bound),
        )
        .await;
        drop(guard);
        let sentence = refused.err().unwrap_or_else(|| {
            panic!("a bound session credential is refused (oauth_as configured: {configured})")
        });
        assert!(
            sentence.contains("DPoP-bound") && sentence.contains(&env),
            "the refusal names the binding and {env}: {sentence}"
        );
        assert_refused_record(&buf.take(), "session", "unverifiable", "line session");
        assert!(
            crate::root::serve::lines::session(
                app.clone(),
                "mcp",
                "stdio",
                Some(AUDIENCE),
                Some(&unbound),
            )
            .await
            .is_ok(),
            "an unbound audience-bound credential still reaches the chain and is admitted \
             (oauth_as configured: {configured})"
        );
    }
}
