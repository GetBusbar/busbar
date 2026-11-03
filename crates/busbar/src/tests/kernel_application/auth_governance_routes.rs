// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::test_common as common;
use crate::root::test_plugins as plugins;

// ROOT_CARD has process lifetime. Each ordinary test owns one cold root and one Store lineage.
fn in_isolated_root() -> bool {
    const CHILD: &str = "BUSBAR_AUTH_GOVERNANCE_ROOT_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let name = std::thread::current()
        .name()
        .expect("ordinary test name")
        .to_owned();
    let mut child = Child(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD, "1")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("isolate the actual root"),
    );
    let until = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            use std::io::Read;
            let mut output = String::new();
            child
                .0
                .stdout
                .take()
                .expect("captured child output")
                .read_to_string(&mut output)
                .unwrap();
            assert!(
                status.success(),
                "actual-root case {name} failed: {status}: {output}"
            );
            assert!(
                output.contains(&format!("GOVERNANCE_ROOT_COMPLETED:{name}")),
                "the exact child must execute its assertions: {output}"
            );
            return false;
        }
        assert!(Instant::now() < until, "actual-root case {name} timed out");
        std::thread::park_timeout(Duration::from_millis(5));
    }
}

async fn stats(
    router: axum::Router,
    credential: Option<(&str, &str)>,
) -> (u16, String, serde_json::Value) {
    let mut request = axum::http::Request::builder().uri("/stats");
    if let Some((name, value)) = credential {
        request = request.header(name, value);
    }
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        tower::ServiceExt::oneshot(router, request.body(axum::body::Body::empty()).unwrap()),
    )
    .await
    .expect("the real /stats request is bounded")
    .unwrap();
    let status = response.status().as_u16();
    let ct = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(response.into_body(), 1 << 20),
    )
    .await
    .expect("the real /stats response is bounded")
    .unwrap();
    (
        status,
        ct,
        serde_json::from_slice(&body).expect("the native root response is JSON"),
    )
}

fn native_refusal(response: (u16, String, serde_json::Value)) {
    assert_eq!(response.0, 401, "{}", response.2);
    assert_eq!(response.1, "application/json");
    assert!(
        response
            .2
            .get("error")
            .is_some_and(serde_json::Value::is_object),
        "{}",
        response.2
    );
}

async fn session(
    app: Arc<busbar_kernel::state::App>,
    token: Option<&str>,
) -> Result<
    (
        busbar_kernel::auth::AuthPrincipal,
        busbar_kernel::governance::PlaneRequestCtx,
    ),
    busbar_kernel::auth::IdentityRefusal,
> {
    tokio::time::timeout(
        Duration::from_secs(10),
        busbar_kernel::auth::admit::admit_session(app, token.map(str::to_owned), String::new()),
    )
    .await
    .expect("actual session admission is bounded")
}

fn mint(gov: &busbar_kernel::governance::GovState, name: &str) -> (String, String) {
    let now = busbar_kernel::store::now();
    let (key, secret) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: name.into(),
                ..Default::default()
            },
            now + 3600,
            now,
        )
        .expect("actual Store-minted signed credential");
    (
        key.id,
        secret
            .expose(&busbar_kernel::seal::lend())
            .as_str()
            .to_owned(),
    )
}

#[tokio::test]
async fn keys_chain_preserves_carriers_disable_revoke_and_metering_controls() {
    if !in_isolated_root() {
        return;
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(std::thread::current().name().unwrap());
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator = busbar_kernel::config::operator_provider();
    let operator_secret = directory.join("operator-token");
    std::fs::write(&operator_secret, "admintok").expect("normal configured operator secret");
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32])).expect("normal configured signing key");

    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": serde_json::json!({(operator): {"module":operator,"token":{"file":operator_secret}}}),
        "auth": { "chain": ["keys"], "admin_auth": [operator], "signing_key": {"file": signing},
            "role_bindings": {} },
        "per_request_fee": 1,
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    // Retains disabled/unknown, vendor-carrier, revoked-token, active-governance,
    // and keys-chain-positive oracles formerly behind the synthetic admitting door.
    let gov = app.governance.as_ref().expect("actual Store governance");
    assert!(gov.admin_token_hash().is_some());
    let (enabled_id, enabled) = mint(gov, "enabled");
    let (disabled_id, disabled) = mint(gov, "disabled");
    gov.update_key(&disabled_id, Some(false), None).unwrap();
    let router = busbar_kernel::build_router(app.clone());
    for token in [&disabled, "sk-vk-nope"] {
        native_refusal(
            stats(
                router.clone(),
                Some(("authorization", &format!("Bearer {token}"))),
            )
            .await,
        );
        assert!(session(app.clone(), Some(token)).await.is_err());
    }
    for carrier in ["authorization", "x-api-key", "x-goog-api-key"] {
        let value = if carrier == "authorization" {
            format!("Bearer {enabled}")
        } else {
            enabled.clone()
        };
        let response = stats(router.clone(), Some((carrier, &value))).await;
        assert_eq!(response.0, 200, "valid key via {carrier}: {}", response.2);
    }
    native_refusal(stats(router.clone(), Some(("x-goog-api-key", "sk-vk-nope"))).await);
    native_refusal(stats(router.clone(), None).await);
    let (principal, context) = session(app.clone(), Some(&enabled)).await.unwrap();
    assert_eq!(principal.actor_id(), enabled_id);
    assert_eq!(
        context
            .key()
            .expect("keys chain resolves the actual key")
            .id,
        enabled_id
    );
    // Positive metering control uses the key returned by actual session admission and the
    // production configured cost model, rather than a handler inserted only for this test.
    drop(
        gov.try_admit(
            &app.cost,
            context.key().unwrap(),
            "pa",
            busbar_kernel::store::now(),
        )
        .unwrap(),
    );
    let usage = gov
        .usage_for(&app.cost, &enabled_id, busbar_kernel::store::now())
        .unwrap()
        .unwrap();
    assert_eq!(
        usage.spend_cents, 1,
        "one real configured request fee is charged"
    );
    gov.revoke(&enabled_id, "ordinary auth revocation control")
        .unwrap();
    assert!(gov.is_revoked(&enabled_id));
    native_refusal(
        stats(
            router,
            Some(("authorization", &format!("Bearer {enabled}"))),
        )
        .await,
    );
    assert!(session(app, Some(&enabled)).await.is_err());
    println!(
        "GOVERNANCE_ROOT_COMPLETED:{}",
        std::thread::current().name().unwrap()
    );
}

#[tokio::test]
async fn open_chain_with_operator_is_anonymous_keyless_and_unmetered() {
    if !in_isolated_root() {
        return;
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(std::thread::current().name().unwrap());
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator = busbar_kernel::config::operator_provider();
    let operator_secret = directory.join("operator-token");
    std::fs::write(&operator_secret, "admintok").expect("normal configured operator secret");
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32])).expect("normal configured signing key");

    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": serde_json::json!({(operator): {"module":operator,"token":{"file":operator_secret}}}),
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing},
            "role_bindings": {} },
        "per_request_fee": 1,
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    // The actual /stats endpoint requires Extension<GovCtx>; success proves that the
    // open chain inserts it. Session admission exposes the anonymous keyless context.
    let gov = app.governance.as_ref().expect("actual Store governance");
    assert!(gov.admin_token_hash().is_some());
    let (key_id, secret) = mint(gov, "ignored-in-open-chain");
    let router = busbar_kernel::build_router(app.clone());
    for token in [None, Some(secret.as_str()), Some("unknown")] {
        let (principal, context) = session(app.clone(), token).await.expect("open front door");
        assert_eq!(principal.actor_id(), "anonymous");
        assert!(
            !context.is_governed(),
            "open chain must not resolve a presented key"
        );
        let credential = token.map(|t| ("x-api-key", t));
        let response = stats(router.clone(), credential).await;
        assert_eq!(
            response.0, 200,
            "open chain inserts GovCtx and serves /stats: {}",
            response.2
        );
    }
    let spend = gov
        .usage_for(&app.cost, &key_id, busbar_kernel::store::now())
        .unwrap()
        .map(|u| u.spend_cents)
        .unwrap_or(0);
    assert_eq!(spend, 0, "the ignored presented key is never metered");
    println!(
        "GOVERNANCE_ROOT_COMPLETED:{}",
        std::thread::current().name().unwrap()
    );
}

#[tokio::test]
async fn open_chain_without_operator_still_inserts_default_context() {
    if !in_isolated_root() {
        return;
    }
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(std::thread::current().name().unwrap());
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32])).expect("normal configured signing key");

    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": serde_json::json!({}),
        "auth": { "chain": [], "admin_auth": [], "signing_key": {"file": signing},
            "role_bindings": {} },
        "per_request_fee": 1,
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    // The actual /stats endpoint requires Extension<GovCtx>; success proves that the
    // open chain inserts it. Session admission exposes the anonymous keyless context.
    let gov = app.governance.as_ref().expect("actual Store governance");
    assert!(gov.admin_token_hash().is_none());
    let (key_id, secret) = mint(gov, "ignored-in-open-chain");
    let router = busbar_kernel::build_router(app.clone());
    for token in [None, Some(secret.as_str()), Some("unknown")] {
        let (principal, context) = session(app.clone(), token).await.expect("open front door");
        assert_eq!(principal.actor_id(), "anonymous");
        assert!(
            !context.is_governed(),
            "open chain must not resolve a presented key"
        );
        let credential = token.map(|t| ("x-api-key", t));
        let response = stats(router.clone(), credential).await;
        assert_eq!(
            response.0, 200,
            "open chain inserts GovCtx and serves /stats: {}",
            response.2
        );
    }
    let spend = gov
        .usage_for(&app.cost, &key_id, busbar_kernel::store::now())
        .unwrap()
        .map(|u| u.spend_cents)
        .unwrap_or(0);
    assert_eq!(spend, 0, "the ignored presented key is never metered");
    println!(
        "GOVERNANCE_ROOT_COMPLETED:{}",
        std::thread::current().name().unwrap()
    );
}

#[tokio::test]
async fn ordinary_oidc_chain_keeps_grants_carriers_and_native_refusals() {
    if !in_isolated_root() {
        return;
    }
    const AUDIENCE: &str = "api://ordinary-governance-routes";
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(std::thread::current().name().unwrap());
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator = busbar_kernel::config::operator_provider();
    let operator_secret = directory.join("operator-token");
    std::fs::write(&operator_secret, "admintok").expect("normal configured operator secret");
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32])).expect("normal configured signing key");
    let oidc_path = common::plugins::token_verifier_cdylib_path().expect("actual OIDC library");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .unwrap()
        .expect("actual OIDC statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .unwrap()
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "ordinary-oidc", true);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": serde_json::json!({"ordinary-oidc":{"module":oidc_module,"settings":common::credentials::settings(AUDIENCE)}, (operator):{"module":operator,"token":{"file":operator_secret}}}),
        "auth": { "chain": ["ordinary-oidc"], "admin_auth": [operator], "signing_key": {"file": signing},
            "role_bindings": {"ordinary-oidc":{"bound":{}}} },
        "per_request_fee": 1,
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    // Real OIDC replaces the old synthetic group token. A stored signed key remains
    // irrelevant to this configured chain, whether the operator is configured or absent.
    let gov = app.governance.as_ref().expect("actual Store governance");
    assert!(gov.admin_token_hash().is_some());
    let (persisted_id, persisted) = mint(gov, "persisted-keys-do-not-override-chain");
    let token = common::credentials::token_for("static-chain", &["bound"], AUDIENCE);
    let router = busbar_kernel::build_router(app.clone());
    for carrier in ["authorization", "x-api-key", "x-goog-api-key"] {
        let value = if carrier == "authorization" {
            format!("Bearer {token}")
        } else {
            token.clone()
        };
        let response = stats(router.clone(), Some((carrier, &value))).await;
        assert_eq!(
            response.0, 200,
            "the actual OIDC chain accepts {carrier}: {}",
            response.2
        );
    }
    let (principal, context) = session(app.clone(), Some(&token)).await.unwrap();
    assert_eq!(principal.actor_id(), "oidc:static-chain");
    let key = context
        .key()
        .expect("the bound OIDC role supplies a governed key");
    assert_ne!(
        key.id, persisted_id,
        "the stored key must not override this principal"
    );
    let unbound = common::credentials::token_for("unbound", &["unbound"], AUDIENCE);
    for token in ["not-the-token", persisted.as_str(), unbound.as_str()] {
        native_refusal(stats(router.clone(), Some(("x-api-key", token))).await);
        assert!(session(app.clone(), Some(token)).await.is_err());
    }
    native_refusal(stats(router, None).await);
    println!(
        "GOVERNANCE_ROOT_COMPLETED:{}",
        std::thread::current().name().unwrap()
    );
}

#[tokio::test]
async fn ordinary_oidc_chain_without_operator_ignores_persisted_keys() {
    if !in_isolated_root() {
        return;
    }
    const AUDIENCE: &str = "api://ordinary-governance-routes";
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch(std::thread::current().name().unwrap());
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32])).expect("normal configured signing key");
    let oidc_path = common::plugins::token_verifier_cdylib_path().expect("actual OIDC library");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .unwrap()
        .expect("actual OIDC statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .unwrap()
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "ordinary-oidc", true);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "identity-providers": serde_json::json!({"ordinary-oidc":{"module":oidc_module,"settings":common::credentials::settings(AUDIENCE)}}),
        "auth": { "chain": ["ordinary-oidc"], "admin_auth": [], "signing_key": {"file": signing},
            "role_bindings": {"ordinary-oidc":{"bound":{}}} },
        "per_request_fee": 1,
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        None,
        true,
    )
    .expect("the actual product builds the session deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let app = Arc::new(app);

    // Real OIDC replaces the old synthetic group token. A stored signed key remains
    // irrelevant to this configured chain, whether the operator is configured or absent.
    let gov = app.governance.as_ref().expect("actual Store governance");
    assert!(gov.admin_token_hash().is_none());
    let (persisted_id, persisted) = mint(gov, "persisted-keys-do-not-override-chain");
    let token = common::credentials::token_for("static-chain", &["bound"], AUDIENCE);
    let router = busbar_kernel::build_router(app.clone());
    for carrier in ["authorization", "x-api-key", "x-goog-api-key"] {
        let value = if carrier == "authorization" {
            format!("Bearer {token}")
        } else {
            token.clone()
        };
        let response = stats(router.clone(), Some((carrier, &value))).await;
        assert_eq!(
            response.0, 200,
            "the actual OIDC chain accepts {carrier}: {}",
            response.2
        );
    }
    let (principal, context) = session(app.clone(), Some(&token)).await.unwrap();
    assert_eq!(principal.actor_id(), "oidc:static-chain");
    let key = context
        .key()
        .expect("the bound OIDC role supplies a governed key");
    assert_ne!(
        key.id, persisted_id,
        "the stored key must not override this principal"
    );
    let unbound = common::credentials::token_for("unbound", &["unbound"], AUDIENCE);
    for token in ["not-the-token", persisted.as_str(), unbound.as_str()] {
        native_refusal(stats(router.clone(), Some(("x-api-key", token))).await);
        assert!(session(app.clone(), Some(token)).await.is_err());
    }
    native_refusal(stats(router, None).await);
    println!(
        "GOVERNANCE_ROOT_COMPLETED:{}",
        std::thread::current().name().unwrap()
    );
}
