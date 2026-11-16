// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use busbar_contract::json::{self, JsonValueTrait as _};

use crate::test_common as common;

const AUDIENCE: &str = "api://admin-delegated-authority";

#[tokio::test]
async fn test_admin_v1_idempotency_key_is_principal_scoped() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_65782045F262";
    const WITNESS: &str =
        "actual root case test_admin_v1_idempotency_key_is_principal_scoped completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_idempotency_key_is_principal_scoped-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token = common::credentials::token_for("admins", &["admins"], AUDIENCE);
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "admins": { "admin_scope": "full" } },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let mint = |tok: &str| {
        client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .header("idempotency-key", "shared-value")
            .body(json::json!({"name": "k"}).to_string())
            .send()
    };

    let a = json::parse_value(&mint("admintok").await.unwrap().bytes().await.unwrap()).unwrap();

    let b =
        json::parse_value(&mint(&delegated_token).await.unwrap().bytes().await.unwrap()).unwrap();

    assert!(a["id"].is_string() && b["id"].is_string());
    assert_ne!(
        a["id"], b["id"],
        "a second principal's identical Idempotency-Key must mint a NEW key, not replay A's"
    );
    assert_ne!(
        a["token"], b["token"],
        "B must never receive A's once-shown token via a cross-principal replay"
    );

    let a2 = json::parse_value(&mint("admintok").await.unwrap().bytes().await.unwrap()).unwrap();
    assert_eq!(a2["id"], a["id"], "A's own retry replays A's response");

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_put_auth_dry_run_guard() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_3BEDAEDA0A8F";
    const WITNESS: &str = "actual root case test_admin_v1_put_auth_dry_run_guard completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) =
        crate::distribution::rig::actual_store("test_admin_v1_put_auth_dry_run_guard-actual-store");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token = common::credentials::token_for("admins", &["admins"], AUDIENCE);
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "admins": { "admin_scope": "full" } },
    });
    document["plugins"] = crate::root::test_plugins::trusted_config_document(&directory);
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let put = |tok: &str, body: json::Value| {
        client
            .put(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
    };

    let r = put("admintok", json::json!({"admin_auth": ["saml"]}))
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "unknown module is invalid_request"
    );

    let r = client
        .put(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .header("if-match", "\"999\"")
        .body(json::json!({"admin_auth": [busbar_kernel::config::operator_provider()]}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 409, "stale If-Match conflicts");

    let r = put(
        "admintok",
        json::json!({"admin_auth": ["test-scope-module"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        409,
        "a chain that locks the caller out is refused"
    );
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "nothing changed on the refusal");

    let r = put(
        &delegated_token,
        json::json!({"admin_auth": ["test-scope-module"]}),
    )
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "the surviving caller's change applies"
    );
    let body = json::parse_value(&r.bytes().await.unwrap()).unwrap();
    assert_eq!(body["applied"], true);

    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        401,
        "the dropped module's credential stops working immediately"
    );

    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", &delegated_token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);

    let body = client
        .get(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", &delegated_token)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let body = json::parse_value(&body).unwrap();
    assert_eq!(body["configured"], true);
    assert_eq!(
        body["modules"],
        json::json!(["test-scope-module"]),
        "GET admin-auth mirrors the PUT'd chain verbatim"
    );

    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_put_auth_accepts_a_renamed_operator_provider() {
    const CHILD: &str = "BUSBAR_ADMIN_BOOT_6AD89D35735E";
    const WITNESS: &str =
        "actual root case test_admin_v1_put_auth_accepts_a_renamed_operator_provider completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_put_auth_accepts_a_renamed_operator_provider-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["identity-providers"]["ops"] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    let (addr, handle, _book) =
        crate::distribution::rig::actual_root(document, &directory, &module).await;
    let client = reqwest::Client::new();
    let put = |chain: json::Value| {
        client
            .put(format!("http://{addr}/api/v1/admin/admin-auth"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(json::json!({ "admin_auth": chain }).to_string())
            .send()
    };
    let r = put(json::json!(["ops"])).await.unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap();
    assert_eq!(
        status, 200,
        "a provider backed by the operator module applies: {body}"
    );
    let r = client
        .get(format!("http://{addr}/api/v1/admin/info"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "the operator token admits through `ops`"
    );
    let r = put(json::json!(["saml"])).await.unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "a name no admin module answers is refused"
    );
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_equal_subjects_from_distinct_issuers_cannot_replay_secrets() {
    const CHILD: &str = "BUSBAR_ADMIN_ISSUER_A14_20261105";
    const WITNESS: &str = "actual root case test_admin_v1_equal_subjects_from_distinct_issuers_cannot_replay_secrets completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_equal_subjects_from_distinct_issuers_cannot_replay_secrets-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let token_a = common::credentials::token_for("same-subject", &["admins"], AUDIENCE);
    let issuer_b = "https://issuer-b.e2e.invalid";
    let token_b = common::credentials::token_with_claims(
        "same-subject",
        &["admins"],
        AUDIENCE,
        serde_json::json!({"iss": issuer_b}),
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    let mut settings_b = common::credentials::settings(AUDIENCE);
    settings_b.insert("issuer".into(), serde_json::json!(issuer_b));
    document["identity-providers"]["second-issuer"] = serde_json::json!({
        "module": oidc_module, "settings": settings_b, "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] =
        serde_json::json!(["test-scope-module", "second-issuer", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "admins": { "admin_scope": "full" } },
        "second-issuer": { "admins": { "admin_scope": "full" } },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    // These are separately configured instances of the actual loaded OIDC module.
    let identify = |token: &str| {
        let headers = axum::http::HeaderMap::from_iter([(
            axum::http::HeaderName::from_static("x-admin-token"),
            token.parse().unwrap(),
        )]);
        let door =
            busbar_kernel::auth::admin_verdict(&app, "POST", "/api/v1/admin/keys", &headers).door;
        assert!(busbar_kernel::auth::admin_door_admits(
            &door,
            "POST",
            "/api/v1/admin/keys"
        ));
        busbar_kernel::auth::effect::actor(&door)
            .unwrap()
            .to_owned()
    };
    let actor_a = identify(&token_a);
    let actor_b = identify(&token_b);
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let mint = |tok: &str| {
        client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", tok)
            .header("content-type", "application/json")
            .header("idempotency-key", "shared-value")
            .body(json::json!({"name": "k"}).to_string())
            .send()
    };

    let a = json::parse_value(&mint(&token_a).await.unwrap().bytes().await.unwrap()).unwrap();

    let b = json::parse_value(&mint(&token_b).await.unwrap().bytes().await.unwrap()).unwrap();

    assert!(a["id"].is_string() && b["id"].is_string());
    assert_ne!(
        a["id"], b["id"],
        "a second principal's identical Idempotency-Key must mint a NEW key, not replay A's"
    );
    assert_ne!(
        a["token"], b["token"],
        "B must never receive A's once-shown token via a cross-principal replay"
    );

    let a2 = json::parse_value(&mint(&token_a).await.unwrap().bytes().await.unwrap()).unwrap();
    assert_eq!(a2["id"], a["id"], "A's own retry replays A's response");

    assert_ne!(
        actor_a, actor_b,
        "separate verified issuers must retain different durable actor identities"
    );
    handle.abort();
    println!("{WITNESS}");
}

#[tokio::test]
async fn test_admin_v1_distinct_issuer_connectors_obey_verbs_and_revoke_independently() {
    const CHILD: &str = "BUSBAR_ADMIN_ISSUER_AB_VERBS_20261106";
    const WITNESS: &str = "actual root case test_admin_v1_distinct_issuer_connectors_obey_verbs_and_revoke_independently completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(
        "test_admin_v1_distinct_issuer_connectors_obey_verbs_and_revoke_independently-actual-store",
    );
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::abi::mechanism::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let token_a = common::credentials::token_for("same-subject", &["admins"], AUDIENCE);
    let issuer_b = "https://issuer-b.e2e.invalid";
    let token_b = common::credentials::token_with_claims(
        "same-subject",
        &["admins"],
        AUDIENCE,
        serde_json::json!({"iss": issuer_b}),
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": ["test-scope-module"], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "token": { "file": operator_token },
    });
    document["identity-providers"]["test-scope-module"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    let mut settings_b = common::credentials::settings(AUDIENCE);
    settings_b.insert("issuer".into(), serde_json::json!(issuer_b));
    document["identity-providers"]["second-issuer"] = serde_json::json!({
        "module": oidc_module, "settings": settings_b, "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] =
        serde_json::json!(["test-scope-module", "second-issuer", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "admins": { "verbs": ["get_info"] } },
        "second-issuer": { "admins": { "verbs": ["get_info"] } },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let anchor = crate::root::test_plugins::bootstrap_fresh_application_store(
        &config,
        &plugin_config,
        &directory,
    )
    .await
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugin_config,
        Some(overlay),
        HashSet::new(),
        HashSet::new(),
        (None, None),
        None,
        &rules,
        Some(anchor),
        true,
    )
    .await
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    // These are separately configured instances of the actual loaded OIDC module.
    let identify = |token: &str| {
        let headers = axum::http::HeaderMap::from_iter([(
            axum::http::HeaderName::from_static("authorization"),
            format!("Bearer {token}").parse().unwrap(),
        )]);
        let door =
            busbar_kernel::auth::admin_verdict(&app, "GET", "/api/v1/admin/info", &headers).door;
        assert!(busbar_kernel::auth::admin_door_admits(
            &door,
            "GET",
            "/api/v1/admin/info"
        ));
        busbar_kernel::auth::effect::actor(&door)
            .unwrap()
            .to_owned()
    };
    let actor_a = identify(&token_a);
    let actor_b = identify(&token_b);
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    assert_ne!(
        actor_a, actor_b,
        "the two actual verified issuers retain distinct actors"
    );
    let mut cells = Vec::new();
    for (connector, token) in [("A", &token_a), ("B", &token_b)] {
        let allowed = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        cells.push(json::json!({"connector":connector,"check":"named-verb-allowed","method":"GET","path":"/api/v1/admin/info","status":allowed.status().as_u16()}));
        assert_eq!(
            allowed.status().as_u16(),
            200,
            "issuer {connector} can use its one named verb"
        );
        let denied_read = client
            .get(format!("http://{addr}/api/v1/admin/keys"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap();
        cells.push(json::json!({"connector":connector,"check":"ungranted-read-denied","method":"GET","path":"/api/v1/admin/keys","status":denied_read.status().as_u16()}));
        assert_eq!(
            denied_read.status().as_u16(),
            403,
            "issuer {connector} does not inherit every read-only verb"
        );
        let denied_mint = client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .bearer_auth(token)
            .json(&json::json!({"name":"must-not-mint"}))
            .send()
            .await
            .unwrap();
        cells.push(json::json!({"connector":connector,"check":"mint-denied","method":"POST","path":"/api/v1/admin/keys","status":denied_mint.status().as_u16()}));
        assert_eq!(
            denied_mint.status().as_u16(),
            403,
            "issuer {connector} cannot mint a key"
        );
        let denied_escalation = client
            .put(format!("http://{addr}/api/v1/admin/admin-auth"))
            .bearer_auth(token)
            .json(&json::json!({"admin_auth":[operator]}))
            .send()
            .await
            .unwrap();
        cells.push(json::json!({"connector":connector,"check":"policy-escalation-denied","method":"PUT","path":"/api/v1/admin/admin-auth","status":denied_escalation.status().as_u16()}));
        assert_eq!(
            denied_escalation.status().as_u16(),
            403,
            "issuer {connector} cannot replace its own authorization policy"
        );
    }

    // Provider A stays in the data chain so its role binding remains valid.
    // This revokes admin access only; the test issues no data request.
    // The setup operator is used only for the actual configuration revocation.
    // A and B above and below always present separately issued OIDC JWTs.
    let revoked = client
        .put(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .json(&json::json!({"admin_auth":["second-issuer",operator]}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        revoked.status().as_u16(),
        200,
        "operator removes only connector A's issuer from the actual admin chain"
    );
    cells.push(json::json!({"check":"operator-revokes-only-A-issuer","method":"PUT","path":"/api/v1/admin/admin-auth","status":revoked.status().as_u16()}));
    let body = json::parse_value(&revoked.bytes().await.unwrap()).unwrap();
    assert_eq!(body["applied"], true);
    for attempt in 0..2 {
        let a = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .bearer_auth(&token_a)
            .send()
            .await
            .unwrap();
        cells.push(json::json!({"connector":"A","check":"revoked-still-signed-token-refused","attempt":attempt,"method":"GET","path":"/api/v1/admin/info","status":a.status().as_u16()}));
        assert_eq!(
            a.status().as_u16(),
            401,
            "revoked issuer A cannot replay its still-signed token, attempt {attempt}"
        );
        let b = client
            .get(format!("http://{addr}/api/v1/admin/info"))
            .bearer_auth(&token_b)
            .send()
            .await
            .unwrap();
        cells.push(json::json!({"connector":"B","check":"continues-without-token-reissue","attempt":attempt,"method":"GET","path":"/api/v1/admin/info","status":b.status().as_u16()}));
        assert_eq!(
            b.status().as_u16(),
            200,
            "issuer B continues without reissue after A is revoked, attempt {attempt}"
        );
        let b_denied = client
            .get(format!("http://{addr}/api/v1/admin/keys"))
            .bearer_auth(&token_b)
            .send()
            .await
            .unwrap();
        cells.push(json::json!({"connector":"B","check":"named-verb-ceiling-remains","attempt":attempt,"method":"GET","path":"/api/v1/admin/keys","status":b_denied.status().as_u16()}));
        assert_eq!(
            b_denied.status().as_u16(),
            403,
            "B retains its named-verb ceiling after A is revoked"
        );
    }
    let configured = client
        .get(format!("http://{addr}/api/v1/admin/admin-auth"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let configured = json::parse_value(&configured).unwrap();
    assert_eq!(
        configured["modules"],
        json::json!(["second-issuer", operator])
    );
    println!(
        "{}",
        json::json!({"schema":"busbar.admin-issuer-ab-scoped-proof/1","actor_a":actor_a,"actor_b":actor_b,"same_sub_distinct_issuers":true,"cells":cells,"revocation":"issuerA removed from admin_auth only; stays in data chain; no data request or external IdP JWT revocation claimed","bootstrap_operator_used_as_connector":false,"tls_scope":"separate protocol proof"})
    );
    handle.abort();
    println!("{WITNESS}");
}
