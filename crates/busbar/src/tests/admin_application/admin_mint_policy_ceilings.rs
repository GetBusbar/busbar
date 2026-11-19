// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::json::{self, JsonValueTrait as _};
use std::collections::HashSet;
use std::sync::Arc;

use busbar_kernel::governance::GovState;

use crate::test_common as common;

const AUDIENCE: &str = "api://admin-mint-ceiling";

#[tokio::test]
async fn proof_role_binding_mode_ceiling_bounds_a_delegated_admin() {
    const CHILD: &str = "BUSBAR_ADMIN_MINT_ROW_071D58CAEE11";
    const WITNESS: &str =
        "actual root case test_admin_v1_scope_ladder_e2e_with_group_mapped_principals completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    let allowed_modes = vec!["user-bound".to_string()];
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(&format!(
        "binding-ceiling-{}",
        allowed_modes.join("-")
    ));
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token = common::credentials::token_for(
        &principal.id,
        &principal
            .roles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        AUDIENCE,
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["identity-providers"]["test-scope-module"] = json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = json::json!({
        "test-scope-module": { "app-admin": { "admin_scope": "full" } },
    });
    document["auth"]["policy"] =
        json::json!({"mint_ceilings":{"app-admin":{"binding_modes":allowed_modes}}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
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
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
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
        .expect("this independent actual Store binds its rate history and usage recovery");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", format!("Bearer {}", &delegated_token))
        .json(&json::json!({ "name": "svc" }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let live = gov
        .all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none())
        .count();
    handle.abort();
    let (refused_status, refused_rows) = (status, live);
    assert_eq!(
        refused_status, 400,
        "a role whose binding_modes excludes time-bound must be refused at the mint ceiling"
    );
    assert_eq!(refused_rows, 0, "the refused mint writes NO key row");

    println!("{WITNESS}");
}

#[tokio::test]
async fn proof_role_binding_mode_ceiling_bounds_a_delegated_admin_allowed() {
    const CHILD: &str = "BUSBAR_ADMIN_MINT_ROW_A4CEB07F3D0C";
    const WITNESS: &str =
        "actual root case test_admin_v1_scope_ladder_e2e_with_group_mapped_principals completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    let allowed_modes = vec!["time-bound".to_string()];
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(&format!(
        "binding-ceiling-{}",
        allowed_modes.join("-")
    ));
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token = common::credentials::token_for(
        &principal.id,
        &principal
            .roles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        AUDIENCE,
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["identity-providers"]["test-scope-module"] = json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = json::json!({
        "test-scope-module": { "app-admin": { "admin_scope": "full" } },
    });
    document["auth"]["policy"] =
        json::json!({"mint_ceilings":{"app-admin":{"binding_modes":allowed_modes}}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
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
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
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
        .expect("this independent actual Store binds its rate history and usage recovery");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", format!("Bearer {}", &delegated_token))
        .json(&json::json!({ "name": "svc" }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let live = gov
        .all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none())
        .count();
    handle.abort();
    let (ok_status, ok_rows) = (status, live);
    assert_eq!(
        ok_status, 201,
        "a role whose binding_modes includes time-bound mints the key"
    );
    assert_eq!(ok_rows, 1, "the allowed mint writes exactly one key row");
    println!("{WITNESS}");
}

#[tokio::test]
async fn proof_max_ttl_ceiling_refuses_overask_and_clamps_default() {
    const CHILD: &str = "BUSBAR_ADMIN_MINT_ROW_7704756781AC";
    const WITNESS: &str =
        "actual root case test_admin_v1_scope_ladder_e2e_with_group_mapped_principals completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    async fn live_rows(gov: &GovState) -> usize {
        gov.all_keys_async()
            .await
            .unwrap()
            .into_iter()
            .filter(|k| k.enabled && k.deleted_at.is_none())
            .count()
    }

    let body = json::json!({"name":"svc","expires_in":"48h"});
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(&format!(
        "block-ttl-ceiling-{}",
        busbar_contract::redacted::sha256_hex(body.to_string().as_bytes())
    ));
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["auth"]["policy"] = json::json!({"max_ttl":"24h"});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
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
        .expect("this independent actual Store binds its rate history and usage recovery");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", "Bearer admintok")
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let json = json::parse_value(&resp.bytes().await.unwrap_or_default()).unwrap_or_default();
    let exp = json.get("expires_at").and_then(|v| v.as_u64());
    handle.abort();
    let (refused, gov_refused, _) = (status, gov, exp);
    assert_eq!(
        refused, 400,
        "an explicit expires_in over the max_ttl ceiling MUST be refused"
    );
    assert_eq!(
        live_rows(&gov_refused).await,
        0,
        "the refused over-ask writes NO key row"
    );

    println!("{WITNESS}");
}

#[tokio::test]
async fn proof_max_ttl_ceiling_refuses_overask_and_clamps_default_default_clamped() {
    const CHILD: &str = "BUSBAR_ADMIN_MINT_ROW_BD360208D7DF";
    const WITNESS: &str =
        "actual root case test_admin_v1_scope_ladder_e2e_with_group_mapped_principals completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const CEIL: u64 = 24 * 3600;

    let t0 = busbar_kernel::store::now();
    let body = json::json!({"name":"svc"});
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(&format!(
        "block-ttl-ceiling-{}",
        busbar_contract::redacted::sha256_hex(body.to_string().as_bytes())
    ));
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["auth"]["policy"] = json::json!({"max_ttl":"24h"});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let crate::root::min3_boot::fixture::Admitted {
        core: anchor,
        rules,
    } = crate::root::min3_boot::fixture::open(&config, &plugin_config, rules.clone())
        .await
        .expect("the actual Store opens the configuration authority")
        .admit()
        .await;
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
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
        .expect("this independent actual Store binds its rate history and usage recovery");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", "Bearer admintok")
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let json = json::parse_value(&resp.bytes().await.unwrap_or_default()).unwrap_or_default();
    let exp = json.get("expires_at").and_then(|v| v.as_u64());
    handle.abort();
    let (ok, _gov_ok, exp) = (status, gov, exp);
    assert_eq!(ok, 201, "a mint with no expiry succeeds");
    let exp = exp.expect("the 201 response carries expires_at");
    assert!(
        (t0 + CEIL..=busbar_kernel::store::now() + CEIL).contains(&exp),
        "the default lifetime is CLAMPED to the 24h ceiling (exp≈now+24h): exp={exp}, ceiling={CEIL}"
    );

    assert!(
        exp < t0 + busbar_kernel::governance::mint_policy::DEFAULT_KEY_TTL_SECS,
        "the clamped exp is strictly below the unclamped 90-day default"
    );
    println!("{WITNESS}");
}

#[tokio::test]
async fn proof_role_mint_ceiling_bounds_a_delegated_admin() {
    const CHILD: &str = "BUSBAR_ADMIN_MINT_ROW_54BE816778E7";
    const WITNESS: &str =
        "actual root case test_admin_v1_scope_ladder_e2e_with_group_mapped_principals completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const ROLE_TTL: u64 = 3600;

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    let body = json::json!({"name":"svc","allowed_pools":["pool-forbidden"],"expires_in":"10m"});
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(&format!(
        "role-mint-ceiling-{}",
        busbar_contract::redacted::sha256_hex(body.to_string().as_bytes())
    ));
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token = common::credentials::token_for(
        &principal.id,
        &principal
            .roles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        AUDIENCE,
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["identity-providers"]["test-scope-module"] = json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = json::json!({
        "test-scope-module": { "app-admin": { "admin_scope": "full" } },
    });
    document["auth"]["policy"] = json::json!({"mint_ceilings":{"app-admin":{"max_ttl":format!("{ROLE_TTL}s"),"allowed_pools":["pool-ok"]}}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
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
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
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
        .expect("this independent actual Store binds its rate history and usage recovery");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", format!("Bearer {}", &delegated_token))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let live = gov
        .all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none())
        .count();
    handle.abort();
    let (bad_pool, bad_pool_rows) = (status, live);
    assert_eq!(
        bad_pool, 400,
        "a pool outside the role mint ceiling MUST be refused"
    );
    assert_eq!(
        bad_pool_rows, 0,
        "the refused out-of-ceiling-pool mint writes NO key row"
    );

    println!("{WITNESS}");
}

#[tokio::test]
async fn proof_role_mint_ceiling_bounds_a_delegated_admin_over_ttl() {
    const CHILD: &str = "BUSBAR_ADMIN_MINT_ROW_E93F494407E5";
    const WITNESS: &str =
        "actual root case test_admin_v1_scope_ladder_e2e_with_group_mapped_principals completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const ROLE_TTL: u64 = 3600;

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    let body = json::json!({"name":"svc","allowed_pools":["pool-ok"],"expires_in":"24h"});
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(&format!(
        "role-mint-ceiling-{}",
        busbar_contract::redacted::sha256_hex(body.to_string().as_bytes())
    ));
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token = common::credentials::token_for(
        &principal.id,
        &principal
            .roles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        AUDIENCE,
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["identity-providers"]["test-scope-module"] = json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = json::json!({
        "test-scope-module": { "app-admin": { "admin_scope": "full" } },
    });
    document["auth"]["policy"] = json::json!({"mint_ceilings":{"app-admin":{"max_ttl":format!("{ROLE_TTL}s"),"allowed_pools":["pool-ok"]}}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
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
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
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
        .expect("this independent actual Store binds its rate history and usage recovery");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", format!("Bearer {}", &delegated_token))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let live = gov
        .all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none())
        .count();
    handle.abort();
    let (over_ttl, over_ttl_rows) = (status, live);
    assert_eq!(
        over_ttl, 400,
        "a TTL over the role mint ceiling MUST be refused"
    );
    assert_eq!(
        over_ttl_rows, 0,
        "the refused over-ceiling-TTL mint writes NO key row"
    );

    println!("{WITNESS}");
}

#[tokio::test]
async fn proof_role_mint_ceiling_bounds_a_delegated_admin_allowed() {
    const CHILD: &str = "BUSBAR_ADMIN_MINT_ROW_2FA2917C0833";
    const WITNESS: &str =
        "actual root case test_admin_v1_scope_ladder_e2e_with_group_mapped_principals completed";
    isolated!(CHILD, WITNESS);
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const ROLE_TTL: u64 = 3600;

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    let body = json::json!({"name":"svc","allowed_pools":["pool-ok"],"expires_in":"10m"});
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let (module, directory, settings) = crate::distribution::rig::actual_store(&format!(
        "role-mint-ceiling-{}",
        busbar_contract::redacted::sha256_hex(body.to_string().as_bytes())
    ));
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let oidc_path = common::plugins::token_verifier_cdylib_path()
        .expect("the freshly built actual OIDC product is required");
    let oidc_statement = busbar_plugin_loader::dispatch::rendering_of_library(&oidc_path)
        .expect("the actual OIDC statement reads")
        .expect("the actual OIDC exports its statement");
    let oidc_module = busbar_contract::rendering::read(&oidc_statement)
        .expect("the actual OIDC statement is valid")
        .name;
    common::credentials::install_auth_plugin(&directory, &oidc_module, "test-scope-module", true);
    let delegated_token = common::credentials::token_for(
        &principal.id,
        &principal
            .roles
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        AUDIENCE,
    );
    let signing_key = directory.join("signing-key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&signing_key, hex::encode([9u8; 32])).expect("write the test signing input");
    std::fs::write(&operator_token, "admintok").expect("write the test operator input");
    let operator = busbar_kernel::config::operator_provider();
    let mut document = json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": { "file": signing_key } },
        "store": { "module": module, "settings": settings },
        "advanced": {  },
        "identity-providers": {},
    });
    document["identity-providers"][operator] = json::json!({
        "module": operator, "settings": { "sha256": crate::root::test_plugins::operator_sha256_of(&operator_token) },
    });
    document["identity-providers"]["test-scope-module"] = json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings(AUDIENCE),
        "max_admin_scope": "full",
    });
    document["auth"]["admin_auth"] = json::json!(["test-scope-module", operator]);
    document["auth"]["role_bindings"] = json::json!({
        "test-scope-module": { "app-admin": { "admin_scope": "full" } },
    });
    document["auth"]["policy"] = json::json!({"mint_ceilings":{"app-admin":{"max_ttl":format!("{ROLE_TTL}s"),"allowed_pools":["pool-ok"]}}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        &document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
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
    .expect("the actual Store opens the configuration authority");
    let overlay = busbar_kernel::config::overlay::OverlayStore::from_core(anchor.clone())
        .expect("the actual Store supports conditional configuration records");
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        crate::root::test_plugins::plaintext_listeners(config),
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
        .expect("this independent actual Store binds its rate history and usage recovery");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let gov = app.governance.as_ref().expect("actual governance").clone();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{addr}/api/v1/admin/keys"))
        .header("authorization", format!("Bearer {}", &delegated_token))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let live = gov
        .all_keys_async()
        .await
        .unwrap()
        .into_iter()
        .filter(|k| k.enabled && k.deleted_at.is_none())
        .count();
    handle.abort();
    let (ok, ok_rows) = (status, live);
    assert_eq!(
        ok, 201,
        "an in-ceiling mint (allowed pool, within-ceiling TTL) succeeds"
    );
    assert_eq!(ok_rows, 1, "the allowed mint writes exactly one key row");
    println!("{WITNESS}");
}
