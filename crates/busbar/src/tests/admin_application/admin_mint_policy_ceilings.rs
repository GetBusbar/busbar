// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use busbar_kernel::governance::GovState;

#[path = "../../../../../dist/default/tests/common/mod.rs"]
mod common;
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

const AUDIENCE: &str = "api://admin-mint-ceiling";

#[tokio::test]
async fn proof_role_binding_mode_ceiling_bounds_a_delegated_admin() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    async fn mint_under(
        principal: &busbar_kernel::auth::Principal,
        allowed_modes: Vec<String>,
    ) -> (u16, usize) {
        busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
        crate::dist_root_install::install();
        let store_library = PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
            .expect("the actual Store statement reads")
            .expect("the actual Store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the Store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let directory = plugins::scratch(&format!("binding-ceiling-{}", allowed_modes.join("-")));
        let archive = plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(store_library).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("actual Store settings are JSON");
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
        common::credentials::install_auth_plugin(
            &directory,
            &oidc_module,
            "test-scope-module",
            true,
        );
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
            "test-scope-module": { "app-admin": { "admin_scope": "full" } },
        });
        document["auth"]["policy"] =
            serde_json::json!({"mint_ceilings":{"app-admin":{"binding_modes":allowed_modes}}});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .expect("the actual Store opens the configuration authority");
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(
            anchor
                .calls
                .as_ref()
                .cloned()
                .expect("the actual Store exposes typed calls"),
        )
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
            false,
        )
        .expect("the real root composes the configured Store and admin application");
        limits.keep().expect("the actual limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let gov = app.governance.as_ref().expect("actual governance").clone();
        let router = busbar_kernel::build_router(Arc::new(app));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", &delegated_token)
            .json(&serde_json::json!({ "name": "svc" }))
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let live = gov
            .all_keys()
            .unwrap()
            .into_iter()
            .filter(|k| k.enabled && k.deleted_at.is_none())
            .count();
        handle.abort();
        (status, live)
    }

    let (refused_status, refused_rows) =
        mint_under(&principal, vec!["user-bound".to_string()]).await;
    assert_eq!(
        refused_status, 400,
        "a role whose binding_modes excludes time-bound must be refused at the mint ceiling"
    );
    assert_eq!(refused_rows, 0, "the refused mint writes NO key row");

    let (ok_status, ok_rows) = mint_under(&principal, vec!["time-bound".to_string()]).await;
    assert_eq!(
        ok_status, 201,
        "a role whose binding_modes includes time-bound mints the key"
    );
    assert_eq!(ok_rows, 1, "the allowed mint writes exactly one key row");
}

#[tokio::test]
async fn proof_max_ttl_ceiling_refuses_overask_and_clamps_default() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const CEIL: u64 = 24 * 3600;

    async fn mint(body: serde_json::Value) -> (u16, Arc<GovState>, Option<u64>) {
        busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
        crate::dist_root_install::install();
        let store_library = PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
            .expect("the actual Store statement reads")
            .expect("the actual Store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the Store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let directory = plugins::scratch(&format!(
            "block-ttl-ceiling-{}",
            busbar_contract::redacted::sha256_hex(body.to_string().as_bytes())
        ));
        let archive = plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(store_library).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("actual Store settings are JSON");
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
        document["auth"]["policy"] = serde_json::json!({"max_ttl":"24h"});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .expect("the actual Store opens the configuration authority");
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(
            anchor
                .calls
                .as_ref()
                .cloned()
                .expect("the actual Store exposes typed calls"),
        )
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
            false,
        )
        .expect("the real root composes the configured Store and admin application");
        limits.keep().expect("the actual limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let gov = app.governance.as_ref().expect("actual governance").clone();
        let router = busbar_kernel::build_router(Arc::new(app));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", "admintok")
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let json: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        let exp = json.get("expires_at").and_then(|v| v.as_u64());
        handle.abort();
        (status, gov, exp)
    }

    fn live_rows(gov: &GovState) -> usize {
        gov.all_keys()
            .unwrap()
            .into_iter()
            .filter(|k| k.enabled && k.deleted_at.is_none())
            .count()
    }

    let t0 = busbar_kernel::store::now();
    let (refused, gov_refused, _) =
        mint(serde_json::json!({ "name": "svc", "expires_in": "48h" })).await;
    assert_eq!(
        refused, 400,
        "an explicit expires_in over the max_ttl ceiling MUST be refused"
    );
    assert_eq!(
        live_rows(&gov_refused),
        0,
        "the refused over-ask writes NO key row"
    );

    let (ok, _gov_ok, exp) = mint(serde_json::json!({ "name": "svc" })).await;
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
}

#[tokio::test]
async fn proof_role_mint_ceiling_bounds_a_delegated_admin() {
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    const ROLE_TTL: u64 = 3600;

    let principal = busbar_kernel::auth::Principal {
        id: "delegated-admin".to_string(),
        name: None,
        roles: vec!["app-admin".to_string()],
        ttl_secs: None,
    };

    async fn mint_under(
        principal: &busbar_kernel::auth::Principal,
        body: serde_json::Value,
    ) -> (u16, usize) {
        busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
        crate::dist_root_install::install();
        let store_library = PathBuf::from(
            std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
                .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product"),
        );
        let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
            .expect("the actual Store statement reads")
            .expect("the actual Store exports its statement");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the Store statement is valid")
            .name;
        let mut manifest = plugins::manifest(
            "store",
            &module,
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let directory = plugins::scratch(&format!(
            "role-mint-ceiling-{}",
            busbar_contract::redacted::sha256_hex(body.to_string().as_bytes())
        ));
        let archive = plugins::signed(
            &crate::dist_root_install::release_key(),
            manifest,
            &std::fs::read(store_library).expect("the actual Store artifact reads"),
        );
        std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
        let settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("actual Store settings are JSON");
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
        common::credentials::install_auth_plugin(
            &directory,
            &oidc_module,
            "test-scope-module",
            true,
        );
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
            "test-scope-module": { "app-admin": { "admin_scope": "full" } },
        });
        document["auth"]["policy"] = serde_json::json!({"mint_ceilings":{"app-admin":{"max_ttl":format!("{ROLE_TTL}s"),"allowed_pools":["pool-ok"]}}});
        let deploy = busbar_kernel::config::deploy_from_deserializer(document)
            .expect("the actual admin deployment parses");
        let config = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual admin deployment resolves");
        let rules = Arc::new(crate::root::door_steps::Rules::default())
            as Arc<dyn busbar_kernel::appbuild::RootRules>;
        let plugin_config = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let anchor = busbar_kernel::appbuild::bootstrap_config_store(&config, &plugin_config)
            .expect("the actual Store opens the configuration authority");
        let overlay = busbar_kernel::config::overlay::OverlayStore::new(
            anchor
                .calls
                .as_ref()
                .cloned()
                .expect("the actual Store exposes typed calls"),
        )
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
            false,
        )
        .expect("the real root composes the configured Store and admin application");
        limits.keep().expect("the actual limits commit");
        if let Some(rotate) = rotate {
            rotate();
        }
        let gov = app.governance.as_ref().expect("actual governance").clone();
        let router = busbar_kernel::build_router(Arc::new(app));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/api/v1/admin/keys"))
            .header("x-admin-token", &delegated_token)
            .json(&body)
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let live = gov
            .all_keys()
            .unwrap()
            .into_iter()
            .filter(|k| k.enabled && k.deleted_at.is_none())
            .count();
        handle.abort();
        (status, live)
    }

    let (bad_pool, bad_pool_rows) = mint_under(
        &principal,
        serde_json::json!({ "name": "svc", "allowed_pools": ["pool-forbidden"], "expires_in": "10m" }),
    )
    .await;
    assert_eq!(
        bad_pool, 400,
        "a pool outside the role mint ceiling MUST be refused"
    );
    assert_eq!(
        bad_pool_rows, 0,
        "the refused out-of-ceiling-pool mint writes NO key row"
    );

    let (over_ttl, over_ttl_rows) = mint_under(
        &principal,
        serde_json::json!({ "name": "svc", "allowed_pools": ["pool-ok"], "expires_in": "24h" }),
    )
    .await;
    assert_eq!(
        over_ttl, 400,
        "a TTL over the role mint ceiling MUST be refused"
    );
    assert_eq!(
        over_ttl_rows, 0,
        "the refused over-ceiling-TTL mint writes NO key row"
    );

    let (ok, ok_rows) = mint_under(
        &principal,
        serde_json::json!({ "name": "svc", "allowed_pools": ["pool-ok"], "expires_in": "10m" }),
    )
    .await;
    assert_eq!(
        ok, 201,
        "an in-ceiling mint (allowed pool, within-ceiling TTL) succeeds"
    );
    assert_eq!(ok_rows, 1, "the allowed mint writes exactly one key row");
}
