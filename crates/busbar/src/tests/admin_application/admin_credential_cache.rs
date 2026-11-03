// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use crate::test_common as common;
use crate::root::test_plugins as plugins;

const AUDIENCE: &str = "api://admin-cache-flush";

#[tokio::test]
async fn filtered_credential_flush_uses_actual_admin_and_data_caches() {
    const CHILD: &str = "BUSBAR_ADMIN_CACHE_FLUSH_CHILD";
    const WITNESS: &str =
        "actual root case filtered_credential_flush_uses_actual_admin_and_data_caches completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let name = std::thread::current()
            .name()
            .expect("the test runner names its exact test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root case"),
        );
        let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual-root child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual-root child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    crate::dist_root_install::install();
    let store_library = crate::root::test_plugins::application_store_library();
    let statement = busbar_plugin_loader::dispatch::rendering_of_library(&store_library)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the Store statement is valid")
        .name;
    let mut manifest = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "filtered_credential_flush_uses_actual_admin_and_data_caches-actual-store",
    );
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    document["identity-providers"]["omitted"] = serde_json::json!({
        "module": oidc_module,
        "settings": common::credentials::settings("api://omitted-cache"),
        "max_admin_scope": "full",
    });
    document["auth"]["chain"] = serde_json::json!(["test-scope-module"]);
    document["auth"]["admin_auth"] = serde_json::json!(["test-scope-module", "omitted", operator]);
    document["auth"]["role_bindings"] = serde_json::json!({
        "test-scope-module": { "admins": { "admin_scope": "full" }, "viewers": { "admin_scope": "read-only" } },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
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
        true,
    )
    .expect("the real root composes the configured Store and admin application");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .expect("the actual Store binds rate-card history and usage recovery before activation");
    limits.keep().expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }

    let app = Arc::new(app);
    let target_token = common::credentials::token_for("cache-target", &["admins"], AUDIENCE);
    let omitted_token =
        common::credentials::token_for("cache-omitted", &["admins"], "api://omitted-cache");
    // Seed the real, independently opened admin instances, not a supplied refresh answer.
    for (name, token) in [
        ("test-scope-module", &target_token),
        ("omitted", &omitted_token),
    ] {
        let mut request = busbar_contract::auth_calls::VerifyRequest::default();
        request.credential = Some(busbar_contract::redacted::Secret::new(
            token.as_bytes().to_vec(),
        ));
        request.timestamp = busbar_kernel::store::now();
        let answer = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            app.admin_modules.modules[name].calls.verify(request),
        )
        .await
        .unwrap();
        assert!(matches!(
            answer.verified,
            busbar_contract::auth_calls::Verified::Identity(_)
        ));
    }
    let verdict = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        busbar_kernel::auth::AuthMiddleware::run_chain_on_request_path(
            &app.auth,
            Some(target_token),
            Default::default(),
            app.governance.clone(),
            None,
        ),
    )
    .await
    .unwrap();
    assert!(matches!(
        verdict,
        busbar_kernel::auth::ChainVerdict::Identified { .. }
    ));
    let router = busbar_kernel::build_router(app);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let flush = |token: String, body: serde_json::Value| {
        client
            .post(format!("http://{addr}/api/v1/admin/auth/cache/flush"))
            .header("x-admin-token", token)
            .json(&body)
            .send()
    };
    let viewer = common::credentials::token_for("cache-viewer", &["viewers"], AUDIENCE);
    assert_eq!(
        flush(viewer, serde_json::json!({"module":"test-scope-module"}))
            .await
            .unwrap()
            .status()
            .as_u16(),
        403,
        "a read-only caller cannot flush any cache"
    );
    // The viewer's genuine authentication adds one admin cache entry. Its forbidden
    // mutation leaves both original target entries present: two admin + one data.
    let answer = flush(
        "admintok".into(),
        serde_json::json!({"module":"test-scope-module"}),
    )
    .await
    .unwrap();
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(
        answer.json::<serde_json::Value>().await.unwrap()["flushed"],
        3
    );
    let answer = flush("admintok".into(), serde_json::json!({"module":operator}))
        .await
        .unwrap();
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(
        answer.json::<serde_json::Value>().await.unwrap()["flushed"],
        0
    );
    let answer = flush(
        "admintok".into(),
        serde_json::json!({"module":"not-configured"}),
    )
    .await
    .unwrap();
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(
        answer.json::<serde_json::Value>().await.unwrap()["flushed"],
        0
    );
    let answer = flush("admintok".into(), serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(answer.status().as_u16(), 200);
    assert_eq!(
        answer.json::<serde_json::Value>().await.unwrap()["flushed"],
        1,
        "the filtered flush did not touch the omitted real admin instance"
    );
    let answer = flush("admintok".into(), serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(
        answer.json::<serde_json::Value>().await.unwrap()["flushed"],
        0,
        "the unfiltered flush reached both chains"
    );
    assert_eq!(
        flush("admintok".into(), serde_json::json!({"module":7}))
            .await
            .unwrap()
            .status()
            .as_u16(),
        400
    );
    serving.abort();
    println!("{WITNESS}");
}
