// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn create_and_rotate_operation_namespaces_survive_cache_loss() {
    for create_first in [true, false] {
        for lose_cache in [false, true] {
            busbar_kernel::snapshot::init_for_test(std::time::Duration::from_secs(3600));
            crate::dist_root_install::install();
            let store_library = PathBuf::from(
                std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN").expect(
                    "BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store product",
                ),
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
            let directory =
                plugins::scratch(&format!("operation-namespaces-{create_first}-{lose_cache}"));
            let archive = plugins::signed(
                &crate::dist_root_install::release_key(),
                manifest,
                &std::fs::read(store_library).expect("the actual Store artifact reads"),
            );
            std::fs::write(directory.join("store.tar.gz"), archive)
                .expect("stage the actual Store");
            let settings: serde_json::Value = serde_json::from_str(
                &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS")
                    .unwrap_or_else(|_| "{}".into()),
            )
            .expect("actual Store settings are JSON");
            assert!(
                settings.is_object(),
                "the actual Store settings are an object"
            );
            let signing_key = directory.join("signing-key");
            let operator_token = directory.join("operator-token");
            std::fs::write(&signing_key, hex::encode([9u8; 32]))
                .expect("write the test signing input");
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
            )
            .expect("the real root composes the configured Store and admin application");
            limits.keep().expect("the actual limits commit");
            if let Some(rotate) = rotate {
                rotate();
            }
            let app = Arc::new(app);
            let gov = app.governance.as_ref().expect("actual governance").clone();
            let router = busbar_kernel::build_router(app.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut addr = listener.local_addr().unwrap();
            let mut server =
                tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let client = reqwest::Client::new();
            let created: serde_json::Value = client
                .post(format!("http://{addr}/api/v1/admin/keys"))
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": "rotate-target"}))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            let target = created["id"]
                .as_str()
                .expect("the target was minted")
                .to_string();
            let original_token = created["token"]
                .as_str()
                .expect("mint returned a token")
                .to_string();
            let rotate_header = "operation-collision";
            let create_header = format!(
                "rotate:{}:{}:{}:{}",
                target.len(),
                target,
                rotate_header.len(),
                rotate_header
            );
            for first in [true, false] {
                if !first && lose_cache {
                    server.abort();
                    let _ = server.await;
                    let router = busbar_kernel::build_router(app.clone());
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    addr = listener.local_addr().unwrap();
                    server =
                        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
                }
                let create = first == create_first;
                let request = if create {
                    client
                        .post(format!("http://{addr}/api/v1/admin/keys"))
                        .header("idempotency-key", &create_header)
                        .json(&serde_json::json!({"name": "independent-create"}))
                } else {
                    client
                        .post(format!("http://{addr}/api/v1/admin/keys/{target}/rotate"))
                        .header("idempotency-key", rotate_header)
                };
                let response = request
                    .header("x-admin-token", "admintok")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status().as_u16(), if create { 201 } else { 200 });
                let body: serde_json::Value = response.json().await.unwrap();
                let id = body["id"].as_str().expect("the operation returns a key id");
                let token = body["token"]
                    .as_str()
                    .filter(|t| !t.is_empty())
                    .expect("a real token");
                if create {
                    assert!(
                        id != target,
                        "create must mint its own key, never replay the rotation"
                    );
                } else {
                    assert!(id == target, "rotate must answer for its actual target");
                    assert!(
                        token != original_token,
                        "rotate must retire the original token"
                    );
                }
            }
            assert_eq!(
                gov.all_keys().unwrap().len(),
                2,
                "one target and one independent create"
            );
            server.abort();
            let _ = server.await;
        }
    }
}
