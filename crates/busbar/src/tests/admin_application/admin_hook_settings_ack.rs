// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn test_admin_v1_hook_settings_patch_commit_on_ack_and_schema() {
    const CHILD: &str = "BUSBAR_ADMIN_SETTINGS_F1310C31";
    const WITNESS: &str =
        "actual hook case test_admin_v1_hook_settings_patch_commit_on_ack_and_schema completed";
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
    let directory =
        plugins::scratch("test_admin_v1_hook_settings_patch_commit_on_ack_and_schema-actual-store");
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
    let hook_path = plugins::cdylib_path("busbar_hook_webrequest_plugin")
        .expect("the actual built webrequest hook product is required");
    let hook_statement = busbar_plugin_loader::dispatch::rendering_of_library(&hook_path)
        .expect("actual hook statement reads")
        .expect("the actual hook states its door");
    let hook_module = busbar_contract::abi::mechanism::rendering::read(&hook_statement)
        .expect("valid actual hook statement")
        .name;
    let mut hook_manifest = plugins::manifest(
        "hook",
        &hook_module,
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    hook_manifest.alias = "test-hook".to_string();
    hook_manifest.statement = Some(hex::encode(hook_statement));
    let archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        hook_manifest,
        &std::fs::read(hook_path).unwrap(),
    );
    std::fs::write(directory.join("hook.tar.gz"), archive)
        .expect("stage actual signed hook product");
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
    assert!(
        app.hook_env.registry.resolve("test-hook").is_some(),
        "the actual signed hook is admitted and resolves through its alias"
    );
    let env_for_warm = app.hook_env.clone();
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "cfg-hook",
                "config": {"kind": "gate", "module": "test-hook", "settings": {"url": "http://127.0.0.1:1/"}}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);

    let warm: busbar_kernel::config::HookCfg = serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "settings": {"url": "http://127.0.0.1:1/", "timeout_ms": 40}
    }))
    .expect("hook cfg");
    busbar_kernel::hooks::push_configure(&warm, "cfg-hook", 1, &env_for_warm)
        .await
        .expect("the actual admitted hook acknowledges configuration before PATCH");
    let patched = admin(client.patch(format!(
        "http://{addr}/api/v1/admin/hooks/cfg-hook/settings"
    )))
    .body(
        serde_json::json!({"settings": {"url": "http://127.0.0.1:1/", "timeout_ms": 40}})
            .to_string(),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(patched.status().as_u16(), 200, "{:?}", patched.text().await);
    let got: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    assert_eq!(
        got["settings_keys"],
        serde_json::json!(["timeout_ms", "url"]),
        "committed settings visible as KEY NAMES: {got}"
    );
    assert!(
        got.get("settings").is_none(),
        "the raw settings bag must never be on this wire: {got}"
    );

    let schema: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/hooks/cfg-hook/schema")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert_eq!(
        schema["schema"]["properties"]["timeout_ms"]["type"], "integer",
        "describe schema extracted, single nest: {schema}"
    );

    handle.abort();
    println!("{WITNESS}");
}
