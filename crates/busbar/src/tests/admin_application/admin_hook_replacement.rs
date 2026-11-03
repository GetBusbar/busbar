// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

use crate::root::test_plugins as plugins;

#[tokio::test]
async fn test_admin_v1_put_hook_replaces_live_with_guards() {
    const CHILD: &str = "BUSBAR_ADMIN_HOOK_CBC1E5D09CB7";
    const WITNESS: &str =
        "actual hook case test_admin_v1_put_hook_replaces_live_with_guards completed";
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
    let directory =
        plugins::scratch("test_admin_v1_put_hook_replaces_live_with_guards-actual-store");
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
        crate::root::test_plugins::FIXTURE_PUBLISHER,
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
    let ranking_library = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_TEST_RANKING_CDYLIB")
            .expect("the hook replacement requires the actual Ranking product"),
    );
    let ranking_statement = busbar_plugin_loader::dispatch::rendering_of_library(&ranking_library)
        .expect("the actual Ranking statement reads")
        .expect("the actual Ranking product states its door");
    let ranking_facts = busbar_contract::abi::mechanism::rendering::read(&ranking_statement)
        .expect("the actual Ranking statement parses");
    let ranking_module = ranking_facts.name;
    let mut ranking_manifest =
        plugins::manifest("hook", &ranking_module, plugins::FIXTURE_PUBLISHER);
    ranking_manifest.alias = "ranking".into();
    ranking_manifest.version = ranking_facts.version;
    ranking_manifest.statement = Some(hex::encode(ranking_statement));
    let ranking_archive = plugins::signed(
        &crate::dist_root_install::release_key(),
        ranking_manifest,
        &std::fs::read(ranking_library).expect("the actual Ranking library reads"),
    );
    std::fs::write(directory.join("ranking.tar.gz"), ranking_archive)
        .expect("stage the actual signed Ranking replacement");
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
    assert!(
        app.hook_env.registry.resolve("test-hook").is_some(),
        "the actual signed hook is admitted and resolves through its alias"
    );
    let replacement = app
        .hook_env
        .registry
        .resolve("ranking")
        .expect("the actual signed Ranking replacement is required");
    assert!(
        !replacement.linked,
        "the replacement must be the actual signed dropped product"
    );
    assert_eq!(replacement.kind, "hook");
    assert_eq!(replacement.name, ranking_module);
    let replacement_module = replacement.name;
    assert_ne!(
        replacement_module, hook_module,
        "the replacement is a distinct actual product"
    );
    let router = busbar_kernel::build_router(Arc::new(app));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();

    let admin = |req: reqwest::RequestBuilder| {
        req.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    let missing = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/nope")))
        .body(serde_json::json!({"config": {"kind": "tap", "module": "test-hook", "settings": {"url":"http://127.0.0.1:1/"}}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status().as_u16(), 404);

    let created = admin(client.post(format!("http://{addr}/api/v1/admin/hooks")))
        .body(
            serde_json::json!({
                "name": "rep",
                "config": {"kind": "tap", "module": "test-hook", "settings": {"url":"http://127.0.0.1:1/"}}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201);
    let replaced = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(serde_json::json!({"config": {"kind": "tap", "module": replacement_module, "settings": {"policy":"cheapest"}}}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status().as_u16(), 200);
    let got: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        got["transport"].to_string().contains(&replacement_module),
        "the replacement is live: {got}"
    );

    let escalate = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .body(
            serde_json::json!({"config": {"kind": "gate", "module": "test-hook", "settings": {"url":"http://127.0.0.1:1/"}, "prompt": "rw"}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(escalate.status().as_u16(), 409, "grants are immutable");

    let stale = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", "\"0\"")
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "module": "test-hook", "settings": {"url":"http://127.0.0.1:1/"}},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(stale.status().as_u16(), 409, "stale If-Match conflicts");

    let live = admin(client.get(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .send()
        .await
        .unwrap();
    let etag = live
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .expect("config-plane reads emit the ETag")
        .to_string();
    let fresh = admin(client.put(format!("http://{addr}/api/v1/admin/hooks/rep")))
        .header("if-match", etag)
        .body(
            serde_json::json!({
                "config": {"kind": "tap", "module": "test-hook", "settings": {"url":"http://127.0.0.1:1/"}},
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(fresh.status().as_u16(), 200, "current If-Match applies");
    assert!(
        fresh.headers().get(reqwest::header::ETAG).is_some(),
        "the mutation response carries the NEW ETag for chaining"
    );

    handle.abort();
    handle.abort();
    let _ = handle.await;
    println!("{WITNESS}");
}
