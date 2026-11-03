// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[tokio::test]
async fn a_stuck_mint_or_rotate_is_refused_in_flight_however_old_its_sentinel() {
    const CHILD: &str = "BUSBAR_ADMIN_SENTINEL_F1310C33";
    const WITNESS: &str = "actual hook case a_stuck_mint_or_rotate_is_refused_in_flight_however_old_its_sentinel completed";
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
    let mut manifest = plugins::manifest("store", &module, "third-party");
    manifest.statement = Some(hex::encode(statement));
    let directory = plugins::scratch(
        "a_stuck_mint_or_rotate_is_refused_in_flight_however_old_its_sentinel-actual-store",
    );
    let archive = plugins::signed(
        &plugins::key(0x33),
        manifest,
        &std::fs::read(store_library).expect("the actual Store artifact reads"),
    );
    let archive_sha256 = plugins::sha256(&archive);
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
        .expect("the actual admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual admin deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let mut plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: vec![busbar_kernel::config::PluginFetch::Url(
            busbar_kernel::config::UrlFetch {
                url: "https://plugins.invalid/store.tar.gz".into(),
                sha256: Some(archive_sha256),
            },
        )],
        ..Default::default()
    };
    plugin_config
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            public_key: hex::encode(plugins::key(0x33).verifying_key().as_bytes()),
        });
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
    let gov = app
        .governance
        .as_ref()
        .expect("the actual Store governance is present")
        .clone();
    let cache = Arc::new(busbar_core_admin::keys::KeyReplayCache::new());
    let router = busbar_kernel::build_router(Arc::new(app)).layer(axum::Extension(cache.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let created: serde_json::Value = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "rotated"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_string();
    let generation = || {
        gov.all_keys()
            .unwrap()
            .into_iter()
            .find(|k| k.id == id)
            .map(|k| k.generation_hash)
    };
    let before = generation();
    // These bytes are pinned against the private production key producers by
    // keys::admin_pure_contracts::key_replay_names_match_the_actual_http_controls.
    for key in [
        ("admin".to_string(), "create:10:stuck-mint".to_string()),
        (
            "admin".to_string(),
            format!("rotate:{}:{id}:12:stuck-rotate", id.len()),
        ),
    ] {
        match cache.probe(key, 1) {
            busbar_core_admin::idempotency::Probe::Reserved(r) => r.leak(),
            _ => panic!("a fresh cache reserves the first sighting"),
        }
    }

    let mint = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .header("idempotency-key", "stuck-mint")
        .body(serde_json::json!({"name": "k"}).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        mint.status().as_u16(),
        409,
        "the retry of a mint still in flight is refused, not minted a second time"
    );
    let rotate = client
        .post(format!("{keys_url}/{id}/rotate"))
        .header("x-admin-token", "admintok")
        .header("idempotency-key", "stuck-rotate")
        .send()
        .await
        .unwrap();
    assert_eq!(
        rotate.status().as_u16(),
        409,
        "the retry of a rotate still in flight is refused, not rotated a second time"
    );
    assert_eq!(
        gov.all_keys().unwrap().len(),
        1,
        "the retried mint minted nothing"
    );
    assert_eq!(
        generation(),
        before,
        "the retried rotate issued no new credential"
    );

    handle.abort();
    println!("{WITNESS}");
}
