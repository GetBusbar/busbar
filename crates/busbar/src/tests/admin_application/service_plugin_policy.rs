// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use base64::Engine as _;
use busbar_contract::json::{self, JsonValueTrait};
use std::sync::Arc;

/// The actual product's admin API over the actual native Store, with `extra` plugin names trusted
/// for the fixture publisher's key (an inspected candidate is admitted only when trusted).
async fn admin_api(
    directory: &std::path::Path,
    extra: &[&str],
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>, Vec<u8>) {
    crate::dist_root_install::install();
    let library_path = crate::root::test_plugins::application_store_library();
    let module = crate::root::test_plugins::native_image(&library_path).name;
    let manifest = crate::root::test_plugins::native_manifest(
        "store",
        &library_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), &archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": {  },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let mut plugin_config = crate::root::test_plugins::trusted_config(directory);
    for publisher in &mut plugin_config.trust.publishers {
        if publisher.name == crate::root::test_plugins::FIXTURE_PUBLISHER {
            publisher
                .plugins
                .extend(extra.iter().map(|name| (*name).to_owned()));
        }
    }
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, server, archive)
}

async fn inspect(addr: std::net::SocketAddr, file: &str, tarball: &[u8]) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .json(&json::json!({"file": file, "tarball_b64": base64::engine::general_purpose::STANDARD.encode(tarball)}))
        .send()
        .await
        .unwrap()
}

/// IF r29 l.2764 (core's D_SCHEMA validator): a native image's authoritative schema is its describe's D_SCHEMA,
/// so inspect stages and describes the candidate, and a pathological one is refused before admission.
#[tokio::test]
async fn inspect_bounds_pathological_schema_nesting_depth() {
    let directory = plugins::scratch(&format!(
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let bomb_path = crate::root::test_plugins::native_schema_bomb_path().unwrap_or_else(|| {
        crate::root::test_plugins::missing(
            "native_schema_bomb",
            crate::root::test_plugins::BUILD_LOADER_EXAMPLES,
        )
    });
    let bomb = crate::root::test_plugins::native_image(&bomb_path).name;
    let (addr, server, _) = admin_api(&directory, &[bomb.as_str()]).await;
    let candidate = crate::root::test_plugins::native_manifest(
        "store",
        &bomb_path,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let tarball = plugins::signed(
        &plugins::key(0x5a),
        candidate,
        &std::fs::read(&bomb_path).expect("the bomb image reads"),
    );
    let response = inspect(addr, "depthbomb.tar.gz", &tarball).await;
    assert_eq!(
        response.status().as_u16(),
        400,
        "a pathological authoritative schema is refused before plugin admission"
    );
    let view = json::parse_value(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(view["error"]["code"], "invalid_request");
    let error = view["error"]["message"]
        .as_str()
        .expect("schema refusal is set");
    assert!(error.contains("D_SCHEMA"), "got {error:?}");
    assert!(error.contains("recursion limit exceeded"), "got {error:?}");
    server.abort();
}

/// A native plugin's inspected schema is its describe's D_SCHEMA, not the empty manifest settings_schema.
#[tokio::test]
async fn inspect_serves_a_native_plugins_schema_from_its_describe() {
    let directory = plugins::scratch(&format!(
        "admin-native-schema-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let (addr, server, archive) = admin_api(&directory, &[]).await;
    let response = inspect(addr, "store.tar.gz", &archive).await;
    assert_eq!(response.status().as_u16(), 200, "the actual Store inspects");
    let view = json::parse_value(&response.bytes().await.unwrap()).unwrap();
    assert!(
        view["schema"]["properties"]["db_path"].is_object(),
        "the view serves the image's D_SCHEMA: {view:?}"
    );
    assert!(view["schema_error"].is_null(), "{view:?}");
    server.abort();
}
#[tokio::test]
async fn install_rejects_bad_filenames() {
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
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": {  },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let before: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    for bad in [
        "../escape.tar.gz",
        "sub/dir.tar.gz",
        "no_extension",
        "plain.so",
        "",
    ] {
        let response = client.post(format!("http://{addr}/api/v1/admin/plugins"))
            .header("x-admin-token", "admintok")
            .json(&json::json!({"file":bad, "tarball_b64":base64::engine::general_purpose::STANDARD.encode(b"bytes")}))
            .send().await.unwrap();
        assert_eq!(
            response.status().as_u16(),
            400,
            "filename `{bad}` must reject"
        );
        let error = json::parse_value(&response.bytes().await.unwrap()).unwrap();
        assert_eq!(error["error"]["code"], "invalid_request");
    }
    let after: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(after, before, "invalid filenames publish no files");
    server.abort();
}

#[tokio::test]
async fn inspect_verdicts_refuse_malformed_archives_without_publication() {
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
        "admin-service-plugin-policy-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let operator_token = directory.join("operator-token");
    let signing_key = directory.join("signing-key");
    std::fs::write(&operator_token, "admintok").unwrap();
    std::fs::write(&signing_key, hex::encode([9u8; 32])).unwrap();
    let operator = busbar_kernel::config::operator_provider();
    let mut document = serde_json::json!({
        "providers": {},
        "models": {},
        "groups": {},
        "auth": { "chain": [], "admin_auth": [operator], "signing_key": {"file": signing_key} },
        "identity-providers": {},
        "store": { "module": module, "settings": settings },
        "advanced": {  },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let _book = crate::root::boot::book(&app, &module)
        .await
        .expect("the actual Store binds the rate-card authority before activation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let before: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let response = client.post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .json(&json::json!({"file":"candidate.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(b"not a tarball at all")}))
        .send().await.unwrap();
    assert_eq!(response.status().as_u16(), 400);
    let error = json::parse_value(&response.bytes().await.unwrap()).unwrap();
    assert_eq!(error["error"]["code"], "invalid_request");
    let after: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(after, before, "inspect publishes nothing");
    server.abort();
}
