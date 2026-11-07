// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins as plugins;
use base64::Engine as _;
use std::sync::Arc;

#[tokio::test]
async fn inspect_bounds_pathological_schema_nesting_depth() {
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
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
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
    let bomb = format!("{}true{}", "{\"allOf\":[".repeat(500), "]}".repeat(500));
    let mut candidate = plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    let mut statement = busbar_plugin_loader::dispatch::rendering_of_library(
        &crate::root::test_plugins::application_store_library(),
    )
    .expect("the actual Store statement reads")
    .expect("the actual Store exports its statement");
    let stated = busbar_contract::abi::mechanism::rendering::read(&statement).unwrap();
    let schema = &stated.settings_schema;
    // Replace only the authoritative schema blob in the current signed Statement.
    // The canonical rendering encodes a blob as fmt, flags, u32 length, then bytes.
    let mut original = schema.fmt.to_le_bytes().to_vec();
    original.extend_from_slice(&schema.flags.to_le_bytes());
    original.extend_from_slice(&u32::try_from(schema.bytes.len()).unwrap().to_le_bytes());
    original.extend_from_slice(&schema.bytes);
    let offsets: Vec<_> = statement
        .windows(original.len())
        .enumerate()
        .filter_map(|(at, bytes)| (bytes == original).then_some(at))
        .collect();
    assert_eq!(
        offsets.len(),
        1,
        "the actual schema blob occurs exactly once"
    );
    let mut malformed = schema.fmt.to_le_bytes().to_vec();
    malformed.extend_from_slice(&schema.flags.to_le_bytes());
    malformed.extend_from_slice(&u32::try_from(bomb.len()).unwrap().to_le_bytes());
    malformed.extend_from_slice(bomb.as_bytes());
    statement.splice(offsets[0]..offsets[0] + original.len(), malformed);
    let injected = busbar_contract::abi::mechanism::rendering::read(&statement).unwrap();
    assert_eq!(injected.name, module);
    assert_eq!(injected.settings_schema.bytes, bomb.as_bytes());
    candidate.statement = Some(hex::encode(statement));
    let tarball = plugins::signed(
        &crate::dist_root_install::release_key(),
        candidate,
        &library,
    );
    let router =
        busbar_kernel::build_router(crate::root::real_store::hydrated(Arc::new(app)).await);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let client = reqwest::Client::new();
    let response = client.post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"file":"depthbomb.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(tarball)}))
        .send().await.unwrap();
    assert_eq!(
        response.status().as_u16(),
        400,
        "a pathological authoritative schema is refused before plugin admission"
    );
    let view: serde_json::Value = response.json().await.unwrap();
    assert_eq!(view["error"]["code"], "invalid_request");
    let error = view["error"]["message"]
        .as_str()
        .expect("schema refusal is set");
    assert!(error.contains("Statement settings_schema"), "got {error:?}");
    assert!(error.contains("recursion limit exceeded"), "got {error:?}");
    server.abort();
}
#[tokio::test]
async fn install_rejects_bad_filenames() {
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
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
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
            .json(&serde_json::json!({"file":bad, "tarball_b64":base64::engine::general_purpose::STANDARD.encode(b"bytes")}))
            .send().await.unwrap();
        assert_eq!(
            response.status().as_u16(),
            400,
            "filename `{bad}` must reject"
        );
        let error: serde_json::Value = response.json().await.unwrap();
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
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    });
    document["identity-providers"][operator] =
        serde_json::json!({"module": operator, "token": {"file": operator_token}});
    let deploy = busbar_kernel::config::deploy_from_deserializer(document)
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
        .json(&serde_json::json!({"file":"candidate.tar.gz", "tarball_b64":base64::engine::general_purpose::STANDARD.encode(b"not a tarball at all")}))
        .send().await.unwrap();
    assert_eq!(response.status().as_u16(), 400);
    let error: serde_json::Value = response.json().await.unwrap();
    assert_eq!(error["error"]["code"], "invalid_request");
    let after: std::collections::BTreeSet<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(after, before, "inspect publishes nothing");
    server.abort();
}
