// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use std::sync::Arc;
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;
#[test]
fn boot_refuses_a_provider_api_key_that_does_not_resolve() {
    const CHILD: &str = "BUSBAR_CENTRAL2_PROVIDER_CHILD";
    const WITNESS: &str = "actual root provider boot assertion completed";
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
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }

    const SENTINEL: &str = "sk-sentinel-must-never-be-printed";
    let set_var = format!("BUSBAR_TEST_PROVIDER_KEY_SET_{}", std::process::id());
    let unset_var = format!("BUSBAR_TEST_PROVIDER_KEY_UNSET_{}", std::process::id());
    std::env::set_var(&set_var, SENTINEL);
    std::env::remove_var(&unset_var);

    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
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
    let directory = plugins::scratch("central2-provider-boot");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let dialect = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .next()
        .expect("the actual distribution declares a provider dialect");
    let provider_defs = serde_json::from_value(serde_json::json!({
        "acme": {"protocol": dialect, "base_url": "https://api.example.com"}
    }))
    .expect("the actual provider catalog entry parses");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {"acme": {"protocol": dialect, "base_url": "https://api.example.com", "api_key": "none"}},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let mut cfg = busbar_kernel::config::resolve(&deploy, &provider_defs)
        .expect("the product deployment resolves");
    cfg.providers.get_mut("acme").unwrap().api_key =
        busbar_kernel::config::SecretRef::env(&unset_var);
    let mut resolving = cfg
        .providers
        .get("acme")
        .cloned()
        .expect("fixture provider");
    resolving.api_key = busbar_kernel::config::SecretRef::env(&set_var);
    cfg.providers.insert("resolves".to_string(), resolving);
    for (model, provider) in [("m-unset", "acme"), ("m-set", "resolves")] {
        cfg.models
            .insert(model.to_string(), model_cfg_for_provider(provider));
    }

    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let result = busbar_kernel::build_app_from_config(
        cfg,
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    );
    let err = result
        .err()
        .expect("an api_key that does not resolve must refuse boot, not degrade to an empty key");
    assert!(
        err.contains("acme"),
        "the refusal names the provider: {err}"
    );
    assert!(
        err.contains(&format!("env:{unset_var}")),
        "the refusal names the reference: {err}"
    );
    assert!(
        err.contains("api_key: none"),
        "and points at the keyless declaration for an upstream that takes no credential: {err}"
    );
    assert!(
        !err.contains(SENTINEL),
        "a resolved credential value must never appear in a boot diagnostic"
    );

    std::env::remove_var(&set_var);
    println!("{WITNESS}");
}
#[test]
fn boot_starts_a_keyless_lane_declared_none() {
    const CHILD: &str = "BUSBAR_CENTRAL2_PROVIDER_CHILD";
    const WITNESS: &str = "actual root provider boot assertion completed";
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
            .expect("the test runner names its test thread")
            .to_string();
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start the isolated actual-root test"),
        );
        let until = Instant::now() + Duration::from_secs(60);
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
                    "the actual-root usage witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                return;
            }
            assert!(
                Instant::now() < until,
                "the actual-root usage witness timed out"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }

    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
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
    let directory = plugins::scratch("central2-provider-boot");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    assert!(
        settings.is_object(),
        "the actual store settings are an object"
    );
    let dialect = busbar_kernel::plane_driver::dispatch::provider_dialects()
        .into_iter()
        .next()
        .expect("the actual distribution declares a provider dialect");
    let provider_defs = serde_json::from_value(serde_json::json!({
        "acme": {"protocol": dialect, "base_url": "https://api.example.com"}
    }))
    .expect("the actual provider catalog entry parses");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {"acme": {"protocol": dialect, "base_url": "https://api.example.com", "api_key": "none"}},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let mut cfg = busbar_kernel::config::resolve(&deploy, &provider_defs)
        .expect("the product deployment resolves");

    cfg.models
        .insert("m0".to_string(), model_cfg_for_provider("acme"));
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let result = busbar_kernel::build_app_from_config(
        cfg,
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    );
    let (app, rotate, limits) = result.expect("`api_key: none` starts the lane");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD.keep_in_store(
        app.governance
            .as_ref()
            .unwrap()
            .store_calls()
            .expect("actual Store calls"),
        109,
    );
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("actual rate history boots");
    limits.keep().expect("actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }

    println!("{WITNESS}");
}
fn model_cfg_for_provider(provider: &str) -> busbar_kernel::config::ModelCfg {
    busbar_kernel::config::ModelCfg {
        provider: provider.into(),
        max_concurrent: Some(1),
        max_requests: -1,
        default_max_tokens: None,
        upstream_model: None,
        attempt_timeout_ms: None,
        reasoning: None,
        prompt_caching: None,
        protocol: None,
    }
}
