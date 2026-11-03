// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use std::sync::Arc;
use std::time::{Duration, Instant};
use crate::root::test_plugins as plugins;
#[test]
fn boot_builds_a_pool_of_nine_unbounded_lanes_without_overflowing_its_banner() {
    const CHILD: &str = "BUSBAR_CENTRAL2_UNBOUNDED_CHILD";
    const WITNESS: &str = "actual root nine unbounded lanes completed";
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
    let directory = plugins::scratch("central2-nine-unbounded-lanes");
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let settings: serde_json::Value =
        crate::root::test_plugins::application_store_settings(&directory);
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
    let members: Vec<_> = (0..9).map(|index| format!("unbounded-{index}")).collect();
    for name in &members {
        let model: busbar_kernel::config::ModelCfg =
            serde_json::from_value(serde_json::json!({"provider":"acme"})).unwrap();
        assert_eq!(
            model.max_concurrent, None,
            "the ordinary omitted concurrency limit"
        );
        cfg.models.insert(name.clone(), model);
    }
    cfg.pools.insert(
        "wide".into(),
        serde_json::from_value(serde_json::json!({"members":members})).unwrap(),
    );
    let plugin_config = crate::root::test_plugins::trusted_config(&directory);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        cfg,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual product builds the swap deployment");
    limits.stage_boot();
    let calls = app
        .governance
        .as_ref()
        .expect("actual governance")
        .store_calls()
        .expect("actual Store calls");
    crate::root::kernel::ROOT_CARD.keep_in_store(calls, 107);
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .expect("the actual card history boots");
    limits
        .keep()
        .expect("the booted actual rates and limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert_eq!(app.engine_tables_view().lane_count(), 9);
    assert_eq!(app.engine_tables_view().pool_members("wide").len(), 9);
    println!("{WITNESS}");
}
