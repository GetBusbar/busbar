// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use std::time::{Duration, Instant};
#[path = "../../root/tests/test_plugins.rs"]
mod plugins;
#[test]
fn secrets_block_rejects_builtin_resolver_names() {
    const CHILD: &str = "BUSBAR_CENTRAL2_VALIDATOR_CHILD";
    const WITNESS: &str = "actual root validator phase assertions completed";
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

    for reserved in ["env", "file"] {
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
            busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        let library = std::fs::read(library_path).expect("the actual store library reads");
        let directory = plugins::scratch("central2-validator-order");
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
        let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {"acme": {"protocol": dialect, "base_url": "https://api.example.com", "api_key": "none"}},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
        let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the product deployment resolves");
        cfg.providers.get_mut("acme").unwrap().api_key = busbar_kernel::config::SecretRef::env("K");
        let plugins_cfg = busbar_kernel::config::PluginsCfg {
            enabled: true,
            dir: directory.to_string_lossy().into_owned(),
            ..Default::default()
        };
        cfg.secrets.insert(
            reserved.to_string(),
            busbar_kernel::config::SecretModuleCfg::default(),
        );
        let errs = busbar_kernel::config_validate::validate(&cfg).unwrap_err();
        let refusal = errs
            .iter()
            .find(|e| e.starts_with(&format!("secrets.{reserved}: ")))
            .unwrap_or_else(|| panic!("reserved '{reserved}' not refused: {errs:?}"));
        assert!(
            refusal.starts_with(&format!(
                "secrets.{reserved}: the built-in '{reserved}' secret module takes no \
                 module-level config; its settings ("
            )) && refusal.ends_with(
                ") belong on each individual secret reference, not in the top-level `secrets:` \
                 block"
            ),
            "reserved '{reserved}' refused in the semantic pass's words: {refusal}"
        );

        let refused = busbar_kernel::config_validate::check(
            &cfg,
            busbar_kernel::config_validate::Check {
                plugins: &plugins_cfg,
                unset_env_vars: &[],
                root: &busbar_kernel::config_validate::no_root_rules,
                fetch: None,
                resolve_builtins: false,
            },
        )
        .unwrap_err();
        assert!(
            matches!(&refused, busbar_kernel::config_validate::Refusal::Config(e) if e.contains(refusal)),
            "the one validator refuses '{reserved}' in the semantic pass: {refused:?}"
        );
    }
    println!("{WITNESS}");
}
#[test]
fn one_validator_refuses_in_one_order() {
    const CHILD: &str = "BUSBAR_CENTRAL2_VALIDATOR_CHILD";
    const WITNESS: &str = "actual root validator phase assertions completed";
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
        busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = plugins::scratch("central2-validator-order");
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {"acme": {"protocol": dialect, "base_url": "https://api.example.com", "api_key": "none"}},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let check = |cfg: &busbar_kernel::config::RootCfg,
                 root: &dyn Fn(&busbar_kernel::config::RootCfg) -> Result<(), String>,
                 resolve_builtins: bool| {
        busbar_kernel::config_validate::check(
            cfg,
            busbar_kernel::config_validate::Check {
                plugins: &plugins,
                unset_env_vars: &[],
                root,
                fetch: None,
                resolve_builtins,
            },
        )
    };
    let refuse_root = |_: &busbar_kernel::config::RootCfg| Err("the root refuses".to_string());

    cfg.providers.get_mut("acme").unwrap().api_key = busbar_kernel::config::SecretRef {
        module: "typo-ref".to_string(),
        ..busbar_kernel::config::SecretRef::env("K")
    };
    cfg.secrets.insert(
        "typo-vault".to_string(),
        busbar_kernel::config::SecretModuleCfg::default(),
    );
    match check(&cfg, &busbar_kernel::config_validate::no_root_rules, false) {
        Err(busbar_kernel::config_validate::Refusal::Plugins(e)) => assert!(
            e.starts_with("secrets.typo-vault: no loadable `kind: secret` plugin"),
            "the `secrets:` block is judged before the references: {e}"
        ),
        other => panic!("refused by the registry half: {other:?}"),
    }

    assert_eq!(
        check(&cfg, &refuse_root, false).unwrap_err(),
        busbar_kernel::config_validate::Refusal::Root("the root refuses".to_string())
    );

    cfg.secrets.clear();
    match check(&cfg, &busbar_kernel::config_validate::no_root_rules, false) {
        Err(busbar_kernel::config_validate::Refusal::Plugins(e)) => assert!(
            e.contains("references secret module 'typo-ref', which is not a built-in"),
            "the reference is refused: {e}"
        ),
        other => panic!("refused by the registry half: {other:?}"),
    }

    cfg.limits.reasoning_effort_budgets.minimal = 0;
    assert!(
        matches!(
            check(&cfg, &refuse_root, false),
            Err(busbar_kernel::config_validate::Refusal::Config(_))
        ),
        "the semantic pass answers first"
    );

    let var = "BUSBAR_S10_ONE_VALIDATOR_UNSET_VAR";
    assert!(std::env::var_os(var).is_none());
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("fresh ordinary config resolves");
    cfg.providers.get_mut("acme").unwrap().api_key = busbar_kernel::config::SecretRef::env(var);
    assert!(check(&cfg, &busbar_kernel::config_validate::no_root_rules, false).is_ok());
    match check(&cfg, &busbar_kernel::config_validate::no_root_rules, true) {
        Err(busbar_kernel::config_validate::Refusal::Unresolved(e)) => {
            assert!(e.contains(var), "the unresolved reference is named: {e}")
        }
        other => panic!("refused as unresolved: {other:?}"),
    }
    println!("{WITNESS}");
}
