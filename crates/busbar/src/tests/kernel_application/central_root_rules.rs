// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_kernel::appbuild::RootRules;
use busbar_kernel::config::Destinations;

/// Rules that record every commit raised to them.
#[derive(Default)]
struct Hearing(Mutex<Vec<Destinations>>);

impl RootRules for Hearing {
    fn check(&self, _cfg: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn destinations_applied(&self, destinations: &Destinations) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(destinations.clone());
    }
}

impl Hearing {
    fn heard(&self) -> Vec<Destinations> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[path = "../../root/tests/test_plugins.rs"]
mod plugins;

#[test]
fn boot_refusal_releases_the_completed_candidates_routes_without_committing_limits() {
    #[derive(Default)]
    struct RefuseBoot {
        routes: Mutex<Option<std::sync::Weak<busbar_kernel::plugin_routes::PluginRouteTable>>>,
        committed: std::sync::atomic::AtomicBool,
    }
    impl RootRules for RefuseBoot {
        fn check(&self, _: &busbar_kernel::config::RootCfg) -> Result<(), String> {
            Ok(())
        }
        fn check_built(&self, candidate: &busbar_kernel::state::App) -> Result<(), String> {
            assert_eq!(
                candidate.config_version, 0,
                "this is the actual startup candidate"
            );
            *self.routes.lock().unwrap() = Some(Arc::downgrade(&candidate.plugin_routes));
            Err("startup listener has no owning SERVE dispatcher".into())
        }
        fn destinations_applied(&self, _: &Destinations) {
            self.committed
                .store(true, std::sync::atomic::Ordering::SeqCst);
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
    let directory = plugins::scratch("root-rules-hearing");
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let refusing = Arc::new(RefuseBoot::default());
    let rules: Arc<dyn RootRules> = refusing.clone();
    let refusal = match busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    ) {
        Err(refusal) => refusal,
        Ok(_) => panic!("startup published a refused candidate"),
    };
    assert_eq!(refusal, "startup listener has no owning SERVE dispatcher");
    assert!(
        refusing
            .routes
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .upgrade()
            .is_none(),
        "the rejected candidate's actual route table is released"
    );
    assert!(!refusing.committed.load(std::sync::atomic::Ordering::SeqCst));
}

#[test]
fn a_completed_candidate_refusal_is_returned_before_a_reload_can_replace_the_old_app() {
    struct RefuseBuilt(std::sync::atomic::AtomicUsize);
    impl RootRules for RefuseBuilt {
        fn check(&self, _: &busbar_kernel::config::RootCfg) -> Result<(), String> {
            Ok(())
        }
        fn check_built(&self, candidate: &busbar_kernel::state::App) -> Result<(), String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(
                candidate.config_version, 1,
                "the rule receives the rebuilt candidate, not the old App"
            );
            Err("candidate listener has no compatible auth point".into())
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
    let directory = plugins::scratch("root-rules-hearing");
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let accepting: Arc<dyn RootRules> = Arc::new(busbar_kernel::appbuild::AcceptAll);
    let (prior, rotate, limits) = busbar_kernel::build_app_from_config(
        config.clone(),
        plugin_config.clone(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &accepting,
    )
    .expect("the original generation builds");
    limits.keep().expect("the original limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    let prior_version = prior.config_version;
    let reject = Arc::new(RefuseBuilt(std::sync::atomic::AtomicUsize::new(0)));
    let rules: Arc<dyn RootRules> = reject.clone();
    let result = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&prior),
        &rules,
    );
    let refusal = match result {
        Err(refusal) => refusal,
        Ok(_) => panic!("the completed candidate escaped its listener refusal"),
    };
    assert_eq!(refusal, "candidate listener has no compatible auth point");
    assert_eq!(reject.0.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(prior.config_version, prior_version);
}

#[test]
fn a_kept_build_raises_its_destinations_to_the_rules_it_was_judged_by() {
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
    let directory = plugins::scratch("root-rules-hearing");
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
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let plugin_config = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let mut config = config;
    config.allow_all_metadata = true;
    let expected = config.destinations();
    assert!(
        expected.allow_all_metadata,
        "the configuration states a destination fact"
    );
    let hearing = Arc::new(Hearing::default());
    let rules: Arc<dyn RootRules> = hearing.clone();

    let (_app, _, unkept) = busbar_kernel::build_app_from_config(
        config.clone(),
        plugin_config.clone(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        None,
        &rules,
    )
    .expect("the configuration builds");
    drop(unkept);
    assert!(
        hearing.heard().is_empty(),
        "a build dropped unkept raises nothing"
    );

    let (_app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugin_config,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the configuration builds");
    limits.keep().expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    assert_eq!(
        hearing.heard(),
        vec![expected],
        "the kept build raises its configuration's destinations, once"
    );
}
