// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::migrate::migrate_config_with;
use busbar_kernel::config::migrate_plugins::MigrateHost;

use super::{Index, IndexPlugin};

#[cfg(feature = "export-webhook")]
#[test]
fn core_calls_the_real_webhook_migration_and_applies_its_settings_and_report() {
    let config = "\
store: { module: memory }
export:
  delivery:
    module: request-log-webhook
    settings:
      url: https://collector.example/requests
      auth_header: { name: 'Bad Name', value: 'Bearer private' }
";
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let host = super::RootHost::for_document(config, &directory.0.join("config.yaml"));
    let out = migrate_config_with(config, &host).expect("the real linked export migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("migrated YAML");
    assert_eq!(
        doc["export"]["delivery"]["settings"],
        serde_yaml::from_str::<serde_yaml::Value>("{ url: 'https://collector.example/requests' }")
            .unwrap(),
        "only the header the real plugin cannot send is removed: {}",
        out.yaml
    );
    assert!(
        out.changes
            .iter()
            .any(|line| line.starts_with("busbar-export-webhook:")
                && line.contains("settings.auth_header")),
        "the real plugin's report retains its name and reaches the operator: {:?}",
        out.changes
    );
    assert!(
        out.changes
            .iter()
            .all(|line| !line.contains("Bearer private")),
        "migration reports do not disclose the discarded credential"
    );
}

#[cfg(feature = "plane-llm")]
#[test]
fn core_applies_the_real_llm_migrations_private_destination_need() {
    let config = "\
store: { module: memory }
providers:
  in-rack:
    base_url: http://10.1.2.3:8000/v1
models: {}
pools: {}
";
    let registration = crate::root::loader::dispatch::kinds::plane::registration(
        crate::root::loader::dispatch::kinds::plane::linked_probe(
            busbar_plane_llm::plane_door::door,
            "real-migration",
        ),
    )
    .expect("the real plane's statement registers");
    let plane =
        busbar_kernel::plane_driver::door::fold(registration).expect("the real plane folds");
    let _registry =
        busbar_kernel_testkit::test_support::planes::TestRegistryIsolation::seeded(&[plane]);
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let host = super::RootHost::for_document(config, &directory.0.join("config.yaml"));
    let out = migrate_config_with(config, &host).expect("the real linked plane migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).expect("migrated YAML");
    assert_eq!(
        doc["advanced"]["allow_destinations"],
        serde_yaml::from_str::<serde_yaml::Value>("['10.1.2.3']").unwrap(),
        "the real plane's need is applied to the core-owned allowlist: {}",
        out.yaml
    );
    assert_eq!(
        doc["providers"]["in-rack"]["base_url"], "http://10.1.2.3:8000/v1",
        "the plane's provider settings remain intact"
    );
}

#[test]
fn the_release_index_picks_the_newest_release_built_for_this_core() {
    let kind = "store";
    let speaks = crate::root::loader::registry::supported_abi(kind)[0];
    let index = Index::parse(
        &serde_json::to_vec(&serde_json::json!({
            "plugins": [{
                "repo": "Acme/busbar-store-stub",
                "former_repos": ["Acme/stub-store"],
                "kind": kind,
                "answers_to": ["stub", "busbar-store-stub", "busbar-store-stub-plugin"],
                "releases": [
                    { "tag": "v1.0.6", "abi_version": speaks - 1 },
                    { "tag": "v1.6.1", "abi_version": speaks },
                    { "tag": "v1.6.0", "abi_version": speaks },
                    { "tag": "v2.0.0", "abi_version": speaks + 1 }
                ]
            }]
        }))
        .expect("JSON"),
    )
    .expect("an index");
    let plugin: &IndexPlugin = index
        .by_repo("acme/STUB-store")
        .expect("a former repo resolves");
    assert_eq!(
        plugin.pin_for_this_core().as_deref(),
        Some("Acme/busbar-store-stub@v1.6.1")
    );
    assert!(index.by_module(kind, "busbar-store-stub-plugin").is_some());
    assert!(
        index.by_module("auth", "stub").is_none(),
        "a module is looked up on its own kind"
    );
    assert!(
        Index::parse(br#"{"plugins": [], "extra": 1}"#).is_err(),
        "an index with keys this core does not know is refused"
    );
}

#[test]
fn release_index_orders_prereleases_before_stable_and_numeric_identifiers_numerically() {
    let abi = crate::root::loader::registry::supported_abi("store")[0];
    for tags in [
        vec!["v1.6.0", "v1.6.0-rc.10"],
        vec!["v1.6.0-rc.10", "v1.6.0"],
        vec!["v1.6.0-rc.2", "v1.6.0-rc.10"],
    ] {
        let stable = tags.contains(&"v1.6.0");
        let plugin = IndexPlugin {
            repo: "Acme/stub".into(),
            former_repos: vec![],
            kind: "store".into(),
            answers_to: vec!["stub".into()],
            releases: tags
                .into_iter()
                .map(|tag| super::IndexRelease {
                    tag: tag.into(),
                    abi_version: abi,
                })
                .collect(),
        };
        assert_eq!(
            plugin.pin_for_this_core().as_deref(),
            Some(if stable {
                "Acme/stub@v1.6.0"
            } else {
                "Acme/stub@v1.6.0-rc.10"
            })
        );
    }
    assert_eq!(
        super::version_order("v1.6.0+build.2", "v1.6.0+build.9"),
        std::cmp::Ordering::Equal
    );
    assert!(super::version_order("v1.6.0-alpha", "v1.6.0-alpha.1").is_lt());
    assert!(super::version_order("v1.6.0-11", "v1.6.0-alpha").is_lt());
}

#[test]
fn migration_paths_do_not_consume_later_provider_options() {
    for (option, path) in [
        ("--migrate-config", "--config"),
        ("--migrate-config", "--providers"),
        ("--migrate-config", "-c"),
        ("--config", "--migrate-config"),
    ] {
        let args = [option, path, "--providers", "selected-catalog.yaml"];
        assert_eq!(
            crate::root::cli::value_flag(
                args.into_iter().map(str::to_owned),
                crate::root::cli::OPTION_PROVIDERS,
                None,
            ),
            Some("selected-catalog.yaml".to_owned()),
            "the literal migration path {path} is not a providers option"
        );
    }
}

#[test]
fn migration_staging_owns_only_its_fresh_private_directory() {
    let first = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let second = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    assert_ne!(first.0, second.0);
    std::fs::write(first.0.join("owned"), b"first").unwrap();
    std::fs::write(second.0.join("other"), b"second").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&first.0).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let gone = first.0.clone();
    drop(first);
    assert!(!gone.exists());
    assert_eq!(std::fs::read(second.0.join("other")).unwrap(), b"second");
}

#[test]
fn the_root_hands_the_catalog_boot_reads_to_the_plane_migrations() {
    let config = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/migration-corpus/private-destinations/config.yaml");
    let raw = std::fs::read_to_string(&config).expect("the corpus fixture");
    let host = super::RootHost::for_document(&raw, &config);
    let catalog = host
        .providers_catalog()
        .expect("reads")
        .expect("a catalog beside the configuration");
    assert_eq!(
        catalog["in-rack"]["base_url"],
        serde_json::json!("http://192.168.40.12:8000/v1")
    );
    assert_eq!(
        catalog["corp-gateway"]["token_url"],
        serde_json::json!("http://10.9.8.7/oauth2/token")
    );
}
