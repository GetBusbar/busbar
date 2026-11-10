// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_migrations::config::migrate::migrate_config_with;
use busbar_migrations::config::migrate_plugins::MigrateHost;

use super::{Index, IndexPlugin};

#[test]
fn core_applies_the_real_llm_migrations_private_destination_need() {
    crate::dist_root_install::install();
    let config = "\
store: { module: memory }
providers:
  in-rack:
    base_url: http://10.1.2.3:8000/v1
models: {}
pools: {}
";
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
fn direct_models_migrate_the_catalog_destination_without_a_pool_section() {
    crate::dist_root_install::install();
    let config = "\
store: { module: memory }
providers:
  fixture-openai: { api_key: { env: FIXTURE_UPSTREAM_KEY } }
models:
  m-chat: { provider: fixture-openai }
advanced:
  usage_flush_interval_ms: 3600000
";
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let catalog = "fixture-openai:\n  protocol: openai\n  base_url: http://127.0.0.1:35761\n";
    std::fs::write(directory.0.join("providers.yaml"), catalog).unwrap();
    let host = super::RootHost::for_document(config, &directory.0.join("config.yaml"));
    let out = migrate_config_with(config, &host).expect("the selected LLM plane migrates");
    let doc: serde_yaml::Value = serde_yaml::from_str(&out.yaml).unwrap();
    assert_eq!(
        doc["advanced"]["allow_destinations"],
        serde_yaml::from_str::<serde_yaml::Value>("[127.0.0.1]").unwrap()
    );
    assert!(doc["advanced"].get("block_private_addresses").is_none());
    assert!(
        doc.get("pools").is_none(),
        "migration must not invent a pool section"
    );
    assert_eq!(doc["models"]["m-chat"]["provider"], "fixture-openai");
    assert_eq!(
        doc["providers"]["fixture-openai"]["api_key"]["env"],
        "FIXTURE_UPSTREAM_KEY"
    );
    assert_eq!(
        std::fs::read_to_string(directory.0.join("providers.yaml")).unwrap(),
        catalog
    );
    assert!(out.changes.iter().any(|line| line.contains("127.0.0.1")));
    assert!(out.todos.is_empty(), "{:?}", out.todos);
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

#[test]
fn frozen_overlay_host_keeps_coincident_authored_templates_as_literal_data() {
    let raw = "store: {module: memory, settings: {password: '${COINCIDENT}'}}\n";
    let detection = "store: {module: memory, settings: {password: 'environment-value'}}\n";
    let documents =
        std::sync::Arc::new(crate::root::startup_upgrade::documents::Documents::default());
    let authored = super::RootHost::for_startup_document(
        raw,
        detection,
        std::path::Path::new("config.yaml"),
        documents.clone(),
    )
    .unwrap();
    assert_eq!(
        authored.resolved_authored_scalar("${COINCIDENT}").unwrap(),
        Some(serde_json::Value::String("environment-value".into()))
    );
    let frozen = super::RootHost::for_frozen_overlay(
        raw,
        detection,
        std::path::Path::new("config.yaml"),
        documents,
    )
    .unwrap();
    assert_eq!(
        frozen.resolved_authored_scalar("${COINCIDENT}").unwrap(),
        None
    );
}

#[test]
fn current_settings_validation_does_not_read_a_selected_planes_historical_catalog() {
    use std::cell::Cell;

    struct Host {
        catalog_reads: Cell<usize>,
        auth_validations: Cell<usize>,
    }
    impl MigrateHost for Host {
        fn migrate(
            &self,
            _: &str,
            _: &str,
            _: &serde_json::Value,
            _: &str,
        ) -> Result<Option<(String, busbar_contract::abi::sdk::migrate::MigrationAnswer)>, String>
        {
            Ok(None)
        }
        fn repin(&self, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
            Ok(None)
        }
        fn providers_catalog(
            &self,
        ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
            self.catalog_reads.set(self.catalog_reads.get() + 1);
            Err("historical catalog unavailable".into())
        }
        fn validate_migrated(
            &self,
            kind: &str,
            module: &str,
            settings: &serde_json::Value,
        ) -> Result<(), String> {
            if kind == "auth" {
                assert_eq!(module, "oidc");
                assert_eq!(
                    settings,
                    &serde_json::json!({
                        "issuer": "https://issuer.example", "audience": "witness"
                    })
                );
                self.auth_validations.set(self.auth_validations.get() + 1);
            }
            Ok(())
        }
    }

    crate::dist_root_install::install();
    assert!(
        busbar_kernel::plane_driver::registry::plane_decls()
            .iter()
            .any(|plane| {
                (plane.config_section == "pools" || plane.owned_config_sections.contains(&"pools"))
                    && busbar_kernel::plane_driver::door::consumed_sections(plane)
                        .contains(&"providers")
            }),
        "the actual installed pools plane consumes providers for historical migration"
    );
    let raw = "store: {module: memory}
providers: {}
models: {}
pools: {}
identity-providers: {rig: {module: oidc, settings: {issuer: https://issuer.example, audience: witness}}}
auth: {chain: [keys], admin_auth: [rig], signing_key: {env: UNUSED_CATALOG_WITNESS}, role_bindings: {rig: {reader: {admin_scope: read-only}}}}
";
    let host = Host {
        catalog_reads: Cell::new(0),
        auth_validations: Cell::new(0),
    };
    let current = busbar_migrations::config::normalize_authored(raw, &host).unwrap();
    assert_eq!(host.catalog_reads.get(), 0);
    assert_eq!(host.auth_validations.get(), 1);
    assert!(current.todos.is_empty(), "{:?}", current.todos);
    assert_eq!(current.yaml, raw);

    let historical = migrate_config_with(raw, &host).unwrap();
    assert!(host.catalog_reads.get() > 0);
    assert!(
        historical
            .todos
            .iter()
            .any(|todo| todo.starts_with("providers:")
                && todo.contains("providers catalog could not be read for the plane migrations")
                && todo.contains("historical catalog unavailable")),
        "{:?}",
        historical.todos
    );
}

#[cfg(distribution_root)]
#[test]
fn credential_owner_migration_resolves_outer_source_once_and_keeps_inline_reference() {
    crate::dist_root_install::install();
    let directory = super::FetchedDir::create_in(&std::env::temp_dir()).unwrap();
    let key = directory.0.join(" key.json ");
    let pointer = directory.0.join("old-credential");
    std::fs::write(
        &key,
        br#"{"client_email":"test@example.com","private_key":"SYNTHETIC_KEY"}"#,
    )
    .unwrap();
    std::fs::write(&pointer, format!("{}\r\n", key.display())).unwrap();
    let host = super::RootHost::for_document("{}", &directory.0.join("elsewhere/config.yaml"));
    let sources = host.source_declarations().unwrap();
    let source = |path: &std::path::Path| {
        sources
            .reference_for_role(
                busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH,
                path.to_str().unwrap(),
            )
            .unwrap()
    };
    let original = source(&pointer);
    let migrated = host
        .migrate_credential("oauth", &original, "1.5.5")
        .unwrap()
        .unwrap();
    assert_eq!(migrated, source(&key));
    assert!(host
        .migrate_credential("oauth", &migrated, "1.5.5")
        .unwrap()
        .is_none());
    let error = host
        .migrate_credential(
            "oauth",
            &source(&directory.0.join("SYNTHETIC_ABSENT")),
            "1.5.5",
        )
        .unwrap_err();
    assert!(!error.contains("SYNTHETIC_ABSENT"));
}

include!(concat!(env!("OUT_DIR"), "/context_test_sources.rs"));
owner_test_sources!(config_migrate_export);
