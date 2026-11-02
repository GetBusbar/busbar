// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::sdk::migrate::Migrated;
use busbar_kernel::config::migrate::migrate_config_with;
use busbar_kernel::config::migrate_plugins::MigrateHost;
use busbar_test_kit::root_door_fixtures::migrate_stub as stub;

use super::{Index, IndexPlugin};
use crate::root::loader::dispatch::{load::raw, migrate::migrate_door};

struct StubHost;
impl MigrateHost for StubHost {
    fn migrate(
        &self,
        _: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, Migrated)>, String> {
        if module != "stub" {
            return Ok(None);
        }
        Ok(migrate_door(raw(stub::door), settings, from)?
            .map(|m| ("busbar-secret-stub".to_string(), m)))
    }
    fn repin(&self, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
    fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

#[test]
fn core_calls_the_stub_plugins_migrate_and_applies_the_result() {
    let config = "\
store: { module: memory }
secrets:
  vaulted:
    module: stub
    settings: { signing-secret: { env: S }, url: 10.1.2.3 }
";
    let out = migrate_config_with(config, &StubHost).expect("migrates");
    let body: String = out
        .yaml
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let doc: serde_yaml::Value = serde_yaml::from_str(&body).expect("YAML");
    let want: serde_yaml::Value =
        serde_yaml::from_str("{ signing_secret: { env: S }, url: 10.1.2.3 }").unwrap();
    assert_eq!(doc["secrets"]["vaulted"]["settings"], want, "{}", out.yaml);
    let allowed: serde_yaml::Value = serde_yaml::from_str("['10.1.2.3']").unwrap();
    assert_eq!(
        doc["advanced"]["allow_destinations"], allowed,
        "{}",
        out.yaml
    );
    assert!(
        out.changes.iter().any(|c| c.starts_with(
            "busbar-secret-stub: settings.signing-secret -> settings.signing_secret (renamed in \
             1.6.0; the configuration came from 1.5.5)"
        )),
        "the plugin's report line, under its name: {:?}",
        out.changes
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
