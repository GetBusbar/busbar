// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STUB PLUGIN MIGRATES ITSELF, END TO END ACROSS CORE (owner ruling 2026-10-27): a stub
//! plugin's door states `migrate` (the contract's `Migrator` over its own `Migrate`), the loader
//! calls it through the door with no instance, and the kernel's `--migrate-config` writes the
//! plugin's answer back, applies the destination it raised to `advanced.allow_destinations` and
//! prints its report line under its name. Core knows none of the stub's keys. And the release
//! index picks the release built for this core's ABI.

use busbar_contract::abi::sdk::migrate::Migrated;
use busbar_kernel::config::migrate::migrate_config_with;
use busbar_kernel::config::migrate_plugins::MigrateHost;
use busbar_test_kit::root_door_fixtures::migrate_stub as stub;

use super::{Index, IndexPlugin};
use crate::root::loader::dispatch::{load::raw, migrate::migrate_door};

/// A host whose one plugin is the stub's door, called as the root calls every door's `migrate`.
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
