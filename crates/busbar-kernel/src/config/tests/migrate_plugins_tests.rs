// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's half of a plugin's own migration: it hands each selected plugin its section, writes the
//! answer back, applies only the needs raised against core's keys, prints the report lines under
//! the plugin's name, and rewrites `plugins.fetch` through the release lookup. It knows no plugin's
//! keys: the stub host below does the renaming, as a plugin's `migrate` would.

use busbar_contract::abi::sdk::migrate::{MigrateNeed, Migrated};

use super::{MigrateHost, NoPlugins};
use crate::config::migrate::{migrate_config, migrate_config_with};

/// A stub host: the `stub` store and auth plugins rename `signing-secret` to `signing_secret` and
/// ask for the host their `url` names; `broken` refuses; the index answers `v1.6.0` for the stub's
/// repository, and a pin for the unserved `elsewhere` module.
struct Stub;

impl MigrateHost for Stub {
    fn migrate(
        &self,
        kind: &str,
        module: &str,
        settings: &serde_json::Value,
        from: &str,
    ) -> Result<Option<(String, Migrated)>, String> {
        match module {
            "broken" => Err("its migrate refused: no".into()),
            "stub" => {
                let mut settings = settings.clone();
                let mut report = Vec::new();
                let mut needs = Vec::new();
                if let Some(m) = settings.as_object_mut() {
                    if let Some(v) = m.remove("signing-secret") {
                        m.insert("signing_secret".into(), v);
                        report.push(format!("{kind}: signing-secret -> signing_secret ({from})"));
                    }
                    if let Some(h) = m.get("url").and_then(|u| u.as_str()) {
                        needs.push(MigrateNeed::AllowDestination(h.to_string()));
                    }
                }
                Ok(Some((
                    "busbar-stub".into(),
                    Migrated {
                        settings,
                        report,
                        needs,
                    },
                )))
            }
            _ => Ok(None),
        }
    }

    fn repin(&self, github: &str) -> Result<Option<String>, String> {
        Ok(github
            .starts_with("Acme/busbar-stub@")
            .then(|| "Acme/busbar-stub@v1.6.0".to_string()))
    }

    fn release_for(&self, _: &str, module: &str) -> Result<Option<String>, String> {
        Ok((module == "elsewhere").then(|| "Acme/busbar-elsewhere@v1.6.0".to_string()))
    }
}

const CONFIG: &str = "\
store:
  module: stub
  settings: { signing-secret: { env: S }, url: 10.0.0.7 }
identity-providers:
  corp: { module: stub, settings: { url: 10.0.0.7 } }
  other: { module: elsewhere, settings: { keep: me } }
  sick: { module: broken, settings: { keep: me } }
plugins:
  enabled: true
  fetch:
    - { github: Acme/busbar-stub@v1.0.0, sha256: aaaa }
";

fn doc(yaml: &str) -> serde_yaml::Value {
    let body: String = yaml
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    serde_yaml::from_str(&body).expect("the migrated document parses")
}

fn yaml(text: &str) -> serde_yaml::Value {
    serde_yaml::from_str(text).expect("YAML")
}

#[test]
fn core_writes_back_the_plugins_own_migration_and_applies_only_its_needs() {
    let out = migrate_config_with(CONFIG, &Stub).expect("migrates");
    let d = doc(&out.yaml);
    assert_eq!(
        d["store"]["settings"],
        yaml("{ signing_secret: { env: S }, url: 10.0.0.7 }"),
        "the plugin's answer replaces its section:\n{}",
        out.yaml
    );
    assert_eq!(
        d["advanced"]["allow_destinations"],
        yaml("['10.0.0.7']"),
        "the raised destination, once, and nothing else:\n{}",
        out.yaml
    );
    assert!(
        d["advanced"]["block_private_addresses"].is_null(),
        "core never turns the guard off"
    );
    assert!(
        out.changes
            .iter()
            .any(|c| c == "busbar-stub: store: signing-secret -> signing_secret (1.5.5)"),
        "the report line is printed under the plugin's name: {:?}",
        out.changes
    );
    assert_eq!(
        out.changes
            .iter()
            .filter(|c| c.starts_with("advanced.allow_destinations: added '10.0.0.7'"))
            .count(),
        1,
        "{:?}",
        out.changes
    );
    // A plugin with no migrate passes through; one that refuses is left as written, with a TODO.
    assert_eq!(
        d["identity-providers"]["other"]["settings"],
        yaml("{ keep: me }")
    );
    assert_eq!(
        d["identity-providers"]["sick"]["settings"],
        yaml("{ keep: me }")
    );
    assert!(
        out.todos.iter().any(|t| t.starts_with(
            "identity-providers.sick.settings: the auth plugin 'broken' could not migrate"
        ) && t.contains("its migrate refused: no")),
        "{:?}",
        out.todos
    );
}

#[test]
fn fetch_pins_are_rewritten_through_the_release_lookup_and_unserved_plugins_gain_one() {
    let out = migrate_config_with(CONFIG, &Stub).expect("migrates");
    let d = doc(&out.yaml);
    assert_eq!(
        d["plugins"]["fetch"],
        yaml(
            "[{ github: Acme/busbar-stub@v1.6.0 }, \
             { github: Acme/busbar-elsewhere@v1.6.0 }]"
        ),
        "the old pin is rewritten without its sha256, and the unserved plugin is pinned:\n{}",
        out.yaml
    );
    assert!(out.changes.iter().any(|c| c
        .starts_with("plugins.fetch: 'Acme/busbar-stub@v1.0.0' -> 'Acme/busbar-stub@v1.6.0'")
        && c.contains("its sha256 pinned the old build, so it was removed")));
    assert!(out
        .changes
        .iter()
        .any(|c| c.starts_with("plugins.fetch: added 'Acme/busbar-elsewhere@v1.6.0'")));
    // Idempotent: the migrated document migrates to itself.
    let again = migrate_config_with(&out.yaml, &Stub).expect("migrates again");
    assert!(
        !again.changes.iter().any(|c| c.starts_with("plugins.fetch")
            || c.starts_with("advanced.allow_destinations")),
        "{:?}",
        again.changes
    );
}

#[test]
fn with_no_plugins_at_hand_every_section_passes_through_unchanged() {
    let plain = migrate_config(CONFIG).expect("migrates");
    let hosted = migrate_config_with(CONFIG, &NoPlugins).expect("migrates");
    assert_eq!(plain.yaml, hosted.yaml);
    let d = doc(&plain.yaml);
    assert_eq!(
        d["store"]["settings"],
        yaml("{ signing-secret: { env: S }, url: 10.0.0.7 }"),
        "core never renames a plugin's key"
    );
    assert!(d["advanced"].is_null());
}
