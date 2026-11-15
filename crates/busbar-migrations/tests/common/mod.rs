// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared by the R16a integration binaries: a migrate host that refuses `kind: auth` settings
//! without `sha256` (as admin-tokens does), re-pins the stub plugin, and the two normalizations
//! the proof compares.

use busbar_contract::abi::sdk::migrate::MigrationAnswer;
use busbar_contract::persistence::lifecycle::DocumentSemantics;
use busbar_contract::yaml::{self, prelude::*};
use busbar_migrations::config::migrate_plugins::MigrateHost;

pub const FIXTURE: &str = include_str!("../fixtures/operator_1_5_historical_plugins.yaml");

/// The `plugins:` subtree the fixture normalizes to (the pin is re-pinned, its sha256 dropped).
fn golden_plugins() -> Value {
    yaml::from_str("{ enabled: true, fetch: [{ github: Acme/busbar-stub@v1.6.0 }] }")
        .expect("golden YAML")
}

struct Host {
    /// Refuse `kind: auth` settings that carry no `sha256`.
    gate_auth: bool,
}

impl MigrateHost for Host {
    fn validate_migrated(
        &self,
        kind: &str,
        _module: &str,
        settings: &serde_json::Value,
    ) -> Result<(), String> {
        if self.gate_auth && kind == "auth" && settings.get("sha256").is_none() {
            return Err("settings need a sha256".into());
        }
        Ok(())
    }

    fn migrate(
        &self,
        _: &str,
        _: &str,
        _: &serde_json::Value,
        _: &str,
    ) -> Result<Option<(String, MigrationAnswer)>, String> {
        Ok(None)
    }

    fn repin(&self, github: &str) -> Result<Option<String>, String> {
        Ok(github
            .starts_with("Acme/busbar-stub@")
            .then(|| "Acme/busbar-stub@v1.6.0".to_string()))
    }

    fn release_for(&self, _: &str, _: &str) -> Result<Option<String>, String> {
        Ok(None)
    }
}

/// The `plugins:` of full normalization under a host that checks nothing (V without `ViewOnly`).
fn plain_plugins(raw: &str) -> Option<Value> {
    let out = busbar_migrations::config::normalize_supported_source(
        DocumentSemantics::Historical,
        raw,
        &Host { gate_auth: false },
    )
    .expect("normalizes under a permissive host");
    let doc: Value = yaml::from_str(&out.yaml).expect("normalized YAML");
    doc.get("plugins").cloned()
}

/// The `plugins:` of pass 1 under the auth-refusing host.
fn view(raw: &str) -> Result<Option<Value>, String> {
    busbar_migrations::config::normalize_plugins_view(raw, &Host { gate_auth: true })
}

/// Pass 1's output, put back into a document with the fixture's other sections, as the second
/// start reads it.
fn with_plugins(raw: &str, plugins: &Value) -> String {
    let mut doc: Value = yaml::from_str(raw).expect("fixture YAML");
    if let Some(map) = doc.as_mapping_mut() {
        map.insert_key("plugins", plugins.clone());
    }
    yaml::to_string(&doc).expect("encodes")
}

pub fn check_view_properties(raw: &str) {
    let golden = golden_plugins();
    let v = view(raw);
    assert!(v.is_ok(), "pass 1 refused: {v:?}");
    let v = v.ok().flatten().expect("a plugins view");
    assert_eq!(v, golden, "pass 1 view is the golden plugins subtree");
    assert_eq!(
        plain_plugins(raw).expect("plain plugins"),
        golden,
        "V without ViewOnly"
    );
    // The second start's view: normalizing the upgraded block again leaves it unchanged.
    let again = view(&with_plugins(raw, &v));
    assert!(again.is_ok(), "second pass refused: {again:?}");
    assert_eq!(again.ok().flatten().as_ref(), Some(&v));
}
