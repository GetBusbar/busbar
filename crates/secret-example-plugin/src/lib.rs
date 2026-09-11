// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: secret` plugin** — a `cdylib` exporting the secret C ABI. It is the
//! in-tree ABI-crossing coverage for the `kind: secret` seam (the secret-seam analogue of
//! `busbar-hook-test-plugin`). It also doubles as the reference implementation `docs/plugins.md`'s
//! secret-plugin example is written against, so that example cannot silently drift from the real
//! [`busbar_api::SecretModule`] trait shape (`resolve(&self, settings: &Map<String, Value>) ->
//! SecretResult<Vec<u8>>`).
//!
//! It does NO network and NO real secret-store work: it resolves against a fixed in-memory map baked
//! in at `open` time from its config JSON, keyed by `settings.key`. Config JSON (the secret module's
//! `settings:` map from `config.yaml`'s `secrets:` block, passed verbatim by the engine at load):
//! ```json
//! { "map": { "db-password": "hunter2" } }
//! ```
//! `resolve`'s PER-REFERENCE `settings` (not this open-time config) must then carry `{"key":
//! "db-password"}` to look up that entry. Fail-closed throughout: an unknown key, a missing/
//! non-string `key` field, or malformed open-time config JSON is an `Err`, never an empty `Ok`.

use busbar_api::{SecretError, SecretModule, SecretResult};
use busbar_plugin_sdk::{export_catalog, export_secret_plugin, Catalog};
use serde::Deserialize;

/// This plugin's error catalog, in TWO locales — the reference for what a plugin ships beside its
/// claims. The host reads it once at load and renders these codes from it; a code this plugin
/// emitted that is not declared here would be refused at first use, by name.
///
/// `de` is here on purpose: one locale proves the shape, two prove the LOOKUP — that a caller
/// asking for `de` gets German, and a caller asking for a locale this plugin does not ship falls
/// back to `en` and never to the developer message.
pub const CATALOG: &str = r#"{
  "default_locale": "en",
  "entries": [
    { "code": "secret_example.key_missing", "templates": [
      { "locale": "en", "text": "the reference carries no `key`" },
      { "locale": "de", "text": "die Referenz enthält keinen `key`" } ] },
    { "code": "secret_example.no_entry", "templates": [
      { "locale": "en", "text": "no entry named {key}" },
      { "locale": "de", "text": "kein Eintrag namens {key}" } ] }
  ]
}"#;

/// This plugin's catalog, parsed: what the host reads at load, and what the tests check.
///
/// # Panics
/// Never in a shipped build — the constant above is a catalog document by construction, and the
/// cell beside it is what keeps that true.
#[must_use]
pub fn catalog() -> Catalog {
    serde_json::from_str(CATALOG).expect("the catalog is a catalog document")
}

/// The plugin's opaque open-time config: the whole map this instance resolves against.
#[derive(Deserialize, Default)]
struct ExampleSecretConfig {
    #[serde(default)]
    map: std::collections::BTreeMap<String, String>,
}

struct ExampleSecret {
    map: std::collections::BTreeMap<String, String>,
}

impl SecretModule for ExampleSecret {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> SecretResult<Vec<u8>> {
        let key = settings
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SecretError::invalid("missing or non-string `key` in secret reference settings")
            })?;
        self.map
            .get(key)
            .map(|v| v.clone().into_bytes())
            .ok_or_else(|| {
                SecretError::not_found(format!("no entry named {key:?} in the example secret map"))
            })
    }
}

/// Construct the module from the engine-passed open-time JSON config. An empty config is fine (a
/// module that resolves nothing — every `resolve` fails closed); malformed JSON is a fail-closed
/// load error, exactly like every other plugin kind's `open`.
fn open(cfg: &str) -> Result<Box<dyn SecretModule>, String> {
    let c: ExampleSecretConfig = if cfg.trim().is_empty() {
        ExampleSecretConfig::default()
    } else {
        serde_json::from_str(cfg)
            .map_err(|e| format!("invalid secret-example-plugin config: {e}"))?
    };
    Ok(Box::new(ExampleSecret { map: c.map }))
}

export_catalog!(CATALOG);
export_secret_plugin!(open);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
