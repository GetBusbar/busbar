// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: secret` plugin** — a `cdylib` exporting the secret C ABI. It is the
//! in-tree ABI-crossing coverage for the `kind: secret` seam (the secret-seam analogue of
//! `busbar-hook-test-plugin`). It also doubles as the reference implementation `docs/plugins.md`'s
//! secret-plugin example is written against, so that example cannot silently drift from the real
//! [`SecretHandler`] trait shape (`resolve(&self, settings: &Map<String,
//! Value>) -> Result<Vec<u8>, PluginError>`), and it ships the CATALOG every plugin ships: its
//! codes, templated per locale, in [`CATALOG`].
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

use busbar_plugin_sdk::{
    export_catalog, export_secret_plugin, Catalog, ErrorClass, ParamValue, PluginError,
    SecretHandler,
};
use serde::Deserialize;

/// The code for a reference whose settings carry no usable `key`.
pub const CODE_KEY_MISSING: &str = "secret_example.key_missing";
/// The code for a key the map does not hold.
pub const CODE_NO_ENTRY: &str = "secret_example.no_entry";

/// This plugin's error catalog, as the data the host reads at load. Two locales, so the fallback
/// from a locale the catalog lacks to the default one is a thing the host can be proven to do.
pub const CATALOG: &str = r#"{
  "default_locale": "en",
  "entries": [
    { "code": "secret_example.key_missing", "templates": [
      { "locale": "en", "text": "the reference settings carry no string `key`" },
      { "locale": "de", "text": "die Referenz-Einstellungen enthalten keinen `key`" } ] },
    { "code": "secret_example.no_entry", "templates": [
      { "locale": "en", "text": "no entry named {key} in the map" },
      { "locale": "de", "text": "kein Eintrag namens {key} in der Tabelle" } ] }
  ]
}"#;

/// The plugin's opaque open-time config: the whole map this instance resolves against.
#[derive(Deserialize, Default)]
struct ExampleSecretConfig {
    #[serde(default)]
    map: std::collections::BTreeMap<String, String>,
}

struct ExampleSecret {
    map: std::collections::BTreeMap<String, String>,
}

impl SecretHandler for ExampleSecret {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Vec<u8>, PluginError> {
        let key = settings
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PluginError::new(ErrorClass::Malformed, CODE_KEY_MISSING)
                    .with_message("missing or non-string `key` in secret reference settings")
            })?;
        self.map
            .get(key)
            .map(|v| v.clone().into_bytes())
            .ok_or_else(|| {
                PluginError::new(ErrorClass::NotFound, CODE_NO_ENTRY)
                    .with_param("key", ParamValue::Str(key.to_string()))
                    .with_message(format!("no entry named {key:?} in the example secret map"))
            })
    }
}

/// This plugin's catalog, parsed: what the host reads at load, and what the tests check.
pub fn catalog() -> Catalog {
    serde_json::from_str(CATALOG).expect("the catalog is a catalog document")
}

/// Construct the module from the engine-passed open-time JSON config. An empty config is fine (a
/// module that resolves nothing — every `resolve` fails closed); malformed JSON is a fail-closed
/// load error, exactly like every other plugin kind's `open`.
fn open(cfg: &str) -> Result<Box<dyn SecretHandler>, String> {
    let c: ExampleSecretConfig = if cfg.trim().is_empty() {
        ExampleSecretConfig::default()
    } else {
        serde_json::from_str(cfg)
            .map_err(|e| format!("invalid secret-example-plugin config: {e}"))?
    };
    Ok(Box::new(ExampleSecret { map: c.map }))
}

export_secret_plugin!(handler = open);
export_catalog!(CATALOG);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
