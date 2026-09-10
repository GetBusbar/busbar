// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: secret` plugin** — a `cdylib` exporting the secret C ABI. It is the
//! in-tree ABI-crossing coverage for the `kind: secret` seam (the secret-seam analogue of
//! `busbar-hook-test-plugin`). It also doubles as the reference implementation `docs/plugins.md`'s
//! secret-plugin example is written against, so that example cannot silently drift from the real
//! [`busbar_contract::kinds::Secret`] trait shape.
//!
//! It does NO network and NO real secret-store work: it resolves against a fixed in-memory map baked
//! in at `open` time from its config JSON, keyed by `settings.key`. Config JSON (the secret module's
//! `settings:` map from `config.yaml`'s `secrets:` block, passed verbatim by the engine at load):
//! ```json
//! { "map": { "db-password": "hunter2" } }
//! ```
//! A reference is then `{"key": "db-password"}` — the cold lane's grammar is the reference's own
//! settings object, spelled as JSON, and that is what a [`busbar_contract::kinds::SecretRef`]
//! carries here. Fail-closed throughout: an unknown key, a missing/non-string `key` field, a
//! reference that is not a JSON object at all, or malformed open-time config JSON is an `Err`,
//! never an empty `Ok`.
//!
//! ## Which failure it reports, and why it matters
//!
//! The face's error IS the taxonomy — there is no message field — so choosing the variant IS the
//! whole of what this plugin tells an operator:
//!
//! * an unknown key is `Unknown`: the reference does not resolve, so go and check the key;
//! * a reference this module cannot read at all — no `key`, a non-string `key`, not an object — is
//!   `Malformed`: the reference is outside the grammar, so go and check the reference's SHAPE.
//!
//! Neither is `Unavailable`, because an in-memory map is never an outage, and a plugin that reports
//! one would have an operator waiting for a recovery that is not coming.

use busbar_contract::kinds::{Secret, SecretError, SecretRef, SecretValue};
use busbar_contract::plugin::{AbiVersion, Kind, Plugin};
use serde::Deserialize;

/// The plugin's opaque open-time config: the whole map this instance resolves against.
#[derive(Deserialize, Default)]
struct ExampleSecretConfig {
    #[serde(default)]
    map: std::collections::BTreeMap<String, String>,
}

struct ExampleSecret {
    map: std::collections::BTreeMap<String, String>,
}

impl Plugin for ExampleSecret {
    fn key(&self) -> &'static str {
        "secret-example"
    }

    fn kind(&self) -> Kind {
        Kind::Secret
    }

    fn abi(&self) -> AbiVersion {
        // Read off the shared const rather than written as a literal, so this plugin's declared
        // generation and the SDK's cannot drift apart.
        AbiVersion(busbar_plugin_sdk::secret_abi_version() as u16)
    }
}

impl Secret for ExampleSecret {
    fn ref_grammar(&self) -> &'static str {
        "a JSON object carrying a string `key` naming an entry in this module's map"
    }

    fn resolve(&self, r: &SecretRef) -> Result<SecretValue, SecretError> {
        let settings: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&r.0).map_err(|_| SecretError::Malformed)?;
        let key = settings
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or(SecretError::Malformed)?;
        self.map
            .get(key)
            .map(|v| SecretValue::new(v.clone().into_bytes()))
            .ok_or(SecretError::Unknown)
    }

    fn watch(&self, _r: &SecretRef) -> Result<Option<u64>, SecretError> {
        // The map is baked in at `open` and never changes, so there is nothing to watch. The face
        // documents `None` as exactly this.
        Ok(None)
    }

    fn sign(&self, _key: &str, _bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
        Err(SecretError::Unknown)
    }

    fn seal(&self, _key: &str, _context: &[u8], _plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        Err(SecretError::Unknown)
    }

    fn unseal(&self, _key: &str, _context: &[u8], _sealed: &[u8]) -> Result<Vec<u8>, SecretError> {
        Err(SecretError::Unknown)
    }
}

/// Construct the module from the engine-passed open-time JSON config. An empty config is fine (a
/// module that resolves nothing — every `resolve` fails closed); malformed JSON is a fail-closed
/// load error, exactly like every other plugin kind's `open`.
fn open(cfg: &str) -> Result<Box<dyn Secret>, String> {
    let c: ExampleSecretConfig = if cfg.trim().is_empty() {
        ExampleSecretConfig::default()
    } else {
        serde_json::from_str(cfg)
            .map_err(|e| format!("invalid secret-example-plugin config: {e}"))?
    };
    Ok(Box::new(ExampleSecret { map: c.map }))
}

busbar_plugin_sdk::export_secret_plugin!(open);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
