// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SETTINGS SENSITIVITY: every plugin setting is SENSITIVE unless its plugin declares it public
//! (owner ruling 2026-10-27, "lean sensitive by default"). The one declaration is the plugin's
//! settings schema (the Statement's `settings_schema`, which the host reads at load): a direct
//! member of the schema's root `properties` marked `"x-busbar-public": true` is public. A sensitive
//! value is never shown anywhere the host renders settings (logs, audit records, admin views,
//! config diff and drift output): only its key is. `secret_refs` names secret REFERENCES and is
//! no sensitivity source.

use std::collections::BTreeSet;

/// The schema keyword that declares a root setting public.
pub const PUBLIC_MARK: &str = "x-busbar-public";

/// The settings `schema` declares public: each direct member of its root `properties` marked
/// [`PUBLIC_MARK`] `true`. No schema, or none marked: none (every setting is sensitive).
#[must_use]
pub fn public_settings(schema: &serde_json::Value) -> BTreeSet<String> {
    schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .filter(|(_, p)| p.get(PUBLIC_MARK) == Some(&serde_json::Value::Bool(true)))
        .map(|(k, _)| k.clone())
        .collect()
}

/// The values of `settings` an operator may be shown: the public keys' alone, each as set.
#[must_use]
pub fn public_view(
    settings: &serde_json::Map<String, serde_json::Value>,
    public: &BTreeSet<String>,
) -> serde_json::Map<String, serde_json::Value> {
    settings
        .iter()
        .filter(|(k, _)| public.contains(*k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

#[cfg(test)]
#[path = "tests/settings_public_tests.rs"]
mod tests;
