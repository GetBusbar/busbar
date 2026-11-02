// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SETTINGS SENSITIVITY: every plugin setting is SENSITIVE unless its plugin declares it public

use std::collections::BTreeSet;

/// The schema keyword that declares a root setting public.
pub const PUBLIC_MARK: &str = "x-busbar-public";

/// The settings `schema` declares public: each direct member of its root `properties` marked
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
