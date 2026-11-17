// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STEPS[0]: a 1.5.5 jwt-bearer provider's credential becomes an explicit outbound binding, and its
//! slot is marked in core's side table (LEGACY-KEYFILE-MARKER r2, adopted, §3 and §7).
//!
//! A provider whose effective 1.5.5 style is `jwt-bearer` (the deployment `auth`, else the catalog's)
//! and which a model reaches gets `auth.<p>-outbound = {module: {"$style": jwt-bearer}, config:
//! {style, credential, settings}}`. The provider names that instance, and loses `api_key` and the
//! forwarded keys. The credential slot is recorded in the plan's side table as a [`Mark`]. The
//! written text never carries `$migrated`: core inserts it only at the migrating bind. An unreached
//! jwt-bearer provider gets no binding (1.5.5 never resolved its key). Core never reads a
//! credential's value here.

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::Refusal;

/// The core-reserved bag word for a slot carrying its 1.5.5 value (IF r35 M-1).
pub const MIGRATED: &str = "$migrated";

/// The 1.5.5 style word this pass binds.
const JWT_BEARER: &str = "jwt-bearer";

/// The provider keys 1.5.5 forwarded to a jwt-bearer credential (the binding's `settings`).
const FORWARDED: [&str; 3] = ["token_url", "scope", "subject"];

/// One slot in the plan's side table: the instance's document path and the pointer, relative to its
/// `config`, whose value is 1.5.5's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    /// The instance's path in the document, for example `["auth", "p-outbound"]`.
    pub instance: Vec<String>,
    /// The RFC 6901 pointer into the instance's `config`.
    pub pointer: String,
}

/// Refuse CONFIG when `$migrated` appears anywhere in `resolved` (the document as written).
///
/// # Errors
/// CONFIG naming the word only.
pub(crate) fn refuse_marker(resolved: &Value) -> Result<(), Refusal> {
    fn holds(value: &Value) -> bool {
        match value {
            Value::Map(pairs) => pairs
                .iter()
                .any(|(key, value)| key.as_str() == Some(MIGRATED) || holds(value)),
            Value::Array(items) => items.iter().any(holds),
            _ => false,
        }
    }
    if holds(resolved) {
        return Err(Refusal::Config(format!(
            "`{MIGRATED}` is core migration vocabulary and cannot appear in a configuration; \
             remove it, then boot again"
        )));
    }
    Ok(())
}

/// Bind every reached 1.5.5 jwt-bearer provider of `root` explicitly, recording its slot in
/// `marks`. `resolved` is the 1.5.5 document as interpolated; `catalog` is the resolved providers
/// catalog 1.5.5 read (`Value::Null` when there is none).
///
/// # Errors
/// CONFIG when the binding's instance name is already taken.
pub(crate) fn bind_jwt_bearer(
    root: &mut Pairs,
    resolved: &Value,
    catalog: &Value,
    report: &mut Vec<String>,
    marks: &mut Vec<Mark>,
) -> Result<(), Refusal> {
    let Some(Value::Map(providers)) = resolved.get("providers") else {
        return Ok(());
    };
    let names: Vec<String> = providers
        .iter()
        .filter_map(|(name, _)| name.as_str().map(str::to_owned))
        .collect();
    for name in names {
        let deployed = resolved.get("providers").and_then(|p| p.get(name.as_str()));
        let listed = catalog.get(name.as_str());
        let style = deployed
            .and_then(|d| d.get("auth"))
            .and_then(Value::as_str)
            .or_else(|| listed.and_then(|c| c.get("auth")).and_then(Value::as_str));
        if style != Some(JWT_BEARER) {
            continue;
        }
        let Some(Value::Map(entry)) = root
            .get_key_mut("providers")
            .and_then(|p| p.get_key_mut(name.as_str()))
        else {
            continue;
        };
        if !reached(resolved, &name) {
            entry.remove_key("auth");
            entry.remove_key("api_key");
            report.push(format!(
                "providers.{name}: no model reaches it, so its jwt-bearer credential was not \
                 migrated; its original api_key reference is in config.yaml.1.5.5. Add an auth \
                 binding before routing to it"
            ));
            continue;
        }
        let instance = format!("{name}-outbound");
        let credential = entry.remove_key("api_key").unwrap_or(Value::Null);
        let mut settings: Pairs = Vec::new();
        for key in FORWARDED {
            let authored = entry.remove_key(key);
            let value = authored.or_else(|| listed.and_then(|c| c.get(key)).cloned());
            if let Some(value) = value.filter(|v| !v.is_null()) {
                settings.insert_key(key, value);
            }
        }
        entry.insert_key("auth", Value::from(instance.as_str()));
        let auth = root
            .entry_or_insert_with("auth", || Value::Map(Vec::new()))
            .as_mapping_mut()
            .ok_or_else(|| Refusal::Config("auth: is not a mapping".into()))?;
        if auth.get_key(instance.as_str()).is_some() {
            return Err(Refusal::Config(format!(
                "auth.{instance}: the name the 1.5.5 jwt-bearer provider `{name}` is migrated to is \
                 already taken; rename that instance, then boot again"
            )));
        }
        let config: Pairs = vec![
            (Value::from("style"), Value::from(JWT_BEARER)),
            (Value::from("credential"), credential),
            (Value::from("settings"), Value::Map(settings)),
        ];
        let module: Pairs = vec![(
            Value::from(crate::styles::DEFERRED),
            Value::from(JWT_BEARER),
        )];
        auth.insert_key(
            instance.as_str(),
            Value::Map(vec![
                (Value::from("module"), Value::Map(module)),
                (Value::from("config"), Value::Map(config)),
            ]),
        );
        marks.push(Mark {
            instance: vec!["auth".to_owned(), instance.clone()],
            pointer: "/credential".to_owned(),
        });
        report.push(format!(
            "providers.{name}: its 1.5.5 jwt-bearer credential is bound as auth.{instance}; the \
             auth plugin converts a 1.5.5 key-file reference on this boot"
        ));
    }
    Ok(())
}

/// Whether some 1.5.5 model names `provider` (1.5.5 resolved provider keys only for models).
fn reached(resolved: &Value, provider: &str) -> bool {
    let Some(Value::Map(models)) = resolved.get("models") else {
        return false;
    };
    models
        .iter()
        .any(|(_, model)| model.get("provider").and_then(Value::as_str) == Some(provider))
}

#[cfg(test)]
#[path = "tests/legacy_credentials_tests.rs"]
mod tests;
