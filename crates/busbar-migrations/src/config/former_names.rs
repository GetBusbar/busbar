// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Packaging-declared historical names are converted here, never admitted by runtime.
use serde_yaml::{Mapping, Value};

fn current(old: &str) -> Option<&'static str> {
    let mut selected = None;
    for (key, names) in super::migration_table::rows() {
        let Some(alias) = key.strip_prefix("former.") else {
            continue;
        };
        if alias != old && names.split_whitespace().any(|name| name == old) {
            if selected.is_some_and(|existing| existing != alias) {
                return None;
            }
            selected = Some(alias);
        }
    }
    selected
}

pub(super) fn needed(doc: &Value) -> bool {
    let Some(root) = doc.as_mapping() else {
        return false;
    };
    let former_module = |value: &Value| {
        value
            .get("module")
            .and_then(Value::as_str)
            .is_some_and(|name| current(name).is_some())
    };
    if root.get("store").is_some_and(former_module) {
        return true;
    }
    for section in ["identity-providers", "secrets", "hooks", "export"] {
        if root
            .get(section)
            .and_then(Value::as_mapping)
            .is_some_and(|entries| entries.values().any(former_module))
        {
            return true;
        }
    }
    let instances = root.get("identity-providers").and_then(Value::as_mapping);
    if let Some(auth) = root.get("auth").and_then(Value::as_mapping) {
        for key in ["chain", "admin_auth"] {
            if auth
                .get(key)
                .and_then(Value::as_sequence)
                .is_some_and(|entries| {
                    entries.iter().filter_map(Value::as_str).any(|name| {
                        !instances.is_some_and(|defs| defs.contains_key(name))
                            && current(name).is_some()
                    })
                })
            {
                return true;
            }
        }
    }
    root.get("plugins")
        .and_then(Value::as_mapping)
        .is_some_and(|plugins| {
            plugins
                .keys()
                .filter_map(Value::as_str)
                .any(|name| current(name).is_some())
        })
}

pub(super) fn migrate(root: &mut Mapping, changes: &mut Vec<String>, todos: &mut Vec<String>) {
    if let Some(store) = root.get_mut("store").and_then(Value::as_mapping_mut) {
        module(store, "store", changes);
    }
    for section in ["identity-providers", "secrets", "hooks", "export"] {
        if let Some(entries) = root.get_mut(section).and_then(Value::as_mapping_mut) {
            for (name, value) in entries {
                if let Some(definition) = value.as_mapping_mut() {
                    module(
                        definition,
                        &format!("{section}.{}", name.as_str().unwrap_or("<entry>")),
                        changes,
                    );
                }
            }
        }
    }
    // A current chain names identity-provider instances. Preserve that identity even
    // when its spelling happens to equal a former module name.
    let instances: Vec<String> = root
        .get("identity-providers")
        .and_then(Value::as_mapping)
        .map(|m| {
            m.keys()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if let Some(auth) = root.get_mut("auth").and_then(Value::as_mapping_mut) {
        for key in ["chain", "admin_auth"] {
            if let Some(entries) = auth.get_mut(key).and_then(Value::as_sequence_mut) {
                for entry in entries {
                    if let Some(old) = entry.as_str() {
                        if !instances.iter().any(|name| name == old) {
                            if let Some(alias) = current(old) {
                                changes.push(format!(
                                    "auth.{key}: historical module {old} -> {alias}"
                                ));
                                *entry = alias.into();
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(plugins) = root.get_mut("plugins").and_then(Value::as_mapping_mut) {
        let renamed: Vec<(Value, &'static str)> = plugins
            .keys()
            .filter_map(|key| Some((key.clone(), current(key.as_str()?)?)))
            .collect();
        for (old, alias) in renamed {
            if plugins.contains_key(alias) {
                todos.push(format!("plugins: historical module {} and current alias {alias} both have fetch declarations; resolve the collision", old.as_str().unwrap_or("<entry>")));
            } else if let Some(value) = plugins.remove(&old) {
                changes.push(format!(
                    "plugins: historical module {} -> {alias}",
                    old.as_str().unwrap_or("<entry>")
                ));
                plugins.insert(alias.into(), value);
            }
        }
    }
}

fn module(definition: &mut Mapping, path: &str, changes: &mut Vec<String>) {
    let Some(old) = definition.get("module").and_then(Value::as_str) else {
        return;
    };
    let Some(alias) = current(old) else { return };
    changes.push(format!("{path}.module: historical name {old} -> {alias}"));
    definition.insert("module".into(), alias.into());
}
