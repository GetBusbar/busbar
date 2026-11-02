// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_yaml::{Mapping, Value};

const LEGACY_UNPRICED_BILLABLE_UNIT_RATE: i32 = 0;

pub(super) fn migrate(root: &mut Mapping, changes: &mut Vec<String>, warnings: &mut Vec<String>) {
    drop_hostless_metadata_entries(root, changes);
    price_open_units(root, changes);
    bind_ungoverned_principals(root, changes, warnings);
}

fn mapping_mut<'a>(m: &'a mut Mapping, key: &str) -> Option<&'a mut Mapping> {
    match m.get_mut(Value::from(key)) {
        Some(Value::Mapping(inner)) => Some(inner),
        _ => None,
    }
}

fn drop_hostless(m: &mut Mapping, list_key: &str, path: &str, changes: &mut Vec<String>) {
    let Some(Value::Sequence(entries)) = m.get_mut(Value::from(list_key)) else {
        return;
    };
    entries.retain(|entry| {
        let Some(text) = entry.as_str() else {
            return true;
        };
        match crate::config_validate::metadata_entry_names_no_host(text) {
            Some(why) => {
                changes.push(format!(
                    "{path}: removed entry '{text}' ({why}); it never matched any destination on \
                     1.5.5, and 1.6.0 refuses a list entry that names no usable host, so removing \
                     it changes nothing that was blocked or allowed"
                ));
                false
            }
            None => true,
        }
    });
}

fn drop_hostless_metadata_entries(root: &mut Mapping, changes: &mut Vec<String>) {
    if let Some(security) = mapping_mut(root, "security") {
        for key in ["blocked_metadata_hosts", "allow_metadata_hosts"] {
            drop_hostless(security, key, &format!("security.{key}"), changes);
        }
    }
    if let Some(providers) = mapping_mut(root, "providers") {
        for (name, provider) in providers.iter_mut() {
            let (Some(name), Value::Mapping(provider)) = (name.as_str(), provider) else {
                continue;
            };
            let path = format!("providers.{name}.allow_metadata_hosts");
            drop_hostless(provider, "allow_metadata_hosts", &path, changes);
        }
    }
}

fn price_open_units(root: &mut Mapping, changes: &mut Vec<String>) {
    let open: Vec<&'static str> = crate::plane_driver::registry::plane_decls()
        .iter()
        .filter(|d| d.fallback)
        .flat_map(|d| {
            d.billable_classes
                .iter()
                .map(|c| c.class)
                .filter(move |c| !d.fee_units.contains(c))
        })
        .filter(|c| !busbar_contract::records::RESERVED_UNITS.contains(c))
        .collect();
    if open.is_empty() {
        return;
    }
    let Some(card) = mapping_mut(root, "rate_card") else {
        return;
    };
    for (lane, entry) in card.iter_mut() {
        let Some(lane) = lane.as_str() else { continue };

        if lane.contains(crate::governance::PLANE_LANE_SEP) {
            continue;
        }
        let Value::Mapping(entry) = entry else {
            continue;
        };
        let units = entry
            .entry(Value::from("units"))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        let Value::Mapping(units) = units else {
            continue;
        };
        let added: Vec<&str> = open
            .iter()
            .copied()
            .filter(|u| !units.contains_key(Value::from(*u)))
            .collect();
        for unit in &added {
            units.insert(
                Value::from(*unit),
                Value::from(LEGACY_UNPRICED_BILLABLE_UNIT_RATE),
            );
        }
        if !added.is_empty() {
            changes.push(format!(
                "rate_card.{lane}.units: added {} at 0 (1.6.0 requires every billable unit to be \
                 priced; 1.5.5 billed these units at nothing, which 0 keeps)",
                added.join(", ")
            ));
        }
    }
}

fn ungoverned_role() -> Value {
    Value::from(crate::config::auth::UNGOVERNED_ROLE)
}

fn bind_ungoverned_principals(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(auth) = mapping_mut(root, "auth") else {
        return;
    };
    let chain: Vec<String> = match auth.get(Value::from("chain")) {
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|e| e.as_str().map(str::to_string))
            .collect(),
        _ => return,
    };
    let providers: Vec<String> = chain
        .into_iter()
        .filter(|p| p != crate::config::KEYS_MODULE)
        .collect();
    if providers.is_empty() {
        return;
    }
    let bindings = auth
        .entry(Value::from("role_bindings"))
        .or_insert_with(|| Value::Mapping(Mapping::new()));
    let Value::Mapping(bindings) = bindings else {
        return;
    };
    for provider in providers {
        let table = bindings
            .entry(Value::from(provider.as_str()))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        let Value::Mapping(table) = table else {
            continue;
        };
        if table.contains_key(ungoverned_role()) {
            continue;
        }
        let had_roles = !table.is_empty();
        table.insert(ungoverned_role(), Value::Mapping(Mapping::new()));
        let role = crate::config::auth::UNGOVERNED_ROLE;
        let who = if had_roles {
            "a principal it identifies that asserts no roles"
        } else {
            "every principal it identifies"
        };
        changes.push(format!(
            "auth.role_bindings.{provider}.\"{role}\": added an empty binding (every pool, no \
             group, no budget). 1.5.5 admitted {who} with no grant; 1.6.0 refuses such a principal \
             (401) unless a binding grants it, and this binding keeps 1.5.5's access"
        ));
        warnings.push(format!(
            "auth.role_bindings.{provider}.\"{role}\" was written by the migration to keep 1.5.5's \
             access: {who} is admitted on every pool with no budget, as 1.5.5 admitted them. \
             Tighten it (allowed_pools, a group with limits) or remove it to refuse them."
        ));
    }
}

#[cfg(test)]
#[path = "tests/migrate_1_6_tests.rs"]
mod tests;
