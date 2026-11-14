// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::yaml::prelude::*;

const LEGACY_UNPRICED_BILLABLE_UNIT_RATE: i32 = 0;

pub(super) fn migrate(root: &mut Pairs, changes: &mut Vec<String>, warnings: &mut Vec<String>) {
    migrate_bootstrap(root, changes);
    drop_hostless_metadata_entries(root, changes);
    price_open_units(root, changes);
    bind_ungoverned_principals(root, changes, warnings);
}

pub(super) fn migrate_bootstrap(root: &mut Pairs, changes: &mut Vec<String>) {
    drop_overlay_selector(root, changes);
}

fn drop_overlay_selector(root: &mut Pairs, changes: &mut Vec<String>) {
    if let Some(config) = mapping_mut(root, "config") {
        if super::swap_remove_key(config, "overlay").is_some() {
            changes.push("config.overlay removed; current management uses config.locked and the configured Store".into());
        }
    }
}

fn mapping_mut<'a>(m: &'a mut Pairs, key: &str) -> Option<&'a mut Pairs> {
    match m.get_key_mut(key) {
        Some(Value::Map(inner)) => Some(inner),
        _ => None,
    }
}

fn drop_hostless(m: &mut Pairs, list_key: &str, path: &str, changes: &mut Vec<String>) {
    let Some(Value::Array(entries)) = m.get_key_mut(list_key) else {
        return;
    };
    entries.retain(|entry| {
        let Some(text) = entry.as_str() else {
            return true;
        };
        match busbar_kernel::config_validate::metadata_entry_names_no_host(text) {
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

fn drop_hostless_metadata_entries(root: &mut Pairs, changes: &mut Vec<String>) {
    if let Some(security) = mapping_mut(root, "security") {
        for key in ["blocked_metadata_hosts", "allow_metadata_hosts"] {
            drop_hostless(security, key, &format!("security.{key}"), changes);
        }
    }
    if let Some(providers) = mapping_mut(root, "providers") {
        for (name, provider) in providers.iter_mut() {
            let (Some(name), Value::Map(provider)) = (name.as_str(), provider) else {
                continue;
            };
            let path = format!("providers.{name}.allow_metadata_hosts");
            drop_hostless(provider, "allow_metadata_hosts", &path, changes);
        }
    }
}

fn price_open_units(root: &mut Pairs, changes: &mut Vec<String>) {
    let open: Vec<&'static str> = busbar_kernel::plane_driver::registry::plane_decls()
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

        if lane.contains(busbar_kernel::governance::PLANE_LANE_SEP) {
            continue;
        }
        let Value::Map(entry) = entry else {
            continue;
        };
        let units = entry.entry_or_insert_with("units", || Value::Map(Pairs::new()));
        let Value::Map(units) = units else {
            continue;
        };
        let added: Vec<&str> = open
            .iter()
            .copied()
            .filter(|u| !units.contains_key(*u))
            .collect();
        for unit in &added {
            units.insert_key(*unit, Value::from(LEGACY_UNPRICED_BILLABLE_UNIT_RATE));
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
    Value::from(busbar_kernel::config::auth::UNGOVERNED_ROLE)
}

fn bind_ungoverned_principals(
    root: &mut Pairs,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let Some(auth) = mapping_mut(root, "auth") else {
        return;
    };
    let chain: Vec<String> = match auth.get_key("chain") {
        Some(Value::Array(seq)) => seq
            .iter()
            .filter_map(|e| e.as_str().map(str::to_string))
            .collect(),
        _ => return,
    };
    let providers: Vec<String> = chain
        .into_iter()
        .filter(|p| p != busbar_kernel::config::KEYS_MODULE)
        .collect();
    if providers.is_empty() {
        return;
    }
    let bindings = auth.entry_or_insert_with("role_bindings", || Value::Map(Pairs::new()));
    let Value::Map(bindings) = bindings else {
        return;
    };
    for provider in providers {
        let table = bindings.entry_or_insert_with(provider.as_str(), || Value::Map(Pairs::new()));
        let Value::Map(table) = table else {
            continue;
        };
        if table.contains_key(ungoverned_role()) {
            continue;
        }
        let had_roles = !table.is_empty();
        table.insert_key(ungoverned_role(), Value::Map(Pairs::new()));
        let role = busbar_kernel::config::auth::UNGOVERNED_ROLE;
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

#[cfg(test)]
mod config_management_tests {
    use super::*;
    use busbar_contract::yaml;

    #[test]
    fn one_shot_migration_drops_old_selectors_and_preserves_locked_policy() {
        for locked in [false, true] {
            for selector in ["false", "true", "{file: /old/overlay.json}", "{}", "null"] {
                let mut root: Mapping = yaml::mapping_from_str(&format!(
                    "config: {{locked: {locked}, overlay: {selector}}}\n"
                ))
                .unwrap();
                let mut changes = Vec::new();
                drop_overlay_selector(&mut root, &mut changes);
                let config = root.get_key("config").unwrap().as_mapping().unwrap();
                assert!(!config.contains_key("overlay"));
                assert_eq!(config.get_key("locked"), Some(&Value::Bool(locked)));
                assert_eq!(changes.len(), 1);
                drop_overlay_selector(&mut root, &mut changes);
                assert_eq!(changes.len(), 1, "retry is idempotent");
            }
        }
    }

    #[test]
    fn dropping_selector_does_not_invent_lock_policy_or_discard_other_keys() {
        let mut root: Mapping =
            yaml::mapping_from_str("config: {overlay: false, unknown: retained}\n").unwrap();
        drop_overlay_selector(&mut root, &mut Vec::new());
        let config = root.get_key("config").unwrap().as_mapping().unwrap();
        assert!(!config.contains_key("locked"));
        assert_eq!(config.get_key("unknown"), Some(&Value::from("retained")));
    }
}
