// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 -> 1.6.0 STEPS OVER CORE'S OWN KEYS (`busbar --migrate-config`).
//!
//! Each step rewrites a key core owns so that a configuration 1.5.5 ran keeps running, the same
//! way, on 1.6.0, and each rewrite is reported as one change line naming what changed and why.
//! Nothing here reads or writes inside a plugin's settings: a plugin migrates its own section
//! through its own `migrate` entry. What a step needs to know about a plane (the billable classes a
//! rate card must price) it reads off the plane registry, never out of a list written here.

use serde_yaml::{Mapping, Value};

/// Run every 1.5.5 -> 1.6.0 step over core's keys, in order.
pub(super) fn migrate(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
    unresolved: &mut Vec<String>,
) {
    drop_hostless_metadata_entries(root, changes);
    price_open_units(root, changes);
    bind_ungoverned_principals(root, changes, warnings);
    todo_unresolved_provider_keys(root, unresolved);
}

/// The mapping at `key` of `m`, when it is one.
fn mapping_mut<'a>(m: &'a mut Mapping, key: &str) -> Option<&'a mut Mapping> {
    match m.get_mut(Value::from(key)) {
        Some(Value::Mapping(inner)) => Some(inner),
        _ => None,
    }
}

/// Remove, from the list at `list_key` of `m`, every entry that names no usable host, reporting
/// each under `path`.
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

/// 1.6.0 refuses a metadata host-list entry that names no host the destination guard can judge
/// (`db.1`, `1.2.3.4.5`, a `%` escape). On 1.5.5 such an entry matched nothing, so removing it
/// keeps exactly what 1.5.5 blocked and allowed. A `/` entry is left alone: 1.5.5 refused it too.
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

/// A top-level `rate_card:` must, on 1.6.0, configure every billable unit the fallback plane
/// declares beyond the four reserved token tiers. 1.5.5 billed those units at nothing, so each
/// entry gains `units:` naming every such unit it does not already price, at `0`: exactly what
/// 1.5.5 charged. The unit names are the plane's own declaration, read off the plane registry.
fn price_open_units(root: &mut Mapping, changes: &mut Vec<String>) {
    let open: Vec<&'static str> = crate::plane::registry::plane_decls()
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
        // A plane-qualified key is another plane's card, which 1.5.5 never had.
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
            units.insert(Value::from(*unit), Value::from(0));
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

/// The role a `role_bindings.<provider>` table binds a principal 1.5.5 admitted with no grant by
/// ([`crate::config::auth::UNGOVERNED_ROLE`]).
fn ungoverned_role() -> Value {
    Value::from(crate::config::auth::UNGOVERNED_ROLE)
}

/// 1.5.5 admitted a principal that a data-plane provider identified but no role binding granted
/// (a principal asserting no roles, or any principal of a provider with no `role_bindings` table),
/// with no pool limit and no budget. 1.6.0 refuses every such principal (401). For each data-plane
/// provider whose principals 1.5.5 admitted that way, this writes the explicit binding that admits
/// exactly them again, on every pool, with no group (no budget), and a WARNING naming it: it keeps
/// 1.5.5's access and should be tightened. The built-in signed-key verifier issues its own keys and
/// needs none.
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

/// A provider `api_key` reference that does not resolve refuses the boot on 1.6.0 (1.5.5 ran the
/// lane keyless). The migration cannot know the key, so it names each such provider in a TODO. Only
/// references to a secret source this build links are judged; any other is the plugin's to name.
/// Whether a reference resolves is a fact about the machine running the migration, not about the
/// file, so these TODOs are printed in the summary and never written into the migrated file.
fn todo_unresolved_provider_keys(root: &Mapping, todos: &mut Vec<String>) {
    let Some(Value::Mapping(providers)) = root.get(Value::from("providers")) else {
        return;
    };
    for (name, provider) in providers {
        let (Some(name), Value::Mapping(provider)) = (name.as_str(), provider) else {
            continue;
        };
        let Some(reference) = provider.get(Value::from("api_key")) else {
            continue;
        };
        // An `${VAR}` reference is interpolated at boot, not here.
        if serde_yaml::to_string(reference).is_ok_and(|s| s.contains("${")) {
            continue;
        }
        let Ok(secret) =
            serde_yaml::from_value::<busbar_contract::secret_ref::SecretRef>(reference.clone())
        else {
            continue;
        };
        if !crate::config::secret::is_linked_secret(&secret.module) {
            continue;
        }
        let scope = busbar_contract::config_time::ConfigScope::config_time();
        if let Err(why) = crate::config::secret::resolve_linked_string_at_config(&secret, &scope) {
            todos.push(format!(
                "providers.{name}.api_key: the reference {} does not resolve here ({why}). 1.5.5 \
                 ran this provider with no key; 1.6.0 refuses to start until it resolves. Make it \
                 resolve where busbar runs, or set `api_key: none` to keep running it keyless",
                secret.describe()
            ));
        }
    }
}

#[cfg(test)]
#[path = "tests/migrate_1_6_tests.rs"]
mod tests;
