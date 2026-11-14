// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_yaml::{Mapping, Value};

const LEGACY_UNPRICED_BILLABLE_UNIT_RATE: i32 = 0;

/// The cache-write TTL units. 1.5.5 billed these tokens inside the input, never at 0, so a migrated
/// card prices them at the entry's resolved write rate (its `cache_write_utok`, else `input_utok`).
const WRITE_TIER_UNITS: [&str; 2] = ["cache_write_30m", "cache_write_12h"];

/// The key the TTL write units are priced from, and that rate as an exact `UnitRate` value (with
/// its rendering) when it is a representable number. A present `cache_write_utok` never falls back
/// to `input_utok`; a non-number (an uninterpolated `${RATE}`), a negative rate or one finer than a
/// nano-unit yields `None`, and the units stay unpriced (refused under #42 when hit, audited).
fn resolved_write_unit_rate(entry: &Mapping) -> (&'static str, Option<(Value, String)>) {
    let key = if entry.contains_key(Value::from("cache_write_utok")) {
        "cache_write_utok"
    } else {
        "input_utok"
    };
    let rate = entry
        .get(Value::from(key))
        .and_then(Value::as_f64)
        .and_then(busbar_kernel_ledger::cost::representable_nano_rate)
        .map(busbar_kernel_ledger::cost::UnitRate::from_nanos)
        .and_then(|rate| serde_yaml::to_value(rate).ok())
        .map(|value| {
            let shown = match &value {
                Value::String(text) => text.clone(),
                other => serde_yaml::to_string(other)
                    .map(|text| text.trim_end().to_owned())
                    .unwrap_or_default(),
            };
            (value, shown)
        });
    (key, rate)
}

pub(super) fn migrate(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
    notices: &mut Vec<String>,
) {
    migrate_bootstrap(root, changes, notices);
    drop_hostless_metadata_entries(root, changes);
    price_open_units(root, changes);
    bind_ungoverned_principals(root, changes, warnings);
}

pub(super) fn migrate_bootstrap(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    notices: &mut Vec<String>,
) {
    drop_overlay_selector(root, changes);
    unfold_zero_cache_write(root, changes, notices);
}

/// A root `rate_card.<model>.cache_write_utok: 0` is the 1.5.5 spelling of "no separate write
/// tariff": 1.5.5 billed Chat cache writes inside the input, and its overlay serializer and paste
/// template wrote `0` into every card. YAML carries no provenance, so the spelling gets that one
/// meaning on every path: the key is removed and writes price at `input_utok`, never 0. Each removal
/// is a change line and a notice (only the authored model key and fixed text, never a value), which
/// the startup callers log at WARN because they zeroize change lines. Plane blocks are untouched.
pub(crate) fn unfold_zero_cache_write(
    root: &mut Mapping,
    changes: &mut Vec<String>,
    notices: &mut Vec<String>,
) {
    let models = busbar_kernel::config::zero_cache_write_models(root);
    let Some(card) = mapping_mut(root, "rate_card") else {
        return;
    };
    for model in models {
        if let Some(Value::Mapping(entry)) = card.get_mut(Value::from(model.as_str())) {
            entry.remove(Value::from("cache_write_utok"));
            let line = format!(
                "rate_card.{model}.cache_write_utok: 0 removed (1.5.5 spelling of 'no separate \
                 write tariff'); cache writes price at input_utok"
            );
            changes.push(line.clone());
            notices.push(line);
        }
    }
}

fn drop_overlay_selector(root: &mut Mapping, changes: &mut Vec<String>) {
    if let Some(config) = mapping_mut(root, "config") {
        if config.remove(Value::from("overlay")).is_some() {
            changes.push("config.overlay removed; current management uses config.locked and the configured Store".into());
        }
    }
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
        let Value::Mapping(entry) = entry else {
            continue;
        };
        let (write_source, write_rate) = resolved_write_unit_rate(entry);
        let units = entry
            .entry(Value::from("units"))
            .or_insert_with(|| Value::Mapping(Mapping::new()));
        let Value::Mapping(units) = units else {
            continue;
        };
        let (written, added): (Vec<&str>, Vec<&str>) = open
            .iter()
            .copied()
            .filter(|u| !units.contains_key(Value::from(*u)))
            .partition(|u| WRITE_TIER_UNITS.contains(u));
        if !written.is_empty() {
            match &write_rate {
                Some((rate, shown)) => {
                    for unit in &written {
                        units.insert(Value::from(*unit), rate.clone());
                    }
                    changes.push(format!(
                        "rate_card.{lane}.units: added {} at {shown} (the entry's cache_write_utok, \
                         else input_utok; 1.5.5 billed cache writes inside input, never at 0)",
                        written.join(", ")
                    ));
                }
                None => changes.push(format!(
                    "rate_card.{lane}.units: {} left unpriced: {write_source} is not an exact rate",
                    written.join(", ")
                )),
            }
        }
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
    Value::from(busbar_kernel::config::auth::UNGOVERNED_ROLE)
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
        .filter(|p| p != busbar_kernel::config::KEYS_MODULE)
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

    #[test]
    fn one_shot_migration_drops_old_selectors_and_preserves_locked_policy() {
        for locked in [false, true] {
            for selector in ["false", "true", "{file: /old/overlay.json}", "{}", "null"] {
                let mut root: Mapping = serde_yaml::from_str(&format!(
                    "config: {{locked: {locked}, overlay: {selector}}}\n"
                ))
                .unwrap();
                let mut changes = Vec::new();
                drop_overlay_selector(&mut root, &mut changes);
                let config = root[Value::from("config")].as_mapping().unwrap();
                assert!(!config.contains_key(Value::from("overlay")));
                assert_eq!(config[Value::from("locked")], Value::Bool(locked));
                assert_eq!(changes.len(), 1);
                drop_overlay_selector(&mut root, &mut changes);
                assert_eq!(changes.len(), 1, "retry is idempotent");
            }
        }
    }

    #[test]
    fn dropping_selector_does_not_invent_lock_policy_or_discard_other_keys() {
        let mut root: Mapping =
            serde_yaml::from_str("config: {overlay: false, unknown: retained}\n").unwrap();
        drop_overlay_selector(&mut root, &mut Vec::new());
        let config = root[Value::from("config")].as_mapping().unwrap();
        assert!(!config.contains_key(Value::from("locked")));
        assert_eq!(config[Value::from("unknown")], Value::from("retained"));
    }
}
