// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1d, the 1.5.5 -> 1 step's own passes over core's sections (MIGRATE-ON-BOOT §A7 "STEPS[0],
//! enumerated"): each converts a shape v1.5.5 ran and 1.6.0 reads differently. They work on R, the
//! template tree, and decide on I, the interpolated twin, where 1.5.5 decided on resolved values
//! (§A3 1t). `module:` values and settings bags are left as written: plugins own them (step 2).
//!
//! Not here, by the dead-pass rule: nothing converts a marker's input (1a refuses it) or a section a
//! plane owns (`tools:`, `agents:`: their plane's own `migrate`).

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::templates::{computed, is_template};
use crate::{Facts, Refusal};

/// The cache-write TTL units. 1.5.5 billed these tokens inside the input, never at 0, so a migrated
/// card prices them at the entry's write rate (its `cache_write_utok`, else `input_utok`).
const WRITE_TIER_UNITS: [&str; 2] = ["cache_write_30m", "cache_write_12h"];

/// What 1.5.5 billed an open unit at: nothing. 0 keeps it.
const UNPRICED_RATE: i32 = 0;

/// The passes, in dev's order (`migrate_1_6::migrate`).
pub(crate) fn run(
    root: &mut Pairs,
    resolved: &Value,
    facts: &Facts,
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    migrate_plugin_trust(root, resolved, report)?;
    drop_overlay_selector(root, report);
    unfold_zero_cache_write(root, resolved, report);
    drop_hostless_metadata_entries(root, resolved, report);
    retire_metadata_carve_outs(root, resolved, report);
    price_open_units(root, facts, report)?;
    bind_ungoverned_principals(root, report);
    Ok(())
}

/// Replace old opt-ins only when both grant the same permission. Validate before any mutation,
/// so an ambiguous trust decision or unscoped publisher leaves the input intact.
fn migrate_plugin_trust(
    root: &mut Pairs,
    resolved: &Value,
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    let trust = resolved.at("plugins").at("trust");
    let Some(policy) = trust.as_mapping() else {
        return Ok(());
    };
    if let Some(publishers) = trust.at("publishers").as_sequence() {
        for publisher in publishers {
            if publisher.get("public_key").is_some()
                || publisher.get("plugins").is_none()
                || publisher.get("keys").is_none()
            {
                return Err(Refusal::Config(
                    "plugins.trust.publishers requires explicit plugin scope: use {name: vendor, plugins: [exact-plugin-name], keys: [{public_key: <existing-hex-key>, revoked: false}]}; no wildcard scope is inferred".into(),
                ));
            }
        }
    }
    let has_old = policy.contains_key("allow_unsigned") || policy.contains_key("allow_third_party");
    if !has_old {
        return Ok(());
    }
    if policy.contains_key("allow_untrusted") {
        return Err(Refusal::Config("plugins.trust mixes obsolete allow_unsigned/allow_third_party with allow_untrusted; remove the old fields and explicitly decide allow_untrusted".into()));
    }
    let read_flag = |name: &str| -> Result<bool, Refusal> {
        match policy.get_key(name) {
            None => Ok(false),
            Some(value) => value.as_bool().ok_or_else(|| Refusal::Config(format!("plugins.trust.{name} must resolve to a boolean; explicitly decide allow_untrusted"))),
        }
    };
    let unsigned = read_flag("allow_unsigned")?;
    let third_party = read_flag("allow_third_party")?;
    if unsigned != third_party {
        return Err(Refusal::Config("plugins.trust has exactly one old opt-in enabled; the combined permission would broaden intent. Replace both old fields with an explicit allow_untrusted decision".into()));
    }
    let Some(plugins) = mapping_mut(root, "plugins") else {
        return Ok(());
    };
    let Some(policy) = mapping_mut(plugins, "trust") else {
        return Ok(());
    };
    remove_kept(policy, "allow_unsigned");
    remove_kept(policy, "allow_third_party");
    policy.insert_key("allow_untrusted", Value::from(unsigned));
    report.push(format!("plugins.trust.allow_unsigned/allow_third_party replaced with allow_untrusted: {unsigned}; invalid known-publisher signatures, revoked keys and integrity failures always refuse"));
    Ok(())
}

/// Remove `key`, keeping the order of the rest (the patch writer never reorders an entry).
pub(crate) fn remove_kept(m: &mut Pairs, key: &str) -> Option<Value> {
    let at = m.iter().position(|(k, _)| k.as_str() == Some(key))?;
    Some(m.remove(at).1)
}

fn mapping_mut<'a>(m: &'a mut Pairs, key: &str) -> Option<&'a mut Pairs> {
    match m.get_key_mut(key) {
        Some(Value::Map(inner)) => Some(inner),
        _ => None,
    }
}

/// `config.overlay` selected 1.5.5's overlay file; the fold (1b, 1c) has read it by now, and 1.6.0
/// keeps config in config.yaml and the store.
fn drop_overlay_selector(root: &mut Pairs, report: &mut Vec<String>) {
    if let Some(config) = mapping_mut(root, "config") {
        if remove_kept(config, "overlay").is_some() {
            report.push(
                "config.overlay removed; current management uses config.locked and the configured \
                 Store"
                    .into(),
            );
        }
    }
}

/// A root `rate_card.<model>.cache_write_utok: 0` is the 1.5.5 spelling of "no separate write
/// tariff": 1.5.5 billed cache writes inside the input. The key is removed and writes price at
/// `input_utok`, never 0. Decided on the resolved value (a `${RATE}` that resolves to 0 is the same
/// spelling).
fn unfold_zero_cache_write(root: &mut Pairs, resolved: &Value, report: &mut Vec<String>) {
    let models = resolved
        .as_mapping()
        .map(busbar_kernel::config::zero_cache_write_models)
        .unwrap_or_default();
    let Some(card) = mapping_mut(root, "rate_card") else {
        return;
    };
    for model in models {
        if let Some(Value::Map(entry)) = card.get_key_mut(model.as_str()) {
            if remove_kept(entry, "cache_write_utok").is_some() {
                report.push(format!(
                    "rate_card.{model}.cache_write_utok: 0 removed (1.5.5 spelling of 'no separate \
                     write tariff'); cache writes price at input_utok"
                ));
            }
        }
    }
}

/// `security.blocked_metadata_hosts` entries that name no host matched nothing on 1.5.5, and 1.6.0
/// refuses them. Each is judged on its resolved text.
fn drop_hostless_metadata_entries(root: &mut Pairs, resolved: &Value, report: &mut Vec<String>) {
    let judged: Vec<Option<&'static str>> = resolved
        .at("security")
        .at("blocked_metadata_hosts")
        .as_sequence()
        .map(|entries| {
            entries
                .iter()
                .map(|entry| {
                    entry
                        .as_str()
                        .and_then(busbar_kernel::config_validate::metadata_entry_names_no_host)
                })
                .collect()
        })
        .unwrap_or_default();
    let Some(security) = mapping_mut(root, "security") else {
        return;
    };
    let Some(Value::Array(entries)) = security.get_key_mut("blocked_metadata_hosts") else {
        return;
    };
    if judged.len() != entries.len() {
        return;
    }
    let mut at = 0;
    entries.retain(|entry| {
        let why = judged[at];
        at += 1;
        match why {
            Some(why) => {
                let text = entry.as_str().unwrap_or("?");
                report.push(format!(
                    "security.blocked_metadata_hosts: removed entry '{text}' ({why}); it never \
                     matched any destination on 1.5.5, and 1.6.0 refuses a list entry that names \
                     no usable host, so removing it changes nothing that was blocked or allowed"
                ));
                false
            }
            None => true,
        }
    });
}

/// The 1.5.5 cloud-metadata carve-outs, retired in 1.6.0 (BUSBAR-3136): `security.allow_metadata_hosts`,
/// `security.allow_all_metadata` and each provider's `allow_metadata_hosts` are removed, whatever
/// they hold, and each entry that admitted something is named in a BUSBAR-3411 line: cloud
/// metadata is refused for every outbound connection, so a destination it reached is now refused.
fn retire_metadata_carve_outs(root: &mut Pairs, resolved: &Value, report: &mut Vec<String>) {
    fn retire(path: &str, value: &Value, read: &Value, report: &mut Vec<String>) {
        const CODE: busbar_contract::diagnostic::Banner =
            busbar_kernel::diagnostics::MIGRATE_METADATA_CARVE_OUT_REMOVED.banner();
        let entries: Vec<String> = match value {
            Value::Array(list) => list
                .iter()
                .map(|e| e.as_str().map_or_else(|| format!("{e:?}"), str::to_owned))
                .collect(),
            _ if read.as_bool() == Some(true) => vec!["true".to_owned()],
            _ => Vec::new(),
        };
        if entries.is_empty() {
            report.push(format!(
                "{CODE}: {path}: removed (it admitted nothing; 1.6.0 refuses the key: cloud \
                 metadata is refused for every outbound connection)"
            ));
        }
        for entry in entries {
            report.push(format!(
                "{CODE}: {path}: removed entry '{entry}'; 1.6.0 refuses cloud metadata for every \
                 outbound connection and no configuration admits it, so a destination it reached \
                 is now refused (use workload-identity federation for instance credentials)"
            ));
        }
    }
    if let Some(security) = mapping_mut(root, "security") {
        for key in ["allow_metadata_hosts", "allow_all_metadata"] {
            if let Some(value) = remove_kept(security, key) {
                let read = resolved.at("security").at(key);
                retire(&format!("security.{key}"), &value, read, report);
            }
        }
    }
    if let Some(providers) = mapping_mut(root, "providers") {
        for (name, provider) in providers.iter_mut() {
            let (Some(name), Value::Map(provider)) = (name.as_str(), provider) else {
                continue;
            };
            if let Some(value) = remove_kept(provider, "allow_metadata_hosts") {
                let read = resolved.at("providers").at(name).at("allow_metadata_hosts");
                retire(
                    &format!("providers.{name}.allow_metadata_hosts"),
                    &value,
                    read,
                    report,
                );
            }
        }
    }
}

/// A write tier's rate key and, when exact, the rate value and its rendering.
type WriteRate = (&'static str, Option<(Value, String)>);

/// The entry's cache-write rate as an exact `UnitRate` value and its rendering: `cache_write_utok`
/// when present (never falling back), else `input_utok`. `Ok(None)`: not an exact rate (the units
/// stay unpriced). A template slot refuses by 1t: the rate would be computed from it.
fn write_unit_rate(lane: &str, entry: &Pairs) -> Result<WriteRate, Refusal> {
    let key = if entry.contains_key("cache_write_utok") {
        "cache_write_utok"
    } else {
        "input_utok"
    };
    let Some(source) = entry.get_key(key) else {
        return Ok((key, None));
    };
    if is_template(source) {
        return Err(computed(&format!("rate_card.{lane}.{key}")));
    }
    let rate = source
        .as_f64()
        .and_then(busbar_kernel_ledger::cost::representable_nano_rate)
        .map(busbar_kernel_ledger::cost::UnitRate::from_nanos)
        .and_then(|rate| busbar_contract::yaml::to_value(rate).ok())
        .map(|value| {
            let shown = match &value {
                Value::Text(text) => text.clone(),
                other => busbar_contract::yaml::to_string(other)
                    .map(|text| text.trim_end().to_owned())
                    .unwrap_or_default(),
            };
            (value, shown)
        });
    Ok((key, rate))
}

/// 1.6.0 requires every billable unit of the fallback plane to be priced; a 1.5.5 lane billed the
/// open ones at nothing. Each lane gains the open units it does not price: the cache-write TTL
/// units at the lane's write rate, the rest at 0. The open units are the boot's facts (`Facts`),
/// never a plane list read here.
fn price_open_units(
    root: &mut Pairs,
    facts: &Facts,
    report: &mut Vec<String>,
) -> Result<(), Refusal> {
    if facts.open_units.is_empty() {
        return Ok(());
    }
    let Some(card) = mapping_mut(root, "rate_card") else {
        return Ok(());
    };
    for (lane, entry) in card.iter_mut() {
        let Some(lane) = lane.as_str() else { continue };
        if lane.contains(busbar_kernel::governance::PLANE_LANE_SEP) {
            continue;
        }
        let Value::Map(entry) = entry else {
            continue;
        };
        let missing = |units: Option<&Value>, unit: &str| {
            !units
                .and_then(Value::as_mapping)
                .is_some_and(|units| units.contains_key(unit))
        };
        let (written, added): (Vec<&str>, Vec<&str>) = facts
            .open_units
            .iter()
            .map(String::as_str)
            .filter(|unit| missing(entry.get_key("units"), unit))
            .partition(|unit| WRITE_TIER_UNITS.contains(unit));
        if written.is_empty() && added.is_empty() {
            continue;
        }
        let write_rate = if written.is_empty() {
            None
        } else {
            Some(write_unit_rate(lane, entry)?)
        };
        let units = entry.entry_or_insert_with("units", || Value::Map(Pairs::new()));
        let Value::Map(units) = units else {
            continue;
        };
        if let Some((source, rate)) = write_rate {
            match rate {
                Some((rate, shown)) => {
                    for unit in &written {
                        units.insert_key(*unit, rate.clone());
                    }
                    report.push(format!(
                        "rate_card.{lane}.units: added {} at {shown} (the entry's \
                         cache_write_utok, else input_utok; 1.5.5 billed cache writes inside \
                         input, never at 0)",
                        written.join(", ")
                    ));
                }
                None => report.push(format!(
                    "rate_card.{lane}.units: {} left unpriced: {source} is not an exact rate",
                    written.join(", ")
                )),
            }
        }
        for unit in &added {
            units.insert_key(*unit, Value::from(UNPRICED_RATE));
        }
        if !added.is_empty() {
            report.push(format!(
                "rate_card.{lane}.units: added {} at 0 (1.6.0 requires every billable unit to be \
                 priced; 1.5.5 billed these units at nothing, which 0 keeps)",
                added.join(", ")
            ));
        }
    }
    Ok(())
}

/// 1.5.5 admitted a principal of a non-`keys` chain provider with no grant; 1.6.0 refuses one
/// (401) unless a binding grants it. Each such provider gains an empty `"*"` binding, which keeps
/// 1.5.5's access, unless it has one.
fn bind_ungoverned_principals(root: &mut Pairs, report: &mut Vec<String>) {
    let role = busbar_kernel::config::auth::UNGOVERNED_ROLE;
    let Some(auth) = mapping_mut(root, "auth") else {
        return;
    };
    let providers: Vec<String> = match auth.get_key("chain") {
        Some(Value::Array(seq)) => seq
            .iter()
            .filter_map(|e| e.as_str().map(str::to_owned))
            .filter(|p| p != busbar_kernel::config::KEYS_MODULE)
            .collect(),
        _ => return,
    };
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
        if table.contains_key(role) {
            continue;
        }
        let had_roles = !table.is_empty();
        table.insert_key(role, Value::Map(Pairs::new()));
        let who = if had_roles {
            "a principal it identifies that asserts no roles"
        } else {
            "every principal it identifies"
        };
        report.push(format!(
            "auth.role_bindings.{provider}.\"{role}\": added an empty binding (every pool, no \
             group, no budget). 1.5.5 admitted {who} with no grant; 1.6.0 refuses such a principal \
             (401) unless a binding grants it, and this binding keeps 1.5.5's access"
        ));
        report.push(
            busbar_kernel::diagnostics::coded::migrate_ungoverned_binding_added(
                &provider, role, who,
            )
            .into(),
        );
    }
}

#[cfg(test)]
#[path = "tests/migrate_1_6_tests.rs"]
mod tests;
