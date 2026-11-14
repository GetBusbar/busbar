// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::yaml::prelude::*;

const LEGACY_UNPRICED_BILLABLE_UNIT_RATE: i32 = 0;

/// The cache-write TTL units. 1.5.5 billed these tokens inside the input, never at 0, so a migrated
/// card prices them at the entry's resolved write rate (its `cache_write_utok`, else `input_utok`).
const WRITE_TIER_UNITS: [&str; 2] = ["cache_write_30m", "cache_write_12h"];

/// The key the TTL write units are priced from, and that rate as an exact `UnitRate` value (with
/// its rendering) when it is a representable number. A present `cache_write_utok` never falls back
/// to `input_utok`; a non-number (an uninterpolated `${RATE}`), a negative rate or one finer than a
/// nano-unit yields `None`, and the units stay unpriced (refused under #42 when hit, audited).
fn resolved_write_unit_rate(entry: &Pairs) -> (&'static str, Option<(Value, String)>) {
    let key = if entry.contains_key("cache_write_utok") {
        "cache_write_utok"
    } else {
        "input_utok"
    };
    let rate = entry
        .get_key(key)
        .and_then(Value::as_f64)
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
    (key, rate)
}

pub(super) fn migrate(
    root: &mut Pairs,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
    notices: &mut Vec<String>,
) {
    migrate_bootstrap(root, changes, notices);
    drop_hostless_metadata_entries(root, changes);
    retire_metadata_carve_outs(root, changes, warnings);
    price_open_units(root, changes);
    bind_ungoverned_principals(root, changes, warnings);
    retire_private_reach(root, changes, warnings);
}

pub(super) fn migrate_bootstrap(
    root: &mut Pairs,
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
    root: &mut Pairs,
    changes: &mut Vec<String>,
    notices: &mut Vec<String>,
) {
    let models = busbar_kernel::config::zero_cache_write_models(root);
    let Some(card) = mapping_mut(root, "rate_card") else {
        return;
    };
    for model in models {
        if let Some(Value::Map(entry)) = card.get_key_mut(model.as_str()) {
            entry.remove_key("cache_write_utok");
            let line = format!(
                "rate_card.{model}.cache_write_utok: 0 removed (1.5.5 spelling of 'no separate \
                 write tariff'); cache writes price at input_utok"
            );
            changes.push(line.clone());
            notices.push(line);
        }
    }
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
        drop_hostless(
            security,
            "blocked_metadata_hosts",
            "security.blocked_metadata_hosts",
            changes,
        );
    }
}

/// The 1.5.5 cloud-metadata carve-outs, retired in 1.6.0 (BUSBAR-3136): `security.allow_metadata_hosts`,
/// `security.allow_all_metadata` and each provider's `allow_metadata_hosts` are removed, whatever
/// they hold, and each entry that admitted something is named in a BUSBAR-3411 warning: cloud
/// metadata is refused for every outbound connection, so a destination it reached is now refused.
fn retire_metadata_carve_outs(
    root: &mut Pairs,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    const CODE: busbar_contract::diagnostic::Banner =
        busbar_kernel::diagnostics::MIGRATE_METADATA_CARVE_OUT_REMOVED.banner();
    let mut report = |path: &str, value: Value| {
        let entries: Vec<String> = match &value {
            Value::Array(list) => list
                .iter()
                .map(|e| e.as_str().map_or_else(|| format!("{e:?}"), str::to_owned))
                .collect(),
            Value::Bool(true) => vec!["true".to_owned()],
            _ => Vec::new(),
        };
        if entries.is_empty() {
            changes.push(format!(
                "{CODE}: {path}: removed (it admitted nothing; 1.6.0 refuses the key: cloud metadata \
                 is refused for every outbound connection)"
            ));
        }
        for entry in entries {
            warnings.push(format!(
                "{CODE}: {path}: removed entry '{entry}'; 1.6.0 refuses cloud metadata for every \
                 outbound connection and no configuration admits it, so a destination it reached \
                 is now refused (use workload-identity federation for instance credentials)"
            ));
        }
    };
    if let Some(security) = mapping_mut(root, "security") {
        for key in ["allow_metadata_hosts", "allow_all_metadata"] {
            if let Some(value) = security.remove_key(key) {
                report(&format!("security.{key}"), value);
            }
        }
    }
    if let Some(providers) = mapping_mut(root, "providers") {
        for (name, provider) in providers.iter_mut() {
            let (Some(name), Value::Map(provider)) = (name.as_str(), provider) else {
                continue;
            };
            if let Some(value) = provider.remove_key("allow_metadata_hosts") {
                report(&format!("providers.{name}.allow_metadata_hosts"), value);
            }
        }
    }
}

/// The retired per-registration private-address switch, by the section that carried it.
const PRIVATE_REACH_KEY: &str = "allow_private";

/// The sections whose registrations carried [`PRIVATE_REACH_KEY`] (`tools.<server>`,
/// `agents.<agent>`), and the URL-valued fields of a registration its opens dial: the
/// registration's own `url`, and the token endpoints its credential exchange dials.
const PRIVATE_REACH_SECTIONS: &[&str] = &["tools", "agents"];
const PRIVATE_REACH_URLS: &[&[&str]] = &[
    &["url"],
    &["token_exchange", "token_url"],
    &["oauth", "token_endpoint"],
];

/// `allow_private: true` lifted the private-address refusal for one registration's dials. 1.6.0 has
/// one policy for every outbound connection, `advanced.allow_destinations`, so the key is removed
/// and EXACTLY the hosts that registration dials are listed there (no wildcard, no network). A
/// metadata or unjudgeable host is never listed. `allow_private: false` said nothing and is dropped.
fn retire_private_reach(root: &mut Pairs, changes: &mut Vec<String>, warnings: &mut Vec<String>) {
    const CODE: busbar_contract::diagnostic::Banner =
        busbar_kernel::diagnostics::MIGRATE_PRIVATE_REACH_TO_ALLOWLIST.banner();
    let mut hosts: Vec<(String, String, bool)> = Vec::new();
    for section in PRIVATE_REACH_SECTIONS {
        let Some(registrations) = mapping_mut(root, section) else {
            continue;
        };
        for (name, entry) in registrations.iter_mut() {
            let (Some(name), Value::Map(entry)) = (name.as_str(), entry) else {
                continue;
            };
            let at = format!("{section}.{name}");
            let Some(value) = entry.remove_key(PRIVATE_REACH_KEY) else {
                continue;
            };
            if value.as_bool() != Some(true) {
                changes.push(format!(
                    "{CODE}: {at}.{PRIVATE_REACH_KEY}: removed (it was not `true`, so it admitted nothing; \
                     1.6.0 refuses the key)"
                ));
                continue;
            }
            let urls: Vec<(String, bool)> = PRIVATE_REACH_URLS
                .iter()
                .filter_map(|path| {
                    let mut at: &Value = entry.get_key(path[0])?;
                    for key in &path[1..] {
                        at = at.get(*key)?;
                    }
                    at.as_str()
                        .map(|u| (u.to_owned(), busbar_contract::net::scheme_is(u, "http")))
                })
                .collect();
            if urls.is_empty() {
                changes.push(format!(
                    "{CODE}: {at}.{PRIVATE_REACH_KEY}: removed; the registration names no URL it dials, so \
                     nothing was added to advanced.allow_destinations"
                ));
            }
            for (url, plaintext) in urls {
                hosts.push((at.clone(), url, plaintext));
            }
        }
    }
    for (at, url, plaintext) in hosts {
        allow_registration_host(root, &at, &url, changes, warnings);
        if plaintext && !crate::config::migrate_1_6::names_loopback_url(&url) {
            warnings.push(format!(
                "{CODE}: {at}: `{url}` is plaintext http:// to a host other than loopback, which \
                 `{PRIVATE_REACH_KEY}: true` also let the registration use; it is refused at GA; \
                 use https (a per-destination `plaintext: true` entry arrives after 1.6.0)"
            ));
        }
    }
}

/// List exactly the host `url` names in `advanced.allow_destinations` for the registration at `at`.
fn allow_registration_host(
    root: &mut Pairs,
    at: &str,
    url: &str,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    const CODE: busbar_contract::diagnostic::Banner =
        busbar_kernel::diagnostics::MIGRATE_PRIVATE_REACH_TO_ALLOWLIST.banner();
    use busbar_contract::net::{host_is_cloud_metadata, is_alternate_ipv4_encoding, judged_host};
    let host = busbar_contract::net::target_host(url)
        .and_then(|h| judged_host(&h).ok())
        .filter(|h| !h.is_empty());
    let Some(host) = host else {
        warnings.push(format!(
            "{CODE}: {at}.{PRIVATE_REACH_KEY}: removed; its URL names no host the destination guard can \
             judge, so nothing was added to advanced.allow_destinations; add the host by hand"
        ));
        return;
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    if host_is_cloud_metadata(&host) || is_alternate_ipv4_encoding(&host) {
        warnings.push(format!(
            "{CODE}: {at}.{PRIVATE_REACH_KEY}: removed; '{host}' was not added to \
             advanced.allow_destinations: a cloud-metadata host or an alternate IPv4 spelling is \
             refused whatever the list says (it was refused under `{PRIVATE_REACH_KEY}` too)"
        ));
        return;
    }
    if crate::config::migrate_plugins::already_allowed(root, &host) {
        changes.push(format!(
            "{CODE}: {at}.{PRIVATE_REACH_KEY}: removed; '{host}' is already listed in \
             advanced.allow_destinations, which now governs it"
        ));
        return;
    }
    match crate::config::migrate_plugins::push_allowed(root, at, &host) {
        Ok(_) => changes.push(format!(
            "{CODE}: {at}.{PRIVATE_REACH_KEY}: replaced by advanced.allow_destinations: '{host}' (one \
             setting governs every outbound connection in 1.6.0; exactly this host is allowed, \
             not every private address)"
        )),
        Err(todo) => warnings.push(format!("{CODE}: {todo}")),
    }
}

/// Whether `url` names a LOOPBACK host (`localhost`, `*.localhost`, `127/8`, `::1`): a plaintext
/// registration to one keeps working at GA, so the retirement warns about every other.
pub(crate) fn names_loopback_url(url: &str) -> bool {
    let Some(host) = busbar_contract::net::target_host(url)
        .and_then(|h| busbar_contract::net::judged_host(&h).ok())
    else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match busbar_contract::net::host_ip(host) {
        Some(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Some(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        None => host == "localhost" || host.ends_with(".localhost"),
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
        let (write_source, write_rate) = resolved_write_unit_rate(entry);
        let units = entry.entry_or_insert_with("units", || Value::Map(Pairs::new()));
        let Value::Map(units) = units else {
            continue;
        };
        let (written, added): (Vec<&str>, Vec<&str>) = open
            .iter()
            .copied()
            .filter(|u| !units.contains_key(*u))
            .partition(|u| WRITE_TIER_UNITS.contains(u));
        if !written.is_empty() {
            match &write_rate {
                Some((rate, shown)) => {
                    for unit in &written {
                        units.insert_key(*unit, rate.clone());
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
        warnings.push(
            busbar_kernel::diagnostics::coded::migrate_ungoverned_binding_added(
                provider, role, who,
            )
            .into(),
        );
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
