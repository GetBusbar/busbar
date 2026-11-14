// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_yaml::{Mapping, Value};

const LEGACY_UNPRICED_BILLABLE_UNIT_RATE: i32 = 0;

pub(super) fn migrate(root: &mut Mapping, changes: &mut Vec<String>, warnings: &mut Vec<String>) {
    migrate_bootstrap(root, changes);
    drop_hostless_metadata_entries(root, changes);
    price_open_units(root, changes);
    bind_ungoverned_principals(root, changes, warnings);
    retire_private_reach(root, changes, warnings);
}

pub(super) fn migrate_bootstrap(root: &mut Mapping, changes: &mut Vec<String>) {
    drop_overlay_selector(root, changes);
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
fn retire_private_reach(root: &mut Mapping, changes: &mut Vec<String>, warnings: &mut Vec<String>) {
    let mut hosts: Vec<(String, String, bool)> = Vec::new();
    for section in PRIVATE_REACH_SECTIONS {
        let Some(registrations) = mapping_mut(root, section) else {
            continue;
        };
        for (name, entry) in registrations.iter_mut() {
            let (Some(name), Value::Mapping(entry)) = (name.as_str(), entry) else {
                continue;
            };
            let at = format!("{section}.{name}");
            let Some(value) = entry.remove(Value::from(PRIVATE_REACH_KEY)) else {
                continue;
            };
            if value.as_bool() != Some(true) {
                changes.push(format!(
                    "{at}.{PRIVATE_REACH_KEY}: removed (it was not `true`, so it admitted nothing; \
                     1.6.0 refuses the key)"
                ));
                continue;
            }
            let urls: Vec<(String, bool)> = PRIVATE_REACH_URLS
                .iter()
                .filter_map(|path| {
                    let mut at: &Value = entry.get(Value::from(path[0]))?;
                    for key in &path[1..] {
                        at = at.get(*key)?;
                    }
                    at.as_str()
                        .map(|u| (u.to_owned(), busbar_contract::net::scheme_is(u, "http")))
                })
                .collect();
            if urls.is_empty() {
                changes.push(format!(
                    "{at}.{PRIVATE_REACH_KEY}: removed; the registration names no URL it dials, so \
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
        if plaintext {
            warnings.push(format!(
                "{at}: `{url}` is plaintext http://, which `{PRIVATE_REACH_KEY}: true` also let the \
                 registration use; the scheme a destination may use is now decided by the one \
                 destination guard for every connection. Serve it over https://, or check \
                 docs/configuration.md#advanced for whether plaintext to this host is admitted"
            ));
        }
    }
}

/// List exactly the host `url` names in `advanced.allow_destinations` for the registration at `at`.
fn allow_registration_host(
    root: &mut Mapping,
    at: &str,
    url: &str,
    changes: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    use busbar_contract::net::{host_is_cloud_metadata, is_alternate_ipv4_encoding, judged_host};
    let host = busbar_contract::net::target_host(url)
        .and_then(|h| judged_host(&h).ok())
        .filter(|h| !h.is_empty());
    let Some(host) = host else {
        warnings.push(format!(
            "{at}.{PRIVATE_REACH_KEY}: removed; its URL names no host the destination guard can \
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
            "{at}.{PRIVATE_REACH_KEY}: removed; '{host}' was not added to \
             advanced.allow_destinations: a cloud-metadata host or an alternate IPv4 spelling is \
             refused whatever the list says (it was refused under `{PRIVATE_REACH_KEY}` too)"
        ));
        return;
    }
    if crate::config::migrate_plugins::already_allowed(root, &host) {
        changes.push(format!(
            "{at}.{PRIVATE_REACH_KEY}: removed; '{host}' is already listed in \
             advanced.allow_destinations, which now governs it"
        ));
        return;
    }
    match crate::config::migrate_plugins::push_allowed(root, at, &host) {
        Ok(_) => changes.push(format!(
            "{at}.{PRIVATE_REACH_KEY}: replaced by advanced.allow_destinations: '{host}' (one \
             setting governs every outbound connection in 1.6.0; exactly this host is allowed, \
             not every private address)"
        )),
        Err(todo) => warnings.push(todo),
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
