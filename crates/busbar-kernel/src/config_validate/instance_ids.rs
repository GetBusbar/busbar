// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 §5.3 (C4): instance ids are unique across the deployment. `/records`, `/usage`,
//! `/metrics` labels and `/audit` key on `instance` alone, so no two configured instances may share
//! an id, whatever their kind, and the core instance ids are reserved.
//!
//! The sections are the kinds' own config roots ([`busbar_contract::plugin::Kind::root`]): core
//! reads no plugin name here, only the operator's instance names.

use busbar_contract::plugin::Kind;

use crate::config::RootCfg;

/// The core instances (§5.7): core's own subsystems, served through `/kinds/core/instances`.
/// Their ids are reserved.
pub const CORE_INSTANCES: [&str; 9] = [
    "process",
    "routing",
    "units",
    "limits",
    "ledger",
    "credentials",
    "durability",
    "connector",
    "trust",
];

/// Every collision and reserved id in `cfg`, one message per finding, in section order.
#[must_use]
pub fn instance_id_collisions(cfg: &RootCfg) -> Vec<String> {
    let mut sections: Vec<(&'static str, Vec<&str>)> = Vec::new();
    let mut named = |kind: Kind, names: Vec<&str>| sections.push((kind.root(), names));
    named(
        Kind::Auth,
        cfg.identity_providers.keys().map(String::as_str).collect(),
    );
    named(
        Kind::Export,
        cfg.export_defs.keys().map(String::as_str).collect(),
    );
    named(Kind::Hook, ordered(cfg.hooks.keys()));
    named(
        Kind::Secret,
        cfg.secrets.keys().map(String::as_str).collect(),
    );
    named(Kind::Transport, ordered(cfg.providers.keys()));

    let mut seen: std::collections::BTreeMap<&str, String> = std::collections::BTreeMap::new();
    let mut errors = Vec::new();
    for (section, names) in sections {
        for id in names {
            let position = format!("{section}.{id}");
            if CORE_INSTANCES.contains(&id) {
                errors.push(format!(
                    "instance id \"{id}\" is reserved for the core instance core/{id}; rename \
                     {position}"
                ));
                continue;
            }
            match seen.get(id) {
                Some(first) => errors.push(format!(
                    "instance id \"{id}\" is used by both {first} and {position}; instance ids \
                     are unique across the deployment in 1.6, rename one"
                )),
                None => {
                    seen.insert(id, position);
                }
            }
        }
    }
    errors
}

/// A hash map's names in a stable order, so the findings read the same on every run.
fn ordered<'a>(names: impl Iterator<Item = &'a String>) -> Vec<&'a str> {
    names
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}
