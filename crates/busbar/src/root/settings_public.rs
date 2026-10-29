// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTINGS EACH PLUGIN DECLARES PUBLIC, handed to the kernel
//! (`busbar_kernel::config::settings_public`) before the first configuration is read: every
//! loadable plugin's settings schema, linked or dropped in, read by the loader
//! (`boot::public_settings`), under every word a `module:` may name it by. Every setting a schema
//! does not declare `x-busbar-public` is sensitive.

use std::collections::BTreeSet;

use busbar_contract::abi::mechanism::door::DoorFn;

use super::linked::Linked;
use super::loader::boot::public_settings;
use super::loader::PluginRegistry;

/// One plugin's public settings, by the words it answers to.
#[derive(Debug, Clone)]
struct Row {
    words: Vec<String>,
    public: BTreeSet<String>,
}

/// The table the kernel reads.
#[derive(Debug, Default)]
struct Table(Vec<Row>);

impl busbar_kernel::config::settings_public::PublicSettings for Table {
    fn public(&self, module: &str) -> BTreeSet<String> {
        self.0
            .iter()
            .find(|r| r.words.iter().any(|w| w == module))
            .map(|r| r.public.clone())
            .unwrap_or_default()
    }
}

/// Every row `linked` and `dropped` declare, each plugin once (a linked row first).
///
/// # Errors
/// A settings schema the pack rules refuse, naming the plugin.
fn table(linked: &Linked, dropped: Option<&PluginRegistry>) -> Result<Table, String> {
    let mut doors: Vec<(DoorFn, Vec<&str>)> = Vec::new();
    doors.extend(linked.secrets.iter().map(|d| (*d, Vec::new())));
    doors.extend(linked.hook_doors.iter().map(|d| (*d, Vec::new())));
    doors.extend(
        linked
            .export_doors
            .iter()
            .map(|e| (e.door, vec![e.name, e.alias])),
    );
    doors.extend(
        linked
            .stores
            .iter()
            .map(|(key, _, door, canonical)| (*door, vec![*key, *canonical])),
    );
    doors.extend(
        linked
            .auths
            .iter()
            .map(|(key, canonical, door)| (*door, vec![*key, *canonical])),
    );
    let mut rows = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (door, words) in doors {
        let Ok(stated) = super::loader::dispatch::rendering_of(door) else {
            continue;
        };
        if let Some(r) = public_settings(&stated, &words)? {
            if seen.insert(r.name.clone()) {
                rows.push(Row {
                    words: r.words,
                    public: r.public,
                });
            }
        }
    }
    if let Some(registry) = dropped {
        for c in super::boot::discover(registry)? {
            let words: Vec<&str> = c.aliases.iter().map(String::as_str).collect();
            if let Some(r) = public_settings(&c.stated, &words)? {
                if seen.insert(r.name.clone()) {
                    rows.push(Row {
                        words: r.words,
                        public: r.public,
                    });
                }
            }
        }
    }
    Ok(Table(rows))
}

/// Hand the kernel the public settings of every plugin `linked` and `dropped` hold. A plugin whose
/// settings schema the pack rules refuse (a credential declared public) refuses the boot (exit 2),
/// naming it.
pub fn install(linked: &Linked, dropped: Option<&'static PluginRegistry>) {
    match table(linked, dropped) {
        Ok(t) => busbar_kernel::config::settings_public::install(Box::leak(Box::new(t))),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
#[path = "tests/settings_public.rs"]
mod tests;
