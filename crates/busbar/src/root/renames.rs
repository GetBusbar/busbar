// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGINS' SETTING RENAMES, handed to the kernel (`busbar_kernel::config::plugin_renames`)
//! before the first configuration is read: every rename each loadable plugin's Statement declares
//! (`REWRITE_RENAMED`, with its `REWRITE_RENAMED_SINCE`), linked or dropped in, under every word a
//! `module:` may name it by (its Statement name, its aliases, its linked row's key).

use std::collections::BTreeSet;

use busbar_contract::abi::mechanism::door::{renamed_settings, DoorFn, REWRITE_ALIAS};
use busbar_contract::abi::mechanism::rendering::{read, Read};
use busbar_contract::plugin::Kind;
use busbar_kernel::config::plugin_renames::{SettingRename, SettingRenames};

use super::linked::Linked;
use super::loader::boot::kind_of;
use super::loader::PluginRegistry;

/// One plugin's renames, by kind and the words it answers to.
#[derive(Debug, Clone)]
struct Row {
    /// The plugin's Statement name: each plugin is read once.
    name: String,
    kind: Kind,
    words: Vec<String>,
    renames: Vec<SettingRename>,
}

/// The table the kernel reads.
#[derive(Debug, Default)]
struct Table(Vec<Row>);

impl SettingRenames for Table {
    fn renames(&self, kind: Kind, module: &str) -> Vec<SettingRename> {
        self.0
            .iter()
            .find(|r| r.kind == kind && r.words.iter().any(|w| w == module))
            .map(|r| r.renames.clone())
            .unwrap_or_default()
    }
}

/// The row `stated` (a Statement rendering) declares, answering also to `words`; `None` when it
/// renames nothing.
///
/// # Errors
/// A rendering that does not read back, or a rename declaration [`renamed_settings`] refuses,
/// naming the plugin.
fn row(stated: &[u8], words: &[&str]) -> Result<Option<Row>, String> {
    let r: Read = read(stated)
        .map_err(|e| format!("a Statement rendering does not read back at byte {}", e.at))?;
    let renames = renamed_settings(&r.rewrites)
        .map_err(|e| format!("plugin '{}' declares a settings rename badly: {e}", r.name))?;
    if renames.is_empty() {
        return Ok(None);
    }
    let Some(code) = busbar_contract::abi::mechanism::KindCode::from_raw(r.kind) else {
        return Ok(None);
    };
    let mut answers: Vec<String> = std::iter::once(r.name.clone())
        .chain(
            r.rewrites
                .iter()
                .filter(|(class, _, _)| *class == REWRITE_ALIAS)
                .map(|(_, from, _)| from.clone()),
        )
        .chain(words.iter().map(|w| (*w).to_string()))
        .collect();
    answers.sort();
    answers.dedup();
    Ok(Some(Row {
        name: r.name.clone(),
        kind: kind_of(code),
        words: answers,
        renames: renames
            .into_iter()
            .map(|(from, to, since)| SettingRename { from, to, since })
            .collect(),
    }))
}

/// Every row `linked` and `dropped` declare, each plugin once (a linked row first).
///
/// # Errors
/// As [`row`].
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
        if let Some(r) = row(&stated, &words)? {
            if seen.insert(r.name.clone()) {
                rows.push(r);
            }
        }
    }
    if let Some(registry) = dropped {
        for c in super::boot::discover(registry)? {
            let words: Vec<&str> = c.aliases.iter().map(String::as_str).collect();
            if let Some(r) = row(&c.stated, &words)? {
                if seen.insert(r.name.clone()) {
                    rows.push(r);
                }
            }
        }
    }
    Ok(Table(rows))
}

/// Hand the kernel the renames of every plugin `linked` and `dropped` hold. A plugin that declares
/// a rename badly refuses the boot (exit 2), naming it, as a plugin claiming another's sugar does.
pub fn install(linked: &Linked, dropped: Option<&'static PluginRegistry>) {
    match table(linked, dropped) {
        Ok(t) => busbar_kernel::config::plugin_renames::install(Box::leak(Box::new(t))),
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
#[path = "tests/renames.rs"]
mod tests;
