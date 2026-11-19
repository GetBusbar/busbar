// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RETIRED CARRIERS IN SETTINGS (owner decision 16): a top-level `transport:` entry that names the module
//! `tcp` or `stdio` is ACCEPTED AND IGNORED. Busbar 1.6.0 itself listens on and dials every TCP socket and runs
//! and frames `transport: stdio` child-process servers, so the two carrier plugins (`busbar-transport-tcp`,
//! `busbar-transport-stdio`) are gone and an entry that configured one configures nothing. Old settings are
//! migrated, never refused: the entry is removed with one report line per carrier, and the section goes with
//! its last entry.
//!
//! Two places meet here. 1a ([`crate::legacy_markers::refuse`]) refuses an unstamped config that holds a
//! `transport:` section, because no 1.5.5 config could: a section that names ONLY retired carriers is not that
//! case ([`only_retired`]) and passes. 1d ([`crate::migrate_1_6::run`]) then removes the entries
//! ([`drop_retired`]). A section that names any living transport is left whole for 1a to judge as before.
//!
//! The engine's boot has the same rule for an image of either plugin left in the plugins directory
//! (`busbar` `root/retired_carriers.rs`): the two modules share the spellings, and neither reads any other
//! plugin's name.

use busbar_contract::yaml::{MappingExt, Pairs, Value, ValueExt};

use crate::migrate_1_6::remove_kept;

/// The section a transport instance was configured under.
const SECTION: &str = "transport";

/// The two retired carrier plugins. Every `module:` word that named one is spelled from its plugin name: the
/// whole name, the name without `busbar-`, or the bare carrier word after `busbar-transport-`.
const PLUGINS: [&str; 2] = ["busbar-transport-tcp", "busbar-transport-stdio"];

/// The retired plugin a `module:` word names; `None` for every other word.
fn retired(module: &str) -> Option<&'static str> {
    PLUGINS.iter().copied().find(|plugin| {
        let short = plugin.strip_prefix("busbar-").unwrap_or(plugin);
        let bare = short.strip_prefix("transport-").unwrap_or(short);
        [*plugin, short, bare].contains(&module)
    })
}

/// The retired plugin one `transport:` entry names: its `module:` (the map form), or the bare word (the short
/// form `name: tcp`). An entry with no module word, or with any other, names none.
fn carrier(entry: &Value) -> Option<&'static str> {
    let module = match entry.as_mapping() {
        Some(settings) => settings
            .get_key("module")
            .and_then(|module| module.as_str()),
        None => entry.as_str(),
    }?;
    retired(module)
}

/// Whether `doc` holds a `transport:` section whose every entry names a retired carrier (at least one entry).
/// Such a section is what decision 16 accepts; an empty one, one that is not a mapping, or one with any other
/// entry is not.
pub(crate) fn only_retired(doc: &Value) -> bool {
    doc.at(SECTION).as_mapping().is_some_and(|entries| {
        entries.iter().next().is_some() && entries.iter().all(|(_, entry)| carrier(entry).is_some())
    })
}

/// The line the boot reports for one removed entry's carrier.
fn line(plugin: &str, instance: &str) -> String {
    let serves = if plugin == "busbar-transport-stdio" {
        "Busbar itself now runs and frames `transport: stdio` child-process servers; a line may be at most \
         4 MiB (the plugin's line limit setting is no longer read)"
    } else {
        "Busbar itself now listens on and dials every TCP socket"
    };
    format!(
        "transport.{instance} removed: the `{plugin}` plugin is retired in 1.6.0 and its settings are \
         accepted and ignored. {serves}."
    )
}

/// 1d: remove every `transport:` entry that names a retired carrier, deciding on the interpolated document
/// and editing the template tree (the patch writer keeps the order of what is left). One report line per
/// carrier, naming the first instance that held it; the section is removed with its last entry.
pub(crate) fn drop_retired(root: &mut Pairs, resolved: &Value, report: &mut Vec<String>) {
    let Some(entries) = resolved.at(SECTION).as_mapping() else {
        return;
    };
    let named: Vec<(&str, &'static str)> = entries
        .iter()
        .filter_map(|(instance, entry)| Some((instance.as_str()?, carrier(entry)?)))
        .collect();
    if named.is_empty() {
        return;
    }
    let Some(Value::Map(section)) = root.get_key_mut(SECTION) else {
        return;
    };
    let mut told: Vec<&'static str> = Vec::new();
    for (instance, plugin) in named {
        if remove_kept(section, instance).is_some() && !told.contains(&plugin) {
            told.push(plugin);
            report.push(line(plugin, instance));
        }
    }
    let emptied = section.iter().next().is_none();
    if emptied {
        remove_kept(root, SECTION);
    }
}

#[cfg(test)]
#[path = "tests/retired_carriers_tests.rs"]
mod tests;
