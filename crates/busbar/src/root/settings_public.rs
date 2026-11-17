// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::admission::Stated;
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

/// The table the kernel reads: ONE table over the rows still read from linked door Statements and the rows of
/// the admitted native images (their describe's D_SCHEMA, `Images::public_settings`), the latter joined once the
/// boot's images are admitted ([`install_native`]; plan b: nothing reads public settings before that).
#[derive(Debug, Default)]
struct Table {
    doors: Vec<Row>,
    native: std::sync::OnceLock<Vec<Row>>,
}

impl Table {
    fn of(doors: Vec<Row>) -> Self {
        Self {
            doors,
            native: std::sync::OnceLock::new(),
        }
    }
}

impl busbar_kernel::config::settings_public::PublicSettings for Table {
    fn public(&self, module: &str) -> BTreeSet<String> {
        self.doors
            .iter()
            .chain(self.native.get().into_iter().flatten())
            .find(|r| r.words.iter().any(|w| w == module))
            .map(|r| r.public.clone())
            .unwrap_or_default()
    }
}

static LINKED_CONFIGURATION: std::sync::OnceLock<Vec<busbar_kernel::admission::Stated>> =
    std::sync::OnceLock::new();

pub(crate) fn linked_configuration() -> Vec<busbar_kernel::admission::Stated> {
    LINKED_CONFIGURATION.get().cloned().unwrap_or_default()
}

fn table(
    linked: &Linked,
    dropped: Option<&PluginRegistry>,
    transports: &[(&str, DoorFn)],
) -> Result<(Table, Vec<Stated>, Vec<Stated>), String> {
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
    doors.extend(linked.plane_doors.iter().map(|door| (*door, Vec::new())));
    doors.extend(transports.iter().map(|(_, door)| (*door, Vec::new())));
    let mut configuration = Vec::new();
    let mut rows = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (door, words) in doors {
        let Ok(stated) = super::loader::dispatch::rendering_of(door) else {
            continue;
        };
        let declaration = super::admission::linked_configuration_from_statement(&stated)?;
        if matches!(declaration.kind.as_str(), "plane" | "transport")
            && !configuration
                .iter()
                .any(|row: &busbar_kernel::admission::Stated| row.name == declaration.name)
        {
            configuration.push(declaration);
        }
        if let Some(r) = public_settings(&stated, &words)? {
            if seen.insert(r.name.clone()) {
                rows.push(Row {
                    words: r.words,
                    public: r.public,
                });
            }
        }
    }
    let mut schema_configuration = configuration.clone();
    if let Some(registry) = dropped {
        for c in super::boot::discover(registry)? {
            schema_configuration.push(super::admission::linked_configuration_from_statement(
                &c.stated,
            )?);
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
    Ok((Table::of(rows), configuration, schema_configuration))
}

pub fn install(linked: &Linked, dropped: Option<&'static PluginRegistry>) {
    install_with_transports(linked, dropped, crate::LINKED_TRANSPORT_DOORS);
}

pub(crate) fn install_with_transports(
    linked: &Linked,
    dropped: Option<&'static PluginRegistry>,
    transports: &[(&str, DoorFn)],
) {
    match table(linked, dropped, transports) {
        Ok((t, configuration, schema_configuration)) => {
            busbar_core_admin::v1::json::install_plane_input_schemas(&schema_configuration);
            let _ = LINKED_CONFIGURATION.set(configuration);
            install_table(t);
        }
        Err(refusal) => {
            eprintln!("busbar: {refusal}");
            crate::root::exit::exit(2);
        }
    }
}

/// The process's one installed table, so the admitted native images' rows join it.
static INSTALLED: std::sync::OnceLock<&'static Table> = std::sync::OnceLock::new();

fn install_table(t: Table) -> &'static Table {
    let table: &'static Table = INSTALLED.get_or_init(|| Box::leak(Box::new(t)));
    busbar_kernel::config::settings_public::install(table);
    table
}

/// The public-settings rows of the admitted native images: each image's D_SCHEMA `x-busbar-public` settings,
/// under its identity and former names (`Images::public_settings`).
fn native_rows(images: &busbar_plugin_loader::instance::Images) -> Result<Vec<Row>, String> {
    let _ = images;
    Ok(Vec::new())
}

/// Join the admitted native images' rows to the installed table (once per process: the first boot's images).
pub(crate) fn install_native(
    images: &busbar_plugin_loader::instance::Images,
) -> Result<(), String> {
    let rows = native_rows(images)?;
    let table = match INSTALLED.get() {
        Some(table) => *table,
        None => install_table(Table::default()),
    };
    let _ = table.native.set(rows);
    Ok(())
}

#[cfg(test)]
#[path = "tests/settings_public.rs"]
mod tests;
