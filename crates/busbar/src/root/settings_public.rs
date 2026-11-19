// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeSet;

/// One plugin's public settings, by the words it answers to.
#[derive(Debug, Clone)]
struct Row {
    words: Vec<String>,
    public: BTreeSet<String>,
}

/// The table the kernel reads: the rows of the admitted native images (their describe's D_SCHEMA,
/// `Images::public_settings`), joined once the boot's images are admitted ([`install_native`]; nothing
/// reads public settings before that).
#[derive(Debug, Default)]
struct Table {
    native: std::sync::OnceLock<Vec<Row>>,
}

impl busbar_kernel::config::settings_public::PublicSettings for Table {
    fn public(&self, module: &str) -> BTreeSet<String> {
        self.native
            .get()
            .into_iter()
            .flatten()
            .find(|r| r.words.iter().any(|w| w == module))
            .map(|r| r.public.clone())
            .unwrap_or_default()
    }
}

/// Install the process's one table before any configuration is read; the native images' rows join
/// it once they are admitted.
pub fn install() {
    let _ = install_table();
}

/// The process's one installed table, so the admitted native images' rows join it.
static INSTALLED: std::sync::OnceLock<&'static Table> = std::sync::OnceLock::new();

fn install_table() -> &'static Table {
    let table: &'static Table = INSTALLED.get_or_init(|| Box::leak(Box::new(Table::default())));
    busbar_kernel::config::settings_public::install(table);
    table
}

/// The public-settings rows of the admitted native images: each image's D_SCHEMA `x-busbar-public` settings,
/// under its identity and former names (`Images::public_settings`).
fn native_rows(images: &busbar_plugin_loader::instance::Images) -> Result<Vec<Row>, String> {
    let mut rows = Vec::new();
    for identity in images.identities() {
        if let Some(settings) = images.public_settings(identity, &[])? {
            rows.push(Row {
                words: settings.words,
                public: settings.public,
            });
        }
    }
    Ok(rows)
}

/// Join the admitted native images' rows to the installed table (once per process: the first boot's images).
pub(crate) fn install_native(
    images: &busbar_plugin_loader::instance::Images,
) -> Result<(), String> {
    let rows = native_rows(images)?;
    let table = match INSTALLED.get() {
        Some(table) => *table,
        None => install_table(),
    };
    let _ = table.native.set(rows);
    Ok(())
}

#[cfg(test)]
#[path = "tests/settings_public.rs"]
mod tests;
