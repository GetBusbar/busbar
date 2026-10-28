// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT MIGRATION TABLE (`BUSBAR-1.6.0.md` §2): retired names, and migrations for plugins that
//! are not in the build, live in `[package.metadata.busbar.migration]`, generated from
//! `plugins.yaml`. The table in this crate's manifest is the render of `plugins.yaml` (its tests are
//! red on drift) and `build.rs` emits it as [`MIGRATION_ROWS`]; [`install`] hands it to the kernel
//! before any configuration is read, as the operator credential's words are handed in.

include!(concat!(env!("OUT_DIR"), "/migration_table.rs"));

/// Hand the table to the kernel (`busbar_kernel::config::migration_table`). The first install stands.
pub fn install() {
    busbar_kernel::config::migration_table::install(MIGRATION_ROWS);
}

/// The `module:` words of 1.5.5's built-in exporters, in the order 1.5.5 listed them (the table's
/// `export_modules` row): the order the root registers its linked export rows in.
pub fn export_order() -> Vec<&'static str> {
    MIGRATION_ROWS
        .iter()
        .find(|(k, _)| *k == "export_modules")
        .map(|(_, v)| v.split(" | ").collect())
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/migration_table.rs"]
mod tests;
