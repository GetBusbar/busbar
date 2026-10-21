// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROOT LEGACY TABLE (`BUSBAR-1.6.0.md` §2: "Retired names … and migrations for plugins that are
//! not in the build … live in the root legacy table, `[package.metadata.busbar.legacy]`, generated
//! from `plugins.yaml`"). The table in this crate's manifest is the render of `plugins.yaml` (its
//! tests are red on drift) and `build.rs` emits it as [`LEGACY_ROWS`]. The root OWNS it and LENDS
//! it ([`table`]) to every kernel path that reads it — the config load and parse,
//! `--migrate-config`, the registry link and the metrics recorder — and to its own hook and secret
//! rows' former names; no static of the kernel holds it.

include!(concat!(env!("OUT_DIR"), "/legacy.rs"));

/// THE TABLE, LENT: the value the root hands each kernel reader (`busbar_kernel::config::Legacy`).
#[must_use]
pub fn table() -> busbar_kernel::config::Legacy {
    busbar_kernel::config::Legacy::new(LEGACY_ROWS)
}

/// The former names the table gives the plugin config names `alias` by (its `former.<alias>` row):
/// what the root's linked hook and secret rows answer to beside their own names.
pub fn former_names(alias: &str) -> Vec<String> {
    table().former_names(alias)
}

/// The `module:` words of 1.5.5's built-in exporters, in the order 1.5.5 listed them (the table's
/// `export_modules` row): the order the root registers its linked export rows in.
pub fn export_order() -> Vec<&'static str> {
    LEGACY_ROWS
        .iter()
        .find(|(k, _)| *k == "export_modules")
        .map(|(_, v)| v.split(" | ").collect())
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/legacy.rs"]
mod tests;
