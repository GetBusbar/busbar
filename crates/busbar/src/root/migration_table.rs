// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

include!(concat!(env!("OUT_DIR"), "/migration_table.rs"));

pub fn install() {
    busbar_kernel::config::migration_table::install(MIGRATION_ROWS);
}

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
