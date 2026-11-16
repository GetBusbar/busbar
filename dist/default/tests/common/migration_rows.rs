// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The 1.5.5 migration engine (`busbar-migrations`, deleted whole at C3) as a library. `--migrate-config`
//! is gone from the binary (MIGRATE-ON-BOOT C1), so the tests that still pin what the engine produces
//! call it here, with the frozen customer rows the engine's own tests install.

use busbar_contract::yaml::{Value, ValueExt};

/// Hand the engine the frozen customer migration rows, once per process.
pub fn install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let frozen: Value = busbar_contract::yaml::from_str(include_str!(
            "../../../../crates/busbar-kernel/src/tests/fixtures/frozen_customer_text.yaml"
        ))
        .expect("the frozen customer migration rows parse");
        let rows: Vec<(&'static str, &'static str)> = frozen
            .get("migration_rows")
            .and_then(Value::as_mapping)
            .expect("the frozen migration rows are a map")
            .iter()
            .map(|(key, value)| {
                let key = key.as_str().expect("a migration row name").to_owned();
                let value = value.as_str().expect("a migration row value").to_owned();
                (
                    &*Box::leak(key.into_boxed_str()),
                    &*Box::leak(value.into_boxed_str()),
                )
            })
            .collect();
        busbar_migrations::config::migration_table::install(Box::leak(rows.into_boxed_slice()));
    });
}

/// The migrated YAML and the change/warning/decision summary the retired command printed to stderr.
pub fn migrate(raw: &str) -> (String, String) {
    install();
    let out = busbar_migrations::config::migrate::migrate_config(raw).expect("the config migrates");
    let mut summary = String::new();
    for change in &out.changes {
        summary.push_str(&format!("  - {change}\n"));
    }
    for warning in &out.warnings {
        summary.push_str(&format!("  ! {warning}\n"));
    }
    for todo in &out.todos {
        summary.push_str(&format!("  * {todo}\n"));
    }
    (out.yaml, summary)
}
