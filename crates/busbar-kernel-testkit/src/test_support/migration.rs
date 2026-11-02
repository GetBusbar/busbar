// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::config::migration_table::Rows;
use serde_yaml::Value;

pub fn rows() -> Rows {
    static OWNED: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();
    static ROWS: std::sync::OnceLock<Vec<(&'static str, &'static str)>> =
        std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        OWNED
            .get_or_init(|| {
                let doc: Value = serde_yaml::from_str(include_str!(
                    "../../tests/fixtures/frozen_customer_text.yaml"
                ))
                .expect("the frozen-text fixture parses");
                doc.get("migration_rows")
                    .and_then(Value::as_mapping)
                    .expect("the frozen-text fixture carries `migration_rows`")
                    .iter()
                    .filter_map(|(key, value)| {
                        Some((key.as_str()?.to_owned(), value.as_str()?.to_owned()))
                    })
                    .collect()
            })
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    })
}

pub fn install() {
    busbar_kernel::config::migration_table::install(rows());
}
