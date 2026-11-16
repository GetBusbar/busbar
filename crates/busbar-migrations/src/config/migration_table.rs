// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::yaml::prelude::*;

/// A table of migration rows: (key, text).
pub type Rows = &'static [(&'static str, &'static str)];

static ROWS: std::sync::OnceLock<Rows> = std::sync::OnceLock::new();

/// Hand the engine its rows; the first call wins. The root carries no table (MIGRATE-ON-BOOT C1), so a
/// caller that drives this engine installs its own.
pub fn install(rows: Rows) {
    let _ = ROWS.set(rows);
}

fn installed() -> Rows {
    ROWS.get().copied().unwrap_or(&[])
}

/// The installed migration rows. A test build has no root to hand them in, so it stands in the
/// frozen rows the kernel tests pin (the same rows plugins.yaml renders into the root manifest).
pub fn rows() -> Rows {
    #[cfg(test)]
    install_frozen_rows();
    installed()
}

/// One installed migration row's text; empty when the table has no such row.
pub fn text(key: &str) -> &'static str {
    #[cfg(test)]
    install_frozen_rows();
    installed()
        .iter()
        .find(|(k, _)| *k == key)
        .map_or("", |(_, v)| v)
}

#[cfg(test)]
fn install_frozen_rows() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let frozen: Value = busbar_contract::yaml::from_str(include_str!(
            "../../../busbar-kernel/src/tests/fixtures/frozen_customer_text.yaml"
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
        install(Box::leak(rows.into_boxed_slice()));
    });
}

pub fn pairs(key: &str) -> Vec<(&'static str, &'static str)> {
    text(key)
        .split(" | ")
        .filter_map(|pair| pair.split_once(':'))
        .collect()
}

pub fn rewrite_retired(
    kind_root: &str,
    section: &mut Pairs,
    apply: bool,
) -> Option<(String, &'static str)> {
    let old = section
        .get_key("module")
        .and_then(Value::as_str)?
        .to_string();
    let key = ["retired.", kind_root, ".", &old].concat();
    let alias = text(&key);
    if alias.is_empty() {
        return None;
    }
    if apply {
        section.insert_key("module", alias.into());
    }
    Some((old, alias))
}

pub fn former_names(alias: &str) -> Vec<String> {
    text(&["former.", alias].concat())
        .split_whitespace()
        .map(str::to_string)
        .collect()
}
