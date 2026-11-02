// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde_yaml::{Mapping, Value};

pub type Rows = &'static [(&'static str, &'static str)];

static ROWS: std::sync::OnceLock<Rows> = std::sync::OnceLock::new();

pub fn install(rows: Rows) {
    let _ = ROWS.set(rows);
}

pub fn rows() -> Rows {
    ROWS.get().copied().unwrap_or(&[])
}

pub fn text(key: &str) -> &'static str {
    rows()
        .iter()
        .find(|(k, _)| *k == key)
        .map_or("", |(_, v)| v)
}

pub fn pairs(key: &str) -> Vec<(&'static str, &'static str)> {
    text(key)
        .split(" | ")
        .filter_map(|pair| pair.split_once(':'))
        .collect()
}

pub fn former_names(alias: &str) -> Vec<String> {
    text(&["former.", alias].concat())
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

pub fn rewrite_retired(
    kind_root: &str,
    section: &mut Mapping,
    apply: bool,
) -> Option<(String, &'static str)> {
    let old = section.get("module").and_then(Value::as_str)?.to_string();
    let key = ["retired.", kind_root, ".", &old].concat();
    let alias = text(&key);
    if alias.is_empty() {
        return None;
    }
    if apply {
        section.insert("module".into(), alias.into());
    }
    Some((old, alias))
}
