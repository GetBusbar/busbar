// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub use busbar_kernel::config::declared_vocabulary::{install, rows, text, Rows};
use serde_yaml::{Mapping, Value};

pub fn pairs(key: &str) -> Vec<(&'static str, &'static str)> {
    text(key)
        .split(" | ")
        .filter_map(|pair| pair.split_once(':'))
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

pub fn former_names(alias: &str) -> Vec<String> {
    text(&["former.", alias].concat())
        .split_whitespace()
        .map(str::to_string)
        .collect()
}
