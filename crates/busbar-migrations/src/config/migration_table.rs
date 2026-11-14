// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::yaml::prelude::*;
pub use busbar_kernel::config::declared_vocabulary::{install, rows, text, Rows};

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
