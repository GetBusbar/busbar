// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fleet manifest checks (red-proof stub: every body is `todo!()`).

use std::collections::BTreeSet;
use std::path::Path;

use super::Outcome;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub repo: String,
    pub alias: Option<String>,
    pub manifest_name: Option<String>,
    pub former_names: Vec<String>,
}

#[derive(Debug, Default)]
pub(crate) struct Registry {
    pub entries: Vec<Entry>,
    pub excluded: Vec<String>,
    pub archived: Vec<String>,
}

pub(crate) fn parse_registry(_text: &str) -> Registry {
    todo!("W1-X1")
}
pub(crate) fn fleet_findings(_deps_toml: &str, _plugins_yaml: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn plugin_words(_plugins_yaml: &str, _extra: &str) -> BTreeSet<String> {
    todo!("W1-X1")
}
pub(crate) fn alias_findings(_plugins_yaml: &str, _headers: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn fleet_manifest(_root: &Path) -> Outcome {
    todo!("W1-X1")
}
pub(crate) fn c_alias(_root: &Path, _args: &[String]) -> Outcome {
    todo!("W1-X1")
}
