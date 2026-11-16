// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-plugin-repo rules of IF section 15 (red-proof stub).

use proc_macro2::TokenStream;

use super::Outcome;

#[derive(Debug, Clone)]
pub(crate) struct Tok {
    pub line: usize,
    pub text: String,
}

pub(crate) fn flatten(_stream: TokenStream, _out: &mut Vec<Tok>) {
    todo!("W1-X1")
}
pub(crate) fn is_plugin_crate(_name: &str) -> bool {
    todo!("W1-X1")
}
pub(crate) fn dep_findings(_meta: &serde_json::Value, _dev_edges: bool) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn banned_module_path(_relative: &str) -> Option<String> {
    todo!("W1-X1")
}
pub(crate) fn fs_findings(_source: &str, _file: &str, _allowed: bool) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn loopback_findings(_source: &str, _file: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn plugin_rules(_args: &[String]) -> Outcome {
    todo!("W1-X1")
}
