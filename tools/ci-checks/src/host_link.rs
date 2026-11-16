// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-NO-HOST-LINK (red-proof stub).

use std::path::Path;

use super::Outcome;

pub(crate) fn banned_symbol(_name: &str) -> bool {
    todo!("W1-X1")
}
pub(crate) fn scan_object(_bytes: &[u8]) -> Result<Vec<String>, String> {
    todo!("W1-X1")
}
pub(crate) fn graph_findings(_package: &str, _tree: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn run_cargo(_dir: &Path, _args: &[&str]) -> Result<String, String> {
    todo!("W1-X1")
}
pub(crate) fn cdylib_packages(_metadata: &serde_json::Value) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn no_host_link(_args: &[String]) -> Outcome {
    todo!("W1-X1")
}
