// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Supply-chain text checks (red-proof stub).

use std::collections::BTreeMap;
use std::path::Path;

use super::Outcome;

pub(crate) fn template_drift(_template: &str, _plugin: &str, _name: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn patch_entries(_text: &str) -> BTreeMap<String, (String, String)> {
    todo!("W1-X1")
}
pub(crate) fn patch_drift(_core: &str, _plugin: &str, _name: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn core_patch_findings(_core: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn manifest_findings(_repo_root: &Path, _manifest: &Path, _text: &str) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn template_drift_cli(_args: &[String]) -> Outcome {
    todo!("W1-X1")
}
pub(crate) fn patch_drift_cli(_root: &Path, _args: &[String]) -> Outcome {
    todo!("W1-X1")
}
