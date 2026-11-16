// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Source checks over core (red-proof stub).

use std::path::Path;

use super::Outcome;

pub(crate) fn transport_findings(_files: &[(String, String)]) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn export_stream_findings(_files: &[(String, String)]) -> Vec<String> {
    todo!("W1-X1")
}
pub(crate) fn licence_rust(_source: &str) -> Result<Vec<(usize, String)>, String> {
    todo!("W1-X1")
}
pub(crate) fn licence_header(_source: &str) -> Vec<(usize, String)> {
    todo!("W1-X1")
}
pub(crate) fn count_lines(_source: &str) -> (usize, usize) {
    todo!("W1-X1")
}
pub(crate) fn c_transport(_root: &Path) -> Outcome {
    todo!("W1-X1")
}
pub(crate) fn export_streams(_root: &Path) -> Outcome {
    todo!("W1-X1")
}
pub(crate) fn no_licence(_root: &Path) -> Outcome {
    todo!("W1-X1")
}
pub(crate) fn loc_report(_root: &Path) -> Outcome {
    todo!("W1-X1")
}
