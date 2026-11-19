// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cold code of `crate::export_door`.

use std::sync::Arc;

/// Config: an export plugin's check findings did not read.
#[cold]
pub(crate) fn check_findings_unread(e: &serde_json::Error) -> String {
    format!("export plugin check findings are not a JSON list of strings: {e}")
}

/// Config: an export recorder's declaration did not read.
#[cold]
pub(crate) fn recorder_declaration_unread(e: &serde_json::Error) -> String {
    format!("invalid recorder declaration: {e}")
}

/// Boot: an export instance's node id is drawn once, when it opens.
#[cold]
pub(crate) fn node_id() -> [u8; 8] {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    (t ^ (u64::from(std::process::id()) << 40)).to_le_bytes()
}

/// Boot: the export flusher thread did not start.
#[cold]
pub(crate) fn flusher_unstarted(e: &std::io::Error) -> String {
    format!("the export flusher did not start: {e}")
}

/// Config: an export refresh's new settings did not render.
#[cold]
pub(crate) fn refresh_unrendered(error: &serde_json::Error) -> String {
    error.to_string()
}

/// Error: an export that shed lines reports them on its shed series, under its plugin name.
#[cold]
pub(crate) fn fold_shed_lines(observing: &crate::observe::Observing, name: &str, lines: usize) {
    let metrics = crate::observe::shed_series(name)
        .into_iter()
        .map(|n| serde_json::json!({"name": n, "type": "counter", "value": lines}))
        .collect();
    let report = busbar_contract::observe::Envelope {
        result: (),
        metrics,
        diagnostics: Vec::new(),
    };
    let name: Arc<str> = Arc::from(name);
    observing.fold(&name, busbar_contract::kinds::codes::EXPORT, report);
}
