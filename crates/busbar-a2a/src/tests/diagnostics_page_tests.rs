// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The A2A plane's committed diagnostics pages: the markdown and JSON snapshots of the plane's own
//! page equal a fresh render by the host's renderers. The catalog itself and its invariants live in
//! `busbar-plane-a2a` (`src/diagnostics.rs`); these two tests stay with this crate because the
//! renderers are the host's.

use busbar_contract::diagnostic::Diagnostic;
use busbar_kernel::diagnostics::{render_json_for, render_markdown_for};
use busbar_plane_a2a::diagnostics::DIAGNOSTICS;

/// Committed per-plane markdown snapshot (relative to this crate's manifest dir).
const COMMITTED_MD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics-a2a.md");
/// Committed per-plane machine-readable snapshot.
const COMMITTED_JSON: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/diagnostics-a2a.json"
);

/// THIS PLANE'S OWN PAGE: every code of [`DIAGNOSTICS`] except those the HOST page publishes — the
/// codes the plane took out of the host registry together with the code that emits them (#83a O4),
/// whose page and number are frozen there. One code, one page: the composition root's docs gate
/// renders the host page's share from the same constants.
fn own_page() -> Vec<&'static Diagnostic> {
    let host = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics.json");
    let text = std::fs::read_to_string(host).expect("docs/diagnostics.json is readable");
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(&text).expect("docs/diagnostics.json is a JSON array");
    DIAGNOSTICS
        .iter()
        .copied()
        .filter(|d| !entries.iter().any(|e| e["number"] == u64::from(d.code)))
        .collect()
}

/// The committed per-plane docs equal a fresh render of this plane's own page ([`own_page`]).
/// Regenerate after any catalog change with:
///   `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-a2a diagnostics`
#[test]
fn committed_markdown_matches_diagnostics() {
    let fresh = render_markdown_for(&own_page());
    if std::env::var("UPDATE_DIAGNOSTICS").is_ok_and(|v| v == "1") {
        std::fs::write(COMMITTED_MD, &fresh)
            .unwrap_or_else(|e| panic!("write {COMMITTED_MD}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(COMMITTED_MD).unwrap_or_else(|e| {
        panic!("read {COMMITTED_MD}: {e} — generate it with UPDATE_DIAGNOSTICS=1")
    });
    assert_eq!(
        committed, fresh,
        "per-plane diagnostics markdown is stale — regenerate with \
             `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-a2a diagnostics`"
    );
}

#[test]
fn committed_json_matches_diagnostics() {
    let fresh = render_json_for(&own_page());
    if std::env::var("UPDATE_DIAGNOSTICS").is_ok_and(|v| v == "1") {
        std::fs::write(COMMITTED_JSON, &fresh)
            .unwrap_or_else(|e| panic!("write {COMMITTED_JSON}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(COMMITTED_JSON).unwrap_or_else(|e| {
        panic!("read {COMMITTED_JSON}: {e} — generate it with UPDATE_DIAGNOSTICS=1")
    });
    assert_eq!(
        committed, fresh,
        "per-plane diagnostics json is stale — regenerate with UPDATE_DIAGNOSTICS=1"
    );
}
