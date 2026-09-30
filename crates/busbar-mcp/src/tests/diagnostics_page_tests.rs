// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The MCP plane's committed diagnostics pages: the markdown and JSON snapshots of the plane's page
//! equal a fresh render by the host's renderers. The catalog itself and its invariants live in
//! `busbar-plane-mcp` (`src/diagnostics.rs`); these two tests stay with this crate because the
//! renderers are the host's.

use busbar_kernel::diagnostics::{render_json_for, render_markdown_for};
use busbar_plane_mcp::diagnostics::DIAGNOSTICS;

/// Committed per-plane markdown snapshot (relative to this crate's manifest dir).
const COMMITTED_MD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics-mcp.md");
/// Committed per-plane machine-readable snapshot.
const COMMITTED_JSON: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/diagnostics-mcp.json"
);

/// The committed per-plane docs equal a fresh render of this plane's `DIAGNOSTICS`. Regenerate
/// after any catalog change with:
///   `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-mcp diagnostics`
#[test]
fn committed_markdown_matches_diagnostics() {
    let fresh = render_markdown_for(DIAGNOSTICS);
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
             `UPDATE_DIAGNOSTICS=1 cargo test -p busbar-mcp diagnostics`"
    );
}

#[test]
fn committed_json_matches_diagnostics() {
    let fresh = render_json_for(DIAGNOSTICS);
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
