// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/config/overlay.rs`.

use super::*;

/// An overlay from a NEWER busbar is refused, both for reading and for writing. It is intact and
/// meaningful — unlike a corrupt one — so ignoring it would run with the operator's
/// API-registered hooks and groups silently absent, security gates included. 1.5.0 is the first
/// release that can refuse one at all: a binary without this check never will, whatever version
/// a future overlay stamps.
#[test]
fn an_overlay_from_a_newer_busbar_is_refused_not_ignored() {
    let dir = std::env::temp_dir().join(format!("busbar-overlay-vgate-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("overlay.json");
    std::fs::write(
        &path,
        serde_json::json!({
            "version": OVERLAY_VERSION + 1,
            "hooks": { "gate": { "kind": "gate", "module": "x" } }
        })
        .to_string(),
    )
    .unwrap();

    assert!(
        matches!(read_state(&path), OverlayReadState::VersionTooNew(v) if v == OVERLAY_VERSION + 1),
        "a newer overlay is classified distinctly from corrupt"
    );
    assert!(
        read(&path).is_none(),
        "and is not merged onto the resolved config"
    );
    assert!(
        load_for_rmw(&path).is_none(),
        "and is never overwritten — a write would discard what this binary cannot represent"
    );

    // The current version still loads, so the gate is a ceiling and not a wall.
    std::fs::write(
        &path,
        serde_json::json!({ "version": OVERLAY_VERSION, "hooks": {} }).to_string(),
    )
    .unwrap();
    assert!(read(&path).is_some(), "the understood version still loads");

    let _ = std::fs::remove_dir_all(&dir);
}
