// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-plane diagnostics-catalog invariants for the MCP plane: code/slug uniqueness, the\n//! class↔code thousands-digit contract, and equality of the committed markdown/JSON snapshots with a\n//! fresh render. Relocated out of `diagnostics.rs` per the tests-in-their-own-file convention.

use super::*;
use busbar_substrate::diagnostics::{render_json_for, render_markdown_for};

/// Committed per-plane markdown snapshot (relative to this crate's manifest dir).
const COMMITTED_MD: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/diagnostics-mcp.md");
/// Committed per-plane machine-readable snapshot.
const COMMITTED_JSON: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/diagnostics-mcp.json"
);

/// Codes are unique within this plane's catalog — a collision would make one un-resolvable.
#[test]
fn codes_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for d in DIAGNOSTICS {
        assert!(
            seen.insert(d.code),
            "duplicate code {} ({})",
            d.code,
            d.slug
        );
    }
}

/// The thousands digit of every code equals its class ordinal, and the x000 slot is reserved.
#[test]
fn code_thousands_digit_matches_class() {
    for d in DIAGNOSTICS {
        assert_eq!(
            d.code / 1000,
            d.class.ordinal(),
            "{} ({}) class/code mismatch",
            d.banner(),
            d.slug
        );
        assert!(
            d.code % 1000 != 0,
            "{} ({}) uses the reserved x000 slot",
            d.banner(),
            d.slug
        );
    }
}

/// Slugs are unique, non-empty, kebab-case — they are stable doc anchors and URL fragments.
#[test]
fn slugs_are_unique_and_kebab_case() {
    let mut seen = std::collections::BTreeSet::new();
    for d in DIAGNOSTICS {
        assert!(
            seen.insert(d.slug),
            "duplicate slug {:?} (code {})",
            d.slug,
            d.code
        );
        assert!(!d.slug.is_empty(), "{} has an empty slug", d.banner());
        assert!(
            d.slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "slug {:?} (code {}) is not kebab-case",
            d.slug,
            d.code
        );
        assert!(
            !d.slug.starts_with('-') && !d.slug.ends_with('-') && !d.slug.contains("--"),
            "slug {:?} (code {}) has a leading/trailing/double hyphen",
            d.slug,
            d.code
        );
    }
}

/// Every non-retired entry documents its meaning and an action.
#[test]
fn every_live_entry_documents_meaning_and_action() {
    for d in DIAGNOSTICS {
        if d.retired {
            continue;
        }
        assert!(
            d.summary.len() > 20,
            "{} ({}) has no real summary",
            d.banner(),
            d.slug
        );
        assert!(
            d.action.len() > 3,
            "{} ({}) has no action",
            d.banner(),
            d.slug
        );
    }
}

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
