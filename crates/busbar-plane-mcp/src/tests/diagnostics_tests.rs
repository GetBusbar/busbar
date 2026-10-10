// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-plane diagnostics-catalog invariants for the MCP plane: code/slug uniqueness, the
//! class↔code thousands-digit contract, and the live-entry documentation floor. The committed
//! markdown/JSON snapshot tests render through the host's renderers, which this crate does not
//! link, so they run where those renderers are linked.

use super::*;

/// THE CATALOG IS NOT EMPTY, AND NOT ENTIRELY RETIRED.
///
/// Every other test in this file is a `for d in DIAGNOSTICS` loop whose assertions live INSIDE the
/// loop, and `every_live_entry_documents_meaning_and_action` additionally `continue`s past every
/// retired entry. A catalog that regressed to empty — a bad `cfg` gate, a botched merge — would
/// therefore make all four of them pass green while every documented diagnostic silently
/// disappeared. This is the floor that makes those loops mean something.
#[test]
fn the_catalog_is_not_empty() {
    assert!(
        !DIAGNOSTICS.is_empty(),
        "the diagnostics catalog is empty, which makes every loop test in this file vacuous"
    );
    assert!(
        DIAGNOSTICS.iter().any(|d| !d.retired),
        "the catalog holds nothing but retired entries, which makes \
         `every_live_entry_documents_meaning_and_action` vacuous"
    );
}

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

/// THE PLANE'S `declares.json` IS ITS CATALOG: the static declared metadata the root reads for this
/// linked plugin (its `declares` section: every code this plane raises) states exactly the entries
/// [`DIAGNOSTICS`] holds, field for field, so the two cannot drift — and the plane's breaker fact.
#[test]
fn the_declares_file_states_the_catalog() {
    let declared: serde_json::Value =
        serde_json::from_str(crate::DECLARES).expect("declares.json is JSON");
    let want: Vec<serde_json::Value> = DIAGNOSTICS
        .iter()
        .map(|d| {
            serde_json::json!({
                "code": d.code,
                "slug": d.slug,
                "title": d.title,
                "severity": d.severity.as_str(),
                "summary": d.summary,
                "action": d.action,
                "since": d.since,
            })
        })
        .collect();
    // Beside the catalog, the plane's one breaker fact (ARCHITECT Q4): a transient failure below
    // the trip threshold never benches a member (the 1.5.5 MCP client leg's posture).
    let whole = serde_json::json!({
        "breaker": { "bench_below_trip_threshold": false },
        "diagnostics": want,
    });
    assert_eq!(
        declared,
        whole,
        "declares.json drifted from the catalog; expected:\n{}",
        serde_json::to_string_pretty(&whole).unwrap()
    );
}
