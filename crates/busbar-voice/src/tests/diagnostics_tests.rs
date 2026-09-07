// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-voice/src/diagnostics.rs`.

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
        assert!(seen.insert(d.slug), "duplicate slug {:?}", d.slug);
        assert!(!d.slug.is_empty(), "{} has an empty slug", d.banner());
        assert!(
            d.slug
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "slug {:?} is not kebab-case",
            d.slug
        );
        assert!(
            !d.slug.starts_with('-') && !d.slug.ends_with('-') && !d.slug.contains("--"),
            "slug {:?} has a leading/trailing/double hyphen",
            d.slug
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
        assert!(d.summary.len() > 20, "{} has no real summary", d.banner());
        assert!(d.action.len() > 3, "{} has no action", d.banner());
    }
}
