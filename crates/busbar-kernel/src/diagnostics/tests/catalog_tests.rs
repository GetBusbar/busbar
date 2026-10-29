// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Invariants that keep the host diagnostics registry honest.

use super::*;

/// No two registry entries share a code. A collision would make one code un-resolvable.
#[test]
fn codes_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for d in REGISTRY {
        assert!(
            seen.insert(d.code),
            "duplicate diagnostic code {} ({})",
            d.code,
            d.slug
        );
    }
}

/// The thousands digit of every code equals its class ordinal — the whole point of the scheme.
#[test]
fn code_thousands_digit_matches_class() {
    for d in REGISTRY {
        assert_eq!(
            d.code / 1000,
            d.class.ordinal(),
            "{} ({}) is in class {:?} (ordinal {}) but its code's thousands digit is {}",
            d.banner(),
            d.slug,
            d.class,
            d.class.ordinal(),
            d.code / 1000,
        );
        assert!(
            d.code % 1000 != 0,
            "{} ({}): the x000 slot is reserved for the class itself, not a member",
            d.banner(),
            d.slug
        );
    }
}

/// Slugs are unique, kebab-case, and non-empty — they are stable doc anchors and URL fragments.
#[test]
fn slugs_are_unique_and_kebab_case() {
    let mut seen = std::collections::BTreeSet::new();
    for d in REGISTRY {
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
            "slug {:?} (code {}) is not kebab-case (lowercase/digits/hyphen only)",
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

/// The banner renders zero-padded to four digits: `BUSBAR-1001`, not `BUSBAR-1`.
#[test]
fn banner_is_zero_padded() {
    assert_eq!(
        DURABLE_WRITETHROUGH_BELOW_FLOOR.banner().to_string(),
        "BUSBAR-1001"
    );
    assert_eq!(Banner(42).to_string(), "BUSBAR-0042");
}

/// Every non-retired entry has a summary and an action — an operator who lands here must learn
/// what it means AND what to do.
#[test]
fn every_live_entry_documents_meaning_and_action() {
    for d in REGISTRY {
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
            "{} ({}) has no action (use \"None — self-heals.\" if truly none)",
            d.banner(),
            d.slug
        );
    }
}

/// `Catalogue::by_code` resolves a known code and rejects an unknown one.
#[test]
fn lookup_by_code_works() {
    assert_eq!(
        Catalogue::NEUTRAL.by_code(1001).map(|d| d.slug),
        Some("durable-writethrough-below-floor")
    );
    assert!(Catalogue::NEUTRAL.by_code(9999).is_none());
}

/// 1.5.5 reported an `error_map` value that names no status class with an uncoded warning
/// (v1.5.5 `crates/busbar/src/breaker.rs::warn_unrecognized_error_map_value`), and 1.6.0's only
/// emitter of BUSBAR-3022 was the kernel's wrapper over the deleted normalizer. A code nothing
/// emits and no release ever emitted is not catalogued.
#[test]
fn the_error_map_class_code_no_release_emitted_is_not_catalogued() {
    assert!(
        Catalogue::NEUTRAL.by_code(3022).is_none(),
        "BUSBAR-3022 has no emitter"
    );
    assert!(
        REGISTRY
            .iter()
            .all(|d| d.slug != "config-error-map-class-unrecognized"),
        "config-error-map-class-unrecognized has no emitter"
    );
}

/// D54: the overlay-rejected-at-read diagnostic exists so the one place the parser's message (the
/// offending key + accepted sections) is logged has a stable code. Inert until busbar-core's
/// overlay read path emits it, but it must be registered and resolvable by code.
#[test]
fn config_overlay_rejected_is_registered() {
    assert_eq!(CONFIG_OVERLAY_REJECTED.code, 3023);
    assert_eq!(CONFIG_OVERLAY_REJECTED.severity, Severity::Actionable);
    assert_eq!(
        Catalogue::NEUTRAL.by_code(3023).map(|d| d.slug),
        Some("config-overlay-rejected"),
        "CONFIG_OVERLAY_REJECTED must be in REGISTRY and resolvable by code"
    );
}

// ── THE PUBLISHED PAGE ──────────────────────────────────────────────────────────────────────
//
// docs/diagnostics.{md,json} publish more than this registry: the codes the linked planes took
// with the code that emits them (#83a O4) and the codes the linked first-party plugins declare.
// Only the composition root holds every one of those halves, so the docs-in-sync gate lives there:
// crates/busbar/src/tests/catalogue_tests.rs.

/// A plane-contributed entry no linked plane owns, for the lent-catalogue cell below.
const fn lent_entry(code: u16, slug: &'static str) -> Diagnostic {
    Diagnostic {
        code,
        class: Class::Plane,
        slug,
        title: "A plane-contributed condition",
        severity: Severity::Actionable,
        summary: "A test plane's own condition, folded into one root's catalogue only.",
        action: "None: a test entry.",
        since: "1.6.0",
        retired: false,
    }
}

static ONE: Diagnostic = lent_entry(7996, "lent-catalogue-one");
static TWO: Diagnostic = lent_entry(7997, "lent-catalogue-two");

/// TWO ROOTS' CATALOGUES IN ONE PROCESS EACH RESOLVE ONLY THEIR OWN CODES: the kernel holds no
/// catalogue; the root folds once and lends. Two catalogues lent two different plane-contributed
/// entries resolve and list each its own entry and never the other's, and both still hold the
/// neutral built-ins. While the catalogue was one installed process static, the second root's
/// install panicked and the first root's codes were every reader's.
#[test]
fn two_catalogues_lent_in_one_process_each_resolve_only_their_own_codes() {
    let one = Catalogue::lent(Box::leak(Box::new([&ONE])));
    let two = Catalogue::lent(Box::leak(Box::new([&TWO])));
    assert_eq!(
        one.by_code(7996).map(|d| d.slug),
        Some("lent-catalogue-one")
    );
    assert!(
        one.by_code(7997).is_none(),
        "the first catalogue holds no second-root code"
    );
    assert_eq!(
        two.by_code(7997).map(|d| d.slug),
        Some("lent-catalogue-two")
    );
    assert!(
        two.by_code(7996).is_none(),
        "the second catalogue holds no first-root code"
    );
    assert!(
        Catalogue::NEUTRAL.by_code(7996).is_none() && Catalogue::NEUTRAL.by_code(7997).is_none()
    );
    for (catalogue, own) in [(one, 7996u16), (two, 7997)] {
        let all = catalogue.all();
        assert_eq!(
            all.len(),
            REGISTRY.len() + 1,
            "the built-ins and the one lent entry"
        );
        assert!(all.iter().any(|d| d.code == own));
        assert!(
            catalogue.by_code(1001).is_some(),
            "the built-ins stay in every catalogue"
        );
        assert_eq!(catalogue.installed().len(), 1);
    }
}
