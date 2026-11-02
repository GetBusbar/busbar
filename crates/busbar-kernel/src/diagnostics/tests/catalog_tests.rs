// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

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

#[test]
fn banner_is_zero_padded() {
    assert_eq!(
        DURABLE_WRITETHROUGH_BELOW_FLOOR.banner().to_string(),
        "BUSBAR-1001"
    );
    assert_eq!(Banner(42).to_string(), "BUSBAR-0042");
}

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

#[test]
fn lookup_by_code_works() {
    assert_eq!(
        Catalogue::NEUTRAL.by_code(1001).map(|d| d.slug),
        Some("durable-writethrough-below-floor")
    );
    assert!(Catalogue::NEUTRAL.by_code(9999).is_none());
}

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
