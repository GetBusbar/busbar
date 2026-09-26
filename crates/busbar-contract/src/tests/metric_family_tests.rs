// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The metric-family guard ([`check_metric_families`]): what a plane may declare it adds to over
//! the host's `counter_add`, judged against the reserved rows the host lets a plane carry.

use super::*;

/// The host's carried rows, as a caller supplies them.
const CARRIED: &[(&str, &[&str])] = &[("busbar_carried_total", &["protocol", "reason"])];

/// A declaration keyed `key` stating exactly `families`.
fn decl(key: &'static str, families: &'static [MetricFamily]) -> PlaneDeclaration {
    PlaneDeclaration {
        key,
        fallback: false,
        config_section: key,
        scope_kinds: &[],
        subject_noun: key,
        admin_noun: key,
        audit_kind: key,
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        fee_units: &[],
        metric_families: families,
        served_op_classes: &[],
    }
}

/// A counter family.
const fn counter(name: &'static str, label_keys: &'static [&'static str]) -> MetricFamily {
    MetricFamily {
        name,
        kind: COUNTER,
        label_keys,
    }
}

fn verdict(families: &'static [MetricFamily]) -> Result<(), String> {
    check_metric_families(&[&decl("p", families)], CARRIED)
}

#[test]
fn a_plane_family_and_a_carried_first_party_series_are_admitted() {
    const OWN: &[MetricFamily] = &[counter("p_units_total", &["unit"])];
    const CARRY: &[MetricFamily] = &[counter("busbar_carried_total", &["protocol", "reason"])];
    assert_eq!(verdict(OWN), Ok(()));
    assert_eq!(verdict(CARRY), Ok(()));
    assert_eq!(verdict(&[]), Ok(()));
}

/// RED ARM: a plane cannot mint a first-party series — an unlisted `busbar_` name is refused, and
/// so is a listed one whose label keys differ in set or in order (it would not render the host's
/// bytes).
#[test]
fn a_reserved_family_the_host_does_not_list_is_refused() {
    const MINTED: &[MetricFamily] = &[counter("busbar_minted_total", &[])];
    const REKEYED: &[MetricFamily] = &[counter("busbar_carried_total", &["protocol"])];
    const REORDERED: &[MetricFamily] = &[counter("busbar_carried_total", &["reason", "protocol"])];
    for families in [MINTED, REKEYED, REORDERED] {
        let err = verdict(families).unwrap_err();
        assert!(err.contains("reserved `busbar_` namespace"), "{err}");
    }
}

#[test]
fn a_malformed_family_is_refused() {
    const BAD_NAME: &[MetricFamily] = &[counter("P-units", &[])];
    const BAD_KEY: &[MetricFamily] = &[counter("p_total", &["Unit"])];
    const REPEATED: &[MetricFamily] = &[counter("p_total", &["unit", "unit"])];
    const TOO_MANY: &[MetricFamily] = &[counter(
        "p_total",
        &["a", "b", "c", "d", "e", "f", "g", "h", "i"],
    )];
    const GAUGE: &[MetricFamily] = &[MetricFamily {
        name: "p_total",
        kind: "gauge",
        label_keys: &[],
    }];
    for families in [BAD_NAME, BAD_KEY, REPEATED, TOO_MANY, GAUGE] {
        assert!(verdict(families).is_err(), "{families:?} was admitted");
    }
}

#[test]
fn one_family_has_one_writer() {
    const F: &[MetricFamily] = &[counter("p_total", &[])];
    const TWICE: &[MetricFamily] = &[counter("p_total", &[]), counter("p_total", &[])];
    let err = check_metric_families(&[&decl("a", F), &decl("b", F)], CARRIED).unwrap_err();
    assert!(
        err.contains("plane `b`") && err.contains("plane `a`"),
        "{err}"
    );
    assert!(verdict(TWICE).is_err());
}
