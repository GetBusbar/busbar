// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The words the seam itself says.
//!
//! Three of the strings this unit puts in front of an operator are not produced by a walk at all:
//! the stable name of an availability reason, and the two refusals the decoration and the journal
//! hand back. They are asserted here verbatim, because a diagnostic that renders as an empty string
//! is a diagnostic nobody can act on and nothing else in the crate reads them.

use crate::ports::{DecorationRefused, DurabilityUnavailable, Unavailable};

/// Every reason has its own stable name, and no two share one.
#[test]
fn every_availability_reason_has_its_own_stable_name() {
    let named: &[(Unavailable, &str)] = &[
        (Unavailable::Dead, "dead"),
        (Unavailable::BudgetExhausted, "budget_exhausted"),
        (Unavailable::BreakerOpen { until: 42 }, "breaker_open"),
        (Unavailable::ProbeInFlight, "probe_in_flight"),
        (
            Unavailable::AtCapacity {
                drain_hint_ms: None,
            },
            "at_capacity",
        ),
    ];
    for (reason, expected) in named {
        assert_eq!(
            reason.variant_name(),
            *expected,
            "{reason:?} must name itself {expected}"
        );
    }

    let mut names: Vec<&str> = named.iter().map(|(r, _)| r.variant_name()).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(
        names.len(),
        before,
        "two reasons that share a name are two reasons an operator cannot tell apart"
    );
    assert!(
        names.iter().all(|n| !n.is_empty()),
        "a reason that renders as nothing is a reason nobody can act on"
    );
}

/// The payload a reason carries does not change its name: `BreakerOpen` at any deadline, and
/// `AtCapacity` with or without a drain hint, name themselves the same way.
#[test]
fn the_payload_a_reason_carries_does_not_change_its_name() {
    assert_eq!(
        Unavailable::BreakerOpen { until: 0 }.variant_name(),
        Unavailable::BreakerOpen { until: u64::MAX }.variant_name()
    );
    assert_eq!(
        Unavailable::AtCapacity {
            drain_hint_ms: None
        }
        .variant_name(),
        Unavailable::AtCapacity {
            drain_hint_ms: Some(250)
        }
        .variant_name()
    );
}

/// The decoration's refusal says what could not be done, in words.
#[test]
fn the_decoration_refusal_says_what_it_refused() {
    assert_eq!(
        DecorationRefused.to_string(),
        "the outbound request could not be decorated"
    );
}

/// The journal's refusal says what could not be made durable, in words.
#[test]
fn the_durability_refusal_says_what_could_not_be_recorded() {
    assert_eq!(
        DurabilityUnavailable.to_string(),
        "the dispatch record could not be made durable"
    );
}

/// Both refusals are errors an integrator can propagate, and neither renders as nothing.
#[test]
fn both_refusals_are_errors_that_render_as_something() {
    fn as_error(e: &dyn std::error::Error) -> String {
        e.to_string()
    }
    assert!(!as_error(&DecorationRefused).is_empty());
    assert!(!as_error(&DurabilityUnavailable).is_empty());
    assert_ne!(
        DecorationRefused.to_string(),
        DurabilityUnavailable.to_string(),
        "two different failures must not read as the same sentence"
    );
}
