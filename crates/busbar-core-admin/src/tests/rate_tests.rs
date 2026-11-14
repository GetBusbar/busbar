// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::rate::{MutationClass, MutationLimiter, RateCheck};
use crate::verb::KernelVerb;

#[test]
fn crud_budget_is_60_per_minute_then_denies() {
    let limiter = MutationLimiter::new();
    for i in 0..60 {
        assert!(
            limiter.check("alice", MutationClass::Crud, 0).admitted(),
            "attempt {i} should be admitted"
        );
    }
    assert_eq!(
        limiter.check("alice", MutationClass::Crud, 0),
        RateCheck::Denied {
            first_in_window: true
        }
    );
    assert_eq!(
        limiter.check("alice", MutationClass::Crud, 0),
        RateCheck::Denied {
            first_in_window: false
        }
    );
}

#[test]
fn config_budget_is_10_per_minute() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Config, 0).admitted());
}

#[test]
fn plugin_inspect_budget_is_30_per_minute() {
    let limiter = MutationLimiter::new();
    for _ in 0..30 {
        assert!(limiter
            .check("alice", MutationClass::PluginInspect, 0)
            .admitted());
    }
    assert!(!limiter
        .check("alice", MutationClass::PluginInspect, 0)
        .admitted());
}

#[test]
fn budgets_are_isolated_per_principal() {
    let limiter = MutationLimiter::new();
    for _ in 0..60 {
        assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Crud, 0).admitted());

    assert!(limiter.check("bob", MutationClass::Crud, 0).admitted());
}

#[test]
fn budgets_are_isolated_per_class_for_the_same_principal() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Config, 0).admitted());

    assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
}

#[test]
fn a_new_window_resets_the_budget() {
    let limiter = MutationLimiter::new();
    for _ in 0..60 {
        assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Crud, 0).admitted());

    assert!(limiter.check("alice", MutationClass::Crud, 60).admitted());
}

#[test]
fn forbidden_class_has_zero_budget() {
    let limiter = MutationLimiter::new();
    assert!(!limiter
        .check("alice", MutationClass::Forbidden, 0)
        .admitted());
}

#[test]
fn the_two_read_only_new_verbs_never_spend_a_mutation_slot() {
    for verb in [KernelVerb::Verify, KernelVerb::PlaneFacts] {
        assert_eq!(
            MutationClass::for_verb(verb),
            MutationClass::Forbidden,
            "{verb:?} is a read and must never draw the mutation budget"
        );
    }

    assert_eq!(
        MutationClass::for_verb(KernelVerb::Adjust),
        MutationClass::Crud
    );
}

#[test]
fn every_named_surface_is_never_rate_limited_as_a_mutation() {
    for verb in crate::verb::NAMED_SURFACES {
        assert_eq!(
            MutationClass::for_verb(*verb),
            MutationClass::Forbidden,
            "{verb:?} is a named surface and must never be rate-limited as a mutation"
        );
    }
}

#[test]
fn an_out_of_order_now_cannot_refill_a_spent_budget() {
    let limiter = MutationLimiter::new();
    for i in 0..10 {
        assert!(
            limiter
                .check("alice", MutationClass::Config, 120)
                .admitted(),
            "attempt {i} inside the budget"
        );
    }
    assert!(!limiter
        .check("alice", MutationClass::Config, 120)
        .admitted());

    let _ = limiter.check("mallory", MutationClass::Crud, 60);
    assert!(
        !limiter
            .check("alice", MutationClass::Config, 120)
            .admitted(),
        "a request from an earlier window wiped alice's live counter and handed her a fresh budget"
    );

    let _ = limiter.check("mallory", MutationClass::Crud, 0);
    assert!(
        !limiter
            .check("alice", MutationClass::Config, 120)
            .admitted(),
        "an unreadable wall clock read as 0 wiped alice's live counter"
    );
}

#[test]
fn a_regressing_clock_is_clamped_into_the_live_window_rather_than_opening_an_older_one() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter
            .check("alice", MutationClass::Config, 600)
            .admitted());
    }

    assert!(
        !limiter.check("alice", MutationClass::Config, 0).admitted(),
        "a regressed clock must be clamped into the live window, not open a fresh older one"
    );

    assert!(limiter
        .check("alice", MutationClass::Config, 660)
        .admitted());
}

#[test]
fn the_sweep_drops_only_windows_older_than_the_current_one() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 60).admitted());
    }

    assert!(!limiter
        .check("alice", MutationClass::Config, 119)
        .admitted());

    assert!(limiter
        .check("alice", MutationClass::Config, 120)
        .admitted());

    for _ in 0..9 {
        assert!(limiter
            .check("alice", MutationClass::Config, 120)
            .admitted());
    }
    assert!(!limiter
        .check("alice", MutationClass::Config, 120)
        .admitted());
}

#[path = "rate_window_tests.rs"]
mod rate_window_tests;
