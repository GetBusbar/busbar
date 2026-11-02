// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::rate::{MutationClass, MutationLimiter, MUTATION_RATE_WINDOW_SECS};

fn exhaust(limiter: &MutationLimiter, principal: &str, class: MutationClass, now: u64) {
    for i in 0..class.limit() {
        assert!(
            limiter.check(principal, class, now).admitted(),
            "attempt {i} of {class:?}'s budget was refused inside the budget"
        );
    }
}

#[test]
fn a_budget_exhausted_at_the_top_of_a_minute_is_still_exhausted_later_in_that_minute() {
    let minute = 7 * MUTATION_RATE_WINDOW_SECS;
    for offset in [0, 1, 30, MUTATION_RATE_WINDOW_SECS - 1] {
        let limiter = MutationLimiter::new();
        exhaust(&limiter, "alice", MutationClass::Crud, minute);
        assert!(
            !limiter
                .check("alice", MutationClass::Crud, minute + offset)
                .admitted(),
            "an attempt {offset}s into the same minute was admitted against an exhausted budget"
        );
    }
}

#[test]
fn the_next_minute_starts_a_fresh_budget() {
    let minute = 7 * MUTATION_RATE_WINDOW_SECS;
    let limiter = MutationLimiter::new();
    exhaust(&limiter, "alice", MutationClass::Crud, minute);
    assert!(
        !limiter
            .check("alice", MutationClass::Crud, minute)
            .admitted(),
        "the budget was not actually exhausted"
    );
    assert!(
        limiter
            .check("alice", MutationClass::Crud, minute + MUTATION_RATE_WINDOW_SECS)
            .admitted(),
        "the next minute did not start a fresh budget -- an operator is locked out of their own node"
    );
}

#[test]
fn only_the_first_denial_of_each_window_is_flagged_for_the_audit_row() {
    let limiter = MutationLimiter::new();
    let minute = 7 * MUTATION_RATE_WINDOW_SECS;
    exhaust(&limiter, "alice", MutationClass::Config, minute);

    let first = limiter.check("alice", MutationClass::Config, minute);
    assert_eq!(
        first,
        crate::rate::RateCheck::Denied {
            first_in_window: true
        },
        "the first denial in a window must be the audited one"
    );
    for _ in 0..3 {
        assert_eq!(
            limiter.check("alice", MutationClass::Config, minute + 5),
            crate::rate::RateCheck::Denied {
                first_in_window: false
            },
            "a later denial in the same window must not be audited again"
        );
    }

    let next = minute + MUTATION_RATE_WINDOW_SECS;
    exhaust(&limiter, "alice", MutationClass::Config, next);
    assert_eq!(
        limiter.check("alice", MutationClass::Config, next),
        crate::rate::RateCheck::Denied {
            first_in_window: true
        },
        "the first denial of a new window must be audited"
    );
}

#[test]
fn one_principals_exhausted_budget_does_not_refuse_another_principal() {
    let limiter = MutationLimiter::new();
    let minute = 7 * MUTATION_RATE_WINDOW_SECS;
    exhaust(&limiter, "alice", MutationClass::Config, minute);
    assert!(!limiter
        .check("alice", MutationClass::Config, minute)
        .admitted());
    assert!(
        limiter
            .check("bob", MutationClass::Config, minute)
            .admitted(),
        "bob was refused because alice spent her budget"
    );

    assert!(
        limiter
            .check("alice", MutationClass::Crud, minute)
            .admitted(),
        "alice's CRUD budget was spent by her CONFIG attempts"
    );
}

#[test]
fn every_mutation_class_names_itself_to_the_audit_row() {
    assert_eq!(MutationClass::Config.label(), "config");
    assert_eq!(MutationClass::Crud.label(), "crud");
    assert_eq!(MutationClass::PluginInspect.label(), "plugin-inspect");
    assert_eq!(MutationClass::Forbidden.label(), "forbidden");

    let labels = [
        MutationClass::Config,
        MutationClass::Crud,
        MutationClass::PluginInspect,
        MutationClass::Forbidden,
    ]
    .map(MutationClass::label);
    let mut sorted = labels.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        labels.len(),
        "two classes share one audit label"
    );
    assert!(
        !labels.iter().any(|l| l.is_empty()),
        "a class has no audit label at all"
    );
}

#[test]
fn the_four_budgets_are_the_spec_defaults_and_forbidden_admits_nothing() {
    assert_eq!(MutationClass::Config.limit(), 10);
    assert_eq!(MutationClass::Crud.limit(), 60);
    assert_eq!(MutationClass::PluginInspect.limit(), 30);
    assert_eq!(MutationClass::Forbidden.limit(), 0);

    let limiter = MutationLimiter::new();
    assert!(
        !limiter
            .check(
                "alice",
                MutationClass::Forbidden,
                7 * MUTATION_RATE_WINDOW_SECS
            )
            .admitted(),
        "a Forbidden attempt drew on a budget"
    );

    assert!(MutationClass::Config.limit() < MutationClass::PluginInspect.limit());
    assert!(MutationClass::PluginInspect.limit() < MutationClass::Crud.limit());
}
