// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ported assertions from `busbar-core::admin::rate::tests` for the mutation rate limiter: budgets
//! per class, per-principal isolation, the fixed one-minute window reset, and that a denial still
//! counts (so probing costs the same budget as mutating).

use crate::rate::{MutationClass, MutationLimiter, RateCheck};

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
    // A different principal has its own, untouched budget in the same window.
    assert!(limiter.check("bob", MutationClass::Crud, 0).admitted());
}

#[test]
fn budgets_are_isolated_per_class_for_the_same_principal() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Config, 0).admitted());
    // The CRUD budget is untouched by exhausting CONFIG.
    assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
}

#[test]
fn a_new_window_resets_the_budget() {
    let limiter = MutationLimiter::new();
    for _ in 0..60 {
        assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Crud, 0).admitted());
    // 60 seconds later is a new fixed window.
    assert!(limiter.check("alice", MutationClass::Crud, 60).admitted());
}

#[test]
fn forbidden_class_has_zero_budget() {
    let limiter = MutationLimiter::new();
    assert!(!limiter.check("alice", MutationClass::Forbidden, 0).admitted());
}
