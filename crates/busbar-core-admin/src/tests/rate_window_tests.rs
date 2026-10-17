// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WINDOW IS A MINUTE, NOT A MOMENT — and the class an operator is refused under is named to
//! them.
//!
//! The limiter's whole behaviour turns on one arithmetic line: `now - (now % 60)` floors a
//! timestamp onto the minute it falls in, and every entry from a different minute is swept. The
//! existing batteries spend a budget and check that it runs out, which they do entirely at `now =
//! 0` — where the floor is the identity and almost any arithmetic agrees with the right one. So
//! they say nothing about the property the line exists for: two attempts a caller makes SECONDS
//! apart draw on ONE budget, and an attempt in the next minute draws on a fresh one.
//!
//! An operator who could refresh their own budget by waiting a second has no budget. An operator
//! whose budget never refreshed would be locked out of their own node for as long as the process
//! lives. Both are one character away from the shipped line, and neither was visible.
//!
//! The labels are here for the same reason: they are what an audit row says the refusal was, and a
//! denial recorded under the wrong class (or under no class at all) is a denial nobody can act on.

use crate::rate::{MutationClass, MutationLimiter, MUTATION_RATE_WINDOW_SECS};

/// Spend a whole class budget at `now`, asserting every attempt is admitted.
fn exhaust(limiter: &MutationLimiter, principal: &str, class: MutationClass, now: u64) {
    for i in 0..class.limit() {
        assert!(
            limiter.check(principal, class, now).admitted(),
            "attempt {i} of {class:?}'s budget was refused inside the budget"
        );
    }
}

/// TWO ATTEMPTS IN THE SAME MINUTE DRAW ON ONE BUDGET, WHEREVER IN THE MINUTE THEY LAND.
///
/// The budget is exhausted at the very start of a minute and the next attempt arrives partway
/// through the SAME minute. It must still be refused. Any flooring that is not `now - (now % 60)`
/// — dropping the subtraction, dividing instead of taking the remainder, adding instead of
/// subtracting — maps those two instants to different windows, the sweep drops the exhausted
/// counter, and the caller is handed a fresh sixty attempts by doing nothing but waiting a second.
#[test]
fn a_budget_exhausted_at_the_top_of_a_minute_is_still_exhausted_later_in_that_minute() {
    // A minute that is NOT the epoch: at `now = 0` every plausible arithmetic agrees.
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

/// AND THE MINUTE AFTER IT IS A FRESH BUDGET.
///
/// The other half of the same property, and the half that says the window really is a window
/// rather than a permanent ban. Checked from a non-zero minute so that the boundary being crossed
/// is a real one.
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

/// THE FIRST DENIAL IN A WINDOW IS THE ONE THAT IS AUDITED, AND ONLY THE FIRST.
///
/// The caller writes exactly one audit row per principal per class per window off this flag. If it
/// were true for every denial a retrying client would flood the log it is being refused for; if it
/// were never true the refusal would never be recorded at all. And the counter is per WINDOW: the
/// first denial of the NEXT minute is a first denial again.
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

    // A new window: the budget is fresh, so spend it again and the next denial is a first one.
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

/// ONE PRINCIPAL'S SPENDING IS NOT ANOTHER'S.
///
/// The counters are keyed by `(principal, class)`. An operator exhausting their own budget must not
/// refuse anybody else's mutation, and the sweep must not take a live window with it when it drops
/// a stale one belonging to somebody else.
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
    // And the classes are separate budgets too.
    assert!(
        limiter
            .check("alice", MutationClass::Crud, minute)
            .admitted(),
        "alice's CRUD budget was spent by her CONFIG attempts"
    );
}

/// THE FOUR AUDIT LABELS, PINNED.
///
/// These strings leave the process: they are what the denial audit row calls the class, so an
/// operator reading the log learns which budget refused them and can go and look at the right one.
/// They also have to keep matching `busbar-core`'s own labels, or one node's log and another's stop
/// being readable side by side. Nothing else in this crate asserts them, so nothing else notices if
/// they are emptied, renamed or collapsed onto each other.
#[test]
fn every_mutation_class_names_itself_to_the_audit_row() {
    assert_eq!(MutationClass::Config.label(), "config");
    assert_eq!(MutationClass::Crud.label(), "crud");
    assert_eq!(MutationClass::PluginInspect.label(), "plugin-inspect");
    assert_eq!(MutationClass::Forbidden.label(), "forbidden");

    // No two classes may answer to one label: a log that cannot tell a config refusal from a CRUD
    // one is a log that names no budget at all.
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

/// THE FOUR BUDGETS, PINNED, AND THE ORDER BETWEEN THEM.
///
/// The numbers are the spec's, and `Forbidden` is zero because it is not a budget at all — a class
/// that is never meant to be checked. A `Forbidden` attempt that were ever admitted would mean a
/// read had quietly become a mutation with a budget.
#[test]
fn the_four_budgets_are_the_spec_defaults_and_forbidden_admits_nothing() {
    assert_eq!(MutationClass::Config.limit(), 10);
    assert_eq!(MutationClass::Crud.limit(), 60);
    assert_eq!(MutationClass::PluginInspect.limit(), 30);
    assert_eq!(MutationClass::Forbidden.limit(), 0);

    // Zero is not a decoration: the very first `Forbidden` check is denied.
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

    // A blast-radius config change is capped harder than an ordinary CRUD one, and the plugin
    // dry-run sits between them. The ORDER is the design; the numbers above are the spec.
    assert!(MutationClass::Config.limit() < MutationClass::PluginInspect.limit());
    assert!(MutationClass::PluginInspect.limit() < MutationClass::Crud.limit());
}
