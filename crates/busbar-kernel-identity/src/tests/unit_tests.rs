// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The sealed answer: what the loop actually receives.

use crate::admin::{admin_grants, kernel_verb_scope_satisfied, Grants, Scope};
use crate::challenge::{Challenge, ChallengeBounds};
use crate::principal::Principal;

#[test]
fn a_challenge_advances_within_its_bounds_and_then_stops() {
    let c = Challenge::open(
        b"aa".to_vec(),
        ChallengeBounds {
            max_rounds: 3,
            max_bytes: 6,
        },
    );
    assert_eq!(c.rounds_left, 2);
    assert_eq!(c.bytes_left, 4);
    let c = c.advance(b"bb".to_vec()).expect("within both bounds");
    assert_eq!(c.rounds_left, 1);
    assert_eq!(c.bytes_left, 2);
    assert!(
        c.clone().advance(b"ccc".to_vec()).is_none(),
        "a round larger than the remaining byte budget is refused"
    );
    let c = c.advance(b"cc".to_vec()).expect("exactly the budget");
    assert!(c.exhausted());
    assert!(c.advance(b"d".to_vec()).is_none());
}

#[test]
fn open_admin_grants_full_scope_to_an_absent_principal() {
    let grants = admin_grants(true, None).expect("the open posture grants");
    assert_eq!(grants.scope(), Scope::Full);
    assert!(grants.satisfies(Scope::ReadOnly));
    assert!(grants.satisfies(Scope::Full));
    // With a chain configured, an absent principal holds nothing.
    assert!(admin_grants(false, None).is_none());
    // And a resolved principal's grants come from the bindings, not from the posture.
    assert!(admin_grants(true, Some(&Principal::from_id("alice"))).is_none());
}

#[test]
fn the_kernel_verb_scope_check_is_satisfied_for_anonymous_on_the_open_posture() {
    assert!(kernel_verb_scope_satisfied(true, &Principal::anonymous()));
    assert!(
        !kernel_verb_scope_satisfied(false, &Principal::anonymous()),
        "with a chain configured the check is not satisfied by being nobody"
    );
    assert!(
        !kernel_verb_scope_satisfied(true, &Principal::from_id("alice")),
        "a resolved principal is judged on its own scopes"
    );
}

/// The satisfaction table, pinned pair by pair.
///
/// Pinned rather than derived from an ordering: a comparison would answer for a rung nobody has
/// decided about yet, and the answer it invents comes from where the variant was written. Every
/// pair below is a decision, and adding a rung to `Scope` fails to compile until its pairs are
/// added here too — which is the whole point of spelling satisfaction as a match.
#[test]
fn satisfaction_is_a_decided_table_not_a_declaration_order() {
    let cases = [
        (Scope::ReadOnly, Scope::ReadOnly, true),
        (Scope::ReadOnly, Scope::Full, false),
        (Scope::Full, Scope::ReadOnly, true),
        (Scope::Full, Scope::Full, true),
    ];
    for (held, needed, expected) in cases {
        assert_eq!(
            Grants::of(held).satisfies(needed),
            expected,
            "held {held:?} against needed {needed:?}"
        );
    }
}
