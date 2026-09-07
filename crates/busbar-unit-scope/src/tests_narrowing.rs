// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Narrowing is MONOTONE: applying a ceiling never authorizes anything the uncapped grants did not.
//!
//! A module ceiling (`max_admin_scope:`) is the operator's statement that whatever the role bindings
//! union to, this module's principals may not exceed it. That is only a ceiling if it can subtract
//! and never add. The existing cases check one instance of it — a `Full` grant capped to `ReadOnly`
//! collapses — which is the case where the answer is obvious. What is pinned here is the property
//! over the WHOLE lattice, so a ceiling operator that got an incomparable pair backwards, or that
//! defaulted to the top rung instead of the bottom, has nowhere to hide.
//!
//! Stated as three laws, each checked against every grant set and every ceiling the chain admits:
//!
//! 1. **Narrowing only removes.** Anything the capped grants authorize, the uncapped grants already
//!    authorized. This is the security direction, and it is the one an escalation would break.
//! 2. **Narrowing is idempotent.** Applying the same ceiling twice is applying it once. A ceiling
//!    that kept moving would make a principal's authority depend on how many times the config was
//!    reloaded.
//! 3. **Narrowing is order-independent.** Two ceilings applied in either order give the same
//!    answer, so a principal matching two ceilinged bindings has one authority rather than one per
//!    evaluation order.

use super::*;

/// Every grant set over the two-rung chain: nothing, each scope alone, and both.
fn every_grants() -> Vec<Grants> {
    let mut out = vec![Grants::default()];
    for a in Scope::ALL {
        out.push(Grants::of(a));
        for b in Scope::ALL {
            out.push(Grants::of(a).with(b));
        }
    }
    out
}

/// Law 1, the security direction: a ceiling can only take authority away.
#[test]
fn a_ceiling_never_authorizes_anything_the_uncapped_grants_did_not() {
    for held in every_grants() {
        for cap in Scope::ALL {
            let capped = held.capped_by(cap);
            for needed in Scope::ALL {
                if capped.allows(needed) {
                    assert!(
                        held.allows(needed),
                        "{capped:?} (= {held:?} capped by {cap:?}) authorizes {needed:?}, \
                         which the uncapped grants did not — a ceiling that ESCALATES"
                    );
                }
            }
            // And the ceiling is a ceiling: nothing survives it that the ceiling itself does not
            // authorize, which is the whole of what an operator writing `max_admin_scope:` is
            // asking for.
            for needed in Scope::ALL {
                if capped.allows(needed) {
                    assert!(
                        cap.allows(needed),
                        "{capped:?} authorizes {needed:?}, which the ceiling {cap:?} does not"
                    );
                }
            }
        }
    }
}

/// Law 2: applying a ceiling twice is applying it once.
#[test]
fn a_ceiling_applied_twice_is_the_ceiling_applied_once() {
    for held in every_grants() {
        for cap in Scope::ALL {
            let once = held.capped_by(cap);
            assert_eq!(
                once.capped_by(cap),
                once,
                "{held:?} capped by {cap:?} is not stable under a second application"
            );
        }
    }
}

/// Law 3: two ceilings commute, so a principal's authority does not depend on evaluation order.
#[test]
fn two_ceilings_give_the_same_answer_in_either_order() {
    for held in every_grants() {
        for a in Scope::ALL {
            for b in Scope::ALL {
                assert_eq!(
                    held.capped_by(a).capped_by(b),
                    held.capped_by(b).capped_by(a),
                    "{held:?} under ceilings {a:?} and {b:?} depends on the order they are applied"
                );
            }
        }
    }
}

/// The union direction, stated as the other half of the same property: unioning role bindings only
/// ever ADDS, and the union of two roles authorizes exactly what one or the other did.
///
/// The two together are what make the fold over a principal's bindings well-defined: union up, then
/// meet down, and neither step can be reordered into an escalation.
#[test]
fn a_union_authorizes_exactly_what_one_or_the_other_role_authorized() {
    for held in every_grants() {
        for added in Scope::ALL {
            let union = held.with(added);
            for needed in Scope::ALL {
                assert_eq!(
                    union.allows(needed),
                    held.allows(needed) || Grants::of(added).allows(needed),
                    "{held:?} unioned with {added:?} on {needed:?}"
                );
            }
            assert!(
                union.contains(added),
                "a union keeps the scope it added: {held:?} + {added:?}"
            );
            for s in Scope::ALL {
                if held.contains(s) {
                    assert!(
                        union.contains(s),
                        "a union keeps what was already held: {held:?} + {added:?} lost {s:?}"
                    );
                }
            }
        }
    }
}

/// The refusal that comes out of a narrowed principal names the scope that would have sufficed —
/// the scope the OPERATION needed, never the one the ceiling left.
///
/// A refusal naming the held scope instead would tell an operator to raise the ceiling when what
/// they have to change is the binding, and vice versa.
#[test]
fn a_refusal_after_narrowing_names_the_scope_the_operation_needed() {
    let capped = Grants::of(Scope::Full).capped_by(Scope::ReadOnly);
    assert_eq!(
        approve(capped, Scope::Full),
        Err(Refused::InsufficientScope {
            needed: Scope::Full
        })
    );
    assert!(approve(capped, Scope::ReadOnly).is_ok());
}
