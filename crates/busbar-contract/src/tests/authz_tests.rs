// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two-rung authorization lattice: its bit layout, its chain, and the laws its ceiling obeys.
//! Moved with the lattice's last copy from `busbar-kernel-scope` (Q128 kernel-scope: one home per
//! fact), so the one home is the one that is proven.

use super::*;

// ══ THE BITSET LAYOUT ════════════════════════════════════════════════════════════════════════════

// The [`Grants`] bitset layout itself.
//
// `Grants` is a bitset whose meaning is POSITIONAL: a scope's bit is `1 << its index in
// `Scope::ALL``, and `Grants::contains` reads that same bit back. Every other test in this crate
// exercises the pair together, so any assignment that is internally consistent — including one
// that hands `ReadOnly` the rung `Full` should have had — satisfies all of them. Two variants make
// a swap a bijection, so a swap is invisible from the outside and stays invisible right up until a
// third rung is added, at which point the swap stops being a bijection and starts being a scope
// confusion. So the layout is pinned here directly, on the private constructor, rather than left to
// be inferred from behaviour that cannot see it.

/// Each scope's bit is the single bit at its own index in `Scope::ALL` — `ReadOnly` at the bottom
/// rung (bit 0), `Full` above it (bit 1) — and no two scopes share one.
#[test]
fn each_scopes_bit_is_its_own_index_in_the_declared_chain() {
    assert_eq!(Scope::ReadOnly.bit(), 0b01, "ReadOnly is the bottom rung");
    assert_eq!(Scope::Full.bit(), 0b10, "Full is the rung above it");

    for (i, s) in Scope::ALL.iter().enumerate() {
        assert_eq!(
            s.bit(),
            1u8 << i,
            "{s:?} is at index {i} of Scope::ALL, so its bit is 1 << {i}"
        );
        assert_eq!(s.bit().count_ones(), 1, "{s:?} occupies exactly one bit");
    }

    for a in Scope::ALL {
        for b in Scope::ALL {
            assert_eq!(
                a.bit() == b.bit(),
                a == b,
                "distinct scopes must not share a bit: {a:?} vs {b:?}"
            );
        }
    }
}

/// The bit layout is what `Grants` stores, so pinning the bits pins the set: a single-scope grant
/// holds that scope and nothing else, and the union holds both.
#[test]
fn grants_hold_exactly_the_bits_of_the_scopes_put_in_them() {
    assert!(Grants::of(Scope::ReadOnly).contains(Scope::ReadOnly));
    assert!(
        !Grants::of(Scope::ReadOnly).contains(Scope::Full),
        "a read-only grant does not hold full"
    );
    assert!(Grants::of(Scope::Full).contains(Scope::Full));
    assert!(
        !Grants::of(Scope::Full).contains(Scope::ReadOnly),
        "a full grant holds `full`; it SATISFIES a read, which is `allows`, not `contains`"
    );

    let both = Grants::of(Scope::ReadOnly).with(Scope::Full);
    assert!(both.contains(Scope::ReadOnly));
    assert!(both.contains(Scope::Full));

    assert!(
        Scope::ALL.iter().all(|s| !Grants::default().contains(*s)),
        "the empty grant holds nothing"
    );
}

// ══ THE CHAIN ═══════════════════════════════════════════════════════════════════════════════════

/// `parse` drops the retired delegated tokens; `read-only`/`full` round-trip.
#[test]
fn scope_parse_drops_retired_tokens() {
    assert!(Scope::parse("mint").is_none());
    assert!(Scope::parse("hooks-register").is_none());
    assert!(Scope::parse("bogus").is_none());
    assert_eq!(Scope::parse("read-only"), Some(Scope::ReadOnly));
    assert_eq!(Scope::parse("full"), Some(Scope::Full));
    assert_eq!(Scope::ReadOnly.as_str(), "read-only");
    assert_eq!(Scope::Full.as_str(), "full");
}

/// The two-rung chain: `ReadOnly` does not satisfy a `Full` requirement, `Full` satisfies both, and
/// a `Full` grant capped by a `ReadOnly` ceiling collapses to read-only.
#[test]
fn readonly_not_allow_full_full_allows_readonly() {
    assert!(!Scope::ReadOnly.allows(Scope::Full));
    assert!(Scope::ReadOnly.allows(Scope::ReadOnly));
    assert!(Scope::Full.allows(Scope::ReadOnly));
    assert!(Scope::Full.allows(Scope::Full));

    let capped = Grants::of(Scope::Full).capped_by(Scope::ReadOnly);
    assert!(capped.allows(Scope::ReadOnly));
    assert!(!capped.allows(Scope::Full));

    for a in Scope::ALL {
        for b in Scope::ALL {
            let union = Grants::of(a).with(b);
            for n in Scope::ALL {
                assert_eq!(
                    union.allows(n),
                    a.allows(n) || b.allows(n),
                    "Grants::of({a:?}).with({b:?}).allows({n:?})"
                );
            }
        }
    }
    assert_eq!(Scope::Full.meet(Scope::ReadOnly), Scope::ReadOnly);
    assert!(Scope::Full.dominates(Scope::ReadOnly));
    assert!(!Scope::ReadOnly.dominates(Scope::Full));
}

// ══ NARROWING IS MONOTONE ════════════════════════════════════════════════════════════════════════
// Narrowing is MONOTONE: applying a ceiling never authorizes anything the uncapped grants did not.
//
// A module ceiling (`max_admin_scope:`) is the operator's statement that whatever the role bindings
// union to, this module's principals may not exceed it. That is only a ceiling if it can subtract
// and never add. The existing cases check one instance of it — a `Full` grant capped to `ReadOnly`
// collapses — which is the case where the answer is obvious. What is pinned here is the property
// over the WHOLE lattice, so a ceiling operator that got an incomparable pair backwards, or that
// defaulted to the top rung instead of the bottom, has nowhere to hide.
//
// Stated as three laws, each checked against every grant set and every ceiling the chain admits:
//
// 1. **Narrowing only removes.** Anything the capped grants authorize, the uncapped grants already
//    authorized. This is the security direction, and it is the one an escalation would break.
// 2. **Narrowing is idempotent.** Applying the same ceiling twice is applying it once. A ceiling
//    that kept moving would make a principal's authority depend on how many times the config was
//    reloaded.
// 3. **Narrowing is order-independent.** Two ceilings applied in either order give the same
//    answer, so a principal matching two ceilinged bindings has one authority rather than one per
//    evaluation order.

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
