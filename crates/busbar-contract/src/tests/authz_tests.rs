// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two-rung authorization lattice: its bit layout, its chain, and the laws its ceiling obeys.

use super::*;

/// Each scope's bit is the single bit at its own index in `Scope::ALL` — `ReadOnly` at the bottom
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
