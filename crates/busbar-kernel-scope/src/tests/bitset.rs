// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`Grants`] bitset layout itself.
//!
//! `Grants` is a bitset whose meaning is POSITIONAL: a scope's bit is `1 << its index in
//! `Scope::ALL``, and `Grants::contains` reads that same bit back. Every other test in this crate
//! exercises the pair together, so any assignment that is internally consistent — including one
//! that hands `ReadOnly` the rung `Full` should have had — satisfies all of them. Two variants make
//! a swap a bijection, so a swap is invisible from the outside and stays invisible right up until a
//! third rung is added, at which point the swap stops being a bijection and starts being a scope
//! confusion. So the layout is pinned here directly, on the private constructor, rather than left to
//! be inferred from behaviour that cannot see it.

use super::*;

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
