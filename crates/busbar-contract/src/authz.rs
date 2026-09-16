// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The GENERIC authorization lattice — `Scope`, the strict two-rung chain (`ReadOnly` / `Full`),
//! and `Grants`, the bitset of held scopes derived from it. Zero surface-specific vocabulary: no
//! path, no error text naming a particular served surface anywhere in this module. A served
//! control surface (or any other surface with the same two-rung read/write shape) names this
//! directly instead of reinventing it.
//!
//! What is deliberately NOT here: the ceiling-token parser (`parse_ceiling`, whose error text is
//! wire-pinned to a surface-specific config key), the method+path → `Scope` matrix
//! (`required_scope`), and the surface-specific error taxonomy. Those name that surface and stay
//! there — putting that vocabulary in this crate would just relocate the violation this split
//! exists to remove.

/// The built-in authorization scopes — a strict two-rung chain: `ReadOnly` at the bottom, `Full`
/// at the top. Authorization is checked on the PRINCIPAL per endpoint and is NEVER derived from
/// the request body, so a crafted request cannot escalate.
///
/// The variant set is a FROZEN authorization contract for every consumer built on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The read-only rung: every read, plus any stateless dry-run that mutates nothing.
    ReadOnly,
    /// The full rung: every mutation.
    Full,
}

impl Scope {
    /// The stable wire token for this scope.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::ReadOnly => "read-only",
            Scope::Full => "full",
        }
    }

    /// Parse a scope token (`"read-only"` / `"full"`). `None` = unknown token; callers fail
    /// closed (no grant) or reject at validation time, per their own policy.
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "read-only" => Some(Scope::ReadOnly),
            "full" => Some(Scope::Full),
            _ => None,
        }
    }

    /// Whether a principal holding `self` may call an endpoint requiring `needed`. A strict
    /// chain: `ReadOnly` is satisfied by anything (every grant can read); `Full` is satisfied
    /// only by `Full`.
    pub fn allows(self, needed: Scope) -> bool {
        match needed {
            // Every grant can read.
            Scope::ReadOnly => true,
            // Only the god-mode grant satisfies a full requirement.
            Scope::Full => self == Scope::Full,
        }
    }

    /// Every scope, for the closure operations below. Adding a variant means adding it here too
    /// (the compiler cannot enforce that — `dominates`/`meet`/`Grants` are all derived by
    /// iterating this array, not by matching on `Scope`), and `bit`'s `u8` needs to stay wide
    /// enough for it.
    pub const ALL: [Scope; 2] = [Scope::ReadOnly, Scope::Full];

    /// This scope's bit in a [`Grants`] bitset — its position in `ALL`. Never exposed: callers
    /// combine scopes through `Grants`, never through the bit pattern directly.
    fn bit(self) -> u8 {
        1u8 << Scope::ALL
            .iter()
            .position(|s| *s == self)
            .expect("Scope::ALL enumerates every variant")
    }

    /// Does holding `self` confer everything holding `other` confers? DERIVED from `allows`
    /// (never a hand-written table — a second encoding of the scope model is the exact drift
    /// hazard `Grants` exists to remove): `self` dominates `other` iff every requirement `other`
    /// satisfies, `self` also satisfies. In the two-rung chain `Full` dominates `ReadOnly` (and
    /// itself); `ReadOnly` dominates only itself.
    pub fn dominates(self, other: Scope) -> bool {
        Scope::ALL
            .iter()
            .all(|n| !other.allows(*n) || self.allows(*n))
    }

    /// The greatest scope conferring no more than EITHER operand — the ceiling operator (the
    /// MEET of the two-rung chain): the lower of the two, i.e. `ReadOnly` unless both are `Full`.
    pub fn meet(self, other: Scope) -> Scope {
        if self.dominates(other) {
            other
        } else if other.dominates(self) {
            self
        } else {
            Scope::ReadOnly
        }
    }
}

/// The EFFECTIVE authority of a principal: a SET of scopes. Roles UNION into it (`with`); a
/// ceiling MEETS each member (`capped_by`). Bitset over `Scope::ALL` — `Copy`, no allocation.
/// Kept as a set (rather than a single `Scope`) so role aggregation and ceiling arithmetic go
/// through the same drift-proof `allows`/`meet` seam the scope model derives from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Grants(u8);

impl Grants {
    /// The single-scope grant.
    pub fn of(s: Scope) -> Self {
        Grants(s.bit())
    }

    /// UNION — add `s` to the held grants.
    pub fn with(self, s: Scope) -> Self {
        Grants(self.0 | s.bit())
    }

    /// Pointwise `meet` against a ceiling — replaces `std::cmp::min`. Each held scope is capped
    /// independently, so a principal capped below one of two incomparable grants doesn't lose the
    /// other, and a ceiling incomparable with a grant reduces that grant to `ReadOnly` rather than
    /// inventing or preserving authority the ceiling was meant to cut.
    pub fn capped_by(self, cap: Scope) -> Self {
        Scope::ALL
            .iter()
            .filter(|s| self.contains(**s))
            .fold(Grants::default(), |acc, s| acc.with(s.meet(cap)))
    }

    /// The authorization check: does ANY held scope satisfy `needed`? This is the disjunction
    /// `allows` was always meant to be evaluated as once a principal can hold more than one
    /// grant.
    pub fn allows(self, needed: Scope) -> bool {
        Scope::ALL
            .iter()
            .any(|s| self.contains(*s) && s.allows(needed))
    }

    /// Exact membership — for the few callers that must name one specific scope, not "does this
    /// authorize X".
    pub fn contains(self, s: Scope) -> bool {
        self.0 & s.bit() != 0
    }
}
