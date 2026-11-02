// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The GENERIC authorization lattice — `Scope`, the strict two-rung chain (`ReadOnly` / `Full`),

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
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "read-only" => Some(Scope::ReadOnly),
            "full" => Some(Scope::Full),
            _ => None,
        }
    }

    /// Whether a principal holding `self` may call an endpoint requiring `needed`. A strict
    pub fn allows(self, needed: Scope) -> bool {
        match needed {
            Scope::ReadOnly => true,

            Scope::Full => self == Scope::Full,
        }
    }

    /// Every scope, for the closure operations below. Adding a variant means adding it here too
    pub const ALL: [Scope; 2] = [Scope::ReadOnly, Scope::Full];

    /// This scope's bit in a [`Grants`] bitset — its position in `ALL`. Never exposed: callers
    fn bit(self) -> u8 {
        1u8 << Scope::ALL
            .iter()
            .position(|s| *s == self)
            .expect("Scope::ALL enumerates every variant")
    }

    /// Does holding `self` confer everything holding `other` confers? DERIVED from `allows`
    pub fn dominates(self, other: Scope) -> bool {
        Scope::ALL
            .iter()
            .all(|n| !other.allows(*n) || self.allows(*n))
    }

    /// The greatest scope conferring no more than EITHER operand — the ceiling operator (the
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
    pub fn capped_by(self, cap: Scope) -> Self {
        Scope::ALL
            .iter()
            .filter(|s| self.contains(**s))
            .fold(Grants::default(), |acc, s| acc.with(s.meet(cap)))
    }

    /// The authorization check: does ANY held scope satisfy `needed`? This is the disjunction
    pub fn allows(self, needed: Scope) -> bool {
        Scope::ALL
            .iter()
            .any(|s| self.contains(*s) && s.allows(needed))
    }

    /// Exact membership — for the few callers that must name one specific scope, not "does this
    pub fn contains(self, s: Scope) -> bool {
        self.0 & s.bit() != 0
    }
}

#[cfg(test)]
#[path = "tests/authz_tests.rs"]
mod tests;
