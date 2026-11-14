// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Commit dedupe keys: the caller's queue position, never the operation identity.
//!
//! A slotted key names one of the writer's `pending_operations` queue slots and a
//! strictly larger sequence on every lease, minted only by the kernel's persistence
//! facade (it needs a [`SlotSeal`](crate::caps::SlotSeal)). A self-fenced key carries
//! no slot: its candidate can apply at most once by its own predicates, which
//! [`SelfFenced::check`] proves from the candidate's shape before the key exists.

use super::{control, Address, Candidate, ExpectedValue, Mutation, PreparedCandidate};
use crate::abi::store::v4 as wire;

/// Exclusive upper bound of a writer's queue slots.
pub const MAX_SLOTS: u32 = wire::MAX_SLOTS;
/// Slot value of a self-fenced key; its sequence is always zero.
pub const SLOT_SELF_FENCED: u32 = wire::SLOT_SELF_FENCED;

/// The dedupe key a commit travels with. The loader reads it; only the facade
/// (slotted) or a proven self-fenced candidate (self-fenced) can make one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitKey {
    slot: u32,
    seq: u64,
}

impl CommitKey {
    /// A leased queue slot and its sequence. `None` unless `slot < MAX_SLOTS` and `seq >= 1`.
    #[must_use]
    pub fn slotted(slot: u32, seq: u64, _seal: &crate::caps::SlotSeal) -> Option<Self> {
        (slot < MAX_SLOTS && seq >= 1).then_some(Self { slot, seq })
    }

    /// The key of a candidate already proven to apply at most once.
    #[must_use]
    pub fn self_fenced(_proof: &SelfFenced) -> Self {
        Self {
            slot: SLOT_SELF_FENCED,
            seq: 0,
        }
    }

    /// The wire `(slot, seq)` pair.
    #[must_use]
    pub fn wire(self) -> (u32, u64) {
        (self.slot, self.seq)
    }

    /// Whether this key bypasses the slot queue.
    #[must_use]
    pub fn is_self_fenced(self) -> bool {
        self.slot == SLOT_SELF_FENCED
    }
}

/// Fixed addresses of the self-fencing record families. Core and the migration
/// library build their records from these, so the witness rule cannot drift.
pub mod witness {
    use super::Address;
    use crate::persistence::NamespaceId;

    /// The core format manifest namespace.
    pub const FORMAT_NAMESPACE: NamespaceId = NamespaceId(*b"busbar.format1\0\0");
    /// The first-start birth record namespace.
    pub const BIRTH_NAMESPACE: NamespaceId = NamespaceId(*b"busbar.birth1\0\0\0");
    /// The birth record's key.
    pub const BIRTH_KEY: &[u8] = b"initial";
    /// The migration coordinator namespace (step witnesses and checkpoints).
    pub const MIGRATION_NAMESPACE: NamespaceId = NamespaceId(*b"busbar.migrate1\0");
    /// The migration intent journal namespace (guard, payload, owner and proofs).
    pub const INTENT_NAMESPACE: NamespaceId = NamespaceId(*b"busbar.migint1\0\0");
    /// Length of an intent guard value.
    pub const GUARD_LEN: usize = 48;

    /// The birth record address.
    #[must_use]
    pub fn birth() -> Address {
        Address {
            namespace: BIRTH_NAMESPACE.0,
            key: BIRTH_KEY.to_vec(),
        }
    }

    /// A migration step's single-shot witness address.
    #[must_use]
    pub fn step(migration: [u8; 16], operation: [u8; 16]) -> Address {
        let mut key = Vec::with_capacity(33);
        key.push(b's');
        key.extend_from_slice(&migration);
        key.extend_from_slice(&operation);
        Address {
            namespace: MIGRATION_NAMESPACE.0,
            key,
        }
    }

    /// An intent-journal record address: `kind` is `g` (guard), `p` (payload),
    /// `w` (owner), `a`/`c` (proofs).
    #[must_use]
    pub fn intent(kind: u8, migration: [u8; 16]) -> Address {
        let mut key = Vec::with_capacity(17);
        key.push(kind);
        key.extend_from_slice(&migration);
        Address {
            namespace: INTENT_NAMESPACE.0,
            key,
        }
    }
}

/// Which witness rule proved the candidate single-shot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessKind {
    /// A Put under `Absent` on a key only this attempt can create.
    Absent,
    /// The intent journal's (guard, payload) pair; applied only on value equality.
    Value,
    /// A Put under `Exact(x)`, `x != v`, on a forward-only record.
    Exact,
}

/// The candidate is not provably single-shot; it cannot be committed self-fenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotSelfFenced;

/// Proof, from the candidate alone, that it can apply at most once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfFenced {
    kind: WitnessKind,
    /// Mutation index of the witness Put; for `Value`, the guard Put.
    put: usize,
    /// For `Value`, the payload Put's mutation index.
    pair: Option<usize>,
    no_aba: bool,
}

const ALLOWED: [[u8; 16]; 5] = [
    control::NAMESPACE.0,
    witness::FORMAT_NAMESPACE.0,
    witness::BIRTH_NAMESPACE.0,
    witness::MIGRATION_NAMESPACE.0,
    witness::INTENT_NAMESPACE.0,
];

impl SelfFenced {
    /// Pick the witness by the named rule, in candidate order: (A), then (V), then (E).
    ///
    /// # Errors
    /// The candidate has a time guard or no admissible witness.
    pub fn check<O>(candidate: &PreparedCandidate<O>) -> Result<Self, NotSelfFenced> {
        let body = candidate.candidate();
        if body.time.is_some() {
            return Err(NotSelfFenced);
        }
        let no_aba = body
            .predicates
            .iter()
            .all(|p| ALLOWED.contains(&p.address.namespace));
        let build = |kind, put, pair| Self {
            kind,
            put,
            pair,
            no_aba,
        };
        if let Some(put) = absent_witness(body) {
            return Ok(build(WitnessKind::Absent, put, None));
        }
        if let Some((guard, payload)) = value_witness(body) {
            return Ok(build(WitnessKind::Value, guard, Some(payload)));
        }
        if let Some(put) = exact_witness(body) {
            return Ok(build(WitnessKind::Exact, put, None));
        }
        Err(NotSelfFenced)
    }

    /// The rule that applied.
    #[must_use]
    pub fn kind(&self) -> WitnessKind {
        self.kind
    }

    /// Whether every predicate is on a namespace whose records never return to an
    /// earlier value; only then is a failed predicate final.
    #[must_use]
    pub fn no_aba(&self) -> bool {
        self.no_aba
    }

    /// Mutation indices of the witness Puts: one for (A)/(E), guard then payload for (V).
    #[must_use]
    pub fn witness_puts(&self) -> (usize, Option<usize>) {
        (self.put, self.pair)
    }
}

fn put<O>(candidate: &Candidate<O>, index: usize) -> Option<(&Address, &[u8])> {
    match candidate.mutations.get(index)? {
        Mutation::Put { address, value } => Some((address, value.0.as_slice())),
        _ => None,
    }
}

fn expected<'a, O>(candidate: &'a Candidate<O>, at: &Address) -> Option<&'a ExpectedValue<O>> {
    candidate
        .predicates
        .iter()
        .find(|p| p.address == *at)
        .map(|p| &p.expected)
}

fn absent_witness<O>(candidate: &Candidate<O>) -> Option<usize> {
    (0..candidate.mutations.len()).find(|&index| {
        let Some((at, value)) = put(candidate, index) else {
            return false;
        };
        if !matches!(expected(candidate, at), Some(ExpectedValue::Absent)) {
            return false;
        }
        if at.namespace == control::NAMESPACE.0 {
            return matches!(control::Key::decode(&at.key), Some(control::Key::Writer(_)))
                && control::Writer::decode(value)
                    == Some(control::Writer {
                        retired_through: 0,
                        admitted_through: 1,
                    });
        }
        at.namespace == witness::MIGRATION_NAMESPACE.0
            && at.key.len() == 33
            && at.key[0] == b's'
            && at.key[17..] == candidate.id.operation
    })
}

fn value_witness<O>(candidate: &Candidate<O>) -> Option<(usize, usize)> {
    (0..candidate.mutations.len()).find_map(|guard| {
        let (at, v_g) = put(candidate, guard)?;
        if at.namespace != witness::INTENT_NAMESPACE.0 || at.key.len() != 17 || at.key[0] != b'g' {
            return None;
        }
        let migration: [u8; 16] = at.key[1..].try_into().ok()?;
        let payload_at = witness::intent(b'p', migration);
        let payload = (0..candidate.mutations.len())
            .find(|&i| put(candidate, i).is_some_and(|(a, _)| *a == payload_at))?;
        let (_, v_p) = put(candidate, payload)?;
        let differs = |value: &[u8], expected: &ExpectedValue<O>| match expected {
            ExpectedValue::Absent => true,
            ExpectedValue::Exact(x) => x.0.as_slice() != value,
        };
        let guard_expected = expected(candidate, at)?;
        let payload_expected = expected(candidate, &payload_at)?;
        if !differs(v_g, guard_expected) && !differs(v_p, payload_expected) {
            return None;
        }
        let guard_ok = v_g.len() == witness::GUARD_LEN
            && &v_g[..8] == b"BSMIGD1\0"
            && v_g[8..24] == migration
            && (1..=5).contains(&v_g[40]);
        let payload_ok = v_p.len() >= 56 && &v_p[..8] == b"BSMINT1\0" && v_p[40..56] == v_g[24..40];
        (guard_ok && payload_ok).then_some((guard, payload))
    })
}

fn exact_witness<O>(candidate: &Candidate<O>) -> Option<usize> {
    (0..candidate.mutations.len()).find(|&index| {
        let Some((at, value)) = put(candidate, index) else {
            return false;
        };
        let Some(ExpectedValue::Exact(x)) = expected(candidate, at) else {
            return false;
        };
        if x.0.as_slice() == value {
            return false;
        }
        (at.namespace == control::NAMESPACE.0
            && matches!(control::Key::decode(&at.key), Some(control::Key::Writer(_))))
            || *at == witness::birth()
    })
}

#[cfg(test)]
#[path = "tests/self_fenced_tests.rs"]
mod tests;
