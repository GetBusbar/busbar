// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod amend;
pub mod auditlog;
pub mod journal;
pub mod stream_registry;
pub mod vocab {
    pub use busbar_contract::vocab::*;
}

pub const MAX_AUDIT_ENTRIES: usize = 1000;

use std::marker::PhantomData;

pub(crate) use busbar_kernel_audit::digest::{Digest, Framing};

pub(crate) fn frame_prelude(
    framing: Framing,
    prev_hash: &str,
    scope: Option<&str>,
    seq: u64,
) -> Vec<u8> {
    let mut d = Digest::new(framing);
    d.text(prev_hash);
    if let Some(s) = scope {
        d.text(s);
    }
    d.num(seq);
    d.into_framed()
}

/// The operator-facing words for one stream: what to call the chain, and what to call the thing a
/// chain is scoped to. Carried by a [`ChainBreak`] so the message names WHICH log to go and look at
/// without the error type having to be generic over the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ChainLabels {
    /// Written as it should read mid-sentence, e.g. "the per-call chain".
    pub(crate) chain: &'static str,
    /// The noun for what one chain is scoped TO: "principal", "task", "log".
    pub(crate) scope: &'static str,
}

pub(crate) trait ChainedRecord: Sized {
    type Input;

    const LABELS: &'static ChainLabels;

    const FRAMING: Framing;

    fn framing(&self) -> Framing {
        Self::FRAMING
    }

    fn scope_of(&self) -> &str;
    fn seq(&self) -> u64;
    fn prev_hash(&self) -> &str;
    fn hash(&self) -> &str;

    fn link(scope: &str, seq: u64, prev_hash: String, input: Self::Input) -> Self;

    fn set_hash(&mut self, hash: String);

    fn digest_fields(&self, d: &mut Digest);
}

pub(crate) fn digest<R: ChainedRecord>(record: &R) -> String {
    let mut d = Digest::new(record.framing());
    record.digest_fields(&mut d);
    d.finish()
}

pub(crate) fn seal<R: ChainedRecord>(
    scope: &str,
    seq: u64,
    prev_hash: String,
    input: R::Input,
) -> R {
    let mut record = R::link(scope, seq, prev_hash, input);
    record.set_hash(digest(&record));
    record
}

pub(crate) struct Chain<R> {
    tail_hash: String,

    next_seq: u64,

    _record: PhantomData<fn() -> R>,
}

impl<R> Default for Chain<R> {
    fn default() -> Self {
        Chain {
            tail_hash: String::new(),
            next_seq: 1,
            _record: PhantomData,
        }
    }
}

impl<R> Clone for Chain<R> {
    fn clone(&self) -> Self {
        Chain {
            tail_hash: self.tail_hash.clone(),
            next_seq: self.next_seq,
            _record: PhantomData,
        }
    }
}

impl<R> std::fmt::Debug for Chain<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chain")
            .field("tail_hash", &self.tail_hash)
            .field("next_seq", &self.next_seq)
            .finish()
    }
}

impl<R> PartialEq for Chain<R> {
    fn eq(&self, other: &Self) -> bool {
        self.tail_hash == other.tail_hash && self.next_seq == other.next_seq
    }
}

impl<R> Eq for Chain<R> {}

impl<R: ChainedRecord> Chain<R> {
    pub(crate) fn new() -> Self {
        Chain {
            tail_hash: String::new(),
            next_seq: 1,
            _record: PhantomData,
        }
    }

    pub(crate) fn from_persisted(records: &[R]) -> Result<Self, ChainBreak> {
        verify_chain(records)?;
        Ok(Self::from_persisted_unverified(records))
    }

    pub(crate) fn from_persisted_unverified(records: &[R]) -> Self {
        match records.last() {
            None => Chain::new(),
            Some(last) => Chain {
                tail_hash: last.hash().to_string(),
                next_seq: last.seq().saturating_add(1),
                _record: PhantomData,
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub(crate) fn append(&mut self, scope: &str, input: R::Input) -> R {
        let record: R = seal(scope, self.next_seq, self.tail_hash.clone(), input);
        self.tail_hash = record.hash().to_string();
        self.next_seq = self.next_seq.saturating_add(1);
        record
    }
}

/// WHY a chain failed to verify. Four distinguishable causes, because the operator's response to
/// each is different — a verifier that returns `bool` tells an operator that something is wrong and
/// nothing else, which in practice means it is run once and then ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBreakKind {
    /// This record's stored `hash` is not the digest of its own fields: a field was edited in place.
    DigestMismatch { stored: String, recomputed: String },
    /// This record's `prev_hash` is not the previous record's `hash`: something was inserted,
    /// removed, or reordered around here.
    LinkMismatch { expected: String, found: String },
    /// The sequence is not contiguous: a gap (records removed) or a duplicate/regression. A link
    /// check alone misses this when a whole contiguous run is removed from the TAIL.
    SequenceBreak { expected: u64, found: u64 },
    /// A record from a different scope is present in this chain. A chain is scoped to ONE principal,
    /// task or log; mixing them would make one caller's evidence depend on another caller's rows.
    ForeignScope { expected: String, found: String },
}

/// A verification failure: WHERE it is and WHAT it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The 1-based index INTO THE SLICE at which the break was found. Distinct from `seq`, which is
    /// itself untrustworthy on a `SequenceBreak` — reporting only `seq` would report the tampered
    /// value as if it were a position.
    pub(crate) at_index: usize,
    /// The record's claimed sequence number.
    pub seq: u64,
    /// The scope the chain is scoped to (the principal id, the task id, …).
    pub scope: String,
    /// The stream's own words, carried so the message names WHICH log an operator has to go and
    /// look at without this type being generic over the record.
    pub(crate) labels: &'static ChainLabels,
    pub kind: ChainBreakKind,
}

impl std::fmt::Display for ChainBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} for {} `{}` BROKEN at index {} (seq {}): ",
            self.labels.chain, self.labels.scope, self.scope, self.at_index, self.seq
        )?;
        match &self.kind {
            ChainBreakKind::DigestMismatch { stored, recomputed } => write!(
                f,
                "the record's own fields do not hash to its stored digest (stored {stored}, \
                 recomputed {recomputed}) — this record was EDITED"
            ),
            ChainBreakKind::LinkMismatch { expected, found } => write!(
                f,
                "prev_hash does not match the preceding record's hash (expected {expected}, found \
                 {found}) — a record was INSERTED, REMOVED or REORDERED here"
            ),
            ChainBreakKind::SequenceBreak { expected, found } => write!(
                f,
                "sequence is not contiguous (expected {expected}, found {found}) — records were \
                 REMOVED or DUPLICATED"
            ),
            ChainBreakKind::ForeignScope { expected, found } => write!(
                f,
                "a record belonging to {} `{found}` appears in {} `{expected}`'s chain",
                self.labels.scope, self.labels.scope
            ),
        }
    }
}

pub(crate) fn verify_chain<R: ChainedRecord>(records: &[R]) -> Result<(), ChainBreak> {
    walk(records, Anchor::Genesis)
}

#[cfg(test)]
pub(crate) fn verify_window<R: ChainedRecord>(records: &[R]) -> Result<(), ChainBreak> {
    walk(records, Anchor::Window)
}

enum Anchor {
    Genesis,

    #[cfg(test)]
    Window,
}

fn walk<R: ChainedRecord>(records: &[R], anchor: Anchor) -> Result<(), ChainBreak> {
    let Some(first) = records.first() else {
        return Ok(());
    };
    let scope = first.scope_of().to_string();
    let (mut expected_prev, mut expected_seq) = match anchor {
        Anchor::Genesis => (String::new(), 1u64),
        #[cfg(test)]
        Anchor::Window => (first.prev_hash().to_string(), first.seq()),
    };

    for (i, rec) in records.iter().enumerate() {
        let at_index = i + 1;
        let brk = |kind| ChainBreak {
            at_index,
            seq: rec.seq(),
            scope: scope.clone(),
            labels: R::LABELS,
            kind,
        };
        if rec.scope_of() != scope {
            return Err(brk(ChainBreakKind::ForeignScope {
                expected: scope.clone(),
                found: rec.scope_of().to_string(),
            }));
        }
        if rec.seq() != expected_seq {
            return Err(brk(ChainBreakKind::SequenceBreak {
                expected: expected_seq,
                found: rec.seq(),
            }));
        }

        if rec.prev_hash() != expected_prev {
            return Err(brk(ChainBreakKind::LinkMismatch {
                expected: expected_prev.clone(),
                found: rec.prev_hash().to_string(),
            }));
        }
        let recomputed = digest(rec);
        if recomputed != rec.hash() {
            return Err(brk(ChainBreakKind::DigestMismatch {
                stored: rec.hash().to_string(),
                recomputed,
            }));
        }
        expected_prev = rec.hash().to_string();
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/audit_entry_record.rs"]
pub(crate) mod audit_entry_record;

#[cfg(test)]
#[path = "tests/chain_tests.rs"]
mod chain_tests;

#[cfg(test)]
#[path = "tests/boot_verify_golden.rs"]
mod boot_verify_golden;
