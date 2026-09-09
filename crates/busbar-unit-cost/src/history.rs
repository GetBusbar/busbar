// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated rate-card history: what things cost, and since when.
//!
//! A rate card is not a value that gets replaced. It is an APPEND-ONLY DATED HISTORY of entries
//! `(effective_from, card)`, and a price is a lookup into it at the instant a posting happened. That
//! is the whole difference between "a price change reprices history" and "a price change prices what
//! happens after it".
//!
//! Two orderings live here and they are deliberately different things:
//!
//! - `seq` ORDERS the entries. It is dense and monotone, assigned on append, and it is what an
//!   invoice names when it says which history it was cut against. An entry's `seq` never changes.
//! - `effective_from` DATES an entry. It is wall-clock milliseconds, the same scale a unit's arrival
//!   is recorded in, and it may run BACKWARDS between consecutive entries — that is exactly what a
//!   back-dated amendment is.
//!
//! Because the two orderings differ, the resolution rule has to name one of them, and it names
//! `seq`: among the entries a snapshot can see whose interval covers an instant, the one with the
//! HIGHEST `seq` wins. Overlap is legal and is the point. An amendment does not delete the entry it
//! corrects and does not rewrite it; it out-ranks it, and both are on the record forever.

use crate::rate::RateCard;

/// An entry's own number: dense, monotone, assigned on append.
///
/// THIS IS THE CARD IDENTITY, and it is the only one. It replaces the free-text version name the
/// card used to carry and the bare `u64` the journal, the migration marker and the opening balance
/// each spelled separately — one number, meaning one thing, readable by all of them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HistorySeq(pub u64);

impl HistorySeq {
    /// The opening entry's number. A migration seals a single-entry history at this seq, effective
    /// from instant zero, so every instant a legacy row could carry is covered by it.
    pub const OPENING: HistorySeq = HistorySeq(0);

    /// The number as the journal, the marker and the store all spell it.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for HistorySeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Why an entry exists. The distinction is the whole audit trail: an operator reading the history
/// can tell an ordinary price change from a correction of the past without comparing timestamps.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Author {
    /// Sealed at bootstrap or migration: the opening entry, effective from instant zero.
    Opening,
    /// A configuration write, or a reload. Effective from the moment it was appended, never before.
    Config {
        /// The policy epoch the configuration that produced it belonged to.
        policy_epoch: u64,
    },
    /// The signed amendment verb. Effective from an instant the operator named, which is in the
    /// past — that is what makes it an amendment rather than a configuration write.
    Amend {
        /// Who signed it.
        operator_fingerprint: String,
        /// The digest of the stated reason. The reason itself is free text and is not the record;
        /// its hash is, so the record is fixed-width and the text cannot be edited under it.
        reason_hash: [u8; 32],
    },
}

/// One entry of the history: a card, and the window of instants it prices.
#[derive(Clone, Debug)]
pub struct CardEntry {
    seq: HistorySeq,
    effective_from: u64,
    effective_until: Option<u64>,
    card: RateCard,
    appended_at: u64,
    author: Author,
}

impl CardEntry {
    /// This entry's number. Assigned on append and never changed.
    pub fn seq(&self) -> HistorySeq {
        self.seq
    }

    /// The first instant this entry prices, inclusive, in wall-clock milliseconds.
    pub fn effective_from(&self) -> u64 {
        self.effective_from
    }

    /// The first instant it does NOT price, exclusive. `None` is open-ended.
    pub fn effective_until(&self) -> Option<u64> {
        self.effective_until
    }

    /// The card itself.
    pub fn card(&self) -> &RateCard {
        &self.card
    }

    /// When the entry was WRITTEN, in wall-clock milliseconds.
    ///
    /// Equal to [`Self::effective_from`] for a configuration write; strictly greater for a
    /// back-dated amendment. The two being separate fields is the whole of what makes a back-date
    /// visible: one field would have made a correction of the past indistinguishable from a price
    /// that was always there.
    pub fn appended_at(&self) -> u64 {
        self.appended_at
    }

    /// Why this entry exists.
    pub fn author(&self) -> &Author {
        &self.author
    }

    /// Whether this entry's interval covers `t`: `effective_from <= t < effective_until`.
    pub fn covers(&self, t: u64) -> bool {
        t >= self.effective_from && self.effective_until.is_none_or(|until| t < until)
    }
}

/// An entry before it has a number. The number is the history's to assign, never the caller's — a
/// caller that could choose a `seq` could write over an entry that already exists.
#[derive(Clone, Debug)]
pub struct CardEntryDraft {
    /// The first instant the new entry prices, inclusive.
    pub effective_from: u64,
    /// The first instant it does not, exclusive. `None` is open-ended.
    pub effective_until: Option<u64>,
    /// The card.
    pub card: RateCard,
    /// When the entry is being written.
    pub appended_at: u64,
    /// Why.
    pub author: Author,
}

/// The whole history: append-only, ordered by `seq`, NEVER by `effective_from`.
///
/// Sorting by date would be the natural-looking thing and it would destroy the design: two entries
/// covering the same instant are precisely how a correction is expressed, and the one that wins is
/// the one that was written LAST, not the one that starts latest.
#[derive(Clone, Debug, Default)]
pub struct History {
    entries: Vec<CardEntry>,
}

impl History {
    /// An empty history. Nothing is priceable against it — every instant is a hole — which is the
    /// honest state for a node that has read no configuration yet.
    pub fn new() -> Self {
        History {
            entries: Vec::new(),
        }
    }

    /// **THE MIGRATION HELPER.** A single-entry history: the operator's card, effective from instant
    /// zero, open-ended, authored as the opening entry.
    ///
    /// `card_at` then returns entry zero for every instant, so a lookup against this history is
    /// arithmetically the 1.5.5 read-time derivation at that card — same rates, same order, same
    /// saturation, same single truncation. That equality is what "exact for a single-entry history"
    /// names, and it is why a deployment that never edits a price sees no change at all.
    ///
    /// Effective from ZERO rather than from the migration instant, deliberately: pre-migration rows
    /// carry no instant finer than the UTC day, and they were earned under this card by definition.
    /// An entry starting at the seal would leave every one of them in a hole.
    pub fn opening(card: RateCard, appended_at: u64) -> Self {
        let mut history = History::new();
        history.append(CardEntryDraft {
            effective_from: 0,
            effective_until: None,
            card,
            appended_at,
            author: Author::Opening,
        });
        history
    }

    /// The newest entry's number, or `None` for a history nothing has been appended to.
    ///
    /// `None` rather than a zero: zero is a real seq belonging to a real opening entry, and a head
    /// that answered zero for an empty history would let a caller snapshot an entry that is not
    /// there and read a hole as a card.
    pub fn head(&self) -> Option<HistorySeq> {
        self.entries.last().map(CardEntry::seq)
    }

    /// Every entry, in `seq` order.
    pub fn entries(&self) -> &[CardEntry] {
        &self.entries
    }

    /// How many entries there are.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// **THE REPRODUCIBILITY PRIMITIVE.** Everything with `seq <= at`.
    ///
    /// An invoice cut at a snapshot is re-derivable forever by asking for that snapshot again: the
    /// entries it could see are exactly the entries it can see now, because no entry is ever removed
    /// and no entry's `seq` ever moves. A snapshot above the head sees the whole history rather than
    /// refusing — the caller that asked for a seq that does not exist yet is the one place a refusal
    /// belongs, and it belongs at the endpoint that took the parameter, not in the arithmetic.
    pub fn snapshot(&self, at: HistorySeq) -> HistoryView<'_> {
        let count = self.entries.partition_point(|e| e.seq <= at);
        HistoryView {
            entries: &self.entries[..count],
            at,
        }
    }

    /// The whole history as it stands. Equivalent to snapshotting at the head.
    pub fn current(&self) -> HistoryView<'_> {
        HistoryView {
            entries: &self.entries,
            at: self.head().unwrap_or(HistorySeq::OPENING),
        }
    }

    /// **THE ONLY MUTATOR.** Append an entry and return its number.
    ///
    /// It never modifies an entry that already exists — not even to close the previous open one.
    /// Closing would be a rewrite, and there is no need for one: the resolution rule takes the
    /// highest covering `seq`, so an open-ended entry appended later already out-ranks the
    /// open-ended entry before it at every instant they share.
    pub fn append(&mut self, draft: CardEntryDraft) -> HistorySeq {
        let seq = HistorySeq(self.entries.len() as u64);
        self.entries.push(CardEntry {
            seq,
            effective_from: draft.effective_from,
            effective_until: draft.effective_until,
            card: draft.card,
            appended_at: draft.appended_at,
            author: draft.author,
        });
        seq
    }
}

/// The history as one snapshot saw it: the entries with `seq <= at`, borrowed.
///
/// A view is a borrowed slice and a number. It reads no clock and owns nothing, so a lookup through
/// it allocates nothing and an auditor holding the postings and the history re-derives every invoice
/// by hand.
#[derive(Clone, Copy, Debug)]
pub struct HistoryView<'a> {
    entries: &'a [CardEntry],
    at: HistorySeq,
}

impl HistoryView<'_> {
    /// **THE RESOLUTION RULE.** Among the entries this snapshot can see whose interval covers `t`,
    /// the one with the HIGHEST `seq` wins.
    ///
    /// Overlap is legal and is the point: an amendment does not delete the entry it corrects, it
    /// out-ranks it, and asking an older snapshot still returns the older answer. `None` means no
    /// entry covers `t` at all — a hole, which is a refusal and never a zero. A zero would price a
    /// gap in the record as a free request.
    pub fn card_at(&self, t: u64) -> Option<(HistorySeq, &RateCard)> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.covers(t))
            .map(|e| (e.seq, &e.card))
    }

    /// The entry this view resolved to at `t`, whole.
    pub fn entry_at(&self, t: u64) -> Option<&CardEntry> {
        self.entries.iter().rev().find(|e| e.covers(t))
    }

    /// The snapshot this view is.
    pub fn seq(&self) -> HistorySeq {
        self.at
    }

    /// The entries the snapshot can see.
    pub fn entries(&self) -> &[CardEntry] {
        self.entries
    }

    /// Whether the snapshot can see nothing at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
