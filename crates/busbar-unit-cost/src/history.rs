// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dated rate-card history: what things cost, and since when.
//!
//! This is layer 1 of three. Layer 0 is the quantities — what happened, and when. Layer 2 is the
//! lookup — a pure function of the other two. Both journals here are APPEND-ONLY, and that is what
//! makes an invoice reproducible: name the two inputs and you get the same answer forever.
//!
//! # The two orderings, and why there are two
//!
//! An entry carries a SEQUENCE NUMBER and an EFFECTIVE WINDOW, and they are not the same ordering.
//!
//! - `seq` is the order entries were WRITTEN. Dense, monotone, assigned on append, never reused.
//!   It is the card's identity: "priced against entry 7" says which card AND says when in the
//!   record's life that card was known.
//! - `effective_from` / `effective_until` is the window the card APPLIES to, in wall-clock
//!   milliseconds — the same scale an arrival's wall reading is in.
//!
//! For a card written today and effective today the two agree, and nothing interesting happens. For
//! a BACK-DATED card the two disagree, and their disagreement is the whole audit trail: a later
//! `seq` covering an earlier window is exactly what a correction to the past looks like, and it is
//! visible as such because the entry it corrects is still there.
//!
//! # Why nothing is ever closed
//!
//! Appending an entry does NOT reach back and end the previous one. Overlap is legal and it is the
//! point: [`HistoryView::card_at`] resolves an instant covered by several entries by taking the
//! HIGHEST `seq`, so a correction out-ranks what it corrects instead of deleting it. Closing the
//! previous entry would be a write to a record already made — the one thing this whole design exists
//! to prevent — and it would lose the original figure that a reader needs in order to see what
//! moved.

use crate::rate::RateCard;

/// An entry's own number: dense, monotone, assigned on append.
///
/// THIS IS THE CARD IDENTITY. It replaces the string version the card used to carry and the several
/// `u64` spellings of the same idea that grew up around the journal, the migration marker and the
/// opening balance — one number, one meaning, one type.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HistorySeq(pub u64);

impl HistorySeq {
    /// The opening entry's number: the card a deployment migrated in under.
    pub const OPENING: HistorySeq = HistorySeq(0);

    /// The number as the journal, the marker and the store row record it.
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for HistorySeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Why an entry exists. The distinction is the whole audit trail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Author {
    /// Sealed at bootstrap or migration: the opening entry, effective from the beginning of time.
    Opening,
    /// A configuration write, or a config reload. Effective from the moment it was appended, which
    /// is why such an entry can never move a figure already earned.
    Config {
        /// The policy epoch the write landed in, so the entry can be tied back to the config
        /// generation that produced it.
        policy_epoch: u64,
    },
    /// The signed amend verb. Effective from an instant the operator named, which may be in the
    /// past — and the operator's identity and the hash of their stated reason travel with it
    /// forever, because a back-dated price change with nobody's name on it is the failure mode this
    /// author variant exists to make impossible.
    Amend {
        /// Who signed it.
        operator_fingerprint: String,
        /// A hash of the stated reason. The reason itself is free text and belongs in the record
        /// that carries it; what the entry keeps is the binding, not the prose.
        reason_hash: [u8; 32],
    },
}

/// One entry of the history: a card, and the window it applies to.
#[derive(Clone, Debug)]
pub struct CardEntry {
    /// This entry's number. Assigned by [`History::append`] and never chosen by a caller.
    pub seq: HistorySeq,
    /// Inclusive, wall-clock milliseconds. The same scale an arrival's wall reading is in.
    pub effective_from: u64,
    /// Exclusive. `None` is open-ended, which is what an ordinary configuration write produces.
    pub effective_until: Option<u64>,
    /// The card itself.
    pub card: RateCard,
    /// When the entry was WRITTEN. Equal to `effective_from` for an ordinary write; strictly
    /// greater for a back-dated amend. THE TWO BEING SEPARATE FIELDS IS WHAT MAKES A BACK-DATE
    /// VISIBLE — collapse them and a correction to the past is indistinguishable from a card that
    /// was always there.
    pub appended_at: u64,
    /// Why this entry exists.
    pub author: Author,
}

impl CardEntry {
    /// Whether this entry's window covers an instant: `effective_from` inclusive, `effective_until`
    /// exclusive, an absent end meaning open forever.
    ///
    /// Half-open on purpose. Two adjacent entries meeting at an instant must cover it exactly once
    /// between them, and inclusive-inclusive would make the boundary instant belong to both — which
    /// is not a hole but is a coin toss, and a price decided by a coin toss is not reproducible.
    pub fn covers(&self, t: u64) -> bool {
        t >= self.effective_from && self.effective_until.is_none_or(|until| t < until)
    }
}

/// An entry as a caller proposes it: everything a [`CardEntry`] has except the number, which is the
/// history's to assign.
///
/// The `seq` is absent from this type rather than ignored on it. A draft that carried a number a
/// caller could fill in is a draft that can claim a number already used, and "the number is dense
/// and monotone" would then be a convention rather than a property.
#[derive(Clone, Debug)]
pub struct CardEntryDraft {
    /// Inclusive, wall-clock milliseconds.
    pub effective_from: u64,
    /// Exclusive; `None` is open-ended.
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
/// Ordered by `seq` is not a storage detail. Sorting by effective date would put a back-dated
/// correction BEFORE the entry it corrects, and the resolution rule — later writer wins — would then
/// resolve backwards. The vector is in write order because write order is what the rule reads.
#[derive(Clone, Debug, Default)]
pub struct History {
    entries: Vec<CardEntry>,
}

impl History {
    /// An empty history. Every instant is a hole until something is appended, and a hole is a
    /// refusal rather than a zero.
    pub fn new() -> Self {
        History::default()
    }

    /// **THE MIGRATION'S HISTORY**: exactly one entry, effective from instant 0, open-ended.
    ///
    /// This is what a 1.5.5 deployment becomes. Entry 0 covers every instant there has ever been,
    /// so [`HistoryView::card_at`] answers with it for every posting — including the legacy rows
    /// that carry no instant finer than the UTC day, which is correct, because entry 0 is the card
    /// they were earned under by definition. With one entry the lookup is arithmetically the older
    /// release's read-time derivation at that card: same rates, same order, same saturation, same
    /// single truncation.
    ///
    /// It also closes an honesty gap. The migration marker's recorded card used to be the operator's
    /// claim about what history was earned under, and nothing checked it. Here it is not a claim:
    /// entry 0 IS the card, it is journaled, and if it was the wrong card the fix is an amend from 0
    /// to the migration instant — which leaves adjusting entries. A wrong opening becomes fixable
    /// and visible instead of unfixable and invisible.
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

    /// The newest entry's number. An empty history has no head and answers `None`.
    pub fn head(&self) -> Option<HistorySeq> {
        self.entries.last().map(|e| e.seq)
    }

    /// Every entry, in write order.
    pub fn entries(&self) -> &[CardEntry] {
        &self.entries
    }

    /// How many entries the history holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing has been appended yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Everything with `seq <= at`.
    ///
    /// THE REPRODUCIBILITY PRIMITIVE. An invoice cut at snapshot `S` is re-derivable forever by
    /// asking for `snapshot(S)` again: the entries it saw are a prefix of the entries there are, and
    /// a prefix of an append-only journal cannot change. Two reads at the same snapshot are equal
    /// forever, whatever has happened to the card since.
    pub fn snapshot(&self, at: HistorySeq) -> HistoryView<'_> {
        // Dense and monotone from zero, so the prefix length is the number itself plus one — but
        // the search is written as a partition rather than as arithmetic on the number, because a
        // history recovered from a journal that lost a record must answer with the entries it
        // actually has rather than with the entries their numbers imply.
        let end = self.entries.partition_point(|e| e.seq <= at);
        HistoryView {
            entries: &self.entries[..end],
            at,
        }
    }

    /// The view over everything appended so far. `None` for an empty history.
    pub fn latest(&self) -> Option<HistoryView<'_>> {
        self.head().map(|head| self.snapshot(head))
    }

    /// **THE ONLY MUTATOR.** Appends an entry and returns its number.
    ///
    /// It takes `&mut self` and pushes; there is no method here that can reach an entry already
    /// written, which is how "append-only" is a property of the type rather than a rule somebody
    /// remembers. In particular appending does NOT close the previous entry's window: overlap is
    /// legal, and [`HistoryView::card_at`] resolves it by taking the highest `seq`.
    pub fn append(&mut self, draft: CardEntryDraft) -> HistorySeq {
        let seq = HistorySeq(self.entries.last().map_or(0, |e| e.seq.0 + 1));
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

/// The history as it stood at one snapshot: a borrowed prefix, and the number it is a prefix at.
///
/// Borrowed rather than owned, and a slice rather than a copy: pricing a day of postings takes one
/// view and reads it once per posting, so a view that cloned the cards would clone them per read.
#[derive(Clone, Copy, Debug)]
pub struct HistoryView<'a> {
    entries: &'a [CardEntry],
    at: HistorySeq,
}

impl<'a> HistoryView<'a> {
    /// The snapshot this view is at — the number an invoice cut from it prints, and the number that
    /// regenerates it.
    pub fn seq(&self) -> HistorySeq {
        self.at
    }

    /// The entries this snapshot can see.
    pub fn entries(&self) -> &'a [CardEntry] {
        self.entries
    }

    /// **THE RESOLUTION RULE.** Among the entries this snapshot can see whose window covers `t`,
    /// the one with the HIGHEST `seq` wins.
    ///
    /// Highest `seq`, not nearest date and not longest window: the later WRITER wins. That is what
    /// makes a correction a correction. An amend does not delete the entry it corrects — it
    /// out-ranks it, and both stay on the record, which is what lets a reader see the original
    /// figure and the correction side by side forever.
    ///
    /// `None` means no visible entry covers `t` at all — a hole. A hole is a refusal, never a zero:
    /// pricing an instant nobody has said the price of at zero is a node giving its service away and
    /// reporting that it did so as a fact.
    pub fn card_at(&self, t: u64) -> Option<(HistorySeq, &'a RateCard)> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.covers(t))
            .map(|e| (e.seq, &e.card))
    }
}
