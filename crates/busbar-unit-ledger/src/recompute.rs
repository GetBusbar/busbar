// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The recompute: pricing every line again by lookup, from the dated history it was priced under.
//!
//! ## What a ledger line is now, and what it is not
//!
//! A line carries QUANTITIES and the instant they happened. It also carries the number of the
//! history head it was settled under, the entry that head resolved to at that instant, and the
//! currency the bucket is denominated in. It carries a price as well — and that price is a CACHE.
//! It is re-derivable from the quantities and the history at any moment, it is kept only so that a
//! read does not have to walk a day of lines, and where it disagrees with the lookup the lookup is
//! right.
//!
//! ## Why the recompute became the arbiter
//!
//! It used to be an auditor: it repriced from a sealed policy, compared, and alarmed, because it
//! did not know which of the two numbers was correct. Under a dated history it does know. The
//! history is append-only and journalled, the quantities are immutable, and the lookup over the two
//! is a pure function — so the lookup IS the amount, and a stored figure that differs from it is by
//! definition the stale one. So a disagreement is corrected here rather than only reported.
//!
//! That does not make every disagreement ordinary. Two cases have to be told apart, and telling
//! them apart is the whole of [`Verdict`]:
//!
//! - The head has ADVANCED since the line was settled. Somebody amended the history behind this
//!   line, the cache was computed under an older snapshot, and it going stale is exactly what an
//!   amendment does. Correct it, journal the correction, do not alarm.
//! - The head has NOT moved. Nothing legitimate can have changed the answer, so the quantities or
//!   the cache have been edited by hand. Correct it AND alarm: this is the tamper case the
//!   recompute exists for, and it must not be laundered into a routine cache refresh.
//!
//! ## Why the watermark is a line and not a checkpoint
//!
//! The obvious design is "recompute everything since the last checkpoint". It is wrong, and the
//! reason is arithmetic rather than taste: at a busy node's rate a checkpoint is a few tens of
//! milliseconds old, so "since the last checkpoint" covers a few percent of the lines and quietly
//! skips the rest. Worse, a line edited before the last checkpoint would then never be looked at
//! again — which is exactly the line somebody would edit.
//!
//! So the watermark is the last `node_seq` that was actually recomputed FOR EACH NODE, it is carried
//! in the reconciliation entry so it survives a restart, and the requirement is that it REACHES THE
//! HEAD each tick. A hand-corrupted amount older than the last checkpoint still alarms, and that is
//! stated as a test rather than as a paragraph.
//!
//! Per node, because lines arrive interleaved. One `(node, node_seq)` pair for the whole run,
//! compared lexicographically, is ahead of every line a lower-numbered node writes from the
//! moment it passes a higher-numbered one — so those lines are skipped permanently and the pass
//! calls itself clean over money it never looked at.
//!
//! ## The origin rule on the fee line
//!
//! The per-request fee is charged on client-originated work and not on the rest, so the recompute
//! applies the same rule: a line whose origin is not a client prices its fee line at zero. On a
//! deployment with no rate card the fee line is the whole of what the recompute checks.

use std::collections::BTreeMap;

use busbar_caps::MeterClassId;
use busbar_unit_cost::{
    price, CurrencyCode, History, HistorySeq, HistoryView, Posting as CostPosting, Priced,
    Quantity, Unpriceable,
};

use crate::totals::TotalsKey;

/// Ten thousand basis points is full price.
pub const BASIS_POINTS: u32 = 10_000;

/// The dated card history the recompute reads, and the tier each bucket's chain is on.
///
/// A trait so the recompute reads a SEALED history rather than live configuration: pricing a
/// two-day-old line against today's card would report every price change as a defect. Under the
/// dated model that statement gets sharper — the history is the record of what things cost and
/// since when, so "the card at this line's instant, under the snapshot this line was settled at" is
/// a question with one answer forever.
pub trait HistoryArchive {
    /// The history as it stood at `at`: every entry with `seq <= at`. `None` when the archive has
    /// no snapshot at that number at all, which is itself a finding.
    fn view_at(&self, at: HistorySeq) -> Option<HistoryView<'_>>;

    /// The head the history has reached NOW. This is what decides whether a stale cache is an
    /// ordinary consequence of an amendment or a line somebody edited.
    fn head(&self) -> Option<HistorySeq>;

    /// The tier for `key`, in basis points. Ten thousand when none was sealed, which is full price.
    fn tier_bp(&self, key: &TotalsKey) -> u32;
}

/// A history with the tiers that went with it — the archive the recompute reads.
///
/// The tier is a property of the chain a request was admitted through rather than of the card, so
/// it cannot live inside a `CardEntry`; it is sealed beside the history for the same reason the
/// history is sealed at all, which is that repricing against a tier somebody changed yesterday
/// would report every tier change as a defect.
#[derive(Debug, Clone, Default)]
pub struct SealedHistory {
    /// The dated cards.
    pub history: History,
    /// The tier in basis points, per bucket key. Absent means full price.
    pub tiers: BTreeMap<TotalsKey, u32>,
}

impl SealedHistory {
    /// An archive over a history with no tiers sealed — every bucket at full price.
    pub fn new(history: History) -> Self {
        SealedHistory {
            history,
            tiers: BTreeMap::new(),
        }
    }
}

impl HistoryArchive for SealedHistory {
    fn view_at(&self, at: HistorySeq) -> Option<HistoryView<'_>> {
        let head = self.history.head()?;
        (at <= head).then(|| self.history.snapshot(at))
    }

    fn head(&self) -> Option<HistorySeq> {
        self.history.head()
    }

    fn tier_bp(&self, key: &TotalsKey) -> u32 {
        self.tiers.get(key).copied().unwrap_or(BASIS_POINTS)
    }
}

/// One quantity, against one declared class. The stored truth: no rate, no product, no money.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PricedLine {
    /// Which class.
    pub class: MeterClassId,
    /// How much of it.
    pub quantity: u64,
}

/// Where a unit came from, as far as the fee line is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostingOrigin {
    /// A client asked for this work; the per-request fee applies.
    Client,
    /// The node did this for its own reasons; the fee line prices at zero.
    Internal,
}

/// The price the node computed at settlement — **a cache, never a truth**.
///
/// It is kept for two reasons and neither of them is authority: a totals read that repriced a day
/// of lines on every request would be a different performance profile, and a stored figure to
/// compare the lookup against is what makes a hand edit detectable at all. Where it disagrees with
/// the lookup, the lookup wins and this is corrected in place.
///
/// It says what it is true OF as well as what it is, and that is the point: a figure that named no
/// snapshot would be a number with no way to tell "computed under an older history" from "wrong".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedPrice {
    /// The history head the figure was computed under.
    pub history_seq: HistorySeq,
    /// The entry that head resolved to at the line's instant.
    pub card_seq: HistorySeq,
    /// The amount before the tier was applied.
    pub pre_tier_nanos: i128,
    /// The amount after it.
    pub priced_nanos: i128,
}

impl Default for DerivedPrice {
    /// Nothing, at the opening entry.
    ///
    /// The opening entry rather than an invented sentinel, because [`HistorySeq::OPENING`] is a
    /// real snapshot belonging to a real card: a migrated row's price genuinely is current as of
    /// entry zero, so the default is the honest answer for one rather than a placeholder.
    fn default() -> Self {
        DerivedPrice {
            history_seq: HistorySeq::OPENING,
            card_seq: HistorySeq::OPENING,
            pre_tier_nanos: 0,
            priced_nanos: 0,
        }
    }
}

/// One booked ledger line, as the journal holds it.
///
/// **A booked line is never rewritten.** Everything above [`Posting::cached`] is what happened, and
/// what happened does not change: an amendment to the history moves money by emitting an adjusting
/// entry against this line, not by editing it. The one field this crate ever writes back is the
/// cache, and that is because the cache was never the record in the first place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posting {
    /// Which node wrote it.
    pub node: u64,
    /// That node's sequence number for it.
    pub node_seq: u64,
    /// Which balance it belongs to.
    pub key: TotalsKey,
    /// Which window.
    pub window_start: u64,
    /// The serving lane — the key the card is priced by, and the reason the books now keep it.
    pub lane: String,
    /// The quantities. THE STORED TRUTH.
    pub lines: Vec<PricedLine>,
    /// How many request fees the line carries.
    pub fee_count: u64,
    /// The tier applied, in basis points, as the line recorded it.
    pub tier_bp: u32,
    /// The instant it happened, in wall-clock milliseconds. The scale the history resolves at.
    pub arrived_ms: u64,
    /// The currency the bucket is denominated in. Two currencies never sum.
    pub currency: CurrencyCode,
    /// The cached lookup, and the two history numbers it is current as of. Derived, correctable,
    /// and never the record.
    pub cached: DerivedPrice,
    /// Whether the fee line applies.
    pub origin: PostingOrigin,
}

impl Posting {
    /// The identity the watermark advances over.
    pub fn position(&self) -> (u64, u64) {
        (self.node, self.node_seq)
    }

    /// The history snapshot the line's price is current as of.
    ///
    /// It travels with the price rather than beside it because it is a fact ABOUT the price. What
    /// the line was ORIGINALLY priced under, once an amendment has moved it, is not lost either —
    /// it is on the adjusting entry, which carries both card numbers and both figures and is never
    /// collapsed into the lines it describes.
    pub fn history_seq(&self) -> HistorySeq {
        self.cached.history_seq
    }

    /// The dated entry that snapshot resolves to at this line's instant.
    pub fn card_seq(&self) -> HistorySeq {
        self.cached.card_seq
    }

    /// Whether this line predates the history — a row migrated from the previous release.
    ///
    /// Such a row was earned under the one card the migration sealed, so it reads as priced under
    /// [`HistorySeq::OPENING`] at both numbers: the opening entry is effective from instant zero
    /// with no end, so it covers every instant a legacy row could carry, and there is no earlier
    /// snapshot it could have meant.
    pub fn is_pre_history(&self) -> bool {
        self.cached.history_seq == HistorySeq::OPENING
            && self.cached.card_seq == HistorySeq::OPENING
    }
}

/// Why the recompute disagreed with a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// No entry of the snapshot covers the line's instant. A hole in the history is a refusal and
    /// never a zero: pricing an uncovered instant at nothing is how a gap becomes free service.
    NoCardInForce {
        /// The instant that fell in the hole.
        at: u64,
    },
    /// The archive holds no snapshot at the number the line names, so its price cannot be rechecked
    /// at all. That is itself a finding: a line priced under a history nobody kept.
    HistoryMissing {
        /// Which snapshot.
        seq: HistorySeq,
    },
    /// The card in force does not name the line's currency. NEVER converted from another.
    CurrencyNotPriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The currency the line is denominated in.
        currency: CurrencyCode,
    },
    /// The card in force names no rate for the line's lane.
    LaneUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The lane the card is silent about.
        lane: String,
    },
    /// The card in force names the line's currency but no FLAT FEE in it. Present but unpriced is
    /// never a silent zero: a fee read as nothing bills the line's fees for free and says nothing.
    FeeUnpriced {
        /// The entry that was in force.
        card_seq: HistorySeq,
        /// The currency the card names no fee in.
        currency: CurrencyCode,
    },
    /// The entry the line says it resolved to is not the entry the snapshot resolves to.
    CardSeq {
        /// What the line says.
        posted: HistorySeq,
        /// What the lookup resolves to.
        resolved: HistorySeq,
    },
    /// The cached pre-tier figure does not match the lookup.
    PreTier {
        /// What the cache says.
        posted: i128,
        /// What the lookup makes it.
        recomputed: i128,
    },
    /// The tier the line recorded is not the tier the archive holds.
    Tier {
        /// What the line says.
        posted: u32,
        /// What the archive says.
        sealed: u32,
    },
    /// The cached priced figure does not match the lookup. This is the one that moves money.
    Priced {
        /// What the cache says.
        posted: i128,
        /// What the lookup makes it.
        recomputed: i128,
    },
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Divergence::NoCardInForce { at } => {
                write!(f, "no card is in force at instant {at}")
            }
            Divergence::HistoryMissing { seq } => {
                write!(f, "no history snapshot at {seq} to reprice against")
            }
            Divergence::CurrencyNotPriced { card_seq, currency } => write!(
                f,
                "the card at history entry {card_seq} does not price {currency}"
            ),
            Divergence::LaneUnpriced { card_seq, lane } => write!(
                f,
                "the card at history entry {card_seq} names no rate for lane {lane}"
            ),
            Divergence::FeeUnpriced { card_seq, currency } => write!(
                f,
                "the card at history entry {card_seq} names no per-request fee in {currency}"
            ),
            Divergence::CardSeq { posted, resolved } => write!(
                f,
                "the line was priced under history entry {posted}; the snapshot resolves {resolved}"
            ),
            Divergence::PreTier { posted, recomputed } => write!(
                f,
                "the pre-tier amount is {posted} in the cache and {recomputed} on the lookup"
            ),
            Divergence::Tier { posted, sealed } => write!(
                f,
                "the line recorded a tier of {posted} basis points; the archive holds {sealed}"
            ),
            Divergence::Priced { posted, recomputed } => write!(
                f,
                "the priced amount is {posted} in the cache and {recomputed} on the lookup"
            ),
        }
    }
}

/// What a disagreement MEANS, which is a different question from what it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The head has moved since the line was settled, so the cache is stale for a reason the
    /// deployment consented to. Correct it, journal the correction, and do not alarm.
    Stale,
    /// The head has NOT moved, so nothing legitimate can have changed the answer. Correct it AND
    /// alarm: this is the hand edit the recompute exists to catch, and routing it through the same
    /// quiet path as an amendment would be the way to launder one.
    Alarm,
}

/// One line the recompute disagreed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Which node wrote it.
    pub node: u64,
    /// That node's sequence number for it.
    pub node_seq: u64,
    /// What the disagreement is.
    pub divergence: Divergence,
    /// Whether it is an amendment catching up or somebody's hand.
    pub verdict: Verdict,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let verdict = match self.verdict {
            Verdict::Stale => "stale cache",
            Verdict::Alarm => "ALARM",
        };
        write!(
            f,
            "line {}/{} ({verdict}): {}",
            self.node, self.node_seq, self.divergence
        )
    }
}

/// What one recheck concluded about one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recheck {
    /// Everything the lookup disagreed with, in a fixed order.
    pub divergences: Vec<Divergence>,
    /// The lookup's answer, when it could be taken at all. The cache is corrected TO this — it is
    /// `None` only when the line could not be priced, and an unpriceable line's cache is left
    /// alone, because overwriting a figure with a refusal would turn a hole into a zero.
    pub corrected: Option<DerivedPrice>,
    /// What the disagreement means.
    pub verdict: Verdict,
}

impl Recheck {
    /// Whether the lookup agreed with the line in every respect.
    pub fn agrees(&self) -> bool {
        self.divergences.is_empty()
    }
}

/// How far the recompute has got, PER NODE. Carried in the reconciliation entry so it survives a
/// restart, because a watermark that resets at boot checks nothing on a node that restarts often.
///
/// One mark per node rather than one pair for the whole run, and the reason is that lines arrive
/// interleaved. A single `(node, node_seq)` pair compared lexicographically is ahead of everything a
/// lower-numbered node writes as soon as it passes a higher-numbered one, so those lines are
/// skipped — not deferred, skipped, permanently — and the pass reports itself clean over an amount
/// it declined to look at. A mark per node cannot do that: each node's lines are measured against
/// that node's own progress and nobody else's.
///
/// Nodes are few and their marks are numbers, so this is a small ordered map. Ordered because it is
/// sealed into a reconciliation entry that gets digested, exactly like the book's own keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watermark {
    marks: BTreeMap<u64, u64>,
}

impl Watermark {
    /// The beginning: nothing has been recomputed.
    pub fn start() -> Self {
        Watermark::default()
    }

    /// A watermark from marks a reconciliation entry carried, or a test states.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (u64, u64)>) -> Self {
        let mut watermark = Watermark::start();
        for (node, node_seq) in pairs {
            watermark.advance(node, node_seq);
        }
        watermark
    }

    /// How far `node` has been recomputed, if it has been at all.
    pub fn mark_for(&self, node: u64) -> Option<u64> {
        self.marks.get(&node).copied()
    }

    /// Every mark, by node, in the order a sealed entry writes them.
    pub fn pairs(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.marks.iter().map(|(&node, &seq)| (node, seq))
    }

    /// How many nodes have a mark.
    pub fn nodes(&self) -> usize {
        self.marks.len()
    }

    /// Whether `posting` is after its own node's mark and therefore still owed a recompute.
    pub fn is_behind(&self, posting: &Posting) -> bool {
        match self.marks.get(&posting.node) {
            Some(&mark) => posting.node_seq > mark,
            None => true,
        }
    }

    /// Move `node`'s mark to `node_seq`. A mark only ever moves forward: a line that arrived out
    /// of order behind a number already recomputed must not re-open everything after it.
    pub fn advance(&mut self, node: u64, node_seq: u64) {
        let mark = self.marks.entry(node).or_insert(node_seq);
        *mark = u64::max(*mark, node_seq);
    }
}

impl std::fmt::Display for Watermark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.marks.is_empty() {
            return f.write_str("nothing recomputed yet");
        }
        let mut first = true;
        for (node, seq) in self.pairs() {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{node}/{seq}")?;
            first = false;
        }
        Ok(())
    }
}

/// What one pass of the recompute did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    /// The history snapshot every line in this pass was repriced against.
    ///
    /// On the pass rather than only on each corrected figure, because it is what makes a
    /// reconciliation entry re-derivable: an auditor holding the entry knows which head produced
    /// these findings without having to infer it from the lines. `None` for a pass over an archive
    /// with no history at all, which is the state of a node that has read no configuration yet.
    pub history_seq: Option<HistorySeq>,
    /// Where the watermark is now.
    pub watermark: Watermark,
    /// How many lines were checked.
    pub checked: usize,
    /// How many caches were corrected in place. Every one of these owes a journalled
    /// reconciliation entry, which is the caller's to write: this crate does not touch a disk.
    pub corrected: usize,
    /// Everything the recompute disagreed with, stale and alarming alike.
    pub findings: Vec<Finding>,
}

impl Pass {
    /// Whether every line checked out.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Whether anything needs an operator, as opposed to a journal line.
    ///
    /// A pass full of stale caches after an amendment is not an alarm; a single one under an
    /// unmoved head is.
    pub fn alarms(&self) -> bool {
        self.findings.iter().any(|f| f.verdict == Verdict::Alarm)
    }
}

/// The lookup's answer for one line under one snapshot, at the archive's tier.
///
/// This is the single place the ledger asks what a line costs. It builds the cost unit's posting
/// from the line's own quantities and hands it to the one lookup, rather than re-deriving a product
/// out of a card's parts: a second copy of the multiply-and-sum is how a request comes to be judged
/// at one figure and billed at another, and that has happened here before.
pub fn price_line(
    posting: &Posting,
    view: &HistoryView<'_>,
    tier_bp: u32,
) -> Result<Priced, Unpriceable> {
    let cost = CostPosting {
        lane: posting.lane.clone(),
        quantities: posting
            .lines
            .iter()
            .map(|line| Quantity::new(line.class.as_str(), line.quantity))
            .collect(),
        // The origin rule, applied by charging no fees rather than by a branch further down: a line
        // the node did for its own reasons carries no client request to charge one for.
        fee_count: match posting.origin {
            PostingOrigin::Client => posting.fee_count,
            PostingOrigin::Internal => 0,
        },
        tier_bp,
        arrived_ms: posting.arrived_ms,
        arrived_mono: 0,
        estimated: false,
        cached: None,
    };
    price(view, &cost, posting.currency)
}

/// Name a refusal from the lookup in the recompute's own vocabulary.
///
/// One conversion, in one place, so that a statement and a recheck report the same hole in the same
/// words rather than two callers each deciding what a refusal is called.
pub fn divergence_of(why: Unpriceable) -> Divergence {
    match why {
        Unpriceable::NoCardInForce { at } => Divergence::NoCardInForce { at },
        Unpriceable::CurrencyNotPriced { card_seq, currency } => {
            Divergence::CurrencyNotPriced { card_seq, currency }
        }
        Unpriceable::LaneUnpriced { card_seq, lane } => Divergence::LaneUnpriced { card_seq, lane },
        Unpriceable::FeeUnpriced { card_seq, currency } => {
            Divergence::FeeUnpriced { card_seq, currency }
        }
    }
}

/// Narrow a lookup's unsigned nano-units into the book's signed vocabulary, saturating.
///
/// Saturating rather than wrapping for the reason the whole money path saturates: a figure that
/// wrapped lands negative, and a negative amount in a settled column reads as a credit nobody
/// issued. A saturated figure can only ever disagree, which is an answer an alarm is allowed to
/// give.
fn signed(nanos: u128) -> i128 {
    i128::try_from(nanos).unwrap_or(i128::MAX)
}

/// Price one line again by lookup **at the archive's head**, and report every way the cache
/// disagrees with it.
///
/// At the head, not at the snapshot the cache names, and that is the whole of the arbitration. The
/// head is what the history says today; the cache is what it said when the line was settled. Asking
/// the cache's own snapshot would only ever confirm the cache, which is a check that cannot fail.
///
/// The order is deliberate: an empty archive or an unpriceable line short-circuits, because there
/// is nothing to compare against and reporting a pre-tier mismatch of "everything" would bury the
/// real finding.
pub fn recheck(posting: &Posting, archive: &dyn HistoryArchive) -> Recheck {
    // The verdict is decided from the head alone, BEFORE anything is priced, so that it cannot be
    // influenced by what the comparison happens to find. A head that has moved past the snapshot
    // this line's price is current as of is consent for that price to be behind; a head that has
    // not moved is not.
    let head = archive.head();
    let verdict = match head {
        Some(head) if head > posting.cached.history_seq => Verdict::Stale,
        _ => Verdict::Alarm,
    };
    let refuse = |divergence: Divergence| Recheck {
        divergences: vec![divergence],
        corrected: None,
        verdict,
    };

    // Two ways to have no history to check against, and they are the same finding: an archive that
    // holds nothing, and a line whose price claims a snapshot the archive has never reached. The
    // second is a line asserting a history nobody kept, which is exactly what this variant names.
    let Some(head) = head else {
        return refuse(Divergence::HistoryMissing {
            seq: posting.cached.history_seq,
        });
    };
    if posting.cached.history_seq > head {
        return refuse(Divergence::HistoryMissing {
            seq: posting.cached.history_seq,
        });
    }
    let Some(view) = archive.view_at(head) else {
        return refuse(Divergence::HistoryMissing { seq: head });
    };

    let sealed_tier = archive.tier_bp(&posting.key);
    let priced = match price_line(posting, &view, sealed_tier) {
        Ok(priced) => priced,
        Err(why) => return refuse(divergence_of(why)),
    };

    let mut divergences = Vec::new();
    if priced.card_seq != posting.cached.card_seq {
        divergences.push(Divergence::CardSeq {
            posted: posting.cached.card_seq,
            resolved: priced.card_seq,
        });
    }

    let pre_tier = signed(priced.pre_tier_nanos);
    if pre_tier != posting.cached.pre_tier_nanos {
        divergences.push(Divergence::PreTier {
            posted: posting.cached.pre_tier_nanos,
            recomputed: pre_tier,
        });
    }

    if sealed_tier != posting.tier_bp {
        divergences.push(Divergence::Tier {
            posted: posting.tier_bp,
            sealed: sealed_tier,
        });
    }

    let final_nanos = signed(priced.priced_nanos);
    if final_nanos != posting.cached.priced_nanos {
        divergences.push(Divergence::Priced {
            posted: posting.cached.priced_nanos,
            recomputed: final_nanos,
        });
    }

    Recheck {
        divergences,
        corrected: Some(DerivedPrice {
            history_seq: head,
            card_seq: priced.card_seq,
            pre_tier_nanos: pre_tier,
            priced_nanos: final_nanos,
        }),
        verdict,
    }
}

/// Apply a tier in basis points to a pre-tier amount.
///
/// Integer arithmetic, multiply before divide, so a tier of 9,999 basis points on a small amount
/// does not round to nothing through a division that happened first. The multiply saturates, so a
/// figure at the ceiling stays at the ceiling rather than wrapping through it.
///
/// One multiply and ONE divide, over the summed pre-tier amount — never a sum of per-line floors,
/// which undercharges: two lines of five nano-units at half price are two floors of two, which is
/// four, where the single divide over ten is five.
pub fn apply_tier(pre_tier: i128, tier_bp: u32) -> i128 {
    pre_tier.saturating_mul(i128::from(tier_bp)) / i128::from(BASIS_POINTS)
}

/// Recompute every line after `watermark`, correcting stale caches in place, and advance the
/// watermark to the head.
///
/// The lines are taken by mutable reference because the cache is the one field this crate writes
/// back, and it writes back only the cache: every quantity, instant and sequence number on a booked
/// line is left exactly as it was. Correcting rather than only alarming is what makes an amendment
/// a normal event; leaving the quantities alone is what keeps the line a record.
///
/// The watermark advances over a line the recompute disagreed with, on purpose: the divergence
/// has been reported, and a watermark that stalled on the first bad line would stop checking
/// everything after it — which is how one alarm hides a hundred.
pub fn recompute(
    watermark: Watermark,
    postings: &mut [Posting],
    archive: &dyn HistoryArchive,
) -> Pass {
    let mut at = watermark;
    let mut checked = 0usize;
    let mut corrected = 0usize;
    let mut findings = Vec::new();
    for posting in postings.iter_mut() {
        if !at.is_behind(posting) {
            continue;
        }
        checked += 1;
        let outcome = recheck(posting, archive);
        for divergence in outcome.divergences {
            findings.push(Finding {
                node: posting.node,
                node_seq: posting.node_seq,
                divergence,
                verdict: outcome.verdict,
            });
        }
        if let Some(fresh) = outcome.corrected {
            if fresh != posting.cached {
                posting.cached = fresh;
                corrected += 1;
            }
        }
        at.advance(posting.node, posting.node_seq);
    }
    Pass {
        history_seq: archive.head(),
        watermark: at,
        checked,
        corrected,
        findings,
    }
}
