// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The independent recompute: pricing every posting again, from the policy it was priced under.
//!
//! ## Why "independent" is the load-bearing word
//!
//! The pricing path and the checking path must not share code, because a bug in shared code passes
//! its own check. So this walks the postings and reprices them from the sealed policy — the rate
//! card at the posting's card version, the per-request fee, and the bucket's tier — and compares
//! the answer to the figure the posting carries. A divergence is an alarm, not a correction: the
//! recompute does not know which of the two numbers is right, only that they disagree.
//!
//! ## Why the watermark is a posting and not a checkpoint
//!
//! The obvious design is "recompute everything since the last checkpoint". It is wrong, and the
//! reason is arithmetic rather than taste: at a busy node's rate a checkpoint is a few tens of
//! milliseconds old, so "since the last checkpoint" covers a few percent of the postings and quietly
//! skips the rest. Worse, a posting edited before the last checkpoint would then never be looked at
//! again — which is exactly the posting somebody would edit.
//!
//! So the watermark is the last `node_seq` that was actually recomputed FOR EACH NODE, it is carried
//! in the reconciliation entry so it survives a restart, and the requirement is that it REACHES THE
//! HEAD each tick. A hand-corrupted amount older than the last checkpoint still alarms, and that is
//! stated as a test rather than as a paragraph.
//!
//! Per node, because postings arrive interleaved. One `(node, node_seq)` pair for the whole run,
//! compared lexicographically, is ahead of every posting a lower-numbered node writes from the
//! moment it passes a higher-numbered one — so those postings are skipped permanently and the pass
//! calls itself clean over money it never looked at.
//!
//! ## The origin rule on the fee line
//!
//! The per-request fee is charged on client-originated work and not on the rest, so the recompute
//! applies the same rule: a posting whose origin is not a client prices its fee line at zero. On a
//! deployment with no rate card the fee line is the whole of what the recompute checks, which is
//! why it is not folded into the class loop.

use std::collections::BTreeMap;

use busbar_caps::MeterClassId;

use crate::totals::TotalsKey;

/// A price list, as one policy epoch sealed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateCard {
    /// The card's version, as a posting names it.
    pub version: u64,
    /// What one unit of each declared meter class costs, in nano-units, by class name.
    ///
    /// Keyed by name for the same reason a bucket's dimension is: the card is part of a sealed
    /// policy that gets digested, so its keys need a total order.
    pub prices: BTreeMap<String, i128>,
    /// What one client-originated request costs, in nano-units, before any class line.
    pub per_request_fee: i128,
}

impl RateCard {
    /// An empty card at a version: no class prices, no fee. This is the no-card deployment, and it
    /// is a real configuration rather than a degenerate one.
    pub fn empty(version: u64) -> Self {
        RateCard {
            version,
            prices: BTreeMap::new(),
            per_request_fee: 0,
        }
    }

    /// The price of one unit of `class`, or zero if the card does not name it.
    pub fn price(&self, class: &MeterClassId) -> i128 {
        self.prices.get(class.as_str()).copied().unwrap_or(0)
    }
}

/// What one policy epoch sealed: the cards in force, and the tier that applied to each bucket.
#[derive(Debug, Clone, Default)]
pub struct SealedPolicy {
    /// Which epoch.
    pub epoch: u64,
    /// The cards, by version.
    pub cards: BTreeMap<u64, RateCard>,
    /// The tier in basis points, per bucket key. Absent means no tier, which is ten thousand basis
    /// points — full price.
    pub tiers: BTreeMap<TotalsKey, u32>,
}

impl SealedPolicy {
    /// The card at `version`, if this epoch sealed one.
    pub fn card(&self, version: u64) -> Option<&RateCard> {
        self.cards.get(&version)
    }

    /// The tier for `key`, in basis points. Ten thousand when none was sealed.
    pub fn tier_bp(&self, key: &TotalsKey) -> u32 {
        self.tiers.get(key).copied().unwrap_or(BASIS_POINTS)
    }
}

/// Where the policies live. A trait so the recompute reads sealed policy rather than live
/// configuration: pricing a two-day-old posting against today's card would report every price
/// change as a defect.
pub trait PolicyArchive {
    /// The policy sealed at `epoch`.
    fn at(&self, epoch: u64) -> Option<&SealedPolicy>;
}

impl PolicyArchive for BTreeMap<u64, SealedPolicy> {
    fn at(&self, epoch: u64) -> Option<&SealedPolicy> {
        self.get(&epoch)
    }
}

/// Ten thousand basis points is full price.
pub const BASIS_POINTS: u32 = 10_000;

/// One quantity, against one declared class.
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

/// One posting, as the journal holds it: the inputs to the price, and the price itself.
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
    /// Which policy epoch it was priced under.
    pub policy_epoch: u64,
    /// Which card version.
    pub rate_card_version: u64,
    /// The quantities.
    pub lines: Vec<PricedLine>,
    /// How many request fees the posting carries.
    pub fee_count: u32,
    /// The tier applied, in basis points, as the posting recorded it.
    pub tier_bp: u32,
    /// The amount before the tier was applied.
    pub pre_tier_amount: i128,
    /// The amount after it — the figure the money is actually moved by.
    pub priced_amount: i128,
    /// Whether the fee line applies.
    pub origin: PostingOrigin,
}

impl Posting {
    /// The identity the watermark advances over.
    pub fn position(&self) -> (u64, u64) {
        (self.node, self.node_seq)
    }
}

/// Why the recompute disagreed with a posting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// The policy epoch the posting names was never sealed, so the price cannot be rechecked at
    /// all. That is itself a finding: a posting priced under a policy nobody kept.
    PolicyMissing {
        /// Which epoch.
        epoch: u64,
    },
    /// The card version the posting names is not in the sealed policy.
    CardMissing {
        /// Which epoch.
        epoch: u64,
        /// Which version.
        version: u64,
    },
    /// The pre-tier figure does not match.
    PreTier {
        /// What the posting says.
        posted: i128,
        /// What the recompute makes it.
        recomputed: i128,
    },
    /// The tier the posting recorded is not the tier the sealed policy holds.
    Tier {
        /// What the posting says.
        posted: u32,
        /// What the sealed policy says.
        sealed: u32,
    },
    /// The final figure does not match. This is the one that moves money.
    Priced {
        /// What the posting says.
        posted: i128,
        /// What the recompute makes it.
        recomputed: i128,
    },
}

impl std::fmt::Display for Divergence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Divergence::PolicyMissing { epoch } => {
                write!(f, "no sealed policy at epoch {epoch} to reprice against")
            }
            Divergence::CardMissing { epoch, version } => {
                write!(f, "the policy at epoch {epoch} holds no card version {version}")
            }
            Divergence::PreTier { posted, recomputed } => write!(
                f,
                "the pre-tier amount is {posted} on the posting and {recomputed} on the recompute"
            ),
            Divergence::Tier { posted, sealed } => write!(
                f,
                "the posting recorded a tier of {posted} basis points; the sealed policy holds {sealed}"
            ),
            Divergence::Priced { posted, recomputed } => write!(
                f,
                "the priced amount is {posted} on the posting and {recomputed} on the recompute"
            ),
        }
    }
}

/// One posting the recompute disagreed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Which node wrote it.
    pub node: u64,
    /// That node's sequence number for it.
    pub node_seq: u64,
    /// What the disagreement is.
    pub divergence: Divergence,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "posting {}/{}: {}",
            self.node, self.node_seq, self.divergence
        )
    }
}

/// How far the recompute has got, PER NODE. Carried in the reconciliation entry so it survives a
/// restart, because a watermark that resets at boot checks nothing on a node that restarts often.
///
/// One mark per node rather than one pair for the whole run, and the reason is that postings arrive
/// interleaved. A single `(node, node_seq)` pair compared lexicographically is ahead of everything a
/// lower-numbered node writes as soon as it passes a higher-numbered one, so those postings are
/// skipped — not deferred, skipped, permanently — and the pass reports itself clean over an amount
/// it declined to look at. A mark per node cannot do that: each node's postings are measured against
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

    /// Move `node`'s mark to `node_seq`. A mark only ever moves forward: a posting that arrived out
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
    /// Where the watermark is now.
    pub watermark: Watermark,
    /// How many postings were checked.
    pub checked: usize,
    /// Everything the recompute disagreed with.
    pub findings: Vec<Finding>,
}

impl Pass {
    /// Whether every posting checked out.
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

/// Price one posting again from the sealed policy, and report every way it disagrees.
///
/// The order is deliberate: a missing policy or card short-circuits, because there is nothing to
/// compare against and reporting a pre-tier mismatch of "everything" would bury the real finding.
pub fn recheck(posting: &Posting, policies: &dyn PolicyArchive) -> Vec<Divergence> {
    let Some(policy) = policies.at(posting.policy_epoch) else {
        return vec![Divergence::PolicyMissing {
            epoch: posting.policy_epoch,
        }];
    };
    let Some(card) = policy.card(posting.rate_card_version) else {
        return vec![Divergence::CardMissing {
            epoch: posting.policy_epoch,
            version: posting.rate_card_version,
        }];
    };

    let mut found = Vec::new();

    // The class lines, then the fee line. The fee line is separate because the origin rule applies
    // to it and to nothing else, and because on a no-card deployment it is the whole check.
    // Saturating, like the pricing path this exists to check. A figure that wrapped could land back
    // on the posted one and report a clean pass over a posting that is wrong; a figure that
    // saturates can only ever disagree, which is the answer an alarm is allowed to give.
    let mut pre_tier: i128 = 0;
    for line in &posting.lines {
        pre_tier = pre_tier.saturating_add(
            card.price(&line.class)
                .saturating_mul(i128::from(line.quantity)),
        );
    }
    if posting.origin == PostingOrigin::Client {
        pre_tier = pre_tier.saturating_add(
            card.per_request_fee
                .saturating_mul(i128::from(posting.fee_count)),
        );
    }
    if pre_tier != posting.pre_tier_amount {
        found.push(Divergence::PreTier {
            posted: posting.pre_tier_amount,
            recomputed: pre_tier,
        });
    }

    let sealed_tier = policy.tier_bp(&posting.key);
    if sealed_tier != posting.tier_bp {
        found.push(Divergence::Tier {
            posted: posting.tier_bp,
            sealed: sealed_tier,
        });
    }

    let priced = apply_tier(pre_tier, sealed_tier);
    if priced != posting.priced_amount {
        found.push(Divergence::Priced {
            posted: posting.priced_amount,
            recomputed: priced,
        });
    }
    found
}

/// Apply a tier in basis points to a pre-tier amount.
///
/// Integer arithmetic, multiply before divide, so a tier of 9,999 basis points on a small amount
/// does not round to nothing through a division that happened first. The multiply saturates, so a
/// figure at the ceiling stays at the ceiling rather than wrapping through it.
pub fn apply_tier(pre_tier: i128, tier_bp: u32) -> i128 {
    pre_tier.saturating_mul(i128::from(tier_bp)) / i128::from(BASIS_POINTS)
}

/// Recompute every posting after `watermark`, in order, and advance the watermark to the head.
///
/// The watermark advances over a posting the recompute DISAGREED with, on purpose: the divergence
/// has been reported, and a watermark that stalled on the first bad posting would stop checking
/// everything after it — which is how one alarm hides a hundred.
pub fn recompute(watermark: Watermark, postings: &[Posting], policies: &dyn PolicyArchive) -> Pass {
    let mut at = watermark;
    let mut checked = 0usize;
    let mut findings = Vec::new();
    for posting in postings {
        if !at.is_behind(posting) {
            continue;
        }
        checked += 1;
        for divergence in recheck(posting, policies) {
            findings.push(Finding {
                node: posting.node,
                node_seq: posting.node_seq,
                divergence,
            });
        }
        at.advance(posting.node, posting.node_seq);
    }
    Pass {
        watermark: at,
        checked,
        findings,
    }
}
