// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HEAD HISTORY: the permanent hourly anchors and the current tip.
//!
//! A head says "at position N the chain was THIS". A puller compares it with a head retained
//! outside the node; a window's range read includes its anchor ([`HeadHistory::anchor_at`]).
//!
//! The composition root persists samples and the current tip in an independent Store schema.
//! Its existing journal lane commits a sealed record's final part and head checkpoint atomically.
//! Boot restores these anchors independently of the source records; a deployment predating that
//! schema is backfilled from its complete journal before it can accept new writes. This crate
//! owns the sampling and restoration rules, and opens no Store or filesystem itself.
//!
//! ## Why keeping them all is affordable
//!
//! A head is a position, a digest, a signature, a key identifier and a clock. Hourly sampling adds
//! 8 760 samples per year; serialized records and Store indexes add their own overhead. Sampling
//! bounds the growth rate, never the lifetime of an anchor.
//!
//! ## Sampled, plus the tip
//!
//! Two things are kept and they answer different questions. The SAMPLE SERIES is one head per
//! [`HEAD_SAMPLE_SECONDS`] window, and it is append-only: an entry once written is never rewritten
//! and never dropped. The TIP is the most recent head there is, replaced every seal, because "what
//! is the head right now" is the other question a puller asks and the answer to it changes
//! constantly. [`HeadHistory::series`] gives the samples; [`HeadHistory::tip`] gives the tip, which
//! is what the head read answers with; [`HeadHistory::anchors`] gives both, in position order,
//! which is what a window's anchor is chosen from.

use crate::record::AuditRecord;

/// How often a head joins the permanent series: one per hour.
///
/// Hourly retains 8 760 sampled heads per year and is fine enough that the anchor for any window
/// a puller missed is at most an hour older
/// than the window's start.
pub const HEAD_SAMPLE_SECONDS: u64 = 3_600;

/// ONE HEAD: what the chain's tip was, and who says so.
///
/// The five fields the head read answers with, and the five a counter-signer needs: where in the
/// chain, what the digest was, the signature over it, which key minted that signature, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
    /// The position of the record this was the head after.
    pub seq: u64,
    /// That record's digest — the head itself.
    pub hash: String,
    /// The signature over the digest, absent on a node that seals unsigned.
    pub signature: Option<String>,
    /// Which key minted the signature, absent for the same reason.
    pub key_id: Option<String>,
    /// The wall clock the record carried, in unix seconds.
    pub wall: u64,
}

impl SignedHead {
    /// The head as it stood after one record was sealed.
    #[must_use]
    pub fn of(record: &AuditRecord) -> Self {
        SignedHead {
            seq: record.seq,
            hash: record.hash.clone(),
            signature: record.signature.clone(),
            key_id: record.key_id.clone(),
            wall: record.wall,
        }
    }
}

/// THE ANCHORS THIS NODE HAS PUBLISHED, and nothing that can remove one.
///
/// Read the module comment for where they come from. The API is deliberately missing a `prune`, a
/// `retain`, a `truncate` and a `clear`: the type cannot express the loss of an anchor.
#[derive(Debug, Clone)]
pub struct HeadHistory {
    sample_seconds: u64,
    series: Vec<SignedHead>,
    tip: Option<SignedHead>,
}

impl Default for HeadHistory {
    fn default() -> Self {
        HeadHistory::new()
    }
}

impl HeadHistory {
    /// A history sampling at [`HEAD_SAMPLE_SECONDS`].
    #[must_use]
    pub fn new() -> Self {
        HeadHistory::every(HEAD_SAMPLE_SECONDS)
    }

    /// A history sampling at a chosen rate.
    ///
    /// A rate of zero means EVERY head joins the series. That is a legitimate setting for a node
    /// whose chain is slow — an admin-mutation-rate chain seals a few records a day — and a
    /// ruinous one for a request-rate chain, which is why it is not the default.
    #[must_use]
    pub fn every(sample_seconds: u64) -> Self {
        HeadHistory {
            sample_seconds,
            series: Vec::new(),
            tip: None,
        }
    }

    /// Restore independently retained hourly samples and their current tip.
    ///
    /// # Errors
    /// The samples are unordered, omit genesis, disagree with the tip, or violate the hourly rule.
    pub fn from_retained(
        series: Vec<SignedHead>,
        tip: Option<SignedHead>,
    ) -> Result<Self, &'static str> {
        let Some(tip) = tip else {
            return if series.is_empty() {
                Ok(Self::new())
            } else {
                Err("audit samples have no tip")
            };
        };
        if series.first().is_none_or(|head| head.seq != 1)
            || series.windows(2).any(|pair| {
                pair[0].seq >= pair[1].seq
                    || pair[1].wall.saturating_sub(pair[0].wall) < HEAD_SAMPLE_SECONDS
            })
            || series
                .last()
                .is_none_or(|head| head.seq > tip.seq || head.seq == tip.seq && head != &tip)
        {
            return Err("invalid retained audit head history");
        }
        Ok(Self {
            sample_seconds: HEAD_SAMPLE_SECONDS,
            series,
            tip: Some(tip),
        })
    }

    /// Take the head as it stands after one sealed record.
    ///
    /// The FIRST head always joins the series, whatever the clock says: the genesis anchor is the
    /// one a window-verifier needs to know the chain started where it says it did, and a rule that
    /// waited for the first sample boundary would skip it.
    pub(crate) fn observe(&mut self, record: &AuditRecord) {
        let head = SignedHead::of(record);
        let sample_due = match self.series.last() {
            None => true,
            Some(last) => record.wall.saturating_sub(last.wall) >= self.sample_seconds,
        };
        if sample_due {
            self.series.push(head.clone());
        }
        self.tip = Some(head);
    }

    /// The permanent sample series, oldest first.
    #[must_use]
    pub fn series(&self) -> &[SignedHead] {
        &self.series
    }

    /// The most recent head, which is what the head read answers with.
    #[must_use]
    pub fn tip(&self) -> Option<&SignedHead> {
        self.tip.as_ref()
    }

    /// Every anchor this node can offer, in position order: the series, then the tip if the tip is
    /// not already the last sample.
    #[must_use]
    pub fn anchors(&self) -> Vec<SignedHead> {
        let mut out = self.series.clone();
        if let Some(tip) = &self.tip {
            if out.last().map(|h| h.seq) != Some(tip.seq) {
                out.push(tip.clone());
            }
        }
        out
    }

    /// THE ANCHOR FOR A WINDOW: the newest anchor at or before a position.
    ///
    /// This is the question a puller that was offline asks. It has a run of records ending at
    /// position N, it cannot see anything before that, and it wants something independently
    /// recorded to tie that run to. The answer is the last head this node published at or before N.
    #[must_use]
    pub fn anchor_at(&self, seq: u64) -> Option<SignedHead> {
        self.anchors().into_iter().rfind(|h| h.seq <= seq)
    }

    /// How many anchors there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.anchors().len()
    }

    /// Whether this node has sealed anything yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.series.is_empty() && self.tip.is_none()
    }
}
