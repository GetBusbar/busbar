// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! HEAD HISTORY: the permanent hourly anchors and the current tip.

use std::fmt::Write as _;

use crate::record::AuditRecord;

/// How often a head joins the permanent series: one per hour.
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
    pub key_id: Option<std::sync::Arc<str>>,
    /// The wall clock the record carried, in unix seconds.
    pub wall: u64,
}

impl SignedHead {
    /// The head as it stood after one record was sealed.
    #[must_use]
    pub fn of(record: &AuditRecord) -> Self {
        let mut head = SignedHead {
            seq: 0,
            hash: String::new(),
            signature: None,
            key_id: None,
            wall: 0,
        };
        head.overwrite_from(record);
        head
    }

    /// Become the head `record` leaves, reusing this head's storage.
    fn overwrite_from(&mut self, record: &AuditRecord) {
        self.seq = record.seq;
        self.hash.clone_from(&record.hash);
        self.signature.clone_from(&record.signature);
        self.key_id.clone_from(&record.key_id);
        self.wall = record.wall;
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
    /// Observe an unsigned certificate chain tip. A certificate is not itself a signed head;
    /// authenticated page heads are published only after stamp confirmation.
    pub(crate) fn observe_notary_key(&mut self, record: &crate::notary_key::NotaryKeyRecord) {
        let wall = record.linked_ms / 1_000;
        let sample_due = self
            .series
            .last()
            .is_none_or(|last| wall.saturating_sub(last.wall) >= self.sample_seconds);
        // The tip's storage is reused: the fingerprint is written into its hash text in place.
        let tip = self.tip.get_or_insert_with(|| SignedHead {
            seq: 0,
            hash: String::new(),
            signature: None,
            key_id: None,
            wall: 0,
        });
        tip.seq = record.seq;
        tip.hash.clear();
        let _ = write!(tip.hash, "{}", record.fingerprint);
        tip.signature = None;
        tip.key_id = None;
        tip.wall = wall;
        if sample_due {
            self.series.push(tip.clone());
        }
    }

    /// A history sampling at [`HEAD_SAMPLE_SECONDS`].
    #[must_use]
    pub fn new() -> Self {
        HeadHistory::every(HEAD_SAMPLE_SECONDS)
    }

    /// A history sampling at a chosen rate.
    #[must_use]
    pub fn every(sample_seconds: u64) -> Self {
        HeadHistory {
            sample_seconds,
            series: Vec::new(),
            tip: None,
        }
    }

    /// Take the head as it stands after one sealed record.
    pub(crate) fn observe(&mut self, record: &AuditRecord) {
        let sample_due = match self.series.last() {
            None => true,
            Some(last) => record.wall.saturating_sub(last.wall) >= self.sample_seconds,
        };
        match &mut self.tip {
            Some(tip) => tip.overwrite_from(record),
            None => self.tip = Some(SignedHead::of(record)),
        }
        if sample_due {
            if let Some(tip) = &self.tip {
                self.series.push(tip.clone());
            }
        }
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

    /// THE ANCHOR FOR A WINDOW: the newest anchor at or before a position.
    #[must_use]
    pub fn anchor_at(&self, seq: u64) -> Option<SignedHead> {
        match self.unsampled_tip() {
            Some(tip) if tip.seq <= seq => Some(tip.clone()),
            _ => self.series.iter().rfind(|h| h.seq <= seq).cloned(),
        }
    }

    /// The tip, when it is not already the last sample: the one anchor past the series.
    fn unsampled_tip(&self) -> Option<&SignedHead> {
        self.tip
            .as_ref()
            .filter(|tip| self.series.last().map(|h| h.seq) != Some(tip.seq))
    }

    /// How many anchors there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.series.len() + usize::from(self.unsampled_tip().is_some())
    }

    /// Whether this node has sealed anything yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.series.is_empty() && self.tip.is_none()
    }
}
