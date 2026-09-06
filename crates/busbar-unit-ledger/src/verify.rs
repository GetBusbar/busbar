// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Verification: everything that has to be true between two checkpoints.
//!
//! One entry point, four kinds of answer, and each of them names something an operator would do
//! differently. A verifier that returns a boolean tells nobody anything, gets run once, and is then
//! ignored — so this one returns findings.

use crate::checkpoint::Checkpoint;
use crate::identity::{closed_window_is_settled, residual, ClosedWindowMoved, Imbalance};
use crate::totals::{Totals, TotalsKey, WindowStart};

/// Something verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A checkpoint's stored digest is not the digest of the figures it holds: the checkpoint was
    /// edited after it was sealed.
    CheckpointEdited {
        /// Which checkpoint.
        checkpoint_seq: u64,
    },
    /// A node's sequence went BACKWARDS between the two checkpoints. A repeat is not this finding:
    /// a node that posted nothing between the checkpoints is at the sequence it was at, and an idle
    /// node is the ordinary case rather than a defect.
    SequenceNotMonotonic {
        /// Which node.
        node: u64,
        /// Where it was.
        was: u64,
        /// Where it is now.
        now: u64,
    },
    /// The anchored head is not the checkpoint being verified against.
    AnchorHeadDiffers {
        /// What the anchor says.
        anchored: u64,
        /// What is being verified.
        expected: u64,
    },
    /// One balance does not satisfy the identity.
    Imbalanced(Imbalance),
    /// A balance the checkpoint sealed is no longer in the book.
    ///
    /// Its own finding rather than an imbalance, because the two are different events and only one
    /// of them is a defect. A window retired by `Book::retain_from` is gone on purpose — it was
    /// sealed into a checkpoint, signed and shipped, and the book stopped being the record of it.
    /// Measuring what the checkpoint holds against the zeros the book now reads back answers a
    /// question nobody asked, and answers it two different wrong ways depending on the figures:
    /// silence when the sealed balance happens to balance from zero, and an imbalance the size of
    /// the whole balance when it does not. Neither of them says "this balance left the book".
    ///
    /// So it is named. The other way a balance leaves a book is that somebody removed it, and a
    /// disappearance nobody reported is indistinguishable from housekeeping.
    Retired {
        /// Which balance.
        key: TotalsKey,
        /// Which window.
        window: WindowStart,
    },
    /// A closed window moved after its last transfer.
    ClosedWindowMoved(ClosedWindowMoved),
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Finding::CheckpointEdited { checkpoint_seq } => write!(
                f,
                "checkpoint {checkpoint_seq} does not hash to its own figures — it was EDITED after it was sealed"
            ),
            Finding::SequenceNotMonotonic { node, was, now } => write!(
                f,
                "node {node}'s sequence went from {was} to {now} — records were REMOVED or REPLAYED"
            ),
            Finding::AnchorHeadDiffers { anchored, expected } => write!(
                f,
                "the anchor holds checkpoint {anchored}, not {expected} — the anchored history and this node's do not agree"
            ),
            Finding::Imbalanced(i) => write!(f, "{i}"),
            Finding::Retired { key, window } => write!(
                f,
                "{key} in the window opening at {window} was sealed into the checkpoint and is no longer in the book — retired, or REMOVED"
            ),
            Finding::ClosedWindowMoved(c) => write!(f, "{c}"),
        }
    }
}

/// Which windows have closed, so verification knows which ones must have stopped moving.
pub trait WindowState {
    /// Whether this window is still open.
    fn is_open(&self, key: &TotalsKey, window: WindowStart) -> bool;
}

/// Everything is open. The right answer for a deployment with one rolling window, and a sensible
/// default for a caller that has not wired window state yet.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllWindowsOpen;

impl WindowState for AllWindowsOpen {
    fn is_open(&self, _key: &TotalsKey, _window: WindowStart) -> bool {
        true
    }
}

/// Verify the books as they stand against the last sealed checkpoint.
///
/// `since` is the checkpoint the delta is measured from; `now` is the figures as they stand. Every
/// balance in either of them is checked, so a balance that appeared since the checkpoint is not
/// skipped, and one that is no longer in the book is named as such rather than measured against
/// zeros — see [`Finding::Retired`] for why those are different answers.
pub fn verify(
    since: &Checkpoint,
    now: &std::collections::BTreeMap<(TotalsKey, WindowStart), Totals>,
    windows: &dyn WindowState,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !since.body_hash_verifies() {
        findings.push(Finding::CheckpointEdited {
            checkpoint_seq: since.checkpoint_seq,
        });
    }

    let mut keys: Vec<&(TotalsKey, WindowStart)> = since.totals.keys().collect();
    for key in now.keys() {
        if !since.totals.contains_key(key) {
            keys.push(key);
        }
    }
    keys.sort();
    keys.dedup();

    for (key, window) in keys.into_iter().cloned() {
        let before = since.totals_for(&key, window);
        // A balance the book no longer holds is not a balance measured against zeros. Retiring a
        // sealed window is the ordinary way a book stays bounded, and comparing what the checkpoint
        // holds against the zeros a retired key reads back as reports the whole of it as a hole.
        let Some(&after) = now.get(&(key.clone(), window)) else {
            findings.push(Finding::Retired { key, window });
            continue;
        };
        if windows.is_open(&key, window) {
            let r = residual(&before, &after);
            if !r.holds() {
                findings.push(Finding::Imbalanced(Imbalance {
                    key: key.clone(),
                    window,
                    residual: r,
                }));
            }
        } else if let Err(moved) = closed_window_is_settled(&before, &after) {
            findings.push(Finding::ClosedWindowMoved(ClosedWindowMoved {
                key: key.clone(),
                window,
                moved,
            }));
        }
    }
    findings
}

/// Check that no node's sequence went backwards between two checkpoints.
pub fn sequences_are_monotonic(since: &Checkpoint, now: &Checkpoint) -> Vec<Finding> {
    let mut findings = Vec::new();
    for head in &now.heads {
        if let Some(before) = since.heads.iter().find(|h| h.node == head.node) {
            if head.node_seq < before.node_seq {
                findings.push(Finding::SequenceNotMonotonic {
                    node: head.node,
                    was: before.node_seq,
                    now: head.node_seq,
                });
            }
        }
    }
    findings
}
