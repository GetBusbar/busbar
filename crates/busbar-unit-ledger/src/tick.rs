// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The ledger's own tick: seal, anchor, and only then retire.**
//!
//! ## The defect this closes, stated as it was found
//!
//! The book grows a row per `(bucket, dimension, scope, window)` and nothing ever took one out. A
//! deployment with a daily window and a thousand principals adds a thousand rows a day, forever, and
//! an integrator's only way to bound it was to throw the whole ledger away. [`Book::retain_from`]
//! existed and was never called from anything but a test — and it could not have been called
//! correctly if it had been, because it takes ONE global cutoff while the all-time window's row
//! lives at [`ALL_TIME_WINDOW`]. Any cutoff at all deletes it, and the all-time row is the one
//! balance that must never go.
//!
//! Beside it, [`crate::checkpoint::Checkpoint::seal`] and [`crate::checkpoint::CheckpointAnchor::
//! anchor`] also had no production caller. That is the same defect from the other end: the retention
//! boundary IS the checkpoint, so a book that is never sealed can never safely retire anything, and
//! a node that never anchors has nothing to prove the seal against.
//!
//! ## The boundary, per balance and not per node
//!
//! A row is retired when **all four** are true of it, and each one is a separate reason:
//!
//! 1. It is not the all-time window. That row never rolls, is never closed, and is never retired —
//!    it is the running total a bucket's own cap is compared against.
//! 2. A checkpoint has SEALED it. The book is not the record of a sealed window; the checkpoint is.
//!    A row nothing sealed is a balance nobody else holds.
//! 3. That checkpoint has been ANCHORED. A seal this node signed and filed on its own disk proves
//!    nothing to anybody, and retiring against one is discarding the only copy on the strength of a
//!    claim the node made to itself.
//! 4. It is below `backup_watermark`. Retention may not discard past where the backup has got, which
//!    is the rule the checkpoint's own field states and which nothing was reading.
//!
//! Per balance, because a boundary that is one number for the whole node retires a busy bucket's
//! sealed rows and a quiet bucket's unsealed ones with the same cut.
//!
//! ## Why the tick and never a request
//!
//! Sealing digests every row in the book and anchoring reaches a sink outside the node. Doing either
//! on the path that admits a request would put an unbounded fold and a network call inside the
//! decision that says yes or no. So the driver is a tick — the composition root's clock, off the hot
//! path — and this module's whole surface takes the facts it needs as arguments rather than reading
//! any of them.

use std::collections::BTreeMap;

use busbar_unit_cost::HistorySeq;

use crate::checkpoint::{
    AnchorError, AnchorState, ChainHead, Checkpoint, CheckpointAnchor, CheckpointSecret, SignError,
};
use crate::settle::Ledger;
use crate::totals::{TotalsKey, WindowStart};

/// **The window that never rolls, and is never retired.**
///
/// A bucket's all-time balance opens at the epoch and has no end, so it is never closed, never
/// sealed as final, and never below any watermark in the sense retention means. It is also the row a
/// key's own lifetime cap is read from. Naming it is what makes rule 1 of the boundary a fact about
/// the code rather than a comment: [`Book::retain_from`]'s single global cutoff deleted it on every
/// call, which is why that function has no production caller and this one does.
pub const ALL_TIME_WINDOW: WindowStart = 0;

/// What one tick retired, and why it kept what it kept.
///
/// Every row the book still holds is accounted for by exactly one of the four counters below, so an
/// operator asking why a book is not shrinking gets an answer rather than a number. A book that is
/// growing because nothing anchors reads very differently from one that is growing because the
/// backup has stalled, and both look identical if the only figure reported is `retired`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Retirement {
    /// How many rows were retired.
    pub retired: usize,
    /// How many were kept because they are the all-time window.
    pub kept_all_time: usize,
    /// How many were kept because no checkpoint has sealed them yet.
    pub kept_unsealed: usize,
    /// How many were kept because the checkpoint that sealed them is not anchored.
    pub kept_unanchored: usize,
    /// How many were kept because they are at or above `backup_watermark`.
    pub kept_above_watermark: usize,
}

impl Retirement {
    /// How many rows the book still holds after this tick.
    #[must_use]
    pub fn kept(&self) -> usize {
        self.kept_all_time + self.kept_unsealed + self.kept_unanchored + self.kept_above_watermark
    }
}

/// What the composition root hands the ledger on its tick.
///
/// Every field is a fact the ledger cannot read for itself and must not invent: the clock, the
/// node's identity, where the chains have got to, how far the backup has got, and the key to sign
/// with. A ledger that could read any of them would be a ledger whose sealed body depended on
/// something outside its inputs.
pub struct TickAt<'a> {
    /// Which checkpoint in the deployment's sequence this seal is.
    pub checkpoint_seq: u64,
    /// Which node is sealing.
    pub node: u64,
    /// When, in whole seconds.
    pub wall: u64,
    /// Every node chain's head at this moment.
    pub heads: Vec<ChainHead>,
    /// How far the backup has got. **Retention may not discard at or past this.**
    pub backup_watermark: u64,
    /// The store's sequence high-water.
    pub store_seq_high_water: u64,
    /// The history snapshot the sealed figures were derived against, where the deployment has one.
    pub history_seq: Option<HistorySeq>,
    /// The deployment's signing key, where one is available.
    pub secret: Option<&'a dyn CheckpointSecret>,
}

impl std::fmt::Debug for TickAt<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TickAt")
            .field("checkpoint_seq", &self.checkpoint_seq)
            .field("node", &self.node)
            .field("wall", &self.wall)
            .field("backup_watermark", &self.backup_watermark)
            .field("signing", &self.secret.is_some())
            .finish_non_exhaustive()
    }
}

/// What one tick did.
#[derive(Debug, Clone)]
pub struct Tock {
    /// The checkpoint this tick sealed. The caller journals it — a seal with no position on the
    /// chain is a figure nobody can order against the postings it covers.
    pub checkpoint: Checkpoint,
    /// Whether the anchor sink took it.
    pub anchored: bool,
    /// Why it did not, where it did not. An anchor failure is a FACT about the deployment's
    /// tamper-evidence and is reported rather than logged: a node whose anchor has been failing for
    /// a week stopped being tamper-evident a week ago.
    pub anchor_failure: Option<AnchorError>,
    /// How the anchoring is going, across ticks.
    pub anchor_state: AnchorState,
    /// What the tick retired, and why it kept the rest.
    pub retirement: Retirement,
}

/// What the ledger remembers between ticks: which checkpoint sealed each row, and how far the
/// anchoring has got.
///
/// Held by the ledger rather than by the caller, because the two questions the boundary asks — "was
/// this row sealed, and by which seal" and "how far has the anchor got" — are answered about the
/// ledger's own book and would otherwise be a second copy of it in whatever drives the tick.
#[derive(Debug, Clone, Default)]
pub(crate) struct Sealing {
    /// The checkpoint sequence each surviving row was last sealed into.
    pub(crate) sealed_in: BTreeMap<(TotalsKey, WindowStart), u64>,
    /// The newest checkpoint sequence the anchor sink has taken.
    pub(crate) anchored_through: Option<u64>,
    /// How the anchoring is going.
    pub(crate) state: AnchorState,
}

impl Ledger {
    /// **The tick: seal the book, anchor the seal, retire what the seal now covers.**
    ///
    /// In that order, and the order is the whole design. Sealing first means the rows about to be
    /// retired are IN the checkpoint that permits retiring them — a seal taken after the retirement
    /// would cover a book the rows had already left, and the figures would be gone from both. The
    /// anchor comes second because a seal nobody outside this node has seen is not a reason to
    /// discard the only other copy. The retirement comes last and retires only what the two steps
    /// before it have made safe.
    ///
    /// A tick whose anchor FAILS still seals and still journals; it simply retires nothing new. That
    /// is the correct degradation: the chain stays continuous, the book grows, and the growth is
    /// visible in [`Retirement::kept_unanchored`] rather than silent.
    ///
    /// # Errors
    ///
    /// The checkpoint could not be signed. Nothing has been retired when this happens — the seal is
    /// the permission, so no seal is no permission.
    pub fn tick(
        &mut self,
        at: &TickAt<'_>,
        anchor: &mut dyn CheckpointAnchor,
    ) -> Result<Tock, SignError> {
        // 1. SEAL. The whole live book, which is what a checkpoint is: the figures as they stand,
        //    digested in key order and signed.
        let totals = self.book().snapshot();
        let checkpoint = match at.history_seq {
            Some(seq) => Checkpoint::seal_as_of(
                at.checkpoint_seq,
                at.node,
                at.wall,
                at.heads.clone(),
                totals,
                at.backup_watermark,
                at.store_seq_high_water,
                seq,
                at.secret,
            )?,
            None => Checkpoint::seal(
                at.checkpoint_seq,
                at.node,
                at.wall,
                at.heads.clone(),
                totals,
                at.backup_watermark,
                at.store_seq_high_water,
                at.secret,
            )?,
        };
        for row in checkpoint.totals.keys() {
            self.sealing_mut()
                .sealed_in
                .insert(row.clone(), at.checkpoint_seq);
        }

        // 2. ANCHOR. A separate claim from the signature, so a separate step and a separate answer.
        let anchor_failure = match anchor.anchor(&checkpoint) {
            Ok(()) => {
                let sealing = self.sealing_mut();
                sealing.anchored_through = Some(at.checkpoint_seq);
                sealing.state.consecutive_failures = 0;
                None
            }
            Err(why) => {
                let sealing = self.sealing_mut();
                sealing.state.consecutive_failures =
                    sealing.state.consecutive_failures.saturating_add(1);
                Some(why)
            }
        };
        {
            let self_attesting = anchor.is_self_attesting();
            let head = anchor.head().ok().flatten();
            let sealing = self.sealing_mut();
            sealing.state.self_attesting = self_attesting;
            sealing.state.head = head;
        }

        // 3. RETIRE. Only what the two steps above made safe, per balance.
        let retirement = self.retire_at(at.backup_watermark);

        Ok(Tock {
            checkpoint,
            anchored: anchor_failure.is_none(),
            anchor_failure,
            anchor_state: self.sealing().state.clone(),
            retirement,
        })
    }

    /// How the anchoring is going, as of the last tick.
    #[must_use]
    pub fn anchor_state(&self) -> AnchorState {
        self.sealing().state.clone()
    }

    /// The newest checkpoint the anchor sink has taken, if any.
    #[must_use]
    pub fn anchored_through(&self) -> Option<u64> {
        self.sealing().anchored_through
    }

    /// How many sealing notes the ledger is holding — one per surviving row, and never more.
    ///
    /// The shadow map is the same unbounded growth one level down if a retired row's note stays
    /// behind, so the figure is readable rather than a thing to trust.
    #[must_use]
    pub fn sealed_row_count(&self) -> usize {
        self.sealing().sealed_in.len()
    }

    /// **Retire every row the boundary permits, and say why each survivor survived.**
    ///
    /// The retirement step of [`Ledger::tick`], on its own. Public because the boundary is a
    /// question an operator asks — "why is this book not shrinking" — and answering it should not
    /// require sealing a checkpoint nobody wanted. It seals nothing and anchors nothing: it reads
    /// what earlier ticks recorded, so a call to it can only ever retire rows an earlier tick had
    /// already made safe.
    pub fn retire_at(&mut self, backup_watermark: u64) -> Retirement {
        let sealed_in = self.sealing().sealed_in.clone();
        let anchored_through = self.sealing().anchored_through;
        let mut outcome = Retirement::default();
        let mut retired: Vec<(TotalsKey, WindowStart)> = Vec::new();
        self.book_mut().retire(|key, window, _figures| {
            // 1. The all-time row is never retired, whatever else is true of it.
            if window == ALL_TIME_WINDOW {
                outcome.kept_all_time += 1;
                return false;
            }
            // 2. A row nothing has sealed is a balance nobody else holds.
            let Some(sealed) = sealed_in.get(&(key.clone(), window)).copied() else {
                outcome.kept_unsealed += 1;
                return false;
            };
            // 3. A seal the anchor sink has not taken proves nothing outside this node.
            if anchored_through.is_none_or(|through| sealed > through) {
                outcome.kept_unanchored += 1;
                return false;
            }
            // 4. Retention may not discard at or past where the backup has got.
            if window >= backup_watermark {
                outcome.kept_above_watermark += 1;
                return false;
            }
            outcome.retired += 1;
            retired.push((key.clone(), window));
            true
        });
        // A retired row's sealing note goes with it: the map is the book's shadow and a note for a
        // row that is gone is the same unbounded growth one level down.
        for row in retired {
            self.sealing_mut().sealed_in.remove(&row);
        }
        outcome
    }
}
