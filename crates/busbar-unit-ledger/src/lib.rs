// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-ledger — the ledger unit
//!
//! What money IS, as opposed to where its bytes landed. This crate settles holds, keeps the running
//! figures a checkpoint seals, states the one identity those figures have to satisfy, reprices every
//! line by lookup against the dated rate-card history it was priced under, and hands each posting to
//! the previous release's rows so nothing reading them notices a change.
//!
//! ## Quantities are the truth; a price is a lookup
//!
//! A booked line stores what happened — the quantities, the lane, the instant, the tier, the
//! currency — and the two history numbers that say which snapshot it was settled under and which
//! dated card that snapshot resolved to at that instant. It also stores a price, and that price is
//! a CACHE: derived, re-derivable, and never the record. A statement is cut AS OF a snapshot and
//! re-derives every figure from the quantities; it never sums the caches, so its answer does not
//! depend on whether the recompute has been round yet.
//!
//! **A booked line is never rewritten.** An amendment to the history moves money by emitting an
//! adjusting entry — one [`Repricing`] per affected balance and window, carrying both figures and
//! the delta — which rides the `adjustments` cell the identity already has. `settled` does not
//! move, no term is added to the identity, and a window already sealed into a signed checkpoint is
//! corrected forward rather than edited backward.
//!
//! ## The five things in here, and why each is separate
//!
//! [`mod@settle`] — a hold and a usage report become a posting, and the books move. The hold is taken by
//! value, so it is settled at most once by construction rather than by care.
//!
//! [`mod@totals`] — the running figures, per bucket, per dimension, per scope, per window. Four things
//! in the key because a token cap and a spend cap on the same bucket are two independent balances,
//! and folding them would let one pay the other's overdraft.
//!
//! [`mod@identity`] — the one equation, as a pure function of two snapshots. No clock, no store, no
//! configuration, no state: an auditor can re-derive it from a pair of sealed checkpoints, and a
//! test can throw random postings at it with no fixture at all.
//!
//! [`mod@checkpoint`] — the figures sealed, digested, signed and anchored. Signing and anchoring are
//! separate traits because they are separate claims, and a node that files its own signatures on its
//! own disk has proved nothing to anybody. The crate says so rather than implying otherwise.
//!
//! [`mod@recompute`] — every line priced again by lookup against the sealed history, from a watermark
//! that is the last line actually checked rather than the last checkpoint. The difference is not
//! pedantry: at a busy node's rate "since the last checkpoint" covers a few percent of the lines,
//! and a line edited before that point would never be looked at again. Because the lookup is the
//! amount, the recompute now CORRECTS a stale cache rather than only reporting it — and it still
//! tells the two cases apart, because a cache going stale behind a head that moved is an amendment
//! and a cache going stale behind a head that did not is somebody's hand.
//!
//! [`mod@hydrate`] — the same books, restored at boot from what was settled. It is here rather than at
//! the door because a settled posting is money delivered at the card that was in force when it was
//! delivered, and the door's cells hold tokens rather than money: restoring the tokens and pricing
//! them again is how a window that was already billed gets repriced by a rate correction. What the
//! door is handed instead is one figure per balance — what that balance already carried — which it
//! adds to its own accrual and compares, repricing nothing.
//!
//! ## What this crate does not do
//!
//! It does not admit, and it does not write bytes to a disk. It never asks whether a deployment has
//! a data directory, because a ledger that behaved differently depending on where its records were
//! stored would be two ledgers. Durability is the log's; admission is the door's.
//!
//! ## The one place a capability appears
//!
//! Settling requires a ledger token, because a posting is a capability and only the ledger unit,
//! mid-settlement, may build one. Everything else here is plain arithmetic over plain values, which
//! is what lets the identity be checked by something that was never near a token.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod checkpoint;
pub mod digest;
pub mod hydrate;
pub mod identity;
pub mod legacy;
pub mod migration;
pub mod recompute;
pub mod settle;
pub mod totals;
pub mod verify;

pub use checkpoint::{
    AnchorError, AnchorState, AnchoredHead, ChainHead, Checkpoint, CheckpointAnchor,
    CheckpointSecret, SelfAttestingAnchor, SignError, Signature,
};
pub use hydrate::{Carried, HydratedPosting, Hydration, HydrationError, SpendSource};
pub use identity::{
    attribution_holds, closed_window_is_settled, holds, residual, ClosedWindowMoved, Imbalance,
    Residual,
};
pub use legacy::{
    opening_balances, LegacyHead, LegacyMigrationSource, LegacyPosting, LegacyRows,
    LegacyWriteError, OpeningBalance, RecordingRows,
};
pub use migration::{
    migrate, opening_totals, LegacyFamily, LegacyFigure, LegacyFigures, LegacyLedgerRows,
    MigrationError, MigrationMarker, MigrationRecords, NodeLocalRecords, Opening,
    Outcome as MigrationOutcome, OPENING_CHECKPOINT_SEQ,
};
pub use recompute::{
    apply_tier, divergence_of, price_line, recheck, recompute, DerivedPrice, Divergence,
    Finding as RecomputeFinding, HistoryArchive, Pass, Posting, PostingOrigin, PricedLine, Recheck,
    SealedHistory, Verdict, Watermark, BASIS_POINTS,
};
pub use settle::{adjusting_entries, Ledger, Overdraft, Repricing, Settlement};
pub use totals::{
    totals_as_of, Book, BucketId, BucketScope, CapDimension, Statement, StatementRow, Totals,
    TotalsKey, Unpriced, WindowStart,
};
pub use verify::{
    sequences_are_monotonic, verify, AllWindowsOpen, Finding as VerifyFinding, WindowState,
};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
