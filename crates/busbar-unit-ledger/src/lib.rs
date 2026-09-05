// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-ledger — the ledger unit
//!
//! What money IS, as opposed to where its bytes landed. This crate settles holds, keeps the running
//! figures a checkpoint seals, states the one identity those figures have to satisfy, reprices every
//! posting against the policy it was priced under, and hands each posting to the previous release's
//! rows so nothing reading them notices a change.
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
//! [`mod@recompute`] — every posting priced again from sealed policy, from a watermark that is the last
//! posting actually checked rather than the last checkpoint. The difference is not pedantry: at a
//! busy node's rate "since the last checkpoint" covers a few percent of the postings, and a posting
//! edited before that point would never be looked at again.
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
    apply_tier, recheck, recompute, Divergence, Finding as RecomputeFinding, Pass, PolicyArchive,
    Posting, PostingOrigin, PricedLine, RateCard, SealedPolicy, Watermark, BASIS_POINTS,
};
pub use settle::{Ledger, Overdraft, Settlement};
pub use totals::{Book, BucketId, BucketScope, CapDimension, Totals, TotalsKey, WindowStart};
pub use verify::{
    sequences_are_monotonic, verify, AllWindowsOpen, Finding as VerifyFinding, WindowState,
};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
