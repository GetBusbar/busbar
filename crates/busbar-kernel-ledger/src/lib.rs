// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-kernel-ledger — the ledger unit
//!
//! What money IS, as opposed to where its bytes landed. This crate settles holds, keeps the running
//! figures a checkpoint seals, states the one identity those figures have to satisfy, prices a line
//! by lookup against the dated rate-card history, and hands each posting to the previous release's
//! rows so nothing reading them notices a change.
//!
//! ## Quantities are the truth; a price is a lookup
//!
//! A booked line ([`recompute::Posting`]) stores what happened — the quantities, the lane, the
//! instant, the tier — and no price at all (#71, #77(3)). A statement is cut AS OF a snapshot and
//! derives every figure from the quantities by the one lookup. (The cost unit's own posting type
//! can carry the figure the settlement lookup answered, [`cost::CachedPrice`]; the one production
//! writer sets it on a posting it then drops, and nothing reads it.)
//!
//! **A booked line is never rewritten, and no adjusting line is booked beside it** (#77(2)). An
//! amendment to the history is a dated card entry; the window it corrects reprices as a VIEW over
//! the stored quantities (#77(3), #79), so `settled` does not move, no term is added to the
//! identity, and a window already sealed into a signed checkpoint is never edited.
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
//! [`mod@recompute`] — the booked line and the one lookup that prices it ([`recompute::price_line`]),
//! which a statement calls once per line. There is no watermark, no stored figure to correct and no
//! sweep over the book here: a line carries no price to go stale. The check that a settled figure
//! still agrees with its counts is the root's restart reconciliation, which replays the journal's
//! counts into a second book and compares it with the live one.
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
// Folded from the former cost and usage crates (#36: the book merges
// rates+usage+ledger as three modules).
pub mod cost;
pub mod usage;
// THE MONEY-PATH DURABLE RECORDS ARE NOT HERE. They were relocated BYTE-IDENTICALLY into the ONE
// contract crate's `records` module under DECISIONS #83/#84 — #83 draws the seam (contract =
// SHAPES, the data and its wire encoding; this crate = SEMANTICS, what the shapes MEAN and what may
// be done with them) and #84 is why it is urgent: while they sat here, every third-party plugin's
// compile closure ran plugin → the author SDK → the retiring api shim → THIS CRATE → the contract,
// so a store plugin transitively linked THE MONEY ONE-BOOK and a ledger type change forced every
// third-party plugin to rebuild. Nothing in this crate ever named the `records` module: it sat here
// only because #35 staged it out of the api shim, and it leaves without touching a single line of
// ledger arithmetic. The book still settles, still posts, still seals — it just no longer ships its
// own definition of settlement into a plugin author's build.
pub mod digest;
pub mod identity;
pub mod legacy;
pub mod migration;
pub mod recompute;
pub mod settle;
pub mod totals;
pub mod verify;

pub use checkpoint::{
    AnchorError, AnchoredHead, ChainHead, Checkpoint, CheckpointAnchor, CheckpointSecret,
    CheckpointVerifier, SealRefusal, SelfAttestingAnchor, SignError, Signature,
};
pub use identity::{holds, residual, Imbalance, Residual};
pub use legacy::{
    opening_balances, LegacyHead, LegacyMigrationSource, LegacyPosting, LegacyRows,
    LegacyWriteError, OpeningBalance, RecordingRows, SummedRows,
};
pub use migration::{
    migrate, opening_totals, LegacyFamily, LegacyFigure, LegacyFigures, LegacyLedgerRows,
    MigrationError, MigrationMarker, MigrationRecords, Opening, Outcome as MigrationOutcome,
    OPENING_CHECKPOINT_SEQ,
};
pub use recompute::{
    divergence_of, price_line, Divergence, Posting, PostingOrigin, PricedLine, BASIS_POINTS,
};
pub use settle::{Figures, Ledger, Overdraft, Settlement};
pub use totals::{
    totals_as_of, Book, BucketId, BucketScope, CapDimension, Statement, StatementRow, Totals,
    TotalsKey, Unpriced, WindowStart,
};
pub use verify::{sequences_are_monotonic, verify, Finding as VerifyFinding};

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
