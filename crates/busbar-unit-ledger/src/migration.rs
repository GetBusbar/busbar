// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migration: what the previous release's rows already hold, sealed once as the opening figures.
//!
//! ## What it is for
//!
//! A checkpoint is the point the identity is measured FROM, and on the first boot of a deployment
//! that has been serving for a year there is no such point. Without one, every figure the previous
//! release accumulated is either invisible to this release's books or — worse — looks like value
//! that appeared out of nowhere the first time anything is checked. So the first boot reads what the
//! previous release's rows hold, seals it as an OPENING checkpoint, and measures everything
//! afterwards from there.
//!
//! ## The three rules, and why each is a rule rather than an intention
//!
//! **It runs once.** The marker is written into the ledger's own records, not into the rows it read,
//! and a boot that finds one reads nothing and writes nothing. A migration that ran twice would seal
//! a second opening on top of the first and double every balance in it.
//!
//! **It never writes to what it read.** A deployment may perfectly well be booting against a
//! read-only replica or a grant-restricted database — that is the previous release's supported
//! shape, not an exotic one — so the source seam here has a `read` and nothing else. There is no
//! write-read-back probe, no watermark stamped back onto the legacy rows, and no "mark migrated"
//! column: a seam with no write method cannot grow one by accident.
//!
//! **The sealed figures are the legacy totals, exactly.** Not rounded, not re-priced, not summed
//! across dimensions. One legacy figure is one bucket, on one day, on one lane, from one provider,
//! in one dimension; it lands in one balance, and the balance holds the same integer that was read.
//!
//! ## What "an opening figure" means in the totals
//!
//! Value that the previous release consumed was taken out of the store and posted, so the opening
//! sets DRAWN and SETTLED to the same amount and everything else to zero. That is not a
//! presentational choice: it is what makes the opening checkpoint satisfy the identity by
//! construction — everything drawn is accounted for, in the settled column — so the very first
//! reconciliation after an upgrade measures this release's own postings and not the previous
//! release's history.
//!
//! ## Why the two row families stay apart
//!
//! The previous release keeps a bucket's consumption twice: once as the bucket's own token ledger
//! for a window, and once as per-lane, per-provider metering rows on a day. They are two VIEWS of
//! the same consumption, and folding them into one balance would open the books at double what was
//! actually consumed. So each family seals at its own scope — the window family at the bucket's
//! scope, the metering family in a pool named for the lane and the provider — and the two prefixes
//! are what makes a collision impossible rather than unlikely.
//!
//! ## An empty store is not a failure
//!
//! A deployment whose store keeps nothing across a restart, and an older store that cannot answer
//! at all, both read as nothing. Both seal an opening checkpoint at zero and the node serves. A
//! refusal here would mean a configuration that worked yesterday stops working on upgrade, which is
//! the one outcome a migration may not produce — and a boot that skipped the seal on an empty read
//! would leave the deployment with no point to measure from, which is the defect this module exists
//! to remove.

use std::collections::BTreeMap;

use crate::checkpoint::{ChainHead, Checkpoint, CheckpointSecret, SignError};
use crate::legacy::{opening_balances, LegacyHead, LegacyMigrationSource, OpeningBalance};
use crate::totals::{BucketId, BucketScope, CapDimension, Totals, TotalsKey, WindowStart};

/// The sequence number of the opening checkpoint.
///
/// Zero, because it is the point everything else is measured from: the first checkpoint this
/// deployment seals under its own steam is the one after it. Named rather than spelled inline so
/// the marker, the checkpoint and anything reading either agree by construction.
pub const OPENING_CHECKPOINT_SEQ: u64 = 0;

/// Which of the previous release's two row families a figure was read from.
///
/// It is carried on the figure rather than decided by the reader, because the family is what
/// decides the scope, and the scope is the whole of what keeps two views of one consumption from
/// being added together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegacyFamily {
    /// A bucket's token ledger for one window: what the bucket consumed, with no lane on it.
    Window,
    /// A metering row: one day, one lane, one provider, under the key that was charged.
    Meter,
}

/// One figure the previous release's rows hold.
///
/// Deliberately plain — identifiers as strings, the amount as the integer that was read. Anything
/// richer would be this crate having an opinion about a row shape it does not own, which is the same
/// reason the dual write next door is a trait rather than an implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFigure {
    /// Which family the figure came from.
    pub family: LegacyFamily,
    /// Which bucket it is against.
    pub bucket: String,
    /// Which window or day it fell in, as that window's opening instant in whole seconds.
    pub window: WindowStart,
    /// Which lane served it. Empty where the row carries no lane.
    pub lane: String,
    /// Which provider served it. Empty where the row carries no provider.
    pub provider: String,
    /// What is being counted.
    pub dimension: CapDimension,
    /// How much, as the previous release's row holds it.
    pub amount: i128,
}

impl LegacyFigure {
    /// The balance this figure opens.
    ///
    /// The two families take deliberately different pool prefixes. A metering row whose provider
    /// happens to be empty would otherwise land on the same key as a window row for the same lane,
    /// and the two would silently add — which is the one arithmetic error a migration cannot be
    /// allowed to make, because there is nothing left to compare the result against.
    pub fn key(&self) -> TotalsKey {
        let scope = match (self.family, self.lane.as_str()) {
            (LegacyFamily::Window, "") => BucketScope::All,
            (LegacyFamily::Window, lane) => BucketScope::Pool(format!("lane:{lane}")),
            (LegacyFamily::Meter, lane) => {
                BucketScope::Pool(format!("meter:{lane}/{}", self.provider))
            }
        };
        TotalsKey::new(
            BucketId::new(self.bucket.clone()),
            self.dimension.clone(),
            scope,
        )
    }
}

/// Everything the previous release's rows hold, plus what could not be read.
///
/// The unreadable list is part of the answer rather than an error arm because a migration may not
/// refuse: a store that could not answer for one bucket must not stop a node booting. What it must
/// not do is lose the fact, so the names come back and whatever runs the migration can say so.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyFigures {
    /// Every figure read, in whatever order the rows came back.
    pub figures: Vec<LegacyFigure>,
    /// The rows that could not be read, named.
    pub unreadable: Vec<String>,
}

/// Reads the figures behind the previous release's chain head.
///
/// Note what is NOT on this trait: a write. The rows this reads may be on a read-only replica, and
/// the way to guarantee a migration never writes to them is to give it nothing it could write with.
///
/// It extends the head-reading seam rather than replacing it, so the head and the figures come from
/// one object that read one store, and the two cannot disagree about what was there.
pub trait LegacyLedgerRows: LegacyMigrationSource {
    /// The figures. An implementation that cannot answer returns an empty set rather than an error,
    /// exactly as the head does, and the migration seals a zero opening balance.
    fn read_figures(&self) -> LegacyFigures;
}

/// The record that says this deployment has already migrated.
///
/// It carries the identity of what was sealed, not merely a flag. A flag can only answer "yes"; this
/// answers "yes, checkpoint N, body hash H, B balances, C cells read", which is what an operator
/// asking why a balance looks the way it does actually needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationMarker {
    /// The checkpoint the migration sealed.
    pub checkpoint_seq: u64,
    /// Which node sealed it.
    pub node: u64,
    /// When, in whole seconds.
    pub sealed_at: u64,
    /// The digest of that checkpoint's body.
    pub body_hash: [u8; 32],
    /// How many balances the opening carries.
    pub balances: u64,
    /// How many of the previous release's cells were read to arrive at them.
    pub cells_read: u64,
    /// Which card version the opening entries were priced under.
    pub rate_card_version: u64,
}

/// The ledger's own records, which is where the marker lives.
///
/// Deliberately NOT the rows the migration read. The rows may be read-only, and a marker written
/// beside somebody else's data is a migration that has quietly taken ownership of a schema it does
/// not own. This seam is the ledger's own, and the integrator binds whatever durability the
/// deployment actually has to it.
pub trait MigrationRecords {
    /// The marker, if this deployment has already migrated.
    ///
    /// # Errors
    ///
    /// The records could not be read. The caller decides what to do about it; this crate will not
    /// guess, because "unreadable" and "absent" are different facts and treating one as the other is
    /// how a migration runs twice.
    fn read_marker(&self) -> Result<Option<MigrationMarker>, MigrationError>;

    /// Seal the marker.
    ///
    /// # Errors
    ///
    /// The records could not be written.
    fn write_marker(&mut self, marker: &MigrationMarker) -> Result<(), MigrationError>;
}

/// Why a migration could not be completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationError {
    /// The ledger's own records could not be read or written.
    RecordsUnavailable(String),
    /// The opening checkpoint could not be signed.
    NotSealed(SignError),
    /// Two legacy figures for one balance sum past what a figure can hold.
    ///
    /// A ledger figure is a signed 128-bit integer, so reaching this means the rows that were read
    /// are not a plausible history. Refusing is right: opening at a wrapped figure would seed every
    /// later reconciliation with a number nobody can explain.
    FigureOverflow {
        /// Which balance.
        key: String,
        /// Which window.
        window: WindowStart,
    },
}

impl std::fmt::Display for MigrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationError::RecordsUnavailable(why) => {
                write!(f, "the ledger's own records were not usable: {why}")
            }
            MigrationError::NotSealed(e) => write!(f, "the opening checkpoint was not sealed: {e}"),
            MigrationError::FigureOverflow { key, window } => write!(
                f,
                "the legacy figures for {key} in the window opening at {window} do not fit in a \
                 ledger figure"
            ),
        }
    }
}

impl std::error::Error for MigrationError {}

impl From<SignError> for MigrationError {
    fn from(e: SignError) -> Self {
        MigrationError::NotSealed(e)
    }
}

/// What the migration sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opening {
    /// The opening checkpoint. Its totals ARE the legacy figures.
    pub checkpoint: Checkpoint,
    /// The marker that was written, so the caller need not read the records back to report it.
    pub marker: MigrationMarker,
    /// The opening entry per bucket, at the named card version.
    pub balances: Vec<OpeningBalance>,
    /// The rows that could not be read, named. Empty on a store that answered for everything.
    pub unreadable: Vec<String>,
}

/// What a boot's migration did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// This boot sealed the opening.
    Sealed(Box<Opening>),
    /// A marker was already there. Nothing was read and nothing was written.
    AlreadySealed(MigrationMarker),
}

impl Outcome {
    /// Whether this boot did the sealing.
    pub fn sealed_now(&self) -> bool {
        matches!(self, Outcome::Sealed(_))
    }

    /// The marker, whichever boot wrote it.
    pub fn marker(&self) -> &MigrationMarker {
        match self {
            Outcome::Sealed(opening) => &opening.marker,
            Outcome::AlreadySealed(marker) => marker,
        }
    }
}

/// Fold the legacy figures into the balances an opening checkpoint seals.
///
/// A pure function of the figures: no clock, no store, no records. That is what lets the claim "the
/// sealed figures equal the legacy totals" be checked by a test that never sealed anything, and by
/// an auditor holding a checkpoint and the rows it was made from.
///
/// Drawn and settled move together and everything else stays at zero — see this module's preamble
/// for why that is the shape that makes the opening satisfy the identity.
///
/// # Errors
///
/// Two figures for one balance sum past what a ledger figure can hold.
pub fn opening_totals(
    figures: &[LegacyFigure],
) -> Result<BTreeMap<(TotalsKey, WindowStart), Totals>, MigrationError> {
    let mut totals: BTreeMap<(TotalsKey, WindowStart), Totals> = BTreeMap::new();
    for figure in figures {
        let key = figure.key();
        let entry = totals.entry((key.clone(), figure.window)).or_default();
        let overflow = || MigrationError::FigureOverflow {
            key: key.to_string(),
            window: figure.window,
        };
        entry.drawn = entry
            .drawn
            .checked_add(figure.amount)
            .ok_or_else(overflow)?;
        entry.settled = entry
            .settled
            .checked_add(figure.amount)
            .ok_or_else(overflow)?;
    }
    Ok(totals)
}

/// The previous release's chain head, as a checkpoint cross-links it.
///
/// The head's hash is text of a shape this crate never agreed to, so it is DIGESTED rather than
/// parsed: a fixed-width identity that is a pure function of what was read, and no parse that could
/// fail on a deployment whose previous release wrote something else. A head with neither a sequence
/// number nor a hash cross-links nothing, which is the honest answer for a store that had nothing to
/// say.
fn opening_heads(head: &LegacyHead, node: u64) -> Vec<ChainHead> {
    if head.seq.is_none() && head.hash.is_none() {
        return Vec::new();
    }
    vec![ChainHead {
        node,
        node_seq: head.seq.unwrap_or(0),
        hash: crate::digest::sha256(head.hash.as_deref().unwrap_or("").as_bytes()),
    }]
}

/// Run the migration: read what the previous release holds, seal it as the opening, mark it done.
///
/// Idempotent by the marker AND by the figures. The marker is what makes a second boot cost
/// nothing; but a deployment whose records do not survive a restart re-reads the same read-only rows
/// and seals a checkpoint with the same body hash, so even there running again is indistinguishable
/// from not having run. That is the property to lean on, because it does not depend on where the
/// marker was kept.
///
/// # Errors
///
/// The ledger's own records could not be read or written, the opening could not be signed, or the
/// figures do not fit. A store that could not answer for some rows is NOT an error — those rows come
/// back named in [`Opening::unreadable`] and the node boots.
pub fn migrate(
    source: &dyn LegacyLedgerRows,
    records: &mut dyn MigrationRecords,
    node: u64,
    wall: u64,
    rate_card_version: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Outcome, MigrationError> {
    // The marker first, and the read only if there is no marker. Reading anyway would be harmless
    // arithmetic and a pointless full scan of somebody else's rows on every restart.
    if let Some(marker) = records.read_marker()? {
        return Ok(Outcome::AlreadySealed(marker));
    }

    let head = source.read_head();
    let read = source.read_figures();
    let totals = opening_totals(&read.figures)?;
    let balances = opening_balances(&head, rate_card_version);

    let checkpoint = Checkpoint::seal(
        OPENING_CHECKPOINT_SEQ,
        node,
        wall,
        opening_heads(&head, node),
        totals,
        // Nothing has been backed up under this release yet, and claiming otherwise would let
        // retention discard a segment on the strength of a backup that was never taken.
        0,
        head.seq.unwrap_or(0),
        secret,
    )?;

    let marker = MigrationMarker {
        checkpoint_seq: checkpoint.checkpoint_seq,
        node,
        sealed_at: wall,
        body_hash: checkpoint.body_hash,
        balances: checkpoint.totals.len() as u64,
        cells_read: head.cells_read,
        rate_card_version,
    };
    records.write_marker(&marker)?;

    Ok(Outcome::Sealed(Box::new(Opening {
        checkpoint,
        marker,
        balances,
        unreadable: read.unreadable,
    })))
}

/// Records that keep the marker in this node's own memory.
///
/// The honest default, and labelled as one: on a deployment whose store predates the ledger's own
/// record wire there is nowhere durable for a marker to go, so it goes here and does not survive a
/// restart. That costs a re-read of the previous release's rows on the next boot and nothing else —
/// the seal is a pure function of what was read, so the same rows seal the same checkpoint.
#[derive(Debug, Default, Clone)]
pub struct NodeLocalRecords {
    marker: std::sync::Arc<std::sync::Mutex<Option<MigrationMarker>>>,
}

impl NodeLocalRecords {
    /// A fresh one.
    pub fn new() -> Self {
        NodeLocalRecords::default()
    }

    /// Whether this node has sealed a migration in this process.
    pub fn is_sealed(&self) -> bool {
        self.marker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }
}

impl MigrationRecords for NodeLocalRecords {
    fn read_marker(&self) -> Result<Option<MigrationMarker>, MigrationError> {
        Ok(self
            .marker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone())
    }

    fn write_marker(&mut self, marker: &MigrationMarker) -> Result<(), MigrationError> {
        *self.marker.lock().unwrap_or_else(|e| e.into_inner()) = Some(marker.clone());
        Ok(())
    }
}
