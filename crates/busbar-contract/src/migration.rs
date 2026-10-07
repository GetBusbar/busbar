// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MIGRATION SEAMS: what the previous release's rows hold, read once and sealed as the opening.
//!
//! The ledger states what an opening figure MEANS; the store side reads it off the previous
//! release's rows, because that is where the loaded plugin and its row shapes already are. These
//! are the shapes the two halves trade and the three traits the store side implements and the
//! ledger consumes, so they are the contract's (the same division `slice::SliceStore` makes): the
//! store side names the contract alone.
//!
//! **It never writes to what it read.** A deployment may be booting against a read-only replica or
//! a grant-restricted database — the previous release's supported shape — so the source seams have a
//! read and nothing else. The marker the migration writes goes to the ledger's own records
//! ([`MigrationRecords`]), never onto the rows it read.

/// Why a checkpoint could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The key this deployment signs with is not available.
    KeyUnavailable(String),
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignError::KeyUnavailable(why) => write!(f, "the signing key is not available: {why}"),
        }
    }
}

impl std::error::Error for SignError {}

/// What the previous release's chain head looked like when the migration read it.
///
/// An EMPTY head is a legitimate answer, not a failure. A deployment whose store keeps nothing
/// across a restart has no head to read, and an older store that does not know how to answer says
/// so. Both seal a migration at a zero opening balance and the node serves — a refusal there would
/// mean a configuration that worked yesterday stops working on upgrade, which is the one outcome a
/// migration may not produce.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LegacyHead {
    /// The last sequence number the previous release's chain reached, if any.
    pub seq: Option<u64>,
    /// The hash at that point, if any.
    pub hash: Option<String>,
    /// The opening balance per bucket, as the previous release's rows hold it.
    pub balances: Vec<(String, i128)>,
    /// How many rows were read to arrive at those balances.
    pub cells_read: u64,
}

impl LegacyHead {
    /// The answer a store with nothing to say gives.
    pub fn empty() -> Self {
        LegacyHead::default()
    }

    /// Whether there was anything there.
    pub fn is_empty(&self) -> bool {
        self.seq.is_none() && self.balances.is_empty()
    }
}

/// Reads the previous release's chain head and balances at migration time.
pub trait LegacyMigrationSource {
    /// The head and balances. An implementation that cannot answer returns an empty head rather
    /// than an error, and the migration seals a zero opening balance.
    fn read_head(&self) -> LegacyHead;
}

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

/// What a legacy figure counts: the two dimensions the previous release's rows carry.
///
/// A class is held by its NAME, as the rows hold it; the ledger turns this into its own totals
/// dimension when it folds the figure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegacyCapDimension {
    /// A count of units admitted.
    Requests,
    /// A declared meter class, by name.
    Class(String),
}

/// One figure the previous release's rows hold.
///
/// Deliberately plain — identifiers as strings, the amount as the integer that was read. Anything
/// richer would be the ledger having an opinion about a row shape it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyFigure {
    /// Which family the figure came from.
    pub family: LegacyFamily,
    /// Which bucket it is against.
    pub bucket: String,
    /// Which window or day it fell in, as that window's opening instant in whole seconds.
    pub window: u64,
    /// Which lane served it. Empty where the row carries no lane.
    pub lane: String,
    /// Which provider served it. Empty where the row carries no provider.
    pub provider: String,
    /// What is being counted.
    pub dimension: LegacyCapDimension,
    /// How much, as the previous release's row holds it.
    pub amount: i128,
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
    /// The records could not be read. The caller decides what to do about it; the ledger will not
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
        /// Which window, as its opening instant in whole seconds.
        window: u64,
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
