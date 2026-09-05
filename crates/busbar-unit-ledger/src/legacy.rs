// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The dual write onto the previous release's rows.
//!
//! ## Why this is a trait and not an implementation
//!
//! The previous release's usage rows are a shape that belongs to the previous release. Everything
//! that reads them — the usage endpoint, an operator's dashboard, somebody's export script — must
//! see exactly what it saw before, and the way to guarantee that is to keep writing them from the
//! code that already knows their shape. This crate's contribution is to say WHAT was posted, once,
//! at the one place a posting is made, and to hand it over.
//!
//! Putting the row shape in here would mean this crate has to be edited every time that shape moves,
//! and — worse — that there would be two places that believe they know what a usage row looks like.
//! Two implementations of one wire format that can disagree is the failure mode the whole parity
//! exercise exists to avoid.
//!
//! ## Failure is not a settlement failure
//!
//! The binding is best-effort by design. A settlement that failed because a legacy row would not
//! write would be a behavioural change in the worst possible direction: the previous release
//! settled, so this one has to. The error comes back so the integrator can count it and alarm on it,
//! and the settlement stands either way.

/// One posting, in the terms the previous release's rows are written from.
///
/// Deliberately plain: identifiers as strings, amounts as the unsigned figures a posting carries.
/// Anything richer would be this crate having an opinion about a shape it does not own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyPosting {
    /// Whose posting it is.
    pub principal: String,
    /// Which bucket it was against.
    pub bucket: String,
    /// Which window it fell in.
    pub window_start: u64,
    /// What had been reserved for the unit.
    pub reserved: u64,
    /// What was actually posted.
    pub settled: u64,
    /// How much of what was posted had no reservation behind it.
    pub overdraft: u64,
}

/// Why a legacy row could not be written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegacyWriteError {
    /// The store behind the rows was not usable.
    Unavailable(String),
}

impl std::fmt::Display for LegacyWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LegacyWriteError::Unavailable(why) => {
                write!(f, "the previous release's rows could not be written: {why}")
            }
        }
    }
}

impl std::error::Error for LegacyWriteError {}

/// The binding the integrator supplies: where a posting also goes.
pub trait LegacyRows: Send {
    /// Write one posting onto the previous release's rows.
    fn write(&mut self, posting: &LegacyPosting) -> Result<(), LegacyWriteError>;
}

/// A binding that keeps what it was handed, so a test can look at it and an integrator has
/// something to start from.
#[derive(Debug, Default, Clone)]
pub struct RecordingRows {
    written: std::sync::Arc<std::sync::Mutex<Vec<LegacyPosting>>>,
}

impl RecordingRows {
    /// A fresh one.
    pub fn new() -> Self {
        RecordingRows::default()
    }

    /// A snapshot of everything written, in order.
    pub fn written(&self) -> Vec<LegacyPosting> {
        self.written
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl LegacyRows for RecordingRows {
    fn write(&mut self, posting: &LegacyPosting) -> Result<(), LegacyWriteError> {
        self.written
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(posting.clone());
        Ok(())
    }
}

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

/// The opening entries a migration seals: one per bucket, at the named card version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningBalance {
    /// Which bucket.
    pub bucket: String,
    /// What it opens at.
    pub amount: i128,
    /// Which card version the opening was priced under.
    pub rate_card_version: u64,
}

/// Turn what the previous release held into the opening balances a migration seals.
///
/// An empty head produces an empty list, which seals a migration at zero. That is the whole of the
/// special case, and it is not special: nothing was there, so nothing opens.
pub fn opening_balances(head: &LegacyHead, rate_card_version: u64) -> Vec<OpeningBalance> {
    head.balances
        .iter()
        .map(|(bucket, amount)| OpeningBalance {
            bucket: bucket.clone(),
            amount: *amount,
            rate_card_version,
        })
        .collect()
}
