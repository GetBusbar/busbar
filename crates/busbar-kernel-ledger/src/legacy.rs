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
    /// How many billable requests the posting is: the count the flat fee is charged on, and the
    /// figure the previous release's rows keep as the row's billable requests.
    pub fee_count: u64,
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

/// A binding that keeps EVERY posting it was handed, in order, so a test can look at each one.
///
/// **A TEST RECORDER, NOT A PRODUCTION BINDING.** It grows by one posting per settlement for the
/// life of the process, which is right for a battery that checks posting by posting and wrong for a
/// node that settles all day. A node binds [`SummedRows`], which holds one row per cell whatever
/// the traffic has been.
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

    /// Show each posting to a fold, in order, without copying any of them.
    ///
    /// What a reader that only wants a sum should take. [`written`](Self::written) copies the whole
    /// history — every posting, every owned string in it — to produce an answer whose size does not
    /// depend on the history at all, and a reader holding a lock while it does that makes the copy
    /// everyone else's problem too.
    pub fn fold_written(&self, take: &mut dyn FnMut(&LegacyPosting)) {
        for posting in self
            .written
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            take(posting);
        }
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

/// The cell a previous release's row is kept at: whose, against which bucket, in which window.
type Cell = (String, String, u64);

/// **THE PRODUCTION BINDING**: the previous release's rows as running sums, one per cell.
///
/// What a node's dual write has to keep in memory is what its readers read, and its one reader —
/// the reconciliation view — sums the postings per bucket and window. So this keeps exactly that
/// shape, one level finer (the principal stays in the cell, so a row still names whose it is):
/// every posting into a cell adds its four figures onto that cell's row and is not itself kept.
/// Memory is bounded by the cells the node has settled into, never by how many settlements it has
/// made — a cell settled into a million times is one row.
///
/// The postings themselves are not lost by this. The durable record of every settlement is the
/// node's journal, written before the book moves, and a restart replays it through the same dual
/// write, which rebuilds these sums exactly. This is the in-memory cross-check, and a cross-check
/// over sums needs only the sums.
///
/// Every figure saturates rather than wraps, as every book operator does (`settle.rs`, `totals.rs`):
/// a sum pinned at its bound is a reading a reconciliation can still flag, where a wrapped one is a
/// small number that looks true.
#[derive(Debug, Default, Clone)]
pub struct SummedRows {
    cells: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<Cell, LegacyPosting>>>,
}

impl SummedRows {
    /// A fresh one, holding no row.
    pub fn new() -> Self {
        SummedRows::default()
    }

    /// How many rows it holds: one per cell settled into, however many postings each took.
    pub fn len(&self) -> usize {
        self.cells.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Whether nothing has been posted.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A copy of every row, in cell order.
    pub fn rows(&self) -> Vec<LegacyPosting> {
        self.cells
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect()
    }

    /// Show each row to a fold, in cell order, without copying any of them.
    pub fn fold_rows(&self, take: &mut dyn FnMut(&LegacyPosting)) {
        for row in self
            .cells
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
        {
            take(row);
        }
    }
}

impl LegacyRows for SummedRows {
    fn write(&mut self, posting: &LegacyPosting) -> Result<(), LegacyWriteError> {
        let mut cells = self.cells.lock().unwrap_or_else(|e| e.into_inner());
        let cell = (
            posting.principal.clone(),
            posting.bucket.clone(),
            posting.window_start,
        );
        match cells.get_mut(&cell) {
            Some(row) => {
                row.reserved = row.reserved.saturating_add(posting.reserved);
                row.settled = row.settled.saturating_add(posting.settled);
                row.overdraft = row.overdraft.saturating_add(posting.overdraft);
                row.fee_count = row.fee_count.saturating_add(posting.fee_count);
            }
            None => {
                cells.insert(cell, posting.clone());
            }
        }
        Ok(())
    }
}

/// The head the migration reads and the seam it reads it through: the contract's, because the
/// store adapter implements the seam on the other side of it.
pub use busbar_contract::migration::{LegacyHead, LegacyMigrationSource};

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
