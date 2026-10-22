// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a checkpoint seals: the running figures for one bucket, in one dimension, at one scope.
//!
//! ## Why the key is three things and not one
//!
//! A bucket is a pot of budget. A dimension is what is being counted out of it — money, requests,
//! concurrency, or any declared meter class. A scope narrows a bucket to a pool. The same bucket in
//! two dimensions has two independent balances, and folding them into one figure would mean a token
//! cap and a spend cap could pay each other's overdrafts. So the key carries all three, and every
//! figure below is per key.
//!
//! ## Why every figure is a signed 128-bit integer
//!
//! Amounts are nano-units, so a modest deployment's yearly turnover already needs more than 64 bits
//! of headroom. Signed, because some figures move both ways: an unconfirmed settlement moves out of
//! the settled column and back again, and an overdraft is carried in and out; storing them as
//! unsigned figures with a separate direction flag is how a sign error becomes invisible. Nothing
//! here is floating point, for the reason nothing in a ledger ever is.

//! ## ONE GUARD POLICY FOR THE BOOK: EVERY BOOK OPERATOR SATURATES
//!
//! Every arithmetic operator in this file that moves or derives a BOOK figure saturates — the same
//! policy `settle.rs` states, for the same reason, so the two files that move the books cannot be
//! read as disagreeing about it. The statement below is not the book: it is a money READER, and it
//! refuses an overflow as every other reader does ([`totals_as_of`]).
//!
//! The two derived figures below are the ones that mattered. `headroom` subtracted four `i128`s
//! bare and `overdraft_carried` two, in a file whose statement fold thirty lines further down
//! already used `saturating_add` — one file, two policies, and the unguarded pair were the figures
//! the budget gate reads. Measured: `budget = 0`, `settled = i128::MAX`, `open_holds = i128::MAX`
//! is a book with `-340282366920938463463374607431768211454` of headroom, and the bare subtraction
//! returns **`2`**. An exhausted budget reporting two nano-units of room is a request admitted.
//! Saturated, the same book returns `i128::MIN` — no room, which is the true reading narrowed to
//! what the type can say, and it fails CLOSED.
//!
//! Saturation is also why the figures stay derived rather than stored: pinning at a bound is only
//! honest if the bound is recomputed from the columns every read, and a saturated figure written
//! back into a column would be a lie the next read could not detect.
//!
//! ## The book is bounded
//!
//! A balance is kept per window, so a book nothing retired would grow by every rolling window every
//! key ever touched. A window past [`WINDOW_RETENTION_SECS`] that a checkpoint sealed at the figures
//! the book still holds is retired ([`Book::retirable`], [`Book::retire`]); the all-time window
//! never is.

use std::collections::BTreeMap;

use crate::cost::{HistorySeq, HistoryView};
use busbar_contract::caps::MeterClassId;

use crate::recompute::{price_line, Divergence, Posting};

/// Which pot of budget.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BucketId(String);

impl BucketId {
    /// Name a bucket.
    pub fn new(id: impl Into<String>) -> Self {
        BucketId(id.into())
    }

    /// Its name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BucketId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What is being counted out of a bucket.
///
/// A closed shape over an open key: the four forms are fixed, but any declared meter class can be
/// the subject of the fourth, so a deployment with no rate card still has volume control.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CapDimension {
    /// Money, in nano-units.
    NanoUnits,
    /// A count of units admitted.
    Requests,
    /// How many units may be in flight at once.
    Concurrent,
    /// Any declared meter class, by name.
    ///
    /// The class is held as its NAME rather than as the capability crate's identifier, and the
    /// reason is mechanical rather than aesthetic: a checkpoint's figures are digested in key order
    /// and signed, so the key has to have a total order. The identifier does not have one, and it
    /// is not this crate's to give it one. [`CapDimension::class`] does the conversion in one place
    /// so no call site has to think about it.
    Class(String),
}

impl CapDimension {
    /// The dimension for a declared meter class.
    pub fn class(id: &MeterClassId) -> Self {
        CapDimension::Class(id.as_str().to_string())
    }
}

impl std::fmt::Display for CapDimension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CapDimension::NanoUnits => f.write_str("nano-units"),
            CapDimension::Requests => f.write_str("requests"),
            CapDimension::Concurrent => f.write_str("concurrent"),
            CapDimension::Class(c) => write!(f, "class {c}"),
        }
    }
}

/// How wide a bucket's reach is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BucketScope {
    /// Everything the bucket covers.
    All,
    /// One named pool inside it.
    Pool(String),
}

impl std::fmt::Display for BucketScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BucketScope::All => f.write_str("all"),
            BucketScope::Pool(name) => write!(f, "pool:{name}"),
        }
    }
}

/// The three things that make one balance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TotalsKey {
    /// Which pot.
    pub bucket: BucketId,
    /// Counting what.
    pub dimension: CapDimension,
    /// How wide.
    pub scope: BucketScope,
}

impl TotalsKey {
    /// Build a key.
    pub fn new(bucket: BucketId, dimension: CapDimension, scope: BucketScope) -> Self {
        TotalsKey {
            bucket,
            dimension,
            scope,
        }
    }
}

impl std::fmt::Display for TotalsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}/{}", self.bucket, self.dimension, self.scope)
    }
}

/// A window's opening instant, in whole seconds. Windows do not overlap, so this identifies one.
pub type WindowStart = u64;

/// The all-time window: the one a `total` budget counts in. It opens at zero and never rolls, so it
/// is never over and never retired.
pub const ALL_TIME_WINDOW: WindowStart = 0;

/// **HOW LONG A ROLLING WINDOW'S BALANCES ARE KEPT IN MEMORY**: thirty-one days from the instant the
/// window opened.
///
/// The horizon 1.5.5 bounded its in-memory totals by: its budget cells were swept once
/// `window_start + 31 days` had passed (`max_window`), and its in-memory store kept its usage and
/// metering rows exactly as long. Thirty-one days is the longest window a budget can name, a
/// calendar month, so a window is never retired while it can still be the current one. The durable
/// record of every posting is the node's journal; this bounds only what the process holds.
pub const WINDOW_RETENTION_SECS: u64 = 31 * 86_400;

/// Whether `window` is past the retention horizon at `now` (wall seconds): a rolling window that
/// opened [`WINDOW_RETENTION_SECS`] or more before `now`. The all-time window never is.
pub fn past_retention(window: WindowStart, now: u64) -> bool {
    window != ALL_TIME_WINDOW && window.saturating_add(WINDOW_RETENTION_SECS) <= now
}

/// One balance's running figures, as a checkpoint seals them.
///
/// Every field is a running total for one key, not a delta. The identity is stated over the
/// DIFFERENCE between two of these, which is why nothing here has to be reset at a window boundary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Totals {
    /// What the window was allowed to spend.
    pub budget: i128,
    /// How much has been taken out of the store for this key.
    pub drawn: i128,
    /// How much of what was drawn has been given back.
    pub released: i128,
    /// How much has actually been posted.
    pub settled: i128,
    /// How much is reserved against holds that have not closed.
    pub open_holds: i128,
    /// How much sits in slices that have been drawn but not yet spent or released.
    pub open_slice_remainders: i128,
    /// How much has been moved by a correction, positive or negative.
    pub adjustments: i128,
    /// How much has been posted that the journal has not yet confirmed: a settlement moves here out
    /// of `settled` until its append is acknowledged ([`crate::settle::Ledger::record_unreconciled`]).
    pub unreconciled: i128,
    /// Overdraft carried into this window from the last one.
    pub overdraft_carried_in: i128,
    /// Overdraft this window is carrying out to the next.
    pub overdraft_carried_out: i128,
    /// Value that has crossed this window's boundary: what went OUT, less what came IN.
    ///
    /// The sign takes a moment and is worth stating plainly. The identity asks "everything drawn
    /// into this window — where is it now?", and value that was transferred out is still accounted
    /// for, just somewhere else. So a transfer OUT is positive here (it stands in for the value that
    /// left the other columns) and a transfer IN is negative (the value arrived in another column
    /// without this window having drawn it). Both sides of one transfer are recorded together, so
    /// neither window can be left holding half of it.
    pub cross_window_transfers: i128,
    /// How much is under dispute.
    pub disputed: i128,
    /// The age of the oldest hold still open, in seconds.
    pub oldest_open_hold_age_secs: u64,
    /// How many disputes are open.
    pub open_dispute_count: u64,
    /// The age of the oldest open dispute, in seconds.
    pub oldest_dispute_age_secs: u64,
    /// How many billable requests have settled on this balance: one flat fee each. A count, not a
    /// figure — the reconciliation's count half reads it against the previous release's billable
    /// requests for the same row.
    pub fee_count: u64,
}

impl Totals {
    /// Nothing yet.
    pub fn zero() -> Self {
        Totals::default()
    }

    /// The single overdraft figure the identity uses: what is being carried OUT, less what was
    /// carried IN.
    ///
    /// Stated as one derived figure rather than left as two fields, because the identity subtracts
    /// "overdraft carried" once and a reader should not have to guess which of the two it meant.
    /// The two fields survive separately because a checkpoint seals both, and an operator asking
    /// "what did the last window hand us" is asking for the one the identity has already folded in.
    pub fn overdraft_carried(&self) -> i128 {
        self.overdraft_carried_out
            .saturating_sub(self.overdraft_carried_in)
    }

    /// What is left of the budget once everything posted, held, and carried is accounted for.
    pub fn headroom(&self) -> i128 {
        self.budget
            .saturating_sub(self.settled)
            .saturating_sub(self.open_holds)
            .saturating_sub(self.overdraft_carried_in)
    }
}

/// Every balance the node is keeping, keyed by bucket, dimension, scope and window.
///
/// A `BTreeMap` rather than a hash map on purpose: a checkpoint's body is hashed and signed, and a
/// signature over a map with a non-deterministic iteration order would verify on the node that made
/// it and nowhere else.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Book {
    totals: BTreeMap<(TotalsKey, WindowStart), Totals>,
}

impl Book {
    /// An empty book.
    pub fn new() -> Self {
        Book::default()
    }

    /// The totals for one key in one window, zeros if the key has not been touched.
    pub fn get(&self, key: &TotalsKey, window: WindowStart) -> Totals {
        self.totals
            .get(&(key.clone(), window))
            .copied()
            .unwrap_or_default()
    }

    /// Change the totals for one key in one window.
    pub fn entry(&mut self, key: TotalsKey, window: WindowStart) -> &mut Totals {
        self.totals.entry((key, window)).or_default()
    }

    /// Every key and window in the book, in a fixed order.
    pub fn iter(&self) -> impl Iterator<Item = (&(TotalsKey, WindowStart), &Totals)> {
        self.totals.iter()
    }

    /// How many balances the book holds.
    pub fn len(&self) -> usize {
        self.totals.len()
    }

    /// Whether the book holds nothing.
    pub fn is_empty(&self) -> bool {
        self.totals.is_empty()
    }

    /// **THE WINDOWS THE BOOK MAY LET GO** at `now`, measured against `sealed`, the figures a
    /// checkpoint already sealed: every window past the retention horizon ([`past_retention`]) whose
    /// balances the book holds exactly as `sealed` holds them, none of them with a hold still open.
    ///
    /// Each condition is a reason the book is no longer the only record of the window. Past the
    /// horizon, no budget can name it as current. Sealed at the same figures, a signed checkpoint
    /// holds everything the book would drop, so nothing moved since the seal is lost with it. With
    /// no hold open, no settlement is still on its way to it. A window that fails any one of them
    /// stays, whole: retiring part of a window would leave the dual-write rows, which are kept per
    /// window, holding a balance the book no longer does.
    pub fn retirable(
        &self,
        sealed: &BTreeMap<(TotalsKey, WindowStart), Totals>,
        now: u64,
    ) -> std::collections::BTreeSet<WindowStart> {
        let mut retirable = std::collections::BTreeSet::new();
        let mut kept = std::collections::BTreeSet::new();
        for (at, figures) in &self.totals {
            let window = at.1;
            if !past_retention(window, now) {
                continue;
            }
            if figures.open_holds == 0 && sealed.get(at) == Some(figures) {
                retirable.insert(window);
            } else {
                kept.insert(window);
            }
        }
        retirable.retain(|window| !kept.contains(window));
        retirable
    }

    /// Retire every balance in `windows`, and say how many balances went.
    ///
    /// The owner decides which windows go ([`Book::retirable`] is the rule, and
    /// [`crate::settle::Ledger::retire_windows`] applies it to the book and the dual-write rows
    /// in one step); retiring a window no checkpoint sealed loses balances nobody else holds.
    ///
    /// A retired window reads back as zeros through [`Book::get`], exactly like one never touched,
    /// and the survivors keep the order [`Book::iter`] and [`Book::snapshot`] already gave them — the
    /// order a checkpoint body is hashed in.
    pub fn retire(&mut self, windows: &std::collections::BTreeSet<WindowStart>) -> usize {
        let before = self.totals.len();
        self.totals.retain(|(_, at), _| !windows.contains(at));
        before.saturating_sub(self.totals.len())
    }

    /// The book as a plain map, for a checkpoint to seal.
    pub fn snapshot(&self) -> BTreeMap<(TotalsKey, WindowStart), Totals> {
        self.totals.clone()
    }
}

/// What one balance came to on a statement, re-derived from the quantities.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatementRow {
    /// The money, in nano-units, summed over the balance's lines.
    pub priced_nanos: i128,
    /// The request fees the balance's lines carry between them.
    pub fee_count: u64,
    /// How many lines the figure covers, so the granularity it summarises is stated.
    pub lines: u64,
}

/// A line a statement could not price, and why.
///
/// It is listed rather than dropped and rather than counted as zero: a hole in the history, a lane
/// the card does not name and a class it names no price for are all refusals, and a statement that
/// silently omitted them would read as a smaller bill rather than as an incomplete one. A line that
/// hit several unpriced classes is listed once per class, so every class the card cannot price is
/// named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unpriced {
    /// Which node wrote the line.
    pub node: u64,
    /// That node's sequence number for it.
    pub node_seq: u64,
    /// Why it could not be priced.
    pub why: Divergence,
}

/// A statement, cut AS OF a history snapshot.
///
/// The snapshot is on the face of it, because that is what makes the statement reproducible: name
/// the two inputs — the quantities and the history at this number — and the same figures come back
/// forever, whatever has happened to the card since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    /// The history snapshot the figures were derived against: `None` for a statement cut from the
    /// current view of a history nothing has been appended to, which names no snapshot.
    pub history_seq: Option<HistorySeq>,
    /// The window it covers.
    pub window: WindowStart,
    /// The balances, in key order.
    pub rows: BTreeMap<TotalsKey, StatementRow>,
    /// The lines that could not be priced, one entry per reason: a line with three unpriced
    /// classes is three entries. A line listed here moves no row.
    pub unpriceable: Vec<Unpriced>,
}

impl Statement {
    /// One balance's figures, zeros if the statement covers none.
    pub fn row(&self, key: &TotalsKey) -> StatementRow {
        self.rows.get(key).copied().unwrap_or_default()
    }
}

/// Cut a statement as of a history snapshot: **re-derived from the quantities, every time**.
///
/// This is the read path for money, and it can only re-derive: a booked line carries quantities and
/// an instant and no price at all, so every figure here is the lookup's answer for the line's
/// quantities against the view the caller named, never a figure stored beside them.
///
/// The sum is CHECKED, as every other money reader in this crate is. A line whose figure would carry
/// its balance past what the row can hold is listed as [`Divergence::Overflow`] and moves no row: a
/// sum pinned at the ceiling would be a figure nobody posted (item 28).
///
/// The tier is the line's own: a tier is a property of the chain a request was admitted through,
/// and an amendment to the price of a token is not a re-decision about which chain admitted it.
///
/// `lines` comes last because the first two arguments are the statement's identity — which
/// history and which window — and the lines are what that identity is applied to.
/// Only lines in `window` are counted; lines in another window belong on another statement.
pub fn totals_as_of<'a>(
    view: &HistoryView<'_>,
    window: WindowStart,
    lines: impl IntoIterator<Item = &'a Posting>,
) -> Statement {
    let mut rows: BTreeMap<TotalsKey, StatementRow> = BTreeMap::new();
    let mut unpriceable = Vec::new();
    for line in lines {
        if line.window_start != window {
            continue;
        }
        match price_line(line, view, line.tier_bp) {
            // A lane the card in force does not name is a REFUSAL, not a line of fees: #42 —
            // *"a hit class not priced ⇒ REFUSE … FAILS if billing-on & unpriced"* — and a lane
            // the card is silent about prices none of the classes it hit.
            // The read lookup reports it as a flag rather than an error, so the statement turns
            // the flag into the refusal here, and the line moves no row.
            Ok(priced) if priced.lane_unpriced => unpriceable.push(Unpriced {
                node: line.node,
                node_seq: line.node_seq,
                why: Divergence::LaneUnpriced {
                    card_seq: priced.card_seq,
                    lane: line.lane.clone(),
                },
            }),
            // A class the card names no price for is listed, EVERY one of them (#42 for a class as
            // well as a lane, the fail-closed rule `price_fail_closed` applies at settlement). A
            // line that hit one cannot be priced, so it moves no row either: a statement that
            // summed the classes it could price and dropped the rest would read as a smaller bill
            // rather than as an incomplete one.
            Ok(priced) if priced.lines.iter().any(|l| l.unpriced) => {
                for class in priced.unpriced_classes() {
                    unpriceable.push(Unpriced {
                        node: line.node,
                        node_seq: line.node_seq,
                        why: Divergence::ClassUnpriced {
                            card_seq: priced.card_seq,
                            lane: line.lane.clone(),
                            class: class.to_string(),
                        },
                    });
                }
            }
            Ok(priced) => {
                let row = rows.get(&line.key).copied().unwrap_or_default();
                let summed = i128::try_from(priced.priced_nanos)
                    .ok()
                    .and_then(|figure| row.priced_nanos.checked_add(figure))
                    .zip(row.fee_count.checked_add(priced.fee_count))
                    .zip(row.lines.checked_add(1));
                match summed {
                    Some(((priced_nanos, fee_count), lines)) => {
                        rows.insert(
                            line.key.clone(),
                            StatementRow {
                                priced_nanos,
                                fee_count,
                                lines,
                            },
                        );
                    }
                    None => unpriceable.push(Unpriced {
                        node: line.node,
                        node_seq: line.node_seq,
                        why: Divergence::Overflow,
                    }),
                }
            }
            Err(why) => unpriceable.push(Unpriced {
                node: line.node,
                node_seq: line.node_seq,
                why: crate::recompute::divergence_of(why),
            }),
        }
    }
    Statement {
        history_seq: view.seq(),
        window,
        rows,
        unpriceable,
    }
}
