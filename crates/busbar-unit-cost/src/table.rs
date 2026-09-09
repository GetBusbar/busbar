//! THE RATE TABLE: rows of `(lane, class, price per unit, effective from)`, only ever ADDED.
//!
//! Ruling 3 says price is never stored and money is a read-time conversion: a quantity times the
//! rate row in force for its `(lane, class)` at the line's own instant. This module is that
//! sentence as a data structure, and it is deliberately the smallest one that can answer it.
//!
//! **A ROW IS ADDED, NEVER EDITED AND NEVER DELETED.** There is one mutator, [`RateTable::add`], and
//! it appends. A row may name any `effective_from`, including one in the past: back-dating is how a
//! retroactive reprice happens, and it is free precisely because nothing was stored to correct. A
//! row is SUPERSEDED by a later row for the same cell, which is a statement about what the lookup
//! answers at an instant rather than an act on the earlier row: the earlier row keeps answering for
//! the instants it still covers, forever. There is no `remove`, no `set`, and no `&mut` accessor
//! that could reach a row's price. That is what makes the table an audit trail rather than a cache.
//!
//! **THE LOOKUP IS A ROW, NOT A CARD.** [`RateTable::rate_at`] resolves one cell at one instant:
//! among the rows for that `(lane, class, currency)` whose `effective_from` is at or before the
//! instant, the one with the greatest `effective_from` wins, and where two rows share an instant the
//! one added later wins. The second rule is what lets an operator correct a back-dated row by adding
//! another beside it rather than by reaching into the first.
//!
//! **A MISSING ROW IS NOT A ZERO ROW.** `rate_at` answers `None` where no row covers the instant,
//! and `Some(0)` where a row prices the cell at zero. Ruling 5 turns exactly that distinction into a
//! boot refusal: free is an EXPLICIT zero row, and nothing is priced silently. Collapsing the two
//! would make an unpriced class indistinguishable from a free one, which is the failure the ruling
//! exists to stop.
//!
//! **THE CLASS VOCABULARY IS THE CONFIG/WIRE ONE.** A row's class is spelled the way an operator
//! writes it and the way the usage JSON answers it -- `tokens_input`, `tokens_output`,
//! `tokens_cache_read`, `tokens_cache_write`, `requests`. [`RateCard`], the pricing path this table
//! is derived alongside, still keys its cells by the METER's older spellings (`input`, `output`,
//! `cache_read`, `cache_write`, and the fee as its own `fee` line). The two are the same numbers
//! under two spellings for as long as that is true, and `the_table_and_the_card_price_every_cell_
//! identically` in this crate's tests is the proof rather than the promise. When the meter's
//! posting path adopts the config/wire spelling, the card's keys move onto the table's and that test
//! keeps holding.

use std::collections::BTreeMap;

use crate::currency::CurrencyCode;
use crate::rate::{nano_rate, TierRates};

/// The class a flat per-request fee is priced under.
///
/// Ruling 4: "a flat fee = the `requests` class with a per-unit price". The fee stops being a
/// special case in the arithmetic and becomes a row like any other -- one unit of the `requests`
/// class per request, at whatever that row prices. The name is the config/wire spelling, the same
/// one a group limit already uses (`requests: 500, per: minute`), so a rate row and the cap written
/// beside it name one thing.
pub const CLASS_REQUESTS: &str = "requests";

/// The class a turn's uncached prompt tokens are priced under.
pub const CLASS_TOKENS_INPUT: &str = "tokens_input";
/// The class a turn's generated tokens are priced under.
pub const CLASS_TOKENS_OUTPUT: &str = "tokens_output";
/// The class prompt tokens served from an upstream cache are priced under.
pub const CLASS_TOKENS_CACHE_READ: &str = "tokens_cache_read";
/// The class prompt tokens written to an upstream cache are priced under.
pub const CLASS_TOKENS_CACHE_WRITE: &str = "tokens_cache_write";

/// The four token classes a 1.5.5 `rate_card:` entry prices, paired with the [`TierRates`] field
/// each one reads. The order is the canonical one, so a table derived twice from one config is the
/// same table row for row.
const TIER_CLASSES: [&str; 4] = [
    CLASS_TOKENS_INPUT,
    CLASS_TOKENS_OUTPUT,
    CLASS_TOKENS_CACHE_READ,
    CLASS_TOKENS_CACHE_WRITE,
];

/// A row's position in the table, in the order rows were added.
///
/// It ORDERS; it does not date. Two rows may share an `effective_from` and be told apart only by
/// this, which is what makes "the one added later wins" expressible. Assigned by [`RateTable::add`]
/// and never chosen by a caller: a caller that could pick its own sequence could insert a row
/// BEHIND one already answered against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RowSeq(u64);

impl RowSeq {
    /// The sequence number as an integer, for a reader that has to record it.
    #[must_use]
    pub fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for RowSeq {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Who put a row in the table.
///
/// A back-dated row re-prices work already done, so the table records which act produced it. This
/// is provenance, not policy: nothing in the lookup reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowAuthor {
    /// Derived from the deployment's `rate_card:` at boot or at a config apply.
    Config {
        /// The policy epoch the config was applied under.
        policy_epoch: u64,
    },
    /// Appended by the signed `amend_rate_history` admin verb.
    Amend {
        /// The fingerprint of the operator key that signed the amendment.
        operator_fingerprint: String,
        /// A digest of the operator's stated reason.
        reason_hash: [u8; 32],
    },
}

/// ONE RATE ROW: what one unit of one class costs on one lane, from one instant onward.
///
/// The fields are exactly the four the model names plus the two that make a row attributable (the
/// currency it prices in, and who added it). There is no `effective_until`: a row runs until a later
/// row for the same cell supersedes it, and an end date stored on a row would be a second place for
/// the same fact to live and disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateRow {
    /// The lane the traffic is served on -- the table's key for a destination.
    pub lane: String,
    /// The declared meter class the quantity belongs to, in the config/wire spelling.
    pub class: String,
    /// The currency this row prices in. Rows in different currencies are different rows: there is no
    /// pivot and no cross-rate anywhere in this crate.
    pub currency: CurrencyCode,
    /// The price of ONE unit of the class, in nano-units of the currency's minor unit. Integer, so
    /// no decimal touches money after the single conversion at the config boundary.
    pub nanos_per_unit: u64,
    /// The first instant this row answers for, inclusive, in wall-clock milliseconds. May be in the
    /// past.
    pub effective_from: u64,
    /// Who added the row.
    pub author: RowAuthor,
}

/// The cell key a row is filed under. Lane, class and currency together: the same class costs
/// different amounts on different lanes, and a lane prices several classes.
type CellKey = (String, String, CurrencyCode);

/// THE TABLE. Append-only rows, filed by cell, each cell's rows in the order they were added.
///
/// Filed per cell rather than as one flat list because the lookup is always about one cell: a flat
/// list would make every read a scan over every lane's rows, and the read is on the path that
/// answers a usage query.
#[derive(Debug, Clone, Default)]
pub struct RateTable {
    cells: BTreeMap<CellKey, Vec<(RowSeq, RateRow)>>,
    next_seq: u64,
}

impl RateTable {
    /// An empty table: no rows, so no cell is priced and every lookup refuses.
    ///
    /// Not "everything is free". A deployment that has configured no prices has not said that its
    /// traffic costs nothing; it has said nothing, and ruling 5 is what turns saying nothing into a
    /// refusal at boot rather than a silent zero on an invoice.
    #[must_use]
    pub fn new() -> Self {
        RateTable::default()
    }

    /// ADD A ROW. The only mutator.
    ///
    /// This is `amend_rate_history`'s whole effect: the signed verb decodes an operator's row and
    /// calls this, and the difference between a boot-time row and an amended one is the row's
    /// [`RowAuthor`], not the path it took to get here. `effective_from` may name any instant,
    /// including one already answered against -- that is a retroactive reprice, and it costs nothing
    /// because every read derives money afresh from the rows in force.
    ///
    /// Returns the row's sequence number, which is what a caller records to say which row it added.
    pub fn add(&mut self, row: RateRow) -> RowSeq {
        let seq = RowSeq(self.next_seq);
        self.next_seq += 1;
        let key = (row.lane.clone(), row.class.clone(), row.currency);
        self.cells.entry(key).or_default().push((seq, row));
        seq
    }

    /// THE LOOKUP: the price of one unit of `class` on `lane` in `currency` at instant `at`.
    ///
    /// Among the rows for the cell whose `effective_from` is at or before `at`, the one with the
    /// greatest `effective_from` answers; where two share an instant, the one added later answers.
    ///
    /// `None` means NO ROW COVERS THIS INSTANT, which is not the same answer as a row pricing the
    /// cell at zero. A caller that treats the two alike has turned "nobody has said what this costs"
    /// into "this is free", which is the exact substitution ruling 5's boot refusal exists to make
    /// impossible.
    #[must_use]
    pub fn rate_at(&self, lane: &str, class: &str, currency: CurrencyCode, at: u64) -> Option<u64> {
        self.row_at(lane, class, currency, at)
            .map(|r| r.nanos_per_unit)
    }

    /// The whole row in force for a cell at an instant -- the lookup above, with the row's
    /// provenance still attached, for a reader that has to say WHICH row priced a line.
    #[must_use]
    pub fn row_at(
        &self,
        lane: &str,
        class: &str,
        currency: CurrencyCode,
        at: u64,
    ) -> Option<&RateRow> {
        let key = (lane.to_string(), class.to_string(), currency);
        let rows = self.cells.get(&key)?;
        rows.iter()
            .filter(|(_, r)| r.effective_from <= at)
            .max_by_key(|(seq, r)| (r.effective_from, *seq))
            .map(|(_, r)| r)
    }

    /// Whether the table carries ANY row for this cell, at any instant.
    ///
    /// This is the question boot validation asks, and it is deliberately not "is there a row in
    /// force right now": a row that starts next week is still a price the operator has stated, and
    /// refusing a config for having planned ahead would be refusing the thing the model is for. What
    /// it refuses is a class nobody has priced at all.
    #[must_use]
    pub fn prices_cell(&self, lane: &str, class: &str, currency: CurrencyCode) -> bool {
        self.cells
            .contains_key(&(lane.to_string(), class.to_string(), currency))
    }

    /// Every lane the table carries a row for, in sorted order, without repeats.
    #[must_use]
    pub fn lanes(&self) -> Vec<&str> {
        let mut lanes: Vec<&str> = Vec::new();
        for (lane, _, _) in self.cells.keys() {
            if lanes.last() != Some(&lane.as_str()) {
                lanes.push(lane.as_str());
            }
        }
        lanes
    }

    /// Every row in the table, cell by cell, each cell's rows in the order they were added.
    pub fn rows(&self) -> impl Iterator<Item = &RateRow> + '_ {
        self.cells.values().flatten().map(|(_, r)| r)
    }

    /// How many rows the table holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cells.values().map(Vec::len).sum()
    }

    /// Whether the table holds no rows at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// THE 1.5.5 DERIVATION: the rows a deployment's `rate_card:` and `per_request_fee:` have always
    /// meant, stated as rows.
    ///
    /// This is [`RateCard::from_config`] written as a table, and it derives EXACTLY what that
    /// derives so a 1.5.5 config keeps booting and keeps pricing the same integers:
    ///
    /// - `lanes` is `None` when the deployment configures no `rate_card:` at all. That prices
    ///   nothing, so the table gets NO class rows -- not zero rows, no rows. It is the one case
    ///   where the deployment has said nothing, and the boot check in this cut treats a deployment
    ///   with no card as one that has not opted into pricing rather than as one whose every class is
    ///   unpriced.
    /// - A configured lane gets ALL FOUR token rows, including the ones the operator omitted. That
    ///   is not this function inventing a price: `RateEntryCfg`'s fields are `#[serde(default)]`, so
    ///   an omitted tier has ALREADY been read as `0.0` by the time it reaches here, and a card has
    ///   always priced it at zero. Deriving the row makes that long-standing zero EXPLICIT, which is
    ///   what ruling 5 needs it to be, and changes no arithmetic: the row's price is the same
    ///   integer the card's cell already held.
    /// - Every configured lane also gets a `requests` row at the flat `per_request_fee`, lifted from
    ///   the currency's minor units to nano-units by the same multiplication the card's fee line
    ///   uses. A deployment with a card and no fee therefore carries an explicit zero `requests`
    ///   row, which is the honest reading of "requests are free here".
    ///
    /// Every row is dated `effective_from: 0` -- the opening instant -- because a config's card has
    /// always applied to everything the deployment has ever done. That is the single-entry history
    /// whose equality with the legacy derivation is what keeps the recorded billing cells still.
    #[must_use]
    pub fn from_config<'a>(
        currency: CurrencyCode,
        lanes: Option<impl IntoIterator<Item = (&'a str, TierRates)>>,
        per_request_fee: i64,
        policy_epoch: u64,
    ) -> Self {
        let mut table = RateTable::new();
        let Some(lanes) = lanes else {
            return table;
        };
        // The same lift the card's fee line performs: a fee is configured in whole minor units, and
        // one request buys one unit of the `requests` class, so the row's per-unit price is that fee
        // scaled to nano-units. Clamped at zero for the same reason the card clamps it -- a negative
        // fee can never credit a budget.
        let fee_nanos = u128::try_from(per_request_fee.max(0))
            .unwrap_or(0)
            .saturating_mul(currency.nanos_per_minor());
        let fee_nanos = u64::try_from(fee_nanos).unwrap_or(u64::MAX);
        let author = RowAuthor::Config { policy_epoch };
        for (lane, tiers) in lanes {
            let micros = [
                tiers.input,
                tiers.output,
                tiers.cache_read,
                tiers.cache_write,
            ];
            for (class, micro) in TIER_CLASSES.iter().zip(micros) {
                table.add(RateRow {
                    lane: lane.to_string(),
                    class: (*class).to_string(),
                    currency,
                    nanos_per_unit: nano_rate(micro),
                    effective_from: 0,
                    author: author.clone(),
                });
            }
            table.add(RateRow {
                lane: lane.to_string(),
                class: CLASS_REQUESTS.to_string(),
                currency,
                nanos_per_unit: fee_nanos,
                effective_from: 0,
                author: author.clone(),
            });
        }
        table
    }
}
