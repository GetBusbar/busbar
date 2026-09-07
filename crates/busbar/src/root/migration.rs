// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The first boot after an upgrade: what the previous release already holds, sealed as the ledger's
//! opening figures.
//!
//! ## Where this runs in the boot order, and why exactly there
//!
//! Immediately AFTER the durability branch — the step that builds the journal and constructs the
//! ledger dual-writing onto the previous release's rows — and BEFORE the transport-key unit
//! provisions a listener, which is the step before anything binds an address.
//!
//! Both edges are load-bearing.
//!
//! It cannot run earlier: the opening is a checkpoint the ledger seals, and there is no ledger until
//! the durability step has built one. It cannot run later: the first accepted connection can settle,
//! and a settlement posted before the opening was sealed would be measured from a checkpoint that
//! did not exist when it happened — the residual would be off by the whole of the previous release's
//! history, on a deployment where that history is the entire point.
//!
//! The store adapter is already in hand by then, because the durability step took its shipper and
//! its legacy-rows path from it. So this step adds no new dependency to the boot; it adds one read
//! and one seal between two steps that already exist.
//!
//! ## Where the marker goes
//!
//! On the journal, beside the opening checkpoint it is a marker for. It used to go into the store
//! adapter's node-local shim, which was the honest place for it while there was nowhere else — but
//! the shim holds it for the life of a process only, so a node with a data directory re-read the
//! previous release's rows on every single boot and the one record that says "this deployment has
//! already opened its balances" was the one record with nowhere durable to live.
//!
//! It still does not go into the rows that were READ. Those may be on a read-only replica, and a
//! marker written beside somebody else's data is a migration that has quietly taken ownership of a
//! schema it does not own. The journal is this release's own record, which is exactly what the
//! ledger unit's records seam asked for.
//!
//! ## What the root decides and what it does not
//!
//! The root decides WHICH rows are read, because it is the only thing that has both the loaded store
//! and the resolved configuration: the key rows name their own buckets, and the configured group
//! buckets and the metering days come off the config. Everything after that — what an opening figure
//! is, how it folds into a balance, what the marker says — belongs to the ledger unit, and this
//! module does not have an opinion about any of it.
//!
//! ## Nothing there is fine. Would not say is not.
//!
//! Two answers a store can give look identical in the opening and mean opposite things.
//!
//! A store with NOTHING IN IT seals an opening at zero and the node serves. That is a real, ordinary
//! deployment — a fresh install, or one whose store keeps nothing across a restart — and refusing it
//! would mean a configuration that worked yesterday stops working on upgrade, which is the one
//! outcome a migration may not produce.
//!
//! A store that WOULD NOT ANSWER is a boot refusal. It used to seal an opening over the rows it could
//! reach and carry on, which reads as the same zero: a node that came up with a year of consumption
//! missing from its opening, an identity quietly short by exactly that history, and nothing on the
//! serving path that would ever notice — every later figure reconciles against an opening that was
//! wrong from the first instant. Booting empty over an unreadable store is not degraded operation, it
//! is a wrong ledger presented as a right one, so this step stops instead and names what it could not
//! read. The cost is a boot that fails loudly on a store outage; the alternative is books nobody can
//! ever reconstruct.
//!
//! The ledger unit itself still does not refuse — it seals what it read and withholds the marker so a
//! later boot can complete the read. The decision to serve or not is the ROOT'S, because only the root
//! knows this is a boot.
//!
//! ## The card the opening is priced under
//!
//! The migration seals a rate-card history of exactly one entry: the deployment's configured 1.5.5
//! card, read as a card naming exactly one currency (USD, whose minor unit is the cent every 1.5.5
//! figure was already projected through), effective from instant zero, open-ended,
//! [`busbar_unit_cost::Author::Opening`].
//!
//! Effective from ZERO and not from the seal, deliberately. Pre-migration rows carry no instant finer
//! than the UTC day and were earned under this card by definition; an entry starting at the seal would
//! leave every one of them in a hole, and a hole is a refusal rather than a zero. With one open-ended
//! entry, `card_at(t)` answers entry zero for every instant, so a lookup over the previous release's
//! quantities is arithmetically its read-time derivation at that card — same rates, same order, same
//! saturation, same single truncation. That is why a deployment that never edits a price sees no
//! change at all.
//!
//! The card is an ARGUMENT rather than something read here. The root holds the resolved configuration
//! and the root hands it over; a migration step that built a card out of configuration itself would be
//! a second place in the tree that decides what a configured rate means.

use busbar_plugin_loader::store_adapter::StoreAdapter;
use busbar_unit_cost::{
    price, CurrencyCode, History, HistorySeq, Posting, Quantity, Unpriceable, STANDARD_TIER_BP,
};
use busbar_unit_ledger::checkpoint::CheckpointSecret;
use busbar_unit_ledger::migration::{
    migrate, LegacyFamily, LegacyFigure, LegacyLedgerRows, MigrationError, MigrationRecords,
    Outcome, OPENING_HISTORY_SEQ,
};
use busbar_unit_ledger::totals::CapDimension;

/// What the root reads out of configuration to decide which of the previous release's rows to read.
// No `Default` and no `PartialEq`: a card is neither. There is no default rate card — a deployment
// that configured none has an ABSENT card, which is a decision somebody made and not a value that
// falls out of a derive — and two cards being "equal" is a question about prices that only the
// lookup may answer.
#[derive(Debug, Clone)]
pub struct MigrationConfig {
    /// Which node is sealing.
    pub node: u64,
    /// The window in force for the key buckets, as its opening instant in whole seconds.
    pub window: u64,
    /// The configured group buckets and the window each is on. Not discoverable from the store —
    /// a budget group is a configuration fact — so the root names them.
    pub group_buckets: Vec<(String, u64)>,
    /// The metering days to read.
    pub metering_days: Vec<u64>,
    /// The deployment's configured card, as the one entry of the opening history.
    ///
    /// A 1.5.5 card has no currency; it is read here as a card naming exactly one — USD, whose minor
    /// unit is the cent every 1.5.5 figure was already projected through — so every figure is
    /// bit-identical and nothing about such a deployment changes.
    ///
    /// It replaces the card VERSION this config used to carry. The version was a number an operator
    /// asserted and nothing checked; the card is the thing itself, journaled with the opening, and
    /// its number is the history's to assign.
    pub rate_card: busbar_unit_cost::RateCard,
}

/// What the migration step did.
#[derive(Debug, Clone)]
pub struct Migration {
    /// Whether this boot sealed the opening, and what it sealed.
    pub outcome: Outcome,
    /// The rate-card history this deployment opens with: exactly one entry, effective from instant
    /// zero, holding the configured card.
    ///
    /// Carried on BOTH outcomes, and it has to be. A second boot finds the marker and reads no rows,
    /// but it still has to price what the first boot opened — the history is a pure function of the
    /// configured card, so the boot that sealed nothing rebuilds the identical single entry rather
    /// than serving with no card in force and every instant a hole.
    pub history: History,
}

impl Migration {
    /// Whether this boot did the sealing, as opposed to finding a marker already there.
    #[must_use]
    pub fn sealed_now(&self) -> bool {
        self.outcome.sealed_now()
    }
}

/// Why the node will not boot.
///
/// Deliberately a wider type than the ledger unit's error. That unit may not refuse — it seals what it
/// read and reports what it could not, because a node has to be able to boot over a partial answer if
/// somebody decides that is acceptable. Deciding is this step's, and it decides no: see this module's
/// preamble for why an opening sealed over rows the store would not answer for is worse than a boot
/// that stops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The ledger unit could not complete: the opening would not sign, the ledger's own records were
    /// not usable, or the figures do not fit in a ledger figure.
    Ledger(MigrationError),
    /// The previous release's rows could not be read. Each unanswered read is named.
    ///
    /// NOT the same as an empty store, and the distinction is the whole point of the arm: an empty
    /// store returns no names and boots.
    Unreadable(Vec<String>),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Ledger(e) => write!(f, "{e}"),
            Refusal::Unreadable(rows) => write!(
                f,
                "the previous release's rows could not be read, so this node will not open its \
                 balances over a reading it knows is short ({}). An opening sealed over rows the \
                 store would not answer for is a ledger that reconciles against a figure that was \
                 wrong from the first instant. Fix the store and boot again; nothing has been \
                 written: {}",
                rows.len(),
                rows.join("; ")
            ),
        }
    }
}

impl std::error::Error for Refusal {}

impl From<MigrationError> for Refusal {
    fn from(e: MigrationError) -> Self {
        Refusal::Ledger(e)
    }
}

/// The history a migration opens with: one entry, the configured card, effective from instant zero.
///
/// A free function, and pure, so the claim "a 1.5.5 node upgrading gets exactly one opening entry"
/// is checkable by a test that booted nothing and read no store.
#[must_use]
pub fn opening_history(card: busbar_unit_cost::RateCard, appended_at_ms: u64) -> History {
    History::opening(card, appended_at_ms)
}

/// One of the previous release's metering rows, as a posting the lookup can price.
///
/// The quantities are the row's own counts, unchanged and un-summed — they are the TRUTH, and the
/// only reason this type exists is that the previous release kept them one dimension at a time and a
/// lookup prices a whole row at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyRowPosting {
    /// The key the row was charged to.
    pub bucket: String,
    /// The provider that served it. Not on the posting — the card is keyed by lane — but kept so a
    /// reader can put a priced figure back beside the row it came from.
    pub provider: String,
    /// The UTC day the row falls in, as its opening instant in whole seconds.
    pub day: u64,
    /// The posting itself: lane, quantities, fee count, and the instant the history resolves at.
    pub posting: Posting,
}

/// Read the previous release's metering rows as postings.
///
/// **Quantities are the truth.** Every class the row counted crosses over under the same spelling the
/// card is keyed by, so no name is translated between a row and the entry that prices it. Nothing is
/// summed across rows and nothing is priced here.
///
/// The WINDOW family is deliberately not read: those figures are the enforcement ledger's view of the
/// same consumption, and pricing both would bill a deployment twice for one day's traffic. The two
/// families are kept apart in the opening for exactly this reason, and this function keeps them apart
/// for the same one.
///
/// `arrived_ms` is the day's opening instant in milliseconds. A pre-migration row carries no instant
/// finer than the UTC day, so that is the most precise honest reading there is — and against a
/// single-entry history it resolves to entry zero whatever it is, which is what makes the imprecision
/// cost nothing here and remain visible for anything that later cares.
#[must_use]
pub fn legacy_row_postings(figures: &[LegacyFigure]) -> Vec<LegacyRowPosting> {
    // Grouped in the order the rows came back, not sorted: the previous release's row order is the
    // one an operator comparing this against a `/usage` answer is holding.
    let mut out: Vec<LegacyRowPosting> = Vec::new();
    let mut at: std::collections::HashMap<(String, String, String, u64), usize> =
        std::collections::HashMap::new();
    for figure in figures.iter().filter(|f| f.family == LegacyFamily::Meter) {
        let key = (
            figure.bucket.clone(),
            figure.lane.clone(),
            figure.provider.clone(),
            figure.window,
        );
        let slot = match at.get(&key) {
            Some(slot) => *slot,
            None => {
                at.insert(key, out.len());
                out.push(LegacyRowPosting {
                    bucket: figure.bucket.clone(),
                    provider: figure.provider.clone(),
                    day: figure.window,
                    posting: Posting {
                        lane: figure.lane.clone(),
                        quantities: Vec::new(),
                        fee_count: 0,
                        // The previous release has one tier and no way to express another, so the
                        // standard multiplier is not a default here — it is the only rate a
                        // pre-migration row was ever charged at.
                        tier_bp: STANDARD_TIER_BP,
                        arrived_ms: figure.window.saturating_mul(1_000),
                        // A day bucket orders nothing within itself, and there is no monotonic
                        // reading to invent. Zero says so rather than implying an order that was
                        // never recorded.
                        arrived_mono: 0,
                        // The previous release stored what the destination reported. A floor of the
                        // kernel's own would have been a different row.
                        estimated: false,
                        cached: None,
                    },
                });
                out.len() - 1
            }
        };
        let amount = u64::try_from(figure.amount).unwrap_or(0);
        match &figure.dimension {
            // The flat fee is charged per BILLABLE request, which is the count the previous release
            // refunds and the one its own projection multiplies the fee by. Admitted requests are a
            // cap dimension and not a priced class; folding them in would bill a refused call.
            CapDimension::Class(class)
                if class == busbar_plugin_loader::store_adapter::BILLABLE_REQUESTS_CLASS =>
            {
                out[slot].posting.fee_count = amount;
            }
            CapDimension::Class(class) => out[slot]
                .posting
                .quantities
                .push(Quantity::new(class.as_str(), amount)),
            // Requests are counted, never priced.
            CapDimension::Requests => {}
            other => {
                debug_assert!(
                    false,
                    "a metering row named an unpriced dimension: {other:?}"
                );
            }
        }
    }
    out
}

/// Price the previous release's rows under the opening entry, in the currency a 1.5.5 figure is in.
///
/// Fills each posting's [`Posting::cached`] and nothing else. The cache is not authority and never
/// becomes it: a reader that wants the money asks the lookup, which is why this returns the postings
/// with a cache on them rather than a list of amounts.
///
/// # Errors
///
/// The opening card cannot price a row — an instant no entry covers, a lane a present card names no
/// prices for, or a currency it does not name. Every one of those is a refusal rather than a zero: a
/// row that priced at nothing because nobody could price it is indistinguishable, in the books, from
/// a row that was genuinely free.
pub fn price_at_opening(
    history: &History,
    rows: &mut [LegacyRowPosting],
) -> Result<(), Unpriceable> {
    let opening = HistorySeq(OPENING_HISTORY_SEQ);
    let view = history.snapshot(opening);
    for row in rows.iter_mut() {
        let priced = price(&view, &row.posting, CurrencyCode::USD)?;
        row.posting.cached = Some(priced.as_cache(opening));
    }
    Ok(())
}

/// Read the previous release's rows through the store adapter and seal the opening.
///
/// The rows are read through the adapter — they are the previous release's and nobody else has them
/// — but WHERE the marker goes is the CALLER'S, and it is an argument rather than a default for that
/// reason. On a node built by [`crate::root::durability::build_for_node`] it goes on the one journal,
/// beside the opening checkpoint it is a marker for. There was a default once, the store adapter's
/// node-local shim, and it is what made a second boot on a node with a data directory re-read the
/// previous release's rows anyway.
///
/// # Errors
///
/// The previous release's rows could not be read, the opening could not be signed, the ledger's own
/// records were not usable, or the figures read do not fit. A store with NOTHING in it is not an
/// error — see this module's preamble for the difference and why it is the whole of the decision.
pub fn run(
    adapter: &StoreAdapter,
    records: &mut dyn MigrationRecords,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Migration, Refusal> {
    // The key rows are where the per-key buckets come from. A store that will not list them is a
    // store this node cannot open its balances over: the opening would be missing every bucket it
    // would have discovered there, and no later read would ever notice.
    let plan = adapter
        .key_bucket_plan(cfg.window, &cfg.group_buckets, &cfg.metering_days)
        .map_err(|e| {
            Refusal::Unreadable(vec![format!(
                "the previous release's key rows, which name the per-key buckets: {e}"
            )])
        })?;

    let rows = adapter.legacy_ledger_rows(plan);
    migration_over(&rows, records, cfg, wall, secret)
}

/// The step over the two seams, once the plan is decided: seal, then refuse if the read was short.
///
/// Separate from [`run`] so the refusal rule can be proved against the real traits without a loaded
/// store plugin standing in the way of it.
///
/// # Errors
///
/// As [`run`].
pub fn migration_over(
    rows: &dyn LegacyLedgerRows,
    records: &mut dyn MigrationRecords,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Migration, Refusal> {
    let outcome = seal_opening(rows, records, cfg, wall, secret)?;
    // The order matters. The seal runs FIRST and then its answer is thrown away, because the ledger
    // unit's own rule is that a degraded read withholds the marker — so refusing after the seal
    // leaves the records exactly as they were and the next boot, over a store that answers, seals
    // the identical checkpoint. Refusing before it would have skipped a seal that a complete read
    // would have completed, and the two are not the same on a store that recovered mid-boot.
    if let Outcome::Sealed(opening) = &outcome {
        if !opening.unreadable.is_empty() {
            return Err(Refusal::Unreadable(opening.unreadable.clone()));
        }
    }
    Ok(Migration {
        // Wall seconds to the milliseconds the history is dated in. `appended_at` records WHEN the
        // opening was written; `effective_from` is zero regardless, which is what makes the entry
        // cover the history it opens over rather than only the instants after it.
        history: opening_history(cfg.rate_card.clone(), wall.saturating_mul(1_000)),
        outcome,
    })
}

/// The seal itself, over the two seams and nothing else.
///
/// Separate from [`run`] because [`run`]'s job is to decide what gets read and this one's job is to
/// hand two objects to the ledger unit. Splitting them is what lets the ordering rule be tested
/// against the real traits without a loaded store plugin in the way.
///
/// # Errors
///
/// As [`run`].
pub fn seal_opening(
    rows: &dyn LegacyLedgerRows,
    records: &mut dyn MigrationRecords,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Outcome, MigrationError> {
    migrate(rows, records, cfg.node, wall, secret)
}

#[cfg(test)]
#[path = "tests/migration.rs"]
mod tests;
