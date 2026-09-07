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
mod tests {
    use super::*;
    use busbar_caps::{MeterClassId, QuantitySource, UsageLine};
    use busbar_plugin_loader::store_adapter::BILLABLE_REQUESTS_CLASS;
    use busbar_unit_cost::{
        derive_spend_micros, Author, LaneClass, RateCard, CLASS_CACHE_READ, CLASS_CACHE_WRITE,
        CLASS_INPUT, CLASS_OUTPUT,
    };
    use busbar_unit_ledger::legacy::{LegacyHead, LegacyMigrationSource};
    use busbar_unit_ledger::migration::{
        LegacyFamily, LegacyFigure, LegacyFigures, NodeLocalRecords,
    };
    use busbar_unit_ledger::totals::CapDimension;

    /// Rows a test seeded, counting the reads so "the second boot touched nothing" is an assertion
    /// about the previous release's rows rather than about a return value.
    #[derive(Default)]
    struct SeededRows {
        figures: Vec<LegacyFigure>,
        /// What the store would not answer for. Empty is a store that answered for everything —
        /// which is a different fact from a store with nothing in it, and the two are separate
        /// fields here for exactly the reason the boot decides differently about them.
        unreadable: Vec<String>,
        reads: std::cell::Cell<u32>,
    }

    impl LegacyMigrationSource for SeededRows {
        fn read_head(&self) -> LegacyHead {
            self.reads.set(self.reads.get() + 1);
            LegacyHead {
                seq: Some(90),
                hash: Some("head".to_string()),
                balances: vec![("vk_a".to_string(), 6_000)],
                cells_read: 1,
            }
        }
    }

    impl LegacyLedgerRows for SeededRows {
        fn read_figures(&self) -> LegacyFigures {
            self.reads.set(self.reads.get() + 1);
            LegacyFigures {
                figures: self.figures.clone(),
                unreadable: self.unreadable.clone(),
            }
        }
    }

    /// The 1.5.5 card this deployment configured: one lane, three priced classes, a flat fee.
    ///
    /// Built through the one-currency constructor, which is what "read a 1.5.5 card as a card naming
    /// exactly USD" IS — the crate has no other way to build a card with no currency on it, because
    /// there is no such card.
    fn configured_card() -> RateCard {
        RateCard::from_micro_rates(
            [
                (LaneClass::new("gpt-4", CLASS_INPUT), 30.0),
                (LaneClass::new("gpt-4", CLASS_OUTPUT), 60.0),
                (LaneClass::new("gpt-4", CLASS_CACHE_READ), 3.0),
            ],
            7,
        )
    }

    fn cfg() -> MigrationConfig {
        MigrationConfig {
            node: 1,
            window: 86_400,
            group_buckets: vec![("team".to_string(), 86_400)],
            metering_days: vec![86_400],
            rate_card: configured_card(),
        }
    }

    fn rows() -> SeededRows {
        SeededRows {
            figures: vec![LegacyFigure {
                family: LegacyFamily::Window,
                bucket: "vk_a".to_string(),
                window: 86_400,
                lane: "gpt-4".to_string(),
                provider: String::new(),
                dimension: CapDimension::Class(CLASS_INPUT.to_string()),
                amount: 6_000,
            }],
            unreadable: Vec::new(),
            reads: std::cell::Cell::new(0),
        }
    }

    /// The crate's own constant for a class a metering row named.
    fn static_class(class: &str) -> &'static str {
        for known in [
            CLASS_INPUT,
            CLASS_OUTPUT,
            CLASS_CACHE_READ,
            CLASS_CACHE_WRITE,
        ] {
            if known == class {
                return known;
            }
        }
        panic!("a metering row named a class the card cannot be keyed by: {class}")
    }

    /// One of the previous release's metering rows, spelled as the figures its reader produces: one
    /// figure per counted dimension, all four token classes and both request counts.
    #[allow(clippy::too_many_arguments)]
    fn a_metering_row(
        bucket: &str,
        lane: &str,
        provider: &str,
        day: u64,
        input: u64,
        output: u64,
        cache_read: u64,
        requests: u64,
        billable: u64,
    ) -> Vec<LegacyFigure> {
        let mut out = Vec::new();
        let mut push = |dimension: CapDimension, amount: u64| {
            if amount != 0 {
                out.push(LegacyFigure {
                    family: LegacyFamily::Meter,
                    bucket: bucket.to_string(),
                    window: day,
                    lane: lane.to_string(),
                    provider: provider.to_string(),
                    dimension,
                    amount: i128::from(amount),
                });
            }
        };
        push(CapDimension::Requests, requests);
        push(
            CapDimension::Class(BILLABLE_REQUESTS_CLASS.to_string()),
            billable,
        );
        push(CapDimension::Class(CLASS_INPUT.to_string()), input);
        push(CapDimension::Class(CLASS_OUTPUT.to_string()), output);
        push(
            CapDimension::Class(CLASS_CACHE_READ.to_string()),
            cache_read,
        );
        out
    }

    fn meter_rows() -> SeededRows {
        let mut figures = a_metering_row("vk_a", "gpt-4", "openai", 86_400, 1_200, 340, 55, 9, 7);
        figures.extend(a_metering_row(
            "vk_b", "gpt-4", "openai", 86_400, 3, 1, 0, 1, 1,
        ));
        SeededRows {
            figures,
            unreadable: Vec::new(),
            reads: std::cell::Cell::new(0),
        }
    }

    // ---------------------------------------------------------------------------------------
    // The opening entry
    // ---------------------------------------------------------------------------------------

    /// **A 1.5.5 NODE UPGRADING GETS EXACTLY ONE OPENING ENTRY.**
    ///
    /// One entry, numbered zero, effective from instant zero, open-ended, authored as the opening,
    /// holding the card the configuration named. Every clause is asserted, because every clause is
    /// load-bearing: a second entry would mean two cards could cover one instant with nobody having
    /// asked for a correction; a non-zero `effective_from` would leave every pre-migration row in a
    /// hole; an end would do the same for everything after it; and an author of anything else would
    /// say a price change happened that did not.
    #[test]
    fn a_1_5_5_node_upgrading_gets_one_opening_entry_from_its_configured_card() {
        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let migration = migration_over(&rows, &mut records, &cfg(), 1_700_000_000, None)
            .expect("a store that answered boots");

        assert_eq!(
            migration.history.len(),
            1,
            "a migration opens ONE entry: the card the deployment configured, and nothing else"
        );
        let entry = &migration.history.entries()[0];
        assert_eq!(entry.seq(), HistorySeq::OPENING);
        assert_eq!(
            entry.effective_from(),
            0,
            "effective from instant zero, so a row carrying nothing finer than a UTC day is covered"
        );
        assert_eq!(
            entry.effective_until(),
            None,
            "open-ended, so every later instant is covered until something is appended over it"
        );
        assert!(matches!(entry.author(), Author::Opening));
        assert_eq!(
            entry.appended_at(),
            1_700_000_000_000,
            "appended_at is the seal's wall clock in the milliseconds the history is dated in — the \
             field that would differ from effective_from if this were a back-dated amendment"
        );
        // And the card in it is the configured one, checked through the only thing a card is for.
        let view = migration.history.current();
        let (seq, card) = view.card_at(0).expect("instant zero is covered");
        assert_eq!(seq, HistorySeq::OPENING);
        assert!(card.pricing_enabled());
        assert_eq!(card.per_request_fee(CurrencyCode::USD), 7);
    }

    /// The one entry covers EVERY instant, which is what makes a hole impossible on a node that has
    /// only ever migrated. A hole is a refusal rather than a zero, so an uncovered instant would be a
    /// pre-migration row that could not be priced at all.
    #[test]
    fn the_opening_entry_covers_every_instant_there_is() {
        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let migration =
            migration_over(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("boots");
        let view = migration.history.current();
        for t in [0, 1, 86_400_000, 1_700_000_000_000, u64::MAX] {
            assert!(
                view.card_at(t).is_some(),
                "instant {t} must resolve to the opening entry"
            );
        }
    }

    /// The card is the CONFIGURATION'S, not one this module invented. A deployment that configured
    /// no rate card at all opens with an absent card — every class prices at nothing and the flat
    /// fee still posts — which is exactly what such a deployment is billed today.
    #[test]
    fn a_deployment_that_configured_no_card_opens_with_an_absent_one() {
        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let cfg = MigrationConfig {
            rate_card: RateCard::absent(4),
            ..cfg()
        };
        let migration =
            migration_over(&rows, &mut records, &cfg, 1_700_000_000, None).expect("boots");
        let view = migration.history.current();
        let (_, card) = view.card_at(0).expect("an absent card is still an entry");
        assert!(!card.pricing_enabled());
        assert_eq!(card.per_request_fee(CurrencyCode::USD), 4);
    }

    // ---------------------------------------------------------------------------------------
    // The previous release's rows, as postings
    // ---------------------------------------------------------------------------------------

    /// **EVERY LEGACY METERING ROW READS AS A POSTING** — quantities as the truth, one posting per
    /// row, nothing summed and nothing priced away.
    #[test]
    fn every_legacy_metering_row_reads_as_a_posting_carrying_its_own_quantities() {
        let rows = legacy_row_postings(&meter_rows().figures);
        assert_eq!(
            rows.len(),
            2,
            "one posting per (bucket, lane, provider, day)"
        );

        let first = &rows[0];
        assert_eq!(first.bucket, "vk_a");
        assert_eq!(first.provider, "openai");
        assert_eq!(first.day, 86_400);
        assert_eq!(first.posting.lane, "gpt-4");
        assert_eq!(
            first.posting.arrived_ms, 86_400_000,
            "the day's opening instant, in the milliseconds the history resolves at"
        );
        assert_eq!(
            first.posting.quantities,
            vec![
                Quantity::new(CLASS_INPUT, 1_200),
                Quantity::new(CLASS_OUTPUT, 340),
                Quantity::new(CLASS_CACHE_READ, 55),
            ],
            "the row's own counts, under the spellings the card is keyed by, in the order read"
        );
        assert_eq!(
            first.posting.fee_count, 7,
            "the flat fee rides the BILLABLE request count, which is the one the previous release \
             refunds and the one its own projection multiplies the fee by"
        );
        assert_eq!(
            first.posting.tier_bp, STANDARD_TIER_BP,
            "the previous release has one tier and no way to express another"
        );
        assert!(
            first.posting.cached.is_none(),
            "reading a row prices nothing"
        );
    }

    /// The ADMITTED request count is a cap dimension and never a priced class. Folding it in would
    /// charge the flat fee for a call the previous release refunded.
    #[test]
    fn the_admitted_request_count_is_never_priced() {
        let rows = legacy_row_postings(&meter_rows().figures);
        assert!(
            rows.iter().all(|r| r
                .posting
                .quantities
                .iter()
                .all(|q| q.class != "requests" && q.class != BILLABLE_REQUESTS_CLASS)),
            "neither request count is a priced quantity"
        );
        assert_eq!(
            rows[0].posting.fee_count, 7,
            "and the billable count is the fee count, not 9"
        );
    }

    /// The WINDOW family is the enforcement ledger's view of the same consumption. Reading it as
    /// postings beside the metering rows would bill a deployment twice for one day's traffic.
    #[test]
    fn the_enforcement_ledgers_view_of_the_same_consumption_is_not_read_twice() {
        let mut figures = meter_rows().figures;
        figures.extend(rows().figures);
        let priced = legacy_row_postings(&figures);
        assert_eq!(
            priced.len(),
            2,
            "the window family is a second view of the metering rows, not a third row"
        );
    }

    /// **THE EXACTNESS RULE.** A row priced under the opening entry, in USD, is arithmetically the
    /// previous release's own read-time derivation at the same card: same rates, same order, same
    /// saturation, same single truncation.
    ///
    /// This is the migration's acceptance criterion. If it ever fails, a 1.5.5 deployment's figures
    /// moved on upgrade — which is the one thing the whole single-entry history exists to prevent.
    #[test]
    fn a_row_priced_at_the_opening_entry_equals_the_previous_releases_own_derivation() {
        let card = configured_card();
        let history = opening_history(card.clone(), 1_700_000_000_000);
        let mut rows = legacy_row_postings(&meter_rows().figures);
        price_at_opening(&history, &mut rows).expect("the opening card prices every row");

        for row in &rows {
            let lines: Vec<UsageLine> = row
                .posting
                .quantities
                .iter()
                .map(|q| UsageLine {
                    // The class id is interned for the process's life, so a report is built from
                    // the crate's own class constants rather than from the row's owned string.
                    // Every class a metering row can carry is one of them, which is the point:
                    // a name that fell through here would be one the card is not keyed by either.
                    class: MeterClassId::new(static_class(q.class.as_str())),
                    quantity: q.amount,
                    source: QuantitySource::Count,
                    estimated: false,
                })
                .collect();
            let legacy = derive_spend_micros(
                &card,
                std::iter::once((row.posting.lane.as_str(), lines.as_slice())),
                row.posting.fee_count,
                true,
            );
            let priced = price(
                &history.snapshot(HistorySeq::OPENING),
                &row.posting,
                CurrencyCode::USD,
            )
            .expect("prices");
            assert_eq!(
                priced.micros(),
                legacy,
                "row {} on {}: the lookup at the opening entry must be the 1.5.5 derivation to the \
                 byte",
                row.bucket,
                row.posting.lane
            );
        }
    }

    /// The CACHED figure is the legacy amount, and it is a cache: it names the snapshot it was
    /// computed against and the entry the instant resolved to, so a later read can tell whether it
    /// is still current without trusting it.
    #[test]
    fn the_cached_price_is_the_legacy_figure_at_the_opening_snapshot() {
        let history = opening_history(configured_card(), 1_700_000_000_000);
        let mut rows = legacy_row_postings(&meter_rows().figures);
        price_at_opening(&history, &mut rows).expect("prices");

        let view = history.snapshot(HistorySeq::OPENING);
        let cached = rows[0].posting.cached.expect("priced");
        assert_eq!(cached.history_seq, HistorySeq::OPENING);
        assert_eq!(cached.card_seq, HistorySeq::OPENING);
        assert_eq!(cached.currency, CurrencyCode::USD);
        assert_eq!(
            cached.priced_nanos,
            rows[0]
                .posting
                .priced_nanos(&view, CurrencyCode::USD)
                .expect("prices"),
            "the cache agrees with the lookup at the instant it was taken"
        );
        // And it is NOT authority: a corrupted cache changes nothing the lookup answers.
        let mut tampered = rows[0].clone();
        tampered.posting.cached = Some(busbar_unit_cost::CachedPrice {
            priced_nanos: 1,
            ..cached
        });
        assert_eq!(
            tampered
                .posting
                .priced_nanos(&view, CurrencyCode::USD)
                .expect("prices"),
            cached.priced_nanos,
            "the figure a reader gets is the lookup's, whatever the cache says"
        );
    }

    /// A lane the configured card does not name prices at NOTHING, VISIBLY — and that is not a
    /// concession, it is the exactness rule.
    ///
    /// The previous release's own derivation skips a lane its card is silent about and still charges
    /// the flat fee. A migration that refused such a row instead would refuse to boot a deployment
    /// that has been billing correctly for a year, and a migration that priced it at some other
    /// number would move a 1.5.5 figure on upgrade. So the row reads back at the same money it
    /// always did, and `lane_unpriced` carries the fact so it is a visible nothing rather than a
    /// silent one. Settlement's fail-closed posture is a different question, asked of live traffic.
    #[test]
    fn a_row_on_a_lane_the_card_does_not_name_prices_at_nothing_and_says_so() {
        let card = configured_card();
        let history = opening_history(card.clone(), 1_700_000_000_000);
        let mut rows = legacy_row_postings(&a_metering_row(
            "vk_c",
            "claude-3",
            "anthropic",
            86_400,
            10,
            2,
            0,
            1,
            1,
        ));
        price_at_opening(&history, &mut rows).expect("a row on an unnamed lane still reads back");

        let view = history.snapshot(HistorySeq::OPENING);
        let priced = price(&view, &rows[0].posting, CurrencyCode::USD).expect("prices");
        assert!(
            priced.lane_unpriced,
            "the nothing is visible: the answer says the card named no prices for this lane"
        );
        assert!(
            priced.lines.iter().all(|l| l.class == "fee" || l.unpriced),
            "and every quantity line says so for itself"
        );
        assert_eq!(
            priced.micros(),
            derive_spend_micros(&card, std::iter::empty(), rows[0].posting.fee_count, true),
            "which is the fee and nothing else — exactly what the previous release derived"
        );
    }

    // ---------------------------------------------------------------------------------------
    // Idempotence
    // ---------------------------------------------------------------------------------------

    /// The first boot seals what was there; the opening entry per bucket carries the opening
    /// history entry's own number rather than a version a caller chose.
    #[test]
    fn the_first_boot_seals_the_opening() {
        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let outcome =
            seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals");
        let Outcome::Sealed(opening) = outcome else {
            panic!("the first boot seals");
        };
        assert_eq!(opening.checkpoint.totals.len(), 1);
        assert_eq!(
            opening
                .checkpoint
                .totals
                .values()
                .next()
                .expect("one")
                .settled,
            6_000
        );
        assert_eq!(opening.balances.len(), 1);
        assert_eq!(opening.balances[0].rate_card_version, OPENING_HISTORY_SEQ);
        assert!(records.is_sealed());
    }

    /// The second boot on the same node reads nothing at all: the marker is what makes a restart
    /// free, and it is the ledger's own record rather than anything on the rows that were read.
    #[test]
    fn the_second_boot_reads_nothing() {
        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let first = seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals");
        let after_first = rows.reads.get();
        assert!(after_first > 0);

        let second = seal_opening(&rows, &mut records, &cfg(), 1_700_000_100, None).expect("no-op");
        assert!(!second.sealed_now());
        assert_eq!(rows.reads.get(), after_first);
        assert_eq!(second.marker(), first.marker());
    }

    /// **A SECOND BOOT APPENDS NOTHING.** The history is still one entry, and it is still the entry
    /// the first boot opened — not a second opening beside it.
    ///
    /// The history is rebuilt on the second boot rather than read back, which is why this is worth
    /// asserting rather than obvious: a rebuild that APPENDED would give a node two open-ended
    /// entries covering every instant, the later one out-ranking the first, and a deployment whose
    /// configuration had drifted since the upgrade would quietly re-price its whole history.
    #[test]
    fn a_second_boot_appends_nothing_to_the_history() {
        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let first =
            migration_over(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("boots");
        assert!(first.sealed_now());
        let after_first = rows.reads.get();

        let second =
            migration_over(&rows, &mut records, &cfg(), 1_700_000_100, None).expect("boots again");
        assert!(!second.sealed_now(), "the marker is what makes it free");
        assert_eq!(rows.reads.get(), after_first, "and nothing was read again");
        assert_eq!(
            second.history.len(),
            1,
            "a second boot appends nothing: one entry before, one entry after"
        );
        assert_eq!(second.history.entries()[0].seq(), HistorySeq::OPENING);
        assert!(matches!(
            second.history.entries()[0].author(),
            Author::Opening
        ));
        assert_eq!(
            second.outcome.marker(),
            first.outcome.marker(),
            "and the marker it reports is the one the first boot sealed"
        );
    }

    /// The opening checkpoint closes the identity at zero — everything drawn is in the settled
    /// column — and it still does after a second boot, which seals nothing and so moves nothing.
    #[test]
    fn the_identity_closes_at_zero_before_and_after_a_second_boot() {
        use busbar_unit_ledger::identity::residual;
        use busbar_unit_ledger::totals::Totals;

        let rows = rows();
        let mut records = NodeLocalRecords::new();
        let first =
            migration_over(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("boots");
        let Outcome::Sealed(opening) = &first.outcome else {
            panic!("the first boot seals");
        };
        for (key, totals) in &opening.checkpoint.totals {
            let r = residual(&Totals::default(), totals);
            assert!(
                r.holds(),
                "the opening balance for {key:?} must close at zero: {r}"
            );
        }

        let second =
            migration_over(&rows, &mut records, &cfg(), 1_700_000_100, None).expect("boots again");
        assert!(
            !second.sealed_now(),
            "a second boot seals nothing, so there is nothing new for the identity to measure"
        );
    }

    /// The marker goes on the JOURNAL, and a second boot reading the same journal finds it there and
    /// touches the previous release's rows not at all.
    ///
    /// The same claim as `the_second_boot_reads_nothing` above, made over the seam the root actually
    /// binds: the node-local records that test uses are the ledger unit's own honest default, and
    /// this one proves the root does not settle for it.
    #[test]
    fn the_marker_is_sealed_on_the_journal() {
        use crate::root::durability::{build_for_node, DurabilityConfig};
        use busbar_caps::{DurabilityToken, KernelSeal, StepName};
        use busbar_unit_wal::{NullShipper, RecordClass};

        let rows = rows();
        let token = DurabilityToken::mint(&KernelSeal::acquire_for_kernel());
        let mut durability = build_for_node(
            &DurabilityConfig { data_dir: None },
            1,
            Box::new(NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered journal cannot fail to open");

        let first = {
            let mut records = durability.migration_records(&token, StepName::Meter);
            seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals")
        };
        assert!(first.sealed_now());
        let after_first = rows.reads.get();
        assert!(after_first > 0);

        // The marker is a record on the chain, of the class the contract names for it.
        let replayed = durability
            .journal
            .replay()
            .expect("the journal reads back")
            .expect("and verifies");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].class, RecordClass::Migration);

        // And the second boot over the same journal reads nothing at all.
        let second = {
            let mut records = durability.migration_records(&token, StepName::Meter);
            seal_opening(&rows, &mut records, &cfg(), 1_700_000_100, None).expect("no-op")
        };
        assert!(!second.sealed_now());
        assert_eq!(rows.reads.get(), after_first);
        assert_eq!(second.marker(), first.marker());
    }

    // ---------------------------------------------------------------------------------------
    // Nothing there, versus would not say
    // ---------------------------------------------------------------------------------------

    /// A deployment with nothing behind it seals an opening at zero rather than refusing, and the
    /// node has a point to measure from from its first request onward.
    #[test]
    fn a_deployment_with_nothing_behind_it_still_seals() {
        let rows = SeededRows::default();
        let mut records = NodeLocalRecords::new();
        let Outcome::Sealed(opening) =
            seal_opening(&rows, &mut records, &cfg(), 1_700_000_000, None).expect("seals")
        else {
            panic!("an empty deployment seals an opening at zero");
        };
        assert!(opening.checkpoint.totals.is_empty());
        assert!(opening.checkpoint.body_hash_verifies());
    }

    /// **AN EMPTY STORE BOOTS.** Nothing there is a real deployment, and refusing it would mean a
    /// configuration that worked yesterday stops working on upgrade.
    #[test]
    fn an_empty_store_boots_with_an_opening_at_zero_and_a_card_in_force() {
        let rows = SeededRows::default();
        let mut records = NodeLocalRecords::new();
        let migration = migration_over(&rows, &mut records, &cfg(), 1_700_000_000, None)
            .expect("an empty store is not a failure");
        assert!(migration.sealed_now());
        assert_eq!(
            migration.history.len(),
            1,
            "an empty store still gets its card: a node with no entry has every instant a hole"
        );
    }

    /// **A STORE IT CANNOT READ REFUSES THE BOOT.** It used to seal an opening over the rows it
    /// could reach and serve, which is a node coming up with a wrong ledger presented as a right
    /// one: the identity would reconcile forever against an opening that was short from the first
    /// instant, and nothing on the serving path would ever notice.
    #[test]
    fn a_store_it_cannot_read_refuses_the_boot_rather_than_opening_empty() {
        let rows = SeededRows {
            unreadable: vec!["the token ledger for vk_a at 86400: connection reset".to_string()],
            ..rows()
        };
        let mut records = NodeLocalRecords::new();
        let refusal = migration_over(&rows, &mut records, &cfg(), 1_700_000_000, None)
            .expect_err("a store that would not answer is not a store to open balances over");
        let Refusal::Unreadable(named) = &refusal else {
            panic!("the refusal names what could not be read: {refusal:?}");
        };
        assert_eq!(named.len(), 1);
        assert!(named[0].contains("vk_a"), "and names it: {named:?}");
        assert!(
            refusal.to_string().contains("could not be read"),
            "the operator is told what happened: {refusal}"
        );
    }

    /// The refusal leaves NOTHING behind. The marker is the run-once record, so a boot that refused
    /// over a short read must not have written it — otherwise the next boot, over a store that has
    /// recovered, would short-circuit on the marker and the missing buckets would be missing forever.
    #[test]
    fn a_refused_boot_withholds_the_marker_so_the_next_one_can_complete_the_read() {
        let degraded = SeededRows {
            unreadable: vec!["the metering rows for 86400: connection reset".to_string()],
            ..rows()
        };
        let mut records = NodeLocalRecords::new();
        migration_over(&degraded, &mut records, &cfg(), 1_700_000_000, None).expect_err("refuses");
        assert!(
            !records.is_sealed(),
            "a refused boot writes no marker; the read is retried, not made permanent"
        );

        // The store recovers. The same rows, now answered for, seal and boot.
        let recovered = rows();
        let migration = migration_over(&recovered, &mut records, &cfg(), 1_700_000_100, None)
            .expect("a complete read boots");
        assert!(migration.sealed_now());
        assert!(records.is_sealed());
    }

    /// An empty store and an unreadable one are told apart by the NAMES, not by the figures. Both
    /// read as zero; only one of them is a deployment.
    #[test]
    fn nothing_there_and_would_not_say_are_different_answers() {
        let mut records = NodeLocalRecords::new();
        let empty = migration_over(
            &SeededRows::default(),
            &mut records,
            &cfg(),
            1_700_000_000,
            None,
        );
        assert!(empty.is_ok(), "nothing there boots");

        let mut records = NodeLocalRecords::new();
        let silent = migration_over(
            &SeededRows {
                unreadable: vec!["the metering rows for 86400: timed out".to_string()],
                ..SeededRows::default()
            },
            &mut records,
            &cfg(),
            1_700_000_000,
            None,
        );
        assert!(
            matches!(silent, Err(Refusal::Unreadable(_))),
            "would not say does not: {silent:?}"
        );
    }

    /// A posting this release built and a legacy row of the same quantities price identically at the opening
    /// entry. That is what makes the migration a change of storage and not of money: the previous
    /// release's rows and this release's own postings are the same arithmetic against one card.
    #[test]
    fn a_legacy_row_and_a_live_report_of_the_same_quantities_price_the_same() {
        let card = configured_card();
        let history = opening_history(card, 1_700_000_000_000);
        let view = history.snapshot(HistorySeq::OPENING);

        let mut rows = legacy_row_postings(&a_metering_row(
            "vk_a", "gpt-4", "openai", 86_400, 1_200, 340, 55, 9, 7,
        ));
        price_at_opening(&history, &mut rows).expect("prices");

        let live = Posting {
            lane: "gpt-4".to_string(),
            quantities: vec![
                Quantity::new(CLASS_INPUT, 1_200),
                Quantity::new(CLASS_OUTPUT, 340),
                Quantity::new(CLASS_CACHE_READ, 55),
            ],
            fee_count: 7,
            tier_bp: STANDARD_TIER_BP,
            arrived_ms: 86_400_000,
            arrived_mono: 0,
            estimated: false,
            cached: None,
        };
        assert_eq!(
            price(&view, &live, CurrencyCode::USD)
                .expect("prices")
                .priced_nanos,
            rows[0]
                .posting
                .priced_nanos(&view, CurrencyCode::USD)
                .expect("prices"),
        );
    }
}
