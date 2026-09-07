//! Tests for `migration.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

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
