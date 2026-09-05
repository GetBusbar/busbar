// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The migration: the opening figures ARE the legacy figures, it runs once, and it never writes to
//! what it read.
//!
//! The source double counts its own reads, which is what lets "the second boot is a no-op" be an
//! assertion about the previous release's rows not being touched rather than about a return value.

use std::collections::BTreeMap;

use crate::checkpoint::{CheckpointSecret, SignError, Signature};
use crate::identity::residual;
use crate::legacy::{LegacyHead, LegacyMigrationSource};
use crate::migration::{
    migrate, opening_totals, LegacyFamily, LegacyFigure, LegacyFigures, LegacyLedgerRows,
    MigrationError, MigrationMarker, MigrationRecords, NodeLocalRecords, Outcome,
    OPENING_CHECKPOINT_SEQ,
};
use crate::totals::{BucketScope, CapDimension, Totals, TotalsKey, WindowStart};

/// A source over figures a test seeded, counting every read of the previous release's rows.
#[derive(Default)]
struct SeededRows {
    head: LegacyHead,
    figures: Vec<LegacyFigure>,
    unreadable: Vec<String>,
    reads: std::cell::Cell<u32>,
}

impl SeededRows {
    fn reads(&self) -> u32 {
        self.reads.get()
    }
}

impl LegacyMigrationSource for SeededRows {
    fn read_head(&self) -> LegacyHead {
        self.reads.set(self.reads.get() + 1);
        self.head.clone()
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

/// Records that refuse, so the two failure arms are exercised as failures rather than as prose.
struct RefusingRecords {
    on_read: bool,
}

impl MigrationRecords for RefusingRecords {
    fn read_marker(&self) -> Result<Option<MigrationMarker>, MigrationError> {
        if self.on_read {
            return Err(MigrationError::RecordsUnavailable("read refused".into()));
        }
        Ok(None)
    }

    fn write_marker(&mut self, _marker: &MigrationMarker) -> Result<(), MigrationError> {
        Err(MigrationError::RecordsUnavailable("write refused".into()))
    }
}

struct NoKey;

impl CheckpointSecret for NoKey {
    fn sign(&self, _body: &[u8]) -> Result<Signature, SignError> {
        Err(SignError::KeyUnavailable("under test".into()))
    }
}

fn window_figure(bucket: &str, window: u64, lane: &str, unit: &str, amount: i128) -> LegacyFigure {
    LegacyFigure {
        family: LegacyFamily::Window,
        bucket: bucket.to_string(),
        window,
        lane: lane.to_string(),
        provider: String::new(),
        dimension: CapDimension::Class(unit.to_string()),
        amount,
    }
}

fn meter_figure(
    bucket: &str,
    day: u64,
    lane: &str,
    provider: &str,
    unit: &str,
    amount: i128,
) -> LegacyFigure {
    LegacyFigure {
        family: LegacyFamily::Meter,
        bucket: bucket.to_string(),
        window: day,
        lane: lane.to_string(),
        provider: provider.to_string(),
        dimension: CapDimension::Class(unit.to_string()),
        amount,
    }
}

/// A deployment that has been serving: one bucket's request count and per-lane token ledger for a
/// window, and the metering rows for the same day under two providers.
fn a_serving_deployment() -> SeededRows {
    SeededRows {
        head: LegacyHead {
            seq: Some(4_211),
            hash: Some("d0d0…".to_string()),
            balances: vec![("team-a".to_string(), 9_000), ("team-b".to_string(), 40)],
            cells_read: 7,
        },
        figures: vec![
            LegacyFigure {
                family: LegacyFamily::Window,
                bucket: "team-a".to_string(),
                window: 86_400,
                lane: String::new(),
                provider: String::new(),
                dimension: CapDimension::Requests,
                amount: 512,
            },
            window_figure("team-a", 86_400, "gpt-4", "input", 6_000),
            window_figure("team-a", 86_400, "gpt-4", "output", 2_500),
            window_figure("team-a", 86_400, "claude", "input", 500),
            meter_figure("team-a", 86_400, "gpt-4", "openai", "input", 4_000),
            meter_figure("team-a", 86_400, "gpt-4", "azure", "input", 2_000),
            window_figure("team-b", 86_400, "gpt-4", "input", 40),
        ],
        unreadable: Vec::new(),
        reads: std::cell::Cell::new(0),
    }
}

fn sealed(source: &SeededRows, records: &mut NodeLocalRecords) -> Result<Outcome, MigrationError> {
    migrate(source, records, 1, 1_700_000_000, 3, None)
}

fn figures_for(
    totals: &BTreeMap<(TotalsKey, WindowStart), Totals>,
    bucket: &str,
    dimension: CapDimension,
    scope: BucketScope,
    window: WindowStart,
) -> Totals {
    let key = TotalsKey::new(crate::totals::BucketId::new(bucket), dimension, scope);
    totals.get(&(key, window)).copied().unwrap_or_default()
}

/// Every figure the previous release held is in the opening, at exactly the amount that was read —
/// per bucket, per day, per lane, per provider.
#[test]
fn the_opening_figures_are_the_legacy_figures_exactly() {
    let source = a_serving_deployment();
    let mut records = NodeLocalRecords::new();
    let outcome = sealed(&source, &mut records).expect("a seeded store migrates");
    let Outcome::Sealed(opening) = outcome else {
        panic!("the first boot seals");
    };
    let totals = &opening.checkpoint.totals;

    // The bucket's own request count, at the bucket's scope: no lane, so nothing narrows it.
    let requests = figures_for(
        totals,
        "team-a",
        CapDimension::Requests,
        BucketScope::All,
        86_400,
    );
    assert_eq!(requests.settled, 512);
    assert_eq!(requests.drawn, 512);

    // One lane's input tokens out of the bucket's token ledger.
    assert_eq!(
        figures_for(
            totals,
            "team-a",
            CapDimension::Class("input".into()),
            BucketScope::Pool("lane:gpt-4".into()),
            86_400,
        )
        .settled,
        6_000
    );
    // The same lane's OUTPUT tokens are a separate balance: a token cap and an output cap must not
    // be able to pay each other's overdraft.
    assert_eq!(
        figures_for(
            totals,
            "team-a",
            CapDimension::Class("output".into()),
            BucketScope::Pool("lane:gpt-4".into()),
            86_400,
        )
        .settled,
        2_500
    );
    // And the metering rows keep their provider, one balance each.
    assert_eq!(
        figures_for(
            totals,
            "team-a",
            CapDimension::Class("input".into()),
            BucketScope::Pool("meter:gpt-4/openai".into()),
            86_400,
        )
        .settled,
        4_000
    );
    assert_eq!(
        figures_for(
            totals,
            "team-a",
            CapDimension::Class("input".into()),
            BucketScope::Pool("meter:gpt-4/azure".into()),
            86_400,
        )
        .settled,
        2_000
    );

    assert_eq!(
        totals.len(),
        7,
        "seven figures were read and seven balances opened: nothing was folded into anything else"
    );
    assert!(opening.checkpoint.body_hash_verifies());
    assert_eq!(opening.checkpoint.checkpoint_seq, OPENING_CHECKPOINT_SEQ);
    assert!(opening.unreadable.is_empty());
}

/// Nothing is invented and nothing is lost: the sum of the sealed figures equals the sum of what was
/// read, which is the check that survives a change to the key shape.
#[test]
fn the_sealed_total_equals_the_seeded_total() {
    let source = a_serving_deployment();
    let seeded: i128 = source.figures.iter().map(|f| f.amount).sum();
    let mut records = NodeLocalRecords::new();
    let Outcome::Sealed(opening) = sealed(&source, &mut records).expect("migrates") else {
        panic!("the first boot seals");
    };
    let opened: i128 = opening.checkpoint.totals.values().map(|t| t.settled).sum();
    assert_eq!(opened, seeded);
}

/// The opening satisfies the identity by construction, so the first reconciliation after an upgrade
/// measures this release's postings and not the previous release's history.
#[test]
fn every_opening_balance_satisfies_the_identity() {
    let source = a_serving_deployment();
    let mut records = NodeLocalRecords::new();
    let Outcome::Sealed(opening) = sealed(&source, &mut records).expect("migrates") else {
        panic!("the first boot seals");
    };
    for ((key, window), figures) in &opening.checkpoint.totals {
        let r = residual(&Totals::zero(), figures);
        assert!(
            r.holds(),
            "the opening for {key} in the window at {window} does not balance: {r}"
        );
    }
}

/// The second boot reads nothing and writes nothing. Counted on the source, so this is a statement
/// about the previous release's rows and not about a return value.
#[test]
fn a_second_boot_reads_nothing_and_seals_nothing() {
    let source = a_serving_deployment();
    let mut records = NodeLocalRecords::new();
    let first = sealed(&source, &mut records).expect("the first boot migrates");
    assert!(first.sealed_now());
    let reads_after_first = source.reads();
    assert!(reads_after_first > 0, "the first boot did read the rows");

    let second = sealed(&source, &mut records).expect("the second boot is fine");
    assert!(!second.sealed_now(), "the second boot must not seal again");
    assert_eq!(
        source.reads(),
        reads_after_first,
        "a boot that finds a marker must not touch the previous release's rows at all"
    );
    assert_eq!(
        second.marker(),
        first.marker(),
        "the marker the second boot reports is the one the first wrote"
    );
}

/// The marker is idempotent by the FIGURES as well as by the flag: a node whose records did not
/// survive a restart re-reads the same rows and seals the same body. That is the property that does
/// not depend on where the marker was kept.
#[test]
fn a_lost_marker_reseals_the_identical_checkpoint() {
    let source = a_serving_deployment();
    let mut first_records = NodeLocalRecords::new();
    let mut fresh_records = NodeLocalRecords::new();
    let Outcome::Sealed(first) = sealed(&source, &mut first_records).expect("migrates") else {
        panic!("seals");
    };
    let Outcome::Sealed(again) = sealed(&source, &mut fresh_records).expect("migrates") else {
        panic!("seals");
    };
    assert_eq!(first.checkpoint.body_hash, again.checkpoint.body_hash);
    assert_eq!(first.checkpoint.totals, again.checkpoint.totals);
}

/// A store with no legacy rows opens at zero AND still seals a checkpoint. Both halves matter: a
/// boot that refused would break an upgrade, and a boot that skipped the seal would leave the
/// deployment with no point to measure from.
#[test]
fn a_store_with_nothing_in_it_opens_at_zero_and_still_seals() {
    let source = SeededRows::default();
    let mut records = NodeLocalRecords::new();
    let Outcome::Sealed(opening) = sealed(&source, &mut records).expect("an empty store migrates")
    else {
        panic!("an empty store still seals");
    };
    assert!(
        opening.checkpoint.totals.is_empty(),
        "nothing opens at zero"
    );
    assert!(
        opening.checkpoint.heads.is_empty(),
        "a head with nothing in it cross-links nothing"
    );
    assert!(opening.balances.is_empty());
    assert!(opening.checkpoint.body_hash_verifies());
    assert_eq!(opening.marker.balances, 0);
    assert!(records.is_sealed(), "and the migration is marked done");
}

/// The two row families are two views of one consumption, so they must not fold into one balance —
/// including in the awkward case where a metering row carries no provider at all.
#[test]
fn a_metering_row_with_no_provider_does_not_fold_into_the_window_row() {
    let figures = vec![
        window_figure("team-a", 10, "gpt-4", "input", 100),
        meter_figure("team-a", 10, "gpt-4", "", "input", 100),
    ];
    let totals = opening_totals(&figures).expect("two figures fold");
    assert_eq!(
        totals.len(),
        2,
        "the window row and the metering row are two balances; folding them would open the books at \
         double what was consumed"
    );
    for figures in totals.values() {
        assert_eq!(figures.settled, 100);
    }
}

/// Two rows for the SAME balance do sum — which is the other half of the rule above, and the reason
/// the separation had to be stated rather than assumed.
#[test]
fn two_rows_for_one_balance_sum() {
    let figures = vec![
        window_figure("team-a", 10, "gpt-4", "input", 100),
        window_figure("team-a", 10, "gpt-4", "input", 25),
    ];
    let totals = opening_totals(&figures).expect("two figures fold");
    assert_eq!(totals.len(), 1);
    assert_eq!(totals.values().next().expect("one balance").settled, 125);
}

/// The opening entry per bucket, at the card version the migration was told to name.
#[test]
fn the_opening_entries_carry_the_named_card_version() {
    let source = a_serving_deployment();
    let mut records = NodeLocalRecords::new();
    let Outcome::Sealed(opening) = sealed(&source, &mut records).expect("migrates") else {
        panic!("seals");
    };
    assert_eq!(opening.balances.len(), 2);
    assert_eq!(opening.balances[0].bucket, "team-a");
    assert_eq!(opening.balances[0].amount, 9_000);
    assert!(opening.balances.iter().all(|b| b.rate_card_version == 3));
    assert_eq!(opening.marker.rate_card_version, 3);
    assert_eq!(
        opening.marker.cells_read, 7,
        "the marker records how many of the previous release's cells were read"
    );
    assert_eq!(
        opening.checkpoint.store_seq_high_water, 4_211,
        "the previous release's sequence is where this release's chain continues from"
    );
    assert_eq!(opening.checkpoint.heads.len(), 1);
}

/// A row that could not be read is named, and the node still boots. Losing the fact silently is the
/// failure this arm exists to prevent.
#[test]
fn a_row_that_could_not_be_read_is_named_and_does_not_refuse() {
    let source = SeededRows {
        unreadable: vec!["team-c".to_string()],
        ..Default::default()
    };
    let mut records = NodeLocalRecords::new();
    let Outcome::Sealed(opening) = sealed(&source, &mut records).expect("still migrates") else {
        panic!("seals anyway");
    };
    assert_eq!(opening.unreadable, vec!["team-c".to_string()]);
}

/// An unsigned opening is an error and NO marker is written: a deployment that could not sign must
/// try again next boot rather than record that it migrated when it did not.
#[test]
fn an_unsigned_opening_writes_no_marker() {
    let source = a_serving_deployment();
    let mut records = NodeLocalRecords::new();
    let err =
        migrate(&source, &mut records, 1, 1, 1, Some(&NoKey)).expect_err("the signer refuses");
    assert!(matches!(err, MigrationError::NotSealed(_)));
    assert!(
        !records.is_sealed(),
        "a migration that did not seal must not be marked as done"
    );
}

/// Unreadable records are not the same fact as absent records, and the migration says so instead of
/// guessing — guessing is how a migration runs twice.
#[test]
fn records_that_cannot_be_read_are_an_error_rather_than_a_second_run() {
    let source = a_serving_deployment();
    let mut records = RefusingRecords { on_read: true };
    let err = migrate(&source, &mut records, 1, 1, 1, None).expect_err("the records refuse");
    assert!(matches!(err, MigrationError::RecordsUnavailable(_)));
    assert_eq!(
        source.reads(),
        0,
        "records that could not be read must not lead to a read of the legacy rows"
    );
}

/// A marker that could not be written is an error, so the caller cannot mistake an unsealed
/// migration for a sealed one.
#[test]
fn a_marker_that_cannot_be_written_is_an_error() {
    let source = a_serving_deployment();
    let mut records = RefusingRecords { on_read: false };
    let err = migrate(&source, &mut records, 1, 1, 1, None).expect_err("the records refuse");
    assert!(matches!(err, MigrationError::RecordsUnavailable(_)));
}

/// Figures that do not fit are refused rather than wrapped: opening at a wrapped number would seed
/// every later reconciliation with a figure nobody can explain.
#[test]
fn figures_that_do_not_fit_are_refused() {
    let figures = vec![
        window_figure("team-a", 10, "gpt-4", "input", i128::MAX),
        window_figure("team-a", 10, "gpt-4", "input", 1),
    ];
    assert!(matches!(
        opening_totals(&figures),
        Err(MigrationError::FigureOverflow { .. })
    ));
}
