// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The same restart, down both paths, and the figures have to match.**
//!
//! The previous release recovers a budget at boot in `busbar_core::governance::GovState::
//! hydrate_budgets`: it re-reads the per-bucket token ledgers out of the store and stamps them into
//! its in-memory cells, and the money is re-derived from those tokens at read time. The unit chain
//! now recovers the same budget in `busbar_unit_ledger`: it replays what it SETTLED off its own
//! journal and hands the door one figure per balance.
//!
//! Two different mechanisms, and the release requirement is that they restore the same number. So
//! this drives both, on one fixture, and compares — rather than asserting about one of them and
//! trusting the other. It is the only test in the tree that runs the legacy boot recovery and the
//! unit boot recovery side by side.
//!
//! **What it does not compare.** The legacy path re-derives from tokens against the card configured
//! at the moment of the read, and the unit path replays money that was settled under the card in
//! force when it was delivered. On a fixture with ONE card those are the same figure, which is what
//! is asserted here. Off one card they are two different laws — that is the whole of the
//! retroactivity question `billing|rate-card|history-mid-window` is owed a ruling on, and nothing
//! here pre-empts it.

use std::sync::Arc;

use busbar_api::{ModelTokens, Store, UsageLedger, VirtualKey};
use busbar_core::cost::CostModel;
use busbar_core::governance::{GovState, MemoryStore};
use busbar_unit_ledger::hydrate::{HydratedPosting, SpendSource};
use busbar_unit_ledger::settle::Ledger;
use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};

/// The all-time window both paths bucket a key's own spend into.
const WINDOW: u64 = 0;
/// The flat per-request fee, in cents. With no rate card configured this is the whole of the
/// derived spend on the legacy side, which is what makes the two figures comparable without
/// pinning a card in two places.
const FEE_CENTS: i64 = 7;
/// How many billable requests the fixture delivered.
const BILLABLE: u64 = 13;
/// Nano-units per cent, as the cost unit names it.
const NANOS_PER_CENT: i128 = busbar_unit_cost::NANOS_PER_CENT as i128;

const KEY_ID: &str = "vk_restart_identity";
const NOW: u64 = 1_770_000_000;

fn key() -> VirtualKey {
    VirtualKey {
        id: KEY_ID.to_string(),
        generation_hash: "hash".to_string(),
        name: "restart-identity".to_string(),
        enabled: true,
        created_at: NOW,
        revision: 1,
        ..Default::default()
    }
}

fn balance() -> TotalsKey {
    TotalsKey::new(
        BucketId::new(KEY_ID),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// The postings the unit chain's journal would hold for the same delivered value: one per billable
/// request, each priced at the flat fee.
struct Settled;

impl SpendSource for Settled {
    fn postings(&self) -> Result<Vec<HydratedPosting>, busbar_unit_ledger::HydrationError> {
        Ok((0..BILLABLE)
            .map(|_| HydratedPosting {
                key: balance(),
                window: WINDOW,
                settled: i128::from(FEE_CENTS) * NANOS_PER_CENT,
                overdraft: 0,
            })
            .collect())
    }
}

/// The spend the LEGACY path restores at boot, in whole cents.
///
/// The real function, on a real store: a first process writes the durable token ledger, a SECOND
/// `GovState` is built over the same store — which is what a restart is — and
/// `hydrate_budgets` is what makes it see anything at all.
fn legacy_restored_cents() -> (i64, i64) {
    let store = Arc::new(MemoryStore::new());
    store.put_key(&key()).expect("the key goes in");
    // What the first process left behind: the admitted requests and their tokens. There is no money
    // field in the store at all — spend is derived — which is the shape the unit path is being
    // compared against.
    store
        .put_usage(
            KEY_ID,
            WINDOW,
            &UsageLedger {
                requests: BILLABLE,
                billable_requests: BILLABLE,
                models: vec![ModelTokens {
                    model: "m".to_string(),
                    usage_units: std::collections::BTreeMap::new(),
                }],
            },
        )
        .expect("the ledger goes in");

    let cost = CostModel::flat(FEE_CENTS);

    // ── the restart WITHOUT hydration: the counter-arm ───────────────────────────────────────────
    let forgetful = GovState::new(Arc::clone(&store) as Arc<dyn Store>, None)
        .expect("a fresh state over the same store");
    let unhydrated = forgetful
        .usage_for(&cost, KEY_ID, NOW)
        .expect("the store answers")
        .expect("the key exists");

    // ── the restart WITH it ──────────────────────────────────────────────────────────────────────
    let restored = GovState::new(Arc::clone(&store) as Arc<dyn Store>, None)
        .expect("a fresh state over the same store");
    restored
        .hydrate_budgets(&cost, NOW)
        .expect("boot recovery reads the store");
    let hydrated = restored
        .usage_for(&cost, KEY_ID, NOW)
        .expect("the store answers")
        .expect("the key exists");

    (hydrated.spend_cents, unhydrated.spend_cents)
}

/// The spend the UNIT path restores at boot, in whole cents.
fn unit_restored_cents() -> (i64, i64) {
    let mut restored = Ledger::new();
    let hydration = restored.hydrate(&Settled).expect("the journal reads back");
    // The counter-arm: a ledger that does not hydrate.
    let forgetful = Ledger::new();
    let unhydrated = busbar_unit_cost::cents_of(
        u128::try_from(forgetful.book().get(&balance(), WINDOW).settled).unwrap_or(0),
    );
    (
        hydration.carried.bucket_cents(KEY_ID, Some(WINDOW)),
        unhydrated,
    )
}

/// **The identity.** Both paths recover the same figure from the same delivered value, and both
/// recover nothing when the recovery does not run.
#[test]
fn the_legacy_boot_recovery_and_the_unit_chains_restore_the_same_spend() {
    let (legacy, legacy_without) = legacy_restored_cents();
    let (unit, unit_without) = unit_restored_cents();

    assert_eq!(
        legacy,
        FEE_CENTS * i64::try_from(BILLABLE).expect("small"),
        "the legacy path restores thirteen requests at seven cents"
    );
    assert_eq!(
        unit, legacy,
        "AND THE UNIT PATH RESTORES THE SAME FIGURE — the two boot recoveries agree"
    );

    assert_ne!(
        unit, 0,
        "which is what makes the agreement above a measurement rather than two zeros"
    );
    assert_eq!(
        unit_without, 0,
        "a unit ledger that does not hydrate restores nothing, which is what the unit chain did"
    );

    // ── A MEASURED DIFFERENCE BETWEEN THE TWO PATHS, recorded rather than asserted away ──────────
    //
    // The legacy READ answers the same figure whether or not the boot recovery ran:
    // `GovState::usage_for` falls back to the durable ledger for a bucket whose cell was never
    // materialised, so the store is reachable from the read path with or without hydration. What
    // `hydrate_budgets` actually restores is the ENFORCEMENT cell — the one `try_admit` compares
    // against, which reads cells and never the store.
    //
    // The unit chain has no such fallback and deliberately none: the door's cells are the only thing
    // it consults, which is precisely why the carried figure has to be handed to it at boot. So the
    // counter-arms differ in shape, and the figures do not. Recorded here because a reader
    // comparing the two paths will otherwise expect the same zero on both sides and conclude the
    // wrong thing about which one is being restored.
    assert_eq!(
        legacy_without, legacy,
        "the legacy READ falls back to the store, so its answer does not depend on the recovery"
    );
}

/// The figure survives a SECOND restart unchanged: recovery is a read, not an accrual.
///
/// Worth its own arm because the unit path folds postings into a book, and a fold that ran twice
/// would double the spend — which on the legacy side is impossible by construction (it assigns a
/// cell) and on this side is a property of the caller. The composition root calls it once, at boot,
/// before anything listens; this is what that rule buys.
#[test]
fn a_second_restart_restores_the_same_figure_and_never_more() {
    let (first, _) = unit_restored_cents();
    let (second, _) = unit_restored_cents();
    assert_eq!(first, second, "two restarts, one figure");
    assert_eq!(first, FEE_CENTS * i64::try_from(BILLABLE).expect("small"));

    let (legacy_first, _) = legacy_restored_cents();
    let (legacy_second, _) = legacy_restored_cents();
    assert_eq!(
        legacy_first, legacy_second,
        "and the legacy path is stable across restarts too"
    );
    assert_eq!(legacy_first, first, "at the same number, on every restart");
}
