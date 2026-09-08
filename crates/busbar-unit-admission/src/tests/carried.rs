// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **The restart, at the door: what a balance carried in is part of what it has spent.**
//!
//! The cells are node-local and start empty, so before this seam existed a restart was a clean
//! sheet — a key that had spent its whole cap was admissible again the moment the process came
//! back. The cell below is the two postures side by side, on one fixture: an unbound door forgets
//! and admits; a door carrying what the ledger restored remembers and refuses.
//!
//! The unbound arm is not decoration. It is the byte-identity claim: a door with nothing bound
//! compares the figure the tag compared, so every existing recording is unmoved by this seam
//! existing. Every other test in this crate builds its door through [`super::door`], which binds
//! nothing — so the whole ported corpus is that claim as well.

use std::sync::Arc;

use crate::decide::{CarriedSpend, Metric};
use crate::tests::{
    assert_blocked, card, chain, door, group_cfg, limit, table, toks, LimitMetric, DAY,
};
use crate::{Door, InMemoryCells};

/// What the ledger restored, as a test states it: a flat list of (bucket, window, cents).
#[derive(Debug)]
struct Restored(Vec<(&'static str, u64, i64)>);

impl CarriedSpend for Restored {
    fn carried_cents(&self, bucket_id: &str, window: u64) -> i64 {
        self.0
            .iter()
            .find(|(b, w, _)| *b == bucket_id && *w == window)
            .map_or(0, |(_, _, cents)| *cents)
    }
}

/// The fixture: one group with a 100-cent daily spend cap, and a card that prices output at one
/// cent per hundred tokens.
fn fixture() -> (crate::chain::GroupTable, crate::price::Pricer) {
    let t = table(&[(
        "team",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    // 100 micro-units per output token is 100_000 nano-units; a thousand output tokens is
    // 100_000_000 nano-units, which is ten whole cents.
    (t, card(0, &[("m", 0.0, 100.0)]))
}

const NOW: u64 = 1_770_000_000;

fn daily_bucket() -> String {
    "group:team@day".to_string()
}

#[test]
fn a_door_carrying_nothing_compares_exactly_what_the_tag_compared() {
    let (t, pricer) = fixture();
    let d = door();
    let chain = chain(&t, "acme", Some("team"));

    // Nine thousand output tokens is ninety cents: under the hundred-cent cap, and admitted.
    d.try_admit(&pricer, &chain, "", NOW).expect("admitted");
    d.record_usage(&chain, "", "m", &toks(0, 9_000), NOW);
    assert_eq!(
        d.budget_headroom_cents(&pricer, &chain, "", NOW),
        Some(10),
        "ten cents of the cap are left"
    );
    d.try_admit(&pricer, &chain, "", NOW)
        .expect("still under the cap");

    // One more thousand takes it to a hundred, which is AT the cap and therefore over.
    d.record_usage(&chain, "", "m", &toks(0, 1_000), NOW);
    assert_eq!(
        d.budget_headroom_cents(&pricer, &chain, "", NOW),
        Some(0),
        "nothing is left"
    );
    assert_blocked(
        d.try_admit(&pricer, &chain, "", NOW)
            .expect_err("at the cap blocks"),
        "team",
        Metric::Budget,
        Some(DAY),
        true,
    );
}

#[test]
fn a_restart_forgets_the_spend_unless_the_ledger_carried_it_in() {
    let (t, pricer) = fixture();
    let chain = chain(&t, "acme", Some("team"));
    let window = crate::window::budget_window(DAY, NOW);

    // ── the door the process left behind: ninety cents spent, ten left ───────────────────────────
    let before = door();
    before
        .try_admit(&pricer, &chain, "", NOW)
        .expect("admitted");
    before.record_usage(&chain, "", "m", &toks(0, 9_000), NOW);
    assert_eq!(
        before.budget_headroom_cents(&pricer, &chain, "", NOW),
        Some(10)
    );

    // ── RESTART, unbound: the cells are gone and nothing remembers ───────────────────────────────
    let forgetful = door();
    assert_eq!(
        forgetful.budget_headroom_cents(&pricer, &chain, "", NOW),
        Some(100),
        "THE HAZARD: a fresh process hands the balance its whole cap back"
    );
    forgetful
        .try_admit(&pricer, &chain, "", NOW)
        .expect("and admits, which is the bug");

    // ── RESTART, carrying what the ledger restored ───────────────────────────────────────────────
    let remembering: Door<InMemoryCells> = Door::new(InMemoryCells::new())
        .carrying(Arc::new(Restored(vec![("group:team@day", window, 90)])));
    assert_eq!(
        remembering.budget_headroom_cents(&pricer, &chain, "", NOW),
        Some(10),
        "the figure survived the restart: ten cents left, exactly as before it"
    );
    remembering
        .try_admit(&pricer, &chain, "", NOW)
        .expect("still admissible under the cap");

    // And the post-restart accrual lands ON TOP of what was carried, not instead of it.
    remembering.record_usage(&chain, "", "m", &toks(0, 1_000), NOW);
    assert_eq!(
        remembering.budget_headroom_cents(&pricer, &chain, "", NOW),
        Some(0),
        "ninety carried plus ten accrued is the hundred-cent cap"
    );
    assert_blocked(
        remembering
            .try_admit(&pricer, &chain, "", NOW)
            .expect_err("and the cap blocks after the restart, as it did before it"),
        "team",
        Metric::Budget,
        Some(DAY),
        true,
    );
    assert_eq!(
        daily_bucket(),
        "group:team@day",
        "the bucket the fixture names"
    );
}

#[test]
fn a_balance_already_over_its_cap_is_refused_on_the_first_request_after_a_restart() {
    // The case the previous release's hydrate was written for, stated as an assertion: a key that
    // spent its whole cap must not get a single free request out of the restart.
    let (t, pricer) = fixture();
    let chain = chain(&t, "acme", Some("team"));
    let window = crate::window::budget_window(DAY, NOW);
    let d: Door<InMemoryCells> = Door::new(InMemoryCells::new())
        .carrying(Arc::new(Restored(vec![("group:team@day", window, 140)])));
    assert_eq!(
        d.budget_headroom_cents(&pricer, &chain, "", NOW),
        Some(0),
        "a balance past its cap has no headroom, and never a negative amount of it"
    );
    assert_blocked(
        d.try_admit(&pricer, &chain, "", NOW)
            .expect_err("the first request after the restart is refused"),
        "team",
        Metric::Budget,
        Some(DAY),
        true,
    );
}

#[test]
fn the_carried_figure_is_read_for_the_window_the_request_lands_in() {
    // A carry restored against yesterday's window must not be charged against today's. The window
    // the door asks for is the one the request landed in, and nothing else answers.
    let (t, pricer) = fixture();
    let chain = chain(&t, "acme", Some("team"));
    let yesterday = crate::window::budget_window(DAY, NOW) - 86_400;
    let d: Door<InMemoryCells> = Door::new(InMemoryCells::new())
        .carrying(Arc::new(Restored(vec![("group:team@day", yesterday, 140)])));
    assert_eq!(
        d.budget_headroom_cents(&pricer, &chain, "", NOW),
        Some(100),
        "yesterday's spend is yesterday's window's, and today's cap is whole"
    );
    d.try_admit(&pricer, &chain, "", NOW)
        .expect("today admits, because today has spent nothing");
}

#[test]
fn the_fee_lookahead_survives_the_rearrangement_around_the_subtraction() {
    // The second arm of the comparison, which is the one a rearrangement is most likely to drop:
    // a bucket UNDER its cap must still refuse a request whose flat fee would put it over.
    let t = table(&[(
        "team",
        group_cfg(None, true, vec![limit(LimitMetric::Budget, 100, Some(DAY))]),
    )]);
    let pricer = card(20, &[("m", 0.0, 100.0)]);
    let chain = chain(&t, "acme", Some("team"));
    let window = crate::window::budget_window(DAY, NOW);

    // Ninety cents carried, twenty-cent fee: ten cents left, and the fee does not fit.
    let d: Door<InMemoryCells> = Door::new(InMemoryCells::new())
        .carrying(Arc::new(Restored(vec![("group:team@day", window, 90)])));
    assert_eq!(d.budget_headroom_cents(&pricer, &chain, "", NOW), Some(10));
    assert_blocked(
        d.try_admit(&pricer, &chain, "", NOW)
            .expect_err("the fee lookahead refuses"),
        "team",
        Metric::Budget,
        Some(DAY),
        true,
    );

    // Seventy-nine carried: twenty-one left, and the fee fits.
    let d: Door<InMemoryCells> = Door::new(InMemoryCells::new())
        .carrying(Arc::new(Restored(vec![("group:team@day", window, 79)])));
    assert_eq!(d.budget_headroom_cents(&pricer, &chain, "", NOW), Some(21));
    d.try_admit(&pricer, &chain, "", NOW)
        .expect("twenty-one cents covers a twenty-cent fee");
}
