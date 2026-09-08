// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **PB-20: the book stays bounded, the settled figures do not move, and the chain stays
//! continuous.**
//!
//! The long fixture below is the whole claim. Twenty principals spend for three hundred and
//! sixty-five days; the ledger ticks once a day; and at the end the book holds a bounded number of
//! rows rather than a row per principal per day. Beside that, two things that a pruner is very easy
//! to get wrong and which no row count would catch: every all-time balance still reads exactly what
//! was settled into it, and the checkpoint sequence has no gap.
//!
//! The four reasons a row survives are exercised one at a time as well, because
//! [`Retirement::kept`]'s four counters are four different operator answers and a fixture that only
//! checked the total would report "not shrinking" for all of them.

use std::collections::BTreeMap;

use crate::checkpoint::{
    AnchorError, AnchoredHead, Checkpoint, CheckpointAnchor, SelfAttestingAnchor,
};
use crate::settle::Ledger;
use crate::tick::{TickAt, ALL_TIME_WINDOW};
use crate::totals::{BucketId, BucketScope, CapDimension, TotalsKey, WindowStart};

const DAY: u64 = 86_400;

fn key(bucket: &str) -> TotalsKey {
    TotalsKey::new(
        BucketId::new(bucket),
        CapDimension::NanoUnits,
        BucketScope::All,
    )
}

/// Settle `amount` into a balance's dated window AND into its all-time row, which is what a node
/// with a daily cap and a lifetime cap does on every request.
fn spend(ledger: &mut Ledger, bucket: &str, window: WindowStart, amount: i128) {
    for at in [window, ALL_TIME_WINDOW] {
        let figures = ledger.book_mut().entry(key(bucket), at);
        figures.drawn += amount;
        figures.settled += amount;
    }
}

fn tick_at(seq: u64, wall: u64, backup_watermark: u64) -> TickAt<'static> {
    TickAt {
        checkpoint_seq: seq,
        node: 7,
        wall,
        heads: Vec::new(),
        backup_watermark,
        store_seq_high_water: seq * 10,
        history_seq: None,
        secret: None,
    }
}

/// An anchor that can be told to fail, so the "kept because unanchored" arm is reachable.
#[derive(Debug, Default)]
struct FlakyAnchor {
    head: Option<AnchoredHead>,
    failing: bool,
    taken: Vec<u64>,
}

impl CheckpointAnchor for FlakyAnchor {
    fn anchor(&mut self, checkpoint: &Checkpoint) -> Result<(), AnchorError> {
        if self.failing {
            return Err(AnchorError::Unavailable("the sink is down".into()));
        }
        self.head = Some(AnchoredHead {
            checkpoint_seq: checkpoint.checkpoint_seq,
            body_hash: checkpoint.body_hash,
        });
        self.taken.push(checkpoint.checkpoint_seq);
        Ok(())
    }

    fn head(&self) -> Result<Option<AnchoredHead>, AnchorError> {
        Ok(self.head.clone())
    }

    fn is_self_attesting(&self) -> bool {
        true
    }
}

/// **The long fixture.** A year of daily windows, twenty principals, one tick a day.
#[test]
fn a_year_of_daily_windows_leaves_a_bounded_book_and_unmoved_settled_figures() {
    const PRINCIPALS: usize = 20;
    const DAYS: u64 = 365;
    /// How far behind the live window the backup is allowed to be. Two days, so the boundary's
    /// fourth rule is doing real work rather than never binding.
    const BACKUP_LAG_DAYS: u64 = 2;

    let mut ledger = Ledger::new();
    let mut anchor = SelfAttestingAnchor::new();
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    let mut expected_all_time: BTreeMap<String, i128> = BTreeMap::new();
    let mut peak_rows = 0usize;

    for day in 0..DAYS {
        let window = (day + 1) * DAY; // never zero: the all-time row is the only row at zero
        for p in 0..PRINCIPALS {
            let bucket = format!("vk_{p}");
            let amount = i128::from(day + 1) * 1_000_000 + p as i128;
            spend(&mut ledger, &bucket, window, amount);
            *expected_all_time.entry(bucket).or_insert(0) += amount;
        }
        // The backup is two days behind the window that just closed, which is what a real one is.
        let backup_watermark = window.saturating_sub(BACKUP_LAG_DAYS * DAY);
        let tock = ledger
            .tick(&tick_at(day + 1, window, backup_watermark), &mut anchor)
            .expect("no signer, so no signing failure");
        peak_rows = peak_rows.max(ledger.book().len());
        checkpoints.push(tock.checkpoint);
    }

    // ── BOUNDED ─────────────────────────────────────────────────────────────────────────────────
    //
    // Twenty principals times three hundred and sixty-five days plus twenty all-time rows is 7,320
    // rows if nothing is ever retired. What survives is the twenty all-time rows plus the dated
    // rows the backup has not passed yet — the two-day lag, plus the window sealed by the tick that
    // has not been anchored-and-passed yet.
    let live = ledger.book().len();
    let unbounded = PRINCIPALS * (DAYS as usize + 1);
    assert_eq!(
        live,
        PRINCIPALS * (1 + BACKUP_LAG_DAYS as usize + 1),
        "EXACTLY twenty all-time rows plus three dated windows each — the two the backup has not \
         passed and the one just sealed. {live} of a possible {unbounded}."
    );
    assert_eq!(live, 80, "which is eighty rows, stated as the number it is");
    assert_eq!(
        peak_rows, 80,
        "and it never grew past that at any point in the year"
    );
    assert_eq!(
        unbounded, 7_320,
        "which is the whole point: without retirement this book would hold 7,320 rows"
    );

    // ── THE ALL-TIME ROWS ARE UNTOUCHED ─────────────────────────────────────────────────────────
    for (bucket, settled) in &expected_all_time {
        assert_eq!(
            ledger.book().get(&key(bucket), ALL_TIME_WINDOW).settled,
            *settled,
            "the all-time balance for {bucket} was retired or altered by the pruner"
        );
    }
    assert_eq!(
        expected_all_time.len(),
        PRINCIPALS,
        "and every principal still has one"
    );

    // ── THE CHECKPOINT CHAIN IS CONTINUOUS ──────────────────────────────────────────────────────
    assert_eq!(checkpoints.len(), DAYS as usize, "one seal per tick");
    for (i, checkpoint) in checkpoints.iter().enumerate() {
        assert_eq!(
            checkpoint.checkpoint_seq,
            i as u64 + 1,
            "the sequence has a gap at {i}"
        );
        assert!(
            checkpoint.body_hash_verifies(),
            "checkpoint {} does not verify against its own body",
            checkpoint.checkpoint_seq
        );
    }
    assert_eq!(
        ledger.anchored_through(),
        Some(DAYS),
        "and the anchor sink took every one of them"
    );
    assert_eq!(
        ledger.anchor_state().consecutive_failures,
        0,
        "with no failures outstanding"
    );

    // ── A RETIRED ROW IS IN THE SEAL THAT PERMITTED RETIRING IT ─────────────────────────────────
    //
    // The order the tick runs in, stated as an assertion. A seal taken AFTER the retirement would
    // cover a book the rows had already left, and the figures would be gone from both.
    let day_one = DAY;
    assert_eq!(
        ledger.book().get(&key("vk_0"), day_one).settled,
        0,
        "day one's dated row has been retired from the live book"
    );
    assert_eq!(
        checkpoints[0].totals_for(&key("vk_0"), day_one).settled,
        1_000_000,
        "and it is on the first seal, with the figure it carried"
    );
}

#[test]
fn the_all_time_row_is_never_retired_however_far_the_backup_has_got() {
    let mut ledger = Ledger::new();
    let mut anchor = SelfAttestingAnchor::new();
    spend(&mut ledger, "vk_a", DAY, 500);
    // A watermark past the end of time. Under `retain_from`'s single global cutoff this is exactly
    // the call that deleted the all-time row, because zero is below every cutoff there is.
    let tock = ledger
        .tick(&tick_at(1, DAY, u64::MAX), &mut anchor)
        .expect("seals");
    assert_eq!(tock.retirement.retired, 1, "the dated row went");
    assert_eq!(
        tock.retirement.kept_all_time, 1,
        "and the all-time row was kept for its own reason, not by accident"
    );
    assert_eq!(
        ledger.book().get(&key("vk_a"), ALL_TIME_WINDOW).settled,
        500,
        "with its figure intact"
    );
}

#[test]
fn a_row_no_checkpoint_has_sealed_is_never_retired() {
    let mut ledger = Ledger::new();
    let mut anchor = SelfAttestingAnchor::new();
    spend(&mut ledger, "vk_a", DAY, 500);
    ledger
        .tick(&tick_at(1, DAY, u64::MAX), &mut anchor)
        .expect("seals");
    // A row that appears AFTER the seal. Nothing has it, so nothing may discard it.
    spend(&mut ledger, "vk_b", 2 * DAY, 700);
    let boundary = ledger.retire_at(u64::MAX);
    assert_eq!(boundary.retired, 0, "the fresh row is not retired");
    assert_eq!(
        boundary.kept_unsealed, 1,
        "and the reason is that nothing sealed it"
    );
    assert_eq!(ledger.book().get(&key("vk_b"), 2 * DAY).settled, 700);
}

#[test]
fn a_seal_the_anchor_refused_retires_nothing_and_says_so() {
    let mut ledger = Ledger::new();
    let mut anchor = FlakyAnchor {
        failing: true,
        ..Default::default()
    };
    spend(&mut ledger, "vk_a", DAY, 500);

    let first = ledger
        .tick(&tick_at(1, DAY, u64::MAX), &mut anchor)
        .expect("sealing does not need the anchor");
    assert!(!first.anchored, "the sink refused");
    assert!(first.anchor_failure.is_some(), "and said why");
    assert_eq!(first.anchor_state.consecutive_failures, 1);
    assert_eq!(
        first.retirement.retired, 0,
        "NOTHING is retired against a seal nobody outside this node has seen"
    );
    assert_eq!(first.retirement.kept_unanchored, 1);
    assert_eq!(
        ledger.book().get(&key("vk_a"), DAY).settled,
        500,
        "the figure is still here, which is the correct degradation"
    );

    // A week of failures is a week without tamper-evidence, and the count is the fact an alarm
    // reads.
    for seq in 2..=7 {
        let tock = ledger
            .tick(&tick_at(seq, seq * DAY, u64::MAX), &mut anchor)
            .expect("still seals");
        assert!(!tock.anchored);
    }
    assert_eq!(ledger.anchor_state().consecutive_failures, 7);
    assert!(ledger.anchor_state().should_alarm(5));
    assert_eq!(ledger.anchored_through(), None, "and nothing is anchored");

    // The sink comes back. The next tick anchors, the counter resets, and the rows the earlier
    // seals covered become retirable — the chain never broke.
    anchor.failing = false;
    let recovered = ledger
        .tick(&tick_at(8, 8 * DAY, u64::MAX), &mut anchor)
        .expect("seals");
    assert!(recovered.anchored);
    assert_eq!(recovered.anchor_state.consecutive_failures, 0);
    assert_eq!(
        recovered.retirement.retired, 1,
        "the backlog retires on the first tick that anchors"
    );
    assert_eq!(anchor.taken, vec![8], "and only the one seal was taken");
}

#[test]
fn a_row_at_or_above_the_backup_watermark_is_never_retired() {
    let mut ledger = Ledger::new();
    let mut anchor = SelfAttestingAnchor::new();
    spend(&mut ledger, "vk_a", DAY, 100);
    spend(&mut ledger, "vk_a", 2 * DAY, 200);
    spend(&mut ledger, "vk_a", 3 * DAY, 300);

    // The backup has reached the start of day two. Day one is below it; days two and three are not.
    let tock = ledger
        .tick(&tick_at(1, 3 * DAY, 2 * DAY), &mut anchor)
        .expect("seals");
    assert_eq!(tock.retirement.retired, 1, "only day one goes");
    assert_eq!(
        tock.retirement.kept_above_watermark, 2,
        "the two at or above the watermark are kept, and the reason is named"
    );
    assert_eq!(ledger.book().get(&key("vk_a"), DAY).settled, 0);
    assert_eq!(ledger.book().get(&key("vk_a"), 2 * DAY).settled, 200);
    assert_eq!(ledger.book().get(&key("vk_a"), 3 * DAY).settled, 300);

    // The row exactly AT the watermark is kept, not retired. Retention may not discard past where
    // the backup has got, and "past" includes the boundary itself: a backup that has reached the
    // start of a window has not finished that window.
    assert_eq!(
        tock.retirement.kept(),
        ledger.book().len(),
        "every surviving row is accounted for by exactly one reason"
    );
}

#[test]
fn the_boundary_is_per_balance_and_not_one_cut_across_the_node() {
    // The defect `retain_from` could not avoid: one cutoff for the whole node retires a busy
    // bucket's sealed rows and a quiet bucket's unsealed ones together.
    let mut ledger = Ledger::new();
    let mut anchor = SelfAttestingAnchor::new();
    spend(&mut ledger, "busy", DAY, 100);
    ledger
        .tick(&tick_at(1, DAY, u64::MAX), &mut anchor)
        .expect("seals");
    // `quiet` appears in the SAME window, after the seal.
    spend(&mut ledger, "quiet", DAY, 100);

    let boundary = ledger.retire_at(u64::MAX);
    assert_eq!(boundary.retired, 0, "busy's row already went on the tick");
    assert_eq!(
        boundary.kept_unsealed, 1,
        "and quiet's row in the very same window is kept, because nothing sealed IT"
    );
    assert_eq!(ledger.book().get(&key("quiet"), DAY).settled, 100);
    assert_eq!(ledger.book().get(&key("busy"), DAY).settled, 0);
}

#[test]
fn the_sealing_note_goes_with_the_row_it_described() {
    // The shadow map is the same unbounded growth one level down if a retired row's note stays.
    let mut ledger = Ledger::new();
    let mut anchor = SelfAttestingAnchor::new();
    for day in 1..=50u64 {
        spend(&mut ledger, "vk_a", day * DAY, 10);
        ledger
            .tick(&tick_at(day, day * DAY, u64::MAX), &mut anchor)
            .expect("seals");
    }
    assert_eq!(
        ledger.sealed_row_count(),
        ledger.book().len(),
        "one note per surviving row and not one more"
    );
    assert!(
        ledger.book().len() <= 2,
        "fifty days leave the all-time row and at most the live one"
    );
}
