// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The cell's own state machine, at its edges.
//!
//! Every assertion here is against ONE cell driven by hand, at the exact threshold or the exact
//! second where the decision changes — the trip condition at `min_requests` and at the error-rate
//! threshold itself, the admission at the instant a cooldown elapses, the single-flight probe
//! admitting exactly one holder, the owner check on its release, and the two recovery closes. What
//! a walk makes of those decisions is somebody else's test; what is proved here is that each of
//! them is decided where the design says it is.
//!
//! Nothing here reads a clock. Every `now` is a value the test supplies, which is what makes a
//! decision at a threshold reproducible rather than a race with the machine it runs on.

use crate::cell::{BreakerCell, BreakerState, BreakerVerdict, DeniedBy, FailureEffect, ProbeAdmit};
use crate::cfg::{BreakerCfg, TripConfig, TripMode};

/// An error-rate configuration whose two thresholds are the values under test, with the escalating
/// cooldown pinned out of the way by a large ceiling.
fn error_rate_cfg(min_requests: usize, threshold: f64) -> BreakerCfg {
    BreakerCfg {
        base_cooldown_secs: 10,
        max_cooldown_secs: 1_000_000,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::ErrorRate,
            window_s: 300,
            threshold,
            min_requests,
            consecutive_n: u32::MAX,
        },
        bench_below_trip_threshold: false,
    }
}

/// A consecutive-failure configuration: `n` failures in a row and nothing else trips it.
fn consecutive_cfg(n: u32) -> BreakerCfg {
    BreakerCfg {
        base_cooldown_secs: 1,
        max_cooldown_secs: 1_000_000,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 300,
            threshold: 1.0,
            min_requests: usize::MAX,
            consecutive_n: n,
        },
        bench_below_trip_threshold: false,
    }
}

/// A configuration whose cooldown is EXACTLY what the upstream asked for: the Retry-After floor is
/// honored and set far above anything the jittered ladder can reach, so an armed deadline is a
/// value a test can name rather than a range it has to bracket.
fn pinned_cooldown_cfg() -> BreakerCfg {
    BreakerCfg {
        base_cooldown_secs: 1,
        max_cooldown_secs: 2,
        honor_retry_after: true,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 300,
            threshold: 1.0,
            min_requests: usize::MAX,
            consecutive_n: u32::MAX,
        },
        bench_below_trip_threshold: true,
    }
}

fn until_of(cell: &BreakerCell) -> u64 {
    match cell.state() {
        BreakerState::Open { until } => until,
        other => panic!("the cell was expected to be open, not {other:?}"),
    }
}

// ── the trip condition, at both of its thresholds ───────────────────────────────────────────────

/// `min_requests` is a floor the window must REACH, not pass: the cell trips on the request that
/// brings the window up to it, and not on the one before.
#[test]
fn the_error_rate_trip_fires_at_exactly_min_requests_and_not_before() {
    let cfg = error_rate_cfg(5, 0.5);
    let cell = BreakerCell::new();

    for n in 1..5 {
        assert_eq!(
            cell.record_failure(100, &cfg, None, 86_400),
            FailureEffect::Nothing,
            "{n} failures is short of the five the window needs"
        );
        assert_eq!(cell.state(), BreakerState::Closed);
    }

    assert_eq!(
        cell.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Tripped,
        "the fifth outcome brings the window up to min_requests and the rate is 1.0"
    );
    assert!(matches!(cell.state(), BreakerState::Open { .. }));
}

/// The error rate is the RATIO of the two counts, compared at the threshold itself: exactly at it
/// trips, one outcome short of it does not.
#[test]
fn the_error_rate_trip_fires_at_exactly_the_threshold() {
    // Four outcomes, one of them an error: 0.25, below the 0.5 threshold.
    let cfg = error_rate_cfg(4, 0.5);
    let quarter = BreakerCell::new();
    assert!(!quarter.record_success(100));
    assert!(!quarter.record_success(100));
    assert!(!quarter.record_success(100));
    assert_eq!(
        quarter.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Nothing,
        "one error in four is a quarter, which is under the half the threshold asks for"
    );
    assert_eq!(quarter.state(), BreakerState::Closed);

    // Four outcomes, two of them errors: exactly 0.5, which is the threshold and therefore trips.
    let half = BreakerCell::new();
    assert!(!half.record_success(100));
    assert!(!half.record_success(100));
    assert_eq!(
        half.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Nothing,
        "three outcomes is short of the four the window needs"
    );
    assert_eq!(
        half.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Tripped,
        "two errors in four is exactly the threshold, and the comparison is at-or-above"
    );
}

/// Outcomes that have aged out of the window are not evidence: a cell whose failures are older than
/// the window does not trip on them.
#[test]
fn outcomes_older_than_the_window_are_not_evidence() {
    let mut cfg = error_rate_cfg(3, 0.5);
    cfg.trip.window_s = 10;
    let cell = BreakerCell::new();

    // Three failures within one second of each other trip the cell: all three are in the window.
    let _ = cell.record_failure(100, &cfg, None, 86_400);
    let _ = cell.record_failure(100, &cfg, None, 86_400);
    assert_eq!(
        cell.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Tripped
    );

    // The same three failures spread far enough apart that only the newest is still in the
    // ten-second window when each is evaluated: the window never reaches min_requests.
    let spread = BreakerCell::new();
    for at in [100_u64, 200, 300, 400] {
        assert_eq!(
            spread.record_failure(at, &cfg, None, 86_400),
            FailureEffect::Nothing,
            "at second {at} the older failures have aged out, so the window holds one outcome"
        );
    }
    assert_eq!(spread.state(), BreakerState::Closed);
}

/// Consecutive mode counts failures in a row and trips on the `n`th, not the `n-1`th.
#[test]
fn the_consecutive_trip_fires_on_the_nth_failure_in_a_row() {
    let cfg = consecutive_cfg(3);
    let cell = BreakerCell::new();
    assert_eq!(
        cell.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Nothing
    );
    assert_eq!(
        cell.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Nothing
    );
    assert_eq!(
        cell.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Tripped
    );
}

// ── what a recorded failure reports ─────────────────────────────────────────────────────────────

/// The four arms are told apart by the two questions a caller asks of them: was this a fresh trip a
/// metric counts, and was it a reopen the probe journal records.
#[test]
fn the_two_questions_a_failure_effect_answers() {
    assert!(FailureEffect::Tripped.tripped());
    assert!(!FailureEffect::Reopened.tripped());
    assert!(!FailureEffect::Benched.tripped());
    assert!(!FailureEffect::Nothing.tripped());

    assert!(FailureEffect::Reopened.reopened());
    assert!(!FailureEffect::Tripped.reopened());
    assert!(!FailureEffect::Benched.reopened());
    assert!(!FailureEffect::Nothing.reopened());
}

/// The lifetime error counter counts every recorded failure and is NOT reset by a recovery.
#[test]
fn the_lifetime_error_count_counts_every_failure_and_survives_recovery() {
    let cfg = consecutive_cfg(u32::MAX);
    let cell = BreakerCell::new();
    assert_eq!(cell.err_count(), 0, "a fresh cell has recorded nothing");

    let _ = cell.record_failure(100, &cfg, None, 86_400);
    assert_eq!(cell.err_count(), 1);
    let _ = cell.record_failure(101, &cfg, None, 86_400);
    let _ = cell.record_failure(102, &cfg, None, 86_400);
    assert_eq!(cell.err_count(), 3);

    // A success records nothing against it, and neither does a full recovery.
    assert!(!cell.record_success(103));
    assert_eq!(cell.err_count(), 3);
    cell.close();
    assert_eq!(
        cell.err_count(),
        3,
        "the counter is a lifetime figure the state machine never reads"
    );
}

// ── readiness and the verdict, at the second a cooldown elapses ─────────────────────────────────

/// A fresh cell admits; a suppressed one does not; an expired-Open one does, because its probe is
/// winnable. The three answers are asserted on the same cell as it moves.
#[test]
fn readiness_follows_the_cell_through_its_states() {
    let cell = BreakerCell::new();
    assert!(cell.ready(100), "a fresh cell admits");
    assert_eq!(cell.verdict(100), BreakerVerdict::Ready);

    cell.hard_down(100, 30);
    assert!(
        !cell.ready(100),
        "a cell inside its cooldown does not admit"
    );
    assert_eq!(cell.verdict(100), BreakerVerdict::Open { until: 130 });

    assert!(
        cell.ready(130),
        "at the instant the cooldown elapses the probe is winnable, which is a form of ready"
    );
    assert_eq!(cell.verdict(130), BreakerVerdict::ProbeWinnable);

    assert!(
        !cell.ready(129),
        "and one second earlier it is still suppressed"
    );

    // A peer holding the probe is not ready either.
    assert!(matches!(cell.acquire(130), ProbeAdmit::ProbeWon(_)));
    assert!(!cell.ready(130), "a peer holds the single-flight probe");
    assert_eq!(cell.verdict(130), BreakerVerdict::HalfOpen);
}

/// The observable state names each of the three, and the deadline it carries is the one that was
/// armed.
#[test]
fn the_observable_state_names_each_of_the_three() {
    let cell = BreakerCell::new();
    assert_eq!(cell.state(), BreakerState::Closed);

    cell.hard_down(100, 30);
    assert_eq!(cell.state(), BreakerState::Open { until: 130 });

    assert!(matches!(cell.acquire(130), ProbeAdmit::ProbeWon(_)));
    assert_eq!(cell.state(), BreakerState::HalfOpen);

    assert!(cell.record_success(130));
    assert_eq!(cell.state(), BreakerState::Closed);
}

// ── the admission, and the single-flight probe ──────────────────────────────────────────────────

/// A Closed cell admits without winning anything to release, and a Closed cell still inside a
/// lingering cooldown is refused with that cooldown — at the exact second the two answers change.
#[test]
fn a_closed_cell_admits_at_the_instant_its_cooldown_elapses() {
    let cfg = pinned_cooldown_cfg();
    let cell = BreakerCell::new();
    assert_eq!(
        cell.acquire(100),
        ProbeAdmit::ReadyNoProbe,
        "a fresh cell admits and wins no probe"
    );

    // Benched below the trip threshold: still Closed, but carrying a cooldown to 100 + 500.
    assert_eq!(
        cell.record_failure(100, &cfg, Some(500), 86_400),
        FailureEffect::Benched
    );
    assert_eq!(cell.state(), BreakerState::Closed);

    assert_eq!(
        cell.acquire(599),
        ProbeAdmit::Denied(DeniedBy::Cooling { until: 600 }),
        "one second short of the deadline the cell is still benched"
    );
    assert_eq!(
        cell.acquire(600),
        ProbeAdmit::ReadyNoProbe,
        "at the deadline itself it admits again"
    );
}

/// The half-open probe is single-flight: exactly one caller wins it, and every peer is refused with
/// the reason that refused it — never with a cooldown it does not have.
#[test]
fn the_half_open_probe_admits_exactly_one_holder() {
    let cell = BreakerCell::new();
    cell.hard_down(100, 30);

    assert_eq!(
        cell.acquire(129),
        ProbeAdmit::Denied(DeniedBy::Cooling { until: 130 }),
        "inside the cooldown nobody wins a probe"
    );

    let ProbeAdmit::ProbeWon(epoch) = cell.acquire(130) else {
        panic!("the first caller at the deadline wins the probe");
    };

    for _ in 0..3 {
        assert_eq!(
            cell.acquire(130),
            ProbeAdmit::Denied(DeniedBy::ProbeInFlight),
            "a peer is refused because a probe is in flight, not because the cell is cooling"
        );
    }

    // The winner's own release gives it back, and the next caller wins a NEW probe.
    cell.release_probe_owned(epoch);
    let ProbeAdmit::ProbeWon(next) = cell.acquire(130) else {
        panic!("a released probe is winnable again");
    };
    assert!(
        next > epoch,
        "each win is a new owner token: {epoch} then {next}"
    );
}

/// The release is owner-checked: a token the cell no longer offers reverts nothing, which is what
/// stops a late release from taking back a probe a different caller has since won.
#[test]
fn a_release_that_does_not_own_the_probe_reverts_nothing() {
    let cell = BreakerCell::new();
    cell.hard_down(100, 30);
    let ProbeAdmit::ProbeWon(epoch) = cell.acquire(130) else {
        panic!("the probe was winnable");
    };

    cell.release_probe_owned(epoch.wrapping_add(7));
    assert_eq!(
        cell.state(),
        BreakerState::HalfOpen,
        "a release naming somebody else's token is a strict no-op"
    );
    assert_eq!(
        cell.acquire(130),
        ProbeAdmit::Denied(DeniedBy::ProbeInFlight),
        "and the live probe is still held"
    );

    // The owner's own token does revert it, and leaves the elapsed cooldown intact so the next
    // caller can re-win immediately rather than serving a cooldown for an outcome never recorded.
    cell.release_probe_owned(epoch);
    assert_eq!(cell.state(), BreakerState::Open { until: 130 });
    assert_eq!(cell.verdict(130), BreakerVerdict::ProbeWinnable);
}

/// A probe that fails reopens the cell rather than counting as a fresh trip, and the reopen re-arms
/// the cooldown.
#[test]
fn a_failed_probe_reopens_and_is_not_a_fresh_trip() {
    let cfg = pinned_cooldown_cfg();
    let cell = BreakerCell::new();
    cell.hard_down(100, 30);
    assert!(matches!(cell.acquire(130), ProbeAdmit::ProbeWon(_)));

    let effect = cell.record_failure(130, &cfg, Some(500), 86_400);
    assert_eq!(effect, FailureEffect::Reopened);
    assert!(!effect.tripped(), "the cell was already tripped");
    assert!(effect.reopened());
    assert_eq!(until_of(&cell), 630, "the reopen re-armed the cooldown");
}

/// A failure recorded against an already-Open cell is a no-op: the cooldown does not re-escalate on
/// every request that arrives during it.
#[test]
fn a_failure_against_an_open_cell_changes_nothing() {
    let cfg = pinned_cooldown_cfg();
    let cell = BreakerCell::new();
    cell.hard_down(100, 30);
    let before = until_of(&cell);

    assert_eq!(
        cell.record_failure(105, &cfg, Some(9_999), 86_400),
        FailureEffect::Nothing
    );
    assert_eq!(
        until_of(&cell),
        before,
        "the armed cooldown stands; a failure while open does not re-arm it"
    );
}

// ── recovery ────────────────────────────────────────────────────────────────────────────────────

/// The half-open probe's success is the one call that closes the cell, and it says so. The cell it
/// closes had no failure streak at all — a hard-down arms no streak — which is exactly the shape a
/// fast path that skipped the recovery would swallow.
#[test]
fn a_successful_probe_closes_the_cell_and_says_it_did() {
    let cell = BreakerCell::new();
    cell.hard_down(100, 30);
    assert!(matches!(cell.acquire(130), ProbeAdmit::ProbeWon(_)));
    assert_eq!(cell.state(), BreakerState::HalfOpen);

    assert!(
        cell.record_success(130),
        "the probe's success is what wins the half-open to closed transition"
    );
    assert_eq!(cell.state(), BreakerState::Closed);
    assert_eq!(cell.verdict(130), BreakerVerdict::Ready);

    // Only the call that WON the transition reports it.
    assert!(
        !cell.record_success(131),
        "a later success on an already-closed cell closed nothing"
    );
}

/// A success on a Closed cell resets the failure streak — so a cell that has been failing
/// intermittently needs a fresh run of failures to trip, not the tail of an old one.
#[test]
fn a_success_resets_the_failure_streak_on_a_closed_cell() {
    let cfg = consecutive_cfg(3);
    let cell = BreakerCell::new();

    let _ = cell.record_failure(100, &cfg, None, 86_400);
    let _ = cell.record_failure(101, &cfg, None, 86_400);
    assert_eq!(cell.state(), BreakerState::Closed, "two of the three");

    assert!(!cell.record_success(102));

    assert_eq!(
        cell.record_failure(103, &cfg, None, 86_400),
        FailureEffect::Nothing,
        "the streak restarted, so this is the first failure again"
    );
    assert_eq!(
        cell.record_failure(104, &cfg, None, 86_400),
        FailureEffect::Nothing,
        "and this is the second"
    );
    assert_eq!(
        cell.record_failure(105, &cfg, None, 86_400),
        FailureEffect::Tripped,
        "only the third failure in a row trips it"
    );
}

/// A success that lands on an OPEN cell must NOT wipe the escalating streak: the recovery it would
/// have completed never happened, and the next failure is owed the ladder the cell has climbed.
///
/// Read off the cooldown the reopen arms, which is `base << streak` — the one place the streak is
/// observable from outside.
#[test]
fn a_success_on_an_open_cell_does_not_wipe_the_escalating_streak() {
    let cfg = consecutive_cfg(2);
    let cell = BreakerCell::new();

    // Two failures in a row: the cell trips with a streak of two.
    assert_eq!(
        cell.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Nothing
    );
    assert_eq!(
        cell.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Tripped
    );
    let until = until_of(&cell);

    // A success lands on the open cell. It closes nothing — the recovery CAS only fires from
    // half-open — and it must leave the streak alone.
    assert!(
        !cell.record_success(100),
        "a success on an open cell completes no recovery"
    );

    // Win the probe once the cooldown elapses, then fail it. The reopen arms `base << streak`,
    // which is `1 << 3 == 8` if the streak survived and `1 << 1 == 2` if it was wiped. The ±10%
    // jitter is floored at one second either side, so the two are far apart.
    assert!(matches!(cell.acquire(until), ProbeAdmit::ProbeWon(_)));
    assert_eq!(
        cell.record_failure(until, &cfg, None, 86_400),
        FailureEffect::Reopened
    );
    let armed = until_of(&cell) - until;
    assert!(
        armed >= 7,
        "the ladder had climbed to three; the reopen armed {armed}s, which is a ladder that restarted"
    );
}

/// A full recovery resets everything the trip built: the streak, the outcome window and the
/// cooldown, so the cell starts arguing from nothing.
#[test]
fn a_full_recovery_resets_the_streak_the_window_and_the_cooldown() {
    let cfg = error_rate_cfg(3, 0.5);
    let cell = BreakerCell::new();
    for _ in 0..3 {
        let _ = cell.record_failure(100, &cfg, None, 86_400);
    }
    assert!(matches!(cell.state(), BreakerState::Open { .. }));

    cell.close();
    assert_eq!(cell.state(), BreakerState::Closed);
    assert!(
        cell.ready(100),
        "the cooldown went with the recovery, so the cell admits at once"
    );
    assert_eq!(cell.acquire(100), ProbeAdmit::ReadyNoProbe);

    // The window is empty too: three fresh failures are needed to trip again, not one.
    assert_eq!(
        cell.record_failure(101, &cfg, None, 86_400),
        FailureEffect::Nothing,
        "the outcomes that argued for the trip went with the recovery"
    );
    assert_eq!(
        cell.record_failure(101, &cfg, None, 86_400),
        FailureEffect::Nothing
    );
    assert_eq!(
        cell.record_failure(101, &cfg, None, 86_400),
        FailureEffect::Tripped
    );
}

// ── the out-of-band prober's conditional close ──────────────────────────────────────────────────

/// A cell nothing is suppressing is not recovered, and says so: there was nothing to recover.
#[test]
fn a_healthy_cell_is_not_recovered_by_the_prober() {
    let cell = BreakerCell::new();
    assert!(
        !cell.close_if_recoverable(100, 0),
        "a closed cell with no cooldown was never suppressed"
    );
    assert_eq!(cell.state(), BreakerState::Closed);
}

/// A suppressed cell whose cooldown the probe observed IS recovered — both the Open shape and the
/// Closed-inside-a-lingering-cooldown shape, which are two different reasons to be suppressed.
#[test]
fn the_prober_recovers_both_shapes_of_suppression() {
    // Open, still cooling.
    let open = BreakerCell::new();
    open.hard_down(100, 30);
    assert!(
        open.close_if_recoverable(105, 130),
        "an open cell the probe observed at its own cooldown is recoverable"
    );
    assert_eq!(open.state(), BreakerState::Closed);

    // Open with an ELAPSED cooldown: still suppressed, because the state itself is not closed.
    let elapsed = BreakerCell::new();
    elapsed.hard_down(100, 30);
    assert!(
        elapsed.close_if_recoverable(500, 130),
        "an open cell is suppressed by its state even once the cooldown has run out"
    );
    assert_eq!(elapsed.state(), BreakerState::Closed);

    // Closed, but inside a lingering cooldown.
    let cfg = pinned_cooldown_cfg();
    let benched = BreakerCell::new();
    assert_eq!(
        benched.record_failure(100, &cfg, Some(500), 86_400),
        FailureEffect::Benched
    );
    assert_eq!(benched.state(), BreakerState::Closed);
    assert!(
        benched.close_if_recoverable(200, 600),
        "a closed cell inside a cooldown is suppressed too"
    );
    assert!(
        benched.ready(200),
        "and the cooldown went with the recovery"
    );
}

/// The cooldown edge is exact: a closed cell whose cooldown ends at this very second is no longer
/// suppressed, so there is nothing to recover.
#[test]
fn the_probers_cooldown_edge_is_exact() {
    let cfg = pinned_cooldown_cfg();
    let cell = BreakerCell::new();
    assert_eq!(
        cell.record_failure(100, &cfg, Some(500), 86_400),
        FailureEffect::Benched
    );

    assert!(
        cell.close_if_recoverable(599, 600),
        "one second short of the deadline the cell is still suppressed"
    );

    let again = BreakerCell::new();
    assert_eq!(
        again.record_failure(100, &cfg, Some(500), 86_400),
        FailureEffect::Benched
    );
    assert!(
        !again.close_if_recoverable(600, 600),
        "at the deadline itself the cooldown has run and there is nothing to recover"
    );
}

/// A peer that armed a STRICTER cooldown after the probe read the cell wins: the recovery is
/// refused rather than dropping a suppression the probe never saw.
#[test]
fn a_stricter_cooldown_armed_after_the_probe_read_it_refuses_the_recovery() {
    let cell = BreakerCell::new();
    cell.hard_down(100, 30); // the probe's pre-filter reads 130
    cell.hard_down(100, 1800); // a hard-down lands afterwards: 1900

    assert!(
        !cell.close_if_recoverable(105, 130),
        "the cooldown now armed is later than anything the probe observed"
    );
    assert_eq!(
        cell.state(),
        BreakerState::Open { until: 1900 },
        "and the just-armed suppression stands"
    );

    // A probe that DID observe the newer cooldown recovers it.
    assert!(cell.close_if_recoverable(105, 1900));
    assert_eq!(cell.state(), BreakerState::Closed);
}

/// A cooldown that has been RELAXED since the probe read it is not a stricter one, so the recovery
/// still goes ahead.
#[test]
fn a_cooldown_earlier_than_the_one_observed_still_recovers() {
    let cell = BreakerCell::new();
    cell.hard_down(100, 30);
    assert!(
        cell.close_if_recoverable(105, 9_999),
        "the armed cooldown is earlier than the one observed, which is not a stricter suppression"
    );
    assert_eq!(cell.state(), BreakerState::Closed);
}

// ── the escalating cooldown ─────────────────────────────────────────────────────────────────────

/// The cooldown ladder is a shift on the streak, and the jitter that decorrelates simultaneous
/// trips is drawn across the whole ±10% band rather than pinned to one end of it.
#[test]
fn the_jitter_spans_the_band_rather_than_sitting_at_its_edge() {
    let cfg = BreakerCfg {
        base_cooldown_secs: 100,
        max_cooldown_secs: 1_000_000,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 300,
            threshold: 1.0,
            min_requests: usize::MAX,
            consecutive_n: 1,
        },
        bench_below_trip_threshold: false,
    };

    // Many cells trip on the same base at the same instant. The seed mixes each cell's own address,
    // so their cooldowns must not all land on the same value — that IS the decorrelation.
    let cells: Vec<BreakerCell> = (0..64).map(|_| BreakerCell::new()).collect();
    let mut drawn: Vec<u64> = Vec::new();
    for cell in &cells {
        assert_eq!(
            cell.record_failure(1_000, &cfg, None, 86_400),
            FailureEffect::Tripped
        );
        // The failure that trips bumps the streak to one first, so the ladder is `100 << 1`, and
        // the jitter band around it is ±10%.
        let armed = until_of(cell) - 1_000;
        assert!(
            (180..=220).contains(&armed),
            "a trip on a base of 100 at a streak of one must land inside the ±10% band around \
             200, not at {armed}"
        );
        drawn.push(armed);
    }

    drawn.sort_unstable();
    drawn.dedup();
    assert!(
        drawn.len() > 1,
        "sibling cells tripping on the same base and the same second must not all draw the same \
         cooldown, or they synchronize their recovery probes"
    );
}

/// An upstream's own Retry-After is a floor UNDER the computed cooldown, clamped to the caller's
/// absolute ceiling so a hostile value cannot park a lane indefinitely.
#[test]
fn the_upstreams_retry_after_is_a_floor_and_the_ceiling_is_absolute() {
    let cfg = pinned_cooldown_cfg();

    let cell = BreakerCell::new();
    cell.hard_down(0, 0); // an open cell whose cooldown has already run
    assert!(matches!(cell.acquire(100), ProbeAdmit::ProbeWon(_)));
    assert_eq!(
        cell.record_failure(100, &cfg, Some(500), 86_400),
        FailureEffect::Reopened
    );
    assert_eq!(until_of(&cell), 600, "the upstream's own wait is the floor");

    // The same value, clamped by the caller's ceiling.
    let clamped = BreakerCell::new();
    clamped.hard_down(0, 0);
    assert!(matches!(clamped.acquire(100), ProbeAdmit::ProbeWon(_)));
    assert_eq!(
        clamped.record_failure(100, &cfg, Some(1_000_000), 200),
        FailureEffect::Reopened
    );
    assert_eq!(
        until_of(&clamped),
        300,
        "a hostile Retry-After is honored only up to the ceiling the caller set"
    );
}

/// A configuration whose ceiling is below its floor is answered rather than panicked on: the
/// ceiling is what a ceiling means.
#[test]
fn a_ceiling_below_the_floor_is_answered_with_the_ceiling() {
    let cfg = BreakerCfg {
        base_cooldown_secs: 100,
        max_cooldown_secs: 1,
        honor_retry_after: false,
        trip: TripConfig {
            mode: TripMode::Consecutive,
            window_s: 300,
            threshold: 1.0,
            min_requests: usize::MAX,
            consecutive_n: 1,
        },
        bench_below_trip_threshold: false,
    };
    let cell = BreakerCell::new();
    assert_eq!(
        cell.record_failure(100, &cfg, None, 86_400),
        FailureEffect::Tripped
    );
    assert_eq!(until_of(&cell), 101);
}
