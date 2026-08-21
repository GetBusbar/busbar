// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! VERIFY-ON-CALL, the fail-closed EDGES: the diagnostics latch's lifecycle, freshness under a
//! clock that ran backwards, coalescing that repeats per burst rather than latching off forever, and
//! a prune that spares a subject with a live in-flight fetch.
//!
//! These sit beside `verify_tests.rs` and drive the same plane-neutral `VerifyGate` with a fake
//! ledger (a shared `last_checked_ms`) and a fake fetch (a counter). Nothing here is a protocol fact;
//! every property is the gate's own — the latch that keeps a persistent outage from re-logging on
//! every call yet re-announces after a recovery, the fail-closed reading of a backwards clock, and
//! the epoch-per-call read that makes a SECOND burst coalesce exactly as the first did.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;

use super::super::reverify::{Ledger, Policy};
use super::VerifyGate;
use crate::plane::Plane;

/// A fake ledger reader over a shared `last_checked_ms` cell. `0` means "never checked" (due
/// immediately), matching what a plane's store yields for a registration nothing has ever observed.
fn ledger_of(last: &Arc<AtomicU64>) -> impl Fn() -> Ledger {
    let last = last.clone();
    move || {
        let v = last.load(SeqCst);
        Ledger {
            last_checked_ms: (v != 0).then_some(v),
            ..Default::default()
        }
    }
}

/// THE LATCH RE-ARMS AFTER A RECOVERY. A drift latches (logs once); a CLEAN serving outcome resets
/// the latch; the next drift latches again, so a fingerprint that moves, is worked, and moves a
/// SECOND time is announced the second time rather than swallowed by the first latch.
#[tokio::test]
async fn a_clean_outcome_resets_the_latch_so_a_later_drift_reannounces() {
    let gate = VerifyGate::new();
    let subject = "recoverysubject";

    // First drift latches.
    gate.report(Plane::A2a, subject, true, false);
    assert!(gate.is_latched(subject), "the first drift must latch");

    // A repeat while latched is a no-op — still latched, and (the production point) not re-logged.
    gate.report(Plane::A2a, subject, true, false);
    assert!(gate.is_latched(subject));

    // A CLEAN, serving outcome resets the latch: the upstream recovered and was re-approved.
    gate.report(Plane::A2a, subject, false, false);
    assert!(
        !gate.is_latched(subject),
        "a clean serving outcome must reset the latch so the next drift is announced again"
    );

    // A SECOND drift after the recovery latches once more — the re-announce the reset exists for.
    gate.report(Plane::A2a, subject, true, false);
    assert!(
        gate.is_latched(subject),
        "a post-recovery drift must re-latch rather than stay suppressed by the first latch"
    );
}

/// AN OUTAGE LATCHES AND STAYS LATCHED across repeated unreachable reports — a persistently
/// unreachable upstream logs ONCE, not once per call — and clears ONLY on a clean run.
#[tokio::test]
async fn an_outage_stays_latched_across_repeated_unreachable_and_clears_only_on_a_clean_run() {
    let gate = VerifyGate::new();
    let subject = "outagesubject";

    gate.report(Plane::A2a, subject, false, true);
    assert!(gate.is_latched(subject), "the first outage must latch");

    // Every subsequent unreachable report leaves it latched — this is what suppresses the storm.
    for _ in 0..5 {
        gate.report(Plane::A2a, subject, false, true);
        assert!(
            gate.is_latched(subject),
            "a repeated outage report must stay latched, not re-announce"
        );
    }

    // Only a clean, serving outcome clears it.
    gate.report(Plane::A2a, subject, false, false);
    assert!(
        !gate.is_latched(subject),
        "the latch clears only when the upstream is reachable and serving again"
    );
}

/// A CLEAN OUTCOME ON A NEVER-SEEN SUBJECT CREATES NO LATCH ENTRY. `report` with nothing wrong on a
/// subject the gate has never tracked must not insert a `false` entry — otherwise every serving call
/// to a healthy upstream would leak one map entry per subject, which is the per-call leak the
/// reset-only-if-present rule exists to avoid.
#[tokio::test]
async fn a_clean_outcome_on_a_never_seen_subject_leaves_no_latch_entry() {
    let gate = VerifyGate::new();
    let subject = "healthysubject";

    // The gate has never seen this subject: no flight, no latch.
    assert!(!gate.tracks_subject(subject));

    // A clean serving outcome must not create one.
    gate.report(Plane::A2a, subject, false, false);
    assert!(
        !gate.tracks_subject(subject),
        "a clean call on a never-seen subject must not leak a latch entry"
    );
    assert!(!gate.is_latched(subject));
}

/// A BACKWARDS CLOCK IS FAIL-CLOSED: due, and REFETCHES, even deep inside a wide TTL. A corrected or
/// tampered clock that jumped backwards must not be read as permanent freshness — an upstream never
/// checked again is one that can change freely.
#[tokio::test]
async fn a_backwards_clock_refetches_even_inside_a_wide_ttl() {
    let gate = VerifyGate::new();
    let fetches = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(10_000)); // last verified at t=10_000
    let policy = Policy {
        ttl_ms: 1_000_000, // a very wide freshness window
        recovery_backoff_ms: 0,
    };
    let fetch = |now: u64| {
        let fetches = fetches.clone();
        let last = last.clone();
        move || async move {
            fetches.fetch_add(1, SeqCst);
            last.store(now, SeqCst);
        }
    };

    // CONTROL: a forward clock well within the wide TTL reuses the snapshot — no fetch. This proves
    // the refetch below is the backwards clock and not merely a stale window.
    assert!(
        !gate
            .ensure_fresh(
                "clocksubject",
                &policy,
                10_500,
                ledger_of(&last),
                fetch(10_500)
            )
            .await,
        "a forward clock inside the wide ttl must reuse the snapshot"
    );
    assert_eq!(fetches.load(SeqCst), 0);

    // The clock jumped BACKWARDS to t=5_000 (< last=10_000). Elapsed time cannot be trusted, so the
    // gate treats it as due and refetches despite the million-ms window.
    assert!(
        gate.ensure_fresh(
            "clocksubject",
            &policy,
            5_000,
            ledger_of(&last),
            fetch(5_000)
        )
        .await,
        "a backwards clock must be treated as due and refetch, fail-closed"
    );
    assert_eq!(fetches.load(SeqCst), 1);
}

/// TWO SEQUENTIAL BURSTS EACH COALESCE TO EXACTLY ONE FETCH. The epoch is read PER CALL, so a first
/// burst coalescing to one fetch does not permanently suppress the next: a second burst against the
/// same still-stale snapshot coalesces to one fetch of its own. Two bursts → two fetches, not one and
/// not `2 * N`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_sequential_bursts_each_coalesce_to_one_fetch() {
    let gate = Arc::new(VerifyGate::new());
    let fetches = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(20_000));
    let policy = Policy {
        ttl_ms: 0, // strict-live: every call is stale, so only coalescing can hold the count down
        recovery_backoff_ms: 0,
    };
    let now = 20_000;

    // One burst of six callers, released together off a shared `Notify` so all six are provably
    // parked on the flight lock before the single fetcher completes and bumps the epoch.
    let run_burst = || {
        let gate = gate.clone();
        let fetches = fetches.clone();
        let last = last.clone();
        let policy = policy.clone();
        async move {
            let go = Arc::new(tokio::sync::Notify::new());
            let mut handles = Vec::new();
            for _ in 0..6u32 {
                let gate = gate.clone();
                let fetches = fetches.clone();
                let last = last.clone();
                let go = go.clone();
                let policy = policy.clone();
                handles.push(tokio::spawn(async move {
                    gate.ensure_fresh(
                        "burstsubject",
                        &policy,
                        now,
                        ledger_of(&last),
                        || async move {
                            fetches.fetch_add(1, SeqCst);
                            go.notified().await;
                            last.store(now, SeqCst);
                        },
                    )
                    .await
                }));
            }
            tokio::time::sleep(Duration::from_millis(75)).await;
            go.notify_waiters();
            let mut fetched = 0u32;
            for h in handles {
                if h.await.unwrap() {
                    fetched += 1;
                }
            }
            fetched
        }
    };

    assert_eq!(
        run_burst().await,
        1,
        "the first burst coalesces to one fetch"
    );
    assert_eq!(fetches.load(SeqCst), 1);

    // A SECOND burst, sequential to the first: the epoch is read afresh per call, so this burst is
    // not suppressed by the first's completed epoch — it coalesces to one fetch of its own.
    assert_eq!(
        run_burst().await,
        1,
        "the second burst coalesces to one fetch of its own — the epoch read is per call"
    );
    assert_eq!(
        fetches.load(SeqCst),
        2,
        "two sequential bursts perform exactly two fetches, not one and not twelve"
    );
}

/// RETAIN SPARES A LIVE IN-FLIGHT FETCH while dropping a retired subject, and the held flight
/// COMPLETES UNCORRUPTED. An apply carrying the current registration set prunes retired subjects, but
/// a subject with a fetch in flight is still fronted — its flight must survive the prune, and the
/// fetch it holds must complete and report its fetch as normal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retain_keeps_a_subject_with_a_live_flight_and_drops_a_retired_one() {
    let gate = Arc::new(VerifyGate::new());
    let policy = Policy {
        ttl_ms: 0,
        recovery_backoff_ms: 0,
    };

    // A RETIRED subject with a completed flight on record — the entry a prune should drop.
    {
        let last = Arc::new(AtomicU64::new(0));
        gate.ensure_fresh("retiredsubject", &policy, 1, ledger_of(&last), || async {})
            .await;
    }
    assert!(gate.tracks_subject("retiredsubject"));

    // A LIVE subject whose fetch is held mid-flight on a `Notify`, so it is provably in flight when
    // the prune runs.
    let fetches = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(0));
    let go = Arc::new(tokio::sync::Notify::new());
    let flight = {
        let gate = gate.clone();
        let fetches = fetches.clone();
        let last = last.clone();
        let go = go.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            gate.ensure_fresh("livesubject", &policy, 1, ledger_of(&last), || async move {
                fetches.fetch_add(1, SeqCst);
                go.notified().await; // HOLD the flight open across the prune.
                last.store(1, SeqCst);
            })
            .await
        })
    };

    // Wait for the held fetch to be running (its counter bumped) so the prune races a LIVE flight.
    for _ in 0..200 {
        if fetches.load(SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(fetches.load(SeqCst), 1, "the held fetch must be in flight");

    // The apply's registration set fronts only the live subject.
    let live: HashSet<String> = HashSet::from(["livesubject".to_string()]);
    gate.retain(&live);

    assert!(
        !gate.tracks_subject("retiredsubject"),
        "the retired subject must be pruned"
    );
    assert!(
        gate.tracks_subject("livesubject"),
        "a subject with a live in-flight fetch must survive the prune"
    );

    // Release the held flight; it must complete uncorrupted and report its fetch.
    go.notify_waiters();
    assert!(
        flight.await.unwrap(),
        "the held flight must complete and report having performed the fetch"
    );
    assert_eq!(fetches.load(SeqCst), 1);
}
