// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! VERIFY-ON-CALL, the plane-neutral primitive proven WITHOUT a plane.
//!
//! Every battery drives `VerifyGate::ensure_fresh` with a fake fetch (a counter) and a fake ledger (a
//! shared `last_checked_ms`), because the properties under test are the freshness bound and the
//! single-flight coalescing — neither of which is a protocol fact. The fail-closed REFUSAL is a plane
//! integration property (a failed fetch records `Failed`, which the plane's own gate refuses) and is
//! proven on the MCP and A2A request paths; here we prove the load-lever the spec turns on: a stale
//! snapshot triggers exactly one fetch no matter how many callers hit it together, and a fresh one
//! triggers none.

use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;

use super::super::reverify::{Ledger, Policy};
use super::VerifyGate;

/// A fake ledger reader over a shared `last_checked_ms` cell. `0` means "never checked" (the
/// fail-closed `NeverChecked`, i.e. due immediately), matching what a plane's store yields for a
/// registration nothing has ever observed.
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

/// A stale snapshot triggers a fetch; a fresh one does not — the whole of the lazy bound, on one
/// subject, with no concurrency in play.
#[tokio::test]
async fn stale_fetches_fresh_reuses() {
    let gate = VerifyGate::new();
    let fetches = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(0)); // never checked → due
    let policy = Policy {
        ttl_ms: 5_000,
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

    // NeverChecked → one fetch, which stamps `last = 1_000`.
    assert!(
        gate.ensure_fresh("s", &policy, 1_000, ledger_of(&last), fetch(1_000))
            .await
    );
    assert_eq!(fetches.load(SeqCst), 1);

    // Well within the ttl → reused, no fetch.
    assert!(
        !gate
            .ensure_fresh("s", &policy, 3_000, ledger_of(&last), fetch(3_000))
            .await
    );
    assert_eq!(fetches.load(SeqCst), 1);
}

/// THE TTL BOUND. A call within `verify_ttl` uses the snapshot (0 fetches); the first call at or past
/// it fetches exactly once; a call within the ttl of THAT fetch reuses again.
#[tokio::test]
async fn a_call_within_ttl_reuses_and_one_past_it_refetches() {
    let gate = VerifyGate::new();
    let fetches = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(1_000)); // last verified at t=1_000
    let policy = Policy {
        ttl_ms: 5_000,
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

    // t=3_000: 2_000 < 5_000 → fresh → no fetch.
    assert!(
        !gate
            .ensure_fresh("s", &policy, 3_000, ledger_of(&last), fetch(3_000))
            .await
    );
    assert_eq!(fetches.load(SeqCst), 0);

    // t=6_000: 5_000 >= 5_000 → reaching the ttl is stale → exactly one fetch, restamps last=6_000.
    assert!(
        gate.ensure_fresh("s", &policy, 6_000, ledger_of(&last), fetch(6_000))
            .await
    );
    assert_eq!(fetches.load(SeqCst), 1);

    // t=8_000: 2_000 < 5_000 against the new stamp → fresh again → no fetch.
    assert!(
        !gate
            .ensure_fresh("s", &policy, 8_000, ledger_of(&last), fetch(8_000))
            .await
    );
    assert_eq!(fetches.load(SeqCst), 1);
}

/// SINGLE-FLIGHT. N callers hit a stale snapshot AT THE SAME INSTANT → exactly ONE fetch runs and all
/// N return. The fetch is held (on a `Notify`) so the other N-1 provably queue on the subject's flight
/// lock — having already read the pre-fetch epoch — before the one fetcher completes and bumps it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n_concurrent_stale_hits_fetch_exactly_once() {
    let gate = Arc::new(VerifyGate::new());
    let fetches = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(0)); // never checked → every caller is stale
    let go = Arc::new(tokio::sync::Notify::new());
    let policy = Policy {
        ttl_ms: 5_000,
        recovery_backoff_ms: 0,
    };
    let now = 10_000;

    let mut handles = Vec::new();
    for _ in 0..8u32 {
        let gate = gate.clone();
        let fetches = fetches.clone();
        let last = last.clone();
        let go = go.clone();
        let policy = policy.clone();
        handles.push(tokio::spawn(async move {
            let ledger = ledger_of(&last);
            gate.ensure_fresh("s", &policy, now, ledger, || async move {
                fetches.fetch_add(1, SeqCst);
                // HOLD the single fetcher so the other seven provably park on the flight lock.
                go.notified().await;
                last.store(now, SeqCst);
            })
            .await
        }));
    }

    // Give all eight tasks time to reach the flight lock (one in the held fetch, seven queued).
    tokio::time::sleep(Duration::from_millis(75)).await;
    go.notify_waiters();

    let mut fetched = 0u32;
    for h in handles {
        if h.await.unwrap() {
            fetched += 1;
        }
    }
    assert_eq!(
        fetches.load(SeqCst),
        1,
        "exactly one upstream fetch for the whole burst"
    );
    assert_eq!(
        fetched, 1,
        "exactly one caller reports having performed the fetch"
    );
}

/// STRICT LIVE (`verify_ttl: 0`). Every SEQUENTIAL call fetches — there is no freshness window — while
/// a concurrent BURST still coalesces to one fetch, exactly as the spec requires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ttl_zero_fetches_every_call_but_coalesces_a_burst() {
    let policy = Policy {
        ttl_ms: 0,
        recovery_backoff_ms: 0,
    };
    let now = 10_000;

    // (a) SEQUENTIAL: each call is stale under a zero window, so each fetches.
    {
        let gate = VerifyGate::new();
        let fetches = Arc::new(AtomicU64::new(0));
        let last = Arc::new(AtomicU64::new(now));
        let fetch = || {
            let fetches = fetches.clone();
            let last = last.clone();
            move || async move {
                fetches.fetch_add(1, SeqCst);
                last.store(now, SeqCst);
            }
        };
        assert!(
            gate.ensure_fresh("s", &policy, now, ledger_of(&last), fetch())
                .await
        );
        assert!(
            gate.ensure_fresh("s", &policy, now, ledger_of(&last), fetch())
                .await
        );
        assert_eq!(fetches.load(SeqCst), 2, "ttl=0 has no freshness window");
    }

    // (b) BURST: a batch arriving together still coalesces to one fetch.
    {
        let gate = Arc::new(VerifyGate::new());
        let fetches = Arc::new(AtomicU64::new(0));
        let last = Arc::new(AtomicU64::new(now));
        let go = Arc::new(tokio::sync::Notify::new());
        let mut handles = Vec::new();
        for _ in 0..6u32 {
            let gate = gate.clone();
            let fetches = fetches.clone();
            let last = last.clone();
            let go = go.clone();
            let policy = policy.clone();
            handles.push(tokio::spawn(async move {
                gate.ensure_fresh("s", &policy, now, ledger_of(&last), || async move {
                    fetches.fetch_add(1, SeqCst);
                    go.notified().await;
                    last.store(now, SeqCst);
                })
                .await
            }));
        }
        tokio::time::sleep(Duration::from_millis(75)).await;
        go.notify_waiters();
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            fetches.load(SeqCst),
            1,
            "a concurrent burst coalesces even at ttl=0"
        );
    }
}

/// TWO SUBJECTS DO NOT SHARE A FLIGHT. A stale hit on `a` must not suppress a stale hit on `b`: the
/// coalescing is per subject, so each fetches once.
#[tokio::test]
async fn distinct_subjects_each_fetch() {
    let gate = VerifyGate::new();
    let fetches = Arc::new(AtomicU64::new(0));
    let last = Arc::new(AtomicU64::new(0));
    let policy = Policy {
        ttl_ms: 5_000,
        recovery_backoff_ms: 0,
    };
    let fetch = || {
        let fetches = fetches.clone();
        move || async move {
            fetches.fetch_add(1, SeqCst);
        }
    };
    assert!(
        gate.ensure_fresh("a", &policy, 1, ledger_of(&last), fetch())
            .await
    );
    assert!(
        gate.ensure_fresh("b", &policy, 1, ledger_of(&last), fetch())
            .await
    );
    assert_eq!(fetches.load(SeqCst), 2);
}

/// RESOURCE: the per-subject coordination is pruned to the live registration set on the carry path,
/// so an operator retiring a server/agent does not leak its `flights`/`drift_latch` entry forever.
///
/// RED, WATCHED: without `VerifyGate::retain`, both assertions on the retired subject below fail — its
/// flight and its latch remain tracked across the (simulated) apply.
#[tokio::test]
async fn retain_drops_retired_subjects_and_keeps_the_live_ones() {
    use std::collections::HashSet;

    let gate = VerifyGate::new();
    let policy = Policy {
        ttl_ms: 0,
        recovery_backoff_ms: 0,
    };
    // Give BOTH subjects a flight (a completed verify) and a latch (a reported drift), the two maps
    // that would otherwise accumulate one dead entry per subject ever seen.
    for subject in ["retired", "surviving"] {
        let last = Arc::new(AtomicU64::new(0));
        gate.ensure_fresh(subject, &policy, 1, ledger_of(&last), || async {})
            .await;
        gate.report("a2a", subject, true, false);
    }
    assert!(gate.tracks_subject("retired") && gate.is_latched("retired"));
    assert!(gate.tracks_subject("surviving") && gate.is_latched("surviving"));

    // The operator removed `retired`; the new registration set fronts only `surviving`.
    let live: HashSet<String> = HashSet::from(["surviving".to_string()]);
    gate.retain(&live);

    assert!(
        !gate.tracks_subject("retired"),
        "the retired subject's flight and latch are pruned — no leak per retired server/agent"
    );
    assert!(
        gate.tracks_subject("surviving") && gate.is_latched("surviving"),
        "a surviving subject keeps its coalescing state AND its latch, so a persistent outage still \
         logs once rather than re-announcing on every call"
    );
}
