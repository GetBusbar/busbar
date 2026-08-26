// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! VERIFY-ON-CALL: the lazy, single-flight freshness gate every plane runs on the REQUEST path.
//!
//! An approval is a statement about an upstream at a moment, and nothing keeps it true. The pin
//! catches a change only when somebody looks — and the somebody is the CALL ITSELF, not a background
//! timer. Before a `tools/call` is dispatched (MCP) or a delegation is relayed (A2A), the request
//! ensures the server's recorded observation is no older than the operator's `verify_ttl`, and if it
//! is stale it re-fetches the upstream's advertised surface and re-compares — fail-closed — before the
//! compare that decides whether the call goes out.
//!
//! ## Why this replaces the background daemon
//!
//! The old shape re-hashed every registration on a `refresh_ttl` cadence with no operator present, and
//! the `tools/call` gate compared the approved digest against that LAST-refreshed cache. A tool that
//! drifted at 10:00 against a cache filled at 08:00 was dispatched to the changed upstream until the
//! next tick. For a platform whose promise is "control what AI can do BEFORE it acts", a call
//! dispatched to a function whose fingerprint moved — undetected for up to the cadence — is a hole.
//! Verifying on the call path against a short-lived snapshot closes it and, with single-flight, holds
//! upstream load to at most one fetch per `verify_ttl` per server regardless of caller count.
//!
//! ## The freshness bound is LAZY, never a schedule
//!
//! There is no timer and no background thread. On each call: if `now - fetched_at >= verify_ttl` a
//! refresh runs, else the snapshot is reused. Between calls nothing runs; a server nobody calls is
//! never fetched. `verify_ttl: 0` is strict-live — every call fetches (bursts still coalesce).
//! Freshness is [`super::reverify::due`]'s own arithmetic: reaching the TTL is stale, so the
//! operator's longest-acceptable-staleness means exactly what it says.
//!
//! ## Single-flight is the load lever, and it is CLOCK-INDEPENDENT
//!
//! When N callers hit a stale snapshot together, exactly ONE fetch runs and all N use its result. The
//! coalescing does NOT key on the fetched-at timestamp — a fixed test clock would make two fetches at
//! the same instant look interchangeable and over-fetch — it keys on a per-subject monotonic EPOCH
//! bumped once per completed fetch. A caller reads the epoch before it waits; if the epoch moved while
//! it waited, a sibling's fetch is its answer and it does not fetch again.
//!
//! ## Plane-neutral, and deliberately so
//!
//! The freshness question, the single-flight coalescing and the fail-closed ordering are written ONCE
//! here — in the neutral substrate, alongside the [`super::reverify::due`] arithmetic they call. Each
//! plane supplies only its FETCH — MCP's async JSON-RPC `tools/list` (+ token exchange), A2A's signed-
//! card read on a blocking thread — as the closure handed to [`VerifyGate::ensure_fresh`], and its
//! LEDGER reader (where its store records `last_checked_ms`). Nothing above the fetch knows which plane
//! it is on: a plane label travels through the diagnostics, never a branch.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::reverify::{Ledger, Policy};
use crate::diagnostics::{TRUST_VERIFY_REFUSED_ON_DRIFT, TRUST_VERIFY_UNREACHABLE};
use crate::{diag_debug, diag_warn};

/// One subject's coalescing state: an async lock the single fetcher holds, and the epoch every waiter
/// reads to learn whether a sibling already fetched. Kept behind an `Arc` so a waiter can drop the map
/// lock the instant it has its subject's flight, rather than holding the whole registry's coordination
/// across a network fetch.
#[derive(Debug)]
struct Flight {
    lock: tokio::sync::Mutex<()>,
    epoch: AtomicU64,
}

/// THE VERIFY-ON-CALL GATE, one per plane. It owns no cadence and no timer: it holds only the
/// per-subject coalescing state, created on first sight of a subject and reused thereafter. Each plane
/// owns its own instance on its per-generation runtime object (MCP folds it into its `McpRuntime`; the
/// A2A plane rides it on the core `App` beside its ledger).
#[derive(Debug, Default)]
pub struct VerifyGate {
    flights: Mutex<HashMap<String, Arc<Flight>>>,
    /// Per-subject latch for the fail-closed diagnostics, so a persistently unreachable or drifted
    /// upstream logs ONCE rather than on every call. `true` once latched; reset on a clean, serving
    /// outcome so the NEXT drift is announced again.
    drift_latch: Mutex<HashMap<String, bool>>,
}

impl VerifyGate {
    /// A fresh gate with no coalescing state. Equivalent to [`VerifyGate::default`]; `pub` because the
    /// extracted plane crates and the core A2A plane both construct one by name.
    pub fn new() -> Self {
        Self::default()
    }

    fn flight_for(&self, subject: &str) -> Arc<Flight> {
        let mut map = self.flights.lock().unwrap_or_else(|p| p.into_inner());
        map.entry(subject.to_string())
            .or_insert_with(|| {
                Arc::new(Flight {
                    lock: tokio::sync::Mutex::new(()),
                    epoch: AtomicU64::new(0),
                })
            })
            .clone()
    }

    /// ENSURE `subject`'s recorded observation is no older than `policy.ttl_ms`, single-flighting the
    /// refresh through `fetch`. `ledger` reads the plane's store for this subject's `last_checked_ms`;
    /// `fetch` performs the plane's own re-fetch AND stamps that ledger (so a completed fetch — success
    /// OR failure — is observed as fresh, and an unreachable upstream is recorded `Failed`, which the
    /// caller's own gate then refuses fail-closed rather than serving past the TTL).
    ///
    /// Returns whether a fetch was performed on THIS call — the counter the single-flight and
    /// ttl-bound batteries assert against.
    pub async fn ensure_fresh<L, F, Fut>(
        &self,
        subject: &str,
        policy: &Policy,
        now_ms: u64,
        ledger: L,
        fetch: F,
    ) -> bool
    where
        L: Fn() -> Ledger,
        F: FnOnce() -> Fut,
        Fut: Future<Output = ()>,
    {
        // FAST PATH: fresh, and nothing to coordinate. The freshness DECISION is `super::reverify::due`
        // ("reaching the TTL is stale") over the plane's OWN `last_checked_ms`; the ledger, coalescing
        // and await stay plane-side. This gate now lives in the neutral substrate ALONGSIDE that
        // arithmetic, so it names `reverify::due` directly rather than crossing a host veneer — the
        // decision is byte-for-byte what the operator wrote.
        if !super::reverify::due(&ledger(), policy, now_ms, false).should_check() {
            return false;
        }
        let flight = self.flight_for(subject);
        // Read the epoch BEFORE queueing on the lock. If it moves while we wait, a sibling fetch
        // landed and its result is ours — CLOCK-INDEPENDENT, so a fixed-clock test still coalesces.
        let seen = flight.epoch.load(Ordering::Acquire);
        let _guard = flight.lock.lock().await;
        if flight.epoch.load(Ordering::Acquire) != seen {
            return false;
        }
        // A prior fetch under a longer ttl may already have made us fresh at the same epoch read.
        // The same `reverify::due` decision as the fast path.
        if !super::reverify::due(&ledger(), policy, now_ms, false).should_check() {
            return false;
        }
        fetch().await;
        flight.epoch.fetch_add(1, Ordering::Release);
        true
    }

    /// EMIT the verify-on-call outcome once the caller's gate has decided. `drifted` is the compare
    /// refusing on a moved fingerprint; `unreachable` is the fetch having failed to reach the upstream
    /// (fail-closed refusal). Latched per subject so persistent drift or a persistent outage logs
    /// once, not per call; a clean, serving outcome resets the latch so the NEXT drift is announced
    /// again. `plane` is a LABEL, never a branch — the same code runs for MCP and A2A.
    pub fn report(&self, plane: &'static str, subject: &str, drifted: bool, unreachable: bool) {
        if !drifted && !unreachable {
            self.reset_latch(subject);
            return;
        }
        {
            let mut latch = self.drift_latch.lock().unwrap_or_else(|p| p.into_inner());
            if latch.get(subject).copied().unwrap_or(false) {
                return;
            }
            latch.insert(subject.to_string(), true);
        }
        if unreachable {
            diag_warn!(
                TRUST_VERIFY_UNREACHABLE,
                plane = plane,
                subject = %subject,
                "verify-on-call could not reach this upstream to re-verify its advertised surface \
                 within `verify_ttl`; the call is REFUSED fail-closed rather than served against a \
                 snapshot older than the operator's bound"
            );
        } else {
            diag_debug!(
                TRUST_VERIFY_REFUSED_ON_DRIFT,
                plane = plane,
                subject = %subject,
                "verify-on-call found the upstream's advertised surface DRIFTED from the approved \
                 fingerprint; the call is refused before dispatch until an operator re-approves"
            );
        }
    }

    fn reset_latch(&self, subject: &str) {
        let mut latch = self.drift_latch.lock().unwrap_or_else(|p| p.into_inner());
        if latch.get(subject).copied().unwrap_or(false) {
            latch.insert(subject.to_string(), false);
        }
    }

    /// PRUNE the per-subject coordination to the subjects the deployment still fronts. Called from the
    /// config-apply/carry path with the CURRENT registration set: without it, `flights` and
    /// `drift_latch` gain one entry per subject ever seen and never lose one, so an operator rotating
    /// or retiring servers/agents leaks an entry per retired subject across every apply. Dropping a
    /// removed subject's flight and latch is safe — a subject no longer in the registration set is
    /// never fetched, so its coalescing state cannot race an in-flight verify — and it is fail-closed:
    /// a surviving subject keeps its latch, and a later re-add simply gets a fresh flight on next sight.
    pub fn retain(&self, live_subjects: &std::collections::HashSet<String>) {
        self.flights
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|subject, _| live_subjects.contains(subject));
        self.drift_latch
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|subject, _| live_subjects.contains(subject));
    }

    /// INTROSPECT the per-subject state, so a battery can assert a prune dropped exactly the retired
    /// subjects and a panic latched the outage, without reaching into the private maps. `pub` because
    /// the test suites that exercise this gate live in more than one crate (this crate's own batteries
    /// and the core A2A plane's carry tests).
    pub fn tracks_subject(&self, subject: &str) -> bool {
        self.flights
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(subject)
            || self
                .drift_latch
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .contains_key(subject)
    }

    /// Whether `subject`'s outage/drift diagnostic is currently latched. `pub` for the same
    /// cross-crate reason as [`VerifyGate::tracks_subject`].
    pub fn is_latched(&self, subject: &str) -> bool {
        self.drift_latch
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(subject)
            .copied()
            .unwrap_or(false)
    }
}
