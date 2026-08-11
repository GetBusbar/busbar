// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JOB THAT DRIVES RE-VERIFICATION. [`super::verify::reverify_once`] was the pass; this is what
//! calls it on a timer, which is the difference between a control that exists and a control that
//! runs.
//!
//! ## THE ASYMMETRY SURVIVES BEING SCHEDULED, and that is the whole point of this file
//!
//! [`super::reverify`] holds detection and demotion apart from recovery: the first drift demotes
//! immediately however long the recovery backoff is, and only a CLEAN answer is ever disbelieved. A
//! scheduler is the obvious place to lose that, because a scheduler is made of exactly the knobs
//! that would: a tick interval, a concurrency cap, a per-agent cooldown, a "skip if we checked
//! recently" fast path. Every one of those would slow DETECTION, and a window an upstream can open
//! for itself by flapping is a window it will use.
//!
//! So this file has **no knob at all**, deliberately:
//!
//! - **The tick is a constant** ([`REVERIFY_TICK`]), not config. A configurable sweep interval is a
//!   configurable detection delay wearing a scheduling costume. The cadence an operator is supposed
//!   to control is the per-registration `reverify_ttl`, which [`super::reverify::due`] already owns;
//!   the tick only decides how finely the job can notice that a TTL has elapsed, and making it
//!   coarser can only ever make detection later.
//! - **No agent is ever skipped.** The sweep asks [`super::reverify::due`] about every registration
//!   on every tick and lets it answer. There is no rate limit on being CHECKED, no backoff on being
//!   checked, and no "this one failed last time so leave it a while" — a failing upstream is the one
//!   that most needs looking at.
//! - **`operator_sync` is always `false` here.** The timer is not an operator. The verb path passes
//!   `true` and OUTRANKS the timer; nothing on this path can suppress a check that the timer's own
//!   arithmetic says is due.
//!
//! `tests/scheduler_tests.rs` re-runs the pure function's own asymmetry case — a registration whose
//! `recovery_backoff_ms` is `u64::MAX` — THROUGH THIS SWEEP, so the claim is a property of the code
//! that actually runs rather than of the function underneath it.
//!
//! ## ONE TRANSPORT PER REGISTRATION, and it is a correctness property rather than a refactor
//!
//! This file used to build ONE transport and use it for every registration on the plane. That read
//! as an efficiency, and it was a defect with a name: `pin.mechanism: mtls` could be written in
//! config and could never work, because the client certificate busbar must present is per
//! REGISTRATION — it is the certificate this operator agreed to present to THAT vendor — and a
//! single plane-wide transport has exactly one place to put one. Anywhere it went, it went to
//! everybody.
//!
//! So the sweep takes a [`CardTransports`] and asks it, INSIDE the loop, for the transport belonging
//! to the registration it is about to re-verify. The bundle is built once per config generation from
//! identities resolved at boot, so the per-agent shape costs a map lookup per registration per tick
//! and no key material is touched on the tick at all.
//!
//! ## There is no final sweep at shutdown, and that is not the flusher's mistake repeated
//!
//! The write-behind flusher does a final flush on the shutdown signal because unflushed spend is
//! LOST. A skipped sweep loses nothing: no observation is buffered here, the ledger is the durable
//! record of what was seen, and a registration that was not checked before the process stopped is
//! `NeverChecked` or `TtlExpired` at the next boot — which is to say, due immediately. Doing card
//! fetches against every registered upstream while the process is trying to exit would trade a
//! guarantee we already have for a slower shutdown.

use std::sync::Arc;
use std::time::Duration;

use super::fetch::{FetchPolicy, Resolver, Transport};
use super::plane::A2aPlane;
use super::transport::LiveCardFetch;
use super::verify::{reverify_once, Pass};

/// HOW OFTEN THE SWEEP LOOKS FOR WORK. A constant, and see the module note on why it is not config.
///
/// It bounds only the GRANULARITY of detection, never its policy: a registration whose TTL elapsed
/// mid-tick is re-verified on the next one. The value is small relative to the smallest sensible
/// `reverify_ttl` and large relative to the cost of asking `due` about a handful of registrations,
/// which is integer arithmetic over a struct.
pub(crate) const REVERIFY_TICK: Duration = Duration::from_secs(30);

/// WHICH TRANSPORT ONE REGISTRATION IS RE-VERIFIED OVER.
///
/// THE SEAM THAT USED NOT TO EXIST, and its absence was the whole of the `mtls` defect. [`sweep`]
/// took a single `&dyn Transport` and used it for every registration on the plane, so an outbound
/// client identity — which is per registration by definition, being the certificate this operator
/// agreed to present to THAT vendor — had nowhere to live. Any place it could have been put would
/// have been a place that presented it to everybody.
///
/// It is deliberately not a factory returning an owned transport: the production implementation
/// builds one transport per agent ONCE per config generation, and a `-> Box<dyn Transport>` would
/// have invited a rebuild per agent per tick, which is a fresh TLS client every thirty seconds for
/// every registration.
pub(crate) trait CardTransports {
    /// The transport for `agent_id`. Total, because a sweep must never skip a registration: an
    /// agent with no client identity gets one that presents no certificate and is refused by an
    /// mTLS peer, which is an observation the ledger should record rather than a hole in the sweep.
    fn for_agent(&self, agent_id: &str) -> &dyn Transport;
}

/// ONE TRANSPORT FOR EVERY REGISTRATION — the shape this file used to have, kept as a NAMED adapter
/// so what it costs is legible at the call site.
///
/// It is `#[cfg(test)]`, so it is not merely unused in production — it is ABSENT from the release
/// binary. A future caller that wants one transport for the whole plane has to write the words "one
/// for all" and compile it in, which is the review conversation the old signature never prompted.
/// It exists for the tests whose subject is the re-verification cadence rather than the connection.
#[cfg(test)]
pub(crate) struct OneForAll<'a>(pub(crate) &'a dyn Transport);

#[cfg(test)]
impl CardTransports for OneForAll<'_> {
    fn for_agent(&self, _agent_id: &str) -> &dyn Transport {
        self.0
    }
}

/// WHAT ONE SWEEP DID TO ONE REGISTRATION, so the outcome can be logged and surfaced rather than
/// re-derived by a reader who would have to guess.
#[derive(Debug)]
pub(crate) struct SweepOutcome {
    pub(crate) agent_id: String,
    pub(crate) pass: Pass,
}

/// ONE SWEEP over every registration on the plane.
///
/// Takes the clock as an argument and holds no timer of its own, which is what makes the asymmetry
/// testable: a test drives the same function the job drives, at times it chooses, with no sleeping
/// and nothing for a scheduler to race.
///
/// The write lock is held for the whole sweep. That is deliberate on a registry whose size is the
/// operator's `agents:` count: a sweep that released the lock between registrations could interleave
/// with a config apply and leave half the registry re-verified against one generation's pins and
/// half against another's.
pub(crate) fn sweep(
    plane: &A2aPlane,
    resolver: &dyn Resolver,
    transports: &dyn CardTransports,
    now_ms: u64,
) -> Vec<SweepOutcome> {
    let base: FetchPolicy = plane.fetch_policy().clone();
    plane.with_registrations_mut(|registrations| {
        let mut out = Vec::with_capacity(registrations.len());
        for reg in registrations.iter_mut() {
            // A registration whose pin is not in this generation's config is one the operator has
            // REMOVED. It is not re-verified against a remembered pin: verifying a card against a
            // trust root nobody currently declares would be busbar deciding the operator did not
            // mean it.
            let Some(pin_cfg) = plane.pin_for(&reg.agent_id).cloned() else {
                continue;
            };
            // THE POLICY IS PER REGISTRATION, because `allow_private:` is. Read off the record
            // rather than from `fetch_policy_for` — this closure already holds the registry's write
            // lock, and re-entering it to read one bool would deadlock. It is the same value: the
            // record is where `from_config` lowered the operator's line to.
            let policy = FetchPolicy {
                allow_private: reg.allow_private,
                ..base.clone()
            };
            // THE TRANSPORT THAT BELONGS TO THIS REGISTRATION, carrying this registration's client
            // certificate and no other's. Asked for INSIDE the loop, per agent, which is the entire
            // structural change: one transport per plane could only ever have presented one
            // identity.
            let transport = transports.for_agent(&reg.agent_id);
            let pass = reverify_once(
                reg, &pin_cfg, resolver, transport, &policy, now_ms,
                // THE TIMER IS NOT AN OPERATOR. `sync` outranks the timer; the timer never claims
                // to be a sync, and there is no argument here through which a check could be
                // suppressed.
                false,
            );
            out.push(SweepOutcome {
                agent_id: reg.agent_id.clone(),
                pass,
            });
        }
        out
    })
}

/// Log what a sweep did. Separated from [`sweep`] so the decision is testable without a subscriber
/// and the reporting is not something a test has to tolerate.
pub(crate) fn report(outcomes: &[SweepOutcome]) {
    for SweepOutcome { agent_id, pass } in outcomes {
        if !pass.due.should_check() {
            continue;
        }
        if let Some(trip) = &pass.trip {
            tracing::warn!(agent = %agent_id, reason = %trip.reason(), "a2a: the anomaly breaker suspended a registration");
        }
        if let Some(refusal) = &pass.refusal {
            tracing::warn!(agent = %agent_id, due = ?pass.due, error = %refusal, "a2a: re-verification could not authenticate the card; recorded as a failed contact");
            continue;
        }
        let Some(settled) = &pass.settled else {
            continue;
        };
        if settled.drift_observed {
            tracing::warn!(agent = %agent_id, due = ?pass.due, "a2a: the agent card DRIFTED from the approved pin; the registration is demoted");
        } else if settled.recovery_held {
            tracing::info!(agent = %agent_id, "a2a: a clean card was observed but is not yet believed; the recovery backoff since the last drift has not elapsed");
        }
    }
}

/// SPAWN THE RE-VERIFICATION JOB for the process lifetime.
///
/// Shaped like the write-behind flusher — a `select!` between the tick and the shutdown broadcast —
/// because that is the crate's settled spawned-job shape and a second shape is a second set of
/// shutdown bugs. It differs in the one place the two jobs genuinely differ: there is no final
/// sweep, for the reason in the module note.
///
/// Returns the `JoinHandle` even though production drops it, so a test can shut the job down and
/// JOIN it rather than guess a wall-clock duration.
pub(crate) fn spawn_reverifier(
    plane: Arc<A2aPlane>,
    identities: &crate::a2a::transport::ClientIdentities,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    // THE PER-AGENT TRANSPORTS, BUILT ONCE for the job's lifetime rather than per tick. The
    // identities were resolved at boot and the plane the job holds is this generation's, so
    // rebuilding the bundle every thirty seconds would re-derive a constant — and, now that a
    // transport can carry a private key, would do so with key material in hand on every tick.
    let live = Arc::new(LiveCardFetch::presenting(
        plane.fetch_policy().clone(),
        identities,
    ));
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(REVERIFY_TICK) => {
                    let plane = Arc::clone(&plane);
                    let live = Arc::clone(&live);
                    // OFF THE REACTOR. A card fetch is a blocking socket read behind a guard that
                    // resolves, pins and connects synchronously; running it on a worker thread
                    // would stall every request sharing that thread for as long as an upstream
                    // chose to take.
                    let swept = tokio::task::spawn_blocking(move || {
                        let outcomes = sweep(
                            &plane,
                            live.resolver(),
                            live.as_ref(),
                            now_ms(),
                        );
                        report(&outcomes);
                    })
                    .await;
                    if let Err(e) = swept {
                        // A panicked sweep is reported and the job CONTINUES. Exiting the loop
                        // would turn one bad card into a deployment that never re-verifies
                        // anything again, silently — the failure mode this job exists to prevent.
                        tracing::error!(error = %e, "a2a: a re-verification sweep panicked; the job continues");
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    })
}

/// The wall clock in MILLISECONDS, which is the unit the cadence is written in.
///
/// DELEGATES to [`crate::store::now_ms`] rather than reading the clock again. This function used to
/// own the arithmetic, and the MCP task plane grew an identical one with the opposite signedness —
/// two functions of one name over one clock, differing in a way no reviewer sees. Unifying the
/// concern is the fix; keeping the local name is what lets the two call sites keep reading in their
/// own plane's vocabulary.
///
/// A clock that went backwards is deliberately not smoothed — [`super::reverify::due`] has an arm
/// for exactly that and treats it as DUE, and hiding it would hide a corrected or tampered clock
/// reading as permanent freshness.
fn now_ms() -> u64 {
    crate::store::now_ms()
}

#[cfg(test)]
#[path = "tests/scheduler_tests.rs"]
mod scheduler_tests;
