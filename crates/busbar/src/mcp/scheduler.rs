// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JOB THAT DRIVES THE MCP REFRESH. [`super::connect::refresh`] was the pass; this is what calls
//! it on a timer, which is the difference between a control that exists and a control that runs.
//!
//! ## WHY THIS FILE EXISTS AT ALL
//!
//! Schema hash-pinning with automatic drift quarantine is the one thing on this engine that the
//! competitive survey found nobody else shipping. It was also, until this file, a defence that
//! depended on somebody pressing a button: quarantine-on-drift is automatic GIVEN a refresh, and
//! `refresh`'s only caller was the admin verb `POST /admin/tools/{name}/connect`. An upstream that
//! rug-pulls a schema at 02:00 on a Saturday against a deployment whose operator is asleep was
//! detected exactly never. A defence that requires an operator to be present is a defence with an
//! availability window, and the attacker picks the moment.
//!
//! ## MODELLED ON THE SIBLING PLANE ON PURPOSE, NOT COPIED
//!
//! [`crate::a2a::scheduler`] solved this same problem for card re-verification first. The house rule
//! is to unify the duplicate before it can drift, and three of this release's security defects came
//! from one concern implemented twice — so the DECISION half is genuinely shared:
//! [`crate::trust::reverify`] (`Policy`, `Ledger`, `Due`, `due`) was promoted out of `a2a/` to
//! `trust/` when this file became its second consumer, which is the move that module's own header
//! specified in advance. Both planes now ask the SAME `due` whether it is time to look.
//!
//! What is NOT shared is the fetch, and it should not be: an A2A card is one signed document read
//! over a blocking socket, while an MCP refresh is an async JSON-RPC round trip through a connection
//! pool that may first perform an RFC 8693 token exchange. Forcing one function over both would be a
//! shared shape hiding two behaviours.
//!
//! ## NO KNOB, for the same reason the sibling has none
//!
//! - **The tick is a constant** ([`REFRESH_TICK`]), not config. A configurable sweep interval is a
//!   configurable detection delay wearing a scheduling costume. The cadence an operator controls is
//!   the per-registration `refresh_ttl:`, which [`crate::trust::reverify::due`] owns; the tick only
//!   decides how finely the job notices that a TTL elapsed, and coarsening it can only make
//!   detection later.
//! - **No server is ever skipped.** The sweep asks `due` about every registration on every tick and
//!   lets it answer. There is no rate limit on being CHECKED, no backoff on being checked, and no
//!   "this one failed last time so leave it a while" — a failing upstream is the one that most needs
//!   looking at.
//! - **`operator_sync` is always `false` here.** The timer is not an operator. The admin verb
//!   outranks the timer, and nothing on this path can suppress a check the timer's own arithmetic
//!   says is due.
//!
//! ## THE ONE STATED DIFFERENCE FROM A2A
//!
//! A2A's sweep runs the observation through [`crate::trust::reverify::settle`], which holds a CLEAN
//! answer for a recovery backoff after a drift. MCP's does not, because
//! [`super::client::catalogue::ServerCatalogue::observe`] has no arm that can decline to adopt what
//! it saw. `refresh_policy_for` therefore sets `recovery_backoff_ms: 0` rather than carrying a number
//! nothing reads. The half that matters for A2.1 is untouched and is identical on both planes:
//! **DEMOTION IS NEVER HELD.** The first drift quarantines immediately, on the timer, with no
//! operator present. See [`super::config::refresh_policy_for`].

use std::sync::Arc;
use std::time::Duration;

use crate::trust::reverify::{due, Due};

/// HOW OFTEN THE SWEEP LOOKS FOR WORK. A constant, and see the module note on why it is not config.
///
/// It bounds only the GRANULARITY of detection, never its policy: a registration whose TTL elapsed
/// mid-tick is refreshed on the next one. Deliberately the same value as
/// [`crate::a2a::scheduler::REVERIFY_TICK`] — two planes running the same defence on two different
/// heartbeats would be a difference with no reason behind it.
pub(crate) const REFRESH_TICK: Duration = Duration::from_secs(30);

/// WHAT ONE SWEEP DID TO ONE REGISTRATION, so the outcome can be logged and surfaced rather than
/// re-derived by a reader who would have to guess.
#[derive(Debug)]
pub(crate) struct SweepOutcome {
    pub(crate) server: String,
    /// Why this server was checked, or why it was not.
    pub(crate) due: Due,
    /// What the refresh found. `None` when the server was fresh and nothing was attempted, or when
    /// the refresh could not be attempted at all (an unroutable id, or a `passthrough` credential
    /// posture that has no caller to borrow from on a timer).
    pub(crate) report: Option<super::connect::ConnectReport>,
    /// Why the refresh could not be attempted. Distinct from a refresh that WAS attempted and
    /// failed: one is the operator's own configuration, the other is a network.
    pub(crate) refusal: Option<String>,
}

/// ONE SWEEP over every registered MCP server.
///
/// Takes the clock as an argument and holds no timer of its own, which is what makes the behaviour
/// testable: a test drives the same function the job drives, at times it chooses, with no sleeping
/// and nothing for a scheduler to race.
pub(crate) async fn sweep(app: &crate::state::App, now_ms: u64) -> Vec<SweepOutcome> {
    // The registrations are read from the CATALOGUE — the operator's live intent — and not from the
    // sightings cache. A server the operator registered and nothing has ever observed has no cache
    // entry at all, and iterating the evidence would mean the one registration most in need of a
    // first look is the one the timer never reaches.
    let servers: Vec<_> = app.mcp_catalogue.servers().cloned().collect();
    let mut out = Vec::with_capacity(servers.len());

    for entry in &servers {
        let ledger = ledger_of(&app.mcp_sightings, &entry.id);
        // THE TIMER IS NOT AN OPERATOR. `operator_sync` is `false` and there is no argument on this
        // path through which a due check could be suppressed. The admin verb passes the equivalent
        // of `true` by calling `refresh` outright, and it OUTRANKS this.
        let why = due(&ledger, &entry.refresh_policy, now_ms, false);
        if !why.should_check() {
            out.push(SweepOutcome {
                server: entry.id.clone(),
                due: why,
                report: None,
                refusal: None,
            });
            continue;
        }

        let (report, refusal) =
            match super::connect::refresh(&app.mcp_pool, &app.mcp_sightings, entry).await {
                Ok(report) => (Some(report), None),
                // A refusal means the refresh was never ATTEMPTED — an unroutable id, or a
                // `passthrough` credential posture whose credential belongs to a caller the timer
                // does not have. It is deliberately NOT recorded as a failed contact: nothing was
                // contacted, and writing a failure would demote a server over the operator's own
                // configuration rather than over anything the upstream did.
                Err(refusal) => (None, Some(refusal.to_string())),
            };

        // THE LEDGER IS STAMPED WHETHER OR NOT THE ANSWER WAS GOOD, and drift is counted before any
        // decision about what to believe. Detection and demotion are different acts. A refusal
        // stamps nothing: the clock records when we LOOKED, and we did not look.
        if let Some(r) = &report {
            stamp(&app.mcp_sightings, &entry.id, now_ms, !r.drift.is_empty());
        }

        out.push(SweepOutcome {
            server: entry.id.clone(),
            due: why,
            report,
            refusal,
        });
    }
    out
}

/// This server's refresh ledger, or a fresh one for a registration nothing has ever observed.
///
/// A missing cache entry yields [`crate::trust::reverify::Ledger::default`], whose `last_checked_ms`
/// is `None` — which `due` reads as [`Due::NeverChecked`], i.e. DUE NOW. That is the fail-closed
/// direction: the alternative would treat "we have no record of ever looking" as freshness.
fn ledger_of(
    cache: &super::client::catalogue::CatalogueCache,
    id: &str,
) -> crate::trust::reverify::Ledger {
    super::client::identity::ServerId::new(id)
        .ok()
        .and_then(|sid| cache.load().server(&sid).map(|sc| sc.ledger.clone()))
        .unwrap_or_default()
}

/// Record that we LOOKED, and whether what we saw had drifted.
///
/// Deliberately mirrors the ledger half of [`crate::trust::reverify::settle`] and stops there: the
/// half `settle` adds on top is the recovery hold, which this plane's `observe` cannot express. See
/// the module header's stated difference.
fn stamp(cache: &super::client::catalogue::CatalogueCache, id: &str, now_ms: u64, drifted: bool) {
    let Ok(sid) = super::client::identity::ServerId::new(id) else {
        return;
    };
    cache.apply(|servers| {
        if let Some(sc) = servers.get_mut(sid.as_str()) {
            sc.ledger.last_checked_ms = Some(now_ms);
            if drifted {
                sc.ledger.drift_observations += 1;
                sc.ledger.last_drift_ms = Some(now_ms);
            }
        }
    });
}

/// Log what a sweep did. Separated from [`sweep`] so the decision is testable without a subscriber
/// and the reporting is not something a test has to tolerate.
pub(crate) fn report(outcomes: &[SweepOutcome]) {
    for SweepOutcome {
        server,
        due,
        report,
        refusal,
    } in outcomes
    {
        if !due.should_check() {
            continue;
        }
        if let Some(why) = refusal {
            tracing::warn!(server = %server, error = %why, "mcp: a scheduled refresh could not be attempted; the registration was NOT contacted and its trust state is unchanged");
            continue;
        }
        let Some(r) = report else { continue };
        if let Some(failure) = &r.failure {
            tracing::warn!(server = %server, due = ?due, error = %failure, "mcp: a scheduled refresh could not reach the upstream; recorded as a failed contact");
            continue;
        }
        if !r.drift.is_empty() {
            // THE LINE THIS WHOLE FILE EXISTS TO EMIT. Nobody asked for it, and it is the operator's
            // first notice that an upstream changed a tool underneath an approval.
            tracing::warn!(
                server = %server,
                due = ?due,
                state = r.state_word(),
                changed = ?r.drift.changed,
                added = ?r.drift.added,
                removed = ?r.drift.removed,
                "mcp: the upstream's tools DRIFTED from the approved pin; the server is quarantined and its tools stop dispatching until an operator re-approves"
            );
        }
    }
}

/// SPAWN THE REFRESH JOB for the process lifetime.
///
/// Shaped like [`crate::a2a::scheduler::spawn_reverifier`] and the write-behind flusher — a
/// `select!` between the tick and the shutdown broadcast — because that is the crate's settled
/// spawned-job shape and a second shape is a second set of shutdown bugs.
///
/// It takes the [`crate::state::AppHandle`] rather than a snapshot of the app, and that is the one
/// place this job differs from its sibling in a way that matters: the MCP catalogue is REBUILT on
/// every config apply, so a job holding an `Arc<App>` taken at boot would go on sweeping the
/// registrations of a config the operator has already replaced — refreshing servers they deleted and
/// never looking at the ones they added. Loading the handle on each tick means the sweep always sees
/// the live generation.
///
/// **There is no final sweep at shutdown**, for the same reason the sibling has none: no observation
/// is buffered here, the ledger is the durable record of what was seen, and a registration that was
/// not swept before the process stopped is `NeverChecked` or `TtlExpired` at the next boot — which
/// is to say, due immediately. Doing tool-list fetches against every registered upstream while the
/// process is trying to exit would trade a guarantee we already have for a slower shutdown.
///
/// Returns the `JoinHandle` even though production drops it, so a test can shut the job down and
/// JOIN it rather than guess a wall-clock duration.
pub(crate) fn spawn_refresher(
    handle: Arc<crate::state::AppHandle>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(REFRESH_TICK) => {
                    let app = handle.load();
                    // The sweep is `async` and every leg of it is non-blocking I/O through the
                    // shared pool, so unlike the A2A card fetch there is nothing here to move onto a
                    // blocking thread. It is wrapped so a panic in one upstream's refresh cannot
                    // take the job down: exiting the loop would turn one bad tool list into a
                    // deployment that never refreshes anything again, silently — which is the exact
                    // failure this job exists to prevent.
                    let swept = std::panic::AssertUnwindSafe(sweep(&app, now_ms()));
                    match futures::FutureExt::catch_unwind(swept).await {
                        Ok(outcomes) => report(&outcomes),
                        Err(_) => tracing::error!(
                            "mcp: a scheduled refresh sweep panicked; the job continues"
                        ),
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    })
}

/// The wall clock in MILLISECONDS, which is the unit the cadence is written in.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// THE PROOF THAT THE DEFENCE RUNS WITH NOBODY WATCHING: a schema changed under a live cache, the
// TIMER'S OWN SWEEP (never the admin verb), and the dispatch that is refused because of it.
#[cfg(test)]
#[path = "tests/timer_dispatch_tests.rs"]
mod timer_dispatch_tests;
