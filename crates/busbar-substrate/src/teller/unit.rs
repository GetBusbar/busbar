// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-unit neutral facts the loop threads through every step, and the two small runtime
//! vocabularies every step shares: which step a thing happened at ([`StepName`]) and how a unit
//! ended ([`UnitEnd`]).

use std::sync::atomic::{AtomicU64, Ordering};

/// The nine steps as plain runtime names, in loop order. Ordered so "did this happen after Admit"
/// is a comparison rather than a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StepName {
    /// Step 1.
    Arrival,
    /// Step 2.
    Decode,
    /// Step 3.
    Authenticate,
    /// Step 4.
    Verify,
    /// Step 5.
    Approve,
    /// Step 6 — the door; a pass opens the hold.
    Admit,
    /// Step 7 — runs under the hold.
    Route,
    /// Step 8 — runs under the hold.
    Meter,
    /// Step 9 — closes the hold and posts the unit.
    Audit,
}

impl StepName {
    /// Every step, in the order the loop runs them.
    pub const ALL: [StepName; 9] = [
        StepName::Arrival,
        StepName::Decode,
        StepName::Authenticate,
        StepName::Verify,
        StepName::Approve,
        StepName::Admit,
        StepName::Route,
        StepName::Meter,
        StepName::Audit,
    ];

    /// Whether this step runs under an open hold — i.e. strictly after Admit. A refusal here is
    /// audited WITH the hold (the admission stands: the caller was charged); a refusal at or before
    /// Admit is audited without one (nothing was charged).
    pub fn after_admit(self) -> bool {
        self > StepName::Admit
    }

    /// The step's name as it appears in audit rows and refusals.
    pub fn as_str(self) -> &'static str {
        match self {
            StepName::Arrival => "arrival",
            StepName::Decode => "decode",
            StepName::Authenticate => "authenticate",
            StepName::Verify => "verify",
            StepName::Approve => "approve",
            StepName::Admit => "admit",
            StepName::Route => "route",
            StepName::Meter => "meter",
            StepName::Audit => "audit",
        }
    }
}

impl std::fmt::Display for StepName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a unit ended, as Audit posts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnitEnd {
    /// Every step proceeded; the routed response went out.
    Completed,
    /// A step refused; the plane's refusal went out. Names the step that refused.
    Refused(StepName),
}

/// The neutral per-unit facts ONE loop traversal reads and threads — the resolved caller context,
/// the destination Verify judges, and the correlation/timing the plane's audit row joins on.
/// Everything protocol- or dialect-specific (the parsed body, the handler, the engine) lives on
/// the plane's own value, never here, so this names no plane type. Successor of the older
/// `GauntletRequest`, which the gauntlet adapter now builds from it.
pub struct Unit<'a> {
    /// The resolved caller identity/scope, threaded from the auth layer that ran upstream.
    pub gov: &'a busbar_api::PlaneRequestCtx,
    /// The destination Verify judges. Opaque to the loop; each plane spells its meaning.
    pub destination: &'a str,
    /// The monotonic start instant for the request-duration metric.
    pub started: std::time::Instant,
    /// The header-arrival epoch (whole seconds) the unit was admitted at — the metering window base.
    pub charged_at: u64,
    /// The per-unit correlation id the plane's audit row joins on. Atomic rather than a `Cell` so a
    /// `&Unit` can be held across an `.await` in a `Send` future; set once, by whoever mints the id.
    correlation: AtomicU64,
}

impl<'a> Unit<'a> {
    /// Start a unit with no correlation id yet (zero until [`Unit::set_correlation`]).
    pub fn new(
        gov: &'a busbar_api::PlaneRequestCtx,
        destination: &'a str,
        charged_at: u64,
        started: std::time::Instant,
    ) -> Self {
        Unit {
            gov,
            destination,
            started,
            charged_at,
            correlation: AtomicU64::new(0),
        }
    }

    /// Builder form of [`Unit::set_correlation`].
    pub fn with_correlation(self, correlation: u64) -> Self {
        self.set_correlation(correlation);
        self
    }

    /// The correlation id (zero until one is set).
    pub fn correlation(&self) -> u64 {
        self.correlation.load(Ordering::Relaxed)
    }

    /// Record the correlation id the plane minted for this unit.
    pub fn set_correlation(&self, correlation: u64) {
        self.correlation.store(correlation, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for Unit<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unit")
            .field("destination", &self.destination)
            .field("charged_at", &self.charged_at)
            .field("correlation", &self.correlation())
            .finish_non_exhaustive()
    }
}
