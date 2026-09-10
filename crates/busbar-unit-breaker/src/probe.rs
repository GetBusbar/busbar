// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The active-probe schedule: which destinations are due to be asked whether they are alive.
//!
//! The breaker is fundamentally PASSIVE — it trips on real failures and recovers on the half-open
//! probe that organic traffic drives. Active probing layers a cadence on top, per the operator's
//! per-destination `health:` block:
//!
//! - `none` — no probing (the default; pure passive health).
//! - `dead` — ask ONLY suppressed destinations, so a recovered upstream is picked back up promptly
//!   instead of waiting for organic traffic to drive the half-open probe.
//! - `active` — ask EVERY destination, so a silently-dead upstream trips out before real traffic
//!   hits it.
//!
//! ## What moved here, and what did NOT
//!
//! 1.5.5 kept this inside the retiring engine that also forwarded the request — a unit may not name
//! which one, and the point of the move is that it no longer has to. It was one background task
//! per lane per config generation: a `tokio` interval, a `Weak` upgrade per tick, a generation
//! counter to make stale tasks exit, a spawn-time `fetch_min` and a tick-time `compare_exchange`
//! over a shared deadline table. A hundred and ninety-five of that file's lines existed to make a
//! set of per-generation tasks behave as though they were ONE schedule, and they did not quite: a
//! generation replaced before its first tick never probed, so under swap churn faster than the
//! interval — an onboarding wave provisioning a group per subject, a script applying settings in a
//! loop — probing went entirely DARK for the duration plus one interval while logging that it was
//! enabled.
//!
//! What moved is the ARITHMETIC, and only that: the monotone-earliest rule when a policy is
//! declared, the monotone-later rule when a probe is taken, and the first probe landing one
//! interval out rather than immediately. What did NOT move is every mechanism above that served
//! the per-generation task model, because there are no generations here. This unit is built once
//! by the composition root and outlives every config snapshot, so the deadlines do too: a config
//! apply re-declares its policies against a schedule that never went away, and a destination that
//! is still declared keeps the deadline it already had. The dark-probing defect is closed
//! structurally rather than carried across.
//!
//! ## No clock, no task, no dial
//!
//! Nothing here reads a clock or spawns anything; `now` is a parameter, as it is everywhere else in
//! this crate, and the caller that supplies it is the node's own Tick. Nothing here sends a probe
//! either — this unit says WHICH destinations are due and WHAT the operator allowed; the question
//! itself is the plane's (`Plane::probe_request`) and the sending is the egress unit's. Replaying
//! the same inputs gives the same answer.

use busbar_contract::DestinationId;

/// How much of the pool an operator wants asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProbeMode {
    /// Passive only. The default, and what an undeclared destination is.
    #[default]
    None,
    /// Ask only the destinations the breaker is currently suppressing.
    Dead,
    /// Ask every declared destination.
    Active,
}

/// One destination's declared probe policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbePolicy {
    /// How much of the pool to ask.
    pub mode: ProbeMode,
    /// How often, in whole seconds. Clamped to at least one second by [`ProbePolicy::cadence`],
    /// because a zero interval is a busy loop against somebody else's service.
    pub interval_secs: u64,
    /// How long a single probe may take, in whole seconds. Carried here rather than worked out by
    /// the caller so the operator's two numbers travel together and cannot be read from different
    /// generations of the config.
    pub timeout_secs: u64,
}

impl ProbePolicy {
    /// The interval this policy actually runs at.
    #[must_use]
    pub fn cadence(&self) -> u64 {
        self.interval_secs.max(1)
    }

    /// Whether this policy asks anything at all.
    #[must_use]
    pub fn probes(&self) -> bool {
        !matches!(self.mode, ProbeMode::None)
    }
}

/// One declared destination's policy and the moment it is next due.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Scheduled {
    pub(crate) policy: ProbePolicy,
    /// Unix seconds. The first one is one interval out, never `now`: a cold upstream is not asked
    /// before traffic has had a chance to establish its health, which is 1.5.5's discarded first
    /// tick expressed as a deadline instead of as a dropped event.
    pub(crate) due_at: u64,
}

impl Scheduled {
    /// Declare a policy against whatever was already scheduled for this destination.
    ///
    /// MONOTONE-EARLIEST, and it must be. Keeping whichever deadline is sooner is what makes a
    /// re-declaration — every config apply re-declares every destination — inherit the deadline the
    /// previous generation had established instead of pushing it a fresh interval into the future;
    /// under applies arriving faster than the interval, pushing would mean the deadline never
    /// arrives and probing is dark while the config says it is on. It also makes a SHORTENED
    /// `interval_secs` take effect within one new interval rather than after waiting out the old
    /// one. This is 1.5.5's spawn-time `fetch_min` over the shared deadline slot, and it is the
    /// same rule for the same reason.
    pub(crate) fn declare(previous: Option<Self>, policy: ProbePolicy, now: u64) -> Self {
        let first = now.saturating_add(policy.cadence());
        let due_at = match previous {
            Some(p) => p.due_at.min(first),
            None => first,
        };
        Self { policy, due_at }
    }

    /// Whether this destination is due at `now`.
    pub(crate) fn due(&self, now: u64) -> bool {
        self.policy.probes() && now >= self.due_at
    }

    /// Take this destination's turn: the next one is one interval after NOW, not one interval after
    /// the deadline that just passed.
    ///
    /// MONOTONE-LATER, the asymmetric half of the pair. Measuring from now is what stops a schedule
    /// that fell behind — a node paused, a tick that could not run — from firing a burst of
    /// back-to-back probes to catch up on deadlines that are all in the past. 1.5.5 got the same
    /// property from `MissedTickBehavior::Skip` on the ticker plus a tick-time `compare_exchange`;
    /// with one owner of the slot there is nothing to compare and exchange against.
    pub(crate) fn taken(self, now: u64) -> Self {
        Self {
            due_at: now.saturating_add(self.policy.cadence()),
            ..self
        }
    }
}

/// A destination the schedule says to ask now, with the operator's own bound on the asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DueProbe {
    /// Which destination.
    pub destination: DestinationId,
    /// How long the probe may take, in whole seconds.
    pub timeout_secs: u64,
}
