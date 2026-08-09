// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ANOMALY BREAKER: the runtime correction for an approved agent that betrays the approval.
//!
//! ## Why this carries more weight than it looks like it should
//!
//! Every other control on this plane keys on the CARD. The pin catches a card that changed, the
//! signature catches a card somebody else wrote. None of them sees an agent whose card is
//! byte-identical and correctly signed and which simply starts behaving badly, and busbar is
//! deliberately content-blind on the dispatch path, so it cannot read its way to that conclusion
//! either. With no quality axis and no reward loop on this plane, this breaker is the ONLY remaining
//! mechanism for correcting an approved agent that under-delivers.
//!
//! ## It SUSPENDS. It does not deprioritise
//!
//! A tripped agent leaves the catalogue and is refused at dispatch, without waiting for a card
//! mismatch. The strict arm is the default on purpose: what this defends against is a poisoned
//! result carrying busbar's own provenance stamp, and a de-ranked agent still serves some traffic.
//! This is a security control, not a ranking, so it has no soft form.
//!
//! ## Every trip carries a reason an operator can act on in seconds
//!
//! The reason is part of the decision rather than a nicety. It names WHICH signal tripped, its
//! OBSERVED value, the CONFIGURED threshold, and the window the contributing observations fall in.
//! A breaker whose trips cannot be explained gets its thresholds raised until it never fires, and
//! then it protects nothing. That failure mode is the one this module is shaped around: an operator
//! looking at a suspended agent has to be able to tell a genuine degradation from a false positive
//! without going and reading the code.
//!
//! ## Where the two halves live
//!
//! [`Thresholds`] is operator INTENT and belongs in config. [`Window`] is what ACCUMULATES and
//! belongs in the store. The trip is a pure function of the two, which is the same shape as the
//! trust state itself: nothing is stored that could disagree with the observation it summarizes.

use std::fmt::Write as _;

/// Which runtime signal tripped. Card identity is deliberately absent: this breaker exists for the
/// case where the card is beyond reproach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum AnomalySignal {
    /// Transport and protocol errors as a fraction of dispatches.
    ErrorRate,
    /// A sudden surge of tasks reaching a `failed` or `rejected` terminal state. Distinct from
    /// `ErrorRate` because an agent that cleanly ACCEPTS work and then refuses all of it is not
    /// erroring, it is not doing the job it was approved for.
    TerminalFailureRate,
    /// Latency blowout, p95 over the window.
    LatencyP95Ms,
    /// Spend against the agent's egress budget, as a fraction. An approved agent that suddenly costs
    /// several times its usual is the shape of both a defect and an abuse.
    EgressBudget,
}

impl AnomalySignal {
    /// The operator-facing name, which is also what an audit row records.
    pub(crate) fn label(self) -> &'static str {
        match self {
            AnomalySignal::ErrorRate => "error_rate",
            AnomalySignal::TerminalFailureRate => "terminal_failure_rate",
            AnomalySignal::LatencyP95Ms => "latency_p95_ms",
            AnomalySignal::EgressBudget => "egress_budget_ratio",
        }
    }
}

/// The operator's configured trip points. Config, therefore intent.
///
/// Every threshold is OPTIONAL and `None` means NOT CONFIGURED, which can never trip. It does not
/// mean zero. A `None` read as zero would suspend every agent in the deployment the moment the
/// feature shipped, which is the largest availability event this design could cause and it would be
/// caused by a default rather than by an attack.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Thresholds {
    /// The floor below which NO signal can trip, however bad the ratios look.
    ///
    /// This is the single most important field. Without it the first dispatch of the day failing is
    /// a 100 percent error rate, and the agent is suspended on a sample of one. Ratios over tiny
    /// samples are noise, and a security control that fires on noise is an availability control
    /// pointed at the operator.
    pub(crate) min_observations: u32,
    pub(crate) error_rate: Option<f64>,
    pub(crate) terminal_failure_rate: Option<f64>,
    pub(crate) latency_p95_ms: Option<u64>,
    pub(crate) egress_budget_ratio: Option<f64>,
}

/// What was observed over the breaker's window. Store, therefore accumulation.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Window {
    /// Dispatches in the window. The denominator for every ratio, and the sample the floor judges.
    pub(crate) observations: u32,
    pub(crate) errors: u32,
    pub(crate) terminal_failures: u32,
    pub(crate) latency_p95_ms: u64,
    pub(crate) egress_spend_ratio: f64,
    /// The window the contributing observations actually span. Carried into the reason so an
    /// operator can line a suspension up against a deploy or an incident.
    pub(crate) first_observation_ms: u64,
    pub(crate) last_observation_ms: u64,
}

/// A trip, with everything an operator needs to judge it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Trip {
    pub(crate) signal: AnomalySignal,
    pub(crate) observed: String,
    pub(crate) threshold: String,
    pub(crate) observations: u32,
    pub(crate) first_observation_ms: u64,
    pub(crate) last_observation_ms: u64,
}

impl Trip {
    /// THE OPERATOR-VISIBLE REASON. One line, carrying the signal, the observed value, the
    /// configured threshold, the sample size and the window.
    ///
    /// The sample size is in there because "error_rate 1.00" reads like a catastrophe and means
    /// nothing without it, and the window is in there because the first question anyone asks about
    /// a suspension is what else happened at that time.
    pub(crate) fn reason(&self) -> String {
        let mut s = String::new();
        let _ = write!(
            s,
            "anomaly breaker: {} observed {} against threshold {} over {} observation(s), \
             first {}ms last {}ms",
            self.signal.label(),
            self.observed,
            self.threshold,
            self.observations,
            self.first_observation_ms,
            self.last_observation_ms
        );
        s
    }
}

/// EVALUATE the window against the thresholds.
///
/// Returns the trip an operator should see, or `None`. Reaching a threshold trips it: the operator
/// wrote the number they consider unacceptable, so treating it as the last acceptable value would
/// make every configured threshold quietly mean something other than what it says.
///
/// When several signals trip at once the reported one is fixed by [`AnomalySignal`]'s order, not by
/// which was checked first or which looked worst. A reason string that flapped between evaluations
/// would be one an operator cannot correlate with anything, and "worst" is not comparable across
/// signals measured in different units anyway.
pub(crate) fn evaluate(window: &Window, thresholds: &Thresholds) -> Option<Trip> {
    // THE FLOOR, checked before any ratio is formed. It is also what keeps the divisions below from
    // ever meeting a zero denominator: a window with no observations cannot clear a floor of at
    // least one, and a floor of zero with no observations is still refused here.
    if window.observations == 0 || window.observations < thresholds.min_observations {
        return None;
    }
    let n = f64::from(window.observations);
    let trip = |signal, observed: String, threshold: String| {
        Some(Trip {
            signal,
            observed,
            threshold,
            observations: window.observations,
            first_observation_ms: window.first_observation_ms,
            last_observation_ms: window.last_observation_ms,
        })
    };

    // Checked in the enum's own order, so the reported signal is stable across evaluations.
    if let Some(limit) = thresholds.error_rate {
        let rate = f64::from(window.errors) / n;
        if rate >= limit {
            return trip(
                AnomalySignal::ErrorRate,
                format!("{rate:.3}"),
                format!("{limit:.3}"),
            );
        }
    }
    if let Some(limit) = thresholds.terminal_failure_rate {
        let rate = f64::from(window.terminal_failures) / n;
        if rate >= limit {
            return trip(
                AnomalySignal::TerminalFailureRate,
                format!("{rate:.3}"),
                format!("{limit:.3}"),
            );
        }
    }
    if let Some(limit) = thresholds.latency_p95_ms {
        if window.latency_p95_ms >= limit {
            return trip(
                AnomalySignal::LatencyP95Ms,
                window.latency_p95_ms.to_string(),
                limit.to_string(),
            );
        }
    }
    if let Some(limit) = thresholds.egress_budget_ratio {
        if window.egress_spend_ratio >= limit {
            return trip(
                AnomalySignal::EgressBudget,
                format!("{:.3}", window.egress_spend_ratio),
                format!("{limit:.3}"),
            );
        }
    }
    None
}

#[cfg(test)]
#[path = "tests/anomaly_tests.rs"]
mod anomaly_tests;
