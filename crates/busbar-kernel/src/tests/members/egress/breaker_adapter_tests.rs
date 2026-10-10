// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Proves `busbar-unit-egress`'s `ports::Breaker` seam is implementable over
//! `busbar-unit-breaker`'s real API — not a fixture shaped to fit an imagined one.
//!
//! Test-only, on purpose: this crate's library code names no other unit crate (see
//! `ports.rs`'s module doc — every seam is a `// contract:` trait, bound by the integrator, not by
//! this crate). `BreakerAdapter` below is the integrator's binding, written once here to prove the
//! two units' real APIs actually meet, and it lives under `tests/` so it can never be reached from
//! `busbar_kernel_egress`'s own `src/`.
//!
//! The destination locator needs no narrowing: both units name `busbar_contract::DestinationId`.
//! The upstream status needs one small step: this crate's `UpstreamStatus` carries the transport's
//! class (the fee leg) and its fault reading (the breaker's leg); the breaker unit reads the fault
//! reading alone, or, when neither was stated, the fact that no answer came. No number crosses.

use busbar_contract::caps::{KernelSeal, Pass, Route};
use busbar_contract::transport::wire::{WireFault, WireStatusClass};
use busbar_kernel_breaker::cfg::BreakerCfg;
use busbar_kernel_breaker::classify::Reading;
use busbar_kernel_breaker::{Breaker as BreakerUnitTrait, BreakerUnit};
use busbar_kernel_egress::ports::{
    Admit, Breaker, Classified, DestinationId, Disposition, Outcome, Unavailable, UpstreamStatus,
};

/// A fresh `Pass<Route>` for one `observe`/`state` call — test-only, minted through the
/// kernel seal exactly as CG-29 says a real deployment would.
fn route_token() -> Pass<Route> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

/// The integrator's binding of the egress unit's `Breaker` port onto the breaker unit's
/// `BreakerUnit`. A thin wrapper with no policy of its own beyond the one status fold the module
/// doc above names; the destination goes across untouched.
struct BreakerAdapter(BreakerUnit, BreakerCfg);

impl BreakerAdapter {
    fn new() -> Self {
        Self::with_cfg(BreakerCfg::default())
    }

    /// The same adapter over a stated ladder. The default base cooldown (15s) is longer than any
    /// realistic `Retry-After` a test would state, so a test about the upstream's own floor needs
    /// a ladder short enough for the floor to be the thing that decides.
    fn with_cfg(cfg: BreakerCfg) -> Self {
        Self(BreakerUnit::new(), cfg)
    }

    /// The breaker unit's reading: the fault reading, or no answer when neither leg was stated.
    fn reading(status: UpstreamStatus) -> Reading {
        if status.class.is_none() && status.fault.is_none() {
            return Reading::NoAnswer;
        }
        Reading::Answered(status.fault)
    }
}

fn map_outcome_to_breaker(o: Outcome) -> busbar_kernel_breaker::Outcome {
    use busbar_kernel_breaker::Outcome as BO;
    match o {
        Outcome::Success => BO::Success,
        Outcome::Transient { retry_after } => BO::Transient { retry_after },
        Outcome::HardDown => BO::HardDown,
        Outcome::RecordNothing => BO::RecordNothing,
    }
}

fn map_outcome_from_breaker(o: busbar_kernel_breaker::Outcome) -> Outcome {
    use busbar_kernel_breaker::Outcome as BO;
    match o {
        BO::Success => Outcome::Success,
        BO::Transient { retry_after } => Outcome::Transient { retry_after },
        BO::HardDown => Outcome::HardDown,
        BO::RecordNothing => Outcome::RecordNothing,
    }
}

impl Breaker for BreakerAdapter {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        match self.0.try_admit(pool, destination, now) {
            Ok(admit) => Ok(Admit {
                probe_epoch: admit.probe_epoch,
            }),
            Err(state) => Err(match state {
                busbar_kernel_breaker::LaneState::Suppressed { until } => {
                    Unavailable::BreakerOpen { until }
                }
                busbar_kernel_breaker::LaneState::ProbeInFlight => Unavailable::ProbeInFlight,
                busbar_kernel_breaker::LaneState::BudgetExhausted => Unavailable::BudgetExhausted,
                // `try_admit` only errs on a non-`Ready` state; the breaker unit tracks no
                // administrative "Dead" fact of its own (that is the egress/config layer's, per
                // `ports.rs`'s own doc comment on `Unavailable::Dead`), so `Ready` never reaches
                // this arm in practice.
                busbar_kernel_breaker::LaneState::Ready => {
                    unreachable!("BreakerUnit::try_admit does not return Err(Ready)")
                }
            }),
        }
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        matches!(
            self.0.state(pool, destination, now, token),
            busbar_kernel_breaker::LaneState::Ready
        )
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        // The breaker unit's destination-scoped fact is the lifetime budget alone; whether a
        // destination is administratively "Dead" is declared configuration this unit does not
        // hold (see `Unavailable::Dead`'s own doc comment) — out of scope for this adapter.
        self.0.budget_remaining(destination) != Some(0)
    }

    fn cooldown_remaining(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> u64 {
        match self.0.state(pool, destination, now, token) {
            busbar_kernel_breaker::LaneState::Suppressed { until } => until.saturating_sub(now),
            _ => 0,
        }
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        let classified = busbar_kernel_breaker::port::classify_upstream(
            busbar_kernel_breaker::port::UpstreamStatus {
                reading: Self::reading(status),
                retry_after: status.retry_after,
            },
        );
        Classified {
            disposition: classified.disposition,
            outcome: map_outcome_from_breaker(classified.outcome),
            label: classified.label,
        }
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        // Both crates name the same `busbar-caps` `Pass<Route>`, so the token this call was
        // actually lent is what crosses the seam — no adapter-minted stand-in.
        self.0.observe(
            pool,
            destination,
            map_outcome_to_breaker(outcome),
            &self.1,
            now,
            token,
        )
    }

    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        self.0.suppressing(destination, now)
    }

    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, token: &Pass<Route>) {
        let cfg = self.1.clone();
        self.0.probed(
            destination,
            map_outcome_to_breaker(outcome),
            &move |_| Some(cfg.clone()),
            now,
            token,
        );
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, now: u64) {
        self.0.release_probe(pool, destination, epoch, now);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.0.spend_budget(destination)
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.0.refund_budget(destination);
    }
}

// ── proof: the seam is implementable, and behaves as both sides' docs promise ──────────────────

#[test]
fn a_fresh_destination_is_ready_and_admits() {
    let breaker = BreakerAdapter::new();
    assert!(breaker.ready("pool", DestinationId::new(3), 0, &route_token()));
    assert!(breaker.admissible(DestinationId::new(3)));
    assert_eq!(
        breaker.try_admit("pool", DestinationId::new(3), 0),
        Ok(Admit { probe_epoch: None })
    );
}

#[test]
fn classify_reads_the_callers_fault_reading_as_nothing_recorded() {
    // No number crosses the port: the transport read the answer as the caller's fault.
    let breaker = BreakerAdapter::new();
    let out = breaker.classify(
        DestinationId::new(9),
        UpstreamStatus {
            class: Some(WireStatusClass::CallerFault),
            fault: Some(WireFault::Caller),
            retry_after: None,
        },
    );
    assert_eq!(out.disposition, Disposition::ClientFault);
    assert_eq!(out.outcome, Outcome::RecordNothing);
}

#[test]
fn classify_never_reads_the_class_in_place_of_a_fault_reading() {
    // THE RED ARM'S RUNTIME HALF: a framer with no fault table states a class and no reading.
    // The class is the fee leg, never the breaker's: the answer is read as the caller's.
    let breaker = BreakerAdapter::new();
    let out = breaker.classify(
        DestinationId::new(1),
        UpstreamStatus {
            class: Some(WireStatusClass::FarEndFault),
            fault: None,
            retry_after: Some(5),
        },
    );
    assert_eq!(out.disposition, Disposition::ClientFault);
    assert_eq!(out.outcome, Outcome::RecordNothing);
    // And with neither leg stated, no answer came: a transient failure of the destination.
    let none = breaker.classify(DestinationId::new(1), UpstreamStatus::default());
    assert_eq!(none.disposition, Disposition::TransientUpstream);
}

#[test]
fn a_hard_down_trip_suppresses_a_later_admit_with_the_cooldown_the_port_expects() {
    let breaker = BreakerAdapter::new();
    // Touch the "pool" cell before the trip — `hard_down_all` fans out only to pools already
    // known for this destination (the default `""` cell is always included).
    assert!(breaker.ready("pool", DestinationId::new(4), 0, &route_token()));
    let tripped = breaker.observe(
        "pool",
        DestinationId::new(4),
        Outcome::HardDown,
        0,
        &route_token(),
    );
    assert!(tripped);

    assert!(!breaker.ready("pool", DestinationId::new(4), 10, &route_token()));
    let err = breaker
        .try_admit("pool", DestinationId::new(4), 10)
        .unwrap_err();
    assert_eq!(err, Unavailable::BreakerOpen { until: 1800 });
    assert_eq!(
        breaker.cooldown_remaining("pool", DestinationId::new(4), 10, &route_token()),
        1790
    );
}

/// A refused credential is a caller-fault CLASS (the fee leg), and the class alone would record
/// nothing at all. The transport's fault reading says the credential was refused, which is a fact
/// about the SHARED destination — so the disposition is hard-down and the trip fans out to every pool cell that
/// names the destination, not just the pool the failing attempt ran through.
#[test]
fn a_hard_reading_is_hard_down_and_takes_every_sibling_pool_cell_for_the_destination_with_it() {
    let breaker = BreakerAdapter::new();
    let destination = DestinationId::new(41);

    let out = breaker.classify(
        destination,
        UpstreamStatus {
            class: Some(WireStatusClass::CallerFault),
            fault: Some(WireFault::Hard),
            retry_after: None,
        },
    );
    assert_eq!(
        out.disposition,
        Disposition::HardDown,
        "the fault reading is what tells a withdrawn credential from a malformed request"
    );
    assert_eq!(out.outcome, Outcome::HardDown);

    // Two pools name the same destination. Touch both so both cells exist — `hard_down_all` fans
    // out to the pools already known for the destination.
    assert!(breaker.ready("primary", destination, 0, &route_token()));
    assert!(breaker.ready("secondary", destination, 0, &route_token()));

    assert!(breaker.observe("primary", destination, out.outcome, 0, &route_token()));

    assert!(
        breaker.cooldown_remaining("secondary", destination, 0, &route_token()) > 0,
        "the sibling lane goes down with it: a refused credential is not one pool's problem"
    );
    assert!(!breaker.ready("secondary", destination, 0, &route_token()));
}

/// The upstream asked for seven seconds, so it waits seven seconds — the ladder's own (much
/// shorter, here) cooldown is raised to the upstream's floor rather than the two being added or
/// the upstream's being ignored.
#[test]
fn a_transient_reading_with_a_stated_wait_of_seven_sets_a_seven_second_cooldown() {
    let breaker = BreakerAdapter::with_cfg(BreakerCfg {
        base_cooldown_secs: 1,
        ..BreakerCfg::default()
    });
    let destination = DestinationId::new(42);

    let out = breaker.classify(
        destination,
        UpstreamStatus {
            class: Some(WireStatusClass::CallerFault),
            fault: Some(WireFault::Transient),
            retry_after: Some(7),
        },
    );
    assert_eq!(out.disposition, Disposition::TransientUpstream);
    assert_eq!(
        out.outcome,
        Outcome::Transient {
            retry_after: Some(7)
        }
    );

    breaker.observe("primary", destination, out.outcome, 100, &route_token());
    assert_eq!(
        breaker.cooldown_remaining("primary", destination, 100, &route_token()),
        7,
        "the upstream's own wait is the floor the cooldown lands on"
    );
}

/// And an upstream that asked for nothing gets the ladder, untouched. The default is a decision,
/// not a fallback for a wait that went missing on the way here.
#[test]
fn a_transient_reading_with_no_stated_wait_keeps_the_ladders_own_cooldown() {
    let breaker = BreakerAdapter::with_cfg(BreakerCfg {
        base_cooldown_secs: 20,
        ..BreakerCfg::default()
    });
    let destination = DestinationId::new(43);

    let out = breaker.classify(
        destination,
        UpstreamStatus {
            class: Some(WireStatusClass::FarEndFault),
            fault: Some(WireFault::Transient),
            retry_after: None,
        },
    );
    assert_eq!(out.disposition, Disposition::TransientUpstream);
    assert_eq!(out.outcome, Outcome::Transient { retry_after: None });

    breaker.observe("primary", destination, out.outcome, 100, &route_token());
    // The failure streak is incremented before the cooldown is computed, so the first failure is
    // already one rung up the ladder (`base << 1` = 40), and every trip is jittered ±10% — so the
    // claim is the BAND that value sits in, not a point a reseeded jitter would break.
    let remaining = breaker.cooldown_remaining("primary", destination, 100, &route_token());
    assert!(
        (36..=44).contains(&remaining),
        "the ladder's own cooldown, jittered — nothing from the upstream moved it: {remaining}"
    );
}

#[test]
fn budget_spend_and_refund_cross_the_seam() {
    let breaker = BreakerAdapter::new();
    breaker.0.set_budget(DestinationId::new(2), 1);
    assert!(breaker.spend_budget(DestinationId::new(2)));
    assert!(!breaker.admissible(DestinationId::new(2)));
    breaker.refund_budget(DestinationId::new(2));
    assert!(breaker.admissible(DestinationId::new(2)));
}

#[test]
fn probe_release_crosses_the_seam() {
    let breaker = BreakerAdapter::new();
    // Trip and let the cooldown expire so the next admit wins a half-open recovery probe. Touch
    // "pool" first, same as above: `hard_down_all` only fans out to pools already known.
    breaker.ready("pool", DestinationId::new(5), 0, &route_token());
    breaker.observe(
        "pool",
        DestinationId::new(5),
        Outcome::HardDown,
        0,
        &route_token(),
    );
    let admit = breaker
        .try_admit("pool", DestinationId::new(5), 100_000)
        .expect("cooldown has long since expired");
    let epoch = admit
        .probe_epoch
        .expect("an expired cooldown re-admits via a probe");
    // Released without ever completing the dispatch: does not panic, does not wedge the cell.
    breaker.release_probe("pool", DestinationId::new(5), epoch, 100_000);
}
