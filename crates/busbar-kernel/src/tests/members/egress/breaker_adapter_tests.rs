// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::test_support::tokens::pass;
use busbar_contract::caps::{Pass, Route};
use busbar_contract::transport::wire::{WireFault, WireStatusClass};
use busbar_kernel_breaker::cfg::BreakerCfg;
use busbar_kernel_breaker::classify::Reading;
use busbar_kernel_breaker::{Breaker as BreakerUnitTrait, BreakerUnit};
use busbar_kernel_egress::ports::{
    Admit, Breaker, Classified, DestinationId, Disposition, Outcome, Unavailable, UpstreamStatus,
};

struct BreakerAdapter(BreakerUnit, BreakerCfg);

impl BreakerAdapter {
    fn new() -> Self {
        Self::with_cfg(BreakerCfg::default())
    }

    fn with_cfg(cfg: BreakerCfg) -> Self {
        Self(BreakerUnit::new(), cfg)
    }

    fn reading(status: UpstreamStatus) -> Reading {
        if status.class.is_none() && status.fault.is_none() {
            return Reading::NoAnswer;
        }
        Reading::Answered(status.fault)
    }
}

impl Breaker for BreakerAdapter {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
    ) -> Result<Admit, Unavailable> {
        self.0
            .try_admit(pool, destination, now)
            .map_err(|state| match state {
                busbar_kernel_breaker::LaneState::Suppressed { until } => {
                    Unavailable::BreakerOpen { until }
                }
                busbar_kernel_breaker::LaneState::ProbeInFlight => Unavailable::ProbeInFlight,
                busbar_kernel_breaker::LaneState::BudgetExhausted => Unavailable::BudgetExhausted,

                busbar_kernel_breaker::LaneState::Ready => {
                    unreachable!("BreakerUnit::try_admit does not return Err(Ready)")
                }
            })
    }

    fn unavailable(
        &self,
        pool: &str,
        destination: DestinationId,
        now: u64,
        token: &Pass<Route>,
    ) -> Option<Unavailable> {
        match busbar_kernel_breaker::Breaker::state(&self.0, pool, destination, now, token) {
            busbar_kernel_breaker::LaneState::Ready => None,
            busbar_kernel_breaker::LaneState::Suppressed { until } => {
                Some(Unavailable::BreakerOpen { until })
            }
            busbar_kernel_breaker::LaneState::BudgetExhausted => Some(Unavailable::BudgetExhausted),
            busbar_kernel_breaker::LaneState::ProbeInFlight => Some(Unavailable::ProbeInFlight),
        }
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64, token: &Pass<Route>) -> bool {
        matches!(
            self.0.state(pool, destination, now, token),
            busbar_kernel_breaker::LaneState::Ready
        )
    }

    fn admissible(&self, destination: DestinationId) -> bool {
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
        busbar_kernel_breaker::port::classify_upstream(
            busbar_kernel_breaker::port::UpstreamStatus {
                reading: Self::reading(status),
                retry_after: status.retry_after,
            },
        )
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        now: u64,
        token: &Pass<Route>,
    ) -> bool {
        self.0
            .observe(pool, destination, outcome, &self.1, now, token)
    }

    fn suppressing(&self, destination: DestinationId, now: u64) -> bool {
        self.0.suppressing(destination, now)
    }

    fn probed(&self, destination: DestinationId, outcome: Outcome, now: u64, token: &Pass<Route>) {
        let cfg = self.1.clone();
        self.0.probed(
            destination,
            outcome,
            &move |_| Some(cfg.clone()),
            now,
            token,
        );
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, _now: u64) {
        self.0.release_probe(pool, destination, epoch);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.0.spend_budget(destination)
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.0.refund_budget(destination);
    }
}

#[test]
fn a_fresh_destination_is_ready_and_admits() {
    let breaker = BreakerAdapter::new();
    assert!(breaker.ready("pool", DestinationId::new(3), 0, &pass::<Route>()));
    assert!(breaker.admissible(DestinationId::new(3)));
    assert_eq!(
        breaker.try_admit("pool", DestinationId::new(3), 0),
        Ok(Admit { probe_epoch: None })
    );
}

#[test]
fn classify_reads_the_callers_fault_reading_as_nothing_recorded() {
    let breaker = BreakerAdapter::new();
    let out = breaker.classify(
        DestinationId::new(9),
        UpstreamStatus {
            class: Some(WireStatusClass::CallerFault),
            fault: Some(WireFault::Caller),
            code: None,
            retry_after: None,
        },
    );
    assert_eq!(out.disposition, Disposition::ClientFault);
    assert_eq!(out.outcome, Outcome::RecordNothing);
}

#[test]
fn classify_never_reads_the_class_in_place_of_a_fault_reading() {
    let breaker = BreakerAdapter::new();
    let out = breaker.classify(
        DestinationId::new(1),
        UpstreamStatus {
            class: Some(WireStatusClass::FarEndFault),
            fault: None,
            code: None,
            retry_after: Some(5),
        },
    );
    assert_eq!(out.disposition, Disposition::ClientFault);
    assert_eq!(out.outcome, Outcome::RecordNothing);

    let none = breaker.classify(DestinationId::new(1), UpstreamStatus::default());
    assert_eq!(none.disposition, Disposition::TransientUpstream);
}

#[test]
fn a_hard_down_trip_suppresses_a_later_admit_with_the_cooldown_the_port_expects() {
    let breaker = BreakerAdapter::new();

    assert!(breaker.ready("pool", DestinationId::new(4), 0, &pass::<Route>()));
    let tripped = breaker.observe(
        "pool",
        DestinationId::new(4),
        Outcome::HardDown,
        0,
        &pass::<Route>(),
    );
    assert!(tripped);

    assert!(!breaker.ready("pool", DestinationId::new(4), 10, &pass::<Route>()));
    let err = breaker
        .try_admit("pool", DestinationId::new(4), 10)
        .unwrap_err();
    assert_eq!(err, Unavailable::BreakerOpen { until: 1800 });
    assert_eq!(
        breaker.cooldown_remaining("pool", DestinationId::new(4), 10, &pass::<Route>()),
        1790
    );
}

#[test]
fn a_hard_reading_is_hard_down_and_takes_every_sibling_pool_cell_for_the_destination_with_it() {
    let breaker = BreakerAdapter::new();
    let destination = DestinationId::new(41);

    let out = breaker.classify(
        destination,
        UpstreamStatus {
            class: Some(WireStatusClass::CallerFault),
            fault: Some(WireFault::Hard),
            code: None,
            retry_after: None,
        },
    );
    assert_eq!(
        out.disposition,
        Disposition::HardDown,
        "the fault reading is what tells a withdrawn credential from a malformed request"
    );
    assert_eq!(out.outcome, Outcome::HardDown);

    assert!(breaker.ready("primary", destination, 0, &pass::<Route>()));
    assert!(breaker.ready("secondary", destination, 0, &pass::<Route>()));

    assert!(breaker.observe("primary", destination, out.outcome, 0, &pass::<Route>()));

    assert!(
        breaker.cooldown_remaining("secondary", destination, 0, &pass::<Route>()) > 0,
        "the sibling lane goes down with it: a refused credential is not one pool's problem"
    );
    assert!(!breaker.ready("secondary", destination, 0, &pass::<Route>()));
}

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
            code: None,
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

    breaker.observe("primary", destination, out.outcome, 100, &pass::<Route>());
    assert_eq!(
        breaker.cooldown_remaining("primary", destination, 100, &pass::<Route>()),
        7,
        "the upstream's own wait is the floor the cooldown lands on"
    );
}

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
            code: None,
            retry_after: None,
        },
    );
    assert_eq!(out.disposition, Disposition::TransientUpstream);
    assert_eq!(out.outcome, Outcome::Transient { retry_after: None });

    breaker.observe("primary", destination, out.outcome, 100, &pass::<Route>());

    let remaining = breaker.cooldown_remaining("primary", destination, 100, &pass::<Route>());
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

    breaker.ready("pool", DestinationId::new(5), 0, &pass::<Route>());
    breaker.observe(
        "pool",
        DestinationId::new(5),
        Outcome::HardDown,
        0,
        &pass::<Route>(),
    );
    let admit = breaker
        .try_admit("pool", DestinationId::new(5), 100_000)
        .expect("cooldown has long since expired");
    let epoch = admit
        .probe_epoch
        .expect("an expired cooldown re-admits via a probe");
    assert_eq!(
        breaker.try_admit("pool", DestinationId::new(5), 100_000),
        Err(Unavailable::ProbeInFlight)
    );

    breaker.release_probe("pool", DestinationId::new(5), epoch, 100_000);
    let next = breaker
        .try_admit("pool", DestinationId::new(5), 100_000)
        .expect("release returns the cell to probe-winnable Open");
    let next_epoch = next
        .probe_epoch
        .expect("release preserves the recovery probe requirement");
    assert_ne!(next_epoch, epoch, "the next caller owns a fresh probe");
    assert_eq!(
        breaker.try_admit("pool", DestinationId::new(5), 100_000),
        Err(Unavailable::ProbeInFlight)
    );
    breaker.release_probe("pool", DestinationId::new(5), next_epoch, 100_000);
}
