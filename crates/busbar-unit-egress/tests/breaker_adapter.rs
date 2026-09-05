// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Proves `busbar-unit-egress`'s `ports::Breaker` seam is implementable over
//! `busbar-unit-breaker`'s real API — not a fixture shaped to fit an imagined one.
//!
//! Test-only, on purpose: this crate's library code names no other unit crate (see
//! `ports.rs`'s module doc — every seam is a `// contract:` trait, bound by the integrator, not by
//! this crate). `BreakerAdapter` below is the integrator's binding, written once here to prove the
//! two units' real APIs actually meet, and it lives under `tests/` so it can never be reached from
//! `busbar_unit_egress`'s own `src/`.
//!
//! Two width/shape mismatches the adapter narrows, both flagged `// contract:` on the egress side
//! (`ports.rs`):
//! - `DestinationId`: `usize` in this crate, `u64` in the breaker unit. Narrowed with
//!   `u64::try_from`, which only fails on a `usize` wider than 64 bits — not a real platform this
//!   workspace targets, so the adapter panics rather than inventing a fallback that would hide a
//!   genuine locator overflow.
//! - The upstream status: this crate's `UpstreamStatus` carries the transport's own COARSE
//!   `busbar_contract::StatusClass` (`Success` / `ClientError` / `ServerError` / `Other`) as a
//!   fallback leg for when no numeric `code` is known; the breaker unit takes no dependency on
//!   `busbar-contract` at all (its `Cargo.toml` allows only `busbar-caps`), so its own
//!   `port::UpstreamStatus` carries a plain `Option<u16>`. The adapter folds the coarse class down
//!   to a representative HTTP-shaped code before calling in.

use busbar_contract::StatusClass;
use busbar_unit_breaker::cfg::BreakerCfg;
use busbar_unit_breaker::{Breaker as BreakerUnitTrait, BreakerUnit};
use busbar_unit_egress::ports::{
    Admit, Breaker, Classified, Disposition, DestinationId, Outcome, Unavailable, UpstreamStatus,
};

/// The integrator's binding of the egress unit's `Breaker` port onto the breaker unit's
/// `BreakerUnit`. A thin wrapper: every method is a narrow-call-widen, with no policy of its own
/// beyond the two mismatches the module doc above names.
struct BreakerAdapter(BreakerUnit);

impl BreakerAdapter {
    fn new() -> Self {
        Self(BreakerUnit::new())
    }

    /// Narrow this crate's `usize` locator to the breaker unit's `u64` one. Panics only if `usize`
    /// is wider than 64 bits on the build target, which this workspace does not run on.
    fn narrow(destination: DestinationId) -> u64 {
        u64::try_from(destination).expect("DestinationId must fit in the breaker unit's u64")
    }

    /// Fold the transport's coarse status-class reading down to a representative HTTP-shaped code,
    /// for when no numeric `code` was reported. `Success`/`Other` fold to `None` — there is no
    /// non-arbitrary HTTP number for either, and the breaker's own `code: None` fallback (record
    /// nothing, relay as-is) is the same answer 1.5.5 gave an unexpected 2xx/3xx reaching the error
    /// path.
    fn fold_class(class: Option<StatusClass>) -> Option<u16> {
        match class {
            Some(StatusClass::ClientError) => Some(400),
            Some(StatusClass::ServerError) => Some(500),
            Some(StatusClass::Success) | Some(StatusClass::Other) | None => None,
        }
    }
}

fn map_disposition(d: busbar_unit_breaker::classify::Disposition) -> Disposition {
    use busbar_unit_breaker::classify::Disposition as BD;
    match d {
        BD::ClientFault => Disposition::ClientFault,
        BD::TransientUpstream => Disposition::TransientUpstream,
        BD::HardDown => Disposition::HardDown,
        BD::ContextLength => Disposition::ContextLength,
    }
}

fn map_outcome_to_breaker(o: Outcome) -> busbar_unit_breaker::Outcome {
    use busbar_unit_breaker::Outcome as BO;
    match o {
        Outcome::Success => BO::Success,
        Outcome::Transient { retry_after } => BO::Transient { retry_after },
        Outcome::HardDown => BO::HardDown,
        Outcome::RecordNothing => BO::RecordNothing,
    }
}

fn map_outcome_from_breaker(o: busbar_unit_breaker::Outcome) -> Outcome {
    use busbar_unit_breaker::Outcome as BO;
    match o {
        BO::Success => Outcome::Success,
        BO::Transient { retry_after } => Outcome::Transient { retry_after },
        BO::HardDown => Outcome::HardDown,
        BO::RecordNothing => Outcome::RecordNothing,
    }
}

impl Breaker for BreakerAdapter {
    fn try_admit(&self, pool: &str, destination: DestinationId, now: u64) -> Result<Admit, Unavailable> {
        match self.0.try_admit(pool, Self::narrow(destination), now) {
            Ok(admit) => Ok(Admit { probe_epoch: admit.probe_epoch }),
            Err(state) => Err(match state {
                busbar_unit_breaker::LaneState::Suppressed { until } => Unavailable::BreakerOpen { until },
                busbar_unit_breaker::LaneState::ProbeInFlight => Unavailable::ProbeInFlight,
                busbar_unit_breaker::LaneState::BudgetExhausted => Unavailable::BudgetExhausted,
                // `try_admit` only errs on a non-`Ready` state; the breaker unit tracks no
                // administrative "Dead" fact of its own (that is the egress/config layer's, per
                // `ports.rs`'s own doc comment on `Unavailable::Dead`), so `Ready` never reaches
                // this arm in practice.
                busbar_unit_breaker::LaneState::Ready => unreachable!(
                    "BreakerUnit::try_admit does not return Err(Ready)"
                ),
            }),
        }
    }

    fn ready(&self, pool: &str, destination: DestinationId, now: u64) -> bool {
        matches!(
            self.0.state(pool, Self::narrow(destination), now),
            busbar_unit_breaker::LaneState::Ready
        )
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        // The breaker unit's destination-scoped fact is the lifetime budget alone; whether a
        // destination is administratively "Dead" is declared configuration this unit does not
        // hold (see `Unavailable::Dead`'s own doc comment) — out of scope for this adapter.
        self.0.budget_remaining(Self::narrow(destination)) != Some(0)
    }

    fn cooldown_remaining(&self, pool: &str, destination: DestinationId, now: u64) -> u64 {
        match self.0.state(pool, Self::narrow(destination), now) {
            busbar_unit_breaker::LaneState::Suppressed { until } => until.saturating_sub(now),
            _ => 0,
        }
    }

    fn classify(&self, destination: DestinationId, status: UpstreamStatus) -> Classified {
        let code = status.code.or_else(|| Self::fold_class(status.class));
        let classified = self.0.classify(
            Self::narrow(destination),
            busbar_unit_breaker::port::UpstreamStatus { code, retry_after: status.retry_after },
        );
        Classified {
            disposition: map_disposition(classified.disposition),
            outcome: map_outcome_from_breaker(classified.outcome),
            label: classified.label,
        }
    }

    fn observe(&self, pool: &str, destination: DestinationId, outcome: Outcome, now: u64) -> bool {
        self.0.observe(
            pool,
            Self::narrow(destination),
            map_outcome_to_breaker(outcome),
            &BreakerCfg::default(),
            now,
        )
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, now: u64) {
        self.0.release_probe(pool, Self::narrow(destination), epoch, now);
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        self.0.spend_budget(Self::narrow(destination))
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.0.refund_budget(Self::narrow(destination));
    }
}

// ── proof: the seam is implementable, and behaves as both sides' docs promise ──────────────────

#[test]
fn a_fresh_destination_is_ready_and_admits() {
    let breaker = BreakerAdapter::new();
    assert!(breaker.ready("pool", 3, 0));
    assert!(breaker.admissible(3));
    assert_eq!(breaker.try_admit("pool", 3, 0), Ok(Admit { probe_epoch: None }));
}

#[test]
fn classify_folds_the_declared_error_map_through_the_adapter() {
    let breaker = BreakerAdapter::new();
    breaker
        .0
        .set_error_map(9, [("1113".to_string(), "billing".to_string())].into_iter().collect());

    let out = breaker.classify(9, UpstreamStatus { class: None, code: Some(1113), retry_after: None });
    assert_eq!(out.disposition, Disposition::HardDown);
    assert_eq!(out.outcome, Outcome::HardDown);
}

#[test]
fn classify_falls_back_to_the_coarse_transport_class_when_no_code_is_known() {
    // This is the shape the walk actually builds today (`attempt.rs`'s `UpstreamStatus { code:
    // None, .. }`): only the transport's coarse reading is known.
    let breaker = BreakerAdapter::new();
    let out = breaker.classify(
        1,
        UpstreamStatus { class: Some(StatusClass::ServerError), code: None, retry_after: Some(5) },
    );
    assert_eq!(out.disposition, Disposition::TransientUpstream);
    assert_eq!(out.outcome, Outcome::Transient { retry_after: Some(5) });
}

#[test]
fn a_hard_down_trip_suppresses_a_later_admit_with_the_cooldown_the_port_expects() {
    let breaker = BreakerAdapter::new();
    // Touch the "pool" cell before the trip — `hard_down_all` fans out only to pools already
    // known for this destination (the default `""` cell is always included).
    assert!(breaker.ready("pool", 4, 0));
    let tripped = breaker.observe("pool", 4, Outcome::HardDown, 0);
    assert!(tripped);

    assert!(!breaker.ready("pool", 4, 10));
    let err = breaker.try_admit("pool", 4, 10).unwrap_err();
    assert_eq!(err, Unavailable::BreakerOpen { until: 1800 });
    assert_eq!(breaker.cooldown_remaining("pool", 4, 10), 1790);
}

#[test]
fn budget_spend_and_refund_cross_the_seam() {
    let breaker = BreakerAdapter::new();
    breaker.0.set_budget(2, 1);
    assert!(breaker.spend_budget(2));
    assert!(!breaker.admissible(2));
    breaker.refund_budget(2);
    assert!(breaker.admissible(2));
}

#[test]
fn probe_release_crosses_the_seam() {
    let breaker = BreakerAdapter::new();
    // Trip and let the cooldown expire so the next admit wins a half-open recovery probe. Touch
    // "pool" first, same as above: `hard_down_all` only fans out to pools already known.
    breaker.ready("pool", 5, 0);
    breaker.observe("pool", 5, Outcome::HardDown, 0);
    let admit = breaker.try_admit("pool", 5, 100_000).expect("cooldown has long since expired");
    let epoch = admit.probe_epoch.expect("an expired cooldown re-admits via a probe");
    // Released without ever completing the dispatch: does not panic, does not wedge the cell.
    breaker.release_probe("pool", 5, epoch, 100_000);
}
