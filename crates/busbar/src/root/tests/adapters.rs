use super::*;
use busbar_contract::{WireFault, WireStatusClass};
use busbar_kernel_egress::ports::Disposition;

fn route_token() -> Pass<Route> {
    busbar_kernel_testkit::test_support::tokens::pass()
}

#[test]
fn a_transient_fault_reading_is_recorded_against_the_destination_and_suppresses_the_lane() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(14);

    let classified = breaker.classify(
        dest,
        UpstreamStatus {
            class: Some(WireStatusClass::FarEndFault),
            fault: Some(WireFault::Transient),
            code: None,
            retry_after: None,
        },
    );

    assert_eq!(
        classified.disposition,
        Disposition::TransientUpstream,
        "the walk fails over rather than relaying the refusal"
    );
    assert_eq!(
        classified.outcome,
        Outcome::Transient { retry_after: None },
        "and the destination is held responsible"
    );
    assert!(
        breaker.observe("pool", dest, classified.outcome, 0, &route_token()),
        "the outcome was recorded"
    );
    assert!(
        !breaker.ready("pool", dest, 0, &route_token()),
        "one transient fault on this ladder takes the lane down"
    );
}

#[test]
fn the_breakers_classification_never_moves_with_the_number_beside_the_fault_reading() {
    use busbar_contract::transport::registry::status_ns::RESERVED;
    use busbar_contract::WireStatus;
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(21);
    let codes = [
        None,
        Some(WireStatus::new(RESERVED[0], 429)),
        Some(WireStatus::new(RESERVED[0], 503)),
        Some(WireStatus::new(RESERVED[0], 400)),
        Some(WireStatus::new(RESERVED[0], 401)),
        Some(WireStatus::new(RESERVED[0], 200)),
        Some(WireStatus::new(RESERVED[1], 14)),
    ];
    let readings = [
        (
            Some(WireStatusClass::FarEndFault),
            Some(WireFault::Transient),
        ),
        (Some(WireStatusClass::CallerFault), Some(WireFault::Caller)),
        (Some(WireStatusClass::CallerFault), Some(WireFault::Hard)),
        (Some(WireStatusClass::Success), Some(WireFault::Healthy)),
        (Some(WireStatusClass::FarEndFault), None),
        (None, None),
    ];
    for (class, fault) in readings {
        let at = |code| {
            breaker.classify(
                dest,
                UpstreamStatus {
                    class,
                    fault,
                    code,
                    retry_after: Some(3),
                },
            )
        };
        let baseline = at(None);
        for code in codes {
            let got = at(code);
            assert_eq!(
                (got.disposition, got.outcome, got.label),
                (baseline.disposition, baseline.outcome, baseline.label),
                "{class:?} / {fault:?} classified differently with code {code:?}"
            );
        }
    }
}

#[test]
fn the_adapter_reads_the_fault_reading_and_never_the_class() {
    let read = |class, fault| {
        reading(UpstreamStatus {
            class,
            fault,
            code: None,
            retry_after: None,
        })
    };
    assert_eq!(
        read(Some(WireStatusClass::CallerFault), Some(WireFault::Hard)),
        Reading::Answered(Some(WireFault::Hard))
    );
    assert_eq!(
        read(
            Some(WireStatusClass::CallerFault),
            Some(WireFault::Transient)
        ),
        Reading::Answered(Some(WireFault::Transient))
    );
    assert_eq!(
        read(Some(WireStatusClass::FarEndFault), None),
        Reading::Answered(None),
        "a framer with no fault table states no reading, and the breaker reads the caller's"
    );
    assert_eq!(
        read(None, None),
        Reading::NoAnswer,
        "neither a class nor a reading: no answer came"
    );
}

fn a_slow_ladder() -> BreakerCfg {
    BreakerCfg {
        base_cooldown_secs: 300,
        max_cooldown_secs: 600,
        trip: busbar_kernel_breaker::cfg::TripConfig {
            mode: busbar_kernel_breaker::cfg::TripMode::Consecutive,
            consecutive_n: 1,
            ..busbar_kernel_breaker::cfg::TripConfig::default()
        },
        ..BreakerCfg::default()
    }
}

fn adapter_for(pool: &str) -> BreakerAdapter {
    adapter(BreakerPolicy::new().with_pool(pool, a_slow_ladder()))
}

fn adapter(policy: BreakerPolicy) -> BreakerAdapter {
    BreakerAdapter::new(BreakerUnit::new(), policy)
}

#[test]
fn a_fresh_destination_is_ready_and_admits() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(3);
    assert!(breaker.ready("pool", dest, 0, &route_token()));
    assert!(breaker.admissible(dest));
    assert_eq!(
        breaker.try_admit("pool", dest, 0),
        Ok(Admit { probe_epoch: None })
    );
}

#[test]
fn the_configured_ladder_reaches_the_unit_and_not_the_default() {
    let dest = DestinationId::new(1);
    let failure = Outcome::Transient { retry_after: None };

    let configured = adapter_for("pool");
    assert!(
        configured.observe("pool", dest, failure, 0, &route_token()),
        "the configured ladder trips on the first failure"
    );
    let under_configured = configured.cooldown_remaining("pool", dest, 0, &route_token());

    let defaulted = adapter(BreakerPolicy::new().with_pool("pool", BreakerCfg::default()));
    assert!(
        !defaulted.observe("pool", dest, failure, 0, &route_token()),
        "the default ladder waits for an error rate and logs no trip on one failure"
    );
    let under_default = defaulted.cooldown_remaining("pool", dest, 0, &route_token());

    assert!(under_default > 0);
    assert!(
        under_configured > under_default * 4,
        "the cooldown came from the default ladder, not the configured one: \
         {under_configured} against {under_default}"
    );
}

#[test]
fn an_unconfigured_pool_records_nothing_rather_than_guessing() {
    let breaker = adapter(BreakerPolicy::new());
    let dest = DestinationId::new(2);

    assert!(!breaker.observe("unknown-pool", dest, Outcome::HardDown, 0, &route_token()));
    assert!(
        breaker.ready("unknown-pool", dest, 0, &route_token()),
        "nothing was recorded, so nothing tripped"
    );
}

#[test]
fn the_default_cells_ladder_does_not_stand_in_for_a_named_pool() {
    let breaker = adapter(BreakerPolicy::new().with_default_cell(a_slow_ladder()));
    let dest = DestinationId::new(5);

    assert!(
        !breaker.observe(
            "unconfigured-pool",
            dest,
            Outcome::HardDown,
            0,
            &route_token()
        ),
        "a named pool with no entry is unconfigured, whatever the default cell declared"
    );
    assert!(
        breaker.ready("unconfigured-pool", dest, 0, &route_token()),
        "nothing was recorded, so nothing tripped"
    );
}

#[test]
fn the_default_cell_takes_its_own_declared_ladder() {
    let breaker = adapter(BreakerPolicy::new().with_default_cell(a_slow_ladder()));
    let dest = DestinationId::new(4);
    assert!(breaker.observe("", dest, Outcome::HardDown, 0, &route_token()));
    assert!(breaker.cooldown_remaining("", dest, 0, &route_token()) > 0);
}

#[test]
fn a_callers_fault_reading_records_nothing() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(9);

    let out = breaker.classify(
        dest,
        UpstreamStatus {
            class: Some(WireStatusClass::CallerFault),
            fault: Some(WireFault::Caller),
            code: None,
            retry_after: None,
        },
    );
    assert_eq!(out.disposition, Disposition::ClientFault);
    assert_eq!(out.outcome, Outcome::RecordNothing);
    assert!(
        !breaker.observe("pool", dest, out.outcome, 0, &route_token()),
        "nothing recorded against the destination"
    );
    assert!(breaker.ready("pool", dest, 0, &route_token()));
}

#[test]
fn a_transient_reading_carries_the_stated_wait() {
    let breaker = adapter_for("pool");
    let out = breaker.classify(
        DestinationId::new(1),
        UpstreamStatus {
            class: Some(WireStatusClass::CallerFault),
            fault: Some(WireFault::Transient),
            code: None,
            retry_after: Some(5),
        },
    );
    assert_eq!(out.disposition, Disposition::TransientUpstream);
    assert_eq!(
        out.outcome,
        Outcome::Transient {
            retry_after: Some(5)
        }
    );
}

#[test]
fn a_hard_reading_is_hard_down() {
    let breaker = adapter_for("pool");
    let out = breaker.classify(
        DestinationId::new(2),
        UpstreamStatus {
            class: Some(WireStatusClass::CallerFault),
            fault: Some(WireFault::Hard),
            code: None,
            retry_after: Some(5),
        },
    );
    assert_eq!(out.disposition, Disposition::HardDown);
    assert_eq!(out.outcome, Outcome::HardDown);
}

#[test]
fn the_shared_labels_are_the_expected_wire_values() {
    use busbar_kernel_breaker::port::label;
    use busbar_kernel_egress::ports::disposition;

    assert_eq!(label::TRANSIENT_UPSTREAM, "transient_upstream");
    assert_eq!(label::HARD_DOWN, "hard_down");
    assert_eq!(label::CONTEXT_LENGTH, "context_length");
    assert_eq!(disposition::TRANSIENT, "transient_upstream");
    assert_eq!(disposition::HARD_DOWN, "hard_down");
    assert_eq!(disposition::CONTEXT_LENGTH, "context_length");

    assert_eq!(label::CLIENT_FAULT, "client_fault");
    assert_eq!(disposition::ATTEMPT_TIMEOUT, "attempt_timeout");
}

#[test]
fn a_probe_answer_reaches_every_cell_of_the_member() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(21);
    let t = route_token();
    assert!(breaker.observe("pool", dest, Outcome::HardDown, 0, &t));
    assert!(breaker.suppressing(dest, 0));

    breaker.probed(dest, Outcome::RecordNothing, 0, &t);
    assert!(
        breaker.suppressing(dest, 0),
        "a client fault records nothing"
    );

    breaker.probed(dest, Outcome::Success, 0, &t);
    assert!(!breaker.suppressing(dest, 0), "the probe recovered it");
    assert!(breaker.ready("pool", dest, 0, &t));
}
