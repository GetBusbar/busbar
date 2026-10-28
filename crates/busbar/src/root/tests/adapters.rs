//! Tests for `adapters.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_contract::{WireFault, WireStatusClass};
use busbar_kernel_egress::ports::Disposition;

/// A fresh `Pass<Route>` for one `observe`/`ready`/`cooldown_remaining` call — test-only,
/// minted through the kernel seal exactly as CG-29 says a real deployment would
/// (`KernelSeal::acquire_for_kernel` is `// contract:` kernel-only outside test modules; the
/// production adapter above never mints one of its own — it forwards the borrow its caller
/// lent it).
fn route_token() -> Pass<Route> {
    busbar_kernel::test_support::tokens::pass()
}

/// A transport's transient fault reading (its own fault table read the far end's answer as the
/// destination's transient failure), classified, recorded, and the lane suppressed as a result.
/// The number behind it never reaches this port: which numbering spelled it is the transport's.
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

/// ROW 66 HOLDS WITH THE NUMBER ON THE PORT (ARCHITECT ruling on #787, 2026-10-13): the port
/// carries the upstream's numbered status beside the fault reading, for the composition root's
/// model egress alone (the previous release's 429 ladder and 4xx count). The breaker classifies
/// from the fault reading and never reads the number: whatever `code` says, in either reserved
/// numbering or none, a fixed class and fault reading classify the same.
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

/// The breaker reads the FAULT reading and never the class: the class is the fee decision's leg,
/// and the two disagree where the money and the destination's health do. A caller-fault class with
/// a hard reading is a refused credential (the destination is down for everyone); a far-end class
/// with no reading at all is an answer nobody read for the breaker, and is the caller's.
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

/// A ladder that is visibly not the default on both axes a cooldown is decided by: it trips on
/// the first failure rather than on an error rate, and it holds the lane down for five minutes
/// rather than fifteen seconds.
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

/// An adapter over a fresh unit, under `policy`.
fn adapter(policy: BreakerPolicy) -> BreakerAdapter {
    BreakerAdapter::new(BreakerUnit::new(), policy)
}

/// The seam is implementable over the two real APIs, and a fresh destination behaves as both
/// sides' documentation promises.
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

/// **The hazard the adapter exists around**, shown as a difference rather than described. One
/// transient failure, two adapters, two ladders: the configured pool trips on the first failure
/// and stays down for minutes; the same failure under the crate's default trips nothing at all,
/// because the default waits for an error rate over a window. An adapter that closed over the
/// default would produce the second column while the operator read the first, and nothing about
/// the code would look wrong.
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

    // Both bench the lane, and that is the trap: the difference is not "down" versus "up" but
    // HOW LONG, which nothing on the request path will ever tell anybody about.
    assert!(under_default > 0);
    assert!(
        under_configured > under_default * 4,
        "the cooldown came from the default ladder, not the configured one: \
         {under_configured} against {under_default}"
    );
}

/// A pool nobody configured records nothing, rather than having a default ladder applied in its
/// name. A lane that never trips is visible; a lane that trips for the wrong duration is not.
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

/// Declaring the default cell's ladder does not quietly enroll every pool nobody configured.
/// The empty pool name is the one route that declaration speaks for; a NAMED pool with no entry
/// is still a pool nobody configured, and still records nothing.
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

/// The default cell — direct and ad-hoc routes, running under the empty pool name — is a
/// declaration of its own rather than a pool that happens to be missing.
#[test]
fn the_default_cell_takes_its_own_declared_ladder() {
    let breaker = adapter(BreakerPolicy::new().with_default_cell(a_slow_ladder()));
    let dest = DestinationId::new(4);
    assert!(breaker.observe("", dest, Outcome::HardDown, 0, &route_token()));
    assert!(breaker.cooldown_remaining("", dest, 0, &route_token()) > 0);
}

/// No number crosses the port, so no operator map can be filled here that the plane would never
/// read: an answer the transport read as the caller's fault records nothing, whatever its code was.
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

/// The wait the answer's frame stated rides a transient reading through as the cooldown floor.
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

/// A hard reading takes the destination down: the disposition every pool's cell trips on.
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

/// The boot check on the two hand-kept banks. It passes today, which is the point: it is a
/// tripwire on a convention, not a repair of a break.
#[test]
fn the_two_label_banks_agree() {
    assert!(check_label_banks().is_ok());
}

/// And the values themselves, written out, so a change on either side has to change this file
/// too. A label that reaches the scrape is wire, and wire that only one test knows about is
/// wire nobody is holding.
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
    // The two single-sided labels, pinned so that a later attempt to pair them has to notice
    // they were never a pair.
    assert_eq!(label::CLIENT_FAULT, "client_fault");
    assert_eq!(disposition::ATTEMPT_TIMEOUT, "attempt_timeout");
}

/// The drift the check would catch, shown as a value rather than left to the imagination.
#[test]
fn a_drifted_bank_reads_as_a_drift() {
    let drift = LabelDrift {
        breaker: "transient_upstream",
        egress: "transient-upstream",
    };
    assert!(drift.to_string().contains("drifted"));
}

/// A DRIFT REFUSES THE BOOT, NAMING BOTH SPELLINGS (item 248), and the boot seal on today's banks
/// still succeeds, so the label-bank check it runs refuses nothing it should not.
// The seal it drives composes the shipped transport stack (the http rows over the linked transport
// door); a build that links no transport door cannot seal it, so this cell gates on that axis.
#[cfg(linked_axis_transport_door)]
#[test]
fn a_label_drift_refuses_the_boot_and_todays_banks_seal() {
    // What a drift refuses the boot with: both spellings, so an operator reading the boot line can
    // see which side moved.
    let refusal = crate::root::registry::BootRefusal::LabelDrift(LabelDrift {
        breaker: "transient_upstream",
        egress: "transient-upstream",
    });
    let line = refusal.to_string();
    assert!(line.contains("transient_upstream") && line.contains("transient-upstream"));

    assert!(
        crate::root::registry::seal(
            &crate::LINKED,
            crate::root::registry::Dropped::NONE,
            Default::default()
        )
        .is_ok(),
        "today's banks agree, so the seal still passes"
    );
}

/// THE BOOT SEAL RUNS THE LABEL-BANK CHECK (item 248).
///
/// The comparison once existed and passed and nothing ran it: its only caller was the test that
/// shows it passes, so a rename on one side would ship with the binary booting clean. Driven as
/// behaviour: a drift is planted where the check reads its pairs, and the seal itself must refuse
/// with `BootRefusal::LabelDrift` naming both spellings. Moving the call out of the seal makes the
/// seal answer `Ok` here, and this goes red.
#[cfg(linked_axis_transport_door)]
#[test]
fn the_boot_seal_refuses_a_planted_label_drift() {
    struct Unplant;
    impl Drop for Unplant {
        fn drop(&mut self) {
            super::PLANTED_PAIR.with(|p| p.set(None));
        }
    }
    let _unplant = Unplant;
    super::PLANTED_PAIR.with(|p| p.set(Some(("transient_upstream", "transient-upstream"))));

    match crate::root::registry::seal(
        &crate::LINKED,
        crate::root::registry::Dropped::NONE,
        Default::default(),
    ) {
        Err(crate::root::registry::BootRefusal::LabelDrift(drift)) => assert_eq!(
            drift,
            LabelDrift {
                breaker: "transient_upstream",
                egress: "transient-upstream",
            }
        ),
        Err(other) => panic!("the seal refused for another reason: {other}"),
        Ok(_) => panic!("the boot seal sealed over a label drift: it does not run the check"),
    }
}

/// A HEALTH PROBE through the adapter (K7): its answer reaches every cell of the member under the
/// pools' policy. A client fault leaves a member parked in every pool parked; a 2xx recovers it.
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
