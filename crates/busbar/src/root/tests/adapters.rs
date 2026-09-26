//! Tests for `adapters.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_contract::caps::KernelSeal;
use busbar_contract::WireStatus;
use busbar_kernel_egress::ports::Disposition;

/// A fresh `Pass<Route>` for one `observe`/`ready`/`cooldown_remaining` call — test-only,
/// minted through the kernel seal exactly as CG-29 says a real deployment would
/// (`KernelSeal::acquire_for_kernel` is `// contract:` kernel-only outside test modules; the
/// production adapter above never mints one of its own — it forwards the borrow its caller
/// lent it).
fn route_token() -> Pass<Route> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

/// A gRPC upstream's trailers-only `UNAVAILABLE`, at the production adapter's own width: the
/// status leg the egress unit reads off that frame (the transport's coarse `ServerError` plus
/// gRPC's own `14`), classified, recorded, and the lane suppressed as a result.
///
/// This is the money defect. The number used to cross bare, get matched against HTTP's bands,
/// match none of them, and come back `ClientFault` — so nothing was recorded, the lane stayed
/// open, and the walk relayed a dead upstream's refusal instead of failing over. The coarse
/// class had said `ServerError` the whole time.
#[test]
fn a_grpc_unavailable_is_recorded_against_the_destination_and_suppresses_the_lane() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(14);

    let classified = breaker.classify(
        dest,
        UpstreamStatus {
            class: Some(WireStatusClass::ServerError),
            code: Some(WireStatus::new(
                busbar_contract::transport::status_ns::GRPC,
                14,
            )),
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
        "one UNAVAILABLE on this ladder takes the lane down"
    );
}

/// The same digits under HTTP's numbering are not a status at all, and the adapter must keep
/// the two readings apart rather than letting either stand in for the other.
#[test]
fn the_adapter_carries_the_numbering_across_rather_than_the_digits() {
    use busbar_kernel_breaker::port::UpstreamCode;
    let grpc = UpstreamStatus {
        class: Some(WireStatusClass::ServerError),
        code: Some(WireStatus::new(
            busbar_contract::transport::status_ns::GRPC,
            14,
        )),
        retry_after: None,
    };
    let http = UpstreamStatus {
        class: Some(WireStatusClass::ServerError),
        code: Some(WireStatus::new(
            busbar_contract::transport::status_ns::HTTP,
            14,
        )),
        retry_after: None,
    };
    let classless = UpstreamStatus {
        class: Some(WireStatusClass::ServerError),
        code: None,
        retry_after: None,
    };
    assert_eq!(
        BreakerAdapter::narrow_code(grpc),
        Some(UpstreamCode::Grpc(14))
    );
    assert_eq!(
        BreakerAdapter::narrow_code(http),
        Some(UpstreamCode::Http(14))
    );
    assert_eq!(
        BreakerAdapter::narrow_code(classless),
        Some(UpstreamCode::Http(500)),
        "the class fold is the fallback, and only for an answer that carried no number"
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
    BreakerAdapter::with_policy(BreakerPolicy::new().with_pool(pool, a_slow_ladder()))
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

    let defaulted =
        BreakerAdapter::with_policy(BreakerPolicy::new().with_pool("pool", BreakerCfg::default()));
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
    let breaker = BreakerAdapter::with_policy(BreakerPolicy::new());
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
    let breaker =
        BreakerAdapter::with_policy(BreakerPolicy::new().with_default_cell(a_slow_ladder()));
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
    let breaker =
        BreakerAdapter::with_policy(BreakerPolicy::new().with_default_cell(a_slow_ladder()));
    let dest = DestinationId::new(4);
    assert!(breaker.observe("", dest, Outcome::HardDown, 0, &route_token()));
    assert!(breaker.cooldown_remaining("", dest, 0, &route_token()) > 0);
}

/// The port classifies on the status alone: the breaker holds no operator `error_map`, so a
/// provider code an operator could map (`1113` -> `billing` is the stock example) reaches this
/// port as the bare number it is and classifies by HTTP's bands. Mapping an error body is the
/// plane's classifier's work; the unit only takes that classifier's verdict, and there is no
/// second map here for a deployment to fill that the plane would never read.
#[test]
fn the_port_classifies_on_the_status_alone() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(9);

    let out = breaker.classify(
        dest,
        UpstreamStatus {
            class: None,
            code: Some(WireStatus::new(
                busbar_contract::transport::status_ns::HTTP,
                1113,
            )),
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

/// The one fold the adapter performs: with no numeric status reported, the transport's coarse
/// reading stands in. This is the shape the walk actually builds today.
#[test]
fn a_coarse_transport_reading_stands_in_for_a_missing_status() {
    let breaker = adapter_for("pool");
    let out = breaker.classify(
        DestinationId::new(1),
        UpstreamStatus {
            class: Some(WireStatusClass::ServerError),
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

/// A success reaching the error path folds to nothing, which is what the previous release did
/// with the same case: there is no non-arbitrary number to invent for it.
#[test]
fn a_success_folds_to_no_status_at_all() {
    assert_eq!(
        BreakerAdapter::fold_class(Some(WireStatusClass::Success)),
        None
    );
    assert_eq!(
        BreakerAdapter::fold_class(Some(WireStatusClass::Other)),
        None
    );
    assert_eq!(BreakerAdapter::fold_class(None), None);
    assert_eq!(
        BreakerAdapter::fold_class(Some(WireStatusClass::ClientError)),
        Some(400)
    );
    assert_eq!(
        BreakerAdapter::fold_class(Some(WireStatusClass::ServerError)),
        Some(500)
    );
}

/// The lane map is a correspondence, and it round-trips in both directions.
#[test]
fn the_lane_map_round_trips_between_the_two_names() {
    let map = LaneMap::new(vec![
        DestinationId::new(11),
        DestinationId::new(22),
        DestinationId::new(33),
    ]);
    assert_eq!(map.len(), 3);
    assert!(!map.is_empty());
    for lane in 0..map.len() {
        let dest = map.destination(lane).expect("in the table");
        assert_eq!(map.lane(dest), Some(lane));
    }
}

/// A lane the table does not have answers nothing. Saturating to the last member would send a
/// request to somebody else's upstream and look like it worked, which is the worst available
/// failure.
#[test]
fn a_lane_off_the_end_of_the_table_names_no_destination() {
    let map = LaneMap::new(vec![DestinationId::new(11)]);
    assert_eq!(map.destination(1), None);
    assert_eq!(map.lane(DestinationId::new(99)), None);
}

/// An empty pool has no members and says so, rather than answering for a member it does not
/// have.
#[test]
fn an_empty_pool_names_nothing() {
    let map = LaneMap::default();
    assert!(map.is_empty());
    assert_eq!(map.destination(0), None);
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

/// THE CHECK HAS A CALLER, AND IT IS THE BOOT SEAL (item 248).
///
/// The comparison above existed and passed and nothing ran it: its only caller was the test that
/// shows it passes, so a rename on one side would ship with the binary booting clean. The boot seal
/// — the one check every boot that mounts the root passes through — now runs it and refuses on a
/// drift, naming both spellings. Read off the seal's own body, so moving the call out of the boot
/// path goes red here; and the seal on today's banks still succeeds, so the call refuses nothing it
/// should not.
#[test]
fn the_boot_seal_runs_the_label_bank_check_and_a_drift_refuses_the_boot() {
    let registry = include_str!("../registry.rs");
    let start = registry
        .find("pub fn seal(")
        .expect("the boot seal is in the registry module");
    let body = &registry[start..];
    let body = &body[..body.find("\n}\n").expect("the seal's body closes")];
    assert!(
        body.contains("check_label_banks()"),
        "the boot seal does not run the label-bank check"
    );

    // What a drift refuses the boot with: both spellings, so an operator reading the boot line can
    // see which side moved.
    let refusal = crate::root::registry::BootRefusal::LabelDrift(LabelDrift {
        breaker: "transient_upstream",
        egress: "transient-upstream",
    });
    let line = refusal.to_string();
    assert!(line.contains("transient_upstream") && line.contains("transient-upstream"));

    assert!(
        crate::root::registry::seal(&crate::LINKED, Default::default()).is_ok(),
        "today's banks agree, so the seal still passes"
    );
}

/// ONE CELL SET ON THE NODE. The root's breaker is bound to the kernel's own unit through the live
/// snapshot, so a pool observation made through the root adapter is the cell the kernel's admission
/// reads, and a trip the kernel records is the one the adapter answers with. A second unit would
/// pass neither half: its cells are not the lane store's.
#[test]
fn the_root_breaker_observes_into_the_kernels_own_cells() {
    use busbar_kernel::test_support::{LaneSpec, TestApp};
    let app = TestApp::new()
        .lane(LaneSpec::new("m0", "wire-under-test", "http://127.0.0.1:9"))
        .lane(LaneSpec::new("m1", "wire-under-test", "http://127.0.0.1:9"))
        .pool("pool", &[(0, 1), (1, 1)])
        .build();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let trip_on_first = BreakerCfg {
        trip: busbar_kernel_breaker::cfg::TripConfig {
            mode: busbar_kernel_breaker::cfg::TripMode::Consecutive,
            consecutive_n: 1,
            ..Default::default()
        },
        ..BreakerCfg::default()
    };
    let breaker = BreakerAdapter::over_kernel(
        Arc::clone(&handle),
        BreakerPolicy::new().with_pool("pool", trip_on_first),
    );

    // The kernel's own clock: its hard-down below stamps the wall clock in seconds.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();

    // Through the root adapter, into the kernel's cell.
    assert!(breaker.observe(
        "pool",
        DestinationId::new(0),
        Outcome::Transient { retry_after: None },
        now,
        &route_token(),
    ));
    assert!(
        !handle.load().store.ready_in("pool", 0, now),
        "the kernel's admission reads the trip the root adapter recorded"
    );

    // From the kernel's record, out through the root adapter.
    assert!(breaker.ready("pool", DestinationId::new(1), now, &route_token()));
    handle
        .load()
        .store
        .record_hard_down_all_cells(1, "one cell set");
    assert!(
        !breaker.ready("pool", DestinationId::new(1), now, &route_token()),
        "the root adapter answers with the trip the kernel recorded"
    );
}
