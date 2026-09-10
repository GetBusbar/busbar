//! Tests for `adapters.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_caps::KernelSeal;
use busbar_contract::WireStatus;

/// A fresh `UnitToken<Route>` for one `observe`/`ready`/`cooldown_remaining` call — test-only,
/// minted through the kernel seal exactly as CG-29 says a real deployment would
/// (`KernelSeal::acquire_for_kernel` is `// contract:` kernel-only outside test modules; the
/// production adapter above never mints one of its own — it forwards the borrow its caller
/// lent it).
fn route_token() -> UnitToken<Route> {
    UnitToken::mint(&KernelSeal::acquire_for_kernel())
}

/// A sink for a test that is about a ladder rather than about a diagnostic. The breaker crate's
/// own noop, at the shared handle's width, so the unit under test is the production one.
fn silent_sink() -> DiagnosticsSink {
    Arc::new(busbar_unit_breaker::classify::NoopDiagnostics)
}

/// A sink that keeps what it was told, so a test can ask whether the value reached it.
#[derive(Debug, Default)]
struct RecordingSink(std::sync::Mutex<Vec<String>>);

impl RecordingSink {
    fn values(&self) -> Vec<String> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Diagnostics for RecordingSink {
    fn unrecognized_error_map_value(&self, value: &str) {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(value.to_string());
    }
}

/// The binding, end to end at the adapter's own width: a destination whose operator `error_map`
/// names a class busbar has no such thing as, one upstream error that hits it, and the value on
/// the sink the adapter's unit was built over. Without the binding this is the silently-ignored
/// mapping the previous release had; with it the value is reportable.
///
/// The classification itself is unchanged either way — the mapping is ignored and the error is
/// classified from its HTTP status — which is the half that keeps the legacy path byte-identical.
#[test]
fn an_unrecognized_error_map_class_reaches_the_bound_sink() {
    let sink = Arc::new(RecordingSink::default());
    let breaker = BreakerAdapter::with_diagnostics(
        Arc::clone(&sink) as DiagnosticsSink,
        BreakerPolicy::new().with_pool("pool", a_slow_ladder()),
    );
    let dest = DestinationId::new(9);
    breaker.unit().set_error_map(
        dest,
        HashMap::from([("503".to_string(), "rate_limt".to_string())]),
    );

    let classified = breaker.classify(
        dest,
        UpstreamStatus {
            code: Some(WireStatus::new(
                busbar_contract::transport::status_ns::HTTP,
                503,
            )),
            class: None,
            retry_after: None,
        },
    );

    assert_eq!(
        sink.values(),
        vec!["rate_limt".to_string()],
        "the operator's typo reached the sink the root bound"
    );
    assert_eq!(
        classified.disposition,
        Disposition::TransientUpstream,
        "the mapping is still ignored: a 503 classifies from its HTTP status"
    );
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
            class: Some(StatusClass::ServerError),
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
    use busbar_unit_breaker::port::UpstreamCode;
    let grpc = UpstreamStatus {
        class: Some(StatusClass::ServerError),
        code: Some(WireStatus::new(
            busbar_contract::transport::status_ns::GRPC,
            14,
        )),
        retry_after: None,
    };
    let http = UpstreamStatus {
        class: Some(StatusClass::ServerError),
        code: Some(WireStatus::new(
            busbar_contract::transport::status_ns::HTTP,
            14,
        )),
        retry_after: None,
    };
    let classless = UpstreamStatus {
        class: Some(StatusClass::ServerError),
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
        trip: busbar_unit_breaker::cfg::TripConfig {
            mode: busbar_unit_breaker::cfg::TripMode::Consecutive,
            consecutive_n: 1,
            ..busbar_unit_breaker::cfg::TripConfig::default()
        },
        ..BreakerCfg::default()
    }
}

fn adapter_for(pool: &str) -> BreakerAdapter {
    BreakerAdapter::with_diagnostics(
        silent_sink(),
        BreakerPolicy::new().with_pool(pool, a_slow_ladder()),
    )
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

    let defaulted = BreakerAdapter::with_diagnostics(
        silent_sink(),
        BreakerPolicy::new().with_pool("pool", BreakerCfg::default()),
    );
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
    let breaker = BreakerAdapter::with_diagnostics(silent_sink(), BreakerPolicy::new());
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
    let breaker = BreakerAdapter::with_diagnostics(
        silent_sink(),
        BreakerPolicy::new().with_default_cell(a_slow_ladder()),
    );
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
    let breaker = BreakerAdapter::with_diagnostics(
        silent_sink(),
        BreakerPolicy::new().with_default_cell(a_slow_ladder()),
    );
    let dest = DestinationId::new(4);
    assert!(breaker.observe("", dest, Outcome::HardDown, 0, &route_token()));
    assert!(breaker.cooldown_remaining("", dest, 0, &route_token()) > 0);
}

/// The classification comes back through the adapter with the destination's own declared error
/// map applied — the table is the breaker unit's data and the adapter holds no copy of it.
#[test]
fn classification_carries_the_declared_error_map_through() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(9);
    breaker.unit().set_error_map(
        dest,
        [("1113".to_string(), "billing".to_string())]
            .into_iter()
            .collect(),
    );

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
    assert_eq!(out.disposition, Disposition::HardDown);
    assert_eq!(out.outcome, Outcome::HardDown);
}

/// The one fold the adapter performs: with no numeric status reported, the transport's coarse
/// reading stands in. This is the shape the walk actually builds today.
#[test]
fn a_coarse_transport_reading_stands_in_for_a_missing_status() {
    let breaker = adapter_for("pool");
    let out = breaker.classify(
        DestinationId::new(1),
        UpstreamStatus {
            class: Some(StatusClass::ServerError),
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
    assert_eq!(BreakerAdapter::fold_class(Some(StatusClass::Success)), None);
    assert_eq!(BreakerAdapter::fold_class(Some(StatusClass::Other)), None);
    assert_eq!(BreakerAdapter::fold_class(None), None);
    assert_eq!(
        BreakerAdapter::fold_class(Some(StatusClass::ClientError)),
        Some(400)
    );
    assert_eq!(
        BreakerAdapter::fold_class(Some(StatusClass::ServerError)),
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
    use busbar_unit_breaker::port::label;
    use busbar_unit_egress::ports::disposition;

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

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE PORT'S OWN WIDTH — what the served path hands the adapter, driven through the adapter
// ─────────────────────────────────────────────────────────────────────────────────────────────────
//
// The breaker unit already answers all three of these (the equivalence cells in
// `crates/busbar/tests/breaker_equivalence.rs` d2, d3 and d10 prove it against the legacy book).
// What these three cells ask is whether the answer SURVIVES THE SEAM: the egress unit's port is
// what the walk speaks, and a port narrower than the unit behind it hands the unit the defaults
// on every call — so the exemption, the operator's rule and the reason are all there, and none
// of them is reachable from the path that serves.

/// A passthrough 401 is the CALLER's own key failing, not this destination's: the classifier
/// exempts it from any breaker penalty. Through the port, the same answer.
#[test]
fn a_passthrough_401_crosses_the_port_as_the_callers_own_fault() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(11);

    let owned = breaker.classify(dest, shim::status(401, false, None, None));
    assert_eq!(
        owned.disposition,
        Disposition::HardDown,
        "busbar's own credential refused is the destination's fault and must hard-down it"
    );

    let passthrough = breaker.classify(dest, shim::status(401, true, None, None));
    assert_eq!(
        passthrough.disposition,
        Disposition::ClientFault,
        "a caller's own key refused is relayed with no breaker penalty; hard-downing the \
         destination here benches a healthy upstream for every other caller"
    );
    assert_eq!(passthrough.outcome, Outcome::RecordNothing);
}

/// An operator's `error_map` rule is keyed on the provider's OWN vocabulary — the code the dialect
/// read out of the response body — and only falls back to the HTTP status string where the body
/// carried none. Through the port, the body-derived key still fires.
#[test]
fn a_body_derived_error_map_key_crosses_the_port_and_fires() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(12);
    breaker.unit().set_error_map(
        dest,
        HashMap::from([("insufficient_quota".to_string(), "billing".to_string())]),
    );

    let out = breaker.classify(
        dest,
        shim::status(429, false, Some("insufficient_quota"), None),
    );
    assert_eq!(
        out.disposition,
        Disposition::HardDown,
        "the operator's rule names the provider code the dialect read, and a 429 carrying it is a \
         billing hard-down, not a rate limit"
    );

    let unmapped = breaker.classify(dest, shim::status(429, false, None, None));
    assert_eq!(
        unmapped.disposition,
        Disposition::TransientUpstream,
        "with no provider code the status string stands in, and 429 is a transient"
    );
}

/// What the upstream said when the destination went down is the whole value of the event to
/// whoever has to explain it. The classifier decides the reason; `observe` is the only call the
/// walk makes after it; so the reason must ride the outcome across the port or it is lost at the
/// one seam between the two.
#[test]
fn a_hard_down_carries_its_reason_across_the_port_into_the_unit() {
    let breaker = adapter_for("pool");
    let dest = DestinationId::new(13);

    let classified = breaker.classify(dest, shim::status(403, false, None, None));
    assert_eq!(classified.disposition, Disposition::HardDown);
    assert!(
        breaker.observe("pool", dest, classified.outcome, 0, &route_token()),
        "the first hard-down is a fresh trip"
    );
    assert_eq!(
        breaker.unit().hard_down_reason(dest).as_deref(),
        Some("auth rejected (HTTP 403)"),
        "the reason the previous release recorded lane-wide, in its words, recorded here"
    );

    let billing = adapter_for("pool");
    billing.unit().set_error_map(
        dest,
        HashMap::from([("1113".to_string(), "billing".to_string())]),
    );
    let classified = billing.classify(dest, shim::status(1113, false, None, None));
    assert!(billing.observe("pool", dest, classified.outcome, 0, &route_token()));
    assert_eq!(
        billing.unit().hard_down_reason(dest).as_deref(),
        Some("billing / insufficient balance"),
    );
}

mod shim {
    //! One function for the status the cells above want to hand the port. Where the port has the
    //! field, the shim fills it. Where it does not, the shim hands over what the port CAN carry
    //! and its doc comment names the gap — the cell then fails on the difference, which is the
    //! red we want, rather than on a missing field, which is a red nobody can run.
    //!
    //! A shim never implements the missing behaviour. Widening the port means repointing the shim
    //! at the real field and deleting the note.

    use busbar_unit_egress::ports::UpstreamStatus;

    /// An HTTP status as the served path reads it: the number, whose credential it refused, and
    /// the two body-derived signals the dialect read out of the response.
    ///
    /// GAP: the port carries none of the last three. `passthrough`, `provider_code` and
    /// `structured_type` are accepted and dropped here, so every cell that turns on one of them
    /// reads the port's default — a declared credential and a body that said nothing.
    pub fn status(
        code: u16,
        passthrough: bool,
        provider_code: Option<&'static str>,
        structured_type: Option<&'static str>,
    ) -> UpstreamStatus {
        let _ = (passthrough, provider_code, structured_type);
        UpstreamStatus {
            class: None,
            code: Some(busbar_contract::WireStatus::new(
                busbar_contract::transport::status_ns::HTTP,
                u32::from(code),
            )),
            retry_after: None,
        }
    }
}
