// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! RED-before-GREEN: Route and Meter must consume the SAME [`VerifiedDestination`] set the Verify
//! step sealed — not a set they compute for themselves.
//!
//! Before the fix, [`Units::route`] and [`Units::meter`] took no destinations parameter at all: the
//! set [`Units::verify`] sealed was threaded to Approve and Admit inside [`super::open_to_door`] and
//! then simply dropped when that function returned only the [`busbar_contract::caps::Admission`]. A
//! plane's own `route`/`meter` had no way to reach what Verify proved, so a real plane had to
//! re-derive its own idea of "where this unit goes" from its own state — exactly the
//! verify-then-act gap this test closes: the thing later steps act on is now provably the thing
//! Verify sealed, because it is the only thing they are handed.

use std::sync::Mutex;

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, Audit, Authenticate, Authenticated,
    Consumption, Decision, Decode, Dial, Encode, Grant, Hold, LaneId, Meter, OriginKind, Outcome,
    Pass, PrincipalId, Refusal, Route, RoutePlan, ScopeFacts, UnitKey, Usage, VerifiedDestination,
    Verify,
};

use crate::registry::Generation;
use crate::slice::{ConcurrencyGauge, GroupLeaseSlip, LeaseCell};
use crate::teller::{run_unit, AccrualMeter, Ended, Evidence, Kernel, Run, UnitCtx, Units};

fn principal() -> PrincipalId {
    PrincipalId::new("acct:teller-fixture")
}

fn ctx() -> UnitCtx {
    UnitCtx {
        key: UnitKey::new(1),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

fn arrival_record() -> busbar_contract::caps::ArrivalRecord {
    busbar_contract::caps::ArrivalRecord {
        source: "127.0.0.1:9".into(),
        port: 9,
        alpn: None,
        sni: None,
        peer_cert: None,
        transport_chain: vec!["fixture"],
    }
}

fn audit_facts() -> busbar_contract::caps::AuditFacts {
    busbar_contract::caps::AuditFacts {
        op_class: busbar_contract::caps::OpClassId::new("fixture"),
        finish: busbar_contract::FinishClass::Complete,
    }
}

fn encoded_frame() -> busbar_contract::caps::Frame {
    busbar_contract::caps::Frame {
        direction: busbar_contract::Direction::Outbound,
        stream: busbar_contract::StreamId(0),
        bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
        meta: busbar_contract::FrameMeta::default(),
    }
}

/// The lanes VERIFY seals — the sealed set the fix has to thread through.
fn sealed_lanes() -> Vec<LaneId> {
    vec![LaneId::new("sealed-lane-a"), LaneId::new("sealed-lane-b")]
}

/// A lane no step ever seals — standing in for whatever a re-deriving Route would have computed on
/// its own. Never appears in what `verify` seals, so the negative assertion below is not vacuous.
const PLANE_OWN_IDEA: &str = "plane-derived-lane-never-sealed";

/// The plane the battery drives the loop with. `verify` seals a two-lane set; `route` and `meter`
/// each record exactly the destinations slice the LOOP handed them, so the test can compare what
/// they received against what was sealed rather than trust that the two happen to agree.
struct Fixture {
    route_seen: Mutex<Vec<VerifiedDestination>>,
    meter_seen: Mutex<Vec<VerifiedDestination>>,
}

impl Units for Fixture {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        Decision::proceed(token, arrival_record())
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        Decision::proceed(token, busbar_contract::caps::OpClassId::new("fixture"))
    }

    fn authenticate(&self, token: &Pass<Authenticate>, _ctx: &UnitCtx) -> Decision<Authenticate> {
        Decision::proceed(token, Authenticated::Principal(principal()))
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> Decision<Verify> {
        let sealed = sealed_lanes()
            .into_iter()
            .map(|lane| VerifiedDestination::seal(trust, lane))
            .collect();
        Decision::proceed(token, sealed)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        Decision::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> Decision<Admit> {
        Decision::proceed(
            token,
            Admission::Own(Hold::open(admit, principal.clone(), 1_000)),
        )
    }

    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _meter: &AccrualMeter,
        destinations: &[VerifiedDestination],
    ) -> Decision<Route> {
        self.route_seen
            .lock()
            .unwrap()
            .extend_from_slice(destinations);
        Decision::proceed(token, RoutePlan::default())
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage_token: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> Decision<Meter> {
        self.meter_seen
            .lock()
            .unwrap()
            .extend_from_slice(destinations);
        Decision::proceed(
            token,
            Usage::report(usage_token, Vec::new()).expect("an empty usage report is within bound"),
        )
    }

    fn audit(&self, token: &Pass<Audit>, _ctx: &UnitCtx, _outcome: &Outcome) -> Decision<Audit> {
        Decision::proceed(token, audit_facts())
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        Decision::proceed(token, audit_facts())
    }

    fn encode(&self, token: &Pass<Encode>, _ctx: &UnitCtx, _outcome: &Outcome) -> Decision<Encode> {
        Decision::proceed(token, encoded_frame())
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }
}

#[test]
fn route_and_meter_consume_the_destinations_verify_sealed() {
    let kernel = Kernel::new();
    let fixture = Fixture {
        route_seen: Mutex::new(Vec::new()),
        meter_seen: Mutex::new(Vec::new()),
    };
    let gauge = ConcurrencyGauge::new();
    let canary = busbar_contract::caps::Canary::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let cell =
        busbar_contract::caps::HoldCell::new(Hold::open(&kernel.admit_token(), principal(), 0));

    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
    };

    // RED before the fix: `Units::route`/`Units::meter` had no `destinations` parameter to record
    // into `route_seen`/`meter_seen` at all — the fixture above does not even compile against the
    // pre-fix trait. GREEN after: both fire and both record the sealed set.
    let ended = run_unit(&kernel, &fixture, &ctx(), run);
    assert!(
        matches!(ended, Ended::Settled { .. }),
        "the fixture's door always admits, so the unit must settle: {ended:?}"
    );

    // What was actually sealed, reconstructed the same way the fixture built it — the value under
    // test, not a re-statement of the assertion.
    let expected: Vec<VerifiedDestination> = sealed_lanes()
        .into_iter()
        .map(|lane| VerifiedDestination::seal(&Grant::<Dial>::mint(kernel.seal()), lane))
        .collect();

    let route_seen = fixture.route_seen.lock().unwrap().clone();
    let meter_seen = fixture.meter_seen.lock().unwrap().clone();

    assert_eq!(
        route_seen, expected,
        "Route must act on the SAME destination set Verify sealed, not a re-derived one"
    );
    assert_eq!(
        meter_seen, expected,
        "Meter must fold what Route did against the SAME sealed set, not a re-derived one"
    );

    // The negative half of the proof: neither step saw the stand-in for "whatever a re-deriving
    // Route would have computed on its own" — the sealed set won outright, not by coincidence.
    assert!(
        !route_seen
            .iter()
            .any(|d| d.lane().as_str() == PLANE_OWN_IDEA),
        "Route must not see a destination nothing sealed"
    );
    assert!(
        !meter_seen
            .iter()
            .any(|d| d.lane().as_str() == PLANE_OWN_IDEA),
        "Meter must not see a destination nothing sealed"
    );
}
