// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Mutex;

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, Audit, Authenticate, Authenticated,
    Consumption, Decode, Dial, Encode, Grant, Hold, LaneId, Meter, OriginKind, Outcome, Pass,
    PrincipalId, Refusal, Route, RoutePlan, ScopeFacts, SeatVerdict, UnitKey, Usage,
    VerifiedDestination, Verify,
};

use crate::registry::Generation;
use crate::slice::{ConcurrencyGauge, GroupLeaseSlip, LeaseCell};
use crate::teller::{run_unit, AccrualMeter, Ended, Evidence, Kernel, Run, UnitCtx};

fn principal() -> PrincipalId {
    PrincipalId::new("acct:teller-fixture")
}

fn ctx() -> UnitCtx {
    UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
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

fn sealed_lanes() -> Vec<LaneId> {
    vec![LaneId::new("sealed-lane-a"), LaneId::new("sealed-lane-b")]
}

const PLANE_OWN_IDEA: &str = "plane-derived-lane-never-sealed";

struct Fixture {
    admissions: std::sync::atomic::AtomicUsize,
    route_seen: Mutex<Vec<VerifiedDestination>>,
    meter_seen: Mutex<Vec<VerifiedDestination>>,

    audited_seen: Mutex<Vec<busbar_contract::caps::AuditFacts>>,
}

impl crate::teller::DoorSeats for Fixture {
    fn arrival(&self, token: &Pass<Arrival>, _ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        SeatVerdict::proceed(token, arrival_record())
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> SeatVerdict<Decode> {
        SeatVerdict::proceed(token, busbar_contract::caps::OpClassId::new("fixture"))
    }

    fn authenticate(
        &self,
        token: &Pass<Authenticate>,
        _ctx: &UnitCtx,
    ) -> SeatVerdict<Authenticate> {
        SeatVerdict::proceed(token, Authenticated::Principal(principal()))
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        let sealed = sealed_lanes()
            .into_iter()
            .map(|lane| VerifiedDestination::seal(trust, lane))
            .collect();
        SeatVerdict::proceed(token, sealed)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        SeatVerdict::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        _leases: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        self.admissions
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        SeatVerdict::proceed(token, Admission::Own(Hold::open(admit, principal.clone())))
    }
}

impl crate::teller::UnitEnds for Fixture {
    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        self.route_seen
            .lock()
            .unwrap()
            .extend_from_slice(destinations);
        SeatVerdict::proceed(token, RoutePlan::default())
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage_token: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        self.meter_seen
            .lock()
            .unwrap()
            .extend_from_slice(destinations);
        SeatVerdict::proceed(
            token,
            Usage::report(usage_token, Vec::new()).expect("an empty usage report is within bound"),
        )
    }

    fn audit(&self, token: &Pass<Audit>, _ctx: &UnitCtx, _outcome: &Outcome) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(token, audit_facts())
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(token, audit_facts())
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        SeatVerdict::proceed(token, encoded_frame())
    }

    fn audited(
        &self,
        _ctx: &UnitCtx,
        facts: busbar_contract::caps::AuditFacts,
        _pass: Pass<Audit>,
    ) {
        self.audited_seen.lock().unwrap().push(facts);
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        Evidence::default()
    }
}

#[test]
fn route_and_meter_consume_the_destinations_verify_sealed() {
    let kernel = Kernel::new();
    let fixture = Fixture {
        admissions: std::sync::atomic::AtomicUsize::new(0),
        route_seen: Mutex::new(Vec::new()),
        meter_seen: Mutex::new(Vec::new()),
        audited_seen: Mutex::new(Vec::new()),
    };
    let gauge = ConcurrencyGauge::new();
    let canary = crate::canary::Canary::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let cell = busbar_contract::caps::HoldCell::new(Hold::open(&kernel.admit_token(), principal()));

    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
        taps: None,
    };

    let ended = run_unit(&kernel, &fixture, &ctx(), run);
    assert!(
        matches!(ended, Ended::Settled { .. }),
        "the fixture's door always admits, so the unit must settle: {ended:?}"
    );

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

    assert_eq!(
        *fixture.audited_seen.lock().unwrap(),
        vec![audit_facts()],
        "the audit door's facts must reach whoever drives the unit exactly once"
    );

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

#[test]
fn session_own_is_retained_until_completion_cancellation_or_invalid_finish() {
    use crate::teller::{open_unit, SessionOpen};
    use busbar_contract::caps::{Abort, HoldCellState, ReasonCode};

    for terminal in 0..3 {
        let kernel = Kernel::new();
        let fixture = Fixture {
            admissions: std::sync::atomic::AtomicUsize::new(0),
            route_seen: Mutex::new(Vec::new()),
            meter_seen: Mutex::new(Vec::new()),
            audited_seen: Mutex::new(Vec::new()),
        };
        let gauge = ConcurrencyGauge::new();
        let canary = crate::canary::Canary::new();
        let leases = LeaseCell::new();
        let meter = AccrualMeter::new();
        let mut ctx = ctx();
        ctx.call = kernel.next_call();
        let cell = busbar_contract::caps::HoldCell::new(Hold::open(
            &kernel.admit_token_for(ctx.call),
            principal(),
        ));
        let run = || Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
            taps: None,
        };
        let opened = super::block_on(open_unit(&kernel, &fixture, &ctx, run()));
        let SessionOpen::Admitted { own: Some(own), .. } = opened else {
            panic!("actual Own session did not retain terminal custody");
        };
        assert_eq!(cell.state(), HoldCellState::Admitted);
        assert_eq!(canary.counts().drafts, 1);
        assert_eq!(canary.counts().holds, 1);
        assert_eq!(canary.counts().settlements, 0);
        let outcome = if terminal == 1 {
            Outcome::Aborted(Abort::Kernel {
                reason: ReasonCode::ClientGone,
            })
        } else {
            Outcome::Completed
        };
        let mut terminal_ctx = ctx.clone();
        if terminal == 2 {
            terminal_ctx.key = UnitKey::new(2);
        }
        let ended = own.finish(
            &kernel,
            &terminal_ctx,
            run(),
            outcome,
            Evidence {
                reported: Some(37),
                fee_units: 1,
                class: None,
                upstream_candidate: true,
            },
        );
        let Ended::Settled { end, requests, fee } = ended else {
            panic!("actual session hold was not settled");
        };
        if terminal == 2 {
            assert!(
                end.posted().is_err(),
                "foreign terminal context posted money"
            );
            assert_eq!(requests, 0);
        } else {
            assert_eq!(end.posted().unwrap().quantity(), 37);
            assert_eq!(end.posted().unwrap().principal(), &principal());
            assert_eq!(
                requests, 1,
                "ordinary Client authority must remain chargeable"
            );
            assert_eq!(fee, 1);
            assert_eq!(end.outcome(), outcome);
        }
        assert_eq!(cell.state(), HoldCellState::Taken);
        assert!(canary.balanced().is_ok());
        assert!(
            matches!(
                crate::teller::exit(&kernel, &fixture, &ctx, run(), Outcome::Completed, true,),
                Ended::AlreadySettled
            ),
            "session terminal posting was reusable"
        );
    }
}

#[test]
fn screened_session_refuses_before_admission_or_carrier_routing() {
    use crate::teller::{open_unit_screened, RouteAwait, RouteLeg, Screen, SessionOpen};
    use busbar_contract::caps::{HoldCellState, ReasonCode};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Gate(AtomicUsize);
    impl RouteAwait for Gate {
        fn screen<'a>(&'a self, _ctx: &'a UnitCtx) -> Screen<'a> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::ready(Err(Refusal::new(ReasonCode::InFlight))))
        }
        fn route_leg<'a>(
            &'a self,
            _token: &'a Pass<Route>,
            _ctx: &'a UnitCtx,
            _destinations: &'a [VerifiedDestination],
        ) -> RouteLeg<'a> {
            panic!("refused screen must never route a carrier");
        }
        fn abandoned(&self, _ctx: &UnitCtx, _ended: Ended) {}
    }
    let kernel = Kernel::new();
    let fixture = Fixture {
        admissions: AtomicUsize::new(0),
        route_seen: Mutex::new(Vec::new()),
        meter_seen: Mutex::new(Vec::new()),
        audited_seen: Mutex::new(Vec::new()),
    };
    let gate = Gate(AtomicUsize::new(0));
    let gauge = ConcurrencyGauge::new();
    let canary = crate::canary::Canary::new();
    let leases = LeaseCell::new();
    let meter = AccrualMeter::new();
    let mut ctx = ctx();
    ctx.call = kernel.next_call();
    let cell = busbar_contract::caps::HoldCell::new(Hold::open(
        &kernel.admit_token_for(ctx.call),
        principal(),
    ));
    let opened = super::block_on(open_unit_screened(
        &kernel,
        &fixture,
        &ctx,
        Run {
            cell: &cell,
            parent: None,
            leases: &leases,
            gauge: &gauge,
            canary: &canary,
            meter: &meter,
            taps: None,
        },
        &gate,
    ));
    assert!(matches!(opened, SessionOpen::Refused));
    assert_eq!(gate.0.load(Ordering::Relaxed), 1);
    assert_eq!(
        fixture.admissions.load(Ordering::Relaxed),
        0,
        "the screen must refuse before governor admission"
    );
    assert_eq!(cell.state(), HoldCellState::Arrival);
    assert_eq!(canary.counts().drafts, 0);
    assert_eq!(canary.counts().holds, 0);
    assert!(fixture.route_seen.lock().unwrap().is_empty());
    assert_eq!(fixture.audited_seen.lock().unwrap().len(), 1);
}
