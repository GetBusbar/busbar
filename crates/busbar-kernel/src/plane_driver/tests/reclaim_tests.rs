// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DISPATCH SCOPE (`BUSBAR-1.6.0.md` Part 3, "DispatchScope (leak fix)", l.2397-2402): every
//! host-side resource a dispatch takes is reclaimed when the dispatch future is DROPPED (a caller
//! that disconnects, a cancel, a future parked at an await), and synchronously, inside the drop.
//! Driven here through the memory-ABI plane driver, the teller's one loop and the production far
//! end, over the far end's doubles and the probe suite's plane double.

use std::future::Future;
use std::task::Waker;

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival as ArrivalStep, Audit, AuditFacts, Authenticate,
    Authenticated, Consumption, Decode, Dial, Encode, Grant, Hold, HoldCell, HoldCellState, LaneId,
    Meter, OriginKind, Outcome, Pass, PrincipalId, Refusal, Route, RoutePlan, ScopeFacts,
    SeatVerdict, UnitKey, Usage, VerifiedDestination, Verify,
};

use super::*;
use crate::plane_driver::{Arrival, DriverSteps};
use crate::registry::Generation;
use crate::slice::{ConcurrencyGauge, GroupLeaseSlip, LeaseCell, IN_FLIGHT};
use crate::teller::{run_unit_async, AccrualMeter, Evidence, Run, Units};

fn principal() -> PrincipalId {
    PrincipalId::new("acct:reclaim")
}

fn facts() -> AuditFacts {
    AuditFacts {
        op_class: OpClassId::new("probe"),
        finish: busbar_contract::FinishClass::Complete,
    }
}

/// The kernel steps: every one passes, and the door admits the unit with a hold of its own.
struct Door;

impl DriverSteps for Door {}

impl Units for Door {
    fn arrival(&self, token: &Pass<ArrivalStep>, _: &UnitCtx) -> SeatVerdict<ArrivalStep> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::ArrivalRecord {
                source: "127.0.0.1:9".into(),
                port: 9,
                alpn: None,
                sni: None,
                peer_cert: None,
                transport_chain: vec!["reclaim"],
            },
        )
    }

    fn decode(&self, token: &Pass<Decode>, _: &UnitCtx) -> SeatVerdict<Decode> {
        SeatVerdict::proceed(token, OpClassId::new("probe"))
    }

    fn authenticate(&self, token: &Pass<Authenticate>, _: &UnitCtx) -> SeatVerdict<Authenticate> {
        SeatVerdict::proceed(token, Authenticated::Principal(principal()))
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &Grant<Dial>,
        _: &UnitCtx,
        _: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        let sealed = vec![VerifiedDestination::seal(trust, LaneId::new("p"))];
        SeatVerdict::proceed(token, sealed)
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        _: &UnitCtx,
        _: &PrincipalId,
        _: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        SeatVerdict::proceed(token, ScopeFacts::default())
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        _: &UnitCtx,
        principal: &PrincipalId,
        _: &[VerifiedDestination],
        _: &GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        SeatVerdict::proceed(
            token,
            Admission::Own(Hold::open(admit, principal.clone(), 1_000)),
        )
    }

    fn route(
        &self,
        token: &Pass<Route>,
        _: &UnitCtx,
        _: &[VerifiedDestination],
    ) -> SeatVerdict<Route> {
        SeatVerdict::proceed(token, RoutePlan::default())
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage: &Grant<Consumption>,
        _: &UnitCtx,
        _: &Outcome,
        _: &[VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        SeatVerdict::proceed(
            token,
            Usage::report(usage, Vec::new()).expect("an empty report is within bound"),
        )
    }

    fn audit(&self, token: &Pass<Audit>, _: &UnitCtx, _: &Outcome) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(token, facts())
    }

    fn audit_refused(&self, token: &Pass<Audit>, _: &UnitCtx, _: &Refusal) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(token, facts())
    }

    fn encode(&self, token: &Pass<Encode>, _: &UnitCtx, _: &Outcome) -> SeatVerdict<Encode> {
        SeatVerdict::proceed(
            token,
            busbar_contract::caps::Frame {
                direction: busbar_contract::Direction::Outbound,
                stream: busbar_contract::StreamId(0),
                bytes: busbar_contract::SlabBytes::new(Arc::from(&b""[..])),
                meta: busbar_contract::FrameMeta::default(),
            },
        )
    }

    fn evidence(&self, _: &UnitCtx) -> Evidence {
        Evidence::default()
    }
}

/// The caller the dispatch answers. It goes away by being dropped with the dispatch.
struct Gone;

impl crate::plane_driver::CallerEnd for Gone {
    fn head(&self, _: u32, _: crate::plane_driver::HeadFields) {}

    async fn write(&self, _: &[u8]) -> bool {
        true
    }
}

impl crate::plane_driver::SessionCaller for Gone {
    async fn read(&self) -> Option<Vec<u8>> {
        None
    }
}

/// THE DISPATCH SCOPE, PROVEN ON A DROP: a client unit is admitted (its hold in the cell, its
/// in-flight lease drawn), its far end's connection is opened, and the dispatch future is parked
/// on the far end's answer, which never comes. The future is dropped there, as a caller that
/// disconnects drops it; right after the drop, with nothing else polled or swept, the admission is
/// released (the lease is back on the gauge, the hold is out of the cell) and the egress
/// connection is closed. The dispatch owns its far end, as the root's `drive` owns its `DoorFar`.
///
/// RED: with the exit path's `run.leases.release_all(run.gauge)` (`teller.rs`, `exit`) removed the
/// in-flight lease is still on the gauge after the drop; with `e.conns.close(..)` removed from
/// `EgressFarEnd::settled` (`far_end.rs`) the connection is never closed.
#[tokio::test]
async fn a_dispatch_dropped_mid_await_releases_its_admission_and_closes_its_egress() {
    let r = rig(&[("a.test", Script::Silent)], OnExhausted::Status503, None);
    let plane = Arc::new(Prober {
        organic: true,
        ..Prober::default()
    });
    let driver = PlaneDriver::new(
        plane,
        DriverConfig {
            caps: BufferCaps::default(),
            op_classes: vec![OpClassId::new("probe")],
            status_of: refusal_status,
            refusal_statuses: Vec::new(),
            caller_refs: None,
        },
        Arc::new(Till::default()),
        Arc::new(crate::host_services::KernelServices::new()),
        ("reclaim", &serde_yaml::Value::Null),
    )
    .expect("the instance is admitted");
    let kernel = Kernel::new();
    let (gauge, leases, canary, meter) = (
        ConcurrencyGauge::new(),
        LeaseCell::new(),
        busbar_contract::caps::Canary::new(),
        AccrualMeter::new(),
    );
    let cell = HoldCell::new(Hold::open(&kernel.admit_token(), principal(), 0));
    let ctx = UnitCtx {
        key: UnitKey::new(1),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
    };
    let (egress, driver, kernel, ctx) = (&r.egress, &driver, &kernel, &ctx);
    let mut dispatch = Box::pin(async move {
        let far = egress.unit(UnitRoute {
            unit: ctx.key,
            ..route()
        });
        let arrival = Arrival {
            claim: 0,
            method: b"POST".to_vec(),
            target: b"/chat".to_vec(),
            fields: Vec::new(),
            body: Arc::from(&b"{}"[..]),
        };
        let units = driver.unit(&Door, &far, &Gone, arrival, 0);
        run_unit_async(kernel, &units, ctx, run, &units).await
    });

    // Poll until the far end's connection is open and the dispatch is parked on its answer.
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        assert!(
            dispatch.as_mut().poll(&mut cx).is_pending(),
            "the far end never answers, so the dispatch cannot end"
        );
        if !r.table.opened.lock().unwrap().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(
        r.table.opened.lock().unwrap().len(),
        1,
        "the egress is open"
    );
    assert!(
        dispatch.as_mut().poll(&mut cx).is_pending(),
        "parked mid-await"
    );
    assert_eq!(
        gauge.count(&IN_FLIGHT),
        1,
        "admitted: the in-flight lease is drawn"
    );
    assert_eq!(leases.held(), 1, "the unit's slot holds its lease");
    assert_eq!(
        cell.state(),
        HoldCellState::Admitted,
        "the door's hold is in the cell"
    );
    assert_eq!(r.table.closed.load(Ordering::SeqCst), 0);

    // THE CALLER GOES AWAY: the dispatch is dropped where it is parked.
    drop(dispatch);

    assert_eq!(
        gauge.count(&IN_FLIGHT),
        0,
        "the admission's lease went back to the gauge inside the drop"
    );
    assert_eq!(leases.held(), 0, "the unit's slot holds nothing");
    assert_eq!(
        cell.state(),
        HoldCellState::Taken,
        "the hold left the cell inside the drop"
    );
    assert_eq!(
        r.table.closed.load(Ordering::SeqCst),
        1,
        "the egress connection was closed inside the drop"
    );
}
