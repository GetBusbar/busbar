// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, Audit, Authenticate, Consumption, Decode,
    Encode, Grant, Hold, HoldCell, Meter, MeterClassId, OriginKind, Outcome, Pass, PrincipalId,
    ReasonCode, Refusal, Route, ScopeFacts, SeatVerdict, StepName, UnitKey, Usage, UsageLine,
    VerifiedDestination, Verify,
};
use busbar_kernel::plane_driver::DriverSteps;
use busbar_kernel::registry::Generation;
use busbar_kernel::teller::{AccrualMeter, Evidence, Kernel, UnitCtx};

pub struct CappedGroup {
    live: Arc<std::sync::atomic::AtomicUsize>,
    cap: usize,
}

impl CappedGroup {
    pub fn at(cap: usize) -> Arc<Self> {
        Arc::new(CappedGroup {
            live: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cap,
        })
    }

    pub fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    fn count_one(&self) -> Option<GroupCount> {
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.cap).then_some(n + 1)
            })
            .ok()
            .map(|_| GroupCount(Arc::clone(&self.live)))
    }
}

struct GroupCount(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for GroupCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

pub enum Door {
    Own,

    Accrual(Arc<HoldCell>),

    Zero,
}

pub struct TestUnits {
    pub calls: Mutex<Vec<StepName>>,

    pub refuse_at: Option<(StepName, ReasonCode)>,

    pub refuse_wait: Option<u32>,

    pub door: Door,

    pub evidence: Evidence,

    pub spend: u64,

    pub meter: Arc<AccrualMeter>,

    pub refused_door: AtomicBool,

    pub admitted_door: AtomicBool,

    pub challenge: bool,

    pub approved_lanes: Mutex<Vec<busbar_contract::caps::LaneId>>,

    pub seated_principals: Mutex<Vec<PrincipalId>>,

    pub groups: Vec<&'static str>,

    pub capped: Option<Arc<CappedGroup>>,

    pub abandoned: Mutex<Vec<busbar_kernel::teller::Ended>>,

    pub resolved: Option<Vec<u8>>,

    pub tap_faults: Mutex<Vec<(u32, &'static str)>>,
}

impl Default for TestUnits {
    fn default() -> Self {
        TestUnits {
            calls: Mutex::new(Vec::new()),
            refuse_at: None,
            refuse_wait: None,
            door: Door::Own,
            evidence: Evidence::default(),
            spend: 0,
            meter: Arc::new(AccrualMeter::new()),
            challenge: false,
            refused_door: AtomicBool::new(false),
            admitted_door: AtomicBool::new(false),
            approved_lanes: Mutex::new(Vec::new()),
            seated_principals: Mutex::new(Vec::new()),
            groups: Vec::new(),
            capped: None,
            abandoned: Mutex::new(Vec::new()),
            resolved: None,
            tap_faults: Mutex::new(Vec::new()),
        }
    }
}

impl TestUnits {
    pub fn passing() -> Self {
        TestUnits::default()
    }

    pub fn in_groups(groups: &[&'static str]) -> Self {
        TestUnits {
            groups: groups.to_vec(),
            ..TestUnits::default()
        }
    }

    pub fn behind(group: &Arc<CappedGroup>) -> Self {
        TestUnits {
            capped: Some(Arc::clone(group)),
            ..TestUnits::default()
        }
    }

    pub fn refusing(step: StepName, reason: ReasonCode) -> Self {
        TestUnits {
            refuse_at: Some((step, reason)),
            ..TestUnits::default()
        }
    }

    pub fn called(&self) -> Vec<StepName> {
        self.calls.lock().unwrap().clone()
    }

    pub fn doors(&self) -> (bool, bool) {
        (
            self.refused_door.load(Ordering::Acquire),
            self.admitted_door.load(Ordering::Acquire),
        )
    }

    pub fn approved_lanes(&self) -> Vec<busbar_contract::caps::LaneId> {
        self.approved_lanes.lock().unwrap().clone()
    }

    pub fn seated_principals(&self) -> Vec<PrincipalId> {
        self.seated_principals.lock().unwrap().clone()
    }

    fn note(&self, step: StepName) {
        self.calls.lock().unwrap().push(step);
    }

    fn refusal(&self, step: StepName) -> Option<Refusal> {
        match self.refuse_at {
            Some((at, reason)) if at == step => Some(match self.refuse_wait {
                Some(secs) => Refusal::new(reason).retry_after(secs),
                None => Refusal::new(reason),
            }),
            _ => None,
        }
    }
}

pub struct NeverRoutes<'u> {
    pub units: &'u TestUnits,

    pub dropped: &'u AtomicBool,
}

pub struct Never<'u> {
    dropped: &'u AtomicBool,
}

impl std::future::Future for Never<'_> {
    type Output = SeatVerdict<Route>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::task::Poll::Pending
    }
}

impl Drop for Never<'_> {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::Release);
    }
}

impl busbar_kernel::teller::RouteAwait for NeverRoutes<'_> {
    fn route_leg<'a>(
        &'a self,
        _token: &'a Pass<Route>,
        _ctx: &'a UnitCtx,
        _destinations: &'a [busbar_contract::caps::VerifiedDestination],
    ) -> busbar_kernel::teller::RouteLeg<'a> {
        self.units.note(StepName::Route);
        Box::pin(Never {
            dropped: self.dropped,
        })
    }

    fn abandoned(&self, _ctx: &UnitCtx, ended: busbar_kernel::teller::Ended) {
        self.units.abandoned.lock().unwrap().push(ended);
    }
}

pub fn arrival_record() -> busbar_contract::caps::ArrivalRecord {
    busbar_contract::caps::ArrivalRecord {
        source: "127.0.0.1:9".into(),
        port: 9,
        alpn: None,
        sni: None,
        peer_cert: None,
        transport_chain: vec!["battery"],
    }
}

pub fn audit_facts() -> busbar_contract::caps::AuditFacts {
    busbar_contract::caps::AuditFacts {
        op_class: busbar_contract::caps::OpClassId::new("battery"),
        finish: busbar_contract::FinishClass::Complete,
    }
}

pub fn encoded_frame() -> busbar_contract::caps::Frame {
    busbar_contract::caps::Frame {
        direction: busbar_contract::Direction::Outbound,
        stream: busbar_contract::StreamId(0),
        bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
        meta: busbar_contract::FrameMeta::default(),
    }
}

pub struct TestDoor;

impl busbar_kernel::inflight::ArrivalDoor for TestDoor {
    fn arrival_hold(
        &self,
        principal: PrincipalId,
        token: &busbar_contract::caps::Grant<busbar_contract::caps::Admittance>,
    ) -> Hold {
        Hold::open(token, principal)
    }
}

pub fn principal() -> PrincipalId {
    PrincipalId::new("acct:battery")
}

pub fn ctx(key: u64) -> UnitCtx {
    UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

pub fn cell(kernel: &Kernel) -> HoldCell {
    HoldCell::new(Hold::open(&kernel.admit_token(), principal()))
}

pub fn usage(token: &Grant<Consumption>, quantity: u64) -> Usage {
    Usage::report(
        token,
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity,
            source: busbar_contract::caps::QuantitySource::Count,
            estimated: false,
        }],
    )
    .expect("one line is within the bound")
}

macro_rules! step {
    ($self:ident, $name:expr, $facts:expr) => {{
        $self.note($name);
        match $self.refusal($name) {
            Some(refusal) => Err(refusal),
            None => Ok($facts),
        }
    }};
}

fn seated<S: busbar_contract::caps::Step>(
    token: &Pass<S>,
    answer: Result<S::Facts, Refusal>,
) -> SeatVerdict<S> {
    match answer {
        Ok(facts) => SeatVerdict::proceed(token, facts),
        Err(refusal) => SeatVerdict::refuse(token, refusal),
    }
}

pub const TAP_FAULT_PROTOCOL: &str = "plane-driver-test";

impl busbar_kernel::plane_driver::DriverSteps for TestUnits {
    fn arrival(&self, _ctx: &UnitCtx) -> Result<busbar_contract::caps::ArrivalRecord, Refusal> {
        step!(self, StepName::Arrival, arrival_record())
    }

    fn authenticate(
        &self,
        _ctx: &UnitCtx,
    ) -> Result<busbar_contract::caps::Authenticated, Refusal> {
        let facts = if self.challenge {
            busbar_contract::caps::Authenticated::Challenge(busbar_contract::Challenge {
                bytes: b"nonce".to_vec(),
                state: busbar_contract::ChallengeState(Vec::new()),
                rounds_left: 2,
            })
        } else {
            busbar_contract::caps::Authenticated::Principal(principal())
        };
        step!(self, StepName::Authenticate, facts)
    }

    fn verify(
        &self,
        trust: &busbar_contract::caps::Grant<busbar_contract::caps::Dial>,
        _ctx: &UnitCtx,
        _principal: &PrincipalId,
    ) -> Result<Vec<VerifiedDestination>, Refusal> {
        step!(
            self,
            StepName::Verify,
            vec![VerifiedDestination::seal(
                trust,
                busbar_contract::caps::LaneId::new("fixture-lane"),
            )]
        )
    }

    fn approve(
        &self,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> Result<ScopeFacts, Refusal> {
        self.seated_principals
            .lock()
            .unwrap()
            .push(principal.clone());
        self.approved_lanes
            .lock()
            .unwrap()
            .extend(destinations.iter().map(|d| *d.lane()));
        step!(self, StepName::Approve, ScopeFacts::default())
    }

    fn admit(
        &self,
        admit: &Grant<Admittance>,
        _ctx: &UnitCtx,
        principal: &PrincipalId,
        _destinations: &[VerifiedDestination],
        leases: &busbar_kernel::slice::GroupLeaseSlip,
    ) -> Result<Admission, Refusal> {
        self.note(StepName::Admit);
        self.seated_principals
            .lock()
            .unwrap()
            .push(principal.clone());
        if let Some(refusal) = self.refusal(StepName::Admit) {
            return Err(refusal);
        }

        if let Some(group) = &self.capped {
            let Some(counted) = group.count_one() else {
                return Err(Refusal::new(ReasonCode::RateLimited));
            };

            leases.holding(busbar_kernel::slice::DoorGrant::new(counted));
        }

        for group in &self.groups {
            leases.counted(group);
        }
        Ok(match &self.door {
            Door::Own => Admission::Own(Hold::open(admit, principal.clone())),
            Door::Zero => Admission::ZeroHold,
            Door::Accrual(parent) => match parent.accrue_child(principal, admit) {
                Ok(accrual) => Admission::Accrual(accrual),

                Err(_) => Admission::Own(Hold::open(admit, principal.clone())),
            },
        })
    }

    fn meter(
        &self,
        usage_token: &Grant<Consumption>,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
        _destinations: &[VerifiedDestination],
    ) -> Result<Usage, Refusal> {
        step!(self, StepName::Meter, usage(usage_token, self.spend))
    }

    fn audit(&self, _ctx: &UnitCtx, _outcome: &Outcome) -> busbar_contract::caps::AuditFacts {
        self.note(StepName::Audit);
        self.admitted_door.store(true, Ordering::Release);
        audit_facts()
    }

    fn audit_refused(
        &self,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> busbar_contract::caps::AuditFacts {
        self.calls.lock().unwrap().push(StepName::Audit);
        self.refused_door.store(true, Ordering::Release);
        audit_facts()
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        self.evidence.clone()
    }

    fn resolved(&self, _ctx: &UnitCtx) -> Option<Vec<u8>> {
        self.resolved.clone()
    }

    fn usage_tap_fault(&self, _ctx: &UnitCtx, dialect: u32, reason: &'static str) {
        self.tap_faults.lock().unwrap().push((dialect, reason));
        busbar_kernel::snapshot::usage_tap_fault(TAP_FAULT_PROTOCOL, reason);
    }
}

impl busbar_kernel::teller::DoorSeats for TestUnits {
    fn arrival(&self, token: &Pass<Arrival>, ctx: &UnitCtx) -> SeatVerdict<Arrival> {
        seated(token, DriverSteps::arrival(self, ctx))
    }

    fn decode(&self, token: &Pass<Decode>, _ctx: &UnitCtx) -> SeatVerdict<Decode> {
        seated(
            token,
            step!(
                self,
                StepName::Decode,
                busbar_contract::caps::OpClassId::new("battery")
            ),
        )
    }

    fn authenticate(&self, token: &Pass<Authenticate>, ctx: &UnitCtx) -> SeatVerdict<Authenticate> {
        seated(token, DriverSteps::authenticate(self, ctx))
    }

    fn verify(
        &self,
        token: &Pass<Verify>,
        trust: &busbar_contract::caps::Grant<busbar_contract::caps::Dial>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
    ) -> SeatVerdict<Verify> {
        seated(token, DriverSteps::verify(self, trust, ctx, principal))
    }

    fn approve(
        &self,
        token: &Pass<Approve>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
    ) -> SeatVerdict<Approve> {
        seated(
            token,
            DriverSteps::approve(self, ctx, principal, destinations),
        )
    }

    fn admit(
        &self,
        token: &Pass<Admit>,
        admit: &Grant<Admittance>,
        ctx: &UnitCtx,
        principal: &PrincipalId,
        destinations: &[VerifiedDestination],
        leases: &busbar_kernel::slice::GroupLeaseSlip,
    ) -> SeatVerdict<Admit> {
        seated(
            token,
            DriverSteps::admit(self, admit, ctx, principal, destinations, leases),
        )
    }
}

impl busbar_kernel::teller::UnitEnds for TestUnits {
    fn route(
        &self,
        token: &Pass<Route>,
        _ctx: &UnitCtx,
        _destinations: &[busbar_contract::caps::VerifiedDestination],
    ) -> SeatVerdict<Route> {
        self.note(StepName::Route);
        self.meter.accrue(self.spend);
        match self.refusal(StepName::Route) {
            Some(refusal) => SeatVerdict::refuse(token, refusal),
            None => SeatVerdict::proceed(token, busbar_contract::caps::RoutePlan::default()),
        }
    }

    fn meter(
        &self,
        token: &Pass<Meter>,
        usage_token: &Grant<Consumption>,
        ctx: &UnitCtx,
        provisional: &Outcome,
        destinations: &[busbar_contract::caps::VerifiedDestination],
    ) -> SeatVerdict<Meter> {
        seated(
            token,
            DriverSteps::meter(self, usage_token, ctx, provisional, destinations),
        )
    }

    fn audit(&self, token: &Pass<Audit>, ctx: &UnitCtx, outcome: &Outcome) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(token, DriverSteps::audit(self, ctx, outcome))
    }

    fn audit_refused(
        &self,
        token: &Pass<Audit>,
        ctx: &UnitCtx,
        refusal: &Refusal,
    ) -> SeatVerdict<Audit> {
        SeatVerdict::proceed(token, DriverSteps::audit_refused(self, ctx, refusal))
    }

    fn encode(
        &self,
        token: &Pass<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> SeatVerdict<Encode> {
        self.note(StepName::Encode);
        SeatVerdict::proceed(token, encoded_frame())
    }

    fn evidence(&self, ctx: &UnitCtx) -> Evidence {
        DriverSteps::evidence(self, ctx)
    }
}
