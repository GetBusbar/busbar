// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::caps::Frame as Encoded;
use busbar_contract::caps::{
    Admission, Admit, Admittance, Approve, Arrival, Audit, Authenticate, Consumption, Decode,
    Encode, Grant, Hold, HoldCell, Meter, MeterClassId, OriginKind, Outcome, Pass, PrincipalId,
    ReasonCode, Refusal, Route, ScopeFacts, SeatVerdict, StepName, UnitKey, Usage, UsageLine,
    VerifiedDestination, Verify,
};
use busbar_kernel::plane_driver::DriverSteps;
use busbar_kernel::registry::Generation;
use busbar_kernel::teller::{AccrualMeter, Evidence, UnitCtx};

use super::principal::principal;

/// A door-side lease: takes a count into the slip and answers whether the door held one.
pub(crate) type AdmitLease =
    Arc<dyn Fn(&busbar_kernel::slice::GroupLeaseSlip) -> bool + Send + Sync>;

pub struct TestUnits {
    pub calls: Mutex<Vec<StepName>>,

    pub refuse_at: Option<(StepName, ReasonCode)>,

    pub refuse_wait: Option<u32>,

    pub accrual: Option<Arc<HoldCell>>,

    pub zero_hold: bool,

    pub evidence: Evidence,

    pub spend: u64,

    pub meter: Arc<AccrualMeter>,

    pub refused_door: AtomicBool,

    pub admitted_door: AtomicBool,

    pub challenge: bool,

    /// Authenticate settles on the kernel's anonymous principal (an open claim's caller with no key).
    pub anonymous: bool,

    pub approved_lanes: Mutex<Vec<busbar_contract::caps::LaneId>>,

    pub seated_principals: Mutex<Vec<PrincipalId>>,

    pub groups: Vec<&'static str>,

    pub capped: Option<AdmitLease>,

    pub resolved: Option<Vec<u8>>,

    pub tap_faults: Mutex<Vec<(u32, &'static str)>>,
}

impl Default for TestUnits {
    fn default() -> Self {
        TestUnits {
            calls: Mutex::new(Vec::new()),
            refuse_at: None,
            refuse_wait: None,
            accrual: None,
            zero_hold: false,
            evidence: Evidence::default(),
            spend: 0,
            meter: Arc::new(AccrualMeter::new()),
            challenge: false,
            anonymous: false,
            refused_door: AtomicBool::new(false),
            admitted_door: AtomicBool::new(false),
            approved_lanes: Mutex::new(Vec::new()),
            seated_principals: Mutex::new(Vec::new()),
            groups: Vec::new(),
            capped: None,
            resolved: None,
            tap_faults: Mutex::new(Vec::new()),
        }
    }
}

impl TestUnits {
    pub fn passing() -> Self {
        TestUnits::default()
    }

    pub fn note(&self, step: StepName) {
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

pub fn encoded_frame() -> Encoded {
    Encoded {
        direction: busbar_contract::Direction::Outbound,
        stream: busbar_contract::StreamId(0),
        bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
        meta: busbar_contract::FrameMeta::default(),
    }
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

pub fn usage(token: &Grant<Consumption>, quantity: u64) -> Usage {
    Usage::report(
        token,
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity: quantity.into(),
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
            busbar_contract::caps::Authenticated::Principal(if self.anonymous {
                PrincipalId::anonymous()
            } else {
                principal()
            })
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

        if let Some(lease) = &self.capped {
            if !lease(leases) {
                return Err(Refusal::new(ReasonCode::RateLimited));
            }
        }

        for group in &self.groups {
            leases.counted(group);
        }
        Ok(if self.zero_hold {
            Admission::ZeroHold
        } else {
            match &self.accrual {
                None => Admission::Own(Hold::open(admit, principal.clone())),
                Some(parent) => match parent.accrue_child(principal, admit) {
                    Ok(accrual) => Admission::Accrual(accrual),

                    Err(_) => Admission::Own(Hold::open(admit, principal.clone())),
                },
            }
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

impl busbar_kernel::teller::seats::DoorSeats for TestUnits {
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
