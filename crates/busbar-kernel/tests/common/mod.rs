// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The stand-in units the battery drives the loop with.
//!
//! Every unit behind a sealed trait is replaced here by one that records that it was called and
//! answers what the test told it to answer. That is the whole harness: the loop under test is the
//! real one, the money types are the real ones, and only the units are fakes.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use busbar_caps::{
    Admission, Admit, AdmitToken, Approve, Arrival, Audit, Authenticate, Decision, Decode, Encode,
    Hold, HoldCell, Meter, MeterClassId, OriginKind, Outcome, Principal, ReasonCode, Refusal,
    Route, ScopeFacts, StepName, UnitKey, UnitToken, Usage, UsageLine, UsageToken,
    VerifiedDestination, Verify,
};
use busbar_kernel::registry::Generation;
use busbar_kernel::teller::{AccrualMeter, Evidence, Kernel, UnitCtx, Units};

/// What the fake door answers.
pub enum Door {
    /// Open a hold of this size.
    Own(u64),
    /// Spend this much against a parent's hold in this cell.
    Accrual(Arc<HoldCell>, u64),
    /// Hold nothing.
    Zero,
}

/// The units the battery drives the loop with.
pub struct TestUnits {
    /// Every step the loop called, in the order it called them.
    pub calls: Mutex<Vec<StepName>>,
    /// Refuse at this step, with this reason.
    pub refuse_at: Option<(StepName, ReasonCode)>,
    /// What the door answers.
    pub door: Door,
    /// What the settlement table reads at the exit.
    pub evidence: Evidence,
    /// How much the route step spends.
    pub spend: u64,
    /// Whether the door for a unit that never passed the door was used.
    pub refused_door: AtomicBool,
    /// Whether the door for a unit that DID pass was used.
    pub admitted_door: AtomicBool,
}

impl Default for TestUnits {
    fn default() -> Self {
        TestUnits {
            calls: Mutex::new(Vec::new()),
            refuse_at: None,
            door: Door::Own(1_000),
            evidence: Evidence::default(),
            spend: 0,
            refused_door: AtomicBool::new(false),
            admitted_door: AtomicBool::new(false),
        }
    }
}

impl TestUnits {
    /// Units that let every step through.
    pub fn passing() -> Self {
        TestUnits::default()
    }

    /// Units that refuse at `step` for `reason`.
    pub fn refusing(step: StepName, reason: ReasonCode) -> Self {
        TestUnits {
            refuse_at: Some((step, reason)),
            ..TestUnits::default()
        }
    }

    /// The steps the loop called.
    pub fn called(&self) -> Vec<StepName> {
        self.calls.lock().unwrap().clone()
    }

    /// Which audit door the unit left through.
    pub fn doors(&self) -> (bool, bool) {
        (
            self.refused_door.load(Ordering::Acquire),
            self.admitted_door.load(Ordering::Acquire),
        )
    }

    fn note(&self, step: StepName) {
        self.calls.lock().unwrap().push(step);
    }

    fn refusal(&self, step: StepName) -> Option<Refusal> {
        match self.refuse_at {
            Some((at, reason)) if at == step => Some(Refusal::new(reason)),
            _ => None,
        }
    }
}

/// A principal every test shares.
pub fn principal() -> Principal {
    Principal::new("acct:battery")
}

/// A context for a client unit.
pub fn ctx(key: u64) -> UnitCtx {
    UnitCtx {
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

/// A cell holding an arrival hold, ready for the door.
pub fn cell(kernel: &Kernel) -> HoldCell {
    HoldCell::new(Hold::open(&kernel.admit_token(), principal(), 0))
}

/// A usage report of one line, for tests that need one directly.
pub fn usage(token: &UsageToken, quantity: u64) -> Usage {
    Usage::report(
        token,
        vec![UsageLine {
            class: MeterClassId::new("nano_units"),
            quantity,
        }],
    )
    .expect("one line is within the bound")
}

macro_rules! step {
    ($self:ident, $token:ident, $marker:ty, $name:expr, $facts:expr) => {{
        $self.note($name);
        match $self.refusal($name) {
            Some(refusal) => Decision::<$marker>::refuse($token, refusal),
            None => Decision::<$marker>::proceed($token, $facts),
        }
    }};
}

impl Units for TestUnits {
    fn arrival(&self, token: &UnitToken<Arrival>, _ctx: &UnitCtx) -> Decision<Arrival> {
        step!(
            self,
            token,
            Arrival,
            StepName::Arrival,
            busbar_caps::ArrivalFacts
        )
    }

    fn decode(&self, token: &UnitToken<Decode>, _ctx: &UnitCtx) -> Decision<Decode> {
        step!(
            self,
            token,
            Decode,
            StepName::Decode,
            busbar_caps::DecodeFacts
        )
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        _ctx: &UnitCtx,
    ) -> Decision<Authenticate> {
        step!(
            self,
            token,
            Authenticate,
            StepName::Authenticate,
            principal()
        )
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        _ctx: &UnitCtx,
        _principal: &Principal,
    ) -> Decision<Verify> {
        self.note(StepName::Verify);
        match self.refusal(StepName::Verify) {
            Some(refusal) => Decision::refuse(token, refusal),
            None => Decision::proceed(token, Vec::<VerifiedDestination>::new()),
        }
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        _ctx: &UnitCtx,
        _principal: &Principal,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Approve> {
        step!(self, token, Approve, StepName::Approve, ScopeFacts)
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        _ctx: &UnitCtx,
        principal: &Principal,
        _destinations: &[VerifiedDestination],
    ) -> Decision<Admit> {
        self.note(StepName::Admit);
        match self.refusal(StepName::Admit) {
            Some(refusal) => Decision::refuse(token, refusal),
            None => {
                let admission = match &self.door {
                    Door::Own(size) => Admission::Own(Hold::open(admit, principal.clone(), *size)),
                    Door::Zero => Admission::ZeroHold,
                    Door::Accrual(parent, amount) => {
                        match parent.accrue_child(principal, *amount, admit) {
                            Ok(accrual) => Admission::Accrual(accrual),
                            // A refused accrual falls back to the child's own hold, which is what
                            // the loop does when the parent has already exited.
                            Err(_) => Admission::Own(Hold::open(admit, principal.clone(), *amount)),
                        }
                    }
                };
                Decision::proceed(token, admission)
            }
        }
    }

    fn route(
        &self,
        token: &UnitToken<Route>,
        _ctx: &UnitCtx,
        meter: &AccrualMeter,
    ) -> Decision<Route> {
        self.note(StepName::Route);
        meter.accrue(self.spend);
        match self.refusal(StepName::Route) {
            Some(refusal) => Decision::refuse(token, refusal),
            None => Decision::proceed(token, busbar_caps::RouteFacts),
        }
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage_token: &UsageToken,
        _ctx: &UnitCtx,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        self.note(StepName::Meter);
        match self.refusal(StepName::Meter) {
            Some(refusal) => Decision::refuse(token, refusal),
            None => Decision::proceed(token, usage(usage_token, self.spend)),
        }
    }

    fn audit(
        &self,
        token: &UnitToken<Audit>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Audit> {
        self.note(StepName::Audit);
        self.admitted_door.store(true, Ordering::Release);
        Decision::proceed(token, busbar_caps::AuditFacts)
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        _ctx: &UnitCtx,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        self.calls.lock().unwrap().push(StepName::Audit);
        self.refused_door.store(true, Ordering::Release);
        Decision::proceed(token, busbar_caps::AuditFacts)
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        _ctx: &UnitCtx,
        _outcome: &Outcome,
    ) -> Decision<Encode> {
        self.note(StepName::Encode);
        Decision::proceed(token, busbar_caps::EncodeFacts)
    }

    fn evidence(&self, _ctx: &UnitCtx) -> Evidence {
        self.evidence.clone()
    }
}
