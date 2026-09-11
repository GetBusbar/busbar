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
    Hold, HoldCell, Meter, MeterClassId, OriginKind, Outcome, PrincipalId, ReasonCode, Refusal,
    Route, ScopeFacts, StepName, UnitKey, UnitToken, Usage, UsageLine, UsageToken,
    VerifiedDestination, Verify,
};
use busbar_kernel::record::{UnitRecord, UnitViews};
use busbar_kernel::registry::Generation;
use busbar_kernel::teller::{AccrualMeter, Evidence, Kernel, UnitCtx, Units};

/// A group with a `concurrent` cap, kept the way a real door keeps one.
///
/// The kernel depends on no door, so the door's counter is modelled here — and modelled exactly:
/// a count raised while the decision is being taken, released by dropping the value the yes handed
/// back, and a refusal for anything that arrives while the count is at the cap. That shape is the
/// whole of what the fix is about. A grant nothing holds is a count released before the unit it
/// admitted has run, and the N+1th unit is then measured against a gauge that has forgotten the N
/// in flight.
pub struct CappedGroup {
    live: Arc<std::sync::atomic::AtomicUsize>,
    cap: usize,
}

impl CappedGroup {
    /// A group that will run at most `cap` units at once.
    pub fn at(cap: usize) -> Arc<Self> {
        Arc::new(CappedGroup {
            live: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cap,
        })
    }

    /// How many units this group is running right now.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Count one unit, or say the group is full. The count comes back when the answer is dropped.
    fn count_one(&self) -> Option<GroupCount> {
        self.live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.cap).then_some(n + 1)
            })
            .ok()
            .map(|_| GroupCount(Arc::clone(&self.live)))
    }
}

/// One unit's count on a [`CappedGroup`], given back by dropping it.
struct GroupCount(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for GroupCount {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

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
    /// Answer the authenticate step with a challenge instead of an identity.
    pub challenge: bool,
    /// The tier the authenticate step seals on its identity. `None` is a caller on no tier, which
    /// is every case that predates the seal.
    pub tier: Option<busbar_caps::TierId>,
    /// What each step READ off the unit's record when it ran — the step's name and the tier the
    /// record answered with. One entry per step that looked, so a cell can assert that the answer
    /// is the same one at every step rather than that it exists at one of them.
    pub tiers_seen: Mutex<Vec<(StepName, Option<String>)>>,
    /// The lanes the verified set carried when it reached the approve step.
    pub approved_lanes: Mutex<Vec<busbar_caps::LaneId>>,
    /// The capped-`concurrent` groups this door names on its yes, as the root would have interned
    /// them. Empty is the door that names none, which is every case that predates the slip.
    pub groups: Vec<&'static str>,
    /// The capped group this door enforces on its own counter, when it has one. `None` is a door
    /// whose cap is somebody else's, which is every case that predates the grant.
    pub capped: Option<Arc<CappedGroup>>,
}

impl Default for TestUnits {
    fn default() -> Self {
        TestUnits {
            calls: Mutex::new(Vec::new()),
            refuse_at: None,
            door: Door::Own(1_000),
            evidence: Evidence::default(),
            spend: 0,
            challenge: false,
            tier: None,
            tiers_seen: Mutex::new(Vec::new()),
            refused_door: AtomicBool::new(false),
            admitted_door: AtomicBool::new(false),
            approved_lanes: Mutex::new(Vec::new()),
            groups: Vec::new(),
            capped: None,
        }
    }
}

impl TestUnits {
    /// Units that let every step through.
    pub fn passing() -> Self {
        TestUnits::default()
    }

    /// Units whose door counts every unit against these capped groups and says so.
    pub fn in_groups(groups: &[&'static str]) -> Self {
        TestUnits {
            groups: groups.to_vec(),
            ..TestUnits::default()
        }
    }

    /// Units whose door enforces a `concurrent` cap on its own counter, and hands the count it
    /// took to the slot to hold.
    pub fn behind(group: &Arc<CappedGroup>) -> Self {
        TestUnits {
            capped: Some(Arc::clone(group)),
            ..TestUnits::default()
        }
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

    /// The destination set as the approve step received it — what the verify step actually sealed.
    /// What every step that looked read off the unit's record, in the order they ran.
    pub fn tiers_seen(&self) -> Vec<(StepName, Option<String>)> {
        self.tiers_seen.lock().unwrap().clone()
    }

    pub fn approved_lanes(&self) -> Vec<busbar_caps::LaneId> {
        self.approved_lanes.lock().unwrap().clone()
    }

    fn note(&self, step: StepName) {
        self.calls.lock().unwrap().push(step);
    }

    /// READ THE TIER OFF THE UNIT, as a leg does, and keep what the record answered.
    ///
    /// One expression, called from every step that is lent the record, because the claim the tier
    /// carries is "every leg reads the SAME field" and a fixture that read it two ways could not
    /// tell that claim from its opposite.
    fn saw_tier(&self, step: StepName, ctx: &UnitRecord<'_>) {
        self.tiers_seen
            .lock()
            .unwrap()
            .push((step, ctx.tier().map(|t| t.as_str().to_string())));
    }

    fn refusal(&self, step: StepName) -> Option<Refusal> {
        match self.refuse_at {
            Some((at, reason)) if at == step => Some(Refusal::new(reason)),
            _ => None,
        }
    }
}

/// THE UPSTREAM THAT IS STILL THINKING.
///
/// A Route leg that never answers, so the loop is left waiting at its one await — exactly where a
/// client that hangs up mid-request drops it. Nothing else about the plane changes: every other step
/// is [`TestUnits`]', so what the cells around this fixture measure is the await and only the await.
pub struct NeverRoutes<'u> {
    /// The plane the other nine steps come from, so the call order still reads as one unit.
    pub units: &'u TestUnits,
    /// Set when the leg's own future is dropped — the proof that cancellation reached the upstream
    /// rather than stopping at the loop.
    pub dropped: &'u AtomicBool,
}

/// The leg itself. It answers `Pending` for ever, and says so when it is dropped.
pub struct Never<'u> {
    dropped: &'u AtomicBool,
}

impl std::future::Future for Never<'_> {
    type Output = Decision<Route>;

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
        _token: &'a UnitToken<Route>,
        _ctx: &'a UnitRecord<'_>,
        _meter: &'a AccrualMeter,
    ) -> busbar_kernel::teller::RouteLeg<'a> {
        self.units.note(StepName::Route);
        Box::pin(Never {
            dropped: self.dropped,
        })
    }
}

/// A principal every test shares.
/// The arrival record the battery's kernel-owned arrival step hands forward.
pub fn arrival_record() -> busbar_caps::ArrivalRecord {
    busbar_caps::ArrivalRecord {
        source: "127.0.0.1:9".into(),
        port: 9,
        alpn: None,
        sni: None,
        peer_cert: None,
        transport_chain: vec!["battery"],
    }
}

/// What the battery's audit step seals.
pub fn audit_facts() -> busbar_caps::AuditFacts {
    busbar_caps::AuditFacts {
        op_class: busbar_caps::OpClassId::new("battery"),
        finish: busbar_contract::FinishClass::Complete,
    }
}

/// The one frame the battery's encode step produces.
pub fn encoded_frame() -> busbar_caps::Frame {
    busbar_caps::Frame {
        direction: busbar_contract::Direction::Outbound,
        stream: busbar_contract::StreamId(0),
        bytes: busbar_contract::SlabBytes::new(std::sync::Arc::from(&b""[..])),
        meta: busbar_contract::FrameMeta::default(),
    }
}

/// The door, as the table asks it for an arrival hold. The real one is the admission unit; what
/// the battery needs is only that the hold is opened by whoever holds the token, not by the table.
pub struct TestDoor;

impl busbar_kernel::inflight::ArrivalDoor for TestDoor {
    fn arrival_hold(
        &self,
        principal: PrincipalId,
        token: &busbar_caps::AdmitToken<busbar_caps::Admit>,
    ) -> Hold {
        Hold::open(token, principal, 0)
    }
}

pub fn principal() -> PrincipalId {
    PrincipalId::new("acct:battery")
}

/// The configuration block a battery unit reads: none. Every key answers `None`, which is what a
/// unit whose plane declared no schema is given.
pub struct NoConfig;

impl busbar_contract::unit::ConfigView for NoConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

/// The one-layer stack a battery unit arrives on.
pub struct Stack;

impl busbar_contract::unit::TransportView for Stack {
    fn key(&self) -> &'static str {
        "battery"
    }
    fn chain(&self) -> &[&'static str] {
        &["battery"]
    }
    fn fact(&self, _key: &str) -> Option<&str> {
        None
    }
}

static NO_CONFIG: NoConfig = NoConfig;
static STACK: Stack = Stack;
static LABELS: busbar_contract::bounded::Labels<'static> = busbar_contract::bounded::Labels::new();

/// The views a battery unit is run over, as the loop builds its context from them.
///
/// Fixed rather than varied: what every cell in this battery measures is the loop, and a view that
/// differed between two cells would be a second variable in a table that has one.
pub fn views() -> &'static UnitViews<'static> {
    static VIEWS: std::sync::OnceLock<UnitViews<'static>> = std::sync::OnceLock::new();
    VIEWS.get_or_init(|| UnitViews {
        clock: busbar_contract::unit::Clock {
            unix_secs: 1_700_000_000,
            monotonic_nanos: 0,
        },
        config: &NO_CONFIG,
        session: None,
        transport: &STACK,
        labels: &LABELS,
        key_handle: None,
    })
}

/// Open a unit's record over the battery's own memory and views, and run one thing against it.
///
/// A closure and not a value, for the reason the record's own module gives: the memory is owned by
/// the frame and the record borrows one lease of it, so the two cannot leave together.
pub fn with_record<R>(ctx: &UnitCtx, body: impl FnOnce(&UnitRecord<'_>) -> R) -> R {
    let mut memory = busbar_kernel::record::UnitMemory::new();
    let arena = memory.lease();
    body(&UnitRecord::open(ctx, views(), &arena))
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
            source: busbar_caps::QuantitySource::Count,
            estimated: false,
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
    fn arrival(&self, token: &UnitToken<Arrival>, _ctx: &UnitRecord<'_>) -> Decision<Arrival> {
        step!(self, token, Arrival, StepName::Arrival, arrival_record())
    }

    fn decode(&self, token: &UnitToken<Decode>, _ctx: &UnitRecord<'_>) -> Decision<Decode> {
        step!(
            self,
            token,
            Decode,
            StepName::Decode,
            busbar_caps::OpClassId::new("battery")
        )
    }

    fn authenticate(
        &self,
        token: &UnitToken<Authenticate>,
        _ctx: &UnitRecord<'_>,
    ) -> Decision<Authenticate> {
        let facts = if self.challenge {
            busbar_caps::Authenticated::Challenge(busbar_contract::Challenge {
                bytes: b"nonce".to_vec(),
                state: busbar_contract::ChallengeState(Vec::new()),
                rounds_left: 2,
            })
        } else {
            busbar_caps::Authenticated::Principal {
                id: principal(),
                tier: self.tier.clone(),
            }
        };
        step!(self, token, Authenticate, StepName::Authenticate, facts)
    }

    fn verify(
        &self,
        token: &UnitToken<Verify>,
        trust: &busbar_caps::TrustToken,
        ctx: &UnitRecord<'_>,
        _principal: &PrincipalId,
    ) -> Decision<Verify> {
        self.note(StepName::Verify);
        self.saw_tier(StepName::Verify, ctx);
        match self.refusal(StepName::Verify) {
            Some(refusal) => Decision::refuse(token, refusal),
            // The trust token the loop lends this step is what seals a destination, so the fixture
            // seals one: a step that answered with the empty set would exercise the loop's
            // no-destination path on every test rather than the one that names it.
            None => Decision::proceed(
                token,
                vec![VerifiedDestination::seal(
                    trust,
                    busbar_caps::LaneId::new("fixture-lane"),
                )],
            ),
        }
    }

    fn approve(
        &self,
        token: &UnitToken<Approve>,
        ctx: &UnitRecord<'_>,
        _principal: &PrincipalId,
    ) -> Decision<Approve> {
        // What Verify sealed, read off the unit. The battery records it so the cells that assert
        // which lanes reached the door are asserting against the set the loop carried, not against
        // a parameter the loop re-derived on its way there.
        self.approved_lanes
            .lock()
            .unwrap()
            .extend(ctx.verified().iter().map(|d| *d.lane()));
        self.saw_tier(StepName::Approve, ctx);
        step!(
            self,
            token,
            Approve,
            StepName::Approve,
            ScopeFacts::default()
        )
    }

    fn admit(
        &self,
        token: &UnitToken<Admit>,
        admit: &AdmitToken<Admit>,
        ctx: &UnitRecord<'_>,
        principal: &PrincipalId,
        leases: &busbar_kernel::slice::GroupLeaseSlip,
    ) -> Decision<Admit> {
        self.note(StepName::Admit);
        self.saw_tier(StepName::Admit, ctx);
        match self.refusal(StepName::Admit) {
            Some(refusal) => Decision::refuse(token, refusal),
            None => {
                // The cap, on the door's own counter, exactly where a real door takes it: as part
                // of the decision, before anything else is answered. A full group refuses, and the
                // refusal is the rate-limited one the ratified table renders a concurrency cap as.
                if let Some(group) = &self.capped {
                    let Some(counted) = group.count_one() else {
                        return Decision::refuse(token, Refusal::new(ReasonCode::RateLimited));
                    };
                    // And handed straight over, because the count is the cap and the cap has to
                    // outlive the call that took it.
                    leases.holding(busbar_kernel::slice::DoorGrant::new(counted));
                }
                // Named on the yes and only on the yes, exactly where the real door names them:
                // after the decision, never as part of it.
                for group in &self.groups {
                    leases.counted(group);
                }
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
        ctx: &UnitRecord<'_>,
        meter: &AccrualMeter,
    ) -> Decision<Route> {
        self.note(StepName::Route);
        self.saw_tier(StepName::Route, ctx);
        meter.accrue(self.spend);
        match self.refusal(StepName::Route) {
            Some(refusal) => Decision::refuse(token, refusal),
            None => Decision::proceed(token, busbar_caps::RoutePlan::default()),
        }
    }

    fn meter(
        &self,
        token: &UnitToken<Meter>,
        usage_token: &UsageToken,
        ctx: &UnitRecord<'_>,
        _provisional: &Outcome,
    ) -> Decision<Meter> {
        self.note(StepName::Meter);
        self.saw_tier(StepName::Meter, ctx);
        match self.refusal(StepName::Meter) {
            Some(refusal) => Decision::refuse(token, refusal),
            None => Decision::proceed(token, usage(usage_token, self.spend)),
        }
    }

    fn audit(
        &self,
        token: &UnitToken<Audit>,
        ctx: &UnitRecord<'_>,
        _outcome: &Outcome,
    ) -> Decision<Audit> {
        self.note(StepName::Audit);
        self.saw_tier(StepName::Audit, ctx);
        self.admitted_door.store(true, Ordering::Release);
        Decision::proceed(token, audit_facts())
    }

    fn audit_refused(
        &self,
        token: &UnitToken<Audit>,
        _ctx: &UnitRecord<'_>,
        _refusal: &Refusal,
    ) -> Decision<Audit> {
        self.calls.lock().unwrap().push(StepName::Audit);
        self.refused_door.store(true, Ordering::Release);
        Decision::proceed(token, audit_facts())
    }

    fn encode(
        &self,
        token: &UnitToken<Encode>,
        _ctx: &UnitRecord<'_>,
        _outcome: &Outcome,
    ) -> Decision<Encode> {
        self.note(StepName::Encode);
        Decision::proceed(token, encoded_frame())
    }

    fn evidence(&self, _ctx: &UnitRecord<'_>) -> Evidence {
        self.evidence.clone()
    }
}
