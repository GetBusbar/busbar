// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The harness every test in this crate drives the unit through.
//!
//! It is a whole node in miniature: a scripted transport, a plane that reads the script's frames,
//! a breaker with a settable state per cell, a permit store with a settable ceiling per member, a
//! clock that never really sleeps, and counters that record what was called. Nothing here talks to
//! a network, a runtime or a wall clock, which is why the whole walk — including its one bounded
//! wait — runs on a single thread and answers the same way every time.
//!
//! The clock deserves its own sentence, because two tests depend on it exactly. `sleep(0)` is
//! ready at once; every longer sleep is pending on its first poll and ready on its second. That
//! makes a deadline lose to work that can finish now and win against work that cannot, which is
//! precisely what a real timer does and what the two race orders in the unit are written against.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::{
    AdmitFacts, ArenaBytes, AuditFacts, ContentFacts, CredentialLocator, Ctx, DestinationFacts,
    EgressBody, Frame, Ingress, Ir, Kind, Labels, LaneId, PlaneFacts, Plugin, Progress,
    Refusal, RoutePlan, ScopeFacts, SlabBytes, StreamId, TransportEnvelope, TransportKeyHandle,
    Unit, UnitEnd, UsageLocators, VerifiedDestination,
};
use busbar_contract_transport::wire::ArrivalRecord;
use busbar_contract_transport::wire::Conn;
use busbar_contract_transport::wire::ConnHandle;
use busbar_contract_transport::wire::Decode;
use busbar_contract_transport::wire::Direction;
use busbar_contract_transport::wire::Encode;
use busbar_contract_transport::wire::FrameMeta;
use busbar_contract_transport::wire::StatusClass;
use busbar_contract_transport::wire::TransportError;

use crate::ports::{
    disposition, Admit, BoxFut, Breaker, Capacity, Classified, Clock, DestinationId, Dispatched,
    Disposition, DurabilityUnavailable, EgressAuth, Journal, OutboundRequest, Outcome, Permit,
    PermitHandle, Telemetry, Unavailable, UpstreamStatus,
};

/// The kernel-side marker the fixtures present to build the views a plane reads.
pub struct TestSeal;

impl busbar_contract::plugin::KernelSeal for TestSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-unit-egress::tests"
    }
}

// ── the clock ───────────────────────────────────────────────────────────────────────────────────

/// A clock the test moves by hand.
#[derive(Debug, Default)]
pub struct TestClock {
    secs: AtomicU64,
    millis: AtomicU64,
}

impl TestClock {
    pub fn at(secs: u64) -> Self {
        Self {
            secs: AtomicU64::new(secs),
            millis: AtomicU64::new(secs * 1000),
        }
    }

    /// Move time forward.
    pub fn advance_secs(&self, by: u64) {
        self.secs.fetch_add(by, Ordering::Relaxed);
        self.millis.fetch_add(by * 1000, Ordering::Relaxed);
    }
}

impl Clock for TestClock {
    fn now_secs(&self) -> u64 {
        self.secs.load(Ordering::Relaxed)
    }

    fn now_millis(&self) -> u128 {
        u128::from(self.millis.load(Ordering::Relaxed))
    }

    fn sleep(&self, ms: u64) -> BoxFut<'_, ()> {
        Box::pin(TwoPollSleep {
            ready_now: ms == 0,
            polled: false,
        })
    }
}

struct TwoPollSleep {
    ready_now: bool,
    polled: bool,
}

impl std::future::Future for TwoPollSleep {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if self.ready_now || self.polled {
            return std::task::Poll::Ready(());
        }
        self.polled = true;
        cx.waker().wake_by_ref();
        std::task::Poll::Pending
    }
}

// ── the breaker ─────────────────────────────────────────────────────────────────────────────────

/// One member's health, as a test states it.
#[derive(Clone, Copy, Debug, Default)]
pub struct Health {
    /// Administratively down.
    pub dead: bool,
    /// Lifetime budget spent.
    pub budget_exhausted: bool,
    /// The cooldown still to run, in whole seconds. Non-zero means suppressed.
    pub cooldown: u64,
    /// A peer holds the recovery probe.
    pub probe_in_flight: bool,
    /// This member's cell is half-open and the next admission wins the probe.
    pub offers_probe: Option<u64>,
    /// How many units of lifetime budget are left. `None` is unbounded.
    pub budget_remaining: Option<i64>,
}

/// What the breaker was told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// One outcome against one cell.
    Observed(String, DestinationId, Outcome),
    /// A probe given back, owner-checked.
    ProbeReleased(String, DestinationId, u64),
    /// One unit of lifetime budget spent.
    Spent(DestinationId),
    /// One unit given back.
    Refunded(DestinationId),
}

/// A breaker whose every answer is a value the test set.
#[derive(Debug, Default)]
pub struct TestBreaker {
    health: Mutex<HashMap<DestinationId, Health>>,
    /// What the classifier answers, by upstream status class.
    verdicts: Mutex<HashMap<u16, Classified>>,
    pub log: Mutex<Vec<Recorded>>,
    /// Cells that were admitted, in order, so a test can read the pick order off the breaker.
    pub admitted: Mutex<Vec<(String, DestinationId)>>,
}

impl TestBreaker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, destination: DestinationId, health: Health) {
        self.health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(destination, health);
    }

    pub fn set_verdict(&self, code: u16, verdict: Classified) {
        self.verdicts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(code, verdict);
    }

    fn health_of(&self, destination: DestinationId) -> Health {
        self.health
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .copied()
            .unwrap_or_default()
    }

    fn record(&self, entry: Recorded) {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(entry);
    }

    /// Every outcome recorded against one cell.
    pub fn outcomes(&self, pool: &str, destination: DestinationId) -> Vec<Outcome> {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|e| match e {
                Recorded::Observed(p, d, o) if p == pool && *d == destination => Some(*o),
                _ => None,
            })
            .collect()
    }

    /// The order members were admitted in.
    pub fn pick_order(&self) -> Vec<DestinationId> {
        self.admitted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(_, d)| *d)
            .collect()
    }

    /// How many times a unit of budget was spent, minus how many were given back.
    pub fn budget_net(&self, destination: DestinationId) -> i64 {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|e| match e {
                Recorded::Spent(d) if *d == destination => 1,
                Recorded::Refunded(d) if *d == destination => -1,
                _ => 0,
            })
            .sum()
    }

    /// Every probe release, as `(pool, destination, epoch)`.
    pub fn probe_releases(&self) -> Vec<(String, DestinationId, u64)> {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter_map(|e| match e {
                Recorded::ProbeReleased(p, d, epoch) => Some((p.clone(), *d, *epoch)),
                _ => None,
            })
            .collect()
    }
}

impl Breaker for TestBreaker {
    fn try_admit(
        &self,
        pool: &str,
        destination: DestinationId,
        _now: u64,
    ) -> Result<Admit, Unavailable> {
        let health = self.health_of(destination);
        if health.dead {
            return Err(Unavailable::Dead);
        }
        if health.budget_exhausted {
            return Err(Unavailable::BudgetExhausted);
        }
        if health.probe_in_flight {
            return Err(Unavailable::ProbeInFlight);
        }
        if health.cooldown > 0 && health.offers_probe.is_none() {
            return Err(Unavailable::BreakerOpen {
                until: health.cooldown,
            });
        }
        self.admitted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((pool.to_string(), destination));
        Ok(Admit {
            probe_epoch: health.offers_probe,
        })
    }

    fn ready(
        &self,
        _pool: &str,
        destination: DestinationId,
        _now: u64,
        _token: &busbar_caps::UnitToken<busbar_caps::Route>,
    ) -> bool {
        let health = self.health_of(destination);
        !health.dead
            && !health.budget_exhausted
            && !health.probe_in_flight
            && (health.cooldown == 0 || health.offers_probe.is_some())
    }

    fn admissible(&self, destination: DestinationId) -> bool {
        let health = self.health_of(destination);
        !health.dead && !health.budget_exhausted
    }

    fn cooldown_remaining(
        &self,
        _pool: &str,
        destination: DestinationId,
        _now: u64,
        _token: &busbar_caps::UnitToken<busbar_caps::Route>,
    ) -> u64 {
        self.health_of(destination).cooldown
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        // A test states a verdict per numeric code; the harness transport reports none, so a
        // verdict set under zero stands for "whatever this upstream answered".
        let key = status.code.unwrap_or(0);
        if let Some(v) = self
            .verdicts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return *v;
        }
        match status.class {
            Some(StatusClass::ClientError) => Classified {
                disposition: Disposition::ClientFault,
                outcome: Outcome::RecordNothing,
                label: disposition::TRANSIENT,
            },
            _ => Classified {
                disposition: Disposition::TransientUpstream,
                outcome: Outcome::Transient {
                    retry_after: status.retry_after,
                },
                label: disposition::TRANSIENT,
            },
        }
    }

    fn observe(
        &self,
        pool: &str,
        destination: DestinationId,
        outcome: Outcome,
        _now: u64,
        _token: &busbar_caps::UnitToken<busbar_caps::Route>,
    ) -> bool {
        self.record(Recorded::Observed(pool.to_string(), destination, outcome));
        false
    }

    fn release_probe(&self, pool: &str, destination: DestinationId, epoch: u64, _now: u64) {
        self.record(Recorded::ProbeReleased(
            pool.to_string(),
            destination,
            epoch,
        ));
    }

    fn spend_budget(&self, destination: DestinationId) -> bool {
        let health = self.health_of(destination);
        if matches!(health.budget_remaining, Some(0)) {
            return false;
        }
        self.record(Recorded::Spent(destination));
        true
    }

    fn refund_budget(&self, destination: DestinationId) {
        self.record(Recorded::Refunded(destination));
    }
}

// ── the permit store ────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct TestPermit {
    destination: DestinationId,
    held: Arc<Mutex<HashMap<DestinationId, usize>>>,
}

impl PermitHandle for TestPermit {
    fn destination(&self) -> DestinationId {
        self.destination
    }
}

impl Drop for TestPermit {
    fn drop(&mut self) {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let slot = held.entry(self.destination).or_insert(0);
        *slot = slot.saturating_sub(1);
    }
}

/// A permit store with a ceiling per member.
#[derive(Debug, Default)]
pub struct TestCapacity {
    ceilings: Mutex<HashMap<DestinationId, usize>>,
    held: Arc<Mutex<HashMap<DestinationId, usize>>>,
}

impl TestCapacity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set how many concurrent requests a member accepts. A member with no ceiling is unbounded.
    pub fn set_ceiling(&self, destination: DestinationId, ceiling: usize) {
        self.ceilings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(destination, ceiling);
    }

    /// Take a slot and keep it, so the member is at capacity for the rest of the test.
    pub fn saturate(&self, destination: DestinationId) -> Permit {
        self.try_acquire(destination)
            .expect("the member had a free slot to saturate")
    }
}

impl Capacity for TestCapacity {
    fn try_acquire(&self, destination: DestinationId) -> Option<Permit> {
        let ceiling = self
            .ceilings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&destination)
            .copied();
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let slot = held.entry(destination).or_insert(0);
        if let Some(ceiling) = ceiling {
            if *slot >= ceiling {
                return None;
            }
        }
        *slot += 1;
        Some(Permit::new(Box::new(TestPermit {
            destination,
            held: Arc::clone(&self.held),
        })))
    }

    fn acquire_any<'a>(
        &'a self,
        destinations: &'a [DestinationId],
    ) -> BoxFut<'a, Option<(DestinationId, Permit)>> {
        Box::pin(async move {
            for destination in destinations {
                if let Some(permit) = self.try_acquire(*destination) {
                    return Some((*destination, permit));
                }
            }
            // Nothing free right now. The waiter is racing this against its bound, so staying
            // pending is what makes the bound the thing that ends the wait.
            std::future::pending::<Option<(DestinationId, Permit)>>().await
        })
    }
}

// ── the journal, the decoration, the counters ───────────────────────────────────────────────────

/// A journal that records every dispatch and can be told to fail.
#[derive(Debug, Default)]
pub struct TestJournal {
    pub dispatched: Mutex<Vec<Dispatched>>,
    pub abandoned: Mutex<Vec<Dispatched>>,
    pub fail: Mutex<bool>,
}

impl TestJournal {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Journal for TestJournal {
    fn dispatched(&self, record: &Dispatched) -> Result<(), DurabilityUnavailable> {
        if *self.fail.lock().unwrap_or_else(|e| e.into_inner()) {
            return Err(DurabilityUnavailable);
        }
        self.dispatched
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record.clone());
        Ok(())
    }

    fn abandoned(&self, record: &Dispatched) {
        self.abandoned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(record.clone());
    }
}

/// A decoration that adds one field, and can be told to move the lane.
#[derive(Debug, Default)]
pub struct TestEgressAuth {
    /// When set, the decoration writes this value into the lane field — the exact thing the lane
    /// cross-check exists to catch.
    pub rewrite_lane_to: Mutex<Option<String>>,
    pub lane_field: Mutex<Option<String>>,
}

impl TestEgressAuth {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EgressAuth for TestEgressAuth {
    fn decorate(
        &self,
        request: &mut OutboundRequest<'_>,
    ) -> Result<(), crate::ports::DecorationRefused> {
        request
            .fields
            .push(("authorization".to_string(), b"decorated".to_vec()));
        let rewrite = self
            .rewrite_lane_to
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let field = self
            .lane_field
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let (Some(value), Some(field)) = (rewrite, field) {
            for (name, slot) in request.fields.iter_mut() {
                if *name == field {
                    *slot = value.clone().into_bytes();
                }
            }
        }
        Ok(())
    }
}

/// What the counters were told.
#[derive(Debug, Default)]
pub struct TestTelemetry {
    pub attempts: Mutex<Vec<(String, DestinationId)>>,
    pub failures: Mutex<Vec<(String, DestinationId, &'static str)>>,
    pub failovers: Mutex<Vec<(String, &'static str)>>,
    pub trips: Mutex<Vec<(String, DestinationId)>>,
    pub queue_depth: Mutex<i64>,
    pub queue_parks: Mutex<usize>,
}

impl TestTelemetry {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Telemetry for TestTelemetry {
    fn upstream_attempt(&self, pool: &str, destination: DestinationId) {
        self.attempts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((pool.to_string(), destination));
    }

    fn upstream_failure(&self, pool: &str, destination: DestinationId, label: &'static str) {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((pool.to_string(), destination, label));
    }

    fn failover(&self, pool: &str, reason: &'static str) {
        self.failovers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((pool.to_string(), reason));
    }

    fn breaker_trip(&self, pool: &str, destination: DestinationId) {
        self.trips
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((pool.to_string(), destination));
    }

    fn queued(&self, _pool: &str, delta: i64) {
        let mut depth = self.queue_depth.lock().unwrap_or_else(|e| e.into_inner());
        *depth += delta;
        if delta > 0 {
            *self.queue_parks.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        }
    }
}

// ── the transport ───────────────────────────────────────────────────────────────────────────────

/// What one member does when it is dialled.
#[derive(Clone, Debug)]
pub enum Script {
    /// Answer with these frames.
    Frames(Vec<Frame>),
    /// Refuse the dial.
    DialError(TransportError),
    /// Accept the dial and then say nothing at all — the hang the per-attempt cap detects.
    Hang,
    /// Answer with a first frame and then die before the terminal one.
    Truncated(Frame),
}

/// A response frame with the transport's own status reading on it.
pub fn frame(status: Option<StatusClass>, body: &str) -> Frame {
    Frame {
        direction: Direction::Inbound,
        stream: StreamId(0),
        bytes: SlabBytes::new(Arc::from(body.as_bytes().to_vec().into_boxed_slice())),
        meta: FrameMeta {
            bytes: body.len() as u64,
            transport_units: None,
            status,
        },
    }
}

/// A two-frame success: an answer and its terminal.
pub fn ok_frames() -> Vec<Frame> {
    vec![
        frame(Some(StatusClass::Success), "head"),
        frame(Some(StatusClass::Success), "end"),
    ]
}

#[derive(Debug)]
struct TestConn(u64);

impl ConnHandle for TestConn {
    fn id(&self) -> u64 {
        self.0
    }

    fn peer(&self) -> String {
        format!("test-peer-{}", self.0)
    }
}

/// A transport that answers from a per-member script and records what it was asked to write.
#[derive(Debug, Default)]
pub struct TestTransport {
    scripts: Mutex<HashMap<String, Script>>,
    pub dialled: Mutex<Vec<String>>,
    pub written: Mutex<Vec<Vec<u8>>>,
    pub closed: Mutex<usize>,
}

impl TestTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// What the member on this lane does when it is dialled.
    pub fn script(&self, lane: &str, script: Script) {
        self.scripts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lane.to_string(), script);
    }

    fn script_for(&self, lane: &str) -> Script {
        self.scripts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(lane)
            .cloned()
            .unwrap_or_else(|| Script::Frames(ok_frames()))
    }

    fn lane_of(dest: &VerifiedDestination) -> String {
        dest.lane().map(|l| l.to_string()).unwrap_or_default()
    }
}

impl Plugin for TestTransport {
    fn key(&self) -> &'static str {
        "test-transport"
    }

    fn kind(&self) -> Kind {
        Kind::Transport
    }

    fn abi(&self) -> busbar_contract_transport::AbiVersion {
        busbar_contract_transport::AbiVersion(1)
    }
}

impl busbar_contract::Transport for TestTransport {
    fn arrival(&self, _conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: "test".to_string(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["test-transport"],
        }
    }

    fn listen<'a>(
        &'a self,
        _cfg: &'a dyn busbar_contract::TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, busbar_contract_transport::wire::Listener> {
        Box::pin(async { Err(TransportError::Refused) })
    }

    fn accept<'a>(
        &'a self,
        _l: &'a busbar_contract_transport::wire::Listener,
    ) -> busbar_contract::Fut<'a, Conn> {
        Box::pin(async { Err(TransportError::Refused) })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, Conn> {
        let lane = Self::lane_of(dest);
        Box::pin(async move {
            self.dialled
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(lane.clone());
            match self.script_for(&lane) {
                Script::DialError(e) => Err(e),
                _ => Ok(Conn::new(Arc::new(TestConn(1)))),
            }
        })
    }

    fn frames(&self, _conn: Conn) -> busbar_contract::transport::FrameStream {
        // The stream is built from the LAST dialled lane's script, which is the connection that
        // was just opened — the harness dials one member at a time, exactly as the walk does.
        let lane = self
            .dialled
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last()
            .cloned()
            .unwrap_or_default();
        match self.script_for(&lane) {
            Script::Frames(frames) => Box::pin(futures::stream::iter(
                frames.into_iter().map(|f| Ok((StreamId(0), f))),
            )),
            Script::Truncated(first) => {
                Box::pin(futures::stream::iter(vec![Ok((StreamId(0), first))]))
            }
            Script::Hang => Box::pin(futures::stream::pending()),
            Script::DialError(e) => Box::pin(futures::stream::iter(vec![Err(e)])),
        }
    }

    fn write<'a>(
        &'a self,
        _conn: &'a Conn,
        _stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> busbar_contract::Fut<'a, usize> {
        let len = bytes.len();
        Box::pin(async move {
            self.written
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(bytes.as_slice().to_vec());
            Ok(len)
        })
    }

    fn encode_envelope<'a>(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::Arena,
    ) -> Result<busbar_contract::ArenaBytes<'a>, busbar_contract_transport::wire::Encode> {
        // The fixture's own wire shape, standing in for a real transport's: every field, then the
        // body. What the tests assert is that the cross-check and the write see the SAME bytes,
        // and one buffer is what makes that true whatever the layout is.
        let mut out = Vec::new();
        for (name, value) in fields {
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value);
            out.push(b'\n');
        }
        out.push(b'\n');
        out.extend_from_slice(body);
        arena
            .alloc_bytes(&out)
            .map_err(|_| busbar_contract_transport::wire::Encode::ArenaExhausted)
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn busbar_contract::Transport,
        _conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> busbar_contract::Fut<'a, Conn> {
        Box::pin(async { Err(TransportError::HandoffMismatch) })
    }

    fn detach(&self, _conn: &Conn) -> Option<busbar_contract_transport::wire::RawStream> {
        None
    }

    fn composed_over(&self) -> Option<&'static str> {
        None
    }

    fn close(&self, _conn: Conn, _reason: busbar_contract_transport::wire::CloseReason) {
        *self.closed.lock().unwrap_or_else(|e| e.into_inner()) += 1;
    }

    fn unit0_refusal<'a>(
        &'a self,
        _conn: Conn,
        _stream: Option<busbar_contract::StreamId>,
        _refusal: &'a Refusal,
        _bytes: ArenaBytes<'a>,
    ) -> busbar_contract::Fut<'a, ()> {
        Box::pin(async { Ok(()) })
    }
}

// ── the plane ───────────────────────────────────────────────────────────────────────────────────

/// A plane that encodes a fixed body and reads the script's frames back.
///
/// It is as small as the trait allows: the unit calls exactly two of its methods on the egress
/// path, and the rest are here because the contract has no default bodies — a plane that could
/// decline to answer would be indistinguishable from one that answered.
#[derive(Debug, Default)]
pub struct TestPlane {
    /// When set, the egress encode refuses — the assemble failure the attempt bails on.
    pub refuse_encode: Mutex<bool>,
    /// The envelope field the lane name goes in, where the test wants one written.
    pub lane_field: Mutex<Option<String>>,
    pub decoded: Mutex<usize>,
}

impl TestPlane {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Plugin for TestPlane {
    fn key(&self) -> &'static str {
        "test-plane"
    }

    fn kind(&self) -> Kind {
        Kind::Plane
    }

    fn abi(&self) -> busbar_contract_transport::AbiVersion {
        busbar_contract_transport::AbiVersion(1)
    }
}

impl busbar_contract::Plane for TestPlane {
    fn decode_ingress<'u>(
        &self,
        _frames: &mut busbar_contract::FrameCursor<'u>,
        _st: Option<&mut busbar_contract::PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Ingress<'u>, Decode> {
        Ok(Ingress::NeedMore)
    }

    fn encode_egress<'u>(
        &self,
        _u: &Unit<'u>,
        dest: &VerifiedDestination,
        _st: Option<&mut busbar_contract::PlaneSessionState>,
        ctx: &Ctx<'u>,
    ) -> Result<EgressBody<'u>, Encode> {
        if *self.refuse_encode.lock().unwrap_or_else(|e| e.into_inner()) {
            return Err(Encode::Unrepresentable);
        }
        let mut envelope = TransportEnvelope::default();
        if let (Some(field), Some(lane)) = (
            self.lane_field
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            dest.lane(),
        ) {
            let name = ctx
                .arena()
                .alloc_str(&field)
                .map_err(|_| Encode::ArenaExhausted)?;
            let value = ctx
                .arena()
                .alloc_bytes(lane.as_str().as_bytes())
                .map_err(|_| Encode::ArenaExhausted)?;
            envelope
                .fields
                .push(busbar_contract::EnvelopeField { name, value })
                .map_err(|_| Encode::ArenaExhausted)?;
        }
        let body = ctx
            .arena()
            .alloc_bytes(b"request")
            .map_err(|_| Encode::ArenaExhausted)?;
        Ok(EgressBody {
            envelope,
            body,
            auth: busbar_contract::SchemeKey::new("test-scheme"),
        })
    }

    fn encode_ingress_frame<'u>(
        &self,
        _u: &Unit<'u>,
        _f: &Frame,
        _dest: &VerifiedDestination,
        _st: Option<&mut busbar_contract::PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        Ok(None)
    }

    fn decode_response<'u>(
        &self,
        frames: &mut busbar_contract::FrameCursor<'u>,
        _dest: &VerifiedDestination,
        _st: Option<&mut busbar_contract::PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Progress<'u>, Decode> {
        *self.decoded.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        let Some(frame) = frames.next_frame() else {
            return Ok(Progress::NeedMore);
        };
        let response = busbar_contract::Response {
            ir: Ir::new(&[], &[]),
            finish: if frame.bytes.as_slice() == b"end" {
                busbar_contract::FinishClass::Complete
            } else {
                busbar_contract::FinishClass::Partial
            },
            facts: busbar_contract::Facts::new(),
        };
        if frame.bytes.as_slice() == b"end" {
            Ok(Progress::Terminal {
                for_: None,
                r: response,
            })
        } else {
            Ok(Progress::Frame {
                for_: None,
                r: response,
            })
        }
    }

    fn encode_response<'u>(
        &self,
        _r: &busbar_contract::Response<'u>,
        _st: Option<&mut busbar_contract::PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        Ok(ArenaBytes::new(&[]))
    }

    fn encode_refusal<'u>(
        &self,
        _refusal: &Refusal,
        _draft: Option<&busbar_contract::UnitDraft<'u>>,
        _st: Option<&busbar_contract::PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<ArenaBytes<'u>, Encode> {
        Ok(ArenaBytes::new(&[]))
    }

    fn encode_end<'u>(
        &self,
        _u: &Unit<'u>,
        _end: &UnitEnd,
        _st: Option<&mut busbar_contract::PlaneSessionState>,
        _ctx: &Ctx<'u>,
    ) -> Result<Option<ArenaBytes<'u>>, Encode> {
        Ok(None)
    }

    fn authenticate<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> CredentialLocator {
        CredentialLocator::default()
    }

    fn verify<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> DestinationFacts {
        DestinationFacts::Upstream {
            transport: "test-transport",
            address: busbar_contract_transport::dest::UpstreamAddress::socket("test-host"),
            lane: LaneId::new("test-lane"),
        }
    }

    fn approve<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> ScopeFacts {
        ScopeFacts::default()
    }

    fn admit<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> AdmitFacts {
        AdmitFacts::default()
    }

    fn route<'u>(&self, _u: &Unit<'u>, _ctx: &Ctx<'u>) -> RoutePlan {
        RoutePlan::default()
    }

    fn meter<'u>(
        &self,
        _u: &Unit<'u>,
        _r: &busbar_contract::Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> UsageLocators {
        UsageLocators::default()
    }

    fn audit<'u>(&self, _u: &Unit<'u>, _out: &UnitEnd, _ctx: &Ctx<'u>) -> AuditFacts {
        AuditFacts {
            op_class: busbar_contract::OpClassId::new("test-op"),
            finish: busbar_contract::FinishClass::Complete,
        }
    }

    fn plane_facts<'u>(
        &self,
        _verb: busbar_contract::AdminVerbId,
        _subject: Option<&'u str>,
        _ctx: &Ctx<'u>,
    ) -> Result<PlaneFacts<'u>, Decode> {
        Ok(PlaneFacts::default())
    }

    fn content_facts<'u>(
        &self,
        _u: &Unit<'u>,
        _r: &busbar_contract::Response<'u>,
        _ctx: &Ctx<'u>,
    ) -> ContentFacts<'u> {
        ContentFacts::default()
    }
}

// ── the context ─────────────────────────────────────────────────────────────────────────────────

/// An arena that leaks. Every allocation lives for the process, which is exactly right for a test
/// and exactly wrong for a node — the real arena is fixed-size and reset per unit.
#[derive(Debug, Default)]
pub struct LeakArena;

impl busbar_contract::Arena for LeakArena {
    fn alloc_bytes<'a>(
        &'a self,
        src: &[u8],
    ) -> Result<ArenaBytes<'a>, busbar_contract::ArenaBudget> {
        Ok(ArenaBytes::new(Box::leak(src.to_vec().into_boxed_slice())))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, busbar_contract::ArenaBudget> {
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, busbar_contract::Span)],
    ) -> Result<&'a [(&'a str, busbar_contract::Span)], busbar_contract::ArenaBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

/// A configuration view with nothing in it.
#[derive(Debug, Default)]
pub struct EmptyConfig;

impl busbar_contract::ConfigView for EmptyConfig {
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

/// The transport stack under the test unit.
#[derive(Debug, Default)]
pub struct TestTransportView;

impl busbar_contract::TransportView for TestTransportView {
    fn key(&self) -> &'static str {
        "test-transport"
    }

    fn chain(&self) -> &[&'static str] {
        &["test-transport"]
    }

    fn fact(&self, _key: &str) -> Option<&str> {
        None
    }
}

/// Everything the plane is called with, owned so a test can hold it for the length of a walk.
pub struct PlaneContext {
    pub arena: LeakArena,
    pub config: EmptyConfig,
    pub transport: TestTransportView,
    pub labels: Labels<'static>,
}

impl Default for PlaneContext {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaneContext {
    pub fn new() -> Self {
        Self {
            arena: LeakArena,
            config: EmptyConfig,
            transport: TestTransportView,
            labels: Labels::new(),
        }
    }

    pub fn ctx(&self) -> Ctx<'_> {
        Ctx::new(
            busbar_contract::Clock {
                unix_secs: 0,
                monotonic_nanos: 0,
            },
            &self.config,
            None,
            &self.transport,
            &self.labels,
            &self.arena,
        )
    }
}

/// The unit the plane is handed. Built with the kernel-side marker, because a plane that could
/// build one could write its own evidence.
pub fn test_unit() -> Unit<'static> {
    Unit::new(
        &TestSeal,
        busbar_contract::UnitKey::new(1),
        busbar_contract::Origin::Client,
        None,
        Some(StreamId(0)),
        Direction::Outbound,
        None,
        busbar_contract::OpClassId::new("test-op"),
        Ir::new(&[], &[]),
        busbar_contract::bounded::Facts::new(),
        None,
    )
}

/// A sealed destination on the named lane.
pub fn sealed(lane: &'static str) -> VerifiedDestination {
    VerifiedDestination::seal(
        &TestSeal,
        DestinationFacts::Upstream {
            transport: "test-transport",
            address: busbar_contract_transport::dest::UpstreamAddress::socket("test-host"),
            lane: LaneId::new(lane),
        },
        "test-transport",
        None,
    )
}

/// The transport key material handle.
pub fn keys() -> TransportKeyHandle {
    TransportKeyHandle::issue(&TestSeal, 0, "test-fingerprint")
}
