// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The harness every test in this module drives the walk through.
//!
//! It is a node in miniature over the PRODUCTION far end: a scripted connection table, a breaker
//! with a settable state per cell, a permit store with a settable ceiling per member, a clock on
//! the harness's own paused runtime, and counters that record what was called. Nothing here talks
//! to a network or a wall clock, which is why every route — its timeouts, its one bounded wait and
//! a far end that drips its answer — answers the same way every time.
//!
//! The clock deserves its own sentence. It reads the paused runtime's time plus whatever a test
//! moved it by, so the walk's deadline, the far end's caps and a scripted far end's pace are all
//! one timeline: a far end that says nothing is cut exactly when its cap says, and a test that
//! spends the walk's budget by hand spends it without waiting.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::conn::{
    ConnError, ConnId, Conns, InstanceId, OpenDesc, Piece, PieceKind, PollConns, Ticket,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::registry::status_ns;
use busbar_contract::transport::wire::{WireStatus, WireStatusClass};
use busbar_contract::transport::ConnFacts;
use busbar_kernel_breaker::classify::{
    GRPC_ABORTED, GRPC_DATA_LOSS, GRPC_DEADLINE_EXCEEDED, GRPC_INTERNAL, GRPC_PERMISSION_DENIED,
    GRPC_RESOURCE_EXHAUSTED, GRPC_UNAUTHENTICATED, GRPC_UNAVAILABLE, GRPC_UNKNOWN,
};

use busbar_kernel_egress::ports::{
    disposition, Admit, BoxFut, Breaker, Capacity, Classified, Clock, DestinationId, Dispatched,
    Disposition, DurabilityUnavailable, Journal, Outcome, Permit, PermitHandle, Telemetry,
    Unavailable, UpstreamStatus,
};

/// The route step's pass, minted through the kernel seal as the kernel's own loop mints it; this
/// crate is the kernel, so a fixture presents a real `Pass<Route>`.
pub fn route_token() -> busbar_contract::caps::Pass<busbar_contract::caps::Route> {
    busbar_contract::caps::Pass::mint(&busbar_contract::caps::KernelSeal::acquire_for_kernel())
}

// ── the clock ───────────────────────────────────────────────────────────────────────────────────

/// A clock on the harness's paused runtime, which a test can also move by hand.
#[derive(Debug)]
pub struct TestClock {
    /// The runtime whose (paused) time this clock reads.
    handle: tokio::runtime::Handle,
    /// The runtime's time when the clock was made.
    epoch: tokio::time::Instant,
    /// The reading at the epoch, plus every hand-made move since, in milliseconds.
    offset_millis: AtomicU64,
    /// Every `ms` a caller has asked this clock to sleep for, in call order.
    pub durations: Mutex<Vec<u64>>,
}

impl TestClock {
    /// A clock reading `secs` now, on `handle`'s runtime.
    pub fn at(handle: tokio::runtime::Handle, secs: u64) -> Self {
        let epoch = {
            let _in = handle.enter();
            tokio::time::Instant::now()
        };
        Self {
            handle,
            epoch,
            offset_millis: AtomicU64::new(secs * 1000),
            durations: Mutex::new(Vec::new()),
        }
    }

    /// Move time forward by hand.
    pub fn advance_secs(&self, by: u64) {
        self.offset_millis.fetch_add(by * 1000, Ordering::Relaxed);
    }

    fn millis(&self) -> u64 {
        let ran = {
            let _in = self.handle.enter();
            tokio::time::Instant::now().duration_since(self.epoch)
        };
        self.offset_millis
            .load(Ordering::Relaxed)
            .saturating_add(u64::try_from(ran.as_millis()).unwrap_or(u64::MAX))
    }
}

impl Clock for TestClock {
    fn now_secs(&self) -> u64 {
        self.millis() / 1000
    }

    fn now_millis(&self) -> u128 {
        u128::from(self.millis())
    }

    fn sleep(&self, ms: u64) -> BoxFut<'_, ()> {
        self.durations
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(ms);
        let _in = self.handle.enter();
        Box::pin(tokio::time::sleep(Duration::from_millis(ms)))
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
    verdicts: Mutex<HashMap<WireStatus, Classified>>,
    pub log: Mutex<Vec<Recorded>>,
    /// Cells that were admitted, in order, so a test can read the pick order off the breaker.
    pub admitted: Mutex<Vec<(String, DestinationId)>>,
    /// Every status the walk actually handed the classifier, in order — the only way a test can
    /// see WHAT crossed the seam rather than only what came back across it.
    pub classified: Mutex<Vec<UpstreamStatus>>,
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

    pub fn set_verdict(&self, code: WireStatus, verdict: Classified) {
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
        // Winning the single-flight probe marks it in flight on the cell, exactly as the real one
        // does — which is what makes a probe that is never given back exclude the member from
        // every later pick.
        if health.offers_probe.is_some() {
            self.health
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(destination)
                .or_default()
                .probe_in_flight = true;
        }
        Ok(Admit {
            probe_epoch: health.offers_probe,
        })
    }

    fn ready(
        &self,
        _pool: &str,
        destination: DestinationId,
        _now: u64,
        _token: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
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
        _token: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
    ) -> u64 {
        self.health_of(destination).cooldown
    }

    fn classify(&self, _destination: DestinationId, status: UpstreamStatus) -> Classified {
        self.classified
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(status);
        // A test states a verdict per NAMESPACED code; a frame with no numeric status on it
        // reports none, so a verdict set under HTTP zero stands for "whatever this upstream
        // answered".
        let key = status.code.unwrap_or(WireStatus::new(status_ns::HTTP, 0));
        if let Some(v) = self
            .verdicts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return *v;
        }
        // No verdict was stated for this number. When there IS a number, the fallback follows the
        // spec split every real classifier makes on it — a withdrawn credential and a rate limit
        // are not the caller's fault, and folding them in with the rest of the 4xx would let this
        // fixture agree with a walk that dropped the number on the floor. Only a frame carrying no
        // number at all falls through to the coarse class below.
        // Each numbering against its own table, exactly as the real adapter does it: a gRPC code
        // never meets HTTP's bands here either, or this fixture would agree with the very fold the
        // walk must not make.
        // Each numbering is asked for BY NAME, through the keyed accessor, and answers `None` to
        // the other's question because the namespaces differ. A numbering this fixture keeps no
        // table for answers `None` to both and falls through to the coarse class, which is the
        // honest reading and cost this match nothing to acquire.
        let http = status.code.and_then(WireStatus::http);
        let grpc = status
            .code
            .and_then(WireStatus::grpc)
            .and_then(|code| u8::try_from(code).ok());
        match (http, grpc, status.class) {
            (Some(401 | 403), _, _)
            | (_, Some(GRPC_PERMISSION_DENIED | GRPC_UNAUTHENTICATED), _) => Classified {
                disposition: Disposition::HardDown,
                outcome: Outcome::HardDown,
                label: disposition::HARD_DOWN,
            },
            (Some(408 | 429), _, _)
            | (Some(500..=599), _, _)
            | (
                _,
                Some(
                    GRPC_UNKNOWN
                    | GRPC_DEADLINE_EXCEEDED
                    | GRPC_RESOURCE_EXHAUSTED
                    | GRPC_ABORTED
                    | GRPC_INTERNAL
                    | GRPC_UNAVAILABLE
                    | GRPC_DATA_LOSS,
                ),
                _,
            ) => Classified {
                disposition: Disposition::TransientUpstream,
                outcome: Outcome::Transient {
                    retry_after: status.retry_after,
                },
                label: disposition::TRANSIENT,
            },
            (Some(400..=499), _, _)
            | (_, Some(_), _)
            | (None, None, Some(WireStatusClass::CallerFault)) => Classified {
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
        _token: &busbar_contract::caps::Pass<busbar_contract::caps::Route>,
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
        // Owner-checked, as the real cell is: a release naming an epoch the cell no longer offers
        // is a late guard and must not clear a peer's live probe.
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(h) = health.get_mut(&destination) {
            if h.offers_probe == Some(epoch) {
                h.probe_in_flight = false;
            }
        }
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
    /// Slots that are released at the moment a waiter first asks for one, and not before.
    ///
    /// This is the only way to model "a slot freed while the request was parked" honestly: a slot
    /// dropped before the route runs is free at the PICK, so the walk dispatches on it and the wait
    /// terminal is never entered at all. Holding it until `acquire_any` is polled puts the release
    /// strictly after the pick recorded its at-capacity exclusions and after the depth gauge counted
    /// the waiter in.
    free_on_wait: Mutex<Vec<Permit>>,
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

    /// Take a slot now and give it back the first time a waiter asks for one — the member is at
    /// capacity at the pick and free by the time the wait terminal reaches the store.
    pub fn saturate_until_waited(&self, destination: DestinationId) {
        let permit = self.saturate(destination);
        self.free_on_wait
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(permit);
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
            // A waiter has reached the store: anything held only until the wait began is released
            // here, at the first poll, which is strictly after the park.
            let released: Vec<Permit> =
                std::mem::take(&mut *self.free_on_wait.lock().unwrap_or_else(|e| e.into_inner()));
            drop(released);
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

// ── the journal and the counters ───────────────────────────────────────────────────────────────

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

// ── the far end ─────────────────────────────────────────────────────────────────────────────────

/// One answering piece a scripted far end sends: the status class, the exact number and the wait
/// it asked for, on the answer's first piece; its body bytes.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: Option<WireStatusClass>,
    pub code: Option<WireStatus>,
    pub retry_after: Option<u64>,
    pub body: &'static str,
}

/// What one member's far end does when the walk opens a connection to it.
#[derive(Clone, Debug)]
pub enum Script {
    /// Answer with these pieces, then complete.
    Frames(Vec<Reply>),
    /// Refuse the open.
    DialError(ConnError),
    /// Open and then say nothing at all — the hang the per-attempt cap detects.
    Hang,
    /// Answer with a first piece and then drop the connection before the answer completes.
    Truncated(Reply),
    /// Answer with these pieces, `step_ms` of the runtime's time apart (the first one `step_ms`
    /// after the open): the trickle a far end produces when it sends just enough to look alive.
    /// `complete` ends the answer with its last piece; otherwise it never ends.
    Drip {
        replies: Vec<Reply>,
        step_ms: u64,
        complete: bool,
    },
}

/// An answering piece with the far end's status class on it.
pub fn frame(status: Option<WireStatusClass>, body: &'static str) -> Reply {
    frame_with_upstream(status, None, None, body)
}

/// An answering piece carrying the whole status leg a connector reads off an answer: the coarse
/// class, the exact number the far end put on it (in its numbering), and the wait it asked for.
pub fn frame_with_upstream(
    status: Option<WireStatusClass>,
    code: Option<WireStatus>,
    retry_after: Option<u64>,
    body: &'static str,
) -> Reply {
    Reply {
        status,
        code,
        retry_after,
        body,
    }
}

/// A two-piece success.
pub fn ok_frames() -> Vec<Reply> {
    vec![
        frame(Some(WireStatusClass::Success), "head"),
        frame(Some(WireStatusClass::Success), "end"),
    ]
}

/// What a read gets once a connection's scripted pieces are spent.
#[derive(Clone, Copy, Debug)]
enum Tail {
    /// Nothing more, ever (the answer completed, or the far end hangs).
    Silent,
    /// The connection drops.
    Reset,
}

/// One open connection's script, as it plays out.
struct Answer {
    /// The pieces, their bytes and when each may be read (`None`: at once).
    pieces: VecDeque<(Piece, Vec<u8>, Option<tokio::time::Instant>)>,
    tail: Tail,
    /// The timer a read that came early is waiting on, and what it waits for.
    timer: Option<(tokio::time::Instant, Pin<Box<tokio::time::Sleep>>)>,
}

fn body_piece(reply: &Reply) -> (Piece, Vec<u8>) {
    (
        Piece {
            kind: PieceKind::Body,
            stream: StreamId(0),
            len: reply.body.len(),
            end: false,
            status: reply.status,
            status_code: reply.code.map(|c| c.code),
            status_namespace: reply.code.map(|c| c.namespace.to_string()),
            retry_after_secs: reply.retry_after,
            reason: None,
        },
        reply.body.as_bytes().to_vec(),
    )
}

fn completion() -> (Piece, Vec<u8>) {
    (
        Piece {
            kind: PieceKind::Completion,
            stream: StreamId(0),
            len: 0,
            end: true,
            status: None,
            status_code: None,
            status_namespace: None,
            retry_after_secs: None,
            reason: None,
        },
        Vec::new(),
    )
}

/// A connection table whose far ends answer from a per-lane script (the target's host is
/// `<lane>.test`), recording every open.
#[derive(Default)]
pub struct TestConns {
    scripts: Mutex<HashMap<String, Script>>,
    /// Every open, in order: the lane it reached and the attempt cap it was handed, ms.
    pub opened: Mutex<Vec<(String, u64)>>,
    /// Where the body each open was handed lies: the same address is the same allocation.
    pub bodies_at: Mutex<Vec<usize>>,
    live: Mutex<HashMap<u64, Answer>>,
    next: AtomicU64,
    pub closed: AtomicU64,
}

impl TestConns {
    pub fn new() -> Self {
        Self::default()
    }

    /// What the member on this lane does when it is opened.
    pub fn script(&self, lane: &str, script: Script) {
        self.scripts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(lane.to_string(), script);
    }

    /// The lanes opened, in order.
    pub fn dialled(&self) -> Vec<String> {
        self.opened
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(lane, _)| lane.clone())
            .collect()
    }
}

impl Conns for TestConns {
    fn open(
        &self,
        _: InstanceId,
        _: busbar_contract::conn::NeedId,
        d: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let lane = d
            .target
            .split("://")
            .nth(1)
            .and_then(|r| r.split('/').next())
            .and_then(|h| h.strip_suffix(".test"))
            .unwrap_or_default()
            .to_string();
        self.opened
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((lane.clone(), d.timeout_ms));
        self.bodies_at
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(d.body.as_ptr() as usize);
        let script = self
            .scripts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&lane)
            .cloned()
            .unwrap_or_else(|| Script::Frames(ok_frames()));
        let now = tokio::time::Instant::now();
        let at = |p: (Piece, Vec<u8>), due: Option<tokio::time::Instant>| (p.0, p.1, due);
        let (pieces, tail) = match script {
            Script::DialError(e) => return Err(e),
            Script::Frames(replies) => {
                let mut pieces: VecDeque<_> =
                    replies.iter().map(|r| at(body_piece(r), None)).collect();
                pieces.push_back(at(completion(), None));
                (pieces, Tail::Silent)
            }
            Script::Hang => (VecDeque::new(), Tail::Silent),
            Script::Truncated(first) => {
                (VecDeque::from([at(body_piece(&first), None)]), Tail::Reset)
            }
            Script::Drip {
                replies,
                step_ms,
                complete,
            } => {
                let mut due = now;
                let mut pieces = VecDeque::new();
                for r in &replies {
                    due += Duration::from_millis(step_ms);
                    pieces.push_back(at(body_piece(r), Some(due)));
                }
                if complete {
                    pieces.push_back(at(completion(), Some(due)));
                }
                (pieces, Tail::Silent)
            }
        };
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        self.live.lock().unwrap_or_else(|e| e.into_inner()).insert(
            id,
            Answer {
                pieces,
                tail,
                timer: None,
            },
        );
        Ok(ConnId(id))
    }

    fn write(&self, _: InstanceId, _: ConnId, b: &[u8], _: bool) -> Result<usize, ConnError> {
        Ok(b.len())
    }

    fn read(&self, _: InstanceId, _: ConnId, _: Ticket, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Pending)
    }

    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }

    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Ok(ConnFacts::default())
    }

    fn close(&self, _: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&conn.0);
        self.closed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

impl PollConns for TestConns {
    fn poll_read(
        &self,
        _: InstanceId,
        conn: ConnId,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<Piece, ConnError>> {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let Some(answer) = live.get_mut(&conn.0) else {
            return Poll::Ready(Err(ConnError::Closed));
        };
        let Some(due) = answer.pieces.front().map(|p| p.2) else {
            return match answer.tail {
                // A silent far end never answers (and never wakes).
                Tail::Silent => Poll::Pending,
                Tail::Reset => Poll::Ready(Err(ConnError::Closed)),
            };
        };
        if let Some(due) = due {
            if tokio::time::Instant::now() < due {
                if answer.timer.as_ref().map(|(at, _)| *at) != Some(due) {
                    answer.timer = Some((due, Box::pin(tokio::time::sleep_until(due))));
                }
                if let Some((_, timer)) = answer.timer.as_mut() {
                    if timer.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                }
            }
        }
        let Some((piece, bytes, _)) = answer.pieces.pop_front() else {
            return Poll::Pending;
        };
        buf[..bytes.len()].copy_from_slice(&bytes);
        Poll::Ready(Ok(piece))
    }
}
