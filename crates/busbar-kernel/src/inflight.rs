// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::caps::{
    Admittance, CallId, Grant, Hold, HoldCell, OriginKind, PrincipalId, ReasonCode, SessionId,
    StepName, UnitKey,
};

use busbar_contract::Framing;

use crate::pump::{Direction, StreamId};
use crate::slice::LeaseCell;
use crate::teller::Kernel;
use crate::Millis;

pub use busbar_contract::MAX_SESSION_UPSTREAMS;

pub const SHARDS: usize = 16;

/// The step a unit has reached, or the fact that something took its place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progression {
    /// Running, at this step.
    At(StepName),
    /// A later unit superseded this one before it reached the meter.
    Superseded,
    /// The unit has ended.
    Ended,
}

const SUPERSEDED: u8 = 200;
const ENDED: u8 = 201;

fn step_index(step: StepName) -> u8 {
    StepName::ALL
        .iter()
        .position(|s| *s == step)
        .unwrap_or_default() as u8
}

fn step_at(index: u8) -> StepName {
    StepName::ALL[index as usize]
}

/// How far through the loop a unit is, as one atomic byte.
///
/// It is an atomic and not a field behind a lock because the interrupt path has to change it from
/// another task, once, without waiting for the unit that owns it.
#[derive(Debug)]
pub struct StepState(std::sync::atomic::AtomicU8);

impl StepState {
    pub fn new() -> Self {
        StepState(std::sync::atomic::AtomicU8::new(step_index(
            StepName::Arrival,
        )))
    }

    pub fn get(&self) -> Progression {
        match self.0.load(Ordering::Acquire) {
            SUPERSEDED => Progression::Superseded,
            ENDED => Progression::Ended,
            index => Progression::At(step_at(index)),
        }
    }

    pub fn advance_to(&self, step: StepName) -> bool {
        let wanted = step_index(step);
        let mut current = self.0.load(Ordering::Acquire);
        loop {
            if current == SUPERSEDED || current == ENDED {
                break false;
            }
            match self
                .0
                .compare_exchange_weak(current, wanted, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break true,
                Err(seen) => current = seen,
            }
        }
    }

    pub fn end(&self) -> bool {
        self.0.swap(ENDED, Ordering::AcqRel) != ENDED
    }

    pub fn supersede(&self) -> bool {
        let meter = step_index(StepName::Meter);
        loop {
            let current = self.0.load(Ordering::Acquire);
            if current >= meter {
                return false;
            }
            match self.0.compare_exchange_weak(
                current,
                SUPERSEDED,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(_) => continue,
            }
        }
    }
}

impl Default for StepState {
    fn default() -> Self {
        StepState::new()
    }
}

/// The flag that says "stop, and here is why".
///
/// Checked at every await and before every codec call. Tripping it twice keeps the first reason:
/// the first thing that decided to stop the unit is the thing that gets to say why.
#[derive(Debug)]
pub struct CancelToken {
    tripped: AtomicBool,
    reason: AtomicUsize,
}

const NO_REASON: usize = usize::MAX;

impl CancelToken {
    pub fn new() -> Self {
        CancelToken {
            tripped: AtomicBool::new(false),
            reason: AtomicUsize::new(NO_REASON),
        }
    }

    pub fn trip(&self, reason: ReasonCode) -> bool {
        let index = ReasonCode::ALL
            .iter()
            .position(|r| *r == reason)
            .unwrap_or(NO_REASON);
        if self
            .tripped
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            self.reason.store(index, Ordering::Release);
            true
        } else {
            false
        }
    }

    pub fn reason(&self) -> Option<ReasonCode> {
        let index = self.reason.load(Ordering::Acquire);
        ReasonCode::ALL.get(index).copied()
    }
}

impl Default for CancelToken {
    fn default() -> Self {
        CancelToken::new()
    }
}

/// One live unit's slot in the table.
#[derive(Debug)]
pub struct UnitSlot {
    key: UnitKey,
    origin: OriginKind,
    session: Option<SessionId>,
    cell: HoldCell,
    leases: LeaseCell,
    step: StepState,
    cancel: CancelToken,
    marked: AtomicBool,
    last_progress: AtomicU64,
    /// Whether it holds one of the table's counted slots (an exempt origin holds none).
    counted: bool,
}

impl UnitSlot {
    pub fn key(&self) -> UnitKey {
        self.key
    }

    pub fn origin(&self) -> OriginKind {
        self.origin
    }

    pub fn session(&self) -> Option<SessionId> {
        self.session
    }

    pub fn cell(&self) -> &HoldCell {
        &self.cell
    }

    pub fn leases(&self) -> &LeaseCell {
        &self.leases
    }

    pub fn step(&self) -> &StepState {
        &self.step
    }

    pub fn cancel(&self) -> &CancelToken {
        &self.cancel
    }

    pub fn touch(&self, now: Millis) {
        self.last_progress.store(now, Ordering::Release);
    }

    pub fn idle_for(&self, now: Millis) -> Millis {
        now.saturating_sub(self.last_progress.load(Ordering::Acquire))
    }

    pub fn mark(&self) {
        self.marked.store(true, Ordering::Release);
    }

    pub fn is_marked(&self) -> bool {
        self.marked.load(Ordering::Acquire)
    }
}

/// A unit that could not enter the table, with its arrival hold handed straight back.
///
/// The hold comes back rather than being dropped: refusing a unit is still an event that has to
/// balance, and the caller settles or voids what it is given.
#[derive(Debug)]
#[must_use = "the arrival hold has to be settled or voided, not dropped"]
pub struct CapRefused {
    /// The step the refusal is stamped at: arrival for a client unit, decode for every other
    /// origin, because that is where those units are constructed.
    pub step: StepName,
    /// The in-flight cap, or a unit key that is already live in the table (see
    /// [`ReasonCode::InFlightCap`] and [`ReasonCode::InFlight`]).
    pub reason: ReasonCode,
    /// The hold the unit arrived with.
    pub hold: Hold,
}

pub trait ArrivalDoor {
    fn arrival_hold(&self, principal: PrincipalId, token: &Grant<Admittance>) -> Hold;
}

pub fn arrival_hold(
    kernel: &Kernel,
    door: &dyn ArrivalDoor,
    principal: PrincipalId,
    call: CallId,
) -> Hold {
    door.arrival_hold(principal, &kernel.admit_token_for(call))
}

pub fn cap_refusal_step(origin: OriginKind) -> StepName {
    match origin {
        OriginKind::Client => StepName::Arrival,
        _ => StepName::Decode,
    }
}

/// What a unit is asking the table for.
#[derive(Debug)]
#[must_use = "the request carries the arrival hold"]
pub struct Enter {
    /// The unit's key.
    pub key: UnitKey,
    /// Where the unit came from.
    pub origin: OriginKind,
    /// Its session, if it has one.
    pub session: Option<SessionId>,
    /// Whether it arrived on the administrative listener, which is outside the cap entirely.
    pub admin_listener: bool,
    /// Whether it is a zero-hold heartbeat or sweep unit, which never occupies a slot.
    pub zero_hold_tick: bool,
    /// The arrival hold minted at the door of the table.
    pub arrival: Hold,
    /// When the unit entered. The slot's progress clock starts here, so a unit is idle from the
    /// moment it arrived and never from the moment the node booted.
    pub now: Millis,
}

/// The node's live units.
#[derive(Debug)]
pub struct InFlight {
    shards: Vec<Mutex<HashMap<UnitKey, Arc<UnitSlot>>>>,
    /// The units holding a counted slot: what the cap is measured against.
    count: AtomicUsize,
    /// The exempt units (administrative listener, heartbeat and sweep): live, never counted.
    exempt: AtomicUsize,
    cap: usize,
}

impl InFlight {
    pub fn new(cap: usize) -> Self {
        InFlight {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            count: AtomicUsize::new(0),
            exempt: AtomicUsize::new(0),
            cap,
        }
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire) + self.exempt.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    fn ceiling(&self, request: &Enter) -> Option<usize> {
        (!request.admin_listener && !request.zero_hold_tick).then_some(self.cap)
    }

    pub fn admits(&self, request: &Enter) -> bool {
        match self.ceiling(request) {
            None => true,
            Some(ceiling) => self.count.load(Ordering::Acquire) < ceiling,
        }
    }

    fn claim_slot(&self, ceiling: Option<usize>) -> bool {
        match ceiling {
            None => {
                self.exempt.fetch_add(1, Ordering::AcqRel);
                true
            }
            Some(ceiling) => self
                .count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < ceiling).then_some(n + 1)
                })
                .is_ok(),
        }
    }

    pub fn insert(&self, request: Enter) -> Result<Arc<UnitSlot>, CapRefused> {
        let mut shard = self
            .shard(request.key)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if shard.contains_key(&request.key) {
            return Err(CapRefused {
                step: cap_refusal_step(request.origin),
                reason: ReasonCode::InFlight,
                hold: request.arrival,
            });
        }
        let ceiling = self.ceiling(&request);
        if !self.claim_slot(ceiling) {
            return Err(CapRefused {
                step: cap_refusal_step(request.origin),
                reason: ReasonCode::InFlightCap,
                hold: request.arrival,
            });
        }
        let slot = Arc::new(UnitSlot {
            key: request.key,
            origin: request.origin,
            session: request.session,
            cell: HoldCell::new(request.arrival),
            leases: LeaseCell::new(),
            step: StepState::new(),
            cancel: CancelToken::new(),
            marked: AtomicBool::new(false),
            last_progress: AtomicU64::new(request.now),
            counted: ceiling.is_some(),
        });
        shard.insert(request.key, Arc::clone(&slot));
        Ok(slot)
    }

    pub fn get(&self, key: UnitKey) -> Option<Arc<UnitSlot>> {
        self.shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .map(Arc::clone)
    }

    pub fn remove(&self, key: UnitKey) -> Option<Arc<UnitSlot>> {
        let removed = self
            .shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
        if let Some(slot) = &removed {
            let held = if slot.counted {
                &self.count
            } else {
                &self.exempt
            };
            held.fetch_sub(1, Ordering::AcqRel);
        }
        removed
    }

    pub fn snapshot(&self) -> Vec<Arc<UnitSlot>> {
        let mut all = Vec::new();
        for shard in &self.shards {
            let guard = shard.lock().unwrap_or_else(|e| e.into_inner());
            all.extend(guard.values().map(Arc::clone));
        }
        all
    }

    fn shard(&self, key: UnitKey) -> &Mutex<HashMap<UnitKey, Arc<UnitSlot>>> {
        let index = (key.get() as usize) & (SHARDS - 1);
        &self.shards[index]
    }
}

/// Whether a session's principal is cached, or re-checked on every unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// The principal is cached until upgrade, revocation or a failed re-check.
    Bound,
    /// Every unit re-authenticates, and taking a credential from the session is refused.
    Unbound,
}

/// One live session.
#[derive(Debug)]
pub struct SessionSlot {
    id: SessionId,
    binding: Binding,
    principal: Mutex<Option<PrincipalId>>,
    open: Mutex<HashMap<(StreamId, Direction), UnitKey>>,
    upstreams: AtomicUsize,
    last_non_tick: AtomicU64,
    closed: AtomicBool,
}

impl SessionSlot {
    pub fn id(&self) -> SessionId {
        self.id
    }

    pub fn binding(&self) -> Binding {
        self.binding
    }

    pub fn principal(&self) -> Option<PrincipalId> {
        self.principal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn open_unit(&self, stream: StreamId, direction: Direction) -> Option<UnitKey> {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(stream, direction))
            .copied()
    }

    pub fn add_upstream(&self) -> Result<usize, ReasonCode> {
        self.upstreams
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_SESSION_UPSTREAMS).then_some(n + 1)
            })
            .map_err(|_| ReasonCode::SessionBudget)
    }

    pub fn upstreams(&self) -> usize {
        self.upstreams.load(Ordering::Acquire)
    }

    pub fn idle_for(&self, now: Millis) -> Millis {
        now.saturating_sub(self.last_non_tick.load(Ordering::Acquire))
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

/// Every live session on this node.
#[derive(Debug)]
pub struct Sessions {
    shards: Vec<Mutex<HashMap<SessionId, Arc<SessionSlot>>>>,
    count: AtomicUsize,
    budget: usize,
}

impl Sessions {
    pub fn new(budget: usize) -> Self {
        Sessions {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            count: AtomicUsize::new(0),
            budget,
        }
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn open(
        &self,
        id: SessionId,
        binding: Binding,
        now: Millis,
    ) -> Result<Arc<SessionSlot>, ReasonCode> {
        if self
            .count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < self.budget).then_some(n + 1)
            })
            .is_err()
        {
            return Err(ReasonCode::SessionBudget);
        }
        let slot = Arc::new(SessionSlot {
            id,
            binding,
            principal: Mutex::new(None),
            open: Mutex::new(HashMap::new()),
            upstreams: AtomicUsize::new(0),
            last_non_tick: AtomicU64::new(now),
            closed: AtomicBool::new(false),
        });
        let displaced = self
            .shard(id)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&slot));
        if displaced.is_some() {
            self.count.fetch_sub(1, Ordering::AcqRel);
        }
        Ok(slot)
    }

    pub fn get(&self, id: SessionId) -> Option<Arc<SessionSlot>> {
        self.shard(id)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .map(Arc::clone)
    }

    pub fn remove(&self, id: SessionId) -> Option<Arc<SessionSlot>> {
        let removed = self
            .shard(id)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&id);
        if let Some(slot) = &removed {
            slot.close();
            self.count.fetch_sub(1, Ordering::AcqRel);
        }
        removed
    }

    pub fn snapshot(&self) -> Vec<Arc<SessionSlot>> {
        let mut all = Vec::new();
        for shard in &self.shards {
            let guard = shard.lock().unwrap_or_else(|e| e.into_inner());
            all.extend(guard.values().map(Arc::clone));
        }
        all
    }

    fn shard(&self, id: SessionId) -> &Mutex<HashMap<SessionId, Arc<SessionSlot>>> {
        let index = (id.get() as usize) & (SHARDS - 1);
        &self.shards[index]
    }
}

/// Why a session is being hard-closed.
///
/// The list is closed and short on purpose. Everything else — a bad credential on an unbound
/// session, a refused unit, a decode the plane discarded — renders and the session continues,
/// because "wrong credential, try again on this connection" is a normal thing for a client to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardClose {
    /// A provider-origin unit was refused at the in-flight cap, or at the door for a money reason.
    ProviderRefusedForMoney,
    /// A frame could not be decoded on a stream transport, where the stream is now out of step.
    DecodeFailedOnStream,
    /// A plane call panicked, so the session's plane state is poisoned.
    PlanePanic,
    /// A bound session's cached principal failed its re-check.
    BoundPrincipalFailed,
    /// A credential was taken from an unbound session.
    SessionUnbound,
    /// The connection presenting the session-layer binding did not match the handoff fact.
    HandoffMismatch,
    /// The principal was revoked.
    Revoked,
}

pub fn hard_closes(
    origin: OriginKind,
    step: StepName,
    reason: ReasonCode,
    framing: Framing,
    binding: Binding,
) -> Option<HardClose> {
    let money_reason = matches!(
        reason,
        ReasonCode::OverBudget
            | ReasonCode::GroupFrozen
            | ReasonCode::Unpriced
            | ReasonCode::OverdraftCeiling
            | ReasonCode::StaleSlice
            | ReasonCode::DurabilityUnavailable
    );
    match (origin, step, reason) {
        (OriginKind::Provider, _, ReasonCode::InFlightCap) => {
            Some(HardClose::ProviderRefusedForMoney)
        }
        (OriginKind::Provider, StepName::Admit, _) if money_reason => {
            Some(HardClose::ProviderRefusedForMoney)
        }
        (_, _, ReasonCode::PlanePanic) => Some(HardClose::PlanePanic),
        (_, _, ReasonCode::SessionUnbound) => Some(HardClose::SessionUnbound),
        (_, _, ReasonCode::Revoked) => Some(HardClose::Revoked),

        (_, _, ReasonCode::HandoffMismatch) => Some(HardClose::HandoffMismatch),
        (_, StepName::Decode, ReasonCode::DecodeFailed) if framing == Framing::Stream => {
            Some(HardClose::DecodeFailedOnStream)
        }

        (_, StepName::Authenticate, ReasonCode::Unauthenticated) if binding == Binding::Bound => {
            Some(HardClose::BoundPrincipalFailed)
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests/inflight_tests.rs"]
mod inflight_tests;
