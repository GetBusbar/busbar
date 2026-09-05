// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Every live unit on this node, and every live session beside it.
//!
//! The in-flight table is the node's own memory of what it is doing. One slot per unit, and the
//! slot owns four things: the unit's HOLD CELL, the count of children spending against it, its
//! CANCELLATION token, and how far through the steps it got. The Teller borrows the slot while it
//! runs; exactly two callers ever take the hold out of it — the exit path, and the tick sweep — and
//! the cell makes the second one lose.
//!
//! It is also the node's admission control on itself. A unit enters the table before it does
//! anything, and if the table is full it does not enter. Two details matter and both are money:
//!
//! - A share of the table is RESERVED for provider frames of sessions that are already open. A node
//!   under load should shed new arrivals, not the paying conversation it is already having.
//! - The heartbeat sweep never occupies a slot at all. A node whose table is full still runs the
//!   thing that empties it.
//!
//! The session table next to it holds what a session is: whether its principal is cached, which
//! unit owns each direction, how many upstreams it has dialled, and when it last did anything that
//! was not a tick.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_caps::{
    step::Admit, AdmitToken, Hold, HoldCell, OriginKind, PrincipalId, ReasonCode, SessionId,
    StepName, UnitKey,
};

use busbar_contract::Framing;

use crate::pump::{Direction, StreamId};
use crate::teller::Kernel;
use crate::Millis;

/// How many upstream connections one session may pair with.
pub const MAX_SESSION_UPSTREAMS: usize = 8;

/// How many shards the tables are split across. A power of two so the shard is a mask, not a
/// division, and large enough that a busy node's units rarely queue behind each other.
pub const SHARDS: usize = 16;

/// The share of the table held back for provider frames of open sessions, in percent.
pub const RESERVE_PERCENT: usize = 10;

/// How big the reserve is: a tenth of the table where any claimed transport opens sessions, and
/// nothing at all where none does — so a node that only ever serves one-shot requests behaves
/// exactly as it did before the reserve existed.
pub fn reserve_for(cap: usize, any_session_transport: bool) -> usize {
    if any_session_transport {
        cap * RESERVE_PERCENT / 100
    } else {
        0
    }
}

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
    /// A unit that has just arrived.
    pub fn new() -> Self {
        StepState(std::sync::atomic::AtomicU8::new(step_index(
            StepName::Arrival,
        )))
    }

    /// Where it is now.
    pub fn get(&self) -> Progression {
        match self.0.load(Ordering::Acquire) {
            SUPERSEDED => Progression::Superseded,
            ENDED => Progression::Ended,
            index => Progression::At(step_at(index)),
        }
    }

    /// Move to a step. Refused once the unit has been superseded or has ended, so a step cannot
    /// resurrect a unit somebody else already closed.
    ///
    /// Compare-and-set rather than read-then-write: the interrupt runs on another task, and a plain
    /// store would let a step that read "running" a moment ago overwrite a supersede that landed in
    /// between — putting a unit somebody already replaced back on the loop, with two units relaying
    /// one direction under two holds.
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

    /// Mark the unit ended.
    pub fn end(&self) -> bool {
        self.0.swap(ENDED, Ordering::AcqRel) != ENDED
    }

    /// The interrupt: one atomic compare-and-set from "before the meter" to superseded.
    ///
    /// A unit that has already reached the meter has priced what it did, so it is too late to
    /// replace it; the compare-and-set fails, and the failure is recorded on the unit that tried,
    /// which is a no-op rather than an error.
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
    /// A token that has not been tripped.
    pub fn new() -> Self {
        CancelToken {
            tripped: AtomicBool::new(false),
            reason: AtomicUsize::new(NO_REASON),
        }
    }

    /// Stop the unit, for this reason. True if this call is the one that decided it.
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

    /// Whether the unit has been told to stop.
    pub fn is_tripped(&self) -> bool {
        self.tripped.load(Ordering::Acquire)
    }

    /// Why, if it has.
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
    step: StepState,
    cancel: CancelToken,
    marked: AtomicBool,
    last_progress: AtomicU64,
}

impl UnitSlot {
    /// Which unit this is.
    pub fn key(&self) -> UnitKey {
        self.key
    }

    /// Where it came from.
    pub fn origin(&self) -> OriginKind {
        self.origin
    }

    /// Which session it belongs to, if any.
    pub fn session(&self) -> Option<SessionId> {
        self.session
    }

    /// The unit's hold cell. Borrowed by the Teller, taken by the exit path or the sweep.
    pub fn cell(&self) -> &HoldCell {
        &self.cell
    }

    /// How far through the steps it is.
    pub fn step(&self) -> &StepState {
        &self.step
    }

    /// Its cancellation token.
    pub fn cancel(&self) -> &CancelToken {
        &self.cancel
    }

    /// Note that the unit did something: advanced a step, or relayed a frame. The sweep reads
    /// this, and reads nothing else, because those two are exactly what "making progress" means.
    pub fn touch(&self, now: Millis) {
        self.last_progress.store(now, Ordering::Release);
    }

    /// How long since it last did anything.
    pub fn idle_for(&self, now: Millis) -> Millis {
        now.saturating_sub(self.last_progress.load(Ordering::Acquire))
    }

    /// The drop guard MARKS; it never ends a unit. A marked slot whose task is gone is what the
    /// sweep turns into `TaskLost`, and marking is all a guard is allowed to do because a guard
    /// runs during an unwind, where taking a hold and settling it is exactly what must not happen.
    pub fn mark(&self) {
        self.marked.store(true, Ordering::Release);
    }

    /// Whether the guard marked it.
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
    /// Always the in-flight cap.
    pub reason: ReasonCode,
    /// The hold the unit arrived with.
    pub hold: Hold,
}

/// The door, as the in-flight table asks it for a unit's arrival hold.
///
/// The kernel does not open the hold. It lends the door its token for the length of one call —
/// exactly as the loop does at the admission step — and the door is what calls the constructor.
/// That is what makes "a hold exists only because the admission unit opened it" true of the arrival
/// hold as well as of the reservation the door later swaps in; while the table minted its own, that
/// claim had one place it was not true.
pub trait ArrivalDoor {
    /// Open the unit's arrival hold. It reserves nothing, and the door is the only thing that can
    /// open it.
    fn arrival_hold(&self, principal: PrincipalId, token: &AdmitToken<Admit>) -> Hold;
}

/// The in-memory hold a unit carries into the table, before it has reached the door.
///
/// It reserves nothing: a unit that is refused at the gate has spent nothing, and the point of the
/// arrival hold is that even a refusal is an event with a cell of its own to settle. The door swaps
/// it for the real reservation, once.
pub fn arrival_hold(kernel: &Kernel, door: &dyn ArrivalDoor, principal: PrincipalId) -> Hold {
    door.arrival_hold(principal, &kernel.admit_token())
}

/// Which step an in-flight-cap refusal is stamped at, by origin.
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
    /// Whether it is a provider frame of a session that is already open, which is what the
    /// reserve is held back for.
    pub provider_of_open_session: bool,
    /// Whether it is a zero-hold heartbeat or sweep unit, which never occupies a slot.
    pub zero_hold_tick: bool,
    /// The arrival hold minted at the door of the table.
    pub arrival: Hold,
}

/// The node's live units.
#[derive(Debug)]
pub struct InFlight {
    shards: Vec<Mutex<HashMap<UnitKey, Arc<UnitSlot>>>>,
    count: AtomicUsize,
    cap: usize,
    reserve: usize,
}

impl InFlight {
    /// A table bounded at `cap`, with `reserve` of it held back for open sessions.
    pub fn new(cap: usize, reserve: usize) -> Self {
        InFlight {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            count: AtomicUsize::new(0),
            cap,
            reserve: reserve.min(cap),
        }
    }

    /// How many units are live.
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Whether the node is doing nothing at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The cap it was built with.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// The reserve it was built with.
    pub fn reserve(&self) -> usize {
        self.reserve
    }

    /// The ceiling this unit is measured against: the whole table for a provider frame of a session
    /// that is already open and for the exempt origins, the table less the reserve for everything
    /// else.
    fn ceiling(&self, request: &Enter) -> Option<usize> {
        if request.admin_listener || request.zero_hold_tick {
            None
        } else if request.provider_of_open_session {
            Some(self.cap)
        } else {
            Some(self.cap - self.reserve)
        }
    }

    /// Would this unit fit right now?
    ///
    /// A question, not a reservation: [`InFlight::insert`] asks it and takes the slot in one atomic
    /// step, because two units that both read "there is room" and then both entered is exactly how
    /// the table stops being the bound the crash-exposure figure is computed from.
    pub fn admits(&self, request: &Enter) -> bool {
        match self.ceiling(request) {
            None => true,
            Some(ceiling) => self.len() < ceiling,
        }
    }

    /// Take a slot for a unit whose ceiling is `ceiling`, or say the table is full.
    fn claim_slot(&self, ceiling: Option<usize>) -> bool {
        match ceiling {
            None => {
                self.count.fetch_add(1, Ordering::AcqRel);
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

    /// Put a unit in the table, or hand its hold back with the refusal.
    pub fn insert(&self, request: Enter) -> Result<Arc<UnitSlot>, CapRefused> {
        if !self.claim_slot(self.ceiling(&request)) {
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
            step: StepState::new(),
            cancel: CancelToken::new(),
            marked: AtomicBool::new(false),
            last_progress: AtomicU64::new(0),
        });
        self.shard(request.key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(request.key, Arc::clone(&slot));
        Ok(slot)
    }

    /// Find a live unit.
    pub fn get(&self, key: UnitKey) -> Option<Arc<UnitSlot>> {
        self.shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .map(Arc::clone)
    }

    /// Take a unit out. The slot itself may outlive this — the exit path is holding it — but the
    /// table's count drops here, which is what lets the next unit in.
    pub fn remove(&self, key: UnitKey) -> Option<Arc<UnitSlot>> {
        let removed = self
            .shard(key)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
        if removed.is_some() {
            self.count.fetch_sub(1, Ordering::AcqRel);
        }
        removed
    }

    /// Every live unit, for the sweep. Snapshots the slots so the sweep never holds a shard lock
    /// while it settles anything.
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
    /// Which session this is.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Whether its principal is cached.
    pub fn binding(&self) -> Binding {
        self.binding
    }

    /// The cached principal, on a bound session.
    pub fn principal(&self) -> Option<PrincipalId> {
        self.principal
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Cache the principal. Only a bound session keeps one; on an unbound session this is a
    /// record of who the last unit was, which is who an accrual between turns is charged to.
    pub fn remember(&self, principal: PrincipalId) {
        *self.principal.lock().unwrap_or_else(|e| e.into_inner()) = Some(principal);
    }

    /// Forget the principal and everything about the connection's negotiated state, as an in-band
    /// upgrade does.
    pub fn clear_principal(&self) {
        *self.principal.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// Claim the one open slot for a direction of a stream.
    ///
    /// One open unit per direction, and the second one is refused rather than queued: two units
    /// relaying the same direction under two holds is two prices for one conversation.
    pub fn claim_open(
        &self,
        stream: StreamId,
        direction: Direction,
        unit: UnitKey,
    ) -> Result<(), ReasonCode> {
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        match open.entry((stream, direction)) {
            std::collections::hash_map::Entry::Occupied(_) => Err(ReasonCode::OpenSlotBusy),
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(unit);
                Ok(())
            }
        }
    }

    /// Which unit owns a direction, if any.
    pub fn open_unit(&self, stream: StreamId, direction: Direction) -> Option<UnitKey> {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(stream, direction))
            .copied()
    }

    /// Give the direction back, at the unit's end.
    pub fn release_open(&self, stream: StreamId, direction: Direction) {
        self.open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(stream, direction));
    }

    /// Pair another upstream connection with this session.
    ///
    /// The count is taken in one atomic step: two frames dialling at once must not both read the
    /// eighth slot as free.
    pub fn add_upstream(&self) -> Result<usize, ReasonCode> {
        self.upstreams
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_SESSION_UPSTREAMS).then_some(n + 1)
            })
            .map_err(|_| ReasonCode::SessionBudget)
    }

    /// How many upstreams it has paired.
    pub fn upstreams(&self) -> usize {
        self.upstreams.load(Ordering::Acquire)
    }

    /// Note a unit that was not a tick. The idle clock reads this and nothing else, so a priced
    /// accrual tick can run all night without making an idle session look busy.
    pub fn touch_non_tick(&self, now: Millis) {
        self.last_non_tick.store(now, Ordering::Release);
    }

    /// How long since the session did anything that was not a tick.
    pub fn idle_for(&self, now: Millis) -> Millis {
        now.saturating_sub(self.last_non_tick.load(Ordering::Acquire))
    }

    /// Close the session for good.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Whether it is closed.
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
    /// A session table bounded by the node-global session budget.
    pub fn new(budget: usize) -> Self {
        Sessions {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            count: AtomicUsize::new(0),
            budget,
        }
    }

    /// How many sessions are open.
    pub fn len(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Whether the node has none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Open a session, at unit zero. Refused when the node's session budget is spent.
    pub fn open(
        &self,
        id: SessionId,
        binding: Binding,
        now: Millis,
    ) -> Result<Arc<SessionSlot>, ReasonCode> {
        if self.len() >= self.budget {
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
        self.shard(id)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, Arc::clone(&slot));
        self.count.fetch_add(1, Ordering::AcqRel);
        Ok(slot)
    }

    /// Find a session.
    pub fn get(&self, id: SessionId) -> Option<Arc<SessionSlot>> {
        self.shard(id)
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&id)
            .map(Arc::clone)
    }

    /// Drop a session from the table, at close or at lease expiry.
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

    /// Every live session, for the tick.
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

/// Does this ending hard-close the session it happened on?
///
/// The provider case is the one with money in it: content an upstream will invoice arrives on a
/// session whose budget is dry, so the floor line is posted AND the session is closed, and a dry
/// bucket therefore sees at most one such push.
///
/// The framing is the transport's own declaration and it is load-bearing for exactly one arm. A
/// stream that could not decode a frame has lost sync and every later byte on it is suspect, so
/// the session closes; a datagram that could not be decoded is one datagram, and the next is
/// unaffected — it is discarded and the session stands. Without the framing this function read a
/// forged packet as a reason to drop a session, which is a denial of service anyone can post.
pub fn hard_closes(
    origin: OriginKind,
    step: StepName,
    reason: ReasonCode,
    framing: Framing,
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
        // The handoff arm. An upgrade neither leg declared leaves a session standing on a stack
        // nobody wrote down, and there is no later point at which that becomes true again.
        (_, _, ReasonCode::HandoffMismatch) => Some(HardClose::HandoffMismatch),
        (_, StepName::Decode, ReasonCode::DecodeFailed) if framing == Framing::Stream => {
            Some(HardClose::DecodeFailedOnStream)
        }
        _ => None,
    }
}
