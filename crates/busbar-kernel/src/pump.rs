// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Frames in, frames out: which frame belongs to which unit, and when it is allowed to move.
//!
//! The pump is the only thing between a transport and the loop. A transport yields frames and knows
//! nothing; a plane says what a frame MEANS and holds no connection; the pump takes the plane's
//! answer and decides what happens to the unit table because of it. Its rules are short and each
//! one is a rule about money or about fairness:
//!
//! - **One open unit per direction of a stream.** A second open on an occupied direction is
//!   refused, and the refusal is rendered while the session stays up. Two units relaying one
//!   direction would be two holds over one conversation.
//! - **The interrupt is evaluated first.** A frame that supersedes the unit in flight is checked
//!   BEFORE the slot is tested, so a barge-in reaches the compare-and-set instead of bouncing off
//!   the slot it is trying to take over.
//! - **One-shots do not take the slot.** They run under a small fixed concurrency, so a burst of
//!   them cannot starve the open conversation or the node.
//! - **A body arrives before its unit opens.** Where a declared pointer sits at the end of a body,
//!   the body is spooled — against its own budget, in real bytes — and the unit opens when the
//!   deepest pointer has resolved. No pointer is ever read off a truncated document.
//! - **Emitted frames are paced.** On a stream transport an overrun becomes backpressure; on a
//!   datagram transport the frame is dropped and journaled as unemitted. Only emitted frames are
//!   metered.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use busbar_caps::{ReasonCode, SessionId, StepName, UnitKey};

use crate::grammar::{resolve_pointer, DeepestPointer, Resolved};
use crate::inflight::{InFlight, SessionSlot};
use crate::Nanos;

/// How many one-shot units may run at once beside the open unit.
pub const DEFAULT_ONE_SHOT_K: usize = 4;

/// A stream, a direction and a frame, as the contract crate declares them.
///
/// A transport writes all three, so all three arrive from outside the kernel; the pump reads what
/// it was handed rather than a restatement of it.
pub use busbar_contract::{Direction, Frame, StreamId, MAX_NEEDMORE_FRAMES};

/// What the plane made of a frame.
///
/// This is the pump's input, not the plane's trait: the contract's own `Ingress` and `Progress`
/// are richer and borrow the frame buffer, and the pump only needs to know which of these shapes it
/// was. It is a reduction of them, not a second spelling: nothing outside the kernel writes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// Not a whole anything yet.
    NeedMore,
    /// A unit opens here, and relays frames until it closes.
    Open {
        /// The unit this one supersedes, where the plane's interrupt fact named one.
        interrupt: Option<UnitKey>,
    },
    /// A whole unit in one frame.
    OneShot,
    /// A protocol handshake unit.
    Handshake,
    /// A frame belonging to a unit that is already open.
    Relay,
    /// The end of an open unit.
    Close,
    /// The last frame from an upstream.
    Terminal,
    /// Not ours: drop it, count it, change nothing.
    Discard,
}

/// What the pump decided to do about a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// Nothing yet: keep reading.
    Wait,
    /// Open a unit that will hold the direction until it closes.
    OpenUnit,
    /// Open a unit that takes no slot.
    OpenOneShot,
    /// Open a handshake unit. No money moves in one, so it neither takes the slot nor counts
    /// against the one-shot concurrency.
    OpenHandshake,
    /// Supersede the unit in flight, then open in its place.
    Supersede {
        /// The unit being replaced.
        target: UnitKey,
        /// Whether the compare-and-set won. A loss is recorded on the superseding unit and is not
        /// an error: the target had already priced what it did.
        won: bool,
    },
    /// Hand the frame to the unit that owns the direction.
    RelayTo(UnitKey),
    /// End the unit that owns the direction.
    CloseUnit(UnitKey),
    /// Drop the frame and count it into the window's aggregate.
    Drop,
    /// Refuse, at this step, for this reason. Rendered; the session stays open.
    Refuse {
        /// Where the refusal is stamped.
        step: StepName,
        /// Why.
        reason: ReasonCode,
    },
}

/// The scheduler: the open slot, the one-shot concurrency, and the interrupt.
#[derive(Debug)]
pub struct Scheduler {
    one_shots: AtomicUsize,
    k: usize,
    /// How many frames in a row a session has answered "not a whole anything yet" with.
    ///
    /// A session appears here only while it is in such a run: the first frame that IS something
    /// takes it out again, so the map is bounded by the sessions currently stalling, which the
    /// session budget already bounds.
    needmore: Mutex<HashMap<SessionId, usize>>,
}

impl Scheduler {
    /// A scheduler allowing `k` one-shot units at once.
    pub fn new(k: usize) -> Self {
        Scheduler {
            one_shots: AtomicUsize::new(0),
            k,
            needmore: Mutex::new(HashMap::new()),
        }
    }

    /// Count one more consecutive "not yet" for a session, and say whether the run is past the
    /// ceiling. A session with no slot — a one-shot transport — has no run to keep.
    fn ask_again(&self, session: Option<&SessionSlot>) -> bool {
        let Some(session) = session else {
            return false;
        };
        let mut runs = self.needmore.lock().unwrap_or_else(|e| e.into_inner());
        let run = runs.entry(session.id()).or_insert(0);
        *run += 1;
        *run > MAX_NEEDMORE_FRAMES
    }

    /// A frame that was something ends the run.
    fn made_progress(&self, session: Option<&SessionSlot>) {
        if let Some(session) = session {
            self.needmore
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&session.id());
        }
    }

    /// How many one-shots are running.
    pub fn one_shots(&self) -> usize {
        self.one_shots.load(Ordering::Acquire)
    }

    /// Take a one-shot permit, if there is one.
    pub fn start_one_shot(&self) -> bool {
        let mut current = self.one_shots.load(Ordering::Acquire);
        loop {
            if current >= self.k {
                return false;
            }
            match self.one_shots.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(seen) => current = seen,
            }
        }
    }

    /// Give a one-shot permit back.
    pub fn finish_one_shot(&self) {
        let _ = self
            .one_shots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
    }

    /// Decide what happens to one frame.
    ///
    /// `session` is `None` for a one-shot transport, which has no session and therefore no open
    /// slot to contend for.
    pub fn dispatch(
        &self,
        session: Option<&SessionSlot>,
        in_flight: &InFlight,
        stream: StreamId,
        direction: Direction,
        shape: Shape,
    ) -> Dispatch {
        // A frame that is something ends whatever run of "not yet" came before it.
        if shape != Shape::NeedMore {
            self.made_progress(session);
        }
        match shape {
            // The handshake framing ceiling, enforced where it can be: a peer that never finishes a
            // frame otherwise holds its session slot for as long as it likes. The run is counted per
            // session and consecutively, so a slow-but-progressing peer never meets it.
            Shape::NeedMore if self.ask_again(session) => Dispatch::Refuse {
                step: StepName::Decode,
                reason: ReasonCode::Stalled,
            },
            Shape::NeedMore => Dispatch::Wait,
            Shape::Discard => Dispatch::Drop,
            Shape::Handshake => Dispatch::OpenHandshake,
            Shape::OneShot => {
                if self.start_one_shot() {
                    Dispatch::OpenOneShot
                } else {
                    Dispatch::Wait
                }
            }
            Shape::Open { interrupt } => {
                // The interrupt is evaluated BEFORE the slot check, on purpose: a superseding open
                // on an occupied direction has to reach the compare-and-set.
                if let Some(target) = interrupt {
                    let won = in_flight
                        .get(target)
                        .map(|slot| slot.step().supersede())
                        .unwrap_or(false);
                    if won {
                        if let Some(session) = session {
                            session.release_open(stream, direction);
                        }
                    }
                    return Dispatch::Supersede { target, won };
                }
                match session {
                    None => Dispatch::OpenUnit,
                    Some(session) => match session.open_unit(stream, direction) {
                        None => Dispatch::OpenUnit,
                        Some(_) => Dispatch::Refuse {
                            step: StepName::Decode,
                            reason: ReasonCode::OpenSlotBusy,
                        },
                    },
                }
            }
            Shape::Relay | Shape::Terminal => {
                match session.and_then(|s| s.open_unit(stream, direction)) {
                    Some(unit) => Dispatch::RelayTo(unit),
                    None => Dispatch::Drop,
                }
            }
            Shape::Close => match session.and_then(|s| s.open_unit(stream, direction)) {
                Some(unit) => Dispatch::CloseUnit(unit),
                None => Dispatch::Drop,
            },
        }
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Scheduler::new(DEFAULT_ONE_SHOT_K)
    }
}

/// The bounded pool nested units run in, and the depth bound on nesting.
///
/// A parent's route blocks on its child's end, so a node with more parents than child permits is a
/// node that has stopped. The permit count is what keeps that from happening: parents wait for a
/// permit rather than deadlocking on each other, and the count of parents waiting is a number the
/// battery can read.
#[derive(Debug)]
pub struct NestedPool {
    permits: AtomicUsize,
    blocked: AtomicUsize,
    size: usize,
    max_depth: usize,
}

/// A nested child's place in the pool. Give it back when the child ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a permit that is never given back shrinks the pool for good"]
pub struct NestedPermit {
    /// How deep the child is.
    pub depth: usize,
}

impl NestedPool {
    /// A pool of `size` concurrent children, nested at most `max_depth` deep.
    pub fn new(size: usize, max_depth: usize) -> Self {
        NestedPool {
            permits: AtomicUsize::new(size),
            blocked: AtomicUsize::new(0),
            size,
            max_depth,
        }
    }

    /// How many children could still start.
    pub fn available(&self) -> usize {
        self.permits.load(Ordering::Acquire)
    }

    /// How many parents are waiting on a permit.
    pub fn blocked(&self) -> usize {
        self.blocked.load(Ordering::Acquire)
    }

    /// The pool's size.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Try to start a child at `depth`.
    ///
    /// Refused past the depth bound, which is checked at boot too, over the graph of which plane
    /// may nest into which.
    pub fn enter(&self, depth: usize) -> Result<NestedPermit, ReasonCode> {
        if depth >= self.max_depth {
            return Err(ReasonCode::ScopeDenied);
        }
        match self
            .permits
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
        {
            Ok(_) => Ok(NestedPermit { depth }),
            Err(_) => {
                self.blocked.fetch_add(1, Ordering::AcqRel);
                Err(ReasonCode::InFlightCap)
            }
        }
    }

    /// Give a permit back, and wake one waiting parent's accounting.
    pub fn leave(&self, _permit: NestedPermit) {
        self.permits.fetch_add(1, Ordering::AcqRel);
        let _ = self
            .blocked
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
    }
}

/// Whether frames on this transport can be held back, or only dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// A stream: an overrun becomes backpressure on whatever is producing.
    Stream,
    /// A datagram: there is nowhere to push back to, so an overrun is a dropped frame.
    Datagram,
}

/// What the emission clock says about the next frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Emission {
    /// Send it now.
    Send,
    /// Wait this long first. Stream transports only.
    Backpressure {
        /// Nanoseconds to wait.
        wait: Nanos,
    },
    /// Drop it, and journal it as unemitted. Datagram transports only. An unemitted frame is
    /// never metered: the client did not get it, so nobody pays for it.
    Unemitted,
}

/// One emission clock per direction of a stream: the pace a plane declared, and a bounded queue.
#[derive(Debug)]
pub struct EmissionClock {
    ns_per_frame: Nanos,
    next_at: Nanos,
    depth: usize,
    queue_cap: usize,
    kind: TransportKind,
}

impl EmissionClock {
    /// A clock pacing one frame every `ns_per_frame`, queueing at most `queue_cap` frames.
    pub fn new(ns_per_frame: Nanos, queue_cap: usize, kind: TransportKind) -> Self {
        EmissionClock {
            ns_per_frame,
            next_at: 0,
            depth: 0,
            queue_cap,
            kind,
        }
    }

    /// How many frames are queued.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Offer a frame at `now`.
    pub fn offer(&mut self, now: Nanos) -> Emission {
        if now >= self.next_at && self.depth == 0 {
            self.next_at = now.saturating_add(self.ns_per_frame);
            return Emission::Send;
        }
        if self.depth < self.queue_cap {
            self.depth += 1;
            let wait = self.next_at.saturating_sub(now);
            self.next_at = self.next_at.saturating_add(self.ns_per_frame);
            // Inside the queue both kinds behave the same: the frame waits its turn.
            return Emission::Backpressure { wait };
        }
        match self.kind {
            TransportKind::Stream => Emission::Backpressure {
                wait: self.next_at.saturating_sub(now),
            },
            TransportKind::Datagram => Emission::Unemitted,
        }
    }

    /// A queued frame left for the connection.
    pub fn emitted(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

/// The node-global budget for spooled request bodies, counted in real bytes.
///
/// Sized at exactly what was buffered before there was a budget, so no request that used to be
/// served is refused by its existence.
#[derive(Debug)]
pub struct SpillBudget {
    used: AtomicUsize,
    cap: usize,
}

impl SpillBudget {
    /// A budget of `cap` bytes.
    pub fn new(cap: usize) -> Self {
        SpillBudget {
            used: AtomicUsize::new(0),
            cap,
        }
    }

    /// How many bytes are spooled node-wide.
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// Take `bytes` of it.
    pub fn take(&self, bytes: usize) -> Result<(), ReasonCode> {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            if current + bytes > self.cap {
                return Err(ReasonCode::SpillBudget);
            }
            match self.used.compare_exchange_weak(
                current,
                current + bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(seen) => current = seen,
            }
        }
    }

    /// Give bytes back when the body is encoded or the unit ends.
    pub fn give_back(&self, bytes: usize) {
        let _ = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                Some(n.saturating_sub(bytes))
            });
    }
}

/// A body arriving in chunks, and the question "can the unit open yet?".
///
/// The unit opens when the deepest declared pointer has resolved, or when the declared length ends.
/// Until then the chunks are spooled and the scanner is re-run over the longer prefix. This is why
/// a body whose lane key is serialised last still prices correctly: the pointer is simply not
/// resolved until the bytes that hold it have arrived.
#[derive(Debug)]
pub struct BodySpool {
    bytes: Vec<u8>,
    declared_length: Option<usize>,
    deepest: DeepestPointer,
    resolved: bool,
}

impl BodySpool {
    /// A spool for a body of a declared length, or of none where the length is not declared.
    pub fn new(declared_length: Option<usize>, deepest: DeepestPointer) -> Self {
        BodySpool {
            bytes: Vec::new(),
            declared_length,
            deepest,
            resolved: matches!(deepest, DeepestPointer::None),
        }
    }

    /// What has been spooled so far.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// How much.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether nothing has arrived.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Add a chunk, charged to the node's spill budget in actual bytes.
    pub fn push(&mut self, chunk: &[u8], budget: &SpillBudget) -> Result<(), ReasonCode> {
        budget.take(chunk.len())?;
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }

    /// Re-run the declared pointer over everything spooled so far.
    ///
    /// Returns whether the unit may open now.
    pub fn try_resolve(&mut self, pointer: &str) -> bool {
        if self.resolved {
            return true;
        }
        self.resolved = match self.deepest {
            DeepestPointer::None => true,
            DeepestPointer::EndOfBody => self.length_complete(),
            DeepestPointer::Offset(_) => {
                matches!(resolve_pointer(&self.bytes, pointer), Resolved::Found(_))
                    || self.length_complete()
            }
        };
        self.resolved
    }

    /// Whether the body is as long as it said it would be.
    pub fn length_complete(&self) -> bool {
        match self.declared_length {
            Some(length) => self.bytes.len() >= length,
            None => false,
        }
    }

    /// Whether the unit may open.
    pub fn ready(&self) -> bool {
        self.resolved
    }

    /// Hand the spooled bytes back to the budget at the unit's end.
    pub fn release(self, budget: &SpillBudget) {
        budget.give_back(self.bytes.len());
    }
}
