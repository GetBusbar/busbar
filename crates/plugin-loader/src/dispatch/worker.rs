// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE WORKERS: where ticketed ops cross, pend, wake, resume, time out and are cancelled.
//!
//! * TICKETS. Each worker owns a slab; [`Dispatcher::mint`] hands out `(slot, generation)` with the
//!   worker in the slot's high bits (`ticket`). [`Dispatcher::recycle`] bumps the generation (at
//!   once when the ticket is idle, else when its last op ends).
//! * ONE TICKET, ONE OP AT A TIME. Ops submitted on a ticket run in submission order, never
//!   overlapping; ops on distinct tickets are independent. `open`/`refresh`/`retire`/`close` never
//!   overlap on one instance (a second one while one is in flight answers REFUSED without a call);
//!   `tick` and `drive` run alongside request ops.
//! * PENDING. The frame stays where it is (boxed, never the worker's scratch). A wake resumes it:
//!   the SAME op, the SAME ticket, the SAME `in`/`out`, with `FLAG_RESUME`. Wakes are LATCHED (a
//!   wake that arrives before the op answered PENDING resumes it at once) and SPURIOUS-TOLERANT (a
//!   resumed op that is still not ready answers PENDING again). A wake for a stale generation is
//!   dropped and counted. A non-zero `wake_at_ns` is a timer: the op is resumed then without a wake.
//! * DRIVER TICKETS ([`Dispatcher::driver`]): persistent, owned by the instance, outside
//!   `max_inflight`. A wake on one calls `drive`; a PENDING drive resumes like any op.
//! * DEADLINE CLASSES. Call, Stream and Connection: when `deadline_ns` passes with the op pending,
//!   the host calls `cancel` (ticket-less: it may not pend) and answers the kind's timeout outcome;
//!   a client drop does the same. WriteBehind is NEVER cancelled — not by its deadline, a client
//!   drop or a reload: at its deadline the caller stops waiting (the reply answers the timeout
//!   outcome, `detached`), the ticket stays, and a later wake still completes it. A reload drain
//!   ([`Dispatcher::drain`]) never waits on WriteBehind ops: they carry over to the new generation.
//! * THE WATCHDOG (`watchdog`): an op that does not RETURN within its class budget faults its
//!   instance and replaces its worker; see there for what happens to every ticket.

use std::collections::VecDeque;
use std::mem::size_of;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, Weak};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{DeadlineClass, InHead, OutHead, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::lifecycle::{slot, CancelIn, CancelOut, DriveIn};
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::plugin::{is_lifecycle, Crossed, Instance, Plugin};
use super::ticket::{
    decode, encode, next_generation, Completions, WakeRoute, MAX_INDEX, MAX_WORKERS,
};
use super::{in_head, now_ns, out_head, watchdog, Frame, InFrame, Kind, OutFrame};

/// The longest a crossing may take before the watchdog faults it, per class. A crossing never
/// blocks by contract, so these bound a wedged plugin, not a slow request (that is the deadline).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budgets {
    /// Call-class crossings (and `tick`).
    pub call: Duration,
    /// Stream-class crossings.
    pub stream: Duration,
    /// Connection-class crossings (and `drive`).
    pub connection: Duration,
    /// WriteBehind-class crossings.
    pub write_behind: Duration,
    /// `validate`, `open`, `refresh`, `retire` and `close`.
    pub lifecycle: Duration,
}

impl Default for Budgets {
    fn default() -> Self {
        Self {
            call: Duration::from_secs(1),
            stream: Duration::from_secs(1),
            connection: Duration::from_secs(1),
            write_behind: Duration::from_secs(5),
            lifecycle: Duration::from_secs(30),
        }
    }
}

impl Budgets {
    pub(crate) fn of(&self, s: u32, class: DeadlineClass) -> Duration {
        if s == slot::VALIDATE || is_lifecycle(s) {
            return self.lifecycle;
        }
        match class {
            DeadlineClass::Call => self.call,
            DeadlineClass::Stream => self.stream,
            DeadlineClass::Connection => self.connection,
            DeadlineClass::WriteBehind => self.write_behind,
        }
    }
}

/// A dispatcher's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchConfig {
    /// How many workers (clamped to `1..=4096`).
    pub workers: u32,
    /// The watchdog's budgets.
    pub budgets: Budgets,
    /// How often the watchdog looks.
    pub watchdog_period: Duration,
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            budgets: Budgets::default(),
            watchdog_period: Duration::from_millis(50),
        }
    }
}

/// What the dispatcher counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchStats {
    /// Wakes dropped: a stale generation, a recycled slot, an unknown worker or index.
    pub stale_wakes: u64,
    /// Workers the watchdog replaced.
    pub replacements: u64,
    /// WriteBehind ops that completed after their caller stopped waiting.
    pub write_behind_late: u64,
}

#[derive(Debug, Default)]
pub(crate) struct Stats {
    stale_wakes: AtomicU64,
    pub(crate) replacements: AtomicU64,
    write_behind_late: AtomicU64,
}

/// What a worker thread needs besides its worker.
pub(crate) struct Env {
    pub(crate) budgets: Budgets,
    pub(crate) stats: Arc<Stats>,
    pub(crate) completions: Arc<Completions<Vec<u8>>>,
}

/// One op's completion.
#[derive(Debug)]
pub struct Done<I, O> {
    /// The authoritative outcome.
    pub outcome: Outcome,
    /// The error text, copied, for FAILED/REFUSED.
    pub error: Option<Vec<u8>>,
    /// A lease for `release`; `0` = none.
    pub lease: u64,
    /// The frame, back to its owner; `None` when the op was faulted mid-crossing or detached.
    pub frame: Option<Box<Frame<I, O>>>,
    /// A WriteBehind op whose caller stopped waiting at its deadline; it runs on.
    pub detached: bool,
    /// A FAILED answer the kind calls SHORT: re-submit ONCE on the same ticket with bigger
    /// buffers; a second short answer is FAULT (the short-buffer rule on `OutHead`).
    pub short: bool,
    /// When the op ended through `cancel` (a deadline or a client drop): the kind's disposition
    /// `CancelOut.disposition` answered (store: 0 UNKNOWN, 1 NOT_APPLIED, 2 APPLIED). A `cancel`
    /// that FAULTed makes the op FAULT, with no disposition.
    pub disposition: Option<u32>,
}

struct ReplySlot<T> {
    v: Mutex<(bool, Option<T>)>,
    cv: Condvar,
}

impl<T> ReplySlot<T> {
    fn new() -> Self {
        Self {
            v: Mutex::new((false, None)),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, (bool, Option<T>)> {
        self.v.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The FIRST answer wins; `false` when one was already given.
    fn put(&self, t: T) -> bool {
        let mut g = self.lock();
        if g.0 {
            return false;
        }
        *g = (true, Some(t));
        self.cv.notify_all();
        true
    }
}

/// Settling a reply without its frame (a fault, a timeout, a detach).
pub(crate) trait Settle: Send + Sync {
    fn settle(&self, outcome: Outcome, detached: bool) -> bool;
}

impl<I: InFrame, O: OutFrame> Settle for ReplySlot<Done<I, O>> {
    fn settle(&self, outcome: Outcome, detached: bool) -> bool {
        self.put(Done {
            outcome,
            error: None,
            lease: 0,
            frame: None,
            detached,
            short: false,
            disposition: None,
        })
    }
}

/// The caller's end of one op.
pub struct Reply<I, O> {
    slot: Arc<ReplySlot<Done<I, O>>>,
}

impl<I, O> std::fmt::Debug for Reply<I, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply").finish_non_exhaustive()
    }
}

impl<I: InFrame, O: OutFrame> Reply<I, O> {
    /// Wait up to `timeout` for the completion.
    pub fn wait(&self, timeout: Duration) -> Option<Done<I, O>> {
        let until = Instant::now() + timeout;
        let mut g = self.slot.lock();
        loop {
            if let Some(d) = g.1.take() {
                return Some(d);
            }
            let left = until.checked_duration_since(Instant::now())?;
            g = self
                .slot
                .cv
                .wait_timeout(g, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn settled(outcome: Outcome, frame: Frame<I, O>) -> Self {
        let slot = Arc::new(ReplySlot::new());
        slot.put(Done {
            outcome,
            error: None,
            lease: 0,
            frame: Some(Box::new(frame)),
            detached: false,
            short: false,
            disposition: None,
        });
        Self { slot }
    }
}

/// A submitted op's frame and reply, kind-erased.
pub(crate) trait Job: Send {
    fn heads(&mut self) -> (*mut InHead, *mut OutHead, u32);
    /// Deliver the answer with the frame; `false` when the caller already had one (detached).
    fn finish(self: Box<Self>, c: Crossed) -> bool;
}

struct JobOf<I, O> {
    frame: Box<Frame<I, O>>,
    reply: Arc<ReplySlot<Done<I, O>>>,
}

impl<I: InFrame, O: OutFrame> Job for JobOf<I, O> {
    fn heads(&mut self) -> (*mut InHead, *mut OutHead, u32) {
        self.frame.heads()
    }

    fn finish(self: Box<Self>, c: Crossed) -> bool {
        self.reply.put(Done {
            outcome: c.outcome,
            error: c.error,
            lease: c.lease,
            frame: Some(self.frame),
            detached: false,
            short: c.short,
            disposition: c.disposition,
        })
    }
}

/// What an op holds while it is in flight; dropping it gives everything back — the `max_inflight`
/// unit, the drain count, the lifecycle exclusion — and settles an unanswered reply as FAULT.
pub(crate) struct Meta {
    pub(crate) instance: Arc<Instance>,
    slot: u32,
    class: DeadlineClass,
    deadline_ns: u64,
    in_size: u32,
    /// The `max_inflight` units it holds: one, or all of them for `close`.
    units: u32,
    lifecycle: bool,
    drainable: bool,
    pub(crate) reply: Arc<dyn Settle>,
}

impl Drop for Meta {
    fn drop(&mut self) {
        self.reply.settle(Outcome::Fault, false);
        self.instance.release(self.units);
        if self.drainable {
            self.instance.drainable.fetch_sub(1, Ordering::AcqRel);
        }
        if self.lifecycle {
            self.instance.leave_lifecycle();
        }
    }
}

pub(crate) struct Current {
    pub(crate) meta: Meta,
    /// `None` while the frame is out on a crossing.
    job: Option<Box<dyn Job>>,
    pending: bool,
    wake_at_ns: u64,
    detached: bool,
}

pub(crate) struct Driver {
    instance: Arc<Instance>,
    /// `None` while out on a crossing.
    frame: Option<Box<Frame<DriveIn, OutHead>>>,
    pending: bool,
    wake_at_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Start,
    Resume,
    Cancel,
    Drive,
}

#[derive(Default)]
pub(crate) struct Entry {
    pub(crate) generation: u32,
    live: bool,
    latched: bool,
    client_dropped: bool,
    recycle_when_idle: bool,
    /// The op whose last answer was SHORT: its next answer on this ticket is the one re-call.
    short_slot: Option<u32>,
    next: Option<Action>,
    pub(crate) current: Option<Current>,
    pub(crate) queue: VecDeque<(Meta, Box<dyn Job>)>,
    pub(crate) driver: Option<Driver>,
}

#[derive(Default)]
pub(crate) struct WorkerState {
    pub(crate) dead: bool,
    pub(crate) entries: Vec<Entry>,
    free: Vec<u32>,
    runnable: VecDeque<u32>,
}

pub(crate) enum Msg {
    Submit {
        ticket: Ticket,
        meta: Meta,
        job: Box<dyn Job>,
    },
    Wake(Ticket),
    DropClient(Ticket),
    Recycle(Ticket),
    Stop,
}

/// The crossing a worker is inside, for the watchdog.
pub(crate) struct CrossingRecord {
    pub(crate) started: Instant,
    pub(crate) budget: Duration,
    pub(crate) instance: Arc<Instance>,
}

/// One worker incarnation. The watchdog replaces a wedged one with a fresh incarnation at the same
/// index.
pub(crate) struct Worker {
    pub(crate) index: u32,
    tx: Sender<Msg>,
    pub(crate) state: Mutex<WorkerState>,
    pub(crate) crossing: Mutex<Option<CrossingRecord>>,
}

pub(crate) struct WorkerSlot {
    pub(crate) current: RwLock<Arc<Worker>>,
}

impl WorkerSlot {
    pub(crate) fn get(&self) -> Arc<Worker> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// The dispatcher's shared state. Worker threads never hold it (no cycle); instances reach it by a
/// `Weak` for `wake`, the watchdog by a `Weak`.
pub(crate) struct Pool {
    pub(crate) slots: Box<[WorkerSlot]>,
    pub(crate) env: Arc<Env>,
    pub(crate) stop: AtomicBool,
    /// Every instance this dispatcher adopted, for the watchdog's ticket-less scan.
    pub(crate) adopted: Mutex<Vec<Weak<Instance>>>,
}

impl WakeRoute for Pool {
    /// Route a wake to the worker its slot names. Never blocks on the plugin: a channel push.
    fn wake(&self, t: Ticket) {
        let (w, _) = decode(t.slot);
        match self.slots.get(w as usize) {
            Some(slot) => {
                let _ = slot.get().tx.send(Msg::Wake(t));
            }
            None => {
                self.env.stats.stale_wakes.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

impl Pool {
    fn send(&self, t: Ticket, m: Msg) {
        let (w, _) = decode(t.slot);
        if let Some(slot) = self.slots.get(w as usize) {
            // A worker whose thread is gone drops the message; a `Submit`'s `Meta` then settles FAULT.
            let _ = slot.get().tx.send(m);
        }
    }
}

impl Worker {
    /// A fresh incarnation at `index`, its slab's generations `gens` (every slot free).
    pub(crate) fn new(index: u32, gens: Vec<u32>) -> (Arc<Self>, Receiver<Msg>) {
        let (tx, rx) = channel();
        let n = gens.len() as u32;
        let state = WorkerState {
            entries: gens
                .into_iter()
                .map(|generation| Entry {
                    generation,
                    ..Entry::default()
                })
                .collect(),
            free: (0..n).rev().collect(),
            ..WorkerState::default()
        };
        let w = Arc::new(Self {
            index,
            tx,
            state: Mutex::new(state),
            crossing: Mutex::new(None),
        });
        (w, rx)
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, WorkerState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn ticket(&self, idx: u32, generation: u32) -> Ticket {
        Ticket {
            slot: encode(self.index, idx),
            generation,
        }
    }

    fn mint(&self, driver: Option<Driver>) -> Option<Ticket> {
        let mut st = self.lock();
        if st.dead {
            return None;
        }
        let idx = match st.free.pop() {
            Some(i) => i,
            None if (st.entries.len() as u32) < MAX_INDEX => {
                st.entries.push(Entry {
                    generation: 1,
                    ..Entry::default()
                });
                st.entries.len() as u32 - 1
            }
            None => return None,
        };
        let e = &mut st.entries[idx as usize];
        e.live = true;
        e.driver = driver;
        let generation = e.generation;
        Some(self.ticket(idx, generation))
    }

    /// The live entry `t` names on this worker, if its generation is current.
    fn entry<'a>(&self, st: &'a mut WorkerState, t: Ticket) -> Option<(u32, &'a mut Entry)> {
        let (w, idx) = decode(t.slot);
        let e = st.entries.get_mut(idx as usize)?;
        (w == self.index && e.live && e.generation == t.generation).then_some((idx, e))
    }

    fn schedule(st: &mut WorkerState, idx: u32, a: Action) {
        let e = &mut st.entries[idx as usize];
        match e.next {
            None => {
                e.next = Some(a);
                st.runnable.push_back(idx);
            }
            Some(_) if a == Action::Cancel => e.next = Some(a),
            Some(_) => {}
        }
    }

    /// Apply one message; `false` on Stop.
    fn apply(&self, st: &mut WorkerState, m: Msg, env: &Env) -> bool {
        match m {
            Msg::Submit { ticket, meta, job } => match self.entry(st, ticket) {
                Some((idx, e)) if !e.client_dropped && e.driver.is_none() => {
                    e.queue.push_back((meta, job));
                    if e.current.is_none() {
                        Self::schedule(st, idx, Action::Start);
                    }
                }
                Some((_, e)) if e.client_dropped => {
                    meta.reply.settle(Outcome::Refused, false);
                }
                // A stale or foreign ticket: `meta` drops and settles FAULT.
                _ => drop(meta),
            },
            Msg::Wake(t) => match self.entry(st, t) {
                None => {
                    env.stats.stale_wakes.fetch_add(1, Ordering::Relaxed);
                }
                Some((idx, e)) => {
                    if e.driver.is_some() {
                        Self::schedule(st, idx, Action::Drive);
                    } else if e.current.as_ref().is_some_and(|c| c.pending) {
                        Self::schedule(st, idx, Action::Resume);
                    } else {
                        // LATCHED: the op has not answered PENDING yet (or none is running).
                        e.latched = true;
                    }
                }
            },
            Msg::DropClient(t) => {
                if let Some((idx, e)) = self.entry(st, t) {
                    e.client_dropped = true;
                    let (keep, gone): (VecDeque<_>, VecDeque<_>) = std::mem::take(&mut e.queue)
                        .into_iter()
                        .partition(|(m, _)| m.class == DeadlineClass::WriteBehind);
                    e.queue = keep;
                    for (m, _) in gone {
                        m.reply.settle(m.instance.timeout, false);
                    }
                    let cancel = e
                        .current
                        .as_ref()
                        .is_some_and(|c| c.meta.class != DeadlineClass::WriteBehind);
                    if cancel {
                        Self::schedule(st, idx, Action::Cancel);
                    }
                }
            }
            Msg::Recycle(t) => {
                if let Some((idx, e)) = self.entry(st, t) {
                    e.driver = None;
                    if e.current.is_none() && e.queue.is_empty() {
                        self.recycle_now(st, idx, env);
                    } else {
                        e.recycle_when_idle = true;
                    }
                }
            }
            Msg::Stop => return false,
        }
        true
    }

    fn recycle_now(&self, st: &mut WorkerState, idx: u32, env: &Env) {
        let e = &mut st.entries[idx as usize];
        env.completions.forget(self.ticket(idx, e.generation));
        e.generation = next_generation(e.generation);
        e.live = false;
        e.latched = false;
        e.client_dropped = false;
        e.recycle_when_idle = false;
        e.short_slot = None;
        e.next = None;
        e.driver = None;
        st.free.push(idx);
    }

    /// The op on `idx` is over: answer it, give back what it held, start the next.
    fn end(&self, st: &mut WorkerState, idx: u32, mut c: Crossed, env: &Env) {
        let e = &mut st.entries[idx as usize];
        let Some(cur) = e.current.take() else {
            return;
        };
        e.latched = false;
        // THE ONE RE-CALL: a short answer may be re-asked once on this ticket; short twice is FAULT.
        let recall = e.short_slot.take() == Some(cur.meta.slot);
        if c.short && recall {
            c = Crossed::host(Outcome::Fault);
        } else if c.short {
            e.short_slot = Some(cur.meta.slot);
        }
        if let Some(job) = cur.job {
            if !job.finish(c) {
                env.stats.write_behind_late.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(cur.meta);
        if !e.queue.is_empty() {
            Self::schedule(st, idx, Action::Start);
        } else if e.recycle_when_idle {
            self.recycle_now(st, idx, env);
        }
    }

    /// Due deadlines and timers; the wait until the next one.
    fn timers(&self, st: &mut WorkerState, now: u64) -> Duration {
        let mut next = u64::MAX;
        let mut due = Vec::new();
        for (idx, e) in st.entries.iter_mut().enumerate() {
            if let Some(c) = e.current.as_mut().filter(|c| c.pending) {
                let (class, deadline) = (c.meta.class, c.meta.deadline_ns);
                if deadline != 0 && class != DeadlineClass::WriteBehind {
                    if now >= deadline {
                        due.push((idx as u32, Action::Cancel));
                        continue;
                    }
                    next = next.min(deadline);
                }
                if deadline != 0 && class == DeadlineClass::WriteBehind && !c.detached {
                    if now >= deadline {
                        // The caller stops WAITING; the op keeps its ticket and runs on.
                        c.detached = c.meta.reply.settle(c.meta.instance.timeout, true);
                    } else {
                        next = next.min(deadline);
                    }
                }
                if c.wake_at_ns != 0 {
                    if now >= c.wake_at_ns {
                        c.wake_at_ns = 0;
                        due.push((idx as u32, Action::Resume));
                    } else {
                        next = next.min(c.wake_at_ns);
                    }
                }
            }
            if let Some(d) = e.driver.as_mut().filter(|d| d.pending && d.wake_at_ns != 0) {
                if now >= d.wake_at_ns {
                    d.wake_at_ns = 0;
                    due.push((idx as u32, Action::Drive));
                } else {
                    next = next.min(d.wake_at_ns);
                }
            }
        }
        for (idx, a) in due {
            Self::schedule(st, idx, a);
        }
        Duration::from_nanos(next.saturating_sub(now)).min(Duration::from_millis(100))
    }

    fn begin_crossing(&self, instance: Arc<Instance>, budget: Duration) {
        *self.crossing.lock().unwrap_or_else(|e| e.into_inner()) = Some(CrossingRecord {
            started: Instant::now(),
            budget,
            instance,
        });
    }

    fn end_crossing(&self) {
        *self.crossing.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// One crossing with the state unlocked; `None` when the watchdog replaced this worker
    /// meanwhile (the caller exits).
    fn cross<'a>(
        &'a self,
        st: MutexGuard<'a, WorkerState>,
        instance: &Arc<Instance>,
        s: u32,
        heads: (*mut InHead, *mut OutHead, u32),
        budget: Duration,
    ) -> Option<(MutexGuard<'a, WorkerState>, Crossed)> {
        self.begin_crossing(instance.clone(), budget);
        drop(st);
        // SAFETY: the frame is boxed and owned by this crossing; `s` passed `refuse` at submit.
        let crossed = unsafe { instance.cross(s, heads.0, heads.1, heads.2) };
        self.end_crossing();
        let st = self.lock();
        (!st.dead).then_some((st, crossed))
    }

    /// Run the action scheduled for `idx`. `None` when this worker was replaced mid-crossing.
    fn run_one<'a>(
        &'a self,
        mut st: MutexGuard<'a, WorkerState>,
        idx: u32,
        env: &Env,
    ) -> Option<MutexGuard<'a, WorkerState>> {
        let e = &mut st.entries[idx as usize];
        let Some(action) = e.next.take() else {
            return Some(st);
        };
        let generation = e.generation;
        let ticket = self.ticket(idx, generation);
        match action {
            Action::Start => {
                if e.current.is_some() {
                    return Some(st);
                }
                let Some((meta, mut job)) = e.queue.pop_front() else {
                    return Some(st);
                };
                let inst = meta.instance.clone();
                let expired = meta.class != DeadlineClass::WriteBehind
                    && meta.deadline_ns != 0
                    && now_ns() >= meta.deadline_ns;
                let early = if inst.faulted.load(Ordering::Acquire) {
                    Some(Outcome::Fault)
                } else if expired {
                    Some(inst.timeout)
                } else {
                    None
                };
                let heads = job.heads();
                // SAFETY: the job's boxed frame; its head leads the `in`.
                unsafe {
                    let h = &mut *heads.0;
                    h.size = meta.in_size;
                    h.flags = 0;
                    h.deadline_class = meta.class as u8;
                    h.ticket = ticket;
                    h.deadline_ns = meta.deadline_ns;
                }
                let (s, budget) = (meta.slot, env.budgets.of(meta.slot, meta.class));
                e.current = Some(Current {
                    meta,
                    job: Some(job),
                    pending: false,
                    wake_at_ns: 0,
                    detached: false,
                });
                if let Some(o) = early {
                    self.end(&mut st, idx, Crossed::host(o), env);
                    return Some(st);
                }
                self.cross_current(st, idx, &inst, s, budget, env)
            }
            Action::Resume => {
                let Some(cur) = e.current.as_mut().filter(|c| c.pending) else {
                    return Some(st);
                };
                cur.pending = false;
                let inst = cur.meta.instance.clone();
                let (s, budget) = (cur.meta.slot, env.budgets.of(cur.meta.slot, cur.meta.class));
                if inst.faulted.load(Ordering::Acquire) {
                    self.end(&mut st, idx, Crossed::host(Outcome::Fault), env);
                    return Some(st);
                }
                if let Some(job) = cur.job.as_mut() {
                    // SAFETY: as above.
                    unsafe { (*job.heads().0).flags = FLAG_RESUME };
                }
                self.cross_current(st, idx, &inst, s, budget, env)
            }
            Action::Cancel => {
                let Some(cur) = e.current.as_mut() else {
                    return Some(st);
                };
                cur.pending = false;
                let inst = cur.meta.instance.clone();
                let class = cur.meta.class;
                let timeout = inst.timeout;
                if inst.faulted.load(Ordering::Acquire) {
                    self.end(&mut st, idx, Crossed::host(Outcome::Fault), env);
                    return Some(st);
                }
                // `cancel` may not pend: its head carries NONE; the cancelled ticket is its field.
                let mut frame = Frame::new(
                    CancelIn {
                        head: in_head(),
                        ticket,
                    },
                    CancelOut {
                        head: out_head(),
                        disposition: 0,
                        _reserved: 0,
                    },
                );
                frame.input.head.size = size_of::<CancelIn>() as u32;
                frame.input.head.deadline_class = class as u8;
                let budget = env.budgets.of(slot::CANCEL, class);
                let (mut st, c) = self.cross(st, &inst, slot::CANCEL, frame.heads(), budget)?;
                // The op answers the kind's timeout with `cancel`'s disposition; a `cancel` that
                // FAULTed makes the op FAULT.
                let ended = if c.outcome == Outcome::Fault {
                    Crossed::host(Outcome::Fault)
                } else {
                    Crossed {
                        disposition: Some(frame.out.disposition),
                        ..Crossed::host(timeout)
                    }
                };
                self.end(&mut st, idx, ended, env);
                Some(st)
            }
            Action::Drive => {
                let Some(d) = e.driver.as_mut() else {
                    return Some(st);
                };
                let inst = d.instance.clone();
                if inst.faulted.load(Ordering::Acquire) || !inst.is_open() {
                    return Some(st);
                }
                let Some(mut frame) = d.frame.take() else {
                    return Some(st);
                };
                frame.input.head.size = size_of::<DriveIn>() as u32;
                frame.input.head.flags = if d.pending { FLAG_RESUME } else { 0 };
                frame.input.head.deadline_class = DeadlineClass::Connection as u8;
                frame.input.head.ticket = ticket;
                frame.input.driver = ticket;
                d.pending = false;
                let budget = env.budgets.of(slot::DRIVE, DeadlineClass::Connection);
                let (mut st, c) = self.cross(st, &inst, slot::DRIVE, frame.heads(), budget)?;
                let e = &mut st.entries[idx as usize];
                if e.generation == generation {
                    if let Some(d) = e.driver.as_mut() {
                        d.frame = Some(frame);
                        d.pending = c.outcome == Outcome::Pending;
                        d.wake_at_ns = c.wake_at_ns;
                        if d.pending && std::mem::take(&mut e.latched) {
                            Self::schedule(&mut st, idx, Action::Drive);
                        }
                    }
                }
                Some(st)
            }
        }
    }

    fn cross_current<'a>(
        &'a self,
        mut st: MutexGuard<'a, WorkerState>,
        idx: u32,
        inst: &Arc<Instance>,
        s: u32,
        budget: Duration,
        env: &Env,
    ) -> Option<MutexGuard<'a, WorkerState>> {
        let cur = st.entries[idx as usize].current.as_mut()?;
        let mut job = cur.job.take()?;
        let heads = job.heads();
        let (mut st, c) = self.cross(st, inst, s, heads, budget)?;
        let e = &mut st.entries[idx as usize];
        let Some(cur) = e.current.as_mut() else {
            return Some(st);
        };
        cur.job = Some(job);
        if c.outcome == Outcome::Pending {
            cur.pending = true;
            cur.wake_at_ns = c.wake_at_ns;
            if std::mem::take(&mut e.latched) {
                Self::schedule(&mut st, idx, Action::Resume);
            }
        } else {
            self.end(&mut st, idx, c, env);
        }
        Some(st)
    }

    /// Settle everything this worker holds as FAULT (shutdown, or the watchdog replaced it).
    pub(crate) fn fault_all(st: &mut WorkerState) -> Vec<Entry> {
        st.runnable.clear();
        st.free.clear();
        std::mem::take(&mut st.entries)
    }
}

/// THE WORKER LOOP: messages, then timers, then one runnable action; sleep until the next timer
/// or message.
pub(crate) fn run(w: Arc<Worker>, rx: Receiver<Msg>, env: Arc<Env>) {
    let mut st = w.lock();
    loop {
        if st.dead {
            return;
        }
        let mut stop = false;
        while let Ok(m) = rx.try_recv() {
            stop |= !w.apply(&mut st, m, &env);
        }
        if stop {
            st.dead = true;
            let gone = Worker::fault_all(&mut st);
            drop(st);
            drop(gone);
            return;
        }
        let wait = w.timers(&mut st, now_ns());
        if let Some(idx) = st.runnable.pop_front() {
            match w.run_one(st, idx, &env) {
                Some(g) => st = g,
                None => return,
            }
            continue;
        }
        drop(st);
        let m = rx.recv_timeout(wait);
        st = w.lock();
        match m {
            Ok(m) => {
                if !w.apply(&mut st, m, &env) {
                    st.dead = true;
                    let gone = Worker::fault_all(&mut st);
                    drop(st);
                    drop(gone);
                    return;
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

pub(crate) fn spawn_worker(w: Arc<Worker>, rx: Receiver<Msg>, env: Arc<Env>) {
    let name = format!("busbar-dispatch-{}", w.index);
    std::thread::Builder::new()
        .name(name)
        .spawn(move || run(w, rx, env))
        .expect("spawn a dispatch worker");
}

/// A dispatcher's adoption handle ([`Dispatcher::adopter`]), held by a [`super::Bind`].
#[derive(Clone)]
pub struct Adopter {
    pool: Weak<Pool>,
}

impl std::fmt::Debug for Adopter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Adopter").finish_non_exhaustive()
    }
}

impl Adopter {
    /// TEST ONLY: an adopter of no dispatcher; the instance is adopted by the first dispatcher
    /// that submits to it.
    #[cfg(test)]
    pub(crate) fn unwatched() -> Self {
        Self { pool: Weak::new() }
    }

    /// Route `inst`'s wakes to the dispatcher and put it under its watchdog; `false` when the
    /// instance already belongs to another dispatcher (or this one is gone).
    pub(crate) fn adopt(&self, inst: &Arc<Instance>) -> bool {
        let Some(pool) = self.pool.upgrade() else {
            return false;
        };
        let route: Arc<dyn WakeRoute> = pool.clone();
        let mine = Arc::downgrade(&route);
        let bound = inst.wake.route.get_or_init(|| {
            pool.adopted
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Arc::downgrade(inst));
            mine.clone()
        });
        Weak::ptr_eq(bound, &mine)
    }
}

/// THE DISPATCHER: its workers and its watchdog.
pub struct Dispatcher {
    pool: Arc<Pool>,
}

impl std::fmt::Debug for Dispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dispatcher")
            .field("workers", &self.pool.slots.len())
            .finish_non_exhaustive()
    }
}

impl Dispatcher {
    /// Workers and a watchdog, per `config`.
    pub fn new(config: DispatchConfig) -> Self {
        let n = config.workers.clamp(1, MAX_WORKERS);
        let env = Arc::new(Env {
            budgets: config.budgets,
            stats: Arc::default(),
            completions: Arc::default(),
        });
        let mut started = Vec::new();
        let slots = (0..n)
            .map(|i| {
                let (w, rx) = Worker::new(i, Vec::new());
                started.push((w.clone(), rx));
                WorkerSlot {
                    current: RwLock::new(w),
                }
            })
            .collect();
        let pool = Arc::new(Pool {
            slots,
            env: env.clone(),
            stop: AtomicBool::new(false),
            adopted: Mutex::new(Vec::new()),
        });
        for (w, rx) in started {
            spawn_worker(w, rx, env.clone());
        }
        watchdog::spawn(Arc::downgrade(&pool), config.watchdog_period);
        Self { pool }
    }

    /// How many workers.
    pub fn workers(&self) -> u32 {
        self.pool.slots.len() as u32
    }

    /// What the dispatcher counted.
    pub fn stats(&self) -> DispatchStats {
        let s = &self.pool.env.stats;
        DispatchStats {
            stale_wakes: s.stale_wakes.load(Ordering::Relaxed),
            replacements: s.replacements.load(Ordering::Relaxed),
            write_behind_late: s.write_behind_late.load(Ordering::Relaxed),
        }
    }

    /// The completion handles of this dispatcher's tickets.
    pub fn completions(&self) -> &Completions<Vec<u8>> {
        &self.pool.env.completions
    }

    fn worker(&self, worker: u32) -> Option<Arc<Worker>> {
        self.pool.slots.get(worker as usize).map(WorkerSlot::get)
    }

    /// Bind `inst`'s wakes to this dispatcher; `false` when it is bound to another.
    fn adopt(&self, inst: &Arc<Instance>) -> bool {
        self.adopter().adopt(inst)
    }

    /// The handle a [`super::Bind`] carries to be adopted by this dispatcher at bind.
    pub fn adopter(&self) -> Adopter {
        Adopter {
            pool: Arc::downgrade(&self.pool),
        }
    }

    /// Whether an op on `t` is pending (test witness: it has crossed and answered PENDING).
    #[cfg(test)]
    pub(crate) fn is_pending(&self, t: Ticket) -> bool {
        let Some(w) = self.worker(decode(t.slot).0) else {
            return false;
        };
        let mut st = w.lock();
        w.entry(&mut st, t)
            .is_some_and(|(_, e)| e.current.as_ref().is_some_and(|c| c.pending))
    }

    /// Mint a request ticket on `worker`.
    pub fn mint(&self, worker: u32) -> Option<Ticket> {
        self.worker(worker)?.mint(None)
    }

    /// Recycle `t`: its generation is bumped at once when idle, else when its last op ends. Late
    /// wakes for it are dropped from then on.
    pub fn recycle(&self, t: Ticket) {
        self.pool.send(t, Msg::Recycle(t));
    }

    /// The client of `t` went away: its Call/Stream/Connection ops are cancelled (`cancel`, then
    /// the kind's timeout outcome); its WriteBehind ops run on.
    pub fn drop_client(&self, t: Ticket) {
        self.pool.send(t, Msg::DropClient(t));
    }

    /// A DRIVER TICKET for `plugin` on `worker`: persistent until recycled, owned by the instance,
    /// outside `max_inflight`. Every wake on it calls `drive`.
    pub fn driver<K: Kind>(&self, plugin: &Plugin<K>, worker: u32) -> Option<Ticket> {
        let inst = &plugin.inner;
        if !self.adopt(inst) || !inst.is_open() || inst.faulted.load(Ordering::Acquire) {
            return None;
        }
        self.worker(worker)?.mint(Some(Driver {
            instance: inst.clone(),
            frame: Some(Box::new(Frame::new(
                DriveIn {
                    head: in_head(),
                    driver: Ticket::NONE,
                },
                out_head(),
            ))),
            pending: false,
            wake_at_ns: 0,
        }))
    }

    /// Submit op `s` on `ticket`. Answers at once, WITHOUT calling the plugin, when: the ticket is
    /// NONE (use [`Plugin::call`]) → FAULT; the instance is faulted → FAULT; the slot is refused
    /// ([`Instance::refuse`]); a lifecycle op is already in flight → REFUSED; `max_inflight` is full
    /// → REFUSED.
    pub fn submit<K: Kind, I: InFrame, O: OutFrame>(
        &self,
        plugin: &Plugin<K>,
        ticket: Ticket,
        s: u32,
        frame: Frame<I, O>,
        class: DeadlineClass,
        deadline_ns: u64,
    ) -> Reply<I, O> {
        let inst = &plugin.inner;
        if ticket.is_none() {
            return Reply::settled(Outcome::Fault, frame);
        }
        if !self.adopt(inst) {
            return Reply::settled(Outcome::Refused, frame);
        }
        if let Some(o) = inst.refuse(s, size_of::<I>(), size_of::<O>()) {
            return Reply::settled(o, frame);
        }
        let lifecycle = is_lifecycle(s);
        if lifecycle && !inst.enter_lifecycle() {
            return Reply::settled(Outcome::Refused, frame);
        }
        let Some(units) = inst.acquire(s) else {
            // Over the cap, or `close` while other ops are in flight: REFUSED, never called.
            if lifecycle {
                inst.leave_lifecycle();
            }
            return Reply::settled(Outcome::Refused, frame);
        };
        let drainable = class != DeadlineClass::WriteBehind;
        if drainable {
            inst.drainable.fetch_add(1, Ordering::AcqRel);
        }
        let slot = Arc::new(ReplySlot::new());
        let meta = Meta {
            instance: inst.clone(),
            slot: s,
            class,
            deadline_ns,
            in_size: size_of::<I>() as u32,
            units,
            lifecycle,
            drainable,
            reply: slot.clone(),
        };
        let job = Box::new(JobOf {
            frame: Box::new(frame),
            reply: slot.clone(),
        });
        self.pool.send(ticket, Msg::Submit { ticket, meta, job });
        Reply { slot }
    }

    /// A reload DRAIN: wait up to `timeout` until no Call/Stream/Connection op of `plugin` is in
    /// flight. WriteBehind ops are never waited on: they carry over to the next generation.
    pub fn drain<K: Kind>(&self, plugin: &Plugin<K>, timeout: Duration) -> bool {
        let until = Instant::now() + timeout;
        loop {
            if plugin.inner.drainable.load(Ordering::Acquire) == 0 {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        self.pool.stop.store(true, Ordering::Release);
        for slot in self.pool.slots.iter() {
            let _ = slot.get().tx.send(Msg::Stop);
        }
    }
}
