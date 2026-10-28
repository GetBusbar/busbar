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
//!   `max_inflight`. A wake on one calls `drive`; a PENDING drive resumes like any op. The one op
//!   submitted on a driver ticket is `tick` ([`Dispatcher::tick`]): it holds no `max_inflight`
//!   unit, a wake during it is owed to `drive` once it ends, and its PENDING answer ends it, since
//!   what pended inside it goes on through `drive`. Every `drive` that ran is followed by a `tick`
//!   (R-PUSH), PENDING or not: the new cycle's work runs alongside what is held.
//! * HELD WORK ON A DRIVER TICKET. A PENDING is honoured: a `tick` that answered PENDING holds what
//!   pended, and a `drive` that answered PENDING holds what still waits, until a `drive` answers
//!   anything else. While anything is held, a tick's start keeps what the services kept under the
//!   ticket (the conn answers and the stored service results the held work redeems by handle, its
//!   pended services still able to complete and wake it), so each held exchange resumes when its
//!   wake fires while the next tick starts more. The host sees each held exchange as the one
//!   handle its last call pended under (`super::held`): it is released when a call on that handle
//!   answers anything else, one exchange at a time. A tick of a kept cycle that reuses a handle
//!   the cycle already issued is answered FAULT on that call, never another exchange's kept
//!   answer. The held exchanges are bounded by the instance's `max_inflight`: a tick that finds
//!   them full is PARKED, PENDING and not crossed, and crosses once a held exchange ends (its
//!   caller is answered then, with no poke of its own). With nothing held, a tick's start is its
//!   cycle's boundary: what the services kept under the ticket since the last tick is forgotten
//!   then, the most ever kept counted ([`DispatchStats::driver_kept_high`]).
//! * DEADLINE CLASSES. Call, Stream and Connection: when `deadline_ns` passes with the op pending,
//!   the host calls `cancel` (ticket-less: it may not pend) and answers the kind's timeout outcome;
//!   a client drop does the same. WriteBehind is NEVER cancelled — not by its deadline, a client
//!   drop or a reload: at its deadline the caller stops waiting (the reply answers the timeout
//!   outcome, `detached`), the ticket stays, and a later wake still completes it. A reload drain
//!   ([`Dispatcher::drain`]) never waits on WriteBehind ops: they carry over to the new generation.
//! * THE WATCHDOG (`watchdog`): an op that does not RETURN within its class budget faults its
//!   instance and replaces its worker; see there for what happens to every ticket. An op submitted
//!   with its own watch budget ([`Dispatcher::submit_watched`]) is watched for the longer of the two.

use std::collections::VecDeque;
use std::future::Future;
use std::mem::size_of;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{DeadlineClass, InHead, OutHead, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::lifecycle::{slot, TickIn, TickOut};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::conn::InstanceId;

use super::plugin::{is_lifecycle, Crossed, Instance, Plugin};
use super::services::{HostServices, Served, ServiceStore};
use super::ticket::{decode, encode, WakeRoute, MAX_INDEX, MAX_WORKERS};
use super::{in_head, now_ns, out_head, watchdog, DriveFrame, Frame, InFrame, Kind, OutFrame};

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
    /// THE QUARANTINE COUNT, N (THE DESIGN A.8): the breaches of the watch budget an instance
    /// survives before it is quarantined. Every breach replaces its worker and settles the hung
    /// op as FAULT; the Nth also quarantines the instance — every new call answers FAULT without a
    /// crossing (a hook's caller goes to its `on_error`, and the hook door's timed trial brings a
    /// fresh instance back, R2), with a diagnostic and `bb_plugin_quarantined_total`. Clamped to
    /// at least 1; the default [`DEFAULT_QUARANTINE_AFTER`] quarantines on the first breach.
    pub quarantine_after: u32,
}

/// The default [`DispatchConfig::quarantine_after`]: the first breach quarantines, as before the
/// count existed.
pub const DEFAULT_QUARANTINE_AFTER: u32 = 1;

/// The quarantine counter's exposition name (THE DESIGN A.8): [`DispatchStats::quarantined`], the
/// process's sum over every plugin.
pub const QUARANTINED_TOTAL: &str = "bb_plugin_quarantined_total";

/// The lost-wake counter's exposition name (THE DESIGN A.4.3):
/// [`DispatchStats::deadline_without_wake`].
pub const DEADLINE_WITHOUT_WAKE_TOTAL: &str = "bb_deadline_without_wake_total";

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            workers: 1,
            budgets: Budgets::default(),
            watchdog_period: Duration::from_millis(50),
            quarantine_after: DEFAULT_QUARANTINE_AFTER,
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
    /// Instances the watchdog quarantined: `bb_plugin_quarantined_total` (THE DESIGN A.8), the
    /// process's sum over every plugin.
    pub quarantined: u64,
    /// WriteBehind ops that completed after their caller stopped waiting.
    pub write_behind_late: u64,
    /// Library unloads still running on their reapers, process-wide: a count that stays up names a
    /// hung `.fini_array` (never forced; see `load::reap`).
    pub live_reapers: u64,
    /// The most service answers one driver ticket kept over one tick cycle (a high-water gauge).
    pub driver_kept_high: u64,
    /// `bb_deadline_without_wake_total` (THE DESIGN A.4.3): ops that answered PENDING and were
    /// still owed their wake when their DEADLINE settled them (a Call/Stream/Connection op
    /// cancelled, a WriteBehind op's caller released), never woken before it. A door whose every
    /// wait is woken keeps it 0; every conformance script requires 0.
    pub deadline_without_wake: u64,
    /// Contexts plugins handed the host that it did not mint, process-wide (#74,
    /// `dispatch::handle`): each inside a crossing quarantined its instance.
    pub forged_handles: u64,
    /// The off-crossing latch tripped (#74): nothing resolves outside a crossing any more.
    pub handles_latched: bool,
}

/// One `bb_*` counter family the dispatcher exposes: its name, its HELP text and its value.
pub type CounterFamily = (&'static str, &'static str, u64);

impl DispatchStats {
    /// EVERY `bb_*` COUNTER these stats hold, each with its name and HELP text: the dispatcher's
    /// own counts, read by whoever holds the dispatcher (the conformance suite). They are NOT on
    /// the customer `/metrics` scrape: 1.5.5 served no `bb_*` family and the scrape must match it
    /// (oracle row 86).
    #[must_use]
    pub const fn families(&self) -> [CounterFamily; 2] {
        [
            (
                DEADLINE_WITHOUT_WAKE_TOTAL,
                "Plugin operations that waited and were settled by their deadline without ever \
                 being woken; 0 while every plugin wakes what it parks",
                self.deadline_without_wake,
            ),
            (
                QUARANTINED_TOTAL,
                "Plugin instances the crossing watchdog quarantined for overrunning their call \
                 budget, summed over every plugin",
                self.quarantined,
            ),
        ]
    }
}

#[derive(Debug, Default)]
pub(crate) struct Stats {
    stale_wakes: AtomicU64,
    pub(crate) replacements: AtomicU64,
    pub(crate) quarantined: AtomicU64,
    write_behind_late: AtomicU64,
    driver_kept_high: AtomicU64,
    deadline_without_wake: AtomicU64,
}

/// What a worker thread needs besides its worker.
pub(crate) struct Env {
    pub(crate) budgets: Budgets,
    /// [`DispatchConfig::quarantine_after`], at least 1.
    pub(crate) quarantine_after: u32,
    pub(crate) stats: Arc<Stats>,
    /// The host services' stored results.
    pub(crate) services: Arc<ServiceStore>,
    /// What the host services are served from; `None` = the host bound none, and every service
    /// answers REFUSED.
    pub(crate) provider: Option<Arc<dyn HostServices>>,
    /// THE PROCESS'S RUNTIME, the reactor a plugin's connection is registered on: a crossing on a
    /// worker runs inside it, so a dial the connector makes on the worker (a plugin's `exchange`)
    /// lands on a reactor that is always driven (THE DESIGN, the connections section). INSTALLED,
    /// never captured ([`Dispatcher::install_runtime`]): the host installs the process's one
    /// runtime at boot (busbar: the connector's own I/O thread). A runtime taken from whoever
    /// submitted first bound every worker to the control runtime, whose thread waits synchronously
    /// on worker ops at boot, so a socket a plugin opened there was never driven. None installed:
    /// a worker enters no runtime, and its I/O takes the connector's own refusal.
    pub(crate) runtime: std::sync::OnceLock<tokio::runtime::Handle>,
    /// THE HOST'S I/O (`io.*`) the instances of this dispatcher are served from; unset = none, and
    /// every `io` slot answers REFUSED.
    pub(crate) io: std::sync::OnceLock<Arc<dyn busbar_contract::io_host::IoHost>>,
    /// The tickets of ops driven inline on the calling thread (a carrier's connection sides).
    pub(crate) inline: Arc<super::inline::InlineTickets>,
    /// THE HOST'S OBSERVABILITY of every door this dispatcher binds: the observer and the series
    /// predicate the host installs on it ([`Dispatcher::observing`]), never a process-global seam.
    pub(crate) observing: Arc<crate::observe::Observing>,
    /// The key every worker's ticket generations are permuted under (#74), drawn at the
    /// dispatcher's boot: no worker exists without it.
    pub(crate) ticket_key: super::handle::TicketKey,
    /// The latch a forged ticket with no supplier counts against: the process's, but in a test
    /// that names its own ([`Dispatcher::judge_against`]).
    latch: std::sync::OnceLock<&'static super::handle::Latch>,
    /// THE SEAL THE HOST LENT THIS DISPATCHER (Part 2 #54): what a door it binds presents to read
    /// a resolved `Secret` it hands a plugin ([`Dispatcher::lend_seal`]). None lent: every such
    /// reveal is refused.
    pub(crate) seal:
        std::sync::OnceLock<Arc<dyn busbar_contract::plugin::KernelSeal + Send + Sync>>,
}

impl Env {
    fn latch(&self) -> &'static super::handle::Latch {
        self.latch
            .get()
            .copied()
            .unwrap_or_else(super::handle::process_latch)
    }
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
    /// The record writes that `cancel` carried (a plane's, SEAM-L(r)).
    pub cancel_writes: Vec<busbar_contract::plane_calls::CancelWrite>,
}

/// One op's completion slot: filled ONCE by the dispatcher, read by a sync waiter (the condvar)
/// or an async one (the registered [`Waker`]), the same slot for both.
struct ReplySlot<T> {
    v: Mutex<SlotState<T>>,
    cv: Condvar,
}

struct SlotState<T> {
    /// An answer was given (it may already have been taken).
    settled: bool,
    value: Option<T>,
    /// The async waiter to wake when the answer arrives.
    waker: Option<Waker>,
}

impl<T> ReplySlot<T> {
    fn new() -> Self {
        Self {
            v: Mutex::new(SlotState {
                settled: false,
                value: None,
                waker: None,
            }),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SlotState<T>> {
        self.v.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The FIRST answer wins; `false` when one was already given. Wakes the sync waiter and the
    /// async one; the waker is woken outside the lock.
    fn put(&self, t: T) -> bool {
        let waker = {
            let mut g = self.lock();
            if g.settled {
                return false;
            }
            g.settled = true;
            g.value = Some(t);
            g.waker.take()
        };
        self.cv.notify_all();
        if let Some(w) = waker {
            w.wake();
        }
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
            cancel_writes: Vec::new(),
        })
    }
}

/// The caller's end of one op: waited on synchronously ([`Reply::wait`]) or awaited as a
/// [`Future`] on the caller's runtime, never blocking a runtime thread (the dispatcher's worker
/// fills the slot and wakes the task). Both read the one slot.
///
/// DROP IS A CLIENT DROP. Dropping a `Reply` before its answer arrived reaches the dispatcher's
/// cancel path for the op's ticket ([`Dispatcher::drop_client`]: Call/Stream/Connection ops are
/// cancelled, WriteBehind runs on), by a non-blocking message and nothing else, never an await.
/// [`Reply::detach`] lets an op run on with nobody waiting.
pub struct Reply<I, O> {
    slot: Arc<ReplySlot<Done<I, O>>>,
    /// The op's ticket and dispatcher, for the client drop; `None` once detached or when the
    /// reply was answered at submission.
    owner: Option<(Ticket, Weak<Pool>)>,
}

impl<I, O> std::fmt::Debug for Reply<I, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply").finish_non_exhaustive()
    }
}

impl<I: InFrame, O: OutFrame> Reply<I, O> {
    /// Wait up to `timeout` for the completion (a sync caller; it blocks this thread).
    pub fn wait(&self, timeout: Duration) -> Option<Done<I, O>> {
        let until = Instant::now() + timeout;
        let mut g = self.slot.lock();
        loop {
            if let Some(d) = g.value.take() {
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

    /// Wait for the completion, however long the op takes (a sync caller; it blocks this thread).
    /// The dispatcher settles every reply: the op's answer, its deadline's `cancel`, a client drop,
    /// a watchdog fault or the dispatcher's stop. A WriteBehind op submitted with no deadline is
    /// waited on until it completes.
    pub fn wait_done(&self) -> Done<I, O> {
        let mut g = self.slot.lock();
        loop {
            if let Some(d) = g.value.take() {
                return d;
            }
            g = self.slot.cv.wait(g).unwrap_or_else(|e| e.into_inner());
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
            cancel_writes: Vec::new(),
        });
        Self { slot, owner: None }
    }

    /// Let the op run on with nobody waiting: dropping the reply then cancels nothing.
    pub fn detach(mut self) {
        self.owner = None;
    }
}

impl<I: InFrame, O: OutFrame> Future for Reply<I, O> {
    type Output = Done<I, O>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Done<I, O>> {
        let mut g = self.slot.lock();
        if let Some(d) = g.value.take() {
            return Poll::Ready(d);
        }
        match &g.waker {
            Some(w) if w.will_wake(cx.waker()) => {}
            _ => g.waker = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl<I, O> Drop for Reply<I, O> {
    fn drop(&mut self) {
        let settled = {
            let mut g = self.slot.v.lock().unwrap_or_else(|e| e.into_inner());
            // A later answer wakes nobody: this waiter is gone.
            g.waker = None;
            g.settled
        };
        if settled {
            return;
        }
        if let Some((ticket, pool)) = self.owner.take() {
            if let Some(pool) = pool.upgrade() {
                // A message, never an await: the worker cancels the op in its own loop.
                pool.send(ticket, Msg::DropClient(ticket));
            }
        }
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
    /// The memory the frame's pointers lend the plugin ([`Lent`]): held with the frame, so it is
    /// dropped only when the job is — after the op's last crossing returned (an answer, a `cancel`
    /// or a hung crossing that finally returns), never when the caller drops its [`Reply`].
    lent: Option<Lent>,
}

/// HOST-LENT MEMORY, kept alive until the op completes (ARCHITECT ruling 2026-09-29, every kind): an
/// `in` names host buffers by raw pointer (strings, lists, result buffers), so whatever owns them
/// must outlive every crossing of the op. The caller hands its owner to
/// [`Dispatcher::submit_lent`]; the dispatcher holds it with the frame. A caller that stops waiting
/// (its [`Reply`] dropped, its deadline passed, its task cancelled) can therefore never free memory
/// a plugin is still reading on a worker. The caller keeps its own clone to read what the plugin
/// wrote.
pub type Lent = Arc<dyn std::any::Any + Send + Sync>;

impl<I: InFrame, O: OutFrame> Job for JobOf<I, O> {
    fn heads(&mut self) -> (*mut InHead, *mut OutHead, u32) {
        self.frame.heads()
    }

    fn finish(self: Box<Self>, c: Crossed) -> bool {
        let JobOf { frame, reply, lent } = *self;
        let put = reply.put(Done {
            outcome: c.outcome,
            error: c.error,
            lease: c.lease,
            frame: Some(frame),
            detached: false,
            short: c.short,
            disposition: c.disposition,
            cancel_writes: c.cancel_writes,
        });
        // The op is over: nothing crosses on this frame again, so the lent memory may go (the
        // caller's own clone, if it kept one, still holds it).
        drop(lent);
        put
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
    /// The op's own watch budget ([`Dispatcher::submit_watched`]): its crossings are watched for
    /// the longer of this and its class budget. ZERO = the class budget alone.
    watch: Duration,
    /// The `max_inflight` units it holds: one, or all of them for `close`.
    units: u32,
    /// Whether it still holds them (see [`Meta::give_back`]).
    units_held: bool,
    lifecycle: bool,
    drainable: bool,
    /// An admitted unit's op ([`Dispatcher::submit_unit`]): counted in [`Instance::unit_ops`].
    unit: bool,
    pub(crate) reply: Arc<dyn Settle>,
}

/// How an op submitted is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// Under the instance's `max_inflight` ([`Instance::acquire`]).
    Cap,
    /// On a driver ticket: outside `max_inflight`.
    Driver,
    /// An op of an admitted unit: outside `max_inflight`, and in flight for `close`.
    Unit,
}

impl Meta {
    /// Give back what the op held — its `max_inflight` units, its drain count, the lifecycle
    /// exclusion — once. Done BEFORE the answer is delivered, so a caller woken by it finds the
    /// units free.
    fn give_back(&mut self) {
        if std::mem::take(&mut self.units_held) {
            self.instance.release(self.units);
            if self.drainable {
                self.instance.drainable.fetch_sub(1, Ordering::AcqRel);
            }
            if self.unit {
                self.instance.unit_ops.fetch_sub(1, Ordering::SeqCst);
            }
            if self.lifecycle {
                self.instance.leave_lifecycle();
            }
        }
    }
}

impl Drop for Meta {
    fn drop(&mut self) {
        self.give_back();
        self.reply.settle(Outcome::Fault, false);
        hold_past_lock(&self.instance);
    }
}

std::thread_local! {
    /// THE INSTANCES A WORKER LOOP LETS GO WITH NO LOCK HELD (THE DESIGN §11.13 M1, "No plugin code
    /// (`dlclose` included) runs under a host lock"): `Some` on a dispatcher worker's own thread
    /// while [`run`] runs. An op's [`Meta`] and a driver ticket's [`Driver`] are let go while the
    /// worker's state lock is held, and either may hold an instance's last reference, whose drop
    /// closes its connections (a transport's code) and unloads its library. Each keeps its instance
    /// here instead, and the loop lets the list go once the lock is released.
    static LET_GO: std::cell::RefCell<Option<Vec<Arc<Instance>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Keep `instance` past a drop made under the worker's lock: on a worker loop's own thread the loop
/// takes it by [`let_go`] and drops it with the lock released; on any other thread nothing is kept.
fn hold_past_lock(instance: &Arc<Instance>) {
    // `try_with`: a drop made while the thread itself is ending keeps nothing.
    let _ = LET_GO.try_with(|l| {
        if let Some(held) = l.borrow_mut().as_mut() {
            held.push(Arc::clone(instance));
        }
    });
}

/// The instances held past the worker's lock so far, to be dropped by the caller once it has let
/// the lock go.
fn let_go() -> Vec<Arc<Instance>> {
    LET_GO.with(|l| {
        l.borrow_mut()
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    })
}

/// A worker loop's [`LET_GO`] list for its life: armed when made, and on the way out (every
/// return of [`run`], after its lock guard is gone) what is left is let go and the list disarmed.
struct LetGo;

impl LetGo {
    fn arm() -> Self {
        LET_GO.with(|l| *l.borrow_mut() = Some(Vec::new()));
        Self
    }
}

impl Drop for LetGo {
    fn drop(&mut self) {
        let left = LET_GO.with(|l| l.borrow_mut().take());
        drop(left);
    }
}

pub(crate) struct Current {
    pub(crate) meta: Meta,
    /// `None` while the frame is out on a crossing.
    job: Option<Box<dyn Job>>,
    pending: bool,
    wake_at_ns: u64,
    detached: bool,
    /// A `tick` on a driver ticket whose held set is full, not yet crossed: it waits, PENDING, for
    /// a held exchange to end ([`Worker::unpark`]), and then crosses.
    parked: bool,
}

/// THE NAMES A DRIVER TICKET'S READY `drive` ANSWERED (a plane's ready sessions), held for the
/// host until it collects them ([`Driven::take`]): each once, at most [`Driven::HELD`] at a time
/// (a plane that names more before the host collects is told nothing new until it wakes again).
#[derive(Debug, Default)]
#[doc(hidden)] // TEST SEAM: busbar-test-kit
pub struct Driven {
    names: Mutex<Vec<u64>>,
    told: tokio::sync::Notify,
    /// How many `drive` crossings answered, and the last one's outcome: what a synchronous host
    /// that woke the driver waits on ([`Driven::answered_after`]; the published conformance suite
    /// drives `drive` this way, as a wake, THE DESIGN §11.4).
    answers: Mutex<(u64, Option<Outcome>)>,
    answered: Condvar,
    /// A wake's `drive` ran: the host re-polls `tick` (R-PUSH).
    woke: tokio::sync::Notify,
}

impl Driven {
    /// The most names held uncollected.
    const HELD: usize = 1024;

    fn name(&self, names: &[u64]) {
        let mut held = self.names.lock().unwrap_or_else(|e| e.into_inner());
        for n in names {
            if !held.contains(n) && held.len() < Self::HELD {
                held.push(*n);
            }
        }
        drop(held);
        if !names.is_empty() {
            self.told.notify_one();
        }
    }

    /// A `drive` crossing answered `outcome`.
    fn answer(&self, outcome: Outcome) {
        let mut a = self.answers.lock().unwrap_or_else(|e| e.into_inner());
        *a = (a.0 + 1, Some(outcome));
        drop(a);
        self.answered.notify_all();
    }

    /// How many `drive` crossings have answered so far.
    #[cfg(any(test, feature = "test-support"))]
    pub fn answers(&self) -> u64 {
        self.answers.lock().unwrap_or_else(|e| e.into_inner()).0
    }

    /// The first outcome other than PENDING a `drive` answered after the `seen`th answer, waited
    /// for up to `timeout` (a synchronous caller; it blocks this thread). `None` past it.
    #[cfg(any(test, feature = "test-support"))]
    pub fn answered_after(&self, seen: u64, timeout: Duration) -> Option<Outcome> {
        let until = Instant::now() + timeout;
        let mut a = self.answers.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if a.0 > seen && a.1 != Some(Outcome::Pending) {
                return a.1;
            }
            let left = until.checked_duration_since(Instant::now())?;
            a = self
                .answered
                .wait_timeout(a, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Every name held now, taken (none when none is); never waits.
    #[cfg(any(test, feature = "test-support"))]
    pub fn drain(&self) -> Vec<u64> {
        std::mem::take(&mut *self.names.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// A wake of the driver ticket has run its `drive`.
    fn drove(&self) {
        self.woke.notify_one();
    }

    /// Waits until a wake's `drive` has run, once per run; never parks a thread.
    pub(crate) async fn woken(&self) {
        self.woke.notified().await;
    }

    /// Every name held, once one is; never parks a thread.
    pub(crate) async fn take(&self) -> Vec<u64> {
        loop {
            let names = std::mem::take(&mut *self.names.lock().unwrap_or_else(|e| e.into_inner()));
            if !names.is_empty() {
                return names;
            }
            self.told.notified().await;
        }
    }
}

pub(crate) struct Driver {
    instance: Arc<Instance>,
    /// The kind's own `drive` frame ([`Kind::drive_frame`]); `None` while out on a crossing.
    frame: Option<Box<dyn DriveFrame>>,
    pending: bool,
    wake_at_ns: u64,
    /// The ticks that answered PENDING since the last `drive` that answered anything else. While it
    /// is not zero, or the last `drive` answered PENDING (`pending`), or an exchange is held under
    /// a handle (`super::held`), a tick's start keeps the services' answers under the ticket.
    ticks_held: u32,
}

impl Drop for Driver {
    /// A driver ticket is let go under the worker's lock (a recycle): its instance is held past it.
    fn drop(&mut self) {
        hold_past_lock(&self.instance);
    }
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
    /// The slot's mint counter (#74): how many times it has been handed out, from 1.
    pub(crate) count: u32,
    /// The ticket generation of mint `count`: `handle::ticket_generation(key, worker, idx, count)`.
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
    /// The connection-table identity of every instance whose op ran on this ticket: the connector
    /// slots' kept answers are forgotten under each of them, and only them, when it is recycled.
    pub(crate) conns: Vec<InstanceId>,
}

impl Entry {
    /// Note that an op of the instance `id` runs on this ticket.
    fn note(&mut self, id: InstanceId) {
        if !self.conns.contains(&id) {
            self.conns.push(id);
        }
    }
}

#[derive(Default)]
pub(crate) struct WorkerState {
    pub(crate) dead: bool,
    pub(crate) entries: Vec<Entry>,
    free: Vec<u32>,
    runnable: VecDeque<u32>,
    /// The supplier of each forged ticket generation [`Worker::apply`] found, judged by
    /// [`Worker::judge_forgeries`] once the lock is let go (#74): a quarantine takes the
    /// instance's own locks and never runs under the worker's.
    forged: Vec<Option<&'static super::ticket::InstanceWake>>,
}

pub(crate) enum Msg {
    Submit {
        ticket: Ticket,
        meta: Meta,
        job: Box<dyn Job>,
    },
    /// A wake for `.0`, supplied by the instance whose handle `.1` is (`None`: the host's own).
    Wake(Ticket, Option<&'static super::ticket::InstanceWake>),
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
    /// The dispatcher's ticket key ([`Env::ticket_key`]).
    key: super::handle::TicketKey,
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
    fn wake(&self, t: Ticket, supplier: Option<&'static super::ticket::InstanceWake>) {
        if super::inline::is_inline(t) {
            // Judged with the inline table's lock let go (#74): a generation it never minted is
            // the supplier's forgery.
            if self.env.inline.wake(t) == super::inline::Judged::Forged {
                super::handle::forged_ticket(supplier, self.env.latch());
            }
            return;
        }
        let (w, _) = decode(t.slot);
        match self.slots.get(w as usize) {
            Some(slot) => {
                // The supplier the caller carried, never the thread's crossing (#74): a wake fires
                // on whatever thread completes it, inside whichever instance's crossing that is.
                let _ = slot.get().tx.send(Msg::Wake(t, supplier));
            }
            None => {
                // A worker this dispatcher does not run minted nothing: a forgery (#74), judged
                // here, under no lock.
                self.env.stats.stale_wakes.fetch_add(1, Ordering::Relaxed);
                super::handle::forged_ticket(supplier, self.env.latch());
            }
        }
    }

    fn services(&self) -> Option<Served> {
        Some(Served {
            store: Arc::clone(&self.env.services),
            provider: Arc::clone(self.env.provider.as_ref()?),
        })
    }

    fn store(&self) -> Option<Arc<ServiceStore>> {
        Some(Arc::clone(&self.env.services))
    }

    fn io(&self) -> Option<Arc<dyn busbar_contract::io_host::IoHost>> {
        self.env.io.get().cloned()
    }

    fn seal(&self) -> Option<Arc<dyn busbar_contract::plugin::KernelSeal + Send + Sync>> {
        self.env.seal.get().cloned()
    }

    fn inline_waker(&self, t: Ticket) -> Option<std::task::Waker> {
        self.env.inline.waker_of(t)
    }

    fn inline(&self) -> Option<Arc<super::inline::InlineTickets>> {
        Some(Arc::clone(&self.env.inline))
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
    /// A fresh incarnation at `index`, its slab's next mint counters `counts`: every slot free
    /// but a RETIRED one (`None`, [`next_count`]), which is never handed out again.
    pub(crate) fn new(
        index: u32,
        counts: Vec<Option<u32>>,
        key: super::handle::TicketKey,
    ) -> (Arc<Self>, Receiver<Msg>) {
        let (tx, rx) = channel();
        // Lowest index last, so `pop` hands the lowest free slot out first.
        let mut free: Vec<u32> = counts
            .iter()
            .zip(0u32..)
            .filter_map(|(c, idx)| c.map(|_| idx))
            .collect();
        free.reverse();
        let state = WorkerState {
            entries: counts
                .into_iter()
                .zip(0u32..)
                .map(|(count, idx)| match count {
                    Some(count) => Entry {
                        count,
                        generation: super::handle::ticket_generation(key, index, idx, count),
                        ..Entry::default()
                    },
                    None => Entry {
                        count: u32::MAX,
                        ..Entry::default()
                    },
                })
                .collect(),
            free,
            ..WorkerState::default()
        };
        let w = Arc::new(Self {
            index,
            key,
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
                let idx = st.entries.len() as u32;
                st.entries.push(Entry {
                    count: 1,
                    generation: super::handle::ticket_generation(self.key, self.index, idx, 1),
                    ..Entry::default()
                });
                st.entries.len() as u32 - 1
            }
            None => return None,
        };
        let e = &mut st.entries[idx as usize];
        e.live = true;
        if let Some(d) = &driver {
            e.note(d.instance.instance);
        }
        e.driver = driver;
        let generation = e.generation;
        Some(self.ticket(idx, generation))
    }

    /// Whether `t` is a ticket this worker's slab ever handed out: its slot exists and its generation
    /// is the image of a count the slot has reached (`NONE`, generation 0, is a stale wake by rule).
    fn ever_minted(&self, st: &WorkerState, t: Ticket) -> bool {
        if t.generation == 0 {
            return true;
        }
        let (_, idx) = decode(t.slot);
        st.entries.get(idx as usize).is_some_and(|e| {
            let c = super::handle::ticket_count(self.key, self.index, idx, t.generation);
            c >= 1 && c <= e.count
        })
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

    /// A wake on driver `idx`: `drive` next, or, when another op on it is scheduled first, owed
    /// (latched) until that op ends ([`Worker::end`]), so no wake is lost behind a `tick`.
    fn owe_drive(st: &mut WorkerState, idx: u32) {
        match st.entries[idx as usize].next {
            None | Some(Action::Drive) => Self::schedule(st, idx, Action::Drive),
            Some(_) => st.entries[idx as usize].latched = true,
        }
    }

    /// Apply one message; `false` on Stop.
    fn apply(&self, st: &mut WorkerState, m: Msg, env: &Env) -> bool {
        match m {
            Msg::Submit { ticket, meta, job } => match self.entry(st, ticket) {
                Some((idx, e))
                    if !e.client_dropped && (e.driver.is_none() || meta.slot == slot::TICK) =>
                {
                    e.note(meta.instance.instance);
                    e.queue.push_back((meta, job));
                    if e.current.is_none() {
                        Self::schedule(st, idx, Action::Start);
                    }
                }
                Some((_, e)) if e.client_dropped => {
                    let mut meta = meta;
                    meta.give_back();
                    meta.reply.settle(Outcome::Refused, false);
                }
                // A stale or foreign ticket: `meta` drops and settles FAULT.
                _ => drop(meta),
            },
            Msg::Wake(t, supplier) => match self.entry(st, t) {
                None => {
                    env.stats.stale_wakes.fetch_add(1, Ordering::Relaxed);
                    // A generation this slot really minted is a late wake (H2: dropped, never an
                    // error). One it never minted is a forgery (#74): the generation is a keyed
                    // permutation of the slot's counter, so its inverse names the mint it would be.
                    if !self.ever_minted(st, t) {
                        st.forged.push(supplier);
                    }
                }
                Some((idx, e)) => {
                    if e.driver.is_some() {
                        Self::owe_drive(st, idx);
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
                    for (mut m, _) in gone {
                        m.give_back();
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
                        // A tick parked for a slot of a driver ticket that is going: it is
                        // answered REFUSED, never crossed.
                        if e.current.as_ref().is_some_and(|c| c.parked) {
                            self.end(st, idx, Crossed::host(Outcome::Refused), env);
                        }
                    }
                }
            }
            Msg::Stop => return false,
        }
        true
    }

    fn recycle_now(&self, st: &mut WorkerState, idx: u32, env: &Env) {
        let e = &mut st.entries[idx as usize];
        env.services.forget(self.ticket(idx, e.generation));
        let ticket = self.ticket(idx, e.generation);
        env.services.held.untrack(ticket);
        for id in e.conns.drain(..) {
            super::conn_services::forget(id, ticket);
        }
        let next = next_count(e.count);
        if let Some(count) = next {
            e.count = count;
            e.generation = super::handle::ticket_generation(self.key, self.index, idx, count);
        }
        e.live = false;
        e.latched = false;
        e.client_dropped = false;
        e.recycle_when_idle = false;
        e.short_slot = None;
        e.next = None;
        e.driver = None;
        // A slot whose counter is spent is RETIRED: never handed out again, so no generation of
        // it is ever re-minted; the next mint takes a fresh slot.
        if next.is_some() {
            st.free.push(idx);
        }
    }

    /// Judge the forged ticket generations [`Worker::apply`] found, with the worker's lock let go
    /// (#74): each supplier quarantined, a wake with none counted against the process's latch.
    fn judge_forgeries<'a>(
        &'a self,
        mut st: MutexGuard<'a, WorkerState>,
        env: &Env,
    ) -> MutexGuard<'a, WorkerState> {
        if st.forged.is_empty() {
            return st;
        }
        let forged = std::mem::take(&mut st.forged);
        drop(st);
        for supplier in forged {
            super::handle::forged_ticket(supplier, env.latch());
        }
        self.lock()
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
        let mut cur = cur;
        cur.meta.give_back();
        if let Some(job) = cur.job {
            if !job.finish(c) {
                env.stats.write_behind_late.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(cur.meta);
        let owed = e.driver.is_some() && std::mem::take(&mut e.latched);
        if !e.queue.is_empty() {
            Self::schedule(st, idx, Action::Start);
        } else if e.recycle_when_idle {
            self.recycle_now(st, idx, env);
        }
        if owed {
            Self::owe_drive(st, idx);
        }
    }

    /// Due deadlines and timers; the wait until the next one.
    fn timers(&self, st: &mut WorkerState, now: u64, env: &Env) -> Duration {
        let mut without_wake = 0_u64;
        let mut next = u64::MAX;
        let mut due = Vec::new();
        for (idx, e) in st.entries.iter_mut().enumerate() {
            // A wake that came is scheduled as the op's resume: it is not owed any more.
            let owed = !matches!(e.next, Some(Action::Resume));
            if let Some(c) = e.current.as_mut().filter(|c| c.pending) {
                let (class, deadline) = (c.meta.class, c.meta.deadline_ns);
                if deadline != 0 && class != DeadlineClass::WriteBehind {
                    if now >= deadline {
                        // Pending, its wake still owed: the deadline, not a wake, ends it.
                        without_wake += u64::from(owed);
                        due.push((idx as u32, Action::Cancel));
                        continue;
                    }
                    next = next.min(deadline);
                }
                if deadline != 0 && class == DeadlineClass::WriteBehind && !c.detached {
                    if now >= deadline {
                        // The caller stops WAITING; the op keeps its ticket and runs on. Pending,
                        // its wake still owed: the deadline, not a wake, settled its caller.
                        without_wake += u64::from(owed);
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
        if without_wake > 0 {
            env.stats
                .deadline_without_wake
                .fetch_add(without_wake, Ordering::Relaxed);
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
                // A tick on a driver ticket whose held set is full waits for a slot (parked); one
                // of a kept cycle may not reuse a handle the cycle issued (`super::held`).
                let (mut full, mut kept_cycle) = (false, false);
                if let Some(d) = e.driver.as_ref() {
                    let held = env.services.held.held(ticket);
                    if d.ticks_held == 0 && !d.pending && held == 0 {
                        // Nothing is held: the tick starts the driver ticket's next cycle, and the
                        // last cycle's kept answers (and their epoch) go.
                        let kept = env.services.forget(ticket)
                            + super::conn_services::forget(meta.instance.instance, ticket);
                        env.services.held.forget(ticket);
                        env.stats
                            .driver_kept_high
                            .fetch_max(kept as u64, Ordering::Relaxed);
                    } else {
                        // A PENDING is honoured: what is held keeps its answers and its epoch,
                        // and resumes through `drive` when its wake fires. The held exchanges are
                        // bounded by the instance's `max_inflight`.
                        kept_cycle = true;
                        full = held >= meta.instance.cap;
                    }
                } else if e.short_slot != Some(meta.slot) {
                    // A NEW op starts on the ticket (not the one re-call a short answer earns):
                    // its handles count from 0 again (the replay rule, `abi::sdk::conn`), and a
                    // stored result is redeemed only by the op that issued it, on its resume (THE
                    // DESIGN §11.12) — so the last op's kept answers go. Kept, the next op's
                    // `ESTABLISH` (handle 0) would answer the last op's stream without a dial.
                    // The forget ends the last op's epoch too: a service of its still running
                    // completes into nothing, never into this op's same-numbered handle.
                    env.services.forget(ticket);
                    super::conn_services::forget(meta.instance.instance, ticket);
                }
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
                let (s, budget) = (
                    meta.slot,
                    env.budgets.of(meta.slot, meta.class).max(meta.watch),
                );
                let driven = e.driver.is_some();
                e.current = Some(Current {
                    meta,
                    job: Some(job),
                    pending: full,
                    wake_at_ns: 0,
                    detached: false,
                    parked: full,
                });
                if let Some(o) = early {
                    self.end(&mut st, idx, Crossed::host(o), env);
                    return Some(st);
                }
                if full {
                    // PENDING, not crossed: its wake is a held exchange's end ([`Worker::unpark`]),
                    // so whoever awaits the tick is answered then, with no poke of its own.
                    return Some(st);
                }
                if !driven {
                    return self.cross_current(st, idx, &inst, s, budget, env);
                }
                env.services.held.enter(ticket, kept_cycle);
                let st = self.cross_current(st, idx, &inst, s, budget, env);
                env.services.held.leave(ticket);
                st
            }
            Action::Resume => {
                let Some(cur) = e.current.as_mut().filter(|c| c.pending && !c.parked) else {
                    return Some(st);
                };
                cur.pending = false;
                let inst = cur.meta.instance.clone();
                let (s, budget) = (
                    cur.meta.slot,
                    env.budgets
                        .of(cur.meta.slot, cur.meta.class)
                        .max(cur.meta.watch),
                );
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
                let op_slot = cur.meta.slot;
                let timeout = inst.timeout;
                if inst.faulted.load(Ordering::Acquire) {
                    self.end(&mut st, idx, Crossed::host(Outcome::Fault), env);
                    return Some(st);
                }
                // THE UNIT THE CANCELLED OP SERVES, read off the op's own `in` (`Kind::unit_of`): a
                // plane keys its units from `arrive` and frees the one its `cancel` names
                // (`PlaneCancelIn::unit`), so the client-drop path names it too, never `0`.
                let unit = match cur.job.as_mut() {
                    Some(job) => {
                        let (input, _, _) = job.heads();
                        (inst.unit_of)(op_slot, input.cast_const(), cur.meta.in_size as usize)
                    }
                    None => None,
                };
                // `cancel` may not pend: its head carries NONE; the cancelled ticket is its field.
                // The kind's own frame (a plane's lends record buffers, SEAM-L(r)).
                let mut frame = (inst.cancel_frame)();
                frame.name_unit(unit.unwrap_or(0));
                let heads = frame.prepare(ticket, class as u8);
                let budget = env.budgets.of(slot::CANCEL, class);
                let (mut st, c) = self.cross(st, &inst, slot::CANCEL, heads, budget)?;
                // A cancelled `open` that pended will never answer: the plugin still holds its
                // half-open box, and no caller will close an instance that never opened. The host
                // closes it here, once, inside the open's own lifecycle exclusion (given back by
                // `end` below); a later caller's `close` finds nothing and is refused.
                if op_slot == slot::OPEN
                    && inst.half_open()
                    && !inst.faulted.load(Ordering::Acquire)
                {
                    let (mut input, mut out) = (in_head(), out_head());
                    let heads = (&raw mut input, &raw mut out, size_of::<OutHead>() as u32);
                    let budget = env.budgets.of(slot::CLOSE, class);
                    let (back, closed) = self.cross(st, &inst, slot::CLOSE, heads, budget)?;
                    st = back;
                    if closed.outcome != Outcome::Ready {
                        tracing::warn!(
                            plugin = %inst.name(),
                            outcome = ?closed.outcome,
                            "the close of a cancelled open's half-open box did not answer READY"
                        );
                    }
                }
                // The op answers the kind's timeout with `cancel`'s disposition and the writes it
                // carried; a `cancel` that FAULTed makes the op FAULT.
                let ended = if c.outcome == Outcome::Fault {
                    Crossed::host(Outcome::Fault)
                } else {
                    Crossed {
                        disposition: Some(frame.disposition()),
                        cancel_writes: if c.outcome == Outcome::Ready {
                            frame.writes()
                        } else {
                            Vec::new()
                        },
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
                    // A parked tick is answered (the instance's fault) rather than left waiting.
                    self.unpark(&mut st, idx, env);
                    return Some(st);
                }
                let Some(mut frame) = d.frame.take() else {
                    return Some(st);
                };
                let flags = if d.pending { FLAG_RESUME } else { 0 };
                let heads = frame.prepare(ticket, flags);
                d.pending = false;
                let budget = env.budgets.of(slot::DRIVE, DeadlineClass::Connection);
                env.services.held.enter(ticket, false);
                let (mut st, c) = self.cross(st, &inst, slot::DRIVE, heads, budget)?;
                env.services.held.leave(ticket);
                if c.outcome == Outcome::Ready {
                    inst.driven.name(frame.named());
                }
                inst.driven.answer(c.outcome);
                let e = &mut st.entries[idx as usize];
                if e.generation == generation {
                    if let Some(d) = e.driver.as_mut() {
                        d.frame = Some(frame);
                        d.pending = c.outcome == Outcome::Pending;
                        d.wake_at_ns = c.wake_at_ns;
                        // `drive` carries every held exchange on: PENDING while one still waits,
                        // anything else once none does.
                        if !d.pending {
                            d.ticks_held = 0;
                            env.services.held.drained(ticket);
                        }
                        if d.pending && std::mem::take(&mut e.latched) {
                            Self::schedule(&mut st, idx, Action::Drive);
                        }
                    }
                }
                // A held exchange that ended freed a slot: a parked tick crosses now.
                if st.entries[idx as usize].generation == generation {
                    self.unpark(&mut st, idx, env);
                }
                // A wake's `drive` ran: the host re-polls `tick` (R-PUSH), PENDING or not, so the
                // new cycle's work runs alongside what is still held.
                inst.driven.drove();
                Some(st)
            }
        }
    }

    /// A tick parked on driver `idx` (its held set was full) goes back to the head of the queue
    /// once a held exchange has ended (a slot is free) or its instance can no longer cross, and the
    /// queue's head is started.
    fn unpark(&self, st: &mut WorkerState, idx: u32, env: &Env) {
        let e = &mut st.entries[idx as usize];
        let ticket = self.ticket(idx, e.generation);
        let free = e.current.as_ref().filter(|c| c.parked).map(|c| {
            let inst = &c.meta.instance;
            inst.faulted.load(Ordering::Acquire)
                || !inst.is_open()
                || env.services.held.held(ticket) < inst.cap
        });
        if free == Some(true) {
            if let Some(Current {
                meta,
                job: Some(job),
                ..
            }) = e.current.take()
            {
                e.queue.push_front((meta, job));
            }
        }
        if e.current.is_none() && !e.queue.is_empty() {
            Self::schedule(st, idx, Action::Start);
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
        if c.outcome == Outcome::Pending && e.driver.is_none() {
            cur.pending = true;
            cur.wake_at_ns = c.wake_at_ns;
            if std::mem::take(&mut e.latched) {
                Self::schedule(&mut st, idx, Action::Resume);
            }
        } else {
            // A tick on a driver ticket that answered PENDING ends; what pended inside it is held
            // and goes on through `drive`.
            if let Some(d) = e.driver.as_mut().filter(|_| c.outcome == Outcome::Pending) {
                d.ticks_held = d.ticks_held.saturating_add(1);
            }
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

    /// Of `gone`, the entries this worker held when it was replaced, the ORPHANS: an op of a
    /// healthy instance (not `wedged`, the one whose crossing hung, and not faulted) that answered
    /// PENDING and was waiting to be resumed, on a request ticket. Its plugin still holds the op's
    /// state and may still read the memory it was lent, so it is sent `cancel` before its frame and
    /// lent memory go ([`Orphan::cancel`]). The rest go with their `Meta`s' FAULT as before.
    pub(crate) fn orphans(
        &self,
        gone: Vec<Entry>,
        wedged: &Arc<Instance>,
    ) -> (Vec<Orphan>, Vec<Entry>) {
        let mut orphans = Vec::new();
        let mut rest = Vec::new();
        for (idx, e) in gone.into_iter().enumerate() {
            let pending = e.driver.is_none()
                && e.current.as_ref().is_some_and(|c| {
                    c.pending
                        && c.job.is_some()
                        && !Arc::ptr_eq(&c.meta.instance, wedged)
                        && !c.meta.instance.faulted.load(Ordering::Acquire)
                });
            if pending {
                let ticket = self.ticket(idx as u32, e.generation);
                orphans.push(Orphan { ticket, entry: e });
            } else {
                rest.push(e);
            }
        }
        (orphans, rest)
    }
}

/// A healthy instance's PENDING op on a worker that was replaced ([`Worker::orphans`]).
pub(crate) struct Orphan {
    ticket: Ticket,
    entry: Entry,
}

impl Orphan {
    /// Tell the plugin its op on the replaced worker ended: `cancel` of the op's ticket, a watched
    /// ticket-less crossing ([`Instance::cancel_abandoned`]). Only once it has returned is the op's
    /// frame, with the memory it lent the plugin, dropped, and its caller answered FAULT (THE DESIGN
    /// `BUSBAR-1.6.0.md` l.324-325: "The memory a call lends a plugin lives until that call
    /// completes, abandoned or not, for every kind").
    pub(crate) fn cancel(mut self) {
        if let Some(cur) = self.entry.current.as_mut() {
            let unit = cur.job.as_mut().and_then(|job| {
                let (input, _, _) = job.heads();
                (cur.meta.instance.unit_of)(
                    cur.meta.slot,
                    input.cast_const(),
                    cur.meta.in_size as usize,
                )
            });
            let outcome = cur
                .meta
                .instance
                .cancel_abandoned(self.ticket, cur.meta.class, unit);
            if outcome != Outcome::Ready {
                tracing::warn!(
                    plugin = %cur.meta.instance.name(),
                    outcome = ?outcome,
                    "the cancel of an op orphaned by a replaced worker did not answer READY"
                );
            }
        }
        drop(self.entry);
    }
}

/// A slot's mint counter after `count`; `None` once it is spent (#74): the generation is a
/// permutation of the counter, so a counter that wrapped would re-mint a generation the slot
/// already handed out. A spent slot is RETIRED instead, never handed out again.
pub(crate) fn next_count(count: u32) -> Option<u32> {
    count.checked_add(1)
}

/// THE WORKER LOOP: messages, then timers, then one runnable action; sleep until the next timer
/// or message.
pub(crate) fn run(w: Arc<Worker>, rx: Receiver<Msg>, env: Arc<Env>) {
    // Made before the lock guard, so every return lets the guard go first and this second.
    let _let_go = LetGo::arm();
    // Inside the process's runtime once it is known, for the rest of this worker's life.
    let mut entered: Option<tokio::runtime::EnterGuard<'static>> = None;
    let mut st = w.lock();
    loop {
        // What the last turn let go under the lock is dropped with it released (§11.13 M1).
        let late = let_go();
        if !late.is_empty() {
            drop(st);
            drop(late);
            st = w.lock();
        }
        if entered.is_none() {
            if let Some(handle) = env.runtime.get() {
                let handle: &'static tokio::runtime::Handle = Box::leak(Box::new(handle.clone()));
                entered = Some(handle.enter());
            }
        }
        if st.dead {
            return;
        }
        let mut stop = false;
        while let Ok(m) = rx.try_recv() {
            stop |= !w.apply(&mut st, m, &env);
        }
        st = w.judge_forgeries(st, &env);
        if stop {
            st.dead = true;
            let gone = Worker::fault_all(&mut st);
            drop(st);
            drop(gone);
            return;
        }
        let wait = w.timers(&mut st, now_ns(), &env);
        if let Some(idx) = st.runnable.pop_front() {
            match w.run_one(st, idx, &env) {
                Some(g) => st = g,
                None => return,
            }
            continue;
        }
        let late = let_go();
        drop(st);
        drop(late);
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
                st = w.judge_forgeries(st, &env);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

std::thread_local! {
    /// The dispatcher worker this thread is, as `(the dispatcher's Env address, worker index)`;
    /// `None` on every other thread ([`Dispatcher::current_worker`]).
    static ON_WORKER: std::cell::Cell<Option<(usize, u32)>> = const { std::cell::Cell::new(None) };
}

/// The dispatcher worker the calling thread is, or acts for ([`acting_for`]); `None` on any other
/// thread.
pub(crate) fn worker_mark() -> Option<(usize, u32)> {
    ON_WORKER.with(std::cell::Cell::get)
}

/// A crossing handed from a dispatcher worker to a permanent FFI worker acts for that dispatcher
/// worker until the returned guard drops: a host service the plugin calls on the FFI worker then
/// sees the worker it serves ([`Dispatcher::current_worker`]), so a synchronous waiter never
/// submits to the worker blocked on this very crossing.
pub(crate) fn acting_for(mark: Option<(usize, u32)>) -> ActingFor {
    ActingFor(ON_WORKER.with(|c| c.replace(mark)))
}

/// [`acting_for`]'s guard: restores the thread's own mark.
pub(crate) struct ActingFor(Option<(usize, u32)>);

impl Drop for ActingFor {
    fn drop(&mut self) {
        ON_WORKER.with(|c| c.set(self.0));
    }
}

pub(crate) fn spawn_worker(w: Arc<Worker>, rx: Receiver<Msg>, env: Arc<Env>) {
    let name = format!("busbar-dispatch-{}", w.index);
    let me = (Arc::as_ptr(&env) as usize, w.index);
    std::thread::Builder::new()
        .name(name)
        .spawn(move || {
            ON_WORKER.with(|c| c.set(Some(me)));
            run(w, rx, env);
        })
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

    /// The host's observability of the dispatcher this adopter belongs to; `None` when it adopts
    /// for no dispatcher (or that one is gone), and the door's back-channel is then dropped.
    pub(crate) fn observing(&self) -> Option<Arc<crate::observe::Observing>> {
        self.pool
            .upgrade()
            .map(|pool| Arc::clone(&pool.env.observing))
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
    /// Workers and a watchdog, per `config`, with no host services bound: every service answers
    /// REFUSED.
    ///
    /// # Panics
    ///
    /// When the OS random source cannot answer the handle key (#74): a boot with no key is refused,
    /// never run under a weaker one. [`Dispatcher::try_new`] answers the refusal instead.
    pub fn new(config: DispatchConfig) -> Self {
        Self::try_new(config).unwrap_or_else(|e| panic!("{e}"))
    }

    /// THE LOADER'S BOOT (#74): the handle key drawn first, then the dispatcher.
    ///
    /// # Errors
    ///
    /// [`LoadError::Entropy`](super::LoadError::Entropy) when the OS random source cannot answer.
    pub fn try_new(config: DispatchConfig) -> Result<Self, super::LoadError> {
        let key = super::handle::ticket_key()?;
        Ok(Self::build(config, None, key))
    }

    /// The connection table's wake: its wake number ([`super::conn_services::conn_ticket`]) routed to
    /// the worker whose ticket it names, with the caller the table registered it for as the
    /// ticket's supplier (#74: a forged generation quarantines that instance; the root's own
    /// identity names none). The root hands it to its one connector.
    #[must_use]
    pub fn conn_waker(&self) -> busbar_contract::conn::ConnWake {
        let pool = Arc::downgrade(&self.pool);
        Arc::new(move |owner, n| {
            if let Some(pool) = pool.upgrade() {
                pool.wake(
                    super::conn_services::ticket_of(n),
                    super::handle::supplier_of(owner),
                );
            }
        })
    }

    /// THE HOST'S OBSERVABILITY of the doors this dispatcher binds: the composition root installs
    /// its plugin observer ([`crate::observe::Observing::install_observer`]) and its own series
    /// predicate ([`crate::observe::Observing::install_host_series`]) here, before the first door
    /// binds, and every door's envelope folds through it.
    #[must_use]
    pub fn observing(&self) -> &crate::observe::Observing {
        &self.pool.env.observing
    }

    /// LEND THIS DISPATCHER THE HOST'S SEAL (Part 2 #54): a kernel-minted `Pass` or `Grant`, what
    /// a door it binds presents to read a resolved `Secret` it hands a plugin (a verify's
    /// credential, a login's submitted fields, an outbound caller credential, a secret source's
    /// material). The composition root lends `busbar_kernel::seal::lend()` on the process's one
    /// dispatcher at boot. The first lend holds; a later one answers `false`. A dispatcher lent no
    /// seal REFUSES every such reveal (fail closed).
    pub fn lend_seal(
        &self,
        seal: impl busbar_contract::plugin::KernelSeal + Send + Sync + 'static,
    ) -> bool {
        self.pool.env.seal.set(Arc::new(seal)).is_ok()
    }

    /// The seal this dispatcher was lent, if any ([`Self::lend_seal`]).
    pub(crate) fn seal(&self) -> Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)> {
        self.pool.env.seal.get().map(|seal| &**seal)
    }

    /// INSTALL THE PROCESS'S RUNTIME every worker runs its crossings inside (see `Env::runtime`):
    /// the one the host drives on a thread of its own. The first install holds; a later one is
    /// ignored and answers `false`. Never taken from a submitter.
    pub fn install_runtime(&self, handle: tokio::runtime::Handle) -> bool {
        // A worker enters it at the top of its next turn, before it runs anything.
        self.pool.env.runtime.set(handle).is_ok()
    }

    /// The runtime the workers run inside, when one is installed.
    #[cfg(test)]
    pub(crate) fn installed_runtime(&self) -> Option<&tokio::runtime::Handle> {
        self.pool.env.runtime.get()
    }

    /// Workers and a watchdog, per `config`, serving the host services the kernel implements.
    ///
    /// # Panics
    ///
    /// As [`Dispatcher::new`]; [`Dispatcher::try_with_services`] answers the refusal instead.
    pub fn with_services(config: DispatchConfig, provider: Arc<dyn HostServices>) -> Self {
        Self::try_with_services(config, provider).unwrap_or_else(|e| panic!("{e}"))
    }

    /// [`Dispatcher::try_new`], serving `provider`.
    ///
    /// # Errors
    ///
    /// [`LoadError::Entropy`](super::LoadError::Entropy) when the OS random source cannot answer.
    pub fn try_with_services(
        config: DispatchConfig,
        provider: Arc<dyn HostServices>,
    ) -> Result<Self, super::LoadError> {
        let key = super::handle::ticket_key()?;
        Ok(Self::build(config, Some(provider), key))
    }

    fn build(
        config: DispatchConfig,
        provider: Option<Arc<dyn HostServices>>,
        ticket_key: super::handle::TicketKey,
    ) -> Self {
        let built = Self::build_unlent(config, provider, ticket_key);
        // This crate's own tests lend the dev-only test seal to every dispatcher they build.
        #[cfg(test)]
        let _ = built.lend_seal(busbar_contract::plugin::TestKernelSeal);
        built
    }

    /// TEST ONLY: a dispatcher lent NO seal, so every reveal its doors would make is refused (the
    /// fail-closed arm of [`Self::lend_seal`]).
    #[cfg(test)]
    pub(crate) fn new_unlent(config: DispatchConfig) -> Self {
        let key = super::handle::ticket_key().unwrap_or_else(|e| panic!("{e}"));
        Self::build_unlent(config, None, key)
    }

    fn build_unlent(
        config: DispatchConfig,
        provider: Option<Arc<dyn HostServices>>,
        ticket_key: super::handle::TicketKey,
    ) -> Self {
        // The last worker index names the inline tickets (`inline::INLINE_WORKER`), never a worker.
        let n = config.workers.clamp(1, MAX_WORKERS - 1);
        let services: Arc<ServiceStore> = Arc::default();
        let env = Arc::new(Env {
            budgets: config.budgets,
            quarantine_after: config.quarantine_after.max(1),
            stats: Arc::default(),
            inline: Arc::new(super::inline::InlineTickets::new(ticket_key, &services)),
            services,
            provider,
            runtime: std::sync::OnceLock::new(),
            io: std::sync::OnceLock::new(),
            observing: Arc::default(),
            ticket_key,
            latch: std::sync::OnceLock::new(),
            seal: std::sync::OnceLock::new(),
        });
        let mut started = Vec::new();
        let slots = (0..n)
            .map(|i| {
                let (w, rx) = Worker::new(i, Vec::new(), ticket_key);
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

    /// The watchdog's budgets this dispatcher runs on.
    #[must_use]
    pub fn budgets(&self) -> Budgets {
        self.pool.env.budgets
    }

    /// What the dispatcher counted.
    pub fn stats(&self) -> DispatchStats {
        let s = &self.pool.env.stats;
        DispatchStats {
            stale_wakes: s.stale_wakes.load(Ordering::Relaxed),
            replacements: s.replacements.load(Ordering::Relaxed),
            quarantined: s.quarantined.load(Ordering::Relaxed),
            write_behind_late: s.write_behind_late.load(Ordering::Relaxed),
            live_reapers: super::load::live_reapers(),
            driver_kept_high: s.driver_kept_high.load(Ordering::Relaxed),
            deadline_without_wake: s.deadline_without_wake.load(Ordering::Relaxed),
            forged_handles: super::handle::forged(),
            handles_latched: super::handle::latched(),
        }
    }

    /// The host services' stored results.
    pub fn services(&self) -> &ServiceStore {
        &self.pool.env.services
    }

    /// The host services this dispatcher serves; `None` when it was built with none, and then
    /// every service answers REFUSED.
    pub fn host_services(&self) -> Option<&Arc<dyn HostServices>> {
        self.pool.env.provider.as_ref()
    }

    fn worker(&self, worker: u32) -> Option<Arc<Worker>> {
        self.pool.slots.get(worker as usize).map(WorkerSlot::get)
    }

    /// Bind `inst`'s wakes to this dispatcher; `false` when it is bound to another.
    fn adopt(&self, inst: &Arc<Instance>) -> bool {
        self.adopter().adopt(inst)
    }

    /// Serve every instance of this dispatcher the HOST'S I/O (`io.*`) from `io`; the first install
    /// stands. `false` when one was installed already.
    pub fn install_io(&self, io: Arc<dyn busbar_contract::io_host::IoHost>) -> bool {
        self.pool.env.io.set(io).is_ok()
    }

    /// A ticket for ops driven INLINE on the calling thread ([`super::inline`]): one per side of a
    /// carrier's connection. `None` when every inline slot is held.
    #[must_use]
    pub fn inline_ticket(&self) -> Option<super::inline::InlineTicket> {
        self.pool.env.inline.mint()
    }

    /// The handle a [`super::Bind`] carries to be adopted by this dispatcher at bind.
    pub fn adopter(&self) -> Adopter {
        Adopter {
            pool: Arc::downgrade(&self.pool),
        }
    }

    /// The host services' store itself (test witness: a test serves into it as an instance's
    /// service call would).
    #[cfg(test)]
    pub(crate) fn service_store(&self) -> Arc<ServiceStore> {
        Arc::clone(&self.pool.env.services)
    }

    /// TEST ONLY: a forged ticket with no supplier counts against `latch`, not the process's.
    #[cfg(test)]
    pub(crate) fn judge_against(&self, latch: &'static super::handle::Latch) {
        assert!(
            self.pool.env.latch.set(latch).is_ok(),
            "one latch per dispatcher"
        );
    }

    /// TEST ONLY: live ticket `t`'s slot as if handed out `count` times; its ticket at that count.
    #[cfg(test)]
    pub(crate) fn seed_count(&self, t: Ticket, count: u32) -> Ticket {
        let (wi, idx) = decode(t.slot);
        let w = self.worker(wi).expect("the ticket's worker");
        let mut st = w.lock();
        let e = &mut st.entries[idx as usize];
        assert!(e.live, "a live ticket");
        e.count = count;
        e.generation = super::handle::ticket_generation(w.key, wi, idx, count);
        w.ticket(idx, e.generation)
    }

    /// TEST ONLY: `t`'s slot as `(live, free, count)` (test witness of a recycle and a retirement).
    #[cfg(test)]
    pub(crate) fn slot_state(&self, t: Ticket) -> (bool, bool, u32) {
        let (wi, idx) = decode(t.slot);
        let w = self.worker(wi).expect("the ticket's worker");
        let st = w.lock();
        let e = &st.entries[idx as usize];
        (e.live, st.free.contains(&idx), e.count)
    }

    /// TEST ONLY: the inline tickets, shared, for a test that mints from inside a hook.
    #[cfg(test)]
    pub(crate) fn inline_tickets_arc(&self) -> Arc<super::inline::InlineTickets> {
        Arc::clone(&self.pool.env.inline)
    }

    /// TEST ONLY: the inline tickets, for a test that seeds a slot's counter.
    #[cfg(test)]
    pub(crate) fn inline_tickets(&self) -> &super::inline::InlineTickets {
        &self.pool.env.inline
    }

    /// TEST ONLY: the dispatcher's ticket key.
    #[cfg(test)]
    pub(crate) fn ticket_key(&self) -> super::handle::TicketKey {
        self.pool.env.ticket_key
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

    /// The index of this dispatcher's worker the calling thread IS; `None` on any other thread. A
    /// synchronous caller that waits on a reply never submits to its own worker: that worker cannot
    /// run the op while its thread waits.
    #[must_use]
    pub fn current_worker(&self) -> Option<u32> {
        let mine = Arc::as_ptr(&self.pool.env) as usize;
        ON_WORKER
            .with(std::cell::Cell::get)
            .filter(|(env, _)| *env == mine)
            .map(|(_, index)| index)
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
        let driver = self.worker(worker)?.mint(Some(Driver {
            instance: inst.clone(),
            frame: Some(K::drive_frame()),
            pending: false,
            wake_at_ns: 0,
            ticks_held: 0,
        }))?;
        self.pool.env.services.held.track(driver);
        Some(driver)
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
        self.submit_with(
            plugin,
            ticket,
            s,
            frame,
            class,
            deadline_ns,
            None,
            Duration::ZERO,
            Admit::Cap,
        )
    }

    /// [`Dispatcher::submit`], with the owner of the memory `frame`'s pointers lend the plugin:
    /// the dispatcher keeps `lent` alive until the op completes (its answer, its `cancel`, or a hung
    /// crossing's return), even when the caller drops the [`Reply`] first ([`Lent`]).
    #[allow(clippy::too_many_arguments)] // `submit`'s six, plus the lent memory
    pub fn submit_lent<K: Kind, I: InFrame, O: OutFrame>(
        &self,
        plugin: &Plugin<K>,
        ticket: Ticket,
        s: u32,
        frame: Frame<I, O>,
        class: DeadlineClass,
        deadline_ns: u64,
        lent: Lent,
    ) -> Reply<I, O> {
        self.submit_with(
            plugin,
            ticket,
            s,
            frame,
            class,
            deadline_ns,
            Some(lent),
            Duration::ZERO,
            Admit::Cap,
        )
    }

    /// [`Dispatcher::submit_lent`], with the op's own WATCH BUDGET: the watchdog faults one of its
    /// crossings only past the longer of `watch` and its class budget, never sooner. The caller
    /// states the budget its row carries (a hook's `timeout_ms`, `BUSBAR-1.6.0.md` §11.7: "The
    /// watchdog's budget is the hook's `timeout_ms`"); every other op keeps its class budget.
    #[allow(clippy::too_many_arguments)] // `submit_lent`'s seven, plus the watch budget
    pub fn submit_watched<K: Kind, I: InFrame, O: OutFrame>(
        &self,
        plugin: &Plugin<K>,
        ticket: Ticket,
        s: u32,
        frame: Frame<I, O>,
        class: DeadlineClass,
        deadline_ns: u64,
        lent: Lent,
        watch: Duration,
    ) -> Reply<I, O> {
        self.submit_with(
            plugin,
            ticket,
            s,
            frame,
            class,
            deadline_ns,
            Some(lent),
            watch,
            Admit::Cap,
        )
    }

    /// [`Dispatcher::submit_lent`] for an op of an ADMITTED UNIT, on the request ticket the unit
    /// minted and reuses for all its ops (`BUSBAR-1.6.0.md` A.4.1: "A request or stream mints one
    /// ticket and reuses it for all its ops"): a plane unit's `on_piece` and `serve`. Like an op on
    /// a driver ticket it holds no `max_inflight` unit, so it is never REFUSED for the instance's
    /// cap: the unit was admitted when it arrived, it has at most one op in flight (its pump awaits
    /// each), and a piece refused mid-answer would cut a stream already answered to its caller.
    /// Everything else is [`Dispatcher::submit_lent`]'s: the instance's own refusals, the drain
    /// count, the lent memory and the watchdog.
    #[allow(clippy::too_many_arguments)] // `submit_lent`'s seven
    pub(crate) fn submit_unit<K: Kind, I: InFrame, O: OutFrame>(
        &self,
        plugin: &Plugin<K>,
        ticket: Ticket,
        s: u32,
        frame: Frame<I, O>,
        class: DeadlineClass,
        deadline_ns: u64,
        lent: Lent,
    ) -> Reply<I, O> {
        self.submit_with(
            plugin,
            ticket,
            s,
            frame,
            class,
            deadline_ns,
            Some(lent),
            Duration::ZERO,
            Admit::Unit,
        )
    }

    /// `tick` at `now_ns` on `driver`, the instance's driver ticket ([`Dispatcher::driver`]). The
    /// head carries `driver`, so a service that pends inside `tick` registers on it and its wake
    /// calls `drive`. Outside `max_inflight`, as every op on a driver ticket: it never holds a
    /// slot. The caller owns the schedule (`TickOut::next_tick_ns`); this is one crossing of it.
    pub fn tick<K: Kind>(
        &self,
        plugin: &Plugin<K>,
        driver: Ticket,
        now_ns: u64,
    ) -> Reply<TickIn, TickOut> {
        let frame = Frame::new(
            TickIn {
                head: in_head(),
                now_ns,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 0,
            },
        );
        let mut reply = self.submit_with(
            plugin,
            driver,
            slot::TICK,
            frame,
            DeadlineClass::Call,
            0,
            None,
            Duration::ZERO,
            Admit::Driver,
        );
        // Dropping it cancels nothing: a client drop would end the instance's driver ticket.
        reply.owner = None;
        reply
    }

    #[allow(clippy::too_many_arguments)]
    fn submit_with<K: Kind, I: InFrame, O: OutFrame>(
        &self,
        plugin: &Plugin<K>,
        ticket: Ticket,
        s: u32,
        frame: Frame<I, O>,
        class: DeadlineClass,
        deadline_ns: u64,
        lent: Option<Lent>,
        watch: Duration,
        admit: Admit,
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
        // An op on a driver ticket, or of an admitted unit ([`Dispatcher::submit_unit`]), holds no
        // `max_inflight` unit.
        let Some(units) = (if admit == Admit::Cap {
            inst.acquire(s)
        } else {
            Some(0)
        }) else {
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
        // An admitted unit's op is IN FLIGHT until it ends: `close` is refused while one is.
        let unit = admit == Admit::Unit;
        if unit {
            inst.unit_ops.fetch_add(1, Ordering::SeqCst);
        }
        let slot = Arc::new(ReplySlot::new());
        let meta = Meta {
            instance: inst.clone(),
            slot: s,
            class,
            deadline_ns,
            in_size: size_of::<I>() as u32,
            watch,
            units,
            units_held: true,
            lifecycle,
            drainable,
            unit,
            reply: slot.clone(),
        };
        let job = Box::new(JobOf {
            frame: Box::new(frame),
            reply: slot.clone(),
            lent,
        });
        self.pool.send(ticket, Msg::Submit { ticket, meta, job });
        Reply {
            slot,
            owner: Some((ticket, Arc::downgrade(&self.pool))),
        }
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
