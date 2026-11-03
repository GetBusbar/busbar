// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
use super::services::{HostServices, Served, ServiceStore, ServicesSlot};
use super::ticket::{decode, encode, WakeRoute, MAX_INDEX, MAX_WORKERS};
use super::{in_head, now_ns, out_head, watchdog, DriveFrame, Frame, InFrame, Kind, OutFrame};

#[path = "worker_unit_cancel.rs"]
mod unit_cancel;

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

pub const DEFAULT_QUARANTINE_AFTER: u32 = 1;

pub const QUARANTINED_TOTAL: &str = "bb_plugin_quarantined_total";

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

pub type CounterFamily = (&'static str, &'static str, u64);

impl DispatchStats {
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

pub(crate) struct Env {
    pub(crate) budgets: Budgets,

    pub(crate) quarantine_after: u32,
    pub(crate) stats: Arc<Stats>,

    pub(crate) services: Arc<ServiceStore>,

    pub(crate) provider: Arc<ServicesSlot>,

    pub(crate) runtime: std::sync::OnceLock<tokio::runtime::Handle>,

    pub(crate) io: std::sync::OnceLock<Arc<dyn busbar_contract::io_host::IoHost>>,

    pub(crate) auth: std::sync::OnceLock<Arc<dyn super::auth_handle::AuthHandleHost>>,

    pub(crate) inline: Arc<super::inline::InlineTickets>,

    pub(crate) observing: Arc<crate::observe::Observing>,

    pub(crate) ticket_key: super::handle::TicketKey,

    latch: std::sync::OnceLock<&'static super::handle::Latch>,

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
    pub frame: Option<Frame<I, O>>,
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

struct Queued<I, O> {
    done: Done<I, O>,
    lease: UnhandedLease,
    short: UnhandedShort,
}
impl<I, O> Queued<I, O> {
    fn unleased(done: Done<I, O>) -> Self {
        Self {
            done,
            lease: UnhandedLease(None),
            short: UnhandedShort(None),
        }
    }
    fn take(mut self) -> Done<I, O> {
        if let Some(lease) = self.lease.0.as_mut() {
            lease.id = 0;
        }
        self.short.0 = None;
        self.done
    }
}

struct UnhandedLease(Option<LeaseReturn>);

pub(crate) struct ShortLease {
    id: AtomicU64,
    instance: Arc<Instance>,
    framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
}
impl ShortLease {
    fn release(&self) {
        let id = self.id.swap(0, Ordering::AcqRel);
        if id != 0 {
            drop_after_lock(Box::new(LeaseReturn {
                instance: Arc::clone(&self.instance),
                framing: self.framing.clone(),
                id,
            }));
        }
    }
}
impl Drop for ShortLease {
    fn drop(&mut self) {
        self.release();
        hold_past_lock(&self.instance);
        if let Some(framing) = self.framing.take() {
            drop_after_lock(Box::new(framing));
        }
    }
}
struct UnhandedShort(Option<Arc<ShortLease>>);
impl Drop for UnhandedShort {
    fn drop(&mut self) {
        if let Some(short) = self.0.take() {
            short.release();
        }
    }
}
impl UnhandedLease {
    fn new(
        instance: &Arc<Instance>,
        framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
        id: u64,
    ) -> Self {
        Self((id != 0).then(|| LeaseReturn {
            instance: Arc::clone(instance),
            framing,
            id,
        }))
    }
}
impl Drop for UnhandedLease {
    fn drop(&mut self) {
        if let Some(lease) = self.0.take() {
            drop_after_lock(Box::new(lease));
        }
    }
}
struct LeaseReturn {
    instance: Arc<Instance>,
    framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    id: u64,
}
impl Drop for LeaseReturn {
    fn drop(&mut self) {
        if self.id != 0 {
            let _scope = super::framing_context::enter(self.framing.clone());
            self.instance.release_unread(self.id);
        }
    }
}

struct ReplySlot<T> {
    v: Mutex<SlotState<T>>,
    cv: Condvar,
}

struct SlotState<T> {
    settled: bool,

    abandoned: bool,
    value: Option<T>,

    waker: Option<Waker>,
}

impl<T> ReplySlot<T> {
    fn new() -> Self {
        Self {
            v: Mutex::new(SlotState {
                settled: false,
                abandoned: false,
                value: None,
                waker: None,
            }),
            cv: Condvar::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, SlotState<T>> {
        self.v.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn put(&self, t: T) -> bool {
        let mut value = Some(t);
        let (accepted, waker) = {
            let mut g = self.lock();
            if g.settled {
                (false, None)
            } else {
                g.settled = true;
                let accepted = !g.abandoned;
                if accepted {
                    g.value = value.take();
                }
                (accepted, g.waker.take())
            }
        };

        drop(value);
        self.cv.notify_all();
        if let Some(waker) = waker {
            drop_after_lock(Box::new(WakeAfterLock(Some(waker))));
        }
        accepted
    }
}

pub(crate) trait Settle: Send + Sync {
    fn settle(&self, outcome: Outcome, detached: bool) -> bool;
}

impl<I: InFrame, O: OutFrame> Settle for ReplySlot<Queued<I, O>> {
    fn settle(&self, outcome: Outcome, detached: bool) -> bool {
        self.put(Queued::unleased(Done {
            outcome,
            error: None,
            lease: 0,
            frame: None,
            detached,
            short: false,
            disposition: None,
            cancel_writes: Vec::new(),
        }))
    }
}

pub struct Reply<I, O> {
    slot: Arc<ReplySlot<Queued<I, O>>>,

    owner: Option<(Ticket, Weak<Pool>)>,
}

impl<I, O> std::fmt::Debug for Reply<I, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply").finish_non_exhaustive()
    }
}

impl<I: InFrame, O: OutFrame> Reply<I, O> {
    pub fn wait(&self, timeout: Duration) -> Option<Done<I, O>> {
        let until = Instant::now() + timeout;
        let mut g = self.slot.lock();
        loop {
            if let Some(d) = g.value.take() {
                drop(g);
                return Some(d.take());
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

    pub fn wait_done(&self) -> Done<I, O> {
        let mut g = self.slot.lock();
        loop {
            if let Some(d) = g.value.take() {
                drop(g);
                return d.take();
            }
            g = self.slot.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn settled(outcome: Outcome, frame: Frame<I, O>) -> Self {
        let slot = Arc::new(ReplySlot::new());
        slot.put(Queued::unleased(Done {
            outcome,
            error: None,
            lease: 0,
            frame: Some(frame),
            detached: false,
            short: false,
            disposition: None,
            cancel_writes: Vec::new(),
        }));
        Self { slot, owner: None }
    }

    pub fn detach(mut self) {
        self.owner = None;
    }
}

impl<I: InFrame, O: OutFrame> Future for Reply<I, O> {
    type Output = Done<I, O>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Done<I, O>> {
        let mut waker = Some(cx.waker().clone());
        let mut g = self.slot.lock();
        if let Some(d) = g.value.take() {
            drop(g);
            return Poll::Ready(d.take());
        }
        let old = match &g.waker {
            Some(w) if w.will_wake(waker.as_ref().expect("new waiter")) => None,
            _ => std::mem::replace(&mut g.waker, waker.take()),
        };
        drop(g);
        drop(old);
        Poll::Pending
    }
}

impl<I, O> Drop for Reply<I, O> {
    fn drop(&mut self) {
        let (settled, value, waker) = {
            let mut g = self.slot.v.lock().unwrap_or_else(|e| e.into_inner());
            g.abandoned = true;
            (g.settled, g.value.take(), g.waker.take())
        };
        drop(waker);
        drop(value);
        if settled {
            return;
        }
        if let Some((ticket, pool)) = self.owner.take() {
            if let Some(pool) = pool.upgrade() {
                pool.send(ticket, Msg::DropClient(ticket));
            }
        }
    }
}

pub(crate) trait Job: Send {
    fn heads(&mut self) -> (*mut InHead, *mut OutHead, u32);
    fn keep_lent(&self) -> Option<Lent>;
    fn closes_unit(&self, slot: u32, final_answer: bool) -> bool;

    fn finish(self: Box<Self>, c: Crossed, short: Option<Arc<ShortLease>>) -> bool;
}

struct JobOf<I, O> {
    frame: Frame<I, O>,
    reply: Arc<ReplySlot<Queued<I, O>>>,
    instance: Arc<Instance>,
    framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,

    lent: Option<Lent>,
}

pub type Lent = Arc<dyn std::any::Any + Send + Sync>;

impl<I: InFrame, O: OutFrame> Job for JobOf<I, O> {
    fn heads(&mut self) -> (*mut InHead, *mut OutHead, u32) {
        self.frame.heads()
    }

    fn keep_lent(&self) -> Option<Lent> {
        self.lent.clone()
    }

    fn closes_unit(&self, slot: u32, final_answer: bool) -> bool {
        unit_cancel::closes(&self.instance, slot, &self.frame, final_answer)
    }

    fn finish(self: Box<Self>, c: Crossed, short: Option<Arc<ShortLease>>) -> bool {
        let lease = UnhandedLease::new(&self.instance, self.framing.clone(), c.lease);
        self.reply.put(Queued {
            done: Done {
                outcome: c.outcome,
                error: c.error,
                lease: c.lease,
                frame: Some(self.frame),
                detached: false,
                short: c.short,
                disposition: c.disposition,
                cancel_writes: c.cancel_writes,
            },
            lease,
            short: UnhandedShort(short),
        })
    }
}

impl<I, O> Drop for JobOf<I, O> {
    fn drop(&mut self) {
        if self.lent.is_some() || self.framing.is_some() {
            drop_after_lock(Box::new((self.lent.take(), self.framing.take())));
        }
        hold_past_lock(&self.instance);
    }
}

pub(crate) struct Meta {
    pub(crate) instance: Arc<Instance>,
    framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    tracing: Option<Arc<TraceContext>>,
    slot: u32,
    class: DeadlineClass,
    deadline_ns: u64,
    in_size: u32,

    watch: Duration,

    units: u32,

    units_held: bool,
    lifecycle: bool,
    drainable: bool,

    unit: bool,

    unit_key: Option<u64>,
    unit_final: bool,

    tick_copy: bool,
    pub(crate) reply: Arc<dyn Settle>,
}

/// How an op submitted is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// Under the instance's `max_inflight` ([`Instance::acquire`]).
    Cap,
    /// On a driver ticket: outside `max_inflight`.
    Driver,
    /// A plane driver tick whose caller only copies the scalar schedule.
    DriverCopy,
    /// An op of an admitted unit: outside `max_inflight`, and in flight for `close`.
    Unit,
}

impl Meta {
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
        if let Some(framing) = self.framing.take() {
            drop_after_lock(Box::new(framing));
        }
        if let Some(tracing) = self.tracing.take() {
            drop_after_lock(Box::new(tracing));
        }
    }
}

/// The submitting host's context, never a parent supplied by a plugin. Shared so selecting a
/// queued crossing under the worker lock calls no subscriber, including `Span::clone`/`drop`.
struct TraceContext {
    dispatch: tracing::Dispatch,
    span: tracing::Span,
}

impl TraceContext {
    fn current() -> Arc<Self> {
        Arc::new(Self {
            dispatch: tracing::dispatcher::get_default(Clone::clone),
            span: tracing::Span::current(),
        })
    }

    fn in_scope<T>(&self, f: impl FnOnce() -> T) -> T {
        tracing::dispatcher::with_default(&self.dispatch, || self.span.in_scope(f))
    }
}

std::thread_local! {
    /// THE INSTANCES A WORKER LOOP LETS GO WITH NO LOCK HELD (THE DESIGN §11.13 M1, "No plugin code
    /// (`dlclose` included) runs under a host lock"): `Some` on a dispatcher worker's own thread
    /// while [`run`] runs. An op's [`Meta`] and a driver ticket's [`Driver`] are let go while the
    /// worker's state lock is held, and either may hold an instance's last reference, whose drop
    /// closes its connections (a transport's code) and unloads its library. Each keeps its instance
    /// here instead, and the loop lets the list go once the lock is released.
    /// The dials a recycled or restarted ticket left in flight ([`super::conn_services::Closes`])
    /// are kept here the same way: their close may cross into a transport door.
    static LET_GO: std::cell::RefCell<Option<Vec<Late>>> =
        const { std::cell::RefCell::new(None) };
}

type Late = Box<dyn std::any::Any>;

pub(crate) fn drop_after_lock(value: Late) {
    let mut value = Some(value);
    let _ = LET_GO.try_with(|list| {
        if let Some(held) = list.borrow_mut().as_mut() {
            held.extend(value.take());
        }
    });
    drop(value);
}

struct WakeAfterLock(Option<Waker>);
impl Drop for WakeAfterLock {
    fn drop(&mut self) {
        if let Some(waker) = self.0.take() {
            waker.wake();
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
struct RetirementAck {
    prior: Vec<Late>,
    ack: Sender<()>,
}

#[cfg(any(test, feature = "test-support"))]
impl Drop for RetirementAck {
    fn drop(&mut self) {
        for owner in std::mem::take(&mut self.prior) {
            drop(owner);
        }
        let _ = self.ack.send(());
    }
}

fn hold_past_lock(instance: &Arc<Instance>) {
    let _ = LET_GO.try_with(|l| {
        if let Some(held) = l.borrow_mut().as_mut() {
            held.push(Box::new(Arc::clone(instance)));
        }
    });
}

fn forget_conns(id: InstanceId, ticket: Ticket) -> usize {
    let (kept, closes) = super::conn_services::forget(id, ticket);
    let mut closes = Some(closes);
    let _ = LET_GO.try_with(|l| {
        if let Some(held) = l.borrow_mut().as_mut() {
            held.extend(closes.take().map(|c| Box::new(c) as Late));
        }
    });
    drop(closes);
    kept
}

fn let_go() -> Vec<Late> {
    LET_GO.with(|l| {
        l.borrow_mut()
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    })
}

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

    job: Option<Box<dyn Job>>,
    pending: bool,
    wake_at_ns: u64,
    detached: bool,

    parked: bool,
}

/// THE NAMES A DRIVER TICKET'S READY OR PENDING `drive` ANSWERED (a plane's ready sessions), held for the
/// host until it collects them ([`Driven::take`]): each once, at most [`Driven::HELD`] at a time
/// (a plane that names more before the host collects is told nothing new until it wakes again).
#[derive(Debug, Default)]
#[doc(hidden)]
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

    fn answer(&self, outcome: Outcome) {
        let mut a = self.answers.lock().unwrap_or_else(|e| e.into_inner());
        *a = (a.0 + 1, Some(outcome));
        drop(a);
        self.answered.notify_all();
    }

    pub fn answers(&self) -> u64 {
        self.answers.lock().unwrap_or_else(|e| e.into_inner()).0
    }

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

    pub fn drain(&self) -> Vec<u64> {
        std::mem::take(&mut *self.names.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn drove(&self) {
        self.woke.notify_one();
    }

    pub(crate) async fn woken(&self) {
        self.woke.notified().await;
    }

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
    tracing: Option<Arc<TraceContext>>,

    frame: Option<Box<dyn DriveFrame>>,
    pending: bool,
    wake_at_ns: u64,

    ticks_held: u32,
}

impl Drop for Driver {
    fn drop(&mut self) {
        hold_past_lock(&self.instance);
        if let Some(tracing) = self.tracing.take() {
            drop_after_lock(Box::new(tracing));
        }
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
    /// Immutable negotiated SHORT storage belongs to this live ticket until recall or abandon.
    short_reply: Option<UnhandedShort>,
    next: Option<Action>,
    pub(crate) current: Option<Current>,
    pub(crate) queue: VecDeque<(Meta, Box<dyn Job>)>,
    pub(crate) driver: Option<Driver>,
    /// The connection-table identity of every instance whose op ran on this ticket: the connector
    /// slots' kept answers are forgotten under each of them, and only them, when it is recycled.
    pub(crate) conns: Vec<InstanceId>,
    unit_binding: Option<unit_cancel::Binding>,
    unit_waiters: Vec<unit_cancel::Waiter>,
}

impl Entry {
    fn note(&mut self, id: InstanceId) {
        if !self.conns.contains(&id) {
            self.conns.push(id);
        }
    }
}

#[derive(Default)]
pub(crate) struct WorkerState {
    pub(crate) dead: bool,
    /// The instance of the crossing this worker is inside, for the watchdog's breach: set before
    /// the lock is let go for the crossing, cleared once it is taken back.
    pub(crate) crossing: Option<Arc<Instance>>,
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

    Wake(Ticket, Option<&'static super::ticket::InstanceWake>),
    DropClient(Ticket),
    Recycle(Ticket),
    #[cfg(any(test, feature = "test-support"))]
    RetirementBarrier(Sender<()>),
    BindUnit {
        ticket: Ticket,
        instance: Arc<Instance>,
        unit: u64,
    },
    CancelUnit {
        ticket: Ticket,
        instance: Arc<Instance>,
        unit: u64,
        waiter: unit_cancel::Waiter,
    },
    Stop,
}

pub(crate) struct Worker {
    pub(crate) index: u32,

    key: super::handle::TicketKey,
    tx: Sender<Msg>,
    pub(crate) state: Mutex<WorkerState>,

    pub(crate) crossing_since: AtomicU64,

    pub(crate) crossing_budget: AtomicU64,
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

pub(crate) struct Pool {
    pub(crate) slots: Box<[WorkerSlot]>,
    pub(crate) env: Arc<Env>,
    pub(crate) stop: AtomicBool,

    pub(crate) adopted: Mutex<Vec<Weak<Instance>>>,
}

impl WakeRoute for Pool {
    fn wake(&self, t: Ticket, supplier: Option<&'static super::ticket::InstanceWake>) {
        if super::inline::is_inline(t) {
            if self.env.inline.wake(t) == super::inline::Judged::Forged {
                super::handle::forged_ticket(supplier, self.env.latch());
            }
            return;
        }
        let (w, _) = decode(t.slot);
        match self.slots.get(w as usize) {
            Some(slot) => {
                let _ = slot.get().tx.send(Msg::Wake(t, supplier));
            }
            None => {
                self.env.stats.stale_wakes.fetch_add(1, Ordering::Relaxed);
                super::handle::forged_ticket(supplier, self.env.latch());
            }
        }
    }

    fn services(&self) -> Option<Served<'_>> {
        Some(Served {
            store: &self.env.services,
            provider: self.env.provider.get()?.as_ref(),
        })
    }

    fn store(&self) -> Option<Arc<ServiceStore>> {
        Some(Arc::clone(&self.env.services))
    }

    fn io(&self) -> Option<Arc<dyn busbar_contract::io_host::IoHost>> {
        self.env.io.get().cloned()
    }

    fn service_store(&self) -> Option<Arc<ServiceStore>> {
        Some(Arc::clone(&self.env.services))
    }

    fn auth_handle(&self) -> Option<Arc<dyn super::auth_handle::AuthHandleHost>> {
        self.env.auth.get().cloned()
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
            let _ = slot.get().tx.send(m);
        }
    }
}

impl Worker {
    pub(crate) fn new(
        index: u32,
        counts: Vec<Option<u32>>,
        key: super::handle::TicketKey,
    ) -> (Arc<Self>, Receiver<Msg>) {
        let (tx, rx) = channel();

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
            crossing_since: AtomicU64::new(0),
            crossing_budget: AtomicU64::new(0),
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

    fn owe_drive(st: &mut WorkerState, idx: u32) {
        match st.entries[idx as usize].next {
            None | Some(Action::Drive) => Self::schedule(st, idx, Action::Drive),
            Some(_) => st.entries[idx as usize].latched = true,
        }
    }

    fn apply(&self, st: &mut WorkerState, m: Msg, env: &Env) -> bool {
        match m {
            Msg::Submit {
                ticket,
                mut meta,
                job,
            } => {
                if self.entry(st, ticket).is_none() {
                    drop(meta);
                    drop_after_lock(Box::new(job));
                    return true;
                }
                if !self.accept_unit(st, ticket, &meta) {
                    meta.give_back();
                    meta.reply.settle(Outcome::Refused, false);
                    return true;
                }
                match self.entry(st, ticket) {
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

                    _ => drop(meta),
                }
            }
            Msg::Wake(t, supplier) => match self.entry(st, t) {
                None => {
                    env.stats.stale_wakes.fetch_add(1, Ordering::Relaxed);

                    if !self.ever_minted(st, t) {
                        st.forged.push(supplier);
                    }
                }
                Some((idx, e)) => {
                    if e.unit_binding.as_ref().is_some_and(|b| b.closed()) {
                        return true;
                    }
                    if e.driver.is_some() {
                        Self::owe_drive(st, idx);
                    } else if e.current.as_ref().is_some_and(|c| c.pending) {
                        Self::schedule(st, idx, Action::Resume);
                    } else if e.current.is_none() && !e.queue.is_empty() {
                        Self::schedule(st, idx, Action::Start);
                    } else {
                        e.latched = true;
                    }
                }
            },
            Msg::DropClient(t) => {
                if let Some((idx, e)) = self.entry(st, t) {
                    e.client_dropped = true;
                    e.short_reply = None;
                    e.short_slot = None;
                    if e.unit_binding.is_some() {
                        Self::schedule(st, idx, Action::Cancel);
                        return true;
                    }
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

                        if e.current.as_ref().is_some_and(|c| c.parked) {
                            self.end(st, idx, Crossed::host(Outcome::Refused), env);
                        }
                    }
                }
            }
            #[cfg(any(test, feature = "test-support"))]
            Msg::RetirementBarrier(ack) => {
                let prior = let_go();
                drop_after_lock(Box::new(RetirementAck { prior, ack }));
            }
            Msg::BindUnit {
                ticket,
                instance,
                unit,
            } => {
                self.bind_unit_entry(st, ticket, &instance, unit);
                drop_after_lock(Box::new(instance));
            }
            Msg::CancelUnit {
                ticket,
                instance,
                unit,
                waiter,
            } => {
                self.request_unit_cancel(st, ticket, &instance, unit, waiter);
                drop_after_lock(Box::new(instance));
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
            forget_conns(id, ticket);
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
        e.short_reply = None;
        e.next = None;
        e.driver = None;
        e.unit_binding = None;
        e.unit_waiters.clear();

        if next.is_some() {
            st.free.push(idx);
        }
    }

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

    fn end(&self, st: &mut WorkerState, idx: u32, mut c: Crossed, env: &Env) {
        let e = &mut st.entries[idx as usize];
        let Some(cur) = e.current.take() else {
            return;
        };

        let owed = e.driver.is_some() && std::mem::take(&mut e.latched);
        e.latched = false;

        let recall = e.short_slot.take() == Some(cur.meta.slot);
        e.short_reply = None;
        if c.short && recall {
            let _lease = UnhandedLease::new(&cur.meta.instance, cur.meta.framing.clone(), c.lease);
            let _short =
                UnhandedLease::new(&cur.meta.instance, cur.meta.framing.clone(), c.short_lease);
            c = Crossed::host(Outcome::Fault);
        } else if c.short {
            e.short_slot = Some(cur.meta.slot);
            let lease = std::mem::take(&mut c.short_lease);
            if lease != 0 {
                let owner = Arc::new(ShortLease {
                    instance: Arc::clone(&cur.meta.instance),
                    framing: cur.meta.framing.clone(),
                    id: AtomicU64::new(lease),
                });
                if !e.client_dropped && !e.recycle_when_idle {
                    e.short_reply = Some(UnhandedShort(Some(owner)));
                }
            }
        }
        let mut cur = cur;
        cur.meta.give_back();
        if let Some(job) = cur.job {
            let short = e.short_reply.as_ref().and_then(|owner| owner.0.clone());
            if !job.finish(c, short) {
                e.short_reply = None;
                env.stats.write_behind_late.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(cur.meta);
        if !e.queue.is_empty() {
            Self::schedule(st, idx, Action::Start);
        } else if e.recycle_when_idle {
            self.recycle_now(st, idx, env);
        }
        if owed {
            Self::owe_drive(st, idx);
        }
    }

    fn timers(&self, st: &mut WorkerState, now: u64, env: &Env) -> Duration {
        let mut without_wake = 0_u64;
        let mut next = u64::MAX;
        let mut due = Vec::new();
        for (idx, e) in st.entries.iter_mut().enumerate() {
            let owed = !matches!(e.next, Some(Action::Resume));
            if let Some(c) = e.current.as_mut().filter(|c| c.pending) {
                let (class, deadline) = (c.meta.class, c.meta.deadline_ns);
                if deadline != 0 && class != DeadlineClass::WriteBehind {
                    if now >= deadline {
                        without_wake += u64::from(owed);
                        due.push((idx as u32, Action::Cancel));
                        continue;
                    }
                    next = next.min(deadline);
                }
                if deadline != 0 && class == DeadlineClass::WriteBehind && !c.detached {
                    if now >= deadline {
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

    fn cross<'a>(
        &'a self,
        mut st: MutexGuard<'a, WorkerState>,
        instance: &Arc<Instance>,
        s: u32,
        heads: (*mut InHead, *mut OutHead, u32),
        budget: Duration,
        framing: Option<Arc<dyn busbar_contract::framing_scope::FramingScope>>,
    ) -> Option<(MutexGuard<'a, WorkerState>, Crossed)> {
        st.crossing = Some(instance.clone());
        // Only a raw driver's TICK hands its PENDING frame to a caller. Ordinary PENDING
        // and DRIVE retain host frames, but no caller owns their intermediate answer leases.
        // Instance::cross already copied the common head and negotiated reply extensions.
        // SAFETY: this crossing owns the host input frame.
        let ticket = unsafe { (*heads.0).ticket };
        let entry = st.entries.get(decode(ticket.slot).1 as usize);
        let tracing = entry.and_then(|e| {
            e.current
                .as_ref()
                .and_then(|c| c.meta.tracing.clone())
                .or_else(|| e.driver.as_ref().and_then(|d| d.tracing.clone()))
        });
        let tick_copy = s == slot::TICK
            && entry
                .and_then(|e| e.current.as_ref())
                .is_some_and(|c| c.meta.tick_copy);
        let pending_is_handed =
            s == slot::TICK && !tick_copy && entry.is_some_and(|e| e.driver.is_some());
        let budget = u64::try_from(budget.as_nanos()).unwrap_or(u64::MAX);
        self.crossing_budget.store(budget, Ordering::Relaxed);
        self.crossing_since
            .store(now_ns().max(1), Ordering::Release);
        drop(st);
        let crossing = || {
            let _framing = super::framing_context::enter(framing.clone());
            // SAFETY: the frame is boxed and owned by this crossing; `s` passed `refuse` at submit.
            unsafe { instance.cross(s, heads.0, heads.1, heads.2) }
        };
        let mut crossed = match &tracing {
            Some(tracing) => tracing.in_scope(crossing),
            None => crossing(),
        };
        if tick_copy || (crossed.outcome == Outcome::Pending && !pending_is_handed) {
            let lease = std::mem::take(&mut crossed.lease);
            if lease != 0 {
                let _scope = super::framing_context::enter(framing.clone());
                match &tracing {
                    Some(tracing) => tracing.in_scope(|| instance.release_unread(lease)),
                    None => instance.release_unread(lease),
                }
            }
        }
        self.crossing_since.store(0, Ordering::Release);
        let mut st = self.lock();
        st.crossing = None;
        if st.dead {
            drop(st);
            let release = || {
                let _scope = super::framing_context::enter(framing);
                if crossed.lease != 0 {
                    instance.release_unread(crossed.lease);
                }
                if crossed.short_lease != 0 {
                    instance.release_unread(crossed.short_lease);
                }
            };
            match &tracing {
                Some(tracing) => tracing.in_scope(release),
                None => release(),
            }
            None
        } else {
            // A span's final drop can export its record and re-enter this dispatcher.
            // Its crossing guards ended before the lock; defer the context's owner drop too.
            drop_after_lock(Box::new(tracing));
            Some((st, crossed))
        }
    }

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
                let admission = match e.queue.front() {
                    Some((meta, _)) => meta.instance.export_admission(meta.slot, ticket),
                    None => return Some(st),
                };
                let Ok(admission) = admission else {
                    return Some(st);
                };
                if let Some(admission) = admission {
                    drop_after_lock(Box::new(admission));
                }
                let Some((meta, mut job)) = e.queue.pop_front() else {
                    return Some(st);
                };
                if e.short_reply
                    .as_ref()
                    .and_then(|owner| owner.0.as_ref())
                    .is_some_and(|kept| {
                        kept.id.load(Ordering::Acquire) == 0
                            || e.short_slot != Some(meta.slot)
                            || !Arc::ptr_eq(&kept.instance, &meta.instance)
                    })
                {
                    e.short_reply = None;
                    e.short_slot = None;
                }

                let (mut full, mut kept_cycle) = (false, false);
                if let Some(d) = e.driver.as_ref() {
                    let held = env.services.held.held(ticket);
                    if d.ticks_held == 0 && !d.pending && held == 0 {
                        let kept = env.services.forget(ticket)
                            + forget_conns(meta.instance.instance, ticket);
                        env.services.held.forget(ticket);
                        env.stats
                            .driver_kept_high
                            .fetch_max(kept as u64, Ordering::Relaxed);
                    } else {
                        kept_cycle = true;
                        full = held >= meta.instance.cap;
                    }
                } else if e.short_slot != Some(meta.slot) {
                    env.services.forget(ticket);
                    forget_conns(meta.instance.instance, ticket);
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
                let admission = cur
                    .meta
                    .instance
                    .binding_resume_admission(cur.meta.slot, ticket);
                let Ok(admission) = admission else {
                    return Some(st);
                };
                if let Some(admission) = admission {
                    drop_after_lock(Box::new(admission));
                }
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
                if e.unit_binding.is_some() {
                    return self.cancel_unit_group(st, idx, env);
                }
                let Some(cur) = e.current.as_mut() else {
                    return Some(st);
                };
                cur.pending = false;
                let inst = cur.meta.instance.clone();
                let framing = cur.meta.framing.clone();
                let class = cur.meta.class;
                let op_slot = cur.meta.slot;
                let timeout = inst.timeout;
                if inst.faulted.load(Ordering::Acquire) {
                    self.end(&mut st, idx, Crossed::host(Outcome::Fault), env);
                    return Some(st);
                }

                let unit = match cur.job.as_mut() {
                    Some(job) => {
                        let (input, _, _) = job.heads();
                        (inst.unit_of)(op_slot, input.cast_const(), cur.meta.in_size as usize)
                    }
                    None => None,
                };

                let mut frame = (inst.cancel_frame)();
                frame.name_unit(unit.unwrap_or(0));
                let heads = frame.prepare(ticket, class as u8);
                let budget = env.budgets.of(slot::CANCEL, class);
                let (mut st, c) =
                    self.cross(st, &inst, slot::CANCEL, heads, budget, framing.clone())?;
                let _cancel_lease = UnhandedLease::new(&inst, framing.clone(), c.lease);

                if op_slot == slot::OPEN
                    && inst.half_open()
                    && !inst.faulted.load(Ordering::Acquire)
                {
                    let (mut input, mut out) = (in_head(), out_head());
                    let heads = (&raw mut input, &raw mut out, size_of::<OutHead>() as u32);
                    let budget = env.budgets.of(slot::CLOSE, class);
                    let (back, closed) =
                        self.cross(st, &inst, slot::CLOSE, heads, budget, framing)?;
                    st = back;
                    if closed.outcome != Outcome::Ready {
                        tracing::warn!(
                            plugin = %inst.name(),
                            outcome = ?closed.outcome,
                            "the close of a cancelled open's half-open box did not answer READY"
                        );
                    }
                }

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
                let framing = e.current.as_ref().and_then(|c| c.meta.framing.clone());
                let idle = e.current.is_none();
                let Some(d) = e.driver.as_mut() else {
                    return Some(st);
                };
                if idle && !d.pending && d.ticks_held == 0 && env.services.held.held(ticket) == 0 {
                    // An autonomous wake can start a new cycle without Action::Start.
                    // Only a custody-empty cycle may release its preceding generation pin.
                    env.services.forget(ticket);
                    forget_conns(d.instance.instance, ticket);
                    env.services.held.forget(ticket);
                }
                let admission = d.instance.binding_resume_admission(slot::DRIVE, ticket);
                let Ok(admission) = admission else {
                    return Some(st);
                };
                if let Some(admission) = admission {
                    drop_after_lock(Box::new(admission));
                }
                let inst = d.instance.clone();
                if inst.faulted.load(Ordering::Acquire) || !inst.is_open() {
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
                let (mut st, c) =
                    self.cross(st, &inst, slot::DRIVE, heads, budget, framing.clone())?;
                let _drive_lease = UnhandedLease::new(&inst, framing, c.lease);
                env.services.held.leave(ticket);
                if matches!(c.outcome, Outcome::Ready | Outcome::Pending) {
                    inst.driven.name(frame.named());
                }
                inst.driven.answer(c.outcome);
                let e = &mut st.entries[idx as usize];
                if e.generation == generation {
                    if let Some(d) = e.driver.as_mut() {
                        d.frame = Some(frame);
                        d.pending = c.outcome == Outcome::Pending;
                        d.wake_at_ns = c.wake_at_ns;

                        if !d.pending {
                            d.ticks_held = 0;
                            env.services.held.drained(ticket);
                        }
                        if d.pending && std::mem::take(&mut e.latched) {
                            Self::schedule(&mut st, idx, Action::Drive);
                        }
                    }
                }

                if st.entries[idx as usize].generation == generation {
                    self.unpark(&mut st, idx, env);
                }

                inst.driven.drove();
                Some(st)
            }
        }
    }

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
        let framing = cur.meta.framing.clone();
        let mut job = cur.job.take()?;
        let heads = job.heads();
        let reference = st.entries[idx as usize]
            .short_reply
            .as_ref()
            .and_then(|owner| owner.0.as_ref())
            .map(|kept| kept.id.load(Ordering::Acquire))
            .filter(|&id| id != 0);
        // SAFETY: `job` exclusively owns this frame until after the guard restores its head.
        let _reference = match reference {
            Some(lease) => match unsafe { super::plugin::RecallInput::new(heads.0, lease) } {
                Ok(reference) => Some(reference),
                Err(()) => {
                    st.entries[idx as usize].current.as_mut()?.job = Some(job);
                    self.end(&mut st, idx, Crossed::host(Outcome::Refused), env);
                    return Some(st);
                }
            },
            None => None,
        };
        let (mut st, c) = self.cross(st, inst, s, heads, budget, framing)?;
        drop(_reference);
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
            if let Some(d) = e.driver.as_mut().filter(|_| c.outcome == Outcome::Pending) {
                d.ticks_held = d.ticks_held.saturating_add(1);
            }
            self.finish_unit_answer(&mut st, idx, &c, env);
            self.end(&mut st, idx, c, env);
        }
        Some(st)
    }

    pub(crate) fn fault_all(st: &mut WorkerState) -> Vec<Entry> {
        st.runnable.clear();
        st.free.clear();
        std::mem::take(&mut st.entries)
    }

    pub(crate) fn orphans(
        &self,
        gone: Vec<Entry>,
        wedged: &Arc<Instance>,
    ) -> (Vec<Orphan>, Vec<Entry>) {
        unit_cancel::group_orphans(self, gone, wedged)
    }
}

pub(crate) struct Orphan {
    entries: Vec<(Ticket, Entry)>,
}

impl Drop for Orphan {
    fn drop(&mut self) {
        for (ticket, entry) in &self.entries {
            for id in &entry.conns {
                drop(super::conn_services::forget(*id, *ticket));
            }
        }
    }
}

impl Orphan {
    pub(crate) fn fault_replies(&mut self) {
        unit_cancel::fault_orphan_replies(self);
    }

    pub(crate) fn cancel(self) {
        unit_cancel::cancel_orphan(self);
    }
}

pub(crate) fn next_count(count: u32) -> Option<u32> {
    count.checked_add(1)
}

pub(crate) fn run(w: Arc<Worker>, rx: Receiver<Msg>, env: Arc<Env>) {
    let _let_go = LetGo::arm();

    let mut entered = None;
    let mut st = w.lock();
    loop {
        let late = let_go();
        if !late.is_empty() {
            drop(st);
            drop(late);
            st = w.lock();
        }
        if entered.is_none() {
            if let Some(handle) = env.runtime.get() {
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

pub(crate) fn worker_mark() -> Option<(usize, u32)> {
    ON_WORKER.with(std::cell::Cell::get)
}

pub(crate) fn acting_for(mark: Option<(usize, u32)>) -> ActingFor {
    ActingFor(ON_WORKER.with(|c| c.replace(mark)))
}

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
    #[cfg(test)]
    pub(crate) fn unwatched() -> Self {
        Self { pool: Weak::new() }
    }

    pub(crate) fn observing(&self) -> Option<Arc<crate::observe::Observing>> {
        self.pool
            .upgrade()
            .map(|pool| Arc::clone(&pool.env.observing))
    }

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
    pub fn new(config: DispatchConfig) -> Self {
        Self::try_new(config).unwrap_or_else(|e| panic!("{e}"))
    }

    pub fn try_new(config: DispatchConfig) -> Result<Self, super::LoadError> {
        let key = super::handle::ticket_key()?;
        Ok(Self::build(config, None, key))
    }

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

    #[must_use]
    pub fn observing(&self) -> &crate::observe::Observing {
        &self.pool.env.observing
    }

    pub fn lend_seal(
        &self,
        seal: impl busbar_contract::plugin::KernelSeal + Send + Sync + 'static,
    ) -> bool {
        self.pool.env.seal.set(Arc::new(seal)).is_ok()
    }

    pub(crate) fn seal(&self) -> Option<&(dyn busbar_contract::plugin::KernelSeal + Send + Sync)> {
        self.pool.env.seal.get().map(|seal| &**seal)
    }

    pub fn install_runtime(&self, handle: tokio::runtime::Handle) -> bool {
        self.pool.env.runtime.set(handle).is_ok()
    }

    #[cfg(test)]
    pub(crate) fn installed_runtime(&self) -> Option<&tokio::runtime::Handle> {
        self.pool.env.runtime.get()
    }

    pub fn with_services(config: DispatchConfig, provider: Arc<dyn HostServices>) -> Self {
        Self::with_slot(config, ServicesSlot::of(provider))
    }

    pub fn with_slot(config: DispatchConfig, slot: Arc<ServicesSlot>) -> Self {
        Self::try_with_slot(config, slot).unwrap_or_else(|e| panic!("{e}"))
    }

    pub fn try_with_slot(
        config: DispatchConfig,
        slot: Arc<ServicesSlot>,
    ) -> Result<Self, super::LoadError> {
        let key = super::handle::ticket_key()?;
        Ok(Self::build(config, Some(slot), key))
    }

    fn build(
        config: DispatchConfig,
        provider: Option<Arc<ServicesSlot>>,
        ticket_key: super::handle::TicketKey,
    ) -> Self {
        let built = Self::build_unlent(config, provider, ticket_key);

        #[cfg(test)]
        let _ = built.lend_seal(busbar_contract::plugin::TestKernelSeal);
        built
    }

    #[cfg(test)]
    pub(crate) fn new_unlent(config: DispatchConfig) -> Self {
        let key = super::handle::ticket_key().unwrap_or_else(|e| panic!("{e}"));
        Self::build_unlent(config, None, key)
    }

    fn build_unlent(
        config: DispatchConfig,
        provider: Option<Arc<ServicesSlot>>,
        ticket_key: super::handle::TicketKey,
    ) -> Self {
        let n = config.workers.clamp(1, MAX_WORKERS - 1);
        let services: Arc<ServiceStore> = Arc::default();
        let env = Arc::new(Env {
            budgets: config.budgets,
            quarantine_after: config.quarantine_after.max(1),
            stats: Arc::default(),
            inline: Arc::new(super::inline::InlineTickets::new(ticket_key, &services)),
            services,
            provider: provider.unwrap_or_default(),
            runtime: std::sync::OnceLock::new(),
            io: std::sync::OnceLock::new(),
            auth: std::sync::OnceLock::new(),
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

    pub fn workers(&self) -> u32 {
        self.pool.slots.len() as u32
    }

    #[must_use]
    pub fn budgets(&self) -> Budgets {
        self.pool.env.budgets
    }

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

    pub fn services(&self) -> &ServiceStore {
        &self.pool.env.services
    }

    pub fn host_services(&self) -> Option<&Arc<dyn HostServices>> {
        self.pool.env.provider.get()
    }

    fn worker(&self, worker: u32) -> Option<Arc<Worker>> {
        self.pool.slots.get(worker as usize).map(WorkerSlot::get)
    }

    fn adopt(&self, inst: &Arc<Instance>) -> bool {
        self.adopter().adopt(inst)
    }

    pub fn install_io(&self, io: Arc<dyn busbar_contract::io_host::IoHost>) -> bool {
        self.pool.env.io.set(io).is_ok()
    }

    pub fn install_auth_handle(&self, host: Arc<dyn super::auth_handle::AuthHandleHost>) -> bool {
        self.pool.env.auth.set(host).is_ok()
    }

    pub fn framing_context(
        &self,
        owner: u64,
        listener: u64,
        connection: u64,
    ) -> Result<Arc<super::framing_context::FramingContext>, &'static str> {
        super::framing_context::FramingContext::new(
            owner,
            listener,
            connection,
            self.pool.env.auth.get().map(Arc::downgrade),
        )
    }

    pub fn adopting_context(
        &self,
        owner: u64,
        source: Arc<dyn busbar_contract::framing_scope::FramingScope>,
    ) -> Result<Arc<super::framing_context::FramingContext>, &'static str> {
        super::framing_context::FramingContext::adopt(
            owner,
            source,
            self.pool.env.auth.get().map(Arc::downgrade),
        )
    }

    #[must_use]
    pub fn inline_ticket(&self) -> Option<super::inline::InlineTicket> {
        self.pool.env.inline.mint()
    }

    pub fn adopter(&self) -> Adopter {
        Adopter {
            pool: Arc::downgrade(&self.pool),
        }
    }

    #[cfg(test)]
    pub(crate) fn service_store(&self) -> Arc<ServiceStore> {
        Arc::clone(&self.pool.env.services)
    }

    #[cfg(test)]
    pub(crate) fn judge_against(&self, latch: &'static super::handle::Latch) {
        assert!(
            self.pool.env.latch.set(latch).is_ok(),
            "one latch per dispatcher"
        );
    }

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

    #[cfg(test)]
    pub(crate) fn slot_state(&self, t: Ticket) -> (bool, bool, u32) {
        let (wi, idx) = decode(t.slot);
        let w = self.worker(wi).expect("the ticket's worker");
        let st = w.lock();
        let e = &st.entries[idx as usize];
        (e.live, st.free.contains(&idx), e.count)
    }

    #[cfg(test)]
    pub(crate) fn inline_tickets_arc(&self) -> Arc<super::inline::InlineTickets> {
        Arc::clone(&self.pool.env.inline)
    }

    #[cfg(test)]
    pub(crate) fn inline_tickets(&self) -> &super::inline::InlineTickets {
        &self.pool.env.inline
    }

    #[cfg(test)]
    pub(crate) fn ticket_key(&self) -> super::handle::TicketKey {
        self.pool.env.ticket_key
    }

    #[cfg(test)]
    pub(crate) fn is_pending(&self, t: Ticket) -> bool {
        let Some(w) = self.worker(decode(t.slot).0) else {
            return false;
        };
        let mut st = w.lock();
        w.entry(&mut st, t)
            .is_some_and(|(_, e)| e.current.as_ref().is_some_and(|c| c.pending))
    }

    #[must_use]
    pub fn current_worker(&self) -> Option<u32> {
        let mine = Arc::as_ptr(&self.pool.env) as usize;
        ON_WORKER
            .with(std::cell::Cell::get)
            .filter(|(env, _)| *env == mine)
            .map(|(_, index)| index)
    }

    pub fn mint(&self, worker: u32) -> Option<Ticket> {
        self.worker(worker)?.mint(None)
    }

    pub fn recycle(&self, t: Ticket) {
        self.pool.send(t, Msg::Recycle(t));
    }

    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn retirement_barrier(&self, ticket: Ticket, timeout: Duration) -> bool {
        let (worker, _) = decode(ticket.slot);
        if ticket.is_none() || self.current_worker() == Some(worker) {
            return false;
        }
        let (ack, retired) = channel();

        self.pool.send(ticket, Msg::RetirementBarrier(ack));
        retired.recv_timeout(timeout).is_ok()
    }

    pub fn drop_client(&self, t: Ticket) {
        self.pool.send(t, Msg::DropClient(t));
    }

    pub fn driver<K: Kind>(&self, plugin: &Plugin<K>, worker: u32) -> Option<Ticket> {
        let inst = &plugin.inner;
        if !self.adopt(inst) || !inst.is_open() || inst.faulted.load(Ordering::Acquire) {
            return None;
        }
        let driver = self.worker(worker)?.mint(Some(Driver {
            instance: inst.clone(),
            tracing: Some(TraceContext::current()),
            frame: Some(K::drive_frame()),
            pending: false,
            wake_at_ns: 0,
            ticks_held: 0,
        }))?;
        self.pool.env.services.held.track(driver);
        Some(driver)
    }

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

    #[allow(clippy::too_many_arguments)]
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

    #[allow(clippy::too_many_arguments)]
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

    #[allow(clippy::too_many_arguments)]
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

    pub fn tick<K: Kind>(
        &self,
        plugin: &Plugin<K>,
        driver: Ticket,
        now_ns: u64,
    ) -> Reply<TickIn, TickOut> {
        self.tick_with(plugin, driver, now_ns, Admit::Driver)
    }

    pub(crate) fn tick_copy<K: Kind>(
        &self,
        plugin: &Plugin<K>,
        driver: Ticket,
        now_ns: u64,
    ) -> Reply<TickIn, TickOut> {
        self.tick_with(plugin, driver, now_ns, Admit::DriverCopy)
    }

    fn tick_with<K: Kind>(
        &self,
        plugin: &Plugin<K>,
        driver: Ticket,
        now_ns: u64,
        admit: Admit,
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
            admit,
        );

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

        let owner = super::handle::instance_id(inst.ctx()).0;
        if let Some(o) = K::admit(
            s,
            std::ptr::addr_of!(frame.input).cast(),
            size_of::<I>(),
            owner,
        ) {
            return Reply::settled(o, frame);
        }
        let lifecycle = is_lifecycle(s);
        if lifecycle && !inst.enter_lifecycle() {
            return Reply::settled(Outcome::Refused, frame);
        }

        let Some(units) = (if admit == Admit::Cap {
            inst.acquire(s)
        } else {
            Some(0)
        }) else {
            if lifecycle {
                inst.leave_lifecycle();
            }
            return Reply::settled(Outcome::Refused, frame);
        };
        let drainable = class != DeadlineClass::WriteBehind;
        if drainable {
            inst.drainable.fetch_add(1, Ordering::AcqRel);
        }

        let unit = admit == Admit::Unit;
        if unit {
            inst.unit_ops.fetch_add(1, Ordering::SeqCst);
        }
        let slot = Arc::new(ReplySlot::new());
        let meta = Meta {
            instance: inst.clone(),
            framing: super::framing_context::current(),
            tracing: Some(TraceContext::current()),
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
            unit_key: unit_cancel::key(inst, s, &frame.input),
            unit_final: unit_cancel::final_piece(inst, s, &frame.input),
            tick_copy: admit == Admit::DriverCopy,
            reply: slot.clone(),
        };
        let job = Box::new(JobOf {
            frame,
            reply: slot.clone(),
            instance: Arc::clone(inst),
            framing: meta.framing.clone(),
            lent,
        });
        self.pool.send(ticket, Msg::Submit { ticket, meta, job });
        Reply {
            slot,
            owner: Some((ticket, Arc::downgrade(&self.pool))),
        }
    }

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

#[cfg(test)]
#[allow(unsafe_code)]
#[path = "worker_lease_tests.rs"]
mod lease_tests;
