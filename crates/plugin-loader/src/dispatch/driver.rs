// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DRIVER TICKETS ([`super::Dispatcher::driver`]): one per instance that asks, persistent, outside
//! `max_inflight`, an INLINE ticket (`super::inline`) whose wake calls `drive`. The one op a host
//! starts on it is `tick` ([`super::Dispatcher::tick`]).
//!
//! * ONE CROSSING AT A TIME on a driver ticket: a `tick` and a `drive` never overlap. A wake that
//!   arrives during a crossing is OWED: `drive` runs once that crossing returns, so no wake is lost
//!   behind a `tick`. A `drive` that answered PENDING is resumed (`FLAG_RESUME`) on its next wake
//!   or at its `wake_at_ns`. Crossings run on plugin threads, each watched by the watchdog.
//! * HELD WORK. A PENDING is honoured: a `tick` that answered PENDING holds what pended, and a
//!   `drive` that answered PENDING holds what still waits, until a `drive` answers anything else.
//!   While anything is held, a tick's start keeps what the services kept under the ticket, so each
//!   held exchange resumes when its wake fires while the next tick starts more (`super::held`: a
//!   tick of a kept cycle that reuses a handle the cycle issued is FAULT on that call). The held
//!   exchanges are bounded by the instance's `max_inflight`: a tick that finds them full is
//!   PARKED, not crossed, and crosses once a held exchange ends. With nothing held, a tick's start
//!   is its cycle's boundary: what the services kept under the ticket is forgotten then, the most
//!   ever kept counted ([`super::DispatchStats::driver_kept_high`]).
//! * Every `drive` that ran is followed by the host's `tick` (R-PUSH, [`Driven::woken`]).

use std::collections::VecDeque;
use std::future::Future;
use std::mem::size_of;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome, FLAG_RESUME};
use busbar_contract::abi::mechanism::lifecycle::{slot, TickIn, TickOut};
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::dispatcher::Stats;
use super::inline::InlineTicket;
use super::plugin::{Crossed, Instance, Watched};
use super::services::ServiceStore;
use super::timer::{sleep_until, Sleep};
use super::{in_head, now_ns, out_head, DriveFrame, Frame};

/// THE NAMES A DRIVER TICKET'S READY `drive` ANSWERED (a plane's ready sessions), held for the
/// host until it collects them ([`Driven::take`]): each once, at most [`Driven::HELD`] at a time
/// (a plane that names more before the host collects is told nothing new until it wakes again).
#[derive(Debug, Default)]
pub(crate) struct Driven {
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

    pub(crate) fn name(&self, names: &[u64]) {
        let mut held = self.names.lock().unwrap_or_else(PoisonError::into_inner);
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
    pub(crate) fn answer(&self, outcome: Outcome) {
        let mut a = self.answers.lock().unwrap_or_else(PoisonError::into_inner);
        *a = (a.0 + 1, Some(outcome));
        drop(a);
        self.answered.notify_all();
    }

    /// How many `drive` crossings have answered so far.
    #[cfg(any(test, feature = "conformance"))]
    pub(crate) fn answers(&self) -> u64 {
        self.answers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .0
    }

    /// The first outcome other than PENDING a `drive` answered after the `seen`th answer, waited
    /// for up to `timeout` (a synchronous caller; it blocks this thread). `None` past it.
    #[cfg(any(test, feature = "conformance"))]
    pub(crate) fn answered_after(&self, seen: u64, timeout: Duration) -> Option<Outcome> {
        let until = Instant::now() + timeout;
        let mut a = self.answers.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            if a.0 > seen && a.1 != Some(Outcome::Pending) {
                return a.1;
            }
            let left = until.checked_duration_since(Instant::now())?;
            a = self
                .answered
                .wait_timeout(a, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// Every name held now, taken (none when none is); never waits.
    #[cfg(any(test, feature = "conformance"))]
    pub(crate) fn drain(&self) -> Vec<u64> {
        std::mem::take(&mut *self.names.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// A wake of the driver ticket has run its `drive`.
    pub(crate) fn drove(&self) {
        self.woke.notify_one();
    }

    /// Waits until a wake's `drive` has run, once per run; never parks a thread.
    pub(crate) async fn woken(&self) {
        self.woke.notified().await;
    }

    /// Every name held, once one is; never parks a thread.
    pub(crate) async fn take(&self) -> Vec<u64> {
        loop {
            let names =
                std::mem::take(&mut *self.names.lock().unwrap_or_else(PoisonError::into_inner));
            if !names.is_empty() {
                return names;
            }
            self.told.notified().await;
        }
    }
}

/// What one `tick` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticked {
    /// The authoritative outcome.
    pub outcome: Outcome,
    /// The error text its answer carried.
    pub error: Option<Vec<u8>>,
    /// The lease its answer carried.
    pub lease: u64,
    /// When the instance asks to be ticked next (`0`: it names no time); read on READY or PENDING.
    pub next_tick_ns: u64,
}

impl Ticked {
    fn host(outcome: Outcome) -> Self {
        Self {
            outcome,
            error: None,
            lease: 0,
            next_tick_ns: 0,
        }
    }
}

/// ONE DRIVER TICKET: the instance it drives, its inline ticket and its state.
pub(crate) struct Driver {
    me: Weak<Driver>,
    inst: Arc<Instance>,
    ticket: InlineTicket,
    services: Arc<ServiceStore>,
    stats: Arc<Stats>,
    st: Mutex<State>,
}

#[derive(Default)]
struct State {
    /// The kind's own `drive` frame; `None` while out on a crossing.
    frame: Option<Box<dyn DriveFrame>>,
    /// A crossing (a `tick` or a `drive`) is running on the ticket.
    busy: bool,
    /// A wake arrived that no `drive` has answered yet.
    owed: bool,
    /// The last `drive` answered PENDING: the next one resumes it.
    pending: bool,
    /// The timer of a PENDING `drive`'s `wake_at_ns`.
    timer: Option<Pin<Box<Sleep>>>,
    /// The ticks that answered PENDING since the last `drive` that answered anything else.
    ticks_held: u32,
    /// The ticks waiting for the ticket (another crossing runs) or for a held slot (parked).
    waiting: VecDeque<Waker>,
    /// The watchdog judged a crossing on the ticket a breach: it may never return, so every tick
    /// waiting on it, and every later one, is answered FAULT.
    breached: bool,
}

impl Driver {
    /// A driver ticket for `inst`, minted from `ticket`.
    pub(crate) fn new(
        inst: Arc<Instance>,
        ticket: InlineTicket,
        frame: Box<dyn DriveFrame>,
        services: Arc<ServiceStore>,
        stats: Arc<Stats>,
    ) -> Arc<Self> {
        ticket.note(inst.instance);
        services.held.track(ticket.ticket());
        let d = Arc::new_cyclic(|me| Self {
            me: me.clone(),
            inst,
            ticket,
            services,
            stats,
            st: Mutex::new(State {
                frame: Some(frame),
                ..State::default()
            }),
        });
        d.ticket.register(&d.waker());
        d
    }

    /// Whether this is a driver of `inst`.
    pub(crate) fn is_of(&self, inst: &Arc<Instance>) -> bool {
        Arc::ptr_eq(&self.inst, inst)
    }

    /// The ticket.
    pub(crate) fn ticket(&self) -> Ticket {
        self.ticket.ticket()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn waker(&self) -> Waker {
        Waker::from(Arc::new(Woken(self.me.clone())))
    }

    /// The instance can no longer cross: every waiting tick is answered rather than left waiting.
    fn gone(&self) -> bool {
        self.inst.faulted.load(Ordering::Acquire) || !self.inst.is_open()
    }

    /// No tick can be answered by a crossing on this ticket any more: the instance can no longer
    /// cross, or a crossing on the ticket was judged a breach.
    fn dead(&self) -> bool {
        self.gone() || self.lock().breached
    }

    /// Wake every waiting tick: each looks again.
    fn release_waiting(st: &mut State) {
        for w in st.waiting.drain(..) {
            w.wake();
        }
    }

    /// A wake (or the timer of a PENDING `drive`): `drive` now, or once the running crossing
    /// returns.
    fn woke(&self) {
        let start = {
            let mut st = self.lock();
            st.owed = true;
            !std::mem::replace(&mut st.busy, true)
        };
        if start {
            self.run_drives();
        }
    }

    /// Run the owed `drive`s on a plugin thread, then free the ticket.
    fn run_drives(&self) {
        let Some(me) = self.me.upgrade() else {
            return;
        };
        crate::ffi_thread::spawn_on_plugin_thread(move || me.drives());
    }

    fn drives(&self) {
        loop {
            let (frame, resume) = {
                let mut st = self.lock();
                if !std::mem::take(&mut st.owed) || self.gone() {
                    st.busy = false;
                    st.owed = false;
                    Self::release_waiting(&mut st);
                    return;
                }
                st.timer = None;
                (st.frame.take(), st.pending)
            };
            // Registered before the crossing: a wake from inside it, or after, is owed to the next.
            self.ticket.register(&self.waker());
            let Some(mut frame) = frame else {
                self.lock().busy = false;
                return;
            };
            let flags = if resume { FLAG_RESUME } else { 0 };
            let ticket = self.ticket();
            let heads = frame.prepare(ticket, flags);
            self.services.held.enter(ticket, false);
            let c = self.cross(slot::DRIVE, heads, DeadlineClass::Connection, None);
            self.services.held.leave(ticket);
            if c.outcome == Outcome::Ready {
                self.inst.driven.name(frame.named());
            }
            self.inst.driven.answer(c.outcome);
            {
                let mut st = self.lock();
                st.frame = Some(frame);
                st.pending = c.outcome == Outcome::Pending;
                if st.pending {
                    if c.wake_at_ns != 0 {
                        st.timer = Some(Box::pin(sleep_until(at(c.wake_at_ns))));
                        let waker = self.waker();
                        if let Some(t) = st.timer.as_mut() {
                            if t.as_mut().poll(&mut Context::from_waker(&waker)).is_ready() {
                                st.owed = true;
                            }
                        }
                    }
                } else {
                    st.ticks_held = 0;
                    self.services.held.drained(ticket);
                }
                // A held exchange that ended freed a slot: a parked tick crosses now.
                Self::release_waiting(&mut st);
            }
            // A wake's `drive` ran: the host re-polls `tick` (R-PUSH).
            self.inst.driven.drove();
        }
    }

    /// One crossing of `s` on this ticket, on this thread, watched by the watchdog: a breach
    /// answers every waiting tick.
    fn cross(
        &self,
        s: u32,
        heads: (
            *mut busbar_contract::abi::mechanism::call::InHead,
            *mut busbar_contract::abi::mechanism::call::OutHead,
            u32,
        ),
        class: DeadlineClass,
        also: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Crossed {
        if self.inst.faulted.load(Ordering::Acquire) {
            return Crossed::host(Outcome::Fault);
        }
        let id = self.inst.next_call.fetch_add(1, Ordering::Relaxed);
        let me = self.me.clone();
        self.inst.lock_calls().push(Watched {
            breach: Some(Arc::new(move || {
                if let Some(also) = &also {
                    also();
                }
                if let Some(d) = me.upgrade() {
                    let mut st = d.lock();
                    st.breached = true;
                    Self::release_waiting(&mut st);
                }
            })),
            ..Watched::new(id, s, Duration::ZERO, class)
        });
        // SAFETY: the frame is the caller's, live and not aliased for the crossing; `s` is a
        // lifecycle slot every kind's table carries.
        let crossed = unsafe { self.inst.cross(s, heads.0, heads.1, heads.2) };
        self.inst.lock_calls().retain(|c| c.id != id);
        crossed
    }

    /// `tick` at `now_ns`: once the ticket is free and, in a kept cycle, a held slot is.
    pub(crate) async fn tick(self: Arc<Self>, now_ns: u64) -> Ticked {
        if self
            .inst
            .refuse(slot::TICK, size_of::<TickIn>(), size_of::<TickOut>())
            .is_some()
        {
            return Ticked::host(Outcome::Refused);
        }
        let ticket = self.ticket();
        // The ticket, once free; then whether this tick starts a cycle or keeps one.
        let mut look = Box::pin(sleep_until(Instant::now() + LOOK));
        let kept = std::future::poll_fn(|cx| {
            if self.gone() {
                return Poll::Ready(None);
            }
            // Looked at again every `LOOK`: an instance quarantined or closed meanwhile, by another
            // op, answers a waiting tick.
            while look.as_mut().poll(cx).is_ready() {
                look = Box::pin(sleep_until(Instant::now() + LOOK));
            }
            let mut st = self.lock();
            if st.breached {
                return Poll::Ready(None);
            }
            if st.busy {
                st.waiting.push_back(cx.waker().clone());
                return Poll::Pending;
            }
            let held = self.services.held.held(ticket);
            if st.ticks_held == 0 && !st.pending && held == 0 {
                st.busy = true;
                return Poll::Ready(Some(false));
            }
            if held >= self.inst.cap {
                // PARKED: it crosses once a held exchange ends.
                st.waiting.push_back(cx.waker().clone());
                return Poll::Pending;
            }
            st.busy = true;
            Poll::Ready(Some(true))
        })
        .await;
        let Some(kept) = kept else {
            return Ticked::host(Outcome::Fault);
        };
        if !kept {
            // Nothing is held: the tick starts the ticket's next cycle, and the last cycle's kept
            // answers (and their epoch) go.
            let n = self.services.forget(ticket)
                + super::conn_services::forget(self.inst.instance, ticket);
            self.services.held.forget(ticket);
            self.stats
                .driver_kept_high
                .fetch_max(n as u64, Ordering::Relaxed);
        }
        let ticked = Arc::new(Answer::default());
        {
            let me = Arc::clone(&self);
            let ticked = Arc::clone(&ticked);
            // The tick counts for a reload drain until it returns, or until the watchdog judges it a
            // breach, whichever is first.
            self.inst.drainable.fetch_add(1, Ordering::AcqRel);
            let drained = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let undrain: Arc<dyn Fn() + Send + Sync> = {
                let inst = Arc::clone(&self.inst);
                Arc::new(move || {
                    if !drained.swap(true, Ordering::AcqRel) {
                        inst.drainable.fetch_sub(1, Ordering::AcqRel);
                    }
                })
            };
            crate::ffi_thread::spawn_on_plugin_thread(move || {
                let mut frame = Frame::new(
                    TickIn {
                        head: in_head(),
                        now_ns,
                    },
                    TickOut {
                        head: out_head(),
                        next_tick_ns: 0,
                    },
                );
                let heads = frame.heads();
                // SAFETY: the frame is ours; its heads lead the structs.
                unsafe {
                    let h = &mut *heads.0;
                    h.size = size_of::<TickIn>() as u32;
                    h.flags = 0;
                    h.deadline_class = DeadlineClass::Call as u8;
                    h.ticket = ticket;
                    h.deadline_ns = 0;
                }
                me.services.held.enter(ticket, kept);
                let c = me.cross(
                    slot::TICK,
                    heads,
                    DeadlineClass::Call,
                    Some(Arc::clone(&undrain)),
                );
                me.services.held.leave(ticket);
                undrain();
                let owed = {
                    let mut st = me.lock();
                    // A tick that answered PENDING ends; what pended inside it is held and goes on
                    // through `drive`.
                    if c.outcome == Outcome::Pending {
                        st.ticks_held = st.ticks_held.saturating_add(1);
                    }
                    if st.owed {
                        true
                    } else {
                        st.busy = false;
                        Self::release_waiting(&mut st);
                        false
                    }
                };
                ticked.set(Ticked {
                    outcome: c.outcome,
                    error: c.error,
                    lease: c.lease,
                    next_tick_ns: frame.out.next_tick_ns,
                });
                if owed {
                    me.drives();
                }
            });
        }
        let mut look = Box::pin(sleep_until(Instant::now() + LOOK));
        std::future::poll_fn(|cx| {
            while look.as_mut().poll(cx).is_ready() {
                look = Box::pin(sleep_until(Instant::now() + LOOK));
            }
            let answered = ticked.poll(cx, || self.dead());
            if answered.is_pending() {
                // A breach of the tick's crossing wakes the waiting: this caller is answered then.
                self.lock().waiting.push_back(cx.waker().clone());
            }
            answered
        })
        .await
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.services.held.untrack(self.ticket.ticket());
    }
}

/// A wake of a driver ticket: `drive` on it.
struct Woken(Weak<Driver>);

impl Wake for Woken {
    fn wake(self: Arc<Self>) {
        if let Some(d) = self.0.upgrade() {
            d.woke();
        }
    }
}

/// One tick's answer, handed from its crossing to the caller.
#[derive(Default)]
struct Answer(Mutex<(Option<Ticked>, Option<Waker>)>);

impl Answer {
    fn set(&self, t: Ticked) {
        let w = {
            let mut a = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            a.0 = Some(t);
            a.1.take()
        };
        if let Some(w) = w {
            w.wake();
        }
    }

    /// The answer once it came; FAULT at once when the instance can no longer cross (the watchdog
    /// judged the crossing a breach: it runs on, and nobody waits for it).
    fn poll(&self, cx: &mut Context<'_>, gone: impl Fn() -> bool) -> Poll<Ticked> {
        let mut a = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(t) = a.0.take() {
            return Poll::Ready(t);
        }
        if gone() {
            return Poll::Ready(Ticked::host(Outcome::Fault));
        }
        a.1 = Some(cx.waker().clone());
        Poll::Pending
    }
}

/// How often a waiting tick looks whether its instance can still cross.
const LOOK: Duration = Duration::from_secs(1);

/// The instant `ns` (the dispatcher's clock) names.
fn at(ns: u64) -> Instant {
    let now = now_ns();
    Instant::now() + Duration::from_nanos(ns.saturating_sub(now))
}
