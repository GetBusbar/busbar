// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE CALL PATH: one op of any kind, from admission to its final answer, with no scheduler.
//!
//! * ADMITTED ONCE: its `max_inflight` units are held from the first crossing to the final answer,
//!   PENDING included.
//! * OFFLOADED CROSSINGS: each crossing runs on a permanent plugin thread (`ffi_thread`), never on
//!   the caller's, over a frame the op owns (`Box<Frame>` plus what it lends). So the caller can
//!   stop waiting at its deadline while a crossing is still inside the plugin ("the budget cuts the
//!   wait, not the plugin"), and plugin code never runs on a thread that retires.
//! * SHORT: one re-call over regrown buffers, on the same ticket (its kept service answers stay).
//! * PENDING: the op holds an inline ticket, never a thread. The caller's task is the ticket's
//!   waker (registered before every crossing, so no wake is lost) and the call clock (`timer`) wakes
//!   it at the op's `wake_at_ns` or its deadline; it then crosses again with `FLAG_RESUME`.
//! * DEADLINE AND ABANDONMENT: when the deadline passes, or the call is dropped, while the op is
//!   pending, `cancel` crosses on a plugin thread, never in a `Drop` and never under a host lock. A
//!   crossing still running when the caller leaves ends the op itself: a PENDING answer is
//!   cancelled, a lease handed back, the units and the ticket given back.

use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::inline::InlineTicket;
use super::plugin::{Admitted, Called, Plugin};
use super::timer::sleep_until;
use super::worker::Lent;
use super::{in_head, out_head, Frame, InFrame, Kind, OutFrame};

/// How one op is called.
#[derive(Debug, Clone)]
pub(crate) struct Opts {
    /// The deadline class stamped in the op's head.
    pub(crate) class: DeadlineClass,
    /// When the caller stops waiting: a pending op is cancelled then.
    pub(crate) deadline: Instant,
    /// The watchdog's budget for each crossing, when longer than the class's (a hook's
    /// `timeout_ms`).
    pub(crate) watch: Duration,
    /// At the deadline the caller stops waiting even for a crossing still inside the plugin (the
    /// hook kind's frozen 1.5.5 rule). Otherwise a crossing is always waited for, and only an op
    /// still PENDING at the deadline is cancelled.
    pub(crate) leave: bool,
    /// The ordered lane the op's crossings run on (`None`: any free plugin thread).
    pub(crate) lane: Option<Arc<Lane>>,
}

/// An ORDERED LANE: the crossings put on it run one at a time, in the order they were put (an
/// export instance's deliveries start in queue order, as they did on the one worker they shared).
#[derive(Default)]
pub(crate) struct Lane {
    jobs: Mutex<(std::collections::VecDeque<Box<dyn FnOnce() + Send>>, bool)>,
}

impl std::fmt::Debug for Lane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lane").finish_non_exhaustive()
    }
}

impl Lane {
    /// Put `job` on the lane: it runs on a plugin thread after every job put before it.
    fn put(self: &Arc<Self>, job: Box<dyn FnOnce() + Send>) {
        let start = {
            let mut j = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
            j.0.push_back(job);
            !std::mem::replace(&mut j.1, true)
        };
        if start {
            let lane = Arc::clone(self);
            crate::ffi_thread::spawn_on_plugin_thread(move || loop {
                let job = {
                    let mut j = lane.jobs.lock().unwrap_or_else(PoisonError::into_inner);
                    match j.0.pop_front() {
                        Some(job) => job,
                        None => {
                            j.1 = false;
                            return;
                        }
                    }
                };
                job();
            });
        }
    }
}

/// What one op answered.
#[derive(Debug)]
pub(crate) enum Ran<I, O> {
    /// Its final answer (never PENDING), with the frame it answered in and what that frame lends.
    Answered {
        /// The answer.
        called: Called,
        /// The frame.
        frame: Box<Frame<I, O>>,
        /// What it lends.
        lent: Lent,
    },
    /// The deadline passed first: the op was cancelled (or is, once its crossing returns).
    TimedOut,
}

/// The regrow after a SHORT answer: a new frame over bigger buffers and what it lends, or `None`.
pub(crate) type Regrow<'r, I, O> =
    &'r mut (dyn FnMut(&Frame<I, O>) -> Option<(Frame<I, O>, Lent)> + Send);

/// Call op `s` of `plugin` over `frame` (lending `lent`).
pub(crate) async fn call<K: Kind, I: InFrame, O: OutFrame>(
    plugin: &Arc<Plugin<K>>,
    s: u32,
    frame: Frame<I, O>,
    lent: Lent,
    opts: Opts,
    regrow: Regrow<'_, I, O>,
) -> Ran<I, O> {
    let mut admitted = match plugin.admit(s, size_of::<I>(), size_of::<O>()) {
        Ok(a) => a,
        Err(o) => {
            return Ran::Answered {
                called: Called::host(o),
                frame: Box::new(frame),
                lent,
            }
        }
    };
    admitted.watch = opts.watch;
    let ticket = plugin.inline_ticket();
    let op = Arc::new(Op {
        plugin: Arc::clone(plugin),
        lane: opts.lane.clone(),
        s,
        class: opts.class,
        ticket: ticket.as_ref().map_or(Ticket::NONE, InlineTicket::ticket),
        state: Mutex::new(State {
            frame: Some(Box::new(frame)),
            lent: Some(lent),
            answered: None,
            crossing: false,
            pending: false,
            gone: false,
            admitted: Some(admitted),
            ticket,
            waker: None,
        }),
    });
    let mut held = Held(Some(Arc::clone(&op)));
    let mut resume = false;
    let mut regrown = false;
    loop {
        op.register().await;
        Op::cross(&op, resume);
        if !op.answered_by(opts.leave.then_some(opts.deadline)).await {
            return Ran::TimedOut;
        }
        let (called, wake_at) = op.take_answer();
        if called.recall.is_some() {
            if regrown {
                return held.finish(Called::host(Outcome::Fault));
            }
            if let Some((frame, lent)) = op.with_frame(|f| regrow(f)) {
                op.replace_frame(frame, lent);
                regrown = true;
                resume = false;
                continue;
            }
            return held.finish(called);
        }
        if called.outcome != Outcome::Pending {
            return held.finish(called);
        }
        if !op.woken_by(wake_at, opts.deadline).await {
            return Ran::TimedOut;
        }
        resume = true;
    }
}

/// One op in flight, shared by its caller and the plugin thread crossing it.
struct Op<K: Kind, I, O> {
    plugin: Arc<Plugin<K>>,
    /// The ordered lane its crossings run on; `None`: any free plugin thread.
    lane: Option<Arc<Lane>>,
    s: u32,
    class: DeadlineClass,
    ticket: Ticket,
    state: Mutex<State<I, O>>,
}

struct State<I, O> {
    /// The op's frame; `None` while a crossing holds it.
    frame: Option<Box<Frame<I, O>>>,
    /// What the frame lends; it lives as long as the frame.
    lent: Option<Lent>,
    /// The last crossing's answer and the `wake_at_ns` it named.
    answered: Option<(Called, u64)>,
    /// A crossing is running.
    crossing: bool,
    /// The last answer was PENDING (a `cancel` is owed if the op is abandoned).
    pending: bool,
    /// The caller stopped waiting.
    gone: bool,
    /// The op's units, given back when the op ends.
    admitted: Option<Admitted>,
    /// The op's ticket, recycled when the op ends.
    ticket: Option<InlineTicket>,
    /// The caller's task, woken when a crossing returns.
    waker: Option<Waker>,
}

impl<K: Kind, I: InFrame, O: OutFrame> Op<K, I, O> {
    fn lock(&self) -> MutexGuard<'_, State<I, O>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register the calling task as the ticket's waker, before a crossing.
    async fn register(&self) {
        std::future::poll_fn(|cx| {
            if let Some(t) = &self.lock().ticket {
                t.register(cx.waker());
            }
            Poll::Ready(())
        })
        .await;
    }

    /// Start one crossing on a plugin thread.
    fn cross(op: &Arc<Self>, resume: bool) {
        {
            let mut st = op.lock();
            st.crossing = true;
            st.answered = None;
        }
        let job = {
            let op = Arc::clone(op);
            move || op.run(resume)
        };
        match &op.lane {
            Some(lane) => lane.put(Box::new(job)),
            None => crate::ffi_thread::spawn_on_plugin_thread(job),
        }
    }

    /// The crossing, on a plugin thread. A caller gone before it starts gets none: a fresh op is
    /// never made, a pending one is cancelled.
    fn run(&self, resume: bool) {
        let (mut frame, admitted) = {
            let mut st = self.lock();
            if st.gone {
                st.crossing = false;
                drop(st);
                self.cancel_pending();
                return;
            }
            (st.frame.take(), st.admitted.take())
        };
        let answered = match (&mut frame, &admitted) {
            (Some(f), Some(a)) => {
                let called =
                    self.plugin
                        .cross_inline(a, self.s, f, self.ticket, resume, self.class);
                let (_, out, _) = f.heads();
                // SAFETY: the frame's `out` leads with its head.
                let wake_at = unsafe { (*out).wake_at_ns };
                (called, wake_at)
            }
            _ => (Called::host(Outcome::Fault), 0),
        };
        let mut st = self.lock();
        st.frame = frame;
        st.admitted = admitted;
        st.crossing = false;
        st.pending = answered.0.outcome == Outcome::Pending;
        if st.gone {
            drop(st);
            self.abandon(&answered.0);
            return;
        }
        st.answered = Some(answered);
        let waker = st.waker.take();
        drop(st);
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// The caller left while this crossing ran: end the op here, on the plugin thread.
    fn abandon(&self, called: &Called) {
        if called.outcome == Outcome::Pending {
            self.cancel_pending();
            return;
        }
        release(&self.plugin, called.lease);
        self.end();
    }

    /// `cancel` of the op if it is pending, then its end (a plugin thread).
    fn cancel_pending(&self) {
        let owed = std::mem::take(&mut self.lock().pending);
        if owed {
            let _ = self.plugin.cancel_inline(self.ticket, self.class, None);
        }
        self.end();
    }

    /// Give back the op's units and ticket.
    fn end(&self) {
        let (admitted, ticket) = {
            let mut st = self.lock();
            st.pending = false;
            (st.admitted.take(), st.ticket.take())
        };
        drop(admitted);
        drop(ticket);
    }

    /// Wait for the crossing's answer: `false` = the deadline (`None`: none) came first (the caller
    /// is gone; the crossing ends the op).
    async fn answered_by(&self, deadline: Option<Instant>) -> bool {
        let mut sleep = std::pin::pin!(deadline.map(sleep_until));
        std::future::poll_fn(|cx| {
            {
                let mut st = self.lock();
                if st.answered.is_some() {
                    return Poll::Ready(true);
                }
                st.waker = Some(cx.waker().clone());
            }
            if sleep
                .as_mut()
                .as_pin_mut()
                .is_some_and(|s| s.poll(cx).is_ready())
            {
                let mut st = self.lock();
                if st.answered.is_some() {
                    return Poll::Ready(true);
                }
                st.gone = true;
                return Poll::Ready(false);
            }
            Poll::Pending
        })
        .await
    }

    /// Wait for the op's wake or its `wake_at_ns`: `false` = the deadline came first (a `cancel`
    /// is sent on a plugin thread).
    async fn woken_by(self: &Arc<Self>, wake_at_ns: u64, deadline: Instant) -> bool {
        let until = if wake_at_ns == 0 {
            deadline
        } else {
            let left = wake_at_ns.saturating_sub(super::now_ns());
            (Instant::now() + Duration::from_nanos(left)).min(deadline)
        };
        let mut sleep = std::pin::pin!(sleep_until(until));
        let mut armed = false;
        let woke = std::future::poll_fn(|cx| {
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Instant::now() < deadline);
            }
            if armed {
                return Poll::Ready(true);
            }
            armed = true;
            Poll::Pending
        })
        .await;
        if !woke {
            self.lock().gone = true;
            let op = Arc::clone(self);
            crate::ffi_thread::spawn_on_plugin_thread(move || op.cancel_pending());
        }
        woke
    }

    fn take_answer(&self) -> (Called, u64) {
        self.lock()
            .answered
            .take()
            .unwrap_or_else(|| (Called::host(Outcome::Fault), 0))
    }

    fn with_frame<R>(&self, f: impl FnOnce(&Frame<I, O>) -> R) -> R {
        let st = self.lock();
        let frame = st
            .frame
            .as_ref()
            .expect("no crossing holds the frame between crossings");
        f(frame)
    }

    fn replace_frame(&self, frame: Frame<I, O>, lent: Lent) {
        let mut st = self.lock();
        st.frame = Some(Box::new(frame));
        st.lent = Some(lent);
    }
}

/// The caller's hold on its op. A call that ends with its op unanswered (its future dropped)
/// leaves the op to a plugin thread: a pending op is cancelled there, a running crossing ends it.
struct Held<K: Kind, I: InFrame, O: OutFrame>(Option<Arc<Op<K, I, O>>>);

impl<K: Kind, I: InFrame, O: OutFrame> Held<K, I, O> {
    /// The op answered `called`: it ends here, and its frame goes back to the caller.
    fn finish(&mut self, called: Called) -> Ran<I, O> {
        let op = self.0.take().expect("an op is finished once");
        let (frame, lent) = {
            let mut st = op.lock();
            (st.frame.take(), st.lent.take())
        };
        op.end();
        match (frame, lent) {
            (Some(frame), Some(lent)) => Ran::Answered {
                called,
                frame,
                lent,
            },
            _ => Ran::TimedOut,
        }
    }
}

impl<K: Kind, I: InFrame, O: OutFrame> Drop for Held<K, I, O> {
    fn drop(&mut self) {
        let Some(op) = self.0.take() else {
            return;
        };
        let mut st = op.lock();
        if st.gone {
            return;
        }
        st.gone = true;
        let crossing = st.crossing;
        drop(st);
        if !crossing {
            crate::ffi_thread::spawn_on_plugin_thread(move || op.cancel_pending());
        }
    }
}

/// Hand a lease back (ticket-less; a release never pends). `0` is none.
pub(crate) fn release<K: Kind>(plugin: &Plugin<K>, lease: u64) {
    if lease == 0 {
        return;
    }
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    let _ = plugin.call(life::RELEASE, &mut f);
}

/// A WRITE-BEHIND op (`DeadlineClass::WriteBehind`): never cancelled, by a deadline, a dropped
/// caller or a reload. It runs on the write-behind runner (one permanent thread polling every such
/// op), so the caller only watches it: dropping the returned future leaves the op running to its
/// end, woken by its own wakes, and its frame and lent memory go with it.
pub(crate) fn call_write_behind<K: Kind, I: InFrame, O: OutFrame>(
    plugin: Arc<Plugin<K>>,
    s: u32,
    frame: Frame<I, O>,
    lent: Lent,
    lane: Arc<Lane>,
    mut regrow: Box<dyn FnMut(&Frame<I, O>) -> Option<(Frame<I, O>, Lent)> + Send>,
) -> impl Future<Output = Ran<I, O>> + Send {
    let watched = Arc::new(Mutex::new(Watch::<I, O> {
        ran: None,
        waker: None,
    }));
    let report = Arc::clone(&watched);
    write_behind::spawn(Box::pin(async move {
        let opts = Opts {
            class: DeadlineClass::WriteBehind,
            deadline: Instant::now() + NEVER,
            watch: Duration::ZERO,
            leave: false,
            lane: Some(lane),
        };
        let ran = call(&plugin, s, frame, lent, opts, &mut *regrow).await;
        let mut w = report.lock().unwrap_or_else(PoisonError::into_inner);
        w.ran = Some(ran);
        if let Some(waker) = w.waker.take() {
            waker.wake();
        }
    }));
    std::future::poll_fn(move |cx| {
        let mut w = watched.lock().unwrap_or_else(PoisonError::into_inner);
        match w.ran.take() {
            Some(ran) => Poll::Ready(ran),
            None => {
                w.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    })
}

/// A write-behind op has no deadline: this far ahead is never reached by a running process.
const NEVER: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

struct Watch<I, O> {
    ran: Option<Ran<I, O>>,
    waker: Option<Waker>,
}

/// THE WRITE-BEHIND RUNNER: one permanent thread polling every write-behind op to its end.
mod write_behind {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Mutex, OnceLock, PoisonError};
    use std::task::Poll;

    use futures::channel::mpsc::{unbounded, UnboundedSender};
    use futures::stream::{FuturesUnordered, StreamExt};

    type Op = Pin<Box<dyn Future<Output = ()> + Send>>;

    fn runner() -> &'static Mutex<UnboundedSender<Op>> {
        static RUNNER: OnceLock<Mutex<UnboundedSender<Op>>> = OnceLock::new();
        RUNNER.get_or_init(|| {
            let (tx, mut rx) = unbounded::<Op>();
            std::thread::Builder::new()
                .name("busbar-plugin-write-behind".to_string())
                .spawn(move || {
                    let mut running = FuturesUnordered::new();
                    futures::executor::block_on(std::future::poll_fn(|cx| loop {
                        while let Poll::Ready(Some(op)) = rx.poll_next_unpin(cx) {
                            running.push(op);
                        }
                        match running.poll_next_unpin(cx) {
                            Poll::Ready(Some(())) => {}
                            Poll::Ready(None) | Poll::Pending => return Poll::<()>::Pending,
                        }
                    }));
                })
                .expect("spawn the plugin write-behind runner");
            Mutex::new(tx)
        })
    }

    /// Run `op` to its end on the runner.
    pub(super) fn spawn(op: Op) {
        let _ = runner()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .unbounded_send(op);
    }
}
