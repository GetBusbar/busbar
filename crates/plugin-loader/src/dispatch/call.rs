// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE CALL PATH: one op of any kind, from admission to its final answer, with no scheduler.
//!
//! * ADMITTED ONCE: its `max_inflight` units are held from the first crossing to the final answer,
//!   PENDING included, and given back before the caller is woken with that answer. An op that is
//!   not write-behind counts in its instance's `drainable`, so a reload drain waits for it.
//! * OFFLOADED CROSSINGS: each crossing runs on a permanent plugin thread (`ffi_thread`), never on
//!   the caller's, over a frame the op owns (`Box<Frame>` plus what it lends), its head stamped
//!   with the op's deadline. A crossing never enters an instance the watchdog has faulted: it is
//!   answered FAULT instead, a resume included.
//! * SHORT: one re-call over regrown buffers, on the same ticket (its kept service answers stay).
//! * PENDING: the op holds an inline ticket, never a thread. The ticket's waker is the op's own
//!   LATCH: a wake sets it, whenever it comes (during the crossing that answers PENDING included),
//!   and wakes the caller's task; the op is resumed on the latch, its `wake_at_ns` (the call
//!   clock, `timer`) or nothing at all before its deadline, never on a bare re-poll.
//! * DEADLINE AND ABANDONMENT: an op still PENDING at its deadline is cancelled on a plugin
//!   thread and the caller answered with what the `cancel` said; a call dropped while its op is
//!   pending has it cancelled the same way, never in a `Drop`. With `leave` (the hook kind's
//!   frozen 1.5.5 rule) the caller also stops waiting for a crossing still inside the plugin, and
//!   that crossing ends the op itself: a PENDING answer cancelled, a lease handed back.

use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Poll, Wake, Waker};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::Ticket;

use super::inline::InlineTicket;
use super::plugin::{Admitted, Called, Cancelled, Plugin};
use super::timer::sleep_until;
use super::worker::Lent;
use super::{in_head, now_ns, out_head, Frame, InFrame, Kind, OutFrame};

/// How one op is called.
#[derive(Debug, Clone, Copy)]
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
    /// The deadline passed first. `cancelled`: what the op's `cancel` answered, when the caller
    /// waited for it; `None` when the caller left first (the op is cancelled once its crossing
    /// returns).
    TimedOut {
        /// The `cancel`'s answer.
        #[allow(dead_code, reason = "read by the store and plane stages")]
        cancelled: Option<Cancelled>,
    },
    /// The op may pend and no ticket could be had for it: it was never made.
    NoTicket,
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
    let Some(ticket) = plugin.inline_ticket() else {
        return Ran::NoTicket;
    };
    let drainable = opts.class != DeadlineClass::WriteBehind;
    let mut admitted = match plugin.admit(s, size_of::<I>(), size_of::<O>(), drainable) {
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
    let left = opts.deadline.saturating_duration_since(Instant::now());
    let op = Arc::new(Op {
        plugin: Arc::clone(plugin),
        s,
        class: opts.class,
        ticket: ticket.ticket(),
        deadline_ns: now_ns().saturating_add(u64::try_from(left.as_nanos()).unwrap_or(u64::MAX)),
        latch: Arc::new(Latch::default()),
        state: Mutex::new(State {
            frame: Some(Box::new(frame)),
            lent: Some(lent),
            answered: None,
            cancelled: None,
            crossing: false,
            pending: false,
            gone: false,
            unit: None,
            admitted: Some(admitted),
            ticket: Some(ticket),
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
            return Ran::TimedOut { cancelled: None };
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
            let cancelled = op.cancel_now().await;
            held.0 = None;
            return Ran::TimedOut {
                cancelled: Some(cancelled),
            };
        }
        resume = true;
    }
}

/// TEST ONLY: the plugin (by its `Arc` address) whose crossings panic in the host, before the
/// plugin is entered.
#[cfg(test)]
pub(crate) static PANIC_IN_RUN_FOR: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// The op's own waker: a wake sets it and wakes the task waiting on the op.
#[derive(Default)]
struct Latch {
    woke: AtomicBool,
    task: Mutex<Option<Waker>>,
}

impl Wake for Latch {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woke.store(true, Ordering::Release);
        let task = self
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(t) = task {
            t.wake();
        }
    }
}

/// One op in flight, shared by its caller and the plugin thread crossing it.
struct Op<K: Kind, I, O> {
    plugin: Arc<Plugin<K>>,
    s: u32,
    class: DeadlineClass,
    ticket: Ticket,
    /// The deadline stamped in every crossing's head.
    deadline_ns: u64,
    latch: Arc<Latch>,
    state: Mutex<State<I, O>>,
}

struct State<I, O> {
    /// The op's frame; `None` while a crossing holds it.
    frame: Option<Box<Frame<I, O>>>,
    /// What the frame lends; it lives as long as the frame.
    lent: Option<Lent>,
    /// The last crossing's answer and the `wake_at_ns` it named.
    answered: Option<(Called, u64)>,
    /// What the `cancel` the caller waits for answered.
    cancelled: Option<Cancelled>,
    /// A crossing is running.
    crossing: bool,
    /// The last answer was PENDING (a `cancel` is owed if the op is abandoned).
    pending: bool,
    /// The caller stopped waiting.
    gone: bool,
    /// The unit the op serves (a plane's `cancel` names it), read off its `in` when it pended.
    unit: Option<u64>,
    /// The op's units, given back when the op answers.
    admitted: Option<Admitted>,
    /// The op's ticket, recycled when the op ends.
    ticket: Option<InlineTicket>,
    /// The caller's task, woken when a crossing or a `cancel` returns.
    waker: Option<Waker>,
}

impl<K: Kind, I: InFrame, O: OutFrame> Op<K, I, O> {
    fn lock(&self) -> MutexGuard<'_, State<I, O>> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Before a crossing: the calling task is the one the op's latch wakes, the latch is the
    /// ticket's waker, and an earlier wake is forgotten (the crossing reads its state afresh).
    async fn register(&self) {
        std::future::poll_fn(|cx| {
            *self
                .latch
                .task
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(cx.waker().clone());
            self.latch.woke.store(false, Ordering::Release);
            if let Some(t) = &self.lock().ticket {
                t.register(&Waker::from(Arc::clone(&self.latch)));
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
        let op = Arc::clone(op);
        crate::ffi_thread::spawn_on_plugin_thread(move || op.run(resume));
    }

    /// The crossing, on a plugin thread. A caller gone before it starts gets none (a fresh op is
    /// never made, a pending one is cancelled); a faulted instance gets none (FAULT). A host
    /// panic inside it ends the op as FAULT, the caller woken.
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
        let crossed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            #[cfg(test)]
            if PANIC_IN_RUN_FOR.load(Ordering::SeqCst) == Arc::as_ptr(&self.plugin) as usize {
                panic!("the host panics inside a crossing (test)");
            }
            match (&mut frame, &admitted) {
                (Some(f), Some(a)) if !self.plugin.is_faulted() => {
                    let (input, _, _) = f.heads();
                    // SAFETY: the frame's `in` leads with its head.
                    unsafe { (*input).deadline_ns = self.deadline_ns };
                    let called =
                        self.plugin
                            .cross_inline(a, self.s, f, self.ticket, resume, self.class);
                    let (input, out, _) = f.heads();
                    // SAFETY: the frame's `out` leads with its head.
                    let wake_at = unsafe { (*out).wake_at_ns };
                    let unit = (called.outcome == Outcome::Pending)
                        .then(|| {
                            self.plugin
                                .unit_of(self.s, input.cast_const(), size_of::<I>())
                        })
                        .flatten();
                    (called, wake_at, unit)
                }
                _ => (Called::host(Outcome::Fault), 0, None),
            }
        }));
        let (called, wake_at, unit) =
            crossed.unwrap_or_else(|_| (Called::host(Outcome::Fault), 0, None));
        let pending = called.outcome == Outcome::Pending;
        let short = called.recall.is_some();
        let mut st = self.lock();
        st.frame = frame;
        st.crossing = false;
        st.pending = pending;
        st.unit = unit;
        if st.gone {
            st.admitted = admitted;
            drop(st);
            self.abandon(&called);
            return;
        }
        // A final answer gives its units back before its caller is woken with it.
        let freed = if pending || short {
            st.admitted = admitted;
            None
        } else {
            admitted
        };
        st.answered = Some((called, wake_at));
        let waker = st.waker.take();
        drop(st);
        drop(freed);
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
        self.end();
        release(&self.plugin, called.lease);
    }

    /// `cancel` of the op if it is pending, then its end (a plugin thread). What `cancel` answered,
    /// `None` when nothing was pending.
    fn cancel_pending(&self) -> Option<Cancelled> {
        let (owed, unit) = {
            let mut st = self.lock();
            (std::mem::take(&mut st.pending), st.unit)
        };
        let cancelled = owed.then(|| self.plugin.cancel_inline(self.ticket, self.class, unit));
        if let Some(c) = cancelled.as_ref().filter(|c| c.outcome != Outcome::Ready) {
            tracing::warn!(
                plugin = %self.plugin.name(),
                outcome = ?c.outcome,
                "the cancel of a pending op did not answer READY"
            );
        }
        self.end();
        cancelled
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

    /// Wait for the op's wake (its latch), its `wake_at_ns` or its deadline: `false` = the
    /// deadline came first.
    async fn woken_by(&self, wake_at_ns: u64, deadline: Instant) -> bool {
        let until = if wake_at_ns == 0 {
            deadline
        } else {
            let left = wake_at_ns.saturating_sub(now_ns());
            (Instant::now() + Duration::from_nanos(left)).min(deadline)
        };
        let mut sleep = std::pin::pin!(sleep_until(until));
        std::future::poll_fn(|cx| {
            *self
                .latch
                .task
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(cx.waker().clone());
            if self.latch.woke.swap(false, Ordering::AcqRel) {
                return Poll::Ready(true);
            }
            if sleep.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Instant::now() < deadline);
            }
            Poll::Pending
        })
        .await
    }

    /// The deadline passed with the op pending: cancel it on a plugin thread and wait for the
    /// answer.
    async fn cancel_now(self: &Arc<Self>) -> Cancelled {
        {
            let mut st = self.lock();
            st.gone = true;
            st.cancelled = None;
        }
        let op = Arc::clone(self);
        crate::ffi_thread::spawn_on_plugin_thread(move || {
            let cancelled = op.cancel_pending().unwrap_or(Cancelled {
                outcome: Outcome::Ready,
                disposition: None,
                writes: Vec::new(),
            });
            let mut st = op.lock();
            st.cancelled = Some(cancelled);
            let waker = st.waker.take();
            drop(st);
            if let Some(w) = waker {
                w.wake();
            }
        });
        std::future::poll_fn(|cx| {
            let mut st = self.lock();
            match st.cancelled.take() {
                Some(c) => Poll::Ready(c),
                None => {
                    st.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
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
/// leaves the op to a plugin thread: a pending op is cancelled there, a running crossing ends it,
/// an answer nobody read has its lease handed back.
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
            _ => Ran::TimedOut { cancelled: None },
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
        let unread = st.answered.take();
        drop(st);
        if !crossing {
            crate::ffi_thread::spawn_on_plugin_thread(move || {
                let _ = op.cancel_pending();
                if let Some((called, _)) = unread {
                    if called.outcome != Outcome::Pending {
                        release(&op.plugin, called.lease);
                    }
                }
            });
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
