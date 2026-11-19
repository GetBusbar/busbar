// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `MemIo`: the in-plugin executor and byte pipes for hyper/h2, feature `memio` (IF §9, r4 §3.8(b)).
//!
//! One connection's world with no sockets, no threads and no clock of its own: bytes arrive through `feed`,
//! tasks run inside `run` with the time the caller states, and what the tasks wrote leaves through `flush` as
//! WRITE records plus one WAKE_AT. Wakers, tasks and timers never cross the boundary. No `unsafe`: the task
//! wakers are `std::task::Wake`, the read side fills hyper's cursor with `put_slice`.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};

use crate::kinds::transport::transport::tag;
use crate::records::{Full, Writer};

/// The bytes of one WRITE record at most (a longer drain is several WRITE records, in order).
const WRITE_CHUNK: usize = 16 * 1024;

#[path = "memio_provenance.rs"]
mod provenance;
pub use provenance::Provenance;

type Task = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// A poisoned lock only means a task panicked mid-poll; the state under it is still plain data.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Default)]
struct Pipes {
    /// The far end's bytes not yet read: wiped as they are read and when the conn is released.
    read: busbar_secure::SecureVec,
    eof: bool,
    reader: Option<Waker>,
    write: busbar_secure::SecureVec,
    writer: Option<Waker>,
    plan: Option<provenance::Plan>,
    shut: bool,
    close_reported: bool,
}

#[derive(Default)]
struct Sched {
    /// Task ids whose waker fired (each at most once: the `queued` flag dedupes).
    ready: VecDeque<usize>,
    /// Futures spawned (by `MemIo::spawn` or `MemExec`) and not yet in the slab.
    inbox: Vec<Task>,
}

/// One live sleep: its deadline on the clock `run` is given, whether it fired, the task waiting on it.
struct Slot {
    id: u64,
    deadline_ns: u64,
    fired: bool,
    waker: Option<Waker>,
}

/// The conn's live sleeps, in no order. Each `MemSleep` names its slot by `id` and removes it when
/// dropped, so `live` holds only sleeps someone still awaits. Its buffer is kept by `Shared`, grows
/// to the most sleeps live at once (hyper keeps a few per conn) and is released with the conn.
#[derive(Default)]
struct Timers {
    next: u64,
    live: Vec<Slot>,
}
impl Timers {
    fn slot(&mut self, id: u64) -> Option<&mut Slot> {
        self.live.iter_mut().find(|s| s.id == id)
    }
}

struct Shared {
    pipes: Mutex<Pipes>,
    sched: Mutex<Sched>,
    timers: Mutex<Timers>,
    now_ns: AtomicU64,
    /// The `Instant` that stands for zero on the clock `run` is given: `MemTimer::now` answers
    /// `base + now_ns`, and a deadline `Instant` (hyper's timer API) is read back as its distance
    /// from `base`. Only an anchor: no time is ever read from it.
    base: Instant,
}

/// A task's waker. `Shared` stores wakers (the pipe's reader and writer, timer slots, provenance
/// release gates), so the waker must not own `Shared`: a strong reference here would make the state
/// hold itself and never be freed. Once the conn is gone a wake has nothing to queue and does nothing.
struct TaskWaker {
    id: usize,
    queued: AtomicBool,
    shared: Weak<Shared>,
}
impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::AcqRel)
            && let Some(shared) = self.shared.upgrade()
        {
            lock(&shared.sched).ready.push_back(self.id);
        }
    }
}

struct Entry {
    fut: Task,
    waker: Arc<TaskWaker>,
}

/// One connection's in-plugin executor and byte pipes for hyper/h2. Lives in the plugin's session state.
pub struct MemIo {
    shared: Arc<Shared>,
    tasks: Vec<Option<Entry>>,
    free: Vec<usize>,
    live: usize,
    budget_out: bool,
}

impl Default for MemIo {
    fn default() -> Self {
        Self::new()
    }
}

impl MemIo {
    pub fn new() -> Self {
        MemIo {
            shared: Arc::new(Shared {
                pipes: Mutex::new(Pipes::default()),
                sched: Mutex::new(Sched::default()),
                timers: Mutex::new(Timers::default()),
                now_ns: AtomicU64::new(0),
                base: Instant::now(),
            }),
            tasks: Vec::new(),
            free: Vec::new(),
            live: 0,
            budget_out: false,
        }
    }
    /// The hyper IO object for this conn (implements hyper::rt::Read + hyper::rt::Write). Call once.
    pub fn io(&self) -> MemStream {
        MemStream {
            shared: self.shared.clone(),
        }
    }
    /// Implements hyper::rt::Executor<F> for F: Future<Output = ()> + Send + 'static.
    pub fn executor(&self) -> MemExec {
        MemExec {
            shared: self.shared.clone(),
        }
    }
    /// Implements hyper::rt::Timer; time is the `now_mono_ns` the caller gives `run` (the Host's `mono_ns`).
    pub fn timer(&self) -> MemTimer {
        MemTimer {
            shared: self.shared.clone(),
        }
    }
    /// Feed bytes from `ingest` (empty = EOF) and wake the registered reader.
    pub fn feed(&mut self, bytes: &[u8]) {
        let waker = {
            let mut p = lock(&self.shared.pipes);
            if bytes.is_empty() {
                p.eof = true;
            } else {
                p.read.extend_from_slice(bytes);
            }
            p.reader.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
    /// Spawn a task on this conn (the connection driver itself, stream handlers).
    pub fn spawn(&mut self, fut: impl Future<Output = ()> + Send + 'static) {
        lock(&self.shared.sched).inbox.push(Box::pin(fut));
    }
    /// Poll only woken tasks, at most `budget` polls (256 by default), with now = mono_ns.
    pub fn run(&mut self, now_mono_ns: u64, budget: u32) -> Ran {
        self.shared.now_ns.store(now_mono_ns, Ordering::Release);
        self.fire_timers(now_mono_ns);
        let mut polls = 0u32;
        loop {
            self.admit();
            if polls >= budget {
                break;
            }
            let Some(id) = lock(&self.shared.sched).ready.pop_front() else {
                break;
            };
            let Some(entry) = self.tasks.get_mut(id).and_then(Option::as_mut) else {
                continue;
            };
            // Cleared before the poll, so a wake during it queues the task again.
            entry.waker.queued.store(false, Ordering::Release);
            let waker = Waker::from(entry.waker.clone());
            let mut cx = Context::from_waker(&waker);
            polls += 1;
            if entry.fut.as_mut().poll(&mut cx).is_ready() {
                self.tasks[id] = None;
                self.free.push(id);
                self.live -= 1;
            }
        }
        self.admit();
        self.budget_out = !lock(&self.shared.sched).ready.is_empty();
        if self.budget_out {
            return Ran::BudgetLeft;
        }
        let p = lock(&self.shared.pipes);
        if self.live == 0
            && (p.eof || p.shut)
            && p.plan
                .as_ref()
                .is_none_or(|plan| plan.responses.is_empty() && plan.queue.is_empty())
        {
            Ran::Closed
        } else {
            Ran::Idle
        }
    }
    /// Drain written bytes and the earliest timer (or `now` when the budget ran out) into WAKE_AT.
    /// INTERIM (transport 2.0): the plain WRITE record is retired, so an unlabelled drain writes its bytes as
    /// WIRE_PART on stream 0, class control. That is right only for connection-level bytes; a helper that
    /// drains a stream's bytes this way breaks rule L3. This whole drain is replaced by the labelled helper
    /// (`busbar-kind-transport-hyper`), where each write carries its stream and class.
    pub fn flush(&mut self, out: &mut impl Writer) -> Result<(), Full> {
        {
            let mut p = lock(&self.shared.pipes);
            let before = p.write.len();
            // Attributed callers use flush_attributed after reserving a continuation.
            // Refuse an accidental legacy drain before consuming any state.
            if p.plan.is_some() {
                return Err(Full);
            }
            while !p.write.is_empty() {
                let n = p.write.len().min(WRITE_CHUNK);
                let part = crate::kinds::transport::transport::WirePart {
                    stream: 0,
                    class: crate::kinds::transport::transport::WIRE_CONTROL,
                    _r: 0,
                };
                out.put_pod_tail(tag::WIRE_PART, &part, &p.write.as_slice()[..n])?;
                p.write.consume(n);
            }
            if p.write.len() < before
                && let Some(waker) = p.writer.take()
            {
                waker.wake();
            }
        }
        let wake = if self.budget_out {
            Some(self.shared.now_ns.load(Ordering::Acquire))
        } else {
            self.earliest()
        };
        if let Some(ns) = wake {
            out.put(tag::WAKE_AT, &ns.to_le_bytes())?;
        }
        Ok(())
    }

    /// Moves spawned futures into the slab and queues each for its first poll.
    fn admit(&mut self) {
        let fresh = std::mem::take(&mut lock(&self.shared.sched).inbox);
        for fut in fresh {
            let id = self.free.pop().unwrap_or_else(|| {
                self.tasks.push(None);
                self.tasks.len() - 1
            });
            let waker = Arc::new(TaskWaker {
                id,
                queued: AtomicBool::new(true),
                shared: Arc::downgrade(&self.shared),
            });
            self.tasks[id] = Some(Entry { fut, waker });
            self.live += 1;
            lock(&self.shared.sched).ready.push_back(id);
        }
    }
    /// One walk of the live sleeps under one lock; the due ones' tasks are woken after it is released.
    fn fire_timers(&self, now: u64) {
        let mut wakers = Vec::new();
        for s in lock(&self.shared.timers).live.iter_mut() {
            if !s.fired && s.deadline_ns <= now {
                s.fired = true;
                wakers.extend(s.waker.take());
            }
        }
        for w in wakers {
            w.wake();
        }
    }
    fn earliest(&self) -> Option<u64> {
        lock(&self.shared.timers)
            .live
            .iter()
            .filter(|s| !s.fired)
            .map(|s| s.deadline_ns)
            .min()
    }
}

/// The conn's tasks end with it. One spawned after the last `run` still waits in `Shared`'s inbox
/// and may hold a handle to `Shared` (a `MemStream`, a `MemTimer`): `Shared` would hold itself, so
/// the inbox is emptied here, its tasks dropped outside the lock, until dropping spawns no more.
impl Drop for MemIo {
    fn drop(&mut self) {
        self.tasks.clear();
        loop {
            let spawned = std::mem::take(&mut lock(&self.shared.sched).inbox);
            if spawned.is_empty() {
                break;
            }
            drop(spawned);
        }
    }
}

/// The conn's byte pipe for hyper: reads what `feed` supplied, writes what `flush` drains.
pub struct MemStream {
    shared: Arc<Shared>,
}
impl hyper::rt::Read for MemStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let mut p = lock(&self.shared.pipes);
        if !p.read.is_empty() {
            // Straight from the pipe into hyper's cursor, then wiped from the pipe.
            let n = p.read.len().min(buf.remaining());
            buf.put_slice(&p.read.as_slice()[..n]);
            p.read.consume(n);
            return Poll::Ready(Ok(()));
        }
        if p.eof {
            return Poll::Ready(Ok(()));
        }
        p.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}
impl hyper::rt::Write for MemStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut p = lock(&self.shared.pipes);
        if p.shut {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if let Some(plan) = p.plan.as_mut() {
            if plan.fault || buf.len() as u64 > plan.serialized - plan.accepted {
                plan.fault = true;
                return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
            }
            let available = plan
                .byte_limit
                .saturating_sub((plan.accepted - plan.emitted) as usize);
            if available == 0 && !buf.is_empty() {
                p.writer = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n = available.min(buf.len());
            plan.accepted += n as u64;
            if p.write.extend(&buf[..n]).is_err() {
                if let Some(plan) = p.plan.as_mut() {
                    plan.fault = true;
                }
                return Poll::Ready(Err(io::ErrorKind::OutOfMemory.into()));
            }
            return Poll::Ready(Ok(n));
        }
        p.write.extend_from_slice(buf);

        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        lock(&self.shared.pipes).shut = true;
        Poll::Ready(Ok(()))
    }
}

/// Hands hyper's spawned futures to the conn's task slab.
#[derive(Clone)]
pub struct MemExec {
    shared: Arc<Shared>,
}
impl<F> hyper::rt::Executor<F> for MemExec
where
    F: Future<Output = ()> + Send + 'static,
{
    fn execute(&self, fut: F) {
        lock(&self.shared.sched).inbox.push(Box::pin(fut));
    }
}

/// hyper's timer over the monotonic time `run` is given.
#[derive(Clone)]
pub struct MemTimer {
    shared: Arc<Shared>,
}
impl MemTimer {
    /// One allocation, the box hyper's trait asks for: the slot lives in the conn's `Timers`.
    fn sleep_at(&self, deadline_ns: u64) -> Pin<Box<dyn hyper::rt::Sleep>> {
        let id = {
            let mut timers = lock(&self.shared.timers);
            let id = timers.next;
            timers.next = id.wrapping_add(1);
            timers.live.push(Slot {
                id,
                deadline_ns,
                fired: false,
                waker: None,
            });
            id
        };
        Box::pin(MemSleep {
            shared: self.shared.clone(),
            id,
        })
    }
    /// A deadline `Instant` as nanoseconds on the clock `run` is given: its distance from `base`.
    fn offset(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.shared.base).as_nanos()).unwrap_or(u64::MAX)
    }
    /// The `Instant` that names `ns` on the clock `run` is given: the inverse of `offset`. An
    /// `Instant` reaches far more than 2^64 nanoseconds (585 years) past any `base` on every std
    /// target, so the add does not fail; `base` only stands in for a time no `Instant` can name.
    fn instant_at(&self, ns: u64) -> Instant {
        self.shared
            .base
            .checked_add(Duration::from_nanos(ns))
            .unwrap_or(self.shared.base)
    }
}
impl hyper::rt::Timer for MemTimer {
    /// The time `run` was last given, never the OS clock: hyper states its deadlines as
    /// `now() + d`, so each one lands on the one clock `run` compares with and WAKE_AT names.
    fn now(&self) -> Instant {
        self.instant_at(self.shared.now_ns.load(Ordering::Acquire))
    }
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn hyper::rt::Sleep>> {
        let add = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        self.sleep_at(
            self.shared
                .now_ns
                .load(Ordering::Acquire)
                .saturating_add(add),
        )
    }
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn hyper::rt::Sleep>> {
        self.sleep_at(self.offset(deadline))
    }
    fn reset(&self, sleep: &mut Pin<Box<dyn hyper::rt::Sleep>>, new_deadline: Instant) {
        let at = self.offset(new_deadline);
        if let Some(s) = sleep.as_mut().downcast_mut_pin::<MemSleep>() {
            if let Some(slot) = lock(&s.shared.timers).slot(s.id) {
                slot.deadline_ns = at;
                slot.fired = false;
            }
        } else {
            *sleep = self.sleep_at(at);
        }
    }
}

/// A sleep hyper holds: its slot in the conn's `Timers`, by id, for as long as it lives.
struct MemSleep {
    shared: Arc<Shared>,
    id: u64,
}
impl hyper::rt::Sleep for MemSleep {}

impl Future for MemSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let now = self.shared.now_ns.load(Ordering::Acquire);
        let mut timers = lock(&self.shared.timers);
        // The slot is removed only when this sleep is dropped, so it is always there.
        let Some(s) = timers.slot(self.id) else {
            return Poll::Ready(());
        };
        if s.fired || s.deadline_ns <= now {
            s.fired = true;
            return Poll::Ready(());
        }
        match &mut s.waker {
            Some(w) if w.will_wake(cx.waker()) => {}
            w => *w = Some(cx.waker().clone()),
        }
        Poll::Pending
    }
}

impl Drop for MemSleep {
    fn drop(&mut self) {
        let gone = {
            let mut timers = lock(&self.shared.timers);
            let at = timers.live.iter().position(|s| s.id == self.id);
            at.map(|i| timers.live.swap_remove(i))
        };
        // The slot's waker is released after the lock, as it was when the slot was its own `Arc`.
        drop(gone);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ran {
    Idle,
    BudgetLeft,
    Closed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::rt::{Executor, Read, ReadBuf, Timer, Write};
    use std::future::poll_fn;

    /// Collects records the way a Writer would, without core's buffers.
    #[derive(Default)]
    struct Rec(Vec<(u16, Vec<u8>)>);
    impl Writer for Rec {
        fn put_parts(&mut self, _: u16, _: &[&[u8]]) -> Result<(), Full> {
            unreachable!()
        }
        fn put_pod_nested<T: crate::records::Pod>(
            &mut self,
            _: u16,
            _: &T,
            _: impl FnOnce(&mut crate::records::Nested<'_>) -> Result<(), Full>,
        ) -> Result<(), Full> {
            unreachable!()
        }
        fn put(&mut self, tag: u16, body: &[u8]) -> Result<(), Full> {
            self.0.push((tag, body.to_vec()));
            Ok(())
        }
        fn put_u32s(
            &mut self,
            _: u16,
            _: impl FnOnce(&mut crate::records::U32s<'_>) -> Result<(), Full>,
        ) -> Result<(), Full> {
            unreachable!()
        }
        fn put_pod<T: crate::records::Pod>(&mut self, _: u16, _: &T) -> Result<(), Full> {
            unreachable!()
        }
        fn put_pod_tail<T: crate::records::Pod>(
            &mut self,
            _: u16,
            _: &T,
            _: &[u8],
        ) -> Result<(), Full> {
            unreachable!()
        }
        fn put_text(&mut self, _: u16, _: &str) -> Result<(), Full> {
            unreachable!()
        }
        fn put_pair(&mut self, _: u16, _: &str, _: &[u8]) -> Result<(), Full> {
            unreachable!()
        }
        fn put_fact(&mut self, _: u32, _: u64) -> Result<(), Full> {
            unreachable!()
        }
        fn put_fact_text(&mut self, _: u32, _: &str) -> Result<(), Full> {
            unreachable!()
        }
        fn put_metric(&mut self, _: u32, _: u32, _: f64, _: &[&str]) -> Result<(), Full> {
            unreachable!()
        }
        fn put_nested(
            &mut self,
            _: u16,
            _: impl FnOnce(&mut crate::records::Nested<'_>) -> Result<(), Full>,
        ) -> Result<(), Full> {
            unreachable!()
        }
    }

    #[test]
    fn echo_reads_fed_bytes_and_writes_them_out() {
        let mut m = MemIo::new();
        let mut io = m.io();
        m.spawn(async move {
            let mut got = Vec::new();
            while got.len() < 5 {
                let mut raw = [std::mem::MaybeUninit::<u8>::uninit(); 16];
                let mut rb = ReadBuf::uninit(&mut raw);
                poll_fn(|cx| Pin::new(&mut io).poll_read(cx, rb.unfilled()))
                    .await
                    .unwrap();
                got.extend_from_slice(rb.filled());
            }
            poll_fn(|cx| Pin::new(&mut io).poll_write(cx, &got))
                .await
                .unwrap();
        });
        assert_eq!(m.run(0, 256), Ran::Idle);
        m.feed(b"he");
        m.feed(b"llo");
        assert_eq!(m.run(1, 256), Ran::Idle);
        let mut out = Rec::default();
        m.flush(&mut out).unwrap();
        // Transport 2.0: a WIRE_PART body is its 16-byte fixed part (stream 0, control), then the bytes.
        assert_eq!(out.0.len(), 1);
        assert_eq!(out.0[0].0, tag::WIRE_PART);
        assert_eq!(&out.0[0].1[16..], b"hello");
    }

    #[test]
    fn eof_closes_once_tasks_end() {
        let mut m = MemIo::new();
        let mut io = m.io();
        m.spawn(async move {
            let mut raw = [std::mem::MaybeUninit::<u8>::uninit(); 4];
            let mut rb = ReadBuf::uninit(&mut raw);
            poll_fn(|cx| Pin::new(&mut io).poll_read(cx, rb.unfilled()))
                .await
                .unwrap();
            assert!(rb.filled().is_empty());
        });
        assert_eq!(m.run(0, 256), Ran::Idle);
        m.feed(&[]);
        assert_eq!(m.run(1, 256), Ran::Closed);
    }

    #[test]
    fn budget_bounds_polls_and_wake_at_is_now() {
        let mut m = MemIo::new();
        for _ in 0..3 {
            m.spawn(async {});
        }
        assert_eq!(m.run(7, 2), Ran::BudgetLeft);
        let mut out = Rec::default();
        m.flush(&mut out).unwrap();
        assert_eq!(out.0, vec![(tag::WAKE_AT, 7u64.to_le_bytes().to_vec())]);
        assert_eq!(m.run(8, 2), Ran::Idle);
    }

    #[test]
    fn timer_fires_at_its_deadline_and_wake_at_names_it() {
        let mut m = MemIo::new();
        let timer = m.timer();
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        m.spawn(async move {
            timer.sleep(Duration::from_nanos(500)).await;
            d.store(true, Ordering::SeqCst);
        });
        assert_eq!(m.run(1_000, 256), Ran::Idle);
        let mut out = Rec::default();
        m.flush(&mut out).unwrap();
        assert_eq!(out.0, vec![(tag::WAKE_AT, 1_500u64.to_le_bytes().to_vec())]);
        m.run(1_499, 256);
        assert!(!done.load(Ordering::SeqCst));
        m.run(1_500, 256);
        assert!(done.load(Ordering::SeqCst));
        let mut out = Rec::default();
        m.flush(&mut out).unwrap();
        assert!(out.0.is_empty());
    }

    #[test]
    fn a_dropped_sleep_leaves_no_slot_and_names_no_wake_at() {
        let mut m = MemIo::new();
        let timer = m.timer();
        let sooner = timer.sleep(Duration::from_secs(5));
        let later = timer.sleep(Duration::from_secs(9));
        drop(sooner);
        m.run(0, 256);
        let mut out = Rec::default();
        m.flush(&mut out).unwrap();
        assert_eq!(
            out.0,
            vec![(tag::WAKE_AT, 9_000_000_000u64.to_le_bytes().to_vec())]
        );
        drop(later);
        assert!(lock(&m.shared.timers).live.is_empty());
    }

    /// A host clock far from zero: an engine that has been up a minute states times like this.
    const MINUTE: u64 = 60_000_000_000;
    const GET: &[u8] = b"GET / HTTP/1.1\r\nhost: peer.test\r\n\r\n";

    /// hyper arms its timers with `timer.now() + d`: `now` must be the time `run` was given, so the
    /// deadline lands on the clock WAKE_AT is stated in.
    #[test]
    fn now_is_the_time_run_was_given_and_a_deadline_from_it_lands_on_that_clock() {
        let mut m = MemIo::new();
        let timer = m.timer();
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        m.spawn(async move {
            let at = timer.now() + Duration::from_millis(10);
            timer.sleep_until(at).await;
            d.store(true, Ordering::SeqCst);
        });
        assert_eq!(m.run(MINUTE, 256), Ran::Idle);
        assert!(
            !done.load(Ordering::SeqCst),
            "a ten-millisecond sleep fired at once"
        );
        let mut out = Rec::default();
        m.flush(&mut out).unwrap();
        assert_eq!(
            out.0,
            vec![(tag::WAKE_AT, (MINUTE + 10_000_000).to_le_bytes().to_vec())]
        );
        m.run(MINUTE + 9_999_999, 256);
        assert!(!done.load(Ordering::SeqCst));
        m.run(MINUTE + 10_000_000, 256);
        assert!(done.load(Ordering::SeqCst));
    }

    /// `reset` (hyper's kept-alive header timer) states its new deadline from `now` too.
    #[test]
    fn a_reset_deadline_lands_on_the_run_clock() {
        let mut m = MemIo::new();
        let timer = m.timer();
        let done = Arc::new(AtomicBool::new(false));
        let d = done.clone();
        m.spawn(async move {
            let mut sleep = timer.sleep(Duration::from_secs(1));
            timer.reset(&mut sleep, timer.now() + Duration::from_secs(30));
            sleep.await;
            d.store(true, Ordering::SeqCst);
        });
        m.run(MINUTE, 256);
        assert!(!done.load(Ordering::SeqCst), "a reset sleep fired at once");
        let mut out = Rec::default();
        m.flush(&mut out).unwrap();
        assert_eq!(
            out.0,
            vec![(
                tag::WAKE_AT,
                (MINUTE + 30_000_000_000).to_le_bytes().to_vec()
            )]
        );
        m.run(MINUTE + 30_000_000_000, 256);
        assert!(done.load(Ordering::SeqCst));
    }

    /// An HTTP/1.1 server conn over this MemIo with hyper's thirty-second header-read timeout.
    fn http1_server(m: &mut MemIo) {
        let io = m.io();
        let timer = m.timer();
        m.spawn(async move {
            let mut b = hyper::server::conn::http1::Builder::new();
            b.timer(timer).header_read_timeout(Duration::from_secs(30));
            let service =
                hyper::service::service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(String::from("ok")))
                });
            let _ = b.serve_connection(io, service).await;
        });
    }

    /// The `200` status lines in what `flush` wrote.
    fn served(m: &mut MemIo) -> usize {
        let mut out = Rec::default();
        m.flush(&mut out).unwrap();
        let wrote: Vec<u8> = out
            .0
            .iter()
            .filter(|(t, _)| *t == tag::WIRE_PART)
            .flat_map(|(_, body)| body.iter().skip(16).copied())
            .collect();
        wrote.windows(12).filter(|w| *w == b"HTTP/1.1 200").count()
    }

    #[test]
    fn a_kept_alive_http1_conn_serves_a_second_request_a_minute_in() {
        let mut m = MemIo::new();
        http1_server(&mut m);
        m.run(MINUTE, 256);
        m.feed(GET);
        m.run(MINUTE + 1_000, 256);
        assert_eq!(served(&mut m), 1, "the first request was not served");
        m.feed(GET);
        m.run(MINUTE + 2_000, 256);
        assert_eq!(
            served(&mut m),
            1,
            "the second request on a kept-alive conn was not served"
        );
    }

    #[test]
    fn a_head_split_across_two_reads_is_served_a_minute_in() {
        let mut m = MemIo::new();
        http1_server(&mut m);
        m.run(MINUTE, 256);
        let (a, b) = GET.split_at(20);
        m.feed(a);
        m.run(MINUTE + 1_000, 256);
        m.feed(b);
        m.run(MINUTE + 2_000, 256);
        assert_eq!(
            served(&mut m),
            1,
            "a head split across two reads was not served"
        );
    }

    #[test]
    fn executor_spawns_run_on_the_next_poll_round() {
        let mut m = MemIo::new();
        let exec = m.executor();
        let hit = Arc::new(AtomicBool::new(false));
        let h = hit.clone();
        m.spawn(async move {
            exec.execute(async move { h.store(true, Ordering::SeqCst) });
        });
        m.run(0, 256);
        assert!(hit.load(Ordering::SeqCst));
    }

    #[test]
    fn a_wake_queues_a_task_once() {
        let mut m = MemIo::new();
        let mut io = m.io();
        let polls = Arc::new(AtomicU64::new(0));
        let p = polls.clone();
        m.spawn(async move {
            loop {
                p.fetch_add(1, Ordering::SeqCst);
                let mut raw = [std::mem::MaybeUninit::<u8>::uninit(); 64];
                let mut rb = ReadBuf::uninit(&mut raw);
                poll_fn(|cx| Pin::new(&mut io).poll_read(cx, rb.unfilled()))
                    .await
                    .unwrap();
                if rb.filled().is_empty() {
                    return;
                }
            }
        });
        m.run(0, 256);
        m.feed(b"a");
        m.feed(b"b");
        m.run(0, 256);
        // First poll, then one wake for both feeds (the second feed finds no registered reader).
        assert!(polls.load(Ordering::SeqCst) <= 3);
    }

    /// The drop probe: no strong reference to the conn's state is left once every handle is gone.
    fn assert_freed(state: &std::sync::Weak<Shared>) {
        assert_eq!(
            state.strong_count(),
            0,
            "the conn's shared state outlived every handle to it"
        );
    }

    #[test]
    fn a_conn_dropped_with_hyper_parked_on_its_reader_frees_its_state() {
        let mut m = MemIo::new();
        http1_server(&mut m);
        m.run(MINUTE, 256);
        m.feed(GET);
        m.run(MINUTE + 1_000, 256);
        assert_eq!(served(&mut m), 1);
        // The kept-alive conn now waits for its next request: hyper's task waker is in `pipes.reader`.
        assert!(lock(&m.shared.pipes).reader.is_some());
        let state = Arc::downgrade(&m.shared);
        drop(m);
        assert_freed(&state);
    }

    #[test]
    fn an_attributed_conn_dropped_with_parked_wakers_frees_its_state_and_plan() {
        let mut m = MemIo::new();
        let plan = m.attributed_output(1, 4, 1024);
        plan.admit(1, u64::MAX).unwrap();
        let gate = plan.clone();
        let mut io = m.io();
        m.spawn(async move {
            let _ = poll_fn(|cx| gate.poll_release(1, cx)).await;
        });
        m.spawn(async move {
            let mut raw = [std::mem::MaybeUninit::<u8>::uninit(); 8];
            let mut rb = ReadBuf::uninit(&mut raw);
            let _ = poll_fn(|cx| Pin::new(&mut io).poll_read(cx, rb.unfilled())).await;
        });
        assert_eq!(m.run(0, 256), Ran::Idle);
        assert!(lock(&m.shared.pipes).reader.is_some());
        let state = Arc::downgrade(&m.shared);
        drop(plan);
        drop(m);
        assert_freed(&state);
    }

    #[test]
    fn a_task_spawned_after_the_last_run_is_dropped_with_the_conn() {
        let mut m = MemIo::new();
        let io = m.io();
        m.executor().execute(async move { drop(io) });
        let state = Arc::downgrade(&m.shared);
        drop(m);
        assert_freed(&state);
    }

    #[test]
    fn a_wake_after_the_conn_is_dropped_does_nothing() {
        let mut m = MemIo::new();
        let mut io = m.io();
        m.spawn(async move {
            let mut raw = [std::mem::MaybeUninit::<u8>::uninit(); 8];
            let mut rb = ReadBuf::uninit(&mut raw);
            let _ = poll_fn(|cx| Pin::new(&mut io).poll_read(cx, rb.unfilled())).await;
        });
        m.run(0, 256);
        let waker = lock(&m.shared.pipes)
            .reader
            .clone()
            .expect("a parked reader");
        let state = Arc::downgrade(&m.shared);
        drop(m);
        assert_freed(&state);
        waker.wake_by_ref();
        waker.wake();
    }
}

#[cfg(test)]
#[path = "memio_provenance_tests.rs"]
mod provenance_tests;
