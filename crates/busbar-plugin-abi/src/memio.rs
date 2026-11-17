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
    read: VecDeque<u8>,
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

struct Slot {
    deadline_ns: u64,
    fired: bool,
    waker: Option<Waker>,
}

struct Shared {
    pipes: Mutex<Pipes>,
    sched: Mutex<Sched>,
    timers: Mutex<Vec<Weak<Mutex<Slot>>>>,
    now_ns: AtomicU64,
    /// The anchor `std::time::Instant` deadlines (hyper's timer API) are measured from.
    base: Instant,
}

struct TaskWaker {
    id: usize,
    queued: AtomicBool,
    shared: Arc<Shared>,
}
impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        if !self.queued.swap(true, Ordering::AcqRel) {
            lock(&self.shared.sched).ready.push_back(self.id);
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
                timers: Mutex::new(Vec::new()),
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
                p.read.extend(bytes.iter().copied());
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
    /// Drain written bytes into WRITE records, and the earliest timer (or `now` when the budget ran out) into WAKE_AT.
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
                out.put(tag::WRITE, &p.write.as_slice()[..n])?;
                p.write.consume(n);
            }
            if p.write.len() < before {
                if let Some(waker) = p.writer.take() {
                    waker.wake();
                }
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
                shared: self.shared.clone(),
            });
            self.tasks[id] = Some(Entry { fut, waker });
            self.live += 1;
            lock(&self.shared.sched).ready.push_back(id);
        }
    }
    fn fire_timers(&self, now: u64) {
        let mut wakers = Vec::new();
        {
            let mut timers = lock(&self.shared.timers);
            timers.retain(|w| w.strong_count() > 0);
            for slot in timers.iter().filter_map(Weak::upgrade) {
                let mut s = lock(&slot);
                if !s.fired && s.deadline_ns <= now {
                    s.fired = true;
                    wakers.extend(s.waker.take());
                }
            }
        }
        for w in wakers {
            w.wake();
        }
    }
    fn earliest(&self) -> Option<u64> {
        lock(&self.shared.timers)
            .iter()
            .filter_map(Weak::upgrade)
            .filter_map(|slot| {
                let s = lock(&slot);
                (!s.fired).then_some(s.deadline_ns)
            })
            .min()
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
            let n = p.read.len().min(buf.remaining());
            let chunk: Vec<u8> = p.read.drain(..n).collect();
            buf.put_slice(&chunk);
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
    fn sleep_at(&self, deadline_ns: u64) -> Pin<Box<dyn hyper::rt::Sleep>> {
        let slot = Arc::new(Mutex::new(Slot {
            deadline_ns,
            fired: false,
            waker: None,
        }));
        lock(&self.shared.timers).push(Arc::downgrade(&slot));
        Box::pin(MemSleep {
            shared: self.shared.clone(),
            slot,
        })
    }
    fn offset(&self, at: Instant) -> u64 {
        u64::try_from(at.saturating_duration_since(self.shared.base).as_nanos()).unwrap_or(u64::MAX)
    }
}
impl hyper::rt::Timer for MemTimer {
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
            let mut slot = lock(&s.slot);
            slot.deadline_ns = at;
            slot.fired = false;
        } else {
            *sleep = self.sleep_at(at);
        }
    }
}

struct MemSleep {
    shared: Arc<Shared>,
    slot: Arc<Mutex<Slot>>,
}
impl hyper::rt::Sleep for MemSleep {}

impl Future for MemSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let now = self.shared.now_ns.load(Ordering::Acquire);
        let mut s = lock(&self.slot);
        if s.fired || s.deadline_ns <= now {
            s.fired = true;
            return Poll::Ready(());
        }
        s.waker = Some(cx.waker().clone());
        Poll::Pending
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
        assert_eq!(out.0, vec![(tag::WRITE, b"hello".to_vec())]);
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
}

#[cfg(test)]
#[path = "memio_provenance_tests.rs"]
mod provenance_tests;
