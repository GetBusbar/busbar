// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SANS-IO `hyper` DRIVE, AS AN SDK MACRO: [`hyper_io!`](crate::hyper_io) expands, inside a
//! framer plugin, the pipe, executor, host-clock timer and sink fill that run `hyper` over the
//! host's bytes. It is a macro, not a module of this crate, so that the contract depends on neither
//! `hyper` nor a byte-buffer crate: no plugin's resolved tree
//! gains them through the contract, and a framer's closure stays the contract alone (#40(a)). The
//! framer that expands it already depends on `hyper`, and names the buffer type its bodies yield.

/// THE SANS-IO DRIVE A FRAMER USES TO RUN `hyper`, expanded as `pub(crate) mod hyper_io` in the
/// calling crate as `hyper_io!(<buffer type>)`. The expanding crate must depend on `hyper` itself
/// (the expansion names `::hyper`), and it names the frame-buffer type: the one hyper's bodies
/// yield (`::hyper::body::Bytes`). This crate depends on neither and names no buffer type.
///
/// What it holds: [`HostIo`] (one framing's pipe, executor, host-clock timer and record-only waker;
/// `rounds` drives again only while something woke), and [`fill`], which hands the host what a
/// framing ([`Owed`]) owes, as far as its `FramerSink` holds: wire bytes, then [`Piece`]s (a piece
/// that does not fit whole is split, its end-of-frame on its last part), then the yield flags.
///
/// THE ONE REAL-CLOCK READ. `std::time::Instant` has no constructor but `now()`, and `hyper`'s
/// timer speaks `Instant`, so each `HostIo` reads the real clock ONCE, at `HostIo::new`, as the
/// epoch host times are laid on. Nothing advances from it; every instant after it is host time.
#[doc(hidden)]
#[macro_export]
macro_rules! hyper_io {
    ($buf:ty) => {
        /// The sans-IO `hyper` drive (`busbar_contract::hyper_io!`).
        #[allow(dead_code)]
        pub(crate) mod hyper_io {
            use std::collections::{HashMap, VecDeque};
            use std::future::Future;
            use std::io;
            use std::pin::Pin;
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::{Arc, Mutex};
            use std::task::{Context, Poll, Wake, Waker};
            use std::time::{Duration, Instant};

            /// The frame buffer the expanding crate named: cheap to clone and to split.
            pub type Buf = $buf;
            use ::hyper::rt::{Executor, ReadBufCursor, Sleep, Timer};

            use $crate::abi::sdk::{HostBuf, Lent, Out};
            use $crate::abi::transport::{FramerOut, FramerSink};

            /// The most bytes `hyper` may leave in the pipe's write half before its writes pend.
            pub const WRITE_HIGH_WATER: usize = 256 * 1024;

            /// The most drive rounds one op makes. A round repeats only when something woke during
            /// it, so a settled connection stops after one; the bound is the backstop.
            pub const MAX_ROUNDS: usize = 64;

            // ── the pipe ─────────────────────────────────────────────────────────────────────────

            /// What the far side sent and has not been read, whether the far side has ended, and
            /// what was written and the host has not been handed.
            #[derive(Default)]
            struct Pipe {
                rx: VecDeque<u8>,
                eof: bool,
                tx: Vec<u8>,
            }

            /// `hyper`'s I/O: the framing's pipe.
            pub struct HostStream(Arc<Mutex<Pipe>>);

            impl ::hyper::rt::Read for HostStream {
                fn poll_read(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    mut buf: ReadBufCursor<'_>,
                ) -> Poll<io::Result<()>> {
                    let mut p = self.0.lock().expect("pipe");
                    if p.rx.is_empty() {
                        // The far side's end reads as a zero-length read; otherwise wait for
                        // `ingest`.
                        return if p.eof {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Pending
                        };
                    }
                    let (a, b) = p.rx.as_slices();
                    let src = if a.is_empty() { b } else { a };
                    let n = src.len().min(buf.remaining());
                    buf.put_slice(&src[..n]);
                    p.rx.drain(..n);
                    Poll::Ready(Ok(()))
                }
            }

            impl ::hyper::rt::Write for HostStream {
                fn poll_write(
                    self: Pin<&mut Self>,
                    _cx: &mut Context<'_>,
                    b: &[u8],
                ) -> Poll<io::Result<usize>> {
                    let mut p = self.0.lock().expect("pipe");
                    if p.tx.len() >= WRITE_HIGH_WATER {
                        return Poll::Pending;
                    }
                    p.tx.extend_from_slice(b);
                    Poll::Ready(Ok(b.len()))
                }
                fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
                fn poll_shutdown(
                    self: Pin<&mut Self>,
                    _: &mut Context<'_>,
                ) -> Poll<io::Result<()>> {
                    Poll::Ready(Ok(()))
                }
            }

            // ── the executor ─────────────────────────────────────────────────────────────────────

            type Task = Pin<Box<dyn Future<Output = ()> + Send>>;

            /// `hyper`'s executor: the framing's task list, polled inside the op that is running.
            #[derive(Clone, Default)]
            pub struct HostExec(Arc<Mutex<Vec<Task>>>);

            impl<F: Future<Output = ()> + Send + 'static> Executor<F> for HostExec {
                fn execute(&self, fut: F) {
                    self.0.lock().expect("exec").push(Box::pin(fut));
                }
            }

            impl HostExec {
                fn run(&self, cx: &mut Context<'_>) {
                    let mut tasks = std::mem::take(&mut *self.0.lock().expect("exec"));
                    tasks.retain_mut(|t| t.as_mut().poll(cx).is_pending());
                    let mut q = self.0.lock().expect("exec");
                    // Tasks spawned during the pass run on the next round.
                    tasks.append(&mut q);
                    *q = tasks;
                }
            }

            // ── the timer ────────────────────────────────────────────────────────────────────────

            /// The host's clock as `hyper` sees it, and the sleeps waiting on it.
            struct Clock {
                epoch: Instant,
                epoch_ns: u64,
                now_ns: u64,
                next_id: u64,
                sleeps: HashMap<u64, (Instant, Option<Waker>)>,
            }

            impl Clock {
                fn at(&self, ns: u64) -> Instant {
                    self.epoch + Duration::from_nanos(ns.saturating_sub(self.epoch_ns))
                }
                fn ns_of(&self, i: Instant) -> u64 {
                    let d = i.saturating_duration_since(self.epoch);
                    self.epoch_ns
                        .saturating_add(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
                }
            }

            /// `hyper`'s timer, on the host's clock.
            #[derive(Clone)]
            pub struct HostTimer(Arc<Mutex<Clock>>);

            struct HostSleep {
                clock: Arc<Mutex<Clock>>,
                id: u64,
            }

            impl Future for HostSleep {
                type Output = ();
                fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                    let mut c = self.clock.lock().expect("clock");
                    let now = c.at(c.now_ns);
                    let Some(entry) = c.sleeps.get_mut(&self.id) else {
                        return Poll::Ready(());
                    };
                    if entry.0 <= now {
                        Poll::Ready(())
                    } else {
                        entry.1 = Some(cx.waker().clone());
                        Poll::Pending
                    }
                }
            }

            impl Drop for HostSleep {
                fn drop(&mut self) {
                    if let Ok(mut c) = self.clock.lock() {
                        c.sleeps.remove(&self.id);
                    }
                }
            }

            impl Sleep for HostSleep {}

            impl Timer for HostTimer {
                fn sleep(&self, d: Duration) -> Pin<Box<dyn Sleep>> {
                    self.sleep_until(self.now() + d)
                }
                fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
                    let mut c = self.0.lock().expect("clock");
                    let id = c.next_id;
                    c.next_id += 1;
                    c.sleeps.insert(id, (deadline, None));
                    Box::pin(HostSleep {
                        clock: self.0.clone(),
                        id,
                    })
                }
                fn now(&self) -> Instant {
                    let c = self.0.lock().expect("clock");
                    c.at(c.now_ns)
                }
                fn reset(&self, sleep: &mut Pin<Box<dyn Sleep>>, new_deadline: Instant) {
                    if let Some(s) = sleep.as_mut().downcast_mut_pin::<HostSleep>() {
                        if let Some(e) = self.0.lock().expect("clock").sleeps.get_mut(&s.id) {
                            e.0 = new_deadline;
                            return;
                        }
                    }
                    *sleep = self.sleep_until(new_deadline);
                }
            }

            impl HostTimer {
                /// The instant host time `ns` is.
                #[must_use]
                pub fn at_ns(&self, ns: u64) -> Instant {
                    self.0.lock().expect("clock").at(ns)
                }
                /// A sleep until host time `at_ns` (monotonic nanoseconds).
                #[must_use]
                pub fn sleep_until_ns(&self, at_ns: u64) -> Pin<Box<dyn Sleep>> {
                    let at = self.0.lock().expect("clock").at(at_ns);
                    self.sleep_until(at)
                }
                /// The host's time now, in monotonic nanoseconds.
                #[must_use]
                pub fn now_ns(&self) -> u64 {
                    self.0.lock().expect("clock").now_ns
                }
                fn set(&self, now_ns: u64) {
                    let due: Vec<Waker> = {
                        let mut c = self.0.lock().expect("clock");
                        c.now_ns = c.now_ns.max(now_ns);
                        let now = c.at(c.now_ns);
                        c.sleeps
                            .values_mut()
                            .filter(|(d, _)| *d <= now)
                            .filter_map(|(_, w)| w.take())
                            .collect()
                    };
                    due.into_iter().for_each(Waker::wake);
                }
                fn next_deadline(&self) -> Option<u64> {
                    let c = self.0.lock().expect("clock");
                    let now = c.at(c.now_ns);
                    c.sleeps
                        .values()
                        .map(|(d, _)| *d)
                        .filter(|d| *d > now)
                        .min()
                        .map(|d| c.ns_of(d))
                }
            }

            // ── the waker ────────────────────────────────────────────────────────────────────────

            /// Every waker a driven future sees: it records that something woke, and the op drives
            /// again.
            #[derive(Default)]
            struct Woken(AtomicBool);

            impl Wake for Woken {
                fn wake(self: Arc<Self>) {
                    self.0.store(true, Ordering::Release);
                }
                fn wake_by_ref(self: &Arc<Self>) {
                    self.0.store(true, Ordering::Release);
                }
            }

            // ── one framing's drive ──────────────────────────────────────────────────────────────

            /// One framing's pipe, executor, timer and waker.
            #[derive(Clone)]
            pub struct HostIo {
                pipe: Arc<Mutex<Pipe>>,
                exec: HostExec,
                timer: HostTimer,
                woken: Arc<Woken>,
                waker: Waker,
            }

            impl HostIo {
                /// A drive whose clock starts at host time `now_ns` (the one real-clock read:
                /// module docs).
                #[must_use]
                pub fn new(now_ns: u64) -> Self {
                    let woken = Arc::new(Woken::default());
                    Self {
                        pipe: Arc::new(Mutex::new(Pipe::default())),
                        exec: HostExec::default(),
                        timer: HostTimer(Arc::new(Mutex::new(Clock {
                            epoch: Instant::now(),
                            epoch_ns: now_ns,
                            now_ns,
                            next_id: 0,
                            sleeps: HashMap::new(),
                        }))),
                        waker: Waker::from(woken.clone()),
                        woken,
                    }
                }

                /// The stream `hyper` reads and writes.
                #[must_use]
                pub fn stream(&self) -> HostStream {
                    HostStream(self.pipe.clone())
                }

                /// The executor `hyper` spawns onto.
                #[must_use]
                pub fn exec(&self) -> HostExec {
                    self.exec.clone()
                }

                /// The timer `hyper` sleeps on.
                #[must_use]
                pub fn timer(&self) -> HostTimer {
                    self.timer.clone()
                }

                /// The far side sent `bytes` (`end` = and then ended).
                pub fn ingest(&self, bytes: &[u8], end: bool) {
                    let mut p = self.pipe.lock().expect("pipe");
                    p.rx.extend(bytes);
                    p.eof |= end;
                }

                /// Take up to `cap` wire bytes owed to the far side.
                #[must_use]
                pub fn take_wire(&self, cap: usize) -> Vec<u8> {
                    let mut p = self.pipe.lock().expect("pipe");
                    let n = p.tx.len().min(cap);
                    p.tx.drain(..n).collect()
                }

                /// Write as many wire bytes owed to the far side as `into` has room for, straight
                /// into the host's buffer (no copy of them in between), and owe only the rest.
                pub fn wire_into(&self, into: &mut HostBuf<'_, u8>) {
                    let mut p = self.pipe.lock().expect("pipe");
                    let n = into.stream(&p.tx);
                    p.tx.drain(..n);
                }

                /// Whether wire bytes are still owed.
                #[must_use]
                pub fn wire_pending(&self) -> bool {
                    !self.pipe.lock().expect("pipe").tx.is_empty()
                }

                /// Set the host's time (monotonic nanoseconds) and wake every sleep it passed.
                pub fn set_time(&self, now_ns: u64) {
                    self.timer.set(now_ns);
                }

                /// The earliest sleep still waiting, as host time.
                #[must_use]
                pub fn next_deadline(&self) -> Option<u64> {
                    self.timer.next_deadline()
                }

                /// Drive: each round runs the executor's tasks, then `round`; another round follows
                /// only when something woke during it, up to [`MAX_ROUNDS`]. The first error
                /// ends the drive.
                ///
                /// # Errors
                ///
                /// `round`'s error.
                pub fn rounds<E>(
                    &self,
                    mut round: impl FnMut(&mut Context<'_>) -> Result<(), E>,
                ) -> Result<(), E> {
                    let waker = self.waker.clone();
                    let mut cx = Context::from_waker(&waker);
                    for _ in 0..MAX_ROUNDS {
                        self.woken.0.store(false, Ordering::Release);
                        self.exec.run(&mut cx);
                        round(&mut cx)?;
                        if !self.woken.0.load(Ordering::Acquire) {
                            break;
                        }
                    }
                    Ok(())
                }
            }

            // ── the sink (`abi::sdk::transport::sink`, over `Buf`) ───────────────────────────────

            pub use $crate::abi::sdk::transport::sink::{field_cut, mark_stream_full};

            /// A stream's head words, for its head slots
            /// (`busbar_contract::abi::sdk::transport::sink::HeadWords`).
            pub type HeadWords = $crate::abi::sdk::transport::sink::HeadWords<Buf>;

            /// A frame piece waiting for the host's sink
            /// (`busbar_contract::abi::sdk::transport::sink::Piece`).
            pub type Piece = $crate::abi::sdk::transport::sink::Piece<Buf>;

            /// What a framing owes the host, as [`fill`] reads it.
            pub trait Owed {
                /// Take up to `cap` wire bytes owed to the far side.
                fn take_wire(&mut self, cap: usize) -> Vec<u8>;
                /// Write as many wire bytes owed to the far side as `into` has room for. A framing
                /// whose wire is a [`HostIo`]'s writes them straight in
                /// (`self.io.wire_into(into)`); by default they are taken ([`Owed::take_wire`])
                /// and copied in.
                fn wire_into(&mut self, into: &mut HostBuf<'_, u8>) {
                    let room = into.cap().saturating_sub(into.asked());
                    into.extend(&self.take_wire(room));
                }
                /// Whether wire bytes are still owed after a take.
                fn wire_pending(&self) -> bool;
                /// The pieces waiting for the host.
                fn pieces(&mut self) -> &mut VecDeque<Piece>;
                /// The earliest host time the framing must be called at.
                fn next_deadline(&self) -> Option<u64>;
                /// Whether the connection has ended.
                fn ended(&self) -> bool;
            }

            /// An [`Owed`] as the SDK's sink reads it: a split piece keeps its rest as a slice of
            /// the same buffer, never a copy.
            struct Owing<'a, F>(&'a mut F);

            impl<F: Owed> $crate::abi::sdk::transport::sink::Owed<Buf> for Owing<'_, F> {
                fn wire_into(&mut self, into: &mut HostBuf<'_, u8>) {
                    self.0.wire_into(into);
                }
                fn wire_pending(&self) -> bool {
                    self.0.wire_pending()
                }
                fn pieces(&mut self) -> &mut VecDeque<Piece> {
                    self.0.pieces()
                }
                fn next_deadline(&self) -> Option<u64> {
                    self.0.next_deadline()
                }
                fn ended(&self) -> bool {
                    self.0.ended()
                }
                fn rest(bytes: &mut Buf, at: usize) {
                    *bytes = bytes.slice(at..);
                }
            }

            /// Hand the host what `f` owes it, as far as the sink holds
            /// (`busbar_contract::abi::sdk::transport::sink::fill`).
            pub fn fill(
                f: &mut impl Owed,
                sink: Lent<'_, FramerSink>,
                o: &mut Out<'_, FramerOut>,
                class_of: impl Fn(u16) -> u8,
                fault_of: impl Fn(u16) -> u8,
            ) {
                $crate::abi::sdk::transport::sink::fill::<Buf, _>(
                    &mut Owing(f),
                    sink,
                    o,
                    class_of,
                    fault_of,
                );
            }

            /// `headers` as a field block (`busbar_contract::abi::transport::fields`):
            /// `name: value\r\n` per value, in the map's order (names as they first arrived, a
            /// repeated name's values each on its own line after it), hop-by-hop fields and those
            /// `connection` names dropped, `content-length` too (the pieces carry the body hyper
            /// already unframed), and every name in `also`.
            #[must_use]
            pub fn field_block(headers: &::hyper::header::HeaderMap, also: &[&str]) -> Vec<u8> {
                use $crate::abi::transport::fields::{hop_by_hop, LINE_END, SEPARATOR};
                let nominated = headers.get_all(::hyper::header::CONNECTION);
                let mut block = Vec::new();
                for (name, value) in headers {
                    let name = name.as_str();
                    if name == "content-length"
                        || also.contains(&name)
                        || hop_by_hop(
                            name,
                            nominated.iter().map(::hyper::header::HeaderValue::as_bytes),
                        )
                    {
                        continue;
                    }
                    block.extend_from_slice(name.as_bytes());
                    block.extend_from_slice(SEPARATOR);
                    block.extend_from_slice(value.as_bytes());
                    block.extend_from_slice(LINE_END);
                }
                block
            }
        }
    };
}
