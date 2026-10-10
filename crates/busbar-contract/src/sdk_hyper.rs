// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SANS-IO `hyper` DRIVE, AS AN SDK MACRO: [`hyper_io!`](crate::hyper_io) expands, inside a
//! framer plugin, the pipe, executor, host-clock timer and sink fill that run `hyper` over the
//! host's bytes. It is a macro, not a module of this crate, so that the contract depends on neither
//! `hyper` nor a byte-buffer crate (ARCHITECT ruling 2026-09-30 (c)): no plugin's resolved tree
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
            use $crate::abi::transport::{
                FramePiece, FrameSpan, FramerOut, FramerSink, HeadSlots, PIECE_CONTINUED,
                PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE, PIECE_HAS_RETRY_AFTER,
                PIECE_STREAM_FAILED, PIECE_WRITABLE, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
                YIELD_STREAM_FULL,
            };

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

            // ── the sink ─────────────────────────────────────────────────────────────────────────

            /// A stream's head words, for its head slots (`HeadSlots`): what a head says that is
            /// never a field. Empty = absent. An accepted stream states `method`, `target` and,
            /// where the caller named one, `authority`; a dialled one the far end's `reason`.
            #[derive(Debug, Clone, Default, PartialEq, Eq)]
            pub struct HeadWords {
                /// The method.
                pub method: Buf,
                /// The target (path and query).
                pub target: Buf,
                /// The authority the caller named.
                pub authority: Buf,
                /// The far end's reason phrase, exactly as sent.
                pub reason: Buf,
            }

            impl HeadWords {
                /// The far end's reason phrase alone.
                #[must_use]
                pub fn reason(reason: Buf) -> Self {
                    Self {
                        reason,
                        ..Self::default()
                    }
                }
                fn len(&self) -> usize {
                    self.method.len() + self.target.len() + self.authority.len() + self.reason.len()
                }
            }

            /// A frame piece waiting for the host's sink.
            #[derive(Debug, Clone, PartialEq, Eq)]
            pub struct Piece {
                /// The stream.
                pub stream: u64,
                /// The frame bytes (empty with nothing else set: the stream's frames are over).
                pub bytes: Buf,
                /// The status code the piece states, in the claim's own numbering.
                pub status: Option<u16>,
                /// The wait the far side asked for.
                pub retry_after_secs: Option<u64>,
                /// The stream failed; `bytes` are the reason, and this is its last piece.
                pub failed: bool,
                /// `bytes` are a field block (`PIECE_FIELDS`): a head, or the trailers.
                pub fields: bool,
                /// A full sink split this field block mid-line: `bytes` open by continuing a line.
                pub continued: bool,
                /// The stream's head words, handed with its head's first piece.
                pub head: Option<HeadWords>,
                /// The stream is writable again (`PIECE_WRITABLE`): an empty piece, nothing else
                /// set, after an `emit` answered the stream full ([`mark_stream_full`]).
                pub writable: bool,
            }

            impl Piece {
                /// Frame bytes on `stream`.
                #[must_use]
                pub fn data(stream: u64, bytes: Buf) -> Self {
                    Self {
                        stream,
                        bytes,
                        status: None,
                        retry_after_secs: None,
                        failed: false,
                        fields: false,
                        continued: false,
                        head: None,
                        writable: false,
                    }
                }
                /// A field block on `stream`.
                #[must_use]
                pub fn fields(stream: u64, block: Buf) -> Self {
                    Self {
                        fields: true,
                        ..Self::data(stream, block)
                    }
                }
                /// `stream` failed, for `why`.
                #[must_use]
                pub fn failure(stream: u64, why: &str) -> Self {
                    Self {
                        failed: true,
                        ..Self::data(stream, Buf::from(why.to_owned()))
                    }
                }
                /// `stream` is writable again: the host may emit on it.
                #[must_use]
                pub fn writable(stream: u64) -> Self {
                    Self {
                        writable: true,
                        ..Self::data(stream, Buf::from(String::new()))
                    }
                }
            }

            /// The `emit` just answered left its stream's queue at its high-water mark
            /// (`YIELD_STREAM_FULL`): the host holds that stream's emits until a
            /// [`Piece::writable`] or the stream's last piece. Set after [`fill`], on `emit` only.
            pub fn mark_stream_full(o: &mut Out<'_, FramerOut>) {
                let mut y = o.get().yielded;
                y.flags |= YIELD_STREAM_FULL;
                o.set(|x| &x.yielded, y);
            }

            /// What a framing owes the host, as [`fill`] reads it.
            pub trait Owed {
                /// Take up to `cap` wire bytes owed to the far side.
                fn take_wire(&mut self, cap: usize) -> Vec<u8>;
                /// Whether wire bytes are still owed after a take.
                fn wire_pending(&self) -> bool;
                /// The pieces waiting for the host.
                fn pieces(&mut self) -> &mut VecDeque<Piece>;
                /// The earliest host time the framing must be called at.
                fn next_deadline(&self) -> Option<u64>;
                /// Whether the connection has ended.
                fn ended(&self) -> bool;
            }

            /// Hand the host what `f` owes it, as far as the sink holds: wire bytes, then pieces (a
            /// piece that does not fit whole is split, its end-of-frame on its last part; a field
            /// block only where a continuation extends a value), each stream's head words in its
            /// head slots ahead of its head's first piece, then the yield flags. `class_of` maps a
            /// piece's status code to its class.
            pub fn fill(
                f: &mut impl Owed,
                sink: Lent<'_, FramerSink>,
                o: &mut Out<'_, FramerOut>,
                class_of: impl Fn(u16) -> u8,
            ) {
                let mut wire_buf = sink.wire();
                let wire = f.take_wire(wire_buf.cap());
                wire_buf.extend(&wire);
                let mut y = o.get().yielded;
                y.wire_len = wire_buf.written() as u64;
                let (mut frame, mut pieces): (HostBuf<'_, u8>, HostBuf<'_, FramePiece>) =
                    (sink.frame(), sink.pieces());
                let mut frame_len = 0_usize;
                let mut n = 0_usize;
                let mut head_slots: HostBuf<'_, HeadSlots> = sink.heads();
                let mut heads = 0_usize;
                while n < pieces.cap() {
                    let Some(piece) = f.pieces().front_mut() else {
                        break;
                    };
                    // A head's words ride its stream's head slots, in the answer that carries the
                    // head's first piece, their bytes in the frame ahead of the piece's. A host
                    // that takes no slots (or a frame too small ever to hold them) is not handed
                    // them.
                    if let Some(words) = piece.head.take() {
                        let need = words.len();
                        if head_slots.cap() == 0 || need > frame.cap() {
                            // Dropped.
                        } else if heads == head_slots.cap() || need > frame.cap() - frame_len {
                            piece.head = Some(words);
                            break;
                        } else {
                            // The words fit the frame's room and `heads < heads_cap`.
                            let mut span = |b: &Buf| {
                                let at = frame_len;
                                frame.extend(b);
                                frame_len += b.len();
                                FrameSpan {
                                    offset: if b.is_empty() { 0 } else { at as u64 },
                                    len: b.len() as u64,
                                }
                            };
                            let slots = HeadSlots {
                                stream: piece.stream,
                                method: span(&words.method),
                                target: span(&words.target),
                                authority: span(&words.authority),
                                reason: span(&words.reason),
                            };
                            head_slots.push(slots);
                            heads += 1;
                        }
                    }
                    let room = frame.cap() - frame_len;
                    // A field block is cut only where the host takes a continuation: at a line's
                    // start or inside a value. A name longer than the whole frame is cut anyway
                    // (the host refuses it by name) rather than never moving.
                    let take = if piece.fields {
                        match field_cut(&piece.bytes, room, piece.continued) {
                            0 if frame_len == 0 => piece.bytes.len().min(room),
                            cut => cut,
                        }
                    } else {
                        piece.bytes.len().min(room)
                    };
                    if take == 0 && !piece.bytes.is_empty() {
                        break;
                    }
                    let whole = take == piece.bytes.len();
                    let mut flags = if piece.writable {
                        // A signal about the stream: it ends no frame.
                        PIECE_WRITABLE
                    } else if whole {
                        PIECE_END_OF_FRAME
                    } else {
                        0
                    };
                    // A failure frame may span pieces like any other; its LAST piece says the
                    // stream failed.
                    if piece.failed && whole {
                        flags |= PIECE_STREAM_FAILED;
                    }
                    if piece.fields {
                        flags |= PIECE_FIELDS;
                        if piece.continued {
                            flags |= PIECE_CONTINUED;
                        }
                    }
                    let mut fp = FramePiece {
                        stream: piece.stream,
                        offset: frame_len as u64,
                        len: take as u64,
                        code: 0,
                        status_class: 0,
                        flags: 0,
                        _reserved: 0,
                        retry_after_secs: 0,
                    };
                    if let Some(code) = piece.status {
                        flags |= PIECE_HAS_CODE;
                        fp.code = u32::from(code);
                        fp.status_class = class_of(code);
                    }
                    if let Some(secs) = piece.retry_after_secs {
                        flags |= PIECE_HAS_RETRY_AFTER;
                        fp.retry_after_secs = secs;
                    }
                    fp.flags = flags;
                    // `take <= room` and `n < pieces_cap`: both fit.
                    frame.extend(&piece.bytes[..take]);
                    pieces.push(fp);
                    frame_len += take;
                    n += 1;
                    if whole {
                        f.pieces().pop_front();
                    } else {
                        // The rest opens mid-line unless what was taken ended one.
                        piece.continued = !piece.bytes[..take].ends_with(b"\n");
                        let rest = piece.bytes.slice(take..);
                        piece.bytes = rest;
                    }
                }
                y.frame_len = frame_len as u64;
                y.pieces_len = n as u32;
                y.heads_len = heads as u32;
                let more = f.wire_pending() || !f.pieces().is_empty();
                let mut flags = 0;
                if more {
                    flags |= YIELD_MORE;
                }
                if let Some(at) = f.next_deadline() {
                    flags |= YIELD_HAS_DEADLINE;
                    y.next_deadline_ns = at;
                }
                if !more && f.ended() {
                    flags |= YIELD_ENDED;
                }
                y.flags = flags;
                o.set(|x| &x.yielded, y);
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

            /// How much of a field block's `bytes` a sink with `room` may take: all of it when it
            /// fits, else the furthest cut at a line's start or inside a value, so a continued piece
            /// always extends a value (the host refuses any other continuation). `in_value`: the
            /// bytes open inside a value. `0`: no cut fits.
            #[must_use]
            pub fn field_cut(bytes: &[u8], room: usize, in_value: bool) -> usize {
                if bytes.len() <= room {
                    return bytes.len();
                }
                // 0 = a line's start, 1 = a name, 2 = a value.
                let mut at = if in_value { 2 } else { 0 };
                let mut best = 0;
                for (i, &b) in bytes[..room].iter().enumerate() {
                    at = match (at, b) {
                        (0 | 1, b':') => 2,
                        (0 | 1, _) => 1,
                        (_, b'\n') => 0,
                        _ => 2,
                    };
                    if at != 1 {
                        best = i + 1;
                    }
                }
                best
            }
        }
    };
}
