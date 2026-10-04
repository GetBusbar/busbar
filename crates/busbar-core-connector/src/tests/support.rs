// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST FRAMER ENTRY, in Rust behind the [`FramerDoor`] seam: an identity framer (the bytes are the
//! frames, one frame per ingest on stream `0`) with knobs a test turns — a target that asks for
//! connection security, a silence deadline, a `locate` that names another authority — and a record
//! of every crossing and the thread it ran on. The one place in this crate that writes a host sink
//! through its raw pointers, as a plugin does.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::thread::ThreadId;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{
    FramePiece, FrameSpan, FramerOut, FramerSink, HeadSlots, EMIT_TEXT, PIECE_END_OF_FRAME,
    PIECE_TEXT, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
};

use super::framer::{Call, Crossed, DoorFacts, FramerDoor};

/// The knobs.
#[derive(Debug, Clone, Default)]
pub struct Knobs {
    /// `locate` says the target asks for connection security, offering this name.
    pub secure_name: Option<&'static str>,
    /// A framing that has heard nothing for this long fails at its `timer`.
    pub silence: Option<Duration>,
    /// `locate` answers this authority whatever the target.
    pub authority: Option<&'static str>,
    /// `begin` yields one request head, `GET /v1` on stream `1`, as an accepted framing does.
    pub head: bool,
    /// Every frame the framing yields is a text message (`PIECE_TEXT`), as ws states one.
    pub text: bool,
}

#[derive(Default)]
struct State {
    inbound: VecDeque<u8>,
    outbound: VecDeque<u8>,
    ended: bool,
    heard: bool,
    deadline_ns: u64,
    text: bool,
}

/// The test entry.
pub struct TestDoor {
    facts: DoorFacts,
    knobs: Knobs,
    framings: Mutex<HashMap<u64, State>>,
    next: AtomicU64,
    /// Every crossing, by op.
    pub crossings: Mutex<Vec<&'static str>>,
    /// Every thread a crossing ran on.
    pub threads: Mutex<HashSet<ThreadId>>,
    /// The neutral status every `refuse` crossing carried, in order.
    pub refused_statuses: Mutex<Vec<u32>>,
}

impl TestDoor {
    /// An entry named `name`, claiming `claims`, over `composes_over`.
    pub fn new(
        name: &str,
        claims: &[&'static str],
        composes_over: &[&'static str],
        knobs: Knobs,
    ) -> Self {
        Self {
            facts: DoorFacts {
                name: name.to_owned(),
                claims: claims.to_vec(),
                composes_over: composes_over.to_vec(),
            },
            knobs,
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            crossings: Mutex::new(Vec::new()),
            threads: Mutex::new(HashSet::new()),
            refused_statuses: Mutex::new(Vec::new()),
        }
    }

    /// An identity entry over the host's socket, claiming `scheme`.
    pub fn identity(scheme: &'static str) -> Self {
        Self::new(scheme, &[scheme], &[], Knobs::default())
    }

    /// How many crossings of `op` there were.
    pub fn count(&self, op: &str) -> usize {
        self.crossings
            .lock()
            .unwrap()
            .iter()
            .filter(|o| **o == op)
            .count()
    }
}

fn raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    if ptr.is_null() || len == 0 {
        return &[];
    }
    // SAFETY: host-borrowed input of `len` bytes, valid for the call.
    unsafe { std::slice::from_raw_parts(ptr, len) }
}

fn put(to: *mut u8, from: &mut VecDeque<u8>, n: usize) {
    for i in 0..n {
        let b = from.pop_front().unwrap();
        // SAFETY: `to` is a host buffer the caller bounded `n` by.
        unsafe { to.add(i).write(b) };
    }
}

fn answer(st: &mut State, sink: &FramerSink, o: &mut FramerOut, silence: Option<Duration>) {
    let y = &mut o.yielded;
    let w = st.outbound.len().min(sink.wire_cap);
    put(sink.wire, &mut st.outbound, w);
    y.wire_len = w as u64;
    if !st.inbound.is_empty() && sink.pieces_cap > 0 {
        let n = st.inbound.len().min(sink.frame_cap);
        put(sink.frame, &mut st.inbound, n);
        let flags = if st.inbound.is_empty() {
            PIECE_END_OF_FRAME
        } else {
            0
        } | if st.text && n > 0 { PIECE_TEXT } else { 0 };
        // SAFETY: a host buffer of at least one piece.
        unsafe {
            sink.pieces.write(FramePiece {
                stream: 0,
                offset: 0,
                len: n as u64,
                code: 0,
                status_class: 0,
                flags,
                _reserved: 0,
                retry_after_secs: 0,
            });
        }
        y.frame_len = n as u64;
        y.pieces_len = 1;
    }
    let mut flags = 0;
    if !st.outbound.is_empty() || !st.inbound.is_empty() {
        flags |= YIELD_MORE;
    } else if st.ended {
        flags |= YIELD_ENDED;
    }
    if let (Some(d), false) = (silence, st.heard) {
        if st.deadline_ns == 0 {
            st.deadline_ns = sink.now_monotonic_ns + d.as_nanos() as u64;
        }
        flags |= YIELD_HAS_DEADLINE;
        y.next_deadline_ns = st.deadline_ns;
    }
    y.flags = flags;
}

impl FramerDoor for TestDoor {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        self.threads
            .lock()
            .unwrap()
            .insert(std::thread::current().id());
        let ok = Crossed {
            outcome: Outcome::Ready,
            error: None,
        };
        let failed = |why: &str| Crossed {
            outcome: Outcome::Failed,
            error: Some(why.as_bytes().to_vec()),
        };
        let silence = self.knobs.silence;
        let mut framings = self.framings.lock().unwrap();
        let (op, answered) = match call {
            Call::Locate(i, o) => {
                let target = raw(i.target.ptr, i.target.len);
                let authority = self.knobs.authority.map_or(target, str::as_bytes);
                // SAFETY: host buffer of `authority_cap` bytes; the test's authorities fit.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        authority.as_ptr(),
                        i.authority_buf,
                        authority.len().min(i.authority_cap),
                    );
                }
                o.authority_written = authority.len() as u64;
                if let Some(name) = self.knobs.secure_name {
                    o.secure = 1;
                    o.has_name = 1;
                    // SAFETY: as above.
                    unsafe {
                        std::ptr::copy_nonoverlapping(name.as_ptr(), i.name_buf, name.len());
                    }
                    o.name_written = name.len() as u64;
                }
                ("locate", ok)
            }
            Call::Begin(i, o) => {
                let token = self.next.fetch_add(1, Ordering::Relaxed);
                let mut st = State {
                    text: self.knobs.text,
                    ..State::default()
                };
                answer(&mut st, &i.sink, o, silence);
                if self.knobs.head {
                    let bytes = b"GET/v1";
                    // SAFETY: host buffers; the frame holds at least these bytes, and a head is
                    // written only where the host gave room for one.
                    unsafe {
                        std::ptr::copy_nonoverlapping(bytes.as_ptr(), i.sink.frame, bytes.len());
                        if i.sink.heads_cap > 0 {
                            i.sink.heads.write(HeadSlots {
                                stream: 1,
                                method: FrameSpan { offset: 0, len: 3 },
                                target: FrameSpan { offset: 3, len: 3 },
                                ..HeadSlots::default()
                            });
                        }
                    }
                    o.yielded.frame_len = bytes.len() as u64;
                    o.yielded.heads_len = 1;
                }
                framings.insert(token, st);
                o.framing = token;
                ("begin", ok)
            }
            Call::Adopt(i, o) => {
                let token = self.next.fetch_add(1, Ordering::Relaxed);
                let mut st = State::default();
                st.inbound.extend(raw(i.leftover, i.leftover_len));
                answer(&mut st, &i.sink, o, silence);
                framings.insert(token, st);
                o.framing = token;
                ("adopt", ok)
            }
            Call::Ingest(i, o) => match framings.get_mut(&i.framing) {
                None => ("ingest", failed("no such framing")),
                Some(st) => {
                    let bytes = raw(i.bytes, i.len);
                    st.heard |= !bytes.is_empty();
                    st.inbound.extend(bytes);
                    st.ended |= i.end != 0;
                    answer(st, &i.sink, o, silence);
                    ("ingest", ok)
                }
            },
            Call::Emit(i, o) => match framings.get_mut(&i.framing) {
                None => ("emit", failed("no such framing")),
                Some(st) => {
                    st.outbound.extend(raw(i.bytes, i.len));
                    answer(st, &i.sink, o, silence);
                    // A text emit is counted as its own op, so a test sees the bit cross.
                    let op = if i.flags & EMIT_TEXT != 0 {
                        "emit text"
                    } else {
                        "emit"
                    };
                    (op, ok)
                }
            },
            Call::Refuse(i, o) => match framings.get_mut(&i.framing) {
                None => ("refuse", failed("no such framing")),
                Some(st) => {
                    self.refused_statuses.lock().unwrap().push(i.status);
                    st.outbound.extend(raw(i.bytes, i.len));
                    answer(st, &i.sink, o, silence);
                    ("refuse", ok)
                }
            },
            Call::Timer(i, o) => match framings.get_mut(&i.framing) {
                None => ("timer", failed("no such framing")),
                Some(st) if !st.heard && st.deadline_ns != 0 => {
                    let _ = (i, o);
                    (
                        "timer",
                        failed("the far end said nothing before its deadline"),
                    )
                }
                Some(st) => {
                    answer(st, &i.sink, o, silence);
                    ("timer", ok)
                }
            },
            Call::Encode(i, o) => {
                let body = raw(i.body, i.body_len);
                // SAFETY: `encode` is given room for the body.
                unsafe {
                    std::ptr::copy_nonoverlapping(body.as_ptr(), i.sink.wire, body.len());
                }
                o.yielded.wire_len = body.len() as u64;
                ("encode", ok)
            }
            Call::Finish(i, o) => {
                framings.remove(&i.framing);
                o.yielded.flags = YIELD_ENDED;
                ("finish", ok)
            }
            Call::Detach(i, o) => match framings.remove(&i.framing) {
                None => ("detach", failed("no such framing")),
                Some(mut st) => {
                    let n = st.inbound.len().min(i.sink.frame_cap);
                    put(i.sink.frame, &mut st.inbound, n);
                    o.yielded.frame_len = n as u64;
                    ("detach", ok)
                }
            },
        };
        self.crossings.lock().unwrap().push(op);
        answered
    }
}

/// The threads this process runs now.
pub fn thread_count() -> usize {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc/self/task")
            .map(Iterator::count)
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let out = std::process::Command::new("ps")
            .args(["-M", "-p", &std::process::id().to_string()])
            .output()
            .expect("ps runs");
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .count()
            .saturating_sub(1)
    }
}

/// A current-thread runtime, as a worker runs: its reactor and its clock, and no other thread.
pub fn worker() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
