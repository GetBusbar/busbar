// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST TRANSPORT ENTRY, in Rust behind the [`FramerDoor`] seam: an identity framer (the bytes are
//! the frames, one frame per ingest on stream `0`) with knobs a test turns — a target that asks for
//! connection security, a silence deadline, a `locate` that names another authority — and, stated a
//! CARRIER, a carrier over the process's host I/O (`crate::hostio`, called as a carrier calls
//! `io.*`); a record of every crossing and the thread it ran on. The one place in this crate that
//! writes a host sink through its raw pointers, as a plugin does.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Wake, Waker};
use std::thread::ThreadId;
use std::time::Duration;

use busbar_contract::abi::host::io::DIR_WRITE;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::{
    FramePiece, FrameSpan, FramerOut, FramerSink, HeadSlots, DEST_PROGRAM, EMIT_TEXT,
    PIECE_END_OF_FRAME, PIECE_TEXT, READ_END_OF_FRAME, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE,
};
use busbar_contract::io_host::{IoHost, IoRefusal, Spawn};
use futures::task::AtomicWaker;

use super::carrier::{Carry, Side};
use super::compose::Via;
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
    /// `locate` answers this protocol offer (ProtocolNameList bytes).
    pub offer: Option<&'static [u8]>,
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

/// One `begin` crossing's opening head fields, name and value.
pub type OpeningFields = Vec<(Vec<u8>, Vec<u8>)>;

/// The test entry.
pub struct TestDoor {
    facts: DoorFacts,
    knobs: Knobs,
    framings: Mutex<HashMap<u64, State>>,
    next: AtomicU64,
    /// Every crossing, by op.
    pub crossings: Mutex<Vec<&'static str>>,
    /// Every CARRIER crossing, by op.
    pub carried: Mutex<Vec<&'static str>>,
    /// The sides of its carried connections, by their ticket's slot.
    sides: Mutex<HashMap<u32, Arc<TestSide>>>,
    /// Every thread a crossing ran on.
    pub threads: Mutex<HashSet<ThreadId>>,
    /// The neutral status every `refuse` crossing carried, in order.
    pub refused_statuses: Mutex<Vec<u32>>,
    /// The opening head fields every `begin` crossing carried (`BeginIn::fields`), in order.
    pub begun_fields: Mutex<Vec<OpeningFields>>,
    /// The target every `begin` crossing was handed (`BeginIn::target`), in order.
    pub begun_targets: Mutex<Vec<Vec<u8>>>,
}

impl TestDoor {
    /// An entry named `name`, claiming `claims`, over `composes_over`. Its role is a FRAMER where it
    /// names a layer (the shape these fixtures used for "framed" before the role was stated) and a
    /// CARRIER otherwise; [`TestDoor::with_role`] states it outright.
    pub fn new(
        name: &str,
        claims: &[&'static str],
        composes_over: &[&'static str],
        knobs: Knobs,
    ) -> Self {
        // A knob only a framer answers (a secure target, a protocol offer, a head, text frames, a
        // silence deadline, another authority) states the entry a FRAMER: a carrier frames nothing.
        let frames = knobs.secure_name.is_some()
            || knobs.offer.is_some()
            || knobs.head
            || knobs.text
            || knobs.silence.is_some()
            || knobs.authority.is_some();
        Self {
            facts: DoorFacts {
                name: name.to_owned(),
                claims: claims.to_vec(),
                role: if composes_over.is_empty() && !frames {
                    busbar_contract::abi::transport::ROLE_CARRIER
                } else {
                    busbar_contract::abi::transport::ROLE_FRAMER
                },
                composes_over: composes_over.to_vec(),
                ported: composes_over.is_empty() && !frames,
                status_rows: Vec::new(),
                duplex: Vec::new(),
            },
            knobs,
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            crossings: Mutex::new(Vec::new()),
            carried: Mutex::new(Vec::new()),
            sides: Mutex::new(HashMap::new()),
            threads: Mutex::new(HashSet::new()),
            refused_statuses: Mutex::new(Vec::new()),
            begun_fields: Mutex::new(Vec::new()),
            begun_targets: Mutex::new(Vec::new()),
        }
    }

    /// The same entry, stating `role` (`ROLE_CARRIER` | `ROLE_FRAMER`).
    #[must_use]
    pub fn with_role(mut self, role: u32) -> Self {
        self.facts.role = role;
        self.facts.ported = role == busbar_contract::abi::transport::ROLE_CARRIER;
        self
    }

    /// The same entry, its claim serving no port (a carrier reached by a path or a program).
    #[must_use]
    pub fn unported(mut self) -> Self {
        self.facts.ported = false;
        self
    }

    /// The same entry, its claim reading a port whatever its role (a framer stating one is still no
    /// carrier).
    #[must_use]
    pub fn with_port(mut self) -> Self {
        self.facts.ported = true;
        self
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

    fn side(&self) -> Option<Box<dyn Side>> {
        if self.facts.role != busbar_contract::abi::transport::ROLE_CARRIER {
            return None;
        }
        let side = Arc::new(TestSide {
            ticket: TICKETS.fetch_add(1, Ordering::Relaxed),
            waker: AtomicWaker::new(),
        });
        self.sides
            .lock()
            .unwrap()
            .insert(side.ticket, Arc::clone(&side));
        Some(Box::new(Held(side)))
    }

    fn carry(&self, side: &dyn Side, _resume: bool, call: Carry<'_>) -> Crossed {
        self.carry_io(side, call)
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
                if let Some(offer) = self.knobs.offer {
                    // SAFETY: host buffer of `alpn_cap` bytes; the test's offers fit.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            offer.as_ptr(),
                            i.alpn_buf,
                            offer.len().min(i.alpn_cap),
                        );
                    }
                    o.alpn_written = offer.len() as u64;
                }
                ("locate", ok)
            }
            Call::Begin(i, o) => {
                self.begun_targets
                    .lock()
                    .unwrap()
                    .push(raw(i.target.ptr, i.target.len).to_vec());
                let fields = if i.fields.is_null() {
                    &[][..]
                } else {
                    // SAFETY: host-borrowed fields, `fields_len` of them, valid for the call.
                    unsafe { std::slice::from_raw_parts(i.fields, i.fields_len) }
                };
                self.begun_fields.lock().unwrap().push(
                    fields
                        .iter()
                        .map(|f| {
                            (
                                raw(f.name.ptr, f.name.len).to_vec(),
                                raw(f.value.ptr, f.value.len).to_vec(),
                            )
                        })
                        .collect(),
                );
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

/// The owner every test carrier's host I/O calls are made under.
pub const OWNER: u64 = 0x7e57;

/// A side of a test carrier's connection: a ticket and the task its pending op wakes.
#[derive(Default)]
pub struct TestSide {
    ticket: u32,
    waker: AtomicWaker,
}

impl Wake for TestSide {
    fn wake(self: Arc<Self>) {
        self.waker.wake();
    }
}

/// A side as the connector holds it.
struct Held(Arc<TestSide>);

impl Side for Held {
    fn ticket(&self) -> Ticket {
        Ticket {
            slot: self.0.ticket,
            generation: 1,
        }
    }
    fn register(&self, waker: &Waker) {
        self.0.waker.register(waker);
    }
}

static TICKETS: AtomicU32 = AtomicU32::new(1);

/// A host answer as a carrier's crossing reads it.
fn io_crossed<T>(r: Result<T, IoRefusal>, ok: impl FnOnce(T)) -> Crossed {
    match r {
        Ok(v) => {
            ok(v);
            Crossed {
                outcome: Outcome::Ready,
                error: None,
            }
        }
        Err(IoRefusal::Refused(t)) => Crossed {
            outcome: Outcome::Refused,
            error: Some(t.into_bytes()),
        },
        Err(IoRefusal::Failed(t)) => Crossed {
            outcome: Outcome::Failed,
            error: Some(t.into_bytes()),
        },
    }
}

fn polled<T>(p: Poll<Result<T, IoRefusal>>, ok: impl FnOnce(T)) -> Crossed {
    match p {
        Poll::Pending => Crossed {
            outcome: Outcome::Pending,
            error: None,
        },
        Poll::Ready(r) => io_crossed(r, ok),
    }
}

fn text_of(s: busbar_contract::abi::mechanism::call::AbiStr) -> String {
    String::from_utf8_lossy(raw(s.ptr, s.len)).into_owned()
}

impl TestDoor {
    /// The carrier ops: a byte-stream carrier over the process's host I/O, each connection named by
    /// the host's own handle.
    fn carry_io(&self, side: &dyn Side, call: Carry<'_>) -> Crossed {
        let io = super::hostio::process();
        let t = side.ticket();
        self.threads
            .lock()
            .unwrap()
            .insert(std::thread::current().id());
        let (op, c) = match call {
            Carry::Listen(i, o) => {
                let bind = text_of(i.bind);
                (
                    "listen",
                    io_crossed(io.listen(OWNER, t, &bind), |(h, addr)| {
                        let mut bytes: VecDeque<u8> = addr.into_bytes().into();
                        let n = bytes.len().min(i.addr_cap);
                        put(i.addr_buf, &mut bytes, n);
                        o.addr_written = n as u64;
                        o.listener = h;
                    }),
                )
            }
            Carry::Accept(i, o) => (
                "accept",
                polled(
                    io.accept(OWNER, t, i.listener, &self.waker_of(side)),
                    |(h, peer)| {
                        let mut bytes: VecDeque<u8> = peer.into_bytes().into();
                        let n = bytes.len().min(i.peer_cap);
                        put(i.peer_buf, &mut bytes, n);
                        o.peer_written = n as u64;
                        o.conn = h;
                    },
                ),
            ),
            Carry::Dial(i, o) => {
                // SAFETY: the connector's destination, live for the call.
                let d = unsafe { &*i.dest };
                let r = if d.kind == DEST_PROGRAM {
                    let program = text_of(d.program);
                    let args: Vec<String> = (0..d.args_len)
                        // SAFETY: `args_len` strings at `args`.
                        .map(|k| text_of(unsafe { *d.args.add(k) }))
                        .collect();
                    let env: Vec<(String, String)> = (0..d.env_len)
                        .map(|k| {
                            // SAFETY: `env_len` fields at `env`.
                            let f = unsafe { *d.env.add(k) };
                            (text_of(f.name), text_of(f.value))
                        })
                        .collect();
                    let args: Vec<&str> = args.iter().map(String::as_str).collect();
                    let env: Vec<(&str, &str)> =
                        env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                    io.spawn(
                        OWNER,
                        t,
                        &Spawn {
                            program: &program,
                            args: &args,
                            env: &env,
                        },
                    )
                } else {
                    io.open(OWNER, t, &text_of(d.authority))
                };
                ("dial", io_crossed(r, |h| o.conn = h))
            }
            Carry::Read(i, o) => {
                // SAFETY: the host's buffer of `cap` bytes.
                let buf = unsafe { std::slice::from_raw_parts_mut(i.buf, i.cap) };
                (
                    "read",
                    polled(io.read(OWNER, i.conn, buf, &self.waker_of(side)), |n| {
                        o.len = n as u64;
                        if n > 0 {
                            o.flags = READ_END_OF_FRAME;
                        }
                    }),
                )
            }
            Carry::Write(i, o) => (
                "write",
                polled(
                    io.write(OWNER, i.conn, raw(i.bytes, i.len), &self.waker_of(side)),
                    |n| o.len = n as u64,
                ),
            ),
            Carry::Flush(i, _) => (
                "flush",
                polled(
                    io.ready(OWNER, i.conn, DIR_WRITE, &self.waker_of(side)),
                    |()| {},
                ),
            ),
            Carry::Shut(i, _) => {
                let _ = io.close(OWNER, i.conn);
                ("shut", io_crossed(Ok(()), |()| {}))
            }
            Carry::Arrival(i, o) => (
                "arrival",
                io_crossed(io.ends(OWNER, i.conn), |(port, peer)| {
                    let mut bytes: VecDeque<u8> = peer.into_bytes().into();
                    let n = bytes.len().min(i.peer_cap);
                    put(i.peer_buf, &mut bytes, n);
                    o.peer_written = n as u64;
                    o.local_port = u32::from(port);
                }),
            ),
            Carry::Cancel(_, _) => ("cancel", io_crossed(Ok(()), |()| {})),
        };
        self.carried.lock().unwrap().push(op);
        c
    }

    /// A waker that wakes whatever task `side` registered.
    fn waker_of(&self, side: &dyn Side) -> Waker {
        let slot = side.ticket().slot;
        self.sides
            .lock()
            .unwrap()
            .get(&slot)
            .map(|s| Waker::from(Arc::clone(s)))
            .unwrap_or_else(|| Waker::noop().clone())
    }
}

/// THE TEST CARRIER every test dial rides: a test entry stated a carrier, over the process's host I/O.
pub fn via() -> Via {
    static CARRIER: std::sync::OnceLock<Arc<dyn FramerDoor>> = std::sync::OnceLock::new();
    let door = Arc::clone(CARRIER.get_or_init(|| Arc::new(TestDoor::identity("test-carrier"))));
    Via {
        door,
        io: super::hostio::process(),
    }
}
