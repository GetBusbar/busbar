// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A TEST TRANSPORT ENTRY, in Rust behind the [`FramerDoor`] seam: an identity framer (the bytes are

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Poll, Wake, Waker};
use std::thread::ThreadId;
use std::time::Duration;

use busbar_contract::abi::host::io::DIR_WRITE;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::transport::{FramePiece, FrameSpan, FramerOut, FramerSink, HeadSlots};
use busbar_contract::io_host::{IoHost, IoRefusal, Spawn};
use busbar_contract::transport::codes::{
    DEST_PROGRAM, DEST_RETIRED, EMIT_TEXT, PIECE_END, PIECE_END_OF_FRAME, PIECE_FIELDS,
    PIECE_HAS_CODE, PIECE_HAS_DECLARED_LEN, PIECE_INTERIM, PIECE_TEXT, PIECE_WRITABLE,
    READ_END_OF_FRAME, YIELD_ENDED, YIELD_HAS_DEADLINE, YIELD_MORE, YIELD_STREAM_FULL,
};
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
    /// Locate the authority of a URL-shaped target through the shared contract reader.
    pub locate_authority: bool,
    /// `begin` yields one request head, `GET /v1` on stream `1`, as an accepted framing does.
    pub head: bool,
    /// Every frame the framing yields is a text message (`PIECE_TEXT`), as ws states one.
    pub text: bool,
    /// `locate` answers this protocol offer (ProtocolNameList bytes).
    pub offer: Option<&'static [u8]>,
    /// `locate` asked for the ACCEPTING side (`LocateIn::accept`) answers this offer instead.
    pub accept_offer: Option<&'static [u8]>,
    /// The far end's bytes are SCRIPTED messages on this stream, one piece per byte: `b` an empty
    /// binary message, `t` an empty text message, `e` the stream's end (`PIECE_END`), any other
    /// byte a one-byte binary message; `i` an interim head (an empty field block stating code
    /// `103`, `PIECE_INTERIM`), `h` a final head (an empty field block stating `200`).
    pub messages: Option<u64>,
    /// Script replies on the latest emitted exchange, for sequential pooled requests.
    pub messages_follow_emit: bool,
    /// Every frame piece the framing yields holds at most this many bytes, so one frame arrives
    /// in several pieces (the last ends it), as a line framer cuts a line its sink cannot hold.
    pub piece: Option<usize>,
    /// Every frame the framing yields is a field block (`PIECE_FIELDS`), as a framer hands the far
    /// end's head.
    pub fields: bool,
    /// Every field block the framing yields states this declared body length
    /// (`PIECE_HAS_DECLARED_LEN`).
    pub declared_len: Option<u64>,
    /// Every field block the framing yields states this code (`PIECE_HAS_CODE`).
    pub head_code: Option<u32>,
    /// Every field block the framing yields carries these piece flags too.
    pub head_flags: u16,
    /// Every byte the framing ingests is also answered back to the far end (as a framer answers a
    /// ping with a pong, unasked by the caller).
    pub echo: bool,
    /// Every answer the framing gives says it owes more (`YIELD_MORE`), whatever it wrote.
    pub spin: bool,
    /// A STREAM'S OWN BACKPRESSURE: an `emit` that brings the bytes emitted since the stream was
    /// last writable to this many answers `YIELD_STREAM_FULL`; a scripted `w` from the far end
    /// ([`Knobs::messages`]) is a `PIECE_WRITABLE` piece on the scripted stream, and makes it
    /// writable again.
    pub full_at: Option<usize>,
    /// `locate` answers SHORT, needing this many authority bytes, while the host offers fewer;
    /// offered as many, it answers READY with the target as its authority.
    pub authority_needed: Option<u64>,
    /// It states the sealed-values record (`abi::transport::EXT_SEALED_VALUES`).
    pub seals: bool,
    /// `encode` renders its fields (`name: value` CRLF each, then CRLF) before the body.
    pub render_fields: bool,
    /// Render the request target verbatim before fields, for query-custody tests.
    pub render_target: bool,
    /// An accepting `begin` states this agreed protocol (`FramerYield::agreed`, a 1-based position
    /// in the accepting offer).
    pub agreed: Option<u32>,
    /// `locate` states these head lines of its own (`LocateIn::defaults_buf`, `name: value\r\n`
    /// each), which the host adds to a head that does not carry them.
    pub head_lines: Option<&'static [u8]>,
    /// `locate` states the body's length is the host's to state (`LocateOut::states_length`).
    pub states_length: bool,
    /// Every `emit` FAILS with this error: the framer could not render what the host sends.
    pub fail_emit: Option<&'static str>,
    /// Every `ingest` of the far end's bytes FAILS with this error: the framer rejects them.
    pub fail_ingest: Option<&'static str>,
}

#[derive(Default)]
struct State {
    inbound: VecDeque<u8>,
    outbound: VecDeque<u8>,
    ended: bool,
    heard: bool,
    deadline_ns: u64,
    text: bool,
    messages: Option<u64>,
    piece: Option<usize>,
    fields: bool,
    declared_len: Option<u64>,
    head_code: Option<u32>,
    head_flags: u16,
    echo: bool,
    spin: bool,
    full_at: Option<usize>,
    emitted: usize,
}

/// One `begin` crossing's opening head fields, name and value.
pub type OpeningFields = Vec<(Vec<u8>, Vec<u8>)>;

/// The test entry.
pub struct TestDoor {
    pub(crate) facts: DoorFacts,
    pub(crate) io: Option<Arc<super::hostio::HostIo>>,
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
    /// The supervision key every `dial` crossing carried (`DialIn::supervision_key`), in order.
    pub dialled_keys: Mutex<Vec<u64>>,
    /// The supervision keys a [`DEST_RETIRED`] `dial` told it to forget, in order.
    pub retired_keys: Mutex<Vec<u64>>,
    /// The supervision keys whose `dial` it REFUSES, as a carrier's supervisor refuses a member's
    pub held_keys: Mutex<HashSet<u64>>,
    /// The authority capacity every `locate` crossing offered (`LocateIn::authority_cap`), in order.
    pub locate_caps: Mutex<Vec<usize>>,
    /// EVERY BYTE THE FRAMER WAS HANDED: each `begin` and `encode` field value and each `emit`'s
    pub handed: Mutex<Vec<u8>>,
}

impl TestDoor {
    /// An entry named `name`, claiming `claims`, over `composes_over`. Its role is a FRAMER where it
    pub fn new(
        name: &str,
        claims: &[&'static str],
        composes_over: &[&'static str],
        knobs: Knobs,
    ) -> Self {
        let frames = knobs.secure_name.is_some()
            || knobs.offer.is_some()
            || knobs.head
            || knobs.text
            || knobs.fields
            || knobs.silence.is_some()
            || knobs.authority.is_some()
            || knobs.locate_authority
            || knobs.authority_needed.is_some()
            || knobs.messages.is_some()
            || knobs.head_lines.is_some()
            || knobs.states_length
            // Only a framer takes `emit` and `ingest`: a door whose emit or ingest fails is one.
            || knobs.fail_emit.is_some()
            || knobs.fail_ingest.is_some();
        Self {
            facts: DoorFacts {
                dials: true,
                name: name.to_owned(),
                claims: claims.to_vec(),
                role: if composes_over.is_empty() && !frames {
                    busbar_contract::transport::codes::ROLE_CARRIER
                } else {
                    busbar_contract::transport::codes::ROLE_FRAMER
                },
                composes_over: composes_over.to_vec(),
                ported: composes_over.is_empty() && !frames,
                status_rows: Vec::new(),
                status_namespaces: claims.iter().map(|_| Some("test-status".into())).collect(),
                handoff_status: claims.iter().map(|_| Some("test-opening".into())).collect(),
                duplex: Vec::new(),
                datagram: false,
            },
            knobs,
            io: None,
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            crossings: Mutex::new(Vec::new()),
            carried: Mutex::new(Vec::new()),
            sides: Mutex::new(HashMap::new()),
            threads: Mutex::new(HashSet::new()),
            refused_statuses: Mutex::new(Vec::new()),
            begun_fields: Mutex::new(Vec::new()),
            dialled_keys: Mutex::new(Vec::new()),
            retired_keys: Mutex::new(Vec::new()),
            held_keys: Mutex::new(HashSet::new()),
            locate_caps: Mutex::new(Vec::new()),
            handed: Mutex::new(Vec::new()),
        }
    }

    /// An identity entry over the host's socket, claiming `scheme`.
    pub fn identity(scheme: &'static str) -> Self {
        Self::new(scheme, &[scheme], &[], Knobs::default())
    }
}

pub(crate) fn raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
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
    if let Some(stream) = st.messages {
        let mut frame_len = 0;
        let mut n = 0;
        while n < sink.pieces_cap && frame_len < sink.frame_cap {
            let Some(b) = st.inbound.pop_front() else {
                break;
            };
            let mut code = 0;
            let (len, flags) = match b {
                b'i' => {
                    code = 103;
                    (
                        0,
                        PIECE_FIELDS | PIECE_HAS_CODE | PIECE_END_OF_FRAME | PIECE_INTERIM,
                    )
                }
                b'h' => {
                    code = 200;
                    (0, PIECE_FIELDS | PIECE_HAS_CODE | PIECE_END_OF_FRAME)
                }
                b'b' => (0, PIECE_END_OF_FRAME),
                b't' => (0, PIECE_TEXT | PIECE_END_OF_FRAME),
                b'e' => (0, PIECE_END | PIECE_END_OF_FRAME),
                b'w' => {
                    st.emitted = 0;
                    (0, PIECE_WRITABLE)
                }
                other => {
                    // SAFETY: `frame_len < frame_cap`.
                    unsafe { sink.frame.add(frame_len).write(other) };
                    (1, PIECE_END_OF_FRAME)
                }
            };
            // SAFETY: `n < pieces_cap`.
            unsafe {
                sink.pieces.add(n).write(FramePiece {
                    stream,
                    offset: frame_len as u64,
                    len,
                    code,
                    status_class: 0,
                    flags,
                    fault: 0,
                    retry_after_secs: 0,
                    declared_len: 0,
                });
            }
            frame_len += len as usize;
            n += 1;
        }
        y.frame_len = frame_len as u64;
        y.pieces_len = n as u32;
    } else if !st.inbound.is_empty() && sink.pieces_cap > 0 {
        let n = st
            .inbound
            .len()
            .min(sink.frame_cap)
            .min(st.piece.unwrap_or(usize::MAX));
        put(sink.frame, &mut st.inbound, n);
        let flags = if st.inbound.is_empty() {
            PIECE_END_OF_FRAME
        } else {
            0
        } | if st.text && n > 0 { PIECE_TEXT } else { 0 }
            | if st.fields { PIECE_FIELDS } else { 0 }
            | if st.declared_len.is_some() {
                PIECE_HAS_DECLARED_LEN
            } else {
                0
            }
            | if st.fields && st.head_code.is_some() {
                PIECE_HAS_CODE | st.head_flags
            } else {
                0
            };
        // SAFETY: a host buffer of at least one piece.
        unsafe {
            sink.pieces.write(FramePiece {
                stream: 0,
                offset: 0,
                len: n as u64,
                code: if st.fields {
                    st.head_code.unwrap_or(0)
                } else {
                    0
                },
                status_class: 0,
                flags,
                fault: 0,
                retry_after_secs: 0,
                declared_len: st.declared_len.unwrap_or(0),
            });
        }
        y.frame_len = n as u64;
        y.pieces_len = 1;
    }
    let mut flags = 0;
    if st.spin || !st.outbound.is_empty() || !st.inbound.is_empty() {
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
    fn io_owner(&self) -> Option<u64> {
        Some(OWNER)
    }
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn seals_values(&self) -> bool {
        self.knobs.seals
    }

    fn side(&self) -> Option<Box<dyn Side>> {
        if self.facts.role != busbar_contract::transport::codes::ROLE_CARRIER {
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
            Call::Locate(i, o) => 'locate: {
                self.locate_caps.lock().unwrap().push(i.authority_cap);
                let target = raw(i.target.ptr, i.target.len);
                if let Some(needed) = self
                    .knobs
                    .authority_needed
                    .filter(|n| *n > i.authority_cap as u64)
                {
                    o.authority_needed = needed;
                    break 'locate ("locate", failed("short"));
                }
                let located = self.knobs.locate_authority.then(|| {
                    busbar_contract::net::url_authority(
                        std::str::from_utf8(target).expect("the test target is UTF-8"),
                    )
                    .host_port
                    .as_bytes()
                });
                let authority = self
                    .knobs
                    .authority
                    .map(str::as_bytes)
                    .or(located)
                    .unwrap_or(target);
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
                let offer = if i.accept == 1 {
                    self.knobs.accept_offer
                } else {
                    self.knobs.offer
                };
                if let Some(offer) = offer {
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
                if let Some(lines) = self.knobs.head_lines {
                    // SAFETY: host buffer of `defaults_cap` bytes; the test's lines fit.
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            lines.as_ptr(),
                            i.defaults_buf,
                            lines.len().min(i.defaults_cap),
                        );
                    }
                    o.defaults_written = lines.len() as u64;
                }
                o.states_length = u8::from(self.knobs.states_length);
                ("locate", ok)
            }
            Call::Begin(i, o) => {
                let fields = if i.fields.is_null() {
                    &[][..]
                } else {
                    // SAFETY: host-borrowed fields, `fields_len` of them, valid for the call.
                    unsafe { std::slice::from_raw_parts(i.fields, i.fields_len) }
                };
                for f in fields {
                    self.handed
                        .lock()
                        .unwrap()
                        .extend_from_slice(raw(f.value.ptr, f.value.len));
                }
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
                    messages: self.knobs.messages,
                    piece: self.knobs.piece,
                    fields: self.knobs.fields,
                    declared_len: self.knobs.declared_len,
                    head_code: self.knobs.head_code,
                    head_flags: self.knobs.head_flags,
                    echo: self.knobs.echo,
                    spin: self.knobs.spin,
                    full_at: self.knobs.full_at,
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
                if let Some(n) = self
                    .knobs
                    .agreed
                    .filter(|_| i.side != busbar_contract::transport::codes::SIDE_DIAL)
                {
                    o.yielded.agreed = n;
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
                Some(_) if i.len != 0 && self.knobs.fail_ingest.is_some() => {
                    ("ingest", failed(self.knobs.fail_ingest.unwrap_or_default()))
                }
                Some(st) => {
                    let bytes = raw(i.bytes, i.len);
                    st.heard |= !bytes.is_empty();
                    st.inbound.extend(bytes);
                    if st.echo {
                        st.outbound.extend(bytes);
                    }
                    st.ended |= i.end != 0;
                    answer(st, &i.sink, o, silence);
                    ("ingest", ok)
                }
            },
            Call::Emit(i, o) => match framings.get_mut(&i.framing) {
                None => ("emit", failed("no such framing")),
                Some(_) if self.knobs.fail_emit.is_some() => {
                    ("emit", failed(self.knobs.fail_emit.unwrap_or_default()))
                }
                Some(st) => {
                    if self.knobs.messages_follow_emit && st.messages.is_some() {
                        st.messages = Some(i.stream);
                    }
                    self.handed
                        .lock()
                        .unwrap()
                        .extend_from_slice(raw(i.bytes, i.len));
                    st.outbound.extend(raw(i.bytes, i.len));
                    st.emitted += i.len;
                    answer(st, &i.sink, o, silence);
                    if st.full_at.is_some_and(|n| st.emitted >= n) {
                        o.yielded.flags |= YIELD_STREAM_FULL;
                    }

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
                let mut message = Vec::new();
                if self.knobs.render_target {
                    let target = raw(i.target.ptr, i.target.len);
                    self.handed.lock().unwrap().extend_from_slice(target);
                    message.extend_from_slice(target);
                    message.extend_from_slice(b"\r\n");
                }
                if self.knobs.render_fields && !i.fields.is_null() {
                    // SAFETY: host-borrowed fields, `fields_len` of them, valid for the call.
                    for f in unsafe { std::slice::from_raw_parts(i.fields, i.fields_len) } {
                        let value = raw(f.value.ptr, f.value.len);
                        self.handed.lock().unwrap().extend_from_slice(value);
                        message.extend_from_slice(raw(f.name.ptr, f.name.len));
                        message.extend_from_slice(b": ");
                        message.extend_from_slice(value);
                        message.extend_from_slice(b"\r\n");
                    }
                    message.extend_from_slice(b"\r\n");
                }
                message.extend_from_slice(raw(i.body, i.body_len));
                let body = &message[..];
                // SAFETY: `encode` is given room for the body and every field.
                unsafe {
                    std::ptr::copy_nonoverlapping(body.as_ptr(), i.sink.wire, body.len());
                }
                o.yielded.wire_len = body.len() as u64;
                if self.knobs.spin {
                    o.yielded.flags = YIELD_MORE;
                }
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
            error: Some(t.as_bytes().to_vec()),
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
    fn carry_io(&self, side: &dyn Side, call: Carry<'_>) -> Crossed {
        let io = self.io.clone().unwrap_or_else(super::hostio::process);
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
                        let mut bytes: VecDeque<u8> = addr.bytes().collect();
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
                        let mut bytes: VecDeque<u8> = peer.bytes().collect();
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
                if d.kind == DEST_RETIRED {
                    self.retired_keys.lock().unwrap().push(i.supervision_key);
                    self.carried.lock().unwrap().push("dial");
                    return io_crossed(Ok(()), |()| o.conn = 0);
                }
                self.dialled_keys.lock().unwrap().push(i.supervision_key);
                let held = self.held_keys.lock().unwrap().contains(&i.supervision_key);
                let r = if held {
                    Err(IoRefusal::Refused(
                        "held down by the carrier's supervisor".into(),
                    ))
                } else if d.kind == DEST_PROGRAM {
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
