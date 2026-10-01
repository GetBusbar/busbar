// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST HOST the `grpc` door's integration tests share, and the tonic peer they talk to.
//!
//! The host is what the connector is in production. It holds the socket (bridged from a tokio
//! runtime of its own: an in-memory duplex, a TCP stream, or TLS over one), the clock (a virtual
//! monotonic clock moved by hand), and the sink buffers. It calls the framer only through the
//! transport kind's table, from the test's own thread and outside any runtime.
//!
//! The peer is tonic: `TestSvc` routes four methods of service `t.T` through
//! `tonic::server::Grpc` with a byte-blind codec. The test serves it with tonic's own server, or with
//! hyper's HTTP/2 server over TLS. On the accepted side, tonic's `Channel` is the client.

#![allow(dead_code, unsafe_code, missing_docs)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::ffi::c_void;
use std::future::Future;
use std::mem::{size_of, zeroed};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, Op, OutHead, Outcome, BLOB_JSON,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::DOOR_SYMBOL;
use busbar_contract::abi::transport::check::{
    check_framer, check_framer_fields, check_head_slots, check_locate,
};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, EncodeIn, FramePiece, FrameSpan, FramerOut, FramerSink,
    FramingIn, HeadSlots, IngestIn, LocateIn, LocateOut, Ops, RefuseIn, PIECE_END_OF_FRAME,
    PIECE_FIELDS, PIECE_HAS_CODE, PIECE_STREAM_FAILED, YIELD_HAS_DEADLINE, YIELD_MORE,
};
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::{Request, Response, Status};

pub const SEC: u64 = 1_000_000_000;

/// The sink's capacities: wire bytes, frame bytes, pieces.
#[derive(Clone, Copy)]
pub struct Caps(pub usize, pub usize, pub usize);
pub const ROOMY: Caps = Caps(64 * 1024, 64 * 1024, 64);
/// Small enough that every answer overflows, so every op is re-called with `YIELD_MORE`.
pub const TIGHT: Caps = Caps(7, 5, 1);

pub fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

pub fn s(text: &str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

pub fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime")
}

// ── the door, linked and dropped in ──────────────────────────────────────────────────────────────

pub fn linked() -> &'static Ops {
    let d = busbar_transport_grpc::door::door();
    // SAFETY: the door's `'static` table.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

pub fn dropped() -> (&'static Ops, &'static libloading::Library) {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = format!(
        "{}grpc_door{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = [
        profile.join("examples").join(&file),
        profile.join("examples").join("deps").join(&file),
    ]
    .into_iter()
    .find(|p| p.exists())
    .unwrap_or_else(|| panic!("the dropped-in image ({file}) is not built"));
    // SAFETY: our own example, built by this `cargo test`.
    let lib: &'static libloading::Library = Box::leak(Box::new(
        unsafe { libloading::Library::new(path) }.expect("load"),
    ));
    // SAFETY: the one exported symbol, a `DoorFn`.
    let door: libloading::Symbol<'_, extern "C" fn() -> *const Door> =
        unsafe { lib.get(DOOR_SYMBOL) }.expect("the door symbol");
    let d = door();
    // SAFETY: the dropped-in door's `'static` table.
    (unsafe { &*(*d).ops.cast::<Ops>() }, lib)
}

// ── the socket ───────────────────────────────────────────────────────────────────────────────────

/// The socket the host holds: what the far end wrote and the host has not ingested (and whether
/// it has ended), and the way to the far end.
pub struct Socket {
    rx: Mutex<(VecDeque<u8>, bool)>,
    to_far: mpsc::UnboundedSender<Vec<u8>>,
}

/// Bridge `io` (running on `rt`) to a [`Socket`] the host's thread reads and writes.
pub fn bridge<IO>(rt: &tokio::runtime::Runtime, io: IO) -> Arc<Socket>
where
    IO: AsyncRead + AsyncWrite + Send + 'static,
{
    let (to_tx, mut to_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let sock = Arc::new(Socket {
        rx: Mutex::new((VecDeque::new(), false)),
        to_far: to_tx,
    });
    let (mut rd, mut wr) = tokio::io::split(io);
    let s2 = sock.clone();
    rt.spawn(async move {
        let mut buf = vec![0_u8; 16384];
        loop {
            let n = rd.read(&mut buf).await.unwrap_or(0);
            let mut g = s2.rx.lock().expect("rx");
            g.0.extend(&buf[..n]);
            g.1 |= n == 0;
            if n == 0 {
                break;
            }
        }
    });
    rt.spawn(async move {
        while let Some(b) = to_rx.recv().await {
            if wr.write_all(&b).await.is_err() {
                break;
            }
        }
    });
    sock
}

// ── the host ─────────────────────────────────────────────────────────────────────────────────────

/// One frame piece as the host read it out of its sink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Got {
    pub stream: u64,
    pub bytes: Vec<u8>,
    pub flags: u16,
    pub code: u32,
    pub class: u8,
}

impl Got {
    /// The piece states the stream's status: the trailers, or a failure no trailers came with.
    pub fn coded(&self) -> bool {
        self.flags & PIECE_HAS_CODE != 0
    }
    pub fn failed(&self) -> bool {
        self.flags & PIECE_STREAM_FAILED != 0
    }
    /// A field block: the head, or the trailers.
    pub fn fields(&self) -> bool {
        self.flags & PIECE_FIELDS != 0
    }
}

/// Stream `stream`'s end, once it arrived: the status (code and class, from the trailers or a
/// failure), and the terminal piece after it (whether the stream failed, and its whole bytes:
/// empty on `OK`, else the decoded `grpc-message`).
pub fn over(got: &[Got], stream: u64) -> Option<(u32, u8, bool, Vec<u8>)> {
    let mut status = None;
    let mut bytes = Vec::new();
    for g in got.iter().filter(|g| g.stream == stream) {
        if g.coded() {
            status = Some((g.code, g.class));
        }
        if let Some((code, class)) = status {
            if !g.fields() {
                bytes.extend_from_slice(&g.bytes);
                if g.flags & PIECE_END_OF_FRAME != 0 {
                    return Some((code, class, g.failed(), bytes));
                }
            }
        }
    }
    None
}

pub struct Host {
    pub ops: &'static Ops,
    inst: *mut c_void,
    pub now: u64,
    pub framing: u64,
    pub sock: Option<Arc<Socket>>,
    pub wire_log: Vec<u8>,
    pub frame_log: Vec<u8>,
    pub got: Vec<Got>,
    deadline: Option<u64>,
    more: bool,
    caps: Caps,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
    heads: Vec<HeadSlots>,
    /// Each accepted stream's head words: (stream, method, target, authority).
    pub words: Vec<(u64, String, String, String)>,
    // Kept alive while the framer may read it.
    facts_text: String,
}

pub fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
    // SAFETY: `I` leads with an `InHead`, `O` with an `OutHead` (the table's own structs).
    unsafe {
        let ih = std::ptr::from_mut(i).cast::<InHead>();
        (*ih).size = size_of::<I>() as u32;
        (*ih).op = index;
        let oh = std::ptr::from_mut(o).cast::<OutHead>();
        (*oh).size = size_of::<O>() as u32;
    }
    let raw = (op.expect("every slot is filled"))(
        inst,
        std::ptr::from_ref(i).cast(),
        std::ptr::from_mut(o).cast(),
    );
    raw.outcome()
}

/// What `locate` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    pub authority: String,
    pub name: String,
    pub secure: bool,
    pub offer: Vec<u8>,
}

impl Host {
    pub fn open(ops: &'static Ops, settings: &'static str, caps: Caps) -> Self {
        let mut i: OpenIn = z();
        i.settings = Blob {
            ptr: settings.as_ptr(),
            len: settings.len(),
            fmt: BLOB_JSON,
            flags: 0,
        };
        let mut o: OpenOut = z();
        assert_eq!(
            call(
                ops.head.open,
                std::ptr::null_mut(),
                &mut i,
                &mut o,
                life::OPEN
            ),
            Outcome::Ready
        );
        Self {
            ops,
            inst: o.instance,
            now: 7 * SEC,
            framing: 0,
            sock: None,
            wire_log: Vec::new(),
            frame_log: Vec::new(),
            got: Vec::new(),
            deadline: None,
            more: false,
            caps,
            wire: vec![0; caps.0.max(4096)],
            frame: vec![0; caps.1],
            pieces: vec![z(); caps.2],
            heads: vec![HeadSlots::default(); 4],
            words: Vec::new(),
            facts_text: String::new(),
        }
    }

    fn sink(&mut self) -> FramerSink {
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.caps.0,
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.caps.1,
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.caps.2,
            now_monotonic_ns: self.now,
            now_unix_ns: 1_790_000_000 * SEC + self.now,
            heads: self.heads.as_mut_ptr(),
            heads_cap: self.heads.len(),
        }
    }

    /// `locate` `target`, judged by the kind's own check.
    pub fn locate(&mut self, target: &str) -> Result<Located, Outcome> {
        let (mut a, mut n, mut p) = (vec![0_u8; 256], vec![0_u8; 256], vec![0_u8; 64]);
        let mut i: LocateIn = z();
        i.target = s(target);
        (i.authority_buf, i.authority_cap) = (a.as_mut_ptr(), a.len());
        (i.name_buf, i.name_cap) = (n.as_mut_ptr(), n.len());
        (i.alpn_buf, i.alpn_cap) = (p.as_mut_ptr(), p.len());
        let mut o: LocateOut = z();
        let r = call(self.ops.locate, self.inst, &mut i, &mut o, slot::LOCATE);
        let offer = p[..o.alpn_written as usize].to_vec();
        check_locate(r, &o, 256, 256, 64, &offer).expect("locate passes the kind's check");
        if r != Outcome::Ready {
            return Err(r);
        }
        Ok(Located {
            authority: String::from_utf8_lossy(&a[..o.authority_written as usize]).into_owned(),
            name: String::from_utf8_lossy(&n[..o.name_written as usize]).into_owned(),
            secure: o.secure != 0,
            offer,
        })
    }

    /// Take an op's answer: judge it by the kind's own check, send its wire bytes, keep its pieces.
    fn take(&mut self, outcome: Outcome, o: &FramerOut) -> Outcome {
        let n = o.yielded.pieces_len as usize;
        check_framer(
            outcome,
            o,
            &self.pieces[..n],
            self.caps.0 as u64,
            self.caps.1 as u64,
            self.caps.2 as u64,
        )
        .expect("the answer passes the kind's check");
        if outcome != Outcome::Ready {
            return outcome;
        }
        let frame = &self.frame[..o.yielded.frame_len as usize];
        check_framer_fields(&self.pieces[..n], frame).expect("no pseudo-field in a field block");
        check_head_slots(o, &self.heads, self.heads.len() as u64).expect("the head slots pass");
        let text = |s: FrameSpan| {
            String::from_utf8_lossy(&frame[s.offset as usize..(s.offset + s.len) as usize])
                .into_owned()
        };
        for h in &self.heads[..o.yielded.heads_len as usize] {
            self.words.push((
                h.stream,
                text(h.method),
                text(h.target),
                text(h.authority),
            ));
        }
        let w = self.wire[..o.yielded.wire_len as usize].to_vec();
        if !w.is_empty() {
            self.wire_log.extend_from_slice(&w);
            if let Some(sock) = &self.sock {
                let _ = sock.to_far.send(w);
            }
        }
        for p in &self.pieces[..n] {
            let bytes = self.frame[p.offset as usize..(p.offset + p.len) as usize].to_vec();
            self.frame_log.extend_from_slice(&bytes);
            self.got.push(Got {
                stream: p.stream,
                bytes,
                flags: p.flags,
                code: p.code,
                class: p.status_class,
            });
        }
        self.deadline =
            (o.yielded.flags & YIELD_HAS_DEADLINE != 0).then_some(o.yielded.next_deadline_ns);
        self.more = o.yielded.flags & YIELD_MORE != 0;
        outcome
    }

    /// Re-call a framing op that answered `YIELD_MORE`, with NO new bytes, until it stops.
    fn drain(&mut self, index: u32, stream: u64) -> Outcome {
        let mut calls = 0_u32;
        while self.more {
            calls += 1;
            assert!(calls < 100_000, "a YIELD_MORE re-call never ran dry");
            let mut o: FramerOut = z();
            let r = match index {
                slot::EMIT => {
                    let mut i: EmitIn = z();
                    i.framing = self.framing;
                    i.stream = stream;
                    i.sink = self.sink();
                    call(self.ops.emit, self.inst, &mut i, &mut o, index)
                }
                slot::REFUSE => {
                    let mut i: RefuseIn = z();
                    i.framing = self.framing;
                    i.stream = stream;
                    i.has_stream = 1;
                    i.sink = self.sink();
                    call(self.ops.refuse, self.inst, &mut i, &mut o, index)
                }
                slot::INGEST => {
                    let mut i: IngestIn = z();
                    i.framing = self.framing;
                    i.sink = self.sink();
                    call(self.ops.ingest, self.inst, &mut i, &mut o, index)
                }
                _ => {
                    let mut i: FramingIn = z();
                    i.framing = self.framing;
                    i.sink = self.sink();
                    call(self.ops.timer, self.inst, &mut i, &mut o, index)
                }
            };
            if self.take(r, &o) != Outcome::Ready {
                return r;
            }
        }
        Outcome::Ready
    }

    /// `begin` on `side`, over `sock`, with `agreed` the protocol connection security agreed.
    pub fn begin(&mut self, side: u32, target: &str, agreed: &str, sock: Option<Arc<Socket>>) {
        assert_eq!(
            self.try_begin(side, target, agreed, sock),
            Outcome::Ready,
            "begin"
        );
    }

    /// `begin`, answering its outcome.
    pub fn try_begin(
        &mut self,
        side: u32,
        target: &str,
        agreed: &str,
        sock: Option<Arc<Socket>>,
    ) -> Outcome {
        self.sock = sock;
        self.facts_text = agreed.to_owned();
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        if !agreed.is_empty() {
            facts.agreed_protocol = s(&self.facts_text);
        }
        let mut i: BeginIn = z();
        i.side = side;
        i.target = s(target);
        i.facts = &facts;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN);
        self.framing = o.framing;
        if self.take(r, &o) != Outcome::Ready {
            return r;
        }
        self.drain(slot::TIMER, 0)
    }

    /// `encode` an envelope: `path` as the target head word, then `fields`, then the one message
    /// `body`.
    pub fn encode(&mut self, path: &str, fields: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let all: Vec<Field> = fields
            .iter()
            .map(|(n, v)| Field {
                name: s(n),
                value: s(v),
            })
            .collect();
        let mut i: EncodeIn = z();
        i.target = s(path);
        i.fields = all.as_ptr();
        i.fields_len = all.len();
        i.body = body.as_ptr();
        i.body_len = body.len();
        i.sink = self.sink();
        // `encode` renders a whole call at once, so the host gives it the whole buffer.
        i.sink.wire_cap = self.wire.len();
        let mut o: FramerOut = z();
        assert_eq!(
            call(self.ops.encode, self.inst, &mut i, &mut o, slot::ENCODE),
            Outcome::Ready
        );
        self.wire[..o.yielded.wire_len as usize].to_vec()
    }

    /// `emit` `bytes` on `stream`.
    pub fn emit(&mut self, stream: u64, bytes: &[u8], end: bool, deadline_ns: u64) -> Outcome {
        let mut i: EmitIn = z();
        i.framing = self.framing;
        i.stream = stream;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = u32::from(end);
        i.deadline_ns = deadline_ns;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT);
        if self.take(r, &o) != Outcome::Ready {
            return r;
        }
        self.drain(slot::EMIT, stream)
    }

    /// `encode` a one-message call and `emit` it as one whole frame.
    pub fn ask(&mut self, stream: u64, path: &str, body: &[u8], deadline_ns: u64) {
        let c = self.encode(path, &[], body);
        assert_eq!(self.emit(stream, &c, true, deadline_ns), Outcome::Ready);
    }

    /// `refuse` accepted `stream` with the trailer block `bytes`.
    pub fn refuse(&mut self, stream: u64, bytes: &[u8]) -> Outcome {
        let mut i: RefuseIn = z();
        i.framing = self.framing;
        i.stream = stream;
        i.has_stream = 1;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.refuse, self.inst, &mut i, &mut o, slot::REFUSE);
        if self.take(r, &o) != Outcome::Ready {
            return r;
        }
        self.drain(slot::REFUSE, stream)
    }

    /// Ingest whatever the far end sends until it stays quiet for `quiet` or `until` holds; the
    /// first op that fails ends the pump with its outcome.
    pub fn pump_until(&mut self, quiet: Duration, until: impl Fn(&[Got]) -> bool) -> Outcome {
        let mut idle = Duration::ZERO;
        let step = Duration::from_millis(5);
        while idle < quiet && !until(&self.got) {
            let (bytes, end) = {
                let sock = self.sock.as_ref().expect("a socket");
                let mut g = sock.rx.lock().expect("rx");
                let end = g.1;
                g.1 = false;
                (g.0.drain(..).collect::<Vec<u8>>(), end)
            };
            if bytes.is_empty() && !end {
                std::thread::sleep(step);
                idle += step;
                continue;
            }
            idle = Duration::ZERO;
            let mut i: IngestIn = z();
            i.framing = self.framing;
            i.bytes = bytes.as_ptr();
            i.len = bytes.len();
            i.end = u32::from(end);
            i.sink = self.sink();
            let mut o: FramerOut = z();
            let r = call(self.ops.ingest, self.inst, &mut i, &mut o, slot::INGEST);
            if self.take(r, &o) != Outcome::Ready {
                return r;
            }
            let r = self.drain(slot::INGEST, 0);
            if r != Outcome::Ready || end {
                return r;
            }
        }
        Outcome::Ready
    }

    pub fn pump(&mut self, quiet: Duration) -> Outcome {
        self.pump_until(quiet, |_| false)
    }

    /// Move the clock to `at` and call `timer` if the framer asked for a deadline by then.
    pub fn advance(&mut self, at: u64) -> Outcome {
        self.now = at;
        if self.deadline.is_some_and(|d| d <= at) {
            let mut i: FramingIn = z();
            i.framing = self.framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            let r = call(self.ops.timer, self.inst, &mut i, &mut o, slot::TIMER);
            if self.take(r, &o) != Outcome::Ready {
                return r;
            }
            return self.drain(slot::TIMER, 0);
        }
        Outcome::Ready
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.deadline
    }

    pub fn close(self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE);
    }

    // ── reading what arrived ─────────────────────────────────────────────────────────────────────

    /// Stream `stream`'s whole frames (pieces joined up to each end-of-frame) up to its status:
    /// the head, the messages and (on an accepted stream) the far end's empty last.
    pub fn frames(&self, stream: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut cur = Vec::new();
        for g in self.got.iter().filter(|g| g.stream == stream) {
            if g.coded() {
                break;
            }
            cur.extend_from_slice(&g.bytes);
            if g.flags & PIECE_END_OF_FRAME != 0 {
                out.push(std::mem::take(&mut cur));
            }
        }
        out
    }

    /// Stream `stream`'s end (`over`), once it arrived.
    pub fn terminal(&self, stream: u64) -> Option<(u32, u8, bool, Vec<u8>)> {
        over(&self.got, stream)
    }

    /// Accepted stream `stream`'s head words: (method, target, authority).
    pub fn head_words(&self, stream: u64) -> Option<(String, String, String)> {
        self.words
            .iter()
            .find(|w| w.0 == stream)
            .map(|w| (w.1.clone(), w.2.clone(), w.3.clone()))
    }
}

/// The value of `name` in a head block frame.
pub fn field(block: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(block).ok()?;
    text.split("\r\n").find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_owned())
    })
}

/// `payload` as one length-prefixed message.
pub fn lpm(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

// ── the tonic peer ───────────────────────────────────────────────────────────────────────────────

/// A byte-blind codec: messages are bytes both ways.
#[derive(Debug, Clone, Default)]
pub struct RawCodec;

pub struct RawEncoder;
pub struct RawDecoder;

impl Codec for RawCodec {
    type Encode = Vec<u8>;
    type Decode = Bytes;
    type Encoder = RawEncoder;
    type Decoder = RawDecoder;
    fn encoder(&mut self) -> RawEncoder {
        RawEncoder
    }
    fn decoder(&mut self) -> RawDecoder {
        RawDecoder
    }
}

impl Encoder for RawEncoder {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        use bytes::BufMut;
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for RawDecoder {
    type Item = Bytes;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
        use bytes::Buf;
        let n = src.remaining();
        Ok(Some(src.copy_to_bytes(n)))
    }
}

type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// `/t.T/Unary`: answers `got:<message>`, and `;timeout=<grpc-timeout>` when the call carried one.
struct Unary;
impl tower::Service<Request<Bytes>> for Unary {
    type Response = Response<Vec<u8>>;
    type Error = Status;
    type Future = BoxFut<Result<Response<Vec<u8>>, Status>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Status>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: Request<Bytes>) -> Self::Future {
        let timeout = req
            .metadata()
            .get("grpc-timeout")
            .and_then(|v| v.to_str().ok())
            .map(|v| format!(";timeout={v}"))
            .unwrap_or_default();
        let meta = req
            .metadata()
            .get("x-meta")
            .and_then(|v| v.to_str().ok())
            .map(|v| format!(";meta={v}"))
            .unwrap_or_default();
        let mut out = b"got:".to_vec();
        out.extend_from_slice(req.get_ref());
        out.extend_from_slice(timeout.as_bytes());
        out.extend_from_slice(meta.as_bytes());
        Box::pin(async move {
            let mut r = Response::new(out);
            r.metadata_mut()
                .insert("x-answer", "yes".parse().expect("value"));
            Ok(r)
        })
    }
}

type MsgStream = Pin<Box<dyn futures::Stream<Item = Result<Vec<u8>, Status>> + Send>>;

/// `/t.T/List`: three messages, `a`, `bb`, `ccc`.
struct List;
impl tower::Service<Request<Bytes>> for List {
    type Response = Response<MsgStream>;
    type Error = Status;
    type Future = BoxFut<Result<Response<MsgStream>, Status>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Status>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<Bytes>) -> Self::Future {
        Box::pin(async move {
            let items: Vec<Result<Vec<u8>, Status>> =
                vec![Ok(b"a".to_vec()), Ok(b"bb".to_vec()), Ok(b"ccc".to_vec())];
            let s: MsgStream = Box::pin(futures::stream::iter(items));
            Ok(Response::new(s))
        })
    }
}

/// `/t.T/Fail`: `NOT_FOUND`, with a message that needs percent-encoding.
struct Fail;
impl tower::Service<Request<Bytes>> for Fail {
    type Response = Response<Vec<u8>>;
    type Error = Status;
    type Future = BoxFut<Result<Response<Vec<u8>>, Status>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Status>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Request<Bytes>) -> Self::Future {
        Box::pin(async move { Err(Status::not_found("no such key: \u{2713} 100%")) })
    }
}

/// The text `Fail` answers, as the far end meant it.
pub const FAIL_TEXT: &str = "no such key: \u{2713} 100%";

/// Service `t.T`.
#[derive(Clone, Default)]
pub struct TestSvc;

impl tonic::server::NamedService for TestSvc {
    const NAME: &'static str = "t.T";
}

impl<B> tower::Service<http::Request<B>> for TestSvc
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>> + Send + 'static,
{
    type Response = http::Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = BoxFut<Result<Self::Response, Infallible>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let path = req.uri().path().to_owned();
        Box::pin(async move {
            let mut g = tonic::server::Grpc::new(RawCodec);
            Ok(match path.as_str() {
                "/t.T/Unary" => g.unary(Unary, req).await,
                "/t.T/List" => g.server_streaming(List, req).await,
                "/t.T/Fail" => g.unary(Fail, req).await,
                "/t.T/Hang" => std::future::pending().await,
                _ => Status::unimplemented("no such method").into_http(),
            })
        })
    }
}

/// Serve `t.T` with hyper's HTTP/2 server over `io`.
pub async fn serve_h2<IO>(io: IO)
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let svc = hyper_util::service::TowerToHyperService::new(TestSvc);
    let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(hyper_util::rt::TokioIo::new(io), svc)
        .await;
}

/// Serve `t.T` in memory: the host's end of a duplex whose far end tonic's service answers.
pub fn serve_in_memory(rt: &tokio::runtime::Runtime) -> Arc<Socket> {
    let (cli, srv) = tokio::io::duplex(1 << 20);
    rt.spawn(serve_h2(srv));
    let _g = rt.enter();
    bridge(rt, cli)
}
