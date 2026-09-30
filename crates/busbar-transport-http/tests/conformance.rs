// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `http` DOOR'S CONFORMANCE: the same door, compiled in and dropped in, driven the same way.
//!
//! The test is the HOST. It holds the socket (an in-memory duplex to a real hyper server on a tokio
//! runtime of its own), the clock (a virtual monotonic clock it advances by hand) and the sink
//! buffers, and it calls the framer only through the transport kind's table: `begin`, `emit`,
//! `ingest`, `timer`. The framer is driven from the test's own thread, outside any runtime.
//!
//! Each scenario runs twice, through the linked door and through the cdylib `cargo test` built from
//! `examples/http_door.rs`, and both must print the same proof lines.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::ffi::c_void;
use std::mem::{size_of, zeroed};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use busbar_contract::abi::mechanism::DOOR_SYMBOL;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, Op, OutHead, Outcome, BLOB_JSON,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, EncodeIn, FramePiece, FramerOut, FramerSink, FramingIn,
    IngestIn, Ops, PIECE_END_OF_FRAME, PIECE_FIELDS, PIECE_HAS_CODE, PIECE_STREAM_FAILED, SIDE_DIAL,
    YIELD_HAS_DEADLINE, YIELD_MORE,
};
use busbar_contract::abi::transport::check::check_framer;
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

/// The sink's capacities: wire bytes, frame bytes, pieces.
#[derive(Clone, Copy)]
struct Caps(usize, usize, usize);
const ROOMY: Caps = Caps(64 * 1024, 64 * 1024, 64);
/// Small enough that every answer overflows, so every op is re-called with `YIELD_MORE`.
const TIGHT: Caps = Caps(7, 5, 1);
const SEC: u64 = 1_000_000_000;

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn s(text: &'static str) -> AbiStr {
    AbiStr {
        ptr: text.as_ptr(),
        len: text.len(),
    }
}

// ── the far end: a real hyper server ─────────────────────────────────────────────────────────────

/// A response body the test releases: the first chunk at once, the rest when told.
struct ChanBody(mpsc::Receiver<Bytes>);
impl Body for ChanBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|o| o.map(|b| Ok(Frame::data(b))))
    }
}

/// The socket the host holds: what the server wrote and the host has not ingested, and a switch
/// that drops the server's bytes on the floor (a far end gone silent).
struct Socket {
    rx: Mutex<(VecDeque<u8>, bool)>,
    silent: AtomicBool,
    to_server: mpsc::UnboundedSender<Vec<u8>>,
    release: mpsc::Sender<()>,
}

fn serve(rt: &tokio::runtime::Runtime, h2: bool) -> Arc<Socket> {
    let (cli, srv) = tokio::io::duplex(1 << 20);
    let (rel_tx, rel_rx) = mpsc::channel::<()>(4);
    let rel_rx = Arc::new(tokio::sync::Mutex::new(rel_rx));
    rt.spawn(async move {
        let svc = hyper::service::service_fn(move |req: hyper::Request<Incoming>| {
            let rel = rel_rx.clone();
            async move {
                if req.uri().path() == "/hang" {
                    std::future::pending::<()>().await;
                }
                let got = http_body_util::BodyExt::collect(req.into_body())
                    .await
                    .expect("request body")
                    .to_bytes();
                let (tx, rx) = mpsc::channel(4);
                tokio::spawn(async move {
                    let _ = tx.send(Bytes::from(format!("got={};a", got.len()))).await;
                    rel.lock().await.recv().await;
                    let _ = tx.send(Bytes::from_static(b"b")).await;
                    let _ = tx.send(Bytes::from_static(b"c")).await;
                });
                Ok::<_, Infallible>(hyper::Response::new(ChanBody(rx)))
            }
        });
        let io = hyper_util::rt::TokioIo::new(srv);
        if h2 {
            let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        } else {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await;
        }
    });
    let (to_tx, mut to_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let sock = Arc::new(Socket {
        rx: Mutex::new((VecDeque::new(), false)),
        silent: AtomicBool::new(false),
        to_server: to_tx,
        release: rel_tx,
    });
    let (mut rd, mut wr) = tokio::io::split(cli);
    let s2 = sock.clone();
    rt.spawn(async move {
        let mut buf = vec![0_u8; 16384];
        loop {
            let n = rd.read(&mut buf).await.unwrap_or(0);
            if !s2.silent.load(Ordering::SeqCst) || n == 0 {
                let mut g = s2.rx.lock().expect("rx");
                g.0.extend(&buf[..n]);
                g.1 |= n == 0;
            }
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
#[derive(Debug, Clone)]
struct Got {
    stream: u64,
    bytes: Vec<u8>,
    flags: u16,
    code: u32,
}

struct Host {
    ops: &'static Ops,
    inst: *mut c_void,
    now: u64,
    framing: u64,
    sock: Arc<Socket>,
    wire_log: Vec<u8>,
    frame_log: Vec<u8>,
    deadline: Option<u64>,
    more: bool,
    caps: Caps,
    wire: Vec<u8>,
    frame: Vec<u8>,
    pieces: Vec<FramePiece>,
}

fn call<I, O>(op: Option<Op>, inst: *mut c_void, i: &mut I, o: &mut O, index: u32) -> Outcome {
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

impl Host {
    fn open(ops: &'static Ops, settings: &'static str, sock: Arc<Socket>, caps: Caps) -> Self {
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
            sock,
            wire_log: Vec::new(),
            frame_log: Vec::new(),
            deadline: None,
            more: false,
            caps,
            // The encoded request is read out of `wire` too, so it is never smaller than a message.
            wire: vec![0; caps.0.max(4096)],
            frame: vec![0; caps.1],
            pieces: vec![z(); caps.2],
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
        }
    }

    /// Take an op's answer: judge it by the kind's own check, send its wire bytes, keep its pieces.
    fn take(&mut self, outcome: Outcome, o: &FramerOut, got: &mut Vec<Got>) -> Outcome {
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
        let w = self.wire[..o.yielded.wire_len as usize].to_vec();
        if !w.is_empty() {
            self.wire_log.extend_from_slice(&w);
            self.sock.to_server.send(w).expect("server");
        }
        for p in &self.pieces[..n] {
            self.frame_log
                .extend_from_slice(&self.frame[p.offset as usize..(p.offset + p.len) as usize]);
            got.push(Got {
                stream: p.stream,
                bytes: self.frame[p.offset as usize..(p.offset + p.len) as usize].to_vec(),
                flags: p.flags,
                code: p.status_code,
            });
        }
        self.deadline =
            (o.yielded.flags & YIELD_HAS_DEADLINE != 0).then_some(o.yielded.next_deadline_ns);
        self.more = o.yielded.flags & YIELD_MORE != 0;
        outcome
    }

    /// Re-call a framing op that answered `YIELD_MORE`, with NO new bytes, until it stops.
    fn drain(&mut self, index: u32, stream: u64, got: &mut Vec<Got>) -> Outcome {
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
            if self.take(r, &o, got) != Outcome::Ready {
                return r;
            }
        }
        Outcome::Ready
    }

    fn begin(&mut self, agreed: &'static str) {
        let mut facts: ConnFacts = z();
        facts.size = size_of::<ConnFacts>() as u32;
        if !agreed.is_empty() {
            facts.agreed_protocol = s(agreed);
        }
        let mut i: BeginIn = z();
        i.side = SIDE_DIAL;
        i.target = s("http://upstream.test");
        i.facts = &facts;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let r = call(self.ops.begin, self.inst, &mut i, &mut o, slot::BEGIN);
        self.framing = o.framing;
        let mut got = Vec::new();
        assert_eq!(self.take(r, &o, &mut got), Outcome::Ready);
        assert_eq!(self.drain(slot::TIMER, 0, &mut got), Outcome::Ready);
    }

    /// `encode` an envelope, then `emit` it on `stream`.
    fn ask(&mut self, stream: u64, path: &'static str, body: &'static str) -> Vec<Got> {
        let fields = [
            Field {
                name: s("method"),
                value: s("POST"),
            },
            Field {
                name: s("path"),
                value: s(path),
            },
            Field {
                name: s("authorization"),
                value: s("Bearer sk-test"),
            },
            Field {
                name: s("content-type"),
                value: s("application/json"),
            },
        ];
        let mut i: EncodeIn = z();
        i.fields = fields.as_ptr();
        i.fields_len = fields.len();
        i.body = body.as_ptr();
        i.body_len = body.len();
        i.sink = self.sink();
        // `encode` renders a whole message at once, so the host gives it the whole buffer.
        i.sink.wire_cap = self.wire.len();
        let mut o: FramerOut = z();
        assert_eq!(
            call(self.ops.encode, self.inst, &mut i, &mut o, slot::ENCODE),
            Outcome::Ready
        );
        let message = self.wire[..o.yielded.wire_len as usize].to_vec();
        let mut i: EmitIn = z();
        i.framing = self.framing;
        i.stream = stream;
        i.bytes = message.as_ptr();
        i.len = message.len();
        i.end_of_frame = 1;
        i.sink = self.sink();
        let mut o: FramerOut = z();
        let mut got = Vec::new();
        let r = call(self.ops.emit, self.inst, &mut i, &mut o, slot::EMIT);
        assert_eq!(self.take(r, &o, &mut got), Outcome::Ready);
        assert_eq!(self.drain(slot::EMIT, stream, &mut got), Outcome::Ready);
        got
    }

    /// Ingest whatever the far end has sent until it stays quiet for `quiet`; the first op that
    /// fails ends the pump with its outcome.
    fn pump(&mut self, quiet: Duration, got: &mut Vec<Got>) -> Outcome {
        let mut idle = Duration::ZERO;
        let step = Duration::from_millis(10);
        while idle < quiet {
            let (bytes, end) = {
                let mut g = self.sock.rx.lock().expect("rx");
                (g.0.drain(..).collect::<Vec<u8>>(), g.1)
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
            if self.take(r, &o, got) != Outcome::Ready {
                return r;
            }
            let r = self.drain(slot::INGEST, 0, got);
            if r != Outcome::Ready {
                return r;
            }
            if end {
                break;
            }
        }
        Outcome::Ready
    }

    /// Move the clock to `at` and call `timer` if the framer asked for a deadline by then.
    fn advance(&mut self, at: u64, got: &mut Vec<Got>) -> Outcome {
        self.now = at;
        if self.deadline.is_some_and(|d| d <= at) {
            let mut i: FramingIn = z();
            i.framing = self.framing;
            i.sink = self.sink();
            let mut o: FramerOut = z();
            let r = call(self.ops.timer, self.inst, &mut i, &mut o, slot::TIMER);
            if self.take(r, &o, got) != Outcome::Ready {
                return r;
            }
            return self.drain(slot::TIMER, 0, got);
        }
        Outcome::Ready
    }

    /// Non-ACK PING frames the framer has written (HTTP/2, after the 24-byte preface).
    fn pings(&self) -> usize {
        let log = &self.wire_log;
        let (mut i, mut k) = (24, 0);
        while i + 9 <= log.len() {
            let len =
                usize::from(log[i]) << 16 | usize::from(log[i + 1]) << 8 | usize::from(log[i + 2]);
            if log[i + 3] == 6 && log[i + 4] & 1 == 0 {
                k += 1;
            }
            i += 9 + len;
        }
        k
    }

    fn close(self) {
        let mut i: InHead = z();
        let mut o: OutHead = z();
        call(self.ops.head.close, self.inst, &mut i, &mut o, life::CLOSE);
    }
}

fn text(got: &[Got], stream: u64) -> String {
    got.iter()
        .filter(|g| g.stream == stream && g.code == 0)
        .map(|g| String::from_utf8_lossy(&g.bytes).into_owned())
        .collect()
}

fn ended(got: &[Got], stream: u64) -> bool {
    got.iter()
        .any(|g| {
            g.stream == stream
                && g.bytes.is_empty()
                && g.flags & PIECE_END_OF_FRAME != 0
                && g.flags & PIECE_FIELDS == 0
        })
}

// ── the scenarios ────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Case {
    /// Cleartext, no protocol agreed, the prior-knowledge key on: HTTP/2.
    H2cPriorKnowledge,
    /// Connection security agreed `h2`.
    AlpnH2,
    /// HTTP/2 with the far end gone silent: the keep-alive timeout.
    KeepAliveTimeout,
    /// Connection security agreed `http/1.1` (the http1-only key's offer).
    Http1Only,
}

fn scenario(label: &str, ops: &'static Ops, rt: &tokio::runtime::Runtime, case: Case) {
    assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "the framer is driven outside any runtime"
    );
    let h2 = case != Case::Http1Only;
    let sock = serve(rt, h2);
    let (settings, agreed) = match case {
        Case::H2cPriorKnowledge | Case::KeepAliveTimeout => {
            (r#"{"advanced.upstream_h2_prior_knowledge":true}"#, "")
        }
        Case::AlpnH2 => ("{}", "h2"),
        Case::Http1Only => (r#"{"advanced.upstream_http1_only":true}"#, "http/1.1"),
    };
    let mut host = Host::open(ops, settings, sock.clone(), ROOMY);
    host.begin(agreed);
    let t0 = host.now;
    let mut got = host.ask(1, "/v1/messages", "hello");
    assert_eq!(
        host.pump(Duration::from_millis(300), &mut got),
        Outcome::Ready
    );
    let head = got
        .iter()
        .find(|g| g.flags & PIECE_HAS_CODE != 0)
        .expect("a head frame");
    println!("PROOF {label}: HEAD {}", head.code);
    assert_eq!((head.stream, head.code), (1, 200));
    // The head is ONE field block, flagged as one: no status line, no hop-by-hop field.
    assert_ne!(head.flags & PIECE_FIELDS, 0, "the head is a fields piece");
    let block = String::from_utf8_lossy(&head.bytes).into_owned();
    assert!(!block.starts_with("HTTP/"), "{block}");
    assert!(
        block.split_terminator("\r\n").all(|l| l.contains(": ")
            && l.split(": ").next().is_some_and(|n| n == n.to_ascii_lowercase())),
        "{block}"
    );
    println!("PROOF {label}: body so far {:?}", text(&got, 1));
    assert_eq!(text(&got, 1), "got=5;a");
    assert!(!ended(&got, 1), "the stalled response is not whole");

    if h2 {
        let p0 = host.pings();
        if case == Case::KeepAliveTimeout {
            sock.silent.store(true, Ordering::SeqCst);
        }
        assert_eq!(host.advance(t0 + 29 * SEC, &mut got), Outcome::Ready);
        let p29 = host.pings();
        assert_eq!(
            host.advance(t0 + 30 * SEC + SEC / 2, &mut got),
            Outcome::Ready
        );
        host.pump(Duration::from_millis(200), &mut got);
        let p30 = host.pings();
        println!("PROOF {label}: keep-alive pings before={p0} at_29s={p29} at_30.5s={p30}");
        assert!(p0 >= 1, "the adaptive window pinged when data arrived");
        assert_eq!(p29, p0, "no keep-alive ping before 30s");
        assert_eq!(p30, p0 + 1, "one keep-alive ping at 30s");
        if case == Case::KeepAliveTimeout {
            assert_eq!(
                host.advance(t0 + 39 * SEC, &mut got),
                Outcome::Ready,
                "not before 10s"
            );
            let r = host.advance(t0 + 41 * SEC, &mut got);
            println!("PROOF {label}: at 41s the timer op answers {r:?}");
            assert_eq!(
                r,
                Outcome::Failed,
                "the unanswered ping fails the connection"
            );
            host.close();
            return;
        }
    }
    rt.block_on(sock.release.send(())).expect("release");
    host.pump(Duration::from_millis(300), &mut got);
    println!(
        "PROOF {label}: body {:?}, whole={}",
        text(&got, 1),
        ended(&got, 1)
    );
    assert_eq!(text(&got, 1), "got=5;abc");
    assert!(ended(&got, 1));
    host.close();
}

fn linked() -> &'static Ops {
    let d = busbar_transport_http::door::door();
    // SAFETY: the door's `'static` table.
    unsafe { &*(*d).ops.cast::<Ops>() }
}

fn dropped() -> (&'static Ops, &'static libloading::Library) {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = format!(
        "{}http_door{}",
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

#[test]
fn the_linked_and_the_dropped_in_door_frame_the_same() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let l = linked();
    let (d, _lib) = dropped();
    assert!(
        !std::ptr::eq(l, d),
        "two images: the linked table and the dropped-in one"
    );
    for (image, ops) in [("linked", l), ("dropped", d)] {
        for (name, case) in [
            ("h2c-prior-knowledge", Case::H2cPriorKnowledge),
            ("alpn-h2", Case::AlpnH2),
            ("h2-keepalive-timeout", Case::KeepAliveTimeout),
            ("http1-only", Case::Http1Only),
        ] {
            scenario(&format!("{image} {name}"), ops, &rt, case);
        }
    }
}

/// Two requests on ONE HTTP/2 connection: the one whose head never comes fails ALONE, at the
/// request timeout (one clock per stream, send to body end), with a failure piece on its stream;
/// its sibling, which finished inside its own clock, is untouched and the connection lives.
fn one_stream_fails_alone(label: &str, ops: &'static Ops, rt: &tokio::runtime::Runtime) {
    let sock = serve(rt, true);
    let mut host = Host::open(
        ops,
        r#"{"advanced.upstream_h2_prior_knowledge":true,"limits.upstream_request_timeout_secs":5}"#,
        sock.clone(),
        ROOMY,
    );
    host.begin("");
    let t0 = host.now;
    let mut got = host.ask(1, "/hang", "");
    got.extend(host.ask(3, "/v1/messages", "hello"));
    assert_eq!(
        host.pump(Duration::from_millis(300), &mut got),
        Outcome::Ready
    );
    assert_eq!(text(&got, 3), "got=5;a", "the sibling answered");
    assert_eq!(host.advance(t0 + 4 * SEC, &mut got), Outcome::Ready);
    assert!(
        !got.iter().any(|g| g.flags & PIECE_STREAM_FAILED != 0),
        "not before 5s"
    );
    rt.block_on(sock.release.send(())).expect("release");
    host.pump(Duration::from_millis(300), &mut got);
    println!(
        "PROOF {label}: stream 3 {:?}, whole={}",
        text(&got, 3),
        ended(&got, 3)
    );
    assert_eq!(text(&got, 3), "got=5;abc");
    assert!(ended(&got, 3));
    assert_eq!(
        host.advance(t0 + 5 * SEC + SEC / 10, &mut got),
        Outcome::Ready,
        "the connection lives"
    );
    let failed: Vec<&Got> = got
        .iter()
        .filter(|g| g.flags & PIECE_STREAM_FAILED != 0)
        .collect();
    println!(
        "PROOF {label}: stream {} failed alone: {:?}",
        failed[0].stream,
        String::from_utf8_lossy(&failed[0].bytes)
    );
    assert_eq!(failed.len(), 1, "one stream failed");
    assert_eq!(failed[0].stream, 1);
    assert_eq!(
        failed[0].bytes,
        b"the request timeout passed before the response was whole"
    );
    assert!(failed[0].flags & PIECE_END_OF_FRAME != 0);
    host.close();
}

/// The wire and frame bytes of one exchange, as the host collected them.
fn exchange(ops: &'static Ops, rt: &tokio::runtime::Runtime, caps: Caps) -> (Vec<u8>, Vec<u8>) {
    let sock = serve(rt, true);
    let mut host = Host::open(
        ops,
        r#"{"advanced.upstream_h2_prior_knowledge":true}"#,
        sock.clone(),
        caps,
    );
    host.begin("");
    let mut got = host.ask(1, "/v1/messages", "hello");
    host.pump(Duration::from_millis(300), &mut got);
    rt.block_on(sock.release.send(())).expect("release");
    host.pump(Duration::from_millis(300), &mut got);
    assert!(ended(&got, 1), "the exchange completed");
    // The server stamps its head with the second it answered in; that one field is not the
    // framer's, so it is taken out of both runs before they are compared.
    let mut frames = host.frame_log.clone();
    if let Some(at) = frames.windows(6).position(|w| w == b"date: ") {
        let end = at
            + frames[at..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("a line")
            + 2;
        frames.drain(at..end);
    }
    let out = (host.wire_log.clone(), frames);
    host.close();
    out
}

/// The re-call rule's check: an exchange collected through a sink so small that every op is
/// re-called must be the SAME bytes as one collected through a roomy sink. A framer that answered
/// anything twice on a re-call, or dropped anything, differs.
fn recall_continues(tight: &(Vec<u8>, Vec<u8>), roomy: &(Vec<u8>, Vec<u8>)) -> Result<(), String> {
    if tight.0 != roomy.0 {
        return Err(format!(
            "wire differs: {} bytes vs {}",
            tight.0.len(),
            roomy.0.len()
        ));
    }
    if tight.1 != roomy.1 {
        return Err(format!(
            "frames differ: {} bytes vs {}",
            tight.1.len(),
            roomy.1.len()
        ));
    }
    Ok(())
}

#[test]
fn one_h2_stream_fails_alone_linked_and_dropped() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (d, _lib) = dropped();
    one_stream_fails_alone("linked", linked(), &rt);
    one_stream_fails_alone("dropped", d, &rt);
}

#[test]
fn a_yield_more_recall_answers_nothing_twice() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let (d, _lib) = dropped();
    for (image, ops) in [("linked", linked()), ("dropped", d)] {
        let roomy = exchange(ops, &rt, ROOMY);
        let tight = exchange(ops, &rt, TIGHT);
        println!(
            "PROOF {image}: re-called exchange wire={} frame={} bytes, same as roomy: {:?}",
            tight.0.len(),
            tight.1.len(),
            recall_continues(&tight, &roomy)
        );
        assert_eq!(recall_continues(&tight, &roomy), Ok(()));
        // RED: a framer that answered the head frame's first piece twice is caught.
        let mut dup = tight.clone();
        let first = dup.1[..5].to_vec();
        dup.1.splice(5..5, first);
        assert!(
            recall_continues(&dup, &roomy).is_err(),
            "a duplicated piece is caught"
        );
    }
}
