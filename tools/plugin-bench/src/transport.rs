// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TRANSPORT: an accepting HTTP framer's per-request read/write path, over in-memory bytes.
//!
//! A framer is sans-IO: the host reads the socket and hands the framer its bytes (`ingest`), and
//! the framer answers the bytes owed to the far side in a host buffer (`FramerSink::wire`). So the
//! bench needs no socket at all: the "connection" is the request bytes this module owns (handed
//! to `ingest` from a lent buffer) and the wire buffer the framer writes the answer into. That is
//! exactly what core's connector does with a listener's socket bytes
//! (`busbar-core-connector::framer::Framing::{begin_lent, ingest, emit_head, emit}`), minus the
//! socket read/write itself.
//!
//! Each crossing is the connector's: `begin`/`ingest`/`emit` on the framing's INLINE ticket
//! (`Plugin::answer_inline`, as `doors.rs::cross_on` does), every one under the connection's host
//! framing context (`framing_context::with_context`, as `cross_scoped` does), `finish` as a plain
//! `Plugin::answer`. The listener's guest list is one `none` line (`POST /v1/chat/completions`), its
//! auth handle lent by the loader (`auth_handle::lend_none_line`), so the request's hand-in
//! (`unit.hand_in`) is served by the loader's own none-line path: no kernel, no auth plugin.
//!
//! The connection is KEPT ALIVE: one framing per bench thread, opened outside the measurement and
//! finished when the thread's scenario is dropped. Every unit is one request on it: `ingest` of
//! the whole request (head ~450 B + a 1 KiB / 8 KiB / 100 KiB OpenAI body), then the answer: its
//! head (`emit` with the status and a field block), then either the whole JSON body (one `emit`,
//! end of answer) or an SSE stream (`--deltas` chunk emits and a final `[DONE]` emit). The
//! framer forgets each finished request, so only the stream counter moves. The `conn` scenario
//! opens a connection per request instead (`begin` .. `finish` timed too). The `h2` scenarios
//! are the same exchanges over cleartext HTTP/2 by prior knowledge (hand-built frames: the
//! preface and SETTINGS once per connection, then per request a connection WINDOW_UPDATE, HEADERS
//! and 16 KiB DATA frames on the next odd stream id).
//!
//! Every READY framer answer leases its retained-input report (the SDK's `framer.retained_input`).
//! The bench crosses through the loader's public `answer`/`answer_inline`, as core's connector
//! does, which release that lease inside the crossing: each timed op includes its RELEASE.

use std::sync::Arc;
use std::time::Instant;

use busbar_contract::abi::host::service::{AuthRef, SCHEME_PLAIN};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::transport::route::{RouteMatch, METHOD_POST, PATH_EXACT};
use busbar_contract::abi::transport::{
    slot, BeginIn, ConnFacts, EmitIn, FinishIn, FramePiece, FramerOut, FramerSink, HeadSlots,
    IngestIn, LineEntry, PIECE_END, PIECE_FIELDS, PIECE_STREAM_FAILED, PIECE_WRITABLE, SIDE_ACCEPT,
    YIELD_ENDED, YIELD_MORE,
};
use busbar_contract::framing_scope::FramingScope;
use busbar_contract::json::{self, json, Value};
use busbar_plugin_loader::dispatch::framing_context::with_context;
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{ConnTable, Dispatcher, Frame, InlineTicket, Plugin};

use crate::frames::{abi, input, json as json_blob, output};
use crate::stats::Recorder;
use crate::{Config, Scenario, Spec, Target};

/// The `none` line's id, as the kernel would number it.
const LINE: u32 = 1;
/// The none line's auth handle id the loader lends.
const NONE_AUTH_ID: u64 = 0x6e6f_6e65_0001;
const PATH: &[u8] = b"/v1/chat/completions";
const PIECES: usize = 1024;
const HEADS: usize = 16;

struct Opened {
    plugin: Plugin<Transport>,
    d: Arc<Dispatcher>,
    owner: u64,
    auth: AuthRef,
}

// SAFETY: one opened framer instance is shared by the bench threads as core's connector shares it
// between its connections; every measured op is a `Plugin::answer`/`answer_inline` on it.
unsafe impl Sync for Opened {}
unsafe impl Send for Opened {}

fn open(cfg: &Config, target: &Target) -> Result<Arc<Opened>, String> {
    let d = crate::dispatcher();
    let plugin = crate::load::<Transport>(
        target,
        crate::bind(&d, "bench-transport", ConnTable::NoNeeds),
    )?;
    // The connector deals each declared setting's deployment value; `{}` takes every declared
    // default (h1/h2 auto, 300 s, 32 MiB body).
    let settings = cfg.settings.clone().unwrap_or_else(|| b"{}".to_vec());
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = json_blob(&settings);
    let called = plugin.answer(life::OPEN, &mut f);
    if called.outcome != Outcome::Ready {
        return Err(format!(
            "transport open answered {:?}: {}",
            called.outcome,
            String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
        ));
    }
    plugin
        .ready(&d, std::time::Duration::from_secs(30))
        .map_err(|e| format!("transport ready: {e}"))?;
    let owner = plugin.instance().0;
    let auth = busbar_plugin_loader::dispatch::auth_handle::lend_none_line(owner, NONE_AUTH_ID)
        .ok_or("the loader would not lend a none line")?;
    Ok(Arc::new(Opened {
        plugin,
        d,
        owner,
        auth,
    }))
}

/// The OpenAI SDK's request head for a body of `len` bytes (~450 B).
fn request_head(len: usize) -> Vec<u8> {
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\n\
         host: api.busbar.test\r\n\
         user-agent: OpenAI/Python 1.54.4\r\n\
         accept: application/json\r\n\
         accept-encoding: gzip, deflate\r\n\
         content-type: application/json\r\n\
         authorization: Bearer sk-bench-000000000000000000000000000000000000000000000000\r\n\
         x-stainless-lang: python\r\n\
         x-stainless-package-version: 1.54.4\r\n\
         x-stainless-os: Linux\r\n\
         x-stainless-arch: x64\r\n\
         x-stainless-runtime: CPython\r\n\
         x-stainless-runtime-version: 3.12.7\r\n\
         x-stainless-retry-count: 0\r\n\
         connection: keep-alive\r\n\
         content-length: {len}\r\n\r\n"
    )
    .into_bytes()
}

/// An OpenAI chat request body of about `size` bytes.
fn request_body(size: usize, stream: bool) -> Vec<u8> {
    let mut v = json!({
        "model": "gpt",
        "max_tokens": 256,
        "messages": [
            {"role": "system", "content": "You are a concise assistant."},
            {"role": "user", "content": ""}
        ],
    });
    if stream {
        v["stream"] = json!(true);
        v["stream_options"] = json!({"include_usage": true});
    }
    let base = json::to_vec(&v).expect("json").len();
    let words = "the quick brown fox jumps over the lazy dog ";
    let pad: String = words
        .chars()
        .cycle()
        .take(size.saturating_sub(base))
        .collect();
    v["messages"][1]["content"] = json!(pad);
    json::to_vec(&v).expect("json")
}

const H2_DATA: u8 = 0;
const H2_HEADERS: u8 = 1;
const H2_SETTINGS: u8 = 4;
const H2_WINDOW_UPDATE: u8 = 8;
const H2_END_STREAM: u8 = 1;
const H2_END_HEADERS: u8 = 4;
/// The default SETTINGS_MAX_FRAME_SIZE: the largest DATA payload a client sends unasked.
const H2_MAX_FRAME: usize = 16_384;

fn h2_frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() as u32).to_be_bytes();
    let mut f = vec![len[1], len[2], len[3], ty, flags];
    f.extend_from_slice(&stream.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// An HPACK integer with an `n`-bit prefix under `first`'s high bits (RFC 7541 §5.1).
fn hpack_int(out: &mut Vec<u8>, first: u8, n: u32, mut v: usize) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(first | v as u8);
        return;
    }
    out.push(first | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

/// An HPACK string literal, not Huffman-coded.
fn hpack_str(out: &mut Vec<u8>, s: &[u8]) {
    hpack_int(out, 0, 7, s.len());
    out.extend_from_slice(s);
}

/// The OpenAI SDK's request on HTTP/2: a connection WINDOW_UPDATE returning what the previous
/// answer's DATA used (`answer_data` bytes, so the client's window stays level), the HEADERS
/// (HPACK literals without indexing, so every request codes the same) and the body in DATA frames
/// of at most 16 KiB, the last ending the stream. Answers the bytes and the offset of every stream
/// id in them (rewritten per request).
fn h2_request(body: &[u8], answer_data: usize) -> (Vec<u8>, Vec<usize>) {
    let mut block = vec![0x83, 0x86]; // :method POST, :scheme http (static table)
    hpack_int(&mut block, 0, 4, 4); // :path, literal without indexing
    hpack_str(&mut block, PATH);
    hpack_int(&mut block, 0, 4, 1); // :authority
    hpack_str(&mut block, b"api.busbar.test");
    let len = body.len().to_string();
    for (name, value) in [
        ("user-agent", "OpenAI/Python 1.54.4"),
        ("accept", "application/json"),
        ("accept-encoding", "gzip, deflate"),
        ("content-type", "application/json"),
        (
            "authorization",
            "Bearer sk-bench-000000000000000000000000000000000000000000000000",
        ),
        ("x-stainless-lang", "python"),
        ("x-stainless-package-version", "1.54.4"),
        ("x-stainless-os", "Linux"),
        ("x-stainless-arch", "x64"),
        ("x-stainless-runtime", "CPython"),
        ("x-stainless-runtime-version", "3.12.7"),
        ("x-stainless-retry-count", "0"),
        ("content-length", len.as_str()),
    ] {
        block.push(0);
        hpack_str(&mut block, name.as_bytes());
        hpack_str(&mut block, value.as_bytes());
    }
    let mut wire = h2_frame(
        H2_WINDOW_UPDATE,
        0,
        0,
        &(answer_data.max(1) as u32).to_be_bytes(),
    );
    let mut at = Vec::new();
    at.push(wire.len() + 5);
    wire.extend(h2_frame(H2_HEADERS, H2_END_HEADERS, 0, &block));
    let parts: Vec<&[u8]> = body.chunks(H2_MAX_FRAME).collect();
    for (n, part) in parts.iter().enumerate() {
        let flags = if n + 1 == parts.len() {
            H2_END_STREAM
        } else {
            0
        };
        at.push(wire.len() + 5);
        wire.extend(h2_frame(H2_DATA, flags, 0, part));
    }
    (wire, at)
}

/// The whole JSON answer (~0.7 KiB).
fn whole_answer() -> Vec<u8> {
    let text = "Here is a short answer with a handful of sentences. ".repeat(8);
    json::to_vec(&json!({
        "id": "chatcmpl-bench", "object": "chat.completion", "created": 1_700_000_000,
        "model": "gpt", "system_fingerprint": "fp_bench",
        "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                     "logprobs": null, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 312, "completion_tokens": 96, "total_tokens": 408}
    }))
    .expect("json")
}

/// The SSE answer's events: `deltas` content chunks, a finish chunk and a usage chunk; `[DONE]`
/// is the final emit.
fn sse_chunks(deltas: usize) -> Vec<Box<[u8]>> {
    let event = |v: Value| {
        let mut b = b"data: ".to_vec();
        b.extend_from_slice(&json::to_vec(&v).expect("json"));
        b.extend_from_slice(b"\n\n");
        b.into_boxed_slice()
    };
    let chunk = |delta: Value, finish: Value| {
        event(json!({
            "id": "chatcmpl-bench", "object": "chat.completion.chunk", "created": 1_700_000_000,
            "model": "gpt", "system_fingerprint": "fp_bench",
            "choices": [{"index": 0, "delta": delta, "logprobs": null, "finish_reason": finish}]
        }))
    };
    let mut out = vec![chunk(
        json!({"role": "assistant", "content": ""}),
        json!(null),
    )];
    for i in 0..deltas.saturating_sub(3) {
        out.push(chunk(json!({"content": format!("word{i} ")}), json!(null)));
    }
    out.push(chunk(json!({}), json!("stop")));
    out.push(event(json!({
        "id": "chatcmpl-bench", "object": "chat.completion.chunk", "created": 1_700_000_000,
        "model": "gpt", "choices": [],
        "usage": {"prompt_tokens": 312, "completion_tokens": deltas, "total_tokens": 312 + deltas}
    })));
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// Keep-alive; the answer is one whole JSON body.
    Whole,
    /// Keep-alive; the answer is an SSE stream.
    Sse,
    /// A connection per request (`begin` .. `finish` timed), the answer one whole JSON body.
    Conn,
}

pub(crate) fn specs(cfg: &Config, target: &Target) -> Result<Vec<Spec>, String> {
    let opened = open(cfg, target)?;
    let deltas = cfg.deltas.max(4);
    let mut specs = Vec::new();
    for (h2, proto) in [(false, "http1"), (true, "h2")] {
        for &size in &cfg.body_sizes {
            let o = opened.clone();
            specs.push(Spec {
                name: format!("{proto}.keepalive(req {size}B, json answer)"),
                ops: vec!["ingest", "emit.head", "emit.body"],
                primary: 0,
                make: Box::new(move |_| {
                    Ok(Box::new(Conn::new(o.clone(), h2, Shape::Whole, size, 0)?))
                }),
            });
        }
        let o = opened.clone();
        specs.push(Spec {
            name: format!("{proto}.keepalive(req 1024B, sse {deltas} chunks)"),
            ops: vec!["ingest", "emit.head", "emit.chunk", "emit.end"],
            primary: 2,
            make: Box::new(move |_| {
                Ok(Box::new(Conn::new(
                    o.clone(),
                    h2,
                    Shape::Sse,
                    1024,
                    deltas,
                )?))
            }),
        });
    }
    let o = opened;
    specs.push(Spec {
        name: "http1.conn-per-request(req 1024B, json answer)".into(),
        ops: vec!["begin", "ingest", "emit.head", "emit.body", "finish"],
        primary: 1,
        make: Box::new(move |_| Ok(Box::new(Conn::new(o.clone(), false, Shape::Conn, 1024, 0)?))),
    });
    Ok(specs)
}

/// One accepted connection and every buffer its requests lend, allocated once.
struct Conn {
    opened: Arc<Opened>,
    shape: Shape,
    ticket: InlineTicket,
    context: Option<Arc<dyn FramingScope>>,
    framing: u64,
    origin: Instant,
    // The sink.
    wire: Box<[u8]>,
    frame: Box<[u8]>,
    pieces: Box<[FramePiece]>,
    heads: Box<[HeadSlots]>,
    // What `begin` lends for the framing's life.
    facts: Box<ConnFacts>,
    lines: Box<[LineEntry; 1]>,
    // The request and its answer.
    request: Box<[u8]>,
    body_len: usize,
    answer_head: Box<[u8]>,
    answer: Box<[u8]>,
    chunks: Box<[Box<[u8]>]>,
    done: Box<[u8]>,
    // HTTP/2 (prior knowledge): where the stream id sits in the request's frames, and the next.
    h2: bool,
    stream_at: Box<[usize]>,
    next_stream: u32,
    // Per unit.
    wired: u64,
    first_wire: bool,
}

impl Conn {
    fn new(
        opened: Arc<Opened>,
        h2: bool,
        shape: Shape,
        size: usize,
        deltas: usize,
    ) -> Result<Self, String> {
        let ticket = opened
            .d
            .inline_ticket()
            .ok_or("the dispatcher minted no inline ticket")?;
        let sse = shape == Shape::Sse;
        let body = request_body(size, sse);
        let answer = whole_answer();
        let chunks = if sse { sse_chunks(deltas) } else { Vec::new() };
        let done = b"data: [DONE]\n\n".to_vec();
        let data = if sse {
            chunks.iter().map(|c| c.len()).sum::<usize>() + done.len()
        } else {
            answer.len()
        };
        let (request, stream_at) = if h2 {
            h2_request(&body, data)
        } else {
            let mut r = request_head(body.len());
            r.extend_from_slice(&body);
            (r, Vec::new())
        };
        let answer_head = if sse {
            b"content-type: text/event-stream; charset=utf-8\r\n\
              cache-control: no-cache\r\n\
              x-request-id: req_0123456789abcdef\r\n\
              openai-processing-ms: 312\r\n"
                .to_vec()
        } else {
            format!(
                "content-type: application/json\r\n\
                 content-length: {}\r\n\
                 x-request-id: req_0123456789abcdef\r\n\
                 openai-processing-ms: 312\r\n",
                answer.len()
            )
            .into_bytes()
        };
        let room = request.len() + 64 * 1024;
        // SAFETY: `HeadSlots` is plain integers; all-zero is valid.
        let head_zero: HeadSlots = unsafe { std::mem::zeroed() };
        let none = abi(b"");
        let mut c = Self {
            opened: opened.clone(),
            shape,
            ticket,
            context: None,
            framing: 0,
            origin: Instant::now(),
            wire: vec![0; room].into_boxed_slice(),
            frame: vec![0; room].into_boxed_slice(),
            pieces: vec![FramePiece::ZERO; PIECES].into_boxed_slice(),
            heads: vec![head_zero; HEADS].into_boxed_slice(),
            facts: Box::new(ConnFacts {
                size: size_of::<ConnFacts>() as u32,
                _reserved: 0,
                offered_name: none,
                agreed_protocol: none,
                peer_subject: none,
                peer_issuer: none,
                peer_fingerprint: none,
                claim: none,
                local_certificate: none,
            }),
            lines: Box::new([LineEntry {
                line: LINE,
                points: 0,
                auth: opened.auth,
                body_limit: 0,
                route: RouteMatch {
                    methods: METHOD_POST,
                    path_form: PATH_EXACT,
                    path: abi(PATH),
                    ..RouteMatch::EMPTY
                },
            }]),
            request: request.into_boxed_slice(),
            body_len: body.len(),
            answer_head: answer_head.into_boxed_slice(),
            answer: answer.into_boxed_slice(),
            chunks: chunks.into_boxed_slice(),
            done: done.into_boxed_slice(),
            h2,
            stream_at: stream_at.into_boxed_slice(),
            next_stream: 1,
            wired: 0,
            first_wire: true,
        };
        if shape != Shape::Conn {
            c.begin(None)?;
            if h2 {
                c.h2_preface()?;
            }
            // One untimed request first: the framer's first-use allocations stay out of the numbers.
            c.request_unit(None)?;
        }
        Ok(c)
    }

    fn sink(&mut self) -> FramerSink {
        let mono = 1_000_000_000 + self.origin.elapsed().as_nanos() as u64;
        FramerSink {
            wire: self.wire.as_mut_ptr(),
            wire_cap: self.wire.len(),
            frame: self.frame.as_mut_ptr(),
            frame_cap: self.frame.len(),
            pieces: self.pieces.as_mut_ptr(),
            pieces_cap: self.pieces.len(),
            now_monotonic_ns: mono,
            now_unix_ns: 1_700_000_000_000_000_000 + mono,
            heads: self.heads.as_mut_ptr(),
            heads_cap: self.heads.len(),
        }
    }

    /// One crossing, timed as op `op` when a recorder is given: the connector's `cross_scoped` over
    /// `cross_on` (inline ticket) or `cross` (no ticket).
    fn cross<I, O>(
        &mut self,
        rec: Option<&mut Recorder>,
        op: usize,
        s: u32,
        ticketed: bool,
        f: &mut Frame<I, O>,
        what: &str,
    ) -> Result<(), String>
    where
        I: busbar_plugin_loader::dispatch::InFrame,
        O: busbar_plugin_loader::dispatch::OutFrame,
    {
        let context = self.context.clone();
        let plugin = &self.opened.plugin;
        let ticket = self.ticket.ticket();
        let go = || {
            with_context(context, || {
                if ticketed {
                    plugin.answer_inline(ticket, false, s, f)
                } else {
                    plugin.answer(s, f)
                }
            })
        };
        let called = match rec {
            Some(rec) => rec.time(op, go),
            None => go(),
        };
        if called.outcome != Outcome::Ready {
            return Err(format!(
                "{what} answered {:?}: {}",
                called.outcome,
                String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
            ));
        }
        Ok(())
    }

    fn yielded(&mut self, out: &FramerOut, what: &str) -> Result<(), String> {
        let y = out.yielded;
        if y.flags & YIELD_MORE != 0 {
            return Err(format!("{what}: a sink buffer filled (YIELD_MORE)"));
        }
        if y.flags & YIELD_ENDED != 0 {
            return Err(format!("{what}: the framer ended the connection"));
        }
        if y.wire_len > 0 {
            if self.first_wire && !self.h2 && !self.wire.starts_with(b"HTTP/1.1 200 OK\r\n") {
                return Err(format!(
                    "{what}: the answer's wire does not start with its status line: {:?}",
                    String::from_utf8_lossy(&self.wire[..(y.wire_len as usize).min(64)])
                ));
            }
            self.first_wire = false;
            self.wired += y.wire_len;
        }
        Ok(())
    }

    fn begin(&mut self, rec: Option<&mut Recorder>) -> Result<(), String> {
        let o = &self.opened;
        let context: Arc<dyn FramingScope> =
            o.d.framing_context(o.owner, 0, 0)
                .map_err(|e| format!("framing context: {e}"))?;
        self.context = Some(context.clone());
        let mut i: BeginIn = input();
        i.side = SIDE_ACCEPT;
        i.scheme = SCHEME_PLAIN;
        i.target = abi(b"");
        i.facts = &*self.facts;
        i.lines = self.lines.as_ptr();
        i.lines_len = self.lines.len();
        i.sink = self.sink();
        let mut f = Frame::new(i, output::<FramerOut>());
        self.cross(rec, 0, slot::BEGIN, true, &mut f, "begin")?;
        self.framing = f.out.framing;
        context
            .confirm(self.framing)
            .map_err(|e| format!("framing confirm: {e}"))?;
        self.yielded(&f.out, "begin")
    }

    fn finish(&mut self, rec: Option<&mut Recorder>, op: usize) -> Result<(), String> {
        let mut i: FinishIn = input();
        i.framing = self.framing;
        i.sink = self.sink();
        let mut f = Frame::new(i, output::<FramerOut>());
        let r = self.cross(rec, op, slot::FINISH, false, &mut f, "finish");
        if let Some(c) = self.context.take() {
            c.closing();
            c.end();
        }
        self.framing = 0;
        r
    }

    /// One `ingest` of `len` bytes at `bytes` (this connection's own, live for the call).
    fn ingest_raw(
        &mut self,
        rec: Option<&mut Recorder>,
        op: usize,
        bytes: *const u8,
        len: usize,
    ) -> Result<FramerOut, String> {
        let mut i: IngestIn = input();
        i.framing = self.framing;
        i.bytes = bytes;
        i.len = len;
        i.sink = self.sink();
        let mut f = Frame::new(i, output::<FramerOut>());
        self.cross(rec, op, slot::INGEST, true, &mut f, "ingest")?;
        self.yielded(&f.out, "ingest")?;
        Ok(f.out)
    }

    /// The client's HTTP/2 connection preface (untimed): SETTINGS with the largest stream window,
    /// a connection WINDOW_UPDATE, then the ACK of the server's SETTINGS once it has sent them.
    fn h2_preface(&mut self) -> Result<(), String> {
        let mut settings = Vec::new();
        for (id, value) in [(0x2u16, 0u32), (0x4, 0x7fff_ffff)] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&value.to_be_bytes());
        }
        let mut open = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        open.extend(h2_frame(H2_SETTINGS, 0, 0, &settings));
        open.extend(h2_frame(
            H2_WINDOW_UPDATE,
            0,
            0,
            &(1u32 << 30).to_be_bytes(),
        ));
        self.ingest_raw(None, 0, open.as_ptr(), open.len())?;
        if self.wired == 0 {
            return Err("h2: the server sent no SETTINGS for the preface".into());
        }
        let ack = h2_frame(H2_SETTINGS, 1, 0, &[]);
        self.ingest_raw(None, 0, ack.as_ptr(), ack.len())?;
        self.wired = 0;
        Ok(())
    }

    /// `ingest` the whole request; check it went up as one head, the whole body and its end.
    fn ingest(&mut self, rec: Option<&mut Recorder>, op: usize) -> Result<u64, String> {
        if self.h2 {
            let id = self.next_stream.to_be_bytes();
            for &at in &self.stream_at {
                self.request[at..at + 4].copy_from_slice(&id);
            }
            self.next_stream += 2;
        }
        let (bytes, len) = (self.request.as_ptr(), self.request.len());
        let out = self.ingest_raw(rec, op, bytes, len)?;
        let f = &out;
        let (mut stream, mut body, mut end) = (0, 0, false);
        for p in &self.pieces[..f.yielded.pieces_len as usize] {
            if p.flags & PIECE_STREAM_FAILED != 0 {
                return Err("ingest: the request's stream failed".into());
            }
            if p.flags & PIECE_FIELDS != 0 {
                stream = p.stream;
            } else if p.flags & PIECE_END != 0 {
                end = true;
            } else if p.flags & PIECE_WRITABLE == 0 {
                body += p.len;
            }
        }
        if stream == 0 || !end || body != self.body_len as u64 {
            return Err(format!(
                "ingest: went up as stream {stream}, {body} of {} body bytes, end {end} \
                 ({} pieces)",
                self.body_len, f.yielded.pieces_len
            ));
        }
        Ok(stream)
    }

    fn emit(
        &mut self,
        rec: Option<&mut Recorder>,
        op: usize,
        stream: u64,
        which: Emit,
    ) -> Result<(), String> {
        let (bytes, end, status) = match which {
            Emit::Head => (&self.answer_head, false, 200),
            Emit::Body => (&self.answer, true, 0),
            Emit::Chunk(n) => (&self.chunks[n], false, 0),
            Emit::Done => (&self.done, true, 0),
        };
        let mut i: EmitIn = input();
        i.framing = self.framing;
        i.stream = stream;
        i.bytes = bytes.as_ptr();
        i.len = bytes.len();
        i.end_of_frame = u32::from(end);
        i.status = status;
        i.sink = self.sink();
        let mut f = Frame::new(i, output::<FramerOut>());
        self.cross(rec, op, slot::EMIT, true, &mut f, "emit")?;
        self.yielded(&f.out, "emit")
    }

    /// One request and its whole answer on the open connection.
    fn request_unit(&mut self, mut rec: Option<&mut Recorder>) -> Result<(), String> {
        let base = usize::from(self.shape == Shape::Conn);
        self.wired = 0;
        self.first_wire = true;
        let stream = self.ingest(rec.as_deref_mut(), base)?;
        self.emit(rec.as_deref_mut(), base + 1, stream, Emit::Head)?;
        let least = if self.shape == Shape::Sse {
            for n in 0..self.chunks.len() {
                self.emit(rec.as_deref_mut(), 2, stream, Emit::Chunk(n))?;
            }
            self.emit(rec.as_deref_mut(), 3, stream, Emit::Done)?;
            self.chunks.iter().map(|c| c.len()).sum::<usize>() + self.done.len()
        } else {
            self.emit(rec, base + 2, stream, Emit::Body)?;
            self.answer.len()
        };
        // h1 owes the field block verbatim; h2 HPACK-codes it, so only its DATA is a floor.
        let least = if self.h2 {
            least
        } else {
            least + self.answer_head.len()
        };
        if self.wired < least as u64 {
            return Err(format!(
                "the answer's wire is {} bytes, short of the {least} bytes owed",
                self.wired
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Emit {
    Head,
    Body,
    Chunk(usize),
    Done,
}

impl Scenario for Conn {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        if self.shape == Shape::Conn {
            self.begin(Some(rec))?;
            self.request_unit(Some(rec))?;
            return self.finish(Some(rec), 4);
        }
        self.request_unit(Some(rec))
    }
}

impl Drop for Conn {
    fn drop(&mut self) {
        if self.framing != 0 {
            if let Err(e) = self.finish(None, 0) {
                if crate::report::verbose() {
                    eprintln!("[transport] finish: {e}");
                }
            }
        }
    }
}
