// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A KIND-LEVEL HTTP/1.1 REQUEST/RESPONSE FRAMER DOUBLE, in-tree: a transport door of role FRAMER
//! claiming `http` and `https`, built from the contract's SDK door macros and the SDK's sink fill,
//! so core's connector tests drive a request/response framer through the loader, the dispatcher
//! and the dispatched door with no plugin built or loaded (owner ruling: "core knows nothing about
//! plugins just kinds, plugins test themselves").
//!
//! It keeps the rules a request/response framer states to the host on the dialled side:
//! * `locate` reads an `http`/`https` URL (never one carrying userinfo): the authority to dial, the
//!   name to offer, whether the target is secured, its protocol offer (`http/1.1` under
//!   connection security), and its own client head lines (`accept: */*`, then `host`, the port only
//!   when it is not the scheme's own); it states that its head states the body's length;
//! * `encode` renders one HTTP/1.1 request message: the request line (the head words, else the
//!   envelope's `method`/`path`), every other field in order, a `content-length` for a non-empty
//!   body the envelope does not state, the blank line and the body;
//! * `emit` sends the message's bytes as the far end reads them, the request target in origin form
//!   (a request naming none takes the dialled target's own path);
//! * `ingest` reads the response: ONE field block first (lower-case names, `content-length` and the
//!   hop-by-hop fields dropped, each name's values together in the order the names first came), with
//!   its status, its reason phrase exactly as sent and its declared length; then its body (by
//!   length, chunked, or to the close); then the end of the stream.
//!
//! Include it with `#[path]` and load it with [`row`].

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::transport::sink::{fill, HeadWords, Owed, Piece};
use busbar_contract::abi::sdk::transport::{form_codes, settings_reading};
use busbar_contract::abi::sdk::{HostBuf, Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::abi::transport::fields::hop_by_hop;
use busbar_contract::abi::transport::{
    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut, DialIn,
    EmitIn, EncodeIn, FaultRow, FinishIn, FramerOut, FramerSink, FramingIn, IngestIn, IoOut,
    ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn, StatusRow,
    TransportTail, WriteIn, CANCEL_NOTHING_MOVED, FACT_DIALS, FAULT_CALLER, FRAME_PIECE_SIZE,
    FRAMING_STREAM, STATUS_AT_FIRST_FRAME,
};
use busbar_contract::plugin::markers::TransportKind;
use busbar_contract::secure::SecureVec;
use busbar_contract::transport::codes::{
    EMIT_TRAILERS, FAULT_HARD, FAULT_NONE, FAULT_RATE_LIMIT, FAULT_TRANSIENT, ROLE_FRAMER,
    SIDE_DIAL, STATUS_CALLER_FAULT, STATUS_FAR_END_FAULT, STATUS_OTHER, STATUS_SUCCESS,
    YIELD_ENDED,
};
use busbar_contract::transport::registry::facts as tfacts;
use busbar_contract::SelectorForm;

/// The plain claim: the entry's first claim.
pub const KEY: &str = "http";
/// The secured claim: the same wire, its bytes secured by the connector before they leave.
const SECURE_KEY: &str = "https";

const SELECTOR_FORMS: &[SelectorForm] = &[
    SelectorForm::ExactPath,
    SelectorForm::PrefixOneLevel,
    SelectorForm::PathPattern,
    SelectorForm::HeaderPresent,
    SelectorForm::HeaderPrefix,
    SelectorForm::PathSuffix,
    SelectorForm::PathContains,
];
const SELECTOR_CODES: [u8; SELECTOR_FORMS.len()] = form_codes(SELECTOR_FORMS);

const FACTS: &[AbiStr] = &[
    abi_str(tfacts::PATH),
    abi_str(tfacts::METHOD),
    abi_str(tfacts::AUTHORITY),
    abi_str(tfacts::PEER),
];

const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY), abi_str(SECURE_KEY)];

const ROW: Claim = {
    let mut c = Claim::EMPTY.with_facts(FACTS);
    c.selector_forms = AbiStr::of_bytes(&SELECTOR_CODES);
    c.egress_selector_forms = abi_str("");
    c.status_namespace = abi_str("http");
    c.status_at = STATUS_AT_FIRST_FRAME;
    c
};

const CLAIMS: &[Claim] = &[ROW, ROW];

/// HTTP's status classes, read alike on both claims.
const CLASSES: [(u32, u32, u8); 3] = [
    (200, 299, STATUS_SUCCESS),
    (400, 499, STATUS_CALLER_FAULT),
    (500, 599, STATUS_FAR_END_FAULT),
];

const STATUS_ROWS: &[StatusRow] = &{
    let mut out = [StatusRow::ZERO; 2 * CLASSES.len()];
    let mut i = 0;
    while i < out.len() {
        let (lo, hi, class) = CLASSES[i % CLASSES.len()];
        out[i] = StatusRow {
            claim: (i / CLASSES.len()) as u32,
            lo,
            hi,
            class: class as u32,
        };
        i += 1;
    }
    out
};

/// What each answer means to the breaker, in HTTP's numbering.
const FAULTS: [(u32, u32, u8); 10] = [
    (400, 400, FAULT_CALLER),
    (401, 401, FAULT_HARD),
    (402, 402, FAULT_CALLER),
    (403, 403, FAULT_HARD),
    (404, 407, FAULT_CALLER),
    (408, 408, FAULT_TRANSIENT),
    (409, 428, FAULT_CALLER),
    (429, 429, FAULT_RATE_LIMIT),
    (430, 499, FAULT_CALLER),
    (500, 599, FAULT_TRANSIENT),
];

const FAULT_ROWS: &[FaultRow] = &{
    let mut out = [FaultRow::ZERO; 2 * FAULTS.len()];
    let mut i = 0;
    while i < out.len() {
        let (lo, hi, fault) = FAULTS[i % FAULTS.len()];
        out[i] = FaultRow {
            claim: (i / FAULTS.len()) as u32,
            lo,
            hi,
            fault: fault as u32,
        };
        i += 1;
    }
    out
};

const TAIL: TransportTail = {
    let mut t = TransportTail::EMPTY
        .with_claim_rows(CLAIMS)
        .with_status_rows(STATUS_ROWS)
        .with_fault_rows(FAULT_ROWS);
    t.role = ROLE_FRAMER;
    t.framing = FRAMING_STREAM;
    t.facts = FACT_DIALS;
    t.frame_piece_size = FRAME_PIECE_SIZE;
    t
};

const STATEMENT: Statement = statement("http-framer-double", "1.6.0", 64)
    .with_kind_tail(&TAIL)
    .with_claims(CLAIM_NAMES);

/// The protocol offer under connection security, in the handshake's ProtocolNameList encoding:
/// this framer speaks HTTP/1.1 alone.
const OFFER: &[u8] = b"\x08http/1.1";

fn class_of(code: u16) -> u8 {
    let code = u32::from(code);
    CLASSES
        .iter()
        .find(|(lo, hi, _)| (*lo..=*hi).contains(&code))
        .map_or(STATUS_OTHER, |(_, _, class)| *class)
}

fn fault_of(code: u16) -> u8 {
    let code = u32::from(code);
    FAULTS
        .iter()
        .find(|(lo, hi, _)| (*lo..=*hi).contains(&code))
        .map_or(FAULT_NONE, |(_, _, fault)| *fault)
}

/// One instance: its framings, by the token it minted.
pub struct Framer {
    framings: Mutex<HashMap<u64, Framing>>,
    next: AtomicU64,
}

type State = Held<Framer>;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn no_settings(settings: &[u8]) -> Result<(), Refusal> {
    settings_reading(settings, &[]).map(drop)
}

impl Life for Framer {
    type Kind = TransportKind;
    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        no_settings(settings)
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        no_settings(settings)?;
        Ok(Self {
            framings: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        no_settings(settings)?;
        Ok(Refreshed::default())
    }
}

/// Where a response stands.
enum Reading {
    /// No request is out: nothing is owed by the far end.
    Idle,
    /// A request is out; its response head has not come whole.
    Head,
    /// `left` body bytes are owed.
    Length(usize),
    /// A chunked body: the next chunk's size line, or `left` bytes of a chunk and its line end.
    Chunked(Chunk),
    /// A body to the far end's close.
    Close,
}

#[derive(Clone, Copy)]
enum Chunk {
    Size,
    Data(usize),
    DataEnd,
    Trailers,
}

/// One dialled connection's HTTP/1.1 machine.
struct Framing {
    /// The dialled target's own path and query: a request naming none takes it.
    dial_path: Vec<u8>,
    /// Bytes owed to the far end (a wiping queue: what is sent is wiped as it leaves).
    out: SecureVec,
    /// A request head still arriving from the host (its request line not yet sent).
    head: Vec<u8>,
    /// Whether the current request's head has gone out (later bytes are its body).
    head_sent: bool,
    /// The far end's bytes not yet read.
    inbound: Vec<u8>,
    /// The far end ended.
    in_ended: bool,
    /// The stream the current exchange runs on.
    stream: u64,
    reading: Reading,
    pieces: VecDeque<Piece<Vec<u8>>>,
}

impl Framing {
    fn dial(target: &[u8]) -> Result<Self, &'static str> {
        let uri = std::str::from_utf8(target)
            .ok()
            .and_then(|t| t.parse::<http::Uri>().ok())
            .ok_or("begin: the target is not a URL")?;
        if uri.authority().is_some_and(|a| a.as_str().contains('@')) {
            return Err("begin: the target carries userinfo; credentials never ride a URL");
        }
        let dial_path = uri
            .path_and_query()
            .map_or("/", http::uri::PathAndQuery::as_str);
        let dial_path = if dial_path.is_empty() { "/" } else { dial_path };
        Ok(Self {
            dial_path: dial_path.as_bytes().to_vec(),
            out: SecureVec::new(),
            head: Vec::new(),
            head_sent: false,
            inbound: Vec::new(),
            in_ended: false,
            stream: 0,
            reading: Reading::Idle,
            pieces: VecDeque::new(),
        })
    }

    /// Bytes of one request message for `stream`; `end` is the host's end of it.
    fn emit(&mut self, stream: u64, bytes: &[u8], end: bool) -> Result<(), &'static str> {
        if !self.head_sent {
            self.stream = stream;
            self.head.extend_from_slice(bytes);
            let Some(at) = find(&self.head, b"\r\n\r\n") else {
                if end && !self.head.is_empty() {
                    return Err("emit: the request message ended inside its head");
                }
                return Ok(());
            };
            let head = std::mem::take(&mut self.head);
            let line_end = find(&head, b"\r\n").unwrap_or(at);
            let mut words = head[..line_end].splitn(3, |b| *b == b' ');
            let (Some(method), Some(target), Some(version)) =
                (words.next(), words.next(), words.next())
            else {
                return Err("emit: the request line is not `method target version`");
            };
            let target = origin_form(target, &self.dial_path);
            self.out.extend_from_slice(method);
            self.out.extend_from_slice(b" ");
            self.out.extend_from_slice(&target);
            self.out.extend_from_slice(b" ");
            self.out.extend_from_slice(version);
            self.out.extend_from_slice(&head[line_end..]);
            self.head_sent = true;
            self.reading = Reading::Head;
        } else {
            self.out.extend_from_slice(bytes);
        }
        if end {
            self.head_sent = false;
        }
        Ok(())
    }

    /// The far end sent `bytes` (`end` = and then ended).
    fn ingest(&mut self, bytes: &[u8], end: bool) {
        self.inbound.extend_from_slice(bytes);
        self.in_ended |= end;
        self.read();
    }

    /// Read as far as the far end's bytes go.
    fn read(&mut self) {
        loop {
            match self.reading {
                Reading::Idle => {
                    self.inbound.clear();
                    return;
                }
                Reading::Head => {
                    let Some(at) = find(&self.inbound, b"\r\n\r\n") else {
                        return self.short("the connection closed before the response head");
                    };
                    let head: Vec<u8> = self.inbound.drain(..at + 4).collect();
                    if let Err(why) = self.response_head(&head[..at + 2]) {
                        self.pieces.push_back(Piece::failure(self.stream, why));
                        self.reading = Reading::Idle;
                    }
                }
                Reading::Length(0) => self.finish(),
                Reading::Length(left) => {
                    if self.inbound.is_empty() {
                        return self.short("the connection closed before the body was whole");
                    }
                    let n = left.min(self.inbound.len());
                    let data: Vec<u8> = self.inbound.drain(..n).collect();
                    self.pieces.push_back(Piece::data(self.stream, data));
                    self.reading = Reading::Length(left - n);
                }
                Reading::Close => {
                    if !self.inbound.is_empty() {
                        let data = std::mem::take(&mut self.inbound);
                        self.pieces.push_back(Piece::data(self.stream, data));
                    }
                    if self.in_ended {
                        self.finish();
                    }
                    return;
                }
                Reading::Chunked(chunk) => {
                    if !self.chunked(chunk) {
                        return self.short("the connection closed inside a chunked body");
                    }
                }
            }
        }
    }

    /// One step of a chunked body: whether it moved.
    fn chunked(&mut self, chunk: Chunk) -> bool {
        match chunk {
            Chunk::Size => {
                let Some(at) = find(&self.inbound, b"\r\n") else {
                    return false;
                };
                let line: Vec<u8> = self.inbound.drain(..at + 2).collect();
                let size = line[..at]
                    .split(|b| *b == b';')
                    .next()
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .and_then(|s| usize::from_str_radix(s.trim(), 16).ok());
                self.reading = match size {
                    Some(0) => Reading::Chunked(Chunk::Trailers),
                    Some(n) => Reading::Chunked(Chunk::Data(n)),
                    None => {
                        self.pieces
                            .push_back(Piece::failure(self.stream, "a chunk size is not hex"));
                        Reading::Idle
                    }
                };
                true
            }
            Chunk::Data(left) => {
                if self.inbound.is_empty() {
                    return false;
                }
                let n = left.min(self.inbound.len());
                let data: Vec<u8> = self.inbound.drain(..n).collect();
                self.pieces.push_back(Piece::data(self.stream, data));
                self.reading = Reading::Chunked(if left == n {
                    Chunk::DataEnd
                } else {
                    Chunk::Data(left - n)
                });
                true
            }
            Chunk::DataEnd => {
                if self.inbound.len() < 2 {
                    return false;
                }
                self.inbound.drain(..2);
                self.reading = Reading::Chunked(Chunk::Size);
                true
            }
            Chunk::Trailers => {
                if self.inbound.starts_with(b"\r\n") {
                    self.inbound.drain(..2);
                } else if let Some(at) = find(&self.inbound, b"\r\n\r\n") {
                    self.inbound.drain(..at + 4);
                } else {
                    return false;
                }
                self.finish();
                true
            }
        }
    }

    /// Nothing more to read now: when the far end has ended, the exchange failed short of whole.
    fn short(&mut self, why: &'static str) {
        if self.in_ended {
            self.pieces.push_back(Piece::failure(self.stream, why));
            self.reading = Reading::Idle;
        }
    }

    /// The response is whole: its stream ends.
    fn finish(&mut self) {
        self.pieces.push_back(Piece::end(self.stream));
        self.reading = Reading::Idle;
    }

    /// Read a response head (its status line and field lines, each ended by CRLF).
    fn response_head(&mut self, head: &[u8]) -> Result<(), &'static str> {
        let mut lines = head
            .split(|b| *b == b'\n')
            .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
            .filter(|l| !l.is_empty());
        let status_line = lines.next().ok_or("the response has no status line")?;
        let mut words = status_line.splitn(3, |b| *b == b' ');
        let version = words.next().unwrap_or_default();
        if !version.starts_with(b"HTTP/1.") {
            return Err("the response is not HTTP/1.x");
        }
        let code = words
            .next()
            .and_then(|c| std::str::from_utf8(c).ok())
            .and_then(|c| c.parse::<u16>().ok())
            .filter(|c| (100..=999).contains(c))
            .ok_or("the response status is not a number")?;
        let reason = words.next().unwrap_or_default().to_vec();
        if (100..200).contains(&code) && code != 101 {
            // An interim answer: the final head follows.
            return Ok(());
        }
        // Each name lower-cased, its values together, in the order the names first came.
        let mut named: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
        for line in lines {
            let Some(colon) = line.iter().position(|b| *b == b':') else {
                return Err("a response field line has no colon");
            };
            let name = line[..colon].to_ascii_lowercase();
            let value = line[colon + 1..].trim_ascii().to_vec();
            match named.iter_mut().find(|(n, _)| *n == name) {
                Some((_, values)) => values.push(value),
                None => named.push((name, vec![value])),
            }
        }
        let all = |name: &[u8]| {
            named
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_slice())
                .unwrap_or_default()
        };
        let chunked = all(b"transfer-encoding")
            .iter()
            .any(|v| v.to_ascii_lowercase().ends_with(b"chunked"));
        let declared = if all(b"transfer-encoding").is_empty() {
            declared_len(all(b"content-length"))
        } else {
            None
        };
        let nominated: Vec<&[u8]> = all(b"connection").iter().map(Vec::as_slice).collect();
        let mut block = Vec::new();
        for (name, values) in &named {
            let Ok(text) = std::str::from_utf8(name) else {
                continue;
            };
            if text == "content-length" || hop_by_hop(text, nominated.iter().copied()) {
                continue;
            }
            for value in values {
                block.extend_from_slice(name);
                block.extend_from_slice(b": ");
                block.extend_from_slice(value);
                block.extend_from_slice(b"\r\n");
            }
        }
        let bodiless = code == 204 || code == 304 || (100..200).contains(&code);
        let reading = if bodiless {
            Reading::Length(0)
        } else if chunked {
            Reading::Chunked(Chunk::Size)
        } else if let Some(n) = declared {
            Reading::Length(usize::try_from(n).map_err(|_| "the declared length is too big")?)
        } else {
            Reading::Close
        };
        let empty = matches!(reading, Reading::Length(0));
        self.pieces.push_back(Piece {
            status: Some(code),
            declared_len: declared.filter(|n| *n == 0 || !empty),
            head: (!reason.is_empty()).then(|| HeadWords::reason(reason)),
            ..Piece::fields(self.stream, block)
        });
        self.reading = reading;
        Ok(())
    }
}

/// The body length a head's `content-length` lines declare: one number they all state.
fn declared_len(values: &[Vec<u8>]) -> Option<u64> {
    let mut one = None;
    for value in values {
        for s in value.split(|b| *b == b',') {
            let s = std::str::from_utf8(s.trim_ascii()).ok()?;
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n = s.parse::<u64>().ok()?;
            if one.is_some_and(|m| m != n) {
                return None;
            }
            one = Some(n);
        }
    }
    one
}

/// A request target in origin form: an absolute one cut to its path and query, an empty one the
/// dialled target's own path.
fn origin_form(target: &[u8], dial_path: &[u8]) -> Vec<u8> {
    if target.is_empty() {
        return dial_path.to_vec();
    }
    if target.starts_with(b"http://") || target.starts_with(b"https://") {
        let after = target
            .iter()
            .position(|b| *b == b':')
            .map_or(0, |at| at + 3);
        let rest = &target[after..];
        return match rest.iter().position(|b| *b == b'/') {
            Some(at) => rest[at..].to_vec(),
            None => b"/".to_vec(),
        };
    }
    target.to_vec()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

impl Owed<Vec<u8>> for Framing {
    fn wire_into(&mut self, into: &mut HostBuf<'_, u8>) {
        let n = self
            .out
            .len()
            .min(into.cap().saturating_sub(into.written()));
        into.extend(&self.out[..n]);
        self.out.consume(n);
    }
    fn wire_pending(&self) -> bool {
        !self.out.is_empty()
    }
    fn pieces(&mut self) -> &mut VecDeque<Piece<Vec<u8>>> {
        &mut self.pieces
    }
    fn next_deadline(&self) -> Option<u64> {
        None
    }
    fn ended(&self) -> bool {
        self.in_ended && matches!(self.reading, Reading::Idle)
    }
    fn rest(bytes: &mut Vec<u8>, at: usize) {
        bytes.drain(..at);
    }
}

/// Run `op` on framing `token`, then hand the host what it owes.
fn with(
    inst: &Instance<'_, State, TransportKind>,
    token: u64,
    sink: Lent<'_, FramerSink>,
    o: &mut Out<'_, FramerOut>,
    op: impl FnOnce(&mut Framing) -> Result<(), &'static str>,
) -> Outcome {
    let Some(framer) = inst.get().map(Held::life) else {
        return o.fail(Refusal::failed("no open instance"));
    };
    let mut framings = lock(&framer.framings);
    let Some(framing) = framings.get_mut(&token) else {
        return o.fail(Refusal::failed("no such framing"));
    };
    if let Err(why) = op(framing) {
        return o.fail(Refusal::failed(why));
    }
    fill(framing, sink, o, class_of, fault_of);
    Outcome::Ready
}

busbar_contract::not_served! {
    state: State, role: "http framer double";
    NoListen(ListenIn => ListenOut) "listen";
    NoAccept(AcceptIn => AcceptOut) "accept";
    NoDial(DialIn => ConnOut) "dial";
    NoRead(ReadIn => IoOut) "read";
    NoWrite(WriteIn => IoOut) "write";
    NoFlush(ConnIn => busbar_contract::abi::mechanism::call::OutHead) "flush";
    NoShut(ShutIn => busbar_contract::abi::mechanism::call::OutHead) "shut";
    NoArrival(ArrivalIn => ArrivalOut) "arrival";
    NoRefuse(RefuseIn => FramerOut) "refuse";
    NoDetach(FramingIn => FramerOut) "detach";
    NoAdopt(AdoptIn => FramerOut) "adopt";
}

/// `locate`: where a target is, its offer and the framer's own head lines.
pub struct Locate;
impl SafeSlot for Locate {
    type Kind = TransportKind;
    type In = LocateIn;
    type Out = LocateOut;
    type State = State;
    fn call(
        _: Instance<'_, State, TransportKind>,
        i: Lent<'_, LocateIn>,
        mut o: Out<'_, LocateOut>,
    ) -> Outcome {
        let (mut a, mut n, mut l) = (i.authority_buf(), i.name_buf(), i.alpn_buf());
        let mut d = i.defaults_buf();
        let secure = if i.accept == 1 {
            true
        } else {
            let Some(uri) = i
                .target()
                .as_str()
                .ok()
                .and_then(|t| t.parse::<http::Uri>().ok())
            else {
                return o.fail(Refusal::failed("locate: the target is not a URL"));
            };
            if uri.authority().is_some_and(|x| x.as_str().contains('@')) {
                return o.fail(Refusal::failed(
                    "locate: the target carries userinfo; credentials never ride a URL",
                ));
            }
            let secure = match uri.scheme_str() {
                Some("https") => true,
                Some("http") => false,
                _ => {
                    return o.fail(Refusal::failed(
                        "locate: the target's scheme is not http or https",
                    ))
                }
            };
            let Some(host) = uri.host() else {
                return o.fail(Refusal::failed("locate: the target names no host"));
            };
            let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            let name = bare.to_ascii_lowercase();
            if bare.contains(':') {
                a.extend(format!("[{bare}]:{port}").as_bytes());
            } else {
                a.extend(format!("{bare}:{port}").as_bytes());
            }
            n.extend(name.as_bytes());
            d.extend(b"accept: */*\r\n");
            let default_port = if secure { 443 } else { 80 };
            let host_line = match uri.port_u16().filter(|p| *p != default_port) {
                Some(p) => format!("host: {}:{p}\r\n", host.to_ascii_lowercase()),
                None => format!("host: {}\r\n", host.to_ascii_lowercase()),
            };
            d.extend(host_line.as_bytes());
            secure
        };
        if secure {
            l.extend(OFFER);
        }
        o.set(|x| &x.secure, u32::from(secure));
        o.set(|x| &x.has_name, u32::from(n.asked() != 0));
        let short = !(a.fits() && n.fits() && l.fits() && d.fits());
        let (aw, and) = a.settle(short);
        let (nw, nnd) = n.settle(short);
        let (lw, lnd) = l.settle(short);
        let (dw, dnd) = d.settle(short);
        o.set(|x| &x.authority_written, aw as u64);
        o.set(|x| &x.authority_needed, and as u64);
        o.set(|x| &x.name_written, nw as u64);
        o.set(|x| &x.name_needed, nnd as u64);
        o.set(|x| &x.alpn_written, lw as u64);
        o.set(|x| &x.alpn_needed, lnd as u64);
        o.set(|x| &x.states_length, 1u8);
        o.set(|x| &x.defaults_written, dw as u64);
        o.set(|x| &x.defaults_needed, dnd as u64);
        if short {
            return o.fail(Refusal::failed("locate: a host buffer is too small"));
        }
        Outcome::Ready
    }
}

/// `begin`: a dialled connection's framing.
pub struct Begin;
impl SafeSlot for Begin {
    type Kind = TransportKind;
    type In = BeginIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, BeginIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(framer) = inst.get().map(Held::life) else {
            return o.fail(Refusal::failed("begin: no open instance"));
        };
        if i.side != SIDE_DIAL {
            return o.fail(Refusal::refused(
                "begin: the http framer double frames dialled connections",
            ));
        }
        let agreed = i.facts().map_or(&[][..], |f| f.agreed_protocol().bytes());
        if !matches!(agreed, b"" | b"http/1.1") {
            return o.fail(Refusal::refused(
                "begin: the agreed protocol is not http/1.1",
            ));
        }
        let mut framing = match Framing::dial(i.target().bytes()) {
            Ok(framing) => framing,
            Err(why) => return o.fail(Refusal::failed(why)),
        };
        fill(&mut framing, i.sink(), &mut o, class_of, fault_of);
        let token = framer.next.fetch_add(1, Ordering::Relaxed);
        lock(&framer.framings).insert(token, framing);
        o.set(|x| &x.framing, token);
        Outcome::Ready
    }
}

/// `ingest`: the far end's bytes.
pub struct Ingest;
impl SafeSlot for Ingest {
    type Kind = TransportKind;
    type In = IngestIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, IngestIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let (bytes, end) = (i.bytes(), i.end != 0);
        with(&inst, i.framing, i.sink(), &mut o, |f| {
            f.ingest(bytes, end);
            Ok(())
        })
    }
}

/// `emit`: a request message's bytes.
pub struct Emit;
impl SafeSlot for Emit {
    type Kind = TransportKind;
    type In = EmitIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, EmitIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        if i.flags & EMIT_TRAILERS != 0 {
            return o.fail(Refusal::refused(
                "emit: a dialled HTTP/1.1 request carries no trailers here",
            ));
        }
        let (bytes, end, stream) = (i.bytes(), i.end_of_frame != 0, i.stream);
        with(&inst, i.framing, i.sink(), &mut o, |f| {
            f.emit(stream, bytes, end)
        })
    }
}

/// `timer`: hand the host what is owed.
pub struct Timer;
impl SafeSlot for Timer {
    type Kind = TransportKind;
    type In = FramingIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, FramingIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        with(&inst, i.framing, i.sink(), &mut o, |_| Ok(()))
    }
}

/// `finish`: the framing is let go.
pub struct Finish;
impl SafeSlot for Finish {
    type Kind = TransportKind;
    type In = FinishIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        inst: Instance<'_, State, TransportKind>,
        i: Lent<'_, FinishIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let Some(framer) = inst.get().map(Held::life) else {
            return o.fail(Refusal::failed("finish: no open instance"));
        };
        if lock(&framer.framings).remove(&i.framing).is_none() {
            return o.fail(Refusal::failed("finish: no such framing"));
        }
        o.set(|x| &x.yielded.flags, YIELD_ENDED);
        Outcome::Ready
    }
}

/// Whether `name` is an HTTP field-name token.
fn is_token(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

/// `encode`: one HTTP/1.1 request message into the wire buffer.
pub struct Encode;
impl SafeSlot for Encode {
    type Kind = TransportKind;
    type In = EncodeIn;
    type Out = FramerOut;
    type State = State;
    fn call(
        _: Instance<'_, State, TransportKind>,
        i: Lent<'_, EncodeIn>,
        mut o: Out<'_, FramerOut>,
    ) -> Outcome {
        let fields: Vec<(&[u8], &[u8])> = i
            .fields()
            .iter()
            .map(|f| (f.name().bytes(), f.value().bytes()))
            .collect();
        let field = |name: &[u8]| {
            fields
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| *v)
        };
        let word_method = i.method().bytes();
        let word_target = i.target().bytes();
        let method = if word_method.is_empty() {
            field(b"method").unwrap_or(b"POST")
        } else {
            word_method
        };
        let target = if word_target.is_empty() {
            field(b"path").unwrap_or_default()
        } else {
            word_target
        };
        let clean = |v: &[u8]| !v.iter().any(|b| matches!(b, b'\r' | b'\n' | 0));
        if !is_token(method) || !clean(target) || target.contains(&b' ') {
            return o.fail(Refusal::failed(
                "encode: the envelope cannot be expressed on this wire",
            ));
        }
        let body = i.body();
        let mut wire = Vec::with_capacity(body.len() + 256);
        wire.extend_from_slice(method);
        wire.push(b' ');
        wire.extend_from_slice(target);
        wire.extend_from_slice(b" HTTP/1.1\r\n");
        let mut states_length = false;
        for (name, value) in &fields {
            if name.eq_ignore_ascii_case(b"method") || name.eq_ignore_ascii_case(b"path") {
                continue;
            }
            if !is_token(name) || !clean(value) {
                return o.fail(Refusal::failed(
                    "encode: the envelope cannot be expressed on this wire",
                ));
            }
            states_length |= name.eq_ignore_ascii_case(b"content-length")
                || name.eq_ignore_ascii_case(b"transfer-encoding");
            wire.extend_from_slice(name);
            wire.extend_from_slice(b": ");
            wire.extend_from_slice(value);
            wire.extend_from_slice(b"\r\n");
        }
        if !body.is_empty() && !states_length {
            wire.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
        }
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(body);
        let mut out = i.sink().wire();
        if wire.len() > out.cap() {
            return o.fail(Refusal::failed(
                "encode: the rendered message is larger than the wire buffer",
            ));
        }
        out.extend(&wire);
        o.set(|x| &x.yielded.wire_len, out.written() as u64);
        Outcome::Ready
    }
}

busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: life(Framer),
    kind_ops: {
        listen: Safe<NoListen>,
        accept: Safe<NoAccept>,
        dial: Safe<NoDial>,
        read: Safe<NoRead>,
        write: Safe<NoWrite>,
        flush: Safe<NoFlush>,
        shut: Safe<NoShut>,
        arrival: Safe<NoArrival>,
        locate: Safe<Locate>,
        begin: Safe<Begin>,
        ingest: Safe<Ingest>,
        emit: Safe<Emit>,
        encode: Safe<Encode>,
        refuse: Safe<NoRefuse>,
        finish: Safe<Finish>,
        detach: Safe<NoDetach>,
        adopt: Safe<NoAdopt>,
        timer: Safe<Timer>,
    },
}

/// The framer's linked row: its door and the Statement it renders, for `load_linked`.
pub fn row() -> busbar_plugin_loader::dispatch::LinkedRow {
    busbar_plugin_loader::dispatch::LinkedRow::of_macro(MACRO_DOOR)
        .expect("the HTTP framer double states itself")
}
