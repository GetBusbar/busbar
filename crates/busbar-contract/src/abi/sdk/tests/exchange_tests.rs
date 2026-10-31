// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`exchange`] and [`send_and_ack`] through a scripted connector host: every service pends once
//! and completes on the host's side, the op's re-entry re-issues each handle and reads the stored
//! result, and no service ever runs twice. The host records what the framer was handed.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::Mutex;

use super::*;
use crate::abi::host::conn::connector::{
    service, ConnectorSlots, FactsIn, IoIn, ReplyIn, RequestIn, StreamFacts, SERVICES,
};
use crate::abi::host::service::{ServiceHead, ServiceOut};
use crate::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use crate::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use crate::abi::sdk::conn::Host;

/// One scripted reply piece: `(kind, code, reason, fields, body)`.
type Scripted = (u32, u32, &'static [u8], &'static [u8], &'static [u8]);

/// A scripted piece (the byte strings coerce to slices here).
fn piece(
    kind: u32,
    code: u32,
    reason: &'static [u8],
    fields: &'static [u8],
    body: &'static [u8],
) -> Scripted {
    (kind, code, reason, fields, body)
}

/// A scripted read the host answers FAILED (the far end went away mid-reply), in place of a piece.
const READ_FAILS: u32 = u32::MAX - 1;

/// What the framer was handed, as the host saw it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Framed {
    method: Vec<u8>,
    target: Vec<u8>,
    fields: Vec<u8>,
    timeout_ms: u64,
    body: Vec<u8>,
    ended: bool,
}

/// The scripted host: its stored results per handle `seq`, its runs per service, the reply it
/// plays, what the framer was handed, and whether the stream is framed.
#[derive(Default)]
struct Script {
    stored: HashMap<u32, (Outcome, u64, u64)>,
    runs: HashMap<u32, u32>,
    reads: usize,
    reply: Vec<Scripted>,
    framed: Framed,
    unframed: bool,
    /// The registration each ESTABLISH named, in order (`None` = an absent member).
    members: Vec<Option<Vec<u8>>>,
    /// Streams established and not closed: the host's held streams.
    held: i64,
    /// Every service the host ran (a replay runs none), in order.
    ops: Vec<u32>,
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
/// One test at a time: the script is process-wide.
static SERIAL: Mutex<()> = Mutex::new(());
/// A scripted read the host FAILS (the stream reset under it), in place of a reply piece.
const RESET: u32 = u32::MAX;
/// The host's refusal text for a request on a stream that is not framed.
const NOT_FRAMED: &str = "the stream is not framed: write its bytes";

fn answer(out: *mut ServiceOut, o: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    let out = unsafe { &mut *out };
    out.outcome = RawOutcome::of(o);
    out.value = value;
    out.len = len;
    if o == Outcome::Refused {
        out.error = AbiStr {
            ptr: NOT_FRAMED.as_ptr(),
            len: NOT_FRAMED.len(),
        };
    }
    RawOutcome::of(o)
}

/// Write one reply piece the way a connector host does: its bytes (reason, then the field block,
/// or the body) into the plugin's buffer, its descriptor into the plugin's slot.
fn play(io: ReplyIn, (kind, code, reason, fields, body): Scripted) -> u64 {
    let mut bytes = Vec::new();
    let mut piece = ReplyPiece {
        kind,
        code,
        ..ReplyPiece::default()
    };
    if kind == REPLY_BODY {
        bytes.extend_from_slice(body);
    } else {
        piece.reason = span(0, reason.len());
        bytes.extend_from_slice(reason);
        piece.fields = span(bytes.len(), fields.len());
        bytes.extend_from_slice(fields);
    }
    assert!(bytes.len() <= io.len);
    // SAFETY: `io.buf` holds `io.len` writable bytes and `io.piece` a writable descriptor, both
    // the SDK's parked ones, until the read completes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), io.buf, bytes.len());
        io.piece.write(piece);
    }
    bytes.len() as u64
}

/// Take one request piece the way a framer does: read its descriptor and the bytes it names.
fn take(framed: &mut Framed, io: RequestIn) -> u64 {
    // SAFETY: the SDK's parked descriptor and bytes, valid until the write completes.
    let (p, bytes) = unsafe { (*io.piece, std::slice::from_raw_parts(io.buf, io.len)) };
    match p.kind {
        REQUEST_HEAD => {
            framed.method = spanned(bytes, p.method).to_vec();
            framed.target = spanned(bytes, p.target).to_vec();
            framed.fields = spanned(bytes, p.fields).to_vec();
            framed.timeout_ms = p.timeout_ms;
        }
        REQUEST_BODY => framed.body.extend_from_slice(bytes),
        REQUEST_END => framed.ended = true,
        k => panic!("an unknown request piece {k}"),
    }
    io.len as u64
}

/// One scripted service: the first issue of a handle runs it (and pends, or refuses at once); a
/// re-issue answers the stored result.
fn serve(op: u32, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: every service `in` leads with a `ServiceHead`.
    let head = unsafe { *input.cast::<ServiceHead>() };
    assert_eq!(head.op, op);
    let seq = head.handle.seq;
    let mut g = SCRIPT.lock().unwrap();
    let s = g.as_mut().expect("a script");
    if let Some(&(o, v, l)) = s.stored.get(&seq) {
        return answer(out, o, v, l);
    }
    *s.runs.entry(seq).or_default() += 1;
    s.ops.push(op);
    if op == service::READ_REPLY && s.reply.get(s.reads).map(|p| p.0) == Some(READ_FAILS) {
        s.stored.insert(seq, (Outcome::Failed, 0, 0));
        return answer(out, Outcome::Pending, 0, 0);
    }
    let (value, len) = match op {
        service::ESTABLISH => {
            // SAFETY: an `EstablishIn` (the SDK states its whole size).
            let i = unsafe { *input.cast::<crate::abi::host::conn::connector::EstablishIn>() };
            s.held += 1;
            s.members.push((!i.member.ptr.is_null()).then(|| {
                // SAFETY: the SDK's own string, live for the call.
                unsafe { std::slice::from_raw_parts(i.member.ptr, i.member.len) }.to_vec()
            }));
            (7, 0)
        }
        service::WRITE => {
            // SAFETY: an `IoIn`.
            let io = unsafe { *input.cast::<IoIn>() };
            (0, io.len as u64)
        }
        service::WRITE_REQUEST if s.unframed => {
            s.stored.insert(seq, (Outcome::Refused, 0, 0));
            return answer(out, Outcome::Refused, 0, 0);
        }
        service::WRITE_REQUEST => {
            // SAFETY: a `RequestIn`.
            let io = unsafe { *input.cast::<RequestIn>() };
            (0, take(&mut s.framed, io))
        }
        service::READ_REPLY => {
            // SAFETY: a `ReplyIn`.
            let io = unsafe { *input.cast::<ReplyIn>() };
            let piece = s.reply[s.reads.min(s.reply.len() - 1)];
            s.reads += 1;
            if piece.0 == RESET {
                s.stored.insert(seq, (Outcome::Failed, 0, 0));
                return answer(out, Outcome::Pending, 0, 0);
            }
            (0, play(io, piece))
        }
        service::CLOSE => {
            s.held -= 1;
            (0, 0)
        }
        _ => (0, 0),
    };
    s.stored.insert(seq, (Outcome::Ready, value, len));
    answer(out, Outcome::Pending, 0, 0)
}

/// The C ABI, spelled once for every slot below: each spelling of its literal is a Law 0 hit (the
/// scan reads it as a secret instance's id).
macro_rules! slot {
    ($(#[$m:meta])* fn $name:ident($i:ident, $o:ident) $body:block) => {
        $(#[$m])*
        extern "C" fn $name(_: HostCtx, $i: *const c_void, $o: *mut ServiceOut) -> RawOutcome $body
    };
    ($name:ident, $op:expr) => {
        slot! {
            fn $name(i, o) {
                serve($op, i, o)
            }
        }
    };
}
slot!(establish, service::ESTABLISH);
slot!(write, service::WRITE);
slot!(write_request, service::WRITE_REQUEST);
slot!(read_reply, service::READ_REPLY);
slot!(close, service::CLOSE);

/// The far end's key pin the scripted host's `FACTS` reports.
const OBSERVED_PIN: &str = "c2NyaXB0ZWQga2V5";

slot! {
    /// `FACTS`, as a connector host answers it on a stream already dialled: READY at once with the
    /// facts written on a handle's first issue; a re-issue answers the stored outcome and writes
    /// nothing (the replay rule).
    fn facts(i, o) {
        // SAFETY: a `FactsIn`.
        let io = unsafe { *i.cast::<FactsIn>() };
        assert_eq!(io.head.op, service::FACTS);
        let seq = io.head.handle.seq;
        let mut g = SCRIPT.lock().unwrap();
        let s = g.as_mut().expect("a script");
        if s.stored.contains_key(&seq) {
            return answer(o, Outcome::Ready, 0, 0);
        }
        *s.runs.entry(seq).or_default() += 1;
        s.stored.insert(seq, (Outcome::Ready, 0, 0));
        // SAFETY: the SDK's facts slot, live for the call.
        unsafe {
            io.facts.write(StreamFacts {
                size: std::mem::size_of::<StreamFacts>() as u32,
                secure: 1,
                endpoint: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                agreed_protocol: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                peer_cert_hash: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                peer_key_pin: AbiStr {
                    ptr: OBSERVED_PIN.as_ptr(),
                    len: OBSERVED_PIN.len(),
                },
                client_identity: 1,
                _reserved: 0,
            });
        }
        answer(o, Outcome::Ready, 0, 0)
    }
}

static SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: Some(write),
    upgrade_secure: None,
    facts: Some(facts),
    checkout: None,
    checkin: None,
    close: Some(close),
    random: None,
    identity: None,
    read_reply: Some(read_reply),
    write_request: Some(write_request),
};

fn host() -> Host {
    Host::of(&HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &SLOTS,
        services: std::ptr::null(),
        io: std::ptr::null(),
    })
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 1,
};

/// What one run of an op answered, how many entries it took, how often each service ran, and what
/// the framer was handed.
struct Run<T> {
    answered: Result<T, ConnFailure>,
    entries: u32,
    runs: HashMap<u32, u32>,
    framed: Framed,
    /// The registration each ESTABLISH named.
    members: Vec<Option<Vec<u8>>>,
    /// The exchange's state once it completed.
    state: Exchange,
    /// Streams the host still holds when the op answered.
    held: i64,
    /// Every service the host ran, in order.
    ops: Vec<u32>,
}

/// Run the op to completion under `reply`: a fresh connector each entry, the same parked state.
fn run<T>(
    reply: Vec<Scripted>,
    unframed: bool,
    mut state: Exchange,
    budget_ms: Option<u64>,
    body: impl Fn(&mut Connector<'_>, &mut Exchange) -> Answer<T>,
) -> Run<T> {
    *SCRIPT.lock().unwrap() = Some(Script {
        reply,
        unframed,
        ..Script::default()
    });
    let h = host();
    let mut entries = 0;
    let answered = loop {
        entries += 1;
        assert!(entries < 40, "the op never completed");
        let c = h.connector(TICKET);
        let mut c = match budget_ms {
            Some(b) => c.within(b),
            None => c,
        };
        if let Poll::Ready(r) = body(&mut c, &mut state) {
            break r;
        }
    };
    let s = SCRIPT.lock().unwrap().take().unwrap();
    Run {
        answered,
        entries,
        runs: s.runs,
        framed: s.framed,
        members: s.members,
        state,
        held: s.held,
        ops: s.ops,
    }
}

fn post() -> Request {
    Request {
        method: b"POST".to_vec(),
        target: b"/hook?x=1".to_vec(),
        fields: vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"x-busbar".to_vec(), b"1".to_vec()),
        ],
        body: br#"{"a":1}"#.to_vec(),
        timeout_ms: 0,
    }
}

fn http_reply() -> Vec<Scripted> {
    vec![
        piece(
            REPLY_HEAD,
            200,
            b"Totally Fine",
            b"x-a: 1\r\nx-b: two\r\n",
            b"",
        ),
        piece(REPLY_BODY, 0, b"", b"", b"hello "),
        piece(REPLY_BODY, 0, b"", b"", b"world"),
        piece(REPLY_END, 0, b"", b"", b""),
    ]
}

/// RED: the request's head (method, target, fields) reaches the framer; its body streams and END
/// ends it; the reply's reason crosses exactly as the peer sent it, a non-canonical phrase
/// included; no service runs twice.
#[test]
fn a_request_reaches_the_framer_and_the_reply_comes_back_as_sent() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        http_reply(),
        false,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/hook")),
    );
    let reply = r.answered.expect("the exchange completes");
    assert_eq!(
        r.framed,
        Framed {
            method: b"POST".to_vec(),
            target: b"/hook?x=1".to_vec(),
            fields: b"content-type: application/json\r\nx-busbar: 1\r\n".to_vec(),
            timeout_ms: 0,
            body: br#"{"a":1}"#.to_vec(),
            ended: true,
        }
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.reason.as_deref(), Some(&b"Totally Fine"[..]));
    assert_eq!(
        reply.fields,
        vec![
            (b"x-a".to_vec(), b"1".to_vec()),
            (b"x-b".to_vec(), b"two".to_vec())
        ]
    );
    assert_eq!(reply.body, b"hello world");
    // establish, head, body, end, four reads, close: nine services, each run once, and every one
    // pended once, so the op entered once more than it made services.
    assert_eq!(r.runs.len(), 9);
    assert!(r.runs.values().all(|&n| n == 1), "{:?}", r.runs);
    assert_eq!(r.entries, 10);
}

/// RED: the request's timeout is clamped to what is left of the op's deadline; `0` asks for all of
/// it.
#[test]
fn a_request_timeout_is_clamped_to_the_ops_deadline() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let long = Request {
        timeout_ms: 60_000,
        ..post()
    };
    let r = run(
        http_reply(),
        false,
        Exchange::request(long).unwrap(),
        Some(10_000),
        |c, st| exchange(c, st, 0, None),
    );
    assert!(r.answered.is_ok());
    assert_eq!(r.framed.timeout_ms, 10_000, "clamped");
    let short = Request {
        timeout_ms: 2_000,
        ..post()
    };
    let r = run(
        http_reply(),
        false,
        Exchange::request(short).unwrap(),
        Some(10_000),
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(r.framed.timeout_ms, 2_000, "within the budget");
    let r = run(
        http_reply(),
        false,
        Exchange::request(post()).unwrap(),
        Some(10_000),
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(r.framed.timeout_ms, 10_000, "0 = the op's deadline");
}

/// RED: a stream that is not framed refuses a request piece, and the host's text reaches the
/// plugin verbatim.
#[test]
fn a_stream_that_is_not_framed_refuses_a_request() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        http_reply(),
        true,
        Exchange::request(post()).unwrap(),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(
        r.answered,
        Err(ConnFailure::Refused(NOT_FRAMED.to_string()))
    );
}

/// RED: a pseudo-field (or a line break) in a request's fields is refused before anything is sent.
#[test]
fn a_pseudo_field_in_a_request_is_refused() {
    let pseudo = Request {
        fields: vec![(b":path".to_vec(), b"/x".to_vec())],
        ..post()
    };
    assert!(matches!(
        Exchange::request(pseudo),
        Err(ConnFailure::Refused(t)) if t.contains("pseudo-field")
    ));
    let split = Request {
        fields: vec![(b"x-a".to_vec(), b"1\r\nx-b: 2".to_vec())],
        ..post()
    };
    assert!(matches!(
        Exchange::request(split),
        Err(ConnFailure::Refused(t)) if t.contains("line break")
    ));
}

/// RED: a pure-send transport's ack FAILURE (a code and the peer's text) reaches the plugin
/// verbatim, as an answer, never as a lost request.
#[test]
fn a_pure_send_acks_its_failure_with_a_code_and_the_peers_text() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reply = vec![piece(REPLY_ACK, 550, b"mailbox unavailable", b"", b"")];
    let r = run(
        reply,
        false,
        Exchange::send(b"ping".to_vec()),
        None,
        |c, st| send_and_ack(c, st, 0, None),
    );
    assert_eq!(
        r.answered,
        Ok(Ack {
            code: 550,
            reason: b"mailbox unavailable".to_vec()
        })
    );
    assert!(r.runs.values().all(|&n| n == 1));
}

/// RED: a transport that answers a read with no reply piece breaks the every-request-is-acked
/// rule: the plugin is told so, never left without an answer.
#[test]
fn a_transport_that_never_acks_is_a_conformance_failure() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        vec![piece(0, 0, b"", b"", b"")],
        false,
        Exchange::send(b"ping".to_vec()),
        None,
        |c, st| send_and_ack(c, st, 0, None),
    );
    assert!(
        matches!(&r.answered, Err(ConnFailure::Failed(t)) if t.contains("every request is acked")),
        "{:?}",
        r.answered
    );
}

/// THE TRANSPORT PIN, PLUGIN SIDE (the transport pin, ARCHITECT 2026-10-03): an exchange that asks reads its stream's facts
/// once the reply ended, before the close — the far end's key and whether busbar presented its
/// client identity — and keeps them across the op's re-entries, whose replayed `FACTS` writes
/// nothing; no service runs twice. An exchange that does not ask makes no `FACTS` at all.
#[test]
fn an_observing_exchange_reads_its_streams_facts_before_the_close() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        http_reply(),
        false,
        Exchange::request(post()).expect("a request").observing(),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/hook")),
    );
    assert_eq!(r.answered.expect("the exchange completes").status, 200);
    let observed = r.state.observed().expect("the facts were read");
    assert_eq!(observed.peer_key_pin.as_deref(), Some(OBSERVED_PIN));
    assert!(observed.client_identity && observed.secure);
    // establish, head, body, end, four reads, facts, close: ten services, each run once.
    assert_eq!(r.runs.len(), 10);
    assert!(r.runs.values().all(|&n| n == 1), "{:?}", r.runs);

    let plain = run(
        http_reply(),
        false,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/hook")),
    );
    assert!(plain.state.observed().is_none());
    assert_eq!(plain.runs.len(), 9, "no facts asked, none made");
}

/// RED (SEAM-4p): an exchange that names a REGISTRATION (`Exchange::as_member`) establishes its
/// stream naming it (`EstablishIn::member`), so the host's per-registration private reach applies
/// to its dial; one that names none establishes naming none.
#[test]
fn an_exchange_names_its_registration_on_its_establish() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let named = run(
        http_reply(),
        false,
        Exchange::request(post())
            .expect("a request")
            .as_member("inside"),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/hook")),
    );
    named.answered.expect("the exchange completes");
    assert_eq!(named.members, vec![Some(b"inside".to_vec())]);
    let plain = run(
        http_reply(),
        false,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/hook")),
    );
    plain.answered.expect("the exchange completes");
    assert_eq!(plain.members, vec![None], "no registration named");
}

/// `framed_fields` reads the fields back off the head the exchange will send, in order, and a raw
/// send frames none: what the far end is handed, never a copy of the caller's request.
#[test]
fn the_framed_fields_are_the_head_the_exchange_sends() {
    let request = Request {
        method: b"POST".to_vec(),
        target: b"/notify".to_vec(),
        fields: vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"authorization".to_vec(), b"Bearer abc".to_vec()),
        ],
        body: b"{}".to_vec(),
        timeout_ms: 0,
    };
    let ex = Exchange::request(request).expect("the request frames");
    assert_eq!(
        ex.framed_fields(),
        vec![
            (&b"content-type"[..], &b"application/json"[..]),
            (&b"authorization"[..], &b"Bearer abc"[..]),
        ]
    );
    assert!(Exchange::send(b"raw".to_vec()).framed_fields().is_empty());
}

/// A reply of two body pieces, `first` then `second` bytes long.
fn body_reply(first: usize, second: usize) -> Vec<Scripted> {
    let body = |n: usize| -> &'static [u8] { Box::leak(vec![b'x'; n].into_boxed_slice()) };
    vec![
        piece(REPLY_HEAD, 200, b"", b"", b""),
        piece(REPLY_BODY, 0, b"", b"", body(first)),
        piece(REPLY_BODY, 0, b"", b"", body(second)),
        piece(REPLY_END, 0, b"", b"", b""),
    ]
}

/// RED: a reply whose body passes the exchange's lowered limit is refused as one past `REPLY_MAX`
/// is: the same failure, the same text.
#[test]
fn a_reply_over_the_exchanges_limit_is_refused() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        body_reply(60, 41),
        false,
        Exchange::request(post())
            .expect("a request")
            .reply_limit(100),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(
        r.answered.expect_err("the reply passes the limit"),
        ConnFailure::Failed(REPLY_OVER_BOUND.to_string())
    );
}

/// RED: a reply whose body is exactly the limit passes whole.
#[test]
fn a_reply_at_the_exchanges_limit_passes() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        body_reply(60, 40),
        false,
        Exchange::request(post())
            .expect("a request")
            .reply_limit(100),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(r.answered.expect("at the limit").body.len(), 100);
}

/// The op's instance, as [`Op`] parks on it: one parked exchange, on [`TICKET`].
#[derive(Default)]
struct Parked(std::cell::RefCell<Option<Box<Exchange>>>);

impl Parks for Parked {
    fn ticket(&self) -> Ticket {
        TICKET
    }
    fn park(&self, exchange: Exchange) {
        *self.0.borrow_mut() = Some(Box::new(exchange));
    }
    fn resume(&self) -> Option<Box<Exchange>> {
        self.0.borrow_mut().take()
    }
}

/// Run [`Op::exchange_bounded`] under `reply` to completion: re-entered from the top while it
/// pends, as the op's wake re-enters it. What it answered, and how often it built its request.
fn op_bounded(reply: Vec<Scripted>, limit: usize) -> (Result<ExchangeResponse, ConnFailure>, u32) {
    *SCRIPT.lock().unwrap() = Some(Script {
        reply,
        ..Script::default()
    });
    let h = host();
    let parked = Parked::default();
    let op = Op {
        on: &parked,
        host: Some(&h),
    };
    let built = std::cell::Cell::new(0_u32);
    let mut entries = 0;
    let answered = loop {
        entries += 1;
        assert!(entries < 40, "the op never completed");
        let answer = op.exchange_bounded(0, None, limit, || {
            built.set(built.get() + 1);
            Ok(post())
        });
        if let Poll::Ready(r) = answer {
            break r;
        }
    };
    SCRIPT.lock().unwrap().take();
    (answered, built.get())
}

/// RED (a plugin with a documented reply cap below `REPLY_MAX`, secret-vault's 1 MiB): an op's
/// exchange takes the cap, and a reply past it is refused as it is read, through [`Op`], with the
/// bound's own text. RED before: `Op` had no way to lower the ceiling (this did not compile).
#[test]
fn an_ops_bounded_exchange_refuses_a_reply_over_its_limit() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (answered, built) = op_bounded(body_reply(60, 41), 100);
    assert_eq!(
        answered.expect_err("the reply passes the op's limit"),
        ConnFailure::Failed(REPLY_OVER_BOUND.to_string())
    );
    assert_eq!(built, 1, "the request is built on the first entry only");
}

/// The limit holds across the op's re-entries: a reply exactly at it passes whole, the resumed
/// exchange keeping the ceiling it was built with.
#[test]
fn an_ops_bounded_exchange_passes_a_reply_at_its_limit() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (answered, built) = op_bounded(body_reply(60, 40), 100);
    assert_eq!(answered.expect("at the limit").body.len(), 100);
    assert_eq!(built, 1);
}

/// How many times the host ran `op` in `r`.
fn ran<T>(r: &Run<T>, op: u32) -> usize {
    r.ops.iter().filter(|&&o| o == op).count()
}

/// RED (status row 159, a failed exchange leaks its connection): a reply the host fails mid-read
/// closes the stream the exchange established, once, and the exchange holds no stream after it.
#[test]
fn a_failed_reply_read_closes_its_stream() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reply = vec![
        piece(REPLY_HEAD, 200, b"", b"", b""),
        piece(READ_FAILS, 0, b"", b"", b""),
    ];
    let r = run(
        reply,
        false,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert!(
        matches!(r.answered, Err(ConnFailure::Failed(_))),
        "{:?}",
        r.answered
    );
    assert_eq!(ran(&r, service::CLOSE), 1, "{:?}", r.ops);
    assert_eq!(r.ops.last(), Some(&service::CLOSE));
    assert_eq!(r.state.stream(), None);
    assert!(r.runs.values().all(|&n| n == 1), "{:?}", r.runs);
}

/// RED (status row 159): a reply past the exchange's limit is refused with its own failure, and
/// the stream is closed once right after the read that passed it: no read follows the refusal.
#[test]
fn a_reply_over_the_limit_closes_its_stream() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        body_reply(60, 41),
        false,
        Exchange::request(post())
            .expect("a request")
            .reply_limit(100),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(
        r.answered.as_ref().expect_err("the reply passes the limit"),
        &ConnFailure::Failed(REPLY_OVER_BOUND.to_string())
    );
    assert_eq!(
        r.ops,
        vec![
            service::ESTABLISH,
            service::WRITE_REQUEST,
            service::WRITE_REQUEST,
            service::WRITE_REQUEST,
            service::READ_REPLY,
            service::READ_REPLY,
            service::READ_REPLY,
            service::CLOSE,
        ]
    );
    assert_eq!(r.state.stream(), None);
}

/// RED (status row 159): a request the stream refuses (a send that fails) closes the stream it
/// was established on, and the refusal is still what the exchange answers.
#[test]
fn a_refused_send_closes_its_stream() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        http_reply(),
        true,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(
        r.answered,
        Err(ConnFailure::Refused(NOT_FRAMED.to_string()))
    );
    assert_eq!(ran(&r, service::CLOSE), 1, "{:?}", r.ops);
    assert_eq!(r.ops.last(), Some(&service::CLOSE));
    assert_eq!(r.state.stream(), None);
}

/// GREEN twin: an exchange that completes still closes its stream exactly once, last, and holds
/// none after it; a send that is acked does the same.
#[test]
fn a_completed_exchange_closes_its_stream_once() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        http_reply(),
        false,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(
        r.answered.as_ref().expect("the exchange completes").status,
        200
    );
    assert_eq!(ran(&r, service::CLOSE), 1, "{:?}", r.ops);
    assert_eq!(r.ops.last(), Some(&service::CLOSE));
    assert_eq!(r.state.stream(), None);
    let acked = run(
        vec![piece(REPLY_ACK, 250, b"ok", b"", b"")],
        false,
        Exchange::send(b"ping".to_vec()),
        None,
        |c, st| send_and_ack(c, st, 0, None),
    );
    assert_eq!(acked.answered.as_ref().expect("acked").code, 250);
    assert_eq!(ran(&acked, service::CLOSE), 1, "{:?}", acked.ops);
    assert_eq!(acked.ops.last(), Some(&service::CLOSE));
}

/// RED: a limit above `REPLY_MAX` clamps to it, and an exchange that sets none holds `REPLY_MAX`.
#[test]
fn a_limit_above_reply_max_clamps() {
    let req = || Exchange::request(post()).expect("a request");
    assert_eq!(req().reply_ceiling, REPLY_MAX);
    assert_eq!(req().reply_limit(REPLY_MAX + 1).reply_ceiling, REPLY_MAX);
    assert_eq!(req().reply_limit(usize::MAX).reply_ceiling, REPLY_MAX);
    assert_eq!(req().reply_limit(7).reply_ceiling, 7);
}

/// RED (Q128, a send-once caller's leak): an exchange that FAILS after it established its stream
/// closes the stream before it answers, as a whole one does, so a caller that sends once and moves
/// on holds nothing per failed delivery. The far end answers no reply piece; a stream that is not
/// framed refuses the request. Each answers its failure with the host holding no stream. RED
/// before: the failed exchange answered with its stream still held.
#[test]
fn a_failed_exchange_closes_its_stream_before_it_answers() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let no_piece = run(
        vec![piece(0, 0, b"", b"", b"")],
        false,
        Exchange::send(b"ping".to_vec()),
        None,
        |c, st| send_and_ack(c, st, 0, None),
    );
    assert!(no_piece.answered.is_err(), "{:?}", no_piece.answered);
    assert_eq!(no_piece.held, 0, "a failed exchange left its stream held");
    let refused = run(
        http_reply(),
        true,
        Exchange::request(post()).unwrap(),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert!(refused.answered.is_err(), "{:?}", refused.answered);
    assert_eq!(refused.held, 0, "a refused request left its stream held");
    // A whole exchange closes its stream too.
    let whole = run(
        http_reply(),
        false,
        Exchange::request(post()).unwrap(),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert!(whole.answered.is_ok(), "{:?}", whole.answered);
    assert_eq!(whole.held, 0);
}

/// A buffer whose TYPE wipes it on drop: the bound is the proof, checked at compile time.
fn wipes_on_drop<T: zeroize::ZeroizeOnDrop + ?Sized>(_: &T) {}

/// A type a plugin can wipe (`zeroize::Zeroizing::new(value)`).
fn wipeable<T: Zeroize>() {}

/// Every buffer an exchange holds of the request or the reply wipes on drop: the head it frames,
/// the body it sends, the raw bytes a send carries, the read buffer and the reply it gathers. The
/// request, reply and ack a plugin hands in or is handed back are wipeable.
#[test]
fn every_buffer_an_exchange_holds_wipes_on_drop() {
    wipeable::<Request>();
    wipeable::<ExchangeResponse>();
    wipeable::<Ack>();
    let framed = Exchange::request(post()).expect("a request");
    let Sending::Framed { head, body, .. } = &framed.sending else {
        panic!("a request is framed");
    };
    wipes_on_drop(head);
    wipes_on_drop(body);
    wipes_on_drop(&framed.buf);
    wipes_on_drop(&framed.reply);
    let raw = Exchange::send(b"ping".to_vec());
    let Sending::Raw(bytes) = &raw.sending else {
        panic!("a send is raw");
    };
    wipes_on_drop(bytes);
}

/// RED: the read buffer is reused for every piece of the reply (and every replay of one); once the
/// exchange completes it holds no byte of the reply, while the reply itself arrived whole.
#[test]
fn the_reused_read_buffer_keeps_no_reply_bytes() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        http_reply(),
        false,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/hook")),
    );
    let reply = r.answered.expect("the exchange completes");
    assert_eq!(reply.body, b"hello world");
    assert_eq!(reply.reason.as_deref(), Some(&b"Totally Fine"[..]));
    assert!(
        r.state.buf.iter().all(|&b| b == 0),
        "the read buffer still holds reply bytes"
    );
}

/// The head is allocated once at its exact length: no outgrown allocation holds a copy of a field.
#[test]
fn the_head_is_framed_into_one_exact_allocation() {
    let ex = Exchange::request(post()).expect("a request");
    let Sending::Framed { head, .. } = &ex.sending else {
        panic!("a request is framed");
    };
    assert_eq!(head.capacity(), head.len());
    assert_eq!(
        &head[..],
        &b"POST/hook?x=1content-type: application/json\r\nx-busbar: 1\r\n"[..]
    );
}

/// The reply body grows as `Vec` grows it (the same capacities, so the same allocations), and
/// holds the same bytes.
#[test]
fn the_reply_body_grows_as_a_vec_grows() {
    let mut wiped = Vec::new();
    let mut plain = Vec::new();
    for n in [1usize, 3, 5, 16, 1, 100, 7, 300, 0, 4096] {
        let chunk = vec![u8::try_from(n % 251).unwrap(); n];
        extend_wiping(&mut wiped, &chunk);
        plain.extend_from_slice(&chunk);
        assert_eq!(wiped.capacity(), plain.capacity(), "after {n}");
    }
    assert_eq!(wiped, plain);
}

/// What the request, reply and ack carried is gone once a plugin wipes them.
#[test]
fn a_request_a_reply_and_an_ack_wipe_to_empty() {
    let mut request = post();
    request.timeout_ms = 9;
    request.zeroize();
    assert_eq!(request, Request::default());
    let mut reply = ExchangeResponse {
        status: 200,
        reason: Some(b"OK".to_vec()),
        fields: vec![(b"set-cookie".to_vec(), b"s=1".to_vec())],
        body: b"token".to_vec(),
    };
    reply.zeroize();
    assert_eq!(reply, ExchangeResponse::default());
    let mut ack = Ack {
        code: 250,
        reason: b"queued".to_vec(),
    };
    ack.zeroize();
    assert_eq!(ack, Ack::default());
}

/// RED: a reply whose stream resets after its head fails, and the exchange says the head was
/// received and what status it carried: a failure reading the body, not a failed send.
#[test]
fn a_reset_after_the_head_reports_the_head_and_its_status() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reply = vec![
        piece(
            REPLY_HEAD,
            200,
            b"OK",
            b"content-type: application/json\r\n",
            b"",
        ),
        piece(REPLY_BODY, 0, b"", b"", b"{\"keys\":"),
        piece(RESET, 0, b"", b"", b""),
    ];
    let r = run(
        reply,
        false,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/jwks")),
    );
    assert!(
        matches!(r.answered, Err(ConnFailure::Failed(_))),
        "{:?}",
        r.answered
    );
    assert!(r.state.head_seen());
    assert_eq!(r.state.head_status(), Some(200));
}

/// RED: an exchange whose send fails received no head and reports no status.
#[test]
fn a_send_failure_reports_no_head() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        http_reply(),
        true,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert!(r.answered.is_err());
    assert!(!r.state.head_seen());
    assert_eq!(r.state.head_status(), None);
    let fresh = Exchange::request(post()).expect("a request");
    assert!(!fresh.head_seen(), "no head before any read");
    assert_eq!(fresh.head_status(), None);
}

/// RED: a reply whose body passes the exchange's bound is refused, and its head's status is still
/// answered, so a driver judges the status before the body.
#[test]
fn a_reply_over_the_bound_still_reports_its_status() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut reply = body_reply(60, 41);
    reply[0] = piece(REPLY_HEAD, 503, b"Service Unavailable", b"", b"");
    let r = run(
        reply,
        false,
        Exchange::request(post())
            .expect("a request")
            .reply_limit(100),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    assert_eq!(
        r.answered.expect_err("the reply passes the limit"),
        ConnFailure::Failed(REPLY_OVER_BOUND.to_string())
    );
    assert!(r.state.head_seen());
    assert_eq!(r.state.head_status(), Some(503));
}

/// A completed exchange reports its head's status as its reply does.
#[test]
fn a_completed_exchange_reports_its_heads_status() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let r = run(
        http_reply(),
        false,
        Exchange::request(post()).expect("a request"),
        None,
        |c, st| exchange(c, st, 0, None),
    );
    let status = r.answered.expect("the exchange completes").status;
    assert_eq!(r.state.head_status(), Some(status));
}

#[test]
fn sealed_fields_go_in_at_their_place_and_never_read_back() {
    use crate::abi::sdk::cred::Cred;
    let key = Cred::captured(zeroize::Zeroizing::new(b"sk-CANARY".to_vec()));
    let r = Request {
        method: b"POST".to_vec(),
        target: b"/hook".to_vec(),
        fields: vec![(b"content-type".to_vec(), b"application/json".to_vec())],
        body: b"{}".to_vec(),
        timeout_ms: 0,
    };
    let ex = Exchange::request_sealed(
        r,
        vec![
            (0, b"authorization".to_vec(), key.bearer()),
            (9, b"x-api-key".to_vec(), key.field()),
        ],
    )
    .expect("frames");
    let seen = ex.framed_fields();
    assert_eq!(
        seen,
        vec![
            (&b"authorization"[..], &b"<sealed>"[..]),
            (&b"content-type"[..], &b"application/json"[..]),
            (&b"x-api-key"[..], &b"<sealed>"[..]),
        ]
    );
    let Sending::Framed { head, .. } = &ex.sending else {
        panic!("framed")
    };
    let head = String::from_utf8_lossy(head);
    assert!(head.contains("authorization: Bearer sk-CANARY"), "{head}");
    assert!(head.contains("x-api-key: sk-CANARY"), "{head}");
}

#[test]
fn a_sealed_body_replaces_the_requests_own() {
    use crate::abi::sdk::cred::{Cred, FormBody};
    let secret = Cred::captured(zeroize::Zeroizing::new(b"s3c".to_vec()));
    let body = FormBody::new()
        .public("grant_type", "authorization_code")
        .sealed("client_secret", &secret)
        .encoded()
        .expect("encodes");
    let r = Request {
        method: b"POST".to_vec(),
        target: b"/token".to_vec(),
        fields: vec![],
        body: b"ignored".to_vec(),
        timeout_ms: 0,
    };
    let ex = Exchange::request_with(r, Vec::new(), Some(body)).expect("frames");
    let Sending::Framed { body, .. } = &ex.sending else {
        panic!("framed")
    };
    assert_eq!(
        &body[..],
        b"grant_type=authorization_code&client_secret=s3c"
    );
}

/// SECURE_REQUIRED (CHIP-DESIGN v4.1 change 4), RED before the check: a credential the operator's
/// URL requires secured goes out only to a secured target. A framed request is made whole when its
/// stream opens, so a target whose scheme is not secure is refused before the open; a credential
/// with no requirement goes out either way.
#[test]
fn a_credential_that_must_go_out_secured_is_refused_on_a_clear_target() {
    use crate::abi::sdk::cred::{Cred, NOT_SECURE};
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let required = Cred::captured(zeroize::Zeroizing::new(b"sk-CANARY".to_vec()))
        .secure_for("https://far/hook");
    let free = Cred::captured(zeroize::Zeroizing::new(b"sk-CANARY".to_vec()));
    let go = |cred: &Cred, target: &'static str| {
        let ex =
            Exchange::request_sealed(post(), vec![(0, b"authorization".to_vec(), cred.bearer())])
                .expect("frames");
        run(http_reply(), false, ex, None, move |c, st| {
            exchange(c, st, 0, Some(target))
        })
    };
    let refused = go(&required, "http://far/hook");
    assert!(
        matches!(&refused.answered, Err(ConnFailure::Refused(t)) if t == NOT_SECURE),
        "{:?}",
        refused.answered.as_ref().err()
    );
    assert!(
        refused.ops.is_empty(),
        "the stream was opened: {:?}",
        refused.ops
    );
    let sent = go(&required, "https://far/hook");
    assert_eq!(sent.answered.expect("sent secured").status, 200);
    let clear = go(&free, "http://far/hook");
    assert_eq!(clear.answered.expect("no requirement").status, 200);
}

/// One READ_CHUNK of body: a reply that plays it without end passes [`REPLY_MAX`].
static HUGE: [u8; READ_CHUNK] = [b'x'; READ_CHUNK];

/// A 2xx head, then body pieces with no end: the scripted host plays the last piece on every read
/// after the script, so the body runs on for as long as the exchange reads.
fn head_then_endless_body() -> Vec<Scripted> {
    vec![
        piece(REPLY_HEAD, 200, b"OK", b"x-a: 1\r\n", b""),
        piece(REPLY_BODY, 0, b"", b"", &HUGE),
    ]
}

/// RED: a HEAD-ONLY exchange is judged on the reply's head, as 1.5.5 judged a webhook delivery. A
/// 2xx head followed by a slow or huge body that never ends answers status 200 on the head read
/// alone: no body is read or buffered, no `REPLY_OVER_BOUND`, and the stream is closed. Every entry
/// after the head replays its read, and the replayed head ends the reads too; no service runs
/// twice. An observing head-only exchange reads its facts before the close.
#[test]
fn a_head_only_exchange_is_judged_on_the_head_and_never_reads_the_body() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let reads = |ops: &[u32]| ops.iter().filter(|&&o| o == service::READ_REPLY).count();
    let r = run(
        head_then_endless_body(),
        false,
        Exchange::request(post()).expect("a request").head_only(),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/hook")),
    );
    let reply = r.answered.expect("the head judges the exchange");
    assert_eq!(reply.status, 200);
    assert_eq!(reply.reason.as_deref(), Some(&b"OK"[..]));
    assert_eq!(reply.fields, vec![(b"x-a".to_vec(), b"1".to_vec())]);
    assert!(reply.body.is_empty(), "no body is read");
    assert_eq!(reads(&r.ops), 1, "the head is the only piece read");
    assert_eq!(r.ops.last(), Some(&service::CLOSE), "the stream is closed");
    // establish, head, body, end, one read, close: six services, each run once.
    assert_eq!(r.runs.len(), 6, "{:?}", r.runs);
    assert!(r.runs.values().all(|&n| n == 1), "{:?}", r.runs);
    assert_eq!(r.entries, 7);

    let observed = run(
        head_then_endless_body(),
        false,
        Exchange::request(post())
            .expect("a request")
            .observing()
            .head_only(),
        None,
        |c, st| exchange(c, st, 0, Some("https://far/hook")),
    );
    assert_eq!(observed.answered.expect("the head judges it").status, 200);
    let facts = observed.state.observed().expect("the facts were read");
    assert_eq!(facts.peer_key_pin.as_deref(), Some(OBSERVED_PIN));
    assert_eq!(reads(&observed.ops), 1);
    assert_eq!(observed.ops.last(), Some(&service::CLOSE));
    // establish, head, body, end, one read, facts, close.
    assert_eq!(observed.runs.len(), 7, "{:?}", observed.runs);
    assert!(
        observed.runs.values().all(|&n| n == 1),
        "{:?}",
        observed.runs
    );
}

/// [`Op::exchange_bounded`] run to completion under `reply`, its reply capped at `limit` bytes.
fn op_run(reply: Vec<Scripted>, limit: usize) -> Result<ExchangeResponse, ConnFailure> {
    op_bounded(reply, limit).0
}

/// RED (SV-F): an op's exchange takes the reply limit, so a source can cap a reply (a vault read
/// at 1 MiB) without buffering up to `REPLY_MAX`: past it the reply is refused as one past
/// `REPLY_MAX` is; at it, it passes whole.
#[test]
fn an_ops_exchange_takes_its_reply_limit() {
    let _g = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(
        op_run(body_reply(60, 41), 100).expect_err("the reply passes the limit"),
        ConnFailure::Failed(REPLY_OVER_BOUND.to_string())
    );
    assert_eq!(
        op_run(body_reply(60, 40), 100)
            .expect("at the limit")
            .body
            .len(),
        100
    );
}
