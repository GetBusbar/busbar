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
}

static SCRIPT: Mutex<Option<Script>> = Mutex::new(None);
/// One test at a time: the script is process-wide.
static SERIAL: Mutex<()> = Mutex::new(());
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
    let (value, len) = match op {
        service::ESTABLISH => {
            // SAFETY: an `EstablishIn` (the SDK states its whole size).
            let i = unsafe { *input.cast::<crate::abi::host::conn::connector::EstablishIn>() };
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
            (0, play(io, piece))
        }
        _ => (0, 0),
    };
    s.stored.insert(seq, (Outcome::Ready, value, len));
    answer(out, Outcome::Pending, 0, 0)
}

macro_rules! slot {
    ($name:ident, $op:expr) => {
        extern "C" fn $name(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
            serve($op, i, o)
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

/// `FACTS`, as a connector host answers it on a stream already dialled: READY at once with the
/// facts written on a handle's first issue; a re-issue answers the stored outcome and writes
/// nothing (the replay rule).
extern "C" fn facts(_: HostCtx, i: *const c_void, o: *mut ServiceOut) -> RawOutcome {
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
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
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
