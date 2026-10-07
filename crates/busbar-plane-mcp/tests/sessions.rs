// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION REVISIONS AND THE LEGACY EVENT STREAM, THROUGH THE DOOR (THE DESIGN section 2, the mcp
//! bullet): a `2025-06-18` client opens a session with `initialize` and is served inside it, a
//! session presented by another owner is unknown (`404`), a GET naming no revision opens the
//! `2024-11-05` event stream and a GET or DELETE naming no session is `405`; as a client, busbar
//! reaches an upstream that requires a session by negotiation, and sends a stateless upstream the
//! bytes it always sent.
//!
//! The door is driven over its own ABI here, op by op, under a host whose services and connector
//! are stand-ins written in this file: a clock, the kernel's entitlement and trust answers (all
//! yes), a counting `random.fill`, and two upstreams behind the connector, one that requires a
//! session and one that speaks the stateless revision.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use busbar_contract::abi::host::conn::connector::{
    ConnectorSlots, EstablishIn, ReplyIn, ReplyPiece, RequestIn, RequestPiece, StreamIn,
    REPLY_BODY, REPLY_END, REPLY_HEAD, REQUEST_BODY, REQUEST_HEAD, SERVICES as CONN_SERVICES,
};
use busbar_contract::abi::host::service::{
    ClockNowIn, HostSlots, RandomFillIn, ServiceOut, DISTRUST_NONE, ENTITLED,
    SERVICES as HOST_SERVICES, TRUST_NEW,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, InHead, OutHead, Outcome, RawOutcome, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, OpsHead};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, Ops, OutField, PlaneOpenIn, PlaneOpenOut,
    RecordWrite, UnitCount, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL,
    PIECE_HAS_STATUS, PIECE_LAST,
};
use busbar_contract::abi::transport::FrameSpan;
use busbar_plane_mcp::{door, tool_door};
use serde_json::{json, Value};

// ── the host's services ─────────────────────────────────────────────────────────────────────────

fn answer(out: *mut ServiceOut, outcome: Outcome, value: u64, len: u64) -> RawOutcome {
    // SAFETY: the SDK's `out`, live for the call.
    unsafe {
        out.write(ServiceOut {
            size: std::mem::size_of::<ServiceOut>() as u32,
            outcome: RawOutcome::of(outcome),
            _reserved: [0; 3],
            value,
            len,
            items: 0,
            needed_bytes: 0,
            needed_items: 0,
            error: AbiStr {
                ptr: std::ptr::null(),
                len: 0,
            },
        });
    }
    RawOutcome::of(outcome)
}

/// The host's monotonic clock: it moves a second on every reading.
static MONO: AtomicU64 = AtomicU64::new(1_000_000_000);

extern "C" fn clock_now(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `ClockNowIn` whose reading slot it owns.
    let i = unsafe { input.cast::<ClockNowIn>().read() };
    let mono = MONO.fetch_add(1_000_000_000, Ordering::SeqCst);
    // SAFETY: as above.
    unsafe {
        (*i.reading).wall_ns = 1_800_000_000_000_000_000 + mono;
        (*i.reading).mono_ns = mono;
    }
    answer(out, Outcome::Ready, 0, 0)
}

extern "C" fn entitled(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, ENTITLED, 0)
}

/// Every fill differs from the last: a counter, spelled into the buffer.
static FILLS: AtomicU64 = AtomicU64::new(0);

extern "C" fn random_fill(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `RandomFillIn` over its own buffer.
    let i = unsafe { input.cast::<RandomFillIn>().read() };
    let n = FILLS.fetch_add(1, Ordering::SeqCst) + 1;
    let len = usize::try_from(i.len).expect("a small fill");
    // SAFETY: the SDK's buffer of `cap >= len` bytes.
    let buf = unsafe { std::slice::from_raw_parts_mut(i.into.buf, i.into.cap) };
    for (k, b) in buf.iter_mut().take(len).enumerate() {
        *b = (n as u8).wrapping_mul(31).wrapping_add(k as u8) | 1;
    }
    answer(out, Outcome::Ready, 0, i.len)
}

extern "C" fn serves(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, DISTRUST_NONE, 0)
}

extern "C" fn sighted(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    answer(out, Outcome::Ready, TRUST_NEW, 0)
}

static HOST_SLOTS: HostSlots = HostSlots {
    size: std::mem::size_of::<HostSlots>() as u32,
    slots: HOST_SERVICES,
    clock_now: Some(clock_now),
    records_get: None,
    records_list: None,
    records_claim: None,
    dest_judge: None,
    sign: None,
    unit_nest: None,
    work_open: None,
    work_find: None,
    work_settle: None,
    work_resume: None,
    trust_sight: Some(sighted),
    trust_due: None,
    verify_lookup: None,
    verify_store: None,
    entitlement_check: Some(entitled),
    content_scan: None,
    hook_call: None,
    random_fill: Some(random_fill),
    need_admit: None,
    trust_verify: None,
    records_secret: None,
    disk_append: None,
    snapshot_read: None,
    trust_sight_item: Some(sighted),
    trust_serves: Some(serves),
    trust_decide: None,
    trust_state: None,
    session_emit: None,
};

// ── the upstreams behind the connector ──────────────────────────────────────────────────────────

/// The upstream that requires a session.
const SESSION_URL: &str = "https://up.example/sess";
/// The upstream that speaks the stateless revision.
const STATELESS_URL: &str = "https://up.example/st";
/// The session the session upstream names.
const UPSTREAM_SESSION: &str = "up-session-1";

/// One request an upstream received over the connector.
#[derive(Debug, Clone)]
struct Seen {
    url: String,
    fields: Vec<(String, String)>,
    body: Value,
}

/// One reply an upstream writes: its status, its head fields and its body.
type Reply = (u32, Vec<(String, String)>, Vec<u8>);

/// One open exchange: where it goes, what it sent so far, and its reply once the request ended.
#[derive(Default)]
struct Wire {
    url: String,
    head: Vec<(String, String)>,
    body: Vec<u8>,
    reply: Option<Reply>,
    step: u8,
}

#[derive(Default)]
struct Upstreams {
    next: u64,
    open: HashMap<u64, Wire>,
    seen: Vec<Seen>,
}

static UPSTREAMS: Mutex<Option<Upstreams>> = Mutex::new(None);

fn upstreams() -> MutexGuard<'static, Option<Upstreams>> {
    UPSTREAMS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn field_of<'a>(fields: &'a [(String, String)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn rpc_result(id: &Value, result: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result})).unwrap()
}

const JSON_TYPE: (&str, &str) = ("content-type", "application/json");

fn json_head() -> Vec<(String, String)> {
    vec![(JSON_TYPE.0.to_string(), JSON_TYPE.1.to_string())]
}

/// What an upstream answers one request.
fn upstream_answer(url: &str, fields: &[(String, String)], body: &Value) -> Reply {
    let id = body.get("id").cloned().unwrap_or(Value::Null);
    let method = body.get("method").and_then(Value::as_str).unwrap_or("");
    let tools = json!({"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]});
    if url.starts_with(STATELESS_URL) {
        return match method {
            "tools/list" => (200, json_head(), rpc_result(&id, tools)),
            "tools/call" => (
                200,
                json_head(),
                rpc_result(
                    &id,
                    json!({"content": [{"type": "text", "text": "stateless"}], "resultType": "complete"}),
                ),
            ),
            _ => (404, Vec::new(), b"no such method".to_vec()),
        };
    }
    if method == "initialize" {
        let mut head = json_head();
        head.push(("mcp-session-id".to_string(), UPSTREAM_SESSION.to_string()));
        let asked = body
            .pointer("/params/protocolVersion")
            .cloned()
            .unwrap_or(Value::Null);
        let result = json!({
            "protocolVersion": asked,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "up", "version": "1"},
        });
        return (200, head, rpc_result(&id, result));
    }
    if field_of(fields, "mcp-session-id") != Some(UPSTREAM_SESSION) {
        return (
            400,
            json_head(),
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Bad Request: no valid session ID"}}"#
                .to_vec(),
        );
    }
    match method {
        "notifications/initialized" => (202, Vec::new(), Vec::new()),
        "tools/list" => (200, json_head(), rpc_result(&id, tools)),
        "tools/call" => (
            200,
            json_head(),
            rpc_result(
                &id,
                json!({"content": [{"type": "text", "text": "in-session"}]}),
            ),
        ),
        _ => (404, Vec::new(), Vec::new()),
    }
}

fn span(buf: &[u8], s: FrameSpan) -> &[u8] {
    let at = usize::try_from(s.offset).unwrap();
    &buf[at..at + usize::try_from(s.len).unwrap()]
}

extern "C" fn establish(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands an `EstablishIn`.
    let i = unsafe { input.cast::<EstablishIn>().read() };
    // SAFETY: the SDK's target text, live for the call.
    let url = unsafe { std::slice::from_raw_parts(i.target.ptr, i.target.len) };
    let url = String::from_utf8_lossy(url).into_owned();
    let mut ups = upstreams();
    let ups = ups.get_or_insert_with(Upstreams::default);
    ups.next += 1;
    let id = ups.next;
    ups.open.insert(
        id,
        Wire {
            url,
            ..Wire::default()
        },
    );
    answer(out, Outcome::Ready, id, 0)
}

extern "C" fn write_request(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `RequestIn` over its own bytes and descriptor.
    let i = unsafe { input.cast::<RequestIn>().read() };
    // SAFETY: as above.
    let (bytes, piece) = unsafe {
        (
            std::slice::from_raw_parts(i.buf, i.len),
            i.piece.cast::<RequestPiece>().read(),
        )
    };
    let mut ups = upstreams();
    let ups = ups.get_or_insert_with(Upstreams::default);
    let Some(wire) = ups.open.get_mut(&i.stream) else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    match piece.kind {
        REQUEST_HEAD => {
            let block = String::from_utf8_lossy(span(bytes, piece.fields)).into_owned();
            wire.head = block
                .split("\r\n")
                .filter_map(|l| l.split_once(": "))
                .map(|(n, v)| (n.to_ascii_lowercase(), v.to_string()))
                .collect();
        }
        REQUEST_BODY => wire.body.extend_from_slice(bytes),
        _ => {
            let body: Value = serde_json::from_slice(&wire.body).unwrap_or(Value::Null);
            wire.reply = Some(upstream_answer(&wire.url, &wire.head, &body));
            let seen = Seen {
                url: wire.url.clone(),
                fields: wire.head.clone(),
                body,
            };
            ups.seen.push(seen);
        }
    }
    answer(out, Outcome::Ready, 0, i.len as u64)
}

extern "C" fn read_reply(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `ReplyIn` over its own buffer and descriptor slot.
    let i = unsafe { input.cast::<ReplyIn>().read() };
    // SAFETY: as above.
    let buf = unsafe { std::slice::from_raw_parts_mut(i.buf, i.len) };
    let mut ups = upstreams();
    let ups = ups.get_or_insert_with(Upstreams::default);
    let Some(wire) = ups.open.get_mut(&i.stream) else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    let Some((status, head, body)) = wire.reply.clone() else {
        return answer(out, Outcome::Failed, 0, 0);
    };
    let (piece, n) = match wire.step {
        0 => {
            let block: String = head.iter().map(|(n, v)| format!("{n}: {v}\r\n")).collect();
            buf[..block.len()].copy_from_slice(block.as_bytes());
            (
                ReplyPiece {
                    kind: REPLY_HEAD,
                    code: status,
                    fields: FrameSpan {
                        offset: 0,
                        len: block.len() as u64,
                    },
                    ..ReplyPiece::default()
                },
                block.len(),
            )
        }
        1 if !body.is_empty() => {
            buf[..body.len()].copy_from_slice(&body);
            (
                ReplyPiece {
                    kind: REPLY_BODY,
                    ..ReplyPiece::default()
                },
                body.len(),
            )
        }
        _ => (
            ReplyPiece {
                kind: REPLY_END,
                ..ReplyPiece::default()
            },
            0,
        ),
    };
    wire.step = if wire.step == 0 && body.is_empty() {
        2
    } else {
        wire.step + 1
    };
    // SAFETY: the SDK's descriptor slot.
    unsafe { i.piece.write(piece) };
    answer(out, Outcome::Ready, 0, n as u64)
}

extern "C" fn close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK hands a `StreamIn`.
    let i = unsafe { input.cast::<StreamIn>().read() };
    if let Some(ups) = upstreams().as_mut() {
        ups.open.remove(&i.stream);
    }
    answer(out, Outcome::Ready, 0, 0)
}

static CONN_SLOTS: ConnectorSlots = ConnectorSlots {
    size: std::mem::size_of::<ConnectorSlots>() as u32,
    slots: CONN_SERVICES,
    establish: Some(establish),
    reject_endpoint: None,
    side_stream: None,
    read: None,
    write: None,
    upgrade_secure: None,
    facts: None,
    checkout: None,
    checkin: None,
    close: Some(close),
    random: None,
    identity: None,
    read_reply: Some(read_reply),
    write_request: Some(write_request),
};

struct Tables(HostTables);
// SAFETY: the tables name only `'static` tables of `extern "C"` functions.
unsafe impl Sync for Tables {}

static TABLES: Tables = Tables(HostTables {
    size: std::mem::size_of::<HostTables>() as u32,
    _reserved: 0,
    ctx: HostCtx {
        ptr: std::ptr::null_mut(),
    },
    wake: None,
    conns: &CONN_SLOTS,
    services: &HOST_SLOTS,
});

/// One test at a time: the upstreams are the process's.
static SERIAL: Mutex<()> = Mutex::new(());

// ── the door, op by op ──────────────────────────────────────────────────────────────────────────

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { std::mem::zeroed() }
}

fn str_of(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn head<T>(op: u32, ticket: Ticket) -> InHead {
    InHead {
        size: std::mem::size_of::<T>() as u32,
        op,
        ticket,
        ..z()
    }
}

fn out_head<T>() -> OutHead {
    OutHead {
        size: std::mem::size_of::<T>() as u32,
        ..z()
    }
}

fn ops() -> &'static Ops {
    // SAFETY: the door is a `'static` table whose ops are the plane kind's.
    unsafe { &*(*tool_door::door()).ops.cast::<Ops>() }
}

fn lifecycle() -> &'static OpsHead {
    &ops().head
}

/// One opened instance of the door.
struct Door {
    instance: *mut c_void,
}

/// The section: a registration that requires a session, and one that speaks the stateless revision.
const SECTION: &str = r#"{
    "fs": {"url": "https://up.example/sess", "pin": {"mechanism": "unpinned"}, "verify_ttl": "1h", "tools_allow": {"read_file": {}}},
    "st": {"url": "https://up.example/st", "pin": {"mechanism": "unpinned"}, "verify_ttl": "1h", "tools_allow": {"read_file": {}}, "resources_allow": {"file:///readme": {"name": "readme", "text": "hi"}}}
}"#;

fn open() -> Door {
    let mut i: PlaneOpenIn = z();
    i.open = OpenIn {
        head: head::<PlaneOpenIn>(life::OPEN, Ticket::NONE),
        host: &TABLES.0,
        settings: octets(SECTION.as_bytes()),
        generation: 1,
        ..z()
    };
    i.public_url = str_of("https://busbar.example");
    let mut o: PlaneOpenOut = z();
    o.open = OpenOut {
        head: out_head::<PlaneOpenOut>(),
        ..z()
    };
    let f = lifecycle().open.expect("the door opens");
    let ret = f(
        std::ptr::null_mut(),
        std::ptr::from_ref(&i).cast(),
        std::ptr::from_mut(&mut o).cast(),
    );
    assert_eq!(ret.outcome(), Outcome::Ready, "the door opens");
    Door {
        instance: o.open.instance,
    }
}

/// What `arrive` answered: its outcome and, refused, the status the refusal wears.
#[derive(Debug)]
struct Arrived {
    outcome: Outcome,
    refusal_status: u32,
}

fn claim(verb: &str) -> u32 {
    let i = door::ROUTES
        .iter()
        .position(|r| r.verb == verb && r.target == "/mcp" && r.carrier == "http")
        .expect("the door routes it");
    u32::try_from(i).unwrap()
}

impl Door {
    fn arrive(
        &self,
        unit: u64,
        verb: &str,
        target: &str,
        body: &[u8],
        fields: &[(&str, &str)],
    ) -> Arrived {
        let fields: Vec<Field> = fields
            .iter()
            .map(|(n, v)| Field {
                name: str_of(n),
                value: str_of(v),
            })
            .collect();
        let mut i: ArriveIn = z();
        i.head = head::<ArriveIn>(slot::ARRIVE, Ticket::NONE);
        i.unit = unit;
        i.claim = claim(verb);
        i.target = str_of(target);
        i.method = str_of(verb);
        i.body = octets(body);
        (i.fields, i.fields_len) = (fields.as_ptr(), fields.len());
        let mut units = [z::<UnitCount>(); 8];
        (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
        let mut o: ArriveOut = z();
        o.head = out_head::<ArriveOut>();
        let f = ops().arrive.expect("arrive");
        let ret = f(
            self.instance,
            std::ptr::from_ref(&i).cast(),
            std::ptr::from_mut(&mut o).cast(),
        );
        Arrived {
            outcome: ret.outcome(),
            refusal_status: o.refusal_status,
        }
    }

    /// One piece of `unit`, re-called while the door says `more`: the outcome, the status, the
    /// head fields, the bytes, whether the bytes went to the far end, and the request line.
    fn piece(&self, unit: u64, given: &Given<'_>) -> Answered {
        let ticket = Ticket {
            slot: u32::try_from(unit).unwrap(),
            generation: 1,
        };
        let head_fields: Vec<Field> = given
            .head
            .iter()
            .map(|(n, v)| Field {
                name: str_of(n),
                value: str_of(v),
            })
            .collect();
        let mut reply = vec![0_u8; 1 << 16];
        let mut fields = [z::<OutField>(); 16];
        let mut arena = vec![0_u8; 1 << 14];
        let mut records = [z::<RecordWrite>(); 16];
        let mut units = [z::<UnitCount>(); 8];
        let mut got = Answered::default();
        let mut first = true;
        for _ in 0..64 {
            let mut i: OnPieceIn = z();
            i.head = head::<OnPieceIn>(slot::ON_PIECE, ticket);
            i.unit = unit;
            i.from = given.from;
            i.stream = given.stream;
            i.caller_ref = str_of(given.caller);
            if first {
                i.flags = given.flags;
                i.bytes = octets(given.bytes);
                i.status_code = given.status;
                i.attempt_no = given.attempt;
                i.member = str_of(given.member);
                (i.head_fields, i.head_fields_len) = (head_fields.as_ptr(), head_fields.len());
            } else {
                i.bytes = octets(b"");
            }
            (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
            (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
            (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
            (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
            (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
            let mut o: OnPieceOut = z();
            o.head = out_head::<OnPieceOut>();
            let f = ops().on_piece.expect("on_piece");
            let ret = f(
                self.instance,
                std::ptr::from_ref(&i).cast(),
                std::ptr::from_mut(&mut o).cast(),
            );
            first = false;
            got.outcome = Some(ret.outcome());
            if o.reply_status != 0 {
                got.status = o.reply_status;
            }
            let at = |s: busbar_contract::abi::mechanism::call::Span| {
                let from = s.offset as usize;
                String::from_utf8_lossy(&arena[from..from + s.len as usize]).into_owned()
            };
            got.fields.extend(
                fields[..o.fields_written as usize]
                    .iter()
                    .map(|f| (at(f.name), at(f.value))),
            );
            if o.verb.len != 0 {
                got.request = format!("{} {}", at(o.verb), at(o.target));
            }
            got.far |= o.flags & EMIT_TO_FAR_END != 0;
            got.done |= o.flags & EMIT_DONE != 0;
            got.bytes
                .extend_from_slice(&reply[..usize::try_from(o.emitted).unwrap()]);
            if ret.outcome() != Outcome::Ready || o.more == 0 {
                break;
            }
        }
        got
    }
}

/// One piece as the kernel pushes it.
struct Given<'a> {
    from: u32,
    flags: u32,
    stream: u64,
    status: u32,
    attempt: u32,
    member: &'a str,
    caller: &'a str,
    head: Vec<(&'a str, &'a str)>,
    bytes: &'a [u8],
}

impl<'a> Given<'a> {
    /// The caller's whole body, under the caller reference `caller`.
    fn caller(caller: &'a str, bytes: &'a [u8]) -> Self {
        Given {
            from: FROM_CALLER,
            flags: PIECE_LAST,
            stream: 0,
            status: 0,
            attempt: 0,
            member: "",
            caller,
            head: Vec::new(),
            bytes,
        }
    }

    /// The caller's side of a held stream opening: the request's (empty) body.
    fn stream_open(caller: &'a str, stream: u64) -> Self {
        Given {
            flags: 0,
            stream,
            ..Given::caller(caller, b"")
        }
    }

    /// The kernel collecting a held stream's output.
    fn collect(caller: &'a str, stream: u64) -> Self {
        Given {
            from: FROM_KERNEL,
            flags: 0,
            stream,
            ..Given::caller(caller, b"")
        }
    }

    /// The kernel's ATTEMPT naming `member`.
    fn attempt(caller: &'a str, member: &'a str) -> Self {
        Given {
            from: FROM_KERNEL,
            flags: 0,
            attempt: 1,
            member,
            ..Given::caller(caller, b"")
        }
    }

    /// The far end's whole answer.
    fn far(caller: &'a str, status: u32, head: Vec<(&'a str, &'a str)>, bytes: &'a [u8]) -> Self {
        Given {
            from: FROM_FAR_END,
            flags: PIECE_LAST | PIECE_HAS_STATUS,
            status,
            head,
            ..Given::caller(caller, bytes)
        }
    }
}

#[derive(Debug, Default)]
struct Answered {
    outcome: Option<Outcome>,
    status: u32,
    fields: Vec<(String, String)>,
    bytes: Vec<u8>,
    far: bool,
    done: bool,
    request: String,
}

impl Answered {
    fn field(&self, name: &str) -> Option<&str> {
        field_of(&self.fields, name)
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.bytes).unwrap_or_else(|e| {
            panic!(
                "a JSON answer ({e}): {}",
                String::from_utf8_lossy(&self.bytes)
            )
        })
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

/// Two callers' opaque references, as the kernel lends them.
const ALICE: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const BOB: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";

const INIT_2025: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}"#;
const LIST_2025: &[u8] = br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
const INITIALIZED: &[u8] = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
const ACCEPT_BOTH: (&str, &str) = ("accept", "application/json, text/event-stream");

/// `initialize` on the endpoint, as `caller`: the answer.
fn initialize(d: &Door, unit: u64, caller: &str) -> Answered {
    let arrived = d.arrive(unit, "POST", "/mcp", INIT_2025, &[ACCEPT_BOTH]);
    assert_eq!(
        arrived.outcome,
        Outcome::Ready,
        "a 2025-06-18 `initialize` is served, not refused: {arrived:?}"
    );
    d.piece(unit, &Given::caller(caller, INIT_2025))
}

/// A `tools/list` in session `session` as `caller`.
fn listed(d: &Door, unit: u64, session: &str, caller: &str) -> Answered {
    let fields = [
        ACCEPT_BOTH,
        ("mcp-session-id", session),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let arrived = d.arrive(unit, "POST", "/mcp", LIST_2025, &fields);
    assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
    d.piece(unit, &Given::caller(caller, LIST_2025))
}

// ── (a) and (b): the session revisions ──────────────────────────────────────────────────────────

/// A `2025-06-18` client: `initialize` answers the revision it asked for and names a session of 128
/// bits in `Mcp-Session-Id`; a request in that session is served, its answer in the session
/// revision's shape (no stateless-only members).
#[test]
fn a_2025_initialize_opens_a_session_that_serves_its_requests() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open();
    let init = initialize(&d, 1, ALICE);
    assert_eq!(init.status, 200, "{}", init.text());
    assert_eq!(init.outcome, Some(Outcome::Ready));
    assert!(init.done, "the answer is whole");
    let session = init
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string();
    assert_eq!(session.len(), 32, "128 bits, as hex");
    assert!(session.bytes().all(|b| b.is_ascii_hexdigit()));
    let body = init.json();
    assert_eq!(body["id"], json!(1));
    assert_eq!(body["result"]["protocolVersion"], json!("2025-06-18"));
    assert!(body["result"]["capabilities"]["tools"].is_object());

    let arrived = d.arrive(
        2,
        "POST",
        "/mcp",
        INITIALIZED,
        &[ACCEPT_BOTH, ("mcp-session-id", session.as_str())],
    );
    assert_eq!(arrived.outcome, Outcome::Ready);
    let noted = d.piece(2, &Given::caller(ALICE, INITIALIZED));
    assert_eq!(noted.status, 202);

    let list = listed(&d, 3, &session, ALICE);
    assert_eq!(list.status, 200, "{}", list.text());
    let body = list.json();
    assert_eq!(body["id"], json!(2));
    let tools = body["result"]["tools"].as_array().expect("a tool list");
    assert!(!tools.is_empty(), "the caller is entitled to every tool");
    assert!(
        body["result"].get("resultType").is_none() && body["result"].get("ttlMs").is_none(),
        "lowered into the session revision: {body}"
    );
}

/// A session is bound to the owner that opened it: another caller presenting its id is told it is
/// unknown (`404`), on POST and on DELETE alike, and the owner's DELETE ends it.
#[test]
fn a_session_presented_by_another_owner_is_unknown() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open();
    let init = initialize(&d, 11, ALICE);
    let session = init
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string();
    assert_eq!(listed(&d, 12, &session, BOB).status, 404);
    assert_eq!(listed(&d, 13, &session, ALICE).status, 200);
    assert_eq!(
        listed(&d, 14, "0123456789abcdef0123456789abcdef", ALICE).status,
        404
    );

    let delete = |unit: u64, caller: &str| {
        let arrived = d.arrive(
            unit,
            "DELETE",
            "/mcp",
            b"",
            &[("mcp-session-id", session.as_str())],
        );
        assert_eq!(arrived.outcome, Outcome::Ready, "{arrived:?}");
        d.piece(unit, &Given::caller(caller, b""))
    };
    assert_eq!(delete(15, BOB).status, 404);
    assert_eq!(delete(16, ALICE).status, 200);
    assert_eq!(listed(&d, 17, &session, ALICE).status, 404, "ended");
}

// ── (c) and (d): the sessionless GET and DELETE ─────────────────────────────────────────────────

/// A GET that names no session and no revision is the `2024-11-05` client's: its stream opens with
/// the `endpoint` event naming the message address; a message POSTed there is accepted (`202`) and
/// answered on the stream. A GET that names a revision, or does not accept an event stream, is
/// `405`, and so is a DELETE that names no session.
#[test]
fn a_sessionless_get_is_the_legacy_stream_or_405() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let d = open();
    let sse = ("accept", "text/event-stream");
    let named = d.arrive(
        21,
        "GET",
        "/mcp",
        b"",
        &[sse, ("mcp-protocol-version", "2025-06-18")],
    );
    assert_eq!(
        (named.outcome, named.refusal_status),
        (Outcome::Refused, 405)
    );
    let plain = d.arrive(22, "GET", "/mcp", b"", &[("accept", "application/json")]);
    assert_eq!(
        (plain.outcome, plain.refusal_status),
        (Outcome::Refused, 405)
    );
    let delete = d.arrive(23, "DELETE", "/mcp", b"", &[]);
    assert_eq!(
        (delete.outcome, delete.refusal_status),
        (Outcome::Refused, 405)
    );

    let legacy = d.arrive(24, "GET", "/mcp", b"", &[sse]);
    assert_eq!(legacy.outcome, Outcome::Ready, "{legacy:?}");
    let opened = d.piece(24, &Given::stream_open(ALICE, 24));
    assert_eq!(opened.status, 200);
    assert_eq!(opened.field("content-type"), Some("text/event-stream"));
    let text = opened.text();
    let address = text
        .strip_prefix("event: endpoint\ndata: ")
        .and_then(|rest| rest.split('\n').next())
        .unwrap_or_else(|| panic!("the stream opens with the endpoint event: {text:?}"))
        .to_string();
    let session = address
        .strip_prefix("/mcp?sessionId=")
        .expect("the message address names the session");
    assert_eq!(session.len(), 32);

    let init = br#"{"jsonrpc":"2.0","id":7,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"old","version":"1"}}}"#;
    let posted = d.arrive(
        25,
        "POST",
        &address,
        init,
        &[("content-type", "application/json")],
    );
    assert_eq!(posted.outcome, Outcome::Ready, "{posted:?}");
    let accepted = d.piece(25, &Given::caller(ALICE, init));
    assert_eq!(accepted.status, 202);
    assert!(accepted.bytes.is_empty());

    let delivered = d.piece(24, &Given::collect(ALICE, 24));
    let text = delivered.text();
    let data = text
        .strip_prefix("event: message\ndata: ")
        .and_then(|rest| rest.split('\n').next())
        .unwrap_or_else(|| panic!("the answer is delivered on the stream: {text:?}"));
    let answer: Value = serde_json::from_str(data).expect("one JSON-RPC message");
    assert_eq!(answer["id"], json!(7));
    assert_eq!(answer["result"]["protocolVersion"], json!("2024-11-05"));

    // The message address is the owner's: another caller posting to it is told it is unknown.
    let foreign = d.arrive(
        26,
        "POST",
        &address,
        init,
        &[("content-type", "application/json")],
    );
    assert_eq!(foreign.outcome, Outcome::Ready);
    assert_eq!(d.piece(26, &Given::caller(BOB, init)).status, 404);
}

// ── (e): busbar as a client ──────────────────────────────────────────────────────────────────────

const CALL: &[u8] = br#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
const CALL_FIELDS: &[(&str, &str)] = &[
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/call"),
    ("mcp-name", "fs_read_file"),
];
const ST_CALL: &[u8] = br#"{"jsonrpc":"2.0","id":31,"method":"tools/call","params":{"name":"st_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
const ST_FIELDS: &[(&str, &str)] = &[
    ("mcp-protocol-version", "2026-07-28"),
    ("mcp-method", "tools/call"),
    ("mcp-name", "st_read_file"),
];

fn seen() -> Vec<Seen> {
    upstreams()
        .as_ref()
        .map(|u| u.seen.clone())
        .unwrap_or_default()
}

/// An upstream that refuses the stateless revision and requires `initialize` is reached by
/// negotiation: busbar opens a session with it, and the relayed call is answered from inside it.
/// When the upstream then forgets that session, the walk's answer (`404`) is recovered by a fresh
/// `initialize` and the call is still answered.
#[test]
fn an_upstream_that_requires_a_session_is_reached_by_negotiation() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    assert_eq!(
        d.arrive(40, "POST", "/mcp", CALL, CALL_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(40, &Given::attempt(ALICE, "fs"));
    let send = d.piece(40, &Given::caller(ALICE, CALL));
    assert!(
        send.far,
        "the call is relayed, not refused: {} {}",
        send.status,
        send.text()
    );
    let sent: Value = serde_json::from_slice(&send.bytes).expect("a JSON-RPC request");
    assert_eq!(sent["method"], json!("tools/call"));
    assert_eq!(
        send.field("mcp-session-id"),
        Some(UPSTREAM_SESSION),
        "the relayed call rides the session negotiated with the upstream: {:?}",
        send.fields
    );
    assert!(
        sent.pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .is_none(),
        "lowered into the session revision: {sent}"
    );
    let methods: Vec<String> = seen()
        .iter()
        .filter(|s| s.url.starts_with(SESSION_URL))
        .map(|s| s.body["method"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(
        methods,
        [
            "tools/list",
            "initialize",
            "notifications/initialized",
            "tools/list"
        ],
        "the verify fetch probed statelessly, was refused, and negotiated"
    );
    let far_ok =
        br#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"in-session"}]}}"#;
    let answered = d.piece(40, &Given::far(ALICE, 200, vec![JSON_TYPE], far_ok));
    assert_eq!(answered.status, 200, "{}", answered.text());
    let body = answered.json();
    assert_eq!(body["id"], json!(30));
    assert_eq!(body["result"]["content"][0]["text"], json!("in-session"));

    // The upstream forgot the session: the walk's answer is its 404, and busbar re-initialises.
    assert_eq!(
        d.arrive(41, "POST", "/mcp", CALL, CALL_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(41, &Given::attempt(ALICE, "fs"));
    let send = d.piece(41, &Given::caller(ALICE, CALL));
    assert!(send.far);
    let answered = d.piece(
        41,
        &Given::far(
            ALICE,
            404,
            vec![JSON_TYPE],
            br#"{"error":"unknown session"}"#,
        ),
    );
    assert_eq!(answered.status, 200, "{}", answered.text());
    let body = answered.json();
    assert_eq!(body["id"], json!(30));
    assert_eq!(body["result"]["content"][0]["text"], json!("in-session"));
}

/// An upstream that speaks the stateless revision sees exactly the request the dialect's builder
/// writes, with no handshake ahead of it.
#[test]
fn a_stateless_upstream_sees_the_stateless_request_unchanged() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    assert_eq!(
        d.arrive(50, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(50, &Given::attempt(ALICE, "st"));
    let send = d.piece(50, &Given::caller(ALICE, ST_CALL));
    assert!(send.far, "{} {}", send.status, send.text());
    assert_eq!(send.request, "POST /st");
    let sent: Value = serde_json::from_slice(&send.bytes).expect("a JSON-RPC request");
    assert_eq!(
        sent,
        json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "progressToken": null,
                },
            },
        })
    );
    assert_eq!(
        send.fields,
        vec![
            ("content-type".to_string(), "application/json".to_string()),
            (
                "accept".to_string(),
                "application/json, text/event-stream".to_string()
            ),
            ("mcp-protocol-version".to_string(), "2026-07-28".to_string()),
            ("mcp-method".to_string(), "tools/call".to_string()),
            ("mcp-name".to_string(), "read_file".to_string()),
        ]
    );
    let to_st: Vec<Seen> = seen()
        .into_iter()
        .filter(|s| s.url.starts_with(STATELESS_URL))
        .collect();
    assert_eq!(to_st.len(), 1, "one verify fetch, no handshake: {to_st:?}");
    assert_eq!(to_st[0].body["method"], json!("tools/list"));
    assert_eq!(
        field_of(&to_st[0].fields, "mcp-protocol-version"),
        Some("2026-07-28")
    );
    let far_ok = br#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"stateless"}],"resultType":"complete"}}"#;
    let answered = d.piece(50, &Given::far(ALICE, 200, vec![JSON_TYPE], far_ok));
    assert_eq!(answered.status, 200, "{}", answered.text());
    assert_eq!(
        answered.json()["result"]["content"][0]["text"],
        json!("stateless")
    );
}

// ── subscribe stays for the old revisions ───────────────────────────────────────────────────────

/// A `2025-06-18` session that subscribes to a declared resource hears the announcing server's
/// `notifications/resources/updated` on its GET stream: here the upstream announces it on the event
/// stream it answers a relayed call with.
#[test]
fn a_session_subscription_hears_the_upstreams_resource_update() {
    let _serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    *upstreams() = Some(Upstreams::default());
    let d = open();
    let init = initialize(&d, 60, ALICE);
    let session = init
        .field("mcp-session-id")
        .expect("the answer names its session")
        .to_string();
    assert_eq!(
        init.json()["result"]["capabilities"]["resources"]["subscribe"],
        json!(true),
        "subscribe stays for the old revisions"
    );
    let in_session = [
        ACCEPT_BOTH,
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    let subscribe =
        br#"{"jsonrpc":"2.0","id":3,"method":"resources/subscribe","params":{"uri":"file:///readme"}}"#;
    assert_eq!(
        d.arrive(61, "POST", "/mcp", subscribe, &in_session).outcome,
        Outcome::Ready
    );
    let subscribed = d.piece(61, &Given::caller(ALICE, subscribe));
    assert_eq!(subscribed.status, 200, "{}", subscribed.text());
    assert_eq!(subscribed.json()["result"], json!({}));

    let stream = [
        ("accept", "text/event-stream"),
        ("mcp-session-id", session.as_str()),
        ("mcp-protocol-version", "2025-06-18"),
    ];
    assert_eq!(
        d.arrive(62, "GET", "/mcp", b"", &stream).outcome,
        Outcome::Ready
    );
    let opened = d.piece(62, &Given::stream_open(ALICE, 62));
    assert_eq!(opened.status, 200);
    assert_eq!(opened.field("content-type"), Some("text/event-stream"));

    assert_eq!(
        d.arrive(63, "POST", "/mcp", ST_CALL, ST_FIELDS).outcome,
        Outcome::Ready
    );
    d.piece(63, &Given::attempt(BOB, "st"));
    assert!(d.piece(63, &Given::caller(BOB, ST_CALL)).far);
    let far = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\",\"params\":{\"uri\":\"file:///readme\"}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{\"content\":[],\"resultType\":\"complete\"}}\n\n";
    let answered = d.piece(
        63,
        &Given::far(BOB, 200, vec![("content-type", "text/event-stream")], far),
    );
    assert_eq!(answered.status, 200);

    let delivered = d.piece(62, &Given::collect(ALICE, 62)).text();
    assert!(
        delivered.contains(r#""method":"notifications/resources/updated""#)
            && delivered.contains("file:///readme"),
        "the subscriber hears the update: {delivered:?}"
    );
}
