// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A PLANE'S DOOR, BOTH WAYS (BUSBAR-1.6.0.md Part 2 #2 steps (4) and (5)): the `plane-door` row of
//! `[package.metadata.busbar.both-ways]` names the fixture, reached here by KIND
//! ([`fixture`]). Its `plane_door::door` is loaded LINKED (through `load_linked`) and DROPPED (the
//! `plane_door_fixture` example, through `load_dropped`), and ONE script drives the door's
//! lifecycle through the loader's plane kind:
//!
//! * `validate` refuses a bad registration in the grammar's own sentence and accepts a good one;
//! * `open` publishes the first generation's snapshot over the public base URL, `refresh` the next,
//!   each read through the loader's own copy (`Plugin<Plane>::open`/`refresh`), so the test reads
//!   no plugin memory;
//! * `retire` drops the first; `tick`, `drive` and `cancel` answer their dispositions;
//! * `arrive` on the JSON-RPC line decides a request (its op class, dialect and principal need)
//!   and refuses a wrong media type in the plane's own words, which `refusal` renders with the
//!   plane's status; a kernel refusal renders at the kernel's status on the target line;
//! * `on_piece` relays the extended-card read addressed to one agent: the ATTEMPT names `POST` at
//!   the agent's own path with the engine's three fields, the caller's body goes to the far end
//!   verbatim, and the far end's answer comes back as the caller's, `reply_cap` bytes at a time
//!   (`more = 1`), with the hop's moved bytes as its reported units;
//! * every other request-path op answers REFUSED (TRANSITIONAL: filled when the kernel's plane
//!   driver serves the request path).
//!
//! The two transcripts must be identical, and the validate refusal must be the exact sentence.

use std::ptr::{null, null_mut};
use std::sync::Arc;

use crate::both_ways::plane_door_fixture as fixture;
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, Span, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn, PlaneDriveOut,
    PlaneOpenIn, PlaneOpenOut, PlaneRefreshOut, RecordWrite, RefusalIn, RefusalOut, UnitCount,
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, REFUSAL_ARRIVE,
    REFUSAL_GATE, REFUSAL_KERNEL,
};
use fixture::arrival::H_VERSION;
use fixture::door::{DIALECT_DOCUMENT, DIALECT_FRAMED, DIALECT_TARGET, ROUTES};
use fixture::MOUNT_PATH as MOUNT;

use crate::dispatch::kinds::plane::{OwnedSnapshot, Plane};
use crate::dispatch::{
    in_head, load_dropped, load_linked, out_head, rendering_of, Bind, DispatchConfig, Dispatcher,
    Frame, LinkedRow, NoSink, Plugin,
};

/// The settings the script opens with: one fronted agent.
const GOOD: &[u8] =
    br#"{"vendor": {"url": "https://vendor.example/agent", "pin": {"mechanism": "unpinned"}}}"#;
/// A registration the grammar refuses.
const BAD: &[u8] =
    br#"{"vendor": {"url": "ftp://vendor.example", "pin": {"mechanism": "unpinned"}}}"#;
/// The grammar's own sentence for [`BAD`] (the predev refusal bytes).
const BAD_SENTENCE: &str =
    "`agents.vendor`: `url:` must be an http:// or https:// endpoint, got `ftp://vendor.example`";
/// The deployment's public base URL.
const PUBLIC: &[u8] = b"https://gw.example";

/// The one dispatcher both doors bind to, held for the test binary's life.
fn dispatcher() -> &'static Dispatcher {
    static ONE: std::sync::OnceLock<Dispatcher> = std::sync::OnceLock::new();
    ONE.get_or_init(|| Dispatcher::new(DispatchConfig::default()))
}

fn bind() -> Bind {
    Bind {
        instance: Arc::from("both-ways"),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher().adopter(),
        conns: None,
    }
}

fn json(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// The bytes of `path` under the plane's mount, held for the test binary's life.
fn at(path: &str) -> &'static [u8] {
    Box::leak(format!("{MOUNT}{path}").into_boxed_str()).as_bytes()
}

fn text(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

/// The host's copy of a snapshot, as one line.
fn snapshot(s: Option<OwnedSnapshot>) -> String {
    let Some(s) = s else {
        return "no snapshot".to_string();
    };
    let mut out = format!(
        "gen={} audience={} metadata={} openapi_bytes={}",
        s.generation,
        s.audience.as_deref().unwrap_or("-"),
        s.resource_metadata.as_deref().unwrap_or("-"),
        s.openapi.as_ref().map_or(0, Vec::len)
    );
    for c in &s.claims {
        out.push_str(&format!(
            " | {} {} {} flags={}",
            c.verb, c.target, c.carrier, c.flags
        ));
    }
    for r in &s.admin_routes {
        out.push_str(&format!(
            " | admin {} {} flags={}",
            r.verb, r.target, r.flags
        ));
    }
    out
}

fn linked() -> Plugin<Plane> {
    let row = LinkedRow::of(fixture::plane_door::door).expect("the door states");
    load_linked::<Plane>(&row, bind()).expect("the linked door loads")
}

/// The example `cdylib` in this target dir. Under CI a missing artifact is a failure, never a skip.
fn dropped() -> Option<Plugin<Plane>> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}plane_door_fixture{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    assert!(
        path.exists() || std::env::var_os("CI").is_none(),
        "the plane_door_fixture example is not built under CI; a both-ways proof must not skip"
    );
    let stated = rendering_of(fixture::plane_door::door).expect("the door renders");
    path.exists()
        .then(|| load_dropped::<Plane>(&path, &stated, bind()).expect("the dropped door loads"))
}

fn gen_frame(generation: u64) -> Frame<GenIn, busbar_contract::abi::mechanism::call::OutHead> {
    Frame::new(
        GenIn {
            head: in_head(),
            generation,
        },
        out_head(),
    )
}

/// One JSON-RPC request the line classes.
const SEND: &[u8] = br#"{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}"#;

/// `refusal` over `words` for `cause` at `status` in `dialect`, as one line: the outcome, the
/// status the rendering names, its head fields and its body.
fn refuse(p: &Plugin<Plane>, cause: u32, status: u32, dialect: u32, words: &[u8]) -> String {
    let none = Span { offset: 0, len: 0 };
    let mut reply = vec![0_u8; 4096];
    let mut fields = vec![
        OutField {
            name: none,
            value: none,
        };
        4
    ];
    let mut arena = vec![0_u8; 256];
    let mut r = Frame::new(
        RefusalIn {
            head: in_head(),
            cause,
            status,
            dialect,
            reason: 0,
            text: AbiStr {
                ptr: words.as_ptr(),
                len: words.len(),
            },
            reply_buf: reply.as_mut_ptr(),
            reply_cap: reply.len(),
            fields_buf: fields.as_mut_ptr(),
            fields_cap: fields.len(),
            arena_buf: arena.as_mut_ptr(),
            arena_cap: arena.len(),
            unit: 0,
            plane_code: 0,
            retry_after_s: 0,
            target: AbiStr {
                ptr: null(),
                len: 0,
            },
        },
        RefusalOut {
            head: out_head(),
            reply_written: 0,
            reply_needed: 0,
            arena_written: 0,
            arena_needed: 0,
            marker: 0,
            fields_written: 0,
            fields_needed: 0,
            status: 0,
        },
    );
    let c = p.call(slot::REFUSAL, &mut r);
    let at = |s: Span| String::from_utf8_lossy(&arena[s.offset as usize..][..s.len as usize]);
    let named: Vec<String> = fields[..r.out.fields_written as usize]
        .iter()
        .map(|f| format!("{}: {}", at(f.name), at(f.value)))
        .collect();
    format!(
        "refusal cause={cause} dialect={dialect} {:?} status={} marker={} [{}] {}",
        c.outcome,
        r.out.status,
        r.out.marker,
        named.join(", "),
        String::from_utf8_lossy(&reply[..r.out.reply_written as usize])
    )
}

/// The extended-card read the relay script sends one agent.
const CARD_ASK: &[u8] = br#"{"jsonrpc":"2.0","id":9,"method":"GetExtendedAgentCard"}"#;
/// The agent's answer to it.
const CARD_ANSWER: &[u8] = br#"{"jsonrpc":"2.0","id":9,"result":{"name":"Vendor"}}"#;

/// One `on_piece` of `unit` from `from` (with `flags`, `status`, `bytes`, the ATTEMPT's `member`),
/// over a reply buffer of `reply_cap` bytes, as one line: the outcome, the emit flags, `more`, the
/// reply status, the verb and target, the head fields, the units and the emitted bytes.
#[allow(clippy::too_many_arguments)] // one piece's inputs, each a column of the line
fn piece(
    p: &Plugin<Plane>,
    unit: u64,
    from: u32,
    flags: u32,
    status: u32,
    bytes: &'static [u8],
    member: &'static [u8],
    reply_cap: usize,
) -> String {
    let none = Span { offset: 0, len: 0 };
    let mut reply = vec![0_u8; reply_cap];
    let mut units = vec![
        UnitCount {
            class: 0,
            source: 0,
            amount: 0,
        };
        2
    ];
    let mut records = vec![
        RecordWrite {
            kind: 0,
            op: 0,
            key: none,
            value: none,
        };
        1
    ];
    let mut fields = vec![
        OutField {
            name: none,
            value: none,
        };
        4
    ];
    let mut arena = vec![0_u8; 256];
    let blank = AbiStr {
        ptr: null(),
        len: 0,
    };
    let mut f = Frame::new(
        OnPieceIn {
            head: in_head(),
            unit,
            from,
            flags,
            stream: 0,
            bytes: json(bytes),
            status_code: status,
            status_class: 0,
            reply_buf: reply.as_mut_ptr(),
            reply_cap: reply.len(),
            units_buf: units.as_mut_ptr(),
            units_cap: units.len(),
            records_buf: records.as_mut_ptr(),
            records_cap: records.len(),
            fields_buf: fields.as_mut_ptr(),
            fields_cap: fields.len(),
            arena_buf: arena.as_mut_ptr(),
            arena_cap: arena.len(),
            member: if member.is_empty() {
                blank
            } else {
                text(member)
            },
            attempt_no: u32::from(from == FROM_KERNEL),
            _reserved: 0,
            pool: blank,
            caller_ref: blank,
            claim: 0,
            dialect: DIALECT_DOCUMENT,
            head_fields: null(),
            head_fields_len: 0,
            passthrough: 0,
            _reserved_tail: 0,
        },
        OnPieceOut {
            head: out_head(),
            emitted: 0,
            more: 0,
            flags: 0,
            reply_status: 0,
            fields_written: 0,
            fields_needed: 0,
            units_written: 0,
            units_needed: 0,
            records_written: 0,
            records_needed: 0,
            verdict: 0,
            arena_written: 0,
            arena_needed: 0,
            verb: none,
            target: none,
        },
    );
    let c = p.call(slot::ON_PIECE, &mut f);
    let o = f.out;
    let at = |s: Span| String::from_utf8_lossy(&arena[s.offset as usize..][..s.len as usize]);
    let named: Vec<String> = fields[..o.fields_written as usize]
        .iter()
        .map(|f| format!("{}: {}", at(f.name), at(f.value)))
        .collect();
    let counted: Vec<String> = units[..o.units_written as usize]
        .iter()
        .map(|u| format!("{}/{}={}", u.class, u.source, u.amount))
        .collect();
    format!(
        "piece {:?} flags={} more={} status={} {} {} [{}] units=[{}] {}",
        c.outcome,
        o.flags,
        o.more,
        o.reply_status,
        at(o.verb),
        at(o.target),
        named.join(", "),
        counted.join(" "),
        String::from_utf8_lossy(&reply[..o.emitted as usize])
    )
}

/// THE SCRIPT: the lifecycle end to end, then the request path.
fn script(p: &Plugin<Plane>) -> Vec<String> {
    let mut t = Vec::new();

    let mut reason = vec![0_u8; 1024];
    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(BAD),
            err_buf: reason.as_mut_ptr(),
            err_cap: reason.len(),
        },
        out_head(),
    );
    let c = p.call(life::VALIDATE, &mut v);
    t.push(format!(
        "validate bad {:?} {}",
        c.outcome,
        String::from_utf8_lossy(&c.error.unwrap_or_default())
    ));
    v.input.settings = json(GOOD);
    t.push(format!(
        "validate {:?}",
        p.call(life::VALIDATE, &mut v).outcome
    ));

    let mut o = Frame::new(
        PlaneOpenIn {
            open: OpenIn {
                head: in_head(),
                host: null(),
                settings: json(GOOD),
                secrets: null(),
                secrets_len: 0,
                generation: 1,
                err_buf: null_mut(),
                err_cap: 0,
            },
            public_url: text(PUBLIC),
        },
        PlaneOpenOut {
            open: OpenOut {
                head: out_head(),
                instance: null_mut(),
                err_len: 0,
            },
            snapshot: null(),
        },
    );
    let (c, s) = p.open(&mut o);
    t.push(format!("open {:?} {}", c.outcome, snapshot(s)));

    let mut r = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: json(GOOD),
            secrets: null(),
            secrets_len: 0,
        },
        PlaneRefreshOut {
            head: out_head(),
            snapshot: null(),
        },
    );
    let (c, s) = p.refresh(&mut r);
    t.push(format!("refresh {:?} {}", c.outcome, snapshot(s)));

    t.push(format!(
        "retire 1 {:?}",
        p.call(life::RETIRE, &mut gen_frame(1)).outcome
    ));

    let mut k = Frame::new(
        TickIn {
            head: in_head(),
            now_ns: 5,
        },
        TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    let c = p.call(life::TICK, &mut k);
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

    let mut d = Frame::new(
        PlaneDriveIn {
            drive: DriveIn {
                head: in_head(),
                driver: Ticket::NONE,
            },
            sessions_buf: null_mut(),
            sessions_cap: 0,
        },
        PlaneDriveOut {
            head: out_head(),
            sessions_written: 0,
            sessions_needed: 0,
        },
    );
    let c = p.call(life::DRIVE, &mut d);
    t.push(format!(
        "drive {:?} sessions={}",
        c.outcome, d.out.sessions_written
    ));

    let mut x = Frame::new(
        CancelIn {
            head: in_head(),
            ticket: Ticket::NONE,
        },
        CancelOut {
            head: out_head(),
            disposition: 0,
            _reserved: 0,
        },
    );
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!(
        "cancel {:?} disposition={}",
        c.outcome, x.out.disposition
    ));

    // The request path. An arrival on a line other than JSON-RPC is REFUSED, TRANSITIONAL until
    // the kernel's plane driver serves it.
    let mut a = Frame::new(
        ArriveIn {
            head: in_head(),
            unit: 1,
            claim: 0,
            _reserved: 0,
            target: text(at("")),
            fields: null(),
            fields_len: 0,
            body: json(b"{}"),
            units_buf: null_mut(),
            units_cap: 0,
            method: text(b"POST"),
        },
        ArriveOut {
            head: out_head(),
            op_class: 0,
            principal_need: 0,
            dialect: 0,
            units_written: 0,
            units_needed: 0,
            refusal: 0,
            refusal_status: 0,
            _reserved: 0,
            correlation: 0,
            cancels: 0,
        },
    );
    t.push(format!("arrive {:?}", p.call(slot::ARRIVE, &mut a).outcome));

    // The JSON-RPC line: a request is classed, spoken in the line's dialect, and needs a principal.
    let line = ROUTES
        .iter()
        .position(|r| r.verb == "POST" && r.target == MOUNT)
        .expect("the JSON-RPC endpoint");
    a.input.claim = u32::try_from(line).expect("an index");
    a.input.unit = 2;
    a.input.body = json(SEND);
    let c = p.call(slot::ARRIVE, &mut a);
    t.push(format!(
        "arrive jsonrpc {:?} op={} dialect={} principal={}",
        c.outcome, a.out.op_class, a.out.dialect, a.out.principal_need
    ));
    // A media type the line does not read is refused in the plane's own words ...
    let head = [Field {
        name: text(b"content-type"),
        value: text(b"text/plain"),
    }];
    a.input.unit = 3;
    a.input.fields = head.as_ptr();
    a.input.fields_len = head.len();
    let c = p.call(slot::ARRIVE, &mut a);
    let words = c.error.unwrap_or_default();
    t.push(format!(
        "arrive refused {:?} {}",
        c.outcome,
        String::from_utf8_lossy(&words)
    ));
    // ... which `refusal` renders with the plane's status; a kernel refusal keeps the kernel's.
    t.push(refuse(p, REFUSAL_ARRIVE, 400, DIALECT_DOCUMENT, &words));
    t.push(refuse(
        p,
        REFUSAL_KERNEL,
        403,
        DIALECT_TARGET,
        b"this key may not reach that agent",
    ));
    // On the framed line the plane's own refusal is the envelope at its neutral status; a gate's no
    // keeps the kernel's status and its marker, which the plane never sets.
    t.push(refuse(p, REFUSAL_ARRIVE, 400, DIALECT_FRAMED, &words));
    t.push(refuse(
        p,
        REFUSAL_GATE,
        403,
        DIALECT_DOCUMENT,
        b"a gate said no",
    ));
    // A method the vocabulary does not list is relayed, never refused: classed as the unary hop.
    a.input.unit = 4;
    a.input.fields = null();
    a.input.fields_len = 0;
    a.input.body = json(br#"{"jsonrpc":"2.0","id":2,"method":"vendor/Thing"}"#);
    let c = p.call(slot::ARRIVE, &mut a);
    t.push(format!(
        "arrive unlisted {:?} op={} dialect={}",
        c.outcome, a.out.op_class, a.out.dialect
    ));
    // THE UNARY RELAY: the extended card of the agent the caller addressed.
    let line = ROUTES
        .iter()
        .position(|r| r.verb == "POST" && r.target == format!("{MOUNT}/agents/{{agent_id}}"))
        .expect("the per-agent JSON-RPC endpoint");
    a.input.claim = u32::try_from(line).expect("an index");
    a.input.unit = 5;
    a.input.target = text(at("/agents/vendor"));
    a.input.body = json(CARD_ASK);
    let c = p.call(slot::ARRIVE, &mut a);
    t.push(format!("arrive card {:?}", c.outcome));
    t.push(piece(p, 5, FROM_KERNEL, 0, 0, b"", b"vendor", 64));
    t.push(piece(p, 5, FROM_CALLER, PIECE_LAST, 0, CARD_ASK, b"", 4096));
    let last = PIECE_LAST | PIECE_HAS_STATUS;
    t.push(piece(p, 5, FROM_FAR_END, last, 200, CARD_ANSWER, b"", 32));
    t.push(piece(p, 5, FROM_FAR_END, 0, 0, b"", b"", 4096));
    t.push(format!(
        "piece after done {}",
        piece(p, 5, FROM_FAR_END, last, 200, CARD_ANSWER, b"", 4096)
    ));
    // A unit `on_piece` does not serve yet (a task-bearing verb) is REFUSED.
    t.push(format!(
        "piece unserved {}",
        piece(p, 2, FROM_KERNEL, 0, 0, b"", b"vendor", 64)
    ));
    // THE TARGET LINE: the envelope its request spells, decided as the JSON-RPC line decides it,
    // in the line's dialect; a `POST /tasks/{id}` naming no verb is the engine's 404 in its words.
    let rest_line = |verb: &str, target: &str| {
        let at = ROUTES
            .iter()
            .position(|r| r.verb == verb && r.target == target)
            .expect("a target-line route");
        u32::try_from(at).expect("an index")
    };
    a.input.claim = rest_line("GET", &format!("{MOUNT}/tasks"));
    a.input.unit = 6;
    a.input.target = text(at("/tasks?pageSize=5&status=working"));
    a.input.body = json(b"");
    let c = p.call(slot::ARRIVE, &mut a);
    t.push(format!(
        "arrive rest {:?} op={} dialect={}",
        c.outcome, a.out.op_class, a.out.dialect
    ));
    a.input.claim = rest_line("POST", &format!("{MOUNT}/tasks/{{id}}"));
    a.input.unit = 7;
    a.input.target = text(at("/tasks/t-1:bogus"));
    let c = p.call(slot::ARRIVE, &mut a);
    t.push(format!(
        "arrive rest refused {:?} {}",
        c.outcome,
        String::from_utf8_lossy(&c.error.unwrap_or_default())
    ));
    for s in [slot::HYDRATE, slot::START] {
        t.push(format!("{s} {:?}", p.call(s, &mut gen_frame(2)).outcome));
    }
    t
}

#[test]
fn the_plane_door_answers_identically_linked_and_dropped_in() {
    let linked = script(&linked());
    assert_eq!(
        linked[0],
        format!("validate bad {:?} {BAD_SENTENCE}", Outcome::Refused),
        "the door refuses in the grammar's own sentence"
    );
    assert!(
        linked[2].starts_with(&format!(
            "open {:?} gen=1 audience=https://gw.example{MOUNT}",
            Outcome::Ready
        )),
        "{}",
        linked[2]
    );
    assert!(
        linked[3].starts_with(&format!("refresh {:?} gen=2", Outcome::Ready)),
        "{}",
        linked[3]
    );
    let line = |prefix: &str| {
        linked
            .iter()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no `{prefix}` line in {linked:?}"))
            .clone()
    };
    assert_eq!(
        line("arrive jsonrpc"),
        format!(
            "arrive jsonrpc {:?} op=0 dialect={DIALECT_DOCUMENT} principal=1",
            Outcome::Ready
        ),
        "SendMessage is the message_send class, on the JSON-RPC dialect, with a principal"
    );
    let list = fixture::door::op_class_index(fixture::ops::OP_TASK_LIST)
        .expect("ListTasks is a declared class");
    assert_eq!(
        line("arrive rest "),
        format!(
            "arrive rest {:?} op={list} dialect={DIALECT_TARGET}",
            Outcome::Ready
        ),
        "GET {MOUNT}/tasks arrives as ListTasks on the target dialect"
    );
    assert!(
        line("arrive rest refused").starts_with(&format!(
            "arrive rest refused {:?} 404 -32601 null\n`t-1:bogus` names no operation",
            Outcome::Refused
        )),
        "{}",
        line("arrive rest refused")
    );
    assert!(
        line("arrive refused").starts_with(&format!(
            "arrive refused {:?} 415 -32005 null\n",
            Outcome::Refused
        )),
        "{}",
        line("arrive refused")
    );
    let own = line(&format!(
        "refusal cause={REFUSAL_ARRIVE} dialect={DIALECT_DOCUMENT}"
    ));
    assert!(
        own.contains("status=415 marker=0 [content-type: application/json] {")
            && own.contains(r#""code":-32005"#)
            && own.contains(r#""reason":"CONTENT_TYPE_NOT_SUPPORTED""#),
        "{own}"
    );
    let kernel = line(&format!("refusal cause={REFUSAL_KERNEL}"));
    assert!(
        kernel.contains("status=0 marker=0 [content-type: application/json] {")
            && kernel.contains(r#""code":403"#)
            && kernel.contains(r#""status":"UNIMPLEMENTED""#),
        "{kernel}"
    );
    let framed = line(&format!(
        "refusal cause={REFUSAL_ARRIVE} dialect={DIALECT_FRAMED}"
    ));
    assert_eq!(
        framed.split_once(' ').map(|(_, rest)| rest.replacen(
            &format!("dialect={DIALECT_FRAMED}"),
            &format!("dialect={DIALECT_DOCUMENT}"),
            1
        )),
        own.split_once(' ').map(|(_, rest)| rest.to_string()),
        "the framed line renders the envelope at the same neutral status"
    );
    let gate = line(&format!("refusal cause={REFUSAL_GATE}"));
    assert!(
        gate.contains("marker=0"),
        "the plane never sets the gate marker: {gate}"
    );
    for l in linked.iter().filter(|l| l.starts_with("refusal")) {
        assert!(l.contains(" marker=0 "), "{l}");
    }
    assert_eq!(
        line("arrive unlisted"),
        format!(
            "arrive unlisted {:?} op=0 dialect={DIALECT_DOCUMENT}",
            Outcome::Ready
        ),
        "an unlisted method is the message_send class, never refused"
    );
    // THE UNARY RELAY, in the engine's bytes (`relay::build_request`, `receive::unary_hop`).
    let relay: Vec<&String> = linked
        .iter()
        .skip_while(|l| !l.starts_with("arrive card"))
        .take(7)
        .collect();
    let ready = format!("{:?}", Outcome::Ready);
    assert_eq!(relay[0], &format!("arrive card {ready}"));
    assert_eq!(
        relay[1],
        &format!(
            "piece {ready} flags=1 more=0 status=0 POST /agent [content-type: application/json, \
             accept: application/json, {H_VERSION}: 0.3] units=[] "
        ),
        "the ATTEMPT posts to the agent's own path with the engine's three fields"
    );
    assert_eq!(
        relay[2],
        &format!(
            "piece {ready} flags=1 more=0 status=0   [] units=[] {}",
            String::from_utf8_lossy(CARD_ASK)
        ),
        "the caller's body goes to the far end verbatim"
    );
    let moved = CARD_ASK.len() + CARD_ANSWER.len();
    // Built as the engine builds it: the envelope's members in the order `json!` writes them.
    let answer = serde_json::to_string(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": 9,
        "result": {"name": "Vendor"},
    }))
    .expect("json");
    assert_eq!(
        relay[3],
        &format!(
            "piece {ready} flags=0 more=1 status=200   [content-type: application/json] \
             units=[0/1={moved}] {}",
            &answer[..32]
        ),
        "the answer starts with its status and media type, {} bytes at a time",
        32
    );
    assert_eq!(
        relay[4],
        &format!(
            "piece {ready} flags=2 more=0 status=0   [] units=[0/1={moved}] {}",
            &answer[32..]
        ),
        "the re-call writes the rest and ends the unit"
    );
    assert_eq!(
        relay[5],
        &format!(
            "piece after done piece {:?} flags=0 more=0 status=0   [] units=[] ",
            Outcome::Refused
        ),
        "a finished unit is forgotten"
    );
    assert!(
        relay[6].starts_with(&format!("piece unserved piece {:?}", Outcome::Refused)),
        "{}",
        relay[6]
    );
    if let Some(dropped) = dropped() {
        assert_eq!(
            script(&dropped),
            linked,
            "linked and dropped-in answer alike"
        );
    }
}
