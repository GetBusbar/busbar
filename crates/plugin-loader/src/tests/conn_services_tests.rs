// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR SLOTS, both ways: an instance whose Statement declares a need is handed the slots
//! and its needs are declared on the host's one connection table (the whole need, under its
//! Statement index) — a need whose `target_from` names a config path at `open` and every `refresh`,
//! pinned to what the path resolves to in the settings (ARCHITECT ruling 2026-09-30 on the conns
//! fill, option A); `ESTABLISH` reaches the table under the instance's own identity. An instance
//! that declares no need is handed no table, and the table refuses an open under its identity.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::conn::connector::{service, EstablishIn, Need, DIRECTION_OUTBOUND};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{Door, Statement};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, RefreshIn};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
};
use busbar_contract::transport::ConnFacts;

use super::CONN_SLOTS;
use crate::dispatch::load::validate_door;
use crate::dispatch::{in_head, out_head, Adopter, Bind, Frame, NoSink, Plugin, NO_BLOB};
use crate::dispatch_test_plugin as plug;
use crate::dispatch_tests::TestKind;

/// One declaration as it reached the table: owner, need, the need, the target it resolved to.
type Declared = (InstanceId, NeedId, ReadNeed, Option<String>);

/// A connection table that records what reached it, ownership kept by the shared [`ConnSlab`].
#[derive(Default)]
struct Recording {
    slab: ConnSlab<()>,
    declared: Mutex<Vec<Declared>>,
    opened: Mutex<Vec<(InstanceId, NeedId, String)>>,
}

impl DeclaredConns for Recording {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
    ) -> Result<(), ConnError> {
        self.declared
            .lock()
            .unwrap()
            .push((owner, need, spec.clone(), target.map(str::to_owned)));
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
}

impl Conns for Recording {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let id = self.slab.insert(caller, need, ())?;
        self.opened
            .lock()
            .unwrap()
            .push((caller, need, desc.target.to_owned()));
        Ok(id)
    }
    fn write(&self, _: InstanceId, _: ConnId, _: &[u8], _: bool) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(&self, _: InstanceId, _: ConnId, _: u64, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Closed)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
        Ok(())
    }
}

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

const NEEDS: [Need; 1] = [Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: 0,
    transport: abi_str("sock"),
    auth: NONE,
    target_from: abi_str("settings.upstream"),
    trust_from: NONE,
    details: NO_BLOB,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
}];

/// The test plugin's door, its Statement declaring `needs`, bound over `table`.
fn bound(needs: &'static [Need], table: &Arc<Recording>) -> Plugin<TestKind> {
    // SAFETY: the real door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..st
    }));
    let door: &'static Door = Box::leak(Box::new(Door {
        statement: st,
        ..real
    }));
    let v = validate_door::<TestKind>(door).expect("the door validates");
    let conns: Arc<dyn DeclaredConns> = table.clone();
    Plugin::bind(
        v,
        None,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: Some(conns),
        },
    )
    .expect("the instance binds")
}

/// `ESTABLISH` through the slots, under `p`'s context, for `need` at `target`.
fn establish(p: &Plugin<TestKind>, need: u32, target: &'static str) -> ServiceOut {
    let i = EstablishIn {
        head: ServiceHead {
            size: std::mem::size_of::<EstablishIn>() as u32,
            op: service::ESTABLISH,
            handle: CompletionHandle {
                ticket: Ticket::NONE,
                seq: 0,
                _reserved: 0,
            },
        },
        need,
        _reserved: 0,
        target: abi_str(target),
        within: NONE,
    };
    // SAFETY: an all-zero `ServiceOut` is a valid value the slot overwrites.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    let slot = CONN_SLOTS.establish.expect("ESTABLISH is served");
    let _: RawOutcome = slot(p.inner.ctx(), std::ptr::from_ref(&i).cast(), &mut out);
    out
}

/// A JSON settings blob over `json`.
fn settings(json: &'static [u8]) -> Blob {
    Blob {
        ptr: json.as_ptr(),
        len: json.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// `open` with `json` as the instance's settings, ticket-less.
fn open_with(p: &Plugin<TestKind>, json: &'static [u8]) -> Outcome {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: settings(json),
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    p.call(slot::OPEN, &mut f).outcome
}

/// `refresh` with `json` as the instance's new settings, ticket-less.
fn refresh_with(p: &Plugin<TestKind>, json: &'static [u8]) -> Outcome {
    let mut f = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: settings(json),
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        out_head(),
    );
    p.call(slot::REFRESH, &mut f).outcome
}

/// The targets `table` was last declared with for `p`'s need 0, oldest first.
fn targets(table: &Recording, p: &Plugin<TestKind>) -> Vec<Option<String>> {
    table
        .declared
        .lock()
        .unwrap()
        .iter()
        .filter(|(owner, need, _, _)| (*owner, *need) == (p.instance(), NeedId(0)))
        .map(|(_, _, _, target)| target.clone())
        .collect()
}

/// RED: the instance that declares a need is handed the slots; its config-targeted need is not
/// declared at bind (an establish before `open` is refused as undeclared), and at `open` it is
/// declared whole — its target source intact — pinned to the target its `target_from` resolves to
/// in the settings, after which `ESTABLISH` opens it under the instance's own identity.
#[test]
fn an_instance_with_a_declared_need_is_declared_and_its_establish_reaches_the_table() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    assert!(!p.inner.conns_table().is_null(), "it is handed the slots");
    assert!(
        table.declared.lock().unwrap().is_empty(),
        "a config-targeted need waits for its settings"
    );
    assert_eq!(
        establish(&p, 0, "127.0.0.1:9").outcome,
        RawOutcome::of(Outcome::Refused),
        "an establish before open is undeclared"
    );
    assert_eq!(
        open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#),
        Outcome::Ready
    );
    let declared = table.declared.lock().unwrap().clone();
    assert_eq!(declared.len(), 1);
    let (owner, need, spec, target) = &declared[0];
    assert_eq!((*owner, *need), (p.instance(), NeedId(0)));
    assert_eq!(spec.direction, DIRECTION_OUTBOUND);
    assert_eq!(spec.transport, "sock");
    assert_eq!(
        spec.target_from, "settings.upstream",
        "the target source reaches declare intact"
    );
    assert_eq!(
        target.as_deref(),
        Some("127.0.0.1:9"),
        "pinned to its setting"
    );
    let out = establish(&p, 0, "127.0.0.1:9");
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Ready));
    assert_eq!(
        table.opened.lock().unwrap().as_slice(),
        &[(p.instance(), NeedId(0), "127.0.0.1:9".to_owned())]
    );
}

/// RED: a `refresh` that changes the setting re-declares the need at the new target, and one whose
/// `target_from` resolves to nothing declares it without a target, which the table refuses.
#[test]
fn a_refresh_re_declares_a_config_targeted_need_at_its_new_target() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    assert_eq!(
        open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#),
        Outcome::Ready
    );
    assert_eq!(
        refresh_with(&p, br#"{"upstream":"127.0.0.2:9"}"#),
        Outcome::Ready
    );
    assert_eq!(
        refresh_with(&p, br#"{"other":"127.0.0.3:9"}"#),
        Outcome::Ready
    );
    assert_eq!(
        targets(&table, &p),
        vec![
            Some("127.0.0.1:9".to_owned()),
            Some("127.0.0.2:9".to_owned()),
            None
        ]
    );
}

/// `target_from` names `settings.<key>[.<key>...]`, walked to a non-empty string.
#[test]
fn a_target_from_path_resolves_only_to_a_non_empty_string_under_settings() {
    use crate::dispatch::plugin::resolve_target;
    let doc = serde_json::json!({
        "upstream": "db:5432",
        "nested": {"url": "h:1"},
        "n": 3,
        "e": "",
    });
    assert_eq!(
        resolve_target(&doc, "settings.upstream").as_deref(),
        Some("db:5432")
    );
    assert_eq!(
        resolve_target(&doc, "settings.nested.url").as_deref(),
        Some("h:1")
    );
    for miss in [
        "settings.n",
        "settings.e",
        "settings.absent",
        "upstream",
        "settings.nested",
    ] {
        assert_eq!(resolve_target(&doc, miss), None, "{miss}");
    }
}

/// RED: an instance that declares no need is handed no table, its slots (reached anyway) answer
/// that it is unarmed, and the table refuses an open under its identity as undeclared.
#[test]
fn an_instance_without_a_need_is_handed_no_table_and_its_open_is_undeclared() {
    let table = Arc::new(Recording::default());
    let p = bound(&[], &table);
    assert!(p.inner.conns_table().is_null(), "no need, no table");
    assert!(table.declared.lock().unwrap().is_empty());
    let out = establish(&p, 0, "127.0.0.1:9");
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Refused));
    assert_eq!(
        table.open(p.instance(), NeedId(0), &OpenDesc::default()),
        Err(ConnError::UndeclaredNeed)
    );
    assert_ne!(
        bound(Box::leak(Box::new(NEEDS)), &table).instance(),
        p.instance(),
        "every bind mints its own identity"
    );
}

// ── FRAMED REQUESTS, REPLIES AND THE REPLAY RULE ──

use std::collections::VecDeque;

use busbar_contract::abi::host::conn::connector::{
    IoIn, ReplyIn, ReplyPiece, RequestIn, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END,
    REPLY_HEAD, REQUEST_BODY, REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::host::service::ServiceFn;
use busbar_contract::abi::transport::FrameSpan;
use busbar_contract::conn::PieceKind;
use busbar_contract::ids::StreamId;

/// What one open carried: the need, target, head words, fields and body.
type Opened = (
    NeedId,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<(String, Vec<u8>)>,
    Vec<u8>,
);

/// A connection table whose needs are framed (or not), whose opens are recorded (or refused) and
/// whose reads answer a script, one piece and its bytes per read.
#[derive(Default)]
struct Scripted {
    slab: ConnSlab<()>,
    framed: bool,
    refuse: Option<ConnError>,
    opened: Mutex<Vec<Opened>>,
    /// The address set each open was stated within, in open order.
    within: Mutex<Vec<Vec<std::net::IpAddr>>>,
    writes: Mutex<Vec<Vec<u8>>>,
    script: Mutex<VecDeque<(Piece, Vec<u8>)>>,
}

impl DeclaredConns for Scripted {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        self.framed
    }
}

impl Conns for Scripted {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        self.opened.lock().unwrap().push((
            need,
            desc.target.to_owned(),
            desc.method.to_vec(),
            desc.head_target.to_vec(),
            desc.fields
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
                .collect(),
            desc.body.to_vec(),
        ));
        self.within.lock().unwrap().push(desc.within.to_vec());
        if let Some(e) = self.refuse {
            return Err(e);
        }
        self.slab.insert(caller, need, ())
    }
    fn write(&self, c: InstanceId, id: ConnId, b: &[u8], _: bool) -> Result<usize, ConnError> {
        self.slab.get(c, id)?;
        self.writes.lock().unwrap().push(b.to_vec());
        Ok(b.len())
    }
    fn read(&self, c: InstanceId, id: ConnId, _: u64, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        let (mut p, bytes) = self
            .script
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(ConnError::Pending)?;
        buf[..bytes.len()].copy_from_slice(&bytes);
        p.len = p.len.min(bytes.len());
        Ok(p)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.slab.remove(c, id).map(|_| ())
    }
}

/// A need the plugin names the target of: declared at bind.
const NAMED: [Need; 1] = [Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: 0,
    transport: abi_str("sock"),
    auth: NONE,
    target_from: NONE,
    trust_from: NONE,
    details: NO_BLOB,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
}];

/// The ticket every op in these tests runs on.
const T: Ticket = Ticket {
    slot: 7,
    generation: 3,
};

fn bound_over(table: &Arc<Scripted>) -> Plugin<TestKind> {
    // SAFETY: the real door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: NAMED.as_ptr(),
        needs_len: NAMED.len(),
        ..st
    }));
    let door: &'static Door = Box::leak(Box::new(Door {
        statement: st,
        ..real
    }));
    let v = validate_door::<TestKind>(door).expect("the door validates");
    let conns: Arc<dyn DeclaredConns> = table.clone();
    Plugin::bind(
        v,
        None,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: Some(conns),
        },
    )
    .expect("the instance binds")
}

fn head_of<I>(op: u32, seq: u32) -> ServiceHead {
    ServiceHead {
        size: std::mem::size_of::<I>() as u32,
        op,
        handle: CompletionHandle {
            ticket: T,
            seq,
            _reserved: 0,
        },
    }
}

/// One crossing of `f` with `input`, under `p`'s context.
fn call<I>(p: &Plugin<TestKind>, f: Option<ServiceFn>, input: &I) -> ServiceOut {
    // SAFETY: an all-zero `ServiceOut` is a valid value the slot overwrites.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    let _: RawOutcome =
        f.expect("served")(p.inner.ctx(), std::ptr::from_ref(input).cast(), &mut out);
    out
}

fn opened_stream(p: &Plugin<TestKind>, seq: u32) -> ServiceOut {
    pinned_stream(p, seq, "")
}

/// `ESTABLISH` of need 0 at `127.0.0.1:9`, its dial stated `within` the address set `within`.
fn pinned_stream(p: &Plugin<TestKind>, seq: u32, within: &'static str) -> ServiceOut {
    let i = EstablishIn {
        head: head_of::<EstablishIn>(service::ESTABLISH, seq),
        need: 0,
        _reserved: 0,
        target: abi_str("127.0.0.1:9"),
        within: abi_str(within),
    };
    call(p, CONN_SLOTS.establish, &i)
}

fn request(
    p: &Plugin<TestKind>,
    seq: u32,
    stream: u64,
    piece: &RequestPiece,
    bytes: &[u8],
) -> ServiceOut {
    let i = RequestIn {
        head: head_of::<RequestIn>(service::WRITE_REQUEST, seq),
        stream,
        buf: bytes.as_ptr(),
        len: bytes.len(),
        piece: std::ptr::from_ref(piece),
    };
    call(p, CONN_SLOTS.write_request, &i)
}

fn span(offset: usize, len: usize) -> FrameSpan {
    FrameSpan {
        offset: offset as u64,
        len: len as u64,
    }
}

/// `PATCH /v1/x` with one field, as `exchange()` lays its head out.
const HEAD_BYTES: &[u8] = b"PATCH/v1/xa: 1\r\n";

fn head_piece() -> RequestPiece {
    RequestPiece {
        kind: REQUEST_HEAD,
        _reserved: 0,
        method: span(0, 5),
        target: span(5, 5),
        fields: span(10, 6),
        timeout_ms: 250,
    }
}

fn kind_piece(kind: u32) -> RequestPiece {
    RequestPiece {
        kind,
        ..RequestPiece::default()
    }
}

fn read_reply(
    p: &Plugin<TestKind>,
    seq: u32,
    stream: u64,
    buf: &mut [u8],
) -> (ServiceOut, ReplyPiece) {
    let mut piece = ReplyPiece::default();
    let i = ReplyIn {
        head: head_of::<ReplyIn>(service::READ_REPLY, seq),
        stream,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
        piece: std::ptr::from_mut(&mut piece),
    };
    let out = call(p, CONN_SLOTS.read_reply, &i);
    (out, piece)
}

fn ready(o: &ServiceOut) -> bool {
    o.outcome == RawOutcome::of(Outcome::Ready)
}

fn error_text(o: &ServiceOut) -> String {
    if o.error.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the host's static text.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) })
        .into_owned()
}

fn piece(
    kind: PieceKind,
    code: Option<u32>,
    reason: Option<std::ops::Range<usize>>,
    len: usize,
) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: true,
        status: None,
        status_code: code,
        status_namespace: None,
        retry_after_secs: None,
        reason,
    }
}

/// RED: a framed need's ESTABLISH opens nothing (no request goes out before the plugin wrote
/// one); WRITE_REQUEST's head, body and end then open it ONCE, the whole request its opening
/// message: the head words, the field block's fields, the body and the timeout.
#[test]
fn a_framed_request_goes_out_whole_as_the_opening_message_with_its_head_words() {
    let table = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let est = opened_stream(&p, 0);
    assert!(ready(&est));
    assert!(
        table.opened.lock().unwrap().is_empty(),
        "nothing is sent at establish"
    );
    let stream = est.value;
    let h = request(&p, 1, stream, &head_piece(), HEAD_BYTES);
    assert!(ready(&h));
    assert_eq!(h.len, HEAD_BYTES.len() as u64);
    assert!(ready(&request(
        &p,
        2,
        stream,
        &kind_piece(REQUEST_BODY),
        b"hi"
    )));
    assert!(ready(&request(
        &p,
        3,
        stream,
        &kind_piece(REQUEST_BODY),
        b"!"
    )));
    assert!(
        table.opened.lock().unwrap().is_empty(),
        "nothing is sent before the end"
    );
    assert!(ready(&request(
        &p,
        4,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
    assert_eq!(
        table.opened.lock().unwrap().as_slice(),
        &[(
            NeedId(0),
            "127.0.0.1:9".to_owned(),
            b"PATCH".to_vec(),
            b"/v1/x".to_vec(),
            vec![("a".to_owned(), b"1".to_vec())],
            b"hi!".to_vec()
        )]
    );
}

/// RED: a raw stream refuses WRITE_REQUEST (its bytes go through WRITE), and a framed request's
/// body before its head is refused.
#[test]
fn write_request_is_refused_on_a_raw_stream_and_out_of_order() {
    let raw = Arc::new(Scripted::default());
    let p = bound_over(&raw);
    let stream = opened_stream(&p, 0).value;
    assert_eq!(
        raw.opened.lock().unwrap().len(),
        1,
        "a raw stream opens at establish"
    );
    let o = request(&p, 1, stream, &head_piece(), HEAD_BYTES);
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
    let framed = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let q = bound_over(&framed);
    let held = opened_stream(&q, 0).value;
    let o = request(&q, 1, held, &kind_piece(REQUEST_BODY), b"x");
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
}

/// RED: the reply reads as its head (code, reason exactly as sent, field block), its body, and
/// ONE terminal END; nothing reads after the end.
#[test]
fn a_reply_reads_its_head_its_body_and_one_terminal_end() {
    let table = Arc::new(Scripted::default());
    table.script.lock().unwrap().extend([
        (
            piece(PieceKind::Fields, Some(201), Some(6..16), 6),
            b"x: y\r\nFine By Me".to_vec(),
        ),
        (piece(PieceKind::Body, None, None, 3), b"abc".to_vec()),
        (piece(PieceKind::Completion, None, None, 0), Vec::new()),
    ]);
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let mut buf = [0_u8; 64];
    let (o, h) = read_reply(&p, 1, stream, &mut buf);
    assert!(ready(&o));
    assert_eq!(
        h,
        ReplyPiece {
            kind: REPLY_HEAD,
            code: 201,
            reason: span(6, 10),
            fields: span(0, 6),
        }
    );
    assert_eq!(&buf[6..16], b"Fine By Me");
    let (o, b) = read_reply(&p, 2, stream, &mut buf);
    assert_eq!((b.kind, o.len), (REPLY_BODY, 3));
    assert_eq!(&buf[..3], b"abc");
    let (o, e) = read_reply(&p, 3, stream, &mut buf);
    assert!(ready(&o));
    assert_eq!(e.kind, REPLY_END);
    let (o, _) = read_reply(&p, 4, stream, &mut buf);
    assert_eq!(
        o.outcome,
        RawOutcome::of(Outcome::Failed),
        "one terminal piece"
    );
}

/// RED: a reply that had no head (a raw stream) ends in ONE ack.
#[test]
fn a_reply_without_a_head_ends_in_one_ack() {
    let table = Arc::new(Scripted::default());
    table.script.lock().unwrap().extend([
        (piece(PieceKind::Body, None, None, 2), b"ok".to_vec()),
        (piece(PieceKind::Completion, None, None, 0), Vec::new()),
    ]);
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let mut buf = [0_u8; 8];
    assert_eq!(read_reply(&p, 1, stream, &mut buf).1.kind, REPLY_BODY);
    let (o, ack) = read_reply(&p, 2, stream, &mut buf);
    assert!(ready(&o));
    assert_eq!(ack.kind, REPLY_ACK);
}

/// RED: a framed request whose open the egress class refused is handed over (its end answers),
/// and its reply is the FAILED ACK: the refusal, with its text; the reply has ended.
#[test]
fn an_egress_refusal_is_a_failed_ack_with_its_text() {
    let table = Arc::new(Scripted {
        framed: true,
        refuse: Some(ConnError::Refused),
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    assert!(ready(&request(&p, 1, stream, &head_piece(), HEAD_BYTES)));
    assert!(ready(&request(
        &p,
        2,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
    let mut buf = [0_u8; 8];
    let (o, _) = read_reply(&p, 3, stream, &mut buf);
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
    assert_eq!(error_text(&o), ConnError::Refused.text());
    let (o, _) = read_reply(&p, 4, stream, &mut buf);
    assert_eq!(
        o.outcome,
        RawOutcome::of(Outcome::Failed),
        "the reply has ended"
    );
}

/// RED: the host never runs a service twice: a re-issued ESTABLISH handle answers the same
/// stream without a second open, a re-issued WRITE_REQUEST head is not a second head, and a
/// re-issued WRITE writes once.
#[test]
fn a_replayed_handle_never_runs_its_service_twice() {
    let raw = Arc::new(Scripted::default());
    let p = bound_over(&raw);
    let first = opened_stream(&p, 0);
    let again = opened_stream(&p, 0);
    assert_eq!(again.value, first.value);
    assert_eq!(raw.opened.lock().unwrap().len(), 1, "one open");
    let w = IoIn {
        head: head_of::<IoIn>(service::WRITE, 1),
        stream: first.value,
        buf: b"once".as_ptr().cast_mut(),
        len: 4,
    };
    assert!(ready(&call(&p, CONN_SLOTS.write, &w)));
    assert!(ready(&call(&p, CONN_SLOTS.write, &w)));
    assert_eq!(raw.writes.lock().unwrap().len(), 1, "one write");

    let framed = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let q = bound_over(&framed);
    let stream = opened_stream(&q, 0).value;
    let h = request(&q, 1, stream, &head_piece(), HEAD_BYTES);
    let replayed = request(&q, 1, stream, &head_piece(), HEAD_BYTES);
    assert!(ready(&h));
    assert!(
        ready(&replayed),
        "the replay answers the stored result, not a second head"
    );
    assert_eq!(replayed.len, h.len);
    super::forget(T);
    let fresh = request(&q, 1, stream, &head_piece(), HEAD_BYTES);
    assert_eq!(
        fresh.outcome,
        RawOutcome::of(Outcome::Refused),
        "a forgotten ticket's handle runs afresh"
    );
}

/// THE LANDING RULE AT THE LOADER: ESTABLISH's `within` reaches the connection table's open, the
/// connect, for a raw need at ESTABLISH and for a FRAMED need at WRITE_REQUEST's end, the open
/// that carries the request; so the connector holds its pinned address to the set before the
/// request's bytes leave. An empty `within` states no set (today's open); an entry that is not an
/// IP literal is REFUSED and nothing opens. RED on the loader that dropped `within`.
#[test]
fn establish_within_reaches_the_connect_raw_and_framed() {
    let set: Vec<std::net::IpAddr> = vec![
        "203.0.113.5".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
    ];
    let raw = Arc::new(Scripted::default());
    let p = bound_over(&raw);
    assert!(ready(&pinned_stream(&p, 0, "203.0.113.5,2001:db8::1")));
    assert!(ready(&pinned_stream(&p, 1, "")));
    assert_eq!(
        raw.within.lock().unwrap().as_slice(),
        &[set.clone(), Vec::new()]
    );

    let framed = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let p = bound_over(&framed);
    let stream = pinned_stream(&p, 0, "203.0.113.5,2001:db8::1").value;
    assert!(framed.within.lock().unwrap().is_empty(), "nothing opens at establish");
    assert!(ready(&request(&p, 1, stream, &head_piece(), HEAD_BYTES)));
    assert!(framed.within.lock().unwrap().is_empty(), "nor before the end");
    assert!(ready(&request(&p, 2, stream, &kind_piece(REQUEST_END), b"")));
    assert_eq!(framed.within.lock().unwrap().as_slice(), &[set]);

    let refused = Arc::new(Scripted::default());
    let p = bound_over(&refused);
    for (seq, bad) in [(0, "203.0.113.5,api.example.com"), (1, "203.0.113.5:443")] {
        let o = pinned_stream(&p, seq, bad);
        assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused), "{bad}");
        assert_eq!(
            error_text(&o),
            "an address the dial must land on is not an IP literal"
        );
    }
    assert!(refused.opened.lock().unwrap().is_empty(), "nothing opened");
}
