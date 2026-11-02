// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual distribution's A2A relay, through its typed linked row and actual dropped image.
//! Mounted only by the distribution's ordinary bin tests. Both product origins are mandatory.
//! Original ce4f transfer inputs keep their caller/agent bytes; the peer now authenticates its
//! card and the operator approves it through the real administrative routes.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS, FLAG_RESUME,
};
use busbar_contract::abi::mechanism::lifecycle::{self as life, GenIn, ReleaseIn};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::plane::{slot, *};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::conn::{DeclaredConns, PollConns};
use busbar_kernel::host_services::BlockingPool;
use busbar_kernel::plane_driver::{EndPost, PlaneMoney};
use ed25519_dalek::Signer as _;
use tower::ServiceExt as _;

use crate::root::loader::dispatch::{
    self, kinds::plane::Plane, load_dropped, load_linked, rendering_of_library, Bind, ConnTable,
    DispatchConfig, Dispatcher, Done, Frame, Lent, LinkedRow, NoSink, Plugin,
};

const REQUEST: &[u8] = br##"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m1","contextId":"ctx-7","parts":[{"text":"hi"}]}}}"##;
const ANSWER: &[u8] = br##"{"jsonrpc":"2.0","id":1,"result":{"role":"agent","messageId":"a1","parts":[{"text":"the agent's reply, that buffer that holds the whole request takes the answer in several writes. the agent's reply, long enough that a buffer that holds the whole request takes the answer in several writes. the agent's reply, long enough that a buffer that holds the whole request takes the answer in several writes. ","kind":"text"}],"kind":"message"}}"##;
const ANSWER_OUT: &[u8] = br##"{"jsonrpc":"2.0","id":1,"result":{"role":"agent","messageId":"a1","parts":[{"text":"the agent's reply, that buffer that holds the whole request takes the answer in several writes. the agent's reply, long enough that a buffer that holds the whole request takes the answer in several writes. the agent's reply, long enough that a buffer that holds the whole request takes the answer in several writes. ","kind":"text"}],"kind":"message","contextId":"ctx-7"}}"##;
const REFUSAL: &[u8] = br##"{"error":{"code":-32004,"data":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","domain":"a2a-protocol.org","reason":"UNSUPPORTED_OPERATION"}],"message":"denied"},"id":null,"jsonrpc":"2.0"}"##;
const ADMIN_TOKEN: &str = "a2a-parity-operator-token";
const CAP: usize = 32;
const OPEN_CLAIMS: &[(&str, &str)] = &[
    ("POST", "/a2a/message:send"),
    ("POST", "/a2a/message:stream"),
    ("GET", "/a2a/tasks"),
    ("GET", "/a2a/tasks/{id}"),
    ("POST", "/a2a/tasks/{id}"),
    ("POST", "/a2a/tasks/{id}/pushNotificationConfigs"),
    ("GET", "/a2a/tasks/{id}/pushNotificationConfigs"),
    ("GET", "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}"),
    (
        "DELETE",
        "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}",
    ),
    ("GET", "/a2a/extendedAgentCard"),
    ("GET", "/.well-known/oauth-protected-resource/a2a"),
    ("GET", "/.well-known/agent-card.json"),
    ("GET", "/a2a/agents/{agent_id}/.well-known/agent-card.json"),
    ("GET", "/a2a/agents/{agent_id}"),
    ("POST", "/a2a/agents/{agent_id}"),
    ("POST", "/a2a"),
    ("POST", "/a2a/"),
    ("POST", "/lf.a2a.v1.A2AService/{method}"),
    ("POST", "/a2a/agents/vendor/"),
];
const REFRESH_CLAIMS: &[(&str, &str)] = &[
    ("POST", "/a2a/message:send"),
    ("POST", "/a2a/message:stream"),
    ("GET", "/a2a/tasks"),
    ("GET", "/a2a/tasks/{id}"),
    ("POST", "/a2a/tasks/{id}"),
    ("POST", "/a2a/tasks/{id}/pushNotificationConfigs"),
    ("GET", "/a2a/tasks/{id}/pushNotificationConfigs"),
    ("GET", "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}"),
    (
        "DELETE",
        "/a2a/tasks/{id}/pushNotificationConfigs/{config_id}",
    ),
    ("GET", "/a2a/extendedAgentCard"),
    ("GET", "/.well-known/oauth-protected-resource/a2a"),
    ("GET", "/.well-known/agent-card.json"),
    ("GET", "/a2a/agents/{agent_id}/.well-known/agent-card.json"),
    ("GET", "/a2a/agents/{agent_id}"),
    ("POST", "/a2a/agents/{agent_id}"),
    ("POST", "/a2a"),
    ("POST", "/a2a/"),
    ("POST", "/lf.a2a.v1.A2AService/{method}"),
    ("POST", "/a2a/agents/other/"),
    ("POST", "/a2a/agents/vendor/"),
];

#[derive(Clone, Copy, Debug)]
enum Origin {
    Linked,
    Dropped,
}

fn abi(bytes: &[u8]) -> AbiStr {
    AbiStr {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
    }
}

fn blob(bytes: &[u8], fmt: u32) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt,
        flags: 0,
    }
}

fn canonical(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            format!(
                "{{{}}}",
                keys.into_iter()
                    .map(|key| {
                        format!(
                            "{}:{}",
                            serde_json::Value::String(key.clone()),
                            canonical(&map[key])
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            )
        }
        serde_json::Value::Array(values) => format!(
            "[{}]",
            values.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        other => other.to_string(),
    }
}

fn peer_card(endpoint: &str, issuer: &ed25519_dalek::SigningKey) -> serde_json::Value {
    let mut card = serde_json::json!({
        "name": "Vendor", "description": "the conformance agent", "url": endpoint,
        "version": "1.0.0", "protocolVersion": "0.3.0", "capabilities": {},
        "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "reply", "name": "reply", "description": "replies", "tags": ["reply"]}]
    });
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let protected = b64.encode(br#"{"alg":"EdDSA"}"#);
    let signature = issuer.sign(format!("{protected}.{}", b64.encode(canonical(&card))).as_bytes());
    card["signatures"] = serde_json::json!([{
        "protected": protected, "signature": b64.encode(signature.to_bytes())
    }]);
    card
}

fn peer_entry(endpoint: &str, issuer: &ed25519_dalek::SigningKey) -> serde_json::Value {
    let mut spki = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    spki.extend_from_slice(issuer.verifying_key().as_bytes());
    serde_json::json!({
        "url": endpoint, "allow_private": true, "reverify_ttl": "1h",
        "pin": {"mechanism": "jws_issuer_key", "key": base64::engine::general_purpose::STANDARD.encode(spki)}
    })
}

async fn http_bytes(
    router: &axum::Router,
    path: &str,
    body: Vec<u8>,
    header: (&str, &str),
) -> (u16, Vec<u8>) {
    let request = axum::http::Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .header(header.0, header.1)
        .body(axum::body::Body::from(body))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(20), async {
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("the actual root's small response stays within its fixture bound");
        (status, bytes.to_vec())
    })
    .await
    .expect("the actual root headers and complete body finish within one deadline")
}

fn bind_plane(origin: Origin, instance: &str, dispatcher: &Dispatcher) -> Plugin<Plane> {
    let bind = Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Host(crate::root::connector::the().clone() as Arc<dyn DeclaredConns>),
    };
    let row = crate::LINKED
        .plane_doors
        .iter()
        .find_map(|&door| {
            let row = LinkedRow::of(door).expect("the linked product states its identity");
            let stated = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
            (stated.name == "a2a").then_some(row)
        })
        .expect("the actual distribution must link the A2A product; this proof never skips");
    match origin {
        Origin::Linked => load_linked::<Plane>(&row, bind).expect("the actual linked A2A binds"),
        Origin::Dropped => {
            let path = std::path::PathBuf::from(
                std::env::var_os("BUSBAR_TEST_A2A_CDYLIB")
                    .expect("the actual distribution proof requires the freshly built A2A image"),
            );
            assert!(
                path.is_absolute() && path.is_file(),
                "the actual A2A artifact must exist: {}",
                path.display()
            );
            let stated = rendering_of_library(&path)
                .expect("the actual A2A image reads")
                .expect("the actual A2A image states its identity");
            assert_eq!(
                busbar_contract::abi::mechanism::rendering::read(&stated)
                    .unwrap()
                    .name,
                "a2a"
            );
            assert_eq!(
                row.statement, stated,
                "linked and dropped A2A must state identical public metadata and declarations"
            );
            load_dropped::<Plane>(&path, &stated, bind).expect("the actual dropped A2A binds")
        }
    }
}

struct RawA2aUnits(Arc<busbar_kernel::host_units::UnitRecords>);

impl Drop for RawA2aUnits {
    fn drop(&mut self) {
        for unit in [7, 9, 11] {
            self.0.ended(unit);
        }
    }
}

struct PieceBytes {
    bytes: Vec<u8>,
    reply: Vec<u8>,
    units: Vec<UnitCount>,
    records: Vec<RecordWrite>,
    fields: Vec<OutField>,
    arena: Vec<u8>,
}

struct PieceAnswer {
    done: Done<OnPieceIn, OnPieceOut>,
    bytes: Arc<PieceBytes>,
}

impl PieceAnswer {
    fn out(&self) -> &OnPieceOut {
        &self
            .done
            .frame
            .as_ref()
            .expect("the bounded actual crossing returns its frame")
            .out
    }
    fn emitted(&self) -> &[u8] {
        let n = usize::try_from(self.out().emitted).unwrap();
        assert!(n <= self.bytes.reply.len());
        &self.bytes.reply[..n]
    }
    fn units(&self) -> Vec<(u32, u64, u32)> {
        let n = self.out().units_written as usize;
        assert!(n <= self.bytes.units.len());
        self.bytes.units[..n]
            .iter()
            .map(|u| (u.class, u.amount, u.source))
            .collect()
    }
    fn ready(&self) {
        assert_eq!(self.done.outcome, Outcome::Ready, "{:?}", self.done.error);
        assert!(!self.done.short);
        assert_eq!(self.done.lease, 0);
    }
    fn final_answer(&self) {
        self.ready();
        assert_eq!(self.emitted(), ANSWER_OUT);
        assert_eq!(self.out().reply_status, 200);
        assert_eq!(self.out().more, 0);
        assert_eq!(self.out().flags & EMIT_TO_FAR_END, 0);
        assert_ne!(self.out().flags & EMIT_DONE, 0);
        assert_eq!(
            self.units(),
            vec![(0, 582, UNITS_REPORTED), (1, 1, UNITS_REPORTED)]
        );
    }
}

fn piece(
    plane: &Plugin<Plane>,
    dispatcher: &Dispatcher,
    (ticket, unit): (Ticket, u64),
    (from, flags, bytes): (u32, u32, &[u8]),
    (reply_cap, units_cap): (usize, usize),
) -> PieceAnswer {
    let mut buffers = Arc::new(PieceBytes {
        bytes: bytes.to_vec(),
        reply: vec![0; reply_cap],
        units: vec![UnitCount::ZERO; CAP],
        records: vec![RecordWrite::ZERO; CAP],
        fields: vec![OutField::ZERO; CAP],
        arena: vec![0; 16384],
    });
    let b = Arc::get_mut(&mut buffers).unwrap();
    let mut input: OnPieceIn = blank_in();
    input.head = dispatch::in_head();
    input.unit = unit;
    input.claim = 14;
    input.from = from;
    input.flags = flags;
    input.bytes = blob(&b.bytes, BLOB_OCTETS);
    input.caller_ref = abi(b"c0ffee01");
    if from == FROM_KERNEL {
        input.member = abi(b"vendor");
        input.attempt_no = 1;
    }
    if flags & PIECE_HAS_STATUS != 0 {
        input.status_code = 200;
        // These exact static fields are process-lived. Keeping the tiny Field list permanent
        // avoids an unsafe Send implementation in the root for pointer-bearing input metadata.
        let fields = Box::leak(
            vec![Field {
                name: abi(b"content-type"),
                value: abi(b"application/json"),
            }]
            .into_boxed_slice(),
        );
        input.head_fields = fields.as_ptr();
        input.head_fields_len = fields.len();
    }
    input.reply_buf = b.reply.as_mut_ptr();
    input.reply_cap = b.reply.len();
    input.units_buf = b.units.as_mut_ptr();
    input.units_cap = units_cap;
    input.records_buf = b.records.as_mut_ptr();
    input.records_cap = b.records.len();
    input.fields_buf = b.fields.as_mut_ptr();
    input.fields_cap = b.fields.len();
    input.arena_buf = b.arena.as_mut_ptr();
    input.arena_cap = b.arena.len();
    let mut out: OnPieceOut = blank_out();
    out.head = dispatch::out_head();
    let done = dispatcher
        .submit_lent(
            plane,
            ticket,
            slot::ON_PIECE,
            Frame::new(input, out),
            DeadlineClass::Stream,
            dispatch::now_ns().saturating_add(15_000_000_000),
            buffers.clone() as Lent,
        )
        .wait(Duration::from_secs(20))
        .expect("the actual A2A crossing settles within its deadline");
    PieceAnswer {
        done,
        bytes: buffers,
    }
}

fn arrive(
    plane: &Plugin<Plane>,
    unit: u64,
    claim: u32,
    method: &[u8],
    target: &[u8],
) -> (dispatch::Called, ArriveOut) {
    let mut units = [UnitCount::ZERO; CAP];
    let mut input: ArriveIn = blank_in();
    input.head = dispatch::in_head();
    input.unit = unit;
    input.claim = claim;
    input.method = abi(method);
    input.target = abi(target);
    input.body = blob(REQUEST, BLOB_OCTETS);
    input.units_buf = units.as_mut_ptr();
    input.units_cap = units.len();
    let mut out: ArriveOut = blank_out();
    out.head = dispatch::out_head();
    let mut frame = Frame::new(input, out);
    (plane.call(slot::ARRIVE, &mut frame), frame.out)
}

fn caller_body(
    plane: &Plugin<Plane>,
    dispatcher: &Dispatcher,
    ticket: Ticket,
    unit: u64,
    cap: usize,
) {
    assert_eq!(
        arrive(plane, unit, 14, b"POST", b"/a2a").0.outcome,
        Outcome::Ready
    );
    let attempt = piece(
        plane,
        dispatcher,
        (ticket, unit),
        (FROM_KERNEL, 0, b""),
        (cap, CAP),
    );
    attempt.ready();
    assert_ne!(attempt.out().flags & EMIT_TO_FAR_END, 0);
    let body = piece(
        plane,
        dispatcher,
        (ticket, unit),
        (FROM_CALLER, PIECE_LAST, REQUEST),
        (cap, CAP),
    );
    body.ready();
    assert_eq!(body.emitted(), REQUEST);
    assert_eq!(body.out().more, 0);
    assert_ne!(body.out().flags & EMIT_TO_FAR_END, 0);
}

fn raw_relay_and_lifecycle(
    plane: &Plugin<Plane>,
    dispatcher: &Dispatcher,
    entry: &serde_json::Value,
) {
    let settings = serde_json::to_vec(&serde_json::json!({"agents": {"vendor": entry}})).unwrap();
    let mut validate: Frame<life::ValidateIn, OutHead> = Frame::new(blank_in(), blank_out());
    validate.input.settings = blob(&settings, BLOB_JSON);
    assert_eq!(
        plane.call(life::slot::VALIDATE, &mut validate).outcome,
        Outcome::Ready
    );
    assert_eq!(
        arrive(plane, 7, 14, b"POST", b"/a2a").0.outcome,
        Outcome::Refused
    );

    let mut opened: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(blank_in(), blank_out());
    opened.input.open.generation = 1;
    opened.input.open.settings = blob(&settings, BLOB_JSON);
    opened.input.public_url = abi(b"https://gw.example");
    let (answer, snapshot) = plane.open(&mut opened);
    assert_eq!(answer.outcome, Outcome::Ready, "{:?}", answer.error);
    let snapshot = snapshot.expect("the actual first snapshot is owned by the host");
    assert_eq!(snapshot.generation, 1);
    assert_eq!(snapshot.claims.len(), 19);
    assert_eq!(
        snapshot
            .claims
            .iter()
            .map(|c| (c.verb.as_str(), c.target.as_str()))
            .collect::<Vec<_>>(),
        OPEN_CLAIMS
    );
    let driver = dispatcher
        .driver(plane, 0)
        .expect("the actual lifecycle driver ticket");
    assert_eq!(
        plane.open(&mut opened).0.outcome,
        Outcome::Refused,
        "one OPEN per actual instance"
    );
    for slot in [slot::HYDRATE, slot::START] {
        let mut frame: Frame<GenIn, OutHead> = Frame::new(blank_in(), blank_out());
        frame.input.generation = 1;
        assert_eq!(plane.call(slot, &mut frame).outcome, Outcome::Ready);
    }
    let (unclaimed, out) = arrive(plane, 8, 99, b"GET", b"/a2a/unclaimed");
    assert_eq!(unclaimed.outcome, Outcome::Refused);
    assert_eq!(out.refusal_status, 404);

    let whole = dispatcher.mint(0).expect("the real whole-answer ticket");
    caller_body(plane, dispatcher, whole, 7, 1024);
    piece(
        plane,
        dispatcher,
        (whole, 7),
        (FROM_FAR_END, PIECE_LAST | PIECE_HAS_STATUS, ANSWER),
        (1024, CAP),
    )
    .final_answer();
    dispatcher.recycle(whole);

    let narrow = dispatcher.mint(0).expect("the real narrow-answer ticket");
    caller_body(plane, dispatcher, narrow, 9, 150);
    let mut joined = Vec::new();
    for index in 0..4 {
        let answer = if index == 0 {
            piece(
                plane,
                dispatcher,
                (narrow, 9),
                (FROM_FAR_END, PIECE_LAST | PIECE_HAS_STATUS, ANSWER),
                (150, CAP),
            )
        } else {
            piece(
                plane,
                dispatcher,
                (narrow, 9),
                (FROM_FAR_END, 0, b""),
                (150, CAP),
            )
        };
        answer.ready();
        joined.extend_from_slice(answer.emitted());
        assert_eq!(answer.out().flags & EMIT_TO_FAR_END, 0);
        assert_eq!(
            answer.out().more,
            u32::from(index != 3),
            "first write plus exactly three MORE calls"
        );
        assert_eq!(answer.out().flags & EMIT_DONE != 0, index == 3);
        if index == 0 {
            assert_eq!(answer.out().reply_status, 200);
            assert_eq!(
                answer.units(),
                vec![(0, 582, UNITS_REPORTED), (1, 1, UNITS_REPORTED)]
            );
        }
    }
    assert_eq!(joined, ANSWER_OUT);
    dispatcher.recycle(narrow);

    let short = dispatcher.mint(0).expect("the real short-answer ticket");
    caller_body(plane, dispatcher, short, 11, 1024);
    let first = piece(
        plane,
        dispatcher,
        (short, 11),
        (FROM_FAR_END, PIECE_LAST | PIECE_HAS_STATUS, ANSWER),
        (1024, 0),
    );
    assert_eq!(first.done.outcome, Outcome::Failed);
    assert!(first.done.short);
    assert!(first.out().units_needed > 0);
    let mut frame = first
        .done
        .frame
        .expect("the terminal SHORT returns its input for one fresh recall");
    // A prior Pending resume may be reflected in the returned input. Terminal SHORT ends
    // that invocation; its one recall is a fresh call, retaining only the original ticket/body.
    frame.input.head.flags &= !FLAG_RESUME;
    assert_eq!(
        frame.input.head.flags & FLAG_RESUME,
        0,
        "the SHORT recall is fresh"
    );
    assert_eq!(
        frame.input.head.ticket, short,
        "the fresh recall keeps its original ticket"
    );
    frame.input.units_cap = CAP;
    let again = dispatcher
        .submit_lent(
            plane,
            short,
            slot::ON_PIECE,
            frame,
            DeadlineClass::Stream,
            dispatch::now_ns().saturating_add(15_000_000_000),
            first.bytes.clone() as Lent,
        )
        .wait(Duration::from_secs(20))
        .expect("one fresh same-ticket recall settles");
    let again = PieceAnswer {
        done: again,
        bytes: first.bytes,
    };
    again.final_answer();
    dispatcher.recycle(short);

    let mut reply = [0; 1024];
    let mut arena = [0; 1024];
    let mut fields = [OutField::ZERO; CAP];
    let mut refusal: Frame<RefusalIn, RefusalOut> = Frame::new(blank_in(), blank_out());
    refusal.input.cause = REFUSAL_GATE;
    refusal.input.status = 403;
    refusal.input.text = abi(b"denied");
    refusal.input.reply_buf = reply.as_mut_ptr();
    refusal.input.reply_cap = reply.len();
    refusal.input.fields_buf = fields.as_mut_ptr();
    refusal.input.fields_cap = fields.len();
    refusal.input.arena_buf = arena.as_mut_ptr();
    refusal.input.arena_cap = arena.len();
    assert_eq!(
        plane.call(slot::REFUSAL, &mut refusal).outcome,
        Outcome::Ready
    );
    assert_eq!(refusal.out.status, 403);
    assert_eq!(&reply[..refusal.out.reply_written as usize], REFUSAL);

    let driven = &plane.inner.driven;
    let seen = driven.answers();
    dispatch::ticket::host_wake(plane.inner.ctx(), driver);
    assert_eq!(
        driven.answered_after(seen, Duration::from_secs(15)),
        Some(Outcome::Ready)
    );
    let _ = driven.drain();
    let tick = dispatcher
        .tick(plane, driver, 1000)
        .wait(Duration::from_secs(20))
        .expect("the real lifecycle tick settles");
    assert_eq!(tick.outcome, Outcome::Ready);
    let mut cancel: Frame<PlaneCancelIn, PlaneCancelOut> = Frame::new(blank_in(), blank_out());
    assert_eq!(
        plane.call(life::slot::CANCEL, &mut cancel).outcome,
        Outcome::Ready
    );
    let mut release: Frame<ReleaseIn, OutHead> = Frame::new(blank_in(), blank_out());
    let released = plane.call(life::slot::RELEASE, &mut release);
    assert_eq!(released.lease, 0);
    assert!(
        released.outcome == Outcome::Ready
            || (released.outcome == Outcome::Refused
                && released.error.as_deref() == Some(b"release: no such lease"))
    );

    let settings =
        serde_json::to_vec(&serde_json::json!({"agents": {"vendor": entry, "other": entry}}))
            .unwrap();
    let mut refresh: Frame<life::RefreshIn, PlaneRefreshOut> = Frame::new(blank_in(), blank_out());
    refresh.input.generation = 2;
    refresh.input.settings = blob(&settings, BLOB_JSON);
    let (answer, snapshot) = plane.refresh(&mut refresh);
    assert_eq!(answer.outcome, Outcome::Ready);
    let snapshot = snapshot.expect("the actual refreshed snapshot is owned by the host");
    assert_eq!(snapshot.generation, 2);
    assert_eq!(snapshot.claims.len(), 20);
    assert_eq!(
        snapshot
            .claims
            .iter()
            .map(|c| (c.verb.as_str(), c.target.as_str()))
            .collect::<Vec<_>>(),
        REFRESH_CLAIMS
    );
    let mut retire: Frame<GenIn, OutHead> = Frame::new(blank_in(), blank_out());
    retire.input.generation = 1;
    assert_eq!(
        plane.call(life::slot::RETIRE, &mut retire).outcome,
        Outcome::Ready
    );
    let mut close: Frame<InHead, OutHead> = Frame::new(blank_in(), blank_out());
    assert_eq!(
        plane.call(life::slot::CLOSE, &mut close).outcome,
        Outcome::Ready
    );
    assert_eq!(
        arrive(plane, 7, 14, b"POST", b"/a2a").0.outcome,
        Outcome::Fault
    );
    // The after-CLOSE payload is deliberately never inspected.
    dispatcher.recycle(driver);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_a2a_relay_keeps_whole_narrow_short_and_lifecycle_both_ways() {
    let _one = crate::root::PUBLISHING.lock().await;
    crate::dist_root_install::install();
    assert_eq!(
        REQUEST.len() + ANSWER.len(),
        582,
        "the original reported byte count includes caller and far-end input"
    );
    let store_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("the proof requires a freshly built actual Store image"),
    );
    assert!(store_path.is_absolute() && store_path.is_file());
    let stated = rendering_of_library(&store_path)
        .unwrap()
        .expect("the actual Store states its identity");
    let module = busbar_contract::abi::mechanism::rendering::read(&stated)
        .unwrap()
        .name;
    let directory = crate::root::test_plugins::scratch("actual-a2a-parity");
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(stated));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &std::fs::read(&store_path).unwrap(),
    );
    std::fs::write(directory.join("store.tar.gz"), archive).unwrap();
    let operator_file = directory.join("operator.token");
    std::fs::write(&operator_file, ADMIN_TOKEN).unwrap();
    let signing_file = directory.join("signing.key");
    std::fs::write(&signing_file, hex::encode([9u8; 32])).unwrap();
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .unwrap();
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": ["keys"], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]}
    }))
    .unwrap();
    let mut config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let mut admin =
        busbar_kernel::config::AuthChainEntry::bare(busbar_kernel::config::operator_provider());
    admin.token = Some(busbar_kernel::config::SecretRef::file(
        operator_file.to_string_lossy().into_owned(),
    ));
    let auth = config
        .auth
        .as_mut()
        .expect("the explicit normal auth config");
    auth.admin_auth = vec![admin];
    auth.signing_key = Some(busbar_kernel::config::SecretRef::file(
        signing_file.to_string_lossy().into_owned(),
    ));
    config.per_request_fee = 1;
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_config) {
        step(&config.limits);
    }
    let destinations = config.destinations();
    let (app, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the actual Store boots the normal root");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module)
        .expect("the normal node book opens on its actual Store");
    limits.keep().expect("the actual boot card activates");
    if let Some(rotate) = rotate {
        rotate();
    }
    let ctx = crate::root::linked::BookCtx {
        book: &book,
        app: &app,
    };
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_book) {
        step(&ctx);
    }
    let app = Arc::new(app);
    let gov = app
        .governance
        .as_ref()
        .expect("the actual governance Store")
        .clone();
    let (key, token) = gov
        .mint_signed(
            busbar_kernel::governance::NewKeySpec {
                name: "a2a-parity".into(),
                plane_scopes: Some(vec![busbar_contract::records::ScopeRef {
                    kind: "agent".into(),
                    value: "vendor".into(),
                }]),
                ..Default::default()
            },
            4_000_000_000,
            busbar_kernel::store::now(),
        )
        .unwrap();
    gov.hydrate_budgets(&app.cost, 0).unwrap();
    let verified = gov
        .verify_token(
            token.expose(&busbar_kernel::seal::lend()),
            busbar_kernel::store::now(),
            None,
        )
        .expect("the actual Store-backed token verifies");
    assert!(verified.scope_allowed("agent", "vendor"));
    assert!(!verified.scope_allowed("agent", "other"));
    let bearer = format!("Bearer {}", token.expose(&busbar_kernel::seal::lend()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/agent", listener.local_addr().unwrap());
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let card = serde_json::to_vec(&peer_card(&endpoint, &issuer)).unwrap();
    let entry = peer_entry(&endpoint, &issuer);
    let peer_routes = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let card = card.clone();
        async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let body = tokio::time::timeout(
                Duration::from_secs(20),
                axum::body::to_bytes(request.into_body(), 64 * 1024),
            )
            .await
            .expect("the actual peer request body finishes within its deadline")
            .expect("the actual peer request stays within its byte bound");
            let reply = if method == axum::http::Method::POST {
                assert_eq!(path, "/agent");
                assert_eq!(
                    body.as_ref(),
                    REQUEST,
                    "the actual root sends the original request byte for byte"
                );
                ANSWER.to_vec()
            } else {
                assert_eq!(method, axum::http::Method::GET);
                assert!(matches!(
                    path.as_str(),
                    "/.well-known/agent-card.json" | "/.well-known/agent.json"
                ));
                card
            };
            axum::http::Response::builder()
                .status(200)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(reply))
                .unwrap()
        }
    });
    let peer = tokio::spawn(async move {
        axum::serve(listener, peer_routes).await.unwrap();
    });

    for origin in [Origin::Linked, Origin::Dropped] {
        let instance = format!("actual-a2a-{origin:?}");
        let services = crate::root::serve::LateServices::new();
        let kernel = Arc::new(
            crate::root::serve::kernel_services(
                crate::root::connector::guard_for(&destinations)
                    .expect("the normal deployment destination policy resolves"),
            )
            .with_signer(gov.clone())
            .with_pool(Arc::new(BlockingPool::new(
                tokio::runtime::Handle::current(),
                busbar_kernel::host_records::QUEUE_CAP,
            )))
            .with_records(Arc::new(busbar_kernel::host_records::StoreRows(
                gov.store_calls().expect("the real Store has typed records"),
            ))),
        );
        services.install_kernel(kernel.clone(), kernel).unwrap();
        let dispatcher = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            services.served(),
        ));
        let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
        let plane = bind_plane(origin, &instance, &dispatcher);
        assert_eq!(plane.served().section, "agents");
        assert_eq!(
            plane.served().billable_classes,
            ["bytes", busbar_contract::plane::PER_REQUEST]
        );
        assert_eq!(
            plane.served().fee_units,
            [busbar_contract::plane::PER_REQUEST]
        );
        let post = Arc::new(crate::root::plane_node::NodeEndPost::new(
            crate::root::plane_node::node(),
        ));
        let money = Arc::new(PlaneMoney::new(
            gov.clone(),
            post.clone() as Arc<dyn EndPost>,
        ));
        let providers = BTreeMap::new();
        let conns = crate::root::connector::the().clone();
        let reach = crate::root::door_steps::DoorReach {
            providers: &providers,
            secrets: Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
            auths: Arc::new(crate::root::door_steps::OutboundAuths::new(
                dispatcher.clone(),
                crate::LINKED.auths,
                None,
                ConnTable::Host(conns.clone() as Arc<dyn DeclaredConns>),
                busbar_kernel::diagnostics::Catalogue::NEUTRAL,
            )),
            conns: conns as Arc<dyn PollConns>,
            stream_ceiling_secs: 15,
            catalog: None,
            models: None,
            upgrades: Vec::new(),
        };
        let sections = BTreeMap::from([(
            "agents",
            serde_yaml::to_value(serde_json::json!({"vendor": entry})).unwrap(),
        )]);
        let tables = app.serve_tables.clone();
        let mut served = crate::root::serve::compose_planes(
            &[(instance.clone(), Arc::new(plane))],
            &dispatcher,
            &services,
            &sections,
            Some("https://gw.example"),
            &|| money.clone(),
            Some(&crate::root::serve::DoorEgress {
                reach: &reach,
                journal: post.clone() as Arc<dyn busbar_kernel_egress::ports::Journal>,
            }),
            None,
            &tables,
        )
        .expect("the actual A2A product composes through normal root services");
        assert_eq!(served.planes.len(), 1);
        assert_eq!(served.planes[0].snapshot.claims.len(), 19);
        served.post = Some(post);
        let routes = crate::root::serve::door_routes(
            served,
            || crate::root::kernel::ROOT_CARD.pin(),
            &[],
            &[],
        )
        .unwrap();
        let (data, admin, handle) =
            busbar_kernel::build_split_routers_serving(app.clone(), routes, 1 << 20, 0, false);
        let kernel = services
            .kernel()
            .expect("the actual production host is installed");
        assert!(kernel.attach_standing(busbar_kernel::plane_driver::live_standing(handle)));
        let (status, preview) = http_bytes(
            &admin,
            "/api/v1/admin/agents/vendor/connect",
            Vec::new(),
            ("x-admin-token", ADMIN_TOKEN),
        )
        .await;
        let preview: serde_json::Value =
            serde_json::from_slice(&preview).expect("connect returns its actual fingerprint");
        assert_eq!(status, 200, "{preview}");
        let fingerprint = preview["fingerprint"]
            .as_str()
            .expect("the authenticated card has a fingerprint");
        let (status, approved) = http_bytes(
            &admin,
            "/api/v1/admin/agents/vendor/approve",
            serde_json::to_vec(&serde_json::json!({"fingerprint": fingerprint})).unwrap(),
            ("x-admin-token", ADMIN_TOKEN),
        )
        .await;
        let approved: serde_json::Value = serde_json::from_slice(&approved).unwrap();
        assert_eq!(status, 200, "{approved}");
        assert_eq!(approved["state"], "approved");
        let before = gov
            .usage_for(&app.cost, &key.id, busbar_kernel::store::now())
            .unwrap()
            .unwrap_or_default();
        let (status, answer) =
            http_bytes(&data, "/a2a", REQUEST.to_vec(), ("authorization", &bearer)).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            answer, ANSWER_OUT,
            "the real root relays the exact fixed-context answer without RNG normalization"
        );

        let after = gov
            .usage_for(&app.cost, &key.id, busbar_kernel::store::now())
            .unwrap()
            .unwrap();
        assert_eq!(
            after.requests,
            before.requests + 1,
            "the actual root counts one completed request"
        );
        assert_eq!(
            after.billable_requests,
            before.billable_requests + 1,
            "the actual root keeps the fee unit exactly once"
        );

        // This is raw ABI/host-services qualification, separate from the governed HTTP
        // admission and paid billing above. The public owner seam holds the real verified key's
        // exact agent:vendor grant for these original raw unit ids. The opaque caller_ref bytes
        // below are original protocol input, never the source of authority.
        let raw = bind_plane(origin, &instance, &dispatcher);
        let units = RawA2aUnits(kernel.units().clone());
        let caller = busbar_contract::services::Caller {
            instance: Arc::from(instance.as_str()),
            plugin: Arc::from(raw.name()),
            kind: busbar_contract::abi::mechanism::KindCode::Plane,
        };
        for unit in [7, 9, 11] {
            assert!(
                units.0.get(unit).is_none(),
                "the raw fixture must never overwrite a live unit"
            );
            units.0.admitted(
                unit,
                busbar_kernel::host_units::UnitRecord {
                    principal: Some(verified.clone()),
                    depth: 0,
                },
            );
            assert!(kernel.entitled(&caller, Some(unit), "agent:vendor"));
            assert!(!kernel.entitled(&caller, Some(unit), "agent:other"));
        }
        raw_relay_and_lifecycle(&raw, &dispatcher, &entry);
        drop(units);
        for unit in [7, 9, 11] {
            assert!(kernel.units().get(unit).is_none());
        }
        tables.withdraw(&instance);
    }
    peer.abort();
}
