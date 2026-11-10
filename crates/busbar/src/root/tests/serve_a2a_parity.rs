// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual distribution's A2A relay, through its typed linked row and actual dropped image.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use busbar_contract::abi::hook::SignalEntry;
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Field, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS,
    FLAG_RESUME,
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

#[path = "serve_a2a_cancel.rs"]
mod cancellation;

const REQUEST: &[u8] = br##"{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","messageId":"m1","contextId":"ctx-7","parts":[{"text":"hi"}]}}}"##;
const ANSWER: &[u8] = br##"{"jsonrpc":"2.0","id":1,"result":{"role":"agent","messageId":"a1","parts":[{"text":"the agent's reply, that buffer that holds the whole request takes the answer in several writes. the agent's reply, long enough that a buffer that holds the whole request takes the answer in several writes. the agent's reply, long enough that a buffer that holds the whole request takes the answer in several writes. ","kind":"text"}],"kind":"message"}}"##;
const ANSWER_OUT: &[u8] = br##"{"jsonrpc":"2.0","id":1,"result":{"role":"agent","messageId":"a1","parts":[{"text":"the agent's reply, that buffer that holds the whole request takes the answer in several writes. the agent's reply, long enough that a buffer that holds the whole request takes the answer in several writes. the agent's reply, long enough that a buffer that holds the whole request takes the answer in several writes. ","kind":"text"}],"kind":"message","contextId":"ctx-7"}}"##;
const REFUSAL: &[u8] = br##"{"jsonrpc":"2.0","id":null,"error":{"code":-32004,"message":"denied","data":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","domain":"a2a-protocol.org","reason":"UNSUPPORTED_OPERATION"}]}}"##;
const ADMIN_TOKEN: &str = "a2a-parity-operator-token";
const PARITY_CASES: &str = "BUSBAR_A2A_PARITY_CASES";
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
    // Configured agent order is preserved by the plane.
    ("POST", "/a2a/agents/vendor/"),
    ("POST", "/a2a/agents/other/"),
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

/// Consume only the genuine public witness committed by the exclusive fresh-Store provisioner.
/// Each instance is migrated before any ordinary serving or lifecycle assertion starts.
async fn cold_record_receipt(
    directory: &std::path::Path,
    gov: &busbar_kernel::governance::GovState,
    instance: &str,
    store_fingerprint: &str,
) -> busbar_kernel::host_record_bootstrap::ColdRecordReceipt {
    let creation = std::fs::read(directory.join("principal-creation-evidence.json"))
        .expect("the exclusive Store creation provenance is retained");
    let witness = crate::root::loader::sign::sha256_hex(&creation);
    let schema = "test.fixture.principal-creation";
    let scope = busbar_kernel::persistence::scoped::ScopedStore::host_private(
        gov.core_store_handle().unwrap(),
        "busbar.fixture.principal-creation",
        [schema.into()],
    )
    .expect("fixture witness scope");
    let committed = scope
        .get(schema, b"namespace")
        .await
        .expect("the actual public witness reads")
        .expect("fresh principal initialization committed its public witness");
    let committed = committed.expose(&busbar_kernel::seal::lend());
    assert_eq!(committed.as_slice(), witness.as_bytes());
    let mut epoch = [0u8; 16];
    getrandom::fill(&mut epoch).expect("a fresh cold migration epoch");
    busbar_kernel::host_record_bootstrap::ColdRecordReceipt {
        version: 1,
        epoch: hex::encode(epoch),
        instance: instance.into(),
        namespace_hex: hex::encode(busbar_kernel::host_records::record_key(instance, &[])),
        store_config_sha256: store_fingerprint.into(),
        store_witness: busbar_kernel::host_record_bootstrap::StoreWitness {
            schema: schema.into(),
            key_hex: hex::encode(b"namespace"),
            value_hex: hex::encode(committed.as_slice()),
        },
        sender_quiesced: true,
        backend_quiesced: true,
        actor: "isolated actual A2A parity fixture provisioner".into(),
        reason:
            "exclusive new Store; this namespace has no prior sender; earlier cold hosts drained"
                .into(),
    }
}

fn peer_card(endpoint: &str, issuer: &ed25519_dalek::SigningKey) -> serde_json::Value {
    let mut card = serde_json::json!({
        "name": "Vendor", "description": "the conformance agent", "version": "1.0.0",
        "supportedInterfaces": [{
            "url": endpoint, "protocolBinding": "JSONRPC", "protocolVersion": "1.0",
        }],
        "capabilities": {},
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
    eprintln!("actual A2A root POST {path} starting");
    tokio::time::timeout(Duration::from_secs(20), async {
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("the actual root's small response stays within its fixture bound");
        (status, bytes.to_vec())
    })
    .await
    .unwrap_or_else(|why| {
        panic!("actual A2A root POST {path}: headers and complete body must finish within one deadline: {why}")
    })
}

fn bind_plane(
    origin: Origin,
    instance: &str,
    dispatcher: &Dispatcher,
    conns: Arc<dyn DeclaredConns>,
) -> Plugin<Plane> {
    let bind = Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: dispatcher.adopter(),
        conns: ConnTable::Host(crate::root::connector::admit(conns)),
    };
    let (row, getter) = crate::LINKED
        .plane_doors
        .iter()
        .find_map(|&door| {
            let row = LinkedRow::of(door).expect("the linked product states its identity");
            let stated = busbar_contract::abi::mechanism::rendering::read(&row.statement).unwrap();
            (stated.name == "a2a").then_some((row, door))
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

            let linked = getter();
            let dropped = dispatch::load::door_addresses_of_library(&path)
                .expect("the actual dropped descriptor reads")
                .expect("the actual dropped door exists");
            assert_ne!(
                std::ptr::from_ref(linked) as usize,
                dropped.0,
                "the dropped descriptor is a distinct actual image"
            );
            assert_ne!(
                linked.ops() as usize,
                dropped.1,
                "the dropped operation table is a distinct actual image"
            );
            load_dropped::<Plane>(&path, &stated, bind).expect("the actual dropped A2A binds")
        }
    }
}

fn first_crossings(plane: &Plugin<Plane>) -> u64 {
    let (crossings, resumes) = plane.test_invocations();
    crossings - resumes
}

struct RawA2aUnits {
    records: Arc<busbar_kernel::host_units::UnitRecords>,
    owned: Vec<u64>,
}

impl Drop for RawA2aUnits {
    fn drop(&mut self) {
        for unit in self.owned.drain(..) {
            self.records.ended(unit);
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
    no_crossing: bool,
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
    let before = first_crossings(plane);
    let answer = plane.call(slot::ARRIVE, &mut frame);
    if no_crossing {
        assert_eq!(first_crossings(plane) - before, 0);
    }
    (answer, frame.out)
}

fn caller_body(
    plane: &Plugin<Plane>,
    dispatcher: &Dispatcher,
    ticket: Ticket,
    unit: u64,
    cap: usize,
) {
    assert_eq!(
        arrive(plane, unit, 14, b"POST", b"/a2a", false).0.outcome,
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

struct A2aAuxBuffers {
    reply: Vec<u8>,
    fields: Vec<OutField>,
    arena: Vec<u8>,
    signals: Vec<u128>,
}

fn serve_and_project(plane: &Plugin<Plane>, dispatcher: &Dispatcher) -> [String; 2] {
    let mut serve_bytes = Arc::new(A2aAuxBuffers {
        reply: vec![0; 512],
        fields: vec![OutField::ZERO; 2],
        arena: vec![0; 256],
        signals: Vec::new(),
    });
    let b = Arc::get_mut(&mut serve_bytes).unwrap();
    let mut input: ServeIn = blank_in();
    input.head = dispatch::in_head();
    input.reply_buf = b.reply.as_mut_ptr();
    input.reply_cap = b.reply.len();
    input.fields_buf = b.fields.as_mut_ptr();
    input.fields_cap = b.fields.len();
    input.arena_buf = b.arena.as_mut_ptr();
    input.arena_cap = b.arena.len();
    let ticket = dispatcher.mint(0).expect("the actual SERVE ticket");
    let done = dispatcher
        .submit_lent(
            plane,
            ticket,
            slot::SERVE,
            Frame::new(input, blank_out::<ServeOut>()),
            DeadlineClass::Call,
            dispatch::now_ns().saturating_add(15_000_000_000),
            serve_bytes.clone() as Lent,
        )
        .wait(Duration::from_secs(20))
        .expect("the real SERVE finishes within its bound");
    assert_ne!(
        done.outcome,
        Outcome::Fault,
        "the old SERVE positive never faulted"
    );
    let out = &done
        .frame
        .as_ref()
        .expect("the actual SERVE returns its owned frame")
        .out;
    assert!(out.reply_written as usize <= serve_bytes.reply.len());
    let serve = format!(
        "{:?} lease={} error={} status={} reply_written={}",
        done.outcome,
        done.lease != 0,
        String::from_utf8_lossy(done.error.as_deref().unwrap_or_default()),
        out.status,
        out.reply_written
    );
    dispatcher.recycle(ticket);

    assert_eq!(
        std::mem::align_of::<u128>() % std::mem::align_of::<SignalEntry>(),
        0
    );
    let mut project_bytes = Arc::new(A2aAuxBuffers {
        reply: Vec::new(),
        fields: Vec::new(),
        arena: vec![0; 256],
        signals: vec![
            0;
            (4 * std::mem::size_of::<SignalEntry>()).div_ceil(std::mem::size_of::<u128>())
        ],
    });
    let b = Arc::get_mut(&mut project_bytes).unwrap();
    let mut input: ProjectIn = blank_in();
    input.head = dispatch::in_head();
    input.claim = 14;
    input.target = abi(b"/a2a");
    input.body = blob(REQUEST, BLOB_OCTETS);
    input.signals_buf = b.signals.as_mut_ptr().cast();
    input.signals_cap = 4;
    input.arena_buf = b.arena.as_mut_ptr();
    input.arena_cap = b.arena.len();
    let mut frame = Frame::new(input, blank_out::<ProjectOut>());

    let called = plane.call(slot::PROJECT, &mut frame);
    assert_ne!(
        called.outcome,
        Outcome::Fault,
        "the old PROJECT positive never faulted"
    );
    assert!(frame.out.view.signals_len <= 4);
    let project = format!(
        "{:?} lease={} error={} signals={}",
        called.outcome,
        called.lease != 0,
        String::from_utf8_lossy(called.error.as_deref().unwrap_or_default()),
        frame.out.view.signals_len
    );
    [serve, project]
}

fn raw_relay_and_lifecycle(
    plane: &Plugin<Plane>,
    dispatcher: &Dispatcher,
    entry: &serde_json::Value,
) -> [String; 2] {
    assert_eq!(
        first_crossings(plane),
        0,
        "metadata facts and admission cross no lifecycle slot"
    );
    let settings = serde_json::to_vec(&serde_json::json!({"agents": {"vendor": entry}})).unwrap();
    let mut validate: Frame<life::ValidateIn, OutHead> = Frame::new(blank_in(), blank_out());
    validate.input.settings = blob(&settings, BLOB_JSON);
    assert_eq!(
        plane.call(life::slot::VALIDATE, &mut validate).outcome,
        Outcome::Ready
    );
    assert_eq!(
        arrive(plane, 7, 14, b"POST", b"/a2a", true).0.outcome,
        Outcome::Refused
    );

    let section = serde_json::to_vec(&serde_json::json!({"vendor": entry})).unwrap();
    let mut opened: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(blank_in(), blank_out());
    opened.input.open.generation = 1;
    opened.input.open.settings = blob(&section, BLOB_JSON);
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
    assert!(
        plane.has_ready(),
        "the actual A2A product declares readiness"
    );
    plane
        .ready(dispatcher, Duration::from_secs(20))
        .expect("the actual A2A READY completes");
    let driver = dispatcher
        .driver(plane, 0)
        .expect("the actual lifecycle driver ticket");
    let before = first_crossings(plane);
    assert_eq!(
        plane.open(&mut opened).0.outcome,
        Outcome::Refused,
        "one OPEN per actual instance"
    );
    assert_eq!(first_crossings(plane) - before, 0);
    for slot in [slot::HYDRATE, slot::START] {
        let mut frame: Frame<GenIn, OutHead> = Frame::new(blank_in(), blank_out());
        frame.input.generation = 1;
        assert_eq!(plane.call(slot, &mut frame).outcome, Outcome::Ready);
    }
    let (unclaimed, out) = arrive(plane, 8, 99, b"GET", b"/a2a/unclaimed", false);
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
    assert_eq!(
        first.out().emitted,
        0,
        "terminal SHORT publishes no partial caller bytes"
    );
    assert_eq!(
        first.out().units_written,
        0,
        "terminal SHORT publishes no partial bill"
    );
    assert_eq!(
        first.out().records_written,
        0,
        "terminal SHORT publishes no partial record writes"
    );
    let mut frame = first
        .done
        .frame
        .expect("the terminal SHORT returns its input for one fresh recall");

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
    assert_eq!(
        refusal.out.status, 0,
        "the plane retains the requested status"
    );

    let refusal_status = if refusal.out.status == 0 {
        refusal.input.status
    } else {
        refusal.out.status
    };
    assert_eq!(refusal_status, 403);
    assert_eq!(&reply[..refusal.out.reply_written as usize], REFUSAL);
    let auxiliary = serve_and_project(plane, dispatcher);
    let seen = plane.test_driver_answers();
    dispatch::ticket::host_wake(plane.test_host_context(), driver);
    assert_eq!(
        plane.test_driver_answer_after(seen, Duration::from_secs(15)),
        Some(Outcome::Ready)
    );
    let _ = plane.test_driver_sessions();

    // Recycle queues retirement; the raw lifecycle calls below need it finished.
    dispatcher.recycle(driver);
    assert!(
        dispatcher.retirement_barrier(driver, Duration::from_secs(20)),
        "the real driver retires before the isolated lifecycle crossings"
    );
    let lifecycle = dispatcher
        .mint(0)
        .expect("the actual lifecycle tick ticket");
    let tick = dispatcher
        .tick(plane, lifecycle, 1000)
        .wait(Duration::from_secs(20))
        .expect("the real lifecycle tick settles");
    assert_eq!(tick.outcome, Outcome::Ready);
    dispatcher.recycle(lifecycle);
    assert!(
        dispatcher.retirement_barrier(lifecycle, Duration::from_secs(20)),
        "the completed tick releases lifecycle admission before raw REFRESH"
    );
    let mut cancel: Frame<PlaneCancelIn, PlaneCancelOut> = Frame::new(blank_in(), blank_out());
    assert_eq!(
        plane.call(life::slot::CANCEL, &mut cancel).outcome,
        Outcome::Ready
    );
    let mut release: Frame<ReleaseIn, OutHead> = Frame::new(blank_in(), blank_out());
    let released = plane.call(life::slot::RELEASE, &mut release);
    assert_eq!(released.lease, 0);
    assert!(
        (released.outcome == Outcome::Ready
            && released.error.as_ref().is_none_or(|bytes| bytes.is_empty()))
            || (released.outcome == Outcome::Refused
                && released.error.as_deref() == Some(b"release: no such lease"))
    );

    let settings =
        serde_json::to_vec(&serde_json::json!({"vendor": entry, "other": entry})).unwrap();
    let mut refresh: Frame<life::RefreshIn, PlaneRefreshOut> = Frame::new(blank_in(), blank_out());
    refresh.input.generation = 2;
    refresh.input.settings = blob(&settings, BLOB_JSON);
    let (answer, snapshot) = plane.refresh(&mut refresh);
    assert_eq!(
        answer.outcome,
        Outcome::Ready,
        "actual REFRESH: {:?}",
        answer.error
    );
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
        arrive(plane, 7, 14, b"POST", b"/a2a", true).0.outcome,
        Outcome::Fault
    );

    auxiliary
}

fn isolated_a2a_case() -> bool {
    const CHILD: &str = "BUSBAR_A2A_PARITY_CHILD";
    const WITNESS: &str = "actual A2A parity assertions completed";
    let name = std::thread::current()
        .name()
        .expect("the exact test is named")
        .to_owned();
    if std::env::var(CHILD).ok().as_deref() == Some(name.as_str()) {
        return false;
    }
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    // Keep each linked/dropped pair together, with fresh application state for cancellation.
    // Each child performs eight real admin mutations, inside the unchanged config-rate budget.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
    for cases in ["relay", "cancel"] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD, &name)
            .env(PARITY_CASES, cases)
            .stdout(std::process::Stdio::piped());
        let mut settings: serde_json::Value = serde_json::from_str(
            &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
        )
        .expect("actual Store settings");
        if settings.get("db_path").is_some() {
            let directory = crate::root::test_plugins::scratch("a2a-parity-child-store");
            settings["db_path"] = serde_json::json!(directory.join("governance.sqlite"));
            command.env(
                "BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS",
                settings.to_string(),
            );
        }
        let mut child = Child(
            command
                .spawn()
                .expect("start the exact isolated A2A parity case"),
        );
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual A2A parity child failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child did not complete its assertions: {output}"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < until,
                "the actual A2A parity child timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    true
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_a2a_relay_keeps_whole_narrow_short_and_lifecycle_both_ways() {
    if isolated_a2a_case() {
        return;
    }
    let _one = crate::root::PUBLISHING.lock().await;
    crate::dist_root_install::install();
    assert_eq!(
        REQUEST.len() + ANSWER.len(),
        582,
        "the original reported byte count includes caller and far-end input"
    );
    let store_path = crate::root::test_plugins::application_store_library();
    assert!(store_path.is_absolute() && store_path.is_file());
    let stated = rendering_of_library(&store_path)
        .unwrap()
        .expect("the actual Store states its identity");
    let module = busbar_contract::abi::mechanism::rendering::read(&stated)
        .unwrap()
        .name;
    let directory = crate::root::test_plugins::scratch("actual-a2a-parity");
    let mut manifest = crate::root::test_plugins::manifest("store", &module, "third-party");
    manifest.statement = Some(hex::encode(stated));
    let archive = crate::root::test_plugins::signed(
        &crate::root::test_plugins::key(0x33),
        manifest,
        &std::fs::read(&store_path).unwrap(),
    );
    let store_pin = busbar_contract::redacted::sha256_hex(&archive);
    std::fs::write(directory.join("store.tar.gz"), archive).unwrap();
    let operator_file = directory.join("operator.token");
    std::fs::write(&operator_file, ADMIN_TOKEN).unwrap();
    let signing_file = directory.join("signing.key");
    std::fs::write(&signing_file, hex::encode([9u8; 32])).unwrap();
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/agent", listener.local_addr().unwrap());
    let issuer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let card = serde_json::to_vec(&peer_card(&endpoint, &issuer)).unwrap();
    let entry = peer_entry(&endpoint, &issuer);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {}, "auth": {"chain": ["keys"], "admin_auth": []},
        "agents": {"vendor": entry.clone()},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]}
    }))
    .unwrap();
    let mut config = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    let mut admin =
        busbar_kernel::config::AuthChainEntry::bare(busbar_kernel::config::operator_provider());
    admin.token = Some(crate::root::test_plugins::source_reference(
        crate::root::linked::secret_rows(),
        busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH,
        operator_file.to_string_lossy().into_owned(),
    ));
    let auth = config
        .auth
        .as_mut()
        .expect("the explicit normal auth config");
    auth.admin_auth = vec![admin];
    auth.signing_key = Some(crate::root::test_plugins::source_reference(
        crate::root::linked::secret_rows(),
        busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH,
        signing_file.to_string_lossy().into_owned(),
    ));
    config.per_request_fee = 1;
    let mut plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        fetch: serde_json::from_value(serde_json::json!([{
            "url":"https://plugins.example/store.tar.gz", "sha256":store_pin
        }]))
        .expect("the operator pins the exact signed Store archive"),
        ..Default::default()
    };
    plugins
        .trust
        .publishers
        .push(busbar_kernel::config::PluginPublisher {
            name: "third-party".into(),
            public_key: hex::encode(
                crate::root::test_plugins::key(0x33)
                    .verifying_key()
                    .as_bytes(),
            ),
        });
    let rules: Arc<dyn busbar_kernel::appbuild::RootRules> =
        Arc::new(crate::root::door_steps::Rules::default());
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_config) {
        step(&config.limits);
    }
    let destinations = config.destinations();
    let transport_settings = crate::root::policy::client_settings(&config.limits);
    let seal = busbar_kernel::seal::acquire();
    let store_fingerprint = busbar_kernel::host_record_bootstrap::store_fingerprint(
        &serde_json::to_value(config.store.as_ref().map(|store| store.authoring(&seal)))
            .expect("the actual effective Store selection"),
    );
    let fresh =
        crate::root::test_plugins::provision_fresh_application_store(&config, &plugins, &directory)
            .await
            .expect("exclusively provision the real durable Store");
    fresh
        .commit_creation_witness()
        .await
        .expect("commit the actual exclusive Store creation witness");
    let opened = fresh.opened();
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(opened),
        false,
    )
    .await
    .expect("the actual Store boots the normal root");
    limits.stage_boot();
    let book = crate::root::boot::book(&app, &module)
        .await
        .expect("the normal node book opens on its actual Store");
    limits.keep().await.expect("the actual boot card activates");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let ctx = crate::root::linked::BookCtx {
        book: &book,
        app: &app,
    };
    for step in crate::ROOT_UNITS.iter().filter_map(|unit| unit.on_book) {
        step(&ctx);
    }
    let app = Arc::new(app);
    busbar_kernel::boot::hydrate_all(&app)
        .await
        .expect("normal startup hydrates the actual durable admin audit stream");
    let gov = app
        .governance
        .as_ref()
        .expect("the actual governance Store")
        .clone();
    let (key, token) = gov
        .mint_signed_async(
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
        .await
        .unwrap();
    gov.hydrate_budgets_async(&app.cost, 0).await.unwrap();
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

    let control = Arc::new(cancellation::CardPeerControl::new(&endpoint));
    let peer_control = control.clone();
    let peer_routes = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let card = card.clone();
        let peer_control = peer_control.clone();
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
                if body.as_ref() == cancellation::WAITER_REQUEST {
                    serde_json::to_vec(&serde_json::json!({
                        "jsonrpc": "2.0", "id": 1,
                        "result": serde_json::from_slice::<serde_json::Value>(&card).unwrap()
                    }))
                    .unwrap()
                } else {
                    assert_eq!(
                        body.as_ref(),
                        REQUEST,
                        "the actual root sends the original request byte for byte"
                    );
                    ANSWER.to_vec()
                }
            } else {
                assert_eq!(method, axum::http::Method::GET);
                assert!(matches!(
                    path.as_str(),
                    "/.well-known/agent-card.json" | "/.well-known/agent.json"
                ));
                peer_control.card_requested().await;
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

    let mut auxiliary_parity = None;
    let cancelling = match std::env::var(PARITY_CASES).as_deref() {
        Ok("relay") => false,
        Ok("cancel") => true,
        other => panic!("the isolated child must name its parity cases: {other:?}"),
    };
    let cases = [(Origin::Linked, cancelling), (Origin::Dropped, cancelling)];
    // First migrate every actual namespace through a real signed request. Ordinary hosts are
    // then opened without a bootstrap grant, so raw rebind/refresh/cancel assertions stay real.
    for (initializing, (origin, cancelling)) in [true, false]
        .into_iter()
        .flat_map(|initializing| cases.into_iter().map(move |case| (initializing, case)))
    {
        let instance = if cancelling {
            format!("actual-a2a-{origin:?}-cancel")
        } else {
            format!("actual-a2a-{origin:?}")
        };
        let mut entry = entry.clone();
        if cancelling {
            entry["reverify_ttl"] = serde_json::Value::String("0s".into());
        }
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
            ))),
        );
        assert!(kernel.attach_persistence(gov.core_store_handle().unwrap()));
        if initializing {
            kernel
                .arm_record_bootstrap(
                    cold_record_receipt(&directory, &gov, &instance, &store_fingerprint).await,
                    &store_fingerprint,
                    |schema, key, _| {
                        if schema != "test.fixture.principal-creation" || key != b"namespace" {
                            return Err("unexpected fixture creation witness");
                        }
                        busbar_kernel::persistence::scoped::migration_address(
                            true,
                            "busbar.fixture.principal-creation",
                            schema,
                            key,
                        )
                        .map_err(|_| "invalid fixture witness address")
                    },
                )
                .await
                .expect("the actual cold host consumes the committed fresh-Store witness");
        }
        services.install_kernel(kernel.clone(), kernel).unwrap();
        let dispatcher = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            services.served(),
            busbar_kernel::host_services::caller_binding(),
        ));
        let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
        crate::root::connector::install_io(&dispatcher);

        let conns = busbar_core_connector::process::build_with_secrets(
            || {
                crate::root::connector::entries_on(
                    &dispatcher,
                    crate::LINKED_TRANSPORT_DOORS,
                    &transport_settings,
                )
            },
            crate::root::connector::guard_for(&destinations)
                .expect("the normal deployment destination policy resolves"),
            &[],
            dispatcher.conn_waker(),
            crate::root::connector::pool_posture(&transport_settings),
            crate::root::connector::spawn_secret_resolver(),
        )
        .expect("the actual transports compose on the plane's dispatcher");
        let plane = Arc::new(bind_plane(
            origin,
            &instance,
            &dispatcher,
            conns.clone() as Arc<dyn DeclaredConns>,
        ));
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
        let reach = crate::root::door_steps::DoorReach {
            providers: &providers,
            secrets: Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
            auths: Arc::new(crate::root::door_steps::OutboundAuths::new(
                dispatcher.clone(),
                crate::LINKED.auths,
                None,
                ConnTable::Host(crate::root::connector::admit(
                    conns.clone() as Arc<dyn DeclaredConns>
                )),
                busbar_kernel::diagnostics::Catalogue::NEUTRAL,
            )),
            conns: conns.clone() as Arc<dyn PollConns>,
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
            &[(instance.clone(), plane.clone())],
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
        .await
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
            .unwrap_or_else(|| panic!("the authenticated card has a fingerprint: {preview}"));
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
        if initializing {
            let (status, answer) =
                http_bytes(&data, "/a2a", REQUEST.to_vec(), ("authorization", &bearer)).await;
            assert_eq!(
                status,
                200,
                "real cold migration: {}",
                String::from_utf8_lossy(&answer)
            );
            assert_eq!(
                answer, ANSWER_OUT,
                "the actual peer completed the cold migration request"
            );
            tables.withdraw(&instance);
            drop(data);
            drop(admin);
            drop(plane);
            assert!(
                kernel.drain_plane_cleanup(Duration::from_secs(10)).await,
                "all cold migration callers settle before ordinary serving"
            );
            let draining = kernel.clone();
            assert!(
                tokio::task::spawn_blocking(move || draining.drain(Duration::from_secs(10)))
                    .await
                    .expect("the cold host drain completes"),
                "all cold migration backend writes settle before ordinary serving"
            );
            continue;
        }
        if cancelling {
            cancellation::run(
                &data,
                &bearer,
                plane.clone(),
                dispatcher.clone(),
                kernel.units().clone(),
                verified.clone(),
                control.clone(),
            )
            .await;
            tables.withdraw(&instance);
            continue;
        }
        gov.flush_budgets().await;

        let fee_lane = busbar_kernel_ledger::cost::plane_fee_lane(plane.name());
        let fee_quantity = |ledger: &busbar_contract::records::UsageLedger| {
            ledger
                .models
                .iter()
                .filter(|row| row.model == fee_lane)
                .map(|row| {
                    busbar_contract::count::Count::from_stored(
                        row.tier(busbar_contract::plane::PER_REQUEST),
                        row.scale,
                    )
                    .and_then(busbar_contract::count::Count::whole_u64)
                    .expect("the fixture fee quantity is an exact nonnegative whole count")
                })
                .sum::<u64>()
        };
        let before_ledger = gov
            .core_store()
            .unwrap()
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .expect("the actual Store reads the total fee quantity before the request");
        let before_billable = fee_quantity(&before_ledger);
        let before = gov
            .usage_for_async(&app.cost, &key.id, busbar_kernel::store::now())
            .await
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
            .usage_for_async(&app.cost, &key.id, busbar_kernel::store::now())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            after.requests,
            before.requests + 1,
            "the actual root counts one completed request"
        );
        gov.flush_budgets().await;
        let after_ledger = gov
            .core_store()
            .unwrap()
            .ledger()
            .get_usage(&key.id, 0)
            .await
            .expect("the actual Store reads the settled total fee quantity");
        let after_billable = fee_quantity(&after_ledger);
        assert_eq!(
            after_billable,
            before_billable + 1,
            "the actual root keeps the fee unit exactly once"
        );
        assert_eq!(
            after_ledger.billable_requests, before_ledger.billable_requests,
            "a plane fee must not also charge the pool-plane legacy fee scalar"
        );

        let raw = bind_plane(
            origin,
            &instance,
            &dispatcher,
            conns.clone() as Arc<dyn DeclaredConns>,
        );
        let mut units = RawA2aUnits {
            records: kernel.units().clone(),
            owned: Vec::new(),
        };
        let caller = busbar_contract::services::Caller::for_test(
            Arc::from(instance.as_str()),
            busbar_contract::abi::mechanism::KindCode::Plane,
        );
        for unit in [7, 9, 11] {
            assert!(
                units.records.get(unit).is_none(),
                "the raw fixture must never overwrite a live unit"
            );
            units.records.admitted(
                unit,
                busbar_kernel::host_units::UnitRecord {
                    principal: Some(verified.clone()),
                    depth: 0,
                },
            );
            units.owned.push(unit);
            assert!(kernel.entitled(&caller, Some(unit), "agent:vendor"));
            assert!(!kernel.entitled(&caller, Some(unit), "agent:other"));
        }
        let observed = raw_relay_and_lifecycle(&raw, &dispatcher, &entry);
        if let Some(expected) = &auxiliary_parity {
            assert_eq!(
                &observed, expected,
                "SERVE and PROJECT preserve actual linked/dropped parity"
            );
        } else {
            auxiliary_parity = Some(observed);
        }
        drop(units);
        for unit in [7, 9, 11] {
            assert!(kernel.units().get(unit).is_none());
        }
        tables.withdraw(&instance);
    }
    peer.abort();
    println!("actual A2A parity assertions completed");
}
