// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S REPLY AGAINST THE ENGINE'S. The same far-end answer is served twice: through the
//! engine's served path (`forward_with_pool` against a scripted far end: the attempt, the capped
//! reads, the buffered translate, the stream body) and through the plane's sans-I/O
//! `xchg::reply::Reply`; the caller reads the same status, head fields and bytes, and the far
//! end's reported usage is the same figure.
//!
//! Corpus: every native whole answer in the codec's golden corpus (`resp_X2Y_*.json` is a body in
//! dialect Y), a native stream of every dialect (the OpenAI stream below as the plane's translator
//! writes it for that dialect), the far end's error envelopes, and cuts. Every caller dialect.
//!
//! The plane also judges a far-end error with its own copy of the class rule (it cannot name the
//! breaker unit's); the engine's normalizer places every raw error shape in the class the plane's
//! does.

use crate::engine::xchg::arrive::{Arrived, PathModel};
use crate::engine::xchg::attempt::stream_intent;
use crate::engine::xchg::reply::{At, Reply, ReplyCtx, Units, Verdict};
use crate::engine::xchg::shaping::Lane;
use crate::engine::{forward_with_pool, TapCell, UsageSink, WeightedLane};
use crate::test_support::engine_kit::{EngineTestKit as _, TestAppKit};
use crate::test_support::{LaneSpec, TestApp};
use busbar_contract::operation::OpVerb;
use busbar_contract::upstream::RawUpstreamError;
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[test]
fn the_planes_class_rule_is_the_breakers() {
    let maps: Vec<HashMap<String, String>> = vec![
        HashMap::new(),
        [
            ("1302", "rate_limit"),
            ("quota", "billing"),
            ("ctx", "context_length"),
            ("typo", "rate_limt"),
            ("overloaded_error", "overloaded"),
            ("invalid_request_error", "context_length"),
            ("auth", "auth"),
            ("slow", "timeout"),
            ("net", "network"),
            ("bad", "client_error"),
            ("boom", "server_error"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect(),
    ];
    let codes = [
        None,
        Some("1302"),
        Some("quota"),
        Some("ctx"),
        Some("typo"),
        Some("context_length_exceeded"),
        Some("auth"),
        Some("unmapped"),
    ];
    let types = [
        None,
        Some("overloaded_error"),
        Some("invalid_request_error"),
        Some("slow"),
        Some("net"),
        Some("bad"),
        Some("boom"),
        Some("unmapped"),
    ];
    let statuses = [
        200, 302, 400, 401, 403, 404, 408, 413, 422, 429, 500, 502, 503, 504, 529,
    ];
    let mut checked = 0;
    for em in &maps {
        for code in codes {
            for ty in types {
                for status in statuses {
                    for retry in [None, Some(7)] {
                        let mut raw = RawUpstreamError::from_status(status);
                        raw.provider_code = code.map(str::to_string);
                        raw.structured_type = ty.map(str::to_string);
                        raw.retry_after_secs = retry;
                        assert_eq!(
                            crate::engine::xchg::reply::failure::normalize(status, &raw, em),
                            crate::engine::normalize_raw_error(&raw, em),
                            "{raw:?} under {em:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
    }
    assert_eq!(checked, 2 * 8 * 8 * 15 * 2);
}

// ── the scripted far end ────────────────────────────────────────────────────────────────────────

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

/// One far-end answer: its status, head, body pieces, and whether the transfer drops after them.
#[derive(Clone, Debug)]
struct Far {
    status: u16,
    head: Vec<(&'static str, String)>,
    pieces: Vec<Vec<u8>>,
    drop_after: bool,
}

type Script = Arc<Mutex<Option<Far>>>;

async fn serve(script: Script) -> (String, tokio::sync::oneshot::Sender<()>) {
    use axum::response::IntoResponse;
    let app = axum::Router::new().fallback(move || {
        let script = script.clone();
        async move {
            let far = script.lock().unwrap().take().expect("one scripted answer");
            let mut rb = axum::http::Response::builder().status(far.status);
            for (n, v) in &far.head {
                rb = rb.header(*n, v.as_str());
            }
            let pieces = far
                .pieces
                .into_iter()
                .map(|p| Ok::<Bytes, std::io::Error>(Bytes::from(p)));
            let body = if far.drop_after {
                use futures::StreamExt;
                let drop = futures::stream::once(async {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    Err(std::io::Error::other("the far end drops the connection"))
                });
                axum::body::Body::from_stream(futures::stream::iter(pieces).chain(drop))
            } else {
                axum::body::Body::from_stream(futures::stream::iter(pieces))
            };
            rb.body(body).unwrap().into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await
            .unwrap();
    });
    (format!("http://{addr}"), tx)
}

/// A chat request in `ingress`'s own dialect (a path-model dialect's body carries the model and the
/// stream flag the arrival splices in, and the array flag when asked).
fn request(ingress: &str, stream: bool, json_array: bool) -> Value {
    let mut v = match ingress {
        "anthropic" => json!({"model": "p", "max_tokens": 64, "stream": stream,
            "messages": [{"role": "user", "content": "hi"}]}),
        "responses" => json!({"model": "p", "stream": stream, "input": "hi"}),
        "gemini" => json!({"model": "p", "stream": stream,
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}]}),
        "bedrock" => json!({"model": "p", "stream": stream,
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]}),
        _ => json!({"model": "p", "stream": stream,
            "messages": [{"role": "user", "content": "hi"}]}),
    };
    if json_array {
        let key = crate::DECLS
            .iter()
            .find(|d| d.name == ingress)
            .and_then(|d| d.array_stream_shim_key)
            .expect("the dialect declares an array shim");
        v[key] = Value::Bool(true);
    }
    v
}

/// What the caller read: status, head fields, bytes (and whether its body ended in an error), and
/// the usage the far end reported.
#[derive(Debug, PartialEq)]
struct Read {
    status: u16,
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    body_failed: bool,
    units: Units,
}

async fn served(ingress: &'static str, egress: &'static str, req: &Value, far: Far) -> Read {
    crate::testkit::install_test_seams();
    let script: Script = Arc::new(Mutex::new(Some(far)));
    let (base, stop) = serve(script).await;
    let store = crate::test_support::engine_kit::CORE_ENGINE_KIT.scratch_store();
    let gov_kit = crate::test_support::engine_kit::CORE_ENGINE_KIT
        .governance(store, None, None)
        .expect("governance");
    let (key, _secret) = gov_kit
        .create_key(Default::default(), 1_700_000_000)
        .expect("create key");
    let mut builder = TestApp::new()
        .lane(LaneSpec::new("m0", egress, &base))
        .pool("p", &[(0, 1)]);
    TestAppKit::set_governance(&mut builder, gov_kit.clone());
    let app = builder.build();
    let (host, _rt) = crate::engine::test_host_rt(&app);
    let sink = UsageSink {
        pin: host.meter_pin().expect("governance is configured"),
        key: Arc::new(key),
        pool: Arc::from("p"),
        charged_at: crate::engine::now(),
        admit: None,
    };
    let op = crate::test_support::op_for(
        ingress,
        OpVerb::CHAT,
        busbar_contract::transport::transport::Transport::Http,
    )
    .expect("every dialect serves chat");
    let resp = forward_with_pool(
        &app,
        vec![WeightedLane {
            reasoning: None,
            idx: 0,
            weight: 1,
            attempt_timeout_ms: None,
        }],
        serde_json::to_vec(req).unwrap().into(),
        None,
        "p",
        None,
        ingress,
        op,
        Some(sink),
    )
    .await;
    let status = resp.status().as_u16();
    let fields = resp
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();
    let tap = resp.extensions().get::<TapCell>().cloned();
    let mut body = Vec::new();
    let mut body_failed = false;
    {
        use http_body_util::BodyExt;
        let mut b = resp.into_body();
        while let Some(frame) = b.frame().await {
            match frame {
                Ok(f) => {
                    if let Ok(d) = f.into_data() {
                        body.extend_from_slice(&d);
                    }
                }
                Err(_) => {
                    body_failed = true;
                    break;
                }
            }
        }
    }
    let _ = stop.send(());
    let report = tap.as_ref().and_then(|t| t.get());
    let units = Units::of(
        report.and_then(|r| r.usage.as_ref()),
        report.map(|r| r.open_units.clone()).unwrap_or_default(),
    );
    Read {
        status,
        fields,
        body,
        body_failed,
        units,
    }
}

fn lane(egress: &'static str) -> Lane {
    Lane {
        model: "m0".to_string(),
        provider: "p".to_string(),
        dialect: egress,
        path: None,
        path_base: None,
        upstream_model: None,
        default_max_tokens: None,
        context_max: None,
        reasoning: false,
        prompt_caching: false,
        caps: Default::default(),
        error_map: Default::default(),
    }
}

fn arrived(ingress: &'static str, req: &Value, json_array: bool) -> Arrived {
    let path_model = matches!(ingress, "gemini" | "bedrock").then(|| PathModel {
        stream: req["stream"].as_bool().unwrap_or(false),
        json_array,
        model_not_found_message: None,
    });
    Arrived {
        dialect: ingress,
        operation: OpVerb::CHAT,
        model: "p".to_string(),
        content_type: "application/json".to_string(),
        body: serde_json::to_vec(req).unwrap(),
        parsed: Some(req.clone()),
        path: String::new(),
        query: None,
        path_model,
    }
}

/// The plane's reply to the same far-end answer, fed in the same pieces.
fn planed(ingress: &'static str, egress: &'static str, req: &Value, far: &Far, now_s: u64) -> Read {
    let json_array = crate::DECLS
        .iter()
        .find(|d| d.name == ingress)
        .and_then(|d| d.array_stream_shim_key)
        .is_some_and(|k| req.get(k).is_some());
    let arrived = arrived(ingress, req, json_array);
    let lane = lane(egress);
    let handler = crate::DECLS
        .iter()
        .find(|d| d.name == ingress)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(OpVerb::CHAT))
        .expect("chat");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane: &lane,
        intent: stream_intent(handler, arrived.parsed.as_ref()),
        passthrough: false,
    };
    let head: Vec<(&[u8], &[u8])> = far
        .head
        .iter()
        .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
        .collect();
    let mut reply = Reply::new(&ctx, far.status, &head);
    let at = At {
        now_s,
        elapsed_ms: Some(0),
    };
    let mut read = Read {
        status: 0,
        fields: Vec::new(),
        body: Vec::new(),
        body_failed: false,
        units: Units::default(),
    };
    let n = far.pieces.len();
    let mut pieces: Vec<crate::engine::xchg::reply::Piece<'static>> = Vec::new();
    for (i, p) in far.pieces.iter().enumerate() {
        let piece = reply.feed(&ctx, p, i + 1 == n && !far.drop_after, at);
        pieces.push(crate::engine::xchg::reply::Piece {
            bytes: std::borrow::Cow::Owned(piece.bytes.into_owned()),
            ..piece
        });
    }
    if n == 0 {
        let piece = reply.feed(&ctx, &[], !far.drop_after, at);
        pieces.push(crate::engine::xchg::reply::Piece {
            bytes: std::borrow::Cow::Owned(piece.bytes.into_owned()),
            ..piece
        });
    }
    if far.drop_after {
        pieces.push(reply.cut(&ctx, true));
        // A cut with no in-band frame ends the caller's body in an error.
        read.body_failed = pieces.last().is_some_and(|p| p.bytes.is_empty());
    }
    for p in pieces {
        if let Some(h) = p.head {
            read.status = h.status;
            read.fields = h.fields;
        }
        read.body.extend_from_slice(&p.bytes);
        if p.done || p.verdict != Verdict::None {
            read.units = p.units;
        }
    }
    read
}

// ── what varies run to run: minted ids, clock stamps, a reported latency ───────────────────────

/// The members a dialect writer mints from the host's entropy or stamps from a clock.
const VARYING: [&str; 10] = [
    "id",
    "request_id",
    "responseId",
    "item_id",
    "call_id",
    "generation_id",
    "response_id",
    "created",
    "created_at",
    "latencyMs",
];

fn mask(v: &mut Value) {
    match v {
        Value::Object(o) => {
            for (k, x) in o.iter_mut() {
                if VARYING.contains(&k.as_str()) && (x.is_string() || x.is_number()) {
                    *x = Value::from("<varies>");
                } else {
                    mask(x);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(mask),
        _ => {}
    }
}

fn masked(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut v = serde_json::from_slice::<Value>(bytes).ok()?;
    mask(&mut v);
    serde_json::to_vec(&v).ok()
}

/// `bytes` with every varying member masked: a JSON body, each `data:` line of an event stream,
/// or each frame of a binary event stream (re-read, so its checksums need not match).
fn canon(bytes: &[u8]) -> Vec<u8> {
    if let Some(m) = masked(bytes) {
        return m;
    }
    if bytes.starts_with(b"data:") || bytes.starts_with(b"event:") {
        let mut out = Vec::new();
        for line in bytes.split(|b| *b == b'\n') {
            match line.strip_prefix(b"data: ").and_then(masked) {
                Some(m) => {
                    out.extend_from_slice(b"data: ");
                    out.extend(m);
                }
                None => out.extend_from_slice(line),
            }
            out.push(b'\n');
        }
        return out;
    }
    let mut out = Vec::new();
    let mut rest = bytes;
    while rest.len() >= 16 {
        let total = u32::from_be_bytes(rest[0..4].try_into().unwrap()) as usize;
        let hlen = u32::from_be_bytes(rest[4..8].try_into().unwrap()) as usize;
        if total < 16 + hlen || total > rest.len() {
            break;
        }
        out.extend_from_slice(&rest[12..12 + hlen]);
        let payload = &rest[12 + hlen..total - 4];
        out.extend(masked(payload).unwrap_or_else(|| payload.to_vec()));
        rest = &rest[total..];
    }
    if out.is_empty() || !rest.is_empty() {
        return bytes.to_vec();
    }
    out
}

/// Head fields with a minted request id masked to its length.
fn canon_fields(fields: &[(String, Vec<u8>)]) -> Vec<(String, Vec<u8>)> {
    // The served side is written by a real server: its `date` is the clock's, and its
    // per-connection fields are the writer's (the plane leaves both to the writer).
    fields
        .iter()
        .filter(|(n, _)| {
            n != "date" && !busbar_kernel::proxy::answer_re_derived(n, std::iter::empty())
        })
        .map(|(n, v)| {
            if n == "request-id" || n == "x-amzn-requestid" {
                // A forwarded far-end id is its own bytes; a minted one is masked to its length.
                if v.starts_with(b"req_far") || v.starts_with(b"amzn-far") {
                    (n.clone(), v.clone())
                } else {
                    (n.clone(), format!("<minted {}>", v.len()).into_bytes())
                }
            } else {
                (n.clone(), v.clone())
            }
        })
        .collect()
}

fn same(a: &Read, b: &Read) -> bool {
    a.status == b.status
        && canon_fields(&a.fields) == canon_fields(&b.fields)
        && canon(&a.body) == canon(&b.body)
        && a.body_failed == b.body_failed
        && a.units == b.units
}

async fn assert_parity(
    ingress: &'static str,
    egress: &'static str,
    req: Value,
    far: Far,
    what: &str,
) {
    let legacy = served(ingress, egress, &req, far.clone()).await;
    let plane = planed(ingress, egress, &req, &far, crate::engine::now());
    assert!(
        same(&legacy, &plane),
        "{ingress}<-{egress} {what}:\nserved {:?} {:?}\n{}\nplane  {:?} {:?}\n{}\nunits {:?} vs {:?}",
        legacy.status,
        legacy.fields,
        String::from_utf8_lossy(&legacy.body),
        plane.status,
        plane.fields,
        String::from_utf8_lossy(&plane.body),
        legacy.units,
        plane.units,
    );
}

// ── the corpus ──────────────────────────────────────────────────────────────────────────────────

fn letter(dialect: &str) -> char {
    match dialect {
        "anthropic" => 'a',
        "openai" => 'o',
        "gemini" => 'g',
        "bedrock" => 'b',
        "responses" => 'r',
        _ => 'c',
    }
}

/// Every native whole answer of `dialect` in the codec's golden corpus.
fn native_answers(dialect: &str) -> Vec<(String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../busbar-plane-llm/src/codec/tests/proto/golden");
    let infix = format!("2{}_", letter(dialect));
    let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
        .expect("the golden corpus is readable")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("resp_") && n.ends_with(".json") && n[6..].starts_with(&infix))
        .map(|n| {
            let bytes = std::fs::read(dir.join(&n)).expect("a golden is readable");
            (n, bytes)
        })
        .collect();
    out.sort();
    out
}

/// The far end's head: its content type and the request ids a native answer carries.
fn far_head(content_type: &str) -> Vec<(&'static str, String)> {
    vec![
        ("content-type", content_type.to_string()),
        ("request-id", "req_far0001".to_string()),
        ("x-amzn-requestid", "amzn-far-0001".to_string()),
    ]
}

fn whole_far(body: &[u8]) -> Far {
    Far {
        status: 200,
        head: far_head("application/json"),
        pieces: vec![body.to_vec()],
        drop_after: false,
    }
}

fn openai_stream() -> Vec<u8> {
    let chunk = |delta: &str, finish: &str| {
        format!(
            "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m0\",\"choices\":[{{\"index\":0,\"delta\":{delta},\"finish_reason\":{finish}}}]}}\n\n"
        )
    };
    let mut s = String::new();
    s += &chunk(r#"{"role":"assistant","content":"Hel"}"#, "null");
    s += &chunk(r#"{"content":"lo"}"#, "null");
    s += &chunk("{}", r#""stop""#);
    s += "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m0\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n";
    s += "data: [DONE]\n\n";
    s.into_bytes()
}

/// A native stream of `dialect`, and its content type.
fn native_stream(dialect: &'static str) -> (Vec<u8>, &'static str) {
    let handler = crate::DECLS
        .iter()
        .find(|d| d.name == dialect)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(OpVerb::CHAT))
        .expect("chat");
    let mut r = crate::engine::xchg::reply::relay::Relay::new(
        crate::engine::xchg::reply::relay::RelayCtx {
            ingress: dialect,
            egress: "openai",
            far_is_stream: true,
            json_array: false,
            client_include_usage: true,
            request: None,
            handler,
            meter: true,
        },
    );
    let mut out = Vec::new();
    if let (crate::engine::xchg::reply::relay::Fed::Bytes(b), _) = r.feed(&openai_stream()) {
        out.extend_from_slice(&b);
    }
    out.extend(r.end().bytes);
    let ct = crate::engine::xchg::reply::wire::ingress_stream_content_type(dialect)
        .expect("a stream content type");
    (out, ct)
}

/// The stream cut into pieces on frame-ish boundaries (the far end's writes).
fn stream_far(dialect: &'static str, drop_at_half: bool) -> Far {
    let (bytes, ct) = native_stream(dialect);
    let mut pieces: Vec<Vec<u8>> = bytes.chunks(64).map(<[u8]>::to_vec).collect();
    if drop_at_half {
        pieces.truncate(pieces.len() / 2);
    }
    Far {
        status: 200,
        head: far_head(ct),
        pieces,
        drop_after: drop_at_half,
    }
}

// ── the parity ──────────────────────────────────────────────────────────────────────────────────

/// A whole native answer from every far end, to a caller of every dialect that did not ask to
/// stream: the same-dialect verbatim relay and the cross-dialect buffered translate.
#[tokio::test]
async fn a_whole_answer_reads_the_same_through_the_plane() {
    let mut checked = 0;
    for egress in SIX {
        for (name, body) in native_answers(egress) {
            for ingress in SIX {
                assert_parity(
                    ingress,
                    egress,
                    request(ingress, false, false),
                    whole_far(&body),
                    &name,
                )
                .await;
                checked += 1;
            }
        }
    }
    assert!(checked >= 36, "{checked}");
    eprintln!("whole answers: {checked} cases");
}

/// A caller that asked to stream, answered one body: the buffered translate writes the caller's own
/// stream frames (or its one-element array).
#[tokio::test]
async fn a_stream_intent_answered_one_body_reads_the_same_through_the_plane() {
    let mut checked = 0;
    for egress in SIX {
        let (name, body) = native_answers(egress)
            .into_iter()
            .next()
            .expect("an answer");
        for ingress in SIX {
            assert_parity(
                ingress,
                egress,
                request(ingress, true, false),
                whole_far(&body),
                &name,
            )
            .await;
            checked += 1;
        }
        assert_parity(
            "gemini",
            egress,
            request("gemini", true, true),
            whole_far(&body),
            "json array",
        )
        .await;
        checked += 1;
    }
    eprintln!("stream intent, whole answers: {checked} cases");
}

/// A stream from every far end, to a caller of every dialect (and a JSON-array caller).
#[tokio::test]
async fn a_stream_reads_the_same_through_the_plane() {
    let mut checked = 0;
    for egress in SIX {
        for ingress in SIX {
            assert_parity(
                ingress,
                egress,
                request(ingress, true, false),
                stream_far(egress, false),
                "stream",
            )
            .await;
            checked += 1;
        }
        assert_parity(
            "gemini",
            egress,
            request("gemini", true, true),
            stream_far(egress, false),
            "json array stream",
        )
        .await;
        checked += 1;
    }
    eprintln!("streams: {checked} cases");
}

/// A stream the far end drops halfway: the caller's in-band error frame, in its own framing.
#[tokio::test]
async fn a_cut_stream_reads_the_same_through_the_plane() {
    let mut checked = 0;
    for egress in ["openai", "anthropic", "bedrock"] {
        for ingress in SIX {
            assert_parity(
                ingress,
                egress,
                request(ingress, true, false),
                stream_far(egress, true),
                "cut stream",
            )
            .await;
            checked += 1;
        }
    }
    eprintln!("cut streams: {checked} cases");
}

/// A far-end error the caller reads: a client fault (verbatim within a dialect, reshaped across)
/// and the far end refusing the deployment's credential (the caller dialect's own refusal).
#[tokio::test]
async fn a_far_end_error_reads_the_same_through_the_plane() {
    let bodies: [(u16, Value); 3] = [
        (
            400,
            json!({"error": {"message": "max_tokens is too large", "type": "invalid_request_error"}}),
        ),
        (422, json!({"message": "bad field"})),
        (
            401,
            json!({"error": {"message": "invalid x-api-key", "type": "authentication_error"}}),
        ),
    ];
    let mut checked = 0;
    for egress in SIX {
        for ingress in SIX {
            for (status, body) in &bodies {
                let far = Far {
                    status: *status,
                    head: far_head("application/json"),
                    pieces: vec![serde_json::to_vec(body).unwrap()],
                    drop_after: false,
                };
                assert_parity(
                    ingress,
                    egress,
                    request(ingress, false, false),
                    far,
                    &status.to_string(),
                )
                .await;
                checked += 1;
            }
        }
    }
    eprintln!("far-end errors: {checked} cases");
}

/// A far-end error the walk may go past (a transient, a rate limit): the relay the plane answers
/// is the one the engine's degraded path renders (`shape_cross_protocol_error` across dialects,
/// the far end's own bytes within one).
#[tokio::test]
async fn a_far_end_errors_relay_is_the_engines() {
    crate::testkit::install_test_seams();
    let body = serde_json::to_vec(&json!({"error": {"message": "slow down"}})).unwrap();
    let head: Vec<(&[u8], &[u8])> = vec![(b"content-type", b"application/json")];
    let mut checked = 0;
    for status in [429u16, 500, 503, 504, 529] {
        for egress in SIX {
            for ingress in SIX {
                let far = crate::engine::xchg::reply::failure::FarError {
                    status,
                    head: &head,
                    body: &body,
                };
                let plane = crate::engine::xchg::reply::failure::relay(ingress, egress, &far);
                if ingress != egress {
                    let legacy = crate::engine::shape_cross_protocol_error(
                        ingress,
                        axum::http::StatusCode::from_u16(status).unwrap(),
                        &body,
                    );
                    assert_eq!(legacy.status().as_u16(), plane.status);
                    let fields: Vec<(String, Vec<u8>)> = legacy
                        .headers()
                        .iter()
                        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
                        .collect();
                    assert_eq!(
                        canon_fields(&fields),
                        canon_fields(&plane.fields),
                        "{ingress}<-{egress} {status}"
                    );
                    let bytes = axum::body::to_bytes(legacy.into_body(), usize::MAX)
                        .await
                        .unwrap();
                    assert_eq!(canon(&bytes), canon(&plane.body), "{ingress}<-{egress}");
                } else {
                    assert_eq!(plane.body, body);
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 5 * 36);
}
