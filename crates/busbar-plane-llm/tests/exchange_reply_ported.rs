// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The far end's answer as the caller reads it, ported from the legacy engine's tests before that
//! crate is deleted: each test below keeps the legacy test's far-end bytes, its caller and its
//! expectation, and drives them through the plane's own reply (`arrive` for the caller, `Reply` for
//! the answer, `cut` for a transfer that fails) instead of the engine's served path. Each test names
//! the legacy test it ports.

use std::collections::HashMap;

use busbar_contract::abi::transport::FAULT_TRANSIENT;
use busbar_contract::operation::OpVerb;
use busbar_contract::upstream::{Disposition, StatusClass};
use busbar_plane_llm::exchange::arrive::{arrive, Arrived};
use busbar_plane_llm::exchange::attempt::stream_intent;
use busbar_plane_llm::exchange::refuse::render;
use busbar_plane_llm::exchange::reply::failure::{judge, relay, FarError};
use busbar_plane_llm::exchange::reply::relay::{Fed, Relay, RelayCtx};
use busbar_plane_llm::exchange::reply::whole::{self, WholeCtx, WholeEnd};
use busbar_plane_llm::exchange::reply::wire;
use busbar_plane_llm::exchange::reply::{At, Fault, Reply, ReplyCtx, Units, Verdict};
use busbar_plane_llm::exchange::shaping::Lane;
use busbar_plane_llm::plane_door::breaker_fault;
use serde_json::{json, Value};

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

const AT: At = At {
    now_s: 1_752_000_000,
    elapsed_ms: Some(3),
};

/// The host's entropy, so a dialect that mints an id mints one (the same bytes every draw, so two
/// renders of one answer are byte-equal).
fn entropy() {
    busbar_contract::codec::install_entropy_source(|out| {
        out.fill(7);
        true
    });
}

fn lane(dialect: &'static str) -> Lane {
    Lane {
        model: "m0".to_string(),
        provider: "p".to_string(),
        dialect,
        path: None,
        path_base: None,
        organization: None,
        project: None,
        upstream_model: None,
        default_max_tokens: None,
        context_max: None,
        reasoning: false,
        prompt_caching: false,
        caps: Default::default(),
        error_map: Default::default(),
        statics: &[],
    }
}

/// One arrival at `target`, read by the plane as the door reads it.
fn arrive_at(target: &str, head: &[(&str, &str)], body: &Value) -> Arrived {
    let mut fields: Vec<(&[u8], &[u8])> = Vec::new();
    fields.push((b"content-type", b"application/json"));
    fields.extend(head.iter().map(|(n, v)| (n.as_bytes(), v.as_bytes())));
    let bytes = serde_json::to_vec(body).expect("a JSON body");
    arrive("POST", target, &fields, &bytes, &()).unwrap_or_else(|d| panic!("{target}: {d:?}"))
}

/// A chat arrival in `dialect`'s own surface, asking to stream or not (a Gemini stream asks for
/// server-sent events; [`gemini_array`] asks for the JSON array).
fn arrival(dialect: &str, stream: bool) -> Arrived {
    let messages = json!([{"role": "user", "content": "hi"}]);
    match dialect {
        "openai" => arrive_at(
            "/v1/chat/completions",
            &[],
            &json!({"model": "p", "stream": stream, "messages": messages}),
        ),
        "anthropic" => arrive_at(
            "/v1/messages",
            &[("anthropic-version", "2023-06-01")],
            &json!({"model": "p", "max_tokens": 16, "stream": stream, "messages": messages}),
        ),
        "cohere" => arrive_at(
            "/v2/chat",
            &[],
            &json!({"model": "p", "stream": stream, "messages": messages}),
        ),
        "responses" => arrive_at(
            "/v1/responses",
            &[],
            &json!({"model": "p", "stream": stream, "input": "hi"}),
        ),
        "gemini" => arrive_at(
            if stream {
                "/v1beta/models/p:streamGenerateContent?alt=sse"
            } else {
                "/v1beta/models/p:generateContent"
            },
            &[],
            &json!({"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}),
        ),
        "bedrock" => arrive_at(
            if stream {
                "/model/p/converse-stream"
            } else {
                "/model/p/converse"
            },
            &[],
            &json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}),
        ),
        other => panic!("{other}"),
    }
}

/// A Gemini stream asked for as a JSON array (`:streamGenerateContent` without `alt=sse`), on the
/// beta surface or the stable one.
fn gemini_array(stable: bool) -> Arrived {
    arrive_at(
        if stable {
            "/v1/models/p:streamGenerateContent"
        } else {
            "/v1beta/models/p:streamGenerateContent"
        },
        &[],
        &json!({"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}),
    )
}

fn handler_of(a: &Arrived) -> &'static dyn busbar_contract::codec::OperationHandler {
    busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == a.dialect)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(a.operation))
        .expect("the caller's dialect serves the operation")
}

/// The reply's context, as the door builds it.
fn ctx<'a>(arrived: &'a Arrived, lane: &'a Lane) -> ReplyCtx<'a> {
    ReplyCtx {
        arrived,
        lane,
        intent: stream_intent(handler_of(arrived), arrived.parsed.as_ref()),
        passthrough: false,
    }
}

/// What the caller read of one attempt's answer.
#[derive(Debug)]
struct Read {
    status: u16,
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    units: Units,
    verdict: Verdict,
    fault: Option<Fault>,
    done: bool,
}

impl Read {
    fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| std::str::from_utf8(v).expect("a text field"))
    }

    fn count(&self, name: &str) -> usize {
        self.fields.iter().filter(|(n, _)| n == name).count()
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("a JSON body ({e}): {}", self.text()))
    }
}

/// The caller's read of a far end answering `status`, `head` and the body `pieces` to a caller of
/// `arrived` over a member of `egress`; `cut` fails the transfer after the last piece.
fn answer(
    arrived: &Arrived,
    egress: &'static str,
    status: u16,
    head: &[(&str, &str)],
    pieces: &[&[u8]],
    cut: bool,
) -> Read {
    let lane = lane(egress);
    let ctx = ctx(arrived, &lane);
    let head: Vec<(&[u8], &[u8])> = head
        .iter()
        .map(|(n, v)| (n.as_bytes(), v.as_bytes()))
        .collect();
    let mut reply = Reply::new(&ctx, status, &head);
    let mut read = Read {
        status: 0,
        fields: Vec::new(),
        body: Vec::new(),
        units: Units::default(),
        verdict: Verdict::None,
        fault: None,
        done: false,
    };
    let mut take = |piece: busbar_plane_llm::exchange::reply::Piece<'_>| {
        if let Some(h) = piece.head {
            assert_eq!(read.status, 0, "one head per answer");
            read.status = h.status;
            read.fields = h.fields;
        }
        read.body.extend_from_slice(&piece.bytes);
        read.units = piece.units;
        read.verdict = piece.verdict;
        read.fault = piece.fault;
        read.done = piece.done;
    };
    let pieces: Vec<&[u8]> = if pieces.is_empty() {
        vec![&[]]
    } else {
        pieces.to_vec()
    };
    for (i, p) in pieces.iter().enumerate() {
        let last = !cut && i + 1 == pieces.len();
        take(reply.feed(&ctx, p, last, AT));
    }
    if cut {
        take(reply.cut(&ctx, true));
    }
    read
}

/// One server-sent event frame: `data:` alone, or under an `event:` line.
fn sse(event: &str, data: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    busbar_plane_llm::codec::dialect::write_sse_frame(&mut out, event, data);
    out
}

/// Bare `data:` frames of `events`.
fn data_frames(events: &[&str]) -> Vec<u8> {
    events
        .iter()
        .flat_map(|e| format!("data: {e}\n\n").into_bytes())
        .collect()
}

/// The legacy far end's three-event OpenAI stream (no identity members, the usage on the stop).
const OPENAI_STREAM_EVENTS: [&str; 3] = [
    r#"{"choices":[{"delta":{"role":"assistant"}}]}"#,
    r#"{"choices":[{"delta":{"content":"hi"}}]}"#,
    r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#,
];

/// The one frame a legacy far end sent before it dropped the connection.
const OPENAI_FIRST_EVENT: &str = r#"{"choices":[{"delta":{"content":"hi"}}]}"#;

const SSE_HEAD: &[(&str, &str)] = &[("content-type", "text/event-stream")];
const JSON_HEAD: &[(&str, &str)] = &[("content-type", "application/json")];
const EVENTSTREAM_HEAD: &[(&str, &str)] = &[
    ("content-type", "application/vnd.amazon.eventstream"),
    ("x-amzn-requestid", "fixed-upstream-amzn-req-id-err1"),
];

/// Every `(event, data)` frame of a server-sent event body (the `[DONE]` sentinel skipped).
fn sse_frames(body: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for frame in body.split("\n\n") {
        let mut event = String::new();
        let mut data: Option<String> = None;
        for line in frame.lines() {
            if let Some(rest) = line.strip_prefix("event:") {
                event = rest.trim().to_string();
            } else if let Some(rest) = line.strip_prefix("data:") {
                data = Some(rest.trim().to_string());
            }
        }
        if let Some(d) = data {
            if d != busbar_plane_llm::codec::dialect::SSE_DONE_SENTINEL {
                out.push((event, d));
            }
        }
    }
    out
}

/// Every JSON `data:` payload of a server-sent event body.
fn payloads(body: &str) -> Vec<Value> {
    sse_frames(body)
        .into_iter()
        .filter_map(|(_, d)| serde_json::from_str(&d).ok())
        .collect()
}

/// The IEEE CRC-32 an event-stream frame is checked with.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in bytes {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// A binary event-stream body read as whole CRC-checked frames: each frame's headers block (as
/// text) and payload. Panics on a frame whose lengths or checksums do not hold, or on trailing
/// bytes that are no whole frame.
fn binary_frames(mut bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        assert!(bytes.len() >= 16, "a partial prelude: {bytes:?}");
        let total = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let hlen = u32::from_be_bytes(bytes[4..8].try_into().unwrap()) as usize;
        assert!(
            total >= 16 + hlen && total <= bytes.len(),
            "a frame's lengths"
        );
        let prelude_crc = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        assert_eq!(prelude_crc, crc32(&bytes[..8]), "the prelude's checksum");
        let msg_crc = u32::from_be_bytes(bytes[total - 4..total].try_into().unwrap());
        assert_eq!(
            msg_crc,
            crc32(&bytes[..total - 4]),
            "the message's checksum"
        );
        out.push((
            String::from_utf8_lossy(&bytes[12..12 + hlen]).into_owned(),
            bytes[12 + hlen..total - 4].to_vec(),
        ));
        bytes = &bytes[total..];
    }
    out
}

/// The `:event-type` names of a binary event-stream body, in order.
fn event_names(bytes: &[u8]) -> Vec<String> {
    let mut buf = bytes.to_vec();
    busbar_plane_llm::codec::eventstream::drain_frames_checked(&mut buf, None)
        .0
        .into_iter()
        .map(|(n, _)| n)
        .collect()
}

fn no_sse_text(body: &[u8]) -> bool {
    !body.windows(7).any(|w| w == b"event: ") && !body.windows(6).any(|w| w == b"data: ")
}

// ── a stream cut after its first byte ───────────────────────────────────────────────────────────

/// A same-dialect Bedrock stream whose far end drops mid-body ends on a CRC-valid binary exception
/// frame (`InternalServerException`), never on server-sent event text, under the far end's own
/// event-stream content type. Ports legacy
/// `ingress_integration_tests.rs::test_bedrock_same_protocol_stream_mid_stream_transport_error_appends_binary_exception`.
#[test]
fn a_same_dialect_binary_stream_cut_mid_body_ends_on_a_binary_exception_frame() {
    entropy();
    let first = busbar_plane_llm::codec::eventstream::encode_frame(
        "messageStart",
        br#"{"role":"assistant"}"#,
    );
    let r = answer(
        &arrival("bedrock", true),
        "bedrock",
        200,
        EVENTSTREAM_HEAD,
        &[&first],
        true,
    );
    assert_eq!(r.status, 200);
    assert!(
        r.field("content-type")
            .is_some_and(|ct| ct.starts_with("application/vnd.amazon.eventstream")),
        "{:?}",
        r.fields
    );
    assert!(no_sse_text(&r.body), "no event text: {:?}", r.body);
    let frames = binary_frames(&r.body);
    assert!(frames.len() >= 2, "the real frame, then the exception");
    let raw = String::from_utf8_lossy(&r.body);
    assert!(raw.contains(":exception-type"), "{raw}");
    assert!(raw.contains("InternalServerException"), "{raw}");
    assert_eq!(r.fault, Some(Fault::Transient("mid-stream")));
}

/// A Bedrock caller's stream reframed from an OpenAI far end that drops mid-body ends on a
/// CRC-valid binary exception frame, never server-sent event text. Ports legacy
/// `ingress_integration_tests.rs::test_bedrock_ingress_mid_stream_transport_error_appends_binary_exception`.
#[test]
fn a_reframed_binary_stream_cut_mid_body_ends_on_a_binary_exception_frame() {
    entropy();
    let first = data_frames(&[r#"{"choices":[{"delta":{"role":"assistant"}}]}"#]);
    let r = answer(
        &arrival("bedrock", true),
        "openai",
        200,
        SSE_HEAD,
        &[&first],
        true,
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        r.field("content-type"),
        Some("application/vnd.amazon.eventstream")
    );
    assert!(no_sse_text(&r.body), "no event text: {:?}", r.body);
    let frames = binary_frames(&r.body);
    assert!(!frames.is_empty());
    let raw = String::from_utf8_lossy(&r.body);
    assert!(raw.contains(":exception-type"), "{raw}");
    assert!(raw.contains("InternalServerException"), "{raw}");
}

/// An OpenAI caller's stream cut mid-body ends on a bare `data:` frame (no `event:` line) carrying
/// OpenAI's own error envelope. Ports legacy
/// `ingress_integration_tests.rs::test_openai_ingress_mid_stream_transport_error_appends_native_sse`.
#[test]
fn an_openai_stream_cut_mid_body_ends_on_a_bare_data_error_frame() {
    entropy();
    let first = data_frames(&[OPENAI_FIRST_EVENT]);
    let r = answer(
        &arrival("openai", true),
        "openai",
        200,
        SSE_HEAD,
        &[&first],
        true,
    );
    assert_eq!(r.status, 200);
    let text = r.text();
    assert!(!text.contains("event:"), "{text}");
    let frames: Vec<&str> = text
        .split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .collect();
    let last = frames
        .last()
        .and_then(|f| f.lines().find_map(|l| l.strip_prefix("data: ")))
        .expect("a trailing data: frame");
    let v: Value = serde_json::from_str(last).expect("the error envelope is JSON");
    assert!(v.get("error").is_some(), "{v}");
}

/// A Gemini caller's `:streamGenerateContent?alt=sse` over an OpenAI far end reads server-sent
/// events whose frames are Gemini's own (`candidates[]`), none OpenAI's (`choices`). Ports legacy
/// `ingress_integration_tests.rs::test_gemini_stream_generate_content_alt_sse_is_event_stream`.
#[test]
fn a_gemini_event_stream_caller_reads_its_own_frames() {
    entropy();
    let far = data_frames(&OPENAI_STREAM_EVENTS);
    let r = answer(
        &arrival("gemini", true),
        "openai",
        200,
        SSE_HEAD,
        &[&far],
        false,
    );
    assert_eq!(r.status, 200);
    assert!(
        r.field("content-type")
            .is_some_and(|ct| ct.starts_with("text/event-stream")),
        "{:?}",
        r.fields
    );
    let text = r.text();
    let p = payloads(&text);
    assert!(!p.is_empty(), "{text}");
    assert!(p.iter().any(|c| c.get("candidates").is_some()), "{text}");
    assert!(p.iter().all(|c| c.get("choices").is_none()), "{text}");
}

/// The same caller, its far end dropping mid-body: the stream ends on Gemini's own error frame
/// (`google.rpc.Status`, `error.status`), a bare `data:` frame with no `event:` line, and nothing of
/// OpenAI's leaks. Ports legacy
/// `ingress_integration_tests.rs::test_gemini_alt_sse_mid_stream_transport_error_appends_native_sse_frame`.
#[test]
fn a_gemini_event_stream_cut_mid_body_ends_on_its_own_status_frame() {
    entropy();
    let first = data_frames(&[OPENAI_FIRST_EVENT]);
    let r = answer(
        &arrival("gemini", true),
        "openai",
        200,
        SSE_HEAD,
        &[&first],
        true,
    );
    assert!(
        r.field("content-type")
            .is_some_and(|ct| ct.starts_with("text/event-stream")),
        "{:?}",
        r.fields
    );
    let text = r.text();
    assert!(!text.contains("event:"), "{text}");
    let p = payloads(&text);
    assert!(!p.is_empty(), "{text}");
    assert!(p.iter().all(|c| c.get("choices").is_none()), "{text}");
    assert!(!text.contains("chat.completion.chunk"), "{text}");
    let last = p.last().expect("a trailing frame");
    assert!(
        last.get("error").and_then(|e| e.get("status")).is_some(),
        "{text}"
    );
}

/// A Gemini caller that asked for its stream as a JSON array, its far end dropping mid-body, still
/// reads one valid JSON array under `application/json`, closed on a Gemini error element, with no
/// server-sent event text anywhere. Ports legacy
/// `ingress_integration_tests.rs::test_gemini_json_array_mid_stream_error_closes_array_no_sse`.
#[test]
fn a_gemini_array_stream_cut_mid_body_closes_the_array_on_an_error_element() {
    entropy();
    let first = data_frames(&[OPENAI_FIRST_EVENT]);
    let r = answer(
        &gemini_array(false),
        "openai",
        200,
        SSE_HEAD,
        &[&first],
        true,
    );
    assert!(
        r.field("content-type")
            .is_some_and(|ct| ct.starts_with("application/json")),
        "{:?}",
        r.fields
    );
    let text = r.text();
    let v = r.json();
    let arr = v.as_array().unwrap_or_else(|| panic!("an array: {text}"));
    assert!(
        !text.contains("event:") && !text.contains("data:"),
        "{text}"
    );
    assert!(
        arr.iter()
            .any(|el| el.get("error").and_then(|e| e.get("status")).is_some()),
        "{text}"
    );
}

/// A stream reframed for an Anthropic caller opens on a full `message_start` skeleton: a minted
/// `msg_` id, `type: message`, `content: []`, and a null `stop_reason` and `stop_sequence`. Ports
/// legacy `ingress_integration_tests.rs::test_anthropic_cross_protocol_message_start_full_skeleton`.
#[test]
fn a_reframed_anthropic_stream_opens_on_a_full_message_skeleton() {
    entropy();
    let far = data_frames(&OPENAI_STREAM_EVENTS);
    let r = answer(
        &arrival("anthropic", true),
        "openai",
        200,
        SSE_HEAD,
        &[&far],
        false,
    );
    assert_eq!(r.status, 200);
    let text = r.text();
    let start = text
        .split("\n\n")
        .find(|f| f.contains("event: message_start"))
        .and_then(|f| f.lines().find(|l| l.starts_with("data: ")))
        .map(|l| l.trim_start_matches("data: ").to_string())
        .unwrap_or_else(|| panic!("no message_start: {text}"));
    let ev: Value = serde_json::from_str(&start).expect("message_start is JSON");
    let msg = ev.get("message").expect("a message");
    assert!(
        msg.get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .starts_with("msg_"),
        "{msg}"
    );
    assert_eq!(msg.get("type").and_then(Value::as_str), Some("message"));
    assert!(
        msg.get("content").and_then(Value::as_array).is_some(),
        "{msg}"
    );
    assert!(msg.get("stop_reason").is_some_and(Value::is_null), "{msg}");
    assert!(
        msg.get("stop_sequence").is_some_and(Value::is_null),
        "{msg}"
    );
}

/// A Cohere caller's stream cut mid-body ends on Cohere's own terminator: a bare `data:` frame of
/// type `message-end` whose `delta.finish_reason` is `ERROR`, with no free-text `message` and nothing
/// of OpenAI's. Ports legacy
/// `ingress_integration_tests.rs::test_cohere_ingress_mid_stream_transport_error_appends_native_sse`.
#[test]
fn a_cohere_stream_cut_mid_body_ends_on_its_own_error_terminator() {
    entropy();
    let first = data_frames(&[OPENAI_FIRST_EVENT]);
    let r = answer(
        &arrival("cohere", true),
        "openai",
        200,
        SSE_HEAD,
        &[&first],
        true,
    );
    assert_eq!(r.status, 200);
    let text = r.text();
    assert!(!text.contains("event:"), "{text}");
    assert!(!text.contains("chat.completion.chunk"), "{text}");
    let last = sse_frames(&text)
        .into_iter()
        .next_back()
        .map(|(_, d)| d)
        .expect("a trailing frame");
    let v: Value = serde_json::from_str(&last).expect("JSON");
    assert_eq!(v.get("type").and_then(Value::as_str), Some("message-end"));
    assert!(
        v.pointer("/delta/finish_reason")
            .and_then(Value::as_str)
            .is_some_and(|f| f.starts_with("ERROR")),
        "{v}"
    );
    assert!(v.get("message").is_none(), "{v}");
}

/// A Responses caller's stream cut mid-body ends on `event: response.failed` whose payload is the
/// stream shape `{"response":{"status":"failed","error":{..}}}`, never a top-level `error`. Ports
/// legacy
/// `ingress_integration_tests.rs::test_responses_ingress_mid_stream_transport_error_appends_response_failed`.
#[test]
fn a_responses_stream_cut_mid_body_ends_on_response_failed() {
    entropy();
    let first = data_frames(&[OPENAI_FIRST_EVENT]);
    let r = answer(
        &arrival("responses", true),
        "openai",
        200,
        SSE_HEAD,
        &[&first],
        true,
    );
    assert_eq!(r.status, 200);
    let text = r.text();
    assert!(text.contains("event: response.failed"), "{text}");
    let failed = sse_frames(&text)
        .into_iter()
        .find(|(ev, _)| ev == "response.failed")
        .map(|(_, d)| d)
        .expect("a response.failed frame");
    let v: Value = serde_json::from_str(&failed).expect("JSON");
    assert!(v.get("response").is_some(), "{v}");
    assert_eq!(v["response"]["status"], "failed", "{v}");
    assert!(v["response"]["error"]["message"].is_string(), "{v}");
    assert!(v.get("error").is_none(), "{v}");
}

/// The stable `/v1/models/*:streamGenerateContent` surface without `alt=sse` reads the JSON-array
/// framing exactly as the beta surface does: one array of Gemini chunks under `application/json`.
/// Ports legacy `ingress_integration_tests.rs::test_gemini_v1_stable_stream_generate_content_no_alt_sse`.
#[test]
fn the_stable_gemini_stream_surface_reads_a_json_array() {
    entropy();
    let far = data_frames(&OPENAI_STREAM_EVENTS);
    let r = answer(&gemini_array(true), "openai", 200, SSE_HEAD, &[&far], false);
    assert_eq!(r.status, 200);
    assert!(
        r.field("content-type")
            .is_some_and(|ct| ct.starts_with("application/json")),
        "{:?}",
        r.fields
    );
    let v = r.json();
    let arr = v.as_array().expect("an array");
    assert!(!arr.is_empty());
    assert!(arr.iter().any(|c| c.get("candidates").is_some()), "{v}");
    assert!(arr.iter().all(|c| c.get("choices").is_none()), "{v}");
}

// ── a far-end error across dialects ─────────────────────────────────────────────────────────────

/// The status-to-kind table a far-end error is reshaped with for a caller of another dialect.
/// Ports legacy `ingress_indistinguishability_tests.rs::test_cross_protocol_error_kind_mapping`.
#[test]
fn a_far_end_status_names_its_cross_dialect_kind() {
    for (status, kind) in [
        (401, "authentication_error"),
        (403, "permission_error"),
        (429, "rate_limit_error"),
        (500, "api_error"),
        (502, "api_error"),
        (503, "overloaded"),
        (504, "timeout"),
        (400, "invalid_request_error"),
        (404, "invalid_request_error"),
    ] {
        assert_eq!(wire::cross_protocol_error_kind(status), kind, "{status}");
    }
}

/// A caller's own credential refused by an OpenAI far end reaches an Anthropic caller as
/// Anthropic's `authentication_error` (401) or `permission_error` (403), its status kept and the far
/// end's message lifted. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_shape_cross_protocol_error_auth_kinds`.
#[test]
fn a_callers_refused_credential_reads_in_its_own_envelope() {
    entropy();
    let head: Vec<(&[u8], &[u8])> = vec![(b"content-type", b"application/json")];
    let body = br#"{"error":{"message":"nope"}}"#;
    for (status, kind) in [(401, "authentication_error"), (403, "permission_error")] {
        let far = FarError {
            status,
            head: &head,
            body,
        };
        let j = judge(
            "anthropic",
            "openai",
            OpVerb::CHAT,
            &HashMap::new(),
            true,
            &far,
        );
        assert_eq!(j.disposition, Disposition::ClientFault);
        assert_eq!(j.answer.status, status);
        let v: Value = serde_json::from_slice(&j.answer.body).expect("JSON");
        assert_eq!(v["error"]["type"], kind, "{v}");
        assert_eq!(v["error"]["message"], "nope", "{v}");
    }
}

/// A far end's transient error (429, 500, 503, 504, 529) relayed to the caller: across dialects it
/// is the caller dialect's own error of the status's kind, carrying the far end's message; within
/// one dialect it is the far end's own bytes. Ports legacy
/// `plane_reply_parity_tests.rs::a_far_end_errors_relay_is_the_engines`.
#[test]
fn a_far_end_transient_error_relays_in_the_callers_envelope() {
    entropy();
    let body = serde_json::to_vec(&json!({"error": {"message": "slow down"}})).unwrap();
    let head: Vec<(&[u8], &[u8])> = vec![(b"content-type", b"application/json")];
    let mut checked = 0;
    for status in [429u16, 500, 503, 504, 529] {
        for egress in SIX {
            for ingress in SIX {
                let far = FarError {
                    status,
                    head: &head,
                    body: &body,
                };
                let r = relay(ingress, egress, &far);
                assert_eq!(r.status, status, "{ingress}<-{egress}");
                if ingress == egress {
                    assert_eq!(r.body, body, "{ingress}: the far end's bytes");
                } else {
                    let kind = wire::cross_protocol_error_kind(status);
                    assert_eq!(
                        r,
                        render(ingress, status, kind, "slow down", 0),
                        "{ingress}<-{egress} {status}"
                    );
                    assert!(
                        String::from_utf8_lossy(&r.body).contains("slow down"),
                        "{ingress}<-{egress}"
                    );
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, 5 * 36);
}

/// The content type a caller's stream wears follows its dialect: server-sent events for five, the
/// binary event stream for Bedrock, none for a dialect the plane does not hold. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_ingress_stream_content_type_by_protocol`.
#[test]
fn a_callers_stream_content_type_follows_its_dialect() {
    for d in ["openai", "anthropic", "gemini", "cohere", "responses"] {
        assert_eq!(
            wire::ingress_stream_content_type(d),
            Some("text/event-stream"),
            "{d}"
        );
    }
    assert_eq!(
        wire::ingress_stream_content_type("bedrock"),
        Some("application/vnd.amazon.eventstream")
    );
    assert_eq!(wire::ingress_stream_content_type("nonsense"), None);
}

// ── a whole answer across dialects ──────────────────────────────────────────────────────────────

/// An OpenAI answer with an empty `choices` the reader refuses.
const EMPTY_CHOICES: &str = r#"{"id":"chatcmpl-EMPTY","object":"chat.completion","created":1234567890,"model":"glm-4.5","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#;

/// A 2xx the caller's dialect cannot be written from is the caller's 500 and a transient fault the
/// breaker records (the kernel's walk refunds and records it), with no units charged. Ports the
/// plane half of legacy
/// `ingress_indistinguishability_tests.rs::test_untranslatable_2xx_refunds_budget_and_trips_breaker`.
#[test]
fn an_untranslatable_success_is_a_500_and_a_transient_fault() {
    entropy();
    let r = answer(
        &arrival("anthropic", false),
        "openai",
        200,
        JSON_HEAD,
        &[EMPTY_CHOICES.as_bytes()],
        false,
    );
    assert_eq!(r.status, 500);
    assert!(r.done);
    assert_eq!(r.verdict, Verdict::Hard);
    assert_eq!(r.fault, Some(Fault::Transient("untranslatable-2xx")));
    assert_eq!(breaker_fault(r.fault.as_ref()), FAULT_TRANSIENT);
    assert_eq!(
        r.units,
        Units::default(),
        "nothing delivered, nothing charged"
    );
}

/// A Bedrock answer translated for a Gemini caller carries `usageMetadata.totalTokenCount` (7 + 3)
/// and a minted `responseId`, under `application/json`, and no foreign id. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_cross_protocol_bedrock_to_gemini_carries_total_tokens_and_response_id`.
#[test]
fn a_bedrock_answer_for_a_gemini_caller_carries_its_total_and_a_response_id() {
    entropy();
    let far = json!({
        "output": {"message": {"role": "assistant", "content": [{"text": "Hi"}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 7, "outputTokens": 3}
    })
    .to_string();
    let r = answer(
        &arrival("gemini", false),
        "bedrock",
        200,
        JSON_HEAD,
        &[far.as_bytes()],
        false,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.field("content-type"), Some("application/json"));
    let v = r.json();
    assert_eq!(v["usageMetadata"]["totalTokenCount"], json!(10u64), "{v}");
    assert_eq!(v["usageMetadata"]["promptTokenCount"], json!(7u64), "{v}");
    assert_eq!(
        v["usageMetadata"]["candidatesTokenCount"],
        json!(3u64),
        "{v}"
    );
    assert!(
        !v["responseId"].as_str().unwrap_or("").is_empty(),
        "a minted responseId: {v}"
    );
    let raw = r.text();
    assert!(!raw.contains("chatcmpl-") && !raw.contains("msg_"), "{raw}");
}

/// An OpenAI chat answer reporting 7 in and 3 out.
const OPENAI_OK: &str = r#"{"id":"chatcmpl-ok","object":"chat.completion","created":1234567890,"model":"glm-4.5","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#;

/// A Bedrock caller's translated success carries exactly one `x-amzn-RequestId`, a minted UUID.
/// Ports legacy `ingress_indistinguishability_tests.rs::test_bedrock_ingress_success_carries_amzn_request_id`.
#[test]
fn a_bedrock_callers_translated_success_carries_one_amzn_request_id() {
    entropy();
    let r = answer(
        &arrival("bedrock", false),
        "openai",
        200,
        JSON_HEAD,
        &[OPENAI_OK.as_bytes()],
        false,
    );
    assert_eq!(r.status, 200);
    let id = r.field("x-amzn-requestid").unwrap_or("");
    assert_eq!(id.len(), 36, "a UUID: {id:?}");
    assert_eq!(r.count("x-amzn-requestid"), 1, "{:?}", r.fields);
}

/// An Anthropic caller's translated success carries exactly one minted `request-id` of the `req_`
/// shape. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_anthropic_ingress_success_carries_request_id_header`.
#[test]
fn an_anthropic_callers_translated_success_carries_one_request_id() {
    entropy();
    let r = answer(
        &arrival("anthropic", false),
        "openai",
        200,
        JSON_HEAD,
        &[OPENAI_OK.as_bytes()],
        false,
    );
    assert_eq!(r.status, 200);
    assert!(
        r.field("request-id")
            .is_some_and(|id| id.starts_with("req_")),
        "{:?}",
        r.fields
    );
    assert_eq!(r.count("request-id"), 1, "{:?}", r.fields);
}

/// An Anthropic caller's stream from an Anthropic far end that sent no request id carries a minted
/// `request-id` of the `req_` shape. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_anthropic_ingress_stream_carries_request_id_header`.
#[test]
fn an_anthropic_callers_stream_carries_a_request_id() {
    entropy();
    let mut far = sse(
        "message_start",
        &json!({"type": "message_start", "message": {"id": "msg_x", "role": "assistant",
            "content": [], "usage": {"input_tokens": 3, "output_tokens": 0}}}),
    );
    far.extend(sse("message_stop", &json!({"type": "message_stop"})));
    let r = answer(
        &arrival("anthropic", true),
        "anthropic",
        200,
        SSE_HEAD,
        &[&far],
        false,
    );
    assert_eq!(r.status, 200);
    assert!(
        r.field("request-id")
            .is_some_and(|id| id.starts_with("req_")),
        "{:?}",
        r.fields
    );
}

/// A Bedrock `ConverseStream` caller answered one OpenAI body reads the binary event stream: the
/// event-stream content type, a UUID `x-amzn-RequestId`, and Bedrock's own frames (`messageStart`
/// first, then a `contentBlockDelta`, `messageStop` and `metadata`). Ports legacy
/// `ingress_indistinguishability_tests.rs::test_bedrock_converse_stream_buffered_cross_protocol_emits_binary_eventstream`.
#[test]
fn a_bedrock_stream_caller_answered_one_body_reads_binary_frames() {
    entropy();
    let far = OPENAI_OK.replace("chatcmpl-ok", "chatcmpl-buf");
    let r = answer(
        &arrival("bedrock", true),
        "openai",
        200,
        JSON_HEAD,
        &[far.as_bytes()],
        false,
    );
    assert_eq!(r.status, 200);
    assert_eq!(
        r.field("content-type"),
        Some("application/vnd.amazon.eventstream")
    );
    assert_eq!(r.field("x-amzn-requestid").unwrap_or("").len(), 36);
    binary_frames(&r.body);
    let names = event_names(&r.body);
    assert_eq!(
        names.first().map(String::as_str),
        Some("messageStart"),
        "{names:?}"
    );
    for n in ["contentBlockDelta", "messageStop", "metadata"] {
        assert!(names.iter().any(|x| x == n), "{n}: {names:?}");
    }
}

/// An OpenAI caller that asked to stream, answered one Anthropic body, reads its own server-sent
/// events: every `data:` payload a plain chunk object (never an array), one carrying `choices`.
/// Ports legacy
/// `ingress_indistinguishability_tests.rs::test_non_gemini_stream_buffered_cross_protocol_stays_a_plain_object_not_an_array`.
#[test]
fn a_non_gemini_stream_caller_answered_one_body_reads_plain_chunks() {
    entropy();
    let far = json!({"id": "msg_buf", "type": "message", "role": "assistant",
        "content": [{"type": "text", "text": "Hi"}], "model": "claude-3",
        "stop_reason": "end_turn", "usage": {"input_tokens": 7, "output_tokens": 3}})
    .to_string();
    let r = answer(
        &arrival("openai", true),
        "anthropic",
        200,
        JSON_HEAD,
        &[far.as_bytes()],
        false,
    );
    assert_eq!(r.status, 200);
    assert!(
        r.field("content-type")
            .is_some_and(|ct| ct.starts_with("text/event-stream")),
        "{:?}",
        r.fields
    );
    let text = r.text();
    assert!(!text.trim_start().starts_with('['), "{text}");
    let mut saw_choices = false;
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data == "[DONE]" {
            continue;
        }
        let v: Value = serde_json::from_str(data).expect("a JSON chunk");
        assert!(v.is_object(), "{v}");
        saw_choices |= v.get("choices").is_some();
    }
    assert!(saw_choices, "{text}");
}

/// An embeddings answer for a caller whose dialect serves no embeddings is that dialect's 404,
/// delivers nothing and carries no units (so nothing is charged and the budget unit comes back).
/// Ports the plane half of legacy
/// `crossproto_delivery_billing_tests.rs::ingress_unsupported_404_does_not_charge`.
#[test]
fn an_answer_for_an_operation_the_callers_dialect_lacks_is_a_404_that_charges_nothing() {
    entropy();
    let body = br#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":42}}"#;
    let w = whole::translate(
        &WholeCtx {
            ingress: "anthropic",
            egress: "openai",
            operation: OpVerb::EMBEDDINGS,
            model: "m0",
            wants_stream: false,
            json_array: false,
            request: None,
            now_s: AT.now_s,
            elapsed_ms: None,
        },
        200,
        body,
    );
    assert_eq!(w.end, WholeEnd::IngressUnsupported);
    assert_eq!(w.answer.status, 404);
    assert!(w.usage.is_none(), "no usage stands");

    let arrived = Arrived {
        dialect: "anthropic",
        operation: OpVerb::EMBEDDINGS,
        model: "p".to_string(),
        content_type: "application/json".to_string(),
        body: b"{}".to_vec(),
        parsed: Some(json!({})),
        path: "/v1/embeddings".to_string(),
        query: None,
        path_model: None,
    };
    let lane = lane("openai");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane: &lane,
        intent: Default::default(),
        passthrough: false,
    };
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let mut reply = Reply::new(&ctx, 200, head);
    let piece = reply.feed(&ctx, body, true, AT);
    assert_eq!(piece.head.map(|h| h.status), Some(404));
    assert_eq!(piece.units, Units::default());
    assert_eq!(piece.fault, None);
    assert_eq!(piece.verdict, Verdict::Hard);
}

/// A translated answer relays none of the far end's head fields: it is the caller dialect's own
/// answer. Ports legacy `client_header_forwarding_tests.rs::a_translated_answer_relays_no_upstream_head`.
#[test]
fn a_translated_answer_relays_no_far_head_field() {
    entropy();
    let far = json!({"id": "chatcmpl-x", "object": "chat.completion", "created": 1,
        "model": "test-model", "choices": [{"index": 0,
        "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
    .to_string();
    let r = answer(
        &arrival("anthropic", false),
        "openai",
        200,
        &[
            ("content-type", "application/json"),
            ("x-ratelimit-remaining-tokens", "99"),
            ("openai-processing-ms", "12"),
            ("openai-organization", "org-operator"),
            ("openai-project", "proj-operator"),
        ],
        &[far.as_bytes()],
        false,
    );
    assert_eq!(r.status, 200);
    assert!(
        r.field("x-ratelimit-remaining-tokens").is_none(),
        "{:?}",
        r.fields
    );
    assert!(r.field("openai-processing-ms").is_none(), "{:?}", r.fields);
}

// ── a stream-intent caller answered one body ────────────────────────────────────────────────────

/// The letter the codec's golden corpus names each dialect by.
fn letter(dialect: &str) -> char {
    match dialect {
        "anthropic" => 'a',
        "openai" => 'o',
        "gemini" => 'g',
        "bedrock" => 'b',
        "responses" => 'r',
        "cohere" => 'c',
        other => panic!("{other}"),
    }
}

/// The first native answer of `dialect` the codec's golden corpus holds.
fn native_answer(dialect: &str) -> Vec<u8> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/tests/proto/golden");
    let infix = format!("2{}_", letter(dialect));
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("the golden corpus is readable")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("resp_") && n.ends_with(".json") && n[6..].starts_with(&infix))
        .collect();
    names.sort();
    std::fs::read(dir.join(names.first().expect("an answer"))).expect("a golden is readable")
}

/// A caller of every dialect that asked to stream, answered one native body by a far end of every
/// dialect: within one dialect the body relays as it came; across dialects the caller reads its own
/// stream frames under its own stream content type (server-sent events, or Bedrock's binary frames);
/// a Gemini caller that asked for its stream as an array reads a one-element array. Ports legacy
/// `plane_reply_parity_tests.rs::a_stream_intent_answered_one_body_reads_the_same_through_the_plane`.
#[test]
fn a_stream_intent_answered_one_body_reads_the_callers_own_frames() {
    entropy();
    let mut checked = 0;
    for egress in SIX {
        let body = native_answer(egress);
        for ingress in SIX {
            let r = answer(
                &arrival(ingress, true),
                egress,
                200,
                JSON_HEAD,
                &[&body],
                false,
            );
            assert_eq!(r.status, 200, "{ingress}<-{egress}");
            assert_eq!(r.verdict, Verdict::Ok, "{ingress}<-{egress}");
            if ingress == egress {
                assert_eq!(r.body, body, "{ingress}: relayed as it came");
                assert_eq!(r.field("content-type"), Some("application/json"));
            } else {
                let ct = wire::ingress_stream_content_type(ingress).expect("a stream type");
                assert_eq!(r.field("content-type"), Some(ct), "{ingress}<-{egress}");
                if ingress == "bedrock" {
                    assert!(!binary_frames(&r.body).is_empty(), "{ingress}<-{egress}");
                } else {
                    let text = r.text();
                    assert!(
                        !text.trim_start().starts_with('['),
                        "{ingress}<-{egress}: {text}"
                    );
                    assert!(!payloads(&text).is_empty(), "{ingress}<-{egress}: {text}");
                }
            }
            checked += 1;
        }
        if egress != "gemini" {
            let r = answer(
                &gemini_array(false),
                egress,
                200,
                JSON_HEAD,
                &[&body],
                false,
            );
            assert_eq!(r.status, 200);
            assert_eq!(r.field("content-type"), Some("application/json"));
            assert_eq!(
                r.json().as_array().map(Vec::len),
                Some(1),
                "gemini<-{egress}: {}",
                r.text()
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 36 + 5);
}

/// The answer a far end of `egress` gives a stream-asking caller when it ignores the stream: one
/// JSON body for a one-text-block completion of `hi`, 11 in and 7 out.
fn buffered_answer(egress: &str) -> String {
    let usage_oa = json!({"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18});
    match egress {
        "anthropic" => {
            json!({"id": "msg_up", "type": "message", "role": "assistant", "model": "m0",
            "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
            "stop_sequence": null, "usage": {"input_tokens": 11, "output_tokens": 7}})
        }
        "openai" => json!({"id": "chatcmpl-up", "object": "chat.completion", "created": 0,
            "model": "m0", "choices": [{"index": 0, "message": {"role": "assistant",
            "content": "hi"}, "finish_reason": "stop"}], "usage": usage_oa}),
        "cohere" => json!({"id": "cohere-up", "finish_reason": "COMPLETE",
            "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
            "usage": {"billed_units": {"input_tokens": 11, "output_tokens": 7},
                      "tokens": {"input_tokens": 11, "output_tokens": 7}}}),
        "gemini" => json!({"candidates": [{"content": {"role": "model",
            "parts": [{"text": "hi"}]}, "finishReason": "STOP", "index": 0}],
            "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 7,
                              "totalTokenCount": 18}, "modelVersion": "m0"}),
        "bedrock" => json!({"output": {"message": {"role": "assistant",
            "content": [{"text": "hi"}]}}, "stopReason": "end_turn",
            "usage": {"inputTokens": 11, "outputTokens": 7, "totalTokens": 18},
            "metrics": {"latencyMs": 12}}),
        other => panic!("{other}"),
    }
    .to_string()
}

/// A `stream: true` Responses caller over a far end of `egress` that answered one JSON body reads
/// a Responses event stream: `response.created` first, `response.completed` last (its response
/// `completed`, a `resp_` id, the far end's text and 11/7/18 usage), no `[DONE]`, every frame's
/// `type` its event name; and the answer's 11 in and 7 out are reported once, on its one piece.
fn a_responses_stream_over_a_buffered(egress: &'static str) {
    entropy();
    let arrived = arrival("responses", true);
    let lane = lane(egress);
    let ctx = ctx(&arrived, &lane);
    let body = buffered_answer(egress);
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let mut reply = Reply::new(&ctx, 200, head);
    let (a, b) = body.as_bytes().split_at(body.len() / 2);
    let first = reply.feed(&ctx, a, false, AT);
    assert_eq!(
        first.units,
        Units::default(),
        "{egress}: nothing reported yet"
    );
    assert!(first.bytes.is_empty() && first.head.is_none());
    let piece = reply.feed(&ctx, b, true, AT);
    let head = piece.head.clone().expect("the head");
    assert_eq!(head.status, 200);
    let ct = head
        .fields
        .iter()
        .find(|(n, _)| n == "content-type")
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default();
    assert!(ct.starts_with("text/event-stream"), "{egress}: {ct}");
    assert_eq!(
        (piece.units.tokens_in, piece.units.tokens_out),
        (11, 7),
        "{egress}: the usage, once"
    );
    let text = String::from_utf8(piece.bytes.to_vec()).expect("UTF-8");
    let frames: Vec<(String, String)> = text
        .split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .map(|frame| {
            let mut event = String::new();
            let mut data: Vec<&str> = Vec::new();
            for line in frame.lines() {
                if let Some(e) = line.strip_prefix("event:") {
                    event = e.trim().to_string();
                } else if let Some(d) = line.strip_prefix("data:") {
                    data.push(d.strip_prefix(' ').unwrap_or(d));
                }
            }
            (event, data.join("\n"))
        })
        .collect();
    assert!(!frames.is_empty(), "{egress}");
    assert_eq!(frames[0].0, "response.created", "{egress}: {text}");
    assert!(!text.contains("[DONE]"), "{egress}: {text}");
    let (last_event, last_data) = frames.last().expect("a terminal frame");
    assert_eq!(last_event, "response.completed", "{egress}: {text}");
    let completed: Value = serde_json::from_str(last_data).expect("JSON");
    assert_eq!(completed["type"], "response.completed");
    assert!(completed["sequence_number"].is_u64(), "{last_data}");
    let response = &completed["response"];
    assert_eq!(response["object"], "response", "{last_data}");
    assert_eq!(response["status"], "completed", "{last_data}");
    assert!(
        response["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("resp_")),
        "{last_data}"
    );
    assert_eq!(
        response["output"][0]["content"][0]["text"], "hi",
        "{last_data}"
    );
    assert_eq!(response["usage"]["input_tokens"], 11, "{last_data}");
    assert_eq!(response["usage"]["output_tokens"], 7, "{last_data}");
    assert_eq!(response["usage"]["total_tokens"], 18, "{last_data}");
    for (event, data) in &frames {
        let v: Value = serde_json::from_str(data).expect("a JSON frame");
        assert_eq!(v["type"], event.as_str(), "{egress}: {data}");
    }
}

/// Ports legacy `responses_ingress_stream_tests.rs::responses_stream_over_anthropic_buffered`.
#[test]
fn a_responses_stream_over_a_buffered_anthropic_answer() {
    a_responses_stream_over_a_buffered("anthropic");
}

/// Ports legacy `responses_ingress_stream_tests.rs::responses_stream_over_openai_buffered`.
#[test]
fn a_responses_stream_over_a_buffered_openai_answer() {
    a_responses_stream_over_a_buffered("openai");
}

/// Ports legacy `responses_ingress_stream_tests.rs::responses_stream_over_cohere_buffered`.
#[test]
fn a_responses_stream_over_a_buffered_cohere_answer() {
    a_responses_stream_over_a_buffered("cohere");
}

/// Ports legacy `responses_ingress_stream_tests.rs::responses_stream_over_gemini_buffered`.
#[test]
fn a_responses_stream_over_a_buffered_gemini_answer() {
    a_responses_stream_over_a_buffered("gemini");
}

/// Ports legacy `responses_ingress_stream_tests.rs::responses_stream_over_bedrock_buffered`.
#[test]
fn a_responses_stream_over_a_buffered_bedrock_answer() {
    a_responses_stream_over_a_buffered("bedrock");
}

// ── usage ───────────────────────────────────────────────────────────────────────────────────────

/// A Gemini caller's JSON-array stream from an OpenAI far end that reports its usage in a separate
/// trailing chunk (`include_usage`) carries `usageMetadata.promptTokenCount` 600, not 0 or absent.
/// Ports legacy
/// `ingress_indistinguishability_tests.rs::test_cross_protocol_stream_delivers_trailing_usage_gemini_json_array`.
#[test]
fn a_gemini_array_stream_carries_the_far_ends_trailing_usage() {
    entropy();
    let far = [
        "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n",
        "data: [DONE]\n\n",
    ];
    let pieces: Vec<&[u8]> = far.iter().map(|f| f.as_bytes()).collect();
    let r = answer(
        &gemini_array(false),
        "openai",
        200,
        SSE_HEAD,
        &pieces,
        false,
    );
    let v = r.json();
    let prompt = v.as_array().and_then(|els| {
        els.iter().find_map(|el| {
            el.get("usageMetadata")
                .and_then(|u| u.get("promptTokenCount"))
                .and_then(Value::as_i64)
        })
    });
    assert_eq!(prompt, Some(600), "{}", r.text());
}

/// An Anthropic message with `usage` as given.
fn message_with_usage(usage: &str) -> String {
    format!(
        r#"{{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[{{"type":"text","text":"hi"}}],"stop_reason":"end_turn","stop_sequence":null,"usage":{usage}}}"#
    )
}

/// A same-dialect body whose usage the reader refuses (a count spelled as a string) bills the floor
/// over the delivered bytes, never 0; the same body with a readable usage bills exactly what it
/// says. The bytes relay verbatim either way. Ports legacy
/// `unreadable_usage_floor_tests.rs::buffered_relay_refused_usage_bills_the_floor_not_zero`.
#[test]
fn a_relayed_body_whose_usage_is_refused_bills_the_floor_not_zero() {
    entropy();
    let readable = message_with_usage(r#"{"input_tokens":1500,"output_tokens":9}"#);
    let r = answer(
        &arrival("anthropic", false),
        "anthropic",
        200,
        JSON_HEAD,
        &[readable.as_bytes()],
        false,
    );
    assert_eq!(r.body, readable.as_bytes());
    assert_eq!(r.units.tokens_in + r.units.tokens_out, 1509);

    let refused = message_with_usage(r#"{"input_tokens":"1500","output_tokens":9}"#);
    let r = answer(
        &arrival("anthropic", false),
        "anthropic",
        200,
        JSON_HEAD,
        &[refused.as_bytes()],
        false,
    );
    assert_eq!(r.body, refused.as_bytes(), "the body relays verbatim");
    let billed = r.units.tokens_in + r.units.tokens_out;
    assert_ne!(billed, 0, "never 0");
    assert_eq!(
        billed,
        wire::estimate_usage_from_truncated_tail(refused.len()).output,
        "the floor over the delivered bytes"
    );
}

/// A same-dialect OpenAI stream whose usage chunk the reader refuses ends on the reader's parse
/// error and bills the floor over the bytes the far end sent, never 0. Ports legacy
/// `unreadable_usage_floor_tests.rs::stream_refused_usage_bills_the_floor_not_zero`.
#[test]
fn a_relayed_stream_whose_usage_is_refused_bills_the_floor_not_zero() {
    entropy();
    let base = json!({"id": "chatcmpl-refused", "object": "chat.completion.chunk",
        "created": 0, "model": "m0"});
    let mut first = base.clone();
    first["choices"] = json!([{"index": 0,
        "delta": {"role": "assistant", "content": "hello"}, "finish_reason": null}]);
    let mut last = base.clone();
    last["choices"] = json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]);
    let mut usage = base;
    usage["choices"] = json!([]);
    usage["usage"] = json!({"prompt_tokens": "1500", "completion_tokens": 9});
    let mut far = Vec::new();
    for e in [first, last, usage] {
        far.extend(format!("data: {e}\n\n").into_bytes());
    }
    far.extend_from_slice(busbar_plane_llm::codec::dialect::SSE_DONE_FRAME);
    let r = answer(
        &arrival("openai", true),
        "openai",
        200,
        SSE_HEAD,
        &[&far],
        false,
    );
    assert_eq!(r.status, 200);
    let billed = r.units.tokens_in + r.units.tokens_out;
    assert_ne!(billed, 0, "never 0");
    assert_eq!(
        billed,
        wire::estimate_usage_from_truncated_tail(far.len()).output,
        "the floor over the bytes the far end sent"
    );
}

/// An OpenAI usage-only chunk reporting 600 in and 400 out.
const USAGE_CHUNK: &[u8] =
    b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n";

/// A run of bytes past the largest frame the reframing holds, with no frame end: the translator
/// gives up on the stream.
fn overflow() -> Vec<u8> {
    vec![b'x'; busbar_plane_llm::codec::eventstream::MAX_FRAME_BYTES + 16]
}

/// The counts the door is handed for `units`: what the money steps keep as the unit's last report.
fn door_counts(units: &Units) -> Vec<(u32, u64)> {
    busbar_plane_llm::plane_door::counts(units)
        .iter()
        .map(|u| (u.class, u.amount))
        .collect()
}

/// A reframed stream whose translator gives up after its first byte (its reassembly overran) ends
/// as a failure the breaker records (a transient), and bills NOTHING: the 1000 tokens reported
/// before the abort are replaced by a stated zero at the stream's natural end. A translator abort is
/// busbar failing to produce the answer, not a cut (ARCHITECT RULING U11 Q2 2026-10-06; 1.5.5's
/// stream end, v1.5.5 `crates/busbar/src/proxy/response_body.rs:563-575`, `billing_failed`). Ports
/// legacy
/// `ingress_indistinguishability_tests.rs::test_streaming_translate_abort_trips_breaker_and_skips_billing`.
#[test]
fn a_reframed_stream_whose_translator_gives_up_faults_and_bills_nothing() {
    entropy();
    let arrived = arrival("anthropic", true);
    let lane = lane("openai");
    let ctx = ctx(&arrived, &lane);
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"text/event-stream")];
    let mut reply = Reply::new(&ctx, 200, head);
    let first = reply.feed(&ctx, USAGE_CHUNK, false, AT);
    assert_eq!(
        first.units.tokens_in + first.units.tokens_out,
        1000,
        "before the abort the stream reports what it read"
    );
    let big = overflow();
    let _ = reply.feed(&ctx, &big, false, AT);
    let r = reply.feed(&ctx, &[], true, AT);
    assert!(r.done);
    assert_eq!(r.verdict, Verdict::Hard);
    assert_eq!(r.fault, Some(Fault::Transient("stream-translate-abort")));
    assert_eq!(breaker_fault(r.fault.as_ref()), FAULT_TRANSIENT);
    assert_eq!(r.units, Units::withheld(), "nothing bills: {:?}", r.units);
    assert_eq!(
        door_counts(&r.units),
        vec![(0, 0), (1, 0), (2, 0), (3, 0)],
        "the zero is stated, so it replaces the 1000 reported before the abort"
    );
}

/// A caller that leaves a reframed stream after its translator gave up bills NOTHING: the units
/// fall to a stated zero at the abort, and the cancel finds no partial answer (it answers ABORTED).
/// The abort takes precedence over the caller's leaving (ARCHITECT RULING U11 Q2 2026-10-06; 1.5.5's
/// drop arm, v1.5.5 `crates/busbar/src/proxy/response_body.rs:641-647`). The legacy test pinned that
/// the streamed tokens bill; the ruling restates it to 0. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_cancel_drop_bills_streamed_tokens_on_aborted_translate`.
#[test]
fn a_caller_leaving_a_stream_whose_translator_gave_up_bills_nothing() {
    entropy();
    let arrived = arrival("anthropic", true);
    let lane = lane("openai");
    let ctx = ctx(&arrived, &lane);
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"text/event-stream")];
    let mut reply = Reply::new(&ctx, 200, head);
    let first = reply.feed(&ctx, USAGE_CHUNK, false, AT);
    assert_eq!(first.units.tokens_in + first.units.tokens_out, 1000);
    let big = overflow();
    let second = reply.feed(&ctx, &big, false, AT);
    assert_eq!(
        second.units,
        Units::withheld(),
        "the abort states zero over what streamed"
    );
    assert_eq!(
        door_counts(&second.units),
        vec![(0, 0), (1, 0), (2, 0), (3, 0)]
    );
    assert!(
        !reply.partial(),
        "the caller leaves no partial answer: its cancel bills nothing"
    );
}

/// A caller that leaves a reframed stream mid-relay, with no abort, leaves a partial answer whose
/// streamed units stand: its cancel bills what streamed (Part 2 #62, a mid-stream cut is not a
/// refund). The door's own cell is `serve_tests.rs`
/// `the_pools_door_bills_a_stream_the_caller_dropped_what_its_readers_counted`.
#[test]
fn a_caller_leaving_a_reframed_stream_with_no_abort_bills_what_streamed() {
    entropy();
    let arrived = arrival("anthropic", true);
    let lane = lane("openai");
    let ctx = ctx(&arrived, &lane);
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"text/event-stream")];
    let mut reply = Reply::new(&ctx, 200, head);
    let first = reply.feed(&ctx, USAGE_CHUNK, false, AT);
    assert_eq!(first.units.tokens_in + first.units.tokens_out, 1000);
    assert!(
        reply.partial(),
        "the caller leaves a partial answer: its cancel bills the 1000 that streamed"
    );
}

// ── a failed generation ─────────────────────────────────────────────────────────────────────────

/// A Cohere non-stream body ending `finish_reason`, reporting 10 in and 5 out.
fn cohere_body(finish_reason: &str) -> String {
    json!({"id": "c-1", "finish_reason": finish_reason,
        "message": {"role": "assistant", "content": [{"type": "text", "text": "x"}]},
        "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}})
    .to_string()
}

/// A same-dialect Cohere `finish_reason: "ERROR"` relays to the Cohere caller byte for byte under
/// its 200, yet ends as a failure the breaker records, and the 10/5 the far end reported is charged.
/// Ports legacy
/// `failed_generation.rs::same_protocol_cohere_error_relays_verbatim_faults_the_breaker_and_charges_10_5`.
#[test]
fn a_same_dialect_failed_generation_relays_verbatim_faults_and_charges() {
    entropy();
    let body = cohere_body("ERROR");
    let r = answer(
        &arrival("cohere", false),
        "cohere",
        200,
        JSON_HEAD,
        &[body.as_bytes()],
        false,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.body, body.as_bytes(), "byte for byte");
    assert_eq!(r.verdict, Verdict::Hard);
    assert_eq!(
        r.fault,
        Some(Fault::Transient("upstream-generation-failed"))
    );
    assert_eq!(breaker_fault(r.fault.as_ref()), FAULT_TRANSIENT);
    assert_eq!((r.units.tokens_in, r.units.tokens_out), (10, 5));

    let ok = cohere_body("COMPLETE");
    let r = answer(
        &arrival("cohere", false),
        "cohere",
        200,
        JSON_HEAD,
        &[ok.as_bytes()],
        false,
    );
    assert_eq!((r.verdict, r.fault), (Verdict::Ok, None), "the control");
    assert_eq!((r.units.tokens_in, r.units.tokens_out), (10, 5));
}

/// A Gemini stream to an OpenAI caller ending `MALFORMED_FUNCTION_CALL` ends on an error frame, as
/// a failure the breaker records, and still charges the 10/5 it streamed; the same stream ending
/// `STOP` is a clean success. Ports legacy
/// `failed_generation.rs::streamed_gemini_malformed_function_call_is_an_error_frame_a_breaker_fault_and_charges`.
#[test]
fn a_streamed_failed_generation_ends_on_an_error_frame_faults_and_charges() {
    entropy();
    let stream = |finish: &str| {
        let first = json!({"candidates": [{"index": 0,
            "content": {"role": "model", "parts": [{"text": "x"}]}}]});
        let last = json!({"candidates": [{"index": 0,
            "content": {"role": "model", "parts": [{"text": ""}]},
            "finishReason": finish}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5,
                "totalTokenCount": 15}});
        format!("data: {first}\n\ndata: {last}\n\n").into_bytes()
    };
    let far = stream("MALFORMED_FUNCTION_CALL");
    let r = answer(
        &arrival("openai", true),
        "gemini",
        200,
        SSE_HEAD,
        &[&far],
        false,
    );
    assert_eq!(r.status, 200);
    assert!(r.text().contains("\"error\""), "{}", r.text());
    assert!(
        matches!(r.fault, Some(Fault::Transient(_))),
        "{:?}",
        r.fault
    );
    assert_eq!(breaker_fault(r.fault.as_ref()), FAULT_TRANSIENT);
    assert_eq!(r.verdict, Verdict::Hard);
    assert_eq!((r.units.tokens_in, r.units.tokens_out), (10, 5));

    let far = stream("STOP");
    let r = answer(
        &arrival("openai", true),
        "gemini",
        200,
        SSE_HEAD,
        &[&far],
        false,
    );
    assert!(!r.text().contains("\"error\""), "{}", r.text());
    assert_eq!((r.verdict, r.fault), (Verdict::Ok, None), "the control");
    assert_eq!((r.units.tokens_in, r.units.tokens_out), (10, 5));
}

/// Relay a Cohere body arriving in `chunks` within one dialect with nothing metered (the relay
/// keeps no copy of the body): the bytes the caller read, and whether the end failed.
fn relay_unmetered(chunks: &[&[u8]]) -> (Vec<u8>, bool, bool) {
    let handler = busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == "cohere")
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(OpVerb::CHAT))
        .expect("cohere chat");
    let mut r = Relay::new(RelayCtx {
        ingress: "cohere",
        egress: "cohere",
        far_is_stream: false,
        json_array: false,
        client_include_usage: false,
        request: None,
        handler,
        meter: false,
    });
    let mut out = Vec::new();
    for c in chunks {
        if let (Fed::Bytes(b), _) = r.feed(c) {
            out.extend_from_slice(&b);
        }
    }
    let end = r.end();
    out.extend(end.bytes);
    (out, end.generation_failed, end.failed)
}

const SPLIT_FIRST: &[u8] = br#"{"id":"c-1","finish_re"#;

/// The stop-reason key of a same-dialect Cohere body arriving split across two pieces
/// (`"finish_re` | `ason":"ERROR"…`) is still found with nothing metered: the generation failed
/// (the breaker's fault, an error end) and the caller's bytes are the far end's. Ports legacy
/// `failed_generation.rs::ungoverned_same_protocol_cohere_error_split_key_faults_the_breaker`.
#[test]
fn a_split_stop_key_of_a_failed_generation_is_still_found() {
    let second: &[u8] = br#"ason":"ERROR","message":{"role":"assistant","content":[{"type":"text","text":"x"}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":5}}}"#;
    let (served, generation_failed, failed) = relay_unmetered(&[SPLIT_FIRST, second]);
    assert_eq!(served, [SPLIT_FIRST, second].concat(), "unchanged");
    assert!(generation_failed && failed);

    let arrived = arrival("cohere", false);
    let r = answer(
        &arrived,
        "cohere",
        200,
        JSON_HEAD,
        &[SPLIT_FIRST, second],
        false,
    );
    assert_eq!(
        r.fault,
        Some(Fault::Transient("upstream-generation-failed"))
    );
    assert_eq!(r.body, [SPLIT_FIRST, second].concat());
}

/// The same split body ending `COMPLETE` is no failure and ends complete. Ports legacy
/// `failed_generation.rs::ungoverned_same_protocol_cohere_complete_split_key_is_no_fault`.
#[test]
fn a_split_stop_key_of_a_completed_generation_is_no_fault() {
    let second: &[u8] = br#"ason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"x"}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":5}}}"#;
    let (served, generation_failed, failed) = relay_unmetered(&[SPLIT_FIRST, second]);
    assert_eq!(served, [SPLIT_FIRST, second].concat());
    assert!(!generation_failed && !failed);

    let arrived = arrival("cohere", false);
    let r = answer(
        &arrived,
        "cohere",
        200,
        JSON_HEAD,
        &[SPLIT_FIRST, second],
        false,
    );
    assert_eq!((r.verdict, r.fault), (Verdict::Ok, None));
}

// ── the in-band error frame and its words ───────────────────────────────────────────────────────

/// Every client-facing fallback message is free of transport and gateway vocabulary; the Gemini
/// array's closing error element carries the generic message and no transport marker; the SSE
/// dialects' error frames carry it; Cohere's is its own `message-end` `ERROR` frame with no message.
/// Ports legacy `mid_stream_error_tests.rs::test_mid_stream_generic_detail_has_no_leak_markers`.
#[test]
fn the_fallback_messages_name_no_transport_or_gateway() {
    const LEAK_MARKERS: &[&str] = &[
        "http://",
        "https://",
        "reqwest",
        "hyper",
        "tcp",
        "dns",
        "connect",
        "amazonaws",
        "url",
        "error sending request",
        "upstream",
        "proxy",
        "gateway",
        "backend",
        "lane",
        "translat",
    ];
    for detail in [
        wire::MID_STREAM_GENERIC_DETAIL,
        wire::GENERIC_REJECTED_DETAIL,
        wire::GENERIC_RESPONSE_ERROR_DETAIL,
    ] {
        for marker in LEAK_MARKERS {
            assert!(
                !detail.to_ascii_lowercase().contains(marker),
                "{marker:?} in {detail:?}"
            );
        }
    }
    let mut framer = busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == "gemini")
        .and_then(|d| d.dialect())
        .and_then(|dc| dc.make_array_stream_framer())
        .expect("gemini frames an array");
    let arr = framer.finish_with_server_error(wire::MID_STREAM_GENERIC_DETAIL);
    let arr = String::from_utf8_lossy(&arr);
    assert!(arr.contains(wire::MID_STREAM_GENERIC_DETAIL), "{arr}");
    for marker in ["https://", "reqwest", "hyper", "amazonaws"] {
        assert!(!arr.contains(marker), "{marker}: {arr}");
    }
    for d in ["openai", "anthropic", "gemini", "responses"] {
        let bytes = wire::mid_stream_error_bytes(d, false, wire::MID_STREAM_GENERIC_DETAIL, None);
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains(wire::MID_STREAM_GENERIC_DETAIL),
            "{d}: {text}"
        );
    }
    let cohere =
        wire::mid_stream_error_bytes("cohere", false, wire::MID_STREAM_GENERIC_DETAIL, None);
    let cohere = String::from_utf8_lossy(&cohere);
    assert!(
        cohere.contains("message-end") && cohere.contains("ERROR"),
        "{cohere}"
    );
    assert!(
        !cohere.contains(wire::MID_STREAM_GENERIC_DETAIL),
        "{cohere}"
    );
}

/// A Bedrock caller's in-band error is one CRC-valid binary exception frame
/// (`:message-type` exception, `:exception-type` `InternalServerException`) whose payload carries the
/// message, never server-sent event text. Ports legacy
/// `mid_stream_error_tests.rs::test_bedrock_ingress_mid_stream_error_is_binary_exception_frame`.
#[test]
fn a_bedrock_callers_in_band_error_is_one_binary_exception_frame() {
    let bytes = wire::mid_stream_error_bytes("bedrock", true, "connection reset by peer", None);
    assert!(!bytes.starts_with(b"event:") && !bytes.starts_with(b"data:"));
    let frames = binary_frames(&bytes);
    assert_eq!(frames.len(), 1);
    let (headers, payload) = &frames[0];
    assert!(headers.contains(":message-type"), "{headers}");
    assert!(headers.contains("exception"), "{headers}");
    assert!(headers.contains(":exception-type"), "{headers}");
    assert!(headers.contains("InternalServerException"), "{headers}");
    let v: Value = serde_json::from_slice(payload).expect("a JSON payload");
    assert_eq!(v["message"], "connection reset by peer");
}

/// Each server-sent event dialect's in-band error is its own streaming error event: a bare `data:`
/// frame for OpenAI, Cohere and Gemini; `event: error` for Anthropic; `event: response.failed` with
/// the `response` wrapper for Responses. Ports legacy
/// `mid_stream_error_tests.rs::test_sse_ingress_mid_stream_error_uses_native_framing`.
#[test]
fn each_dialects_in_band_error_is_its_own_stream_event() {
    for d in ["openai", "cohere", "gemini"] {
        let text =
            String::from_utf8(wire::mid_stream_error_bytes(d, false, "boom", None)).expect("text");
        assert!(text.starts_with("data: "), "{d}: {text}");
        assert!(!text.contains("event:"), "{d}: {text}");
        let data = text
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("a data line");
        let v: Value = serde_json::from_str(data).expect("JSON");
        let cohere_end = v.get("type").and_then(Value::as_str) == Some("message-end")
            && v.pointer("/delta/finish_reason")
                .and_then(Value::as_str)
                .is_some_and(|f| f.starts_with("ERROR"));
        assert!(
            v.get("error").is_some() || v.get("message").is_some() || cohere_end,
            "{d}: {v}"
        );
    }
    let text = String::from_utf8(wire::mid_stream_error_bytes(
        "anthropic",
        false,
        "boom",
        None,
    ))
    .expect("text");
    assert!(text.starts_with("event: error\n"), "{text}");
    let data = text
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("a data line");
    let v: Value = serde_json::from_str(data).expect("JSON");
    assert!(v["error"]["message"].is_string(), "{v}");

    let text = String::from_utf8(wire::mid_stream_error_bytes(
        "responses",
        false,
        "boom",
        None,
    ))
    .expect("text");
    assert!(text.starts_with("event: response.failed\n"), "{text}");
    let data = text
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("a data line");
    let v: Value = serde_json::from_str(data).expect("JSON");
    assert!(v.get("response").is_some(), "{v}");
    assert_eq!(v["response"]["status"], "failed", "{v}");
    assert!(v["response"]["error"]["message"].is_string(), "{v}");
    assert!(v.get("error").is_none(), "{v}");
}

/// A dialect the plane does not hold gets a bare `data:` frame over the agnostic envelope
/// (`api_error`, the message), no `event:` line. Ports legacy
/// `wire_tests.rs::unknown_ingress_mid_stream_error_is_a_bare_data_frame_from_core`.
#[test]
fn an_unknown_dialects_in_band_error_is_a_bare_agnostic_frame() {
    let s = String::from_utf8(wire::mid_stream_error_bytes(
        "no-such-protocol",
        false,
        "upstream vanished",
        None,
    ))
    .expect("text");
    assert!(s.starts_with("data: ") && s.ends_with("\n\n"), "{s}");
    assert!(!s.contains("event:"), "{s}");
    let payload = s.trim_start_matches("data: ").trim_end_matches("\n\n");
    let v: Value = serde_json::from_str(payload).expect("JSON");
    assert_eq!(v["error"]["type"], "api_error");
    assert_eq!(v["error"]["message"], "upstream vanished");
}

/// A client fault's kind by its class: context length is `context_length_exceeded`, a client error
/// `invalid_request_error`. Ports legacy `mid_stream_error_tests.rs::test_client_fault_kind_mapping`.
#[test]
fn a_client_faults_kind_follows_its_class() {
    assert_eq!(
        wire::client_fault_kind(StatusClass::ContextLength),
        "context_length_exceeded"
    );
    assert_eq!(
        wire::client_fault_kind(StatusClass::ClientError),
        "invalid_request_error"
    );
}

/// The whole class-to-kind column, pinned as bytes: every class `invalid_request_error` but context
/// length. Ports legacy `wire_tests.rs::status_word_golden_engine_client_fault_kind`.
#[test]
fn every_class_names_its_client_fault_kind() {
    let golden: [(StatusClass, &str); 9] = [
        (StatusClass::RateLimit, "invalid_request_error"),
        (StatusClass::Overloaded, "invalid_request_error"),
        (StatusClass::ServerError, "invalid_request_error"),
        (StatusClass::Timeout, "invalid_request_error"),
        (StatusClass::Network, "invalid_request_error"),
        (StatusClass::Auth, "invalid_request_error"),
        (StatusClass::Billing, "invalid_request_error"),
        (StatusClass::ClientError, "invalid_request_error"),
        (StatusClass::ContextLength, "context_length_exceeded"),
    ];
    for (class, word) in golden {
        assert_eq!(wire::client_fault_kind(class), word, "{class:?}");
    }
}

/// The far end's error message across vendor shapes (`error.message`, a top-level `message`), and
/// none for a body that is not JSON or names none. Ports legacy
/// `mid_stream_error_tests.rs::test_extract_error_message`.
#[test]
fn a_far_end_errors_message_is_read_across_shapes() {
    assert_eq!(
        wire::extract_error_message(br#"{"error":{"message":"bad param"}}"#).as_deref(),
        Some("bad param")
    );
    assert_eq!(
        wire::extract_error_message(br#"{"message":"flat"}"#).as_deref(),
        Some("flat")
    );
    assert_eq!(wire::extract_error_message(b"not json"), None);
    assert_eq!(wire::extract_error_message(br#"{"foo":1}"#), None);
}

/// A streamed answer's content type is recognised by prefix (server-sent events, with or without
/// parameters, and the binary event stream); JSON and an empty type are not streams. Ports legacy
/// `mid_stream_error_tests.rs::test_is_stream_content_type`.
#[test]
fn a_stream_content_type_is_recognised_by_prefix() {
    assert!(wire::is_stream_content_type("text/event-stream"));
    assert!(wire::is_stream_content_type(
        "application/vnd.amazon.eventstream"
    ));
    assert!(wire::is_stream_content_type(
        "text/event-stream; charset=utf-8"
    ));
    assert!(!wire::is_stream_content_type("application/json"));
    assert!(!wire::is_stream_content_type(""));
}
