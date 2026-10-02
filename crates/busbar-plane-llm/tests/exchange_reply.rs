// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The far end's answer, sans I/O: a far-end error judged, a whole answer translated, a relayed
//! answer, and the reply that drives them, through the public API.

use std::collections::HashMap;

use busbar_contract::operation::OpVerb;
use busbar_contract::upstream::{Disposition, RawUpstreamError, StatusClass};
use busbar_plane_llm::exchange::reply::failure::{
    auth_failure, judge, normalize, relay_verbatim, FarError,
};
use busbar_plane_llm::exchange::reply::wire::head_field;
use serde_json::Value;

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

fn raw(status: u16, code: Option<&str>, ty: Option<&str>) -> RawUpstreamError {
    let mut r = RawUpstreamError::from_status(status);
    r.provider_code = code.map(str::to_string);
    r.structured_type = ty.map(str::to_string);
    r
}

fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn field<'a>(fields: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
}

/// A dialect may declare a relayed head field the way its vendor spells it; the caller reads the
/// wire (lower-case) form, and a name that is no legal field name is dropped, never fatal.
#[test]
fn a_declared_head_field_name_is_lowered_and_an_illegal_one_dropped() {
    let (name, value) = head_field("x-amzn-RequestId", b"req-1").expect("a legal name");
    assert_eq!(name, "x-amzn-requestid");
    assert_eq!(value, b"req-1");
    assert_eq!(
        head_field("x-amzn-requestid", b"req-1").map(|f| f.0),
        Some(name)
    );
    for illegal in ["x amzn requestid", "x-amzn-\u{1f600}", ""] {
        assert!(head_field(illegal, b"v").is_none(), "{illegal:?}");
    }
}

/// The class of a far-end error: a mapped code, the built-in context-length code on a request-size
/// status only, a mapped structured type, and the status; `context_length` never masks a 5xx.
#[test]
fn a_far_end_error_is_placed_in_its_class() {
    let em = map(&[
        ("1302", "rate_limit"),
        ("quota", "billing"),
        ("ctx", "context_length"),
        ("typo", "rate_limt"),
        ("overloaded_error", "overloaded"),
    ]);
    let cases: &[(u16, Option<&str>, Option<&str>, StatusClass)] = &[
        (400, Some("1302"), None, StatusClass::RateLimit),
        (402, Some("quota"), None, StatusClass::Billing),
        (400, Some("ctx"), None, StatusClass::ContextLength),
        (503, Some("ctx"), None, StatusClass::ServerError),
        (
            400,
            Some("context_length_exceeded"),
            None,
            StatusClass::ContextLength,
        ),
        (
            413,
            Some("context_length_exceeded"),
            None,
            StatusClass::ContextLength,
        ),
        (
            401,
            Some("context_length_exceeded"),
            None,
            StatusClass::Auth,
        ),
        (400, Some("typo"), None, StatusClass::ClientError),
        (500, None, Some("overloaded_error"), StatusClass::Overloaded),
        (503, None, Some("ctx"), StatusClass::ServerError),
        (401, None, None, StatusClass::Auth),
        (403, None, None, StatusClass::Auth),
        (429, None, None, StatusClass::RateLimit),
        (408, None, None, StatusClass::Timeout),
        (529, None, None, StatusClass::Overloaded),
        (502, None, None, StatusClass::ServerError),
        (404, None, None, StatusClass::ClientError),
        (302, None, None, StatusClass::ClientError),
    ];
    for &(status, code, ty, want) in cases {
        let r = raw(status, code, ty);
        assert_eq!(normalize(status, &r, &em).class, want, "{r:?}");
    }
    let sig = normalize(400, &raw(400, Some("1302"), None), &em);
    assert_eq!(sig.provider_signal.as_deref(), Some("1302"));
}

const JSON_HEAD: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];

/// A far-end error judged, for every dialect: a caller's own credential failing is relayed
/// unjudged; a client fault within one dialect is the far end's bytes, across dialects the
/// caller's envelope; the deployment's refused credential is the caller's own refusal; a transient
/// carries the relay the walk ends on.
#[test]
fn a_far_end_error_is_judged_for_every_pair() {
    let head = JSON_HEAD;
    let body = br#"{"error":{"message":"bad things","type":"invalid_request_error"}}"#;
    for ingress in SIX {
        for egress in SIX {
            let far = |status| FarError { status, head, body };
            let j = judge(
                ingress,
                egress,
                OpVerb::CHAT,
                &HashMap::new(),
                true,
                &far(401),
            );
            assert_eq!(j.signal, None);
            assert_eq!(j.disposition, Disposition::ClientFault);
            assert_eq!(j.answer.status, 401);

            let j = judge(
                ingress,
                egress,
                OpVerb::CHAT,
                &HashMap::new(),
                false,
                &far(400),
            );
            assert_eq!(
                j.disposition,
                Disposition::ClientFault,
                "{ingress}<-{egress}"
            );
            if ingress == egress {
                assert_eq!(j.answer.body, body, "{ingress}: verbatim");
                assert_eq!(
                    field(&j.answer.fields, "content-type"),
                    Some(b"application/json".as_slice())
                );
            } else {
                let v: Value = serde_json::from_slice(&j.answer.body).expect("JSON");
                assert!(
                    v.to_string().contains("bad things"),
                    "{ingress}<-{egress}: {v}"
                );
            }

            let j = judge(
                ingress,
                egress,
                OpVerb::CHAT,
                &HashMap::new(),
                false,
                &far(401),
            );
            assert_eq!(j.disposition, Disposition::HardDown);
            assert_eq!(j.answer, auth_failure(ingress), "{ingress}<-{egress}");

            let j = judge(
                ingress,
                egress,
                OpVerb::CHAT,
                &HashMap::new(),
                false,
                &far(503),
            );
            assert_eq!(j.disposition, Disposition::TransientUpstream);
            assert_eq!(j.answer.status, 503);
        }
    }
}

/// A caller that relays the far end's `x-amzn-*` fields reads them verbatim on a same-dialect
/// relay; any other caller reads the far end's own request id.
#[test]
fn a_verbatim_relay_carries_the_native_head_fields() {
    let head: &[(&[u8], &[u8])] = &[
        (b"Content-Type", b"application/json"),
        (b"x-amzn-requestid", b"amzn-1"),
        (b"x-amzn-errortype", b"ValidationException"),
        (b"request-id", b"req_1"),
    ];
    let far = FarError {
        status: 400,
        head,
        body: b"{}",
    };
    let bedrock = relay_verbatim("bedrock", &far);
    assert_eq!(
        field(&bedrock.fields, "x-amzn-requestid"),
        Some(b"amzn-1".as_slice())
    );
    assert_eq!(
        field(&bedrock.fields, "x-amzn-errortype"),
        Some(b"ValidationException".as_slice())
    );
    let anthropic = relay_verbatim("anthropic", &far);
    assert_eq!(
        field(&anthropic.fields, "request-id"),
        Some(b"req_1".as_slice())
    );
    let openai = relay_verbatim("openai", &far);
    assert_eq!(
        openai.fields.len(),
        4,
        "every far field: {:?}",
        openai.fields
    );
}

/// BUSBAR IS INVISIBLE ON A SAME-DIALECT ANSWER: every far head field reaches the caller in order,
/// except what busbar governs (the far end's echo of the operator's tenant); nothing is invented.
#[test]
fn a_verbatim_relay_carries_every_far_field_but_the_governed_ones() {
    let head: &[(&[u8], &[u8])] = &[
        (b"content-type", b"application/json"),
        (b"x-ratelimit-remaining-tokens", b"99"),
        (b"Retry-After", b"3"),
        (b"openai-organization", b"org-operator"),
        (b"openai-project", b"proj-operator"),
    ];
    let far = FarError {
        status: 429,
        head,
        body: b"{}",
    };
    let openai = relay_verbatim("openai", &far);
    let names: Vec<&str> = openai.fields.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "content-type",
            "x-ratelimit-remaining-tokens",
            "retry-after"
        ]
    );
    let anthropic = relay_verbatim("anthropic", &far);
    assert!(
        !anthropic.fields.iter().any(|(n, _)| n == "request-id"),
        "a plane never invents a head field: {:?}",
        anthropic.fields
    );
    assert!(anthropic
        .fields
        .iter()
        .any(|(n, _)| n == "openai-organization"));
}

// ── a whole answer ──────────────────────────────────────────────────────────────────────────────

use busbar_plane_llm::exchange::reply::whole::{self, WholeCtx, WholeEnd};

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

/// Every native answer of `dialect` the codec's golden corpus holds: each `resp_X2Y_*.json` is a
/// body written in dialect Y, so it is also a far end of dialect Y answering.
pub fn native_answers(dialect: &str) -> Vec<(String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/codec/tests/proto/golden");
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

fn ctx<'a>(
    ingress: &'a str,
    egress: &'a str,
    wants_stream: bool,
    json_array: bool,
) -> WholeCtx<'a> {
    WholeCtx {
        ingress,
        egress,
        operation: OpVerb::CHAT,
        model: "m-1",
        wants_stream,
        json_array,
        request: None,
        now_s: 1_752_000_000,
        elapsed_ms: Some(12),
    }
}

/// Every far end's native answer, for a caller of every other dialect, is delivered in the
/// caller's own dialect under `application/json`, with the usage the far end reported.
#[test]
fn a_whole_answer_is_delivered_in_the_callers_dialect() {
    let mut checked = 0;
    for egress in SIX {
        let answers = native_answers(egress);
        assert!(
            !answers.is_empty(),
            "{egress}: no native answer in the corpus"
        );
        for (name, body) in &answers {
            for ingress in SIX.iter().copied().filter(|i| *i != egress) {
                let w = whole::translate(&ctx(ingress, egress, false, false), 200, body);
                assert_eq!(
                    w.end,
                    WholeEnd::Delivered,
                    "{ingress}<-{egress} {name}: {:?}",
                    w.refused
                );
                assert_eq!(w.answer.status, 200);
                assert_eq!(
                    field(&w.answer.fields, "content-type"),
                    Some(b"application/json".as_slice()),
                    "{ingress}<-{egress} {name}"
                );
                let _: Value = serde_json::from_slice(&w.answer.body).expect("a JSON answer");
                assert!(w.usage.is_some(), "{ingress}<-{egress} {name}: usage");
                checked += 1;
            }
        }
    }
    assert!(checked >= 6 * 5, "{checked}");
}

/// A generation the far end reports as failed is a 502 that still carries the usage it reported.
#[test]
fn a_failed_generation_is_a_502_that_keeps_its_usage() {
    let body = br#"{"id":"c-1","finish_reason":"ERROR","message":{"role":"assistant","content":[{"type":"text","text":"x"}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":5}}}"#;
    let w = whole::translate(&ctx("openai", "cohere", false, false), 200, body);
    assert_eq!(w.end, WholeEnd::FailedGeneration);
    assert_eq!(w.answer.status, 502);
    assert!(w.usage.is_some());
}

/// An answer the caller's dialect cannot be written from is a 500 in the caller's envelope; the
/// cap and the cut are the 500 and the 502 of the same envelope.
#[test]
fn an_untranslatable_answer_is_the_callers_500() {
    for ingress in SIX {
        let w = whole::translate(
            &ctx(ingress, "anthropic", false, false),
            200,
            b"not json at all",
        );
        assert_eq!(w.end, WholeEnd::NotTranslatable, "{ingress}");
        assert_eq!(w.answer.status, 500);
        assert!(w.usage.is_none());
        assert_eq!(whole::over_cap(ingress).answer.status, 500);
        assert_eq!(whole::over_cap(ingress).end, WholeEnd::OverCap);
        assert_eq!(whole::cut(ingress).answer.status, 502);
        assert_eq!(whole::cut(ingress).end, WholeEnd::Cut);
    }
}

/// A caller that asked for a JSON-array stream from a far end that answered one body reads a
/// one-element array under `application/json`, and no request id.
#[test]
fn a_json_array_caller_reads_a_one_element_array() {
    let (_, body) = native_answers("openai")
        .into_iter()
        .next()
        .expect("an openai answer");
    let w = whole::translate(&ctx("gemini", "openai", true, true), 200, &body);
    assert_eq!(w.end, WholeEnd::Delivered);
    let v: Value = serde_json::from_slice(&w.answer.body).expect("JSON");
    assert_eq!(v.as_array().map(Vec::len), Some(1), "{v}");
    assert_eq!(w.answer.fields.len(), 1, "{:?}", w.answer.fields);
}

// ── a relayed answer ────────────────────────────────────────────────────────────────────────────

use busbar_plane_llm::exchange::reply::relay::{self, ContentType, Fed, Relay, RelayCtx};

fn chat_handler(dialect: &str) -> &'static dyn busbar_contract::codec::OperationHandler {
    busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == dialect)
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(OpVerb::CHAT))
        .expect("every dialect serves chat")
}

fn relay_ctx<'a>(ingress: &'a str, egress: &'a str, far_is_stream: bool) -> RelayCtx<'a> {
    RelayCtx {
        ingress,
        egress,
        far_is_stream,
        json_array: false,
        client_include_usage: false,
        request: None,
        handler: chat_handler(ingress),
        meter: true,
    }
}

/// An OpenAI chat stream: two text deltas, the stop, the usage chunk and the terminator.
fn openai_stream() -> Vec<u8> {
    let chunk = |delta: &str, finish: &str| {
        format!(
            "data: {{\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m-1\",\"choices\":[{{\"index\":0,\"delta\":{delta},\"finish_reason\":{finish}}}]}}\n\n"
        )
    };
    let mut s = String::new();
    s += &chunk(r#"{"role":"assistant","content":"Hel"}"#, "null");
    s += &chunk(r#"{"content":"lo"}"#, "null");
    s += &chunk("{}", r#""stop""#);
    s += "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"m-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n";
    s += "data: [DONE]\n\n";
    s.into_bytes()
}

/// Every piece a relay answers, concatenated, for `far` fed in pieces of `step` bytes.
fn relay_all(r: &mut Relay, far: &[u8], step: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in far.chunks(step) {
        if let (Fed::Bytes(b), _) = r.feed(piece) {
            out.extend_from_slice(&b);
        }
    }
    out.extend(r.end().bytes);
    out
}

/// A far end's native stream of `dialect`: the OpenAI stream above as the translator writes it for
/// a caller of that dialect.
fn native_stream(dialect: &str) -> Vec<u8> {
    let mut ctx = relay_ctx(dialect, "openai", true);
    ctx.client_include_usage = true;
    let mut r = Relay::new(ctx);
    relay_all(&mut r, &openai_stream(), usize::MAX)
}

/// A same-dialect whole body relays untouched (the far end's own bytes, borrowed) and its usage is
/// read at the end — in every dialect, Bedrock included (no busbar-measured `metrics` is added).
#[test]
fn a_same_dialect_whole_body_relays_untouched_and_meters() {
    for dialect in SIX {
        let (_, body) = native_answers(dialect)
            .into_iter()
            .next()
            .expect("an answer");
        let mut r = Relay::new(relay_ctx(dialect, dialect, false));
        let mut out = Vec::new();
        for piece in body.chunks(9) {
            match r.feed(piece) {
                (Fed::Bytes(std::borrow::Cow::Borrowed(b)), _) => out.extend_from_slice(b),
                other => panic!("{dialect}: {other:?}"),
            }
        }
        let end = r.end();
        assert_eq!(out, body, "{dialect}");
        assert!(end.bytes.is_empty() && !end.failed, "{dialect}");
        assert!(end.usage.is_some(), "{dialect}: usage");
        assert_eq!(
            relay::content_type(dialect, dialect, false, false),
            ContentType::Far
        );
    }
}

/// `json` with a member busbar has never heard of spliced in after its first opening brace.
fn with_unknown_member(json: &[u8]) -> Vec<u8> {
    let brace = json.iter().position(|b| *b == b'{').expect("an object");
    let mut out = json[..=brace].to_vec();
    out.extend_from_slice(br#""zz_never_heard_of":{"b":1,"a":[1.50, "x"]},"#);
    out.extend_from_slice(&json[brace + 1..]);
    out
}

/// SAME-DIALECT IDENTITY, the answer side (LLM DIALECT FIDELITY; DIALECT-FIDELITY-DESIGN F4): in
/// every dialect a buffered answer and a stream that carry a member busbar has never heard of reach
/// the caller byte-identical, and are still metered. The RED arm is any reserialize or rebuild on
/// the relay (a parse-and-write drops the member, sorts the keys, prints `1.50` as `1.5`).
#[test]
fn a_same_dialect_answer_carrying_an_unknown_member_reaches_the_caller_byte_identical() {
    for dialect in SIX {
        let (_, body) = native_answers(dialect)
            .into_iter()
            .next()
            .expect("an answer");
        let body = with_unknown_member(&body);
        let mut r = Relay::new(relay_ctx(dialect, dialect, false));
        let out = relay_all(&mut r, &body, 9);
        assert_eq!(out, body, "{dialect}: buffered");

        let native = native_stream(dialect);
        let far = if dialect == "bedrock" {
            let mut far = busbar_plane_llm::codec::eventstream::encode_frame(
                "zzNeverHeardOf",
                br#"{"zz":{"b":1,"a":[1.50]}}"#,
            );
            far.extend_from_slice(&native);
            far
        } else {
            let at = native
                .windows(5)
                .position(|w| w == b"data:")
                .expect("a data line");
            let mut far = native[..at].to_vec();
            far.extend_from_slice(&with_unknown_member(&native[at..]));
            far
        };
        let mut ctx = relay_ctx(dialect, dialect, true);
        ctx.client_include_usage = true;
        let mut r = Relay::new(ctx);
        let out = relay_all(&mut r, &far, 7);
        assert_eq!(out, far, "{dialect}: stream");
        let mut ctx = relay_ctx(dialect, dialect, true);
        ctx.client_include_usage = true;
        let mut r = Relay::new(ctx);
        for piece in far.chunks(7) {
            let _ = r.feed(piece);
        }
        assert!(r.end().usage.is_some(), "{dialect}: the stream is metered");
    }
}

/// A stream from a far end of every dialect reaches a caller of every dialect whole, whatever the
/// piece boundaries, and its usage is read at the end.
#[test]
fn a_stream_relays_for_every_pair_whatever_the_piece_boundaries() {
    let mut checked = 0;
    for egress in SIX {
        let far = native_stream(egress);
        assert!(!far.is_empty(), "{egress}");
        for ingress in SIX {
            let whole = relay_all(
                &mut Relay::new(relay_ctx(ingress, egress, true)),
                &far,
                usize::MAX,
            );
            let mut r = Relay::new(relay_ctx(ingress, egress, true));
            let pieces = relay_all(&mut r, &far, 7);
            assert!(!whole.is_empty(), "{ingress}<-{egress}");
            if ingress != "responses" && ingress != "anthropic" && ingress != "cohere" {
                // Dialects that mint ids per stream answer different bytes run to run; the rest
                // answer the same bytes whatever the boundaries.
                assert_eq!(pieces, whole, "{ingress}<-{egress}");
            }
            let mut r = Relay::new(relay_ctx(ingress, egress, true));
            for piece in far.chunks(5) {
                let _ = r.feed(piece);
            }
            let end = r.end();
            assert!(!end.failed, "{ingress}<-{egress}");
            assert!(end.usage.is_some(), "{ingress}<-{egress}: usage");
            checked += 1;
        }
    }
    assert_eq!(checked, 36);
}

/// A stream cut after its first byte ends on the caller's own in-band error; one cut before any
/// byte ends with no bytes and reports the far end's transfer as failed.
#[test]
fn a_cut_stream_ends_on_the_callers_error_frame() {
    for ingress in SIX {
        let far = native_stream("openai");
        let mut r = Relay::new(relay_ctx(ingress, "openai", true));
        let _ = r.feed(&far[..far.len() / 2]);
        let cut = r.cut(true);
        assert_eq!(cut.reason, "mid-stream");
        assert!(cut.partial);
        assert!(cut.bytes.is_some_and(|b| !b.is_empty()), "{ingress}");

        let mut r = Relay::new(relay_ctx(ingress, "openai", true));
        let cut = r.cut(true);
        assert_eq!(cut.reason, "pre-first-byte-transport");
        assert!(!cut.partial && cut.bytes.is_none() && cut.usage.is_none());
    }
}

/// A caller that asked for its stream as a JSON array reads one array, under `application/json`.
#[test]
fn a_json_array_caller_reads_its_stream_as_one_array() {
    let far = native_stream("gemini");
    let mut ctx = relay_ctx("gemini", "gemini", true);
    ctx.json_array = true;
    let out = relay_all(&mut Relay::new(ctx), &far, 11);
    let v: Value = serde_json::from_slice(&out).expect("one JSON array");
    assert!(v.as_array().is_some_and(|a| !a.is_empty()), "{v}");
    assert_eq!(
        relay::content_type("gemini", "gemini", true, true),
        ContentType::Json
    );
    assert!(relay::takes_whole("openai", "anthropic", false));
    assert!(!relay::takes_whole("openai", "openai", false));
    assert!(!relay::takes_whole("openai", "anthropic", true));
}

// ── the reply ───────────────────────────────────────────────────────────────────────────────────

use busbar_plane_llm::exchange::arrive::Arrived;
use busbar_plane_llm::exchange::attempt::stream_intent;
use busbar_plane_llm::exchange::reply::{At, Fault, Reply, ReplyCtx, Verdict};
use busbar_plane_llm::exchange::shaping::Lane;

fn lane(dialect: &'static str) -> Lane {
    Lane {
        model: "m-1".to_string(),
        provider: "p".to_string(),
        dialect,
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

fn arrival(dialect: &'static str, stream: bool) -> Arrived {
    let body = serde_json::json!({"model": "p", "stream": stream,
        "messages": [{"role": "user", "content": "hi"}]});
    Arrived {
        dialect,
        operation: OpVerb::CHAT,
        model: "p".to_string(),
        content_type: "application/json".to_string(),
        body: serde_json::to_vec(&body).unwrap(),
        parsed: Some(body),
        path: "/v1/chat/completions".to_string(),
        query: None,
        path_model: None,
    }
}

const AT: At = At {
    now_s: 1_752_000_000,
    elapsed_ms: Some(3),
};

/// A relayed stream: the caller's head on the first piece with an `Ok`, the bytes as frames
/// complete, the usage cumulative, and the end on the last piece.
#[test]
fn a_reply_relays_a_stream_piece_by_piece() {
    let arrived = arrival("openai", true);
    let lane = lane("anthropic");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane: &lane,
        intent: stream_intent(chat_handler("openai"), arrived.parsed.as_ref()),
        passthrough: false,
    };
    let far = native_stream("anthropic");
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"text/event-stream")];
    let mut reply = Reply::new(&ctx, 200, head);
    let pieces: Vec<&[u8]> = far.chunks(40).collect();
    let mut body = Vec::new();
    for (i, p) in pieces.iter().enumerate() {
        let last = i + 1 == pieces.len();
        let piece = reply.feed(&ctx, p, last, AT);
        if i == 0 {
            let h = piece.head.clone().expect("the head rides the first piece");
            assert_eq!(h.status, 200);
            assert_eq!(
                field(&h.fields, "content-type"),
                Some(b"text/event-stream".as_slice())
            );
            assert_eq!(piece.verdict, Verdict::Ok);
        } else {
            assert!(piece.head.is_none());
        }
        assert_eq!(piece.done, last);
        body.extend_from_slice(&piece.bytes);
        if last {
            assert_eq!(piece.verdict, Verdict::Ok);
            assert_eq!(piece.fault, None);
            assert_eq!((piece.units.tokens_in, piece.units.tokens_out), (11, 7));
        }
    }
    let text = String::from_utf8(body).expect("event text");
    assert!(
        text.starts_with("data: ") && text.ends_with("data: [DONE]\n\n"),
        "{text}"
    );
}

/// A whole answer: nothing for the caller until the last piece, then the head, the translated
/// body, the usage and `Ok`; over the cap, the caller's 500 at once.
#[test]
fn a_reply_takes_a_whole_answer_whole() {
    let arrived = arrival("openai", false);
    let lane = lane("cohere");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane: &lane,
        intent: stream_intent(chat_handler("openai"), arrived.parsed.as_ref()),
        passthrough: false,
    };
    let (_, far) = native_answers("cohere")
        .into_iter()
        .next()
        .expect("an answer");
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"application/json")];
    let mut reply = Reply::new(&ctx, 200, head);
    let (a, b) = far.split_at(far.len() / 2);
    let first = reply.feed(&ctx, a, false, AT);
    assert!(first.head.is_none() && first.bytes.is_empty() && !first.done);
    assert_eq!(first.verdict, Verdict::None);
    let last = reply.feed(&ctx, b, true, AT);
    assert_eq!(last.head.map(|h| h.status), Some(200));
    assert!(last.done);
    assert_eq!(last.verdict, Verdict::Ok);
    assert!(last.units.tokens_in > 0 && last.units.tokens_out > 0);
    let v: Value = serde_json::from_slice(&last.bytes).expect("JSON");
    assert_eq!(v["object"], "chat.completion", "{v}");
}

/// A far-end error: a client fault is `Hard` with the caller's answer; a transient is `Retry`
/// with the relay the walk ends on; the fault names the disposition and the class.
#[test]
fn a_reply_judges_a_far_end_error() {
    let arrived = arrival("openai", false);
    let lane = lane("anthropic");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane: &lane,
        intent: stream_intent(chat_handler("openai"), arrived.parsed.as_ref()),
        passthrough: false,
    };
    let body = br#"{"type":"error","error":{"type":"invalid_request_error","message":"too long"}}"#;
    for (status, verdict, disposition) in [
        (400, Verdict::Hard, Disposition::ClientFault),
        (529, Verdict::Retry, Disposition::TransientUpstream),
        (401, Verdict::Hard, Disposition::HardDown),
    ] {
        let mut reply = Reply::new(&ctx, status, JSON_HEAD);
        let (a, b) = body.split_at(10);
        assert!(!reply.feed(&ctx, a, false, AT).done);
        let piece = reply.feed(&ctx, b, true, AT);
        assert!(piece.done);
        assert_eq!(piece.verdict, verdict, "{status}");
        assert!(matches!(
            piece.fault,
            Some(Fault::Judged { disposition: d, class: Some(_) }) if d == disposition
        ));
        assert!(piece.head.is_some());
    }
}

/// A cut: a stream after its first byte ends on the caller's error frame, `Hard`, the far end's
/// transfer at fault; a whole answer cut is the caller's 502.
#[test]
fn a_reply_that_is_cut_says_so() {
    let arrived = arrival("openai", true);
    let lane = lane("anthropic");
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane: &lane,
        intent: stream_intent(chat_handler("openai"), arrived.parsed.as_ref()),
        passthrough: false,
    };
    let far = native_stream("anthropic");
    let head: &[(&[u8], &[u8])] = &[(b"content-type", b"text/event-stream")];
    let mut reply = Reply::new(&ctx, 200, head);
    let _ = reply.feed(&ctx, &far[..far.len() / 2], false, AT);
    let cut = reply.cut(&ctx, true);
    assert!(cut.done && !cut.bytes.is_empty());
    assert_eq!(cut.verdict, Verdict::Hard);
    assert_eq!(cut.fault, Some(Fault::Transient("mid-stream")));

    let arrived = arrival("openai", false);
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane: &lane,
        intent: stream_intent(chat_handler("openai"), arrived.parsed.as_ref()),
        passthrough: false,
    };
    let mut reply = Reply::new(&ctx, 200, JSON_HEAD);
    let _ = reply.feed(&ctx, b"{\"id\":", false, AT);
    let cut = reply.cut(&ctx, true);
    assert_eq!(cut.head.map(|h| h.status), Some(502));
    assert_eq!(cut.fault, Some(Fault::Transient("transport")));
}
