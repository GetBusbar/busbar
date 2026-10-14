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

/// SAME-DIALECT IDENTITY, the answer side (DIALECT FIDELITY; DIALECT-FIDELITY-DESIGN F4): in
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

/// One instant for the whole process: a relay timed on it reports a stream's latency as 0 however
/// long the relay took.
fn stopped_clock() -> std::time::Instant {
    static AT: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    *AT.get_or_init(std::time::Instant::now)
}

/// A stream from a far end of every dialect reaches a caller of every dialect whole, whatever the
/// piece boundaries, and its usage is read at the end.
///
/// ONE CLOCK FOR BOTH RELAYS. A Bedrock caller's `metadata` frame reports the stream's real elapsed
/// `metrics.latencyMs` (1.5.5 bytes), so two relays of one stream on the wall clock answer
/// different bytes whenever they straddle a millisecond (bedrock<-responses, latencyMs 1 vs 0, on a
/// loaded runner: merge-queue run 37136423381). The byte equality below is the piece-boundary claim,
/// not a race against the clock, so both relays are timed on [`stopped_clock`].
#[test]
fn a_stream_relays_for_every_pair_whatever_the_piece_boundaries() {
    let mut checked = 0;
    for egress in SIX {
        let far = native_stream(egress);
        assert!(!far.is_empty(), "{egress}");
        for ingress in SIX {
            let whole = relay_all(
                &mut Relay::new_on(relay_ctx(ingress, egress, true), stopped_clock),
                &far,
                usize::MAX,
            );
            let mut r = Relay::new_on(relay_ctx(ingress, egress, true), stopped_clock);
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

/// THE BREAKER'S READING beside the walk's verdict (ARCHITECT BREAKER OUTCOME):
/// a request too large for the window fails over with nothing recorded (RETRY, FAULT_NONE); an
/// `error_map` entry naming `rate_limit` fails over and counts toward the trip (RETRY,
/// FAULT_TRANSIENT); the caller's own bad input records nothing (HARD, FAULT_CALLER); a refused
/// credential trips every cell (HARD, FAULT_HARD) — 1.5.5's per-disposition records.
#[test]
fn a_judged_far_end_error_carries_the_breakers_reading_apart_from_its_verdict() {
    use busbar_contract::abi::transport::{FAULT_CALLER, FAULT_HARD, FAULT_NONE, FAULT_TRANSIENT};
    use busbar_plane_llm::plane_door::breaker_fault;
    let arrived = arrival("openai", false);
    let mut lane = lane("openai");
    lane.error_map = map(&[("1302", "rate_limit")]);
    let ctx = ReplyCtx {
        arrived: &arrived,
        lane: &lane,
        intent: stream_intent(chat_handler("openai"), arrived.parsed.as_ref()),
        passthrough: false,
    };
    let error = |code: &str| {
        format!(r#"{{"error":{{"message":"m","type":"invalid_request_error","code":"{code}"}}}}"#)
    };
    for (status, code, verdict, reading) in [
        (400, "context_length_exceeded", Verdict::Retry, FAULT_NONE),
        (400, "1302", Verdict::Retry, FAULT_TRANSIENT),
        (400, "bad_field", Verdict::Hard, FAULT_CALLER),
        (401, "invalid_api_key", Verdict::Hard, FAULT_HARD),
        (503, "busy", Verdict::Retry, FAULT_TRANSIENT),
    ] {
        let mut reply = Reply::new(&ctx, status, JSON_HEAD);
        let body = error(code);
        let piece = reply.feed(&ctx, body.as_bytes(), true, AT);
        assert!(piece.done, "{status} {code}");
        assert_eq!(piece.verdict, verdict, "{status} {code}");
        assert_eq!(
            breaker_fault(piece.fault.as_ref()),
            reading,
            "{status} {code}"
        );
    }
    // RED: a 2xx that failed after its head is the compensating transient 1.5.5 recorded; an
    // answer with no fault is no reading at all.
    assert_eq!(
        breaker_fault(Some(&Fault::Transient("upstream-generation-failed"))),
        FAULT_TRANSIENT
    );
    assert_eq!(breaker_fault(None), FAULT_NONE);
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

// ── the stream's one drop path (design F3 "Drops", DF-MAP-IR-GAPS section E) ─────────────────────

/// A far end's stream of `far`, relayed to a caller of `caller`: the paths the relay dropped.
fn stream_drops(caller: &str, far: &str, bytes: &[u8]) -> Vec<String> {
    let mut ctx = relay_ctx(caller, far, true);
    ctx.client_include_usage = true;
    let mut r = Relay::new(ctx);
    for piece in bytes.chunks(7) {
        let _ = r.feed(piece);
    }
    r.end().dropped
}

/// The far end's spec-shaped stream of `dialect` (the OpenAI stream itself, or as busbar writes it
/// for that dialect).
fn far_stream(dialect: &str) -> Vec<u8> {
    if dialect == "openai" {
        openai_stream()
    } else {
        native_stream(dialect)
    }
}

/// RED ARM of the stream walk: a stream of members every dialect's map or code carries drops
/// nothing, for every translated pair. A walk that named a carried member (a chunk's `id`, a
/// keepalive, a block index) would fail here.
#[test]
fn a_translated_stream_of_carried_members_drops_nothing() {
    for far in SIX {
        let bytes = far_stream(far);
        for caller in SIX.into_iter().filter(|c| *c != far) {
            assert_eq!(
                stream_drops(caller, far, &bytes),
                Vec::<String>::new(),
                "{far} -> {caller}"
            );
        }
    }
}

/// A member the caller's dialect has no form for is dropped on the one drop path, named by its wire
/// path ONCE for the whole stream however many frames carry it. RED before: a stream dropped it
/// silently (no warn, no path, no audit row).
#[test]
fn a_translated_stream_names_each_unmapped_path_once() {
    let far = String::from_utf8(openai_stream())
        .unwrap()
        .replace("\"object\":", "\"obfuscation\":\"x\",\"object\":");
    assert_eq!(
        stream_drops("anthropic", "openai", far.as_bytes()),
        vec!["obfuscation".to_string()]
    );

    // An event of a kind the far end's reader does not carry: Anthropic's frame is a union on `type`.
    let mut far = far_stream("anthropic");
    for _ in 0..2 {
        far.extend_from_slice(b"event: zz_future\ndata: {\"type\":\"zz_future\",\"x\":1}\n\n");
    }
    assert_eq!(
        stream_drops("openai", "anthropic", &far),
        vec!["type=zz_future".to_string()]
    );

    // A Responses refusal streamed as its own event: the stream reader does not carry it.
    let mut far = far_stream("responses");
    far.extend_from_slice(
        b"event: response.refusal.delta\ndata: {\"type\":\"response.refusal.delta\",\"item_id\":\"m1\",\"output_index\":0,\"content_index\":0,\"delta\":\"no\",\"sequence_number\":99}\n\n",
    );
    assert!(stream_drops("openai", "responses", &far)
        .contains(&"type=response.refusal.delta".to_string()));

    // Bedrock's frames are keyed by their event name.
    let mut far =
        busbar_plane_llm::codec::eventstream::encode_frame("zzNeverHeardOf", br#"{"zz":{"b":1}}"#);
    far.extend_from_slice(&far_stream("bedrock"));
    assert_eq!(
        stream_drops("anthropic", "bedrock", &far),
        vec!["zzNeverHeardOf".to_string()]
    );
}

/// A same-dialect stream is a relay: its reader is a tap and drops nothing, whatever it carries.
#[test]
fn a_same_dialect_stream_drops_nothing() {
    let far = String::from_utf8(openai_stream())
        .unwrap()
        .replace("\"object\":", "\"obfuscation\":\"x\",\"object\":");
    assert!(stream_drops("openai", "openai", far.as_bytes()).is_empty());
}

// ── rehomed: the engine's metered-answer tests on the served reply (F25 REHOME, status row 155) ──

/// The legacy engine's tests that pin what an answer bills (`crates/busbar-llm/src/engine/**`),
/// rehomed onto the served reply: the far end's reported units each piece carries, and the
/// verdict and fault that decide whether the request's fee stands. Each test names the legacy test
/// it replaces, the 1.5.5 figure it pins, and its RED.
mod rehomed_metering {
    use super::*;
    use std::borrow::Cow;

    use busbar_contract::abi::transport::{FAULT_NONE, FAULT_TRANSIENT};
    use busbar_plane_llm::codec::wire_shim::TRUNCATED_TAIL_BYTES_PER_TOKEN;
    use busbar_plane_llm::exchange::arrive::PathModel;
    use busbar_plane_llm::exchange::attempt::StreamIntent;
    use busbar_plane_llm::exchange::reply::{Piece, Units};
    use busbar_plane_llm::plane_door::breaker_fault;
    use serde_json::json;

    const SSE_HEAD: &[(&[u8], &[u8])] = &[(b"content-type", b"text/event-stream")];
    const EVENTSTREAM: &str = "application/vnd.amazon.eventstream";

    /// The host's entropy, so a dialect that mints an id mints one.
    fn entropy() {
        busbar_contract::codec::install_entropy_source(|out| {
            out.fill(7);
            true
        });
    }

    thread_local! {
        /// The translation cap this test thread runs under; `None` is the host default.
        static CAP: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    }

    fn read_cap() -> usize {
        CAP.with(std::cell::Cell::get)
            .unwrap_or(busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT)
    }

    /// A small translation cap for the test that holds it (its own thread only), the host default
    /// again when it is dropped.
    struct CapGuard;

    impl CapGuard {
        fn install(cap: usize) -> Self {
            busbar_contract::codec::install_translate_cap_reader(read_cap);
            CAP.with(|cell| cell.set(Some(cap)));
            assert_eq!(
                busbar_contract::codec::max_translate_body_bytes(),
                cap,
                "the cap reader this binary installs is the one in force"
            );
            CapGuard
        }
    }

    impl Drop for CapGuard {
        fn drop(&mut self) {
            CAP.with(|cell| cell.set(None));
        }
    }

    /// A chat request in `dialect`'s own shape.
    fn chat_request(dialect: &str, stream: bool) -> Value {
        match dialect {
            "anthropic" => json!({"model": "p", "max_tokens": 64, "stream": stream,
                "messages": [{"role": "user", "content": "hi"}]}),
            "responses" => json!({"model": "p", "stream": stream, "input": "hi"}),
            "gemini" => json!({"model": "p", "stream": stream,
                "contents": [{"role": "user", "parts": [{"text": "hi"}]}]}),
            "bedrock" => json!({"model": "p", "stream": stream,
                "messages": [{"role": "user", "content": [{"text": "hi"}]}]}),
            _ => json!({"model": "p", "stream": stream,
                "messages": [{"role": "user", "content": "hi"}]}),
        }
    }

    /// The caller's arrival of `request` for `operation` in `dialect` (`None`: a body that is not
    /// JSON); `json_array` is a stream asked without the event-stream switch.
    fn arrived_for(
        dialect: &'static str,
        operation: OpVerb,
        request: Option<Value>,
        json_array: bool,
    ) -> Arrived {
        let stream = request
            .as_ref()
            .and_then(|body| body["stream"].as_bool())
            .unwrap_or(false);
        Arrived {
            dialect,
            operation,
            model: "p".to_string(),
            content_type: "application/json".to_string(),
            body: request
                .as_ref()
                .map(|body| serde_json::to_vec(body).expect("JSON"))
                .unwrap_or_default(),
            parsed: request,
            path: String::new(),
            query: None,
            path_model: matches!(dialect, "gemini" | "bedrock").then_some(PathModel {
                stream,
                json_array,
                model_not_found_message: None,
            }),
        }
    }

    /// A `caller` asking a far end of `far` for a chat answer, streamed when `stream`.
    fn ask(caller: &'static str, far: &'static str, stream: bool) -> (Arrived, Lane) {
        (
            arrived_for(
                caller,
                OpVerb::CHAT,
                Some(chat_request(caller, stream)),
                false,
            ),
            lane(far),
        )
    }

    fn reply_ctx<'a>(arrived: &'a Arrived, lane: &'a Lane) -> ReplyCtx<'a> {
        let wants_stream = arrived
            .parsed
            .as_ref()
            .and_then(|request| request["stream"].as_bool())
            .unwrap_or(false);
        ReplyCtx {
            arrived,
            lane,
            intent: StreamIntent {
                wants_stream,
                client_include_usage: false,
            },
            passthrough: false,
        }
    }

    /// A piece the caller read, its bytes its own.
    fn owned(piece: Piece<'_>) -> Piece<'static> {
        Piece {
            head: piece.head,
            bytes: Cow::Owned(piece.bytes.into_owned()),
            units: piece.units,
            verdict: piece.verdict,
            fault: piece.fault,
            done: piece.done,
            dropped: piece.dropped,
        }
    }

    /// What the caller read of one answer.
    struct Read {
        status: u16,
        fields: Vec<(String, Vec<u8>)>,
        body: Vec<u8>,
        pieces: Vec<Piece<'static>>,
    }

    impl Read {
        /// The piece that ended the answer.
        fn end(&self) -> &Piece<'static> {
            self.pieces
                .iter()
                .find(|piece| piece.done)
                .or(self.pieces.last())
                .expect("a piece")
        }

        /// The far end's reported (input, output) tokens the answer settled on.
        fn tokens(&self) -> (u64, u64) {
            (self.end().units.tokens_in, self.end().units.tokens_out)
        }

        /// How many pieces ended the answer: the one settlement.
        fn settlements(&self) -> usize {
            self.pieces.iter().filter(|piece| piece.done).count()
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.body).into_owned()
        }

        fn json(&self) -> Value {
            serde_json::from_slice(&self.body)
                .unwrap_or_else(|err| panic!("a JSON body ({err}): {}", self.text()))
        }

        /// The first head field named `name`, as text.
        fn value(&self, name: &str) -> Option<String> {
            field(&self.fields, name).map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        }
    }

    /// One answer through the served reply: the far end's `status` and `head`, its body in
    /// `pieces`, then a transport cut when `cut`.
    fn answer(
        ctx: &ReplyCtx<'_>,
        status: u16,
        head: &[(&[u8], &[u8])],
        pieces: &[&[u8]],
        cut: bool,
    ) -> Read {
        let mut reply = Reply::new(ctx, status, head);
        let mut out: Vec<Piece<'static>> = Vec::new();
        for (index, bytes) in pieces.iter().enumerate() {
            let last = index + 1 == pieces.len() && !cut;
            out.push(owned(reply.feed(ctx, bytes, last, AT)));
        }
        if pieces.is_empty() {
            out.push(owned(reply.feed(ctx, &[], !cut, AT)));
        }
        if cut {
            out.push(reply.cut(ctx, true));
        }
        let mut read = Read {
            status: 0,
            fields: Vec::new(),
            body: Vec::new(),
            pieces: Vec::new(),
        };
        for piece in &out {
            if let (Some(head), 0) = (&piece.head, read.status) {
                read.status = head.status;
                read.fields = head.fields.clone();
            }
            read.body.extend_from_slice(&piece.bytes);
        }
        read.pieces = out;
        read
    }

    /// `events` framed as a far end's `data:` stream.
    fn data_frames(events: &[&str]) -> Vec<u8> {
        events
            .iter()
            .map(|event| format!("data: {event}\n\n"))
            .collect::<String>()
            .into_bytes()
    }

    // ── a failed generation (failed_generation.rs) ─────────────────────────────────────────────

    /// A cohere whole chat body with `finish_reason`, reporting 10 in / 5 out.
    fn cohere_body(finish_reason: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": "c-1",
            "finish_reason": finish_reason,
            "message": {"role": "assistant", "content": [{"type": "text", "text": "x"}]},
            "usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
        }))
        .expect("JSON")
    }

    /// A gemini event stream: a text chunk, then the terminal chunk with `finish_reason`,
    /// reporting 10 prompt / 5 candidate tokens.
    fn gemini_stream(finish_reason: &str) -> Vec<u8> {
        let first = json!({"candidates": [{"index": 0,
            "content": {"role": "model", "parts": [{"text": "x"}]}}]});
        let last = json!({"candidates": [{"index": 0,
            "content": {"role": "model", "parts": [{"text": ""}]},
            "finishReason": finish_reason}],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5,
                "totalTokenCount": 15}});
        data_frames(&[&first.to_string(), &last.to_string()])
    }

    /// REHOMES `crates/busbar-llm/src/engine/attempt/tests/failed_generation.rs::buffered_cohere_error_is_an_error_a_breaker_fault_and_charges_10_5`
    /// (map row 5). 1.5.5 (item 302, Q31): a whole cohere `finish_reason: "ERROR"` to a chat
    /// caller is a 502 with no `finish_reason` in the body, a transient fault on the far end, an
    /// error end, and the far end's reported 10 in / 5 out (15 tokens) still billed.
    /// RED: a failed generation delivered as a 200 success, no breaker fault, or its usage dropped
    /// (0 billed) or changed.
    #[test]
    fn buffered_cohere_error_is_an_error_a_breaker_fault_and_charges_10_5() {
        let (arrived, lane) = ask("openai", "cohere", false);
        let ctx = reply_ctx(&arrived, &lane);
        let body = cohere_body("ERROR");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 502, "{}", read.text());
        assert!(
            !read.text().contains("\"finish_reason\""),
            "{}",
            read.text()
        );
        assert_eq!(read.end().verdict, Verdict::Hard);
        assert_eq!(
            read.end().fault,
            Some(Fault::Transient("upstream-generation-failed"))
        );
        assert_eq!(breaker_fault(read.end().fault.as_ref()), FAULT_TRANSIENT);
        assert_eq!(read.tokens(), (10, 5));
        assert_eq!(read.tokens().0 + read.tokens().1, 15);
    }

    /// REHOMES `crates/busbar-llm/src/engine/attempt/tests/failed_generation.rs::buffered_cohere_complete_is_a_success_and_charges_10_5`
    /// (map row 6). 1.5.5: the same body ending `COMPLETE` is a 200 success, no fault, 10 / 5
    /// (15 tokens) billed.
    /// RED: a completed generation faulted, or its usage anything but 10 / 5.
    #[test]
    fn buffered_cohere_complete_is_a_success_and_charges_10_5() {
        let (arrived, lane) = ask("openai", "cohere", false);
        let ctx = reply_ctx(&arrived, &lane);
        let body = cohere_body("COMPLETE");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200, "{}", read.text());
        assert_eq!(read.end().verdict, Verdict::Ok);
        assert_eq!(read.end().fault, None);
        assert_eq!(breaker_fault(read.end().fault.as_ref()), FAULT_NONE);
        assert_eq!(read.tokens(), (10, 5));
        assert_eq!(read.tokens().0 + read.tokens().1, 15);
    }

    /// REHOMES `crates/busbar-llm/src/engine/attempt/tests/failed_generation.rs::same_protocol_cohere_error_relays_verbatim_faults_the_breaker_and_charges_10_5`
    /// (map row 7). 1.5.5 (Q31 follow-up): a same-dialect cohere `ERROR` relays the far bytes
    /// unchanged under the far 200, yet ends as an error, faults the far end, and bills 10 / 5.
    /// RED: the relay counted a success (no fault), or its usage not billed.
    #[test]
    fn same_protocol_cohere_error_relays_verbatim_faults_the_breaker_and_charges_10_5() {
        let (arrived, lane) = ask("cohere", "cohere", false);
        let ctx = reply_ctx(&arrived, &lane);
        let body = cohere_body("ERROR");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert_eq!(read.body, body, "the far end's bytes");
        assert_eq!(read.end().verdict, Verdict::Hard);
        assert_eq!(
            read.end().fault,
            Some(Fault::Transient("upstream-generation-failed"))
        );
        assert_eq!(breaker_fault(read.end().fault.as_ref()), FAULT_TRANSIENT);
        assert_eq!(read.tokens(), (10, 5));
    }

    /// REHOMES `crates/busbar-llm/src/engine/attempt/tests/failed_generation.rs::same_protocol_cohere_complete_is_a_success_and_charges_10_5`
    /// (map row 8). 1.5.5: the same-dialect `COMPLETE` relay is a 200 success, no fault, exactly
    /// 10 / 5 (15 tokens) billed.
    /// RED: a same-dialect relay billing presence but not the far figures.
    #[test]
    fn same_protocol_cohere_complete_is_a_success_and_charges_10_5() {
        let (arrived, lane) = ask("cohere", "cohere", false);
        let ctx = reply_ctx(&arrived, &lane);
        let body = cohere_body("COMPLETE");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert_eq!(read.end().verdict, Verdict::Ok);
        assert_eq!(read.end().fault, None);
        assert_eq!(read.tokens(), (10, 5));
        assert_eq!(read.tokens().0 + read.tokens().1, 15);
    }

    /// REHOMES `crates/busbar-llm/src/engine/attempt/tests/failed_generation.rs::streamed_gemini_malformed_function_call_is_an_error_frame_a_breaker_fault_and_charges`
    /// (map row 9). 1.5.5 (item 303, #62): a gemini stream ending `MALFORMED_FUNCTION_CALL`, to a
    /// chat caller, is served 200 on its head, ends in an `"error"` frame, faults the far end, and
    /// bills the 10 / 5 it streamed.
    /// RED: a failed generation ending as a normal `stop`, no fault, or its streamed usage not
    /// billed.
    #[test]
    fn streamed_gemini_malformed_function_call_is_an_error_frame_a_breaker_fault_and_charges() {
        let (arrived, lane) = ask("openai", "gemini", true);
        let ctx = reply_ctx(&arrived, &lane);
        let far = gemini_stream("MALFORMED_FUNCTION_CALL");
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        assert!(read.text().contains("\"error\""), "{}", read.text());
        assert_eq!(read.end().verdict, Verdict::Hard);
        assert_eq!(breaker_fault(read.end().fault.as_ref()), FAULT_TRANSIENT);
        assert_eq!(read.tokens(), (10, 5));
        assert_eq!(read.tokens().0 + read.tokens().1, 15);
    }

    /// REHOMES `crates/busbar-llm/src/engine/attempt/tests/failed_generation.rs::streamed_gemini_stop_is_a_success_and_charges`
    /// (map row 10). 1.5.5: the same stream ending `STOP` is 200 with no `"error"` frame, no
    /// fault, a complete end, and exactly 10 / 5 (15 tokens) billed.
    /// RED: a clean stream framed or faulted as an error, or billed anything but 10 / 5.
    #[test]
    fn streamed_gemini_stop_is_a_success_and_charges() {
        let (arrived, lane) = ask("openai", "gemini", true);
        let ctx = reply_ctx(&arrived, &lane);
        let far = gemini_stream("STOP");
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        assert!(!read.text().contains("\"error\""), "{}", read.text());
        assert_eq!(read.end().verdict, Verdict::Ok);
        assert_eq!(read.end().fault, None);
        assert_eq!(read.tokens(), (10, 5));
        assert_eq!(read.tokens().0 + read.tokens().1, 15);
    }

    // ── a delivered or undelivered whole answer (crossproto_delivery_billing_tests.rs) ─────────

    /// REHOMES `crates/busbar-llm/src/engine/engine_tests/crossproto_delivery_billing_tests.rs::delivered_cross_protocol_response_bills_once`
    /// (map row 13). 1.5.5: a chat-dialect completion (13 + 9) delivered to an anthropic caller is
    /// a 200 that bills exactly 22 tokens once and keeps the request's fee (a success status, no
    /// fault).
    /// RED: a delivered answer billed twice, billed short, or its fee refunded.
    #[test]
    fn delivered_cross_protocol_response_bills_once() {
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane);
        let body = br#"{"id":"x","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":13,"completion_tokens":9}}"#;
        let (head, tail) = body.split_at(body.len() / 2);
        let read = answer(&ctx, 200, JSON_HEAD, &[head, tail], false);
        assert_eq!(read.status, 200);
        assert_eq!(read.end().verdict, Verdict::Ok);
        assert_eq!(read.end().fault, None);
        assert_eq!(read.tokens(), (13, 9));
        assert_eq!(read.tokens().0 + read.tokens().1, 22);
        assert_eq!(read.settlements(), 1, "billed once");
        assert_eq!(
            read.pieces[0].units,
            Units::default(),
            "nothing billed before the whole answer is read"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/engine_tests/crossproto_delivery_billing_tests.rs::ingress_unsupported_404_does_not_charge`
    /// (map row 14). 1.5.5: a chat-dialect embeddings answer (42 prompt tokens) to an anthropic
    /// caller, whose dialect serves no embeddings, is a 404 that bills none of the 42 tokens and
    /// refunds the request's fee (a non-success status with no units).
    /// RED: the 42 far tokens billed for an answer the caller never received.
    #[test]
    fn ingress_unsupported_404_does_not_charge() {
        let body = br#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":42}}"#;
        let request = json!({"model": "p", "input": "hi"});
        let arrived = arrived_for("anthropic", OpVerb::EMBEDDINGS, Some(request), false);
        let lane = lane("openai");
        let ctx = reply_ctx(&arrived, &lane);
        let read = answer(&ctx, 200, JSON_HEAD, &[body], false);
        assert_eq!(read.status, 404, "{}", read.text());
        assert_eq!(read.end().units, Units::default(), "nothing billed");
        assert_eq!(read.end().verdict, Verdict::Hard);
        assert_eq!(read.end().fault, None);
        let mut whole_ctx = super::ctx("anthropic", "openai", false, false);
        whole_ctx.operation = OpVerb::EMBEDDINGS;
        let answered = whole::translate(&whole_ctx, 200, body);
        assert_eq!(answered.end, WholeEnd::IngressUnsupported);
        assert_eq!(answered.usage, None);
    }

    /// REHOMES `crates/busbar-llm/src/engine/engine_tests/crossproto_delivery_billing_tests.rs::untranslatable_500_does_not_charge`
    /// (map row 15). 1.5.5: a chat-dialect SPEECH answer (opaque audio bytes) to an anthropic
    /// caller, whose dialect serves no speech, is the caller's 500 that bills nothing and refunds
    /// the request's fee.
    /// RED: the opaque answer metered (a flat or token charge) though nothing was delivered.
    #[test]
    fn untranslatable_500_does_not_charge() {
        let body: &[u8] = &[
            0x00, 0x01, 0x02, 0xFF, b'n', b'o', b't', b'-', b'j', b's', b'o', b'n',
        ];
        let arrived = arrived_for("anthropic", OpVerb::SPEECH, None, false);
        let lane = lane("openai");
        let ctx = reply_ctx(&arrived, &lane);
        let read = answer(&ctx, 200, JSON_HEAD, &[body], false);
        assert_eq!(read.status, 500, "{}", read.text());
        assert_eq!(read.end().units, Units::default(), "nothing billed");
        assert_eq!(read.end().verdict, Verdict::Hard);
    }

    /// A chat-dialect 2xx whose `choices` is empty: the chat reader refuses it.
    const EMPTY_CHOICES: &[u8] = br#"{"id":"chatcmpl-EMPTY","object":"chat.completion","created":1234567890,"model":"glm-4.5","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#;

    /// REHOMES `crates/busbar-llm/src/engine/tests/forward_once_pool_cell_tests.rs::test_forward_once_untranslatable_2xx_refunds_budget_and_trips_breaker`
    /// (map row 123). 1.5.5: on the last-resort attempt, an untranslatable 2xx (empty `choices`)
    /// to an anthropic caller is the caller's 500, a HARD verdict with a transient fault (the
    /// breaker penalised), and no units (the request's fee refunded, the 7 / 3 not billed).
    /// RED: the untranslatable 2xx recorded as a success, or its usage billed.
    #[test]
    fn test_forward_once_untranslatable_2xx_refunds_budget_and_trips_breaker() {
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane);
        let read = answer(&ctx, 200, JSON_HEAD, &[EMPTY_CHOICES], false);
        assert_eq!(read.status, 500, "{}", read.text());
        assert_eq!(read.end().verdict, Verdict::Hard);
        assert_eq!(
            read.end().fault,
            Some(Fault::Transient("untranslatable-2xx"))
        );
        assert_eq!(breaker_fault(read.end().fault.as_ref()), FAULT_TRANSIENT);
        assert_eq!(read.end().units, Units::default());
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_untranslatable_2xx_refunds_budget_and_trips_breaker`
    /// (map row 334). 1.5.5: on the main path the same untranslatable 2xx records a breaker
    /// transient and returns the request's fee: the whole translate refuses it (no usage), and the
    /// reply is a 500 with a transient fault and no units.
    /// RED: a lane answering undecodable 200s forever never trips, or the 500 bills.
    #[test]
    fn test_untranslatable_2xx_refunds_budget_and_trips_breaker() {
        let answered = whole::translate(
            &super::ctx("anthropic", "openai", false, false),
            200,
            EMPTY_CHOICES,
        );
        assert_eq!(answered.end, WholeEnd::NotTranslatable);
        assert_eq!(answered.usage, None);
        assert_eq!(answered.answer.status, 500);
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane);
        let read = answer(&ctx, 200, JSON_HEAD, &[EMPTY_CHOICES], false);
        assert_eq!(read.status, 500);
        assert_eq!(breaker_fault(read.end().fault.as_ref()), FAULT_TRANSIENT);
        assert_eq!(read.end().units, Units::default());
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_openai_ingress_single_model_anthropic_response_translated`
    /// (map row 196). 1.5.5: an anthropic answer (`hi there`, `end_turn`, 9 in / 3 out) to a chat
    /// caller is 200, `object: "chat.completion"`, `choices[0].message.content: "hi there"`,
    /// `finish_reason: "stop"`, `usage.prompt_tokens: 9`, `usage.completion_tokens: 3`, no
    /// `stop_reason`, and 9 / 3 billed.
    /// RED: the far body relayed raw, or the usage figures moved in translation.
    #[test]
    fn test_openai_ingress_single_model_anthropic_response_translated() {
        let (arrived, lane) = ask("openai", "anthropic", false);
        let ctx = reply_ctx(&arrived, &lane);
        let body = br#"{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"text","text":"hi there"}],"stop_reason":"end_turn","usage":{"input_tokens":9,"output_tokens":3}}"#;
        let read = answer(&ctx, 200, JSON_HEAD, &[body], false);
        assert_eq!(read.status, 200);
        let completion = read.json();
        assert_eq!(completion["object"], "chat.completion", "{completion}");
        assert_eq!(completion["choices"][0]["message"]["content"], "hi there");
        assert_eq!(completion["choices"][0]["finish_reason"], "stop");
        assert_eq!(completion["usage"]["prompt_tokens"], 9);
        assert_eq!(completion["usage"]["completion_tokens"], 3);
        assert!(completion.get("stop_reason").is_none(), "{completion}");
        assert_eq!(read.tokens(), (9, 3));
    }

    // ── a same-dialect whole body's usage (ingress_indistinguishability_tests.rs) ──────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_same_protocol_nonstream_multichunk_counts_usage`
    /// (map row 335). 1.5.5: a same-dialect whole body split before its trailing `usage` (600 in +
    /// 400 out) reaches the caller byte-identical and bills exactly 1000 tokens.
    /// RED: a per-piece usage read that keeps no state across pieces bills 0.
    #[test]
    fn test_same_protocol_nonstream_multichunk_counts_usage() {
        let (arrived, lane) = ask("openai", "openai", false);
        let ctx = reply_ctx(&arrived, &lane);
        let body = r#"{"id":"chatcmpl-split","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":600,"completion_tokens":400}}"#;
        let split = body.find(r#""usage""#).expect("a usage member");
        let read = answer(
            &ctx,
            200,
            JSON_HEAD,
            &[&body.as_bytes()[..split], &body.as_bytes()[split..]],
            false,
        );
        assert_eq!(read.body, body.as_bytes(), "byte-identical");
        assert_eq!(read.end().verdict, Verdict::Ok);
        assert_eq!(read.tokens(), (600, 400));
        assert_eq!(read.tokens().0 + read.tokens().1, 1000);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_same_protocol_nonstream_over_cap_body_still_bills_tail_usage`
    /// (map row 336). 1.5.5: under a 4096-byte cap, a same-dialect body three caps long whose
    /// `usage` (600 + 400) trails it reaches the caller whole and still bills 1000 tokens: the
    /// billing copy keeps the tail, not the head.
    /// RED: a head-truncated billing copy never reaches the trailing usage and bills 0.
    #[test]
    fn test_same_protocol_nonstream_over_cap_body_still_bills_tail_usage() {
        const CAP: usize = 4096;
        let _cap = CapGuard::install(CAP);
        let (arrived, lane) = ask("openai", "openai", false);
        let ctx = reply_ctx(&arrived, &lane);
        let filler = "x".repeat(CAP * 3);
        let body = format!(
            r#"{{"id":"chatcmpl-huge","object":"chat.completion","choices":[{{"index":0,"message":{{"role":"assistant","content":"{filler}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":600,"completion_tokens":400}}}}"#
        );
        assert!(body.len() > CAP * 2);
        let pieces: Vec<&[u8]> = body.as_bytes().chunks(512).collect();
        let read = answer(&ctx, 200, JSON_HEAD, &pieces, false);
        assert_eq!(read.body, body.as_bytes(), "the whole body, verbatim");
        assert_eq!(read.tokens(), (600, 400));
        assert_eq!(read.tokens().0 + read.tokens().1, 1000);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_truncated_beyond_recovery_bills_nonzero_floor_not_zero`
    /// (map row 337). 1.5.5 (C2): under a 4096-byte cap, a same-dialect body whose `usage` sits at
    /// its front, pushed out of the kept tail by the filler, bills the floor over the 4096 kept
    /// bytes: 4096 / 4 = 1024 output tokens, never 0.
    /// RED: an unrecoverable usage billed as zero tokens (only the flat fee lands).
    #[test]
    fn test_truncated_beyond_recovery_bills_nonzero_floor_not_zero() {
        const CAP: usize = 4096;
        let _cap = CapGuard::install(CAP);
        let (arrived, lane) = ask("openai", "openai", false);
        let ctx = reply_ctx(&arrived, &lane);
        let filler = "x".repeat(CAP * 3);
        let body = format!(
            r#"{{"id":"chatcmpl-huge","object":"chat.completion","usage":{{"prompt_tokens":600,"completion_tokens":400}},"choices":[{{"index":0,"message":{{"role":"assistant","content":"{filler}"}},"finish_reason":"stop"}}]}}"#
        );
        let pieces: Vec<&[u8]> = body.as_bytes().chunks(512).collect();
        let read = answer(&ctx, 200, JSON_HEAD, &pieces, false);
        assert_eq!(read.body, body.as_bytes(), "the whole body, verbatim");
        let floor = CAP as u64 / TRUNCATED_TAIL_BYTES_PER_TOKEN;
        assert_eq!(floor, 1024);
        assert_eq!(read.tokens(), (0, floor));
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_cross_protocol_stream_delivers_trailing_usage_gemini_json_array`
    /// (map row 339). 1.5.5: a chat-dialect stream whose usage (600 / 400) arrives in its own
    /// trailing chunk, to a gemini JSON-array caller, is one JSON array whose terminal
    /// `usageMetadata.promptTokenCount` is 600, and 600 / 400 bill.
    /// RED: the trailing usage chunk dropped by the array close (0 or absent), or not billed.
    #[test]
    fn test_cross_protocol_stream_delivers_trailing_usage_gemini_json_array() {
        let arrived = arrived_for(
            "gemini",
            OpVerb::CHAT,
            Some(chat_request("gemini", true)),
            true,
        );
        let lane = lane("openai");
        let ctx = reply_ctx(&arrived, &lane);
        let far = [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":null}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n",
            "data: [DONE]\n\n",
        ];
        let pieces: Vec<&[u8]> = far.iter().map(|frame| frame.as_bytes()).collect();
        let read = answer(&ctx, 200, SSE_HEAD, &pieces, false);
        let array = read.json();
        let prompt = array.as_array().and_then(|elements| {
            elements
                .iter()
                .find_map(|element| element["usageMetadata"]["promptTokenCount"].as_i64())
        });
        assert_eq!(prompt, Some(600), "{array}");
        assert_eq!(read.tokens(), (600, 400));
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_mid_stream_transport_error_does_not_bill_partial_usage`
    /// (map row 341). 1.5.5 (#62): an anthropic stream to a chat caller, cut after it reported 100
    /// input (`message_start`) and 50 output (`message_delta`), bills exactly those 150 tokens.
    /// RED: a cut stream refunded to 0 tokens, or billed more than streamed.
    #[test]
    fn test_mid_stream_transport_error_does_not_bill_partial_usage() {
        let (arrived, lane) = ask("openai", "anthropic", true);
        let ctx = reply_ctx(&arrived, &lane);
        let far = [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"usage\":{\"input_tokens\":100,\"output_tokens\":0}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":50}}\n\n",
        ];
        let pieces: Vec<&[u8]> = far.iter().map(|frame| frame.as_bytes()).collect();
        let read = answer(&ctx, 200, SSE_HEAD, &pieces, true);
        let cut = read.pieces.last().expect("the cut");
        assert!(
            cut.done && !cut.bytes.is_empty(),
            "the caller's error frame"
        );
        assert_eq!(cut.verdict, Verdict::Hard);
        assert_eq!(cut.fault, Some(Fault::Transient("mid-stream")));
        assert_eq!((cut.units.tokens_in, cut.units.tokens_out), (100, 50));
        assert_eq!(cut.units.tokens_in + cut.units.tokens_out, 150);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_cross_protocol_bedrock_to_gemini_carries_total_tokens_and_response_id`
    /// (map row 343). 1.5.5: a Converse answer (no body identity; 7 in / 3 out) to a gemini
    /// caller is 200 `application/json` with `usageMetadata` 7 / 3 / total 10, a minted
    /// `responseId`, no foreign id, and 7 / 3 billed.
    /// RED: an identity-empty far answer read as same-dialect, dropping `totalTokenCount` and
    /// `responseId`.
    #[test]
    fn test_cross_protocol_bedrock_to_gemini_carries_total_tokens_and_response_id() {
        entropy();
        let (arrived, lane) = ask("gemini", "bedrock", false);
        let ctx = reply_ctx(&arrived, &lane);
        let body = br#"{"output":{"message":{"role":"assistant","content":[{"text":"Hi"}]}},"stopReason":"end_turn","usage":{"inputTokens":7,"outputTokens":3}}"#;
        let read = answer(&ctx, 200, JSON_HEAD, &[body], false);
        assert_eq!(read.status, 200);
        assert_eq!(
            read.value("content-type").as_deref(),
            Some("application/json")
        );
        let answer_body = read.json();
        assert_eq!(
            answer_body["usageMetadata"]["totalTokenCount"],
            json!(10u64)
        );
        assert_eq!(
            answer_body["usageMetadata"]["promptTokenCount"],
            json!(7u64)
        );
        assert_eq!(
            answer_body["usageMetadata"]["candidatesTokenCount"],
            json!(3u64)
        );
        assert!(
            !answer_body["responseId"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "{answer_body}"
        );
        let text = read.text();
        assert!(
            !text.contains("chatcmpl-") && !text.contains("msg_"),
            "{text}"
        );
        assert_eq!(read.tokens(), (7, 3));
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_cross_protocol_nonstream_over_cap_body_returns_500_uncharged`
    /// (map row 359). 1.5.5: under a 4096-byte cap, a chat-dialect body over the cap (5 / 999999
    /// reported) to an anthropic caller is the caller's 500 at once, no units billed, and no fault
    /// on the far end (the cap is ours).
    /// RED: an over-cap answer translated and delivered (its 999999 tokens billed), or the far end
    /// faulted for our limit.
    #[test]
    fn test_cross_protocol_nonstream_over_cap_body_returns_500_uncharged() {
        const CAP: usize = 4096;
        let _cap = CapGuard::install(CAP);
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane);
        let huge = "x".repeat(CAP + 1024);
        let body = serde_json::to_vec(&json!({
            "id": "chatcmpl-huge", "object": "chat.completion", "created": 1_234_567_890,
            "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": huge},
                "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 999_999}
        }))
        .expect("JSON");
        let pieces: Vec<&[u8]> = body.chunks(512).collect();
        let read = answer(&ctx, 200, JSON_HEAD, &pieces, false);
        assert_eq!(read.status, 500, "{}", read.text());
        assert_eq!(read.settlements(), 1);
        let end = read.end();
        assert_eq!(end.verdict, Verdict::Hard);
        assert_eq!(end.fault, None, "our cap, not the far end's fault");
        assert_eq!(end.units, Units::default(), "nothing billed");
        assert!(
            read.pieces
                .iter()
                .all(|piece| piece.units == Units::default()),
            "no piece bills"
        );
    }

    // ── a stream that ends early (ingress_indistinguishability_tests.rs) ──────────────────────

    /// A chat-dialect trailing usage chunk: 600 prompt / 400 completion.
    const USAGE_CHUNK: &[u8] =
        b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":600,\"completion_tokens\":400}}\n\n";

    /// More bytes than one event-stream frame may hold, with no frame end: the reframing gives up.
    fn overflow() -> Vec<u8> {
        vec![b'x'; busbar_plane_llm::codec::eventstream::MAX_FRAME_BYTES + 16]
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_streaming_translate_abort_trips_breaker_and_skips_billing`
    /// (map row 367). 1.5.5 (#62): a translated stream whose reframing gives up after its first
    /// byte records a transient fault on the far end (the optimistic success reversed) and still
    /// bills the 600 / 400 (1000 tokens) read before it.
    /// RED: an abort that records no fault, or one that refunds what streamed.
    #[test]
    fn test_streaming_translate_abort_trips_breaker_and_skips_billing() {
        let (arrived, lane) = ask("anthropic", "openai", true);
        let ctx = reply_ctx(&arrived, &lane);
        let overflow = overflow();
        let read = answer(&ctx, 200, SSE_HEAD, &[USAGE_CHUNK, &overflow], false);
        let end = read.end();
        assert!(end.done);
        assert_eq!(end.verdict, Verdict::Hard);
        assert_eq!(end.fault, Some(Fault::Transient("stream-translate-abort")));
        assert_eq!(breaker_fault(end.fault.as_ref()), FAULT_TRANSIENT);
        assert_eq!(read.tokens(), (600, 400));
        assert_eq!(read.tokens().0 + read.tokens().1, 1000);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_cancel_drop_bills_partial_tokens`
    /// (map row 368). 1.5.5: a caller that leaves mid-stream, after the usage chunk was read, bills
    /// the 600 / 400 (1000 tokens) captured so far: the piece it last read states them, and the
    /// answer is a usable partial.
    /// RED: a cancel that bills 0 because the stream never reached its end.
    #[test]
    fn test_cancel_drop_bills_partial_tokens() {
        let (arrived, lane) = ask("anthropic", "openai", true);
        let ctx = reply_ctx(&arrived, &lane);
        let mut reply = Reply::new(&ctx, 200, SSE_HEAD);
        let piece = reply.feed(&ctx, USAGE_CHUNK, false, AT);
        assert!(!piece.done);
        assert_eq!((piece.units.tokens_in, piece.units.tokens_out), (600, 400));
        assert_eq!(piece.units.tokens_in + piece.units.tokens_out, 1000);
        assert!(reply.partial(), "the caller had a usable part");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_cancel_drop_bills_streamed_tokens_on_aborted_translate`
    /// (map row 369). 1.5.5 (#62): a caller that leaves after the reframing gave up still bills the
    /// 600 / 400 (1000 tokens) streamed before the abort.
    /// RED: an aborted translate's captured usage dropped on the cancel.
    #[test]
    fn test_cancel_drop_bills_streamed_tokens_on_aborted_translate() {
        let (arrived, lane) = ask("anthropic", "openai", true);
        let ctx = reply_ctx(&arrived, &lane);
        let mut reply = Reply::new(&ctx, 200, SSE_HEAD);
        let first = reply.feed(&ctx, USAGE_CHUNK, false, AT);
        assert_eq!((first.units.tokens_in, first.units.tokens_out), (600, 400));
        let overflow = overflow();
        let after = reply.feed(&ctx, &overflow, false, AT);
        assert!(!after.done);
        assert_eq!((after.units.tokens_in, after.units.tokens_out), (600, 400));
        assert_eq!(after.units.tokens_in + after.units.tokens_out, 1000);
    }

    // ── a cut stream, every caller (plane_reply_parity_tests.rs) ─────────────────────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/plane_reply_parity_tests.rs::a_cut_stream_reads_the_same_through_the_plane`
    /// (map row 563). 1.5.5, for far ends of the chat, anthropic and bedrock dialects x all six
    /// callers, a stream cut halfway: the head is 200 under the caller's stream content type, the
    /// cut is HARD with the transient `mid-stream` fault, its bytes are exactly one error frame in
    /// the caller's own framing (bedrock: one binary `InternalServerException` frame, byte-equal to
    /// the dialect's; chat and gemini: a bare `data:` `error` frame; cohere: a `message-end`
    /// `ERROR`; anthropic: `event: error`; responses: `event: response.failed`), and the units it
    /// settles are exactly the units the stream had reported before the cut (the chat stream's
    /// usage rides its last chunk, so 0 / 0 there).
    /// RED: a cut ending in another dialect's frame, no frame, or settling units other than what
    /// streamed (a refund to zero, or a guess).
    #[test]
    fn a_cut_stream_reads_the_same_through_the_plane() {
        use busbar_plane_llm::exchange::reply::wire;
        let mut checked = 0;
        for far in ["openai", "anthropic", "bedrock"] {
            let bytes = native_stream(far);
            let far_type = wire::ingress_stream_content_type(far).expect("a stream type");
            let head: &[(&[u8], &[u8])] = &[(b"content-type", far_type.as_bytes())];
            let mut pieces: Vec<&[u8]> = bytes.chunks(64).collect();
            pieces.truncate(pieces.len() / 2);
            for caller in SIX {
                let what = format!("{caller}<-{far}");
                let (arrived, lane) = ask(caller, far, true);
                let ctx = reply_ctx(&arrived, &lane);
                let read = answer(&ctx, 200, head, &pieces, true);
                assert_eq!(read.status, 200, "{what}");
                let caller_type = wire::ingress_stream_content_type(caller).expect("a type");
                assert_eq!(
                    read.value("content-type").as_deref(),
                    Some(caller_type),
                    "{what}"
                );
                let cut = read.pieces.last().expect("the cut");
                assert!(cut.done, "{what}");
                assert_eq!(cut.verdict, Verdict::Hard, "{what}");
                assert_eq!(cut.fault, Some(Fault::Transient("mid-stream")), "{what}");
                let before = &read.pieces[read.pieces.len() - 2].units;
                assert_eq!(
                    (cut.units.tokens_in, cut.units.tokens_out),
                    (before.tokens_in, before.tokens_out),
                    "{what}: the cut settles what streamed"
                );
                if far == "openai" {
                    assert_eq!(
                        (cut.units.tokens_in, cut.units.tokens_out),
                        (0, 0),
                        "{what}"
                    );
                }
                let frame: &[u8] = &cut.bytes;
                let text = String::from_utf8_lossy(frame);
                match caller {
                    "bedrock" => {
                        assert_eq!(
                            frame,
                            wire::mid_stream_error_bytes(
                                "bedrock",
                                true,
                                wire::MID_STREAM_GENERIC_DETAIL,
                                None
                            )
                            .as_slice(),
                            "{what}"
                        );
                        let mut buf = frame.to_vec();
                        let frames = busbar_plane_llm::codec::eventstream::drain_frames_checked(
                            &mut buf, None,
                        )
                        .0;
                        assert_eq!((frames.len(), buf.len()), (1, 0), "{what}");
                        assert!(text.contains("InternalServerException"), "{what}");
                    }
                    "anthropic" => {
                        assert!(text.starts_with("event: error\n"), "{what}: {text}");
                        assert_eq!(text.matches("\n\n").count(), 1, "{what}: {text}");
                    }
                    "responses" => {
                        assert!(
                            text.starts_with("event: response.failed\n"),
                            "{what}: {text}"
                        );
                        assert_eq!(text.matches("\n\n").count(), 1, "{what}: {text}");
                    }
                    _ => {
                        assert!(
                            text.starts_with("data: ") && text.ends_with("\n\n"),
                            "{what}: {text}"
                        );
                        assert!(!text.contains("event:"), "{what}: {text}");
                        assert_eq!(text.matches("\n\n").count(), 1, "{what}: {text}");
                        let data: Value = serde_json::from_str(
                            text.trim_start_matches("data: ").trim_end_matches("\n\n"),
                        )
                        .expect("JSON");
                        if caller == "cohere" {
                            assert_eq!(data["type"], "message-end", "{what}: {data}");
                            assert!(
                                data["delta"]["finish_reason"]
                                    .as_str()
                                    .is_some_and(|reason| reason.starts_with("ERROR")),
                                "{what}: {data}"
                            );
                        } else {
                            assert!(data.get("error").is_some(), "{what}: {data}");
                        }
                    }
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 3 * 6);
    }

    // ── a responses caller that asked to stream (responses_ingress_stream_tests.rs) ───────────

    const MARKER: &str = "hi";
    const IN_TOK: u64 = 11;
    const OUT_TOK: u64 = 7;

    /// Event-stream frames: each `(event, data)`, the event line left out when empty.
    fn sse(frames: &[(&str, Value)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (event, data) in frames {
            busbar_plane_llm::codec::dialect::write_sse_frame(&mut out, event, data);
        }
        out
    }

    /// The far end's answer, in `far`'s dialect, to a stream request: its content type and bytes,
    /// a native stream when `stream`, else one whole body. One text block of `MARKER`, 11 in / 7
    /// out (the legacy fixtures, byte for byte).
    fn upstream_answer(far: &str, stream: bool) -> (&'static str, Vec<u8>) {
        let usage_chat = json!({"prompt_tokens": IN_TOK, "completion_tokens": OUT_TOK,
            "total_tokens": IN_TOK + OUT_TOK});
        match (far, stream) {
            ("anthropic", true) => (
                "text/event-stream",
                sse(&[
                    (
                        "message_start",
                        json!({"type": "message_start", "message": {"id": "msg_up",
                        "type": "message", "role": "assistant", "model": "m0", "content": [],
                        "stop_reason": null, "usage": {"input_tokens": IN_TOK, "output_tokens": 0}}}),
                    ),
                    (
                        "content_block_start",
                        json!({"type": "content_block_start", "index": 0,
                        "content_block": {"type": "text", "text": ""}}),
                    ),
                    (
                        "content_block_delta",
                        json!({"type": "content_block_delta", "index": 0,
                        "delta": {"type": "text_delta", "text": MARKER}}),
                    ),
                    (
                        "content_block_stop",
                        json!({"type": "content_block_stop", "index": 0}),
                    ),
                    (
                        "message_delta",
                        json!({"type": "message_delta",
                        "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                        "usage": {"output_tokens": OUT_TOK}}),
                    ),
                    ("message_stop", json!({"type": "message_stop"})),
                ]),
            ),
            ("anthropic", false) => (
                "application/json",
                json!({"id": "msg_up", "type": "message", "role": "assistant", "model": "m0",
                    "content": [{"type": "text", "text": MARKER}], "stop_reason": "end_turn",
                    "stop_sequence": null,
                    "usage": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}})
                .to_string()
                .into_bytes(),
            ),
            ("openai", true) => {
                let base = json!({"id": "chatcmpl-up", "object": "chat.completion.chunk",
                    "created": 0, "model": "m0"});
                let mut first = base.clone();
                first["choices"] = json!([{"index": 0,
                    "delta": {"role": "assistant", "content": MARKER}, "finish_reason": null}]);
                let mut last = base;
                last["choices"] = json!([{"index": 0, "delta": {}, "finish_reason": "stop"}]);
                last["usage"] = usage_chat;
                let mut body = sse(&[("", first), ("", last)]);
                body.extend_from_slice(busbar_plane_llm::codec::dialect::SSE_DONE_FRAME);
                ("text/event-stream", body)
            }
            ("openai", false) => (
                "application/json",
                json!({"id": "chatcmpl-up", "object": "chat.completion", "created": 0,
                    "model": "m0",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": MARKER},
                        "finish_reason": "stop"}],
                    "usage": usage_chat})
                .to_string()
                .into_bytes(),
            ),
            ("cohere", true) => {
                let mut body = sse(&[
                    (
                        "",
                        json!({"type": "message-start", "id": "cohere-up",
                        "delta": {"message": {"role": "assistant", "content": []}}}),
                    ),
                    (
                        "",
                        json!({"type": "content-delta", "index": 0,
                        "delta": {"message": {"content": {"type": "text", "text": MARKER}}}}),
                    ),
                    (
                        "",
                        json!({"type": "message-end", "delta": {"finish_reason": "COMPLETE",
                        "usage": {"tokens": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}}}}),
                    ),
                ]);
                body.extend_from_slice(busbar_plane_llm::codec::dialect::SSE_DONE_FRAME);
                ("text/event-stream", body)
            }
            ("cohere", false) => (
                "application/json",
                json!({"id": "cohere-up", "finish_reason": "COMPLETE",
                    "message": {"role": "assistant", "content": [{"type": "text", "text": MARKER}]},
                    "usage": {"billed_units": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK},
                        "tokens": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK}}})
                .to_string()
                .into_bytes(),
            ),
            ("gemini", stream) => {
                let body = json!({"candidates": [{"content": {"role": "model",
                    "parts": [{"text": MARKER}]}, "finishReason": "STOP", "index": 0}],
                    "usageMetadata": {"promptTokenCount": IN_TOK, "candidatesTokenCount": OUT_TOK,
                        "totalTokenCount": IN_TOK + OUT_TOK},
                    "modelVersion": "m0"});
                if stream {
                    ("text/event-stream", sse(&[("", body)]))
                } else {
                    ("application/json", body.to_string().into_bytes())
                }
            }
            ("bedrock", true) => {
                let frames: [(&str, Value); 5] = [
                    ("messageStart", json!({"role": "assistant"})),
                    (
                        "contentBlockDelta",
                        json!({"delta": {"text": MARKER}, "contentBlockIndex": 0}),
                    ),
                    ("contentBlockStop", json!({"contentBlockIndex": 0})),
                    ("messageStop", json!({"stopReason": "end_turn"})),
                    (
                        "metadata",
                        json!({"usage": {"inputTokens": IN_TOK, "outputTokens": OUT_TOK,
                        "totalTokens": IN_TOK + OUT_TOK}, "metrics": {"latencyMs": 12}}),
                    ),
                ];
                let mut body = Vec::new();
                for (event, payload) in frames {
                    body.extend(busbar_plane_llm::codec::eventstream::encode_frame(
                        event,
                        &busbar_plane_llm::codec::json::to_vec(&payload).expect("frame JSON"),
                    ));
                }
                (EVENTSTREAM, body)
            }
            ("bedrock", false) => (
                "application/json",
                json!({"output": {"message": {"role": "assistant", "content": [{"text": MARKER}]}},
                    "stopReason": "end_turn",
                    "usage": {"inputTokens": IN_TOK, "outputTokens": OUT_TOK,
                        "totalTokens": IN_TOK + OUT_TOK},
                    "metrics": {"latencyMs": 12}})
                .to_string()
                .into_bytes(),
            ),
            ("responses", true) => {
                let item_done = json!({"type": "message", "id": "msg_up", "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": MARKER, "annotations": []}]});
                let usage = json!({"input_tokens": IN_TOK,
                    "input_tokens_details": {"cached_tokens": 0}, "output_tokens": OUT_TOK,
                    "output_tokens_details": {"reasoning_tokens": 0},
                    "total_tokens": IN_TOK + OUT_TOK});
                (
                    "text/event-stream",
                    sse(&[
                        (
                            "response.created",
                            json!({"type": "response.created",
                            "sequence_number": 0, "response": {"id": "resp_up", "object": "response",
                            "created_at": 0, "model": "m0", "status": "in_progress", "error": null,
                            "output": [], "usage": null}}),
                        ),
                        (
                            "response.output_item.added",
                            json!({"type": "response.output_item.added",
                            "sequence_number": 1, "output_index": 0, "item": {"type": "message",
                            "id": "msg_up", "role": "assistant", "status": "in_progress",
                            "content": []}}),
                        ),
                        (
                            "response.output_text.delta",
                            json!({"type": "response.output_text.delta",
                            "sequence_number": 2, "output_index": 0, "content_index": 0,
                            "item_id": "msg_up", "delta": MARKER}),
                        ),
                        (
                            "response.output_item.done",
                            json!({"type": "response.output_item.done",
                            "sequence_number": 3, "output_index": 0, "item": item_done}),
                        ),
                        (
                            "response.completed",
                            json!({"type": "response.completed",
                            "sequence_number": 4, "response": {"id": "resp_up", "object": "response",
                            "created_at": 0, "model": "m0", "status": "completed", "error": null,
                            "output": [item_done], "usage": usage}}),
                        ),
                    ]),
                )
            }
            ("responses", false) => (
                "application/json",
                json!({"id": "resp_up", "object": "response", "status": "completed", "model": "m0",
                    "output": [{"type": "message", "id": "msg_up", "role": "assistant",
                        "status": "completed",
                        "content": [{"type": "output_text", "text": MARKER, "annotations": []}]}],
                    "usage": {"input_tokens": IN_TOK, "output_tokens": OUT_TOK,
                        "total_tokens": IN_TOK + OUT_TOK}})
                .to_string()
                .into_bytes(),
            ),
            (other, _) => panic!("no far-end fixture for {other}"),
        }
    }

    /// One `stream: true` responses request answered by a far end of `far` (a native stream when
    /// `stream`, else one whole body): the caller reads a responses event stream (or, within one
    /// dialect, the far end's whole body unchanged), and the answer bills exactly 11 / 7 once.
    fn responses_case(far: &'static str, stream: bool) {
        entropy();
        let label = format!("responses<-{far} (stream: {stream})");
        let (content_type, body) = upstream_answer(far, stream);
        let (arrived, lane) = ask("responses", far, true);
        let ctx = reply_ctx(&arrived, &lane);
        let head: &[(&[u8], &[u8])] = &[(b"content-type", content_type.as_bytes())];
        let pieces: Vec<&[u8]> = body.chunks(97).collect();
        let read = answer(&ctx, 200, head, &pieces, false);
        assert_eq!(read.status, 200, "{label}");
        let read_type = read.value("content-type").unwrap_or_default();
        if far == "responses" && !stream {
            assert_eq!(read_type, content_type, "{label}");
            assert_eq!(read.body, body, "{label}: the far end's bytes");
        } else {
            assert!(
                read_type.starts_with("text/event-stream"),
                "{label}: {read_type}"
            );
            let text = read.text();
            assert!(!text.contains("[DONE]"), "{label}: {text}");
            let mut frames: Vec<(String, String)> = Vec::new();
            for frame in text.split("\n\n").filter(|frame| !frame.trim().is_empty()) {
                let mut event = String::new();
                let mut data: Vec<&str> = Vec::new();
                for line in frame.lines() {
                    if let Some(rest) = line.strip_prefix("event:") {
                        event = rest.trim().to_string();
                    } else if let Some(rest) = line.strip_prefix("data:") {
                        data.push(rest.strip_prefix(' ').unwrap_or(rest));
                    }
                }
                frames.push((event, data.join("\n")));
            }
            assert!(!frames.is_empty(), "{label}");
            assert_eq!(frames[0].0, "response.created", "{label}: {text}");
            let (last_event, last_data) = frames.last().expect("a terminal frame");
            assert_eq!(last_event, "response.completed", "{label}: {text}");
            let completed: Value = serde_json::from_str(last_data).expect("JSON");
            assert_eq!(completed["type"], "response.completed", "{label}");
            assert!(
                completed["sequence_number"].is_u64(),
                "{label}: {last_data}"
            );
            let response = &completed["response"];
            assert_eq!(response["object"], "response", "{label}");
            assert_eq!(response["status"], "completed", "{label}");
            assert!(
                response["id"]
                    .as_str()
                    .is_some_and(|id| id.starts_with("resp_")),
                "{label}: {last_data}"
            );
            assert_eq!(
                response["output"][0]["content"][0]["text"], MARKER,
                "{label}: {last_data}"
            );
            assert_eq!(response["usage"]["input_tokens"], IN_TOK, "{label}");
            assert_eq!(response["usage"]["output_tokens"], OUT_TOK, "{label}");
            assert_eq!(
                response["usage"]["total_tokens"],
                IN_TOK + OUT_TOK,
                "{label}"
            );
            for (event, data) in &frames {
                let payload: Value = serde_json::from_str(data).expect("JSON");
                assert_eq!(payload["type"], event.as_str(), "{label}");
            }
        }
        assert_eq!(read.tokens(), (IN_TOK, OUT_TOK), "{label}");
        assert_eq!(read.settlements(), 1, "{label}: billed once");
        assert!(
            read.pieces
                .iter()
                .all(|piece| piece.units.tokens_in <= IN_TOK && piece.units.tokens_out <= OUT_TOK),
            "{label}: never more than the far end reported"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_anthropic_stream`
    /// (map row 588). 1.5.5: a responses stream over an anthropic stream opens `response.created`,
    /// has no `[DONE]`, ends `response.completed` (a u64 `sequence_number`, `object: "response"`,
    /// `status: "completed"`, a `resp_` id, the text, usage 11 / 7 / 18), and bills 11 / 7 once.
    /// RED: the event sequence broken, the usage figures moved, or the answer billed twice or not
    /// at all.
    #[test]
    fn responses_stream_over_anthropic_stream() {
        responses_case("anthropic", true);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_anthropic_buffered`
    /// (map row 589). 1.5.5: a responses caller that asked to stream, answered one anthropic body,
    /// reads the same responses event stream and bills 11 / 7 once.
    /// RED: the buffered answer delivered as JSON to a stream caller, or not billed.
    #[test]
    fn responses_stream_over_anthropic_buffered() {
        responses_case("anthropic", false);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_openai_stream`
    /// (map row 590). 1.5.5: as row 588 over a chat-dialect stream; 11 / 7 billed once.
    /// RED: the event sequence broken, the usage figures moved, or the answer billed twice.
    #[test]
    fn responses_stream_over_openai_stream() {
        responses_case("openai", true);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_openai_buffered`
    /// (map row 591). 1.5.5: as row 589 over one chat-dialect body; 11 / 7 billed once.
    /// RED: the buffered answer delivered as JSON to a stream caller, or not billed.
    #[test]
    fn responses_stream_over_openai_buffered() {
        responses_case("openai", false);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_cohere_stream`
    /// (map row 592). 1.5.5: as row 588 over a cohere stream; 11 / 7 billed once.
    /// RED: the event sequence broken, the usage figures moved, or the answer billed twice.
    #[test]
    fn responses_stream_over_cohere_stream() {
        responses_case("cohere", true);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_cohere_buffered`
    /// (map row 593). 1.5.5: as row 589 over one cohere body; 11 / 7 billed once.
    /// RED: the buffered answer delivered as JSON to a stream caller, or not billed.
    #[test]
    fn responses_stream_over_cohere_buffered() {
        responses_case("cohere", false);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_gemini_stream`
    /// (map row 594). 1.5.5: as row 588 over a gemini stream; 11 / 7 billed once.
    /// RED: the event sequence broken, the usage figures moved, or the answer billed twice.
    #[test]
    fn responses_stream_over_gemini_stream() {
        responses_case("gemini", true);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_gemini_buffered`
    /// (map row 595). 1.5.5: as row 589 over one gemini body; 11 / 7 billed once.
    /// RED: the buffered answer delivered as JSON to a stream caller, or not billed.
    #[test]
    fn responses_stream_over_gemini_buffered() {
        responses_case("gemini", false);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_bedrock_stream`
    /// (map row 596). 1.5.5: as row 588 over a bedrock binary event stream; 11 / 7 billed once.
    /// RED: the event sequence broken, the usage figures moved, or the answer billed twice.
    #[test]
    fn responses_stream_over_bedrock_stream() {
        responses_case("bedrock", true);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_bedrock_buffered`
    /// (map row 597). 1.5.5: as row 589 over one Converse body; 11 / 7 billed once.
    /// RED: the buffered answer delivered as JSON to a stream caller, or not billed.
    #[test]
    fn responses_stream_over_bedrock_buffered() {
        responses_case("bedrock", false);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_responses_stream`
    /// (map row 598). 1.5.5: as row 588 over a responses stream (relayed within one dialect);
    /// 11 / 7 billed once.
    /// RED: the same-dialect stream rewritten, or its usage billed twice or not at all.
    #[test]
    fn responses_stream_over_responses_stream() {
        responses_case("responses", true);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/responses_ingress_stream_tests.rs::responses_stream_over_responses_buffered`
    /// (map row 599). 1.5.5 (DIALECT FIDELITY): a responses far end that answered one body to a
    /// stream request is relayed under its own content type, bytes unchanged, and bills 11 / 7
    /// once.
    /// RED: the same-dialect body reframed as a stream, or its usage not billed.
    #[test]
    fn responses_stream_over_responses_buffered() {
        responses_case("responses", false);
    }

    // ── an unreadable usage after delivery (unreadable_usage_floor_tests.rs) ──────────────────

    /// The floor the far end's `delivered` bytes bill when no usage can be read: a quarter of
    /// them, as output, never 0.
    fn floor_for(delivered: usize) -> u64 {
        (delivered as u64 / TRUNCATED_TAIL_BYTES_PER_TOKEN).max(1)
    }

    fn message_with_usage(usage: &str) -> String {
        format!(
            r#"{{"id":"msg_1","type":"message","role":"assistant","model":"claude-x","content":[{{"type":"text","text":"hi"}}],"stop_reason":"end_turn","stop_sequence":null,"usage":{usage}}}"#
        )
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/unreadable_usage_floor_tests.rs::buffered_relay_refused_usage_bills_the_floor_not_zero`
    /// (map row 620). 1.5.5 (item 133): a same-dialect anthropic body relays verbatim; a readable
    /// usage bills exactly 1500 + 9 = 1509; a count the reader refuses (`"1500"`) bills the floor
    /// over the delivered bytes (their length / 4, as output), never 0.
    /// RED: a refused usage on a delivered body billed as zero tokens.
    #[test]
    fn buffered_relay_refused_usage_bills_the_floor_not_zero() {
        let (arrived, lane) = ask("anthropic", "anthropic", false);
        let ctx = reply_ctx(&arrived, &lane);
        let readable = message_with_usage(r#"{"input_tokens":1500,"output_tokens":9}"#);
        let read = answer(&ctx, 200, JSON_HEAD, &[readable.as_bytes()], false);
        assert_eq!(read.body, readable.as_bytes());
        assert_eq!(read.tokens(), (1500, 9));
        assert_eq!(read.tokens().0 + read.tokens().1, 1509);

        let refused = message_with_usage(r#"{"input_tokens":"1500","output_tokens":9}"#);
        let read = answer(&ctx, 200, JSON_HEAD, &[refused.as_bytes()], false);
        assert_eq!(read.body, refused.as_bytes(), "the body relays verbatim");
        assert_ne!(read.tokens(), (0, 0), "never 0");
        assert_eq!(read.tokens(), (0, floor_for(refused.len())));
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/unreadable_usage_floor_tests.rs::stream_refused_usage_bills_the_floor_not_zero`
    /// (map row 621). 1.5.5: a same-dialect chat stream whose usage chunk carries a count the
    /// reader refuses (`"prompt_tokens":"1500"`) is served 200 and bills the floor over every byte
    /// the far end sent (their length / 4, as output), never 0.
    /// RED: a refused stream usage billed as zero tokens.
    #[test]
    fn stream_refused_usage_bills_the_floor_not_zero() {
        let (arrived, lane) = ask("openai", "openai", true);
        let ctx = reply_ctx(&arrived, &lane);
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
        let mut far = data_frames(&[&first.to_string(), &last.to_string(), &usage.to_string()]);
        far.extend_from_slice(busbar_plane_llm::codec::dialect::SSE_DONE_FRAME);
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        assert_ne!(read.tokens(), (0, 0), "never 0");
        assert_eq!(read.tokens(), (0, floor_for(far.len())));
    }
}
