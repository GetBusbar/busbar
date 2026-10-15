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
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
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
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
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
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
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
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
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
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
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
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
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
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
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
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
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

// ── rehomed: the engine's answer tests on the served reply (F25 REHOME, status row 155) ──────────

/// The legacy engine's answer tests (`crates/busbar-llm/src/engine/**`), rehomed onto the served
/// reply. Each test names the legacy test it replaces, the 1.5.5 behaviour it pins, and its RED.
mod rehomed_answers {
    use super::*;
    use std::borrow::Cow;

    use busbar_contract::abi::transport::{FAULT_HARD, FAULT_TRANSIENT};
    use busbar_contract::upstream::CanonicalSignal;
    use busbar_plane_llm::codec::eventstream;
    use busbar_plane_llm::exchange::arrive::PathModel;
    use busbar_plane_llm::exchange::attempt::StreamIntent;
    use busbar_plane_llm::exchange::reply::{failure, wire, Piece};
    use busbar_plane_llm::plane_door::breaker_fault;
    use serde_json::json;

    const SSE_HEAD: &[(&[u8], &[u8])] = &[(b"content-type", b"text/event-stream")];
    const EVENTSTREAM: &str = "application/vnd.amazon.eventstream";

    /// The host's entropy, so a dialect that mints an id (a request id, a message id) mints one.
    fn entropy() {
        busbar_contract::codec::install_entropy_source(|out| {
            out.fill(7);
            true
        });
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

    /// The caller's arrival of `request` in `dialect`: a path-model dialect's URL names the model
    /// and the stream, and `json_array` is a stream asked without the event-stream switch.
    fn arrived(dialect: &'static str, request: Value, json_array: bool) -> Arrived {
        let stream = request["stream"].as_bool().unwrap_or(false);
        Arrived {
            dialect,
            operation: OpVerb::CHAT,
            model: "p".to_string(),
            content_type: "application/json".to_string(),
            body: serde_json::to_vec(&request).expect("JSON"),
            parsed: Some(request),
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
            arrived(caller, chat_request(caller, stream), false),
            lane(far),
        )
    }

    fn reply_ctx<'a>(arrived: &'a Arrived, lane: &'a Lane, passthrough: bool) -> ReplyCtx<'a> {
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
            passthrough,
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

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.body).into_owned()
        }

        fn json(&self) -> Value {
            serde_json::from_slice(&self.body)
                .unwrap_or_else(|err| panic!("a JSON body ({err}): {}", self.text()))
        }

        /// How many head fields are named `name`.
        fn count(&self, name: &str) -> usize {
            self.fields
                .iter()
                .filter(|(field_name, _)| field_name == name)
                .count()
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

    /// The `(event, data)` frames of an event stream, the `[DONE]` sentinel left out.
    fn sse_frames(text: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for frame in text.split("\n\n") {
            let mut event = String::new();
            let mut data: Option<String> = None;
            for line in frame.lines() {
                if let Some(rest) = line.strip_prefix("event:") {
                    event = rest.trim().to_string();
                } else if let Some(rest) = line.strip_prefix("data:") {
                    data = Some(rest.trim().to_string());
                }
            }
            if let Some(data) = data.filter(|payload| payload != "[DONE]") {
                out.push((event, data));
            }
        }
        out
    }

    /// The JSON payload of every `data:` frame of an event stream.
    fn sse_payloads(text: &str) -> Vec<Value> {
        sse_frames(text)
            .into_iter()
            .filter_map(|(_, data)| serde_json::from_str(&data).ok())
            .collect()
    }

    /// `events` framed as a far end's `data:` stream, ended by the `[DONE]` frame.
    fn data_stream(events: &[&str]) -> Vec<u8> {
        let mut out: String = events
            .iter()
            .map(|event| format!("data: {event}\n\n"))
            .collect();
        out += "data: [DONE]\n\n";
        out.into_bytes()
    }

    /// The legacy engine's chat stream fixture: a role delta, the text, the stop with its usage.
    fn chat_stream_events() -> Vec<u8> {
        data_stream(&[
            r#"{"choices":[{"delta":{"role":"assistant"}}]}"#,
            r#"{"choices":[{"delta":{"content":"hi"}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#,
        ])
    }

    /// A chat completion of `text`, as a far end of the chat dialect answers it whole.
    fn chat_completion(text: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": "chatcmpl-ok", "object": "chat.completion", "created": 1_234_567_890,
            "model": "glm-4.5",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}
        }))
        .expect("JSON")
    }

    /// A binary event-stream body decoded: its frames' event names and whatever bytes were left.
    fn eventstream_names(body: &[u8]) -> (Vec<String>, usize) {
        let mut buf = body.to_vec();
        let frames = eventstream::drain_frames_checked(&mut buf, None).0;
        (
            frames.into_iter().map(|(name, _)| name).collect(),
            buf.len(),
        )
    }

    /// A UUID-v4-shaped id: 8-4-4-4-12 lowercase hex.
    fn is_uuid(id: &str) -> bool {
        id.split('-').map(str::len).collect::<Vec<_>>() == [8, 4, 4, 4, 12]
            && id
                .chars()
                .all(|ch| ch == '-' || (ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()))
    }

    /// `dialect`'s own error envelope for `status`, `kind` and `message`, written by its codec.
    fn own_envelope(dialect: &str, status: u16, kind: &str, message: &str) -> Value {
        busbar_plane_llm::codec::DECLS
            .iter()
            .find(|decl| decl.name == dialect)
            .and_then(|decl| decl.dialect())
            .expect("the dialect has a codec")
            .write_error(status, kind, message)
    }

    /// An envelope with the request id its writer mints taken out.
    fn without_minted_id(mut envelope: Value) -> Value {
        if let Some(obj) = envelope.as_object_mut() {
            obj.remove("request_id");
        }
        envelope
    }

    // ── a same-dialect failed generation, ungoverned (failed_generation.rs) ────────────────────────

    const SPLIT_HEAD: &[u8] = br#"{"id":"c-1","finish_re"#;

    /// The second half of a split same-dialect body whose stop reason is `finish`.
    fn split_tail(finish: &str) -> Vec<u8> {
        format!(
            r#"ason":"{finish}","message":{{"role":"assistant","content":[{{"type":"text","text":"x"}}]}},"usage":{{"tokens":{{"input_tokens":10,"output_tokens":5}}}}}}"#
        )
        .into_bytes()
    }

    /// A same-dialect whole body in two pieces through a relay that meters nothing (the ungoverned
    /// relay): the caller's bytes and the end.
    fn ungoverned_relay(first: &[u8], second: &[u8]) -> (Vec<u8>, relay::End) {
        let mut ctx = relay_ctx("cohere", "cohere", false);
        ctx.meter = false;
        let mut relay = Relay::new(ctx);
        let mut out = Vec::new();
        for piece in [first, second] {
            if let (Fed::Bytes(bytes), _) = relay.feed(piece) {
                out.extend_from_slice(&bytes);
            }
        }
        let end = relay.end();
        out.extend_from_slice(&end.bytes);
        (out, end)
    }

    /// REHOMES `crates/busbar-llm/src/engine/attempt/tests/failed_generation.rs::ungoverned_same_protocol_cohere_error_split_key_faults_the_breaker`
    /// (map row 11). 1.5.5 (Q31 follow-up): an ungoverned same-dialect body whose stop-reason key
    /// arrives split across two pieces (`"finish_re` | `ason":"ERROR"`) still ends as an error and
    /// faults the far end, and the caller reads the far end's bytes unchanged.
    /// RED: a stop-reason scan that keeps no state across pieces (or that runs only when metering)
    /// reads the generation as a success, and the breaker records no fault.
    #[test]
    fn ungoverned_same_protocol_cohere_error_split_key_faults_the_breaker() {
        let tail = split_tail("ERROR");
        let (out, end) = ungoverned_relay(SPLIT_HEAD, &tail);
        assert_eq!(
            out,
            [SPLIT_HEAD, tail.as_slice()].concat(),
            "bytes unchanged"
        );
        assert!(end.generation_failed && end.failed, "the end is an error");
        assert_eq!(end.usage, None, "an ungoverned relay reads no usage");

        let (arrived, lane) = ask("cohere", "cohere", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let read = answer(&ctx, 200, JSON_HEAD, &[SPLIT_HEAD, &tail], false);
        assert_eq!(read.body, [SPLIT_HEAD, tail.as_slice()].concat());
        assert_eq!(read.end().verdict, Verdict::Hard);
        assert_eq!(
            read.end().fault,
            Some(Fault::Transient("upstream-generation-failed"))
        );
        assert_eq!(breaker_fault(read.end().fault.as_ref()), FAULT_TRANSIENT);
    }

    /// REHOMES `crates/busbar-llm/src/engine/attempt/tests/failed_generation.rs::ungoverned_same_protocol_cohere_complete_split_key_is_no_fault`
    /// (map row 12). 1.5.5: the same split body ending `COMPLETE` is a clean success, no fault.
    /// RED: a scan that reads a split key as a failure (or any token as one) faults a healthy far
    /// end.
    #[test]
    fn ungoverned_same_protocol_cohere_complete_split_key_is_no_fault() {
        let tail = split_tail("COMPLETE");
        let (out, end) = ungoverned_relay(SPLIT_HEAD, &tail);
        assert_eq!(out, [SPLIT_HEAD, tail.as_slice()].concat());
        assert!(!end.generation_failed && !end.failed, "a clean end");

        let (arrived, lane) = ask("cohere", "cohere", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let read = answer(&ctx, 200, JSON_HEAD, &[SPLIT_HEAD, &tail], false);
        assert_eq!(read.end().verdict, Verdict::Ok);
        assert_eq!(read.end().fault, None);
    }

    // ── the answer's head (client_header_forwarding_tests.rs) ──────────────────────────────────

    const FAR_ANSWER_HEAD: &[(&[u8], &[u8])] = &[
        (b"content-type", b"application/json"),
        (b"x-ratelimit-remaining-tokens", b"99"),
        (b"openai-processing-ms", b"12"),
        (b"openai-organization", b"org-operator"),
        (b"openai-project", b"proj-operator"),
    ];

    /// REHOMES `crates/busbar-llm/src/engine/tests/client_header_forwarding_tests.rs::a_same_dialect_answer_relays_the_upstream_head`
    /// (map row 89). 1.5.5 (DIALECT-FIDELITY F2): a same-dialect 2xx answer carries every far head
    /// field (`x-ratelimit-remaining-tokens: 99`, `openai-processing-ms: 12`) but the far end's echo
    /// of the operator's tenant (`openai-organization`, `openai-project`).
    /// RED: a success relay that drops the far head, or one that leaks the operator's tenant.
    #[test]
    fn a_same_dialect_answer_relays_the_upstream_head() {
        let (arrived, lane) = ask("openai", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = chat_completion("hi");
        let read = answer(&ctx, 200, FAR_ANSWER_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert_eq!(read.end().verdict, Verdict::Ok);
        assert_eq!(
            read.value("x-ratelimit-remaining-tokens").as_deref(),
            Some("99")
        );
        assert_eq!(read.value("openai-processing-ms").as_deref(), Some("12"));
        assert_eq!(read.count("openai-organization"), 0, "{:?}", read.fields);
        assert_eq!(read.count("openai-project"), 0, "{:?}", read.fields);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/client_header_forwarding_tests.rs::a_same_dialect_error_relays_the_upstream_head`
    /// (map row 90). 1.5.5: a same-dialect 400 `invalid_request_error` reaches the caller with the
    /// far head's values (`x-ratelimit-remaining-tokens: 99`, `retry-after: 7`) and without
    /// `openai-organization`.
    /// RED: a client-fault relay that keeps only the names, rewrites a value, or leaks the tenant.
    #[test]
    fn a_same_dialect_error_relays_the_upstream_head() {
        let (arrived, lane) = ask("openai", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let mut head = FAR_ANSWER_HEAD.to_vec();
        head.push((b"retry-after", b"7"));
        let body = br#"{"error":{"message":"bad","type":"invalid_request_error"}}"#;
        let read = answer(&ctx, 400, &head, &[body], false);
        assert_eq!(read.status, 400);
        assert_eq!(read.end().verdict, Verdict::Hard);
        assert_eq!(
            read.value("x-ratelimit-remaining-tokens").as_deref(),
            Some("99")
        );
        assert_eq!(read.value("retry-after").as_deref(), Some("7"));
        assert_eq!(read.count("openai-organization"), 0, "{:?}", read.fields);
        assert_eq!(read.body, body, "the far end's bytes");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/client_header_forwarding_tests.rs::a_translated_answer_relays_no_upstream_head`
    /// (map row 91). 1.5.5: a translated answer is busbar's own answer in the caller's dialect and
    /// carries none of the far end's head fields.
    /// RED: a translated whole answer that relays the far head (`x-ratelimit-*`, `openai-*`).
    #[test]
    fn a_translated_answer_relays_no_upstream_head() {
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = chat_completion("hi");
        let read = answer(&ctx, 200, FAR_ANSWER_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        for name in [
            "x-ratelimit-remaining-tokens",
            "openai-processing-ms",
            "openai-organization",
            "openai-project",
        ] {
            assert_eq!(read.count(name), 0, "{name}: {:?}", read.fields);
        }
    }

    // ── the relayed stream (forward_pool_integration_tests.rs) ─────────────────────────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_sse_events_single_data_prefix`
    /// (map row 154). 1.5.5: each relayed event carries exactly one `data: ` prefix.
    /// RED: a relay that re-prefixes a relayed frame (`data: data: event-0`).
    #[test]
    fn test_sse_events_single_data_prefix() {
        let (arrived, lane) = ask("anthropic", "anthropic", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = data_stream(&["event-0", "event-1"]);
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        let text = read.text();
        assert!(!text.contains("data: data:"), "{text}");
        assert!(
            text.contains("data: event-0\n\n") && text.contains("data: event-1\n\n"),
            "{text}"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_stream_inspection_tap_usage_parsing`
    /// (map row 164). 1.5.5: a same-dialect stream reaches the caller byte-identical, its `[DONE]`
    /// frame included, while its usage is read as it goes by.
    /// RED: a usage tap that rewrites, drops or reorders a frame on the relay.
    #[test]
    fn test_stream_inspection_tap_usage_parsing() {
        let (arrived, lane) = ask("anthropic", "anthropic", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = data_stream(&[
            r#"{"type":"message_start"}"#,
            r#"{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}"#,
            r#"{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello"}}"#,
            r#"{"type":"message_delta","usage":{"input_tokens":10,"output_tokens":5}}"#,
            r#"{"type":"message_stop"}"#,
        ]);
        let pieces: Vec<&[u8]> = far.chunks(17).collect();
        let read = answer(&ctx, 200, SSE_HEAD, &pieces, false);
        assert_eq!(read.status, 200);
        assert_eq!(read.text(), String::from_utf8_lossy(&far), "byte-identical");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_forward_once_cross_protocol_auth_kinds_match_main_path`
    /// (map row 183). 1.5.5: a far end of another dialect refusing the deployment's own credential
    /// with a 401 OR a 403 reaches an anthropic caller as its own refusal (status 401, `type:
    /// "error"`, `error.type: "authentication_error"`), records a hard fault, and never relays the
    /// far end's body; the last-resort attempt runs the same judge.
    /// RED: a 403 shaped as `permission_error` or `invalid_request_error`, or the far body relayed.
    #[test]
    fn test_forward_once_cross_protocol_auth_kinds_match_main_path() {
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = br#"{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","code":"invalid_api_key"}}"#;
        for status in [401, 403] {
            let read = answer(&ctx, status, JSON_HEAD, &[body], false);
            assert_eq!(read.status, 401, "{status}");
            let envelope = read.json();
            assert_eq!(envelope["type"], "error", "{status}: {envelope}");
            assert_eq!(
                envelope["error"]["type"], "authentication_error",
                "{status}: {envelope}"
            );
            assert!(
                !read.text().contains("Incorrect API key"),
                "{status}: {envelope}"
            );
            assert_eq!(read.end().verdict, Verdict::Hard, "{status}");
            assert_eq!(
                breaker_fault(read.end().fault.as_ref()),
                FAULT_HARD,
                "{status}"
            );
        }
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_cross_protocol_stream_openai_lane_to_anthropic_client`
    /// (map row 201). 1.5.5: a chat-dialect stream reaches an anthropic caller as anthropic events
    /// (`message_start`, `content_block_delta` with a `text_delta` of "hi", `message_stop`) and no
    /// `chat.completion.chunk` leaks.
    /// RED: a translated stream relaying the far end's frames, or missing the event sequence.
    #[test]
    fn test_cross_protocol_stream_openai_lane_to_anthropic_client() {
        let (arrived, lane) = ask("anthropic", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = data_stream(&[
            r#"{"choices":[{"delta":{"role":"assistant"}}]}"#,
            r#"{"choices":[{"delta":{"content":"hi"}}]}"#,
            r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}"#,
        ]);
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        let text = read.text();
        for needle in [
            "event: message_start",
            "event: content_block_delta",
            "text_delta",
            "\"hi\"",
            "event: message_stop",
        ] {
            assert!(text.contains(needle), "{needle}: {text}");
        }
        assert!(!text.contains("chat.completion.chunk"), "{text}");
    }

    // ── the error shape across dialects (ingress_indistinguishability_tests.rs) ────────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_cross_protocol_error_kind_mapping`
    /// (map row 326). 1.5.5: the kind a far status is reshaped into across dialects: 401
    /// `authentication_error`, 403 `permission_error`, 429 `rate_limit_error`, 500 and 502
    /// `api_error`, 503 `overloaded`, 504 `timeout`, 400 and 404 `invalid_request_error`.
    /// RED: a 401/403 collapsed into `invalid_request_error`, or a 503 into `api_error`.
    #[test]
    fn test_cross_protocol_error_kind_mapping() {
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

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_shape_cross_protocol_error_auth_kinds`
    /// (map row 327). 1.5.5: a far 401 / 403 `{"error":{"message":"nope"}}` relayed across
    /// dialects to an anthropic caller keeps its status, wears `authentication_error` /
    /// `permission_error`, and carries the far end's message `nope`.
    /// RED: the kind of a 403 taken from the 401 arm, the message dropped for the generic one, or
    /// the status changed.
    #[test]
    fn test_shape_cross_protocol_error_auth_kinds() {
        let body = br#"{"error":{"message":"nope"}}"#;
        for (status, kind) in [(401, "authentication_error"), (403, "permission_error")] {
            let far = FarError {
                status,
                head: JSON_HEAD,
                body,
            };
            let relayed = failure::relay("anthropic", "openai", &far);
            let judged = judge(
                "anthropic",
                "openai",
                OpVerb::CHAT,
                &HashMap::new(),
                true,
                &far,
            );
            for rendered in [relayed, judged.answer] {
                assert_eq!(rendered.status, status);
                let envelope: Value = serde_json::from_slice(&rendered.body).expect("JSON");
                assert_eq!(envelope["error"]["type"], kind, "{status}: {envelope}");
                assert_eq!(envelope["error"]["message"], "nope", "{status}: {envelope}");
            }
        }
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_ingress_stream_content_type_by_protocol`
    /// (map row 331). 1.5.5: a caller's stream wears its own dialect's content type:
    /// `text/event-stream` for the five event-stream dialects, `application/vnd.amazon.eventstream`
    /// for bedrock, none for a dialect the plane does not hold.
    /// RED: the far end's content type kept on a translated stream, or bedrock served as SSE.
    #[test]
    fn test_ingress_stream_content_type_by_protocol() {
        for dialect in ["openai", "anthropic", "gemini", "cohere", "responses"] {
            assert_eq!(
                wire::ingress_stream_content_type(dialect),
                Some("text/event-stream"),
                "{dialect}"
            );
        }
        assert_eq!(
            wire::ingress_stream_content_type("bedrock"),
            Some(EVENTSTREAM)
        );
        assert_eq!(wire::ingress_stream_content_type("nonsense"), None);
        assert_eq!(
            relay::content_type("bedrock", "openai", true, false),
            ContentType::Ingress(EVENTSTREAM)
        );
        assert_eq!(
            relay::content_type("anthropic", "bedrock", true, false),
            ContentType::Ingress("text/event-stream")
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_cross_protocol_response_carries_ingress_ct_and_native_id`
    /// (map row 332). 1.5.5: a chat-dialect answer with id `chatcmpl-LEAK123` and fingerprint
    /// `fp_backend` reaches an anthropic caller as 200 `application/json`, `type: "message"`, an id
    /// minted `msg_`, and neither foreign value anywhere in the body.
    /// RED: the far end's id or fingerprint carried across, or the far content type kept.
    #[test]
    fn test_cross_protocol_response_carries_ingress_ct_and_native_id() {
        entropy();
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = serde_json::to_vec(&json!({
            "id": "chatcmpl-LEAK123", "object": "chat.completion", "created": 1_234_567_890,
            "system_fingerprint": "fp_backend", "model": "glm-4.5",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "Hi"},
                "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}
        }))
        .expect("JSON");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert_eq!(
            read.value("content-type").as_deref(),
            Some("application/json")
        );
        let message = read.json();
        assert_eq!(message["type"], "message", "{message}");
        let id = message["id"].as_str().unwrap_or_default();
        assert!(id.starts_with("msg_") && !id.contains("chatcmpl-"), "{id}");
        let text = read.text();
        assert!(
            !text.contains("chatcmpl-LEAK123") && !text.contains("fp_backend"),
            "{text}"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_bedrock_ingress_success_carries_amzn_request_id`
    /// (map row 344). 1.5.5: a bedrock caller's translated 2xx carries `x-amzn-requestid`, a
    /// 36-character UUID, exactly once.
    /// RED: a success head with no request id, or the id attached twice.
    #[test]
    fn test_bedrock_ingress_success_carries_amzn_request_id() {
        entropy();
        let (arrived, lane) = ask("bedrock", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = chat_completion("Hi");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert_eq!(read.count("x-amzn-requestid"), 1, "{:?}", read.fields);
        let id = read.value("x-amzn-requestid").unwrap_or_default();
        assert_eq!(id.len(), 36, "{id}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_anthropic_ingress_success_carries_request_id_header`
    /// (map row 345). 1.5.5: an anthropic caller's translated 2xx carries a minted `request-id`
    /// in the native `req_` shape, exactly once.
    /// RED: no request id on a translated success, or a duplicate from a double attach.
    #[test]
    fn test_anthropic_ingress_success_carries_request_id_header() {
        entropy();
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = chat_completion("Hi");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert_eq!(read.count("request-id"), 1, "{:?}", read.fields);
        let id = read.value("request-id").unwrap_or_default();
        assert!(id.starts_with("req_"), "{id}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_anthropic_ingress_stream_carries_request_id_header`
    /// (map row 346). 1.5.5: an anthropic caller's streamed 2xx from a far end that sent no id
    /// carries a minted `request-id` in the `req_` shape.
    /// RED: the stream head built without the request id the buffered head carries.
    #[test]
    fn test_anthropic_ingress_stream_carries_request_id_header() {
        entropy();
        let (arrived, lane) = ask("anthropic", "anthropic", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"role\":\"assistant\",\"content\":[],\"usage\":{\"input_tokens\":3,\"output_tokens\":0}}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
        let read = answer(&ctx, 200, SSE_HEAD, &[far], false);
        assert_eq!(read.status, 200);
        let id = read.value("request-id").unwrap_or_default();
        assert!(id.starts_with("req_"), "{id}: {:?}", read.fields);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_cross_protocol_client_fault_reshapes_error_envelope`
    /// (map row 347). 1.5.5: a chat-dialect 400 (`param`, `code`) reaches an anthropic caller as a
    /// 400 `application/json` anthropic envelope (`type: "error"`, `error.type:
    /// "invalid_request_error"`) carrying the far message, with no `param` or `code` member.
    /// RED: the far end's own envelope relayed across dialects.
    #[test]
    fn test_cross_protocol_client_fault_reshapes_error_envelope() {
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = br#"{"error":{"message":"Invalid 'max_tokens': must be positive","type":"invalid_request_error","param":"max_tokens","code":"invalid_value"}}"#;
        let read = answer(&ctx, 400, JSON_HEAD, &[body], false);
        assert_eq!(read.status, 400);
        assert_eq!(
            read.value("content-type").as_deref(),
            Some("application/json")
        );
        let envelope = read.json();
        assert_eq!(envelope["type"], "error", "{envelope}");
        assert_eq!(
            envelope["error"]["type"], "invalid_request_error",
            "{envelope}"
        );
        let text = read.text();
        assert!(
            !text.contains("\"param\"") && !text.contains("\"code\""),
            "{text}"
        );
        assert!(
            envelope["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("max_tokens"),
            "{envelope}"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_anthropic_same_proto_error_relays_upstream_request_id_verbatim_once`
    /// (map row 352). 1.5.5: a same-dialect anthropic 400 carrying `request-id:
    /// upstream-anthropic-rid-0001` reaches the caller as 400 with that `request-id` EXACTLY once.
    /// RED: a minted id in place of the far one, or a second `request-id` appended beside it.
    #[test]
    fn test_anthropic_same_proto_error_relays_upstream_request_id_verbatim_once() {
        let (arrived, lane) = ask("anthropic", "anthropic", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let head: &[(&[u8], &[u8])] = &[
            (b"content-type", b"application/json"),
            (b"request-id", b"upstream-anthropic-rid-0001"),
        ];
        let body =
            br#"{"type":"error","error":{"type":"invalid_request_error","message":"bad request"}}"#;
        let read = answer(&ctx, 400, head, &[body], false);
        assert_eq!(read.status, 400);
        assert_eq!(read.count("request-id"), 1, "{:?}", read.fields);
        assert_eq!(
            read.value("request-id").as_deref(),
            Some("upstream-anthropic-rid-0001")
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_anthropic_same_proto_passthrough_401_relays_request_id_verbatim_once`
    /// (map row 353). 1.5.5: the caller's own credential refused by a same-dialect far end (a
    /// passthrough 401 carrying `request-id: upstream-rid-passthrough`) is relayed as 401, the far
    /// body as it was, unjudged, and that `request-id` exactly once.
    /// RED: a passthrough 401 judged as the deployment's refusal, or its request id minted or
    /// doubled.
    #[test]
    fn test_anthropic_same_proto_passthrough_401_relays_request_id_verbatim_once() {
        let (arrived, lane) = ask("anthropic", "anthropic", false);
        let ctx = reply_ctx(&arrived, &lane, true);
        let head: &[(&[u8], &[u8])] = &[
            (b"content-type", b"application/json"),
            (b"request-id", b"upstream-rid-passthrough"),
        ];
        let body = br#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#;
        let read = answer(&ctx, 401, head, &[body], false);
        assert_eq!(read.status, 401);
        assert_eq!(read.body, body, "the far end's bytes");
        assert_eq!(read.count("request-id"), 1, "{:?}", read.fields);
        assert_eq!(
            read.value("request-id").as_deref(),
            Some("upstream-rid-passthrough")
        );
        assert_eq!(
            read.end().fault,
            Some(Fault::Judged {
                disposition: Disposition::ClientFault,
                class: None
            })
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_bedrock_converse_stream_buffered_cross_protocol_emits_binary_eventstream`
    /// (map row 355). 1.5.5: a bedrock caller that asked to stream, answered one chat-dialect body,
    /// reads `application/vnd.amazon.eventstream` frames (`messageStart` first, then
    /// `contentBlockDelta`, `messageStop`, `metadata`) under a UUID `x-amzn-requestid`.
    /// RED: the buffered answer written as JSON for a stream caller, or as SSE text.
    #[test]
    fn test_bedrock_converse_stream_buffered_cross_protocol_emits_binary_eventstream() {
        entropy();
        let (arrived, lane) = ask("bedrock", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = chat_completion("Hi");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert_eq!(read.value("content-type").as_deref(), Some(EVENTSTREAM));
        assert_eq!(
            read.value("x-amzn-requestid").unwrap_or_default().len(),
            36,
            "{:?}",
            read.fields
        );
        let (names, _) = eventstream_names(&read.body);
        assert_eq!(
            names.first().map(String::as_str),
            Some("messageStart"),
            "{names:?}"
        );
        for name in ["contentBlockDelta", "messageStop", "metadata"] {
            assert!(names.iter().any(|seen| seen == name), "{name}: {names:?}");
        }
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_gemini_json_array_buffered_cross_protocol_emits_one_element_array`
    /// (map row 357). 1.5.5: a gemini caller that asked for a JSON-array stream, answered one
    /// chat-dialect body, reads 200 under exactly `application/json` a one-element array whose
    /// element carries `candidates` and no `choices`.
    /// RED: a bare object, SSE frames, or the far end's `choices` inside the array.
    #[test]
    fn test_gemini_json_array_buffered_cross_protocol_emits_one_element_array() {
        let body = chat_completion("Hi");
        let answered = whole::translate(&ctx("gemini", "openai", true, true), 200, &body);
        assert_eq!(answered.end, WholeEnd::Delivered);
        assert_eq!(answered.answer.status, 200);
        assert_eq!(
            field(&answered.answer.fields, "content-type"),
            Some(b"application/json".as_slice())
        );
        let array: Value = serde_json::from_slice(&answered.answer.body).expect("JSON");
        let elements = array.as_array().expect("an array");
        assert_eq!(elements.len(), 1, "{array}");
        assert!(elements[0].get("candidates").is_some(), "{array}");
        assert!(elements[0].get("choices").is_none(), "{array}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_gemini_json_array_buffered_via_forward_once_matches_primary`
    /// (map row 358). 1.5.5: the last-resort attempt delivers the same one-element array under
    /// `application/json` as the primary path; the served reply runs one translate for both.
    /// RED: the attempt's reply answering anything but the one-element `candidates` array.
    #[test]
    fn test_gemini_json_array_buffered_via_forward_once_matches_primary() {
        let arrived = arrived("gemini", chat_request("gemini", true), true);
        let lane = lane("openai");
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = chat_completion("Hi");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert_eq!(
            read.value("content-type").as_deref(),
            Some("application/json")
        );
        let array = read.json();
        let elements = array.as_array().expect("an array");
        assert_eq!(elements.len(), 1, "{array}");
        assert!(elements[0].get("candidates").is_some(), "{array}");
        assert!(elements[0].get("choices").is_none(), "{array}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_non_gemini_stream_buffered_cross_protocol_stays_a_plain_object_not_an_array`
    /// (map row 371). 1.5.5: a chat caller that asked to stream, answered one anthropic body, reads
    /// its own `text/event-stream` chunks, each `data:` a JSON object, one carrying `choices`, and
    /// never a JSON array.
    /// RED: the array wrap applied to a caller that did not ask for one.
    #[test]
    fn test_non_gemini_stream_buffered_cross_protocol_stays_a_plain_object_not_an_array() {
        let (arrived, lane) = ask("openai", "anthropic", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = br#"{"id":"msg_buf","type":"message","role":"assistant","content":[{"type":"text","text":"Hi"}],"model":"claude-3","stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}"#;
        let read = answer(&ctx, 200, JSON_HEAD, &[body], false);
        assert_eq!(read.status, 200);
        let content_type = read.value("content-type").unwrap_or_default();
        assert!(
            content_type.starts_with("text/event-stream"),
            "{content_type}"
        );
        let text = read.text();
        assert!(!text.trim_start().starts_with('['), "{text}");
        let payloads = sse_payloads(&text);
        assert!(!payloads.is_empty(), "{text}");
        assert!(payloads.iter().all(Value::is_object), "{text}");
        assert!(
            payloads.iter().any(|chunk| chunk.get("choices").is_some()),
            "{text}"
        );
    }

    // ── a bedrock caller (ingress_integration_tests.rs) ────────────────────────────────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_converse_routes_and_returns_json`
    /// (map row 387). 1.5.5: a bedrock caller's non-stream answer from a chat-dialect far end is
    /// Converse JSON (`output`/`usage`) under `application/json`, with an `x-amzn-requestid` shaped
    /// 8-4-4-4-12 lowercase hex.
    /// RED: no request id, or one that is not UUID-shaped.
    #[test]
    fn test_bedrock_converse_routes_and_returns_json() {
        entropy();
        let (arrived, lane) = ask("bedrock", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let body = chat_completion("hello there");
        let read = answer(&ctx, 200, JSON_HEAD, &[&body], false);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with("application/json"));
        let id = read.value("x-amzn-requestid").unwrap_or_default();
        assert!(is_uuid(&id), "{id}");
        let converse = read.json();
        assert!(
            converse.get("output").is_some() || converse.get("usage").is_some(),
            "{converse}"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_converse_stream_returns_binary_eventstream`
    /// (map row 388). 1.5.5: a bedrock caller's stream from a chat-dialect far end is
    /// `application/vnd.amazon.eventstream`, a whole sequence of frames (`messageStart`,
    /// `contentBlockDelta`, `messageStop`) with nothing left over, under a UUID-shaped
    /// `x-amzn-requestid`.
    /// RED: SSE text in a binary body, a partial trailing frame, or no request id on the stream.
    #[test]
    fn test_bedrock_converse_stream_returns_binary_eventstream() {
        entropy();
        let (arrived, lane) = ask("bedrock", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = chat_stream_events();
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with(EVENTSTREAM));
        let id = read.value("x-amzn-requestid").unwrap_or_default();
        assert!(is_uuid(&id), "{id}");
        let (names, left) = eventstream_names(&read.body);
        assert_eq!(left, 0, "a whole sequence of frames");
        for name in ["messageStart", "contentBlockDelta", "messageStop"] {
            assert!(names.iter().any(|seen| seen == name), "{name}: {names:?}");
        }
    }

    /// The far end's native Converse stream frames.
    fn converse_frames(frames: &[(&str, &[u8])]) -> Vec<u8> {
        frames
            .iter()
            .flat_map(|(name, payload)| eventstream::encode_frame(name, payload))
            .collect()
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_same_protocol_stream_passthrough_forwards_upstream_request_id`
    /// (map row 389). 1.5.5: a same-dialect bedrock stream keeps the far content type, relays the
    /// far frames in order (`messageStart`, `contentBlockDelta`, `messageStop`, `metadata`), and
    /// forwards the far `x-amzn-requestid` (`fixed-upstream-amzn-req-id-0001`) once, never minted.
    /// RED: a minted UUID in place of the far id, or a re-encoded or reordered frame sequence.
    #[test]
    fn test_bedrock_same_protocol_stream_passthrough_forwards_upstream_request_id() {
        entropy();
        let (arrived, lane) = ask("bedrock", "bedrock", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let head: &[(&[u8], &[u8])] = &[
            (b"content-type", EVENTSTREAM.as_bytes()),
            (b"x-amzn-requestid", b"fixed-upstream-amzn-req-id-0001"),
        ];
        let far = converse_frames(&[
            ("messageStart", br#"{"role":"assistant"}"#),
            (
                "contentBlockDelta",
                br#"{"delta":{"text":"hi"},"contentBlockIndex":0}"#,
            ),
            ("messageStop", br#"{"stopReason":"end_turn"}"#),
            (
                "metadata",
                br#"{"usage":{"inputTokens":5,"outputTokens":3,"totalTokens":8}}"#,
            ),
        ]);
        let pieces: Vec<&[u8]> = far.chunks(23).collect();
        let read = answer(&ctx, 200, head, &pieces, false);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with(EVENTSTREAM));
        assert_eq!(read.count("x-amzn-requestid"), 1, "{:?}", read.fields);
        assert_eq!(
            read.value("x-amzn-requestid").as_deref(),
            Some("fixed-upstream-amzn-req-id-0001")
        );
        let (names, left) = eventstream_names(&read.body);
        assert_eq!(left, 0);
        assert_eq!(
            names,
            [
                "messageStart",
                "contentBlockDelta",
                "messageStop",
                "metadata"
            ]
        );
        assert_eq!(read.body, far, "the far end's frames, verbatim");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_same_protocol_converse_non_stream_forwards_upstream_request_id`
    /// (map row 390). 1.5.5: a same-dialect bedrock Converse answer relays under the far
    /// `application/json`, its bytes unchanged, with the far `x-amzn-requestid`
    /// (`fixed-upstream-amzn-req-id-nonstream-0001`) once.
    /// RED: the far request id dropped or replaced by a minted one on the non-stream relay.
    #[test]
    fn test_bedrock_same_protocol_converse_non_stream_forwards_upstream_request_id() {
        entropy();
        let (arrived, lane) = ask("bedrock", "bedrock", false);
        let ctx = reply_ctx(&arrived, &lane, false);
        let head: &[(&[u8], &[u8])] = &[
            (b"content-type", b"application/json"),
            (
                b"x-amzn-requestid",
                b"fixed-upstream-amzn-req-id-nonstream-0001",
            ),
        ];
        let body = br#"{"output":{"message":{"role":"assistant","content":[{"text":"hi there"}]}},"stopReason":"end_turn","usage":{"inputTokens":5,"outputTokens":3,"totalTokens":8}}"#;
        let read = answer(&ctx, 200, head, &[body], false);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with("application/json"));
        assert_eq!(read.count("x-amzn-requestid"), 1, "{:?}", read.fields);
        assert_eq!(
            read.value("x-amzn-requestid").as_deref(),
            Some("fixed-upstream-amzn-req-id-nonstream-0001")
        );
        assert_eq!(read.body, body, "the far end's bytes");
    }

    /// The checks every bedrock caller's cut stream answers to: pure binary frames, nothing left
    /// over, and a trailing `InternalServerException` exception frame.
    fn assert_binary_exception_tail(read: &Read) {
        let body = &read.body;
        assert!(
            !body.windows(7).any(|bytes| bytes == b"event: ")
                && !body.windows(6).any(|bytes| bytes == b"data: "),
            "no SSE text in a binary body: {body:?}"
        );
        let (names, left) = eventstream_names(body);
        assert_eq!(left, 0, "a whole sequence of frames");
        assert!(!names.is_empty());
        let raw = String::from_utf8_lossy(body);
        assert!(raw.contains(":exception-type"), "{body:?}");
        assert!(raw.contains("InternalServerException"), "{body:?}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_same_protocol_stream_mid_stream_transport_error_appends_binary_exception`
    /// (map row 391). 1.5.5: a same-dialect bedrock stream cut after its first frame keeps the
    /// eventstream content type and ends on a CRC-valid binary `InternalServerException` frame,
    /// never SSE text.
    /// RED: an SSE error frame spliced into the binary body, or the cut ending with no frame.
    #[test]
    fn test_bedrock_same_protocol_stream_mid_stream_transport_error_appends_binary_exception() {
        let (arrived, lane) = ask("bedrock", "bedrock", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let head: &[(&[u8], &[u8])] = &[
            (b"content-type", EVENTSTREAM.as_bytes()),
            (b"x-amzn-requestid", b"fixed-upstream-amzn-req-id-err1"),
        ];
        let far = converse_frames(&[("messageStart", br#"{"role":"assistant"}"#)]);
        let read = answer(&ctx, 200, head, &[&far], true);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with(EVENTSTREAM));
        assert_binary_exception_tail(&read);
        assert_eq!(read.end().fault, Some(Fault::Transient("mid-stream")));
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_ingress_mid_stream_transport_error_appends_binary_exception`
    /// (map row 392). 1.5.5: a bedrock caller's translated stream cut after its first far event
    /// ends on a binary `InternalServerException` frame, the body pure frames.
    /// RED: the caller's error written as SSE text over a binary stream.
    #[test]
    fn test_bedrock_ingress_mid_stream_transport_error_appends_binary_exception() {
        let (arrived, lane) = ask("bedrock", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = b"data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n";
        let read = answer(&ctx, 200, SSE_HEAD, &[far], true);
        assert_eq!(read.status, 200);
        assert_binary_exception_tail(&read);
    }

    /// The last `data:` frame of a stream, as JSON.
    fn last_payload(text: &str) -> Value {
        sse_payloads(text)
            .pop()
            .unwrap_or_else(|| panic!("a trailing data: frame: {text}"))
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_openai_ingress_mid_stream_transport_error_appends_native_sse`
    /// (map row 393). 1.5.5: a chat caller's stream cut mid-way ends on a bare `data:` frame (no
    /// `event:` line) carrying the native `error` envelope.
    /// RED: a named event on a chat stream, or a trailing frame with no `error` member.
    #[test]
    fn test_openai_ingress_mid_stream_transport_error_appends_native_sse() {
        let (arrived, lane) = ask("openai", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let read = answer(&ctx, 200, SSE_HEAD, &[far], true);
        assert_eq!(read.status, 200);
        let text = read.text();
        assert!(!text.contains("event:"), "{text}");
        assert!(last_payload(&text).get("error").is_some(), "{text}");
    }

    // ── a gemini caller ────────────────────────────────────────────────────────────────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_stream_generate_content_alt_sse_is_event_stream`
    /// (map row 396). 1.5.5: a gemini caller streaming with the event-stream switch reads
    /// `text/event-stream` frames that are native `GenerateContentResponse`s (`candidates`), none
    /// carrying the far end's `choices`.
    /// RED: the far chunks relayed under the right content type.
    #[test]
    fn test_gemini_stream_generate_content_alt_sse_is_event_stream() {
        let (arrived, lane) = ask("gemini", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = chat_stream_events();
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with("text/event-stream"));
        let payloads = sse_payloads(&read.text());
        assert!(!payloads.is_empty());
        assert!(payloads
            .iter()
            .any(|frame| frame.get("candidates").is_some()));
        assert!(payloads.iter().all(|frame| frame.get("choices").is_none()));
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_alt_sse_mid_stream_transport_error_appends_native_sse_frame`
    /// (map row 397). 1.5.5: a gemini event-stream caller's cut stream stays `text/event-stream`,
    /// carries no `event:` line, no `choices` and no `chat.completion.chunk`, and ends on a
    /// `google.rpc.Status`-shaped frame (`error.status`).
    /// RED: a named error event, a JSON-array close, or a chat-dialect error envelope.
    #[test]
    fn test_gemini_alt_sse_mid_stream_transport_error_appends_native_sse_frame() {
        let (arrived, lane) = ask("gemini", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let read = answer(&ctx, 200, SSE_HEAD, &[far], true);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with("text/event-stream"));
        let text = read.text();
        assert!(!text.contains("event:"), "{text}");
        assert!(!text.contains("chat.completion.chunk"), "{text}");
        let payloads = sse_payloads(&text);
        assert!(payloads.iter().all(|frame| frame.get("choices").is_none()));
        let last = last_payload(&text);
        assert!(last["error"].get("status").is_some(), "{text}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_json_array_mid_stream_error_closes_array_no_sse`
    /// (map row 409). 1.5.5: a gemini JSON-array caller's cut stream is `application/json`, still
    /// one valid JSON array, with no `event:`/`data:` text, closing on an `error.status` element.
    /// RED: an unclosed array, or an SSE error frame inside an array body.
    #[test]
    fn test_gemini_json_array_mid_stream_error_closes_array_no_sse() {
        let arrived = arrived("gemini", chat_request("gemini", true), true);
        let lane = lane("openai");
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let read = answer(&ctx, 200, SSE_HEAD, &[far], true);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with("application/json"));
        let text = read.text();
        assert!(
            !text.contains("event:") && !text.contains("data:"),
            "{text}"
        );
        let array = read.json();
        let elements = array.as_array().expect("an array");
        assert!(
            elements
                .iter()
                .any(|element| element["error"].get("status").is_some()),
            "{text}"
        );
    }

    // ── an anthropic caller ────────────────────────────────────────────────────────────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_anthropic_cross_protocol_message_start_full_skeleton`
    /// (map row 411). 1.5.5: a translated stream's `message_start` carries the full skeleton: an
    /// id minted `msg_`, `type: "message"`, `content: []`, `stop_reason: null`, `stop_sequence:
    /// null`.
    /// RED: a `message_start` missing a skeleton member an SDK reads.
    #[test]
    fn test_anthropic_cross_protocol_message_start_full_skeleton() {
        entropy();
        let (arrived, lane) = ask("anthropic", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = chat_stream_events();
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        let text = read.text();
        let (_, data) = sse_frames(&text)
            .into_iter()
            .find(|(event, _)| event == "message_start")
            .unwrap_or_else(|| panic!("a message_start: {text}"));
        let event: Value = serde_json::from_str(&data).expect("JSON");
        let message = &event["message"];
        assert!(
            message["id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("msg_"),
            "{message}"
        );
        assert_eq!(message["type"], "message", "{message}");
        assert!(message["content"].is_array(), "{message}");
        assert!(
            message.get("stop_reason").is_some_and(Value::is_null),
            "{message}"
        );
        assert!(
            message.get("stop_sequence").is_some_and(Value::is_null),
            "{message}"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_passthrough_401_cross_protocol_reshaped_to_ingress`
    /// (map row 412). 1.5.5: the caller's own credential refused by a far end of another dialect
    /// keeps its 401 and is reshaped into the caller's envelope (`type: "error"`, `error.type:
    /// "authentication_error"`), unjudged.
    /// RED: the far end's foreign envelope relayed verbatim across dialects.
    #[test]
    fn test_passthrough_401_cross_protocol_reshaped_to_ingress() {
        let (arrived, lane) = ask("anthropic", "openai", false);
        let ctx = reply_ctx(&arrived, &lane, true);
        let body = br#"{"error":{"message":"Incorrect API key provided","type":"invalid_request_error","code":"invalid_api_key"}}"#;
        let read = answer(&ctx, 401, JSON_HEAD, &[body], false);
        assert_eq!(read.status, 401);
        let envelope = read.json();
        assert_eq!(envelope["type"], "error", "{envelope}");
        assert_eq!(
            envelope["error"]["type"], "authentication_error",
            "{envelope}"
        );
        assert_eq!(
            read.end().fault,
            Some(Fault::Judged {
                disposition: Disposition::ClientFault,
                class: None
            })
        );
    }

    // ── each caller's own stream vocabulary ────────────────────────────────────────────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_openai_ingress_stream_emits_native_openai_frames`
    /// (map row 445). 1.5.5: a same-dialect chat stream is `text/event-stream`, bare `data:` frames
    /// (no `event:` line), every JSON chunk's `object` is `chat.completion.chunk`, and it ends on
    /// `[DONE]`.
    /// RED: a dropped `[DONE]`, a mangled object tag, or a named event injected.
    #[test]
    fn test_openai_ingress_stream_emits_native_openai_frames() {
        let (arrived, lane) = ask("openai", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = data_stream(&[
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#,
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}"#,
            r#"{"id":"chatcmpl-abc","object":"chat.completion.chunk","created":1700000000,"model":"gpt-4o","choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}"#,
        ]);
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with("text/event-stream"));
        let text = read.text();
        assert!(!text.contains("event:"), "{text}");
        assert!(text.contains("[DONE]"), "{text}");
        let objects: Vec<Value> = sse_payloads(&text)
            .into_iter()
            .filter_map(|chunk| chunk.get("object").cloned())
            .collect();
        assert!(!objects.is_empty(), "{text}");
        assert!(
            objects.iter().all(|tag| tag == "chat.completion.chunk"),
            "{objects:?}"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_cohere_ingress_stream_emits_native_cohere_frames`
    /// (map row 446). 1.5.5: a cohere caller's translated stream is `text/event-stream` whose
    /// frames walk `message-start` before `message-end` with a `content-delta`, and no
    /// `chat.completion.chunk` leaks.
    /// RED: the far chunks relayed, or the cohere vocabulary out of order.
    #[test]
    fn test_cohere_ingress_stream_emits_native_cohere_frames() {
        let (arrived, lane) = ask("cohere", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = chat_stream_events();
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with("text/event-stream"));
        let text = read.text();
        assert!(!text.contains("chat.completion.chunk"), "{text}");
        let types: Vec<String> = sse_payloads(&text)
            .into_iter()
            .filter_map(|frame| frame["type"].as_str().map(str::to_string))
            .collect();
        assert!(
            types.iter().any(|kind| kind == "content-delta"),
            "{types:?}"
        );
        let start = types.iter().position(|kind| kind == "message-start");
        let end = types.iter().rposition(|kind| kind == "message-end");
        assert!(
            matches!((start, end), (Some(first), Some(last)) if first < last),
            "{types:?}"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_responses_ingress_stream_emits_native_responses_events`
    /// (map row 447). 1.5.5: a responses caller's translated stream is `text/event-stream` with
    /// `response.created` before `response.completed` and a `response.output_text.delta`, and no
    /// `chat.completion.chunk` leaks.
    /// RED: the far chunks relayed, or the responses events out of order.
    #[test]
    fn test_responses_ingress_stream_emits_native_responses_events() {
        entropy();
        let (arrived, lane) = ask("responses", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = chat_stream_events();
        let read = answer(&ctx, 200, SSE_HEAD, &[&far], false);
        assert_eq!(read.status, 200);
        assert!(read
            .value("content-type")
            .unwrap_or_default()
            .starts_with("text/event-stream"));
        let text = read.text();
        assert!(!text.contains("chat.completion.chunk"), "{text}");
        let events: Vec<String> = sse_frames(&text)
            .into_iter()
            .map(|(event, _)| event)
            .collect();
        assert!(
            events
                .iter()
                .any(|event| event == "response.output_text.delta"),
            "{events:?}"
        );
        let created = events.iter().position(|event| event == "response.created");
        let completed = events
            .iter()
            .rposition(|event| event == "response.completed");
        assert!(
            matches!((created, completed), (Some(first), Some(last)) if first < last),
            "{events:?}"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_cohere_ingress_mid_stream_transport_error_appends_native_sse`
    /// (map row 449). 1.5.5: a cohere caller's cut stream ends on a bare `data:` `message-end`
    /// frame whose `delta.finish_reason` is `ERROR`, with no top-level `message`, no `event:` line
    /// and no `chat.completion.chunk`.
    /// RED: a chat-dialect `{"error":…}` frame, or a free-text detail on a cohere wire.
    #[test]
    fn test_cohere_ingress_mid_stream_transport_error_appends_native_sse() {
        let (arrived, lane) = ask("cohere", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let read = answer(&ctx, 200, SSE_HEAD, &[far], true);
        assert_eq!(read.status, 200);
        let text = read.text();
        assert!(!text.contains("event:"), "{text}");
        assert!(!text.contains("chat.completion.chunk"), "{text}");
        let last = last_payload(&text);
        assert_eq!(last["type"], "message-end", "{last}");
        assert!(
            last["delta"]["finish_reason"]
                .as_str()
                .is_some_and(|reason| reason.starts_with("ERROR")),
            "{last}"
        );
        assert!(last.get("message").is_none(), "{last}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_responses_ingress_mid_stream_transport_error_appends_response_failed`
    /// (map row 450). 1.5.5: a responses caller's cut stream ends on `event: response.failed`
    /// whose data is the stream shape (`response.status: "failed"`, `response.error.message`), with
    /// no top-level `error`.
    /// RED: the non-stream `{"error":…}` envelope written into a responses stream.
    #[test]
    fn test_responses_ingress_mid_stream_transport_error_appends_response_failed() {
        let (arrived, lane) = ask("responses", "openai", true);
        let ctx = reply_ctx(&arrived, &lane, false);
        let far = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
        let read = answer(&ctx, 200, SSE_HEAD, &[far], true);
        assert_eq!(read.status, 200);
        let text = read.text();
        assert!(text.contains("event: response.failed"), "{text}");
        let (_, data) = sse_frames(&text)
            .into_iter()
            .find(|(event, _)| event == "response.failed")
            .unwrap_or_else(|| panic!("a response.failed frame: {text}"));
        let failed: Value = serde_json::from_str(&data).expect("JSON");
        assert_eq!(failed["response"]["status"], "failed", "{failed}");
        assert!(
            failed["response"]["error"]["message"].is_string(),
            "{failed}"
        );
        assert!(failed.get("error").is_none(), "{failed}");
    }

    // ── the cut stream's frame (mid_stream_error_tests.rs, wire_tests.rs) ─────────────────────

    /// REHOMES `crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs::test_mid_stream_generic_detail_has_no_leak_markers`
    /// (map row 498). 1.5.5: every client-facing fallback detail is free of transport and proxy
    /// vocabulary; the gemini array close and the four detail-carrying stream errors carry the
    /// generic detail; cohere's `message-end` `ERROR` frame carries no detail at all.
    /// RED: a fallback string naming `upstream`, `proxy`, a URL or a transport library.
    #[test]
    fn test_mid_stream_generic_detail_has_no_leak_markers() {
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
            .find(|decl| decl.name == "gemini")
            .and_then(|decl| decl.dialect())
            .and_then(|codec| codec.make_array_stream_framer())
            .expect("gemini frames an array stream");
        let closed = framer.finish_with_server_error(wire::MID_STREAM_GENERIC_DETAIL);
        let closed = String::from_utf8_lossy(&closed);
        assert!(closed.contains(wire::MID_STREAM_GENERIC_DETAIL), "{closed}");
        for marker in ["https://", "reqwest", "hyper", "amazonaws"] {
            assert!(!closed.contains(marker), "{marker}: {closed}");
        }
        for dialect in ["openai", "anthropic", "gemini", "responses"] {
            let bytes =
                wire::mid_stream_error_bytes(dialect, false, wire::MID_STREAM_GENERIC_DETAIL, None);
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                text.contains(wire::MID_STREAM_GENERIC_DETAIL),
                "{dialect}: {text}"
            );
        }
        let bytes =
            wire::mid_stream_error_bytes("cohere", false, wire::MID_STREAM_GENERIC_DETAIL, None);
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("message-end") && text.contains("ERROR"),
            "{text}"
        );
        assert!(!text.contains(wire::MID_STREAM_GENERIC_DETAIL), "{text}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs::test_bedrock_ingress_mid_stream_error_is_binary_exception_frame`
    /// (map row 499). 1.5.5: a bedrock caller's cut-stream error is one CRC-valid binary frame
    /// (total length, prelude CRC and message CRC all true) whose headers name an `exception`
    /// `:message-type` of `InternalServerException`, and whose JSON payload `message` is the
    /// detail.
    /// RED: SSE text over a binary stream, a bad CRC, or the detail lost from the payload.
    #[test]
    fn test_bedrock_ingress_mid_stream_error_is_binary_exception_frame() {
        let crc = busbar_plane_llm::codec::crc32::hash;
        let bytes = wire::mid_stream_error_bytes("bedrock", true, "connection reset by peer", None);
        assert!(!bytes.starts_with(b"event:") && !bytes.starts_with(b"data:"));
        let word = |at: usize| {
            u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        let total = word(0) as usize;
        assert_eq!(total, bytes.len(), "the total length");
        assert_eq!(word(8), crc(&bytes[..8]), "the prelude CRC");
        let len = bytes.len();
        assert_eq!(word(len - 4), crc(&bytes[..len - 4]), "the message CRC");
        let headers_len = word(4) as usize;
        let headers = String::from_utf8_lossy(&bytes[12..12 + headers_len]);
        for needle in [
            ":message-type",
            "exception",
            ":exception-type",
            "InternalServerException",
        ] {
            assert!(headers.contains(needle), "{needle}: {headers}");
        }
        let payload: Value =
            serde_json::from_slice(&bytes[12 + headers_len..len - 4]).expect("a JSON payload");
        assert_eq!(payload["message"], "connection reset by peer");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs::test_sse_ingress_mid_stream_error_uses_native_framing`
    /// (map row 500). 1.5.5: the cut-stream frame is each dialect's own streaming error: a bare
    /// `data:` frame for openai, cohere and gemini (cohere's a `message-end` `ERROR`); `event:
    /// error` with `error.message` for anthropic; `event: response.failed` with the stream shape
    /// (`response.status: "failed"`, `response.error.message`, no top-level `error`) for responses.
    /// RED: one dialect's framing (an `event:` line, the HTTP envelope) written for another.
    #[test]
    fn test_sse_ingress_mid_stream_error_uses_native_framing() {
        for dialect in ["openai", "cohere", "gemini"] {
            let text =
                String::from_utf8(wire::mid_stream_error_bytes(dialect, false, "boom", None))
                    .expect("text");
            assert!(text.starts_with("data: "), "{dialect}: {text}");
            assert!(!text.contains("event:"), "{dialect}: {text}");
            let data = text
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .expect("a data line");
            let frame: Value = serde_json::from_str(data).expect("JSON");
            let cohere_end = frame["type"] == "message-end"
                && frame["delta"]["finish_reason"]
                    .as_str()
                    .is_some_and(|reason| reason.starts_with("ERROR"));
            assert!(
                frame.get("error").is_some() || frame.get("message").is_some() || cohere_end,
                "{dialect}: {frame}"
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
            .find_map(|line| line.strip_prefix("data: "))
            .expect("a data line");
        let frame: Value = serde_json::from_str(data).expect("JSON");
        assert!(frame["error"]["message"].is_string(), "{frame}");

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
            .find_map(|line| line.strip_prefix("data: "))
            .expect("a data line");
        let frame: Value = serde_json::from_str(data).expect("JSON");
        assert_eq!(frame["response"]["status"], "failed", "{frame}");
        assert!(frame["response"]["error"]["message"].is_string(), "{frame}");
        assert!(frame.get("error").is_none(), "{frame}");
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs::test_client_fault_kind_mapping`
    /// (map row 501). 1.5.5: a client fault is reshaped with `context_length_exceeded` for the
    /// context-length class and `invalid_request_error` for a client error.
    /// RED: the context-length kind lost to the generic one.
    #[test]
    fn test_client_fault_kind_mapping() {
        assert_eq!(
            wire::client_fault_kind(StatusClass::ContextLength),
            "context_length_exceeded"
        );
        assert_eq!(
            wire::client_fault_kind(StatusClass::ClientError),
            "invalid_request_error"
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs::test_extract_error_message`
    /// (map row 502). 1.5.5: the far message is `error.message`, else a top-level `message`, and
    /// none for a body that is not JSON or names neither.
    /// RED: a foreign body's text lifted when it names no message.
    #[test]
    fn test_extract_error_message() {
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

    /// REHOMES `crates/busbar-llm/src/engine/tests/mid_stream_error_tests.rs::test_is_stream_content_type`
    /// (map row 503). 1.5.5: `text/event-stream` (with parameters too) and
    /// `application/vnd.amazon.eventstream` stream; `application/json` and an empty type do not.
    /// RED: a parameterized SSE type read as a whole body, or JSON read as a stream.
    #[test]
    fn test_is_stream_content_type() {
        assert!(wire::is_stream_content_type("text/event-stream"));
        assert!(wire::is_stream_content_type(EVENTSTREAM));
        assert!(wire::is_stream_content_type(
            "text/event-stream; charset=utf-8"
        ));
        assert!(!wire::is_stream_content_type("application/json"));
        assert!(!wire::is_stream_content_type(""));
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/wire_tests.rs::unknown_ingress_mid_stream_error_is_a_bare_data_frame_from_core`
    /// (map row 635). 1.5.5: a caller of a dialect the plane does not hold gets a bare `data:`
    /// frame (no `event:` line) of the agnostic envelope: `error.type: "api_error"`,
    /// `error.message` the detail.
    /// RED: some dialect's framing or vocabulary claimed for an unknown caller.
    #[test]
    fn unknown_ingress_mid_stream_error_is_a_bare_data_frame_from_core() {
        let text = String::from_utf8(wire::mid_stream_error_bytes(
            "no-such-protocol",
            false,
            "upstream vanished",
            None,
        ))
        .expect("text");
        assert!(
            text.starts_with("data: ") && text.ends_with("\n\n"),
            "{text}"
        );
        assert!(!text.contains("event:"), "{text}");
        let frame: Value =
            serde_json::from_str(text.trim_start_matches("data: ").trim_end_matches("\n\n"))
                .expect("JSON");
        assert_eq!(frame["error"]["type"], "api_error", "{frame}");
        assert_eq!(frame["error"]["message"], "upstream vanished", "{frame}");
        assert_eq!(
            text,
            String::from_utf8_lossy(&wire::agnostic_stream_error_frame("upstream vanished"))
        );
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/wire_tests.rs::status_word_golden_engine_client_fault_kind`
    /// (map row 636). 1.5.5's golden column: every class but context length is reshaped as
    /// `invalid_request_error`; context length as `context_length_exceeded`.
    /// RED: any class's kind word moved (a rate limit shaped `rate_limit_error` on a client fault).
    #[test]
    fn status_word_golden_engine_client_fault_kind() {
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

    // ── the plane's class rule and error relay against 1.5.5's (plane_reply_parity_tests.rs) ─

    /// The breaker's class rule (`busbar-kernel-breaker` `classify::normalize_raw_error`, 1.5.5's),
    /// transcribed: a mapped code (never `context_length` over a 5xx), the built-in context-length
    /// code on 400/413 only, a mapped structured type (same guard), then the status.
    fn breaker_rule(
        raw: &RawUpstreamError,
        error_map: &HashMap<String, String>,
    ) -> CanonicalSignal {
        let masks = |class: StatusClass| {
            class == StatusClass::ContextLength && (500..600).contains(&raw.http_status)
        };
        let signal = |class, provider_signal| CanonicalSignal {
            class,
            provider_signal,
            retry_after: raw.retry_after_secs,
        };
        let provider_signal = match &raw.provider_code {
            Some(code) => {
                if let Some(class) = error_map
                    .get(code)
                    .and_then(|mapped| StatusClass::parse(mapped))
                {
                    if !masks(class) {
                        return signal(class, Some(code.clone()));
                    }
                }
                if code == "context_length_exceeded"
                    && (raw.http_status == 400 || raw.http_status == 413)
                {
                    return signal(StatusClass::ContextLength, Some(code.clone()));
                }
                Some(code.clone())
            }
            None => None,
        };
        if let Some(ty) = &raw.structured_type {
            if let Some(class) = error_map
                .get(ty)
                .and_then(|mapped| StatusClass::parse(mapped))
            {
                if !masks(class) {
                    return signal(class, provider_signal.or_else(|| Some(ty.clone())));
                }
            }
        }
        let class = match raw.http_status {
            401 | 403 => StatusClass::Auth,
            429 => StatusClass::RateLimit,
            408 => StatusClass::Timeout,
            529 => StatusClass::Overloaded,
            500..=599 => StatusClass::ServerError,
            0 => StatusClass::Network,
            // A true 4xx, and a 2xx/3xx reaching the error path: the caller's side.
            _ => StatusClass::ClientError,
        };
        signal(class, provider_signal)
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/plane_reply_parity_tests.rs::the_planes_class_rule_is_the_breakers`
    /// (map row 559). 1.5.5: over 2 error maps x 8 provider codes x 8 structured types x 15
    /// statuses x 2 retry-afters = 3840 raw errors, the plane's `failure::normalize` places each
    /// in the class, provider signal and retry-after the breaker's rule does.
    /// RED: any cell where the plane's copy of the rule drifts from the breaker's (a mapped
    /// `context_length` masking a 5xx, the retry-after dropped, a type winning over a code).
    #[test]
    fn the_planes_class_rule_is_the_breakers() {
        let maps: Vec<HashMap<String, String>> = vec![
            HashMap::new(),
            map(&[
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
            ]),
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
        for error_map in &maps {
            for code in codes {
                for ty in types {
                    for status in statuses {
                        for retry in [None, Some(7)] {
                            let mut error = raw(status, code, ty);
                            error.retry_after_secs = retry;
                            assert_eq!(
                                normalize(status, &error, error_map),
                                breaker_rule(&error, error_map),
                                "{error:?} under {error_map:?}"
                            );
                            checked += 1;
                        }
                    }
                }
            }
        }
        assert_eq!(checked, 2 * 8 * 8 * 15 * 2);
    }

    /// The far head every legacy parity fixture answered with.
    const PARITY_HEAD: &[(&[u8], &[u8])] = &[
        (b"content-type", b"application/json"),
        (b"request-id", b"req_far0001"),
        (b"x-amzn-requestid", b"amzn-far-0001"),
    ];

    /// REHOMES `crates/busbar-llm/src/engine/tests/plane_reply_parity_tests.rs::a_far_end_error_reads_the_same_through_the_plane`
    /// (map row 564). 1.5.5, for every dialect pair and each legacy fixture (400
    /// `invalid_request_error`, 422 `{"message":"bad field"}`, 401 `authentication_error`):
    /// within one dialect a client fault is the far status, every far head field and the far bytes
    /// exactly; across dialects it is the far status in the caller's own envelope (kind
    /// `invalid_request_error`, the far message), its head no far field; a refused deployment
    /// credential is the caller dialect's own refusal (its status, kind and sentence), never the
    /// far message.
    /// RED: a foreign body relayed across dialects, a far id leaked into a reshaped head, a
    /// same-dialect fault rewritten, or a far 401 answered with the far message.
    #[test]
    fn a_far_end_error_reads_the_same_through_the_plane() {
        entropy();
        let fixtures: [(u16, &[u8], Option<&str>); 3] = [
            (
                400,
                br#"{"error":{"message":"max_tokens is too large","type":"invalid_request_error"}}"#,
                Some("max_tokens is too large"),
            ),
            (422, br#"{"message":"bad field"}"#, Some("bad field")),
            (
                401,
                br#"{"error":{"message":"invalid x-api-key","type":"authentication_error"}}"#,
                None,
            ),
        ];
        let mut checked = 0;
        for far in SIX {
            for caller in SIX {
                let (arrived, lane) = ask(caller, far, false);
                let ctx = reply_ctx(&arrived, &lane, false);
                for (status, body, message) in fixtures {
                    let read = answer(&ctx, status, PARITY_HEAD, &[body], false);
                    let what = format!("{caller}<-{far} {status}");
                    assert_eq!(
                        read.value("content-length").as_deref(),
                        Some(read.body.len().to_string().as_str()),
                        "{what}"
                    );
                    match message {
                        Some(_) if caller == far => {
                            assert_eq!(read.status, status, "{what}");
                            assert_eq!(read.body, body, "{what}: verbatim");
                            assert_eq!(
                                read.value("request-id").as_deref(),
                                Some("req_far0001"),
                                "{what}"
                            );
                            assert_eq!(
                                read.value("x-amzn-requestid").as_deref(),
                                Some("amzn-far-0001"),
                                "{what}"
                            );
                        }
                        Some(message) => {
                            assert_eq!(read.status, status, "{what}");
                            assert_eq!(
                                without_minted_id(read.json()),
                                without_minted_id(own_envelope(
                                    caller,
                                    status,
                                    "invalid_request_error",
                                    message
                                )),
                                "{what}"
                            );
                            assert!(
                                read.fields.iter().all(|(_, value)| value != b"req_far0001"
                                    && value != b"amzn-far-0001"),
                                "{what}: {:?}",
                                read.fields
                            );
                        }
                        None => {
                            let decl = busbar_plane_llm::codec::DECLS
                                .iter()
                                .find(|decl| decl.name == caller)
                                .expect("a dialect");
                            let (own_status, kind) = decl.auth_failure_status_and_kind;
                            assert_eq!(read.status, own_status.as_u16(), "{what}");
                            assert_eq!(
                                without_minted_id(read.json()),
                                without_minted_id(own_envelope(
                                    caller,
                                    own_status.as_u16(),
                                    kind,
                                    decl.auth_failure_message
                                )),
                                "{what}"
                            );
                            assert!(!read.text().contains("invalid x-api-key"), "{what}");
                        }
                    }
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 3 * 36);
    }

    /// REHOMES `crates/busbar-llm/src/engine/tests/plane_reply_parity_tests.rs::a_far_end_errors_relay_is_the_engines`
    /// (map row 565). 1.5.5, for 5 far statuses (429, 500, 503, 504, 529) x 36 dialect pairs (180
    /// cases): the relay the walk ends on keeps the far status; within one dialect its body is the
    /// far body byte for byte; across dialects it is the caller's own envelope with the kind 1.5.5
    /// gave that status (429 `rate_limit_error`, 500 and 529 `api_error`, 503 `overloaded`, 504
    /// `timeout`) and the far message `slow down`, under `application/json`.
    /// RED: a foreign body relayed across dialects, a status rewritten, or a kind moved.
    #[test]
    fn a_far_end_errors_relay_is_the_engines() {
        entropy();
        let body = br#"{"error":{"message":"slow down"}}"#;
        let mut checked = 0;
        for (status, kind) in [
            (429u16, "rate_limit_error"),
            (500, "api_error"),
            (503, "overloaded"),
            (504, "timeout"),
            (529, "api_error"),
        ] {
            for far in SIX {
                for caller in SIX {
                    let far_error = FarError {
                        status,
                        head: JSON_HEAD,
                        body,
                    };
                    let relayed = failure::relay(caller, far, &far_error);
                    assert_eq!(relayed.status, status, "{caller}<-{far} {status}");
                    if caller == far {
                        assert_eq!(relayed.body, body, "{caller}: verbatim");
                    } else {
                        assert_eq!(
                            field(&relayed.fields, "content-type"),
                            Some(b"application/json".as_slice()),
                            "{caller}<-{far} {status}"
                        );
                        let envelope: Value = serde_json::from_slice(&relayed.body).expect("JSON");
                        assert_eq!(
                            without_minted_id(envelope),
                            without_minted_id(own_envelope(caller, status, kind, "slow down")),
                            "{caller}<-{far} {status}"
                        );
                    }
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 5 * 36);
    }
}
