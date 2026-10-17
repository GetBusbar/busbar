// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The invoke envelope: an Anthropic Messages exchange carried over Bedrock's `InvokeModel` and
//! `InvokeModelWithResponseStream` (the owner's 2026-09-29 compat scope; ARCHITECT 2026-10-14).
//!
//! RED: before the envelope, `models.<m>.protocol: bedrock-invoke` was refused as an unknown
//! protocol, so none of these builds or holds.

use busbar_contract::operation::OpVerb;
use busbar_plane_llm::codec::eventstream::{encode_exception_frame, encode_frame};
use busbar_plane_llm::exchange::arrive::{arrive, Arrived};
use busbar_plane_llm::exchange::attempt::{build, stream_intent, upstream_path, FarRequest};
use busbar_plane_llm::exchange::handler_of;
use busbar_plane_llm::exchange::invoke::{self, Transcoder};
use busbar_plane_llm::exchange::reply::{At, Reply, ReplyCtx, Verdict};
use busbar_plane_llm::exchange::shaping::Shaping;
use serde_json::{json, Value};

/// The codec host these tests hand the plane: the OS CSPRNG and the system clock in whole seconds,
/// read the way the kernel's host reads them.
struct TestHost;

impl busbar_contract::codec::CodecHost for TestHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        getrandom::fill(out).is_ok()
    }

    fn wall_clock_now(&self) -> Option<u64> {
        Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
    }
}

/// The handle every codec call here is handed.
const HOST: &dyn busbar_contract::codec::CodecHost = &TestHost;

/// A Bedrock provider (its own dialect, SigV4), one model served over it in Converse and one over
/// the invoke envelope, and an Anthropic provider for the carried dialect's own lane.
fn shaping() -> Shaping {
    Shaping::from_settings(&json!({
        "providers": {
            "aws": { "protocol": "bedrock", "base_url": "https://bedrock-runtime.us-east-1.amazonaws.com" },
            "ant": { "protocol": "anthropic", "base_url": "https://anthropic.example" }
        },
        "models": {
            "claude-converse": { "provider": "aws", "upstream_model": "anthropic.claude-3-5-sonnet-20240620-v1:0" },
            "claude-invoke": {
                "provider": "aws",
                "protocol": "bedrock-invoke",
                "upstream_model": "anthropic.claude-3-5-sonnet-20240620-v1:0",
                "default_max_tokens": 256
            },
            "claude": { "provider": "ant" }
        },
        "pools": { "p": { "members": ["claude-invoke"] } }
    }))
    .expect("reads")
}

type Head = Vec<(&'static [u8], &'static [u8])>;

fn arrived(body: &str, extra: &[(&'static [u8], &'static [u8])]) -> (Arrived, Head) {
    let mut h: Head = vec![
        (&b"content-type"[..], &b"application/json"[..]),
        (&b"anthropic-version"[..], &b"2023-06-01"[..]),
    ];
    h.extend_from_slice(extra);
    let a = arrive("POST", "/v1/messages", &h, body.as_bytes(), &()).expect("arrives");
    (a, h)
}

fn field<'a>(r: &'a FarRequest, name: &str) -> Vec<&'a [u8]> {
    r.fields
        .iter()
        .filter(|(n, _)| n == name)
        .map(|(_, v)| v.as_slice())
        .collect()
}

#[test]
fn a_model_naming_the_envelope_is_served_in_the_carried_dialect_over_it() {
    let s = shaping();
    let lane = s.lane("claude-invoke").expect("the lane");
    assert_eq!(lane.dialect, invoke::CARRIED);
    assert!(lane.invoke);
    assert!(
        lane.statics.is_empty(),
        "the envelope states the API version in the body, never as a field"
    );
    let sibling = s.lane("claude-converse").expect("the sibling");
    assert_eq!(
        sibling.dialect, "bedrock",
        "a model naming no protocol keeps its provider's"
    );
    assert!(!sibling.invoke);
    assert!(
        !s.lane("claude")
            .expect("the carried dialect's own lane")
            .invoke
    );
}

#[test]
fn a_provider_never_defaults_to_the_envelope() {
    let refused = Shaping::from_settings(&json!({
        "providers": { "aws": { "protocol": "bedrock-invoke", "base_url": "https://x.example" } },
        "models": { "m": { "provider": "aws" } }
    }))
    .unwrap_err();
    assert_eq!(
        refused,
        "provider 'aws' uses unknown protocol 'bedrock-invoke'"
    );
}

#[test]
fn the_target_is_the_models_invoke_operation() {
    let s = shaping();
    let lane = s.lane("claude-invoke").expect("the lane");
    assert_eq!(
        upstream_path(lane, OpVerb::CHAT, false).as_deref(),
        Some("/model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke")
    );
    assert_eq!(
        upstream_path(lane, OpVerb::CHAT, true).as_deref(),
        Some("/model/anthropic.claude-3-5-sonnet-20240620-v1:0/invoke-with-response-stream")
    );
}

#[test]
fn a_carried_dialect_caller_is_relayed_inside_the_envelope() {
    let body = r#"{"model":"claude-invoke","max_tokens":64,"stream":true,"messages":[{"role":"user","content":"hi"}]}"#;
    let (a, h) = arrived(
        body,
        &[(
            &b"anthropic-beta"[..],
            &b"prompt-caching-2024-07-31, output-128k-2025-02-19"[..],
        )],
    );
    let r = build(HOST, &a, &h, &shaping(), "p", "claude-invoke").expect("built");
    assert!(
        r.target.ends_with("/invoke-with-response-stream"),
        "{}",
        r.target
    );
    assert!(r
        .target
        .starts_with("/model/anthropic.claude-3-5-sonnet-20240620-v1"));
    let sent: Value = serde_json::from_slice(&r.body).expect("json");
    assert_eq!(sent.get("model"), None, "the model rides the target");
    assert_eq!(sent.get("stream"), None, "the operation says it streams");
    assert_eq!(sent["anthropic_version"], "bedrock-2023-05-31");
    assert_eq!(
        sent["anthropic_beta"],
        json!(["prompt-caching-2024-07-31", "output-128k-2025-02-19"])
    );
    assert_eq!(sent["max_tokens"], 64);
    assert!(
        String::from_utf8_lossy(&r.body).contains(r#""messages":[{"role":"user","content":"hi"}]"#),
        "the caller's members go out as its own bytes"
    );
    assert!(field(&r, "anthropic-version").is_empty());
    assert!(field(&r, "anthropic-beta").is_empty());
    assert_eq!(field(&r, "accept"), [invoke::EVENTSTREAM.as_bytes()]);
    assert!(!r.pristine);
}

#[test]
fn a_whole_answer_is_asked_for_on_the_plain_operation() {
    let body = r#"{"model":"claude-invoke","max_tokens":64,"messages":[]}"#;
    let (a, h) = arrived(body, &[]);
    let r = build(HOST, &a, &h, &shaping(), "p", "claude-invoke").expect("built");
    assert!(r.target.ends_with("/invoke"), "{}", r.target);
    let sent: Value = serde_json::from_slice(&r.body).expect("json");
    assert_eq!(sent.get("anthropic_beta"), None, "no beta flags, no member");
    assert_ne!(field(&r, "accept"), [invoke::EVENTSTREAM.as_bytes()]);
}

#[test]
fn the_body_edit_keeps_every_other_byte() {
    let edited = invoke::body(
        br#"{"model":"m","stream":false,"system":"s",  "max_tokens":1}"#,
        &[],
    )
    .expect("an object");
    let text = String::from_utf8(edited).expect("utf-8");
    assert!(
        text.contains(r#""system":"s""#) && text.contains(r#""max_tokens":1"#),
        "{text}"
    );
    assert!(
        !text.contains(r#""model""#) && !text.contains(r#""stream""#),
        "{text}"
    );
    assert!(
        text.contains(r#""anthropic_version":"bedrock-2023-05-31""#),
        "{text}"
    );
    assert_eq!(invoke::body(b"[1]", &[]), None, "not an object");
}

/// One Anthropic stream event as Bedrock frames it: a `chunk` whose `bytes` are the event, base64.
fn chunk(event: &Value) -> Vec<u8> {
    let raw = serde_json::to_vec(event).expect("json");
    let payload = json!({ "bytes": busbar_contract::media::base64_encode(&raw) });
    encode_frame("chunk", &serde_json::to_vec(&payload).expect("json"))
}

fn events() -> Vec<Value> {
    vec![
        json!({"type":"message_start","message":{"id":"msg_1","type":"message","role":"assistant","model":"claude","content":[],"stop_reason":null,"usage":{"input_tokens":11,"output_tokens":1}}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"pong"}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":7}}),
        json!({"type":"message_stop","amazon-bedrock-invocationMetrics":{"inputTokenCount":11,"outputTokenCount":7}}),
    ]
}

#[test]
fn a_stream_is_reframed_into_the_carried_dialects_events_byte_for_byte() {
    let wire: Vec<u8> = events().iter().flat_map(chunk).collect();
    let mut want = Vec::new();
    for e in events() {
        want.extend_from_slice(
            format!("event: {}\ndata: ", e["type"].as_str().unwrap()).as_bytes(),
        );
        want.extend_from_slice(&serde_json::to_vec(&e).unwrap());
        want.extend_from_slice(b"\n\n");
    }
    for step in [1, 7, 64, wire.len()] {
        let mut t = Transcoder::new();
        let got: Vec<u8> = wire.chunks(step).flat_map(|c| t.feed(c)).collect();
        assert_eq!(
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want),
            "fed {step} bytes at a time"
        );
    }
}

#[test]
fn a_mid_stream_exception_ends_the_stream_with_the_carried_dialects_error_event() {
    let mut wire = chunk(&events()[0]);
    wire.extend(encode_exception_frame("ThrottlingException", "slow down"));
    wire.extend(chunk(&events()[1]));
    let out = String::from_utf8(Transcoder::new().feed(&wire)).expect("utf-8");
    assert!(out.starts_with("event: message_start\n"), "{out}");
    assert!(
        out.ends_with("event: error\ndata: {\"error\":{\"message\":\"slow down\",\"type\":\"rate_limit_error\"},\"type\":\"error\"}\n\n"),
        "{out}"
    );
    assert!(
        !out.contains("content_block_start"),
        "nothing after the exception: {out}"
    );
}

#[test]
fn a_refusal_is_restated_in_the_carried_dialects_error_envelope() {
    let head: &[(&[u8], &[u8])] = &[(
        b"x-amzn-ErrorType",
        b"ValidationException:http://internal.amazon.com/coral/com.amazon.bedrock/",
    )];
    let body = invoke::error_body(head, br#"{"message":"max_tokens: field required"}"#);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("json"),
        json!({"type":"error","error":{"type":"invalid_request_error","message":"max_tokens: field required"}})
    );
    let throttled: &[(&[u8], &[u8])] = &[(b"x-amzn-errortype", b"ThrottlingException")];
    let body = invoke::error_body(throttled, br#"{"message":"Too many requests"}"#);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).expect("json")["error"]["type"],
        "rate_limit_error"
    );
}

/// THE MONEY READ: a streamed answer over the envelope reaches the carried dialect's caller as that
/// dialect's own events, and the units it reports are the carried dialect's usage (11 in, 7 out),
/// exactly as on that dialect's own lane.
#[test]
fn a_streamed_answer_meters_the_carried_dialects_usage() {
    let s = shaping();
    let body = r#"{"model":"claude-invoke","max_tokens":64,"stream":true,"messages":[]}"#;
    let (a, _) = arrived(body, &[]);
    let lane = s.lane("claude-invoke").expect("the lane");
    let ctx = ReplyCtx {
        arrived: &a,
        lane,
        intent: stream_intent(handler_of(&a).expect("a handler"), a.parsed.as_ref()),
        passthrough: false,
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
    };
    let head: &[(&[u8], &[u8])] = &[(b"content-type", invoke::EVENTSTREAM.as_bytes())];
    let mut reply = Reply::new(HOST, &ctx, 200, head);
    let wire: Vec<u8> = events().iter().flat_map(chunk).collect();
    let pieces: Vec<&[u8]> = wire.chunks(50).collect();
    let mut out = Vec::new();
    let mut last_piece = None;
    for (i, p) in pieces.iter().enumerate() {
        let last = i + 1 == pieces.len();
        let piece = reply.feed(HOST, &ctx, p, last, At::default());
        if let Some(h) = &piece.head {
            let ct = h
                .fields
                .iter()
                .find(|(n, _)| n == "content-type")
                .map(|(_, v)| v.clone());
            assert_eq!(
                ct.as_deref(),
                Some(&b"text/event-stream"[..]),
                "the carried dialect's stream"
            );
        }
        out.extend_from_slice(&piece.bytes);
        if last {
            last_piece = Some((piece.units.clone(), piece.verdict, piece.done));
        }
    }
    let (units, verdict, done) = last_piece.expect("a last piece");
    assert!(done);
    assert_eq!(verdict, Verdict::Ok);
    assert_eq!((units.tokens_in, units.tokens_out), (11, 7), "{units:?}");
    let text = String::from_utf8_lossy(&out);
    assert!(
        text.contains("event: content_block_delta") && text.contains("pong"),
        "{text}"
    );
}

/// THE KERNEL NEVER SEES THE ENVELOPE (ARCHITECT 2026-10-14 condition 3; Law 0): it is no codec
/// protocol this plane declares, so the protocols the composition root installs, and with them the
/// previous release's "must be one of" list a provider's unknown protocol is refused with, stay
/// exactly 1.5.5's six in 1.5.5's order (oracle cell `boot.refusal|BOOT-020|validate`; the binary's
/// own `validate_unknown_protocol_lists_only_the_configured_planes_dialects` pins the line).
#[test]
fn the_envelope_is_no_declared_protocol_and_the_1_5_5_list_is_unchanged() {
    let declared: Vec<&str> = busbar_plane_llm::codec::DECLS
        .iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(
        declared,
        [
            "anthropic",
            "openai",
            "gemini",
            "bedrock",
            "responses",
            "cohere"
        ]
    );
    assert!(!declared.contains(&invoke::PROTOCOL));
}
