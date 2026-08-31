// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/handlers/chat.rs`.

use super::*;

/// The codecs are REAL: an openai chat request round-trips wire → IrReq::Chat → wire through the
/// openai instance, like any other operation's codec.
#[test]
fn chat_codec_round_trips_openai_request() {
    let chat = ChatOperation("openai");
    let wire = br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
    let ir = chat.read_request(wire, "application/json").expect("parses");
    assert!(matches!(ir, _));
    let back = chat.write_request(&ir);
    let v: Value = serde_json::from_slice(&back).unwrap();
    // The writer may emit the bare-string or block-array content form — both are valid OpenAI.
    let content = &v["messages"][0]["content"];
    let text = content
        .as_str()
        .map(str::to_string)
        .or_else(|| content[0]["text"].as_str().map(str::to_string));
    assert_eq!(text.as_deref(), Some("hi"), "content survived: {v}");
}

/// Response side too: egress wire → IrResp::Chat → caller-dialect wire.
#[test]
fn chat_codec_round_trips_openai_response() {
    let chat = ChatOperation("openai");
    let wire = br#"{"id":"c","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"MOCKTEXT"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":3,"total_tokens":14}}"#;
    let ir = chat.read_response(wire).expect("parses");
    let out = chat.write_response(&ir);
    let v: Value = serde_json::from_slice(&out.bytes).unwrap();
    assert_eq!(v["choices"][0]["message"]["content"], "MOCKTEXT");
    assert_eq!(v["usage"]["prompt_tokens"], 11);
}

/// Cross-protocol through the IR: openai request in, anthropic wire out — the same bridge shape
/// every other operation uses.
#[test]
fn chat_codec_bridges_openai_to_anthropic() {
    let openai = ChatOperation("openai");
    let anthropic = ChatOperation("anthropic");
    let ir = openai
        .read_request(
            br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
            "application/json",
        )
        .unwrap();
    let wire = anthropic.write_request(&ir);
    let v: Value = serde_json::from_slice(&wire).unwrap();
    assert_eq!(v["messages"][0]["content"][0]["text"], "hi");
}

/// A same-protocol 2xx body chat's `extract_usage` cannot decode must still bill 0 tokens
/// (`None`) — the fail-safe outcome is unchanged — but it must now warn, like every other
/// operation's default `extract_usage` does on the identical failure. Before the fix, chat's
/// override collapsed this to `None` via a silent `Option` chain with no log at all.
#[test]
fn extract_usage_warns_on_undecodable_body_and_still_bills_zero() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let chat = ChatOperation("openai");
    // Valid JSON, but not a shape the openai chat reader accepts as a response (no
    // `choices`/`object`) — a same-protocol 2xx body that fails to decode.
    let body = br#"{"not":"a chat completion"}"#;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let usage =
        tracing::subscriber::with_default(subscriber, || chat.extract_usage("openai", body));

    assert_eq!(usage, None, "an undecodable body still bills 0 tokens");
    // Distinguishing text (not just the substring common to all three sites) — this is the
    // `read_response` decode-failure site specifically, proving the 3-site design actually
    // fires the site its cause maps to (a single generic log would pass this test too, but
    // could not tell this failure apart from the other two in an operator's log stream).
    assert!(
        cap.contains("read_response failed to decode")
            && cap.contains("billing 0 tokens for this request"),
        "an undecodable same-protocol 2xx body must warn at the decode-failure site: {:?}",
        cap.messages()
    );
}

/// Malformed JSON hits the earlier parse step of the same collapse — must warn too, at its
/// OWN site (distinct message from the decode-failure site above).
#[test]
fn extract_usage_warns_on_invalid_json_and_still_bills_zero() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let chat = ChatOperation("openai");
    // Include a value ("hunter2") that must NEVER reach the log — `crate::json::parse`'s raw
    // (sonic-rs) error embeds a fragment of the offending bytes, so the parse-failure site
    // must log via `parse_err_log` (byte count only), not the raw error.
    let body = br#"not json at all, but say hunter2 anyway"#;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let usage =
        tracing::subscriber::with_default(subscriber, || chat.extract_usage("openai", body));

    assert_eq!(usage, None);
    assert!(
        cap.contains("failed to parse a same-protocol 2xx body as JSON")
            && cap.contains("billing 0 tokens for this request"),
        "invalid JSON in a same-protocol 2xx body must warn at the parse-failure site: {:?}",
        cap.messages()
    );
    assert!(
        !cap.contains("hunter2"),
        "the parse-failure log must never echo a fragment of the offending body: {:?}",
        cap.messages()
    );
}

/// An unresolvable ingress protocol hits the first step of the same collapse — must warn too,
/// at its OWN site. (Today's sole production caller, `proxy/response_body.rs`, always resolves
/// `ingress_protocol` before storing it, so this arm is defensive rather than
/// currently-reachable in production — but `extract_usage` is a trait method over an
/// arbitrary `&str`, and a caller that skips that normalization must not bill 0 tokens with
/// no diagnostic either.)
#[test]
fn extract_usage_warns_on_unknown_protocol_and_still_bills_zero() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let chat = ChatOperation("openai");
    let body = br#"{"id":"c","object":"chat.completion","created":0,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let usage = tracing::subscriber::with_default(subscriber, || {
        chat.extract_usage("not-a-real-protocol", body)
    });

    assert_eq!(usage, None);
    assert!(
        cap.contains("unknown ingress protocol")
            && cap.contains("billing 0 tokens for this request"),
        "an unresolvable ingress protocol must warn at the protocol-lookup site: {:?}",
        cap.messages()
    );
}
