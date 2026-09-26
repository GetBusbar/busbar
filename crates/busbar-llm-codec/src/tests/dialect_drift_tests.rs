// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DIALECT-HELPER DRIFT GUARD (#83a SD-3): the plane's own copies of the shared wire helpers
//! answer exactly what the host's originals answer — the same constants, the same error codes, the
//! same SSE frame probes, parses and writes, and the same `usage` strips — over one fixture set, so
//! moving a dialect onto its own copy changes no byte it reads or writes.

use super::*;
use busbar_kernel::proto as host;

#[test]
fn the_constants_are_the_host_constants() {
    assert_eq!(CODE_INVALID_API_KEY, host::CODE_INVALID_API_KEY);
    assert_eq!(
        PROVIDER_SIGNAL_CONTEXT_LENGTH,
        host::PROVIDER_SIGNAL_CONTEXT_LENGTH
    );
    assert_eq!(MESSAGE_NAMES_SENTINEL, host::MESSAGE_NAMES_SENTINEL);
    assert_eq!(SSE_DONE_SENTINEL, host::SSE_DONE_SENTINEL);
    assert_eq!(SSE_DONE_FRAME, host::SSE_DONE_FRAME);
    assert_eq!(HDR_AUTHORIZATION, host::HDR_AUTHORIZATION);
    assert_eq!(BASE62_ALPHABET, host::BASE62_ALPHABET);
    assert_eq!(BASE62_REJECT_THRESHOLD, host::BASE62_REJECT_THRESHOLD);
}

#[test]
fn error_codes_and_prose_scans_agree() {
    for t in [
        "authentication_error",
        "insufficient_quota",
        "invalid_request_error",
        "permission_error",
        "not_found_error",
        "rate_limit_error",
        "server_error",
        "api_error",
        "overloaded_error",
        "something_else",
        "",
    ] {
        assert_eq!(bearer_error_code(t), host::bearer_error_code(t), "{t}");
    }
    for text in [
        "this model's maximum context length is 8192 tokens",
        "context length exceeded",
        "please reduce the length of the messages",
        "input exceeds the context window",
        "prompt exceeds token limit",
        "maximum number of tokens allowed per day",
        "exceeds quota",
        "",
    ] {
        assert_eq!(
            context_length_prose_scan(text),
            host::context_length_prose_scan(text),
            "{text}"
        );
    }
}

fn frames() -> Vec<&'static [u8]> {
    vec![
        b"event: message_start\ndata: {\"a\":1}\n\n",
        b"data: {\"a\":1}\n\n",
        b"event: a\r\nevent: b\r\ndata: x\r\ndata: y\r\n\r\n",
        b"event: message_start\rdata: {}\r\r",
        b"event: only\n\n",
        b"data:no-space\n\n",
        b"data: [DONE]\n\n",
        b"\xff\xfe",
        b"",
    ]
}

#[test]
fn sse_probes_parses_and_writes_agree() {
    for frame in frames() {
        assert_eq!(
            sse_event_type(frame),
            host::sse_event_type(frame),
            "{frame:?}"
        );
        assert_eq!(
            parse_sse_frame(frame),
            host::parse_sse_frame(frame),
            "{frame:?}"
        );
    }
    for (event, data) in [
        (
            "message_delta",
            serde_json::json!({"usage": {"output_tokens": 3}}),
        ),
        ("", serde_json::json!({"choices": [], "s": "é \"q\""})),
        ("x", serde_json::json!(null)),
    ] {
        let (mut plane, mut hostv) = (Vec::new(), Vec::new());
        write_sse_frame(&mut plane, event, &data);
        host::write_sse_frame(&mut hostv, event, &data);
        assert_eq!(plane, hostv, "{event}");
    }
}

#[test]
fn value_projections_and_the_usage_strip_agree() {
    for v in [
        serde_json::json!("{not json"),
        serde_json::json!({"a": [1, 2, {"b": "c"}]}),
        serde_json::json!(null),
        serde_json::json!(1.5),
    ] {
        assert_eq!(
            tool_arguments_to_string(&v),
            host::tool_arguments_to_string(&v)
        );
    }
    for messages in [
        vec![serde_json::json!({"role": "user", "content": "hi"})],
        vec![
            serde_json::json!({"role": "user", "content": "hi"}),
            serde_json::json!({"role": "assistant", "content": [{"type": "text"}]}),
        ],
        vec![],
    ] {
        assert_eq!(
            rewrite_text_pairs(&messages),
            host::rewrite_text_pairs(&messages)
        );
    }
    for json in [
        r#"{"id":"x","usage":null,"choices":[]}"#,
        r#"{"usage":{"prompt_tokens":1},"id":"x"}"#,
        r#"{"id":"x","choices":[{"delta":{"content":"\"usage\":null"}}],"usage":null}"#,
        r#"{"a":{"usage":null}}"#,
        r#"{"usage":1,"usage":2}"#,
        r#"  { "usage" : [1,{"x":"}"}] , "k":true }"#,
        r#"[1,2]"#,
        r#"{"unterminated":"#,
        "",
    ] {
        assert_eq!(
            strip_top_level_usage_member(json),
            host::strip_top_level_usage_member(json),
            "{json}"
        );
    }
}
