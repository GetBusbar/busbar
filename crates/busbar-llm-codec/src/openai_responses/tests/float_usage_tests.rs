// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FLOAT-ENCODED USAGE COUNTS, PROVEN THROUGH `read_count_u64`.
//!
//! `serde_json::Value::as_u64()` returns `None` for ANY float-backed number, `27.0` included. The
//! OpenAI Responses dialect's usage reads used to go through that bare idiom with `.unwrap_or(0)`,
//! so a provider (or an OpenAI-compatible proxy) that spells a count as a float had a real count
//! recorded as a billed ZERO. These tests pin realistic float-encoded wire payloads through every
//! usage read site: the truncated-stream recovery path (`recover_truncated_usage`), the streaming
//! terminal `response.completed` event, the buffered `read_response`, and the cached/reasoning
//! sub-buckets (`read_cached_tokens`, `output_tokens_details.reasoning_tokens`) on both paths.

use super::*;
use crate::ir::StreamDecodeState;

/// THE TRUNCATED-STREAM RECOVERY PATH. `recover_truncated_usage` parses the trailing `usage` object
/// independently of the main streaming/buffered decode, so it needed its own proof.
#[test]
fn recover_truncated_usage_reads_float_encoded_counts() {
    let reader = ResponsesReader;
    let tail = br#"..."}],"usage":{"input_tokens":1000.0,"output_tokens":50.0,"input_tokens_details":{"cached_tokens":200.0}}}"#;
    let usage = reader
        .recover_truncated_usage(tail)
        .expect("usage tail must be recoverable");
    assert_eq!(
        usage.input, 800,
        "input_tokens(1000.0) - cached_tokens(200.0), both float-spelled"
    );
    assert_eq!(usage.output, 50, "output_tokens(50.0), float-spelled");
    assert_eq!(usage.cache_read, Some(200));
}

/// THE STREAMING PATH: the terminal `response.completed` event with EVERY usage field
/// float-spelled, including the cached and reasoning sub-buckets. A fix that only covers the
/// buffered response would leave a streamed request reporting these as zero while `stream: false`
/// reported them correctly.
#[test]
fn streaming_terminal_reads_float_encoded_counts() {
    let reader = ResponsesReader;
    let mut state = StreamDecodeState::default();
    let completed = serde_json::json!({
        "response": {
            "status": STATUS_COMPLETED,
            "usage": {
                "input_tokens": 1000.0,
                "output_tokens": 50.0,
                "input_tokens_details": {"cached_tokens": 200.0},
                "output_tokens_details": {"reasoning_tokens": 400.0}
            }
        }
    });
    let events = reader.read_response_events(EVT_RESPONSE_COMPLETED, &completed, &mut state);
    let usage = events
        .into_iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("response.completed must emit a MessageDelta carrying usage");
    assert_eq!(
        usage.input_tokens, 800,
        "input_tokens(1000.0) - cached_tokens(200.0), streamed terminal, both float-spelled"
    );
    assert_eq!(
        usage.output_tokens, 50,
        "output_tokens(50.0), streamed terminal"
    );
    assert_eq!(usage.cache_read_input_tokens, Some(200));
    assert_eq!(usage.detail.reasoning_tokens, Some(400));
}

/// THE BUFFERED PATH. The identical float-spelled usage object on a non-streamed `response` body
/// must read exactly the same as the streaming terminal above.
#[test]
fn buffered_read_response_reads_float_encoded_counts() {
    let body = serde_json::json!({
        "id": "resp_float1",
        "object": OBJ_RESPONSE,
        "created_at": 1_700_000_000_u64,
        "status": STATUS_COMPLETED,
        "model": "gpt-4o",
        "output": [
            {
                "type": ITEM_TYPE_MESSAGE,
                "role": "assistant",
                "content": [{"type": CONTENT_TYPE_OUTPUT_TEXT, "text": "hi"}]
            }
        ],
        "usage": {
            "input_tokens": 1000.0,
            "output_tokens": 50.0,
            "input_tokens_details": {"cached_tokens": 200.0},
            "output_tokens_details": {"reasoning_tokens": 400.0}
        }
    });
    let ir = ResponsesReader.read_response(&body).expect("read_response");
    assert_eq!(
        ir.usage.input_tokens, 800,
        "input_tokens(1000.0) - cached_tokens(200.0), buffered, both float-spelled"
    );
    assert_eq!(ir.usage.output_tokens, 50, "output_tokens(50.0), buffered");
    assert_eq!(ir.usage.cache_read_input_tokens, Some(200));
    assert_eq!(ir.usage.detail.reasoning_tokens, Some(400));
}
