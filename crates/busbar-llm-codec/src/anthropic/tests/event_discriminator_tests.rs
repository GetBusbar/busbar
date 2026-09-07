// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EVENT NAME IS IN THE BODY, NOT ONLY IN THE TRANSPORT.
//!
//! The pinned Anthropic OpenAPI document types the stream as `MessageStreamEvent`, a `oneOf` with
//!
//!   discriminator: { propertyName: "type", mapping: { message_start: …, message_delta: …,
//!                    message_stop: …, content_block_start: …, content_block_delta: …,
//!                    content_block_stop: … } }
//!
//! The DISCRIMINATOR IS THE BODY'S OWN `type` FIELD. The SSE `event:` line is a transport
//! convenience that repeats it; the spec does not make it the identity of the event, and every
//! `MessageStreamEvent` body carries `type` as a required property.
//!
//! This reader dispatched on the `event:` line alone. A frame that arrives as a bare `data:` — an
//! upstream, gateway or SDK relay that emits the JSON without repeating the name on an `event:`
//! line — matched nothing, produced zero IR events, and so contributed nothing to the stream's
//! usage accumulator. The `message_delta` frame is the one that carries `usage.output_tokens`, so
//! the whole stream billed zero.

use super::*;

/// The frame the money rides on: `message_delta` with no `event:` line. Dispatched off the body's
/// own discriminator, it must decode to the terminal delta with its usage.
#[test]
fn a_message_delta_with_no_event_line_still_bills() {
    let data = serde_json::json!({
        "type": "message_delta",
        "delta": { "stop_reason": "end_turn" },
        "usage": { "input_tokens": 300, "output_tokens": 120 }
    });
    let mut state = crate::ir::StreamDecodeState::default();
    // `""` is what `parse_sse_frame` reports for a frame with only a `data:` line.
    let events = AnthropicReader.read_response_events("", &data, &mut state);
    let usage = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("the body names itself `message_delta`; it must decode as one");
    assert_eq!(usage.output_tokens, 120);
    assert_eq!(usage.input_tokens, 300);
}

/// Every name in the spec's discriminator mapping resolves from the body alone, so no part of the
/// stream is silently dropped when the transport omits the `event:` line.
#[test]
fn every_declared_event_name_resolves_from_the_body_alone() {
    let cases: Vec<serde_json::Value> = vec![
        serde_json::json!({
            "type": "message_start",
            "message": { "role": "assistant", "usage": { "input_tokens": 11, "output_tokens": 0 } }
        }),
        serde_json::json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": { "type": "text", "text": "" }
        }),
        serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "text_delta", "text": "hi" }
        }),
        serde_json::json!({ "type": "content_block_stop", "index": 0 }),
        serde_json::json!({
            "type": "message_delta",
            "delta": { "stop_reason": "end_turn" },
            "usage": { "output_tokens": 4 }
        }),
        serde_json::json!({ "type": "message_stop" }),
    ];
    let mut state = crate::ir::StreamDecodeState::default();
    for data in &cases {
        let named = data.get("type").and_then(|t| t.as_str()).unwrap();
        let mut bare_state = crate::ir::StreamDecodeState::default();
        let with_event_line = AnthropicReader.read_response_events(named, data, &mut state);
        let without = AnthropicReader.read_response_events("", data, &mut bare_state);
        assert!(
            !without.is_empty(),
            "`{named}` produced no IR events when the transport omitted the event: line"
        );
        assert_eq!(
            without, with_event_line,
            "`{named}` must decode identically whether or not the transport repeated its name"
        );
    }
}

/// A redacted-thinking `content_block_start` — the one event this reader special-cases ahead of
/// the shared dispatch — resolves from the body too.
#[test]
fn a_redacted_thinking_start_resolves_from_the_body_alone() {
    let data = serde_json::json!({
        "type": "content_block_start",
        "index": 0,
        "content_block": { "type": "redacted_thinking", "data": "OPAQUE" }
    });
    let mut state = crate::ir::StreamDecodeState::default();
    let events = AnthropicReader.read_response_events("", &data, &mut state);
    assert!(
        events.iter().any(|e| matches!(
            e,
            crate::ir::IrStreamEvent::BlockStart {
                block: crate::ir::IrBlockMeta::RedactedThinking,
                ..
            }
        )),
        "the redacted start must survive a bare-data frame: {events:?}"
    );
}

/// The `event:` line still WINS when both are present and the body is a fragment with no `type` —
/// nothing about the transport's name is discarded.
#[test]
fn the_transport_name_is_still_honoured_when_the_body_names_nothing() {
    let data = serde_json::json!({ "index": 0 });
    let mut state = crate::ir::StreamDecodeState::default();
    let events = AnthropicReader.read_response_events(EVT_CONTENT_BLOCK_STOP, &data, &mut state);
    assert!(
        matches!(
            events.as_slice(),
            [crate::ir::IrStreamEvent::BlockStop { index: 0 }]
        ),
        "the event: line remains the name when the body carries none: {events:?}"
    );
}
