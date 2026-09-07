// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A FAILED RESPONSE IS STILL A BILLED ONE.
//!
//! The pinned OpenAI OpenAPI document (openai/openai-openapi @ 91cc0564) declares `status` on the
//! `Response` object with the enum `completed | failed | in_progress | cancelled | queued |
//! incomplete`, and declares `usage` on that SAME object — `ResponseUsage`, with `input_tokens`,
//! `input_tokens_details.cached_tokens`, `output_tokens`,
//! `output_tokens_details.reasoning_tokens` and `total_tokens`, all `required`. Nothing in the
//! document makes `usage` conditional on `status`: a `failed` Response is served as an HTTP 200
//! whose body reports the tokens the model already consumed before it failed.
//!
//! Both failed arms of this reader dropped that object on the floor — the streamed
//! `response.failed` arm returned straight after its `Error`+`MessageStop`, and the buffered
//! `status:"failed"` arm returned `Err` before the usage read further down the function. So a
//! request that burned a full context window and then hit a content filter or a server fault was
//! billed at exactly zero.

use super::*;

fn failed_response_obj() -> serde_json::Value {
    serde_json::json!({
        "id": "resp_failed_1",
        "object": "response",
        "status": "failed",
        "output": [],
        "error": { "code": "server_error", "message": "the model failed" },
        "usage": {
            "input_tokens": 900,
            "input_tokens_details": { "cached_tokens": 100 },
            "output_tokens": 40,
            "output_tokens_details": { "reasoning_tokens": 12 },
            "total_tokens": 940
        }
    })
}

/// The STREAMED failed arm: `response.failed` carries the same nested `Response` object the
/// buffered path answers with, usage included. The translated IR must report those tokens.
#[test]
fn a_streamed_failed_response_bills_the_usage_it_reported() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = ResponsesReader.read_response_events(
        EVT_RESPONSE_FAILED,
        &serde_json::json!({ "response": failed_response_obj() }),
        &mut state,
    );
    // The failure still reaches the client, and the stream still terminates.
    assert!(
        events
            .iter()
            .any(|e| matches!(e, crate::ir::IrStreamEvent::Error(_))),
        "the upstream failure must still be surfaced: {events:?}"
    );
    assert!(
        matches!(events.last(), Some(crate::ir::IrStreamEvent::MessageStop)),
        "the stream must still terminate: {events:?}"
    );
    // ... and the tokens the upstream said it burned are on the IR.
    let usage = events
        .iter()
        .find_map(|e| match e {
            crate::ir::IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
            _ => None,
        })
        .expect("a failed terminal that reported usage must carry it on the IR");
    // `input_tokens` is a TOTAL that includes the cached prefix; the IR normalizes to uncached.
    assert_eq!(usage.input_tokens, 800);
    assert_eq!(usage.cache_read_input_tokens, Some(100));
    assert_eq!(usage.output_tokens, 40);
    assert_eq!(usage.detail.reasoning_tokens, Some(12));
    assert_eq!(
        usage.billable_tokens(),
        940,
        "a failed response bills every token it reported, not zero"
    );
}

/// A failed terminal that reports NO usage object emits no usage delta — the byte-for-byte
/// pre-existing sequence (Error, MessageStop) is unchanged for the common bodyless failure.
#[test]
fn a_streamed_failure_with_no_usage_emits_the_sequence_it_always_did() {
    let mut state = crate::ir::StreamDecodeState::default();
    let events = ResponsesReader.read_response_events(
        EVT_RESPONSE_FAILED,
        &serde_json::json!({ "response": {
            "status": "failed",
            "error": { "code": "server_error" }
        }}),
        &mut state,
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, crate::ir::IrStreamEvent::MessageDelta { .. })),
        "no usage was reported, so no usage delta may be invented: {events:?}"
    );
    assert_eq!(events.len(), 2, "Error then MessageStop, as before");
}

/// The BUFFERED failed arm. OpenAI serves a failed Response as an HTTP 200, so the same-protocol
/// usage tap runs over it — and the tap billed zero because `read_response` answers `Err` for a
/// failed body and the tap had no second reading. The tokens the body reported must reach the
/// ledger.
#[test]
fn a_buffered_failed_response_bills_the_usage_it_reported() {
    let cell = crate::chat_handle::ChatOperation(crate::proto_codec::PROTO_RESPONSES);
    let body = serde_json::to_vec(&failed_response_obj()).unwrap();
    let usage = busbar_substrate_values::handlers::OperationHandler::extract_usage(
        &cell,
        crate::proto_codec::PROTO_RESPONSES,
        &body,
    )
    .expect("a 200 body that reports its usage must not bill zero");
    assert_eq!(usage.input, 800);
    assert_eq!(usage.cache_read, Some(100));
    assert_eq!(usage.output, 40);
}

/// The tap's zero-billing warn path is still the answer for a 2xx body that reports nothing
/// readable: no usage object, no invented tokens.
#[test]
fn a_body_that_reports_no_usage_still_bills_zero() {
    let cell = crate::chat_handle::ChatOperation(crate::proto_codec::PROTO_RESPONSES);
    let body = serde_json::to_vec(&serde_json::json!({
        "status": "failed",
        "error": { "code": "server_error" }
    }))
    .unwrap();
    assert_eq!(
        busbar_substrate_values::handlers::OperationHandler::extract_usage(
            &cell,
            crate::proto_codec::PROTO_RESPONSES,
            &body,
        ),
        None,
        "nothing was reported, so nothing is billed"
    );
}
