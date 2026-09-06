// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Wire shapes held against the PUBLISHED provider specifications pinned by
//! `testing/llm-conformance/spec-digests.tsv` (fetched into `~/.cache/busbar-llm-specs/`), not
//! against busbar's own goldens. Each test names the schema and the clause it is proving, so a
//! re-pin that moves a clause moves the test with it.

use super::*;
use crate::ir::{IrBlock, IrResponse, IrRole, IrTokenLogprob, IrUsage};

/// A minimal assistant response carrying `text`, the given stop reason and the given logprobs —
/// the smallest IR a writer will project into a full native response body.
fn resp(
    stop_reason: Option<crate::ir::IrStopReason>,
    logprobs: Vec<IrTokenLogprob>,
    text: &str,
) -> IrResponse {
    IrResponse {
        logprobs,
        role: IrRole::Assistant,
        content: vec![IrBlock::Text {
            text: text.to_string(),
            cache_control: None,
            citations: Vec::new(),
        }],
        stop_reason,
        usage: IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
            detail: crate::ir::IrUsageDetail::default(),
        },
        model: None,
        id: None,
        created: None,
        system_fingerprint: None,
        stop_sequence: None,
        request_echo: None,
    }
}

/// PUBLISHED OPENAI SPEC (`openai/openai-openapi` `openapi.yaml`, the pinned commit):
/// `CreateChatCompletionResponse.choices[].logprobs` and
/// `CreateChatCompletionStreamResponse.choices[].logprobs` both declare
/// `required: ["content", "refusal"]` — `refusal` is a REQUIRED member of the logprobs object
/// (nullable: a list of refusal tokens, or null when the model did not refuse). The writer emitted
/// only `{"content": [...]}`, so a strict validator (and the Python SDK's Pydantic model, which
/// requires the field) rejects every busbar chat completion that carries carried logprobs.
#[test]
fn openai_logprobs_object_carries_the_required_refusal_member() {
    let lps = vec![IrTokenLogprob {
        token: "hi".to_string(),
        logprob: -0.25,
        bytes: None,
        top: Vec::new(),
    }];
    let out = crate::openai_chat::write_openai_logprobs(&lps);
    assert!(
        out.get("content").is_some_and(|c| c.is_array()),
        "the content member must stay a token array: {out}"
    );
    assert_eq!(
        out.get("refusal"),
        Some(&serde_json::Value::Null),
        "logprobs requires both content and refusal; refusal is null when the model did not \
         refuse: {out}"
    );
}

/// The Responses writer LIFTS the `content` array out of the Chat logprobs object for an
/// `output_text` part's `logprobs` (Responses carries a bare `LogProb[]`, not the Chat object), so
/// adding `refusal` to the Chat object must NOT leak a stray member into the Responses part.
#[test]
fn responses_part_logprobs_stay_a_bare_array_after_the_refusal_member_lands() {
    let ir = resp(
        Some(crate::ir::IrStopReason::EndTurn),
        vec![IrTokenLogprob {
            token: "hi".to_string(),
            logprob: -0.5,
            bytes: None,
            top: Vec::new(),
        }],
        "hi",
    );
    // Bind the interior-mutable const to a local before borrowing
    // (clippy::borrow_interior_mutable_const).
    let writer = openai_responses::ResponsesWriter;
    let wire = writer.write_response(&ir);
    let part = wire
        .pointer("/output/0/content/0")
        .expect("an output_text content part");
    if let Some(lp) = part.get("logprobs") {
        assert!(
            lp.is_array(),
            "a Responses output_text part carries LogProb[] (an array), never the Chat \
             logprobs object: {lp}"
        );
    }
}

/// PUBLISHED OPENAI SPEC: `CreateChatCompletionResponse.choices[]` declares
/// `required: ["finish_reason", "index", "message", "logprobs"]` with
/// `finish_reason: {type: string, enum: [stop, length, tool_calls, content_filter, function_call]}`
/// — NO `nullable: true`. Only the STREAM chunk
/// (`CreateChatCompletionStreamResponse.choices[].finish_reason`) is nullable. A buffered choice
/// with `finish_reason: null` (what a cross-protocol backend that supplies no stop reason produced)
/// is not a valid `chat.completion`; the spec's natural-stop token is `stop`.
#[test]
fn buffered_openai_choice_finish_reason_is_never_null() {
    let ir = resp(None, Vec::new(), "oracle-marker");
    let wire = openai_chat::OpenAiWriter.write_response(&ir);
    let fr = wire
        .pointer("/choices/0/finish_reason")
        .expect("finish_reason is a required member of a buffered choice");
    assert_eq!(
        fr.as_str(),
        Some("stop"),
        "the buffered choice schema is a non-nullable enum; a backend that supplied no stop \
         reason falls back to the natural-stop token: {wire}"
    );
}

/// The STREAM chunk schema keeps `nullable: true` on `finish_reason`, so the non-final chunks must
/// still carry explicit null — the buffered fallback must not leak into the streamed path.
#[test]
fn streamed_openai_chunk_finish_reason_stays_nullable() {
    let writer = openai_chat::OpenAiWriter;
    let ev = writer
        .write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        })
        .expect("a text delta produces a chunk");
    assert_eq!(
        ev.1.pointer("/choices/0/finish_reason"),
        Some(&serde_json::Value::Null),
        "an intermediate chat.completion.chunk carries finish_reason null: {}",
        ev.1
    );
}

/// PUBLISHED ANTHROPIC SPEC (the Stainless-published OpenAPI document the official SDK pins in
/// `.stats.yml`): `ContentBlockStartEvent.content_block` is a `oneOf` DISCRIMINATED on `type`, whose
/// mapping is exactly `{text, thinking, redacted_thinking, tool_use, server_tool_use,
/// web_search_tool_result, web_fetch_tool_result, code_execution_tool_result,
/// bash_code_execution_tool_result, text_editor_code_execution_tool_result,
/// tool_search_tool_result, container_upload}`. There is NO `image` member: an assistant content
/// block on the Anthropic RESPONSE wire is never an image. The writer emitted
/// `content_block: {"type": "image"}`, a frame no Anthropic client can deserialize. Every sibling
/// writer (bedrock, cohere, gemini, openai_chat, openai_responses) already emits NO frame for
/// `IrBlockMeta::Image`.
#[test]
fn anthropic_image_block_start_emits_no_frame() {
    let writer = AnthropicWriter;
    assert!(
        writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Image,
            })
            .is_none(),
        "image is not a member of the content_block discriminator; emit no frame"
    );
}

/// …and the matching `BlockStop` must be suppressed with it: a `content_block_stop` for an index a
/// client never saw a `content_block_start` for is an orphan the SDK accumulator cannot close. This
/// mirrors `BedrockWriter`'s open-index guard.
#[test]
fn anthropic_image_block_stop_is_suppressed_with_its_start() {
    let writer = AnthropicWriter;
    assert!(
        writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Image,
            })
            .is_none(),
        "image BlockStart stays suppressed"
    );
    assert!(
        writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
            .is_none(),
        "a BlockStop whose BlockStart emitted nothing must not emit an orphan content_block_stop"
    );
}

/// A TEXT block's start/stop pair must stay intact once the open-index guard exists — the guard
/// closes only what it opened, and text opens.
#[test]
fn anthropic_text_block_start_stop_pair_survives_the_guard() {
    let writer = AnthropicWriter;
    let start = writer
        .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        })
        .expect("a text block starts");
    assert_eq!(
        start
            .1
            .pointer("/content_block/type")
            .and_then(|v| v.as_str()),
        Some("text")
    );
    assert!(
        writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
            .is_some(),
        "the text block's content_block_stop must still be emitted"
    );
}

/// A REDACTED thinking block emits its start LATE (from the delta that carries the opaque bytes),
/// so its `BlockStop` must still close — the open-index guard must treat it as opened.
#[test]
fn anthropic_redacted_thinking_block_stop_still_closes() {
    let writer = AnthropicWriter;
    assert!(
        writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::RedactedThinking,
            })
            .is_none(),
        "the redacted start is deferred to its delta"
    );
    assert!(
        writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
            .is_some(),
        "the deferred-start redacted block still owes its content_block_stop"
    );
}

/// PUBLISHED ANTHROPIC SPEC: `ErrorResponse.error` is discriminated on `type` over exactly nine
/// tokens — `invalid_request_error`, `authentication_error`, `billing_error`, `permission_error`,
/// `not_found_error`, `rate_limit_error`, `timeout_error`, `api_error`, `overloaded_error`. The
/// writer's catch-all passed an UNKNOWN kind through verbatim, so a budget-exhaustion refusal
/// reached an Anthropic-dialect client as `"type": "insufficient_quota"` (an OpenAI token) and a
/// context overflow as `"type": "context_length_exceeded"` — neither is a member of the union, and
/// the official SDK's error factory falls through to a generic `APIError`. Billing exhaustion is
/// `billing_error`; a context overflow is a request the model cannot accept, i.e.
/// `invalid_request_error`.
#[test]
fn anthropic_error_type_stays_inside_the_published_union() {
    let writer = AnthropicWriter;
    let quota = writer.write_error(429, "insufficient_quota", "budget exhausted");
    assert_eq!(
        quota.pointer("/error/type").and_then(|v| v.as_str()),
        Some("billing_error"),
        "billing exhaustion maps to the union's billing token: {quota}"
    );
    let ctx = writer.write_error(400, "context_length_exceeded", "too many tokens");
    assert_eq!(
        ctx.pointer("/error/type").and_then(|v| v.as_str()),
        Some("invalid_request_error"),
        "a context overflow is a request the model cannot accept: {ctx}"
    );
    let ok = writer.write_error(429, "rate_limit", "slow down");
    assert_eq!(
        ok.pointer("/error/type").and_then(|v| v.as_str()),
        Some("rate_limit_error"),
        "the already-correct mappings must not move: {ok}"
    );
}

/// PUBLISHED OPENAI SPEC: `FunctionToolCall` (the Responses `function_call` output item) declares
/// `required: ["type", "call_id", "name", "arguments"]`. The streamed
/// `response.output_item.added` for a tool call omitted `arguments`, so the item a client receives
/// at open time fails the item schema; real OpenAI opens the item with `"arguments": ""` and fills
/// it through `response.function_call_arguments.delta`.
#[test]
fn responses_output_item_added_seeds_the_required_arguments_member() {
    let writer = openai_responses::ResponsesWriter;
    let evs = writer.write_response_events(&crate::ir::IrStreamEvent::BlockStart {
        index: 0,
        block: crate::ir::IrBlockMeta::ToolUse {
            id: "call_abc".to_string(),
            name: "get_weather".to_string(),
        },
    });
    let added = evs
        .iter()
        .find(|(name, _)| name == "response.output_item.added")
        .map(|(_, v)| v)
        .expect("a tool-call BlockStart opens an output item");
    assert_eq!(
        added.pointer("/item/arguments").and_then(|v| v.as_str()),
        Some(""),
        "arguments is required on a function_call item and opens empty: {added}"
    );
    assert_eq!(
        added.pointer("/item/type").and_then(|v| v.as_str()),
        Some("function_call"),
        "the item type must not move: {added}"
    );
}
