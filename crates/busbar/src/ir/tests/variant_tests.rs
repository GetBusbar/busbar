// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/variant.rs`.

use super::*;

#[test]
fn wants_stream_true_only_for_chat_and_audio() {
    assert!(!IrReq::Embeddings(Default::default()).wants_stream());
    assert!(!IrReq::Moderation(Default::default()).wants_stream());
    assert!(!IrReq::Image(Default::default()).wants_stream());
    let s = SpeechReq {
        stream: true,
        ..Default::default()
    };
    assert!(IrReq::Speech(s).wants_stream());
    assert!(!IrReq::Speech(SpeechReq::default()).wants_stream());
}

#[test]
fn usage_projects_per_operation() {
    // moderation → flat
    assert!(matches!(
        IrResp::Moderation(Default::default()).usage(),
        Some(Billing::Flat)
    ));
    // embeddings → tokens
    let e = EmbeddingsResp {
        usage: Some(TokenUsage {
            input: 5,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(matches!(
        IrResp::Embeddings(e).usage(),
        Some(Billing::Tokens(_))
    ));
    // image with no usage/cost_basis → None
    assert!(IrResp::Image(Default::default()).usage().is_none());
}

#[test]
fn token_usage_maps_token_meter_and_none_for_flat() {
    // A token-metered embeddings response projects its input tokens into an IrUsage.
    let e = EmbeddingsResp {
        usage: Some(TokenUsage {
            input: 12,
            output: 0,
            ..Default::default()
        }),
        ..Default::default()
    };
    let tu = IrResp::Embeddings(e)
        .token_usage()
        .expect("token-metered op yields Some");
    assert_eq!(tu.input_tokens, 12);
    // A flat-metered moderation response has no token usage.
    assert!(IrResp::Moderation(Default::default())
        .token_usage()
        .is_none());
}

#[test]
fn operation_tag_matches_variant_both_directions() {
    assert_eq!(
        IrReq::Image(Default::default()).operation(),
        Operation::Image
    );
    assert_eq!(
        IrResp::Transcription(Default::default()).operation(),
        Operation::Transcription
    );
}

/// THE EIGHTH OPERATION ANSWERS THE PARENT'S WHOLE INTERFACE, and this test is what makes that
/// claim checkable rather than asserted.
///
/// A tool call is the first operation that did not come from the LLM surface, so it is the first
/// real evidence that `IrReq`/`IrResp` is a parent interface and not just a chat enum with extra
/// arms. Each assertion below is a DECISION the compiler forced when the variant landed — the
/// exhaustive matches in `variant.rs` could not be satisfied without answering it — so this test
/// pins the answers rather than re-deriving them.
///
/// It also keeps the variant honestly reachable while its codec cell is still being built. The
/// alternative was an `allow(dead_code)`, which would have silenced the question instead of
/// answering it.
#[test]
fn a_tool_call_answers_the_operation_blind_surface() {
    use crate::ir::toolcall::{ToolCallReq, ToolCallResp};

    let req = IrReq::ToolCall(ToolCallReq {
        tool: "fs_read".to_string(),
        arguments: serde_json::json!({ "path": "/etc/hosts" }),
        extra: Default::default(),
    });
    assert_eq!(req.operation(), Operation::ToolCall);
    assert!(
        !req.wants_stream(),
        "a tool call is one exchange: the tool runs and answers. Progress notifications are a \
         separate channel, not an incremental rendering of THIS result."
    );

    let resp = IrResp::ToolCall(ToolCallResp {
        content: serde_json::json!([{ "type": "text", "text": "127.0.0.1 localhost" }]),
        is_error: false,
        structured: None,
        extra: Default::default(),
    });
    assert_eq!(resp.operation(), Operation::ToolCall);
    assert!(
        matches!(resp.usage(), Some(crate::billing::Billing::Flat)),
        "a tool server reports no tokens, so a tool call is FLAT-metered — one call, one unit. \
         Flat rather than None is what puts it on the same budget tree as a chat completion \
         instead of leaving it invisible to governance."
    );
    assert!(
        resp.token_usage().is_none(),
        "and flat-metered means no token usage to report, exactly as moderation does"
    );

    // AND THE PAYLOAD SURVIVES THE PARENT. Carrying a subclass is only useful if the subclass's
    // own fields come back out intact, so the round trip is asserted rather than assumed — the
    // codec cell that will read a real `tools/call` off the wire depends on exactly this.
    let IrReq::ToolCall(inner) = &req else {
        panic!("the variant is what it was constructed as")
    };
    assert_eq!(inner.tool, "fs_read");
    assert_eq!(inner.arguments["path"], "/etc/hosts");

    let IrResp::ToolCall(inner) = &resp else {
        panic!("the variant is what it was constructed as")
    };
    assert!(
        !inner.is_error,
        "A TOOL THAT RAN AND FAILED IS NOT A FAILED CALL. `is_error` is the tool's own verdict on          a successful protocol exchange; a call that could never be made is a refusal and never          reaches this type. Collapsing the two tells a caller their request was malformed when          their tool merely returned an error."
    );
    assert!(
        inner.structured.is_none(),
        "busbar models no output schema, so structured output is carried, never validated"
    );
    assert_eq!(inner.content[0]["text"], "127.0.0.1 localhost");
}
