// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TODO 585 (IMAGE-DETAIL-WARN): 1.5.5 warned the operator when an image's `image_url.detail` was
//! dropped. The IR now carries the ask (IR-08), so the loss moved to the egress write of a dialect
//! with no slot for it: anthropic, gemini and bedrock each log the 1.5.5 line, once per image,
//! naming the word; `auto` and an absent ask log nothing, and a dialect that carries the ask is
//! silent.

use crate::codec::chat_handle::ChatReqHandle;
use crate::codec::ir::{IrBlock, IrImageDetail, IrImageSource, IrMessage, IrRequest, IrRole};
use busbar_contract::ir::handle::IrHandle;
use busbar_contract::testkit::WarnCapture;

const LINE: &str = "dropping image_url.detail: no cross-protocol carrier exists for this \
                    cost/latency hint (not even on a same-protocol OpenAI round-trip)";

fn image(detail: Option<IrImageDetail>) -> IrBlock {
    IrBlock::Image {
        source: IrImageSource::Url("https://example.test/cat.png".to_string()),
        cache_control: None,
        detail,
    }
}

/// The warn lines one egress write of a request carrying `blocks` logs on `egress`.
fn warns(egress: &str, blocks: Vec<IrBlock>) -> Vec<String> {
    let ir = IrRequest {
        messages: vec![IrMessage {
            role: IrRole::User,
            content: blocks,
        }],
        max_tokens: Some(16),
        ..Default::default()
    };
    let mut handle = ChatReqHandle(ir, Default::default());
    let cap = WarnCapture::default();
    tracing::subscriber::with_default(cap.clone(), || {
        let _ = handle.write_egress_request(egress, "m");
    });
    cap.messages()
        .into_iter()
        .filter(|m| m.contains("image_url.detail"))
        .collect()
}

#[test]
fn a_dialect_without_the_slot_warns_once_per_dropped_detail() {
    for egress in ["anthropic", "gemini", "bedrock"] {
        for (detail, word) in [(IrImageDetail::High, "high"), (IrImageDetail::Low, "low")] {
            assert_eq!(
                warns(egress, vec![image(Some(detail))]),
                vec![format!("{LINE} detail={word}")],
                "{egress}: one warn, the 1.5.5 line, naming the word"
            );
        }
        assert_eq!(
            warns(
                egress,
                vec![
                    image(Some(IrImageDetail::High)),
                    image(Some(IrImageDetail::Low))
                ]
            )
            .len(),
            2,
            "{egress}: one per image"
        );
    }
}

#[test]
fn auto_or_no_ask_logs_nothing() {
    for egress in ["anthropic", "gemini", "bedrock"] {
        assert!(
            warns(egress, vec![image(Some(IrImageDetail::Auto))]).is_empty(),
            "{egress}"
        );
        assert!(warns(egress, vec![image(None)]).is_empty(), "{egress}");
    }
}

#[test]
fn a_dialect_that_carries_the_ask_logs_nothing() {
    for egress in ["openai", "responses", "cohere"] {
        assert!(
            warns(egress, vec![image(Some(IrImageDetail::High))]).is_empty(),
            "{egress}"
        );
    }
}

#[test]
fn an_image_inside_a_tool_result_is_walked_too() {
    let result = IrBlock::ToolResult {
        tool_use_id: "t1".to_string(),
        content: vec![image(Some(IrImageDetail::High))],
        is_error: false,
        cache_control: None,
    };
    assert_eq!(warns("anthropic", vec![result]).len(), 1);
}
