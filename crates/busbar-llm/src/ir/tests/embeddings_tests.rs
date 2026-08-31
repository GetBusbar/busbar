// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/ir/embeddings.rs`.

use super::*;

#[test]
fn response_carries_multiple_typed_vectors_losslessly() {
    let mut item = EmbeddingItem {
        index: 0,
        ..Default::default()
    };
    item.vectors
        .insert(EncFmt::Float, VectorData::Float(vec![0.1, 0.2]));
    item.vectors
        .insert(EncFmt::Int8, VectorData::Int(vec![1, 2]));
    // Both encodings coexist — a flat Vec<f32> would drop the int8 vector.
    assert_eq!(item.vectors.len(), 2);
    assert!(matches!(item.vectors[&EncFmt::Int8], VectorData::Int(_)));
}

#[test]
fn input_type_and_task_type_are_separate_fields() {
    let req = EmbeddingsReq {
        model: "embed-v4".into(),
        input_type: Some("search_document".into()),
        task_type: Some("RETRIEVAL_DOCUMENT".into()),
        ..Default::default()
    };
    assert_ne!(req.input_type, req.task_type);
}

#[test]
fn billing_maps_token_usage_or_none() {
    let resp = EmbeddingsResp {
        usage: Some(TokenUsage {
            input: 11,
            ..Default::default()
        }),
        ..Default::default()
    };
    assert!(matches!(resp.billing(), Some(Billing::Tokens(_))));
    assert!(EmbeddingsResp::default().billing().is_none());
}

// ── IrFacts projection (close-non-chat-gate-blindness) ───────────────────────────────────────────

use busbar_api::operation::Operation;
use busbar_substrate::ir::facts::{ContentItem, IrFacts, OPAQUE_CONTENT_MARKER};

/// Every `ContentItem`'s screenable text, in order — the exact strings a `prompt: ro` gate is shown.
fn screened(items: &[ContentItem<'_>]) -> Vec<String> {
    items
        .iter()
        .map(|i| i.screenable_text().into_owned())
        .collect()
}

#[test]
fn embeddings_projects_input_strings_and_title_as_screenable_text() {
    let req = EmbeddingsReq {
        model: "embed-v4".into(),
        input: EmbInput::Text(vec!["first input".into(), "second input".into()]),
        title: Some("doc title".into()),
        ..Default::default()
    };
    assert_eq!(IrFacts::verb(&req), Operation::EMBEDDINGS);
    assert!(!IrFacts::wants_stream(&req));
    // input strings AND the Gemini retrieval title are all screenable (FATAL-3).
    assert_eq!(
        screened(&req.content()),
        vec!["first input", "second input", "doc title"]
    );
    // The size signal is a sum over the SAME items, never a second walk.
    let shape = req.shape();
    assert_eq!(
        shape.text_chars,
        ("first input".len() + "second input".len() + "doc title".len())
    );
    assert_eq!(shape.system_chars, 0);
    assert!(!shape.has_tools);
    assert_eq!(shape.max_tokens, None);
}

#[test]
fn embeddings_title_is_screened_when_present() {
    // The forcing-function witness for the `title` field (FATAL-3): a request carrying ONLY a title
    // still surfaces it to a gate — a projection that dropped the field would fail here.
    let req = EmbeddingsReq {
        title: Some("SECRET-TITLE".into()),
        ..Default::default()
    };
    assert!(screened(&req.content()).iter().any(|t| t == "SECRET-TITLE"));
}

#[test]
fn embeddings_image_and_token_inputs_are_opaque_not_empty() {
    // MINOR-7: image references embed as opaque (present-but-unscreenable), never silently nothing.
    let img = EmbeddingsReq {
        input: EmbInput::Images(vec!["data:image/png;base64,AAAA".into()]),
        ..Default::default()
    };
    let items = img.content();
    assert_eq!(items.len(), 1);
    assert!(matches!(items[0], ContentItem::Opaque { .. }));
    assert_eq!(items[0].screenable_text(), OPAQUE_CONTENT_MARKER);

    let tokens = EmbeddingsReq {
        input: EmbInput::Tokens(vec![vec![1, 2, 3]]),
        ..Default::default()
    };
    let items = tokens.content();
    assert_eq!(items.len(), 1);
    assert!(matches!(items[0], ContentItem::Opaque { .. }));
}
