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
