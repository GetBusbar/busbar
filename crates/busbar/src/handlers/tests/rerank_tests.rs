// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/handlers/cohere.rs`.

//! The seventh operation, round-tripped through the IR: cohere <-> bedrock are the two rerank
//! wires, and their result shapes are identical, so translation must be exact both ways.
use super::*;
use crate::handlers::bedrock::BedrockRequestHandler;

fn cohere_wire() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "model": "rerank-v3.5",
        "query": "what is a busbar",
        "documents": ["a metal bar", {"text": "a fish"}, "a conductor"],
        "top_n": 2
    }))
    .unwrap()
}

/// cohere ingress -> bedrock egress: query/documents/top_n cross; api_version added; the
/// {text} object form normalizes to a bare string.
#[test]
fn cohere_request_reaches_bedrock() {
    let rh = CohereRequestHandler;
    assert_eq!(
        rh.resolve_operation("/v2/rerank", b"{}"),
        Some(Operation::Rerank)
    );
    let ir = rh
        .operation_handler(Operation::Rerank)
        .unwrap()
        .read_request(&cohere_wire(), "application/json")
        .expect("parses");
    let bh = BedrockRequestHandler;
    let out = bh
        .operation_handler(Operation::Rerank)
        .unwrap()
        .write_request(&ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["query"], "what is a busbar");
    assert_eq!(v["documents"][1], "a fish");
    assert_eq!(v["top_n"], 2);
    assert_eq!(v["api_version"], 2);
}

/// bedrock ingress (invoke body-detect) -> cohere egress; and the response comes back exact.
#[test]
fn bedrock_request_and_response_round_trip() {
    let bh = BedrockRequestHandler;
    let body = serde_json::to_vec(&json!({
        "query": "q", "documents": ["a", "b"], "top_n": 1
    }))
    .unwrap();
    assert_eq!(
        bh.resolve_operation("/model/cohere.rerank-v3-5:0/invoke", &body),
        Some(Operation::Rerank)
    );
    let ir = bh
        .operation_handler(Operation::Rerank)
        .unwrap()
        .read_request(&body, "application/json")
        .expect("parses");
    let ch = CohereRequestHandler;
    let out = ch
        .operation_handler(Operation::Rerank)
        .unwrap()
        .write_request(&ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["query"], "q");
    assert_eq!(v["documents"], json!(["a", "b"]));

    // Response: cohere wire -> IR -> bedrock wire preserves index + relevance_score exactly.
    let resp = serde_json::to_vec(&json!({
        "id": "r1",
        "results": [
            {"index": 2, "relevance_score": 0.98},
            {"index": 0, "relevance_score": 0.11}
        ],
        "meta": {"billed_units": {"search_units": 1}}
    }))
    .unwrap();
    let ir_resp = ch
        .operation_handler(Operation::Rerank)
        .unwrap()
        .read_response(&resp)
        .expect("parses");
    let wire = bh
        .operation_handler(Operation::Rerank)
        .unwrap()
        .write_response(&ir_resp);
    let v: Value = serde_json::from_slice(&wire.bytes).unwrap();
    assert_eq!(v["results"][0]["index"], 2);
    assert_eq!(v["results"][0]["relevance_score"], 0.98);
    assert_eq!(v["results"][1]["index"], 0);
}

#[test]
fn embeddings_write_request_emits_base64_encoding_type() {
    use crate::ir::embeddings::EmbeddingsReq;
    let ir = IrReq::Embeddings(EmbeddingsReq {
        model: "embed-v4".into(),
        input: EmbInput::Text(vec!["a".into()]),
        encoding_formats: vec![EncFmt::Base64],
        ..Default::default()
    });
    let out = CohereEmbeddings.write_request(&ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["embedding_types"], json!(["base64"]));
}

#[test]
fn embeddings_write_request_defaults_to_float_when_empty() {
    use crate::ir::embeddings::EmbeddingsReq;
    let ir = IrReq::Embeddings(EmbeddingsReq {
        model: "embed-v4".into(),
        input: EmbInput::Text(vec!["a".into()]),
        encoding_formats: vec![],
        ..Default::default()
    });
    let out = CohereEmbeddings.write_request(&ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["embedding_types"], json!(["float"]));
}

#[test]
fn embeddings_write_request_preserves_multiple_encoding_types_in_order() {
    use crate::ir::embeddings::EmbeddingsReq;
    let ir = IrReq::Embeddings(EmbeddingsReq {
        model: "embed-v4".into(),
        input: EmbInput::Text(vec!["a".into()]),
        encoding_formats: vec![EncFmt::Float, EncFmt::Base64],
        ..Default::default()
    });
    let out = CohereEmbeddings.write_request(&ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["embedding_types"], json!(["float", "base64"]));
}

#[test]
fn embeddings_write_request_warns_on_dropped_non_text_input() {
    use crate::ir::embeddings::EmbeddingsReq;
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let ir = IrReq::Embeddings(EmbeddingsReq {
        input: EmbInput::Images(vec!["data:image/png;base64,AA==".into()]),
        ..Default::default()
    });
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || CohereEmbeddings.write_request(&ir));

    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["texts"], json!([]));

    assert!(
        cap.contains("dropping a non-text embeddings input"),
        "a dropped non-text embeddings input must warn: {:?}",
        cap.messages()
    );
}

#[test]
fn embeddings_read_response_reads_base64_vectors() {
    let body = serde_json::to_vec(&json!({
        "id": "x",
        "embeddings": {"base64": ["AAAA", "BBBB"]}
    }))
    .unwrap();
    let ir = CohereEmbeddings.read_response(&body).expect("parses");
    let IrResp::Embeddings(r) = ir else {
        panic!("expected embeddings")
    };
    assert_eq!(r.embeddings.len(), 2);
    assert_eq!(
        r.embeddings[0].vectors[&EncFmt::Base64],
        VectorData::Base64("AAAA".into())
    );
    assert_eq!(
        r.embeddings[1].vectors[&EncFmt::Base64],
        VectorData::Base64("BBBB".into())
    );
}

#[test]
fn embeddings_response_roundtrips_int8_not_dropped() {
    // int8/uint8/binary/ubinary arrive as integer arrays and must NOT be dropped on the
    // response leg (they used to yield count=0 -> empty embeddings).
    let body = serde_json::to_vec(&json!({
        "id": "x",
        "embeddings": {"int8": [[1, 2, 3], [4, 5, 6]]}
    }))
    .unwrap();
    let ir = CohereEmbeddings.read_response(&body).expect("parses");
    let IrResp::Embeddings(r) = &ir else {
        panic!("expected embeddings")
    };
    assert_eq!(r.embeddings.len(), 2, "int8 response must not be empty");
    assert!(matches!(
        r.embeddings[0].vectors.get(&EncFmt::Int8),
        Some(VectorData::Int(_))
    ));
    // write_response re-emits the int8 key, not an empty float array.
    let out = CohereEmbeddings.write_response(&ir);
    let v: Value = serde_json::from_slice(&out.bytes).unwrap();
    assert!(v["embeddings"]["int8"].is_array(), "int8 key emitted: {v}");
    assert!(
        v["embeddings"].get("float").is_none(),
        "no spurious float key: {v}"
    );
    let _ = EmbeddingsResp::default();
}

#[test]
fn embeddings_read_response_reads_float_vectors() {
    let body = serde_json::to_vec(&json!({
        "embeddings": {"float": [[0.1, 0.2]]}
    }))
    .unwrap();
    let ir = CohereEmbeddings.read_response(&body).expect("parses");
    let IrResp::Embeddings(r) = ir else {
        panic!("expected embeddings")
    };
    assert_eq!(r.embeddings.len(), 1);
    assert!(matches!(
        r.embeddings[0].vectors[&EncFmt::Float],
        VectorData::Float(_)
    ));
}

#[test]
fn embeddings_write_response_emits_base64_key_not_swallowed_by_empty_float() {
    use crate::ir::embeddings::EmbeddingsResp;
    let mut item = EmbeddingItem {
        index: 0,
        ..Default::default()
    };
    item.vectors
        .insert(EncFmt::Base64, VectorData::Base64("AAAA".into()));
    let ir = IrResp::Embeddings(EmbeddingsResp {
        embeddings: vec![item],
        ..Default::default()
    });
    let out = CohereEmbeddings.write_response(&ir);
    let v: Value = serde_json::from_slice(&out.bytes).unwrap();
    assert_eq!(v["embeddings"]["base64"], json!(["AAAA"]));
    // A base64-only response must NOT emit an empty `float` array that swallows it.
    assert!(v["embeddings"].get("float").is_none());
}

#[test]
fn embeddings_write_response_emits_float_key() {
    use crate::ir::embeddings::EmbeddingsResp;
    let mut item = EmbeddingItem {
        index: 0,
        ..Default::default()
    };
    item.vectors
        .insert(EncFmt::Float, VectorData::Float(vec![0.1, 0.2]));
    let ir = IrResp::Embeddings(EmbeddingsResp {
        embeddings: vec![item],
        ..Default::default()
    });
    let out = CohereEmbeddings.write_response(&ir);
    let v: Value = serde_json::from_slice(&out.bytes).unwrap();
    assert!(v["embeddings"].get("float").is_some());
    let row = v["embeddings"]["float"][0].as_array().expect("float row");
    assert_eq!(row.len(), 2);
    // f32 round-trip: compare with tolerance rather than exact f64 literals.
    assert!((row[0].as_f64().unwrap() - 0.1).abs() < 1e-6);
    assert!((row[1].as_f64().unwrap() - 0.2).abs() < 1e-6);
}

#[test]
fn embeddings_read_request_parses_texts() {
    let body = serde_json::to_vec(&json!({
        "model": "m",
        "texts": ["a", "b"],
        "input_type": "search_query"
    }))
    .unwrap();
    let ir = CohereEmbeddings
        .read_request(&body, "application/json")
        .expect("parses");
    let IrReq::Embeddings(r) = ir else {
        panic!("expected embeddings")
    };
    assert_eq!(r.input, EmbInput::Text(vec!["a".into(), "b".into()]));
}

#[test]
fn embeddings_read_request_rejects_missing_texts() {
    let body = serde_json::to_vec(&json!({"model": "m"})).unwrap();
    let err = CohereEmbeddings
        .read_request(&body, "application/json")
        .expect_err("missing texts must reject");
    assert!(matches!(err, IngressReject::BadRequest(_)));
}

#[test]
fn embeddings_read_request_maps_all_encoding_types_not_just_base64() {
    // Every Cohere embedding_type must map to its IR variant, not collapse to Float. int8/
    // uint8/binary/ubinary were silently downgraded before (only base64 was handled).
    for (wire, want) in [
        ("float", EncFmt::Float),
        ("base64", EncFmt::Base64),
        ("int8", EncFmt::Int8),
        ("uint8", EncFmt::Uint8),
        ("binary", EncFmt::Binary),
        ("ubinary", EncFmt::Ubinary),
    ] {
        let body = serde_json::to_vec(&json!({
            "model": "m", "texts": ["x"], "input_type": "search_query",
            "embedding_types": [wire]
        }))
        .unwrap();
        let IrReq::Embeddings(r) = CohereEmbeddings
            .read_request(&body, "application/json")
            .expect("parses")
        else {
            panic!("expected embeddings")
        };
        assert_eq!(r.encoding_formats, vec![want], "encoding_type {wire}");
    }
}

#[test]
fn embeddings_write_request_carries_output_dimension_and_truncate() {
    // Cohere was the lone embeddings writer dropping these; they must reach the wire so a
    // Matryoshka (output_dimension) or explicit truncate request is honored.
    use crate::ir::embeddings::{EmbeddingsReq, EncFmt};
    let ir = IrReq::Embeddings(EmbeddingsReq {
        model: "embed-v4.0".into(),
        input: EmbInput::Text(vec!["x".into()]),
        dimensions: Some(256),
        truncate: Some("NONE".into()),
        encoding_formats: vec![EncFmt::Int8],
        ..Default::default()
    });
    let out = CohereEmbeddings.write_request(&ir);
    let v: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["output_dimension"], 256);
    assert_eq!(v["truncate"], "NONE");
    assert_eq!(v["embedding_types"], json!(["int8"]));
}

/// A client top_n larger than u32::MAX must DROP to None (omitted), never silently wrap to a
/// bogus small value — the checked-narrowing contract for all client-supplied counts.
#[test]
fn oversized_top_n_drops_to_none_not_wrapped() {
    let body = serde_json::to_vec(&json!({
        "model": "rerank-v3.5", "query": "q", "documents": ["a", "b"],
        "top_n": u64::from(u32::MAX) + 1
    }))
    .unwrap();
    let ir = CohereRequestHandler
        .operation_handler(Operation::Rerank)
        .unwrap()
        .read_request(&body, "application/json")
        .expect("parses");
    let IrReq::Rerank(r) = ir else {
        panic!("expected rerank")
    };
    assert_eq!(
        r.top_n, None,
        "an out-of-range top_n must be omitted, not wrapped"
    );
}

/// Protocols without a rerank surface have NO handler: the universal no-handler 404 covers
/// ingress and egress alike (the deletion-switch symmetry).
#[test]
fn no_rerank_handler_on_the_other_four() {
    for proto in ["openai", "anthropic", "gemini", "responses"] {
        let rh = crate::handlers::request_handler(proto).expect(proto);
        assert!(
            rh.operation_handler(Operation::Rerank).is_none(),
            "{proto} must have no rerank handler"
        );
    }
}
