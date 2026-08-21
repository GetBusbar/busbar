// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cohere `RequestHandler` + cells. Embeddings via `/v2/embed`.

use crate::ir::embeddings::{
    EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData,
};
use busbar_core::handlers::{
    CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody,
};
use busbar_core::ir::handle::IrHandle;
use busbar_core::operation::Operation;
use bytes::Bytes;
use serde_json::{json, Value};

/// Endpoint paths — each appears on BOTH the egress side (`upstream_path`) and the ingress match
/// (`resolve_operation`); single-sourced so the two sides cannot drift.
const PATH_CHAT: &str = "/v2/chat";
const PATH_EMBED: &str = "/v2/embed";
const PATH_RERANK: &str = "/v2/rerank";

pub struct CohereRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: super::super::chat_handle::ChatOperation =
    super::super::chat_handle::ChatOperation("cohere");
static EMB: CohereEmbeddings = CohereEmbeddings;
static RERANK: CohereRerank = CohereRerank;

/// COHERE'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data. A verb absent from
/// it is the standard no-handler 404: Cohere has no moderation/image/audio surface, and the
/// protocol-surface verbs are MCP's and A2A's.
static CELLS: &[busbar_core::handlers::Cell] = &[
    (Operation::CHAT, &CHAT),
    (Operation::EMBEDDINGS, &EMB),
    (Operation::RERANK, &RERANK),
];

/// The egress half of the path constants above; `resolve_operation` reads the same ones inbound.
static PATHS: &[(Operation, &str)] = &[
    (Operation::CHAT, PATH_CHAT),
    (Operation::RERANK, PATH_RERANK),
    (Operation::EMBEDDINGS, PATH_EMBED),
];

impl RequestHandler for CohereRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "cohere"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        busbar_core::handlers::cell_of(CELLS, op)
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        // Unreachable: `operation_handler` returns `None` for a verb absent from the table, so
        // egress path resolution is never reached for one. The fallback is the pre-1.6.0 answer.
        busbar_core::handlers::path_of(PATHS, ctx.operation)
            .unwrap_or(PATH_EMBED)
            .into()
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        if path.ends_with(PATH_CHAT) {
            Some(Operation::CHAT)
        } else if path.ends_with(PATH_EMBED) {
            Some(Operation::EMBEDDINGS)
        } else if path.ends_with(PATH_RERANK) {
            Some(Operation::RERANK)
        } else {
            None
        }
    }
}

/// Cohere `embedding_types` name for an IR encoding — a 1:1 mapping (Cohere v2 supports exactly
/// these six), so a requested encoding is served natively instead of downgraded to float.
fn cohere_embedding_type(f: &EncFmt) -> &'static str {
    match f {
        EncFmt::Float => "float",
        EncFmt::Base64 => "base64",
        EncFmt::Int8 => "int8",
        EncFmt::Uint8 => "uint8",
        EncFmt::Binary => "binary",
        EncFmt::Ubinary => "ubinary",
    }
}

/// Every IR encoding Cohere's `/v2/embed` supports, for iterating the response keys.
const ALL_ENCODINGS: [EncFmt; 6] = [
    EncFmt::Float,
    EncFmt::Base64,
    EncFmt::Int8,
    EncFmt::Uint8,
    EncFmt::Binary,
    EncFmt::Ubinary,
];

/// Inverse of [`cohere_embedding_type`]: a Cohere `embedding_types` wire string → IR encoding. The
/// full 1:1 map (not just base64), so an `int8`/`uint8`/`binary`/`ubinary` ask is not silently
/// collapsed to float on the read side. Unknown strings fall back to float.
fn cohere_encoding_format(s: &str) -> EncFmt {
    match s {
        "base64" => EncFmt::Base64,
        "int8" => EncFmt::Int8,
        "uint8" => EncFmt::Uint8,
        "binary" => EncFmt::Binary,
        "ubinary" => EncFmt::Ubinary,
        _ => EncFmt::Float,
    }
}

/// Cohere v2 embeddings (`/v2/embed`). `input_type` is required by Cohere; default to a document role.
struct CohereEmbeddings;

impl OperationHandler for CohereEmbeddings {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> busbar_core::breaker::RawUpstreamError {
        busbar_core::handlers::protocol_error("cohere", status, body)
    }
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
    /// cohere `/v2/embed` wire → IR (cohere as INGRESS): `texts[]` + required `input_type`.
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::EmbeddingsReqHandle(
            read_embeddings_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(super::super::leaf_handles::EmbeddingsRespHandle(
            read_embeddings_response(wire)?,
        )) as Box<dyn IrHandle>)
    }
}

/// IR → cohere v2 embed request wire (the body of [`CohereEmbeddings::write_request`], moved behind
/// the `(embeddings, cohere)` key so a dissolved leaf-op handle can reach it — G6 A4b option-a).
/// Byte-identical to the pre-cutover inline write.
pub(crate) fn write_embeddings_request(r: &EmbeddingsReq) -> Bytes {
    let texts = match &r.input {
        EmbInput::Text(v) => v.clone(),
        other => {
            tracing::warn!(
                dropped = 1,
                "Cohere embeddings input is text-only here; dropping a non-text embeddings \
                 input ({other:?} kind) with no analog"
            );
            Vec::new()
        }
    };
    let input_type = r
        .input_type
        .clone()
        .unwrap_or_else(|| "search_document".to_string());
    // Honor the caller's requested encoding(s): Cohere's `embedding_types` map 1:1 to the IR
    // `EncFmt` variants, so a base64 ask is served natively rather than silently downgraded to
    // float (the same drop that was fixed for the OpenAI egress writer). Default to float.
    let embedding_types: Vec<&str> = if r.encoding_formats.is_empty() {
        vec!["float"]
    } else {
        r.encoding_formats
            .iter()
            .map(cohere_embedding_type)
            .collect()
    };
    let mut body = json!({
        "model": r.model,
        "texts": texts,
        "input_type": input_type,
        "embedding_types": embedding_types,
    });
    // Carry the shape/truncation controls the reader captures (Cohere is the lone embeddings
    // writer that was dropping these): `output_dimension` (Matryoshka on embed-v4) and `truncate`.
    if let Some(d) = r.dimensions {
        body["output_dimension"] = json!(d);
    }
    if let Some(t) = &r.truncate {
        body["truncate"] = json!(t);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → cohere v2 embed response wire (the body of [`CohereEmbeddings::write_response`], moved behind
/// the `(embeddings, cohere)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_embeddings_response(r: &EmbeddingsResp) -> WireBody {
    // Emit every encoding the IR carries under its own Cohere key (`float`, `base64`, `int8`,
    // ...), so an int8/base64/etc. response (e.g. from a cross-protocol backend) is not silently
    // dropped — the write twin of the six-encoding read. Cohere's `embeddings_by_type` shape
    // holds multiple keys, each a per-item array in candidate order.
    let mut by_enc: std::collections::BTreeMap<EncFmt, Vec<Value>> =
        std::collections::BTreeMap::new();
    for item in &r.embeddings {
        for (enc, vd) in &item.vectors {
            let cell = match vd {
                VectorData::Float(v) => json!(v),
                VectorData::Base64(s) => json!(s),
                VectorData::Int(v) => json!(v),
            };
            by_enc.entry(*enc).or_default().push(cell);
        }
    }
    let mut emb = serde_json::Map::new();
    for (enc, vals) in &by_enc {
        emb.insert(cohere_embedding_type(enc).to_string(), json!(vals));
    }
    // Emit an empty `float` key when the IR carried no vectors, for response-shape stability.
    if emb.is_empty() {
        emb.insert("float".to_string(), json!(Vec::<Vec<f32>>::new()));
    }
    let mut body = json!({
        "response_type": "embeddings_by_type",
        "embeddings": emb,
    });
    if let Some(id) = &r.id {
        body["id"] = json!(id);
    }
    if let Some(texts) = &r.input_echo {
        body["texts"] = json!(texts);
    }
    if let Some(u) = &r.usage {
        body["meta"] = json!({ "billed_units": { "input_tokens": u.input } });
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

/// Cohere v2 rerank (`/v2/rerank`): `{model, query, documents[], top_n?}` →
/// `{results: [{index, relevance_score}], meta.billed_units.search_units}`. Documents arrive as
/// bare strings or `{text}` objects; both normalize to strings.
struct CohereRerank;

pub(crate) fn rerank_documents_pub(v: Option<&Value>) -> Vec<String> {
    rerank_documents(v)
}

fn rerank_documents(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|d| {
                    d.as_str()
                        .map(str::to_string)
                        .or_else(|| d.get("text").and_then(Value::as_str).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl OperationHandler for CohereRerank {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(&self, status: u16, body: &[u8]) -> busbar_core::breaker::RawUpstreamError {
        busbar_core::handlers::protocol_error("cohere", status, body)
    }
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::RerankReqHandle(
            read_rerank_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(super::super::leaf_handles::RerankRespHandle(
            read_rerank_response(wire)?,
        )) as Box<dyn IrHandle>)
    }
}

/// IR → cohere v2 rerank request wire (the body of [`CohereRerank::write_request`], moved behind the
/// `(rerank, cohere)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_rerank_request(r: &crate::ir::rerank::RerankReq) -> Bytes {
    let mut body = json!({
        "model": r.model,
        "query": r.query,
        "documents": r.documents,
    });
    if let Some(n) = r.top_n {
        body["top_n"] = json!(n);
    }
    if let Some(m) = r.max_tokens_per_doc {
        body["max_tokens_per_doc"] = json!(m);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → cohere v2 rerank response wire (the body of [`CohereRerank::write_response`], moved behind the
/// `(rerank, cohere)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_rerank_response(r: &crate::ir::rerank::RerankResp) -> WireBody {
    let results: Vec<Value> = r
        .results
        .iter()
        .map(|x| json!({"index": x.index, "relevance_score": x.relevance_score}))
        .collect();
    let mut body = json!({ "results": results });
    if let Some(id) = &r.id {
        body["id"] = json!(id);
    }
    if let Some(su) = r.search_units {
        body["meta"] = json!({ "billed_units": { "search_units": su } });
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

/// `results[] -> [{index, relevance_score}]` — shared by the Cohere and Bedrock rerank readers
/// (the two wires use the same result shape).
pub(crate) fn read_rerank_results(v: Option<&Value>) -> Vec<crate::ir::rerank::RerankResult> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some(crate::ir::rerank::RerankResult {
                        index: x.get("index").and_then(Value::as_u64)? as usize,
                        relevance_score: x.get("relevance_score").and_then(Value::as_f64)?,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/rerank_tests.rs"]
mod rerank_tests;

/// Wire -> concrete `EmbeddingsReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_embeddings_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::embeddings::EmbeddingsReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let texts = wire
        .get("texts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if texts.is_empty() {
        return Err(IngressReject::BadRequest(
            "embed request requires `texts`".into(),
        ));
    }
    let encoding_formats = wire
        .get("embedding_types")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .map(cohere_encoding_format)
                .collect()
        })
        .unwrap_or_else(|| vec![EncFmt::Float]);
    Ok(crate::ir::embeddings::EmbeddingsReq {
        model: wire
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        input: EmbInput::Text(texts),
        input_type: wire
            .get("input_type")
            .and_then(Value::as_str)
            .map(str::to_string),
        dimensions: wire
            .get("output_dimension")
            .and_then(Value::as_u64)
            .and_then(|d| u32::try_from(d).ok()),
        truncate: wire
            .get("truncate")
            .and_then(Value::as_str)
            .map(str::to_string),
        encoding_formats,
        ..Default::default()
    })
}

/// Wire -> concrete `EmbeddingsResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_embeddings_response(
    wire: &[u8],
) -> Result<crate::ir::embeddings::EmbeddingsResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    // Cohere returns each requested encoding under its own key (`embeddings.float`,
    // `embeddings.base64`, `embeddings.int8`, ...), positionally aligned. Read EVERY encoding the
    // request leg can ask for — float, base64, and the four integer forms — so an int8/uint8/
    // binary/ubinary response is not silently dropped (its `float` key is absent when only that
    // encoding was requested). Float -> Float, base64 -> Base64, the int forms -> Int.
    let emb = v.get("embeddings");
    let arrays: Vec<(EncFmt, &Vec<Value>)> = ALL_ENCODINGS
        .iter()
        .filter_map(|&e| {
            emb.and_then(|o| o.get(cohere_embedding_type(&e)))
                .and_then(Value::as_array)
                .map(|a| (e, a))
        })
        .collect();
    let count = arrays.iter().map(|(_, a)| a.len()).max().unwrap_or(0);
    let embeddings: Vec<EmbeddingItem> = (0..count)
        .map(|idx| {
            let mut item = EmbeddingItem {
                index: idx,
                ..Default::default()
            };
            for (enc, arr) in &arrays {
                let Some(cell) = arr.get(idx) else { continue };
                let vd = match enc {
                    EncFmt::Float => cell.as_array().map(|f| {
                        VectorData::Float(
                            f.iter()
                                .filter_map(|x| x.as_f64().map(|n| n as f32))
                                .collect(),
                        )
                    }),
                    EncFmt::Base64 => cell.as_str().map(|s| VectorData::Base64(s.to_string())),
                    // int8/uint8/binary/ubinary all arrive as JSON integer arrays.
                    _ => cell.as_array().map(|f| {
                        VectorData::Int(
                            f.iter()
                                .filter_map(|x| x.as_i64().map(|n| n as i32))
                                .collect(),
                        )
                    }),
                };
                if let Some(vd) = vd {
                    item.vectors.insert(*enc, vd);
                }
            }
            item
        })
        .collect();
    let usage = v
        .get("meta")
        .and_then(|m| m.get("billed_units"))
        .and_then(|b| b.get("input_tokens"))
        .and_then(Value::as_u64)
        .map(|n| busbar_core::billing::TokenUsage {
            input: n,
            ..Default::default()
        });
    Ok(EmbeddingsResp {
        id: v.get("id").and_then(Value::as_str).map(str::to_string),
        embeddings,
        usage,
        ..Default::default()
    })
}

/// Wire -> concrete `RerankReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_rerank_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::rerank::RerankReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let query = wire
        .get("query")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let documents = rerank_documents(wire.get("documents"));
    if query.is_empty() || documents.is_empty() {
        return Err(IngressReject::BadRequest(
            "rerank request requires `query` and `documents`".into(),
        ));
    }
    Ok(crate::ir::rerank::RerankReq {
        model: wire
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        query,
        documents,
        top_n: wire
            .get("top_n")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        max_tokens_per_doc: wire
            .get("max_tokens_per_doc")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        ..Default::default()
    })
}

/// Wire -> concrete `RerankResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_rerank_response(
    wire: &[u8],
) -> Result<crate::ir::rerank::RerankResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    Ok(crate::ir::rerank::RerankResp {
        id: v.get("id").and_then(Value::as_str).map(str::to_string),
        results: read_rerank_results(v.get("results")),
        search_units: v
            .get("meta")
            .and_then(|m| m.get("billed_units"))
            .and_then(|b| b.get("search_units"))
            .and_then(Value::as_u64),
        ..Default::default()
    })
}
