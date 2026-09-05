// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bedrock `RequestHandler` + cells. Embeddings first (Titan, via InvokeModel).

use crate::ir::embeddings::{
    EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData,
};
use busbar_api::operation::Operation;
use busbar_substrate::handlers::{CodecError, IngressReject, OperationHandler, RequestHandler};
use busbar_substrate::ir::handle::IrHandle;
use busbar_substrate::wire::{EgressCtx, WireBody};
use bytes::Bytes;
use serde_json::{json, Value};

pub struct BedrockRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: super::super::chat_handle::ChatOperation =
    super::super::chat_handle::ChatOperation("bedrock");
static EMB: BedrockEmbeddings = BedrockEmbeddings;
static IMG: BedrockImage = BedrockImage;
static RERANK: BedrockRerank = BedrockRerank;

/// BEDROCK'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data. A verb absent
/// from it is a genuine gap → the standard no-handler 404.
static CELLS: &[busbar_substrate::handlers::Cell] = &[
    (Operation::CHAT, &CHAT),
    (Operation::EMBEDDINGS, &EMB),
    (Operation::IMAGE, &IMG),
    (Operation::RERANK, &RERANK),
];

/// Billable usage for a complete same-protocol (Bedrock -> Bedrock) non-stream 2xx body, keyed by
/// the body's SHAPE rather than by the operation. The buffered Converse translator
/// (`BedrockConverseBodyTranslator`) sits in for the verbatim relay on every Bedrock same-protocol
/// non-stream response, and the forward path then reads billing usage from the translator instead
/// of asking the operation. The translator does not know which operation it serves, so this picks
/// the same `extract_usage` the operation would have run, from the response shape:
///   - `output` / `stopReason` (a Converse body)     -> the chat tap (the Converse reader's usage)
///   - `images`                                        -> the image cell's tap
///   - `embedding` / `inputTextTokenCount`             -> the embeddings cell's tap
///   - `results` (a Rerank body)                       -> nothing (rerank does not tap usage)
///   - anything else                                   -> the chat tap (the decode-failure warn it
///     raises is the one the relay raised too)
///
/// `parsed` is the body already decoded by the caller (`None` when it is not JSON), so the shape
/// probe costs no second parse.
pub(crate) fn same_protocol_usage(
    body: &[u8],
    parsed: Option<&Value>,
) -> Option<busbar_substrate::billing::TokenUsage> {
    let has = |k: &str| parsed.is_some_and(|v| v.get(k).is_some());
    if has("output") || has("stopReason") {
        CHAT.extract_usage("bedrock", body)
    } else if has("images") {
        IMG.extract_usage("bedrock", body)
    } else if has("embedding") || has("inputTextTokenCount") {
        EMB.extract_usage("bedrock", body)
    } else if has("results") {
        None
    } else {
        CHAT.extract_usage("bedrock", body)
    }
}

/// True when a same-protocol non-stream 2xx body is a Converse response (the shape that must carry
/// `metrics.latencyMs`), as opposed to an InvokeModel embeddings / image / rerank body, which has no
/// such member.
pub(crate) fn is_converse_response(v: &Value) -> bool {
    v.as_object()
        .is_some_and(|o| o.contains_key("output") || o.contains_key("stopReason"))
}

impl RequestHandler for BedrockRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "bedrock"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        busbar_substrate::handlers::cell_of(CELLS, op)
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        // Chat uses the Converse API (stream-aware); everything else rides InvokeModel. The
        // discriminator is this protocol's OWN verb constant, compared against this protocol's OWN
        // table — not a core enum's variant, which is the point of the 1.6.0 split.
        if ctx.operation == Operation::CHAT {
            let verb = if ctx.stream {
                "converse-stream"
            } else {
                "converse"
            };
            return format!("/model/{}/{verb}", ctx.model);
        }
        // Embeddings/image/rerank genuinely ride InvokeModel; a verb with no cell above is
        // unreachable here and answers the same thing for want of a truer answer at a site that
        // must return a `String`. That is the pre-1.6.0 answer, verbatim.
        format!("/model/{}/invoke", ctx.model)
    }
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation> {
        // Converse is chat; InvokeModel multiplexes — the BODY names the op (Titan image vs Titan
        // embeddings). Unknown invoke bodies resolve to None (a clean 400 at the route layer).
        if path.ends_with("/converse") || path.ends_with("/converse-stream") {
            return Some(Operation::CHAT);
        }
        if path.ends_with("/invoke") {
            // Anchor every scan to the QUOTED JSON key (`"key"`), not the bare token: an unanchored
            // `inputText` matched the substring inside a rerank query/document VALUE and misrouted the
            // whole request to embeddings. Check rerank (the two-key body) FIRST so a document that
            // merely mentions "inputText"/"textToImageParams" can't steal it.
            let has = |n: &[u8]| body.windows(n.len()).any(|w| w == n);
            // Rerank models (cohere.rerank-*, amazon.rerank-*) take {query, documents} — no
            // other InvokeModel body carries both keys.
            if has(b"\"query\"") && has(b"\"documents\"") {
                return Some(Operation::RERANK);
            }
            if has(b"\"textToImageParams\"") {
                return Some(Operation::IMAGE);
            }
            if has(b"\"inputText\"") {
                return Some(Operation::EMBEDDINGS);
            }
        }
        None
    }
    fn path_model(&self, path: &str) -> Option<String> {
        // `/model/{model}/{converse|converse-stream|invoke}` — the middle segment.
        let rest = path.strip_prefix("/model/")?;
        let (model, _verb) = rest.rsplit_once('/')?;
        (!model.is_empty()).then(|| model.to_string())
    }
}

/// Amazon Titan Image Generator via `/model/{id}/invoke`. prompt in → `images[]` (b64) out.
struct BedrockImage;

impl OperationHandler for BedrockImage {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("bedrock", status, body)
    }
    // Buffer the same-protocol non-stream 2xx body so the default `extract_usage` runs the op's own
    // reader and bills once. Titan/SDXL are per-image with no token usage object, so the tap bills 0
    // tokens and the per-image cost basis on the cross-protocol seam carries the charge — mirrors the
    // OpenAI/Gemini image cells (closes the same-protocol metering gap).
    fn taps_usage(&self) -> bool {
        true
    }
    /// Titan image `InvokeModel` wire → IR (bedrock as INGRESS). Model rides the PATH, not the body —
    /// the route layer resolves it; the IR's `model` is filled by routing (`IrReq::set_model`).
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn IrHandle>, IngressReject> {
        Ok(Box::new(super::super::leaf_handles::ImageReqHandle(
            read_image_request(body, _content_type)?,
        )) as Box<dyn IrHandle>)
    }
    fn read_response(&self, wire: &[u8]) -> Result<Box<dyn IrHandle>, CodecError> {
        Ok(Box::new(super::super::leaf_handles::ImageRespHandle(
            read_image_response(wire)?,
        )) as Box<dyn IrHandle>)
    }
}

/// IR → Titan image request wire (the body of [`BedrockImage::write_request`], moved behind the
/// `(image, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_image_request(r: &crate::ir::image::ImageReq) -> Bytes {
    let mut body = json!({
        "taskType": "TEXT_IMAGE",
        "textToImageParams": { "text": r.prompt.clone().unwrap_or_default() },
        "imageGenerationConfig": { "numberOfImages": r.n.unwrap_or(1) },
    });
    // Re-emit the generation controls `read_image_request` captures, in Titan's native shape, so
    // they survive egress instead of being dropped (round-trip loss). `negativeText` rides
    // `textToImageParams`; `seed` and `cfgScale` ride `imageGenerationConfig` (Titan's own
    // TextToImageParams / ImageGenerationConfig layout). Emitted only when present so a request
    // that never carried them gains no fabricated field.
    if let Some(neg) = &r.negative_prompt {
        body["textToImageParams"]["negativeText"] = json!(neg);
    }
    if let Some(seed) = r.seed {
        body["imageGenerationConfig"]["seed"] = json!(seed);
    }
    if let Some(cfg) = r.guidance_scale {
        body["imageGenerationConfig"]["cfgScale"] = json!(cfg);
    }
    // Titan's ImageGenerationConfig takes explicit `width`/`height` (from the IR's pixel geometry)
    // and a `quality` (standard|premium) — both Titan-native. The old writer dropped them, so an
    // openai->bedrock image request lost its size and quality tier. Only an explicit W×H is emitted
    // (Titan has no `auto`); `quality` is carried verbatim.
    if let Some(crate::ir::image::ImageSize::Wh { width, height }) = r.size {
        body["imageGenerationConfig"]["width"] = json!(width);
        body["imageGenerationConfig"]["height"] = json!(height);
    }
    if let Some(q) = &r.quality {
        body["imageGenerationConfig"]["quality"] = json!(q);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → Titan image response wire (the body of [`BedrockImage::write_response`], moved behind the
/// `(image, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_image_response(r: &crate::ir::image::ImageResp) -> WireBody {
    let images: Vec<&str> = r.images.iter().filter_map(|i| i.b64.as_deref()).collect();
    WireBody::json(Bytes::from(
        serde_json::to_vec(&json!({ "images": images })).unwrap_or_default(),
    ))
}

/// Amazon Titan Embeddings via `/model/{id}/invoke`.
struct BedrockEmbeddings;

impl OperationHandler for BedrockEmbeddings {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("bedrock", status, body)
    }
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
    /// Titan `InvokeModel` wire → IR (bedrock as INGRESS): `inputText` (+ v2 dims/normalize). Model
    /// rides the PATH; routing fills it via `IrReq::set_model`.
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

/// IR → Titan embeddings request wire (the body of [`BedrockEmbeddings::write_request`], moved behind
/// the `(embeddings, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_embeddings_request(r: &EmbeddingsReq) -> Bytes {
    let text = match &r.input {
        EmbInput::Text(v) => {
            // Titan's InvokeModel embeddings takes a SINGLE `inputText`; a multi-input request
            // (OpenAI allows an array) can only embed the first here. Warn rather than silently
            // drop the rest — true multi-input fan-out to single-input backends is a 1.3 item.
            if v.len() > 1 {
                tracing::warn!(
                    dropped = v.len() - 1,
                    "Titan embeddings takes one input; embedding only the first of a \
                     multi-input request (the rest are not sent)"
                );
            }
            v.first().cloned().unwrap_or_default()
        }
        other => {
            tracing::warn!(
                dropped = 1,
                "Titan embeddings takes text input only; dropping a non-text embeddings \
                 input ({other:?} kind) with no analog"
            );
            String::new()
        }
    };
    let mut body = json!({ "inputText": text });
    if let Some(d) = r.dimensions {
        body["dimensions"] = json!(d);
    }
    // Titan v2 embeddings takes a top-level `normalize` boolean, which `read_embeddings_request`
    // captures — emit it when present so it survives egress instead of being dropped (round-trip
    // loss). Titan's own default is `true`, so omit the key when the request never set it rather
    // than fabricate a value.
    if let Some(n) = r.normalize {
        body["normalize"] = json!(n);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → Titan embeddings response wire (the body of [`BedrockEmbeddings::write_response`], moved
/// behind the `(embeddings, bedrock)` key — G6 A4b option-a). Byte-identical to the inline write.
pub(crate) fn write_embeddings_response(r: &EmbeddingsResp) -> WireBody {
    let floats: Vec<f32> = r
        .embeddings
        .first()
        .and_then(|item| match item.vectors.get(&EncFmt::Float) {
            Some(VectorData::Float(v)) => Some(v.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let mut body = json!({ "embedding": floats });
    if let Some(u) = &r.usage {
        body["inputTextTokenCount"] = json!(u.input);
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

/// Bedrock rerank models (`cohere.rerank-*`, `amazon.rerank-*`) via `/model/{id}/invoke`:
/// `{query, documents[], top_n?, api_version}` → `{results: [{index, relevance_score}]}` — the
/// same result shape as Cohere's own `/v2/rerank`, so translation between the two is exact. The
/// model rides the URL (path-model protocol); `api_version: 2` is required by the cohere.rerank
/// models and harmless to amazon.rerank.
struct BedrockRerank;

impl OperationHandler for BedrockRerank {
    /// This protocol's error envelope, shared by every operation it serves: the same
    /// vocabulary its chat cell reports, read from the same upstream.
    fn extract_error(
        &self,
        status: u16,
        body: &[u8],
    ) -> busbar_substrate::breaker::RawUpstreamError {
        super::super::proto_codec::protocol_error("bedrock", status, body)
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

/// IR → bedrock rerank request wire (the body of [`BedrockRerank::write_request`], moved behind the
/// `(rerank, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_rerank_request(r: &crate::ir::rerank::RerankReq) -> Bytes {
    let mut body = json!({
        "query": r.query,
        "documents": r.documents,
        "api_version": 2,
    });
    if let Some(n) = r.top_n {
        body["top_n"] = json!(n);
    }
    // Carry `return_documents` so a rerank hop into Bedrock echoes the ranked text (shared with the
    // Cohere rerank surface, whose response shape Bedrock mirrors).
    if let Some(rd) = r.return_documents {
        body["return_documents"] = json!(rd);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → bedrock rerank response wire (the body of [`BedrockRerank::write_response`], moved behind the
/// `(rerank, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub(crate) fn write_rerank_response(r: &crate::ir::rerank::RerankResp) -> WireBody {
    let results: Vec<Value> = r
        .results
        .iter()
        .map(|x| {
            let mut o = json!({"index": x.index, "relevance_score": x.relevance_score});
            // Echo the ranked document (Cohere/Bedrock `{text}` shape) when present.
            if let Some(doc) = &x.document {
                o["document"] = json!({ "text": doc });
            }
            o
        })
        .collect();
    let mut body = json!({ "results": results });
    if let Some(id) = &r.id {
        body["id"] = json!(id);
    }
    WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
}

#[cfg(test)]
#[path = "tests/handler_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/titan_roundtrip_regression_tests.rs"]
mod titan_roundtrip_regression_tests;

/// Wire -> concrete `ImageReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_image_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::image::ImageReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let params = wire.get("textToImageParams").cloned().unwrap_or_default();
    let cfg = wire
        .get("imageGenerationConfig")
        .cloned()
        .unwrap_or_default();
    Ok(crate::ir::image::ImageReq {
        prompt: params
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_string),
        negative_prompt: params
            .get("negativeText")
            .and_then(Value::as_str)
            .map(str::to_string),
        n: cfg
            .get("numberOfImages")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        seed: cfg.get("seed").and_then(Value::as_u64),
        guidance_scale: cfg
            .get("cfgScale")
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        // Titan-native pixel geometry + quality tier — carried so egress re-emits them.
        size: match (
            cfg.get("width").and_then(Value::as_u64),
            cfg.get("height").and_then(Value::as_u64),
        ) {
            // Checked narrowing (mirrors the `u32::try_from(...).ok()` used for `numberOfImages`
            // above): an out-of-range width/height drops the geometry rather than silently WRAPPING
            // (e.g. `4294967297 as u32 == 1`), which would fabricate a bogus 1px dimension.
            (Some(w), Some(h)) => match (u32::try_from(w).ok(), u32::try_from(h).ok()) {
                (Some(width), Some(height)) => {
                    Some(crate::ir::image::ImageSize::Wh { width, height })
                }
                _ => None,
            },
            _ => None,
        },
        quality: cfg
            .get("quality")
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    })
}

/// Wire -> concrete `ImageResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_image_response(wire: &[u8]) -> Result<crate::ir::image::ImageResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let images: Vec<busbar_substrate::media::ImageOutput> = v
        .get("images")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|b| b.as_str())
                .map(|b| busbar_substrate::media::ImageOutput {
                    b64: Some(b.to_string()),
                    ..Default::default()
                })
                .collect()
        })
        .unwrap_or_default();
    // Titan/SDXL image models are PER-IMAGE (they return N base64 images in `images`, no token usage
    // object). Without a cost basis `ImageResp::billing()` returns `None` when BOTH `usage` and
    // `cost_basis` are unset — every Bedrock image response billed NOTHING. Record the per-image cost
    // basis (count = one image per `images` entry) so `billing()` yields `Billing::Images`. Size /
    // quality tiers live on the request params, which this response-only reader cannot see (`None`).
    let cost_basis = Some(crate::ir::image::CostBasis {
        count: u32::try_from(images.len()).unwrap_or(u32::MAX),
        ..Default::default()
    });
    Ok(crate::ir::image::ImageResp {
        images,
        cost_basis,
        ..Default::default()
    })
}

/// Wire -> concrete `EmbeddingsReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub(crate) fn read_embeddings_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::ir::embeddings::EmbeddingsReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let Some(text) = wire.get("inputText").and_then(Value::as_str) else {
        return Err(IngressReject::BadRequest(
            "invoke embeddings requires `inputText`".into(),
        ));
    };
    Ok(crate::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Text(vec![text.to_string()]),
        dimensions: wire
            .get("dimensions")
            .and_then(Value::as_u64)
            .and_then(|d| u32::try_from(d).ok()),
        normalize: wire.get("normalize").and_then(Value::as_bool),
        encoding_formats: vec![EncFmt::Float],
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
    let mut item = EmbeddingItem::default();
    if let Some(f) = v.get("embedding").and_then(Value::as_array) {
        item.vectors.insert(
            EncFmt::Float,
            VectorData::Float(
                f.iter()
                    .filter_map(|x| x.as_f64().map(|n| n as f32))
                    .collect(),
            ),
        );
    }
    let usage = v
        .get("inputTextTokenCount")
        .and_then(Value::as_u64)
        .map(|n| busbar_substrate::billing::TokenUsage {
            input: n,
            ..Default::default()
        });
    Ok(EmbeddingsResp {
        embeddings: vec![item],
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
    let documents = super::super::cohere::handler::rerank_documents_pub(wire.get("documents"));
    if query.is_empty() || documents.is_empty() {
        return Err(IngressReject::BadRequest(
            "rerank request requires `query` and `documents`".into(),
        ));
    }
    Ok(crate::ir::rerank::RerankReq {
        // Path-model protocol: the model arrives via the URL and routing calls `set_model`.
        model: String::new(),
        query,
        documents,
        top_n: wire
            .get("top_n")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        // Read `return_documents` (cohere.rerank-*/amazon.rerank-* honor it) so a bedrock->bedrock
        // rerank preserves the flag the writer re-emits — the reader formerly skipped it, an
        // asymmetry with Cohere's reader that silently dropped `return_documents:true`.
        return_documents: wire.get("return_documents").and_then(Value::as_bool),
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
        results: super::super::cohere::handler::read_rerank_results(v.get("results")),
        ..Default::default()
    })
}
