// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bedrock `RequestHandler` + cells. Embeddings first (Titan, via InvokeModel).

use crate::codec::ir::embeddings::{
    EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData,
};
use crate::codec::keys;
use crate::codec::leaf_codec::LeafCodec;
use busbar_contract::codec::{CodecError, IngressReject, RequestHandler};
use busbar_contract::codec::{EgressCtx, WireBody};
use busbar_contract::operation::OpVerb;
use busbar_contract::SlabBytes;
use bytes::Bytes;
use serde_json::{json, Value};

pub struct BedrockRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: super::super::chat_handle::ChatOperation =
    super::super::chat_handle::ChatOperation(super::VENDOR_NAME);
static EMB: BedrockEmbeddings = BedrockEmbeddings;
static IMG: BedrockImage = BedrockImage;
static RERANK: BedrockRerank = BedrockRerank;

/// BEDROCK'S ROW OF THE SUPPORT MATRIX — the verbs this protocol speaks, as data. A verb absent
/// from it is a genuine gap → the standard no-handler 404.
static CELLS: &[busbar_contract::codec::Cell] = &[
    (OpVerb::CHAT, &CHAT),
    (OpVerb::EMBEDDINGS, &EMB),
    (OpVerb::IMAGE, &IMG),
    (OpVerb::RERANK, &RERANK),
];

impl RequestHandler for BedrockRequestHandler {
    dialect_identity!(super::VENDOR_NAME);
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        // Chat uses the Converse API (stream-aware); everything else rides InvokeModel. The
        // discriminator is this protocol's OWN verb constant, compared against this protocol's OWN
        // table — not a core enum's variant, which is the point of the 1.6.0 split.
        if ctx.operation == OpVerb::CHAT {
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
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<OpVerb> {
        // Converse is chat; InvokeModel multiplexes — the BODY names the op (Titan image vs Titan
        // embeddings). Unknown invoke bodies resolve to None (a clean 400 at the route layer).
        if path.ends_with("/converse") || path.ends_with("/converse-stream") {
            return Some(OpVerb::CHAT);
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
                return Some(OpVerb::RERANK);
            }
            if has(b"\"textToImageParams\"") {
                return Some(OpVerb::IMAGE);
            }
            if has(b"\"inputText\"") {
                return Some(OpVerb::EMBEDDINGS);
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
///
/// Titan image `InvokeModel` wire → IR (bedrock as INGRESS). Model rides the PATH, not the body —
/// the route layer resolves it; the IR's `model` is filled by routing (`IrReq::set_model`).
struct BedrockImage;

leaf_op! {
    BedrockImage: super::VENDOR_NAME,
    ImageReqHandle = read_image_request,
    ImageRespHandle = read_image_response;
    // Buffer the same-protocol non-stream 2xx body so the default `extract_usage` runs the op's own
    // reader and bills once. Titan/SDXL are per-image with no token usage object, so the tap bills 0
    // tokens and the per-image cost basis on the cross-protocol seam carries the charge — mirrors the
    // OpenAI/Gemini image cells (closes the same-protocol metering gap).
    fn taps_usage(&self) -> bool {
        true
    }
}

/// IR → Titan image request wire (the body of [`BedrockImage::write_request`], moved behind the
/// `(image, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_image_request(r: &crate::codec::ir::image::ImageReq) -> Bytes {
    let mut body = json!({
        "taskType": "TEXT_IMAGE",
        (super::TEXT_TO_IMAGE_PARAMS): { (keys::TEXT): r.prompt.clone().unwrap_or_default() },
        (super::IMAGE_GENERATION_CONFIG): { (super::NUMBER_OF_IMAGES): r.n.unwrap_or(1) },
    });
    // Re-emit the generation controls `read_image_request` captures, in Titan's native shape, so
    // they survive egress instead of being dropped (round-trip loss). `negativeText` rides
    // `textToImageParams`; `seed` and `cfgScale` ride `imageGenerationConfig` (Titan's own
    // TextToImageParams / ImageGenerationConfig layout). Emitted only when present so a request
    // that never carried them gains no fabricated field.
    if let Some(neg) = &r.negative_prompt {
        body[super::TEXT_TO_IMAGE_PARAMS][super::NEGATIVE_TEXT] = json!(neg);
    }
    if let Some(seed) = r.seed {
        body[super::IMAGE_GENERATION_CONFIG][keys::SEED] = json!(seed);
    }
    if let Some(cfg) = r.guidance_scale {
        body[super::IMAGE_GENERATION_CONFIG][super::CFG_SCALE] = json!(cfg);
    }
    // Titan's ImageGenerationConfig takes explicit `width`/`height` (from the IR's pixel geometry)
    // and a `quality` (standard|premium) — both Titan-native. The old writer dropped them, so an
    // openai->bedrock image request lost its size and quality tier. Only an explicit W×H is emitted
    // (Titan has no `auto`); `quality` is carried verbatim.
    if let Some(crate::codec::ir::image::ImageSize::Wh { width, height }) = r.size {
        body[super::IMAGE_GENERATION_CONFIG][super::WIDTH] = json!(width);
        body[super::IMAGE_GENERATION_CONFIG][super::HEIGHT] = json!(height);
    }
    if let Some(q) = &r.quality {
        body[super::IMAGE_GENERATION_CONFIG][keys::QUALITY] = json!(q);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → Titan image response wire (the body of [`BedrockImage::write_response`], moved behind the
/// `(image, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_image_response(r: &crate::codec::ir::image::ImageResp) -> WireBody {
    let images: Vec<&str> = r.images.iter().filter_map(|i| i.b64.as_deref()).collect();
    WireBody::json(SlabBytes::from(
        serde_json::to_vec(&json!({ (super::IMAGES): images })).unwrap_or_default(),
    ))
}

/// Amazon Titan Embeddings via `/model/{id}/invoke`.
///
/// Titan `InvokeModel` wire → IR (bedrock as INGRESS): `inputText` (+ v2 dims/normalize). Model
/// rides the PATH; routing fills it via `IrReq::set_model`.
struct BedrockEmbeddings;

leaf_op! {
    BedrockEmbeddings: super::VENDOR_NAME,
    EmbeddingsReqHandle = read_embeddings_request,
    EmbeddingsRespHandle = read_embeddings_response;
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
}

/// IR → Titan embeddings request wire (the body of [`BedrockEmbeddings::write_request`], moved behind
/// the `(embeddings, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_embeddings_request(r: &EmbeddingsReq) -> Bytes {
    let text = match &r.input {
        EmbInput::Text(v) => {
            // Titan's InvokeModel embeddings takes a SINGLE `inputText`; a multi-input request
            // (OpenAI allows an array) can only embed the first here. Warn rather than silently
            // drop the rest — true multi-input fan-out to single-input backends is a 1.3 item.
            if v.len() > 1 {
                crate::codec::drops::writer_drop!(
                    crate::codec::drops::member(keys::INPUT),
                    &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                    [dropped = v.len() - 1,],
                    "Titan embeddings takes one input; embedding only the first of a \
                     multi-input request (the rest are not sent)"
                );
            }
            v.first().cloned().unwrap_or_default()
        }
        other => {
            crate::codec::drops::writer_drop!(
                crate::codec::drops::member(keys::INPUT),
                &crate::codec::diagnostics::IR_DROP_UNMODELED_KEYS,
                [dropped = 1,],
                "Titan embeddings takes text input only; dropping a non-text embeddings \
                 input ({other:?} kind) with no analog"
            );
            String::new()
        }
    };
    let mut body = json!({ (super::INPUT_TEXT): text });
    if let Some(d) = r.dimensions {
        body[keys::DIMENSIONS] = json!(d);
    }
    // Titan v2 embeddings takes a top-level `normalize` boolean, which `read_embeddings_request`
    // captures — emit it when present so it survives egress instead of being dropped (round-trip
    // loss). Titan's own default is `true`, so omit the key when the request never set it rather
    // than fabricate a value.
    if let Some(n) = r.normalize {
        body[super::NORMALIZE] = json!(n);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → Titan embeddings response wire (the body of [`BedrockEmbeddings::write_response`], moved
/// behind the `(embeddings, bedrock)` key — G6 A4b option-a). Byte-identical to the inline write.
pub fn write_embeddings_response(r: &EmbeddingsResp) -> WireBody {
    let floats: Vec<f32> = r
        .embeddings
        .first()
        .and_then(|item| match item.vectors.get(&EncFmt::Float) {
            Some(VectorData::Float(v)) => Some(v.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let mut body = json!({ (keys::EMBEDDING): floats });
    if let Some(u) = &r.usage {
        body[super::INPUT_TEXT_TOKEN_COUNT] = json!(u.input);
    }
    WireBody::json(SlabBytes::from(
        serde_json::to_vec(&body).unwrap_or_default(),
    ))
}

/// Bedrock rerank models (`cohere.rerank-*`, `amazon.rerank-*`) via `/model/{id}/invoke`:
/// `{query, documents[], top_n?, api_version}` → `{results: [{index, relevance_score}]}` — the
/// same result shape as Cohere's own `/v2/rerank`, so translation between the two is exact. The
/// model rides the URL (path-model protocol); `api_version: 2` is required by the cohere.rerank
/// models and harmless to amazon.rerank.
struct BedrockRerank;

leaf_op! {
    BedrockRerank: super::VENDOR_NAME,
    RerankReqHandle = read_rerank_request,
    RerankRespHandle = read_rerank_response;
    // Search-unit metered, as the Cohere cell: buffer the same-protocol non-stream 2xx body so the
    // relay's tap reads the `meta.billed_units.search_units` it billed (item 134).
    fn taps_usage(&self) -> bool {
        true
    }
}

/// IR → bedrock rerank request wire (the body of [`BedrockRerank::write_request`], moved behind the
/// `(rerank, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_rerank_request(r: &crate::codec::ir::rerank::RerankReq) -> Bytes {
    let mut body = json!({
        (keys::QUERY): r.query,
        (keys::DOCUMENTS): r.documents,
        "api_version": 2,
    });
    if let Some(n) = r.top_n {
        body[keys::TOP_N] = json!(n);
    }
    // Carry `return_documents` so a rerank hop into Bedrock echoes the ranked text (shared with the
    // Cohere rerank surface, whose response shape Bedrock mirrors).
    if let Some(rd) = r.return_documents {
        body[keys::RETURN_DOCUMENTS] = json!(rd);
    }
    Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
}

/// IR → bedrock rerank response wire (the body of [`BedrockRerank::write_response`], moved behind the
/// `(rerank, bedrock)` key — G6 A4b option-a). Byte-identical to the pre-cutover inline write.
pub fn write_rerank_response(r: &crate::codec::ir::rerank::RerankResp) -> WireBody {
    let results: Vec<Value> = r
        .results
        .iter()
        .map(|x| {
            let mut o = json!({"index": x.index, "relevance_score": x.relevance_score});
            // Echo the ranked document (Cohere/Bedrock `{text}` shape) when present.
            if let Some(doc) = &x.document {
                o[keys::DOCUMENT] = json!({ (keys::TEXT): doc });
            }
            o
        })
        .collect();
    let mut body = json!({ (keys::RESULTS): results });
    if let Some(id) = &r.id {
        body[keys::ID] = json!(id);
    }
    WireBody::json(SlabBytes::from(
        serde_json::to_vec(&body).unwrap_or_default(),
    ))
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
pub fn read_image_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::codec::ir::image::ImageReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let params = wire
        .get(super::TEXT_TO_IMAGE_PARAMS)
        .cloned()
        .unwrap_or_default();
    let cfg = wire
        .get(super::IMAGE_GENERATION_CONFIG)
        .cloned()
        .unwrap_or_default();
    Ok(crate::codec::ir::image::ImageReq {
        prompt: params
            .get(keys::TEXT)
            .and_then(Value::as_str)
            .map(str::to_string),
        negative_prompt: params
            .get(super::NEGATIVE_TEXT)
            .and_then(Value::as_str)
            .map(str::to_string),
        n: cfg
            .get(super::NUMBER_OF_IMAGES)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        seed: cfg.get(keys::SEED).and_then(Value::as_u64),
        guidance_scale: cfg
            .get(super::CFG_SCALE)
            .and_then(Value::as_f64)
            .map(|f| f as f32),
        // Titan-native pixel geometry + quality tier — carried so egress re-emits them.
        size: match (
            cfg.get(super::WIDTH).and_then(Value::as_u64),
            cfg.get(super::HEIGHT).and_then(Value::as_u64),
        ) {
            // Checked narrowing (mirrors the `u32::try_from(...).ok()` used for `numberOfImages`
            // above): an out-of-range width/height drops the geometry rather than silently WRAPPING
            // (e.g. `4294967297 as u32 == 1`), which would fabricate a bogus 1px dimension.
            (Some(w), Some(h)) => match (u32::try_from(w).ok(), u32::try_from(h).ok()) {
                (Some(width), Some(height)) => {
                    Some(crate::codec::ir::image::ImageSize::Wh { width, height })
                }
                _ => None,
            },
            _ => None,
        },
        quality: cfg
            .get(keys::QUALITY)
            .and_then(Value::as_str)
            .map(str::to_string),
        ..Default::default()
    })
}

/// Wire -> concrete `ImageResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_image_response(wire: &[u8]) -> Result<crate::codec::ir::image::ImageResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let images: Vec<busbar_contract::media::ImageOutput> = v
        .get(super::IMAGES)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|b| b.as_str())
                .map(|b| busbar_contract::media::ImageOutput {
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
    let cost_basis = Some(crate::codec::ir::image::CostBasis {
        count: u32::try_from(images.len()).unwrap_or(u32::MAX),
        ..Default::default()
    });
    Ok(crate::codec::ir::image::ImageResp {
        images,
        cost_basis,
        ..Default::default()
    })
}

/// Wire -> concrete `EmbeddingsReq` parse, extracted from the `OperationHandler::read_request`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_embeddings_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::codec::ir::embeddings::EmbeddingsReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let Some(text) = wire.get(super::INPUT_TEXT).and_then(Value::as_str) else {
        return Err(IngressReject::BadRequest(
            "invoke embeddings requires `inputText`".into(),
        ));
    };
    Ok(crate::codec::ir::embeddings::EmbeddingsReq {
        input: EmbInput::Text(vec![text.to_string()]),
        dimensions: wire
            .get(keys::DIMENSIONS)
            .and_then(Value::as_u64)
            .and_then(|d| u32::try_from(d).ok()),
        normalize: wire.get(super::NORMALIZE).and_then(Value::as_bool),
        encoding_formats: vec![EncFmt::Float],
        ..Default::default()
    })
}

/// Wire -> concrete `EmbeddingsResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_embeddings_response(
    wire: &[u8],
) -> Result<crate::codec::ir::embeddings::EmbeddingsResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    let mut item = EmbeddingItem::default();
    if let Some(f) = v.get(keys::EMBEDDING).and_then(Value::as_array) {
        item.vectors.insert(
            EncFmt::Float,
            VectorData::Float(
                f.iter()
                    .filter_map(|x| x.as_f64().map(|n| n as f32))
                    .collect(),
            ),
        );
    }
    // BILLED COUNT (item 133): absent or `null` is no usage (unchanged); a present-but-UNREADABLE
    // count REFUSES rather than reading as "no usage reported".
    let usage =
        crate::codec::usage_count::billed_count_opt(Some(&v), super::INPUT_TEXT_TOKEN_COUNT)
            .map_err(|e| CodecError::Malformed(e.to_string()))?
            .map(|n| busbar_contract::billing::TokenUsage {
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
pub fn read_rerank_request(
    body: &[u8],
    _content_type: &str,
) -> Result<crate::codec::ir::rerank::RerankReq, IngressReject> {
    let wire: Value =
        serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
    let query = wire
        .get(keys::QUERY)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let documents = crate::codec::rerank_wire::read_documents(wire.get(keys::DOCUMENTS));
    if query.is_empty() || documents.is_empty() {
        return Err(IngressReject::BadRequest(
            "rerank request requires `query` and `documents`".into(),
        ));
    }
    Ok(crate::codec::ir::rerank::RerankReq {
        // Path-model protocol: the model arrives via the URL and routing calls `set_model`.
        model: String::new(),
        query,
        documents,
        top_n: wire
            .get(keys::TOP_N)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        // Read `return_documents` (cohere.rerank-*/amazon.rerank-* honor it) so a bedrock->bedrock
        // rerank preserves the flag the writer re-emits — the reader formerly skipped it, an
        // asymmetry with Cohere's reader that silently dropped `return_documents:true`.
        return_documents: wire.get(keys::RETURN_DOCUMENTS).and_then(Value::as_bool),
        ..Default::default()
    })
}

/// Wire -> concrete `RerankResp` parse, extracted from the `OperationHandler::read_response`
/// body so a dissolved leaf-op handle and the `(op,proto)` `leaf_codec` read dispatch (G6 A4b,
/// owner ruling b) can recover the concrete IR without a downcast. Byte-identical parse.
pub fn read_rerank_response(
    wire: &[u8],
) -> Result<crate::codec::ir::rerank::RerankResp, CodecError> {
    let v: Value =
        serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
    Ok(crate::codec::ir::rerank::RerankResp {
        id: v.get(keys::ID).and_then(Value::as_str).map(str::to_string),
        results: crate::codec::rerank_wire::read_results(v.get(keys::RESULTS)),
        // A Bedrock-hosted Cohere rerank model answers in Cohere's shape; the search units it billed
        // (`meta.billed_units.search_units`) are read EXACTLY, as the Cohere reader reads them. A body
        // without them stays the flat marker — nothing is estimated.
        search_units: crate::codec::usage_count::billed_count_opt(
            v.get("meta").and_then(|m| m.get("billed_units")),
            "search_units",
        )
        .map_err(|e| CodecError::Malformed(e.to_string()))?,
        ..Default::default()
    })
}

/// This dialect's row of the leaf-op `(operation, protocol)` dispatch, carried on `super::ENTRY`.
pub(crate) const LEAF: crate::codec::leaf_codec::LeafCodecs =
    crate::codec::leaf_codec::LeafCodecs {
        embeddings: Some(LeafCodec {
            write_request: write_embeddings_request,
            write_response: write_embeddings_response,
            read_request: read_embeddings_request,
            read_response: read_embeddings_response,
        }),
        rerank: Some(LeafCodec {
            write_request: write_rerank_request,
            write_response: write_rerank_response,
            read_request: read_rerank_request,
            read_response: read_rerank_response,
        }),
        image: Some(LeafCodec {
            write_request: write_image_request,
            write_response: write_image_response,
            read_request: read_image_request,
            read_response: read_image_response,
        }),
        ..crate::codec::leaf_codec::LeafCodecs::NONE
    };
