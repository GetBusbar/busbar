// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR ↔ wire projection helpers shared across the LLM dialect codecs.
//!
//! Small pure projections between concrete IR and wire-shape decisions: the image-source pair
//! (`image_url` string ↔ IR, both directions), structured-json tool-result detection, and the
//! `tools[].strict` drop warning. They name concrete IR, so they belong beside the codecs that use
//! them rather than in the neutral router; every caller is a `busbar-llm` reader/writer reached
//! through the vtable, so core never names them.

/// Reconstruct an OpenAI/Responses `image_url` string from an [`crate::ir::IrImageSource`] —
/// the inverse of core's `parse_image_url`. A `Url` is emitted verbatim; a `Base64` is re-wrapped
/// into a `data:<mime>;base64,<payload>` URI. A `Vendor` reference has no `image_url` projection, so
/// returns `None` and the caller drops the block with a warn. Shared by the Chat and Responses writers.
pub fn image_url_from_ir(source: &crate::ir::IrImageSource) -> Option<String> {
    match source {
        crate::ir::IrImageSource::Url(url) => Some(url.clone()),
        crate::ir::IrImageSource::Base64 { media_type, data } => {
            Some(format!("data:{media_type};base64,{data}"))
        }
        // An opaque vendor reference has no neutral `image_url` projection.
        crate::ir::IrImageSource::Vendor { .. } => None,
    }
}

/// Decompose an OpenAI/Responses `image_url` string into the IR image source — the inverse of
/// [`image_url_from_ir`]. Shared verbatim by the Chat and Responses readers (both surfaces use the
/// same `image_url` wire shape).
///
/// A `data:<mime>;base64,<payload>` URI is decomposed into its real MIME type ("image/png") and raw
/// base64 payload, matching the IR contract the Anthropic reader/writer use for base64 images. Any
/// other URL (an https reference, or a data URI we cannot confidently split) is preserved verbatim in
/// `data` with an "image_url" media_type sentinel so the writer can reconstruct the exact original
/// `image_url` on a same-protocol round-trip rather than mangling it.
pub fn parse_image_url(url: &str) -> crate::ir::IrImageSource {
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some((meta, payload)) = rest.split_once(',') {
            // meta is e.g. "image/png;base64" or "image/png" — keep only the MIME type.
            let media_type = meta.split(';').next().unwrap_or("").to_string();
            if meta.contains("base64") && !media_type.is_empty() {
                return crate::ir::IrImageSource::Base64 {
                    media_type,
                    data: payload.to_string(),
                };
            }
        }
    }
    // Non-data URL (https://...) or an unrecognized data URI: keep it verbatim as a URL reference so
    // the writer round-trips it as-is rather than mangling it.
    crate::ir::IrImageSource::Url(url.to_string())
}

/// True when an image source is a vendor-scoped reference with no neutral form — a foreign writer
/// that sees one must skip the image with a `tracing::warn!` instead of emitting a corrupt block. The
/// PRODUCING protocol re-emits its own `Vendor` reference same-protocol and does NOT route through
/// here (it matches its own `vendor` tag first).
pub fn is_unresolvable_image_ref(source: &crate::ir::IrImageSource) -> bool {
    matches!(source, crate::ir::IrImageSource::Vendor { .. })
}

/// True when an IR block is a structured-json tool-result content block
/// ([`crate::ir::IrBlock::Json`]) rather than text/image — used by NON-Bedrock ToolResult
/// writers to drop-with-warn it (there is no lossless cross-protocol projection of a Bedrock
/// `{"json":…}` tool-result).
pub fn is_json_tool_result_block(block: &crate::ir::IrBlock) -> bool {
    matches!(block, crate::ir::IrBlock::Json(_))
}

/// Signal that this egress dialect cannot express [`crate::ir::IrTool::strict`], naming the
/// tools whose strict-schema guarantee is being dropped.
///
/// `strict: true` is a BEHAVIOURAL contract — OpenAI guarantees the model's tool arguments conform
/// to the schema exactly, and callers legitimately skip validation because of it. Anthropic, Gemini,
/// Bedrock and Cohere have no per-tool equivalent (Cohere's `strict_tools` is a request-level switch,
/// not a per-tool one), so the guarantee genuinely cannot cross — but it was crossing SILENTLY, which
/// turned "your tool arguments are schema-guaranteed" into "they are not" with nothing said. One warn
/// per request naming the affected tools, so the drop is at least visible in the logs.
///
/// Called by each writer that cannot express the flag; the writers that CAN (OpenAI Chat, Responses)
/// emit it instead and never call this.
pub fn warn_dropped_tool_strict(tools: &[crate::ir::IrTool], egress: &'static str) {
    let named: Vec<&str> = tools
        .iter()
        .filter(|t| t.strict.is_some())
        .map(|t| t.name.as_str())
        .collect();
    if named.is_empty() {
        return;
    }
    tracing::warn!(
        egress = %egress,
        tools = %named.join(","),
        "dropping `tools[].strict` on this egress: the target protocol has no per-tool strict-schema \
         flag, so the model's arguments are NO LONGER GUARANTEED to conform to the tool schema. \
         Validate tool arguments on this route, or pin the request to an openai/responses lane"
    );
}

/// The minimal one-token "ping" IR request an active health probe serializes through a dialect's own
/// `write_request` — so every protocol gets a valid probe body for free, no per-protocol probe code.
/// Shared by every writer's `probe_request` seam; the model is stamped afterward by the caller's
/// `rewrite_model_if_needed`, so this carries none.
pub fn ping_request() -> crate::ir::IrRequest {
    use crate::ir::{IrBlock, IrMessage, IrRequest, IrRole};
    IrRequest {
        reasoning: None,
        reasoning_budgets: None,
        logprobs: None,
        top_logprobs: None,
        user: None,
        parallel_tool_calls: None,
        system: vec![],
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Text {
                text: "ping".to_string(),
                cache_control: None,
                citations: vec![],
            }],
        }],
        tools: vec![],
        max_tokens: Some(1),
        temperature: None,
        top_p: None,
        top_k: None,
        stop: vec![],
        tool_choice: None,
        stream: false,
        frequency_penalty: None,
        presence_penalty: None,
        seed: None,
        n: None,
        response_format: None,
        extra: serde_json::Map::new(),
    }
}
