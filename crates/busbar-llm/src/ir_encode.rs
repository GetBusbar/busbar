// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR → wire ENCODE helpers shared across the LLM dialect writers.
//!
//! Small pure projections of concrete IR onto wire-shape decisions (image source → `image_url`
//! string, structured-json tool-result detection, the `tools[].strict` drop warning). They name
//! concrete IR, so they belong beside the codecs that use them rather than in the neutral router;
//! every caller is a `busbar-llm` writer reached through the vtable, so core never names them.

/// Reconstruct an OpenAI/Responses `image_url` string from an [`busbar_core::ir::IrImageSource`] —
/// the inverse of core's `parse_image_url`. A `Url` is emitted verbatim; a `Base64` is re-wrapped
/// into a `data:<mime>;base64,<payload>` URI. A `Vendor` reference has no `image_url` projection, so
/// returns `None` and the caller drops the block with a warn. Shared by the Chat and Responses writers.
pub fn image_url_from_ir(source: &busbar_core::ir::IrImageSource) -> Option<String> {
    match source {
        busbar_core::ir::IrImageSource::Url(url) => Some(url.clone()),
        busbar_core::ir::IrImageSource::Base64 { media_type, data } => {
            Some(format!("data:{media_type};base64,{data}"))
        }
        // An opaque vendor reference has no neutral `image_url` projection.
        busbar_core::ir::IrImageSource::Vendor { .. } => None,
    }
}

/// True when an image source is a vendor-scoped reference with no neutral form — a foreign writer
/// that sees one must skip the image with a `tracing::warn!` instead of emitting a corrupt block. The
/// PRODUCING protocol re-emits its own `Vendor` reference same-protocol and does NOT route through
/// here (it matches its own `vendor` tag first).
pub fn is_unresolvable_image_ref(source: &busbar_core::ir::IrImageSource) -> bool {
    matches!(source, busbar_core::ir::IrImageSource::Vendor { .. })
}

/// True when an IR block is a structured-json tool-result content block
/// ([`busbar_core::ir::IrBlock::Json`]) rather than text/image — used by NON-Bedrock ToolResult
/// writers to drop-with-warn it (there is no lossless cross-protocol projection of a Bedrock
/// `{"json":…}` tool-result).
pub fn is_json_tool_result_block(block: &busbar_core::ir::IrBlock) -> bool {
    matches!(block, busbar_core::ir::IrBlock::Json(_))
}

/// Signal that this egress dialect cannot express [`busbar_core::ir::IrTool::strict`], naming the
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
pub fn warn_dropped_tool_strict(tools: &[busbar_core::ir::IrTool], egress: &'static str) {
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
