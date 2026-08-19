// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Anthropic `RequestHandler`. Chat-only today (Anthropic ships no embeddings/images/audio API here);
//! its non-chat operations stay `None` = no-handler 404. Chat dispatches through the same registry as
//! every other operation.

use busbar_core::handlers::{EgressCtx, OperationHandler, RequestHandler};
use busbar_core::operation::Operation;

/// Endpoint paths — each appears on BOTH the egress side (`upstream_path`) and the ingress match
/// (`resolve_operation`); single-sourced so the two sides cannot drift.
const PATH_MESSAGES: &str = "/v1/messages";

pub(crate) struct AnthropicRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: busbar_core::handlers::chat::ChatOperation =
    busbar_core::handlers::chat::ChatOperation("anthropic");

/// ANTHROPIC'S ROW OF THE SUPPORT MATRIX — one verb. Every other verb is the standard no-handler
/// 404, and it is the SAME answer for the LLM verbs Anthropic lacks and for the protocol-surface
/// verbs that are MCP's and A2A's rather than a special case: a protocol that does not speak a verb
/// has no cell, so the pair is unrepresentable rather than refused at runtime.
static CELLS: &[busbar_core::handlers::Cell] = &[(Operation::CHAT, &CHAT)];

impl RequestHandler for AnthropicRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "anthropic"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        busbar_core::handlers::cell_of(CELLS, op)
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        match ctx.path_base {
            // Claude-on-Vertex: the model rides the URL via `:rawPredict` / `:streamRawPredict` (native
            // Anthropic is `/v1/messages` with the model in the body). The matching body change — drop
            // `model`, add `anthropic_version` — is applied at wire finalization (see `proxy::wire`).
            Some(base) => {
                let verb = if ctx.stream {
                    "streamRawPredict"
                } else {
                    "rawPredict"
                };
                format!("{base}/{}:{verb}", ctx.model)
            }
            // Native Messages API (chat only); streaming is negotiated via the `stream` flag + SSE Accept.
            None => PATH_MESSAGES.into(),
        }
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        path.ends_with(PATH_MESSAGES).then_some(Operation::CHAT)
    }
}

#[cfg(test)]
#[path = "tests/handler_tests.rs"]
mod tests;
