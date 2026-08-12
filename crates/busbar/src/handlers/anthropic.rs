// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Anthropic `RequestHandler`. Chat-only today (Anthropic ships no embeddings/images/audio API here);
//! its non-chat operations stay `None` = no-handler 404. Chat dispatches through the same registry as
//! every other operation.

use crate::handlers::{EgressCtx, OperationHandler, RequestHandler};
use crate::operation::Operation;

/// Endpoint paths — each appears on BOTH the egress side (`upstream_path`) and the ingress match
/// (`resolve_operation`); single-sourced so the two sides cannot drift.
const PATH_MESSAGES: &str = "/v1/messages";

pub(crate) struct AnthropicRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: crate::handlers::chat::ChatOperation =
    crate::handlers::chat::ChatOperation("anthropic");

impl RequestHandler for AnthropicRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "anthropic"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Chat => Some(&CHAT),
            // Enumerated (not `_`) so adding an operation is a compile error here — the documented
            // removability/symmetry gate. Anthropic serves only chat → no-handler 404 for the rest.
            //
            // The protocol-surface six (Invoke..Control) are `None` for the same reason as the
            // LLM operations Anthropic lacks, and it is the SAME answer rather than a special case:
            // a protocol that does not speak an operation has no cell, so the pair is
            // unrepresentable rather than refused at runtime.
            Operation::Embeddings
            | Operation::Moderation
            | Operation::Image
            | Operation::Transcription
            | Operation::Speech
            | Operation::Rerank
            | Operation::Invoke
            | Operation::Catalogue
            | Operation::Fetch
            | Operation::Task
            | Operation::Subscribe
            | Operation::Control => None,
        }
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
        path.ends_with(PATH_MESSAGES).then_some(Operation::Chat)
    }
}

#[cfg(test)]
#[path = "tests/anthropic_tests.rs"]
mod tests;
