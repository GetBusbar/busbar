// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! OpenAI Responses `RequestHandler`. Chat-only (the `/v1/responses` conversational API); non-chat
//! operations stay `None` = no-handler 404. Chat dispatches through the same registry as every op.

use crate::handlers::{EgressCtx, OperationHandler, RequestHandler};
use crate::operation::Operation;

/// Endpoint paths — each appears on BOTH the egress side (`upstream_path`) and the ingress match
/// (`resolve_operation`); single-sourced so the two sides cannot drift.
const PATH_RESPONSES: &str = "/v1/responses";

pub(crate) struct ResponsesRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: crate::handlers::chat::ChatOperation =
    crate::handlers::chat::ChatOperation("responses");

impl RequestHandler for ResponsesRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "responses"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Chat => Some(&CHAT),
            // Enumerated (not `_`) so adding an operation is a compile error here — the documented
            // removability/symmetry gate. The Responses API serves only chat here.
            Operation::Embeddings
            | Operation::Moderation
            | Operation::Image
            | Operation::Transcription
            | Operation::Speech
            | Operation::Rerank => None,
        }
    }
    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        PATH_RESPONSES.into()
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        path.ends_with(PATH_RESPONSES).then_some(Operation::Chat)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Responses API serves chat only: `operation_handler` must answer `Some` for `Chat` and
    /// `None` for every other operation (the standard no-handler 404 path) — enumerated so a future
    /// `Operation` variant added here without a matching registry arm is a compile error, not a
    /// silent 404.
    #[test]
    fn operation_handler_serves_chat_only() {
        let h = ResponsesRequestHandler;
        assert!(h.operation_handler(Operation::Chat).is_some());
        for op in [
            Operation::Embeddings,
            Operation::Moderation,
            Operation::Image,
            Operation::Transcription,
            Operation::Speech,
            Operation::Rerank,
        ] {
            assert!(
                h.operation_handler(op).is_none(),
                "{op:?} must have no handler on the Responses protocol"
            );
        }
    }

    /// `upstream_path` must egress to the REAL `/v1/responses` endpoint — a path-string typo here
    /// would silently send every Responses-API request to a 404 upstream.
    #[test]
    fn upstream_path_is_the_real_responses_endpoint() {
        let h = ResponsesRequestHandler;
        let ctx = EgressCtx {
            operation: Operation::Chat,
            model: "gpt-4.1",
            stream: false,
            path_base: None,
        };
        assert_eq!(h.upstream_path(&ctx), "/v1/responses");
        // path_base is ignored by this protocol (unlike Anthropic's Vertex rawPredict rewrite):
        // Responses has no known base-path egress variant, so it must stay static regardless.
        let ctx_streaming = EgressCtx {
            stream: true,
            ..ctx
        };
        assert_eq!(h.upstream_path(&ctx_streaming), "/v1/responses");
    }

    /// A request path ending in `/v1/responses` resolves to `Chat`; anything else resolves to
    /// `None` (no-handler 404) — the body is never consulted (Responses names the operation in the
    /// path only).
    #[test]
    fn resolve_operation_matches_the_responses_path_only() {
        let h = ResponsesRequestHandler;
        assert_eq!(
            h.resolve_operation("/v1/responses", b""),
            Some(Operation::Chat)
        );
        // A mounted-prefix path still matches via `ends_with`.
        assert_eq!(
            h.resolve_operation("/proxy/upstream/v1/responses", b""),
            Some(Operation::Chat)
        );
        // Unrelated / sibling paths (including near-misses) must NOT resolve.
        for path in [
            "/v1/chat/completions",
            "/v1/embeddings",
            "/v1/responses/extra",
            "/v1/response",
            "",
        ] {
            assert_eq!(
                h.resolve_operation(path, b""),
                None,
                "path '{path}' must not resolve to any operation"
            );
        }
    }
}
