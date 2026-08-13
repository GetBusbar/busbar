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

/// THE RESPONSES API'S ROW OF THE SUPPORT MATRIX — one verb; every other verb is the standard
/// no-handler 404.
static CELLS: &[crate::handlers::Cell] = &[(Operation::CHAT, &CHAT)];

impl RequestHandler for ResponsesRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "responses"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        crate::handlers::cell_of(CELLS, op)
    }
    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        PATH_RESPONSES.into()
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        path.ends_with(PATH_RESPONSES).then_some(Operation::CHAT)
    }
}

#[cfg(test)]
#[path = "tests/responses_tests.rs"]
mod tests;
