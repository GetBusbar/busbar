// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ANSWERS THE PLANE GIVES FROM WHAT IT HOLDS: every request whose answer is the generation's
//! catalogue or the section's own content, and that reaches no far end. Pure: the arrival's
//! [`Disposition`], the generation's [`Catalogue`] and the caller's `admit` predicate in; the status
//! and the answer's bytes out, or [`Answer::Far`] for a request that is not answered here.
//!
//! The answers are the served engine's, byte for byte, including its refusals: a local answer that
//! refuses answers its own refusal body with its own status.

use serde_json::{json, Value};

use crate::arrival::{Disposition, Refusal};
use crate::catalogue::{complete, Catalogue, CACHE_SCOPE, CACHE_TTL_MS};
use crate::checks::SUPPORTED_PROTOCOL_VERSIONS;
use crate::codec::{IMPLEMENTED_METHODS, PROTOCOL_VERSION};
use crate::ops::{
    OP_COMPLETION, OP_DISCOVER, OP_PROMPTS_LIST, OP_PROMPT_GET, OP_RESOURCES_LIST,
    OP_RESOURCE_READ, OP_RESOURCE_TEMPLATES_LIST, OP_TOOLS_LIST,
};
use crate::reads;

/// The status of a successful answer.
pub const STATUS_OK: u32 = 200;

/// The status a notification is acknowledged with on a request-response carrier: no body.
pub const STATUS_ACCEPTED: u32 = 202;

/// The tasks extension this server advertises unconditionally.
pub const TASKS_EXTENSION_ID: &str = "io.modelcontextprotocol/tasks";

/// What one arrival is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// Answered here: the status and the body (empty for none).
    Here {
        /// The status.
        status: u32,
        /// The body.
        body: Vec<u8>,
    },
    /// Not answered here: the request reaches a far end, or asks its caller first.
    Far,
}

impl Answer {
    fn ok(body: Vec<u8>) -> Self {
        Answer::Here {
            status: STATUS_OK,
            body,
        }
    }

    fn refused(refusal: &Refusal) -> Self {
        Answer::Here {
            status: refusal.status,
            body: refusal.body(),
        }
    }

    fn of(result: Result<Vec<u8>, Refusal>) -> Self {
        match result {
            Ok(body) => Answer::ok(body),
            Err(refusal) => Answer::refused(&refusal),
        }
    }
}

/// `server/discover`: the capabilities, and the catalogue this caller reaches, counted.
#[must_use]
pub fn discover(catalogue: &Catalogue, id: &Value, admit: &impl Fn(&str, &str) -> bool) -> Vec<u8> {
    let tools = catalogue.tools_for(admit);
    let prompts = catalogue.prompts_for(admit);
    let resources = catalogue.resources_for(admit);
    let mut servers: Vec<&str> = tools
        .iter()
        .map(|t| t.server.as_str())
        .chain(prompts.iter().map(|p| p.server.as_str()))
        .chain(resources.iter().map(|r| r.server.as_str()))
        .collect();
    servers.sort_unstable();
    servers.dedup();
    complete(
        id,
        json!({
            "protocolVersion": PROTOCOL_VERSION,
            "supportedVersions": SUPPORTED_PROTOCOL_VERSIONS,
            "serverInfo": { "name": "busbar", "version": crate::plane_door::VERSION },
            "capabilities": {
                "tools": { "listChanged": true },
                "prompts": { "listChanged": true },
                "resources": { "listChanged": true, "subscribe": true },
                "completions": {},
                "logging": {},
                "extensions": { TASKS_EXTENSION_ID: {} },
            },
            "methods": IMPLEMENTED_METHODS,
            "servers": servers,
            "counts": {
                "tools": tools.len(),
                "prompts": prompts.len(),
                "resources": resources.len(),
            },
            "registryEmpty": catalogue.is_empty(),
            "cacheScope": CACHE_SCOPE,
            "ttlMs": CACHE_TTL_MS,
        }),
    )
}

/// `completion/complete`: always the empty completion, never validated against the catalogue.
#[must_use]
pub fn completion(id: &Value) -> Vec<u8> {
    complete(
        id,
        json!({ "completion": { "values": [], "hasMore": false, "total": 0 } }),
    )
}

/// ANSWER ONE ARRIVAL from what the plane holds. `params` is the request body's `params`;
/// `quarantined` is the live trust verdict for a listed tool.
pub fn answer(
    disposition: &Disposition,
    params: Option<&Value>,
    catalogue: &Catalogue,
    admit: &impl Fn(&str, &str) -> bool,
    quarantined: impl Fn(&crate::catalogue::ToolEntry) -> bool,
) -> Answer {
    match disposition {
        Disposition::Refused(refusal) => Answer::refused(refusal),
        Disposition::Notice { .. } => Answer::Here {
            status: STATUS_ACCEPTED,
            body: Vec::new(),
        },
        Disposition::Request { row, id, .. } => {
            let op = row.op;
            if op == OP_TOOLS_LIST {
                Answer::ok(catalogue.tools_list(id, admit, quarantined))
            } else if op == OP_PROMPTS_LIST {
                Answer::ok(catalogue.prompts_list(id, admit))
            } else if op == OP_RESOURCES_LIST {
                Answer::ok(catalogue.resources_list(id, admit))
            } else if op == OP_RESOURCE_TEMPLATES_LIST {
                Answer::ok(catalogue.resource_templates_list(id, admit))
            } else if op == OP_RESOURCE_READ {
                Answer::of(reads::resources_read(catalogue, id, params, admit))
            } else if op == OP_PROMPT_GET {
                match reads::prompt_named(catalogue, id, params, admit) {
                    Err(refusal) => Answer::refused(&refusal),
                    Ok(prompt) if !prompt.ask_caller.is_empty() => Answer::Far,
                    Ok(prompt) => Answer::ok(reads::prompts_get(prompt, id, params)),
                }
            } else if op == OP_COMPLETION {
                Answer::ok(completion(id))
            } else if op == OP_DISCOVER {
                Answer::ok(discover(catalogue, id, admit))
            } else {
                Answer::Far
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/answer.rs"]
mod tests;
