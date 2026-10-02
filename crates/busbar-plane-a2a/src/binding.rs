// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OUTBOUND BINDING (ARCHITECT ruling B4): which of A2A's bindings a hop speaks to an agent,
//! read off the agent's held card (JSON-RPC when no card is held), and the HTTP+JSON framing the
//! relay composes in that binding. Ported from the served engine (`busbar-a2a` `relay::binding_of`,
//! `framing_for`, `HttpJsonFraming`, `refusal_client::bounded_word`), byte for byte.
//!
//! The card says HOW, the operator's `url:` says WHERE: a binding's own URL on the card is never
//! dialled. gRPC is not speakable until the gRPC door lands (GRPC-DOOR #140), so a card that lists
//! it first is reached on the first binding it lists that the plane frames.

use serde_json::{json, Map, Value};

use crate::identity::TASK_ID_MEMBERS;

/// The JSON-RPC binding's card word.
pub const BINDING_JSONRPC: &str = "JSONRPC";
/// The HTTP+JSON binding's card word.
pub const BINDING_HTTP_JSON: &str = "HTTP+JSON";
/// The gRPC binding's card word.
pub const BINDING_GRPC: &str = "GRPC";

/// A binding the plane frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Binding {
    /// JSON-RPC: the caller's bytes, verbatim.
    #[default]
    JsonRpc,
    /// HTTP+JSON (A2A section 11.3): the operation's request line, its params as the body.
    HttpJson,
}

impl Binding {
    /// The card word this binding answers to.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Binding::JsonRpc => BINDING_JSONRPC,
            Binding::HttpJson => BINDING_HTTP_JSON,
        }
    }
}

/// THE LOOKUP: the binding a card word names, if the plane frames it. TRANSITIONAL: gRPC
/// ([`BINDING_GRPC`]) is framed once the gRPC door lands (GRPC-DOOR #140).
#[must_use]
pub fn speakable(word: &str) -> Option<Binding> {
    match word.trim().to_ascii_uppercase().as_str() {
        BINDING_JSONRPC => Some(Binding::JsonRpc),
        BINDING_HTTP_JSON => Some(Binding::HttpJson),
        _ => None,
    }
}

/// THE BINDING A HELD CARD DECLARES, or [`BINDING_JSONRPC`] where none is held or it declares
/// none: the first `supportedInterfaces` word the plane frames, else the card's first word (which
/// the hop refuses by name, never sends as JSON-RPC).
#[must_use]
pub fn binding_of(card: Option<&Value>) -> String {
    let Some(interfaces) = card
        .and_then(|c| c.get("supportedInterfaces"))
        .and_then(Value::as_array)
    else {
        return BINDING_JSONRPC.to_string();
    };
    let words: Vec<&str> = interfaces
        .iter()
        .filter_map(|i| i.get("protocolBinding"))
        .filter_map(Value::as_str)
        .filter(|w| !w.trim().is_empty())
        .collect();
    let Some(first) = words.first() else {
        return BINDING_JSONRPC.to_string();
    };
    words
        .iter()
        .find(|w| speakable(w).is_some())
        .unwrap_or(first)
        .to_string()
}

/// One untrusted word made safe for a caller's error body: at most 48 characters of an
/// identifier-shaped alphabet, everything else `?`.
#[must_use]
pub fn bounded_word(word: &str) -> String {
    const MAX: usize = 48;
    let mut out: String = word
        .chars()
        .take(MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+' | '/') {
                c
            } else {
                '?'
            }
        })
        .collect();
    if out.is_empty() {
        out.push('?');
    }
    out
}

/// The stable token of a hop the plane cannot frame.
pub const UNFRAMABLE_CODE: &str = "a2a.hop.unframable";

/// The caller's sentence for `method` that cannot be carried over `binding`.
#[must_use]
pub fn unframable_text(method: &str, binding: &str) -> String {
    format!(
        "{UNFRAMABLE_CODE}: `{}` could not be carried to this agent over its `{}` binding",
        bounded_word(method),
        bounded_word(binding),
    )
}

/// One operation's place on the HTTP+JSON binding: its request line, the `params` members its query
/// string carries, and whether what is left of `params` is the body.
struct RestOp {
    verb: &'static str,
    path: &'static str,
    query: &'static [&'static str],
    body: bool,
}

/// The HTTP+JSON row of `method`, from either A2A dialect's spelling.
fn rest_op(method: &str) -> Option<RestOp> {
    let (verb, path, query, body): (_, _, &'static [&'static str], _) = match method {
        "SendMessage" | "message/send" => ("POST", "/message:send", &[], true),
        "SendStreamingMessage" | "message/stream" => ("POST", "/message:stream", &[], true),
        "GetTask" | "tasks/get" => ("GET", "/tasks/{id}", &["historyLength"], false),
        "ListTasks" | "tasks/list" => (
            "GET",
            "/tasks",
            &[
                "contextId",
                "status",
                "pageSize",
                "pageToken",
                "historyLength",
                "statusTimestampAfter",
                "includeArtifacts",
            ],
            false,
        ),
        "CancelTask" | "tasks/cancel" => ("POST", "/tasks/{id}:cancel", &[], false),
        "SubscribeToTask" | "tasks/resubscribe" => ("POST", "/tasks/{id}:subscribe", &[], false),
        "CreateTaskPushNotificationConfig" | "tasks/pushNotificationConfig/set" => {
            ("POST", "/tasks/{taskId}/pushNotificationConfigs", &[], true)
        }
        "ListTaskPushNotificationConfigs" | "tasks/pushNotificationConfig/list" => (
            "GET",
            "/tasks/{taskId}/pushNotificationConfigs",
            &["pageSize", "pageToken"],
            false,
        ),
        "GetTaskPushNotificationConfig" | "tasks/pushNotificationConfig/get" => (
            "GET",
            "/tasks/{taskId}/pushNotificationConfigs/{id}",
            &[],
            false,
        ),
        "DeleteTaskPushNotificationConfig" | "tasks/pushNotificationConfig/delete" => (
            "DELETE",
            "/tasks/{taskId}/pushNotificationConfigs/{id}",
            &[],
            false,
        ),
        "GetExtendedAgentCard" | "agent/getAuthenticatedExtendedCard" => {
            ("GET", "/extendedAgentCard", &[], false)
        }
        _ => return None,
    };
    Some(RestOp {
        verb,
        path,
        query,
        body,
    })
}

/// One HTTP+JSON request: its verb, its target under the agent's origin, whether it carries a
/// document, and the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Framed {
    /// The request line's verb.
    pub verb: &'static str,
    /// The path and query, under the agent's origin.
    pub target: String,
    /// The request carries a body (and so a `content-type`).
    pub has_body: bool,
    /// The body.
    pub body: Vec<u8>,
}

/// COMPOSE `method` with `params` on the HTTP+JSON binding under the agent URL `base` (A2A section
/// 11.3): the path joined onto the operator's, its `{member}`s taken from `params`, the query
/// members on the query string, what is left as the body.
///
/// # Errors
/// Why the request cannot be carried on this binding, in the engine's words (never shown to the
/// caller).
pub fn compose(base: &str, method: &str, params: &Value) -> Result<Framed, String> {
    let op = rest_op(method).ok_or_else(|| {
        format!("`{method}` is not one of the eleven operations A2A's HTTP+JSON binding defines")
    })?;
    let base = url::Url::parse(base).map_err(|e| format!("the agent URL does not parse: {e}"))?;
    let empty = Map::new();
    let mut left = params.as_object().unwrap_or(&empty).clone();
    let mut path = String::new();
    let mut rest = op.path;
    while let Some(open) = rest.find('{') {
        path.push_str(&rest[..open]);
        let close = rest[open..]
            .find('}')
            .ok_or_else(|| format!("the route template `{}` is malformed", op.path))?
            + open;
        let name = &rest[open + 1..close];
        // `{id}` on the push-config routes is the CONFIG id, so it stays exact there.
        let spellings: &[&str] = match name {
            "id" if !op.path.contains("{taskId}") => &TASK_ID_MEMBERS,
            "taskId" => &["taskId", "task_id"],
            _ => &[],
        };
        let value = spellings
            .iter()
            .find_map(|s| left.remove(*s))
            .or_else(|| left.remove(name))
            .ok_or_else(|| format!("`{method}` names no `{name}` to address"))?;
        let value = value
            .as_str()
            .map_or_else(|| value.to_string(), str::to_string);
        if value.is_empty() {
            return Err(format!("`{method}`'s `{name}` is empty"));
        }
        path.push_str(&percent(&value));
        rest = &rest[close + 1..];
    }
    path.push_str(rest);
    let mut url = base.clone();
    url.set_path(&format!("{}{path}", base.path().trim_end_matches('/')));
    {
        let mut query = url.query_pairs_mut();
        query.clear();
        for name in op.query {
            if let Some(value) = left.remove(*name) {
                query.append_pair(name, &scalar(&value));
            }
        }
    }
    if url.query() == Some("") {
        url.set_query(None);
    }
    if !op.body && !left.is_empty() {
        let mut names: Vec<&String> = left.keys().collect();
        names.sort();
        return Err(format!(
            "`{method}` carries {names:?}, which A2A's HTTP+JSON binding has nowhere to put on a \
             `{}` request",
            op.verb
        ));
    }
    let body = if op.body {
        serde_json::to_vec(&Value::Object(left))
            .map_err(|e| format!("the request params could not be rendered: {e}"))?
    } else {
        Vec::new()
    };
    let mut target = url.path().to_string();
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    Ok(Framed {
        verb: op.verb,
        target,
        has_body: op.body,
        body,
    })
}

/// THE ANSWER, BACK IN ONE DIALECT: an HTTP+JSON success body IS the `result`, wrapped into the
/// JSON-RPC envelope under `rpc_id` so the one reader reads it; an empty body is `"result": null`.
///
/// # Errors
/// The body is not JSON.
pub fn rewrap(body: &[u8], rpc_id: &Value) -> Result<Vec<u8>, String> {
    let result = if body.iter().all(u8::is_ascii_whitespace) {
        Value::Null
    } else {
        serde_json::from_slice::<Value>(body).map_err(|e| format!("the answer is not JSON: {e}"))?
    };
    serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": rpc_id, "result": result }))
        .map_err(|e| format!("the answer could not be re-framed: {e}"))
}

/// A query-string value: a string as itself, anything else as its JSON rendering.
fn scalar(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_string)
}

/// Percent-encode one path segment against an allowlist, so an id cannot re-point the request line.
fn percent(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
#[path = "tests/binding_tests.rs"]
mod tests;
