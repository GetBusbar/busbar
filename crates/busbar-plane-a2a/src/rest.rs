// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HTTP+JSON LINE'S ARRIVAL: the JSON-RPC envelope the line's request spells, composed from
//! the route, the path, the query and the body, and decided as the JSON-RPC line decides it.
//!
//! A2A section 11.3 defines the REST binding BY REFERENCE to the JSON-RPC one: the request body IS
//! the JSON-RPC `params` verbatim, and the success body IS the `result` verbatim. So nothing about
//! the operation differs between the two lines but where the method NAME comes from (the request
//! line) and how the answer is wrapped. This module is the first half: [`compose`] builds the
//! envelope the served engine's `rest.rs` composed (member for member, the same fixed id), and the
//! door decides it with [`crate::arrival::decide`] under the caller's own head fields, which is the
//! order the engine ran (its route handler composed, then `receive::invoke` judged the head and
//! parsed the composed body). The one refusal composing can earn, a `POST /tasks/{id}:<verb>`
//! naming no verb, comes first, as it did in the engine's handler.

use std::collections::HashMap;

use serde_json::{json, Map, Value};

use crate::arrival::Refusal;
use crate::door::Route;

/// THE JSON-RPC ID OF A COMPOSED ENVELOPE. A JSON-RPC id is a correlation handle for a channel
/// that multiplexes requests; one HTTP request has none, so the id is a fixed string that says
/// what it is, never seen by the caller (the answer is unwrapped before it leaves).
pub const REST_RPC_ID: &str = "a2a-http-json";

/// THE METHOD NAMES, in A2A v1.0's spelling: the HTTP+JSON binding was introduced with v1.0 and
/// the specification's operation table names these, so a REST request composes a v1.0 envelope.
pub mod method {
    /// `POST /message:send`.
    pub const SEND_MESSAGE: &str = "SendMessage";
    /// `POST /message:stream`.
    pub const SEND_STREAM_MESSAGE: &str = "SendStreamingMessage";
    /// `GET /tasks/{id}`.
    pub const GET_TASK: &str = "GetTask";
    /// `GET /tasks`.
    pub const LIST_TASKS: &str = "ListTasks";
    /// `POST /tasks/{id}:cancel`.
    pub const CANCEL_TASK: &str = "CancelTask";
    /// `POST /tasks/{id}:subscribe`.
    pub const SUBSCRIBE_TO_TASK: &str = "SubscribeToTask";
    /// `POST /tasks/{id}/pushNotificationConfigs`.
    pub const CREATE_PUSH_CONFIG: &str = "CreateTaskPushNotificationConfig";
    /// `GET /tasks/{id}/pushNotificationConfigs/{configId}`.
    pub const GET_PUSH_CONFIG: &str = "GetTaskPushNotificationConfig";
    /// `GET /tasks/{id}/pushNotificationConfigs`.
    pub const LIST_PUSH_CONFIGS: &str = "ListTaskPushNotificationConfigs";
    /// `DELETE /tasks/{id}/pushNotificationConfigs/{configId}`.
    pub const DELETE_PUSH_CONFIG: &str = "DeleteTaskPushNotificationConfig";
    /// `GET /extendedAgentCard`.
    pub const GET_EXTENDED_AGENT_CARD: &str = "GetExtendedAgentCard";
}

/// The two operations `POST /tasks/{id}:<verb>` spells. The verb is a suffix INSIDE the captured
/// segment, so the segment is captured once and split here.
const VERB_CANCEL: &str = "cancel";
const VERB_SUBSCRIBE: &str = "subscribe";

/// The status of a `POST /tasks/…` naming no verb this binding defines.
const STATUS_NOT_FOUND: u32 = 404;

/// JSON-RPC's `MethodNotFound`: the fault is in the request line, not the task.
const CODE_METHOD_NOT_FOUND: i64 = -32601;

/// A REQUEST'S PARAMS, built member by member, skipping what the caller did not send. Absent is
/// not empty: a query parameter the caller omitted does not appear in the composed `params`.
#[derive(Default)]
pub struct Params(Map<String, Value>);

impl Params {
    /// No members.
    #[must_use]
    pub fn new() -> Self {
        Self(Map::new())
    }

    /// Set `name` to a value the caller definitely supplied.
    #[must_use]
    pub fn set(mut self, name: &str, value: impl Into<Value>) -> Self {
        self.0.insert(name.to_string(), value.into());
        self
    }

    /// Set `name` only if the caller supplied it, typed by [`json_scalar`].
    #[must_use]
    pub fn maybe(mut self, name: &str, value: Option<&String>) -> Self {
        if let Some(v) = value {
            self.0.insert(name.to_string(), json_scalar(v));
        }
        self
    }

    /// Merge a request body in, VERBATIM (the REST body IS the `params`). A path-derived member is
    /// set AFTER this, so the URL a caller addressed cannot be re-pointed by a member it posted.
    #[must_use]
    pub fn merge(mut self, body: &Value) -> Self {
        if let Some(obj) = body.as_object() {
            for (k, v) in obj {
                self.0.insert(k.clone(), v.clone());
            }
        }
        self
    }

    /// The members as one JSON object.
    #[must_use]
    pub fn into_value(self) -> Value {
        Value::Object(self.0)
    }
}

/// A QUERY-STRING VALUE, TYPED THE WAY THE ENVELOPE WANTS IT: an integer is a number, `true` and
/// `false` are booleans, anything else (a task id, a page token, a status name) stays a string.
#[must_use]
pub fn json_scalar(raw: &str) -> Value {
    if let Ok(n) = raw.parse::<i64>() {
        return json!(n);
    }
    match raw {
        "true" => json!(true),
        "false" => json!(false),
        other => json!(other),
    }
}

/// THE QUERY STRING AS A `name -> value` MAP, decoded as `application/x-www-form-urlencoded`
/// ([`form_decode`]). A repeated key keeps the last value; a malformed pair yields its own bytes.
#[must_use]
pub fn query_map(query: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(raw) = query else {
        return map;
    };
    for pair in raw.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(form_decode(k), form_decode(v));
    }
    map
}

/// Decode ONE `application/x-www-form-urlencoded` component: `+` is a space, `%XX` the byte,
/// anything else verbatim, then the bytes read as UTF-8 lossily.
#[must_use]
pub fn form_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => match (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 3;
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One hex digit's value.
fn hex(b: u8) -> Option<u8> {
    (b as char).to_digit(16).and_then(|d| u8::try_from(d).ok())
}

/// One path capture, percent-decoded as the router decoded it (`%XX` is the byte; `+` stays a
/// `+`). `None` when the decoded bytes are not UTF-8.
#[must_use]
pub fn path_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).ok()
}

/// A request body as the `params`, or the empty object when there is none or it is not JSON: an
/// empty body is no fault on this binding (`:cancel` and `DELETE` carry none), and a body that is
/// not JSON reaches the operation as empty `params`, refused there for the member it lacks.
#[must_use]
pub fn json_body(body: &[u8]) -> Value {
    if body.is_empty() {
        return json!({});
    }
    serde_json::from_slice(body).unwrap_or_else(|_| json!({}))
}

/// The refusal for a `POST /tasks/…` that names no verb this binding defines: `404` +
/// `MethodNotFound`, in the engine's words.
#[must_use]
pub fn not_a_verb(addressed: &str) -> Refusal {
    Refusal {
        status: STATUS_NOT_FOUND,
        id: None,
        code: CODE_METHOD_NOT_FOUND,
        message: format!(
            "`{addressed}` names no operation on this binding; the task operations are \
             `{{id}}:{VERB_CANCEL}` and `{{id}}:{VERB_SUBSCRIBE}`"
        ),
    }
}

/// The path variables `target` binds against `route`'s pattern, by name, each decoded as the
/// router decoded it. `None` when the path does not have the pattern's shape or a capture is not
/// UTF-8.
#[must_use]
pub fn captures(route: &Route, target: &str) -> Option<Vec<(&'static str, String)>> {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    let want: Vec<&'static str> = route.target.split('/').collect();
    let got: Vec<&str> = path.split('/').collect();
    if want.len() != got.len() {
        return None;
    }
    let mut out = Vec::new();
    for (&w, &g) in want.iter().zip(got.iter()) {
        match w.strip_prefix('{').and_then(|w| w.strip_suffix('}')) {
            Some(name) => out.push((name, path_decode(g)?)),
            None if w == g => {}
            None => return None,
        }
    }
    Some(out)
}

/// The query string of `target`, if it has one.
fn query_of(target: &str) -> Option<&str> {
    let rest = target.split('#').next().unwrap_or(target);
    rest.split_once('?').map(|(_, q)| q)
}

/// COMPOSE THE ENVELOPE a request on the HTTP+JSON line spells: `route` is the line's route the
/// arrival matched, `target` the request target as sent (its path captures and query read here),
/// `body` the request body. The envelope's bytes are what the line's unit relays, as the engine
/// relayed the envelope it composed.
///
/// # Errors
///
/// [`not_a_verb`] for a `POST /tasks/{id}` naming no verb. `Ok(None)` for a route that is not one of
/// the line's, or a target that does not fit it, which the door answers as unserved.
pub fn compose(route: &Route, target: &str, body: &[u8]) -> Result<Option<Vec<u8>>, Refusal> {
    let Some(vars) = captures(route, target) else {
        return Ok(None);
    };
    let var = |name: &str| {
        vars.iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    compose_from(route, var, query_of(target), body)
}

/// [`compose`] over captures a router already decoded: `var` answers a path capture by name (the
/// empty string for one the route does not have), `query` is the raw query string. The ONE home of
/// what each of the line's routes composes.
///
/// # Errors
///
/// As [`compose`].
pub fn compose_from(
    route: &Route,
    var: impl Fn(&str) -> String,
    query: Option<&str>,
    body: &[u8],
) -> Result<Option<Vec<u8>>, Refusal> {
    let query = query_map(query);
    let rel = route
        .target
        .strip_prefix(crate::MOUNT_PATH)
        .unwrap_or(route.target);
    let at = |verb: &str, path: &str| route.verb == verb && rel == path;
    let (name, params) = if at("POST", crate::ROUTE_MESSAGE_SEND) {
        (method::SEND_MESSAGE, json_body(body))
    } else if at("POST", crate::ROUTE_MESSAGE_STREAM) {
        (method::SEND_STREAM_MESSAGE, json_body(body))
    } else if at("GET", crate::ROUTE_TASKS) {
        let params = Params::new()
            .maybe("contextId", query.get("contextId"))
            .maybe("status", query.get("status"))
            .maybe("pageSize", query.get("pageSize"))
            .maybe("pageToken", query.get("pageToken"))
            .maybe("historyLength", query.get("historyLength"))
            .maybe("statusTimestampAfter", query.get("statusTimestampAfter"))
            .maybe("includeArtifacts", query.get("includeArtifacts"));
        (method::LIST_TASKS, params.into_value())
    } else if at("GET", crate::ROUTE_TASK) {
        let params = Params::new()
            .set("id", var("id"))
            .maybe("historyLength", query.get("historyLength"));
        (method::GET_TASK, params.into_value())
    } else if at("POST", crate::ROUTE_TASK) {
        let addressed = var("id");
        let Some((id, verb)) = addressed.rsplit_once(':') else {
            return Err(not_a_verb(&addressed));
        };
        let name = match verb {
            VERB_CANCEL => method::CANCEL_TASK,
            VERB_SUBSCRIBE => method::SUBSCRIBE_TO_TASK,
            _ => return Err(not_a_verb(&addressed)),
        };
        (name, Params::new().set("id", id).into_value())
    } else if at("POST", crate::ROUTE_PUSH_CONFIGS) {
        // THE PATH WINS: merged first, `taskId` set after, so a posted member cannot re-point it.
        let params = Params::new()
            .merge(&json_body(body))
            .set("taskId", var("id"));
        (method::CREATE_PUSH_CONFIG, params.into_value())
    } else if at("GET", crate::ROUTE_PUSH_CONFIGS) {
        let params = Params::new()
            .set("taskId", var("id"))
            .maybe("pageSize", query.get("pageSize"))
            .maybe("pageToken", query.get("pageToken"));
        (method::LIST_PUSH_CONFIGS, params.into_value())
    } else if at("GET", crate::ROUTE_PUSH_CONFIG) || at("DELETE", crate::ROUTE_PUSH_CONFIG) {
        let name = if route.verb == "GET" {
            method::GET_PUSH_CONFIG
        } else {
            method::DELETE_PUSH_CONFIG
        };
        let params = Params::new()
            .set("taskId", var("id"))
            .set("id", var("config_id"));
        (name, params.into_value())
    } else if at("GET", crate::ROUTE_EXTENDED_AGENT_CARD) {
        (method::GET_EXTENDED_AGENT_CARD, json!({}))
    } else {
        return Ok(None);
    };
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": REST_RPC_ID,
        "method": name,
        "params": params,
    });
    Ok(Some(serde_json::to_vec(&envelope).unwrap_or_default()))
}

/// RE-FRAME A JSON-RPC ANSWER for the HTTP+JSON line, by what it is (the engine's `rest::reframe`):
/// a `result` becomes the body VERBATIM; an `error` becomes the AIP-193 document at `status`
/// ([`crate::arrival::aip193`]); anything else (not JSON, or neither member) passes untouched.
#[must_use]
pub fn reframe(status: u32, body: &[u8]) -> Vec<u8> {
    let Ok(envelope) = serde_json::from_slice::<Value>(body) else {
        return body.to_vec();
    };
    let reframed = match (envelope.get("result"), envelope.get("error")) {
        (Some(result), _) => result.clone(),
        (None, Some(error)) if !error.is_null() => crate::arrival::aip193(status, error),
        _ => return body.to_vec(),
    };
    serde_json::to_vec(&reframed).unwrap_or_default()
}

#[cfg(test)]
#[path = "tests/rest.rs"]
mod tests;
