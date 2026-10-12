// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE EVENT OFF A RELAYED EVENT STREAM, as busbar reads it (the served engine's `read_event`,
//! `frame_sse`, its HTTP+JSON frame reader and its HTTP+JSON line's event re-framer, in their words
//! and their bytes). Pure: the relay feeds it frames ([`crate::sse::SseReader`]) and the door writes
//! what it answers.
//!
//! * A frame that is not JSON, or that carries neither `result` nor a non-null `error`, passes
//!   through UNCHANGED: an event stream carries comments and keep-alives, and busbar is
//!   content-blind.
//! * A frame that IS a JSON-RPC response is CORRELATED to the caller's request id and answered
//!   under it; one that names a different request is an error, and the hop is refused.
//! * An `error` frame is relayed as it stands under the caller's id: mid-stream, the status is
//!   already spent and the far end's error is content the caller is owed.
//! * A `result` frame leaves under busbar's task identity ([`identity::rewrite_identity`]); the
//!   state it reports, whether it carried an artifact and the far end's own task id are read off it
//!   first, through the v1.0 wrappers as well as the v0.3 bare shape.

use busbar_contract::jsonrpc::{read_response, Reply};
use serde_json::{json, Value};

use crate::a2a::task::TaskState;
use crate::identity;
use crate::sse::sse_data;

/// The media type of an event stream: what a relayed stream's answer is.
pub const EVENTS_MEDIA_TYPE: &str = "text/event-stream";

/// What a hop that may answer with events accepts: an event stream, or one document.
pub const ACCEPT_EVENTS: &str = "text/event-stream, application/json";

/// ONE EVENT, read: its bytes for the caller (identity substituted), and what it said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The event, framed for the caller.
    pub sse: Vec<u8>,
    /// The task state it reported, if it reported one this build can read.
    pub state: Option<TaskState>,
    /// It carried an artifact chunk: the resume cursor advances.
    pub artifact: bool,
    /// The far end's own task id, before the substitution.
    pub backend_task_id: Option<String>,
}

/// One JSON value as a complete event.
fn frame(value: &Value) -> Vec<u8> {
    format!("data: {value}\n\n").into_bytes()
}

/// READ ONE FAR-END EVENT `frame_text` and frame it for the caller of request `rpc_id`, under
/// busbar's `task_id`, `context_id` and the matched `skill`.
///
/// # Errors
/// The frame answers a different request: the correlation's reason.
pub fn read_event(
    frame_text: &str,
    rpc_id: &Value,
    task_id: &str,
    context_id: &str,
    skill: Option<&str>,
) -> Result<Event, String> {
    let verbatim = || {
        Ok(Event {
            sse: frame_text.as_bytes().to_vec(),
            state: None,
            artifact: false,
            backend_task_id: None,
        })
    };
    let Some(data) = sse_data(frame_text) else {
        return verbatim();
    };
    let Ok(mut envelope) = serde_json::from_str::<Value>(&data) else {
        return verbatim();
    };
    let is_response = envelope.get("result").is_some()
        || envelope.get("error").filter(|e| !e.is_null()).is_some();
    if !is_response {
        return verbatim();
    }
    let reply = read_response(&envelope, rpc_id).map_err(|e| e.reason)?;
    if let Some(obj) = envelope.as_object_mut() {
        obj.insert("id".to_string(), rpc_id.clone());
    }
    let Reply::Result(_) = reply else {
        return Ok(Event {
            sse: frame(&envelope),
            state: None,
            artifact: false,
            backend_task_id: None,
        });
    };
    let Some(result) = envelope.get_mut("result") else {
        return verbatim();
    };
    let payload = identity::payload_of(result);
    let artifact = payload.get("artifact").is_some()
        || payload.get("artifacts").is_some()
        || result.get("artifactUpdate").is_some();
    let state = payload
        .pointer("/status/state")
        .and_then(Value::as_str)
        .and_then(identity::wire_state);
    let backend_task_id = identity::backend_task_id(result);
    identity::rewrite_identity(result, task_id, context_id, skill);
    Ok(Event {
        sse: frame(&envelope),
        state,
        artifact,
        backend_task_id,
    })
}

/// AN HTTP+JSON FAR END'S FRAME, wrapped back into the one dialect: its `data:` payload is the
/// bare event, so it becomes `result` under `rpc_id`; a frame with no JSON payload passes as it is.
#[must_use]
pub fn rewrap(frame_text: String, rpc_id: &Value) -> String {
    match sse_data(&frame_text).map(|d| serde_json::from_str::<Value>(&d)) {
        Some(Ok(event)) => format!(
            "data: {}\n\n",
            json!({ "jsonrpc": "2.0", "id": rpc_id, "result": event })
        ),
        _ => frame_text,
    }
}

/// THE HTTP+JSON LINE'S EVENTS: every `data:` payload of `buf` that is a JSON-RPC `result` becomes
/// the bare result; everything else (an `error` frame, a keep-alive, a comment) passes byte for
/// byte, each line's own terminator kept.
#[must_use]
pub fn reframe_events(buf: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(buf) else {
        return buf.to_vec();
    };
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let result = trimmed
            .strip_prefix("data:")
            .and_then(|payload| serde_json::from_str::<Value>(payload.trim()).ok())
            .and_then(|envelope| envelope.get("result").cloned());
        match result {
            Some(result) => {
                out.push_str("data: ");
                out.push_str(&result.to_string());
                out.push_str(&line[trimmed.len()..]);
            }
            None => out.push_str(line),
        }
    }
    out.into_bytes()
}

#[cfg(test)]
#[path = "tests/events_tests.rs"]
mod tests;
