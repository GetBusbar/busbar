//! `tasks/get` — THE PLANE'S HALF: read a settled task off the store face and render the
//! `DetailedTask` document, byte for byte, member for member, the same shape `busbar-mcp`'s own
//! `McpTask::detailed()` built before this crate existed to build it.
//!
//! This is [`ops::settled_document`](crate::ops)'s cousin rather than its twin: that function reads
//! a STATIC table because `completion/complete`'s answer depends on nothing the caller sent.
//! `tasks/get`'s answer depends on which task, so it reads a live store instead of a table — but the
//! shape handed back is the same thing, a BARE result document with no `jsonrpc`, no `id` and no
//! `resultType`, because those three are the dialect's and are stamped by whichever side frames it.

use busbar_contract::tasks::{TaskRecord, TaskStore};

/// Render one [`TaskRecord`] as the bare `DetailedTask` document.
///
/// Member order is DELIBERATE and is the whole of this function's contract: `taskId`, `status`,
/// `createdAt`, `lastUpdatedAt`, `ttlMs`, `pollIntervalMs`, then `result` / `error` /
/// `inputRequests` only where the record carries them — the same order, the same omissions,
/// `busbar-mcp`'s `McpTask::detailed()` wrote before this function existed to write it.
///
/// `result`, `error` and each `inputRequests` value arrive as bytes — the store's own codec's
/// encoding of whatever it settled, per [`busbar_contract::tasks`]'s module note — and are decoded
/// here as this plane's own object notation, because this crate is the one place that notation is
/// named for this plane. A value that fails to decode is DROPPED rather than surfacing a decode
/// error on a document that is otherwise complete: the store handed this crate its own bytes, so a
/// failure here is this crate's bug, and dropping the member is what keeps a bug in one row from
/// making the whole document unparsable.
#[must_use]
pub fn detailed_document(record: &TaskRecord) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("taskId".into(), record.id.clone().into());
    obj.insert("status".into(), record.status.clone().into());
    obj.insert("createdAt".into(), record.created_at.clone().into());
    obj.insert("lastUpdatedAt".into(), record.updated_at.clone().into());
    obj.insert("ttlMs".into(), record.ttl_ms.into());
    obj.insert("pollIntervalMs".into(), record.poll_interval_ms.into());
    if let Some(result) = &record.result {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(result) {
            obj.insert("result".into(), value);
        }
    }
    if let Some(error) = &record.error {
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(error) {
            obj.insert("error".into(), value);
        }
    }
    if !record.input_requests.is_empty() {
        let mut map = serde_json::Map::new();
        for (key, bytes) in &record.input_requests {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
                map.insert(key.clone(), value);
            }
        }
        obj.insert("inputRequests".into(), serde_json::Value::Object(map));
    }
    serde_json::Value::Object(obj)
}

/// `tasks/get`'s whole answer: resolve `task_id` for `principal` through the store face and hand
/// back the bare document. `None` when the store holds nothing for this (id, principal) pair — the
/// caller's own JSON-RPC refusal is its business, not this face's; this function names no error
/// code.
#[must_use]
pub fn get(store: &dyn TaskStore, task_id: &str, principal: &str) -> Option<serde_json::Value> {
    store
        .get(task_id, principal)
        .map(|record| detailed_document(&record))
}

/// `tasks/update`'s whole answer: deliver the caller's `inputResponses` through the store face and
/// hand back the ack. `None` when the store holds nothing for this (id, principal) pair.
///
/// THE ACK CARRIES NO TASK ENVELOPE, and that is the SEP-2322 discriminator rule rather than
/// terseness: a response carrying `taskId`/`status` would be a second, racing view of the task
/// beside `tasks/get`, and a client would have to decide which of the two to believe. One reader.
///
/// The answers arrive as this plane's own object notation — the shape the caller sent — and are
/// ENCODED to bytes on the way into the face, for the reason
/// [`busbar_contract::tasks`](busbar_contract::tasks) states: the store carries whatever its own
/// codec framed, and the face does not speak it. A value that fails to encode is DROPPED rather than
/// failing the whole delivery, symmetric with [`detailed_document`]'s decode: the caller sent the
/// rest in good faith and one unencodable member is this crate's bug, not a reason to lose the other
/// nine answers a client may have waited a round to send.
#[must_use]
pub fn update(
    store: &dyn TaskStore,
    task_id: &str,
    principal: &str,
    responses: &serde_json::Map<String, serde_json::Value>,
    now_ms: u64,
) -> Option<serde_json::Value> {
    let answers: Vec<(String, Vec<u8>)> = responses
        .iter()
        .filter_map(|(k, v)| serde_json::to_vec(v).ok().map(|b| (k.clone(), b)))
        .collect();
    store
        .update(task_id, principal, &answers, now_ms)
        .map(|()| serde_json::json!({}))
}

/// `tasks/cancel`'s whole answer: cancel through the store face and hand back the SAME empty ack
/// [`update`] does. `None` when the store holds nothing for this (id, principal) pair.
///
/// IDEMPOTENT on a task that has already settled — the face says so, and this function does not
/// re-state it as a second rule that could drift from the first.
#[must_use]
pub fn cancel(
    store: &dyn TaskStore,
    task_id: &str,
    principal: &str,
    now_ms: u64,
) -> Option<serde_json::Value> {
    store
        .cancel(task_id, principal, now_ms)
        .map(|()| serde_json::json!({}))
}

#[cfg(test)]
#[path = "tests/tasks.rs"]
mod tests;
