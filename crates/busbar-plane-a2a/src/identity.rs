// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR'S TASK IDENTITY ON A RELAYED HOP (ARCHITECT ruling B1, 2026-10-02: the far end's task id
//! rewritten to busbar's routable id is GOVERNED routing identity, the class of the mapped model).
//! Ported from the served engine (`busbar-a2a` `receive` and `relay::rewrite_identity`, `idmap`),
//! byte for byte; pure, so every rule is tested without a door.
//!
//! * A fresh task's id is `a2a-<agent>-<16 hex>` ([`mint`]), its eight bytes from the kernel's
//!   `random.fill`; its `contextId` is the caller's, or the id when the caller named none.
//! * A request naming a task the caller holds reuses that task's identity ([`named_tasks`]).
//! * The far end's answer leaves under busbar's identity ([`rewrite_identity`]); the far end's own
//!   id is read first ([`backend_task_id`]) so a later request naming busbar's id is sent on under
//!   the far end's ([`translate_request`]).
//! * A refused hop that opened or names a task answers with that task as a `ResourceInfo`
//!   ([`about_task`]).

use serde_json::{json, Map, Value};

use crate::a2a::task::TaskState;
use crate::arrival::Refusal;

/// What every task id busbar mints starts with.
pub const TASK_ID_PREFIX: &str = "a2a";

/// How many random bytes a minted id carries.
pub const MINT_BYTES: usize = 8;

/// A FRESH TASK ID for a task relayed to `agent`: `a2a-<agent>-<16 hex>` over `random`.
#[must_use]
pub fn mint(agent: &str, random: [u8; MINT_BYTES]) -> String {
    format!(
        "{TASK_ID_PREFIX}-{agent}-{:016x}",
        u64::from_be_bytes(random)
    )
}

/// The members of a request's `params` that name a task: `id` is `GetTask`/`CancelTask`'s
/// spelling, `taskId` every verb about a task, `task_id` A2A v1.0's.
pub const TASK_ID_MEMBERS: [&str; 3] = ["id", "taskId", "task_id"];

/// The task ids a request names at the top of its `params`, in [`TASK_ID_MEMBERS`] order: the
/// candidates for the task the request addresses.
#[must_use]
pub fn named_tasks(envelope: &Value) -> Vec<&str> {
    let Some(params) = envelope.get("params").and_then(Value::as_object) else {
        return Vec::new();
    };
    TASK_ID_MEMBERS
        .iter()
        .filter_map(|m| params.get(*m).and_then(Value::as_str))
        .collect()
}

/// The `contextId` the caller's message names; empty when none.
#[must_use]
pub fn context_of(envelope: &Value) -> &str {
    envelope
        .pointer("/params/message/contextId")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Every task id [`translate_request`] may translate: the top-level members, then the message's
/// (a message's own `id` is not a task id).
#[must_use]
pub fn translatable(envelope: &Value) -> Vec<&str> {
    let mut ids = named_tasks(envelope);
    if let Some(message) = envelope
        .pointer("/params/message")
        .and_then(Value::as_object)
    {
        ids.extend(
            TASK_ID_MEMBERS
                .iter()
                .filter(|m| **m != "id")
                .filter_map(|m| message.get(*m).and_then(Value::as_str)),
        );
    }
    ids
}

/// TRANSLATE every busbar task id in a request's `params` (and its message's) to the far end's,
/// through `backend_of`, which answers only for a task the caller holds. `None` when nothing was
/// translated: the caller's bytes then go on UNCHANGED, never re-serialized.
#[must_use]
pub fn translate_request(
    envelope: &Value,
    backend_of: &dyn Fn(&str) -> Option<String>,
) -> Option<Vec<u8>> {
    let params = envelope.get("params")?.as_object()?;
    let mut rewritten = params.clone();
    let mut any = translate_members(&mut rewritten, &TASK_ID_MEMBERS, backend_of);
    if let Some(message) = rewritten.get("message").and_then(Value::as_object) {
        let mut msg = message.clone();
        if translate_members(&mut msg, &TASK_ID_MEMBERS[1..], backend_of) {
            rewritten.insert("message".to_string(), Value::Object(msg));
            any = true;
        }
    }
    if !any {
        return None;
    }
    let mut out = envelope.clone();
    out.as_object_mut()?
        .insert("params".to_string(), Value::Object(rewritten));
    serde_json::to_vec(&out).ok()
}

/// Translate `members` of `obj` in place; `true` when any was.
fn translate_members(
    obj: &mut Map<String, Value>,
    members: &[&str],
    backend_of: &dyn Fn(&str) -> Option<String>,
) -> bool {
    let mut any = false;
    for member in members {
        let Some(backend) = obj
            .get(*member)
            .and_then(Value::as_str)
            .and_then(backend_of)
        else {
            continue;
        };
        obj.insert((*member).to_string(), Value::String(backend));
        any = true;
    }
    any
}

/// The wrapper members an A2A v1.0 `result` puts its payload under, each with the member that
/// identifies the task inside it.
const WRAPPERS: [(&str, &str); 4] = [
    ("task", "id"),
    ("message", "taskId"),
    ("statusUpdate", "taskId"),
    ("artifactUpdate", "taskId"),
];

fn wrapper_of(result: &Value) -> Option<(&'static str, &'static str)> {
    WRAPPERS
        .into_iter()
        .find(|(member, _)| result.get(member).is_some_and(Value::is_object))
}

fn payload_of(result: &Value) -> &Value {
    wrapper_of(result)
        .and_then(|(member, _)| result.get(member))
        .unwrap_or(result)
}

/// THE FAR END'S OWN TASK ID, read off a `result` before [`rewrite_identity`] replaces it.
#[must_use]
pub fn backend_task_id(result: &Value) -> Option<String> {
    let id_member = wrapper_of(result).map_or("id", |(_, m)| m);
    payload_of(result)
        .get(id_member)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// ONE READING OF A FAR END'S STATE TOKEN, in either A2A vocabulary (`input-required` or
/// `TASK_STATE_INPUT_REQUIRED`); `None` for a token this build does not know.
#[must_use]
pub fn wire_state(token: &str) -> Option<TaskState> {
    if let Ok(state) = TaskState::parse(token) {
        return Some(state);
    }
    TaskState::parse(
        &token
            .strip_prefix("TASK_STATE_")?
            .to_ascii_lowercase()
            .replace('_', "-"),
    )
    .ok()
}

/// The task state a `result` reports, `Working` when it reports none this build can read: a relay
/// that guessed `completed` from an unread token would close a running task.
#[must_use]
pub fn reported_task_state(result: &Value) -> TaskState {
    payload_of(result)
        .pointer("/status/state")
        .and_then(Value::as_str)
        .and_then(wire_state)
        .unwrap_or(TaskState::Working)
}

/// The metadata key the matched skill rides under: busbar's own, namespaced annotation.
pub const SKILL_METADATA_KEY: &str = "busbar/skill";

/// SUBSTITUTE BUSBAR'S TASK IDENTITY onto a far end's `result`, leaving everything else alone: the
/// payload's own identity member (inside its wrapper), its `contextId`, the ids a status message
/// nests, and the matched skill as `metadata["busbar/skill"]`.
pub fn rewrite_identity(
    result: &mut Value,
    task_id: &str,
    context_id: &str,
    matched_skill: Option<&str>,
) {
    if !result.is_object() {
        *result = json!({ "kind": "task" });
    }
    let (wrapper, id_member) = match wrapper_of(result) {
        Some((member, id_member)) => (Some(member), id_member),
        None => (None, "id"),
    };
    let payload = match wrapper {
        Some(member) => match result.get_mut(member) {
            Some(inner) => inner,
            None => return,
        },
        None => result,
    };
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    // A standalone message names no task: `taskId` is added only to one that belongs to a task.
    if id_member != "taskId" || wrapper != Some("message") || obj.contains_key("taskId") {
        obj.insert(id_member.to_string(), Value::String(task_id.to_string()));
    }
    obj.insert(
        "contextId".to_string(),
        Value::String(context_id.to_string()),
    );
    if let Some(msg) = obj
        .get_mut("status")
        .and_then(Value::as_object_mut)
        .and_then(|s| s.get_mut("message"))
        .and_then(Value::as_object_mut)
    {
        if msg.contains_key("taskId") {
            msg.insert("taskId".to_string(), Value::String(task_id.to_string()));
        }
        if msg.contains_key("contextId") {
            msg.insert(
                "contextId".to_string(),
                Value::String(context_id.to_string()),
            );
        }
    }
    if let Some(skill) = matched_skill {
        let metadata = obj
            .entry("metadata")
            .or_insert_with(|| Value::Object(Map::new()));
        if !metadata.is_object() {
            *metadata = Value::Object(Map::new());
        }
        if let Some(metadata) = metadata.as_object_mut() {
            metadata.insert(
                SKILL_METADATA_KEY.to_string(),
                Value::String(skill.to_string()),
            );
        }
    }
}

/// The ProtoJSON type URL of `google.rpc.ResourceInfo`, which is how the task a refusal is about
/// travels.
pub const RESOURCE_INFO_TYPE: &str = "type.googleapis.com/google.rpc.ResourceInfo";

/// The resource type a task's `ResourceInfo` names.
pub const TASK_RESOURCE_TYPE: &str = "a2a.busbar/task";

/// THE REFUSAL'S ENVELOPE, NAMING THE TASK: its error carries a `ResourceInfo` for `task_id` after
/// its `ErrorInfo` (the engine's `rpcerror::about_task`).
#[must_use]
pub fn about_task(refusal: &Refusal, task_id: &str) -> Value {
    let mut doc = refusal.envelope();
    let entry = json!({
        "@type": RESOURCE_INFO_TYPE,
        "resourceType": TASK_RESOURCE_TYPE,
        "resourceName": task_id,
    });
    match doc["error"]["data"].as_array_mut() {
        Some(data) => data.push(entry),
        None => doc["error"]["data"] = json!([entry]),
    }
    doc
}

/// The HTTP status A2A section 5.4 binds an error `code` to, for the codes the engine re-emits from
/// a far end's error; `None` for a code A2A does not define.
#[must_use]
pub const fn status_of_code(code: i64) -> Option<u32> {
    Some(match code {
        -32001 | -32601 => 404,
        -32002 => 409,
        -32003 | -32004 | -32007 | -32008 | -32009 | -32600 | -32602 | -32700 => 400,
        -32005 => 415,
        -32006 => 502,
        -32603 => 500,
        _ => return None,
    })
}

#[cfg(test)]
#[path = "tests/identity_tests.rs"]
mod tests;
