// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INVERSE OF THE IDENTITY SUBSTITUTION: busbar's task id, back to the backend's.
//!
//! ## The defect this closes
//!
//! busbar issues its OWN task identity and substitutes it into every answer it relays
//! ([`super::relay::rewrite_identity`]), for a good reason the relay module states: a caller's later
//! reads resolve against busbar's store, which keys on the id busbar issued, so carrying the
//! backend's id through would hand the caller a handle that resolves to nothing.
//!
//! That substitution had no inverse. busbar is content-blind on the receiving side and relays the
//! caller's envelope VERBATIM, so a caller handed `a2a-planner-9f2…` and asking `GetTask` for it had
//! that id forwarded, unchanged, to a backend that has never heard of it. **The identity busbar
//! issues was one busbar could not resolve.** Every read verb on this plane — `GetTask`,
//! `CancelTask`, `SubscribeToTask`, the push-config verbs — therefore failed for any caller who used
//! the id busbar itself gave them. In the official A2A TCK that is `CORE-GET-001`
//! ("GetTask failed"), `CORE-CANCEL-002` and `CORE-SEND-002`, and it is the last cluster of MUST
//! failures that is busbar's own rather than the fronted agent's.
//!
//! A translation is not a break with content-blindness. busbar already reads `method`,
//! `params.message.contextId` and `params.configuration.pushNotificationConfig.url` on the way in,
//! and already rewrites two identity members on the way out. This is the same concern, in the only
//! direction that was missing, and NOTHING else in the envelope is touched: a request with no id
//! busbar issued is forwarded byte-for-byte, as the original `Bytes`.
//!
//! ## WHAT IS NOT BUILT, and it is a real limitation
//!
//! **This mapping is PROCESS-LOCAL and does not survive a restart.** The durable place for it is a
//! column on the task row, and adding one is a change to `busbar_api::TaskRow` and therefore to the
//! store plugin ABI every backing store implements — which is not a change to make as a side effect
//! of a conformance fix. So a `GetTask` for a task whose relay happened in a previous process
//! forwards the busbar id unchanged and the backend answers `TaskNotFound`, exactly as it does today
//! for every task. This is strictly better than what it replaces (which was that state for ALL
//! tasks, always) and it is not the finished article. `pushdeliver::pins` is process-local for the
//! same reason and says so in the same terms.
//!
//! The map is BOUNDED and evicts oldest-first. An unbounded process-local map keyed by a value a
//! caller can cause to be created is a memory leak with an external trigger.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

/// How many task identities are remembered. Generous — an entry is two short strings — and finite,
/// because the alternative is a map a caller grows by making requests.
const CAPACITY: usize = 100_000;

/// busbar task id → the backend's own task id, with an insertion order for eviction.
#[derive(Default)]
struct Table {
    by_busbar_id: HashMap<String, String>,
    /// Insertion order, oldest first. A `VecDeque` would be marginally better for the pop; this is
    /// a `Vec` because eviction happens once per `CAPACITY` insertions and clarity wins.
    order: Vec<String>,
}

static TABLE: std::sync::LazyLock<Mutex<Table>> =
    std::sync::LazyLock::new(|| Mutex::new(Table::default()));

fn table() -> MutexGuard<'static, Table> {
    TABLE.lock().unwrap_or_else(|e| e.into_inner())
}

/// REMEMBER what the backend calls the task busbar calls `busbar_id`.
///
/// Idempotent, and re-recording the same pair does not re-order it: a long-running task that streams
/// a hundred events must not push a hundred other tasks out of the map.
pub(crate) fn remember(busbar_id: &str, backend_id: &str) {
    if busbar_id.is_empty() || backend_id.is_empty() || busbar_id == backend_id {
        return;
    }
    let mut t = table();
    if t.by_busbar_id
        .get(busbar_id)
        .is_some_and(|v| v == backend_id)
    {
        return;
    }
    if t.by_busbar_id
        .insert(busbar_id.to_string(), backend_id.to_string())
        .is_none()
    {
        t.order.push(busbar_id.to_string());
    }
    while t.order.len() > CAPACITY {
        let oldest = t.order.remove(0);
        t.by_busbar_id.remove(&oldest);
    }
}

/// What the backend calls this task, if busbar has seen it answer about one.
pub(crate) fn backend_id_for(busbar_id: &str) -> Option<String> {
    table().by_busbar_id.get(busbar_id).cloned()
}

/// The members of a request's `params` that name a task. `id` is `GetTask`/`CancelTask`'s spelling;
/// `taskId` is the one every verb that is ABOUT a task uses, including the push-config verbs and
/// A2A v1.0's `task_id`.
pub(crate) const TASK_ID_MEMBERS: [&str; 3] = ["id", "taskId", "task_id"];

/// TRANSLATE every busbar task id in a request's `params` back to the backend's.
///
/// Returns `None` when nothing was translated, which is the overwhelmingly common case and the one
/// that matters: the caller's bytes are then forwarded UNCHANGED rather than re-serialized. A
/// gateway that round-tripped every request through `serde_json` would silently normalise member
/// order, number formatting and duplicate keys in somebody else's payload.
pub(crate) fn translate_request(envelope: &serde_json::Value) -> Option<Vec<u8>> {
    let params = envelope.get("params")?.as_object()?;
    let mut rewritten = params.clone();
    let mut any = false;
    for member in TASK_ID_MEMBERS {
        let Some(busbar_id) = rewritten.get(member).and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(backend_id) = backend_id_for(busbar_id) else {
            continue;
        };
        rewritten.insert(member.to_string(), serde_json::Value::String(backend_id));
        any = true;
    }
    if !any {
        return None;
    }
    let mut out = envelope.clone();
    out.as_object_mut()?
        .insert("params".to_string(), serde_json::Value::Object(rewritten));
    serde_json::to_vec(&out).ok()
}

#[cfg(test)]
#[path = "tests/idmap_tests.rs"]
mod idmap_tests;
