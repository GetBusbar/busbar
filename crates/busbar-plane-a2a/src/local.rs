// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VERBS THE PLANE ANSWERS ITSELF, over the task store ([`crate::tasks`]): `ListTasks`, the
//! push-notification config CRUD, and the two refusals of `SubscribeToTask`. Every other method is
//! relayed; these answer a fact about busbar (its task rows, the ids it issued, the callback it
//! delivers), so a backend cannot answer them. The engine's `busbar-a2a` `local.rs` is the
//! behaviour, byte for byte, with one difference that is the point of the move: a config lives in
//! a host record, so it survives a restart rather than living in one process's map.
//!
//! * `ListTasks` answers the caller's own rows, newest first, cut by a cursor; no `status.timestamp`,
//!   no `artifacts`, no `history` (busbar holds none of them).
//! * The push config CRUD holds ONE config per task, judges the callback by the same SSRF floor as
//!   the inline path ([`judge_callback`]), and never echoes the config's `authentication`.
//! * `SubscribeToTask` is refused for a task busbar did not issue to this caller, and for one it
//!   holds as terminal; a live task is the backend's to answer (`None`).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::a2a::task::{Task, TaskState};
use crate::arrival::Refusal;
use crate::records::KIND_PUSH_CONFIG;
use crate::tasks::{self, task_key, Halt, Records, Write};

/// WHICH SPELLING OF THE PUSH-CONFIG VERBS A CALLER USED: v0.3 nests the config under
/// `pushNotificationConfig`, v1.0 flattens it, so the dialect decides the envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    /// A2A v0.3: `tasks/pushNotificationConfig/*`.
    V03,
    /// A2A v1.0: `*TaskPushNotificationConfig`.
    V10,
}

/// A verb this plane answers WITHOUT a backend hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalVerb {
    /// `ListTasks`.
    ListTasks,
    /// Create (or replace) the task's push config.
    CreatePushConfig(Dialect),
    /// Read it back.
    GetPushConfig(Dialect),
    /// List it.
    ListPushConfigs(Dialect),
    /// Delete it.
    DeletePushConfig(Dialect),
    /// Only the two refusals are local; see [`subscribe_refusal`].
    Subscribe,
}

/// The local verb `method` names, listed rather than pattern-matched (the names are
/// [`crate::LOCAL_VERB_METHODS`]).
#[must_use]
pub fn verb_of(method: &str) -> Option<LocalVerb> {
    Some(match method {
        "ListTasks" | "tasks/list" => LocalVerb::ListTasks,
        "CreateTaskPushNotificationConfig" => LocalVerb::CreatePushConfig(Dialect::V10),
        "tasks/pushNotificationConfig/set" => LocalVerb::CreatePushConfig(Dialect::V03),
        "GetTaskPushNotificationConfig" => LocalVerb::GetPushConfig(Dialect::V10),
        "tasks/pushNotificationConfig/get" => LocalVerb::GetPushConfig(Dialect::V03),
        "ListTaskPushNotificationConfigs" => LocalVerb::ListPushConfigs(Dialect::V10),
        "tasks/pushNotificationConfig/list" => LocalVerb::ListPushConfigs(Dialect::V03),
        "DeleteTaskPushNotificationConfig" => LocalVerb::DeletePushConfig(Dialect::V10),
        "tasks/pushNotificationConfig/delete" => LocalVerb::DeletePushConfig(Dialect::V03),
        "SubscribeToTask" | "tasks/resubscribe" => LocalVerb::Subscribe,
        _ => return None,
    })
}

/// The host's reach the verbs need beyond the records: the destination judge.
pub trait Reach: Records {
    /// `dest.judge` of `dest` under the open-web class, its name resolved: a `DEST_*` verdict.
    ///
    /// # Errors
    /// [`Halt`].
    fn judge(&mut self, dest: &str) -> Result<u64, Halt>;
}

/// One local answer: its status and its JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The status.
    pub status: u32,
    /// The body.
    pub body: Vec<u8>,
}

/// `-32001`: no such task for this caller.
const TASK_NOT_FOUND: i64 = -32001;
/// `-32004`: busbar does not do that.
const UNSUPPORTED_OPERATION: i64 = -32004;
/// `-32602`: the params are wrong.
const INVALID_PARAMS: i64 = -32602;
/// `-32603`: busbar failed.
const INTERNAL: i64 = -32603;

/// The refusal every verb gives for a task id it does not hold for this caller: one string, so the
/// verbs cannot drift into different existence oracles.
pub const NO_SUCH_TASK: &str = "no task with that id is open for this caller";

/// A JSON-RPC success under the caller's id.
fn ok(rpc_id: &Value, result: Value) -> Answer {
    let doc = json!({ "jsonrpc": "2.0", "id": rpc_id, "result": result });
    Answer {
        status: 200,
        body: serde_json::to_vec(&doc).unwrap_or_default(),
    }
}

/// A JSON-RPC error at the status A2A section 5.4 binds to its code.
fn err(rpc_id: &Value, code: i64, message: impl Into<String>) -> Answer {
    let refusal = Refusal {
        status: match code {
            TASK_NOT_FOUND => 404,
            UNSUPPORTED_OPERATION | INVALID_PARAMS => 400,
            _ => 500,
        },
        id: Some(rpc_id.clone()),
        code,
        message: message.into(),
    };
    Answer {
        status: refusal.status,
        body: serde_json::to_vec(&refusal.envelope()).unwrap_or_default(),
    }
}

/// The answer when the task store could not be reached: JSON-RPC's internal error.
#[must_use]
pub fn unreadable(rpc_id: &Value) -> Answer {
    err(rpc_id, INTERNAL, "the task store could not be reached")
}

/// ANSWER local verb `verb` of `envelope` for `caller` at `now`; its writes go to `out`. `None`
/// when the answer is not the plane's (a subscribe to a live task).
///
/// # Errors
/// [`Halt::Pending`] when a records call pends; nothing is written then.
pub fn answer(
    reach: &mut dyn Reach,
    verb: LocalVerb,
    envelope: &Value,
    caller: &str,
    now: u64,
    out: &mut Vec<Write>,
) -> Result<Option<Answer>, Halt> {
    let rpc_id = envelope.get("id").cloned().unwrap_or(Value::Null);
    let params = envelope.get("params").cloned().unwrap_or(Value::Null);
    let answered = match verb {
        LocalVerb::ListTasks => list_tasks(reach, &params, &rpc_id, caller, now)?,
        LocalVerb::CreatePushConfig(d) => {
            create_push_config(reach, d, &params, &rpc_id, caller, now, out)?
        }
        LocalVerb::GetPushConfig(d) => get_push_config(reach, d, &params, &rpc_id, caller, now)?,
        LocalVerb::ListPushConfigs(d) => {
            list_push_configs(reach, d, &params, &rpc_id, caller, now)?
        }
        LocalVerb::DeletePushConfig(d) => {
            delete_push_config(reach, d, &params, &rpc_id, caller, now, out)?
        }
        LocalVerb::Subscribe => return subscribe_refusal(reach, &params, &rpc_id, caller, now),
    };
    Ok(Some(answered))
}

// ══ THE TASK PROJECTION ══════════════════════════════════════════════════════════════════════════

/// The protocol's spelling of a task state (the `TASK_STATE_*` tokens of the A2A v1.0 schema).
#[must_use]
pub fn wire_state(state: TaskState) -> &'static str {
    match state {
        TaskState::Submitted => "TASK_STATE_SUBMITTED",
        TaskState::Working => "TASK_STATE_WORKING",
        TaskState::InputRequired => "TASK_STATE_INPUT_REQUIRED",
        TaskState::AuthRequired => "TASK_STATE_AUTH_REQUIRED",
        TaskState::Completed => "TASK_STATE_COMPLETED",
        TaskState::Failed => "TASK_STATE_FAILED",
        TaskState::Canceled => "TASK_STATE_CANCELED",
        TaskState::Rejected => "TASK_STATE_REJECTED",
    }
}

/// One task row as an A2A `Task`: id, context and state, and nothing busbar does not hold.
#[must_use]
pub fn task_json(task: &Task) -> Value {
    json!({
        "id": task.task_id,
        "contextId": task.context_id,
        "status": { "state": wire_state(task.state) },
    })
}

// ══ ListTasks ════════════════════════════════════════════════════════════════════════════════════

/// The page size a caller that asks for none gets.
pub const DEFAULT_PAGE_SIZE: usize = 50;
/// The largest page size.
pub const MAX_PAGE_SIZE: usize = 200;

/// An integer that arrives as a number or, per the schema's `anyOf`, as a decimal string.
fn as_int(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// A member under its camelCase or its snake_case spelling.
fn member<'a>(params: &'a Value, camel: &str, snake: &str) -> Option<&'a Value> {
    params.get(camel).or_else(|| params.get(snake))
}

/// THE PAGE CURSOR: the sort key of the last row returned, `"<updated_at>:<task_id>"`.
#[must_use]
pub fn cursor_of(task: &Task) -> String {
    format!("{}:{}", task.updated_at, task.task_id)
}

/// Is `task` strictly after `cursor` in the descending order? An unreadable cursor selects all.
#[must_use]
pub fn after_cursor(task: &Task, cursor: &str) -> bool {
    let Some((ts, id)) = cursor.rsplit_once(':') else {
        return true;
    };
    let Ok(ts) = ts.parse::<u64>() else {
        return true;
    };
    (task.updated_at, task.task_id.as_str()) < (ts, id)
}

/// `ListTasks`: the caller's own rows, filtered, newest first, one page.
fn list_tasks(
    rec: &mut dyn Records,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
) -> Result<Answer, Halt> {
    let context_id = member(params, "contextId", "context_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let wanted = member(params, "status", "status").and_then(Value::as_str);
    let page_size = as_int(member(params, "pageSize", "page_size"))
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .min(MAX_PAGE_SIZE);
    let token = member(params, "pageToken", "page_token")
        .and_then(Value::as_str)
        .unwrap_or_default();
    // SCOPED FIRST, filtered second: every filter narrows the caller's own set.
    let mut rows: Vec<Task> = tasks::list(rec, caller, now)?
        .iter()
        .filter_map(|r| Task::from_row(r).ok())
        .filter(|t| context_id.is_empty() || t.context_id == context_id)
        .filter(|t| wanted.is_none_or(|w| wire_state(t.state) == w || t.state.as_str() == w))
        .collect();
    rows.sort_by(|a, b| {
        (b.updated_at, b.task_id.as_str()).cmp(&(a.updated_at, a.task_id.as_str()))
    });
    let start: Vec<&Task> = rows
        .iter()
        .filter(|t| token.is_empty() || after_cursor(t, token))
        .collect();
    let page: Vec<&Task> = start.iter().take(page_size).copied().collect();
    // Present on every page and empty on the last, so a client's paging loop ends.
    let next = if start.len() > page.len() {
        page.last().map(|t| cursor_of(t)).unwrap_or_default()
    } else {
        String::new()
    };
    Ok(ok(
        rpc_id,
        json!({
            "tasks": page.iter().map(|t| task_json(t)).collect::<Vec<_>>(),
            "nextPageToken": next,
            "pageSize": i32::try_from(page_size).unwrap_or(i32::MAX),
            "totalSize": i32::try_from(rows.len()).unwrap_or(i32::MAX),
        }),
    ))
}

// ══ PUSH-NOTIFICATION CONFIG CRUD ════════════════════════════════════════════════════════════════

/// ONE registered push config: what a read verb may answer with. The credential is not a member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushConfig {
    /// The caller's id for it.
    pub id: String,
    /// The callback URL, exactly as registered and as it passed the floor.
    pub url: String,
}

/// The credential a config asks busbar to present at its webhook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryAuth {
    /// The HTTP authentication scheme.
    pub scheme: String,
    /// The credentials after it.
    pub credentials: String,
}

/// The config as `dialect` spells it; never with `authentication`.
#[must_use]
pub fn config_json(dialect: Dialect, task_id: &str, cfg: &PushConfig) -> Value {
    match dialect {
        Dialect::V10 => json!({ "taskId": task_id, "id": cfg.id, "url": cfg.url }),
        Dialect::V03 => json!({
            "taskId": task_id,
            "pushNotificationConfig": { "id": cfg.id, "url": cfg.url },
        }),
    }
}

/// The config members of a request, nested (v0.3) or flat (v1.0).
#[must_use]
pub fn config_params(params: &Value) -> &Value {
    params.get("pushNotificationConfig").unwrap_or(params)
}

/// THE CONFIG ID a get/delete names: `id` on v1.0, `pushNotificationConfigId` on v0.3 (where `id`
/// is the TASK); empty when absent.
#[must_use]
pub fn config_id_wanted(dialect: Dialect, params: &Value) -> &str {
    match dialect {
        Dialect::V10 => config_params(params).get("id"),
        Dialect::V03 => params.get("pushNotificationConfigId"),
    }
    .and_then(Value::as_str)
    .unwrap_or_default()
}

/// THE CREDENTIAL a config names, out of `{scheme, credentials}` or `{schemes: [..], credentials}`;
/// `Ok(None)` for none.
///
/// # Errors
/// A credential busbar cannot present, in words that never quote it back.
pub fn delivery_auth(cfg: &Value) -> Result<Option<DeliveryAuth>, String> {
    let Some(auth) = cfg.get("authentication").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let scheme = auth
        .get("scheme")
        .and_then(Value::as_str)
        .or_else(|| {
            auth.get("schemes")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
        })
        .unwrap_or_default()
        .trim()
        .to_string();
    if scheme.is_empty() {
        return Err(
            "a push notification config's `authentication` must name a `scheme` (an HTTP \
             authentication scheme such as `Bearer`), because the scheme is what busbar puts in \
             front of the credential on the `Authorization` header it sends to your receiver"
                .to_string(),
        );
    }
    if !scheme
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'"' && b != b',')
    {
        return Err(format!(
            "the push notification config's authentication scheme `{scheme}` is not an HTTP \
             authentication scheme name: it must be a single token of printable ASCII"
        ));
    }
    let credentials = auth
        .get("credentials")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if credentials
        .bytes()
        .any(|b| !b.is_ascii_graphic() && b != b' ')
    {
        return Err(
            "the push notification config's authentication `credentials` contain a byte that \
             cannot appear in an HTTP header field value"
                .to_string(),
        );
    }
    Ok(Some(DeliveryAuth {
        scheme,
        credentials,
    }))
}

/// THE CALLBACK FLOOR: the engine's push-notification guard, its structural half here and its
/// resolution through the host's destination judge. `Ok` is the URL as registered.
///
/// # Errors
/// [`Halt`] from the judge; `Ok(Err(words))` for a refused callback, in the guard's words.
pub fn judge_callback(reach: &mut dyn Reach, url: &str) -> Result<Result<(), String>, Halt> {
    use busbar_contract::abi::host::service::{DEST_ALLOWED, DEST_NO_ADDRESSES, DEST_UNRESOLVABLE};
    use busbar_contract::net::{ip_is_internal, is_alternate_ipv4_encoding, parse_url, UrlRefusal};
    let malformed = || Ok(Err(format!("push callback URL is malformed: `{url}`")));
    let Some((scheme, _)) = url.split_once("://") else {
        return malformed();
    };
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+')
    {
        return malformed();
    }
    let parts = match parse_url(url) {
        Ok(p) if !p.userinfo => p,
        Err(UrlRefusal::NoHost) => return Ok(Err("push callback URL has no host".into())),
        _ => return malformed(),
    };
    let host = parts.host.to_ascii_lowercase();
    if parts.scheme != "https" {
        return Ok(Err(format!(
            "push callback scheme `{}` is refused; a callback carries task metadata off-box \
             and must be https",
            parts.scheme
        )));
    }
    if is_alternate_ipv4_encoding(&host) {
        return Ok(Err(format!(
            "push callback host `{host}` is an alternate IPv4 encoding, which resolves to an \
             address a canonical literal check would not see"
        )));
    }
    let internal = |shown: &dyn std::fmt::Display| {
        format!(
            "push callback resolves to the INTERNAL address {shown}; delivering there would lend \
             busbar's network position to the caller"
        )
    };
    if let Ok(literal) = host.parse() {
        return Ok(if ip_is_internal(&literal) {
            Err(internal(&literal))
        } else {
            Ok(())
        });
    }
    Ok(match reach.judge(url)? {
        DEST_ALLOWED => Ok(()),
        DEST_UNRESOLVABLE | DEST_NO_ADDRESSES => Err(format!(
            "push callback host `{host}` resolved to no addresses; nothing was checked, so \
             nothing is allowed"
        )),
        // The judge names no address: the host stands where the engine named the address.
        _ => Err(internal(&host)),
    })
}

/// THE TASK a push-config request names, through the same scoped read every verb uses.
fn addressed(
    rec: &mut dyn Records,
    params: &Value,
    caller: &str,
    now: u64,
) -> Result<Option<Task>, Halt> {
    for name in ["taskId", "task_id", "id"] {
        if let Some(id) = params.get(name).and_then(Value::as_str) {
            if let Some(held) = tasks::get(rec, caller, id, now)? {
                if let Ok(task) = Task::from_row(&held.row) {
                    return Ok(Some(task));
                }
            }
        }
    }
    Ok(None)
}

/// The config held for `caller`'s task `task_id`, if any.
fn held_config(
    rec: &mut dyn Records,
    caller: &str,
    task_id: &str,
) -> Result<Option<PushConfig>, Halt> {
    Ok(rec
        .get(KIND_PUSH_CONFIG, &task_key(caller, task_id))?
        .and_then(|b| serde_json::from_slice(&b).ok()))
}

/// `CreateTaskPushNotificationConfig` / `tasks/pushNotificationConfig/set`.
fn create_push_config(
    reach: &mut dyn Reach,
    dialect: Dialect,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
    out: &mut Vec<Write>,
) -> Result<Answer, Halt> {
    let Some(task) = addressed(reach, params, caller, now)? else {
        return Ok(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK));
    };
    let cfg = config_params(params);
    if cfg.get("token").is_some() {
        return Ok(err(
            rpc_id,
            UNSUPPORTED_OPERATION,
            "busbar does not carry a push notification config `token`: there is no header or body \
             member the delivery puts it in, so storing it would promise the receiver a value it \
             never sees. Use `authentication`, which busbar presents on the `Authorization` header, \
             or register the secret in the callback URL your receiver checks.",
        ));
    }
    if let Err(message) = delivery_auth(cfg) {
        return Ok(err(rpc_id, INVALID_PARAMS, message));
    }
    let Some(url) = cfg.get("url").and_then(Value::as_str) else {
        return Ok(err(
            rpc_id,
            INVALID_PARAMS,
            "a push notification config must name the `url` busbar is to call",
        ));
    };
    let id = cfg
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    // ONE CONFIG PER TASK, refused out loud: the delivery is one request.
    if held_config(reach, caller, &task.task_id)?.is_some_and(|c| c.id != id) {
        return Ok(err(
            rpc_id,
            UNSUPPORTED_OPERATION,
            "this task already has a push notification config and busbar holds exactly one \
             per task: its durable task row carries one callback and its delivery is one \
             request. Delete the existing config before registering another.",
        ));
    }
    if let Err(message) = judge_callback(reach, url)? {
        return Ok(err(rpc_id, INVALID_PARAMS, message));
    }
    let stored = PushConfig {
        id,
        url: url.to_string(),
    };
    out.push(Write {
        kind: KIND_PUSH_CONFIG,
        key: task_key(caller, &task.task_id),
        value: serde_json::to_vec(&stored).map_err(|e| Halt::Failed(e.to_string()))?,
    });
    Ok(ok(rpc_id, config_json(dialect, &task.task_id, &stored)))
}

/// `GetTaskPushNotificationConfig` / `tasks/pushNotificationConfig/get`.
fn get_push_config(
    rec: &mut dyn Records,
    dialect: Dialect,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
) -> Result<Answer, Halt> {
    let Some(task) = addressed(rec, params, caller, now)? else {
        return Ok(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK));
    };
    let wanted = config_id_wanted(dialect, params);
    Ok(
        match held_config(rec, caller, &task.task_id)?.filter(|c| c.id == wanted) {
            Some(cfg) => ok(rpc_id, config_json(dialect, &task.task_id, &cfg)),
            None => err(
                rpc_id,
                TASK_NOT_FOUND,
                "no push notification config with that id is registered for this task",
            ),
        },
    )
}

/// `ListTaskPushNotificationConfigs` / `tasks/pushNotificationConfig/list`.
fn list_push_configs(
    rec: &mut dyn Records,
    dialect: Dialect,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
) -> Result<Answer, Halt> {
    let Some(task) = addressed(rec, params, caller, now)? else {
        return Ok(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK));
    };
    let held: Vec<Value> = held_config(rec, caller, &task.task_id)?
        .map(|c| vec![config_json(dialect, &task.task_id, &c)])
        .unwrap_or_default();
    Ok(match dialect {
        Dialect::V10 => ok(rpc_id, json!({ "configs": held, "nextPageToken": "" })),
        Dialect::V03 => ok(rpc_id, Value::Array(held)),
    })
}

/// `DeleteTaskPushNotificationConfig` / `tasks/pushNotificationConfig/delete`. IDEMPOTENT: a
/// config that is not there is no error; one that is goes as a tombstone.
fn delete_push_config(
    rec: &mut dyn Records,
    dialect: Dialect,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
    out: &mut Vec<Write>,
) -> Result<Answer, Halt> {
    let Some(task) = addressed(rec, params, caller, now)? else {
        return Ok(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK));
    };
    let wanted = config_id_wanted(dialect, params);
    if held_config(rec, caller, &task.task_id)?.is_some_and(|c| c.id == wanted) {
        out.push(Write {
            kind: KIND_PUSH_CONFIG,
            key: task_key(caller, &task.task_id),
            value: Vec::new(),
        });
    }
    // v0.3 answers `null`; v1.0's `google.protobuf.Empty` is `{}`.
    Ok(match dialect {
        Dialect::V03 => ok(rpc_id, Value::Null),
        Dialect::V10 => ok(rpc_id, json!({})),
    })
}

// ══ SubscribeToTask ══════════════════════════════════════════════════════════════════════════════

/// The refusal a subscribe earns from busbar's own record, or `None` when the backend answers.
fn subscribe_refusal(
    rec: &mut dyn Records,
    params: &Value,
    rpc_id: &Value,
    caller: &str,
    now: u64,
) -> Result<Option<Answer>, Halt> {
    let Some(named) = ["id", "taskId", "task_id"]
        .iter()
        .find_map(|m| params.get(*m).and_then(Value::as_str))
    else {
        return Ok(None);
    };
    Ok(match tasks::get(rec, caller, named, now)? {
        None => Some(err(rpc_id, TASK_NOT_FOUND, NO_SUCH_TASK)),
        Some(held) => match Task::from_row(&held.row) {
            Ok(task) if task.state.is_terminal() => Some(err(
                rpc_id,
                UNSUPPORTED_OPERATION,
                "this task has reached a terminal state, so there are no further events to \
                 subscribe to",
            )),
            _ => None,
        },
    })
}

#[cfg(test)]
#[path = "tests/local.rs"]
mod tests;
