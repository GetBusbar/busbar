// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VERBS BUSBAR ANSWERS ITSELF, and the argument for each one being busbar's to answer.
//!
//! Every other method on this plane is RELAYED. busbar reads the envelope only far enough to
//! authorise, meter and record it, and the backend agent decides what the answer is
//! (content-blind dispatch: busbar carries a caller's payload without reading it). This module is
//! the deliberate exception,
//! and it is deliberately small: three groups of verbs whose ANSWER IS A FACT ABOUT BUSBAR, not a
//! fact about the backend.
//!
//! Relaying those three is not neutrality. It is busbar asking a backend a question the backend
//! cannot answer, because the subject of the question is a record busbar keeps and an id busbar
//! issued.
//!
//! ## 1. `ListTasks` — busbar's OWN store, and there is no other candidate answer
//!
//! busbar issues its own task ids and puts them in every reply (`super::relay::rewrite_identity`);
//! the backend's names for the same work are held in `super::idmap` and are never client-visible.
//! So a `ListTasks` relayed to a backend enumerates ids the caller has never seen and cannot use,
//! for a tenancy the backend does not know about. The task rows busbar persists — the ones
//! busbar's own task rows are scoped to "the presenting key's own tasks" —
//! are the only set that answers the question the caller actually asked.
//!
//! **What this answer IS, stated so nobody reads more into it.** It is the set of tasks busbar
//! opened for this caller, each carrying THE LAST STATE THE BACKEND REPORTED to busbar. It is not
//! a live poll of the backend. A backend that moves a task on out of band, with no reply and no
//! stream event, moves it somewhere busbar did not see, and this list will say so honestly by
//! saying what busbar last saw.
//!
//! **NO `status.timestamp` IS EMITTED, and that is the honest choice rather than an omission.**
//! A2A's `status.timestamp` is when the AGENT recorded that status. What busbar holds is
//! `updated_at`: when BUSBAR observed it. They are different facts and they differ by a hop. The
//! member is optional in the schema, so publishing busbar's observation time under the agent's
//! field name would be busbar asserting something it does not know in order to fill a slot.
//! Ordering still uses `updated_at`, because it is the only time busbar has, and that is said out
//! loud here rather than implied by a field.
//!
//! **NO `artifacts` AND NO `history` ARE EMITTED, ever, and not only when `includeArtifacts` is
//! false.** busbar is content-blind on this plane and retains neither. A caller asking for
//! artifacts gets a task with no artifacts member, which is what busbar has.
//!
//! ## 2. Push-notification config CRUD — it is BUSBAR'S callback, so it is busbar's config
//!
//! This is the group where relaying was actively wrong rather than merely useless. busbar already
//! owns the whole push mechanism for a config supplied INLINE on a submission: it runs the SSRF
//! guard (`super::pushnotify`), pins the addresses, persists the URL on its own task row, and
//! performs the delivery itself (`super::pushdeliver`). A config registered through the CRUD verbs
//! is the same fact reached by a different method name — so relaying those verbs meant a callback
//! registered one way was guarded, pinned and delivered by busbar, and a callback registered the
//! other way was held by a backend that would call the caller directly, around busbar's guard and
//! outside busbar's provenance. Two answers to one question, chosen by spelling.
//!
//! Two limits are REFUSED OUT LOUD rather than accepted and quietly not honoured:
//!
//! * **One config per task.** busbar's durable task row carries ONE `push_callback` and delivery is
//!   one POST. Accepting a second config would be promising a delivery busbar does not make.
//! * **The same SSRF guard as the inline path**, at registration, refusing as the CALLER's fault.
//!   The delivery-time re-validation in `super::pushdeliver` still runs on top of it.
//!
//! And one that USED to be refused and is now honoured, because the refusal was a real capability
//! gap wearing an honesty argument. `authentication` was rejected on the grounds that the delivery
//! sent no credential, which was true of the delivery and false as a position: a receiver that
//! cannot authenticate its caller has to treat the webhook URL itself as the secret. The member is
//! now stored (`super::pushdeliver::remember_auth`) and presented on delivery. It is deliberately
//! NOT echoed back on `get`/`list` — see [`config_json`] — because a read verb that returns a
//! secret turns any read grant into a way to exfiltrate it.
//!
//! ## 3. `SubscribeToTask` on a task busbar does not hold, or holds as terminal
//!
//! Not the whole verb — a subscribe to a LIVE task busbar holds is relayed exactly as before,
//! because the events are the backend's. Only the two refusals are busbar's, and both are refusals
//! busbar is the only party able to make:
//!
//! * **A task id busbar did not issue to this caller** is `TaskNotFound`. Relayed, the id went to a
//!   backend that has never heard of it, and an accommodating backend opened a stream for it — a
//!   caller was handed a live subscription to work that does not exist. The scoping is
//!   `taskstore::get_scoped`, so another tenant's id is not found either, which is section 7.7's
//!   rule stated as code.
//! * **A task busbar holds in a terminal state** is `UnsupportedOperation`. The task is over;
//!   busbar recorded the ending itself.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::response::Response;

use super::rpcerror::A2aError;
use super::task::{Task, TaskState};

/// WHICH SPELLING OF THE PUSH-CONFIG VERBS A CALLER USED, because the two dialects disagree about
/// the SHAPE of a config and not merely about the method name.
///
/// A2A v0.3 nests the configuration under `pushNotificationConfig`; v1.0 flattens its members into
/// the request and the response. Answering a v0.3 caller in the v1.0 shape would be a well-formed
/// document its client cannot read, so the dialect travels with the verb and decides the envelope.
/// Both are handled for the reason `super::receive::shape_of` handles both streaming spellings:
/// this plane speaks two protocol versions, and reading one vocabulary means the other version's
/// callers silently get a different behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dialect {
    /// A2A v0.3: `tasks/pushNotificationConfig/*`, config nested under `pushNotificationConfig`.
    V03,
    /// A2A v1.0: `*TaskPushNotificationConfig`, config members flattened into the message.
    V10,
}

/// A verb this plane answers WITHOUT a backend hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalVerb {
    ListTasks,
    CreatePushConfig(Dialect),
    GetPushConfig(Dialect),
    ListPushConfigs(Dialect),
    DeletePushConfig(Dialect),
    /// Only the two refusals are local; see [`subscribe_refusal`].
    Subscribe,
}

/// The method names, listed rather than pattern-matched, so a third spelling is a deliberate edit
/// and not something a loose prefix match swallows.
pub(crate) fn verb_of(method: &str) -> Option<LocalVerb> {
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

/// The method an envelope names, or `""`.
pub(crate) fn method_of(envelope: &serde_json::Value) -> &str {
    envelope
        .get("method")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

// ══ THE TASK PROJECTION ══════════════════════════════════════════════════════════════════════════

/// The protocol's spelling of a task state.
///
/// The `TASK_STATE_*` tokens are the ones the A2A v1.0 schema enumerates and the ones the pinned
/// control agent puts on the wire, so a task busbar renders itself and a task busbar relayed read
/// the same to a client. busbar's own store token (`super::task::TaskState::as_str`) is NOT this:
/// it is the durable spelling and it is deliberately not a wire format.
fn wire_state(state: TaskState) -> &'static str {
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

/// ONE OF BUSBAR'S TASK ROWS AS AN A2A `Task`. Three members, and every absent member is absent
/// because busbar does not hold the fact — see the module header for `status.timestamp`,
/// `artifacts` and `history`.
fn task_json(task: &Task) -> serde_json::Value {
    serde_json::json!({
        "id": task.task_id,
        "contextId": task.context_id,
        "status": { "state": wire_state(task.state) },
    })
}

// ══ ListTasks ════════════════════════════════════════════════════════════════════════════════════

/// The default and maximum page sizes. A caller that asks for none gets [`DEFAULT_PAGE_SIZE`]; a
/// caller that asks for more than [`MAX_PAGE_SIZE`] gets [`MAX_PAGE_SIZE`], because the page size is
/// the one number in this request that decides how much work busbar does.
const DEFAULT_PAGE_SIZE: usize = 50;
const MAX_PAGE_SIZE: usize = 200;

/// Read an integer that may arrive as a number or, per the schema's `anyOf`, as a decimal string.
fn as_int(v: Option<&serde_json::Value>) -> Option<i64> {
    match v? {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Read a member under either the camelCase or the snake_case spelling the schema's
/// `patternProperties` admit for the same field.
fn member<'a>(
    params: &'a serde_json::Value,
    camel: &str,
    snake: &str,
) -> Option<&'a serde_json::Value> {
    params.get(camel).or_else(|| params.get(snake))
}

/// THE PAGE CURSOR: the sort key of the last row already returned, `"<updated_at>:<task_id>"`.
///
/// A genuine cursor rather than an offset, and the difference matters on this plane: rows are
/// created and updated while a caller pages, so an offset silently skips or repeats a task every
/// time the set shifts under it. A cursor names a POSITION IN THE ORDER, so a page is "everything
/// strictly after this row", which is stable under insertion.
fn cursor_of(task: &Task) -> String {
    format!("{}:{}", task.updated_at, task.task_id)
}

/// Is `task` strictly after `cursor` in the descending sort order?
fn after_cursor(task: &Task, cursor: &str) -> bool {
    let Some((ts, id)) = cursor.rsplit_once(':') else {
        // An unreadable cursor selects the whole list rather than nothing: a caller cannot forge a
        // cursor into somebody else's rows (the set is already scoped), and answering an empty page
        // would make a client's paging loop terminate silently on a typo.
        return true;
    };
    let Ok(ts) = ts.parse::<u64>() else {
        return true;
    };
    // The same comparison `sort_key` orders by, negated: strictly later than the cursor row.
    (task.updated_at, task.task_id.as_str()) < (ts, id)
}

/// Answer `ListTasks` from busbar's own store, scoped to this principal.
pub(crate) fn list_tasks(
    envelope: &serde_json::Value,
    rpc_id: &serde_json::Value,
    principal: &str,
) -> Response {
    let params = envelope
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let context_id = member(&params, "contextId", "context_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let wanted_state = member(&params, "status", "status")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let page_size = as_int(member(&params, "pageSize", "page_size"))
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .min(MAX_PAGE_SIZE);
    let page_token = member(&params, "pageToken", "page_token")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();

    // SCOPED FIRST, filtered second. `list_scoped` is the authorization boundary of
    // THE SCOPING RULE: a caller can only ever be shown its own rows, and every filter
    // below narrows that set rather than widening it.
    let mut rows: Vec<Task> = super::taskstore::TASKS
        .list_scoped(principal)
        .into_iter()
        .filter(|t| context_id.is_empty() || t.context_id == context_id)
        .filter(|t| match wanted_state.as_deref() {
            None => true,
            // Both spellings of a state, for the same reason both spellings of a method are read.
            Some(want) => wire_state(t.state) == want || t.state.as_str() == want,
        })
        .collect();

    // DESCENDING BY THE ONLY TIME BUSBAR HOLDS, with the task id breaking ties so the order is
    // total. A partial order here would make the cursor ambiguous and a page boundary lossy.
    rows.sort_by(|a, b| {
        (b.updated_at, b.task_id.as_str()).cmp(&(a.updated_at, a.task_id.as_str()))
    });

    let start: Vec<&Task> = if page_token.is_empty() {
        rows.iter().collect()
    } else {
        rows.iter()
            .filter(|t| after_cursor(t, &page_token))
            .collect()
    };
    let page: Vec<&Task> = start.iter().take(page_size).copied().collect();
    // EMPTY WHEN THERE IS NO NEXT PAGE, and PRESENT EITHER WAY. The member is what a client's paging
    // loop terminates on, so omitting it on the last page is how a loop becomes infinite.
    let next = if start.len() > page.len() {
        page.last().map(|t| cursor_of(t)).unwrap_or_default()
    } else {
        String::new()
    };

    ok(
        rpc_id,
        serde_json::json!({
            "tasks": page.iter().map(|t| task_json(t)).collect::<Vec<_>>(),
            "nextPageToken": next,
        }),
    )
}

// ══ PUSH-NOTIFICATION CONFIG CRUD ════════════════════════════════════════════════════════════════

/// ONE registered push-notification config.
///
/// The CREDENTIAL IS NOT A MEMBER OF THIS STRUCT, and that is not an oversight. It is held by
/// [`super::pushdeliver`], which is the only code that needs it, in a map that
/// [`super::pushdeliver::forget`] clears — so nothing on the read path is even holding the secret
/// to echo by accident. What lives here is exactly what a read verb may answer with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PushConfig {
    /// The caller's id for it. Echoed back verbatim and used as the key of every later read.
    pub(crate) id: String,
    /// The callback URL, exactly as registered and exactly as it passed the guard.
    pub(crate) url: String,
}

/// THE REGISTERED CONFIGS, keyed by busbar's task id.
///
/// PROCESS-LOCAL, and stated rather than discovered: the config's URL is mirrored onto the durable
/// task row (`taskstore::set_push_callback`), so a delivery still happens after a restart on a
/// durable store, but the config's ID — the handle the CRUD verbs are addressed by — does not
/// survive. That is the same honesty `super::pushdeliver::pins` is documented with and the same
/// shape as the callback's own durability rule: survival is a property of the configured
/// backend, and the RAM default has none.
fn configs() -> &'static Mutex<HashMap<String, PushConfig>> {
    static CONFIGS: OnceLock<Mutex<HashMap<String, PushConfig>>> = OnceLock::new();
    CONFIGS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Drop config entries whose task the store no longer holds.
///
/// This map is keyed by task id and written at a caller-chosen rate, so it needs a bound. The bound
/// is the TASK STORE's: a config cannot outlive the task it configures, and the task store already
/// has a retention policy (`taskstore::compact`). Pruning on write rather than on a timer keeps the
/// map's lifetime a consequence of the store's rather than a second policy that can disagree.
fn prune() {
    if let Ok(mut map) = configs().lock() {
        map.retain(|task_id, _| super::taskstore::TASKS.get_unscoped(task_id).is_some());
    }
}

/// The config as this dialect spells it on the wire.
///
/// NO `authentication` MEMBER IN EITHER DIALECT, and that is the security decision rather than an
/// unfinished projection. A `get` or a `list` needs only a task id and a config id, so echoing the
/// credential back would turn every read grant into a way to exfiltrate the secret the caller
/// registered — and a caller that already holds its own secret learns nothing from being handed it
/// again. `PushConfig` does not carry it either, so there is nothing here to echo by accident.
fn config_json(dialect: Dialect, task_id: &str, cfg: &PushConfig) -> serde_json::Value {
    match dialect {
        Dialect::V10 => serde_json::json!({
            "taskId": task_id,
            "id": cfg.id,
            "url": cfg.url,
        }),
        Dialect::V03 => serde_json::json!({
            "taskId": task_id,
            "pushNotificationConfig": { "id": cfg.id, "url": cfg.url },
        }),
    }
}

/// The config MEMBERS out of a request, in whichever dialect they arrived.
///
/// v1.0 flattens them into `params`; v0.3 nests them under `pushNotificationConfig`. Both are read
/// from the params object rather than from a dialect-specific struct so that a caller mixing the two
/// — which real clients do while a version moves — is understood rather than silently given an empty
/// config.
fn config_params(params: &serde_json::Value) -> &serde_json::Value {
    params.get("pushNotificationConfig").unwrap_or(params)
}

/// THE CREDENTIAL A CONFIG ASKS BUSBAR TO PRESENT AT ITS WEBHOOK, out of whichever spelling it
/// arrived in.
///
/// `Ok(None)` is "this config names no credential", which is the ordinary case. `Err` is a config
/// that names one busbar cannot present, and it is an error rather than a silent drop for the
/// reason the whole member exists: a caller told its receiver would be authenticated, whose
/// deliveries then arrive bare, has a receiver that rejects every one of them and no way to see
/// why.
///
/// ONE READER FOR BOTH SPELLINGS. A2A's `AuthenticationInfo` is `{scheme, credentials}`; the 0.3-era
/// documents and several SDKs still emit `{schemes: [...], credentials}` with the scheme list
/// pluralised. Reading only one means a caller using the other is silently unauthenticated, which is
/// exactly the class of bug `super::receive::callback_of` was written to close one member up.
pub(crate) fn delivery_auth(
    cfg: &serde_json::Value,
) -> Result<Option<super::pushdeliver::DeliveryAuth>, String> {
    let Some(auth) = cfg.get("authentication").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let scheme = auth
        .get("scheme")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| {
            auth.get("schemes")
                .and_then(serde_json::Value::as_array)
                .and_then(|a| a.first())
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_default();
    let scheme = scheme.trim().to_string();
    if scheme.is_empty() {
        return Err(
            "a push notification config's `authentication` must name a `scheme` (an HTTP \
             authentication scheme such as `Bearer`), because the scheme is what busbar puts in \
             front of the credential on the `Authorization` header it sends to your receiver"
                .to_string(),
        );
    }
    // A SCHEME NAME IS A `token` PER RFC 9110, and busbar is about to write it into a header. A
    // value carrying whitespace, a control character or a non-ASCII byte would either split the
    // field or be refused by the HTTP client with a message about busbar rather than about the
    // caller's config, so it is refused here where the refusal can name the member.
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
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_string();
    if credentials
        .bytes()
        .any(|b| !b.is_ascii_graphic() && b != b' ')
    {
        // The VALUE is refused without being quoted back. A refusal that echoes the secret puts it
        // in the caller's logs, the proxy's logs and busbar's own error path.
        return Err(
            "the push notification config's authentication `credentials` contain a byte that \
             cannot appear in an HTTP header field value"
                .to_string(),
        );
    }
    Ok(Some(super::pushdeliver::DeliveryAuth {
        scheme,
        credentials,
    }))
}

/// THE TASK A PUSH-CONFIG REQUEST NAMES, resolved through the SAME scoped lookup every other read on
/// this plane uses, so an id belonging to another principal is `TaskNotFound` and not a config.
fn addressed(params: &serde_json::Value, principal: &str) -> Option<Task> {
    for name in ["taskId", "task_id", "id"] {
        if let Some(id) = params.get(name).and_then(serde_json::Value::as_str) {
            if let Ok(task) = super::taskstore::TASKS.get_scoped(principal, id) {
                return Some(task);
            }
        }
    }
    None
}

/// `CreateTaskPushNotificationConfig` / `tasks/pushNotificationConfig/set`.
///
/// Async, because the SSRF guard resolves a name and that resolution must be the same one every
/// other outbound decision on this plane reads.
pub(crate) async fn create_push_config(
    dialect: Dialect,
    envelope: &serde_json::Value,
    rpc_id: &serde_json::Value,
    principal: &str,
    seam: std::sync::Arc<dyn super::relay::RelaySeam>,
    now: u64,
) -> Response {
    let params = envelope
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let Some(task) = addressed(&params, principal) else {
        return err(rpc_id, A2aError::TaskNotFound, NO_SUCH_TASK);
    };
    let cfg = config_params(&params);

    // THE MEMBER BUSBAR STILL WILL NOT HONOUR, refused rather than stored. `token` is A2A v0.3's
    // opaque per-config value, which the specification defines the RECEIVER as validating against
    // its own record; busbar has no place to put it on the wire that a receiver is defined to read.
    // Accepting it would promise a check that never happens. `authentication` is a different thing
    // and IS honoured — see the module header.
    if cfg.get("token").is_some() {
        return err(
            rpc_id,
            A2aError::UnsupportedOperation,
            "busbar does not carry a push notification config `token`: there is no header or body \
             member the delivery puts it in, so storing it would promise the receiver a value it \
             never sees. Use `authentication`, which busbar presents on the `Authorization` header, \
             or register the secret in the callback URL your receiver checks.",
        );
    }

    // THE CALLER'S OWN WEBHOOK CREDENTIAL. Read before the URL is judged so a config that names a
    // credential in a shape busbar cannot present is refused as the caller's fault rather than
    // accepted and silently not sent — which is the failure this whole member is replacing.
    let auth = match delivery_auth(cfg) {
        Ok(a) => a,
        Err(message) => return err(rpc_id, A2aError::InvalidParams, message),
    };

    let Some(url) = cfg.get("url").and_then(serde_json::Value::as_str) else {
        return err(
            rpc_id,
            A2aError::InvalidParams,
            "a push notification config must name the `url` busbar is to call",
        );
    };
    let id = cfg
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();

    // ONE CONFIG PER TASK, refused out loud. busbar's durable row holds one callback and the
    // delivery is one POST; a second config would be a registration busbar answers `OK` to and then
    // never calls.
    prune();
    if let Ok(map) = configs().lock() {
        if let Some(existing) = map.get(&task.task_id) {
            if existing.id != id {
                return err(
                    rpc_id,
                    A2aError::UnsupportedOperation,
                    "this task already has a push notification config and busbar holds exactly one \
                     per task: its durable task row carries one callback and its delivery is one \
                     request. Delete the existing config before registering another.",
                );
            }
        }
    }

    // THE SAME GUARD, AT THE SAME MOMENT, AS THE INLINE PATH. A callback registered by this verb and
    // a callback registered on a submission must be judged by one rule; two rules is how one of them
    // ends up being the way around the other.
    let pinned = match super::receive::validate_callback(url.to_string(), seam).await {
        Ok(p) => p,
        Err(message) => return err(rpc_id, A2aError::InvalidParams, message),
    };

    if let Err(e) =
        super::taskstore::TASKS.set_push_callback(&task.task_id, Some(pinned.url.clone()), now)
    {
        tracing::error!(task = %task.task_id, error = %e, "a2a: a push config could not be recorded");
        return err(
            rpc_id,
            A2aError::Internal,
            "the push notification config could not be recorded",
        );
    }
    // The addresses the guard just judged, so the FIRST delivery is a `revalidate` and not a bare
    // `validate` — the same pairing the inline path makes.
    super::pushdeliver::remember(&task.task_id, &pinned);
    // AND THE CREDENTIAL, which `remember_auth` CLEARS when this config names none — a caller
    // replacing an authenticated config with an unauthenticated one has withdrawn the secret.
    super::pushdeliver::remember_auth(&task.task_id, auth.as_ref());

    let stored = PushConfig {
        id,
        url: pinned.url,
    };
    if let Ok(mut map) = configs().lock() {
        map.insert(task.task_id.clone(), stored.clone());
    }
    ok(rpc_id, config_json(dialect, &task.task_id, &stored))
}

/// `GetTaskPushNotificationConfig` / `tasks/pushNotificationConfig/get`.
pub(crate) fn get_push_config(
    dialect: Dialect,
    envelope: &serde_json::Value,
    rpc_id: &serde_json::Value,
    principal: &str,
) -> Response {
    let params = envelope
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let Some(task) = addressed(&params, principal) else {
        return err(rpc_id, A2aError::TaskNotFound, NO_SUCH_TASK);
    };
    // THE CONFIG ID IS `id`, AND THE TASK ID IS `taskId`. On this verb the two are distinct
    // members, so `id` is read as the config's — which is why `addressed` prefers `taskId` and only
    // falls back to `id`.
    let wanted = config_params(&params)
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let found = configs()
        .lock()
        .ok()
        .and_then(|m| m.get(&task.task_id).cloned())
        .filter(|c| c.id == wanted);
    match found {
        Some(cfg) => ok(rpc_id, config_json(dialect, &task.task_id, &cfg)),
        None => err(
            rpc_id,
            A2aError::TaskNotFound,
            "no push notification config with that id is registered for this task",
        ),
    }
}

/// `ListTaskPushNotificationConfigs` / `tasks/pushNotificationConfig/list`.
pub(crate) fn list_push_configs(
    dialect: Dialect,
    envelope: &serde_json::Value,
    rpc_id: &serde_json::Value,
    principal: &str,
) -> Response {
    let params = envelope
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let Some(task) = addressed(&params, principal) else {
        return err(rpc_id, A2aError::TaskNotFound, NO_SUCH_TASK);
    };
    let held: Vec<serde_json::Value> = configs()
        .lock()
        .ok()
        .and_then(|m| m.get(&task.task_id).cloned())
        .map(|c| vec![config_json(dialect, &task.task_id, &c)])
        .unwrap_or_default();
    match dialect {
        // v1.0 wraps the list; v0.3's method answers a bare array.
        Dialect::V10 => ok(
            rpc_id,
            serde_json::json!({ "configs": held, "nextPageToken": "" }),
        ),
        Dialect::V03 => ok(rpc_id, serde_json::Value::Array(held)),
    }
}

/// `DeleteTaskPushNotificationConfig` / `tasks/pushNotificationConfig/delete`.
///
/// IDEMPOTENT: deleting a config that is not there is not an error. A delete whose only job is to
/// make a statement false answers the same way whether or not it had to do anything, and a client
/// retrying a delete after a timeout must not be told its retry failed.
pub(crate) fn delete_push_config(
    envelope: &serde_json::Value,
    rpc_id: &serde_json::Value,
    principal: &str,
    now: u64,
) -> Response {
    let params = envelope
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let Some(task) = addressed(&params, principal) else {
        return err(rpc_id, A2aError::TaskNotFound, NO_SUCH_TASK);
    };
    let wanted = config_params(&params)
        .get("id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let removed = match configs().lock() {
        Ok(mut map) => {
            let hit = map.get(&task.task_id).is_some_and(|c| c.id == wanted);
            if hit {
                map.remove(&task.task_id);
            }
            hit
        }
        Err(_) => false,
    };
    if removed {
        // THE DURABLE ROW GOES WITH IT. Leaving the callback on the row would mean a config the
        // caller deleted still receiving the task's completion, which is the one outcome a delete
        // exists to prevent.
        let _ = super::taskstore::TASKS.set_push_callback(&task.task_id, None, now);
        super::pushdeliver::forget(&task.task_id);
    }
    ok(rpc_id, serde_json::Value::Null)
}

// ══ SubscribeToTask ══════════════════════════════════════════════════════════════════════════════

/// The refusal a subscribe earns from busbar's own record, or `None` when the answer is the
/// backend's to give and the call must be relayed unchanged.
///
/// Returning `None` for the live case is the whole shape of this function: busbar is deciding only
/// what it alone knows — that it issued no such task to this caller, or that it recorded the ending
/// of this one — and is deciding nothing about a task that is still running.
pub(crate) fn subscribe_refusal(
    envelope: &serde_json::Value,
    rpc_id: &serde_json::Value,
    principal: &str,
) -> Option<Response> {
    let params = envelope.get("params")?;
    // The id member A2A names on this verb, in both spellings the schema admits.
    let named = ["id", "taskId", "task_id"]
        .iter()
        .find_map(|m| params.get(*m).and_then(serde_json::Value::as_str))?;
    match super::taskstore::TASKS.get_scoped(principal, named) {
        // NOT BUSBAR'S, OR NOT THIS CALLER'S — one answer for both, because "there is no such task"
        // and "there is such a task and it is not yours" must not be distinguishable.
        Err(_) => Some(err(
            rpc_id,
            A2aError::TaskNotFound,
            "no task with that id is open for this caller",
        )),
        Ok(task) if task.state.is_terminal() => Some(err(
            rpc_id,
            A2aError::UnsupportedOperation,
            "this task has reached a terminal state, so there are no further events to subscribe \
             to",
        )),
        Ok(_) => None,
    }
}

// ══ THE TWO ANSWER SHAPES ════════════════════════════════════════════════════════════════════════

/// The refusal every verb here gives for a task id it does not hold for this caller. One string so
/// the four push verbs cannot drift into four subtly different existence oracles.
const NO_SUCH_TASK: &str = "no task with that id is open for this caller";

/// A JSON-RPC success, under the id the caller sent.
fn ok(rpc_id: &serde_json::Value, result: serde_json::Value) -> Response {
    use axum::response::IntoResponse as _;
    (
        axum::http::StatusCode::OK,
        axum::Json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": result,
        })),
    )
        .into_response()
}

/// A JSON-RPC error in this plane's own wire shape, through the one renderer that binds A2A's status
/// and its `ErrorInfo` body to each code.
fn err(rpc_id: &serde_json::Value, code: A2aError, message: impl Into<String>) -> Response {
    super::rpcerror::respond(rpc_id, code, message)
}

#[cfg(test)]
#[path = "tests/local_tests.rs"]
mod local_tests;
