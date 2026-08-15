// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! BUSBAR'S OWN CALLBACK — the address busbar gives a BACKEND, so the backend never learns the
//! caller's.
//!
//! ## The hole this closes, stated as a customer sees it
//!
//! A2A tasks are asynchronous by design. A backend that accepts a submission, interrupts, and
//! finishes an hour later reports that ending to whoever it was told to report it to. busbar told
//! it nobody: [`super::local`] answers the push-config CRUD verbs itself and
//! [`super::pushdeliver`] delivers only on a transition BUSBAR OBSERVED, and busbar observes one
//! only while it is holding a relayed request or a relayed stream open. So the exact case push
//! notifications exist for — *do not make me poll* — was the case that delivered nothing. A caller
//! registered a callback, got a `200`, hung up, and heard silence for work that completed.
//!
//! ## Why the fix is not "relay the caller's config"
//!
//! Relaying the caller's own `pushNotificationConfig` to the backend hands the backend the caller's
//! webhook URL and its webhook credential, and then the backend calls that URL directly. Every
//! property busbar exists to hold is gone in one line: the delivery does not pass
//! [`super::pushnotify`]'s SSRF guard, it does not appear on busbar's provenance chain, the caller's
//! receiver is exposed to a party it never chose, and the credential the caller gave BUSBAR to
//! present is now held by a third party. That is the defect `super::local`'s push-config section was
//! written to close, and it is not reopened here.
//!
//! ## What busbar does instead: SUBSTITUTION
//!
//! busbar registers **its own** callback with the backend, and holds the caller's.
//!
//! * The backend is told one URL — [`callback_url`], `<public_url>/a2a/push` — and one credential,
//!   a [`Token`] busbar minted for THIS TASK and nothing else.
//! * The caller's URL and the caller's credential stay where they were, in busbar's own record, and
//!   never appear on an outbound hop. `a2a/tests/pushback_tests.rs` scans every byte of
//!   the substituted registration for both.
//! * A push that arrives here is authenticated by the token, resolved to the one task the token
//!   names, recorded as a transition on that task's own hash chain, and then delivered to the
//!   caller by [`super::pushdeliver`] — which re-resolves and re-guards the caller's URL exactly as
//!   it does for every other delivery.
//!
//! So the backend learns a busbar address and an opaque bearer, and can reach exactly one busbar
//! task with them. It cannot reach the caller at all.
//!
//! ## THE TOKEN, and what it is and is not
//!
//! `<task-id>.<hex mac>`, where the MAC is HMAC-SHA256 over the task id under a process secret. It
//! is a CAPABILITY for one task: presenting it moves that task and nothing else, and a backend that
//! holds one for task A learns nothing about task B and cannot address it. Forging one without the
//! secret is forging a MAC.
//!
//! **The secret is PROCESS-LOCAL, and that is the honest floor rather than an oversight** — the
//! same floor `super::pushdeliver::pins` and `super::local`'s config map are documented with. A
//! busbar that restarts holds durable task rows and a fresh secret, so a token minted before the
//! restart no longer verifies and the push carrying it is REFUSED rather than acted on. The caller
//! is not silently misled: the task's state is still whatever the backend reports on the next
//! relayed read, and the next push-config verb re-registers a token that does verify. A durable
//! secret would make a stolen token durable too, which is the trade this takes deliberately.
//!
//! ## WHY THE ROUTE IS `RouteAuth::None`, and what actually authorises it
//!
//! The party calling it is a BACKEND AGENT. It holds no busbar key and must not be issued one —
//! minting a busbar credential for every fronted backend so it could call one webhook would be a
//! far larger grant than the one thing this endpoint does. So the route declares no middleware auth
//! and the handler authenticates the request ITSELF, against the token, in constant time, through
//! `busbar_api::constant_time_eq` — the one constant-time primitive in the tree. A request with no
//! token, an unparseable token, a token whose MAC does not verify, or a token naming a task busbar
//! does not hold is a `401` that says nothing about which of those it was.

use std::sync::OnceLock;

use axum::response::{IntoResponse as _, Response};

use super::task::TaskState;

/// The path busbar's own callback is served at, under [`super::serve::MOUNT_PATH`].
///
/// A FIXED path with the task named by the TOKEN rather than by a path segment. A task id in the
/// URL would be a second place the same fact is written — one authenticated, one not — and the
/// unauthenticated one is the one a log, a proxy and an error page keep.
pub(crate) const PUSH_PATH_SUFFIX: &str = "/push";

/// The scheme busbar names in the config it registers with the backend. RFC 9110's own, because
/// the value is `<scheme> <credentials>` and that is what the field is for.
pub(crate) const TOKEN_SCHEME: &str = "Bearer";

/// The ceiling on a pushed body. A push notification is one `Task` document; this is the same order
/// as the notification busbar itself sends (`super::pushdeliver::notification_body`) with room for a
/// backend that is more generous with its members, and it exists because this endpoint is
/// unauthenticated until the token is read and a body is read before that.
const MAX_PUSH_BODY: usize = 64 * 1024;

/// THE PROCESS SECRET the task tokens are MAC'd under. See the module header for why it is
/// process-local and what a restart therefore costs.
///
/// 32 bytes from the OS CSPRNG. A `getrandom` failure is not papered over with a zero key: it
/// leaves the secret unset, [`mint`] answers `None`, and busbar then registers NO callback with the
/// backend rather than one guarded by a key an attacker can guess.
fn secret() -> Option<&'static [u8; 32]> {
    static SECRET: OnceLock<Option<[u8; 32]>> = OnceLock::new();
    SECRET
        .get_or_init(|| {
            let mut buf = [0u8; 32];
            match getrandom::fill(&mut buf) {
                Ok(()) => Some(buf),
                Err(e) => {
                    tracing::error!(error = %e, "a2a: no CSPRNG, so busbar will register no callback of its own with any backend");
                    None
                }
            }
        })
        .as_ref()
}

/// The MAC over one task id.
fn mac_of(secret: &[u8; 32], task_id: &str) -> String {
    use hmac::digest::KeyInit as _;
    use hmac::Mac as _;
    let mut mac = <hmac::Hmac<sha2::Sha256>>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts a 32-byte key");
    mac.update(task_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// A MINTED CAPABILITY for one task. Opaque to the backend, and a `String` here only because it is
/// about to become a header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Token(String);

impl Token {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Mint the token for `task_id`, or `None` when this process has no secret to mint under.
pub(crate) fn mint(task_id: &str) -> Option<Token> {
    let secret = secret()?;
    Some(Token(format!("{task_id}.{}", mac_of(secret, task_id))))
}

/// THE TASK A PRESENTED TOKEN NAMES, or `None` for every way it can fail to name one.
///
/// ONE `None` for all of them, deliberately: "no such task", "the MAC does not verify" and "that is
/// not a token" are three facts a caller of this endpoint has no business being able to tell apart,
/// because telling them apart is how a task id is confirmed by probing.
fn task_of(presented: &str) -> Option<String> {
    let secret = secret()?;
    let (task_id, presented_mac) = presented.rsplit_once('.')?;
    if task_id.is_empty() {
        return None;
    }
    // THE ONE CONSTANT-TIME PRIMITIVE. A byte-at-a-time comparison here is a MAC oracle: the
    // attacker controls the value and can measure the answer.
    if !busbar_api::constant_time_eq(&mac_of(secret, task_id), presented_mac) {
        return None;
    }
    Some(task_id.to_string())
}

/// BUSBAR'S OWN CALLBACK ADDRESS for this deployment, or `None` when busbar must not offer one.
///
/// `None` in exactly two cases, and both are refusals rather than fallbacks:
///
/// * **No `public_url`.** A deployment configured for delegation only has no receiving side, so
///   there is no address a backend could reach it at. `super::receive::no_receiving_side` says the
///   same thing to a caller one route up.
/// * **A `public_url` that is not `https`.** busbar refuses PLAINTEXT callbacks from its own
///   callers (`super::pushnotify`), and handing a backend a plaintext address for busbar would be
///   busbar doing the thing it refuses on a caller's behalf — a task token in cleartext on the
///   wire, which is the credential this whole endpoint rests on. There is no knob here and there is
///   not going to be one.
pub(crate) fn callback_url(public_url: &str) -> Option<String> {
    let url = reqwest::Url::parse(public_url).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    Some(format!(
        "{}{}{PUSH_PATH_SUFFIX}",
        public_url.trim_end_matches('/'),
        super::serve::MOUNT_PATH
    ))
}

/// THE CONFIG BUSBAR REGISTERS WITH A BACKEND, in A2A v1.0's flattened shape.
///
/// The `id` is busbar's own and is the handle every later verb in the mirrored set addresses: a
/// `get`, a `list` and a `delete` all name the config BUSBAR registered, never the caller's, whose
/// id never leaves busbar.
pub(crate) fn config_id(task_id: &str) -> String {
    format!("busbar-{task_id}")
}

/// The params for a `CreateTaskPushNotificationConfig` naming busbar's own callback.
pub(crate) fn create_params(task_id: &str, url: &str, token: &Token) -> serde_json::Value {
    serde_json::json!({
        "taskId": task_id,
        "id": config_id(task_id),
        "url": url,
        "authentication": { "scheme": TOKEN_SCHEME, "credentials": token.as_str() },
    })
}

/// The params that ADDRESS the one registration busbar made — a `get` and a `delete`.
pub(crate) fn config_params(task_id: &str) -> serde_json::Value {
    serde_json::json!({ "taskId": task_id, "id": config_id(task_id) })
}

/// The params for a `list`, which names the TASK and no config.
///
/// A separate shape rather than [`config_params`] with a spare member, because A2A's HTTP+JSON
/// binding puts `list` on a `GET` with no body: a leftover `id` has nowhere to go and
/// `relay::HttpJsonFraming` refuses the request by name rather than dropping it. One params builder
/// per request shape is what makes that refusal unreachable instead of a runtime surprise on one of
/// three legs.
pub(crate) fn list_params(task_id: &str) -> serde_json::Value {
    serde_json::json!({ "taskId": task_id })
}

/// THE VERB BUSBAR ISSUES WHEN A CALLER USES THIS ONE, or `None` for a local verb that mirrors onto
/// nothing.
///
/// A TABLE rather than four call sites, so the rule — *what the caller did to busbar's record,
/// busbar does to busbar's record at the backend* — is one thing that can be read, and so a fifth
/// push verb is a deliberate line here rather than a branch somebody forgets in one arm.
///
/// The v1.0 spelling on every arm whatever spelling the caller used, because
/// `super::relay::canonical_method` maps both dialects onto it and the two non-JSON-RPC bindings
/// have no v0.3 form at all. `ListTasks` and `SubscribeToTask` mirror onto NOTHING and that is not
/// an omission: neither names a registration busbar holds at a backend.
pub(crate) fn mirrored_verb(verb: super::local::LocalVerb) -> Option<&'static str> {
    use super::local::LocalVerb as V;
    use super::rest::method as m;
    Some(match verb {
        V::CreatePushConfig(_) => m::CREATE_PUSH_CONFIG,
        V::GetPushConfig(_) => m::GET_PUSH_CONFIG,
        V::ListPushConfigs(_) => m::LIST_PUSH_CONFIGS,
        V::DeletePushConfig(_) => m::DELETE_PUSH_CONFIG,
        V::ListTasks | V::Subscribe => return None,
    })
}

// ══ THE ENDPOINT ═════════════════════════════════════════════════════════════════════════════════

/// `POST /a2a/push` — A BACKEND REPORTING A TASK IT MOVED.
///
/// The sequence, and every step is a refusal that costs nothing further:
///
/// 1. the presented token names a task, or `401`;
/// 2. the body is a `Task` document within the ceiling, or `400`;
/// 3. the state it reports is recorded through `taskstore::transition`, which is the SAME
///    transition table and the SAME per-task hash chain every other observation of this task goes
///    through — a push is not a second way for a task to move;
/// 4. and the caller's own delivery is made by [`super::pushdeliver`], with its guard, its
///    re-resolution and its pin.
///
/// **NOTHING FROM THE BODY REACHES THE CALLER'S WEBHOOK.** The delivery is composed from busbar's
/// own task row (`pushdeliver::notification_body`), so a backend cannot use this endpoint to post
/// arbitrary bytes at a URL it has never been told.
pub(crate) async fn push_notification(
    crate::state::CurrentApp(app): crate::state::CurrentApp,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(plane) = app.a2a.as_ref().map(std::sync::Arc::clone) else {
        return refused(
            axum::http::StatusCode::NOT_FOUND,
            "no A2A plane is configured",
        );
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case(TOKEN_SCHEME))
        .map(|(_, token)| token.trim())
        .unwrap_or_default();
    let Some(task_id) = task_of(presented) else {
        return refused(
            axum::http::StatusCode::UNAUTHORIZED,
            "this endpoint is addressed by the push token busbar registered with the agent",
        );
    };
    if body.len() > MAX_PUSH_BODY {
        return refused(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "a push notification is one task document",
        );
    }
    let Some(task) = super::taskstore::TASKS.get_unscoped(&task_id) else {
        // The token verified and the row is gone — a task compacted out from under a backend that
        // is still reporting on it. `401` and not `404`, for the reason `task_of` gives one answer:
        // whether a task exists is not something this endpoint tells its caller.
        return refused(
            axum::http::StatusCode::UNAUTHORIZED,
            "this endpoint is addressed by the push token busbar registered with the agent",
        );
    };
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return refused(
            axum::http::StatusCode::BAD_REQUEST,
            "a push notification is a JSON task document",
        );
    };

    // THE STATE THE BACKEND REPORTED, read by the SAME function that reads a relayed answer's
    // state. A push and a reply are two spellings of one fact and must not be read by two readers.
    let reported = super::relay::reported_task_state(&document);
    let now = crate::store::now();
    let moved = if reported == task.state {
        // Not an error and not a transition: a backend re-reporting a state busbar already holds is
        // a retry, and `transition` would refuse a move to the state it is already in.
        task
    } else {
        match super::taskstore::TASKS.transition(&task_id, reported, now, &task_id) {
            Ok(t) => t,
            Err(e) => {
                // REPORTED, NEVER 5xx. The commonest arrival here is a push about a task busbar
                // already recorded as terminal, which is the backend being redundant rather than
                // busbar failing. A `2xx` stops a retry loop for an event there is nothing to do
                // with.
                tracing::info!(task = %task_id, error = %e, "a2a: a pushed state was not recordable");
                return accepted();
            }
        }
    };

    // AND THE CALLER'S OWN DELIVERY, through the one delivery path. Detached from this response for
    // the reason `receive::notify_push` detaches its own: the party waiting on this response is the
    // BACKEND, and holding its socket open while the caller's webhook thinks would let one
    // customer's slow receiver slow another party's agent down.
    if moved.push_callback.is_some() {
        let seam = plane.relay_seam();
        tokio::task::spawn_blocking(move || {
            let id = moved.task_id.clone();
            if let Err(e) = super::pushdeliver::deliver(seam.as_ref(), &moved) {
                tracing::warn!(task = %id, error = %e, "a2a: a pushed state was not delivered onward");
            }
        });
    }
    accepted()
}

/// `202`, with no document. There is nothing a backend may learn from this endpoint beyond that its
/// report was taken, and every arm that gets this far has taken it.
fn accepted() -> Response {
    (axum::http::StatusCode::ACCEPTED, "").into_response()
}

/// A refusal, in the one shape this endpoint speaks. NOT a JSON-RPC error body: the caller here is
/// an HTTP webhook client, not a JSON-RPC peer, and A2A binds no envelope to this direction.
fn refused(status: axum::http::StatusCode, message: &str) -> Response {
    (
        status,
        axum::Json(serde_json::json!({ "error": { "message": message } })),
    )
        .into_response()
}

/// The state token a mirrored registration is worth making at all.
///
/// A task busbar already holds as TERMINAL has nothing left to report, so registering a callback
/// for it would be arming a webhook for an event that cannot happen. Stated as a function rather
/// than inline at the call site because the mirroring decision is made in two places
/// (`super::receive`'s inline-config arm and its CRUD arm) and one of them drifting is how a
/// customer gets a substitution on one spelling and not the other.
pub(crate) fn worth_registering(state: TaskState) -> bool {
    !state.is_terminal()
}
