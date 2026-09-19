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

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use axum::response::{IntoResponse as _, Response};

use crate::diagnostics::{A2A_NO_CSPRNG_CALLBACK, A2A_PUSHBACK_NOT_DELIVERED};
use busbar_substrate::{diag_debug, diag_error};

use super::task::TaskState;

/// The path busbar's own callback is served at, under [`super::serve::MOUNT_PATH`].
///
/// A FIXED path with the task named by the TOKEN rather than by a path segment. A task id in the
/// URL would be a second place the same fact is written — one authenticated, one not — and the
/// unauthenticated one is the one a log, a proxy and an error page keep.
///
/// The CODEC's, beside the other path suffixes: `busbar-plane-a2a` claims the endpoint this composes
/// and may not name this crate.
pub(crate) use busbar_a2a_codec::PUSH_PATH_SUFFIX;

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
                    diag_error!(A2A_NO_CSPRNG_CALLBACK, error = %e, "a2a: no CSPRNG, so busbar will register no callback of its own with any backend");
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

/// S17: THE PER-TASK RATE MAP. The MAC proves a presented token was minted by this process for one
/// task, and [`token_live`] proves that task has not ended — neither says anything about how OFTEN
/// the token may be presented. A backend holding a live token (its own, or one lifted from an
/// outbound hop's logs — see the module header on why the token rides in the clear on the wire it
/// travels) could otherwise drive this endpoint as fast as it can open sockets: every call reaches
/// `taskstore::transition` and, on a state change, spawns a delivery to the caller's own webhook, so
/// an unbounded rate here is an unbounded rate against a customer's receiver too.
///
/// Keyed by the task id the token already named — never by the token itself, which would let a
/// backend evade the count by presenting the one valid token it holds under a churn of nothing, and
/// never by the caller's IP, which a fronted backend does not have one honest value of. The map can
/// only ever hold entries for task ids a valid MAC has resolved, so its size tracks the number of
/// tasks that have PUSHED at least once — bounded in the ordinary case by eviction-on-terminal
/// ([`rate_forget`], called both here in [`push_notification`] once a push's own transition ends the
/// task and from the dead-token branch above), and bounded in the worst case by the
/// [`RATE_MAP_MAX_ENTRIES`] backstop for a task that reaches terminal some OTHER way and never
/// pushes again to trigger either of those.
struct RateWindow {
    window_start: u64,
    count: u32,
}

/// The window a task's push rate is measured over, and the count admitted within it. Generous
/// enough for the legitimate pattern this endpoint serves — a handful of transitions per task,
/// `working` → `input-required` → a terminal state — while still bounding a runaway or malicious
/// backend to a rate that cannot turn this endpoint into an amplifier against a caller's webhook.
const RATE_WINDOW_SECS: u64 = 60;
const RATE_MAX_PER_WINDOW: u32 = 120;

/// The backstop cap on the rate map's total size. Eviction-on-terminal is the primary cleanup — it
/// fires on the mainline path (a push's own transition lands the task in a terminal state) and on
/// the belt-and-braces path (a dead token presented again) — but neither fires for a task that
/// reaches terminal by some path other than a push landing here and is never presented again. Once
/// the map has grown past this many entries, [`rate_limited`] claims a sweep (at most once per
/// [`RATE_STALE_SECS`], the same "claim the work once" shape `taskstore::sweep_now` uses) that drops
/// every entry whose window has not been touched in that long. A live task's window keeps refreshing
/// itself on every push, so the sweep can never take an entry out from under a task that is still
/// being pushed to.
const RATE_MAP_MAX_ENTRIES: usize = 50_000;

/// How stale a window must be before the backstop sweep will drop it: ten full rate windows with no
/// push at all. Long enough that nothing still in legitimate use looks like this.
const RATE_STALE_SECS: u64 = RATE_WINDOW_SECS * 10;

fn rate_map() -> &'static Mutex<HashMap<String, RateWindow>> {
    static MAP: OnceLock<Mutex<HashMap<String, RateWindow>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `true` once per [`RATE_STALE_SECS`], so the backstop sweep in [`rate_limited`] costs an O(n) walk
/// of the map only occasionally rather than on every call once the map is over the cap.
fn rate_purge_due(now: u64) -> bool {
    static LAST_PURGE: OnceLock<std::sync::atomic::AtomicU64> = OnceLock::new();
    let last = LAST_PURGE.get_or_init(|| std::sync::atomic::AtomicU64::new(0));
    let prev = last.load(std::sync::atomic::Ordering::Relaxed);
    now.saturating_sub(prev) >= RATE_STALE_SECS
        && last
            .compare_exchange(
                prev,
                now,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_ok()
}

/// `true` when `task_id` has exceeded [`RATE_MAX_PER_WINDOW`] presentations within the current
/// [`RATE_WINDOW_SECS`]-second window and this call must be refused before it does any further work.
fn rate_limited(task_id: &str, now: u64) -> bool {
    let mut map = rate_map().lock().unwrap_or_else(|e| e.into_inner());
    let limited = {
        let entry = map.entry(task_id.to_string()).or_insert(RateWindow {
            window_start: now,
            count: 0,
        });
        if now.saturating_sub(entry.window_start) >= RATE_WINDOW_SECS {
            entry.window_start = now;
            entry.count = 0;
        }
        entry.count += 1;
        entry.count > RATE_MAX_PER_WINDOW
    };
    // ── THE BACKSTOP. Only ever looks at the map when it is both over the cap AND a sweep has not
    // run recently, so this is not a cost the mainline path pays.
    if map.len() > RATE_MAP_MAX_ENTRIES && rate_purge_due(now) {
        map.retain(|_, w| now.saturating_sub(w.window_start) < RATE_STALE_SECS);
    }
    limited
}

/// Drop `task_id`'s rate entry. Called once its token has stopped authorising anything
/// ([`token_live`] false), so the map does not hold an entry forever for a task that will never be
/// pushed to again.
fn rate_forget(task_id: &str) {
    rate_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(task_id);
}

/// TEST-ONLY: whether the rate map currently holds an entry for `task_id`. Reads the ONE
/// process-global map every push-callback test in the binary shares, so a test built on this checks
/// only its OWN task's presence/absence — never the map's total size, which a concurrently running
/// test could change between two reads.
#[cfg(all(test, feature = "test-support"))]
pub(crate) fn rate_map_contains(task_id: &str) -> bool {
    rate_map()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .contains_key(task_id)
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
    let url = url::Url::parse(public_url).ok()?;
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
    ctx: busbar_substrate::plane_routes::PlaneReqCtx,
) -> Response {
    // S7 neutral seam: this `RouteAuth::None` handler took only `CurrentApp`, the headers and the
    // body — the caller is a fronted AGENT holding no busbar key, so the middleware attached no
    // identity and this handler authenticates the per-task push token itself, below. The plane is read
    // off the neutral `ctx.host` seam (`runtime_arc_of`), so this handler holds no `App`;
    // `headers`/`body` off `ctx`.
    let headers = ctx.headers;
    let body = ctx.body;
    let Some(plane) = crate::a2a::runtime_arc_of(&ctx.host) else {
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
    // ── THE DEADLINE IS ENFORCED ON PRESENT, NOT ONLY ON SUBMIT. ────────────────────────────────
    //
    // `token_live` below retires a token when its task ends, and `taskstore`'s retention sweep is
    // what ends a task nobody has touched for `ACTIVE_TASK_ABANDON_SECS` — it moves it to
    // `canceled`, which is terminal. Those two facts were supposed to compose into a bound on the
    // token's lifetime, and they did not, because the sweep ran ONLY as a side effect of a new
    // submission. A deployment that stops submitting stops enforcing the bound: the silent task
    // never ages out, and the capability that names it stays live for as long as the process does.
    // The documented deadline was a deadline only on a busy node.
    //
    // So the sweep is run HERE, at the one moment that matters — a token being offered — and the
    // check that reads its result is the next thing that happens. `sweep_now` claims the work once
    // per second, so a backend pushing hard pays an atomic load and nothing else, and the clock is
    // the same wall clock the sweep's bounds are written in.
    //
    // AFTER the MAC, deliberately. The token has already been proven to have been minted by this
    // process, so this is not a scan an anonymous caller can drive.
    crate::taskstore::TASKS.sweep_now(busbar_substrate::store::now());

    if body.len() > MAX_PUSH_BODY {
        return refused(
            axum::http::StatusCode::PAYLOAD_TOO_LARGE,
            "a push notification is one task document",
        );
    }
    let Some(row) = crate::taskstore::TASKS.get_unscoped(&task_id) else {
        // The token verified and the row is gone — a task compacted out from under a backend that
        // is still reporting on it. `401` and not `404`, for the reason `task_of` gives one answer:
        // whether a task exists is not something this endpoint tells its caller.
        return refused(
            axum::http::StatusCode::UNAUTHORIZED,
            "this endpoint is addressed by the push token busbar registered with the agent",
        );
    };
    let Ok(task) = super::task::Task::from_row(&row) else {
        // A row busbar itself wrote must read back; one that does not parse is not a task this
        // endpoint can act on, and its existence is disclosed no more than an absent row's is.
        return refused(
            axum::http::StatusCode::UNAUTHORIZED,
            "this endpoint is addressed by the push token busbar registered with the agent",
        );
    };
    // ── THE CAPABILITY IS STILL LIVE, OR IT AUTHORISES NOTHING. ─────────────────────────────────
    //
    // The MAC says the token was minted by this process for this task. It does NOT say the token
    // still means anything, and until this check that was the entire authorisation of the endpoint:
    // a token captured anywhere it travels — it rides `Authorization: Bearer` on an outbound hop,
    // so a backend's own logs, a proxy and an error page all hold one — replayed for as long as the
    // process lived, on a task that ended days ago.
    //
    // The replay did not even have to lie. Re-reporting the state busbar ALREADY HOLDS is taken as
    // a retry rather than as a transition below, which is correct — `transition` refuses a move to
    // the state it is already in — but it meant the transition table's terminal-refuses-everything
    // rule was never the thing that ran. Each replay delivered to the caller's webhook again and
    // appended another entry to that task's durable provenance chain: a hash chain an external
    // party could grow without bound, on work that had finished.
    //
    // ASKED HERE, before the body is parsed and long before anything is recorded or delivered. A
    // dead capability must cost nothing further, exactly as every other refusal above it does.
    //
    // ONE `401`, and the same sentence as every other refusal on this endpoint, for the reason
    // `task_of` gives one answer for four different failures: whether a task exists, and whether it
    // has ended, are not facts this endpoint tells an unauthenticated caller.
    if !token_live(task.state) {
        // The task has ended, so its token authorises nothing further: it will never be presented
        // validly again, and its rate entry would otherwise linger in the map for as long as this
        // process runs.
        rate_forget(&task_id);
        return refused(
            axum::http::StatusCode::UNAUTHORIZED,
            "this endpoint is addressed by the push token busbar registered with the agent",
        );
    }

    // ── S17: THE RATE MAP. Asked once the token is proven live, so a dead or forged presentation is
    // never what drives an entry into the map — only a token that genuinely still authorises this
    // task can spend its budget. See `rate_limited`'s doc for what this bounds and why it is keyed
    // by task id.
    if rate_limited(&task_id, ctx.host.clock_now_secs()) {
        return refused(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "this task's push callback is being presented too often",
        );
    }

    let Ok(document) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return refused(
            axum::http::StatusCode::BAD_REQUEST,
            "a push notification is a JSON task document",
        );
    };

    // THE STATE THE BACKEND REPORTED, read by the SAME function that reads a relayed answer's
    // state. A push and a reply are two spellings of one fact and must not be read by two readers.
    let reported = super::relay::reported_task_state(&document);
    let now = ctx.host.clock_now_secs();
    let moved = if reported == task.state {
        // Not an error and not a transition: a backend re-reporting a state busbar already holds is
        // a retry, and `transition` would refuse a move to the state it is already in.
        task
    } else {
        let recorded = crate::taskstore::TASKS
            .transition(
                &task_id,
                &task_id,
                super::task::plan_transition(reported, now),
            )
            .map_err(|e| e.to_string())
            .and_then(|row| super::task::Task::from_row(&row).map_err(|e| e.to_string()));
        match recorded {
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

    // ── THE MAINLINE EXIT OUT OF THE RATE MAP. If THIS push is what just ended the task, its rate
    // entry is forgotten right here rather than waiting on a later presentation of a now-dead token
    // that, ordinarily, never comes — a backend has no reason to push again once it has reported an
    // ending. This is the common case `RATE_MAP_MAX_ENTRIES`'s backstop exists beside, not a
    // replacement for it: a task that reaches terminal by some path OTHER than a push landing here
    // still relies on the backstop.
    if moved.state.is_terminal() {
        rate_forget(&task_id);
    }

    // AND THE CALLER'S OWN DELIVERY, through the one delivery path. Detached from this response for
    // the reason `receive::notify_push` detaches its own: the party waiting on this response is the
    // BACKEND, and holding its socket open while the caller's webhook thinks would let one
    // customer's slow receiver slow another party's agent down.
    if moved.push_callback.is_some() {
        let seam = plane.relay_seam();
        let deliver_host = std::sync::Arc::clone(&ctx.host);
        tokio::task::spawn_blocking(move || {
            let id = moved.task_id.clone();
            // DETACHED: the delivery's chained outcome reaches the durable seam through the neutral
            // `EngineHost`, which mints the transient `HostCtx` internally on the blocking thread.
            let delivered =
                super::pushdeliver::deliver(deliver_host.as_ref(), seam.as_ref(), &moved);
            if let Err(e) = delivered {
                diag_debug!(A2A_PUSHBACK_NOT_DELIVERED, task = %id, error = %e, "a2a: a pushed state was not delivered onward");
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

/// **THE CAPABILITY'S LIFETIME, AS ONE PREDICATE.** A per-task push token authorises the endpoint
/// exactly while the task it names is NON-TERMINAL, and the ending of that task is what retires it.
///
/// ONE function, asked on BOTH sides, and that is the whole of the design rather than a convenience:
///
/// * **At mint time** — `super::originate::mirror_push_config` asks it before registering a
///   callback with a backend. A task busbar already holds as terminal has nothing left to report,
///   so arming a webhook for it would be arming it for an event that cannot happen.
/// * **At present time** — [`push_notification`] asks it of the task a presented token resolves to.
///   The same fact, read at the other end: a token minted for work that has since ended no longer
///   speaks for anything.
///
/// This is the successor plane's rule, reached through the fact both planes already share instead
/// of through a second mechanism. Over the composition root the same lifetime is a store record
/// under kind `push_config` that `plane_token_live` reads and the route plan's revoke leg deletes
/// `if key.terminal`; here the task ROW is that record, `state.is_terminal()` is that reading, and
/// the terminal transition — which goes through `super::task`'s transition table like every other
/// observation of this task — is that revocation. There is no second secret, no second deadline and
/// no second lifecycle to drift.
///
/// **The revocation is durable and it is monotone**, which is what makes it a revocation rather
/// than a cache. `TaskState`'s transition table is total and its terminal states accept nothing,
/// including themselves (`super::task`), so a task that has ended can never leave the state that
/// killed its token — not by a later push, not by a relayed read, not across a restart, because the
/// terminal row is what is persisted.
///
/// **And a live token is NOT SPENT by being used.** One task draws several callbacks — `working`,
/// `input-required`, then its ending — and all of them are the same capability being used for what
/// it is for. Single-use would break the interrupted task this whole endpoint exists to serve.
pub(crate) fn token_live(state: TaskState) -> bool {
    !state.is_terminal()
}
