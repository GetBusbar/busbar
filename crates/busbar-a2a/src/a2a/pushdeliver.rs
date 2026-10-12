// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PUSH-NOTIFICATION DELIVERY: the code that actually connects to a caller's webhook.
//!
//! ## What was missing, stated plainly, because the absence looked like a feature
//!
//! Before this module the A2A plane accepted a `pushNotificationConfig.url`, ran a real SSRF guard
//! over it, pinned the addresses, persisted it on the task row, and returned it on reads. Every one
//! of those steps had tests and all of them passed. **Nothing ever delivered.** A caller that
//! registered a callback and hung up got silence, and no test could tell, because there was no
//! socket in the story to be missing.
//!
//! The guard's own strongest function, [`super::pushnotify::revalidate`], had NO CALLER AT ALL for
//! the same reason: it is the delivery path's half of the check, and there was no delivery path.
//!
//! ## THE GUARD RUNS AT DELIVERY, NOT ONLY AT REGISTRATION, AND THAT IS THE WHOLE POINT
//!
//! Registration-time validation is necessary and it is not sufficient, because the two events are
//! separated by an unbounded amount of time. A2A tasks are asynchronous by design: a task can be
//! interrupted waiting on a human and complete a day later, and the row survives a restart. So the
//! DNS answer that was judged when the callback was written may be nothing like the answer the
//! socket would get now — the attacker's nameserver simply waits.
//!
//! Therefore, before EVERY delivery:
//!
//! 1. the host is re-resolved, through the plane's own resolver seam;
//! 2. the full guard runs again over the fresh answer;
//! 3. the socket goes to an address that just passed, pinned, with the client's own resolver
//!    refusing to look the name up a second time.
//!
//! Where a pin from a previous delivery (or from the registration in this same process) is known,
//! step 2 is [`super::pushnotify::revalidate`] rather than `validate`: the fresh answer must pass
//! the guard AND still overlap the pinned set, so a wholesale move to a different — still public —
//! address set is held for an operator instead of followed. Across a restart the in-process pin is
//! gone and the check degrades to `validate`, which is the honest floor: the row is durable and the
//! pin is not, so claiming otherwise would be claiming a guarantee the deployment does not have.
//!
//! ## The caller's own credential IS presented, and busbar's never is
//!
//! A2A lets the registering caller name an `authentication` for its receiver, so the receiver can
//! tell a real delivery from anything else that finds the URL. busbar dropped that member at
//! registration and refused configs that carried one, which left every customer whose webhook
//! authenticates unable to use push notifications at all. It is now stored and presented — see
//! [`DeliveryAuth`] for whose secret it is and why sending it is not the confused-deputy shape the
//! relay path guards against, and [`auths`] for why it lives in memory rather than on the durable
//! row.
//!
//! ## Delivery is best-effort, and a failure never touches the task
//!
//! The task's outcome is already recorded and the caller's poll will find it. A webhook that is
//! down, slow, refused by the guard, or answering 500 is the CALLER's infrastructure failing, and
//! turning that into a failed task would let a caller destroy its own work by pointing at a broken
//! URL. Every refusal is logged with the reason and the task id and goes no further.
//!
//! ## BEST-EFFORT IS NOT UNRECORDED, AND IT USED TO BE
//!
//! "Goes no further" was literally true: all three callers disposed of the outcome with a
//! `tracing::warn!` and nothing reached any chain, so **a delivery refused by the delivery-time SSRF
//! guard left no record**. A security control that fires silently is one nobody can audit after the
//! fact — and this control fires precisely when a callback that was legitimate at registration has
//! been re-pointed at something that is not, which is the event an incident review goes looking for.
//! Every attempt now appends to the TASK's own provenance chain (the neutral audit vocabulary's three
//! `task.push_*` kinds), through the one mechanism in [`busbar_kernel::audit`]. A log line is still emitted;
//! it is no longer the only thing that happens.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

/// The engine seam every delivery reaches the task chain through, named once for this module and
/// its tests.
pub(super) use busbar_kernel::plane_host::EngineHost;

use super::pushnotify::{self, PinnedCallback, PushNotifyError};
use super::relay::RelaySeam;
use super::task::Task;
use crate::diagnostics::{
    A2A_PUSH_NOTIFY_UNDELIVERED, A2A_PUSH_OUTCOME_UNCHAINED, A2A_PUSH_QUEUE_DROPPED,
};
use busbar_contract::diag_debug;
use busbar_contract::vocab as provenance;

/// THE HEADER EVERY DELIVERY CARRIES, whatever else it carries.
///
/// The request's TIME ceiling is the transport's (`transport::RELAY_TIMEOUT`), for the same reason
/// the relay's is: an unbounded one is a way for a caller to pin a busbar thread by pointing at a
/// host that accepts and never answers.
const DELIVERY_HEADERS: &[(&str, &str)] = &[("content-type", "application/json")];

/// The header a webhook credential is presented on. RFC 9110's own, because the value this carries
/// is `<scheme> <credentials>` and that is exactly what the field is for.
const AUTHORIZATION_HEADER: &str = "authorization";

/// THE CREDENTIAL THE CALLER ASKED BUSBAR TO PRESENT AT ITS WEBHOOK.
///
/// ## Whose credential this is, because that is the whole reason it may be sent
///
/// It is not busbar's. It is a secret the CALLER supplied, for the CALLER's own receiver, so that
/// the receiver can tell a real delivery from anything else that finds the URL. Presenting it is
/// therefore not the confused-deputy shape `super::creds::authorise_egress` exists to prevent on
/// the relay path — that is busbar's OWN credential being spent on a host a caller nominated, and
/// none of busbar's credentials come anywhere near this path. This one goes back to the party that
/// issued it, at the address that party named, and nowhere else.
///
/// Registration used to REFUSE the member out loud on the argument that busbar sends no credential,
/// which was an honest statement of what the delivery did and an unbuildable position for a
/// customer: a webhook receiver that cannot authenticate its caller has to treat the URL itself as
/// the secret, and A2A gives it a field precisely so that it does not have to.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DeliveryAuth {
    /// The HTTP authentication scheme, from the IANA registry: `Bearer`, `Basic`, … Case is the
    /// caller's; RFC 9110 section 11.1 makes scheme names case-insensitive, so it is echoed rather
    /// than normalised.
    pub(crate) scheme: String,
    /// The credential itself. **Never logged, never echoed on a read verb, never persisted.** See
    /// [`auths`] for where it lives and why that is not a durable store.
    pub(crate) credentials: busbar_contract::Redacted<String>,
}

impl DeliveryAuth {
    /// The `Authorization` field value: `<scheme> <credentials>`, or the bare scheme where the
    /// caller supplied none (the proto marks `credentials` optional, and a scheme with an empty
    /// value trailing a space is a header a strict receiver rejects).
    fn header_value(&self) -> String {
        if self.credentials.expose_secret().is_empty() {
            self.scheme.clone()
        } else {
            format!("{} {}", self.scheme, self.credentials.expose_secret())
        }
    }
}

/// `Debug` IS WRITTEN RATHER THAN DERIVED, and that is the point of writing it. A derived one puts
/// the credential into the first `tracing` field, `assert_eq!` message or panic payload that ever
/// touches this struct, and none of those are places a caller's secret may appear. There is no
/// accessor that returns the credential either — [`DeliveryAuth::header_value`] is the only way out
/// of this type, and its one caller is the line that writes the request header.
impl std::fmt::Debug for DeliveryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DeliveryAuth {{ scheme: {:?}, credentials: <redacted> }}",
            self.scheme
        )
    }
}

/// Why a delivery did not happen. Each arm names the thing that failed, because "push failed" alone
/// tells an operator nothing about whether to fix DNS, fix the receiver, or look at an attack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PushRefusal {
    /// The task has no callback registered. Not an error anywhere — most tasks do not.
    NoCallback,
    /// The DELIVERY-TIME guard refused. This is the arm that matters: it fires on a callback that
    /// was legitimate when it was registered and is not legitimate now.
    Guard(PushNotifyError),
    /// The name answered nothing on this attempt.
    Unresolved(String),
    /// The URL will not parse as an HTTP URL for the transport.
    NotAUrl(String),
    /// The socket failed, or the receiver's connection did.
    Transport(String),
    /// The receiver answered, and said no.
    Status(u16),
}

impl std::fmt::Display for PushRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PushRefusal::NoCallback => write!(f, "no push callback is registered for this task"),
            PushRefusal::Guard(e) => write!(f, "the delivery-time SSRF guard refused: {e}"),
            PushRefusal::Unresolved(h) => write!(
                f,
                "the push callback host `{h}` resolved to nothing at delivery time"
            ),
            PushRefusal::NotAUrl(u) => write!(f, "the push callback `{u}` is not an HTTP URL"),
            PushRefusal::Transport(e) => write!(f, "the push callback could not be reached: {e}"),
            PushRefusal::Status(s) => {
                write!(f, "the push callback answered {s}")
            }
        }
    }
}

/// THE PINS FROM EARLIER DELIVERIES, keyed by task id.
///
/// Process-local and deliberately NOT durable. It exists only to give
/// [`super::pushnotify::revalidate`] the previous answer to compare against, which is a STRENGTHENING
/// of the check; its absence degrades to `validate`, never to no check. Bounded by the same thing
/// that bounds the in-flight task set: [`forget`] is called when a task reaches a terminal state,
/// which is the last delivery that task will ever have.
fn pins() -> &'static Mutex<HashMap<String, PinnedCallback>> {
    static PINS: OnceLock<Mutex<HashMap<String, PinnedCallback>>> = OnceLock::new();
    PINS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// THE CALLERS' WEBHOOK CREDENTIALS, keyed by task id.
///
/// PROCESS-LOCAL, AND THAT IS A DECISION RATHER THAN A LIMITATION. The alternative — a column on
/// the durable task row — would write a caller's plaintext secret into whichever store an operator
/// configured, where it would be readable by everything with database access, replicated to every
/// standby and captured by every backup, for a value whose only use is one outbound header. The
/// store seam (`crate::TaskRow`) has no notion of a secret and no encryption, so there is no
/// spelling of "persist it" that is not "persist it in the clear".
///
/// The consequence is stated rather than discovered: **a credential does not survive a restart.**
/// The callback URL does (it is on the durable row), so after a restart busbar still delivers, and
/// delivers WITHOUT the header. That is the same honesty [`pins`] and `super::local`'s config map
/// are documented with, and it is the safe direction to degrade in — a receiver that requires the
/// header rejects the delivery, which is a visible failure, where the other direction would be a
/// secret sitting in a backup nobody remembers writing.
fn auths() -> &'static Mutex<HashMap<String, DeliveryAuth>> {
    static AUTHS: OnceLock<Mutex<HashMap<String, DeliveryAuth>>> = OnceLock::new();
    AUTHS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Remember the addresses a callback was pinned to, so the NEXT delivery can require an overlap.
pub(crate) fn remember(task_id: &str, pinned: &PinnedCallback) {
    // Poison-recovering (the house idiom — see e.g. plane_host/creds.rs `registry()`): the maps
    // behind these locks stay consistent after a panic, and a silent `if let Ok` no-op here would
    // let a single poisoned lock quietly stop `forget` clearing secrets for the rest of the
    // process lifetime.
    pins()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(task_id.to_string(), pinned.clone());
}

/// Hold the credential this task's receiver wants presented, or drop the one held when the caller
/// registered a config that names none.
///
/// `None` CLEARS rather than leaves the previous value in place. A caller replacing a config that
/// had authentication with one that does not has withdrawn the credential, and continuing to send
/// it would be busbar spending a secret its owner has retired.
pub(crate) fn remember_auth(task_id: &str, auth: Option<&DeliveryAuth>) {
    let mut map = auths().lock().unwrap_or_else(|e| e.into_inner());
    match auth {
        Some(a) => map.insert(task_id.to_string(), a.clone()),
        None => map.remove(task_id),
    };
}

/// Drop a task's pin AND its credential. Called on the terminal delivery, because a terminal task
/// gets no more — and a secret with no remaining use is a secret that should not still be in memory.
pub(crate) fn forget(task_id: &str) {
    // Poison-recovering for the reason that matters MOST here: this is the path that drops a
    // caller's credential from memory, and the old `if let Ok` no-op meant one panic under either
    // lock silently stopped every future clear — secrets retained for the process lifetime.
    pins()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(task_id);
    auths()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(task_id);
}

/// The pin currently held for a task, for the test that asserts the map is BOUNDED. Reading it is
/// the only way to prove `forget` ran, and an unbounded map keyed by a caller-controlled rate is a
/// leak worth a test.
#[cfg(all(test, feature = "test-support"))]
pub(crate) fn pin_for_test(task_id: &str) -> Option<PinnedCallback> {
    pins()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(task_id)
        .cloned()
}

/// The credential currently held for a task, for the test that asserts [`forget`] clears it. A
/// secret that outlives the task it was supplied for is the bound worth a test, for the same reason
/// [`pin_for_test`] exists.
#[cfg(all(test, feature = "test-support"))]
pub(crate) fn auth_for_test(task_id: &str) -> Option<DeliveryAuth> {
    auths()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(task_id)
        .cloned()
}

/// THE A2A PUSH NOTIFICATION BODY: the Task, as the protocol defines it, under BUSBAR's identity.
///
/// The receiver is the caller's own infrastructure and the ids it knows are the ones busbar issued,
/// so the backend agent's names for this work must not appear here — the same reason
/// [`super::relay::rewrite_identity`] exists on the reply path.
///
/// # THIS IS NOT A JSON-RPC ENVELOPE, AND THAT IS CORRECT. DO NOT "FIX" IT INTO ONE.
///
/// Stated here because the absence looks exactly like the defect this plane's other three response
/// sites really did have. Every other place busbar puts JSON on this plane's wire is a JSON-RPC
/// message and is read or written through [`busbar_kernel::ingress::jsonrpc`]; a reviewer who has just been
/// through those will read the missing `jsonrpc`, `method` and `id` members here as a fourth
/// instance and add them. It would be a protocol violation.
///
/// A push notification is not a request (busbar is not invoking a method on the receiver), it is
/// not a response (the receiver asked busbar nothing), and there is no request for an `id` to
/// correlate to — the receiver is not a JSON-RPC peer at all. A2A puts the correlation duty on the
/// RECEIVER and keys it on the TASK id in this document, not on an envelope id: SPEC 4.3.3,
/// *"Clients MUST validate the task ID matches an expected task"*. That clause only makes sense
/// because the task id is the only correlator there is, and it is the `"id"` field below.
///
/// # IT IS A `StreamResponse`, AND IT WAS A BARE `Task`, WHICH IS THE ONE MEMBER THAT WAS WRONG
///
/// The envelope A2A defines for a delivered event is `StreamResponse`, a `oneof` over `{task,
/// message, statusUpdate, artifactUpdate}` — so the payload is the task NESTED UNDER `"task"`,
/// never the task itself. It was the task itself, and the difference is not stylistic: the official
/// suite runs the delivered body through the specification's own schema, where `StreamResponse` is
/// `additionalProperties: false` over those four names. Its verdict on the un-nested document,
/// verbatim:
///
/// ```text
/// $: 'contextId', 'id', 'kind', 'status' do not match any of the regexes:
///    '^(artifact_update)$', '^(status_update)$'
/// ```
///
/// and on the same document nested under `"task"`, `valid: True`. So a receiver written against the
/// specification's own generated types could not deserialise a busbar delivery at all.
///
/// The other correctness duty is unchanged and still discharged: the ids in this document are
/// BUSBAR'S, never the backend agent's, because busbar's are the only ones the receiver has ever
/// been told about and the only ones that will resolve if it calls back.
pub(crate) fn notification_body(task: &Task) -> Vec<u8> {
    let doc = serde_json::json!({
        "task": {
            "id": task.task_id,
            "contextId": task.context_id,
            "kind": "task",
            "status": {
                "state": task.state.as_str(),
                // AN RFC3339 STRING, never the raw `u64`. `TaskStatus.timestamp` is typed a
                // `Timestamp` in every revision (RFC3339 in the JSON binding, `google.protobuf.Timestamp`
                // whose ProtoJSON IS an RFC3339 string in the proto binding), so a receiver's generated
                // types deserialise the field as a date-time and a JSON NUMBER is a type error at the
                // boundary — the delivery parsed as far as this member and then failed. `task.updated_at`
                // is whole seconds since the epoch; it is rendered rather than emitted raw.
                "timestamp": busbar_contract::civil::rfc3339_from_secs(task.updated_at),
            },
        }
    });
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// DELIVER ONE NOTIFICATION for `task`, re-running the full guard against a FRESH resolution first,
/// AND RECORD THE OUTCOME on the task's own provenance chain.
///
/// Synchronous, because both seams it uses are: the resolver performs a real name lookup and the
/// transport blocks a thread per hop. Callers run it on a blocking thread — see
/// [`super::receive`] — for the same reason the relay does.
///
/// ## Why the chaining is HERE and not at the three call sites
///
/// `deliver` has three production callers — the unary hop's detached `notify_push`, the streaming
/// sink's inline delivery, and the backend-push endpoint's onward delivery — and each of them
/// disposed of the outcome with a `tracing::warn!`. A record written at the call sites would be
/// three records to keep in step, and the fourth caller added later would silently be the one that
/// wrote none. ONE APPEND, at the one place that knows what happened, is the same discipline the
/// chain mechanism itself is under.
///
/// The record is written BEFORE the outcome is returned, so no caller can decide not to be audited.
pub(crate) fn deliver(
    engine_host: &dyn EngineHost,
    seam: &dyn RelaySeam,
    task: &Task,
) -> Result<(), PushRefusal> {
    let outcome = attempt(seam, task);
    record_attempt(engine_host, task, &outcome);
    outcome
}

/// APPEND THE DELIVERY'S OUTCOME to the task's chain, in the ONE mechanism (`busbar_kernel::audit`, through
/// the task registry that owns this task's chain position).
///
/// [`PushRefusal::NoCallback`] writes NOTHING, and that is not an exception to the rule: no delivery
/// was attempted, no guard ran, and a record saying a task with no callback did not receive one
/// would be a row per state change of every task in the deployment that never asked for push at all.
///
/// A failure to record is logged and goes no further. Delivery is best-effort by design ("a failure
/// never touches the task"), and turning a bookkeeping problem into a failed task would be exactly
/// the harm that posture exists to prevent — but it is logged at WARN rather than swallowed, because
/// a missing audit record is itself the thing this file was changed to stop.
fn record_attempt(engine_host: &dyn EngineHost, task: &Task, outcome: &Result<(), PushRefusal>) {
    let kind = match outcome {
        Ok(()) => provenance::EV_PUSH_DELIVERED,
        // NOTHING WENT OUT — busbar's own guard, the resolver, or the stored URL stopped it.
        Err(PushRefusal::Guard(_) | PushRefusal::Unresolved(_) | PushRefusal::NotAUrl(_)) => {
            provenance::EV_PUSH_REFUSED
        }
        // IT WENT OUT AND THE RECEIVER FAILED IT.
        Err(PushRefusal::Transport(_) | PushRefusal::Status(_)) => provenance::EV_PUSH_FAILED,
        Err(PushRefusal::NoCallback) => return,
    };
    if let Err(e) = crate::taskstore::TASKS.record_push_delivery(
        &task.task_id,
        kind,
        engine_host.clock_now_secs(),
        // No inbound request originates a delivery; `request_id` is a join key and is excluded from
        // the digest for exactly this reason.
        "",
    ) {
        diag_debug!(
            A2A_PUSH_OUTCOME_UNCHAINED,
            task = %task.task_id,
            kind = kind,
            error = %e,
            "a2a: the push-notification delivery outcome could not be chained"
        );
    }
}

/// The delivery itself. Split out so that every `?` and every early return in it is still audited by
/// [`deliver`] — an outcome that can be returned without passing the recorder is an outcome that
/// will eventually be returned without passing the recorder.
fn attempt(seam: &dyn RelaySeam, task: &Task) -> Result<(), PushRefusal> {
    let Some(url) = task.push_callback.as_deref() else {
        return Err(PushRefusal::NoCallback);
    };

    // ── 1. RE-RESOLVE. The stored answer is not reused; that is the entire reason this is here. ──
    let host = pushnotify::host_of(url).map_err(PushRefusal::Guard)?;
    // A literal needs no resolver and must not be made to depend on one; `validate` judges it on
    // its own and ignores what is passed. Mirrors `ingress::validate_callback` deliberately, so a
    // literal callback gets the same verdict at both ends.
    let fresh = if host.parse::<std::net::IpAddr>().is_ok() {
        Vec::new()
    } else {
        match seam.resolver().resolve(&host) {
            Ok(addrs) if !addrs.is_empty() => addrs,
            // A resolver ERROR and an EMPTY answer are the same thing to this guard: nothing was
            // checked, and "checked nothing" must never read as "found nothing wrong".
            _ => return Err(PushRefusal::Unresolved(host)),
        }
    };

    // ── 2. RE-VALIDATE, against that fresh answer and not against the stored one. ──
    let previous = pins()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&task.task_id)
        .cloned();
    let pinned = match previous {
        // The stronger check: pass the guard AND still overlap what was pinned before.
        Some(prev) if prev.url == url => {
            pushnotify::revalidate(&prev, &fresh).map_err(PushRefusal::Guard)?
        }
        // No pin for this task in this process — a restart, or the first delivery. The full guard
        // still runs; only the overlap requirement is unavailable.
        _ => pushnotify::validate(url, &fresh).map_err(PushRefusal::Guard)?,
    };

    // ── 3. CONNECT, to an address that just passed, and to nothing else. ──
    let parsed = url::Url::parse(&pinned.url).map_err(|_| PushRefusal::NotAUrl(url.into()))?;
    let Some(addr) = pinned.addrs.first().copied() else {
        return Err(PushRefusal::Unresolved(pinned.host));
    };
    let mut headers: Vec<(String, String)> = DELIVERY_HEADERS
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    // THE CALLER'S OWN CREDENTIAL, ATTACHED ONLY AFTER THE GUARD HAS PASSED. Reading it here rather
    // than before step 1 is deliberate: the credential must be presented to the address the caller
    // registered and to nothing else, so nothing may put it in a header list that a refused
    // destination could ever see.
    if let Some(auth) = auths()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&task.task_id)
        .cloned()
    {
        headers.push((AUTHORIZATION_HEADER.to_string(), auth.header_value()));
    }
    let body = notification_body(task);
    let resp = seam
        .transport()
        .send(
            "POST",
            &parsed,
            // A push callback is public https and nothing else (`pushnotify::validate`), so the host
            // judges the pin with no private and no plaintext reach.
            super::fetch::Pin {
                addr,
                allow_private: false,
                allow_plaintext: false,
            },
            &headers,
            &body,
        )
        .map_err(|f| PushRefusal::Transport(f.err))?;

    // Remember what this delivery pinned, so the next one can require an overlap with it.
    remember(&task.task_id, &pinned);
    if task.state.is_terminal() {
        forget(&task.task_id);
    }

    if (200..300).contains(&resp.status) {
        Ok(())
    } else {
        Err(PushRefusal::Status(resp.status))
    }
}

// ══ BOUNDED RETRY ═══════════════════════════════════════════════════════════════════════════════

/// AT MOST THIS MANY ATTEMPTS, total, for one delivery. ARCHITECT ruling 2026-09-29: 3 attempts,
/// 250ms then 500ms between them, ±20% jitter.
const MAX_DELIVERY_ATTEMPTS: u32 = 3;

/// The delay BEFORE the 2nd and 3rd attempts (index 0 and 1), before jitter is applied.
///
/// FIXED rather than driven by the receiver's own `Retry-After`: the egress response
/// (this plane's `HttpResponse`) carries `status, location, body, peer_spki,
/// client_identity_offered` and NO header map at all, so a `Retry-After` value cannot be read off a
/// real delivery response today. That type is the LEGACY egress path step 36 deletes, and growing it
/// for one caller was ruled out (ARCHITECT, 2026-09-29) rather than done here. **Retry-After will be
/// honoured once push rides the http transport piece — status and retry-after are transport
/// vocabulary there.** Until then a 429 is retried on this same fixed schedule, exactly like a 5xx.
const RETRY_DELAYS_MS: [u64; (MAX_DELIVERY_ATTEMPTS - 1) as usize] = [250, 500];

/// The jitter fraction applied to each delay: the actual wait is `base * (1.0 ± JITTER)`.
const RETRY_JITTER_FRACTION: f64 = 0.20;

/// Whether a refusal is worth a second try.
///
/// ONLY a transport-level failure or a 5xx/429 status. [`PushRefusal::Guard`],
/// [`PushRefusal::Unresolved`], [`PushRefusal::NotAUrl`] and any OTHER 4xx are correctness
/// refusals — retrying a rejected scheme or a refused SSRF judgement three times would not change
/// the answer, it would just spend three sockets (or three guard runs) getting the same "no".
fn is_retryable(refusal: &PushRefusal) -> bool {
    match refusal {
        PushRefusal::Transport(_) => true,
        PushRefusal::Status(429) => true,
        PushRefusal::Status(status) => (500..600).contains(status),
        PushRefusal::NoCallback
        | PushRefusal::Guard(_)
        | PushRefusal::Unresolved(_)
        | PushRefusal::NotAUrl(_) => false,
    }
}

/// `base_ms`, jittered by up to ±[`RETRY_JITTER_FRACTION`]. Falls back to the UN-jittered delay on a
/// `getrandom` failure — a delay is a timing nicety, not a security property, so degrading to
/// exactly `base_ms` rather than refusing to wait at all is the honest floor here.
fn jittered_delay(base_ms: u64) -> std::time::Duration {
    let mut byte = [0u8; 1];
    let signed_unit = if getrandom::fill(&mut byte).is_ok() {
        // byte[0] in 0..=255 -> a value in [-1.0, 1.0].
        (f64::from(byte[0]) / 255.0).mul_add(2.0, -1.0)
    } else {
        0.0
    };
    let scaled = (base_ms as f64) * signed_unit.mul_add(RETRY_JITTER_FRACTION, 1.0);
    std::time::Duration::from_millis(scaled.max(0.0) as u64)
}

/// DELIVER, WITH BOUNDED RETRY, off an async context — the timer between attempts is
/// [`tokio::time::sleep`], never a thread `sleep`, precisely so a retrying delivery holds no thread
/// and no admission/capacity slot while it waits. Each attempt runs [`deliver`] on its own
/// `spawn_blocking` thread (the guard's resolve and the transport's send both block), so the async
/// waiter here is never itself blocked by one.
///
/// EVERY ATTEMPT RE-RUNS THE FULL GUARD, because [`deliver`] does — a retry is a fresh call to
/// [`attempt`], not a re-send of a judgement made once. A name can change between attempt 1 and
/// attempt 2 exactly as it can between registration and the first delivery, and the property this
/// module exists for ("the guard runs at delivery, not only at registration") would be undone by a
/// retry path that skipped it on attempts 2 and 3.
///
/// The ONLY callers of this are the per-task queue workers in [`enqueue`]'s drain loop — a caller
/// that awaited this directly on a request-handling or stream-pumping task would reintroduce the
/// exact stall the queue exists to prevent.
async fn deliver_with_retry(
    engine_host: Arc<dyn EngineHost>,
    seam: Arc<dyn RelaySeam>,
    task: Task,
) -> Result<(), PushRefusal> {
    let mut attempt_no: u32 = 0;
    loop {
        attempt_no += 1;
        let host_for_hop = Arc::clone(&engine_host);
        let seam_for_hop = Arc::clone(&seam);
        let task_for_hop = task.clone();
        let outcome = tokio::task::spawn_blocking(move || {
            deliver(host_for_hop.as_ref(), seam_for_hop.as_ref(), &task_for_hop)
        })
        .await
        .unwrap_or_else(|_| {
            Err(PushRefusal::Transport(
                "the delivery worker thread panicked".to_string(),
            ))
        });

        match &outcome {
            Ok(()) => return outcome,
            Err(refusal) if attempt_no < MAX_DELIVERY_ATTEMPTS && is_retryable(refusal) => {
                let delay_ms = RETRY_DELAYS_MS[(attempt_no - 1) as usize];
                tokio::time::sleep(jittered_delay(delay_ms)).await;
            }
            Err(_) => return outcome,
        }
    }
}

// ══ THE PER-TASK ORDERED DELIVERY QUEUE ═════════════════════════════════════════════════════════

/// One task's callback, waiting its turn. Carries its own `engine_host`/`seam` rather than assuming
/// the queue worker shares one held elsewhere, so a queued item is fully self-contained.
struct QueuedDelivery {
    engine_host: Arc<dyn EngineHost>,
    seam: Arc<dyn RelaySeam>,
    task: Task,
}

/// How many not-yet-attempted notifications one task's queue may hold before the oldest is dropped
/// to make room. A caller cannot slow busbar down by being slow ([`deliver`]'s own doctrine), and an
/// UNBOUNDED per-task queue behind a receiver that never answers would be exactly that: memory
/// growing forever, keyed by a rate the far end controls by holding its socket open.
const QUEUE_CAPACITY: usize = 64;

/// ONE ENTRY PER TASK THAT HAS EVENTS QUEUED OR A WORKER DRAINING THEM. Removed the moment its
/// queue empties (see [`drain_queue`]), so a task that stops changing costs nothing here — the same
/// bound [`pins`] and [`auths`] are documented with.
fn queues() -> &'static Mutex<HashMap<String, VecDeque<QueuedDelivery>>> {
    static QUEUES: OnceLock<Mutex<HashMap<String, VecDeque<QueuedDelivery>>>> = OnceLock::new();
    QUEUES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// ENQUEUE this task's notification for delivery, IN ORDER, without blocking the caller.
///
/// This is the seam both production sites (the unary hop's `notify_push` and the event-stream sink)
/// now call INSTEAD OF [`deliver`] directly. Neither may await a delivery inline: the unary hop
/// already runs detached, and the event-stream sink's caller is the stream's own chunk pump — a
/// notification that blocked there would stall every later chunk of that same stream behind
/// whatever the webhook is doing, retries included.
///
/// ONE WORKER PER TASK ID drains its queue in strict FIFO order, so a task's push notifications
/// arrive at the receiver in the same order its state actually changed — the property the inline
/// call used to get for free by construction and that a queue must keep on purpose. A worker is
/// spawned only when this task had none already running (the queue map's own presence is the flag:
/// see [`drain_queue`]), so calling this from a hot path costs one lock and, ordinarily, nothing
/// else — no new task is spawned once a task's worker is already draining.
///
/// Both production sites in `receive.rs` (`notify_push` and the event-stream sink) call this; neither
/// calls [`deliver`] directly any more.
pub(crate) fn enqueue(engine_host: Arc<dyn EngineHost>, seam: Arc<dyn RelaySeam>, task: Task) {
    if task.push_callback.is_none() {
        return;
    }
    let task_id = task.task_id.clone();
    let item = QueuedDelivery {
        engine_host,
        seam,
        task,
    };
    let spawn_worker = {
        let mut queues = queues().lock().unwrap_or_else(|e| e.into_inner());
        let already_running = queues.contains_key(&task_id);
        let queue = queues.entry(task_id.clone()).or_default();
        if queue.len() >= QUEUE_CAPACITY {
            queue.pop_front();
            diag_debug!(
                A2A_PUSH_QUEUE_DROPPED,
                task = %task_id,
                capacity = QUEUE_CAPACITY,
                "a2a: the push-delivery queue was full; the oldest queued notification was dropped"
            );
        }
        queue.push_back(item);
        !already_running
    };
    if spawn_worker {
        tokio::spawn(drain_queue(task_id));
    }
}

/// DRAIN one task's queue, oldest first, to exhaustion — the worker [`enqueue`] spawns at most one
/// of, per task, at a time.
///
/// The queue's own entry is the flag that says whether a worker is already draining it: this
/// function removes the entry the moment it finds the queue empty, INSIDE the same lock acquisition
/// that observed the emptiness, so a concurrent [`enqueue`] either lands before the removal (and
/// this loop picks the new item up on its next turn) or after it (and finds no entry, so it spawns
/// a fresh worker) — never both, and never neither, because the two critical sections cannot
/// interleave.
///
async fn drain_queue(task_id: String) {
    loop {
        let next = {
            let mut queues = queues().lock().unwrap_or_else(|e| e.into_inner());
            let Some(queue) = queues.get_mut(&task_id) else {
                return;
            };
            let popped = queue.pop_front();
            if popped.is_none() {
                queues.remove(&task_id);
            }
            popped
        };
        let Some(item) = next else {
            return;
        };
        let task_id_for_log = item.task.task_id.clone();
        // NEVER fatal to the task: the outcome is already on its chain (`deliver`), and a webhook
        // that stays down is the caller's to read in this line.
        if let Err(e) = deliver_with_retry(item.engine_host, item.seam, item.task).await {
            diag_debug!(A2A_PUSH_NOTIFY_UNDELIVERED, task = %task_id_for_log, error = %e, "a2a: the push notification was not delivered");
        }
    }
}

/// THE NUMBER OF EVENTS CURRENTLY QUEUED for a task, for the test that asserts the bound holds and
/// the drop is the OLDEST rather than the newest. Not `pub(crate)` beyond tests: production code has
/// no legitimate reason to inspect queue depth, only to enqueue into it.
#[cfg(all(test, feature = "test-support"))]
pub(crate) fn queue_depth_for_test(task_id: &str) -> usize {
    queues()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(task_id)
        .map_or(0, VecDeque::len)
}

#[cfg(all(test, feature = "test-support"))]
#[path = "tests/pushdeliver_tests.rs"]
mod pushdeliver_tests;
