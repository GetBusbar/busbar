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

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use super::pushnotify::{self, PinnedCallback, PushNotifyError};
use super::relay::RelaySeam;
use super::task::Task;

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
    pub(crate) credentials: String,
}

impl DeliveryAuth {
    /// The `Authorization` field value: `<scheme> <credentials>`, or the bare scheme where the
    /// caller supplied none (the proto marks `credentials` optional, and a scheme with an empty
    /// value trailing a space is a header a strict receiver rejects).
    fn header_value(&self) -> String {
        if self.credentials.is_empty() {
            self.scheme.clone()
        } else {
            format!("{} {}", self.scheme, self.credentials)
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
/// store seam (`busbar_api::TaskRow`) has no notion of a secret and no encryption, so there is no
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
    if let Ok(mut map) = pins().lock() {
        map.insert(task_id.to_string(), pinned.clone());
    }
}

/// Hold the credential this task's receiver wants presented, or drop the one held when the caller
/// registered a config that names none.
///
/// `None` CLEARS rather than leaves the previous value in place. A caller replacing a config that
/// had authentication with one that does not has withdrawn the credential, and continuing to send
/// it would be busbar spending a secret its owner has retired.
pub(crate) fn remember_auth(task_id: &str, auth: Option<&DeliveryAuth>) {
    if let Ok(mut map) = auths().lock() {
        match auth {
            Some(a) => map.insert(task_id.to_string(), a.clone()),
            None => map.remove(task_id),
        };
    }
}

/// Drop a task's pin AND its credential. Called on the terminal delivery, because a terminal task
/// gets no more — and a secret with no remaining use is a secret that should not still be in memory.
pub(crate) fn forget(task_id: &str) {
    if let Ok(mut map) = pins().lock() {
        map.remove(task_id);
    }
    if let Ok(mut map) = auths().lock() {
        map.remove(task_id);
    }
}

/// The pin currently held for a task, for the test that asserts the map is BOUNDED. Reading it is
/// the only way to prove `forget` ran, and an unbounded map keyed by a caller-controlled rate is a
/// leak worth a test.
#[cfg(test)]
pub(crate) fn pin_for_test(task_id: &str) -> Option<PinnedCallback> {
    pins().lock().ok().and_then(|m| m.get(task_id).cloned())
}

/// The credential currently held for a task, for the test that asserts [`forget`] clears it. A
/// secret that outlives the task it was supplied for is the bound worth a test, for the same reason
/// [`pin_for_test`] exists.
#[cfg(test)]
pub(crate) fn auth_for_test(task_id: &str) -> Option<DeliveryAuth> {
    auths().lock().ok().and_then(|m| m.get(task_id).cloned())
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
/// message and is read or written through [`crate::ingress::jsonrpc`]; a reviewer who has just been
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
                "timestamp": task.updated_at,
            },
        }
    });
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// DELIVER ONE NOTIFICATION for `task`, re-running the full guard against a FRESH resolution first.
///
/// Synchronous, because both seams it uses are: the resolver performs a real name lookup and the
/// transport blocks a thread per hop. Callers run it on a blocking thread — see
/// [`super::ingress`] — for the same reason the relay does.
pub(crate) fn deliver(seam: &dyn RelaySeam, task: &Task) -> Result<(), PushRefusal> {
    let Some(url) = task.push_callback.as_deref() else {
        return Err(PushRefusal::NoCallback);
    };
    let allow_plaintext = seam.policy().allow_plaintext;

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
        .ok()
        .and_then(|m| m.get(&task.task_id).cloned());
    let pinned = match previous {
        // The stronger check: pass the guard AND still overlap what was pinned before.
        Some(prev) if prev.url == url => {
            pushnotify::revalidate(&prev, &fresh, allow_plaintext).map_err(PushRefusal::Guard)?
        }
        // No pin for this task in this process — a restart, or the first delivery. The full guard
        // still runs; only the overlap requirement is unavailable.
        _ => pushnotify::validate(url, &fresh, allow_plaintext).map_err(PushRefusal::Guard)?,
    };

    // ── 3. CONNECT, to an address that just passed, and to nothing else. ──
    let parsed = reqwest::Url::parse(&pinned.url).map_err(|_| PushRefusal::NotAUrl(url.into()))?;
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
        .ok()
        .and_then(|m| m.get(&task.task_id).cloned())
    {
        headers.push((AUTHORIZATION_HEADER.to_string(), auth.header_value()));
    }
    let body = notification_body(task);
    let resp = seam
        .transport()
        .send("POST", &parsed, addr, &headers, &body)
        .map_err(PushRefusal::Transport)?;

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

#[cfg(test)]
#[path = "tests/pushdeliver_tests.rs"]
mod pushdeliver_tests;
