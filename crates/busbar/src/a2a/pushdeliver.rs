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

/// THE ONLY HEADER A DELIVERY CARRIES. No credential of any kind: the receiver is the CALLER's
/// infrastructure, busbar has no relationship with it, and a webhook that wants authentication
/// carries its own secret in the URL the caller chose. Sending busbar's outbound credential here
/// would spend it on a host the caller nominated, which is the confused-deputy shape
/// `creds::authorise_egress` exists to prevent on the relay path.
///
/// The request's TIME ceiling is the transport's (`transport::RELAY_TIMEOUT`), for the same reason
/// the relay's is: an unbounded one is a way for a caller to pin a busbar thread by pointing at a
/// host that accepts and never answers.
const DELIVERY_HEADERS: &[(&str, &str)] = &[("content-type", "application/json")];

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

/// Remember the addresses a callback was pinned to, so the NEXT delivery can require an overlap.
pub(crate) fn remember(task_id: &str, pinned: &PinnedCallback) {
    if let Ok(mut map) = pins().lock() {
        map.insert(task_id.to_string(), pinned.clone());
    }
}

/// Drop a task's pin. Called on the terminal delivery, because a terminal task gets no more.
pub(crate) fn forget(task_id: &str) {
    if let Ok(mut map) = pins().lock() {
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
/// A push notification is a **bare `Task` document POSTed to a webhook the CALLER nominated**. It is
/// not a request (busbar is not invoking a method on the receiver), it is not a response (the
/// receiver asked busbar nothing), and there is no request for an `id` to correlate to — the
/// receiver is not a JSON-RPC peer at all. A2A puts the correlation duty on the RECEIVER and keys it
/// on the TASK id in this document, not on an envelope id: SPEC 4.3.3, *"Clients MUST validate the
/// task ID matches an expected task"*. That clause only makes sense because the task id is the only
/// correlator there is, and it is the `"id"` field below.
///
/// So there is exactly one correctness duty on this function, and it is discharged: the ids in this
/// document are BUSBAR'S, never the backend agent's, because busbar's are the only ones the
/// receiver has ever been told about and the only ones that will resolve if it calls back.
pub(crate) fn notification_body(task: &Task) -> Vec<u8> {
    let doc = serde_json::json!({
        "id": task.task_id,
        "contextId": task.context_id,
        "kind": "task",
        "status": {
            "state": task.state.as_str(),
            "timestamp": task.updated_at,
        },
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
    let headers: Vec<(String, String)> = DELIVERY_HEADERS
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let body = notification_body(task);
    let resp = seam
        .transport()
        .post(&parsed, addr, &headers, &body)
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
