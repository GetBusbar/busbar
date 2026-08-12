// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/a2a/pushdeliver.rs` — the push-notification DELIVERY path.
//!
//! ## What these tests are for, and it is not "does the POST happen"
//!
//! The delivery itself is four lines. The property worth testing is the one the goal file names:
//! **the SSRF guard runs at DELIVERY time, against a FRESH resolution, not only at registration.**
//! A task row is durable and an A2A task is asynchronous by design, so the row outlives the DNS
//! answer that was judged when it was written — and an attacker who registers a callback on a host
//! it controls simply waits, then re-points the name at the metadata service.
//!
//! So every test below that matters differs from its neighbour ONLY in what the resolver answers at
//! delivery time, with an identical, already-registered, already-validated callback. That is the
//! shape of the threat, and it is the shape a registration-time-only guard cannot see.
//!
//! ## The seam, and why the socket is not real
//!
//! `tests/transport_tests.rs` states the reason and it applies unchanged here: a test HTTP server
//! binds to loopback, loopback is INTERNAL, and the guard refuses it with no override — an
//! escape hatch for tests would be a hole in production. So the seam records what would have gone
//! on the wire, and the socket-level claims (the pin, the refusing resolver, the capped read) are
//! discharged against the real client in `transport_tests.rs`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use super::super::fetch::{FetchPolicy, HttpResponse, Resolver};
use super::super::pushdeliver::{self, PushRefusal};
use super::super::pushnotify::{self, PushNotifyError};
use super::super::relay::{ChunkFlow, RelaySeam, RelayTransport, StreamHead};
use super::super::task::{Direction, Task, TaskState};

const CALLBACK: &str = "https://hook.caller.test/notify";
/// The address the callback resolved to when it was REGISTERED. Public, so it passed.
const AT_REGISTRATION: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
/// A DIFFERENT public address, for the wholesale-move case.
const MOVED_TO: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
/// What the attacker's nameserver answers once the row is durable.
const METADATA: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));

// ══ THE SEAM ═════════════════════════════════════════════════════════════════════════════════════

struct FixedResolver(Vec<IpAddr>);

impl Resolver for FixedResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>, String> {
        Ok(self.0.clone())
    }
}

#[derive(Clone, Debug)]
struct Sent {
    url: String,
    addr: IpAddr,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

struct RecordingTransport {
    log: Arc<Mutex<Vec<Sent>>>,
    status: u16,
}

impl RelayTransport for RecordingTransport {
    fn post(
        &self,
        url: &reqwest::Url,
        addr: IpAddr,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, String> {
        self.log
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Sent {
                url: url.to_string(),
                addr,
                headers: headers.to_vec(),
                body: body.to_vec(),
            });
        Ok(HttpResponse {
            status: self.status,
            location: None,
            body: Vec::new(),
            peer_spki: None,
            client_identity_offered: false,
        })
    }

    fn post_stream(
        &self,
        _url: &reqwest::Url,
        _addr: IpAddr,
        _headers: &[(String, String)],
        _body: &[u8],
        _on_chunk: &mut (dyn FnMut(&[u8]) -> ChunkFlow + Send),
    ) -> Result<StreamHead, String> {
        panic!("a push notification is never a streaming hop")
    }
}

struct Seam {
    resolver: FixedResolver,
    transport: RecordingTransport,
    policy: FetchPolicy,
}

impl RelaySeam for Seam {
    fn resolver(&self) -> &dyn Resolver {
        &self.resolver
    }
    fn transport(&self) -> &dyn RelayTransport {
        &self.transport
    }
    fn policy(&self) -> &FetchPolicy {
        &self.policy
    }
}

/// A seam whose resolver answers `answers` at DELIVERY time, plus the log the transport writes to.
fn seam_answering(answers: &[IpAddr], status: u16) -> (Seam, Arc<Mutex<Vec<Sent>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    (
        Seam {
            resolver: FixedResolver(answers.to_vec()),
            transport: RecordingTransport {
                log: Arc::clone(&log),
                status,
            },
            policy: FetchPolicy::default(),
        },
        log,
    )
}

/// A task in `state` with `CALLBACK` registered, under a task id unique to the calling test so the
/// process-wide pin map cannot make two tests depend on each other's order.
fn task_with_callback(task_id: &str, state: TaskState) -> Task {
    let mut task = Task::submitted(task_id, "ctx-1", "key-1", Direction::Inbound, 100)
        .expect("a well-formed task");
    task.push_callback = Some(CALLBACK.to_string());
    task.state = state;
    task.updated_at = 200;
    task
}

/// REGISTER the callback the way `ingress::rpc` does: validate against the addresses it resolves to
/// NOW, and keep the pin. Every test that starts here is testing a callback that was legitimate.
fn register(task_id: &str) {
    let pinned = pushnotify::validate(CALLBACK, &[AT_REGISTRATION], false)
        .expect("the callback was legitimate when it was registered");
    pushdeliver::remember(task_id, &pinned);
}

// ══ THE DELIVERY HAPPENS AT ALL ══════════════════════════════════════════════════════════════════

/// The base case, and until this module existed there was no code in the tree that could pass it:
/// a completed task with a registered callback results in a POST to the caller's webhook.
#[test]
fn a_completed_task_with_a_callback_is_delivered() {
    let id = "t-deliver-base";
    register(id);
    let (seam, log) = seam_answering(&[AT_REGISTRATION], 200);
    let task = task_with_callback(id, TaskState::Completed);

    pushdeliver::deliver(&seam, &task).expect("the delivery succeeds");

    let sent = log.lock().unwrap();
    assert_eq!(sent.len(), 1, "nothing was delivered: {sent:?}");
    assert_eq!(sent[0].url, CALLBACK);
    // THE SOCKET GOES TO THE ADDRESS THE GUARD JUST JUDGED, not to a name the client would resolve
    // a second time. A delivery that handed the URL to a client and let it look the host up again
    // would reinstate the rebind this whole path exists to close.
    assert_eq!(sent[0].addr, AT_REGISTRATION);

    // THE BODY IS THE TASK UNDER BUSBAR'S IDENTITY. The receiver's later reads resolve against
    // busbar's store, so a backend agent's own id here would be a handle that resolves to nothing.
    let doc: serde_json::Value = serde_json::from_slice(&sent[0].body).expect("a JSON body");
    assert_eq!(doc["id"], id);
    assert_eq!(doc["contextId"], "ctx-1");
    assert_eq!(doc["status"]["state"], "completed");
    pushdeliver::forget(id);
}

/// NO CREDENTIAL LEAVES ON THIS HOP. The receiver is a host the CALLER nominated; presenting
/// busbar's outbound credential there would spend it on a destination the caller chose, which is
/// the confused-deputy shape `creds::authorise_egress` closes on the relay path. Asserted over
/// every header rather than over a named one, because the hazard is the header nobody thought of.
#[test]
fn a_delivery_carries_no_credential_of_any_kind() {
    let id = "t-deliver-nocred";
    register(id);
    let (seam, log) = seam_answering(&[AT_REGISTRATION], 202);
    pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed)).expect("delivered");

    let sent = log.lock().unwrap();
    let names: Vec<String> = sent[0]
        .headers
        .iter()
        .map(|(n, _)| n.to_lowercase())
        .collect();
    assert_eq!(
        names,
        vec!["content-type".to_string()],
        "a push delivery grew a header beyond the content type: {:?}",
        sent[0].headers
    );
    pushdeliver::forget(id);
}

/// A task with no callback is the overwhelmingly common case and must cost a socket to nobody.
#[test]
fn a_task_with_no_callback_delivers_nothing() {
    let (seam, log) = seam_answering(&[AT_REGISTRATION], 200);
    let task = Task::submitted("t-none", "ctx-1", "key-1", Direction::Inbound, 100).unwrap();
    assert_eq!(
        pushdeliver::deliver(&seam, &task),
        Err(PushRefusal::NoCallback)
    );
    assert!(log.lock().unwrap().is_empty());
}

// ══ THE GUARD AT DELIVERY TIME — THE POINT OF THE MODULE ═════════════════════════════════════════

/// **THE TEST THIS MODULE EXISTS FOR.**
///
/// The callback was registered against a public address and passed. Time passes — an interrupt
/// waiting on a human, a deploy, a day. At DELIVERY time the same name answers the cloud metadata
/// service. A guard that ran only at registration has already said yes and stored the row; the only
/// thing standing between the attacker and busbar's instance credentials is this check.
#[test]
fn a_callback_that_became_internal_after_registration_is_refused_at_delivery() {
    let id = "t-deliver-rebind";
    register(id);

    // The ONLY difference from the base case above.
    let (seam, log) = seam_answering(&[METADATA], 200);

    assert_eq!(
        pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed)),
        Err(PushRefusal::Guard(PushNotifyError::InternalAddress(
            METADATA
        ))),
        "a callback that now resolves to the metadata service was delivered to"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "the refusal happened AFTER the socket, which is not a refusal"
    );
    pushdeliver::forget(id);
}

/// THE SAME REBIND, ACROSS A RESTART. The durable row survives; the process-local pin does not, so
/// the check degrades from `revalidate` to `validate`. It must still refuse — a degraded check that
/// degraded to NO check is the failure mode a fallback path is for.
#[test]
fn the_rebind_is_still_refused_when_no_pin_survives_the_restart() {
    let id = "t-deliver-rebind-restart";
    pushdeliver::forget(id); // no `register` — this is the boot-from-store case
    let (seam, log) = seam_answering(&[METADATA], 200);

    assert_eq!(
        pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed)),
        Err(PushRefusal::Guard(PushNotifyError::InternalAddress(
            METADATA
        )))
    );
    assert!(log.lock().unwrap().is_empty());
}

/// A WHOLESALE MOVE to a different — still PUBLIC — address set is its own finding, not an SSRF
/// one, and it is the arm `pushnotify::revalidate` exists for. Until this module there was no
/// caller for that function anywhere in the tree.
#[test]
fn a_wholesale_move_to_another_public_address_is_held_rather_than_followed() {
    let id = "t-deliver-drift";
    register(id);
    let (seam, log) = seam_answering(&[MOVED_TO], 200);

    assert_eq!(
        pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed)),
        Err(PushRefusal::Guard(PushNotifyError::PinDrifted {
            host: "hook.caller.test".to_string()
        })),
        "the delivery followed a name that now means an entirely different host"
    );
    assert!(log.lock().unwrap().is_empty());
    pushdeliver::forget(id);
}

/// THE CONTROL for the test above. A legitimate DNS change that ADDS an address while keeping the
/// pinned one is ordinary operations and must still deliver — otherwise the guard above is just a
/// switch that turns push notifications off.
#[test]
fn an_overlapping_answer_is_a_legitimate_dns_change_and_still_delivers() {
    let id = "t-deliver-widened";
    register(id);
    let (seam, log) = seam_answering(&[MOVED_TO, AT_REGISTRATION], 200);

    pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed))
        .expect("an overlapping answer is a legitimate DNS change");
    assert_eq!(log.lock().unwrap().len(), 1);
    pushdeliver::forget(id);
}

/// AN EMPTY ANSWER IS A REFUSAL, not a pass. "Nothing was checked" must never read as "nothing was
/// found wrong" — that inversion is how a guard with a broken resolver becomes a guard with no
/// resolver.
#[test]
fn a_name_that_resolves_to_nothing_at_delivery_time_is_refused() {
    let id = "t-deliver-unresolved";
    register(id);
    let (seam, log) = seam_answering(&[], 200);

    assert_eq!(
        pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed)),
        Err(PushRefusal::Unresolved("hook.caller.test".to_string()))
    );
    assert!(log.lock().unwrap().is_empty());
    pushdeliver::forget(id);
}

/// A PLAINTEXT CALLBACK is refused at delivery even if it somehow reached the row, because the
/// notification carries the task id and the caller's attribution and this deployment did not opt
/// into putting that on the wire in the clear.
#[test]
fn a_plaintext_callback_is_refused_at_delivery() {
    let (seam, log) = seam_answering(&[AT_REGISTRATION], 200);
    let mut task = task_with_callback("t-deliver-plaintext", TaskState::Completed);
    task.push_callback = Some("http://hook.caller.test/notify".to_string());

    assert_eq!(
        pushdeliver::deliver(&seam, &task),
        Err(PushRefusal::Guard(PushNotifyError::Scheme(
            "http".to_string()
        )))
    );
    assert!(log.lock().unwrap().is_empty());
}

// ══ THE RECEIVER'S OWN FAILURES ══════════════════════════════════════════════════════════════════

/// A receiver that answers 500 is the CALLER's infrastructure failing. It is reported with the
/// status so an operator can tell it apart from a guard refusal, and it goes no further: the task's
/// outcome is already recorded and a caller must not be able to destroy its own work by pointing at
/// a broken URL.
#[test]
fn a_receiver_that_answers_500_is_a_refusal_that_names_the_status() {
    let id = "t-deliver-500";
    register(id);
    let (seam, log) = seam_answering(&[AT_REGISTRATION], 500);

    assert_eq!(
        pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed)),
        Err(PushRefusal::Status(500))
    );
    // The hop DID happen — this is not a guard refusal and must not be mistaken for one.
    assert_eq!(log.lock().unwrap().len(), 1);
    pushdeliver::forget(id);
}

/// Every refusal renders a message naming what failed. An operator reading "push failed" cannot
/// tell whether to fix DNS, fix the receiver, or look at an attack.
#[test]
fn every_refusal_says_which_rule_refused() {
    for (refusal, needle) in [
        (PushRefusal::NoCallback, "no push callback"),
        (
            PushRefusal::Guard(PushNotifyError::InternalAddress(METADATA)),
            "delivery-time SSRF guard",
        ),
        (
            PushRefusal::Unresolved("h.test".to_string()),
            "resolved to nothing at delivery time",
        ),
        (PushRefusal::NotAUrl("x".to_string()), "not an HTTP URL"),
        (
            PushRefusal::Transport("boom".to_string()),
            "could not be reached",
        ),
        (PushRefusal::Status(503), "answered 503"),
    ] {
        let rendered = refusal.to_string();
        assert!(
            rendered.contains(needle),
            "`{rendered}` does not name the rule that refused (wanted `{needle}`)"
        );
    }
}

// ══ THE PIN MAP IS BOUNDED ═══════════════════════════════════════════════════════════════════════

/// A TERMINAL DELIVERY IS THE LAST ONE, so its pin is dropped. Without this the map grows by one
/// entry per task that ever registered a callback, for the life of the process — a slow leak keyed
/// by something a caller controls the rate of.
#[test]
fn the_terminal_delivery_drops_its_pin() {
    let id = "t-deliver-bounded";
    register(id);
    let (seam, _log) = seam_answering(&[AT_REGISTRATION], 200);

    pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Working)).expect("delivered");
    // Still held after a NON-terminal delivery: more are coming, and each should be able to require
    // an overlap with the last.
    assert!(pushdeliver::pin_for_test(id).is_some());

    pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed)).expect("delivered");
    assert!(
        pushdeliver::pin_for_test(id).is_none(),
        "a terminal task's pin outlived the task"
    );
}

// ══ THE BODY IS A BARE TASK, AND THAT IS THE PROTOCOL ════════════════════════════════════════════

/// A REGRESSION LOCK ON AN ABSENCE, which is the only kind of claim that needs one.
///
/// Every other place busbar puts JSON on this plane's wire is a JSON-RPC message read or written
/// through `crate::ingress::jsonrpc`. A reviewer who has just been through the three response sites
/// that really did lack a `jsonrpc` member and an `id` will read the same absence HERE as a fourth
/// instance and add them — and that would be a protocol violation, because a push notification is a
/// bare `Task` document POSTed to a webhook, not a request (busbar invokes no method on the
/// receiver) and not a response (the receiver asked busbar nothing).
///
/// A2A puts the correlation duty on the RECEIVER and keys it on the TASK id in this document, not
/// on an envelope id — SPEC 4.3.3, "Clients MUST validate the task ID matches an expected task".
/// So this asserts both halves: no envelope, and the correlator the spec names is present and is
/// BUSBAR'S id, because busbar's is the only one the receiver has ever been told about.
#[test]
fn the_push_notification_body_is_a_bare_task_document_and_not_a_json_rpc_envelope() {
    let task = task_with_callback("a2a-planner-PUSHED", TaskState::Completed);
    let body = pushdeliver::notification_body(&task);
    let doc: serde_json::Value = serde_json::from_slice(&body).expect("the body is JSON");

    for member in ["jsonrpc", "method", "params", "result", "error"] {
        assert!(
            doc.get(member).is_none(),
            "a push notification is not a JSON-RPC message and must carry no `{member}` member: \
             {doc}"
        );
    }
    assert_eq!(
        doc["kind"], "task",
        "the payload is the Task document itself: {doc}"
    );
    // The `id` here is the TASK id — the correlator SPEC 4.3.3 makes the receiver check — and it is
    // busbar's, never a backend agent's.
    assert_eq!(doc["id"], "a2a-planner-PUSHED", "{doc}");
    assert!(
        doc.get("contextId").is_some() && doc.pointer("/status/state").is_some(),
        "{doc}"
    );
}
