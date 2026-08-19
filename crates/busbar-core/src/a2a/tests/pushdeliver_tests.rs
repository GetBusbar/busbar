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

use super::super::fetch::{HttpResponse, Resolver};
use super::super::pushdeliver::{self, PushRefusal};
use super::super::pushnotify::{self, PushNotifyError};
use super::super::relay::{ChunkFlow, RelaySeam, RelayTransport, StreamHead};
use super::super::task::{Direction, Task, TaskState};
use crate::plane::provenance;

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
    fn send(
        &self,
        _http_method: &str,
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

/// THE SEAM CARRIES NO POLICY, and that is the change this module is pinned against rather than a
/// simplification. It used to hold a `FetchPolicy` purely so `pushdeliver` could read
/// `allow_plaintext` off it; the delivery guard no longer takes that argument, so there is nothing
/// for a seam to answer and no field here for a future caller to set.
struct Seam {
    resolver: FixedResolver,
    transport: RecordingTransport,
}

impl RelaySeam for Seam {
    fn resolver(&self) -> &dyn Resolver {
        &self.resolver
    }
    fn transport(&self) -> &dyn RelayTransport {
        &self.transport
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

/// REGISTER the callback the way `ingress::invoke` does: validate against the addresses it resolves to
/// NOW, and keep the pin. Every test that starts here is testing a callback that was legitimate.
fn register(task_id: &str) {
    let pinned = pushnotify::validate(CALLBACK, &[AT_REGISTRATION])
        .expect("the callback was legitimate when it was registered");
    pushdeliver::remember(task_id, &pinned);
}

// ══ HTTPS IS STRUCTURAL ══════════════════════════════════════════════════════════════════════════

/// **A PLAINTEXT CALLBACK IS REFUSED, AND NO POLICY THIS SEAM COULD CARRY WOULD CHANGE THAT.**
///
/// busbar publishes, of the HTTPS-only push rule, that there is no configuration that relaxes it —
/// no per-registration flag, no deployment setting, no exception. That sentence used to be true by
/// ACCIDENT: `pushdeliver` read `seam.policy().allow_plaintext` and handed it to the guard, and the
/// only reason no deployment could set it was that no config key had ever been wired to the field.
///
/// The parameter and the seam accessor are both gone, so the sentence is now true by SHAPE. Written
/// as a test rather than only as a comment because the ARM would be trivial to restore, and this is
/// the case that goes red when somebody does: the refusal must be the SCHEME, decided before the
/// address check that would otherwise catch this URL for a different reason.
#[test]
fn a_plaintext_callback_is_refused_and_no_policy_reaches_the_delivery_guard() {
    let id = "t-deliver-plaintext-policy";
    let (seam, log) = seam_answering(&[AT_REGISTRATION], 200);
    let mut task = task_with_callback(id, TaskState::Completed);
    // A PUBLIC host that RESOLVES CLEANLY, so nothing but the scheme can be doing the refusing.
    task.push_callback = Some("http://hook.caller.test/notify".to_string());

    let err = pushdeliver::deliver(&seam, &task).expect_err("a plaintext callback must be refused");
    assert_eq!(
        err,
        PushRefusal::Guard(PushNotifyError::Scheme("http".to_string())),
        "the refusal must be the SCHEME, not something the address check happened to catch"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "a refused callback must not have reached the wire"
    );
    pushdeliver::forget(id);
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

    // THE BODY IS THE TASK UNDER BUSBAR'S IDENTITY, inside the `StreamResponse` envelope the
    // protocol defines for a delivered event. The receiver's later reads resolve against busbar's
    // store, so a backend agent's own id here would be a handle that resolves to nothing.
    let doc: serde_json::Value = serde_json::from_slice(&sent[0].body).expect("a JSON body");
    assert_eq!(doc["task"]["id"], id);
    assert_eq!(doc["task"]["contextId"], "ctx-1");
    assert_eq!(doc["task"]["status"]["state"], "completed");
    pushdeliver::forget(id);
}

/// NO CREDENTIAL OF BUSBAR'S LEAVES ON THIS HOP, AND NONE APPEARS UNASKED.
///
/// The receiver is a host the CALLER nominated; presenting busbar's outbound credential there would
/// spend it on a destination the caller chose, which is the confused-deputy shape
/// `creds::authorise_egress` closes on the relay path. So a task whose config named NO
/// authentication gets exactly the content type and nothing else — asserted over every header
/// rather than over a named one, because the hazard is the header nobody thought of.
#[test]
fn a_delivery_for_a_config_with_no_authentication_carries_no_header_but_the_content_type() {
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

/// THE CALLER'S OWN CREDENTIAL IS PRESENTED, and it is the caller's — not busbar's.
///
/// This is the capability `PUSH-DELIVER-001` describes and busbar did not have: the config's
/// `authentication` was dropped at registration, so a customer whose webhook authenticates could
/// not use push notifications at all. The header value is `<scheme> <credentials>` exactly as RFC
/// 9110 spells it, which is what a receiver checks.
#[test]
fn the_callers_own_webhook_credential_is_presented_on_the_delivery() {
    let id = "t-deliver-auth";
    register(id);
    pushdeliver::remember_auth(
        id,
        Some(&pushdeliver::DeliveryAuth {
            scheme: "Bearer".to_string(),
            credentials: "receiver-issued-token".to_string(),
        }),
    );
    let (seam, log) = seam_answering(&[AT_REGISTRATION], 200);
    pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Working)).expect("delivered");

    let sent = log.lock().unwrap();
    let auth = sent[0]
        .headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.clone());
    assert_eq!(
        auth.as_deref(),
        Some("Bearer receiver-issued-token"),
        "the delivery did not present the credential the caller registered: {:?}",
        sent[0].headers
    );
    drop(sent);
    pushdeliver::forget(id);
}

/// WITHDRAWING THE CREDENTIAL WITHDRAWS IT. A caller re-registering a config that names no
/// `authentication` has retired the secret, and a delivery that kept sending the old one would be
/// busbar spending a credential its owner has revoked — the failure a map that only ever inserts
/// produces.
#[test]
fn re_registering_without_authentication_stops_the_credential_being_sent() {
    let id = "t-deliver-auth-withdrawn";
    register(id);
    pushdeliver::remember_auth(
        id,
        Some(&pushdeliver::DeliveryAuth {
            scheme: "Bearer".to_string(),
            credentials: "old-token".to_string(),
        }),
    );
    pushdeliver::remember_auth(id, None);

    let (seam, log) = seam_answering(&[AT_REGISTRATION], 200);
    pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Working)).expect("delivered");

    let sent = log.lock().unwrap();
    assert!(
        !sent[0]
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("authorization")),
        "a withdrawn credential was still presented: {:?}",
        sent[0].headers
    );
    drop(sent);
    pushdeliver::forget(id);
}

/// THE SECRET DOES NOT OUTLIVE THE TASK. `forget` runs on the terminal delivery, and a credential
/// still sitting in memory for a task that will never receive another delivery is a secret with no
/// remaining use — the same bound `pin_for_test` exists to assert for the address pin.
#[test]
fn a_terminal_delivery_drops_the_credential_as_well_as_the_pin() {
    let id = "t-deliver-auth-forgotten";
    register(id);
    pushdeliver::remember_auth(
        id,
        Some(&pushdeliver::DeliveryAuth {
            scheme: "Bearer".to_string(),
            credentials: "short-lived".to_string(),
        }),
    );
    let (seam, _log) = seam_answering(&[AT_REGISTRATION], 200);
    pushdeliver::deliver(&seam, &task_with_callback(id, TaskState::Completed)).expect("delivered");

    assert_eq!(pushdeliver::pin_for_test(id), None);
    assert_eq!(pushdeliver::auth_for_test(id), None);
}

/// THE CREDENTIAL IS NOT PRINTABLE BY ACCIDENT. `Debug` is written rather than derived precisely so
/// that the first `tracing` field, `assert_eq!` message or panic payload to touch this struct does
/// not carry a caller's secret — and a derive added later would silently undo that, which is what
/// this asserts.
#[test]
fn the_delivery_credential_does_not_appear_in_its_own_debug_rendering() {
    let auth = pushdeliver::DeliveryAuth {
        scheme: "Bearer".to_string(),
        credentials: "a-secret-nobody-should-log".to_string(),
    };
    let rendered = format!("{auth:?}");
    assert!(
        !rendered.contains("a-secret-nobody-should-log"),
        "the credential is in its own Debug rendering: {rendered}"
    );
    assert!(rendered.contains("Bearer"), "{rendered}");
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
/// notification carries the task id and the caller's attribution and NO deployment puts that on the
/// wire in the clear. The neighbour above proves the refusal does not depend on the seam's policy;
/// this one is the ordinary path, and it is the one that would still catch a row that reached the
/// store past the registration-time guard.
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

// ══ THE BODY IS A `StreamResponse` CARRYING A TASK, AND THAT IS THE PROTOCOL ═════════════════════

/// A REGRESSION LOCK ON AN ABSENCE AND ON A PRESENCE, and both halves have been wrong here.
///
/// **The absence.** Every other place busbar puts JSON on this plane's wire is a JSON-RPC message
/// read or written through `crate::ingress::jsonrpc`. A reviewer who has just been through the
/// three response sites that really did lack a `jsonrpc` member and an `id` will read the same
/// absence HERE as a fourth instance and add them — and that would be a protocol violation, because
/// a push notification is POSTed to a webhook: it is not a request (busbar invokes no method on the
/// receiver) and not a response (the receiver asked busbar nothing).
///
/// **The presence.** The envelope A2A DOES define for a delivered event is `StreamResponse`, a
/// `oneof` over `{task, message, statusUpdate, artifactUpdate}`, and busbar sent the task
/// un-nested. That is not a shading of the schema: `StreamResponse` is `additionalProperties:
/// false` over those four names, so the specification's own validator rejected every busbar
/// delivery, and a receiver built on the specification's generated types could not deserialise one.
///
/// A2A puts the correlation duty on the RECEIVER and keys it on the TASK id in this document, not
/// on an envelope id — SPEC 4.3.3, "Clients MUST validate the task ID matches an expected task".
/// So this asserts three things: no JSON-RPC envelope, the `StreamResponse` arm, and the correlator
/// the spec names — which is BUSBAR'S id, because busbar's is the only one the receiver has ever
/// been told about.
#[test]
fn the_push_notification_body_is_a_stream_response_carrying_the_task_and_not_a_json_rpc_envelope() {
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
    // EXACTLY ONE MEMBER, AND IT IS ONE OF THE FOUR. `StreamResponse` is a `oneof` rendered with
    // `additionalProperties: false`, so a fifth member at the top level is as invalid as none.
    let top: Vec<&String> = doc.as_object().expect("an object").keys().collect();
    assert_eq!(
        top,
        vec!["task"],
        "the delivered document is a StreamResponse whose payload arm is `task`: {doc}"
    );
    assert_eq!(
        doc["task"]["kind"], "task",
        "the arm carries the Task document itself: {doc}"
    );
    // The `id` here is the TASK id — the correlator SPEC 4.3.3 makes the receiver check — and it is
    // busbar's, never a backend agent's.
    assert_eq!(doc["task"]["id"], "a2a-planner-PUSHED", "{doc}");
    assert!(
        doc.pointer("/task/contextId").is_some() && doc.pointer("/task/status/state").is_some(),
        "{doc}"
    );
}

// ══ THE DELIVERY IS AUDITED ══════════════════════════════════════════════════════════════════════
//
// Every test above proves what goes on the wire. NONE of them could see what this path RECORDED,
// because it recorded nothing: all three production callers disposed of the outcome with a
// `tracing::warn!`, so a delivery refused by the delivery-time SSRF guard — the strongest check on
// this path, and the one that fires exactly when a caller's callback has been re-pointed at
// something it should not reach — left no evidence an auditor could ever find. The three tests
// below drive the same production `deliver` the rest of this file drives, and then read the task's
// own provenance chain back out of a store.

/// Put `task` in the process-wide registry so it has a chain to be recorded on, exactly as the front
/// door does before any delivery is attempted, and hand back the sink the chain is written to.
///
/// The `TASKS_SINK_LOCK` guard the caller holds is what keeps two of these from interleaving on the
/// process-wide registry; see the lock's own note.
async fn a_task_in_the_registry(
    task_id: &str,
    state: TaskState,
) -> (
    Task,
    Arc<crate::plane::taskstore::event_ledger::EventLedger>,
    tokio::sync::MutexGuard<'static, ()>,
) {
    let guard = crate::plane::taskstore::TASKS_SINK_LOCK.lock().await;
    let ledger = Arc::new(crate::plane::taskstore::event_ledger::EventLedger::new());
    crate::plane::taskstore::TASKS.set_sink(crate::plane::store::PlaneStoreView::narrow(ledger.clone()));
    let task = task_with_callback(task_id, state);
    crate::plane::taskstore::TASKS
        .submit(&task, "req-1")
        .expect("the task is admitted");
    (task, ledger, guard)
}

/// The kinds on a task's chain, oldest first, read back out of the store.
fn kinds_of(
    ledger: &crate::plane::taskstore::event_ledger::EventLedger,
    task_id: &str,
) -> Vec<String> {
    let events = ledger.events_for(task_id);
    crate::audit::verify_chain(&events).expect("the per-task chain verifies after a delivery");
    events.into_iter().map(|e| e.kind).collect()
}

/// *** A DELIVERY REFUSED BY THE SSRF GUARD LEAVES A RECORD. ***
///
/// The callback was legitimate when it was registered and its name now answers the cloud metadata
/// address — the exact attack the delivery-time guard exists to stop, and until this test the
/// control fired in total silence. A security control nobody can audit after the fact is one whose
/// firing is indistinguishable from its absence.
#[tokio::test]
async fn a_delivery_the_ssrf_guard_refuses_lands_a_refusal_on_the_tasks_own_chain() {
    let id = "t-chain-refused";
    let (task, ledger, _guard) = a_task_in_the_registry(id, TaskState::Working).await;
    register(id);
    let (seam, log) = seam_answering(&[METADATA], 200);

    let refusal = pushdeliver::deliver(&seam, &task).expect_err("the guard must refuse");
    assert!(
        matches!(refusal, PushRefusal::Guard(_)),
        "this must be the GUARD refusing, not some other failure: {refusal}"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "nothing may reach the wire when the guard refuses"
    );

    let kinds = kinds_of(&ledger, id);
    crate::plane::taskstore::TASKS.clear_sink_for_test();
    pushdeliver::forget(id);
    assert!(
        kinds.contains(&provenance::EV_PUSH_REFUSED.to_string()),
        "the refusal left NO record on the task's chain — the whole point of the control is that \
         somebody can find out afterwards that it fired: {kinds:?}"
    );
    assert!(
        !kinds.contains(&provenance::EV_PUSH_DELIVERED.to_string()),
        "a refused delivery must never be recorded as delivered: {kinds:?}"
    );
}

/// The positive twin: a delivery that goes out is recorded as delivered, and the chain that now
/// carries both a submission and a delivery still recomputes.
///
/// Without it the refusal test above would be satisfied by a path that records `push_refused`
/// unconditionally.
#[tokio::test]
async fn a_delivered_notification_lands_a_delivered_record_on_the_tasks_own_chain() {
    let id = "t-chain-delivered";
    let (task, ledger, _guard) = a_task_in_the_registry(id, TaskState::Working).await;
    register(id);
    let (seam, log) = seam_answering(&[AT_REGISTRATION], 200);

    pushdeliver::deliver(&seam, &task).expect("the delivery succeeds");
    assert_eq!(log.lock().unwrap().len(), 1, "the notification went out");

    let kinds = kinds_of(&ledger, id);
    crate::plane::taskstore::TASKS.clear_sink_for_test();
    pushdeliver::forget(id);
    assert_eq!(
        kinds,
        vec![
            provenance::EV_SUBMITTED.to_string(),
            provenance::EV_PUSH_DELIVERED.to_string()
        ],
        "the task's chain carries the submission that opened it and the delivery that went out, \
         in that order and with nothing invented in between"
    );
}

/// THE RECEIVER'S OWN FAILURE IS NOT BUSBAR'S REFUSAL. A webhook that answers 500 got the delivery;
/// recording that as `push_refused` would send an operator to audit busbar's guard for an incident
/// that happened inside the caller's infrastructure.
#[tokio::test]
async fn a_receiver_that_answers_non_2xx_is_recorded_as_failed_and_not_as_refused() {
    let id = "t-chain-failed";
    let (task, ledger, _guard) = a_task_in_the_registry(id, TaskState::Working).await;
    register(id);
    let (seam, _log) = seam_answering(&[AT_REGISTRATION], 500);

    let refusal = pushdeliver::deliver(&seam, &task).expect_err("a 500 is not a delivery");
    assert!(matches!(refusal, PushRefusal::Status(500)), "{refusal}");

    let kinds = kinds_of(&ledger, id);
    crate::plane::taskstore::TASKS.clear_sink_for_test();
    pushdeliver::forget(id);
    assert!(
        kinds.contains(&provenance::EV_PUSH_FAILED.to_string())
            && !kinds.contains(&provenance::EV_PUSH_REFUSED.to_string()),
        "the delivery WENT OUT and the receiver failed it; the two populations must stay \
         distinguishable: {kinds:?}"
    );
}
