// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR SERVING THE `pools` MAP, HELD TO THE PREVIOUS ENGINE'S END-TO-END TESTS (U11: before the
//! legacy engine crate is deleted, every one of its tests whose behaviour a customer sees keeps a
//! test on the door path). Each test here ports one legacy test, named in its doc comment: the same
//! inputs and the same expected statuses and bytes, the harness translated to the door's rig
//! (`super::hook_seat_tests::rig`): a keyed caller through the data router built with the door's
//! claims, the kernel's hook stage, the model-serving walk over the kernel's lane cells, real
//! loopback far ends, the node's book. A test the door does not yet pass is kept, ignored, with the
//! one-line cause of the divergence.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use busbar_contract::caps::{Outcome, ReasonCode, StepName};
use busbar_kernel_audit::{FinishClass, Subject};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::hook_seat_tests::{
    chunk, far_end_answering, far_end_scripted, rig, DoorRig, RigOpts, Script,
};
use super::planes_tests::{Published as Withdrawn, PUBLISHING as ONE_PUBLISHER};

// ── the far ends and the readings ───────────────────────────────────────────────────────────────

/// An openai chat completion, marked by the member that served it.
const SERVED: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"served-by-the-first"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// The same, served by the second member.
const SERVED_BY_TWIN: &str = r#"{"id":"chatcmpl-2","object":"chat.completion","created":0,"model":"m1","choices":[{"index":0,"message":{"role":"assistant","content":"served-by-the-twin"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// A message in the dialect whose members speak `anthropic`.
const MESSAGE: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"m0","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#;

/// A streamed far end's head: chunked, so a far end that closes before its last chunk CUT it.
const STREAM_HEAD: &str = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                           transfer-encoding: chunked\r\nconnection: close\r\n\r\n";

/// A whole streamed answer's frames: a delta, the stop, the usage, the end.
const FRAMES: [&str; 4] = [
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}"#,
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
    r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}"#,
    "[DONE]",
];

/// One event-stream frame, as a chunk.
fn frame(data: &str) -> Vec<u8> {
    chunk(format!("data: {data}\n\n").as_bytes())
}

/// The whole stream of [`FRAMES`], ended cleanly.
fn whole_stream() -> Script {
    Script {
        head: STREAM_HEAD.to_string(),
        pieces: FRAMES.iter().map(|f| (0, frame(f))).collect(),
        finish: Some(b"0\r\n\r\n".to_vec()),
    }
}

/// A caller's chat on pool `p`, its answer streamed.
fn streamed_chat() -> serde_json::Value {
    serde_json::json!({"model": "p", "stream": true, "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]})
}

/// A caller's chat naming `model`.
fn chat_on(model: &str) -> serde_json::Value {
    serde_json::json!({"model": model, "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]})
}

/// A whole answer with `status` and the JSON `body`, as raw bytes on the wire.
fn json_reply(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n{body}",
        body.len()
    )
}

/// A FAR END THAT KEEPS WHAT IT WAS SENT: each request's line and body, as read. It answers each
/// with `reply` after `after_ms`; `None` never answers (a black hole: the request is read, the
/// connection held open, and nothing is ever written).
struct Recording {
    port: u16,
    hits: Arc<AtomicUsize>,
    /// Each request's line (`POST /v1/messages HTTP/1.1`) and body.
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// One request a far end read: its line and its body.
type Seen = (String, Vec<u8>);

impl Recording {
    fn served(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    /// The `n`th request's body, as JSON.
    fn body(&self, n: usize) -> serde_json::Value {
        let seen = self.seen.lock().unwrap();
        serde_json::from_slice(&seen[n].1).expect("a JSON body")
    }
}

async fn far_end_recording(after_ms: Option<u64>, reply: String) -> Recording {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (counted, kept) = (Arc::clone(&hits), Arc::clone(&seen));
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let (counted, kept, reply) = (Arc::clone(&counted), Arc::clone(&kept), reply.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut got = Vec::new();
                let (line, body) = loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some(at) = text.find("\r\n\r\n") {
                        let length = text[..at]
                            .lines()
                            .find_map(|l| {
                                let (n, v) = l.split_once(':')?;
                                n.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        if got.len() >= at + 4 + length {
                            let line = text.lines().next().unwrap_or_default().to_string();
                            break (line, got[at + 4..at + 4 + length].to_vec());
                        }
                    }
                };
                counted.fetch_add(1, Ordering::SeqCst);
                kept.lock().unwrap().push((line, body));
                let Some(after_ms) = after_ms else {
                    // The black hole: hold the connection, write nothing, until the caller goes.
                    while matches!(socket.read(&mut buf).await, Ok(n) if n > 0) {}
                    return;
                };
                tokio::time::sleep(std::time::Duration::from_millis(after_ms)).await;
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    Recording { port, hits, seen }
}

/// One request through the rig's data router: `body` raw, the caller's bearer token presented when
/// `keyed`, `fields` beside. Its status, head and body.
async fn call(
    rig: &DoorRig,
    method: &str,
    path: &str,
    body: &[u8],
    fields: &[(&str, &str)],
    keyed: bool,
) -> (u16, axum::http::HeaderMap, Vec<u8>) {
    use tower::ServiceExt as _;
    let mut req = axum::http::Request::builder().method(method).uri(path);
    if keyed {
        req = req.header("authorization", format!("Bearer {}", rig.token));
    }
    req = req.header("content-type", "application/json");
    for (name, value) in fields {
        req = req.header(*name, *value);
    }
    let response = rig
        .router
        .clone()
        .oneshot(
            req.body(axum::body::Body::from(body.to_vec()))
                .expect("a request"),
        )
        .await
        .expect("the router answers");
    let status = response.status().as_u16();
    let head = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 22)
        .await
        .map(|b| b.to_vec())
        .unwrap_or_default();
    (status, head, bytes)
}

/// The scrape, as `/metrics` renders it.
fn scrape() -> String {
    busbar_kernel::metrics::render()
}

/// The sum of every `busbar_requests_total` series labelled `pool` and `outcome`.
fn requests_total(scrape: &str, pool: &str, outcome: &str) -> u64 {
    let (pool, outcome) = (format!("pool=\"{pool}\""), format!("outcome=\"{outcome}\""));
    scrape
        .lines()
        .filter(|l| {
            l.starts_with("busbar_requests_total{") && l.contains(&pool) && l.contains(&outcome)
        })
        .filter_map(|l| l.rsplit(' ').next()?.trim().parse::<f64>().ok())
        .map(|v| v as u64)
        .sum()
}

/// The audit records the rig's node sealed so far, oldest first.
fn sealed(rig: &DoorRig) -> Vec<busbar_kernel_audit::AuditRecord> {
    rig.book
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .audit_records
        .clone()
}

/// The audit records once `n` are sealed (bounded: a unit seals at its end, which its caller's
/// last byte may precede).
async fn sealed_after(rig: &DoorRig, n: usize) -> Vec<busbar_kernel_audit::AuditRecord> {
    for _ in 0..300 {
        let records = sealed(rig);
        if records.len() >= n {
            return records;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    sealed(rig)
}

/// Lane `lane`'s lifetime counters on the kernel's lane store.
fn lane(rig: &DoorRig, lane: usize) -> busbar_kernel::store::LaneSnapshot {
    rig.app.store.snapshot(lane, busbar_kernel::store::now())
}

// ── the money at the door ───────────────────────────────────────────────────────────────────────

/// A REQUEST REFUSED BEFORE ITS ROUTE (a body that is not JSON) is never charged, so it refunds
/// nothing: the charge a prior request on the same key landed in the same window stays whole.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_pre_routing_failure_does_not_refund_prior_charge`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_refused_before_its_route_leaves_a_prior_charge_whole() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-prior-charge";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            budget_cents: Some(100),
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200, "the prior, charged request");
    let (requests, spend, _, _) = rig.ledger_after(1).await;
    assert_eq!((requests, spend), (1, 1), "the prior charge is seeded");
    let (status, _, body) = call(
        &rig,
        "POST",
        "/v1/chat/completions",
        b"{ this is not valid json",
        &[],
        true,
    )
    .await;
    assert_eq!(
        status,
        400,
        "a malformed body is refused before its route: {}",
        String::from_utf8_lossy(&body)
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let (requests, spend, _, _) = rig.ledger_after(1).await;
    assert_eq!(
        (requests, spend),
        (1, 1),
        "the refused request was never charged, so it erodes nothing of the prior charge"
    );
    assert_eq!(far.served(), 1);
}

/// AN UNPRICED NAME IS ASKED OF THE KERNEL AS ONE VERDICT, never read off a card: a deployment with
/// no rate card leaves no name unpriced, so a request naming any configured model is served and
/// charged its one fee, never refused for want of a price.
///
/// Ports legacy `unit/tests/chain.rs::the_plane_reads_the_unpriced_verdict_never_the_card`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_card_no_name_is_unpriced_and_the_request_is_served() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-unpriced";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            budget_cents: Some(100),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send("POST", "/v1/chat/completions", Some(chat_on("m0")))
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (_, spend, _, billable) = rig.ledger_after(1).await;
    assert_eq!((spend, billable), (1, 1), "served and charged its fee");
    assert_eq!(far.served(), 1);
}

/// EXHAUSTING A POOL'S BUDGET WITH `on_exhaust: downgrade` DOWNGRADES rather than refusing: the
/// admission lands on the `downgrade_to` pool, its members serve, and the downgraded admission
/// still charges.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_budget_exhaustion_downgrades_pool`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_exhausted_pool_budget_downgrades_onto_its_downgrade_pool() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-downgrade";
    let _published = Withdrawn(instance);
    let (frontier, value) = (
        far_end_answering(200, SERVED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(frontier.port, 1), (value.port, 1)],
            pooled: Some(1),
            pools: &[("v", &[1], "")],
            limits: &[downgrading_limit()],
            ..RigOpts::default()
        },
    )
    .await;
    // A one-cent fee under a two-cent cap: two admissions on `p` spend it; the third would not fit.
    for n in 0..2 {
        assert_eq!(rig.chat().await.0, 200, "admission {n} under the cap");
    }
    assert_eq!(frontier.served(), 2);
    let (status, _, body) = rig.chat().await;
    assert_eq!(
        status,
        200,
        "downgraded, not refused: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        String::from_utf8_lossy(&body).contains("served-by-the-twin"),
        "dispatch followed the charge onto the downgrade pool"
    );
    assert_eq!(value.served(), 1);
    let (requests, _, _, _) = rig.ledger_after(3).await;
    assert_eq!(requests, 3, "the downgraded admission still charges");
}

/// A DOWNGRADE NEVER BYPASSES THE KEY'S POOL GRANT: a key granted only `p` is never routed into the
/// downgrade pool by exhaustion; it meets the plain budget refusal.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_downgrade_never_bypasses_pool_acl`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_downgrade_never_routes_a_key_into_a_pool_it_may_not_reach() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-downgrade-acl";
    let _published = Withdrawn(instance);
    let (frontier, value) = (
        far_end_answering(200, SERVED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(frontier.port, 1), (value.port, 1)],
            pooled: Some(1),
            pools: &[("v", &[1], "")],
            limits: &[downgrading_limit()],
            allowed_pools: Some(&["p"]),
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    assert_eq!(rig.chat().await.0, 200);
    let (status, _, _) = rig.chat().await;
    assert_eq!(
        status, 429,
        "the caller sees the plain quota refusal, not a pool it may not reach"
    );
    assert_eq!(value.served(), 0, "the downgrade pool was never dialled");
}

/// The key's group limit on pool `p`: two cents a day, downgrading to pool `v` when spent.
fn downgrading_limit() -> busbar_kernel::config::groups::LimitCfg {
    use busbar_kernel::config::groups::{LimitCfg, LimitMetric, LimitWindow, OnExhaust};
    LimitCfg {
        metric: LimitMetric::Budget,
        amount: 2,
        per: Some(LimitWindow::Day),
        scope: Some(busbar_contract::records::ScopeRef::pool("p")),
        on_exhaust: Some(OnExhaust::Downgrade),
        downgrade_to: Some(busbar_contract::records::ScopeRef::pool("v")),
        admission: None,
        on_exhaustion: None,
    }
}

/// AN EMPTY DESTINATION SET IS NOT A REFUSAL AT VERIFY: a route that seals nothing (a name the
/// deployment does not hold) proceeds past verify, the admission door draws its slot and keeps it,
/// and only then is the unit refused for its route; nothing is dialled.
///
/// Ports legacy `unit/tests/verify.rs::an_empty_destination_set_proceeds_rather_than_refusing`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_that_seals_nothing_proceeds_past_verify_and_keeps_its_slot() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-empty-set";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, _) = rig
        .send("POST", "/v1/chat/completions", Some(chat_on("pool-a")))
        .await;
    assert_eq!(status, 404, "refused for its route, after the door");
    let records = sealed_after(&rig, 1).await;
    let end = records.last().expect("the unit's record").outcome.unit_end;
    assert!(
        !matches!(end, Outcome::Refused(StepName::Verify, _)),
        "verify proceeded with the empty set: {end:?}"
    );
    let (requests, _, _, _) = rig.ledger_after(0).await;
    assert_eq!(requests, 1, "the door drew the admission slot and kept it");
    assert_eq!(far.served(), 0, "nothing was dialled");
}

// ── the pool grant at the door ──────────────────────────────────────────────────────────────────

/// The message a key refused a pool it may not reach is answered with.
const NOT_PERMITTED: &str = "Your API key does not have permission to access this resource.";

/// THE VERIFY REFUSAL'S WIRE TRIPLE is the one guard reading's: a key granted only another pool
/// naming `p` is refused 403, `permission_error`, in the caller's dialect envelope, before any far
/// end is dialled.
///
/// Ports legacy `unit/tests/chain.rs::the_verify_refusal_carries_the_wire_triple_the_guards_named`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_naming_a_pool_it_may_not_reach_is_refused_with_the_permission_triple() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-verify-triple";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            allowed_pools: Some(&["some-other-pool"]),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig.chat().await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&body));
    let error: serde_json::Value = serde_json::from_slice(&body).expect("a JSON envelope");
    assert_eq!(error["error"]["type"], "permission_error", "{error}");
    assert_eq!(error["error"]["message"], NOT_PERMITTED, "{error}");
    assert_eq!(far.served(), 0);
}

/// THE VERIFY STEP STAMPS ITS REFUSAL WITH ITSELF: the sealed record of a key refused the pool it
/// named says the unit stopped at verify, refused as a pool not permitted.
///
/// Ports legacy `unit/tests/verify.rs::the_step_stamps_its_refusal_with_verify`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_refusal_is_sealed_as_the_verify_steps() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-verify-stamp";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            allowed_pools: Some(&["allowed"]),
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 403);
    let records = sealed_after(&rig, 1).await;
    let outcome = &records.last().expect("the refused unit's record").outcome;
    assert_eq!(
        outcome.unit_end,
        Outcome::Refused(StepName::Verify, ReasonCode::PoolNotPermitted)
    );
    assert_eq!(outcome.step, Some(StepName::Verify));
}

/// THE ACTIVE GOVERNANCE CONTROL: a persisted key scoped to another pool, on a deployment whose
/// data chain verifies keys, is enforced: its request on the pool's own named route is refused 403.
///
/// Ports legacy `engine/tests/auth_dispatch_tests.rs::test_active_governance_persisted_key_is_enforced`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_persisted_key_scoped_elsewhere_is_enforced_on_the_named_route() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-enforced";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, MESSAGE).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            allowed_pools: Some(&["restricted"]),
            dialect: Some("anthropic"),
            ..RigOpts::default()
        },
    )
    .await;
    let body = serde_json::json!({"model": "p", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]});
    let (status, _, answer) = rig.send("POST", "/p/v1/messages", Some(body)).await;
    assert_eq!(
        status,
        403,
        "the key's pool grant is enforced: {}",
        String::from_utf8_lossy(&answer)
    );
    assert_eq!(far.served(), 0, "refused before any far end");
}

/// THE AD-HOC ROUTE ALSO RUNS THE POOL GRANT: a key granted only another pool, naming a configured
/// model on `/<provider>/<model>/v1/messages`, is refused 403 in the messages dialect's own error
/// envelope (`type: error`, `error.type: permission_error`).
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_adhoc_governance_pool_acl_403_via_router`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_adhoc_route_refuses_a_key_its_grant_does_not_reach() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-adhoc-grant";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, MESSAGE).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            allowed_pools: Some(&["other-pool"]),
            dialect: Some("anthropic"),
            ..RigOpts::default()
        },
    )
    .await;
    let body = serde_json::json!({"model": "m0", "messages": [], "max_tokens": 16});
    let (status, _, answer) = rig.send("POST", "/oai0/m0/v1/messages", Some(body)).await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&answer));
    let error: serde_json::Value = serde_json::from_slice(&answer).expect("a JSON envelope");
    assert_eq!(error["type"], "error", "{error}");
    assert_eq!(error["error"]["type"], "permission_error", "{error}");
    assert_eq!(far.served(), 0);
}

/// A PRE-DOOR REFUSAL IS COUNTED UNDER THE POOL IT WAS RAISED AGAINST: a 403 against a configured
/// pool is labelled with that pool's name; a name no deployment configured reads back as the
/// reserved `unresolved` label.
///
/// Ports legacy `unit/tests/chain.rs::the_refused_terminal_labels_a_configured_pool_with_its_name`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_unit_is_counted_under_its_configured_pool_or_unresolved() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-refused-label";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            names: Some(&["refused-label-model"]),
            allowed_pools: Some(&["some-other-pool"]),
            ..RigOpts::default()
        },
    )
    .await;
    let before = scrape();
    let (p, unresolved) = (
        requests_total(&before, "p", "client_error"),
        requests_total(&before, "unresolved", "client_error"),
    );
    assert_eq!(rig.chat().await.0, 403);
    let after = scrape();
    assert_eq!(
        requests_total(&after, "p", "client_error"),
        p + 1,
        "the refusal against the configured pool is labelled with its name:\n{after}"
    );
    let (status, _, _) = rig
        .send(
            "POST",
            "/v1/chat/completions",
            Some(chat_on("no-such-pool-refused-label")),
        )
        .await;
    assert_eq!(status, 403, "the grant is judged over the name first");
    let after = scrape();
    assert_eq!(
        requests_total(&after, "unresolved", "client_error"),
        unresolved + 1,
        "a name nothing configured reads back as `unresolved`:\n{after}"
    );
    assert!(!after.contains("no-such-pool-refused-label"));
}

// ── the request families' labels ────────────────────────────────────────────────────────────────

/// AN UNRESOLVED MODEL IS COUNTED UNDER THE BOUNDED `unresolved` LABEL, never the raw string the
/// client sent (a credential must not mint unbounded series): a model no pool and no model names is
/// a 404, and the scrape carries `pool="unresolved"` and never the string.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_unresolved_model_uses_bounded_pool_label_not_raw_string`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unresolved_model_is_counted_as_unresolved_never_its_raw_name() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-unresolved";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let probe = "zzz-unbounded-cardinality-probe-9f3a";
    let (status, _, _) = rig
        .send(
            "POST",
            "/v1/chat/completions",
            Some(serde_json::json!({"model": probe,
                "messages": [{"role": "user", "content": "hi"}]})),
        )
        .await;
    assert_eq!(status, 404, "an unknown model is a 404");
    let scrape = scrape();
    assert!(
        !scrape.contains(probe),
        "the raw client model never becomes a label:\n{scrape}"
    );
    assert!(
        scrape.contains("pool=\"unresolved\""),
        "the bounded `unresolved` label instead:\n{scrape}"
    );
}

/// AN UNSUPPORTED ACTION ON THE PATH-MODEL DIALECT (`:countTokens`) is a 404 that is still counted:
/// `busbar_requests_total{pool="unresolved",outcome="client_error"}` strictly increases.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_gemini_unsupported_action_is_observable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsupported_path_action_is_a_counted_404() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-count-tokens";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let before = requests_total(&scrape(), "unresolved", "client_error");
    let (status, _, _) = call(
        &rig,
        "POST",
        "/v1beta/models/m0:countTokens",
        br#"{"contents": []}"#,
        &[],
        true,
    )
    .await;
    assert_eq!(status, 404, "an unsupported action is a 404");
    let after = requests_total(&scrape(), "unresolved", "client_error");
    assert!(
        after > before,
        "the unsupported action is counted (pool=unresolved, outcome=client_error): \
         before={before} after={after}"
    );
    assert_eq!(far.served(), 0);
}

/// A REFUSAL NO DIALECT READ STAYS UNCOUNTED: a path no dialect claims (its 404) and a verb a
/// dialect path does not take (its 405) never reached a dialect's own reading, so neither is on
/// `busbar_requests_total`, as 1.5.5's router answered them before its ingress handlers ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_no_dialect_read_is_not_counted() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-uncounted";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let before = requests_total(&scrape(), "unresolved", "client_error");
    let (status, _, _) = call(&rig, "POST", "/nowhere-at-all", b"{}", &[], true).await;
    assert_eq!(status, 404, "an unknown path is a 404");
    let (status, _, _) = call(&rig, "GET", "/v1/chat/completions", b"", &[], true).await;
    assert_eq!(status, 405, "a dialect path takes POST only");
    let after = requests_total(&scrape(), "unresolved", "client_error");
    assert_eq!(
        after, before,
        "neither refusal reached a dialect's reading, so neither is counted"
    );
    assert_eq!(far.served(), 0);
}

/// THE POOL LABEL'S CARDINALITY IS BOUNDED BY THE CONFIGURATION: a configured pool's name is its
/// own label, a configured model routed directly is its own label, and anything else is
/// `unresolved`.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_pool_label_bounds_cardinality`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_request_label_is_a_configured_pool_or_model_else_unresolved() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-label-bounds";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            names: Some(&["label-bounds-model"]),
            ..RigOpts::default()
        },
    )
    .await;
    let before = scrape();
    let counts = |s: &str| {
        (
            requests_total(s, "p", "ok"),
            requests_total(s, "label-bounds-model", "ok"),
            requests_total(s, "unresolved", "client_error"),
        )
    };
    let (pool, model, unresolved) = counts(&before);
    assert_eq!(rig.chat().await.0, 200);
    assert_eq!(
        rig.send(
            "POST",
            "/v1/chat/completions",
            Some(chat_on("label-bounds-model"))
        )
        .await
        .0,
        200
    );
    assert_eq!(
        rig.send(
            "POST",
            "/v1/chat/completions",
            Some(chat_on("anything-else-label-bounds"))
        )
        .await
        .0,
        404
    );
    let after = scrape();
    assert_eq!(
        counts(&after),
        (pool + 1, model + 1, unresolved + 1),
        "pool verbatim, model verbatim, anything else `unresolved`:\n{after}"
    );
    assert!(!after.contains("anything-else-label-bounds"));
}

/// THE UPSTREAM SERIES' POOL LABEL is the routed model for a direct route (the model's own cell)
/// and the pool's name verbatim for a named pool, so those series line up with the request family.
///
/// Ports legacy `engine/tests/forward_once_pool_cell_tests.rs::test_metric_pool_label_resolves_model_for_default_cell`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_upstream_series_label_a_direct_route_by_its_model_and_a_pool_by_its_name() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-upstream-label";
    let _published = Withdrawn(instance);
    let (a, b) = (
        far_end_answering(200, SERVED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(a.port, 1), (b.port, 1)],
            names: Some(&["cell-label-sonnet", "cell-label-gpt"]),
            pooled: Some(1),
            ..RigOpts::default()
        },
    )
    .await;
    for model in ["cell-label-sonnet", "cell-label-gpt", "p"] {
        let (status, _, _) = rig
            .send("POST", "/v1/chat/completions", Some(chat_on(model)))
            .await;
        assert_eq!(status, 200, "{model}");
    }
    let scrape = scrape();
    let attempted = |pool: &str, lane: &str| {
        scrape.lines().any(|l| {
            l.starts_with("busbar_upstream_attempts_total{")
                && l.contains(&format!("pool=\"{pool}\""))
                && l.contains(&format!("lane=\"{lane}\""))
        })
    };
    assert!(
        attempted("cell-label-sonnet", "cell-label-sonnet"),
        "a direct route is labelled by its routed model, never the empty cell key:\n{scrape}"
    );
    assert!(
        attempted("cell-label-gpt", "cell-label-gpt"),
        "the label tracks the routed lane's own model:\n{scrape}"
    );
    assert!(
        attempted("p", "cell-label-sonnet"),
        "a named pool keeps its own name:\n{scrape}"
    );
    assert!(
        !scrape.lines().any(|l| {
            l.starts_with("busbar_upstream_attempts_total{") && l.contains("pool=\"\"")
        }),
        "no series under the empty cell key:\n{scrape}"
    );
}

/// THE LIVE `busbar_pool_queued` GAUGE reads the pool's real park depth: one while a request waits
/// on its pool's `queue` terminal for a member at capacity, zero once it has left the queue; the
/// scrape's line and the depth its refresh reads agree.
///
/// Ports legacy `engine/tests/scrape_queued_depth_tests.rs::test_scrape_gauges_pool_queued_reads_live_depth`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_pool_queue_gauge_reads_the_live_park_depth() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-queued";
    let _published = Withdrawn(instance);
    let slow = far_end_recording(Some(1_500), json_reply(200, SERVED)).await;
    let rig = Arc::new(
        rig(
            instance,
            RigOpts {
                members: &[(slow.port, 1)],
                model_yaml: &[(0, "max_concurrent: 1")],
                pool_yaml: Some("on_exhausted: {queue: {max_ms: 5000}}"),
                ..RigOpts::default()
            },
        )
        .await,
    );
    // Two readings of one depth: the gauge the walk sets on the scrape as a waiter parks and
    // leaves, and the depth the scrape's own refresh reads off the kernel's configuration tables
    // (the one `refresh_scrape_gauges` renders where no engine runtime projects its own tables).
    let gauge = || {
        use busbar_kernel::plane_host::EngineTablesView as _;
        let out = scrape();
        let scraped = out
            .lines()
            .find(|l| l.starts_with("busbar_pool_queued{") && l.contains("pool=\"p\""))
            .and_then(|l| l.rsplit(' ').next()?.trim().parse::<f64>().ok());
        let tables = rig.app.config_tables.queued_depth("p") as f64;
        scraped.filter(|g| *g == tables)
    };
    let first = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.chat().await.0 })
    };
    while slow.served() < 1 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let second = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.chat().await.0 })
    };
    let mut parked = None;
    for _ in 0..100 {
        parked = gauge();
        if parked == Some(1.0) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        parked,
        Some(1.0),
        "busbar_pool_queued is the live park depth: one while parked"
    );
    assert_eq!(first.await.expect("the first"), 200);
    assert_eq!(
        second.await.expect("the queued one"),
        200,
        "served once a permit freed"
    );
    assert_eq!(
        gauge(),
        Some(0.0),
        "back to zero once the parked request left the queue"
    );
}

// ── the dialects, end to end ────────────────────────────────────────────────────────────────────

/// A RESPONSES REQUEST ROUND-TRIPS TO A MESSAGES-DIALECT FAR END: `/v1/responses` is served 2xx,
/// and the far end received a messages array.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_responses_ingress_to_anthropic_backend`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_responses_request_round_trips_through_a_messages_far_end() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-responses";
    let _published = Withdrawn(instance);
    let far = far_end_recording(Some(0), json_reply(200, MESSAGE)).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            dialect: Some("anthropic"),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send(
            "POST",
            "/v1/responses",
            Some(serde_json::json!({"model": "p", "input": "hello", "max_tokens": 16})),
        )
        .await;
    assert_eq!(
        status,
        200,
        "responses round-trips 2xx: {}",
        String::from_utf8_lossy(&body)
    );
    let upstream = far.body(0);
    assert!(
        upstream.get("messages").is_some(),
        "the far end received a messages array; got {upstream}"
    );
}

/// A MODEL REACHED BY NAME ON `/<model>/v1/messages` with no pool naming it is served: 2xx, and
/// the far end received the request.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_named_by_model_fallback_round_trip_via_router`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_model_named_in_the_path_with_no_pool_is_served() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-named-model";
    let _published = Withdrawn(instance);
    let (pooled, alone) = (
        far_end_answering(200, MESSAGE).await,
        far_end_recording(Some(0), json_reply(200, MESSAGE)).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(pooled.port, 1), (alone.port, 1)],
            pooled: Some(1),
            dialect: Some("anthropic"),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send(
            "POST",
            "/m1/v1/messages",
            Some(serde_json::json!({"model": "m1", "messages": [], "max_tokens": 16})),
        )
        .await;
    assert_eq!(
        status,
        200,
        "the model no pool names resolves and round-trips 2xx: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(
        alone.served(),
        1,
        "its far end received the forwarded request"
    );
    assert_eq!(pooled.served(), 0);
}

/// A PERCENT-ENCODED CONVERSE MODEL ID (`%3A`) is decoded, resolved and streamed back as a binary
/// event stream, end to end through the mounted door.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_bedrock_percent_encoded_model_id_converse_stream`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_percent_encoded_converse_model_is_decoded_and_streamed_as_an_event_stream() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-converse";
    let _published = Withdrawn(instance);
    let far = far_end_scripted(whole_stream()).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            // The DECODED, colon-bearing id: a correct decode is the only way it resolves.
            names: Some(&["anthropic.claude-3:haiku"]),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, head, body) = call(
        &rig,
        "POST",
        "/model/anthropic.claude-3%3Ahaiku/converse-stream",
        br#"{"messages": [{"role": "user", "content": [{"text": "hi"}]}]}"#,
        &[],
        true,
    )
    .await;
    assert_eq!(
        status,
        200,
        "the percent-encoded id decodes, resolves and round-trips 2xx: {}",
        String::from_utf8_lossy(&body)
    );
    let content_type = head
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("application/vnd.amazon.eventstream"),
        "a binary event stream; got {content_type}"
    );
    // Each frame: its total length and its headers' length (big-endian), the prelude's checksum,
    // the headers and the payload, the message's checksum.
    let (mut at, mut frames) = (0usize, 0usize);
    while at + 12 <= body.len() {
        let total = u32::from_be_bytes(body[at..at + 4].try_into().expect("four bytes")) as usize;
        assert!(
            total >= 16 && at + total <= body.len(),
            "frame {frames} is whole"
        );
        at += total;
        frames += 1;
    }
    assert!(frames >= 1, "at least one binary frame");
    assert_eq!(at, body.len(), "nothing but whole frames");
}

// ── the walk's bounds ───────────────────────────────────────────────────────────────────────────

/// AFTER THE FIRST BYTE THERE IS NO FAILOVER: the first member streams a real frame then its
/// connection dies; the caller sees that frame and then an in-band error frame in its own dialect,
/// the second member is never dialled, and the first member's lane records the failure.
///
/// Ports legacy `engine/tests/ingress_integration_tests.rs::test_real_mid_stream_failure_does_not_fail_over_to_second_member`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_cut_after_its_first_byte_is_not_failed_over() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-mid-stream";
    let _published = Withdrawn(instance);
    let first = far_end_scripted(Script {
        head: STREAM_HEAD.to_string(),
        pieces: vec![(
            0,
            frame(r#"{"choices":[{"delta":{"content":"MEMBER-1-REAL-FIRST-FRAME"}}]}"#),
        )],
        finish: None,
    })
    .await;
    let second = far_end_scripted(Script {
        head: STREAM_HEAD.to_string(),
        pieces: vec![(
            0,
            frame(r#"{"choices":[{"delta":{"content":"MEMBER-2-MUST-NEVER-APPEAR"}}]}"#),
        )],
        finish: Some(b"0\r\n\r\n".to_vec()),
    })
    .await;
    let rig = rig(
        instance,
        RigOpts {
            // The member that fails mid-stream weighs most, so it is tried first.
            members: &[(first.port, 100), (second.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let err_before = lane(&rig, 0).err;
    let (status, _, body) = rig
        .send("POST", "/v1/chat/completions", Some(streamed_chat()))
        .await;
    assert_eq!(
        status, 200,
        "the stream starts 2xx (member 1's real first byte)"
    );
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("MEMBER-1-REAL-FIRST-FRAME"),
        "member 1's first frame reached the caller:\n{text}"
    );
    assert!(
        !text.contains("MEMBER-2-MUST-NEVER-APPEAR"),
        "member 2 is never dispatched after the first byte:\n{text}"
    );
    let frames: Vec<&str> = text
        .split("\n\n")
        .filter(|f| !f.trim().is_empty())
        .collect();
    let last = frames
        .last()
        .and_then(|f| f.lines().find_map(|l| l.strip_prefix("data: ")))
        .expect("a trailing data: error frame");
    let error: serde_json::Value = serde_json::from_str(last).expect("a JSON envelope");
    assert!(
        error.get("error").is_some(),
        "the in-band terminal frame is the dialect's error envelope; got {error}"
    );
    assert_eq!(second.served(), 0, "member 2 was never dialled");
    let mut err_after = lane(&rig, 0).err;
    for _ in 0..100 {
        if err_after > err_before {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        err_after = lane(&rig, 0).err;
    }
    assert_eq!(
        err_after,
        err_before + 1,
        "member 1's lane records exactly one mid-stream failure"
    );
}

/// A BOUNDED POOL UNDER A CONCURRENT BURST DOES NOT SERIALIZE: its one member at capacity, a burst
/// of requests all spill in parallel to the overflow pool (which serves every one), and the busy
/// member serves none of them.
///
/// Ports legacy `engine/tests/on_exhausted_tests.rs::at_capacity_bounded_burst_all_spill_not_serialized`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_on_a_saturated_pool_all_spills_to_its_overflow_in_parallel() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-burst-spill";
    let _published = Withdrawn(instance);
    let slow = far_end_recording(Some(10_000), json_reply(200, SERVED)).await;
    let fast = far_end_answering(200, SERVED_BY_TWIN).await;
    let rig = Arc::new(
        rig(
            instance,
            RigOpts {
                members: &[(slow.port, 1), (fast.port, 1)],
                pooled: Some(1),
                model_yaml: &[(0, "max_concurrent: 1"), (1, "max_concurrent: 20")],
                pool_yaml: Some("on_exhausted: {fallback_pool: overflow}"),
                pools: &[("overflow", &[1], "")],
                ..RigOpts::default()
            },
        )
        .await,
    );
    // The one bounded slot, taken and held by a request its far end does not answer for ten
    // seconds.
    let holder = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.chat().await })
    };
    while slow.served() < 1 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let n = 4usize;
    let started = std::time::Instant::now();
    let burst = futures::future::join_all((0..n).map(|_| rig.chat())).await;
    for (status, _, body) in &burst {
        assert_eq!(
            *status,
            200,
            "every request in the burst is served by the overflow pool, not queued: {}",
            String::from_utf8_lossy(body)
        );
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "spilled in parallel, never behind the busy slot: {:?}",
        started.elapsed()
    );
    assert_eq!(fast.served(), n, "all {n} spilled to the overflow member");
    assert_eq!(lane(&rig, 1).ok, n as u64);
    assert_eq!(
        lane(&rig, 0).ok,
        0,
        "the single saturated slot served none of them (no serialization)"
    );
    assert_eq!(
        slow.served(),
        1,
        "only the holder ever reached the busy member"
    );
    holder.abort();
}

/// A slow far end (answers after a second and a half) and its fast twin, for the attempt caps.
async fn slow_and_fast() -> (Recording, super::hook_seat_tests::FarEnd) {
    (
        far_end_recording(Some(1_500), json_reply(200, SERVED)).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    )
}

/// One chat on pool `p` over the slow member (tried first) and its twin: who answered, and how
/// long the caller waited.
async fn chat_timed(rig: &DoorRig) -> (u16, String, std::time::Duration) {
    let started = std::time::Instant::now();
    let (status, _, body) = rig.chat().await;
    (
        status,
        String::from_utf8_lossy(&body).to_string(),
        started.elapsed(),
    )
}

/// THE POOL MEMBER'S `attempt_timeout_ms` BEATS THE MODEL'S: the same model capped at ten seconds
/// on its own is capped at 50ms as this pool's member, so its slow answer is cut and the twin
/// serves.
///
/// Ports legacy `engine/tests/attempt_timeout_precedence_tests.rs::test_member_override_wins_over_model_default`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_members_attempt_cap_beats_its_models() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-attempt-member";
    let _published = Withdrawn(instance);
    let (slow, fast) = slow_and_fast().await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(slow.port, 100), (fast.port, 1)],
            model_yaml: &[(0, "attempt_timeout_ms: 10000")],
            member_yaml: &[(0, "attempt_timeout_ms: 50")],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, body, waited) = chat_timed(&rig).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("served-by-the-twin"),
        "the member's 50ms cap cut the slow attempt: {body}"
    );
    assert!(
        waited < std::time::Duration::from_millis(1_400),
        "{waited:?}"
    );
    assert_eq!(slow.served(), 1, "the slow member was tried first");
}

/// A POOL MEMBER WITH NO OVERRIDE INHERITS ITS MODEL'S `attempt_timeout_ms`.
///
/// Ports legacy `engine/tests/attempt_timeout_precedence_tests.rs::test_model_default_applies_when_member_has_no_override`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_member_without_a_cap_inherits_its_models() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-attempt-model";
    let _published = Withdrawn(instance);
    let (slow, fast) = slow_and_fast().await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(slow.port, 100), (fast.port, 1)],
            model_yaml: &[(0, "attempt_timeout_ms: 300")],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, body, waited) = chat_timed(&rig).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("served-by-the-twin"),
        "the model's 300ms cap cut the slow attempt: {body}"
    );
    assert!(
        waited < std::time::Duration::from_millis(1_400),
        "{waited:?}"
    );
    assert_eq!(slow.served(), 1);
}

/// NEITHER THE MEMBER NOR ITS MODEL CAPS THE ATTEMPT: it runs uncapped, so the slow member's answer
/// is the caller's and its twin is never dialled.
///
/// Ports legacy `engine/tests/attempt_timeout_precedence_tests.rs::test_no_cap_anywhere_is_none`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_attempt_neither_member_nor_model_caps_is_uncapped() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-attempt-none";
    let _published = Withdrawn(instance);
    let (slow, fast) = slow_and_fast().await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(slow.port, 100), (fast.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, body, _) = chat_timed(&rig).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("served-by-the-first"),
        "uncapped: the slow member's own answer: {body}"
    );
    assert_eq!(fast.served(), 0);
}

/// A MODEL ROUTED DIRECTLY (no pool member row) TAKES ITS MODEL-LEVEL CAP ALONE: capped, its slow
/// answer is cut and the caller is refused at once; uncapped, the slow answer is the caller's.
///
/// Ports legacy `engine/tests/attempt_timeout_precedence_tests.rs::test_empty_cands_uses_model_default`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_directly_routed_model_takes_its_model_level_cap() {
    let _one = ONE_PUBLISHER.lock().await;
    let capped = {
        let instance = "serve-door-ported-attempt-direct";
        let _published = Withdrawn(instance);
        let slow = far_end_recording(Some(1_500), json_reply(200, SERVED)).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(slow.port, 1)],
                model_yaml: &[(0, "attempt_timeout_ms: 300")],
                ..RigOpts::default()
            },
        )
        .await;
        let started = std::time::Instant::now();
        let (status, _, _) = rig
            .send("POST", "/v1/chat/completions", Some(chat_on("m0")))
            .await;
        (status, started.elapsed(), slow.served())
    };
    assert!(
        capped.0 >= 500,
        "the cut attempt is the caller's upstream failure: {capped:?}"
    );
    assert!(
        capped.1 < std::time::Duration::from_millis(1_400),
        "cut at the model's 300ms: {capped:?}"
    );
    assert_eq!(capped.2, 1);
    let instance = "serve-door-ported-attempt-direct-uncapped";
    let _published = Withdrawn(instance);
    let slow = far_end_recording(Some(1_500), json_reply(200, SERVED)).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(slow.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send("POST", "/v1/chat/completions", Some(chat_on("m0")))
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
}

/// One black-holed streamed request under `secs` of `limits.upstream_request_timeout_secs`: how
/// long the caller waited, and its status.
async fn cut_after(instance: &'static str, secs: u64) -> (u16, std::time::Duration) {
    let _published = Withdrawn(instance);
    let hole = far_end_recording(None, String::new()).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(hole.port, 1)],
            upstream_request_timeout_secs: Some(secs),
            ..RigOpts::default()
        },
    )
    .await;
    let started = std::time::Instant::now();
    let (status, _, _) = tokio::time::timeout(
        std::time::Duration::from_secs(secs + 30),
        rig.send("POST", "/v1/chat/completions", Some(streamed_chat())),
    )
    .await
    .expect("a black-holed stream resolves at its deadline, never hangs");
    (status, started.elapsed())
}

/// A PROXIED STREAM IS CUT BY ONE TIMER, AND IT IS THE OPERATOR'S: a black-holed streamed request
/// is cut at exactly `limits.upstream_request_timeout_secs` (seven seconds, then twenty-three), as
/// an upstream failure; nothing counting idle time cuts it earlier.
///
/// Ports legacy `engine/engine_tests/stream_deadline_tests.rs::a_proxied_stream_is_cut_at_the_configured_second_and_by_nothing_earlier`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_black_holed_stream_is_cut_at_the_configured_second_and_no_earlier() {
    let _one = ONE_PUBLISHER.lock().await;
    let slack = std::time::Duration::from_millis(1_500);
    for (instance, secs) in [
        ("serve-door-ported-deadline-7", 7u64),
        ("serve-door-ported-deadline-23", 23),
    ] {
        let (status, waited) = cut_after(instance, secs).await;
        let configured = std::time::Duration::from_secs(secs);
        assert!(
            (500..600).contains(&status),
            "a cut stream is an upstream failure, got {status}"
        );
        assert!(
            waited >= configured && waited < configured + slack,
            "cut at the configured {secs}s and by nothing earlier: {waited:?}"
        );
    }
}

// ── the unit's principal ────────────────────────────────────────────────────────────────────────

/// THE KEYS ARM: a keyed unit's principal is the resolved key's id, and its sealed record says so.
///
/// Ports legacy `unit/tests/authenticate.rs::the_keys_arm_names_the_resolved_key_and_the_live_read_names_it_too`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_keyed_unit_is_attributed_to_its_resolved_key() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-principal-keyed";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.chat().await.0, 200);
    let records = sealed_after(&rig, 1).await;
    assert_eq!(
        records.last().expect("the unit's record").subject,
        Subject::PrincipalId(rig.key_id.clone())
    );
}

/// THE OPEN ARM: on an open front door an unkeyed unit is attributed to the anonymous actor, the
/// word `AuthPrincipal(None).actor_id()` names.
///
/// Ports legacy `unit/tests/authenticate.rs::the_open_arm_names_the_same_anonymous_actor_the_live_attribution_names`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unkeyed_unit_on_an_open_door_is_attributed_to_the_anonymous_actor() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-principal-open";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            open: true,
            ..RigOpts::default()
        },
    )
    .await;
    let body = serde_json::to_vec(&chat_on("p")).expect("json");
    let (status, _, answer) = call(&rig, "POST", "/v1/chat/completions", &body, &[], false).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&answer));
    let anonymous = busbar_contract::auth::AuthPrincipal(None)
        .actor_id()
        .to_string();
    assert_eq!(anonymous, "anonymous");
    let records = sealed_after(&rig, 1).await;
    assert_eq!(
        records.last().expect("the unit's record").subject,
        Subject::PrincipalId(anonymous)
    );
}

// ── how a unit's end is sealed ──────────────────────────────────────────────────────────────────

/// The streamed far ends whose end only the relay can name: a cut after one frame, and a transfer
/// that failed after its 2xx head before a single byte.
fn cut_after_one_frame() -> Script {
    Script {
        head: STREAM_HEAD.to_string(),
        pieces: vec![(0, frame(FRAMES[0]))],
        finish: None,
    }
}

fn failed_before_a_byte() -> Script {
    Script {
        head: STREAM_HEAD.to_string(),
        pieces: Vec::new(),
        finish: None,
    }
}

/// One streamed chat over a far end answering by `script`: the caller's status, the sealed finish
/// class of its record, and the tokens billed.
async fn streamed_end(instance: &'static str, script: Script) -> (u16, FinishClass, u64) {
    let _published = Withdrawn(instance);
    let far = far_end_scripted(script).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, _) = rig
        .send("POST", "/v1/chat/completions", Some(streamed_chat()))
        .await;
    let records = sealed_after(&rig, 1).await;
    let finish = records.last().expect("the unit's record").outcome.finish;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let tokens = rig.tokens_after().await;
    (status, finish, tokens)
}

/// THE RELAY REPORTS THE END A STATUS LINE CANNOT: a stream cut after one frame and a transfer that
/// failed before its first byte both go out on 2xx heads, yet the cut seals `Partial` and the
/// failed transfer `Error`; neither streamed a usage frame, so neither bills a token.
///
/// Ports legacy `unit/tests/chain.rs::the_tap_reports_the_end_a_status_line_cannot`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cut_stream_seals_partial_and_a_failed_transfer_error_billing_nothing() {
    let _one = ONE_PUBLISHER.lock().await;
    let (status, finish, tokens) =
        streamed_end("serve-door-ported-tap-cut", cut_after_one_frame()).await;
    assert_eq!(status, 200, "the cut stream went out on a 2xx head");
    assert_eq!(
        finish,
        FinishClass::Partial,
        "the cut names the end it reached"
    );
    assert_eq!(tokens, 0, "no usage frame streamed before the cut");
    let (status, finish, tokens) =
        streamed_end("serve-door-ported-tap-failed", failed_before_a_byte()).await;
    assert_eq!(status, 200, "the failed transfer went out on a 2xx head");
    assert_eq!(
        finish,
        FinishClass::Error,
        "nothing was delivered: an error"
    );
    assert_eq!(tokens, 0, "nothing streamed, nothing billed");
}

/// A STREAM AUDITED AT ITS END SEALS THE CLASS ITS RELAY REPORTED, never the `Complete` its 2xx
/// status line says: whole `Complete`, cut `Partial`, failed transfer `Error`.
///
/// Ports legacy `unit/tests/chain.rs::a_stream_audited_at_its_end_seals_the_class_the_tap_reported`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stream_sealed_at_its_end_seals_the_class_its_relay_reported() {
    let _one = ONE_PUBLISHER.lock().await;
    for (instance, script, want) in [
        (
            "serve-door-ported-sealed-whole",
            whole_stream(),
            FinishClass::Complete,
        ),
        (
            "serve-door-ported-sealed-cut",
            cut_after_one_frame(),
            FinishClass::Partial,
        ),
        (
            "serve-door-ported-sealed-failed",
            failed_before_a_byte(),
            FinishClass::Error,
        ),
    ] {
        let (status, finish, _) = streamed_end(instance, script).await;
        assert_eq!(status, 200, "{want:?}: every one is served on a 2xx head");
        assert_eq!(finish, want);
    }
}

/// THE SEALED END IS THE RELAY'S WHERE THERE IS ONE, THE STATUS'S WHERE THERE IS NOT: streamed
/// answers seal what their relay reported (whole `Complete`, cut `Partial`, failed `Error`); a
/// buffered 2xx seals `Complete` and a relayed 502 `Error`; nothing ever seals `TurnComplete`.
///
/// Ports legacy `unit/tests/audit.rs::the_sealed_end_is_the_taps_where_there_is_one_and_the_status_where_there_is_not`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sealed_end_is_the_relays_where_there_is_one_and_the_statuss_where_not() {
    let _one = ONE_PUBLISHER.lock().await;
    for (instance, script, want) in [
        (
            "serve-door-ported-end-whole",
            whole_stream(),
            FinishClass::Complete,
        ),
        (
            "serve-door-ported-end-cut",
            cut_after_one_frame(),
            FinishClass::Partial,
        ),
        (
            "serve-door-ported-end-failed",
            failed_before_a_byte(),
            FinishClass::Error,
        ),
    ] {
        let (_, finish, _) = streamed_end(instance, script).await;
        assert_eq!(finish, want);
        assert_ne!(finish, FinishClass::TurnComplete);
    }
    for (instance, status, body, want) in [
        (
            "serve-door-ported-end-buffered",
            200,
            SERVED,
            FinishClass::Complete,
        ),
        (
            "serve-door-ported-end-502",
            502,
            r#"{"error":{"message":"no","type":"server_error"}}"#,
            FinishClass::Error,
        ),
    ] {
        let _published = Withdrawn(instance);
        let far = far_end_answering(status, body).await;
        let rig = rig(
            instance,
            RigOpts {
                members: &[(far.port, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let _ = rig.chat().await;
        let records = sealed_after(&rig, 1).await;
        let finish = records.last().expect("the unit's record").outcome.finish;
        assert_eq!(finish, want, "no relay report: the status's class");
        assert_ne!(finish, FinishClass::TurnComplete);
    }
}

// ── a config apply ──────────────────────────────────────────────────────────────────────────────

/// A CONFIG APPLY of the rig's door onto a deployment of `members` (each a model `m<i>` on a
/// provider of its own, all in pool `p`), as production's apply hook takes it: the new sections,
/// providers and pools, over the boot's connector, auth plugins and journal, the stream ceiling
/// re-read as `upstream_secs`. The generation the door serves after it.
fn apply(rig: &DoorRig, instance: &str, members: &[u16], upstream_secs: u64) -> u64 {
    let key_file = std::env::temp_dir().join(format!(
        "busbar-door-ported-apply-{}-{instance}",
        std::process::id()
    ));
    std::fs::write(&key_file, "sk-seats").expect("the credential file");
    let mut yaml = String::from("providers:\n");
    for i in 0..members.len() {
        yaml.push_str(&format!(
            "  oai{i}:\n    api_key: {{ file: '{}' }}\n",
            key_file.display()
        ));
    }
    yaml.push_str("models:\n");
    for i in 0..members.len() {
        yaml.push_str(&format!("  m{i}:\n    provider: oai{i}\n"));
    }
    yaml.push_str("pools:\n  p:\n    members:\n");
    for i in 0..members.len() {
        yaml.push_str(&format!("      - model: m{i}\n        weight: 1\n"));
    }
    let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("a deployment");
    let defs: std::collections::HashMap<String, busbar_kernel::config::ProviderDef> =
        serde_yaml::from_str(
            &members
                .iter()
                .enumerate()
                .map(|(i, port)| {
                    format!("oai{i}:\n  protocol: openai\n  base_url: 'http://127.0.0.1:{port}'\n")
                })
                .collect::<String>(),
        )
        .expect("the providers");
    let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
    let providers = crate::root::door_steps::provider_routes(&cfg.providers);
    let sections = crate::root::door_steps::kernel_sections(&cfg);
    let models = crate::root::model_egress::ModelServing {
        pools: crate::root::model_egress::ModelPools::of(&cfg),
        lanes: (0..members.len()).map(|i| (format!("m{i}"), i)).collect(),
        app: {
            let app = Arc::clone(&rig.app);
            Arc::new(move || Arc::clone(&app))
        },
    };
    let secrets = busbar_kernel::config::secret::SecretResolver::builtins_only();
    let reach = crate::root::door_steps::DoorReach {
        providers: &providers,
        secrets: &secrets,
        auths: Arc::clone(&rig.auths),
        conns: Arc::clone(&rig.conns),
        stream_ceiling_secs: upstream_secs,
        models: Some(&models),
        upgrades: Vec::new(),
    };
    rig.appliers.refresh_models(
        &sections,
        &super::DoorEgress {
            reach: &reach,
            journal: Arc::clone(&rig.journal),
        },
    );
    // The credential is read when the egress is sealed, inside the refresh.
    let _ = std::fs::remove_file(&key_file);
    rig.appliers.0[0].current().generation
}

/// The probe schedule the rig's door shares across its generations.
fn probe_schedule(rig: &DoorRig) -> Arc<busbar_kernel::probe::ProbeSchedule> {
    let probes = rig.appliers.0[0]
        .probes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(&probes.1)
}

/// AN APPLY THAT KEEPS THE MEMBER SET CARRIES THE PROBE SCHEDULE (the same one), so a mutation
/// cadence faster than the probe interval never resets probing before its first tick.
///
/// Ports legacy `engine/tests/runtime_carry_tests.rs::a_rebuild_carries_the_probe_schedule` (its
/// carry half).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_apply_over_the_same_members_carries_the_probe_schedule() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-probe-carry";
    let _published = Withdrawn(instance);
    let (a, b) = (
        far_end_answering(200, SERVED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(a.port, 1), (b.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let before = (probe_schedule(&rig), rig.appliers.0[0].current().generation);
    let after = apply(&rig, instance, &[a.port, b.port], 600);
    assert_eq!(after, before.1 + 1, "the apply sealed a new generation");
    assert!(
        Arc::ptr_eq(&before.0, &probe_schedule(&rig)),
        "an unchanged member set carries the probe schedule across the apply"
    );
    assert_eq!(rig.chat().await.0, 200, "and the new generation serves");
}

/// AN APPLY THAT REMOVES A MEMBER MINTS A FRESH PROBE SCHEDULE: its deadlines are kept by member
/// index, and after the change an index names another member.
///
/// Ports legacy `engine/tests/runtime_carry_tests.rs::a_rebuild_carries_the_probe_schedule` (its
/// changed-member-set half).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_apply_that_changes_the_members_mints_a_fresh_probe_schedule() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-probe-fresh";
    let _published = Withdrawn(instance);
    let (a, b) = (
        far_end_answering(200, SERVED).await,
        far_end_answering(200, SERVED_BY_TWIN).await,
    );
    let rig = rig(
        instance,
        RigOpts {
            members: &[(a.port, 1), (b.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let before = (probe_schedule(&rig), rig.appliers.0[0].current().generation);
    let after = apply(&rig, instance, &[a.port], 600);
    assert_eq!(after, before.1 + 1, "the apply sealed a new generation");
    assert!(
        !Arc::ptr_eq(&before.0, &probe_schedule(&rig)),
        "a member-set change must not carry the probe schedule"
    );
}

/// AN APPLY THAT CHANGES NOTHING THE CLIENT READS REUSES ITS WARM CONNECTIONS: the new generation's
/// egress dials through the same connector.
///
/// Ports legacy `engine/tests/runtime_carry_tests.rs::a_changed_upstream_timeout_rebuilds_the_client_an_unrelated_apply_reuses_it`
/// (its reuse half).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrelated_apply_reuses_the_warm_connector() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-client-reuse";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let generation = rig.appliers.0[0].current().generation;
    assert_eq!(apply(&rig, instance, &[far.port], 600), generation + 1);
    let live = rig.appliers.0[0].current();
    let egress = live.egress.as_ref().expect("the new generation's egress");
    assert_eq!(
        Arc::as_ptr(&egress.conns).cast::<()>(),
        Arc::as_ptr(&rig.conns).cast::<()>(),
        "the apply reuses the connector and its warm pool"
    );
    assert_eq!(rig.chat().await.0, 200);
}

// retired: v1.5.5 main.rs:3128-3130 reused the client on every apply; upstream_request_timeout_secs is restart-to-apply (ARCHITECT RULING U11 Q4 2026-10-06)

// ── the kernel router's served-traffic tests, on the door ───────────────────────────────────────

/// A STORED `expires_at` IN THE PAST IS NOT ENFORCED ON THE DATA PLANE: the key row is rewritten
/// with an expiry a month gone, the caches reloaded, and the caller's token (its own `exp` still in
/// the future) is still admitted; a token that is not a key's is refused on the same door, so the
/// admission is a real gate. Measured on the published 1.5.5 and on the release binary: both 200.
///
/// Ports kernel `tests/key_expires_at_cross_plane.rs::a_key_row_whose_expires_at_is_in_the_past_is_admitted_on_the_data_plane`
/// (it drove the model plane through the kernel router, which no longer serves it).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_row_whose_expires_at_is_in_the_past_is_admitted_on_the_door() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-row-expiry";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let gov = rig
        .app
        .governance
        .clone()
        .expect("the rig keeps a governance book");
    let store = gov.store();
    let mut row = store
        .get_key(&rig.key_id)
        .expect("store read")
        .expect("the minted row");
    assert_eq!(
        row.expires_at, None,
        "mint never stamps expires_at; it is a stored field nothing in the engine writes"
    );
    row.expires_at = Some(busbar_kernel::store::now() - 30 * 86_400);
    store.put_key(&row).expect("rewrite the row");
    gov.refresh().expect("reload caches");
    let (status, _, body) = rig.chat().await;
    assert_eq!(
        status,
        200,
        "a key row with a past expires_at is still admitted (1.5.5 never enforced it; measured): {}",
        String::from_utf8_lossy(&body)
    );
    let chat = serde_json::to_vec(&chat_on("p")).expect("json");
    let (status, _, _) = call(
        &rig,
        "POST",
        "/v1/chat/completions",
        &chat,
        &[("authorization", "Bearer bbk_not_a_real_token")],
        false,
    )
    .await;
    assert_eq!(
        status, 401,
        "the keys chain is a real gate on this door: a bad token is refused"
    );
    assert_eq!(
        far.served(),
        1,
        "only the admitted unit reached the far end"
    );
}

/// The words an alarm or a disputes-report entry would carry, matched case-insensitively.
const ALARM_MARKERS: &[&str] = &["alarm", "dispute"];

fn mentions_an_alarm_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    ALARM_MARKERS.iter().any(|m| lower.contains(m))
}

/// The metric name of one exposition line: the token before `{` or the first space on a sample
/// line, or the second token of a `# HELP` / `# TYPE` line.
fn exposition_metric_name(line: &str) -> Option<&str> {
    if let Some(rest) = line.strip_prefix("# ") {
        let mut it = rest.split_whitespace();
        let _kind = it.next()?;
        return it.next();
    }
    let end = line.find(['{', ' ']).unwrap_or(line.len());
    let name = &line[..end];
    (!name.is_empty()).then_some(name)
}

/// AN ALARM AND A DISPUTES-REPORT ENTRY ARE LEDGER-ENDPOINT ROWS ONLY: on a 1.5.5-shaped deployment
/// (no ledger, no data dir) a request lifecycle through the door (a served unit, a unit whose only
/// member is unreachable, the liveness probe, `/stats`) emits no tracing event at DEBUG or above and
/// no metric name that mentions an alarm or a dispute. On the single-threaded runtime, so every
/// event the lifecycle raises is on the capturing thread.
///
/// Ports kernel `tests/alarm_silence_cross_plane.rs::a_1_5_5_request_lifecycle_emits_no_alarm_or_dispute_event_or_metric`
/// (it drove the model plane through the kernel router, which no longer serves it).
#[tokio::test(flavor = "current_thread")]
async fn a_1_5_5_request_lifecycle_emits_no_alarm_or_dispute_event_or_metric() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-alarm-silence";
    let _published = Withdrawn(instance);
    let cap = busbar_kernel::test_support::warn_capture::WarnCapture::capturing_debug();
    let _capturing = {
        use tracing_subscriber::layer::SubscriberExt as _;
        tracing::subscriber::set_default(tracing_subscriber::registry().with(cap.clone()))
    };
    let far = far_end_answering(200, SERVED).await;
    // Pool `p` holds the live member; pool `q` holds one at a closed port, so its unit fails upstream
    // — the path a stall or lane alarm would ride.
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1), (1, 1)],
            pooled: Some(1),
            pools: &[("q", &[1], "")],
            ..RigOpts::default()
        },
    )
    .await;
    let mut statuses: Vec<(&str, u16)> = Vec::new();
    statuses.push((
        "ok request",
        rig.send("POST", "/v1/chat/completions", Some(chat_on("p")))
            .await
            .0,
    ));
    statuses.push((
        "failed-upstream request",
        rig.send("POST", "/v1/chat/completions", Some(chat_on("q")))
            .await
            .0,
    ));
    statuses.push((
        "healthz",
        call(&rig, "GET", "/healthz", b"", &[], false).await.0,
    ));
    statuses.push(("stats", call(&rig, "GET", "/stats", b"", &[], true).await.0));
    let status_of = |what: &str| {
        statuses
            .iter()
            .find(|(w, _)| *w == what)
            .map(|(_, s)| *s)
            .expect("driven")
    };
    assert_eq!(status_of("ok request"), 200, "statuses: {statuses:?}");
    assert_ne!(
        status_of("failed-upstream request"),
        200,
        "statuses: {statuses:?}"
    );
    assert_eq!(status_of("healthz"), 200, "statuses: {statuses:?}");

    let hits: Vec<String> = cap
        .messages()
        .into_iter()
        .filter(|m| mentions_an_alarm_marker(m))
        .collect();
    assert!(
        hits.is_empty(),
        "no tracing event may carry an alarm/dispute message or field on a 1.5.5-shaped \
         deployment; found:\n{}",
        hits.join("\n")
    );
    let exposition = scrape();
    let leaked: Vec<&str> = exposition
        .lines()
        .filter_map(exposition_metric_name)
        .filter(|n| mentions_an_alarm_marker(n))
        .collect();
    assert!(
        leaked.is_empty(),
        "no metric name may mention an alarm or a dispute on a 1.5.5-shaped deployment; found: \
         {leaked:?}"
    );
}
