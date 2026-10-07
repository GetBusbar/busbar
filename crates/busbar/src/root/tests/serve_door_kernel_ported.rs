// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PREVIOUS RELEASE'S ENGINE TESTS WHOSE BEHAVIOUR THE KERNEL OWNS, ON THE DOOR: the ones a
//! kernel unit test cannot express, driven end to end through the door serving the `pools` map
//! (`super::hook_seat_tests::rig`: a keyed caller behind the data listener's auth gate, the
//! kernel's walk, the process connector and real loopback far ends). What the old test read off an
//! upstream mock is read here off the far end the connector dialled; what it read off the
//! response is read off the router's answer.
//!
//! Each test names the legacy test it carries over and keeps that test's inputs and expected
//! statuses and bytes; only the harness is new.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::hook_seat_tests::{far_end_answering, far_end_scripted, rig, RigOpts, Script};
use super::planes_tests::{Published as Withdrawn, PUBLISHING as ONE_PUBLISHER};
use crate::root::loader::dispatch::kinds::plane::Plane;
use crate::root::loader::dispatch::{
    load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};

/// The far end's answer: a chat completion.
const ANSWER: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

fn chat_body() -> serde_json::Value {
    serde_json::json!({"model": "p", "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}]})
}

/// One request through `router` with exactly these fields (no caller credential added).
async fn send_with(
    router: &axum::Router,
    path: &str,
    fields: &[(&str, &str)],
    body: Vec<u8>,
) -> (u16, axum::http::HeaderMap, Vec<u8>) {
    use tower::ServiceExt as _;
    let mut req = axum::http::Request::builder().method("POST").uri(path);
    for (name, value) in fields {
        req = req.header(*name, *value);
    }
    let response = router
        .clone()
        .oneshot(req.body(axum::body::Body::from(body)).expect("a request"))
        .await
        .expect("the router answers");
    let status = response.status().as_u16();
    let head = response.headers().clone();
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20)
        .await
        .expect("the body")
        .to_vec();
    (status, head, bytes)
}

/// A far end on loopback answering every request with [`ANSWER`], keeping each request's head as
/// it arrived on the wire, one `(name, value)` per line, names lower-cased.
async fn far_end_keeping_heads() -> (u16, Arc<Mutex<Vec<Vec<(String, String)>>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let heads = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&heads);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let kept = Arc::clone(&kept);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut got = Vec::new();
                let head = loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&got).to_string();
                    if let Some(at) = text.find("\r\n\r\n") {
                        let fields: Vec<(String, String)> = text[..at]
                            .lines()
                            .skip(1)
                            .filter_map(|l| {
                                let (n, v) = l.split_once(':')?;
                                Some((n.trim().to_ascii_lowercase(), v.trim().to_string()))
                            })
                            .collect();
                        let length = fields
                            .iter()
                            .find(|(n, _)| n == "content-length")
                            .and_then(|(_, v)| v.parse::<usize>().ok())
                            .unwrap_or(0);
                        if got.len() >= at + 4 + length {
                            break fields;
                        }
                    }
                };
                kept.lock().unwrap().push(head);
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{ANSWER}",
                    ANSWER.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, heads)
}

/// Ports legacy `egress_differential_tests.rs::redirects_surface_verbatim_and_are_followed_by_neither_stack`:
/// a far end that answers 3xx is never followed: the exchange with it is the only one, and the
/// address its `Location` names is never reached (a follow would be an unguarded second hop).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_far_ends_redirect_is_never_followed() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-redirect";
    let _published = Withdrawn(instance);
    let target = far_end_answering(200, ANSWER).await;
    let location = format!("http://127.0.0.1:{}/metadata", target.port);
    let redirecting = far_end_scripted(Script {
        head: format!(
            "HTTP/1.1 302 Found\r\nlocation: {location}\r\ncontent-length: 0\r\n\
             connection: close\r\n\r\n"
        ),
        pieces: Vec::new(),
        finish: Some(Vec::new()),
    })
    .await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(redirecting.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, head, _) = rig.chat().await;
    assert_eq!(
        redirecting.served(),
        1,
        "exactly one exchange with the redirecting far end"
    );
    assert_eq!(
        target.served(),
        0,
        "the Location was never followed: no second exchange reached it"
    );
    // The 3xx is not the member's fault and is not followed: it is relayed as it came, its
    // Location verbatim.
    assert_eq!(
        status, 302,
        "the far end's redirect is surfaced, not followed"
    );
    assert_eq!(
        head.get("location").and_then(|v| v.to_str().ok()),
        Some(location.as_str()),
        "the surfaced redirect carries its Location verbatim"
    );
}

/// One chat completion through a fresh rig whose one member is a far end that keeps every head it
/// is sent, with `fields` beside the caller's own; the one head the far end received.
async fn head_the_far_end_received(
    instance: &'static str,
    fields: &[(&str, &str)],
) -> Vec<(String, String)> {
    let (port, heads) = far_end_keeping_heads().await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let response = rig
        .open("POST", "/v1/chat/completions", Some(chat_body()), fields)
        .await;
    assert_eq!(response.status().as_u16(), 200);
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "one request reached the far end");
    heads.into_iter().next().unwrap_or_default()
}

fn field_of(head: &[(String, String)], name: &str) -> Option<String> {
    head.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone())
}

/// Ports legacy `client_header_forwarding_tests.rs::hop_by_hop_host_and_length_are_re_derived`
/// (its fixed fields): the caller's hop-by-hop fields, `host` and `content-length` never reach the
/// far end, which gets the ones its own connection derives; any other field the caller sent passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_callers_per_connection_fields_never_reach_the_far_end() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-hop-by-hop";
    let _published = Withdrawn(instance);
    let head = head_the_far_end_received(
        instance,
        &[
            ("connection", "keep-alive"),
            ("keep-alive", "timeout=5"),
            ("te", "trailers"),
            ("upgrade", "websocket"),
            ("proxy-authorization", "Basic Zm9v"),
            ("host", "client.example"),
            ("content-length", "9999"),
            ("x-client-trace", "abc"),
        ],
    )
    .await;
    for gone in ["keep-alive", "te", "upgrade", "proxy-authorization"] {
        assert_eq!(field_of(&head, gone), None, "{gone} is per-connection");
    }
    assert_ne!(field_of(&head, "host").as_deref(), Some("client.example"));
    assert_ne!(
        field_of(&head, "content-length").as_deref(),
        Some("9999"),
        "the length is the far request's own"
    );
    assert_eq!(field_of(&head, "x-client-trace").as_deref(), Some("abc"));
}

/// Ports legacy `client_header_forwarding_tests.rs::hop_by_hop_host_and_length_are_re_derived`
/// (its nominated field): a field the caller's `connection` field nominates is per-connection too
/// and never reaches the far end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_field_the_callers_connection_nominates_never_reaches_the_far_end() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-nominated";
    let _published = Withdrawn(instance);
    let head = head_the_far_end_received(
        instance,
        &[
            ("connection", "keep-alive, x-nominated"),
            ("x-nominated", "1"),
            ("x-client-trace", "abc"),
        ],
    )
    .await;
    assert_eq!(
        field_of(&head, "x-nominated"),
        None,
        "x-nominated is per-connection"
    );
    assert_eq!(field_of(&head, "x-client-trace").as_deref(), Some("abc"));
}

/// Ports legacy `auth_dispatch_tests.rs::test_governance_accepts_vendor_carriers_and_native_401`:
/// under the keys verifier a virtual key presented in a vendor SDK's carrier (`x-goog-api-key`,
/// `x-api-key`) resolves like a bearer token; an unknown key in one is the native JSON 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_virtual_key_in_a_vendor_carrier_is_admitted_and_a_wrong_one_is_the_native_401() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-carriers";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let body = || chat_body().to_string().into_bytes();
    for carrier in ["x-goog-api-key", "x-api-key"] {
        let (status, _, bytes) = send_with(
            &rig.router,
            "/v1/chat/completions",
            &[(carrier, &rig.token), ("content-type", "application/json")],
            body(),
        )
        .await;
        assert_eq!(
            status,
            200,
            "a valid virtual key via {carrier} passes the gate: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    assert_eq!(
        far.served(),
        2,
        "both admitted requests reached the far end"
    );

    let (status, head, _) = send_with(
        &rig.router,
        "/v1/chat/completions",
        &[
            ("x-goog-api-key", "sk-vk-nope"),
            ("content-type", "application/json"),
        ],
        body(),
    )
    .await;
    assert_eq!(
        status, 401,
        "an unknown virtual key via x-goog-api-key is 401"
    );
    assert_eq!(
        head.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/json"),
        "the 401 carries the native JSON envelope, not text/plain"
    );
    assert_eq!(far.served(), 2, "the refused request reached nothing");
}

/// Ports legacy `auth_native_envelope_tests.rs::test_admin_prefix_is_boundary_safe`: a path that
/// merely starts with the bytes `/api` (`/apix/...`) is the data plane, not the admin branch: a
/// wrong credential there is the normal native 401 of the dialect its suffix names, never an admin
/// refusal or a 500.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_that_only_starts_with_api_is_the_data_plane() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-apix";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let body = serde_json::json!({"model": "apix", "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 16})
    .to_string()
    .into_bytes();
    let (status, head, bytes) = send_with(
        &rig.router,
        "/apix/v1/messages",
        &[("x-api-key", "wrong-token")],
        body,
    )
    .await;
    assert_eq!(
        status, 401,
        "an /apix path with a wrong credential is a normal 401, not a 500 or an admin refusal"
    );
    assert_eq!(
        head.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON envelope");
    assert_eq!(
        envelope["type"], "error",
        "the native envelope of the dialect the path's suffix names: {envelope}"
    );
    assert_eq!(
        envelope["error"]["type"], "authentication_error",
        "the native authentication error: {envelope}"
    );
    assert_eq!(far.served(), 0);
}

/// Ports legacy `dialect_registry_facts_tests.rs::test_oversized_body_413_bedrock_native_envelope_with_amzn_headers`:
/// a body over the limit on a Converse path is refused 413 in that dialect's own envelope
/// (`__type`), with the `x-amzn-` fields a real endpoint always sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_oversized_body_on_a_converse_path_is_refused_in_its_dialects_envelope() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-413";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, ANSWER).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    // Past the rig router's one-mebibyte body limit.
    let body = serde_json::json!({ "pad": "x".repeat(2 << 20) })
        .to_string()
        .into_bytes();
    let bearer = format!("Bearer {}", rig.token);
    let (status, head, bytes) = send_with(
        &rig.router,
        "/model/some.model/converse",
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
        ],
        body,
    )
    .await;
    assert_eq!(status, 413);
    assert_eq!(
        head.get("content-type").and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    assert!(
        head.get("x-amzn-requestid").is_some(),
        "a Converse-path 413 carries x-amzn-RequestId"
    );
    assert!(
        head.get("x-amzn-errortype").is_some(),
        "a Converse-path 413 carries x-amzn-errortype"
    );
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).expect("the reshaped 413 body is JSON");
    assert!(
        v.get("__type").is_some(),
        "a Converse-path 413 carries the native __type envelope; got {v}"
    );
    assert_eq!(far.served(), 0);
}

/// The dialects the linked door serving the `pools` map states, found by what its Statement
/// declares.
fn served_dialects() -> Vec<String> {
    crate::LINKED
        .plane_doors
        .iter()
        .copied()
        .find_map(|door| {
            let probe = Dispatcher::new(DispatchConfig::default());
            let row = LinkedRow::of(door).expect("a linked door states itself");
            let plugin = load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from("ported-dialects-probe"),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: probe.adopter(),
                    conns: None,
                },
            )
            .expect("a linked door binds");
            let served = plugin.served();
            (served.section == busbar_contract::section::RESERVED_POOLS_KEY)
                .then(|| served.dialects.iter().map(|d| (*d).to_string()).collect())
        })
        .expect("the fold switch links the door serving the `pools` map")
}

/// Ports legacy `dialect_registry_facts_tests.rs::test_shipped_providers_catalog_valid`: the
/// shipped `providers.yaml` parses, every provider names a protocol the door serving the `pools`
/// map speaks, and every base URL is https.
#[test]
fn the_shipped_providers_catalog_names_only_served_dialects_over_https() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml");
    let raw = std::fs::read_to_string(path).expect("read providers.yaml");
    let defs: std::collections::HashMap<String, busbar_kernel::config::ProviderDef> =
        serde_yaml::from_str(&raw).expect("parse providers.yaml");
    assert!(defs.len() >= 10, "the catalog is non-trivial");
    let dialects = served_dialects();
    for (name, def) in &defs {
        assert!(
            dialects.contains(&def.protocol),
            "provider '{name}' names protocol '{}', which no served dialect is ({dialects:?})",
            def.protocol
        );
        assert!(
            def.base_url.starts_with("https://"),
            "provider '{name}' base_url must be https"
        );
    }
}

/// Ports legacy `signal_catalog_tests.rs::latency_reservoir_p95_is_nearest_rank_and_bounded`: the
/// reservoir behind a candidate's p95 latency is empty until a sample lands (never a made-up `0`),
/// answers the nearest-rank p95 in whole milliseconds rounded up, ignores garbage samples, and is a
/// bounded ring: once more samples than it holds have arrived, only the most recent decide.
#[test]
fn the_latency_reservoir_is_nearest_rank_and_bounded() {
    use crate::root::model_egress::LatencyReservoir;
    let r = LatencyReservoir::default();
    assert_eq!(r.p95_ms(), None);
    // 1..=100 ms: nearest rank ceil(0.95 * 100) = 95 -> 95 ms.
    for ms in 1..=100 {
        r.record(f64::from(ms));
    }
    assert_eq!(r.p95_ms(), Some(95));
    r.record(f64::NAN);
    r.record(0.0);
    r.record(-3.0);
    assert_eq!(r.p95_ms(), Some(95));
    // A sub-millisecond sample rounds UP to 1 ms.
    let tiny = LatencyReservoir::default();
    tiny.record(0.2);
    assert_eq!(tiny.p95_ms(), Some(1));
    // Overfill the ring with a flat 7 ms: every earlier sample is evicted.
    for _ in 0..1000 {
        r.record(7.0);
    }
    assert_eq!(r.p95_ms(), Some(7));
}
