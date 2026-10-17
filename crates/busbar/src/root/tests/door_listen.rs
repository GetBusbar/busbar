// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUBSCRIPTION CHANNEL OVER HTTP, END TO END THROUGH THE DATA ROUTES (ARCHITECT round 4
//! Q-L3B-SURFACES (a), confirmed round 5 Q-L3B-K6-HTTP (a)): the tool door's `subscriptions/listen`
//! arrives on its claim, its `arrive` states `ROUTE_SESSION`, and the kernel drives the unit as a
//! K6 session whose caller leg is the long-lived HTTP response (the root's ingress caller). What the
//! caller sees is predev's: `200` as an event stream (`content-type: text/event-stream`,
//! `cache-control: no-cache, no-store`), the acknowledgement first and tagged with the request's
//! id, a change frame when the catalogue its caller can see moves, a keepalive comment when it has
//! been quiet, the revision's graceful `complete` result at its bound, the `identity_not_live`
//! refusal when its principal stops standing, and each end closes the stream. A request that can
//! deliver nothing is refused `400` with its JSON-RPC error.
//!
//! The kernel's monotonic clock (`clock.now`, which the subscription's keepalive and bound read) is
//! stepped forward by the rig; the instance's tick runs on the process's clock, as the process
//! spawns it.

use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::http::StatusCode;
use busbar_contract::abi::mechanism::call::{Blob, Outcome as AbiOutcome, BLOB_JSON};
use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
use busbar_contract::abi::plane::PlaneRefreshOut;
use http_body_util::BodyExt as _;

use super::tool_door::{protocol_version, rig_with, surface, tool_digest, tool_server, Rig};
use crate::root::loader::dispatch::{in_head, out_head, Frame};
use crate::root::serve::planes_tests::{Published, PUBLISHING};

/// The keepalive comment an idle stream writes (predev's `: keepalive`).
const KEEPALIVE: &str = ": keepalive\n\n";

/// Further than a quiet stream's keepalive interval (predev's 15 s) and short of its bound.
const PAST_KEEPALIVE: Duration = Duration::from_secs(20);

/// Further than a stream's lifetime bound (predev's 300 s).
const PAST_BOUND: Duration = Duration::from_secs(400);

/// The request id every listen here is opened under.
const ID: u64 = 7;

/// A `subscriptions/listen` asking for `notifications`, as the revision's clients send it.
fn listen_body(notifications: &serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": ID,
        "method": surface("listen_method"),
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": protocol_version(),
                "io.modelcontextprotocol/clientCapabilities": {},
            },
            "notifications": notifications,
        },
    })
    .to_string()
}

/// POST a listen to the door's endpoint under the rig's key: the live response.
async fn listen(rig: &Rig, notifications: &serde_json::Value) -> axum::response::Response {
    use tower::ServiceExt as _;
    let endpoint = format!("/{}", super::tool_door::endpoint_section());
    let req = axum::http::Request::builder()
        .method("POST")
        .uri(endpoint)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header(surface("protocol_header"), protocol_version())
        .header(surface("method_header"), surface("listen_method"))
        .header("authorization", format!("Bearer {}", rig.token))
        .body(axum::body::Body::from(listen_body(notifications)))
        .expect("a request");
    rig.router
        .clone()
        .oneshot(req)
        .await
        .expect("the router answers")
}

/// What a stream said so far, as raw text, and whether it has ended.
#[derive(Default)]
struct Heard {
    text: String,
    ended: bool,
}

impl Heard {
    /// Every `message` event's data, in order.
    fn events(&self) -> Vec<serde_json::Value> {
        self.text
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str(d).ok())
            .collect()
    }

    /// The methods of the events heard, in order.
    fn methods(&self) -> Vec<String> {
        self.events()
            .iter()
            .map(|e| e["method"].as_str().unwrap_or_default().to_string())
            .collect()
    }
}

/// Read `body` into `heard` until `want` holds or the stream ends (bounded): whether `want` held.
async fn read_until(
    body: &mut axum::body::Body,
    heard: &mut Heard,
    want: impl Fn(&Heard) -> bool,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !want(heard) && !heard.ended {
        match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    heard.text.push_str(&String::from_utf8_lossy(&data));
                }
            }
            Ok(None) => heard.ended = true,
            Ok(Some(Err(_))) | Err(_) => break,
        }
    }
    want(heard)
}

/// The `tools:` section the rig opens with, with `extra` more approved tools on its one server.
fn section_with(port: u16, extra: &[&str]) -> serde_yaml::Value {
    let mut tools = format!("    read_file: {{ schema_hash: \"{}\" }}\n", tool_digest());
    for name in extra {
        tools.push_str(&format!(
            "    {name}: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ));
    }
    serde_yaml::from_str(&format!(
        "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \
         \"sha256/K=\" }}\n  tools_allow:\n{tools}"
    ))
    .expect("a section")
}

/// Publish generation 2 of the door over `section` (the operator's reload): the catalogue moves.
fn refresh(rig: &Rig, section: &serde_yaml::Value) {
    let settings = serde_json::to_vec(section).expect("json");
    let mut frame = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: Blob {
                ptr: settings.as_ptr(),
                len: settings.len(),
                fmt: BLOB_JSON,
                flags: 0,
            },
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        PlaneRefreshOut {
            head: out_head(),
            snapshot: std::ptr::null(),
        },
    );
    let (called, snapshot) = rig.plane.refresh(&mut frame);
    assert_eq!(called.outcome, AbiOutcome::Ready, "the refresh is taken");
    assert!(snapshot.is_some(), "generation 2 is published");
}

/// Step the kernel's monotonic clock forward by `by`.
fn step_clock(rig: &Rig, by: Duration) {
    let ns = u64::try_from(by.as_nanos()).expect("in range");
    rig.clock.fetch_add(ns, Ordering::SeqCst);
}

/// THE SUBSCRIPTION, HELD AS A SESSION OVER THE HTTP RESPONSE: `200` as an event stream, its first
/// event the acknowledgement of the accepted filter tagged with the request's id; a new generation
/// whose tools this caller can see changed is told as `notifications/tools/list_changed`; a quiet
/// stream writes the keepalive comment; at its bound the stream ends with the revision's `complete`
/// result correlated to the request, and closes. RED before the K6 route: the door declined the
/// request and the caller was answered a refusal, not a stream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_over_http_is_held_as_a_session_until_its_bound() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-listen-held";
    let _published = Published(instance);
    let (port, _heard) = tool_server().await;
    let rig = rig_with(instance, port, None, &|app| app);
    let response = listen(&rig, &serde_json::json!({ "toolsListChanged": true })).await;
    assert_eq!(response.status(), StatusCode::OK);
    let head = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(head("content-type"), "text/event-stream");
    assert_eq!(head("cache-control"), "no-cache, no-store");
    let mut body = response.into_body();
    let mut heard = Heard::default();

    assert!(
        read_until(&mut body, &mut heard, |h| !h.events().is_empty()).await,
        "the acknowledgement is written at once: {:?}",
        heard.text
    );
    assert!(
        heard.text.starts_with("event: message\ndata: "),
        "{:?}",
        heard.text
    );
    let ack = heard.events().remove(0);
    assert_eq!(ack["method"], serde_json::json!(surface("acknowledged")));
    assert_eq!(
        ack["params"]["_meta"][surface("subscription_id")],
        serde_json::json!(ID),
        "tagged with the request's id"
    );
    assert_eq!(
        ack["params"]["notifications"],
        serde_json::json!({ "toolsListChanged": true }),
        "the accepted filter"
    );

    refresh(&rig, &section_with(port, &["write_file"]));
    let changed = surface("tools_changed").to_string();
    assert!(
        read_until(&mut body, &mut heard, |h| h.methods().contains(&changed)).await,
        "a change the caller can see is told: {:?}",
        heard.text
    );
    let frame = heard.events().pop().expect("the change frame");
    assert_eq!(
        frame["params"]["_meta"][surface("subscription_id")],
        serde_json::json!(ID)
    );
    assert!(frame.get("id").is_none(), "a notification carries no id");

    step_clock(&rig, PAST_KEEPALIVE);
    assert!(
        read_until(&mut body, &mut heard, |h| h.text.contains(KEEPALIVE)).await,
        "a quiet stream says it is alive: {:?}",
        heard.text
    );

    step_clock(&rig, PAST_BOUND);
    assert!(
        read_until(&mut body, &mut heard, |h| h.ended).await,
        "the stream ends at its bound: {:?}",
        heard.text
    );
    let last = heard.events().pop().expect("a last frame");
    let mut meta = serde_json::Map::new();
    meta.insert(
        surface("subscription_id").to_string(),
        serde_json::json!(ID),
    );
    assert_eq!(
        last,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": ID,
            "result": { "resultType": "complete", "_meta": meta },
        }),
        "the revision's graceful end, correlated to the request"
    );
}

/// THE PERMISSION IS RE-ASKED EVERY FRAME: once the caller's key is deleted, the stream's next step
/// ends it with predev's refusal (`-32600`, reason `identity_not_live`) and closes, with nothing
/// after it. RED without the per-frame re-resolution: the stream stayed open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_over_http_ends_when_its_principal_stops_standing() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-listen-lapsed";
    let _published = Published(instance);
    let (port, _heard) = tool_server().await;
    let rig = rig_with(instance, port, None, &|app| app);
    let response = listen(&rig, &serde_json::json!({ "toolsListChanged": true })).await;
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let mut heard = Heard::default();
    assert!(read_until(&mut body, &mut heard, |h| !h.events().is_empty()).await);

    rig.gov.delete_key(&rig.key.id).expect("the key is deleted");
    assert!(
        read_until(&mut body, &mut heard, |h| h.ended).await,
        "the stream ends on the frame after its principal stopped standing: {:?}",
        heard.text
    );
    let events = heard.events();
    assert_eq!(
        events.len(),
        2,
        "the acknowledgement and the refusal: {events:?}"
    );
    let refusal = &events[1];
    assert_eq!(refusal["id"], serde_json::json!(ID));
    assert_eq!(refusal["error"]["code"], serde_json::json!(-32600));
    assert_eq!(
        refusal["error"]["data"]["reason"],
        serde_json::json!(busbar_contract::vocab::REASON_IDENTITY_NOT_LIVE)
    );
    assert!(
        refusal["error"]["message"]
            .as_str()
            .is_some_and(|m| m.ends_with(
                "is no longer live, so the standing decision it was admitted under no longer \
                 applies"
            )),
        "{refusal}"
    );
}

/// A SUBSCRIPTION THAT CAN DELIVER NOTHING IS REFUSED, not held open: `400`, a JSON body, the
/// JSON-RPC invalid-params error correlated to the request, in predev's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_over_http_that_could_deliver_nothing_is_refused() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-door-listen-refused";
    let _published = Published(instance);
    let (port, _heard) = tool_server().await;
    let rig = rig_with(instance, port, None, &|app| app);
    let response = listen(&rig, &serde_json::json!({})).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .expect("the body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body["id"], serde_json::json!(ID));
    assert_eq!(body["error"]["code"], serde_json::json!(-32602));
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("`params.notifications` opts in to no category")),
        "{body}"
    );
}
