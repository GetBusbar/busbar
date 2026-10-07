// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXCHANGE CASES OF THE RETIRED ENGINE CRATE, SERVED THROUGH THE DOOR (U11 port): each cell
//! drives a keyed caller through the data router built with the door serving the `pools` map, the
//! kernel's walk and the node's book (`super::hook_seat_tests::rig`) to real loopback far ends, and
//! reads what the caller reads, what the scrape counts and what the ledger keeps. Each test cites
//! the legacy test it ports.

use std::sync::Arc;

use super::hook_seat_tests::{chunk, far_end_answering, far_end_scripted, rig, RigOpts, Script};
use super::planes_tests::{Published as Withdrawn, PUBLISHING as ONE_PUBLISHER};

/// A served chat completion.
const SERVED: &str = r#"{"id":"chatcmpl-1","object":"chat.completion","created":0,"model":"m0","choices":[{"index":0,"message":{"role":"assistant","content":"served"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;

/// A served anthropic message.
const SERVED_MESSAGE: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"m0","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}"#;

/// A far end failing its transfer.
const BAD_GATEWAY: &str = r#"{"error":{"message":"bad gateway","type":"server_error"}}"#;

/// A far end that has no such resource.
const NOT_FOUND: &str = r#"{"error":{"message":"no such model","type":"invalid_request_error"}}"#;

/// One request through `rig`'s router with raw `body` bytes and exactly the `fields` given (no
/// credential of the rig's own): its status, head and body.
async fn raw(
    rig: &super::hook_seat_tests::DoorRig,
    path: &str,
    fields: &[(&str, &str)],
    body: Vec<u8>,
) -> (u16, axum::http::HeaderMap, Vec<u8>) {
    use tower::ServiceExt as _;
    let mut req = axum::http::Request::builder().method("POST").uri(path);
    for (name, value) in fields {
        req = req.header(*name, *value);
    }
    let req = req.body(axum::body::Body::from(body)).expect("a request");
    let response = rig
        .router
        .clone()
        .oneshot(req)
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

/// The keyed caller's bearer field.
fn bearer(rig: &super::hook_seat_tests::DoorRig) -> String {
    format!("Bearer {}", rig.token)
}

/// `busbar_requests_total` summed over the series carrying every one of `labels`.
fn requests_total(scrape: &str, labels: &[(&str, &str)]) -> u64 {
    scrape
        .lines()
        .filter(|l| l.starts_with(busbar_kernel::metrics::REQUESTS_TOTAL))
        .filter(|l| {
            labels
                .iter()
                .all(|(k, v)| l.contains(&format!("{k}=\"{v}\"")))
        })
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.trim().parse::<u64>().ok())
        .sum()
}

fn content_type(head: &axum::http::HeaderMap) -> String {
    head.get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

// ── a URL-model caller served across dialects ───────────────────────────────────────────────────

/// A bedrock `/model/{id}/converse` caller is served by an openai member, answered in its own
/// Converse JSON with a UUID-shaped `x-amzn-RequestId`, as a native endpoint always answers.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_converse_routes_and_returns_json`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_converse_caller_is_served_across_dialects_in_its_own_shape() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-converse";
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
    let (status, head, body) = rig
        .send(
            "POST",
            "/model/p/converse",
            Some(
                serde_json::json!({"messages": [{"role": "user", "content": [{"text": "hello"}]}]}),
            ),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(
        content_type(&head).starts_with("application/json"),
        "{head:?}"
    );
    let id = head
        .get("x-amzn-requestid")
        .and_then(|v| v.to_str().ok())
        .expect("a converse success carries x-amzn-RequestId")
        .to_string();
    let segs: Vec<usize> = id.split('-').map(str::len).collect();
    assert_eq!(segs, [8, 4, 4, 4, 12], "{id}");
    assert!(
        id.chars()
            .all(|c| (c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) || c == '-'),
        "{id}"
    );
    let v: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert!(
        v.get("output").is_some() || v.get("usage").is_some(),
        "the Converse shape: {v}"
    );
    assert_eq!(far.served(), 1);
}

/// The stable `/v1/models` surface streams with `alt=sse`: an event stream whose frames are the
/// native `candidates[]` shape, never another dialect's `choices`.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_v1_stable_stream_generate_content_alt_sse`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stable_models_surface_streams_events_in_its_own_shape() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-stable-stream";
    let _published = Withdrawn(instance);
    let frames = [
        r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[{"index":0,"delta":{"role":"assistant","content":"hi"},"finish_reason":null}]}"#,
        r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m0","choices":[],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}"#,
        "[DONE]",
    ];
    let far = far_end_scripted(Script {
        head: "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
               transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
            .to_string(),
        pieces: frames
            .iter()
            .map(|f| (0, chunk(format!("data: {f}\n\n").as_bytes())))
            .collect(),
        finish: Some(b"0\r\n\r\n".to_vec()),
    })
    .await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, head, body) = rig
        .send(
            "POST",
            "/v1/models/p:streamGenerateContent?alt=sse",
            Some(serde_json::json!({"contents": [{"role": "user", "parts": [{"text": "hello"}]}]})),
        )
        .await;
    let text = String::from_utf8_lossy(&body).to_string();
    assert_eq!(status, 200, "{text}");
    assert!(
        content_type(&head).starts_with("text/event-stream"),
        "{head:?}"
    );
    let payloads: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .filter(|d| !d.is_empty() && *d != "[DONE]")
        .filter_map(|d| serde_json::from_str(d).ok())
        .collect();
    assert!(!payloads.is_empty(), "{text}");
    assert!(
        payloads.iter().any(|c| c.get("candidates").is_some()),
        "{text}"
    );
    assert!(
        payloads.iter().all(|c| c.get("choices").is_none()),
        "{text}"
    );
}

/// The ad-hoc `/{provider}/{model}/v1/messages` surface resolves the configured provider's model and
/// serves it, through the router, the auth gate and the walk.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_adhoc_success_round_trip_via_router`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_adhoc_surface_serves_a_configured_providers_model() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-adhoc";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED_MESSAGE).await;
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
            "/oai0/m0/v1/messages",
            Some(serde_json::json!({"model": "m0", "messages": [], "max_tokens": 16})),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(far.served(), 1);
}

// ── a refused arrival, counted ──────────────────────────────────────────────────────────────────

/// One refused arrival on a fresh rig: its status, and the `unresolved` client-error count before
/// and after it.
async fn refused_and_counted(instance: &'static str, path: &str, body: &[u8]) -> (u16, u64, u64) {
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let labels = [("pool", "unresolved"), ("outcome", "client_error")];
    let before = requests_total(&busbar_kernel::metrics::render(), &labels);
    let auth = bearer(&rig);
    let (status, _, _) = raw(
        &rig,
        path,
        &[
            ("authorization", auth.as_str()),
            ("content-type", "application/json"),
        ],
        body.to_vec(),
    )
    .await;
    let after = requests_total(&busbar_kernel::metrics::render(), &labels);
    assert_eq!(far.served(), 0, "a refused arrival dials nothing");
    (status, before, after)
}

/// A body that is not JSON, on a dialect that reads its model off the body, is a 400 still counted
/// in `busbar_requests_total` under the bounded `unresolved` pool as a client error.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_body_model_parse_error_is_observable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unparseable_body_is_refused_and_counted() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-count-parse";
    let _published = Withdrawn(instance);
    let (status, before, after) =
        refused_and_counted(instance, "/v1/chat/completions", b"{ this is not json ").await;
    assert_eq!(status, 400);
    assert!(after > before, "counted: before={before} after={after}");
}

/// An InvokeModel body of no recognised shape is a 400 still counted as an `unresolved` client
/// error.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_invoke_unresolvable_body_is_observable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invoke_body_of_no_known_shape_is_refused_and_counted() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-count-invoke";
    let _published = Withdrawn(instance);
    let (status, before, after) = refused_and_counted(
        instance,
        "/model/amazon.titan-embed-text-v1/invoke",
        br#"{"nonsense":1}"#,
    )
    .await;
    assert_eq!(status, 400);
    assert!(after > before, "counted: before={before} after={after}");
}

/// A body naming no model is a 400 still counted as an `unresolved` client error.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_body_model_missing_model_is_observable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_naming_no_model_is_refused_and_counted() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-count-model";
    let _published = Withdrawn(instance);
    let (status, before, after) = refused_and_counted(
        instance,
        "/v1/chat/completions",
        br#"{"messages":[{"role":"user","content":"hi"}]}"#,
    )
    .await;
    assert_eq!(status, 400);
    assert!(after > before, "counted: before={before} after={after}");
}

/// A body that is JSON but no object, on a dialect whose URL names the model, is a 400 still
/// counted as an `unresolved` client error.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_path_model_non_object_body_is_observable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_object_body_on_a_url_model_path_is_refused_and_counted() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-count-object";
    let _published = Withdrawn(instance);
    let (status, before, after) =
        refused_and_counted(instance, "/model/p/converse", b"[1,2,3]").await;
    assert_eq!(status, 400);
    assert!(after > before, "counted: before={before} after={after}");
}

/// A pool the key may not reach is refused 403, counted in `busbar_requests_total` as a client
/// error with its duration observed, and charges the key no fee.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_governance_rejection_is_counted_via_finish`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_the_key_may_not_reach_is_refused_counted_and_charged_nothing() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-pool-denied";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, SERVED).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            allowed_pools: Some(&["elsewhere"]),
            ..RigOpts::default()
        },
    )
    .await;
    let labels = [("outcome", "client_error")];
    let before = requests_total(&busbar_kernel::metrics::render(), &labels);
    let (status, _, _) = rig.chat().await;
    assert_eq!(status, 403, "the pool is not the key's");
    let scrape = busbar_kernel::metrics::render();
    let after = requests_total(&scrape, &labels);
    assert!(after > before, "counted: before={before} after={after}");
    assert!(
        scrape.contains(busbar_kernel::metrics::REQUEST_DURATION_SECONDS),
        "the duration is observed"
    );
    let (_, spend, _, billable) = rig.ledger_after(1).await;
    assert_eq!((spend, billable), (0, 0), "no fee for a refused request");
    assert_eq!(far.served(), 0);
}

// ── session affinity off an anthropic caller's system block ─────────────────────────────────────

/// With no session header, an anthropic caller's `system` block keys the session: every repeat is
/// served by one member.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/forward_pool_integration_tests.rs::test_sticky_from_system_block`
/// (the openai caller's system key and the header key are `serve_door::the_pools_door_pins_a_session_to_one_member`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_anthropic_callers_system_block_pins_its_session() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-system-affinity";
    let _published = Withdrawn(instance);
    let fars = [
        far_end_answering(200, SERVED).await,
        far_end_answering(200, SERVED).await,
    ];
    let rig = rig(
        instance,
        RigOpts {
            members: &[(fars[0].port, 1), (fars[1].port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let body = serde_json::json!({"model": "p", "max_tokens": 100, "system": "my-system-block",
        "messages": [{"role": "user", "content": "hi"}]});
    for _ in 0..4 {
        let (status, _, b) = rig.send("POST", "/v1/messages", Some(body.clone())).await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&b));
    }
    let served: Vec<usize> = fars.iter().map(|f| f.served()).collect();
    assert!(
        served.contains(&4),
        "one member served the session: {served:?}"
    );
}

// ── the fee ─────────────────────────────────────────────────────────────────────────────────────

/// The billable count a rig's key holds after one chat, its far end answering `status`.
async fn billable_after_one_chat(
    instance: &'static str,
    status: u16,
    body: &'static str,
) -> (u16, u64) {
    let far = far_end_answering(status, body).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (caller, _, _) = rig.chat().await;
    let (_, _, _, billable) = rig.ledger_after(1).await;
    (caller, billable)
}

/// THE FEE IS THE LEG AND THE CALLER'S STATUS: one flat fee for a request delivered from a far end
/// with a success; none for a failed transfer, none for a far end's not-found, and none for a unit
/// with no far-end leg (the catalogue) even on a success.
///
/// Ports legacy `crates/busbar-llm/src/unit/tests/meter.rs::the_fee_unit_is_one_per_delivered_request_that_routed_upstream`
/// and `crates/busbar-llm/src/unit/tests/meter.rs::the_fee_is_decided_by_the_leg_and_the_client_facing_status`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fee_is_charged_only_for_a_success_delivered_from_a_far_end() {
    let _one = ONE_PUBLISHER.lock().await;
    let (ok, failed, missing) = (
        "door-ported-fee-ok",
        "door-ported-fee-502",
        "door-ported-fee-404",
    );
    let _published = (Withdrawn(ok), Withdrawn(failed), Withdrawn(missing));

    let far = far_end_answering(200, SERVED).await;
    let rig_ok = rig(
        ok,
        RigOpts {
            members: &[(far.port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig_ok.chat().await.0, 200);
    let (_, _, _, billable) = rig_ok.ledger_after(1).await;
    assert_eq!(billable, 1, "a delivered success is one fee");
    let (status, _, _) = rig_ok.send("GET", "/v1/models", None).await;
    assert_eq!(status, 200, "the catalogue answers");
    let (_, _, _, billable) = rig_ok.ledger_after(2).await;
    assert_eq!(billable, 1, "no far-end leg, no fee");

    let (status, billable) = billable_after_one_chat(failed, 502, BAD_GATEWAY).await;
    assert!(
        status >= 500,
        "the failed transfer reaches the caller: {status}"
    );
    assert_eq!(billable, 0, "a failed transfer posts no fee");

    let (status, billable) = billable_after_one_chat(missing, 404, NOT_FOUND).await;
    assert_eq!(status, 404);
    assert_eq!(billable, 0, "a not-found after admission is unbilled");
}

// ── the refusal statuses the driver chooses ─────────────────────────────────────────────────────

/// The pools door, bound on a probe dispatcher of its own (the composition root names no plane).
fn pools_door_bound(
) -> crate::root::loader::dispatch::Plugin<crate::root::loader::dispatch::kinds::plane::Plane> {
    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    crate::LINKED
        .plane_doors
        .iter()
        .copied()
        .find_map(|door| {
            let probe = Dispatcher::new(DispatchConfig::default());
            let row = LinkedRow::of(door).expect("a linked door states itself");
            let bound = load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from("door-ported-statuses-probe"),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: probe.adopter(),
                    conns: None,
                },
            )
            .expect("a linked door binds");
            (bound.served().section == busbar_contract::section::RESERVED_POOLS_KEY)
                .then_some(bound)
        })
        .expect("the fold switch links the door serving the `pools` map")
}

fn golden_cells() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/shadow-oracle/golden/1.5.5/cells")
}

/// The status the one recorded cell whose name ends `__{suffix}` (or is `suffix`) answered.
fn recorded_status(suffix: &str) -> u32 {
    let dir = golden_cells();
    let tail = format!("__{suffix}.json");
    let exact = format!("{suffix}.json");
    let named: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .expect("the recordings are readable")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == exact || n.ends_with(&tail))
        })
        .collect();
    assert_eq!(named.len(), 1, "one recording for {suffix}: {named:?}");
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&named[0]).expect("readable"))
            .expect("a recording is JSON");
    v["status"].as_u64().expect("a status") as u32
}

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

/// FOR EVERY REFUSAL 1.5.5 RECORDED, the status the kernel's driver chooses from the door's stated
/// rows (else its own default), for the door's dialect and the refusal's reason, is the recorded
/// status.
///
/// Ports legacy `crates/busbar-llm/tests/llm_refusal_statuses.rs::every_recorded_llm_refusal_wears_the_status_the_driver_chooses`.
#[test]
fn every_recorded_refusal_wears_the_status_the_driver_chooses() {
    use busbar_contract::caps::ReasonCode;
    use busbar_kernel::plane_driver::{refusal_status, BufferCaps, DriverConfig};
    let door = pools_door_bound();
    let dialects = door.served().dialects;
    let config = DriverConfig {
        caps: BufferCaps::default(),
        op_classes: Vec::new(),
        status_of: refusal_status,
        refusal_statuses: door.refusal_statuses().to_vec(),
        caller_refs: None,
    };
    let index = |name: &str| {
        dialects
            .iter()
            .position(|d| *d == name)
            .unwrap_or_else(|| panic!("the door states {name}: {dialects:?}")) as u32
    };
    let mut cells: Vec<(String, &str, ReasonCode)> = Vec::new();
    for (condition, reason) in [
        ("unauthenticated", ReasonCode::Unauthenticated),
        ("over_budget_total", ReasonCode::OverBudget),
        ("over_budget", ReasonCode::RateLimited),
        ("malformed", ReasonCode::DecodeFailed),
    ] {
        for d in SIX {
            cells.push((format!("{d}__{d}__request__{condition}"), d, reason));
        }
    }
    for ingress in SIX {
        for far in SIX {
            cells.push((
                format!("{ingress}__{far}__request__upstream_down"),
                ingress,
                ReasonCode::DestinationUnreachable,
            ));
        }
    }
    cells.push((
        "route.failover__fo__all-down".into(),
        "openai",
        ReasonCode::DestinationUnreachable,
    ));
    for (cell, d) in [
        ("http.crosscut__413__anthropic", "anthropic"),
        ("http.crosscut__413__openai", "openai"),
        ("http.crosscut__413__gemini-path", "gemini"),
    ] {
        cells.push((cell.into(), d, ReasonCode::BodyTooLarge));
    }
    cells.push((
        "http.crosscut__unknown-path__openai-suffix".into(),
        "openai",
        ReasonCode::NoRate,
    ));
    let wrong: Vec<String> = cells
        .iter()
        .filter_map(|(cell, d, reason)| {
            let (chosen, want) = (config.status(index(d), *reason), recorded_status(cell));
            (chosen != want)
                .then(|| format!("{cell}: {d} {reason:?} chose {chosen}, 1.5.5 answered {want}"))
        })
        .collect();
    assert!(
        wrong.is_empty(),
        "{} of {}:\n{}",
        wrong.len(),
        cells.len(),
        wrong.join("\n")
    );
}

/// Each status row the door states is needed: the kernel's default alone answers something else.
///
/// Ports legacy `crates/busbar-llm/tests/llm_refusal_statuses.rs::every_stated_row_differs_from_the_kernel_default`.
#[test]
fn every_stated_status_row_differs_from_the_kernel_default() {
    let door = pools_door_bound();
    let rows = door.refusal_statuses().to_vec();
    assert!(!rows.is_empty(), "the door states its statuses");
    for row in rows {
        let reason = busbar_contract::abi::plane::reason_of(row.reason).expect("a known reason");
        assert_ne!(
            busbar_kernel::plane_driver::refusal_status(reason),
            row.status,
            "{reason:?} in dialect {} restates the default",
            row.dialect
        );
    }
}

// ── the catalog merge the door is handed ────────────────────────────────────────────────────────

/// A deployment's capability key overrides the catalog's in the provider section the door is
/// handed; with none, the catalog's stands.
///
/// Ports the deployment-over-catalog arm of legacy
/// `crates/busbar-llm/src/engine/tests/lane_caps_config_tests.rs::lane_caps_default_to_the_pre_capability_forms_and_resolve_provider_then_model_rule`
/// (the rule resolution itself is `exchange_shaping_ported::a_first_matching_model_rule_overrides_the_providers_own_key`
/// in the serving crate).
#[test]
fn a_deployments_capability_key_overrides_the_catalogs() {
    let defs: std::collections::HashMap<String, busbar_kernel::config::ProviderDef> =
        serde_yaml::from_str(
            "x:\n  protocol: openai\n  base_url: 'http://127.0.0.1:9'\n  max_output_key: max_completion_tokens\n",
        )
        .expect("the providers");
    let key_of = |deploy_extra: &str| {
        let yaml = format!(
            "providers:\n  x:\n    api_key: {{ env: BUSBAR_PORTED_UNUSED_KEY }}\n{deploy_extra}\
             models:\n  m:\n    provider: x\n"
        );
        let deploy = busbar_kernel::config::deploy_from_yaml_str(&yaml).expect("a deployment");
        let cfg = busbar_kernel::config::resolve(&deploy, &defs).expect("resolves");
        let sections = crate::root::door_steps::kernel_sections(&cfg);
        sections["providers"]["x"]["max_output_key"]
            .as_str()
            .map(str::to_string)
    };
    assert_eq!(key_of("").as_deref(), Some("max_completion_tokens"));
    assert_eq!(
        key_of("    max_output_key: max_tokens\n").as_deref(),
        Some("max_tokens")
    );
}

// ── a huge request ──────────────────────────────────────────────────────────────────────────────

/// A request well over 128 KiB is served like a small one, on the single-threaded runtime the data
/// plane runs.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/translate_offload_tests.rs::huge_body_translates_via_offload_and_forwards`.
#[tokio::test(flavor = "current_thread")]
async fn a_huge_request_is_served_like_a_small_one() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-huge";
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
    let big = "x".repeat(300 * 1024);
    let (status, _, body) = rig
        .send(
            "POST",
            "/v1/chat/completions",
            Some(serde_json::json!({"model": "p", "max_tokens": 16,
                "messages": [{"role": "user", "content": big}]})),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(rig.chat().await.0, 200, "and a small one after it");
    assert_eq!(far.served(), 2);
}

// ── the credential carriers ─────────────────────────────────────────────────────────────────────

/// The key is admitted on each carrier a native client sends it on (`authorization: Bearer`,
/// `x-api-key`, `x-goog-api-key`); a wrong or missing credential is a 401 in the native JSON error
/// envelope.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/auth_dispatch_tests.rs::test_chain_accepts_all_carriers_and_native_401`
/// (its identified-but-unbound role arm needs an identity chain this rig does not configure).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_credential_carrier_is_admitted_and_a_bad_one_reads_the_native_401() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-carriers";
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
    let body = || {
        serde_json::to_vec(&serde_json::json!({"model": "p", "max_tokens": 16,
            "messages": [{"role": "user", "content": "hi"}]}))
        .expect("serializes")
    };
    let ct = ("content-type", "application/json");
    let auth = bearer(&rig);
    let token = rig.token.clone();
    for carrier in [
        ("authorization", auth.as_str()),
        ("x-api-key", token.as_str()),
        ("x-goog-api-key", token.as_str()),
    ] {
        let (status, _, b) = raw(&rig, "/p/v1/messages", &[carrier, ct], body()).await;
        assert_eq!(
            status,
            200,
            "{}: {}",
            carrier.0,
            String::from_utf8_lossy(&b)
        );
    }
    for fields in [&[("x-api-key", "not-the-token"), ct][..], &[ct][..]] {
        let (status, head, b) = raw(&rig, "/p/v1/messages", fields, body()).await;
        assert_eq!(status, 401, "{fields:?}");
        assert_eq!(content_type(&head), "application/json", "{fields:?}");
        let v: serde_json::Value = serde_json::from_slice(&b).expect("JSON");
        assert!(v.get("error").is_some(), "the native envelope: {v}");
    }
    assert_eq!(far.served(), 3);
}

// ── the whole-path allocation gate ──────────────────────────────────────────────────────────────

/// COMMITTED BOUND, carried over unchanged from the legacy gate: the allocations of one warmed
/// same-dialect request, end to end.
const FORWARD_PASSTHROUGH_MAX_ALLOCS: u64 = 107;

/// The process's allocation requests so far, as jemalloc counts them (every arena, small and large).
#[cfg(not(target_env = "msvc"))]
fn allocation_requests() -> Result<u64, String> {
    use tikv_jemalloc_ctl::{epoch, Access as _, AsName as _};
    epoch::advance().map_err(|e| format!("epoch: {e}"))?;
    let read = |name: &'static [u8]| -> Result<u64, String> {
        name.name().read().map_err(|e| format!("{e}"))
    };
    Ok(read(b"stats.arenas.4096.small.nrequests\0")?
        + read(b"stats.arenas.4096.large.nrequests\0")?)
}

/// One warmed same-dialect request through the door, end to end, stays under the committed
/// allocation bound.
///
/// Ports legacy `crates/busbar-llm/src/engine/tests/alloc_gate_tests.rs::alloc_gate_openai_passthrough_forward`.
#[cfg(not(target_env = "msvc"))]
#[tokio::test(flavor = "current_thread")]
async fn one_warmed_same_dialect_request_stays_under_the_allocation_bound() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "door-ported-alloc";
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
    assert_eq!(rig.chat().await.0, 200, "the warm-up");
    let mut min = u64::MAX;
    for _ in 0..4 {
        let before = allocation_requests().expect("the allocator counts its allocations");
        assert_eq!(rig.chat().await.0, 200);
        let after = allocation_requests().expect("the allocator counts its allocations");
        min = min.min(after - before);
    }
    println!("door same-dialect request: min allocations = {min}");
    assert!(
        min <= FORWARD_PASSTHROUGH_MAX_ALLOCS,
        "one warmed request allocated {min} times, over the bound {FORWARD_PASSTHROUGH_MAX_ALLOCS}"
    );
}
