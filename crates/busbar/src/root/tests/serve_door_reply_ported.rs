// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FAR END'S ANSWER ON THE DOOR, ported from the legacy engine's tests before that crate is
//! deleted: each cell keeps the legacy test's caller, far-end bytes and expectation, and drives
//! them through the door serving the `pools` map end to end (the data router, the kernel's walk
//! over the lane cells, the money steps, a real loopback far end; `super::hook_seat_tests::rig`)
//! instead of the engine's served path. Each cell names the legacy test it ports.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::hook_seat_tests::{chunk, far_end_answering, far_end_scripted, rig, RigOpts, Script};
use super::planes_tests::{Published as Withdrawn, PUBLISHING as ONE_PUBLISHER};

/// An OpenAI chat answer: "hi there", 5 in and 3 out.
const OPENAI_OK: &str = r#"{"id":"chatcmpl-x","object":"chat.completion","model":"glm-4.5","choices":[{"index":0,"message":{"role":"assistant","content":"hi there"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3}}"#;

/// A far end on loopback answering every request with `status` and `body` (JSON), keeping each
/// request's body as it arrived.
async fn far_end_recording(body: &'static str) -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let port = listener.local_addr().expect("its address").port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&seen);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let kept = Arc::clone(&kept);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                let mut got = Vec::new();
                loop {
                    let Ok(n) = socket.read(&mut buf).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    got.extend_from_slice(&buf[..n]);
                    let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&got[..at]).to_ascii_lowercase();
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if got.len() >= at + 4 + length {
                        kept.lock()
                            .unwrap()
                            .push(got[at + 4..at + 4 + length].to_vec());
                        break;
                    }
                }
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(reply.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (port, seen)
}

/// An Anthropic chat on pool `p`, as its own surface takes it.
fn anthropic_chat(stream: bool) -> serde_json::Value {
    serde_json::json!({"model": "p", "max_tokens": 50, "stream": stream,
        "messages": [{"role": "user", "content": "hi"}]})
}

const ANTHROPIC_VERSION: &[(&str, &str)] = &[("anthropic-version", "2023-06-01")];

/// The status and body of one Anthropic chat through the door.
async fn anthropic(rig: &super::hook_seat_tests::DoorRig, stream: bool) -> (u16, Vec<u8>) {
    let response = rig
        .open(
            "POST",
            "/v1/messages",
            Some(anthropic_chat(stream)),
            ANTHROPIC_VERSION,
        )
        .await;
    let status = response.status().as_u16();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("the body")
        .to_vec();
    (status, body)
}

/// A Cohere caller (`POST /v2/chat`) over an OpenAI member: the far end is sent an OpenAI chat
/// request (its `messages`), and the caller reads a native Cohere 200 (a `message`, never OpenAI's
/// `choices`). Ports legacy `ingress_integration_tests.rs::test_cohere_ingress_to_openai_backend`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cohere_caller_over_an_openai_member_round_trips() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-cohere-over-openai";
    let _published = Withdrawn(instance);
    let (port, seen) = far_end_recording(OPENAI_OK).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(port, 1)],
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _, body) = rig
        .send(
            "POST",
            "/v2/chat",
            Some(serde_json::json!({"model": "p",
                "messages": [{"role": "user", "content": "hello"}]})),
        )
        .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let sent: serde_json::Value = serde_json::from_slice(
        seen.lock()
            .unwrap()
            .first()
            .expect("the far end was sent one request"),
    )
    .expect("a JSON request");
    assert!(
        sent.get("messages").is_some(),
        "an OpenAI chat body: {sent}"
    );
    let v: serde_json::Value = serde_json::from_slice(&body).expect("a JSON answer");
    assert!(v.get("message").is_some(), "a Cohere answer: {v}");
    assert!(v.get("choices").is_none(), "nothing of OpenAI's: {v}");
}

/// An OpenAI answer reporting 100 in and 60 out.
const OPENAI_160: &str = r#"{"model":"glm-4.5","choices":[{"index":0,"message":{"role":"assistant","content":"Hello there friend"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":60}}"#;

/// The tokens a translated whole answer reported are charged to the key's group, so with a 30
/// token-per-minute cap the next request in the window is refused 429. Ports legacy
/// `forward_pool_integration_tests.rs::test_cross_protocol_nonstream_records_tokens_for_tpm`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_translated_answers_tokens_count_against_the_groups_token_cap() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-tpm-whole";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, OPENAI_160).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            tokens_per_minute: Some(30),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, body) = anthropic(&rig, false).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let v: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
    assert_eq!(v["model"], "glm-4.5", "the serving model: {v}");
    assert_eq!(rig.tokens_after().await, 160, "100 in + 60 out on the key");
    let (status, body) = anthropic(&rig, false).await;
    assert_eq!(
        status,
        429,
        "the recorded tokens make the cap refuse: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(far.served(), 1, "the refused request dialled nothing");
}

/// The tokens a reframed stream reported are charged at its end, so the next request in the window
/// is refused 429 under the same cap. Ports legacy
/// `forward_pool_integration_tests.rs::test_cross_protocol_stream_records_tokens_for_tpm`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reframed_streams_tokens_count_against_the_groups_token_cap() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-tpm-stream";
    let _published = Withdrawn(instance);
    let events = [
        r#"{"choices":[{"delta":{"role":"assistant"}}]}"#,
        r#"{"choices":[{"delta":{"content":"Hello there friend"}}]}"#,
        r#"{"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":60}}"#,
        "[DONE]",
    ];
    let far = far_end_scripted(Script {
        head: "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
               transfer-encoding: chunked\r\nconnection: close\r\n\r\n"
            .to_string(),
        pieces: events
            .iter()
            .map(|e| (0, chunk(format!("data: {e}\n\n").as_bytes())))
            .collect(),
        finish: Some(b"0\r\n\r\n".to_vec()),
    })
    .await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            tokens_per_minute: Some(30),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, body) = anthropic(&rig, true).await;
    assert_eq!(status, 200);
    assert!(!body.is_empty(), "the stream drains to its end");
    assert_eq!(rig.tokens_after().await, 160, "charged at the stream's end");
    let (status, _) = anthropic(&rig, true).await;
    assert_eq!(status, 429, "the stream's tokens make the cap refuse");
    assert_eq!(far.served(), 1, "the refused request dialled nothing");
}

/// An OpenAI answer with an empty `choices` the reader refuses.
const EMPTY_CHOICES: &str = r#"{"id":"chatcmpl-EMPTY","object":"chat.completion","created":1234567890,"model":"glm-4.5","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":3}}"#;

/// A 2xx the caller's dialect cannot be written from is the caller's 500; the member's budget unit
/// its success spent is given back and its breaker cell records the failure (one is enough to bench
/// it), and no tokens are charged. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_untranslatable_2xx_refunds_budget_and_trips_breaker`
/// (the door has one walk, so this cell is also the fallback-pool twin's).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_untranslatable_success_refunds_the_budget_unit_and_benches_the_member() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-untranslatable";
    let _published = Withdrawn(instance);
    let far = far_end_answering(200, EMPTY_CHOICES).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            lane_budget: Some(1),
            ..RigOpts::default()
        },
    )
    .await;
    assert_eq!(rig.app.store.lane_budget_remaining(0), Some(1));
    assert!(rig.app.store.ready_in("p", 0, busbar_kernel::store::now()));
    let (status, body) = anthropic(&rig, false).await;
    assert_eq!(status, 500, "{}", String::from_utf8_lossy(&body));
    assert_eq!(far.served(), 1);
    assert!(
        !rig.app.store.ready_in("p", 0, busbar_kernel::store::now()),
        "the member's cell recorded the failure"
    );
    assert_eq!(
        rig.tokens_after().await,
        0,
        "nothing delivered, nothing charged"
    );
    assert_eq!(
        rig.app.store.lane_budget_remaining(0),
        Some(1),
        "the budget unit the success spent is given back"
    );
}

/// An answer to translate over the translation cap (the host's default, 32 MiB) is the caller's
/// 500, but the far end served: the member's budget unit is kept, not refunded. Ports legacy
/// `ingress_indistinguishability_tests.rs::test_truncated_body_does_not_refund_budget`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_over_the_translation_cap_keeps_the_budget_unit() {
    let _one = ONE_PUBLISHER.lock().await;
    let instance = "serve-door-ported-over-cap";
    let _published = Withdrawn(instance);
    let cap = busbar_contract::codec::max_translate_body_bytes();
    let huge: &'static str = Box::leak(
        format!(
            r#"{{"id":"chatcmpl-huge","object":"chat.completion","created":1234567890,"model":"gpt-4o","choices":[{{"index":0,"message":{{"role":"assistant","content":"{}"}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":5,"completion_tokens":999999}}}}"#,
            "x".repeat(cap + 1024)
        )
        .into_boxed_str(),
    );
    let far = far_end_answering(200, huge).await;
    let rig = rig(
        instance,
        RigOpts {
            members: &[(far.port, 1)],
            lane_budget: Some(1),
            ..RigOpts::default()
        },
    )
    .await;
    let (status, _) = anthropic(&rig, false).await;
    assert_eq!(status, 500);
    assert_eq!(
        rig.app.store.lane_budget_remaining(0),
        Some(0),
        "our cap, not the far end's fault: the unit the success spent is kept"
    );
}
