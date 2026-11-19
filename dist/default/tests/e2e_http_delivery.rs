// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One HTTP/1.1 request through the real binary: admission, the pool's gate, money, the provider
//! and the answer's delivery, read back as the caller saw it and as the operator's `/records`
//! states it (the `delivery` group: `state`, `reason`, `body_bytes`).

#![cfg(unix)]
#![cfg(all(
    linked_section_pools,
    linked_section_tools,
    linked_section_agents,
    linked_section_decisions,
    linked_section_streams
))]

mod common;
mod e2e_support;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use e2e_support::{
    abstain, chat_answer, delivery, llm, post_json, Deployment, Scripted, CHAT, WAIT,
};
use serde_json::json;

#[test]
fn an_answered_request_is_delivered_whole_and_its_record_states_the_body_bytes() {
    let upstream = Scripted::start(200, &chat_answer(7, 5));
    let gate = Scripted::start(200, &abstain());
    let node = llm("whole", &upstream, Some(&gate)).boot();
    let key = node.mint(&json!({ "name": "e2e-whole" }));

    let reply = post_json(node.data, "/v1/chat/completions", &key.token, CHAT);

    assert_eq!(reply.status, 200, "the answer: {}", reply.text());
    assert_eq!(
        reply.json()["choices"][0]["message"]["content"],
        "ok",
        "the caller received the provider's whole answer"
    );
    assert!(
        gate.posts("/decide") >= 1,
        "the pool's gate was asked before the provider"
    );
    assert_eq!(
        upstream.posts("chat/completions"),
        1,
        "one request reached the provider"
    );
    let records = node.settled(&key, 1);
    assert_eq!(records.len(), 1, "one request is one unit: {records:?}");
    let record = &records[0];
    assert_eq!(record["outcome"], "completed", "{record}");
    assert_eq!(record["finish"], "complete", "{record}");
    assert_eq!(record["status"], 200, "{record}");
    assert_eq!(
        delivery(record),
        ("whole".to_owned(), None, reply.body.len() as u64),
        "the delivery record states the bytes the caller received: {record}"
    );
    assert_eq!(record["usage"]["classes"]["input"], "7", "{record}");
    assert_eq!(record["usage"]["classes"]["output"], "5", "{record}");
}

/// One streamed chunk of an OpenAI chat completion carrying `content`.
fn chunk(content: &str) -> String {
    format!(
        "data: {}\n\n",
        json!({
            "id": "chatcmpl-e2e", "object": "chat.completion.chunk", "created": 1,
            "model": "test-model",
            "choices": [{"index": 0, "delta": {"role": "assistant", "content": content},
                         "finish_reason": null}]
        })
    )
}

/// One piece of a chunked HTTP/1.1 body.
fn piece(conn: &mut TcpStream, bytes: &str) -> std::io::Result<()> {
    write!(conn, "{:x}\r\n{bytes}\r\n", bytes.len())?;
    conn.flush()
}

/// An OpenAI provider that streams: the first chunk at once, the rest only when the test lets one
/// answer go on (one token on `go` per answer).
fn streaming_provider(go: mpsc::Receiver<()>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind the streaming provider");
    let port = listener.local_addr().expect("its address").port();
    let go = Arc::new(Mutex::new(go));
    std::thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                let mut conn = conn;
                let Some((head, _)) = common::upstream::read_request(&mut conn) else {
                    return;
                };
                if !head.contains("chat/completions") {
                    return common::upstream::respond(&mut conn, 200, &"{}");
                }
                let _ = conn.write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                      transfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                );
                let _ = piece(&mut conn, &chunk("one"));
                let _ = go
                    .lock()
                    .expect("the release")
                    .recv_timeout(Duration::from_secs(60));
                // Enough later chunks, spaced out, that a write to a caller who has gone fails.
                for _ in 0..40 {
                    if piece(&mut conn, &chunk("two")).is_err() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let last = format!(
                    "data: {}\n\ndata: [DONE]\n\n",
                    json!({
                        "id": "chatcmpl-e2e", "object": "chat.completion.chunk", "created": 1,
                        "model": "test-model",
                        "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                        "usage": {"prompt_tokens": 7, "completion_tokens": 41, "total_tokens": 48}
                    })
                );
                let _ = piece(&mut conn, &last);
                let _ = conn.write_all(b"0\r\n\r\n");
                let _ = conn.flush();
            });
        }
    });
    port
}

const STREAMED_CHAT: &[u8] =
    br#"{"model":"e2e","stream":true,"messages":[{"role":"user","content":"hi"}]}"#;

/// Send a streamed chat request and read until the first chunk's text has arrived.
fn open_stream(port: u16, token: &str) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect to the node");
    stream.set_read_timeout(Some(WAIT)).expect("a read timeout");
    write!(
        stream,
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\
         Authorization: Bearer {token}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n",
        STREAMED_CHAT.len()
    )
    .expect("send the head");
    stream.write_all(STREAMED_CHAT).expect("send the body");
    let mut seen = Vec::new();
    let mut buffer = [0u8; 4096];
    let deadline = Instant::now() + WAIT;
    loop {
        let body_started = seen
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .is_some_and(|head_end| {
                seen[head_end..]
                    .windows(5)
                    .any(|window| window == b"\"one\"")
            });
        if body_started {
            assert!(
                seen.starts_with(b"HTTP/1.1 200"),
                "the stream opened with a 200: {:?}",
                String::from_utf8_lossy(&seen)
            );
            return stream;
        }
        assert!(
            Instant::now() < deadline,
            "the first chunk never arrived: {:?}",
            String::from_utf8_lossy(&seen)
        );
        let read = stream.read(&mut buffer).expect("read the answer");
        assert!(read > 0, "the node closed before the first chunk");
        seen.extend_from_slice(&buffer[..read]);
    }
}

#[test]
fn a_caller_that_goes_away_mid_body_is_recorded_part_and_its_unit_settles() {
    let (go, released) = mpsc::channel();
    let provider = streaming_provider(released);
    let node = Deployment::new("part")
        .provider("mock", "openai", &format!("http://127.0.0.1:{provider}"))
        .section("models:\n  test-model:\n    provider: mock\n")
        .section("pools:\n  e2e:\n    members:\n      - { model: test-model }\n")
        .section("groups:\n  one-at-a-time:\n    limits:\n      - { concurrent: 1 }\n")
        .boot();
    let key = node.mint(&json!({ "name": "e2e-part", "group": "one-at-a-time" }));

    let stream = open_stream(node.data, &key.token);
    // While that answer is in flight the key's one slot is taken: the unit is open.
    let held = post_json(node.data, "/v1/chat/completions", &key.token, STREAMED_CHAT);
    assert_eq!(
        held.status,
        429,
        "a second request while the first is in flight: {}",
        held.text()
    );
    // The caller goes away with part of the body read: its connection is reset, not closed in order.
    socket2::SockRef::from(&stream)
        .set_linger(Some(Duration::ZERO))
        .expect("reset on close");
    drop(stream);
    go.send(()).expect("the provider is holding the answer");

    let record = node.settled_where(&key, |record| record["status"] == 200);
    assert_eq!(record["finish"], "partial", "{record}");
    let (state, reason, body_bytes) = delivery(&record);
    assert_eq!(
        (state.as_str(), reason.as_deref()),
        ("part", Some("caller_gone")),
        "{record}"
    );
    assert!(
        body_bytes > 0,
        "the first chunk was made for the caller: {record}"
    );
    // The unit settled: the slot it held is free, and the same key is served to the end.
    go.send(()).expect("the provider serves the next answer");
    let next = post_json(node.data, "/v1/chat/completions", &key.token, STREAMED_CHAT);
    assert_eq!(next.status, 200, "the next request: {}", next.text());
    assert!(
        next.text().contains("[DONE]"),
        "the next answer ran to its end: {}",
        next.text()
    );
}
