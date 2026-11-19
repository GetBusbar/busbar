// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A WebSocket upgrade through the real binary (`GET /v1/realtime`, the streaming plane's
//! server-to-server door) to a provider that speaks WebSocket: when the caller is answered 101,
//! what crosses each way and as what kind of frame, how each side's end reaches the other, and
//! what a caller is told when the session cannot be opened.

#![cfg(unix)]
#![cfg(linked_every_plane_door)]

mod common;
mod e2e_support;

use std::sync::Arc;
use std::time::Duration;

use e2e_support::{
    bearer, chat_answer, delivery, post_json, realtime, streams_section, Deployment, Key, Node,
    Scripted, CHAT, WAIT, WS_TRANSPORT_IMAGE,
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

/// What the provider saw.
#[derive(Debug)]
enum Seen {
    /// An upgrade request arrived (nothing has been answered yet).
    Dialled {
        path: String,
        authorization: Option<String>,
    },
    /// One whole message, and whether it was a text frame.
    Message { text: bool, bytes: Vec<u8> },
    /// The session ended, by a close frame or by the connection going away.
    Gone,
}

/// What the test has the provider do on its live session.
enum Tell {
    Send(Message),
    Close,
}

/// A provider that speaks WebSocket. One that is `holding` reads an upgrade request and answers
/// nothing until [`WsProvider::accept`].
struct WsProvider {
    port: u16,
    seen: mpsc::UnboundedReceiver<Seen>,
    tell: mpsc::UnboundedSender<Tell>,
    accepting: watch::Sender<bool>,
}

impl WsProvider {
    async fn start(holding: bool) -> WsProvider {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the provider");
        let port = listener.local_addr().expect("its address").port();
        let (seen_tx, seen) = mpsc::unbounded_channel();
        let (tell, told) = mpsc::unbounded_channel();
        let told = Arc::new(tokio::sync::Mutex::new(told));
        let (accepting, accepted) = watch::channel(!holding);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(
                    stream,
                    seen_tx.clone(),
                    Arc::clone(&told),
                    accepted.clone(),
                ));
            }
        });
        WsProvider {
            port,
            seen,
            tell,
            accepting,
        }
    }

    fn accept(&self) {
        let _ = self.accepting.send(true);
    }

    fn tell(&self, tell: Tell) {
        self.tell.send(tell).expect("the provider is serving");
    }

    /// The next thing the provider saw that `is` holds for; what it saw before is passed over
    /// (a session may open with the engine's own frames).
    async fn seen_where(&mut self, what: &str, is: impl Fn(&Seen) -> bool) -> Seen {
        let deadline = tokio::time::Instant::now() + WAIT;
        let mut passed = Vec::new();
        loop {
            match tokio::time::timeout_at(deadline, self.seen.recv()).await {
                Ok(Some(seen)) if is(&seen) => return seen,
                Ok(Some(seen)) => passed.push(seen),
                Ok(None) | Err(_) => panic!("the provider never saw {what}; it saw {passed:?}"),
            }
        }
    }

    /// Whether an upgrade request has reached the provider so far.
    fn was_dialled(&mut self) -> bool {
        let mut dialled = false;
        while let Ok(seen) = self.seen.try_recv() {
            dialled |= matches!(seen, Seen::Dialled { .. });
        }
        dialled
    }
}

async fn serve(
    mut stream: TcpStream,
    seen: mpsc::UnboundedSender<Seen>,
    told: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<Tell>>>,
    mut accepted: watch::Receiver<bool>,
) {
    // Read the request head without taking it, so nothing is answered before the test says so.
    let mut peeked = vec![0u8; 16 * 1024];
    let head = loop {
        let Ok(read) = stream.peek(&mut peeked).await else {
            return;
        };
        if read == 0 {
            return;
        }
        if let Some(end) = peeked[..read]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break String::from_utf8_lossy(&peeked[..end]).into_owned();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let field = |name: &str| {
        head.lines().skip(1).find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    if !field("upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket")) {
        // A probe, not a session.
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
            .await;
        return;
    }
    let _ = seen.send(Seen::Dialled {
        path: head.split_whitespace().nth(1).unwrap_or("").to_owned(),
        authorization: field("authorization"),
    });
    while !*accepted.borrow() {
        if accepted.changed().await.is_err() {
            return;
        }
    }
    let Ok(socket) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    let (mut sink, mut source) = socket.split();
    let mut told = told.lock().await;
    loop {
        tokio::select! {
            message = source.next() => match message {
                Some(Ok(message)) if message.is_text() || message.is_binary() => {
                    let text = message.is_text();
                    let _ = seen.send(Seen::Message { text, bytes: message.into_data().to_vec() });
                }
                Some(Ok(message)) if message.is_close() => break,
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
            tell = told.recv() => match tell {
                Some(Tell::Send(message)) => {
                    if sink.send(message).await.is_err() {
                        break;
                    }
                }
                Some(Tell::Close) => {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
                None => break,
            },
        }
    }
    let _ = seen.send(Seen::Gone);
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime")
}

/// The streaming plane over a provider at `ws://127.0.0.1:<port>`, on a listener that can carry
/// an upgrade.
fn ws_deployment(tag: &str, provider: u16) -> Deployment {
    realtime(Deployment::new(tag), &format!("ws://127.0.0.1:{provider}"))
        .plugin("transport", WS_TRANSPORT_IMAGE)
}

fn ws_node(tag: &str, provider: u16) -> Node {
    ws_deployment(tag, provider)
        .section(&streams_section(""))
        .boot()
}

const DOOR: &str = "/v1/realtime?model=test-model";

/// The upgrade request a caller writes, as bytes on its own socket.
fn upgrade_head(port: u16, token: &str) -> String {
    format!(
        "GET {DOOR} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: Upgrade\r\n\
         Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nAuthorization: Bearer {token}\r\n\r\n"
    )
}

type Session = WebSocketStream<TcpStream>;

/// Upgrade as `key`. `Err` is the status of the HTTP answer given instead of a 101.
async fn open(node: &Node, key: &Key) -> Result<Session, u16> {
    let tcp = TcpStream::connect(("127.0.0.1", node.data))
        .await
        .expect("connect to the node");
    let mut request = format!("ws://127.0.0.1:{}{DOOR}", node.data)
        .into_client_request()
        .expect("an upgrade request");
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&bearer(&key.token)).expect("a header value"),
    );
    match tokio::time::timeout(WAIT, tokio_tungstenite::client_async(request, tcp)).await {
        Ok(Ok((session, _))) => Ok(session),
        Ok(Err(WsError::Http(answer))) => Err(answer.status().as_u16()),
        Ok(Err(other)) => panic!("the upgrade was neither a 101 nor an HTTP answer: {other}"),
        Err(_) => panic!("the upgrade was not answered within {WAIT:?}"),
    }
}

/// The caller's next text or binary message that `is` holds for.
async fn received(session: &mut Session, what: &str, is: impl Fn(&Message) -> bool) -> Message {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        match tokio::time::timeout_at(deadline, session.next()).await {
            Ok(Some(Ok(message))) if is(&message) => return message,
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) => panic!("the caller's session failed before {what}: {error}"),
            Ok(None) => panic!("the caller's session ended before {what}"),
            Err(_) => panic!("the caller never received {what}"),
        }
    }
}

/// The `type` of a Realtime event.
fn event_type(bytes: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(bytes).ok()?["type"]
        .as_str()
        .map(str::to_owned)
}

#[test]
fn the_caller_is_answered_101_only_after_the_provider_accepts() {
    let runtime = runtime();
    let mut provider = runtime.block_on(WsProvider::start(true));
    let node = ws_node("ws-101", provider.port);
    let key = node.mint(&json!({ "name": "e2e-ws" }));

    runtime.block_on(async {
        let mut caller = TcpStream::connect(("127.0.0.1", node.data))
            .await
            .expect("connect to the node");
        caller
            .write_all(upgrade_head(node.data, &key.token).as_bytes())
            .await
            .expect("send the upgrade request");
        // The engine has dialled the provider, which has not answered it.
        let dialled = provider
            .seen_where("the engine's upgrade request", |seen| {
                matches!(seen, Seen::Dialled { .. })
            })
            .await;
        let Seen::Dialled {
            path,
            authorization,
        } = dialled
        else {
            unreachable!("seen_where returned what it was asked for")
        };
        assert!(
            path.starts_with("/v1/realtime"),
            "the provider's door: {path}"
        );
        assert_eq!(
            authorization.as_deref(),
            Some("Bearer k"),
            "the provider is given the deployment's key, never the caller's"
        );
        let mut answer = [0u8; 1024];
        let early =
            tokio::time::timeout(Duration::from_millis(500), caller.read(&mut answer)).await;
        assert!(
            early.is_err(),
            "the caller was answered before the provider accepted: {:?}",
            early
                .map(|read| read.map(|read| String::from_utf8_lossy(&answer[..read]).into_owned()))
        );

        provider.accept();

        let read = tokio::time::timeout(WAIT, caller.read(&mut answer))
            .await
            .expect("the caller is answered once the provider accepts")
            .expect("read the answer");
        assert!(
            answer[..read].starts_with(b"HTTP/1.1 101"),
            "the answer: {:?}",
            String::from_utf8_lossy(&answer[..read])
        );
    });
}

#[test]
fn a_text_frame_crosses_each_way_as_text() {
    let runtime = runtime();
    let mut provider = runtime.block_on(WsProvider::start(false));
    let node = ws_node("ws-text", provider.port);
    let key = node.mint(&json!({ "name": "e2e-ws" }));

    runtime.block_on(async {
        let mut caller = open(&node, &key).await.expect("a 101");

        caller
            .send(Message::text(r#"{"type":"response.create"}"#))
            .await
            .expect("the caller sends");
        let up = provider
            .seen_where("the caller's response.create", |seen| {
                matches!(seen, Seen::Message { bytes, .. }
                    if event_type(bytes).as_deref() == Some("response.create"))
            })
            .await;
        assert!(
            matches!(up, Seen::Message { text: true, .. }),
            "the caller's text frame reached the provider as {up:?}"
        );

        provider.tell(Tell::Send(Message::text(
            json!({
                "type": "response.done",
                "response": {"id": "resp_e2e", "status": "completed", "usage": {
                    "total_tokens": 3, "input_tokens": 1, "output_tokens": 2,
                    "input_token_details": {"text_tokens": 1, "audio_tokens": 0},
                    "output_token_details": {"text_tokens": 2, "audio_tokens": 0}
                }}
            })
            .to_string(),
        )));
        let down = received(&mut caller, "the provider's response.done", |message| {
            event_type(&message.clone().into_data()).as_deref() == Some("response.done")
        })
        .await;
        assert!(
            down.is_text(),
            "the provider's text frame reached the caller as {down:?}"
        );
    });
}

#[test]
fn a_binary_frame_crosses_each_way_as_binary_with_its_bytes() {
    const UP: [u8; 6] = [0x00, 0xff, 0x10, 0x80, 0x7f, 0x0a];
    const DOWN: [u8; 6] = [0xfe, 0x00, 0x0d, 0x0a, 0x80, 0x01];
    let runtime = runtime();
    let mut provider = runtime.block_on(WsProvider::start(false));
    let node = ws_node("ws-binary", provider.port);
    let key = node.mint(&json!({ "name": "e2e-ws" }));

    runtime.block_on(async {
        let mut caller = open(&node, &key).await.expect("a 101");

        caller
            .send(Message::binary(UP.to_vec()))
            .await
            .expect("the caller sends");
        let up = provider
            .seen_where(
                "the caller's bytes",
                |seen| matches!(seen, Seen::Message { bytes, .. } if bytes[..] == UP),
            )
            .await;
        assert!(
            matches!(up, Seen::Message { text: false, .. }),
            "the caller's binary frame reached the provider as {up:?}"
        );

        provider.tell(Tell::Send(Message::binary(DOWN.to_vec())));
        let down = received(&mut caller, "the provider's bytes", |message| {
            message.clone().into_data()[..] == DOWN
        })
        .await;
        assert!(
            down.is_binary(),
            "the provider's binary frame reached the caller as {down:?}"
        );
    });
}

#[test]
fn a_provider_that_closes_ends_the_callers_session_with_a_close_frame() {
    let runtime = runtime();
    let mut provider = runtime.block_on(WsProvider::start(false));
    let node = ws_node("ws-upstream-close", provider.port);
    let key = node.mint(&json!({ "name": "e2e-ws" }));

    runtime.block_on(async {
        let mut caller = open(&node, &key).await.expect("a 101");
        provider
            .seen_where("the session", |seen| matches!(seen, Seen::Dialled { .. }))
            .await;

        provider.tell(Tell::Close);

        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            match tokio::time::timeout_at(deadline, caller.next()).await {
                Ok(Some(Ok(message))) if message.is_close() => break,
                Ok(Some(Ok(_))) => {}
                Ok(Some(Err(error))) => {
                    panic!("the caller's session was cut, not closed: {error}")
                }
                Ok(None) => panic!("the caller's connection ended with no close frame"),
                Err(_) => panic!("the caller was never told the provider closed"),
            }
        }
    });

    // The engine ended the session itself, to the last byte of its close: delivered whole.
    let record = node.settled_where(&key, |record| record["status"] == 101);
    assert_eq!(delivery(&record).0, "whole", "{record}");
}

#[test]
fn a_caller_that_drops_ends_the_providers_session_and_its_unit_settles() {
    let runtime = runtime();
    let mut provider = runtime.block_on(WsProvider::start(false));
    let node = ws_deployment("ws-caller-drop", provider.port)
        .section(&streams_section(""))
        .section("groups:\n  one-at-a-time:\n    limits:\n      - { concurrent: 1 }\n")
        .boot();
    let key = node.mint(&json!({ "name": "e2e-ws", "group": "one-at-a-time" }));

    let caller = runtime.block_on(async {
        let caller = open(&node, &key).await.expect("a 101");
        provider
            .seen_where("the session", |seen| matches!(seen, Seen::Dialled { .. }))
            .await;
        // While the session is live the key's one slot is taken: the unit is open.
        assert_eq!(
            open(&node, &key).await.err(),
            Some(429),
            "a second session while the first is live"
        );
        caller
    });

    // The caller goes away: no close frame, its connection is gone.
    drop(caller);

    runtime.block_on(async {
        provider
            .seen_where("the end of its session", |seen| matches!(seen, Seen::Gone))
            .await;
    });
    let record = node.settled_where(&key, |record| record["status"] == 101);
    let (state, reason, _) = delivery(&record);
    assert_ne!(state, "whole", "{record}");
    assert_eq!(reason.as_deref(), Some("caller_gone"), "{record}");
    // The unit settled: the slot it held is free, and the same key opens a session again.
    runtime.block_on(async {
        assert!(
            open(&node, &key).await.is_ok(),
            "the dropped session still holds the key's slot"
        );
    });
}

#[test]
fn a_provider_that_cannot_be_dialled_is_an_http_error_and_never_a_101() {
    let runtime = runtime();
    let node = ws_node("ws-no-provider", e2e_support::closed_port());
    let key = node.mint(&json!({ "name": "e2e-ws" }));

    let answered = runtime.block_on(async { open(&node, &key).await.err() });

    let status = answered.expect("a session with no provider was answered 101");
    assert!(
        (500..600).contains(&status),
        "a failed dial is the gateway's error, answered {status}"
    );
}

#[test]
fn a_key_over_its_budget_is_refused_before_any_101_and_the_provider_is_never_dialled() {
    let runtime = runtime();
    let mut provider = runtime.block_on(WsProvider::start(false));
    let chat = Scripted::start(200, &chat_answer(1, 1));
    // Every request costs its group 100 minor units, and the group `tight` may spend 100 in all.
    let node = Deployment::new("ws-over-budget")
        .provider("rt", "openai", &format!("ws://127.0.0.1:{}", provider.port))
        .provider("mock", "openai", &chat.url(""))
        .plugin("transport", WS_TRANSPORT_IMAGE)
        .section(
            "models:\n  chat-model:\n    provider: mock\n  test-model:\n    provider: rt\n\
             pools:\n  e2e:\n    members:\n      \
             - { model: chat-model }\nper_request_fee: 100\nrate_card:\n  \
             chat-model: { input_utok: 0, output_utok: 0 }\n  \
             test-model: { input_utok: 0, output_utok: 0 }\ngroups:\n  tight:\n    limits:\n      \
             - { budget: 100, per: total }\n",
        )
        .section(&streams_section(""))
        .boot();
    let spent = node.mint(&json!({ "name": "e2e-ws-spent", "group": "tight" }));
    let free = node.mint(&json!({ "name": "e2e-ws-free" }));

    // The key spends its group's budget on one chat request, and is then over it.
    let first = post_json(node.data, "/v1/chat/completions", &spent.token, CHAT);
    assert_eq!(
        first.status,
        200,
        "the request that spends the budget: {}",
        first.text()
    );
    node.settled(&spent, 1);
    let over = post_json(node.data, "/v1/chat/completions", &spent.token, CHAT);
    assert_eq!(
        over.status,
        429,
        "the key is over its budget: {}",
        over.text()
    );

    let refused = runtime.block_on(async { open(&node, &spent).await.err() });

    assert_eq!(
        refused,
        Some(429),
        "a session for a key over its budget is refused as an HTTP answer"
    );
    assert!(
        !provider.was_dialled(),
        "a refused session reached the provider"
    );
    // The door is open on this node: a key with no budget to exceed is answered 101.
    runtime.block_on(async {
        assert!(
            open(&node, &free).await.is_ok(),
            "a key under no budget is not answered 101"
        );
    });
}
