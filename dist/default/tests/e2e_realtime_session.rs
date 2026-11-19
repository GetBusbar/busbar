// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One OpenAI Realtime session over WebSocket through the real binary: a caller opens
//! `GET /v1/realtime?model=test-model` with its key, the engine dials the deployment's Realtime
//! provider (a fixture far end on loopback) with the deployment's key, the caller is answered 101,
//! and one recorded text turn (`tests/fixtures/realtime/openai_text_turn.jsonl`) crosses each way
//! as the OpenAI Realtime protocol orders it: the server's `session.created` first, then the
//! caller's `session.update`, `conversation.item.create` and `response.create`, each answered by the
//! provider's events down to `response.done`. The caller closes; the session's unit settles once.
//!
//! The binary links the streaming plane (`plane-streaming`, always on), so this test is not gated
//! on a linked-door cfg: it runs in every unix build of the distribution.

#![cfg(unix)]

mod common;
mod e2e_support;

use std::time::Duration;

use e2e_support::{
    bearer, realtime, streams_section, Deployment, Key, Node, WAIT, WS_TRANSPORT_IMAGE,
};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};
use tokio_tungstenite::WebSocketStream;

/// The recorded turn, one event per line, each with the side that sends it.
const TURN: &str = include_str!("fixtures/realtime/openai_text_turn.jsonl");

/// The door a caller opens, and the model its session names.
const DOOR: &str = "/v1/realtime?model=test-model";

/// Which side sends an event of the recorded turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    /// The caller (a client event).
    Client,
    /// The provider (a server event).
    Server,
}

/// One event of the recorded turn.
#[derive(Debug, Clone)]
struct Step {
    side: Side,
    event: Value,
}

impl Step {
    fn kind(&self) -> &str {
        self.event["type"]
            .as_str()
            .expect("every recorded event states its type")
    }
}

fn turn() -> Vec<Step> {
    TURN.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let row: Value = serde_json::from_str(line).expect("a fixture row is JSON");
            let side = match row["dir"].as_str() {
                Some("client") => Side::Client,
                Some("server") => Side::Server,
                other => panic!("a fixture row's side is client or server: {other:?}"),
            };
            Step {
                side,
                event: row["event"].clone(),
            }
        })
        .collect()
}

/// The `type` of a Realtime event carried in a text frame.
fn event_type(message: &Message) -> Option<String> {
    let Message::Text(text) = message else {
        return None;
    };
    serde_json::from_str::<Value>(text.as_str()).ok()?["type"]
        .as_str()
        .map(str::to_owned)
}

/// What the fixture provider saw of the one session it served.
#[derive(Debug)]
enum Seen {
    /// The engine's upgrade request: its target and the credential it presented.
    Dialled {
        target: String,
        authorization: Option<String>,
    },
    /// A client event of the recorded turn arrived, as a text frame, in its place.
    Event(String),
    /// The provider did not see what the recorded turn says comes next.
    Wrong(String),
    /// The session ended.
    Gone,
}

/// A Realtime provider on loopback that serves one session by the recorded turn: it sends each
/// server event in its place and waits for each client event (frames the engine adds of its own
/// are passed over; a client event of the turn arriving out of its place is wrong).
struct Provider {
    port: u16,
    seen: mpsc::UnboundedReceiver<Seen>,
}

impl Provider {
    async fn start(steps: Vec<Step>) -> Provider {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the provider");
        let port = listener.local_addr().expect("its address").port();
        let (tx, seen) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve(stream, steps.clone(), tx.clone()));
            }
        });
        Provider { port, seen }
    }

    async fn next(&mut self, what: &str) -> Seen {
        match tokio::time::timeout(WAIT, self.seen.recv()).await {
            Ok(Some(seen)) => seen,
            Ok(None) | Err(_) => panic!("the provider never saw {what}"),
        }
    }
}

async fn serve(stream: TcpStream, steps: Vec<Step>, seen: mpsc::UnboundedSender<Seen>) {
    let dialled = seen.clone();
    let callback = move |request: &Request, response: Response| {
        let _ = dialled.send(Seen::Dialled {
            target: request.uri().to_string(),
            authorization: request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        });
        Ok::<Response, ErrorResponse>(response)
    };
    let Ok(socket) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
        return;
    };
    let (mut sink, mut source) = socket.split();
    let client_kinds: Vec<String> = steps
        .iter()
        .filter(|step| step.side == Side::Client)
        .map(|step| step.kind().to_owned())
        .collect();
    for step in &steps {
        match step.side {
            Side::Server => {
                if sink
                    .send(Message::text(step.event.to_string()))
                    .await
                    .is_err()
                {
                    let _ = seen.send(Seen::Wrong(format!(
                        "the session ended before the provider sent {}",
                        step.kind()
                    )));
                    return;
                }
            }
            Side::Client => loop {
                match tokio::time::timeout(WAIT, source.next()).await {
                    Ok(Some(Ok(message))) => match event_type(&message) {
                        Some(kind) if kind == step.kind() => {
                            let _ = seen.send(Seen::Event(kind));
                            break;
                        }
                        Some(kind) if client_kinds.contains(&kind) => {
                            let _ = seen.send(Seen::Wrong(format!(
                                "{kind} arrived where the turn has {}",
                                step.kind()
                            )));
                            return;
                        }
                        // The engine's own frames (a ping, an event of its own) are passed over.
                        _ => {}
                    },
                    Ok(Some(Err(_)) | None) => {
                        let _ = seen.send(Seen::Wrong(format!(
                            "the session ended before the caller's {}",
                            step.kind()
                        )));
                        return;
                    }
                    Err(_) => {
                        let _ = seen.send(Seen::Wrong(format!(
                            "the caller's {} never arrived",
                            step.kind()
                        )));
                        return;
                    }
                }
            },
        }
    }
    // The turn is played: the provider holds the session until its far side ends it.
    while let Some(Ok(message)) = source.next().await {
        if message.is_close() {
            break;
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

fn boot(tag: &str, provider: u16) -> Node {
    realtime(Deployment::new(tag), &format!("ws://127.0.0.1:{provider}"))
        .plugin("transport", WS_TRANSPORT_IMAGE)
        .section(&streams_section(""))
        .boot()
}

type Session = WebSocketStream<TcpStream>;

/// Open the Realtime door as `key`. `Err` is the status of the HTTP answer given instead of a 101.
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

/// The caller's next event of type `kind`; the engine's own frames before it are passed over.
async fn received(session: &mut Session, kind: &str) -> Message {
    let deadline = tokio::time::Instant::now() + WAIT;
    let mut passed = Vec::new();
    loop {
        match tokio::time::timeout_at(deadline, session.next()).await {
            Ok(Some(Ok(message))) if event_type(&message).as_deref() == Some(kind) => {
                return message
            }
            Ok(Some(Ok(message))) => passed.push(event_type(&message)),
            Ok(Some(Err(error))) => panic!("the caller's session failed before {kind}: {error}"),
            Ok(None) => panic!("the caller's session ended before {kind}; it saw {passed:?}"),
            Err(_) => panic!("the caller never received {kind}; it saw {passed:?}"),
        }
    }
}

#[test]
fn e2e_realtime_session_carries_one_text_turn_through_the_binary() {
    let steps = turn();
    let runtime = runtime();
    let mut provider = runtime.block_on(Provider::start(steps.clone()));
    let node = boot("realtime-session", provider.port);
    let key = node.mint(&json!({ "name": "e2e-realtime" }));

    runtime.block_on(async {
        let mut caller = match open(&node, &key).await {
            Ok(session) => session,
            Err(status) => panic!(
                "the hand-over was refused: the Realtime upgrade was answered {status} instead of \
                 101, so no session reached the provider"
            ),
        };

        // The engine dialled the provider's Realtime door for the caller's model, presenting the
        // deployment's key: the caller's own credential never crosses to the provider.
        let Seen::Dialled {
            target,
            authorization,
        } = provider.next("the engine's upgrade request").await
        else {
            panic!("the provider's first sight of the session is its upgrade request")
        };
        assert!(
            target.starts_with("/v1/realtime"),
            "the provider's door: {target}"
        );
        assert!(
            target.contains("model=test-model"),
            "the session names its model to the provider: {target}"
        );
        assert_eq!(
            authorization.as_deref(),
            Some("Bearer k"),
            "the provider is given the deployment's key, never the caller's"
        );
        assert_ne!(
            authorization.as_deref(),
            Some(bearer(&key.token).as_str()),
            "the caller's key reached the provider"
        );

        // The recorded turn, in its order: each side's events reach the other as text frames.
        for step in &steps {
            match step.side {
                Side::Client => {
                    caller
                        .send(Message::text(step.event.to_string()))
                        .await
                        .unwrap_or_else(|error| {
                            panic!("the caller could not send {}: {error}", step.kind())
                        });
                    match provider.next(step.kind()).await {
                        Seen::Event(kind) => assert_eq!(kind, step.kind()),
                        other => panic!("the provider, waiting for {}: {other:?}", step.kind()),
                    }
                }
                Side::Server => {
                    let message = received(&mut caller, step.kind()).await;
                    assert!(
                        message.is_text(),
                        "the provider's {} reached the caller as {message:?}",
                        step.kind()
                    );
                }
            }
        }

        // The caller ends the session as the protocol ends it: a close frame. The provider's side
        // of the session ends with it.
        caller
            .close(None)
            .await
            .expect("the caller closes its session");
        loop {
            match provider.next("the end of the session").await {
                Seen::Gone => break,
                Seen::Wrong(why) => panic!("the provider after the turn: {why}"),
                Seen::Dialled { target, .. } => {
                    panic!("the engine dialled the provider a second time: {target}")
                }
                Seen::Event(_) => {}
            }
        }
        // Nothing more reaches the provider once the session has ended.
        assert!(
            tokio::time::timeout(Duration::from_millis(300), provider.seen.recv())
                .await
                .map_or(true, |more| more.is_none()),
            "the provider saw more after the session ended"
        );
    });

    // The session is one unit, and it settles once.
    let record = node.settled_where(&key, |record| record["status"] == 101);
    let sessions = node
        .records_of(&key)
        .into_iter()
        .filter(|record| record["status"] == 101)
        .count();
    assert_eq!(
        sessions, 1,
        "the session settled as {sessions} units: {record}"
    );
}
