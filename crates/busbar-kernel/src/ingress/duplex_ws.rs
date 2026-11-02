// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures::channel::mpsc::{channel as bounded, unbounded, Receiver, UnboundedSender};
use futures::{SinkExt, StreamExt};

pub(crate) const MAX_QUEUED_INBOUND_FRAMES: usize = 64;

fn max_inbound_message_bytes() -> usize {
    crate::config::limits::installed()
        .map(|l| l.request_body_max_bytes)
        .unwrap_or(crate::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES)
}

pub fn channel(socket: WebSocket) -> (Receiver<Vec<u8>>, UnboundedSender<Vec<u8>>) {
    let (mut ws_tx, mut ws_rx) = socket.split();
    let (mut in_tx, in_rx) = bounded::<Vec<u8>>(MAX_QUEUED_INBOUND_FRAMES);
    let (out_tx, mut out_rx) = unbounded::<Vec<u8>>();

    tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(b)) => {
                    if in_tx.send(b.to_vec()).await.is_err() {
                        break;
                    }
                }
                Ok(Message::Text(t)) => {
                    if in_tx.send(t.as_bytes().to_vec()).await.is_err() {
                        break;
                    }
                }

                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    tokio::spawn(async move {
        while let Some(frame) = out_rx.next().await {
            if ws_tx.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    (in_rx, out_tx)
}

pub fn accept<F, Fut>(upgrade: WebSocketUpgrade, on_socket: F) -> Response
where
    F: FnOnce(Receiver<Vec<u8>>, UnboundedSender<Vec<u8>>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let cap = max_inbound_message_bytes();
    upgrade
        .max_message_size(cap)
        .max_frame_size(cap)
        .on_upgrade(move |socket| async move {
            let (stream, sink) = channel(socket);
            on_socket(stream, sink).await;
        })
}

pub fn bridge(upgrade: WebSocketUpgrade, pipe: crate::plane_routes::SessionPipe) -> Response {
    let cap = max_inbound_message_bytes();
    upgrade
        .max_message_size(cap)
        .max_frame_size(cap)
        .on_upgrade(move |socket| async move {
            let crate::plane_routes::SessionPipe {
                from_caller,
                mut to_caller,
            } = pipe;
            let (mut ws_tx, mut ws_rx) = socket.split();
            let inbound = async move {
                while let Some(Ok(msg)) = ws_rx.next().await {
                    let bytes = match msg {
                        Message::Binary(b) => b.to_vec(),
                        Message::Text(t) => t.as_bytes().to_vec(),
                        Message::Close(_) => break,

                        _ => continue,
                    };
                    if from_caller.send(bytes).await.is_err() {
                        break;
                    }
                }
            };
            let outbound = async move {
                while let Some(out) = to_caller.recv().await {
                    let msg = if out.text {
                        match String::from_utf8(out.bytes) {
                            Ok(text) => Message::Text(text.into()),
                            Err(e) => Message::Binary(e.into_bytes().into()),
                        }
                    } else {
                        Message::Binary(out.bytes.into())
                    };
                    if ws_tx.send(msg).await.is_err() {
                        return;
                    }
                }
                let _ = ws_tx.close().await;
            };
            tokio::select! {
                () = inbound => {}
                () = outbound => {}
            }
        })
}

pub enum SessionUpgrade {
    Ws(WebSocketUpgrade),

    Framed(crate::plane_routes::FramedSession),
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for SessionUpgrade {
    type Rejection = axum::extract::ws::rejection::WebSocketUpgradeRejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        if let Some(slot) = parts
            .extensions
            .get::<crate::plane_routes::FramedSession>()
            .cloned()
        {
            let named = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .map(axum::http::HeaderValue::as_bytes)
            };
            if parts.method == axum::http::Method::GET
                && named("sec-websocket-key").is_some()
                && named("sec-websocket-version") == Some(b"13".as_slice())
            {
                return Ok(Self::Framed(slot));
            }
        }
        <WebSocketUpgrade as axum::extract::FromRequestParts<S>>::from_request_parts(parts, state)
            .await
            .map(Self::Ws)
    }
}

pub fn bridge_either(upgrade: SessionUpgrade, pipe: crate::plane_routes::SessionPipe) -> Response {
    match upgrade {
        SessionUpgrade::Ws(upgrade) => bridge(upgrade, pipe),
        SessionUpgrade::Framed(slot) => {
            slot.put(pipe);
            let mut r = Response::new(axum::body::Body::empty());
            *r.status_mut() = axum::http::StatusCode::SWITCHING_PROTOCOLS;
            r
        }
    }
}
