// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A real WebSocket socket adapter for tests of the kernel's transport-neutral session route.
//! This implementation is dev-only; the kernel's normal dependency graph carries no WS engine.

use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::{FromRequestParts, Request};
use axum::middleware::Next;
use axum::response::Response;
use busbar_kernel::plane_routes::{FramedSession, SessionAdmission, SessionPipe};
use futures::{SinkExt, StreamExt};

/// Adapt real socket upgrades around a kernel router while leaving refused responses intact.
pub fn adapt(router: axum::Router) -> axum::Router {
    router.layer(axum::middleware::from_fn(adapt_request))
}

async fn adapt_request(request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    let Ok(upgrade) = WebSocketUpgrade::from_request_parts(&mut parts, &()).await else {
        return next.run(Request::from_parts(parts, body)).await;
    };
    let (sender, mut admissions) = tokio::sync::mpsc::unbounded_channel::<SessionAdmission>();
    let slot = FramedSession::with_admission(sender, 0);
    parts.extensions.insert(slot.clone());
    let routed = next.run(Request::from_parts(parts, body));
    tokio::pin!(routed);
    // Admission is answered only after the actual wire upgrade extractor accepted this request.
    // Drive the request and its admission exchange together; no per-request task is needed.
    let response = loop {
        tokio::select! {
            request = admissions.recv() => match request {
                Some(request) => { let _ = request.reply.send(request.stream == 0); }
                None => break routed.await,
            },
            response = &mut routed => break response,
        }
    };
    if response.status() != axum::http::StatusCode::SWITCHING_PROTOCOLS {
        return response;
    }
    let Some(pipe) = slot.take() else {
        return response;
    };
    let mut upgraded = bridge(upgrade, pipe);
    for (name, value) in response.headers() {
        if !upgraded.headers().contains_key(name) {
            upgraded.headers_mut().append(name, value.clone());
        }
    }
    upgraded
}

fn bridge(upgrade: WebSocketUpgrade, pipe: SessionPipe) -> Response {
    let cap = busbar_kernel::config::limits::installed()
        .map(|limits| limits.request_body_max_bytes)
        .unwrap_or(busbar_kernel::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES);
    upgrade
        .max_message_size(cap)
        .max_frame_size(cap)
        .on_upgrade(move |socket| async move {
            let SessionPipe {
                from_caller,
                mut to_caller,
            } = pipe;
            let (mut writer, mut reader) = socket.split();
            let inbound = async move {
                while let Some(Ok(message)) = reader.next().await {
                    let bytes = match message {
                        Message::Binary(bytes) => bytes.to_vec(),
                        Message::Text(text) => text.as_bytes().to_vec(),
                        Message::Close(_) => break,
                        _ => continue,
                    };
                    if from_caller.send(bytes).await.is_err() {
                        break;
                    }
                }
            };
            let outbound = async move {
                while let Some(frame) = to_caller.recv().await {
                    let message = if frame.text {
                        match String::from_utf8(frame.bytes) {
                            Ok(text) => Message::Text(text.into()),
                            Err(error) => Message::Binary(error.into_bytes().into()),
                        }
                    } else {
                        Message::Binary(frame.bytes.into())
                    };
                    if writer.send(message).await.is_err() {
                        return;
                    }
                }
                let _ = writer.close().await;
            };
            tokio::select! {
                () = inbound => {}
                () = outbound => {}
            }
        })
}
