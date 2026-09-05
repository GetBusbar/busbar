// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LOOPBACK HTTP "PROVIDER" for plane tests: a real listener on `127.0.0.1` that answers the
//! queued replies and RECORDS what it was dialed with (path, headers, body), so a plane's egress leg
//! is exercised over the production request path and the test asserts on the bytes the upstream
//! actually saw. The neutral twin of the mock server core's own test support carries, so a plane crate
//! drives a loopback provider without naming `busbar_core::test_support`.

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, Response, StatusCode},
    routing::any,
    Router,
};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

/// One queued reply the loopback provider serves.
#[derive(Debug, Clone)]
pub enum MockResponse {
    /// A JSON body under `status`.
    Ok {
        status: StatusCode,
        body: serde_json::Value,
    },
}

impl Default for MockResponse {
    fn default() -> Self {
        MockResponse::Ok {
            status: StatusCode::OK,
            body: serde_json::json!({ "ok": true }),
        }
    }
}

/// The reply queue plus the last request the provider received.
#[derive(Debug, Default)]
pub struct MockServerState {
    queued_replies: Mutex<Vec<MockResponse>>,
    last_auth_header: Mutex<Option<String>>,
    last_request_body: Mutex<Option<Vec<u8>>>,
    last_request_headers: Mutex<Option<axum::http::HeaderMap>>,
    last_request_path: Mutex<Option<String>>,
}

impl MockServerState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a reply (served last-queued-first, matching the core fixture).
    pub fn push(&self, response: MockResponse) {
        self.queued_replies.lock().unwrap().push(response);
    }

    pub fn next_response(&self) -> Option<MockResponse> {
        self.queued_replies.lock().unwrap().pop()
    }

    /// The `Authorization` header the provider was last dialed with.
    pub fn get_last_auth_header(&self) -> Option<String> {
        self.last_auth_header.lock().unwrap().clone()
    }

    /// The request path the provider last received.
    pub fn get_last_request_path(&self) -> Option<String> {
        self.last_request_path.lock().unwrap().clone()
    }

    /// The raw body bytes the provider last received.
    pub fn get_last_request_body(&self) -> Option<Vec<u8>> {
        self.last_request_body.lock().unwrap().clone()
    }

    /// One request header the provider last received, by name (case-insensitive).
    pub fn get_last_request_header(&self, name: &str) -> Option<String> {
        self.last_request_headers
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }
}

/// The running loopback provider; `shutdown` aborts its serve task.
pub struct MockServer {
    addr: SocketAddr,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    /// Bind an ephemeral loopback port and serve every path through `state`'s reply queue.
    pub async fn new(state: Arc<MockServerState>) -> Self {
        let app = Router::new().fallback(any(mock_handler)).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            addr,
            handle: Some(handle),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub async fn shutdown(self) {
        if let Some(handle) = self.handle {
            handle.abort();
        }
    }
}

async fn mock_handler(
    State(state): State<Arc<MockServerState>>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();
    *state.last_request_path.lock().unwrap() = Some(parts.uri.path().to_string());
    *state.last_request_headers.lock().unwrap() = Some(parts.headers.clone());
    if let Some(auth) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        *state.last_auth_header.lock().unwrap() = Some(auth.to_string());
    }
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    *state.last_request_body.lock().unwrap() = Some(body_bytes.to_vec());

    match state.next_response().unwrap_or_default() {
        MockResponse::Ok { status, body } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
    }
}
