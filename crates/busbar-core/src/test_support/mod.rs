// Compiled three ways: under this crate's own cfg(test) (users: the in-crate test trees), under
// the `test-support` FEATURE (users: a dependent crate's tests — the bin's), and never in a
// production build. In the feature-only build the in-crate users are absent, so the fixture set
// reads as dead to rustc; that is the compilation mode, not rot.
#![cfg_attr(not(test), allow(dead_code))]
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! In-crate mock-upstream test harness.

/// A data-plane `AuthMiddleware` whose chain is `[keys]` — the built-in signed-key verifier. Since
/// 1.5.2 virtual-key ENFORCEMENT is driven by the chain shape, not the admin token, so any e2e
/// fixture that mints a vkey and expects it to authenticate must run `keys` in the chain. Used by
/// the `minimal_app()`-style governed fixtures (which set `inner.auth = keys_chain_auth()`) and,
/// via `TestApp::keys_chain()`, by the builder fixtures.
pub(crate) fn keys_chain_auth() -> std::sync::Arc<crate::auth::AuthMiddleware> {
    let cfg = crate::config::AuthCfg {
        chain: vec![crate::config::AuthChainEntry::bare(
            crate::config::KEYS_MODULE,
        )],
        ..crate::config::AuthCfg::default_none()
    };
    std::sync::Arc::new(crate::auth::AuthMiddleware::new_builtin(&cfg))
}

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use futures::{stream, Stream, StreamExt};

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, Response, StatusCode},
    routing::any,
    Router,
};
use serde_json::Value;
use tokio::task::JoinHandle;

#[derive(Debug, Clone)]
pub(crate) enum MockResponse {
    Ok {
        status: StatusCode,
        body: Value,
    },
    RateLimit {
        status: StatusCode,
        provider_signal: Option<&'static str>,
        /// When set, the mock emits a `Retry-After: <n>` response header (whole seconds).
        retry_after: Option<u64>,
    },
    Billing {
        status: StatusCode,
        code: &'static str,
        message: &'static str,
    },
    Auth {
        status: StatusCode,
    },
    ServerError {
        status: StatusCode,
        body: Value,
    },
    /// A non-2xx error that ALSO carries arbitrary response headers (e.g. a native Bedrock error's
    /// `x-amzn-requestid` + `x-amzn-errortype`), so a test can assert the proxy relays them verbatim.
    ServerErrorWithHeaders {
        status: StatusCode,
        body: Value,
        headers: Vec<(&'static str, &'static str)>,
    },
    Sse {
        events: Vec<String>,
        abort_at_index: Option<usize>,
    },
    /// A TRUE mid-stream transport failure: emit `ok_events` real SSE frames, then make the body
    /// stream yield an `Err`, aborting the connection mid-body (NOT a clean SSE `event: error` text
    /// frame, which `Sse{abort_at_index}` emits). The downstream client sees a reqwest transport
    /// error, exercising `FirstByteBody`'s `Poll::Ready(Some(Err))` arm — the path that appends the
    /// ingress protocol's native mid-stream error (a binary exception frame for bedrock ingress, an
    /// SSE error frame for SSE ingress) AFTER the already-sent real frames.
    SseTransportError {
        ok_events: Vec<String>,
    },
    /// A native AWS binary event-stream body (`application/vnd.amazon.eventstream`), as a real
    /// Bedrock ConverseStream backend emits it. `frames` is the ordered `(event_type, json_payload)`
    /// sequence (messageStart / contentBlockDelta / messageStop / metadata, …); each is encoded with
    /// `crate::eventstream::encode_frame` so the bytes carry real prelude/message CRC32s an AWS SDK
    /// validates. `amzn_request_id` is served as the `x-amzn-RequestId` response header — the value a
    /// same-protocol bedrock passthrough must forward VERBATIM rather than synthesizing a fresh UUID.
    /// Exercises the same-protocol bedrock-stream branch (verbatim binary relay, eventstream CT
    /// preservation, upstream-request-id passthrough) that the SSE/`text/event-stream` variants cannot
    /// reach.
    EventStream {
        frames: Vec<(&'static str, Vec<u8>)>,
        amzn_request_id: &'static str,
    },
    /// The BINARY-stream twin of `SseTransportError`: a TRUE mid-stream transport failure on a native
    /// AWS `application/vnd.amazon.eventstream` body. Emits `ok_frames` real CRC-valid binary frames
    /// (each encoded via `crate::eventstream::encode_frame`), then PAUSES so the proxy reliably reads
    /// and forwards the first byte to the client (crossing the after-first-byte failover boundary),
    /// THEN makes the body stream yield an `Err`, aborting the connection mid-binary-body. reqwest
    /// surfaces this as a transport error to the proxy's `FirstByteBody`, exercising the
    /// `Poll::Ready(Some(Err))` arm on a SAME-PROTOCOL bedrock→bedrock passthrough (upstream CT is
    /// `application/vnd.amazon.eventstream`, so `is_sse` is true and `ingress_eventstream` is true).
    /// The proxy must therefore append a CRC-valid BINARY `:message-type: exception` frame — NOT SSE
    /// `event:`/`data:` ASCII text spliced into the binary body. `amzn_request_id` is served as the
    /// `x-amzn-RequestId` header, as a native ConverseStream backend always does.
    EventStreamTransportError {
        ok_frames: Vec<(&'static str, Vec<u8>)>,
        amzn_request_id: &'static str,
    },
    /// A non-2xx error response whose BODY delivery is deterministically gated on a
    /// `tokio::sync::Notify`, rather than the `SseTransportError`/`EventStreamTransportError` idiom's
    /// fixed `tokio::time::sleep` — a real-clock delay is a race by construction (this crate's own
    /// comments on those variants note fast-localhost races), which is unacceptable for a test that
    /// needs to land a second, direct store mutation deterministically WHILE the first request is
    /// still parked reading this body. On first poll of the body stream this notifies `started` (so
    /// the test knows the client has begun reading and `read_capped_body`'s `.await` is now parked),
    /// then awaits `release` before yielding the body once and ending the stream cleanly. Used by
    /// the owned single-flight-probe release proof: the ONE real request that must park mid-body
    /// read; the "second probe" side is simulated directly on the store, copied from
    /// `probe_guard_tests.rs`'s `stalled_guard_does_not_release_a_newer_probe` pattern, rather than
    /// driving a second concurrent HTTP dispatch through the mock server.
    Gated {
        status: StatusCode,
        body: Value,
        started: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::Arc<tokio::sync::Notify>,
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

#[derive(Debug, Default)]
pub(crate) struct MockServerState {
    responses: Mutex<Vec<MockResponse>>,
    last_auth_header: std::sync::Mutex<Option<String>>,
    last_request_body: std::sync::Mutex<Option<Vec<u8>>>,
    last_request_headers: std::sync::Mutex<Option<axum::http::HeaderMap>>,
    last_request_path: std::sync::Mutex<Option<String>>,
}

impl MockServerState {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    pub(crate) fn push(&self, response: MockResponse) {
        self.responses.lock().unwrap().push(response);
    }
    fn next_response(&self) -> Option<MockResponse> {
        self.responses.lock().unwrap().pop()
    }

    /// Record the last seen Authorization header for testing passthrough token forwarding
    pub(crate) fn record_auth_header(&self, header: &str) {
        *self.last_auth_header.lock().unwrap() = Some(header.to_string());
    }

    /// Get the recorded Authorization header (for assertions in tests)
    pub(crate) fn get_last_auth_header(&self) -> Option<String> {
        self.last_auth_header.lock().unwrap().clone()
    }

    /// Clear the recorded Authorization header
    pub(crate) fn clear_auth_header(&self) {
        *self.last_auth_header.lock().unwrap() = None;
    }

    /// Record the received request path (for translation / on-the-wire assertions).
    pub(crate) fn record_request_path(&self, path: &str) {
        *self.last_request_path.lock().unwrap() = Some(path.to_string());
    }

    /// Get the last received request path.
    pub(crate) fn get_last_request_path(&self) -> Option<String> {
        self.last_request_path.lock().unwrap().clone()
    }

    /// Record the last received request body (for translation / on-the-wire assertions).
    pub(crate) fn record_request_body(&self, body: &[u8]) {
        *self.last_request_body.lock().unwrap() = Some(body.to_vec());
    }

    /// Get the last received request body bytes (for assertions in tests).
    pub(crate) fn get_last_request_body(&self) -> Option<Vec<u8>> {
        self.last_request_body.lock().unwrap().clone()
    }

    /// Record the full set of request headers the upstream received (for indistinguishability
    /// assertions — e.g. that a health probe sends the same User-Agent/Accept as organic traffic).
    pub(crate) fn record_request_headers(&self, headers: &axum::http::HeaderMap) {
        *self.last_request_headers.lock().unwrap() = Some(headers.clone());
    }

    /// Get a single request header value the upstream received, by name (case-insensitive).
    pub(crate) fn get_last_request_header(&self, name: &str) -> Option<String> {
        self.last_request_headers
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }
}

pub(crate) struct MockServer {
    addr: SocketAddr,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub(crate) async fn new(state: std::sync::Arc<MockServerState>) -> Self {
        let app = Router::new()
            .route("/v1/messages", any(mock_handler))
            .route("/v1/chat/completions", any(mock_handler))
            // Serve EVERY other upstream path through the same handler so backends whose writer
            // builds a model-scoped path (Bedrock `/model/{model}/converse[-stream]`, Gemini
            // `/v1beta/models/...`, Cohere `/v2/chat`) reach the queued mock response instead of a
            // 404. The queued `MockResponse` already encodes the protocol-specific body shape, so a
            // catch-all route is sufficient and keeps the named routes above for clarity.
            .fallback(any(mock_handler))
            .with_state(state);
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

    pub(crate) fn address(&self) -> SocketAddr {
        self.addr
    }
    pub(crate) fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub(crate) async fn shutdown(self) {
        if let Some(handle) = self.handle {
            handle.abort();
        }
    }
}

async fn mock_handler(
    State(state): State<std::sync::Arc<MockServerState>>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();

    // Record the request path for upstream-path assertions.
    state.record_request_path(parts.uri.path());

    // Record the full header set the upstream received (indistinguishability assertions).
    state.record_request_headers(&parts.headers);

    // Record the Authorization header for passthrough token forwarding tests
    if let Some(auth_header) = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        state.record_auth_header(auth_header);
    }

    // Record the received request body for translation / on-the-wire assertions.
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    state.record_request_body(&body_bytes);

    let response = state.next_response();
    let response = response.unwrap_or_default();
    match response {
        MockResponse::Ok { status, body } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        MockResponse::RateLimit {
            status,
            provider_signal,
            retry_after,
        } => {
            let msg = if provider_signal == Some("1302") {
                "rate_limit"
            } else {
                "Rate limit exceeded"
            };
            let body = serde_json::json!({ "error": { "message": msg, "code": provider_signal.unwrap_or("429") } });
            let mut rb = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json");
            if let Some(ra) = retry_after {
                rb = rb.header(header::RETRY_AFTER, ra.to_string());
            }
            rb.body(Body::from(body.to_string())).unwrap()
        }
        MockResponse::Billing {
            status,
            code,
            message,
        } => {
            let body = serde_json::json!({ "error": { "message": message, "code": code } });
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap()
        }
        MockResponse::Auth { status } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::json!({ "error": "Unauthorized" }).to_string(),
            ))
            .unwrap(),
        MockResponse::ServerError { status, body } => Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap(),
        MockResponse::ServerErrorWithHeaders {
            status,
            body,
            headers,
        } => {
            let mut rb = Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json");
            for (k, v) in headers {
                rb = rb.header(k, v);
            }
            rb.body(Body::from(body.to_string())).unwrap()
        }
        MockResponse::Sse {
            events,
            abort_at_index,
        } => {
            let stream_events: Vec<String> = if let Some(idx) = abort_at_index {
                // Mid-stream abort: send idx events then add SSE error event before ending (no [DONE])
                let mut result: Vec<String> = events
                    .iter()
                    .take(idx)
                    .map(|d| format!("data: {d}\n\n"))
                    .collect();
                // Add SSE error event to notify client of upstream failure
                let err_json = serde_json::json!({
                    "type": "error",
                    "error": {
                        "message": "upstream abort",
                        "source": "upstream"
                    }
                });
                result.push(format!("event: error\ndata: {}\n\n", err_json));
                result
            } else {
                // Normal completion with [DONE]
                let mut result: Vec<String> = events
                    .into_iter()
                    .map(|d| format!("data: {d}\n\n"))
                    .collect();
                // Safety: SSE_DONE_FRAME is a valid UTF-8 literal.
                result.push(
                    std::str::from_utf8(crate::proto::SSE_DONE_FRAME)
                        .unwrap()
                        .to_owned(),
                );
                result
            };

            let s: Pin<Box<dyn Stream<Item = String> + Send>> =
                Box::pin(stream::iter(stream_events));
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(
                    s.map(|s| Ok::<_, std::convert::Infallible>(s.into_bytes())),
                ))
                .unwrap()
        }
        MockResponse::SseTransportError { ok_events } => {
            // Emit the real frames, PAUSE so the proxy reliably reads + forwards the first byte to the
            // client (crossing the after-first-byte failover boundary), THEN yield a stream Err so the
            // connection aborts mid-body. The `io::Error` item type makes `Body::from_stream`
            // propagate a transport failure (not a clean EOF), which reqwest surfaces as a transport
            // error to the proxy's `FirstByteBody`. Without the pause, on fast localhost the error can
            // race ahead of the first byte and trip pre-first-byte failover (a 503) instead.
            // step: 0..ok_events.len() emit a real frame; the final step sleeps then errors; then end.
            let frames: Vec<Bytes> = ok_events
                .into_iter()
                .map(|d| Bytes::from(format!("data: {d}\n\n")))
                .collect();
            let s = stream::unfold((0usize, frames), |(i, frames)| async move {
                if i < frames.len() {
                    let item = Ok::<Bytes, std::io::Error>(frames[i].clone());
                    Some((item, (i + 1, frames)))
                } else if i == frames.len() {
                    // Pause so the proxy forwards the first byte before the error arrives.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let item = Err(std::io::Error::other("mid-stream connection drop"));
                    Some((item, (i + 1, frames)))
                } else {
                    None
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(s))
                .unwrap()
        }
        MockResponse::EventStream {
            frames,
            amzn_request_id,
        } => {
            // Encode each (event_type, payload) into a CRC-valid binary AWS event-stream frame and
            // concatenate — the exact byte layout a native Bedrock ConverseStream backend returns. The
            // `x-amzn-RequestId` header carries the upstream's REAL request id; a same-protocol bedrock
            // passthrough must relay this verbatim (never re-synthesize a fresh UUID).
            let mut bytes: Vec<u8> = Vec::new();
            for (event_type, payload) in &frames {
                bytes.extend(crate::eventstream::encode_frame(event_type, payload));
            }
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/vnd.amazon.eventstream")
                .header("x-amzn-requestid", amzn_request_id)
                .body(Body::from(bytes))
                .unwrap()
        }
        MockResponse::EventStreamTransportError {
            ok_frames,
            amzn_request_id,
        } => {
            // Encode each (event_type, payload) into a CRC-valid binary AWS event-stream frame, then
            // PAUSE and yield a stream `Err` so the connection aborts mid-binary-body — the binary
            // counterpart of `SseTransportError`. The pause lets the proxy forward the first byte
            // (crossing the after-first-byte boundary) before the error races in; on fast localhost
            // an immediate error can otherwise trip pre-first-byte failover (a 503) instead.
            let frames: Vec<Bytes> = ok_frames
                .into_iter()
                .map(|(event_type, payload)| {
                    Bytes::from(crate::eventstream::encode_frame(event_type, &payload))
                })
                .collect();
            let s = stream::unfold((0usize, frames), |(i, frames)| async move {
                if i < frames.len() {
                    let item = Ok::<Bytes, std::io::Error>(frames[i].clone());
                    Some((item, (i + 1, frames)))
                } else if i == frames.len() {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let item = Err(std::io::Error::other("mid-stream connection drop"));
                    Some((item, (i + 1, frames)))
                } else {
                    None
                }
            });
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/vnd.amazon.eventstream")
                .header("x-amzn-requestid", amzn_request_id)
                .body(Body::from_stream(s))
                .unwrap()
        }
        MockResponse::Gated {
            status,
            body,
            started,
            release,
        } => {
            let bytes = Bytes::from(body.to_string());
            let s = stream::unfold(Some((bytes, started, release)), |state| async move {
                let (bytes, started, release) = state?;
                started.notify_one();
                release.notified().await;
                Some((Ok::<Bytes, std::io::Error>(bytes), None))
            });
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from_stream(s))
                .unwrap()
        }
    }
}

// ───────────────────────── test fixtures ─────────────────────────
// One `LaneSpec` describes a lane and emits BOTH its `Lane` (routing/health view) and its
// `LaneData` (breaker/permit view), so the two can't drift. `TestApp` collects lanes + optional
// pools/auth/governance and builds an `Arc<App>` with the in-memory store wired up — replacing the
// ~20-field `Lane`/`LaneData`/`App` literals every test used to hand-roll. Defaults match the
// common case; chainable setters override only what a test cares about. Adding a field to
// `Lane`/`LaneData`/`App` is now a one-line change in `to_lane`/`to_lane_data`/`build`.
//
// `allow(dead_code)`: this is a test DSL — not every setter is exercised by every revision of the
// suite; keeping the full, symmetric builder surface is intentional.
#[allow(dead_code)]
pub(crate) struct LaneSpec {
    model: String,
    provider: String,
    base_url: String,
    protocol: std::sync::Arc<crate::proto::Protocol>,
    max: usize,
    api_key: String,
    error_map: std::collections::HashMap<String, String>,
    context_max: Option<usize>,
    path: Option<String>,
    path_base: Option<String>,
    auth: Option<String>,
    health: Option<crate::config::HealthCfg>,
    default_max_tokens: Option<u32>,
    upstream_model: Option<String>,
    // LaneData-only runtime state (defaults = a fresh, healthy, unlimited lane):
    limited: bool,
    budget: i64,
    cooldown_until: u64,
    streak: u32,
    dead: bool,
    dead_reason: String,
    ok: u64,
    err: u64,
    client_fault: u64,
    /// Optional shared semaphore override. When set, `to_lane_data` reuses this handle instead of
    /// constructing a fresh one, so a test can hold a clone and observe permit acquisition/release.
    sem: Option<std::sync::Arc<tokio::sync::Semaphore>>,
}

#[allow(dead_code)]
impl LaneSpec {
    pub(crate) fn new(model: &str, protocol: crate::proto::Protocol, base_url: &str) -> Self {
        Self {
            model: model.into(),
            provider: "test-provider".into(),
            base_url: base_url.into(),
            protocol: std::sync::Arc::new(protocol),
            max: 10,
            api_key: "k".into(),
            error_map: std::collections::HashMap::new(),
            context_max: None,
            path: None,
            path_base: None,
            auth: None,
            health: None,
            default_max_tokens: None,
            upstream_model: None,
            limited: false,
            budget: -1,
            cooldown_until: 0,
            streak: 0,
            dead: false,
            dead_reason: String::new(),
            ok: 0,
            err: 0,
            client_fault: 0,
            sem: None,
        }
    }
    pub(crate) fn provider(mut self, p: &str) -> Self {
        self.provider = p.into();
        self
    }
    pub(crate) fn max(mut self, n: usize) -> Self {
        self.max = n;
        self
    }
    pub(crate) fn api_key(mut self, k: &str) -> Self {
        self.api_key = k.into();
        self
    }
    pub(crate) fn error_map(mut self, m: std::collections::HashMap<String, String>) -> Self {
        self.error_map = m;
        self
    }
    pub(crate) fn context_max(mut self, n: usize) -> Self {
        self.context_max = Some(n);
        self
    }
    pub(crate) fn path(mut self, p: &str) -> Self {
        self.path = Some(p.into());
        self
    }
    pub(crate) fn path_base(mut self, p: &str) -> Self {
        self.path_base = Some(p.into());
        self
    }
    pub(crate) fn auth(mut self, a: &str) -> Self {
        self.auth = Some(a.into());
        self
    }
    pub(crate) fn health(mut self, h: crate::config::HealthCfg) -> Self {
        self.health = Some(h);
        self
    }
    pub(crate) fn default_max_tokens(mut self, n: u32) -> Self {
        self.default_max_tokens = Some(n);
        self
    }
    pub(crate) fn upstream_model(mut self, n: &str) -> Self {
        self.upstream_model = Some(n.into());
        self
    }
    /// Mark the lane as budget-limited with `n` remaining requests (sets `limited = true`).
    pub(crate) fn budget(mut self, n: i64) -> Self {
        self.limited = true;
        self.budget = n;
        self
    }
    pub(crate) fn cooldown_until(mut self, t: u64) -> Self {
        self.cooldown_until = t;
        self
    }
    pub(crate) fn streak(mut self, n: u32) -> Self {
        self.streak = n;
        self
    }
    pub(crate) fn dead(mut self, reason: &str) -> Self {
        self.dead = true;
        self.dead_reason = reason.into();
        self
    }
    pub(crate) fn ok(mut self, n: u64) -> Self {
        self.ok = n;
        self
    }
    pub(crate) fn err(mut self, n: u64) -> Self {
        self.err = n;
        self
    }
    /// Override the lane's permit semaphore with a shared handle the test retains, so it can
    /// observe permit acquisition/release across the request lifetime.
    pub(crate) fn sem(mut self, sem: std::sync::Arc<tokio::sync::Semaphore>) -> Self {
        self.sem = Some(sem);
        self
    }

    fn to_lane(&self) -> crate::state::Lane {
        let auth = self.auth.as_deref().map(|a| match a {
            "api-key" => crate::config::ProviderAuth::ApiKey,
            "bearer" => crate::config::ProviderAuth::Bearer,
            other => panic!("unexpected test auth style in LaneSpec: {other}"),
        });
        crate::state::Lane {
            reasoning: false,
            prompt_caching: false,
            credential: crate::egress_auth::resolve(self.protocol.name(), auth),
            model: self.model.clone(),
            provider: self.provider.clone(),
            signing_host: crate::proxy::host_from_base(&self.base_url),
            base_url: self.base_url.clone(),
            api_key: busbar_api::Redacted::new(self.api_key.clone()),
            // G6 A4b Lane inversion: `Lane.protocol` is the interned protocol NAME now, not an
            // `Arc<Protocol>`. The builder still holds the fixture `Protocol` for `.name()`/credential.
            protocol: self.protocol.name_static(),
            max: self.max,
            error_map: std::sync::Arc::new(self.error_map.clone()),
            context_max: self.context_max,
            path: self.path.clone(),
            path_base: self.path_base.clone(),
            health: self.health.clone(),
            default_max_tokens: self.default_max_tokens,
            upstream_model: self.upstream_model.clone(),
            attempt_timeout_ms: None,
        }
    }
    fn to_lane_data(&self) -> crate::store::LaneData {
        crate::store::LaneData {
            reasoning: false,
            prompt_caching: false,
            model: self.model.clone(),
            provider: self.provider.clone(),
            max: self.max,
            sem: self
                .sem
                .clone()
                .unwrap_or_else(|| std::sync::Arc::new(tokio::sync::Semaphore::new(self.max))),
            limited: self.limited,
            budget: self.budget,
            cooldown_until: self.cooldown_until,
            streak: self.streak,
            dead: self.dead,
            dead_reason: self.dead_reason.clone(),
            ok: self.ok,
            err: self.err,
            client_fault: self.client_fault,
            upstream_model: self.upstream_model.clone(),
            attempt_timeout_ms: None,
        }
    }
}

/// The plugin route table a test `App` carries: the built-in `prometheus` exporter's `GET /metrics`
/// route when the recorder is installed (`metrics::init()`), else empty. Mirrors production, where the
/// route is built from `export.prometheus` presence — here the recorder handle is the stand-in switch
/// (the harness has no `export:` config surface).
fn test_plugin_route_table() -> crate::plugin_routes::PluginRouteTable {
    if crate::metrics::recorder_installed() {
        let cfg = crate::config::ExportCfg {
            prometheus: Some(crate::config::PrometheusSettings {
                projection: Default::default(),
                buffer_seconds: 60,
                key_gauge_limit: crate::config::default_key_gauge_limit(),
            }),
            ..Default::default()
        };
        crate::plugin_routes::build_route_table(crate::export::route_decls(&cfg))
            .unwrap_or_else(|_| crate::plugin_routes::PluginRouteTable::empty())
    } else {
        crate::plugin_routes::PluginRouteTable::empty()
    }
}

#[allow(dead_code)]
pub(crate) struct TestApp {
    lanes: Vec<LaneSpec>,
    pools: std::collections::HashMap<String, Vec<crate::state::WeightedLane>>,
    auth: Option<std::sync::Arc<crate::auth::AuthMiddleware>>,
    /// `admin_auth:` chain module names for the built App. `None` = the production default
    /// (`[admin-tokens]`); `Some(vec![])` selects the explicit OPEN admin posture (dev).
    admin_chain: Option<Vec<String>>,
    /// Resolved external admin auth modules for the built App (1.5.2 admin-plane OIDC). `None` = the
    /// empty chain (admin-tokens-only, runs inline). A test that needs the OFFLOAD path populates
    /// this with a boxed test module and `has_plugin: true`.
    admin_modules: Option<crate::auth::AdminAuthChain>,
    /// Resolved hosted-login methods (1.5.2). `None` = empty (no hosted login). A test that
    /// drives `GET /auth/token` populates this with a test login module.
    login_methods: Option<crate::auth::token::LoginMethods>,
    /// busbar's public base origin (`public_url:`) for the built App.
    public_url: Option<String>,
    /// The validated MCP resource for the built App. `None` (the default) = not an MCP server, and
    /// the built router mounts no MCP route at all — which is what every pre-existing test expects.
    mcp: Option<crate::mcp::McpResource>,
    /// The built authorization server (`oauth_as:`). `None` (the default) = this deployment is not
    /// one, which is what every pre-existing test expects and what the gating proof in
    /// `oauth_as::tests::mount_tests` asserts costs nothing.
    oauth_as: Option<std::sync::Arc<crate::oauth_as::plane::AsPlane>>,
    tool_defs: crate::mcp::config::ToolsCfg,
    /// The LIVE tool-list sightings the built `App` dispatches against. `None` (the default) means
    /// no upstream has ever been contacted, which is what every pre-existing test expects and what
    /// makes the dispatch gate fall back to the operator's configured hash.
    mcp_sightings: Option<std::sync::Arc<crate::mcp::client::catalogue::CatalogueCache>>,
    mcp_durable_store: Option<std::sync::Arc<dyn busbar_api::Store>>,
    role_bindings: Option<crate::config::RoleBindings>,
    /// The resolved token-mint policy (`auth.policy:`) for the built App. `None` (default) = the empty
    /// policy (no caps). Set by tests that exercise `MintPolicy` enforcement at the mint site.
    mint_policy: Option<crate::admin::MintPolicy>,
    governance: Option<std::sync::Arc<crate::governance::GovState>>,
    cost: Option<std::sync::Arc<crate::cost::CostModel>>,
    failover_cfg: Option<crate::config::FailoverCfg>,
    pool_runtime: std::collections::HashMap<String, crate::state::PoolRuntime>,
    /// The ALL-POOLS `upstream_credentials:` default installed onto the built `App`.
    upstream_credentials: crate::auth::UpstreamCreds,
    fallback_pools: std::collections::HashMap<String, Vec<crate::state::WeightedLane>>,
    on_exhausted_cfgs: std::collections::HashMap<String, crate::config::OnExhausted>,
    hook_registry: std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: Vec<String>,
    base_hook_names: std::collections::HashSet<String>,
    groups_registry: std::collections::BTreeMap<String, crate::config::GroupCfg>,
    base_group_names: std::collections::HashSet<String>,
    identity_providers: crate::config::IdentityProviders,
    export_defs: crate::config::ExportDefs,
    agent_defs: crate::a2a::config::AgentsCfg,
    tool_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
    agent_pools: std::collections::BTreeMap<String, crate::failover::CandidatePoolCfg>,
    overlay_path: Option<std::path::PathBuf>,
    /// 1.5.3: when `true`, build a LOCKED app (no overlay backend) — the only way to get
    /// `overlay_path: None` now that the default is durable. Without it, `build()` provides a writable
    /// temp overlay so mutation tests are durable-by-default, mirroring production boot.
    explicit_no_overlay: bool,
    plugins_dir: Option<std::path::PathBuf>,
    plugins_cfg: Option<crate::config::PluginsCfg>,
    hook_env: Option<crate::hooks::HookEnv>,
    disk_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,
    /// When `true`, build an App that booted with NO plugin routes at all — an EMPTY live table AND an
    /// empty `boot_route_paths`. The explicit form of "this process never mounted `/metrics`", which
    /// the default cannot express: [`test_plugin_route_table`] keys on the PROCESS-GLOBAL recorder, so
    /// a test that merely omits `export:` still gets `/metrics` once any earlier test in the binary
    /// called `metrics::init()`.
    no_plugin_routes: bool,
    /// B1.7 INSTALL SEAM: the pre-built, type-erased plane runtimes `build()` installs into the App's
    /// [`crate::state::App::plane_slots`], keyed by each plane's decl key. `build()` fills this via
    /// [`TestApp::install_plane_runtimes`] (which names the `crate::mcp`/`crate::a2a` plane types) and
    /// then MOVES it into the App slot without naming a plane type itself — the precursor that lets
    /// B2/B3 relocate the plane-specific construction out of core without also restructuring `build()`.
    installed_plane_runtimes:
        std::collections::BTreeMap<&'static str, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
}

#[allow(dead_code)]
impl TestApp {
    pub(crate) fn new() -> Self {
        Self {
            tool_defs: Default::default(),
            mcp_sightings: None,
            mcp_durable_store: None,
            upstream_credentials: crate::auth::UpstreamCreds::Own,
            lanes: Vec::new(),
            pools: std::collections::HashMap::new(),
            auth: None,
            admin_chain: None,
            admin_modules: None,
            login_methods: None,
            public_url: None,
            mcp: None,
            oauth_as: None,
            role_bindings: None,
            mint_policy: None,
            governance: None,
            cost: None,
            failover_cfg: None,
            pool_runtime: std::collections::HashMap::new(),
            fallback_pools: std::collections::HashMap::new(),
            on_exhausted_cfgs: std::collections::HashMap::new(),
            hook_registry: std::collections::HashMap::new(),
            global_hooks: Vec::new(),
            base_hook_names: std::collections::HashSet::new(),
            groups_registry: std::collections::BTreeMap::new(),
            base_group_names: std::collections::HashSet::new(),
            identity_providers: Default::default(),
            export_defs: Default::default(),
            agent_defs: Default::default(),
            tool_pools: Default::default(),
            agent_pools: Default::default(),
            overlay_path: None,
            explicit_no_overlay: false,
            plugins_dir: None,
            plugins_cfg: None,
            hook_env: None,
            disk_paths: None,
            no_plugin_routes: false,
            installed_plane_runtimes: std::collections::BTreeMap::new(),
        }
    }

    /// B1.7 INSTALL SEAM. Install a pre-built, type-erased plane runtime under its plane decl `key`.
    /// `build()` reads the accumulated map back into [`crate::state::App::plane_slots`], so this is the
    /// one doorway a plane runtime enters the built App's type-erased slot through — the seam B2/B3 use
    /// to relocate plane-specific construction out of core.
    pub(crate) fn install_plane_runtime(
        &mut self,
        key: &'static str,
        rt: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) -> &mut Self {
        self.installed_plane_runtimes.insert(key, rt);
        self
    }

    /// Build this fixture's A2A plane runtime, applying busbar's PUBLIC card-issuer key off governance
    /// exactly as production's `a2a_start` hook does — so a fixture that configures both an a2a plane
    /// and a card-signing governance key serves signed cards without running the boot fold. `None` when
    /// no `agents:` receiving side is configured. Names `crate::a2a` here (a plane BUILDER method) so
    /// `build()` need not — B2/B3 relocate this.
    fn build_a2a_plane_runtime(&self) -> Option<std::sync::Arc<crate::a2a::plane::A2aPlane>> {
        let plane =
            crate::a2a::plane::A2aPlane::from_config(&self.agent_defs, self.public_url.as_deref());
        // MIRROR PRODUCTION'S `a2a_start` HOOK: stash busbar's PUBLIC card-issuer key on the plane's
        // own slot, computed from governance exactly as `boot::start_planes` computes `BootCtx`'s.
        if let (Some(p), Some(gov)) = (plane.as_ref(), self.governance.as_ref()) {
            if let Some(issuer) = gov.a2a_card_issuer() {
                p.set_card_issuer(issuer);
            }
        }
        plane
    }

    /// Build this fixture's MCP plane per-generation runtime bundle, type-erased as `Arc<dyn Any>`.
    /// Constructed directly (rather than via `crate::mcp::build_runtime`) so a fixture can still inject
    /// its own `mcp_sightings`; the other five objects match production's `McpRuntime::build`. Names
    /// `crate::mcp` here (a plane BUILDER method) so `build()` need not.
    fn build_mcp_runtime(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(crate::mcp::McpRuntime {
            catalogue: std::sync::Arc::new(crate::mcp::catalogue::Catalogue::build(
                &self.tool_defs,
            )),
            servers: std::sync::Arc::new(self.tool_defs.clone()),
            pool: std::sync::Arc::new(crate::mcp::client::pool::McpConnectionPool::new()),
            sightings: self.mcp_sightings.clone().unwrap_or_default(),
            roots_epochs: Default::default(),
            sampling_spend: Default::default(),
            verify: Default::default(),
        })
    }

    /// Build this fixture's plane dispatch table — mount + admission for the mcp and a2a planes, the
    /// way production mounts them, so a router-walking test sees the surface a deployment would have.
    /// Names `crate::mcp`/`crate::a2a` here (a plane BUILDER method) so `build()` need not.
    fn build_plane_dispatch(
        &self,
        mcp: Option<&crate::mcp::McpResource>,
        a2a_plane: Option<&std::sync::Arc<crate::a2a::plane::A2aPlane>>,
    ) -> crate::plane::PlaneDispatch {
        let mut dispatch = crate::plane::PlaneDispatch::default();
        if let Some(r) = mcp {
            dispatch = dispatch
                .mount("mcp", r.mount_path(), crate::plane::WIRE_JSONRPC)
                .admit("mcp", r.admission());
        }
        if let Some(admission) = a2a_plane.and_then(|p| p.admission()) {
            dispatch = dispatch
                .mount(
                    "a2a",
                    crate::a2a::serve::MOUNT_PATH,
                    crate::plane::WIRE_JSONRPC,
                )
                // THE SECOND BINDING'S PATH, claimed by the same act and for the same reason.
                // gRPC is served at the path the vendored `a2a.proto` dictates rather than under
                // the plane's mount, and a claimed path is where `admission_for` finds the RFC
                // 8707 audience — so leaving it out would not merely mislabel the leg, it would
                // admit a token minted for some other resource on it.
                .mount(
                    "a2a",
                    crate::a2a::serve::GRPC_MOUNT_PATH,
                    crate::plane::WIRE_GRPC,
                )
                .admit("a2a", admission);
        }
        dispatch
    }

    /// Install this fixture's type-erased plane slots (the mcp ENDPOINT resource and the a2a plane)
    /// through the B1.7 [`TestApp::install_plane_runtime`] seam, keyed by each plane's decl key. Names
    /// `crate::mcp`/`crate::a2a` here (a plane BUILDER method) so `build()` need not.
    fn install_plane_runtimes(
        &mut self,
        mcp_arc: Option<std::sync::Arc<crate::mcp::McpResource>>,
        a2a_plane: Option<std::sync::Arc<crate::a2a::plane::A2aPlane>>,
    ) {
        if let Some(r) = mcp_arc {
            self.install_plane_runtime(crate::mcp::PLANE_DECL.key, r);
        }
        if let Some(p) = a2a_plane {
            self.install_plane_runtime(crate::a2a::PLANE_DECL.key, p);
        }
    }

    /// Replay the MCP plane's durable demotion records into the built app's sightings, exactly as
    /// boot's durable-MCP-trust block does. Names `crate::mcp` here so `build()` need not.
    fn hydrate_mcp_demotion(app: &std::sync::Arc<crate::state::App>) {
        // Mint a snapshot-only host over the built app, exactly as boot's replay reads it through one.
        crate::mcp::demotion::hydrate(&crate::plane_host::engine_host(app));
    }

    /// Build an App that BOOTED WITH NO PLUGIN ROUTES: empty live table, empty `boot_route_paths`.
    /// The fixture for the restart-to-apply signal — a config apply that ADDS a
    /// path the router never registered at boot.
    pub(crate) fn no_plugin_routes(mut self) -> Self {
        self.no_plugin_routes = true;
        self
    }

    /// Install a hook plugin-resolution env (for hook-transport resolution tests). Defaults to an
    /// empty registry (a hook's `plugin:` ref resolves to `None`, i.e. gate-absent).
    pub(crate) fn hook_env(mut self, env: crate::hooks::HookEnv) -> Self {
        self.hook_env = Some(env);
        self
    }

    /// Point the plugin surface at a specific directory (for the Admin API plugin catalog / install /
    /// remove / reload tests). Defaults to `plugins` when unset.
    pub(crate) fn plugins_dir(mut self, path: std::path::PathBuf) -> Self {
        self.plugins_dir = Some(path);
        self
    }
    /// Set the whole `plugins.*` posture (for install re-verification tests). Defaults to the
    /// strict disabled default.
    pub(crate) fn plugins_cfg(mut self, cfg: crate::config::PluginsCfg) -> Self {
        self.plugins_cfg = Some(cfg);
        self
    }

    /// Give the snapshot DISK TRUTH — the `config.yaml` / `providers.yaml` paths a rebuild reads.
    /// Without these the app is EPHEMERAL and every rebuild-from-disk path takes its no-disk branch,
    /// so the failure modes of the rebuild itself are unreachable from a test.
    pub(crate) fn disk_paths(
        mut self,
        config: std::path::PathBuf,
        providers: std::path::PathBuf,
    ) -> Self {
        self.disk_paths = Some((config, providers));
        self
    }

    /// Enable config-overlay persistence at `path` (for testing runtime-change durability).
    pub(crate) fn overlay_path(mut self, path: std::path::PathBuf) -> Self {
        self.overlay_path = Some(path);
        self.explicit_no_overlay = false;
        self
    }

    /// 1.5.3: build a LOCKED app (`config.locked: true` at runtime) — no overlay backend, so every
    /// config mutation is refused. Overrides the durable-by-default overlay `build()` otherwise
    /// provides. The only supported way for a test to reach `overlay_path: None`.
    pub(crate) fn no_overlay(mut self) -> Self {
        self.overlay_path = None;
        self.explicit_no_overlay = true;
        self
    }
    /// Register a hook definition in the `hooks:` registry (for the Admin API v1 hooks read surface).
    pub(crate) fn hook(mut self, name: &str, cfg: crate::config::HookCfg) -> Self {
        self.hook_registry.insert(name.into(), cfg);
        self
    }
    /// Register a BASE-config-defined hook (registry AND `base_hook_names`) so the API's base-hook
    /// read-only guards (register/put/patch/delete return 409) can be exercised.
    pub(crate) fn base_hook(mut self, name: &str, cfg: crate::config::HookCfg) -> Self {
        self.hook_registry.insert(name.into(), cfg);
        self.base_hook_names.insert(name.into());
        self
    }
    /// Register a `groups:` entry into the App's group registry (the Admin-API groups read/mutation
    /// surface). Marks it a BASE (config-file) group, so the base-shadow 409 guard sees it.
    pub(crate) fn group(mut self, name: &str, cfg: crate::config::GroupCfg) -> Self {
        self.groups_registry.insert(name.into(), cfg);
        self.base_group_names.insert(name.into());
        self
    }
    /// Seed an `identity-providers:` DEFINITION into the App's effective named map (the read side of
    /// the generic named-map admin CRUD). Mirror whatever the fixture's on-disk config.yaml declares.
    pub(crate) fn identity_provider(
        mut self,
        name: &str,
        cfg: crate::config::IdentityProviderCfg,
    ) -> Self {
        self.identity_providers.insert(name.into(), cfg);
        self
    }
    /// Seed an `export:` DEFINITION into the App's effective named map — the exporter twin of
    /// [`TestApp::identity_provider`].
    pub(crate) fn export_def(mut self, name: &str, cfg: crate::config::ExportDefCfg) -> Self {
        self.export_defs.insert(name.into(), cfg);
        self
    }
    /// Seed an `agents:` DEFINITION into the App's effective named map — the A2A-plane twin of
    /// [`TestApp::export_def`].
    pub(crate) fn agent_def(mut self, name: &str, cfg: crate::a2a::config::AgentDefCfg) -> Self {
        self.agent_defs.agents.insert(name.into(), cfg);
        self
    }
    /// Declare a `tool_pools:` failover pool over already-seeded `mcp_server` registrations —
    /// exactly the operator's grammar: ordered members, optional `repeatable:` operations.
    pub(crate) fn tool_pool(mut self, name: &str, members: &[&str], repeatable: &[&str]) -> Self {
        self.tool_pools.insert(
            name.into(),
            crate::failover::CandidatePoolCfg {
                members: members.iter().map(|m| (*m).to_string()).collect(),
                repeatable: repeatable.iter().map(|o| (*o).to_string()).collect(),
            },
        );
        self
    }
    /// The `agent_pools:` twin of [`TestApp::tool_pool`], over `agent_def` registrations.
    pub(crate) fn agent_pool(mut self, name: &str, members: &[&str]) -> Self {
        self.agent_pools.insert(
            name.into(),
            crate::failover::CandidatePoolCfg {
                members: members.iter().map(|m| (*m).to_string()).collect(),
                repeatable: Vec::new(),
            },
        );
        self
    }
    /// Seed the WHOLE groups tree at once as RUNTIME (non-base) groups: populates the App's group
    /// registry AND builds the cost model from the same tree, so `cost.group_named` (enforcement +
    /// mint existence) and `groups_registry` (the Admin-API write surface / auto-provision) AGREE —
    /// the exact production invariant (both rebuilt together on every apply). NOT marked base, so
    /// the mint auto-provision path can create a `user:<sub>` leaf under one of these without the
    /// base-shadow 409 misfiring. Overwrites any `.cost(...)` set earlier.
    pub(crate) fn groups_tree(
        mut self,
        groups: std::collections::BTreeMap<String, crate::config::GroupCfg>,
    ) -> Self {
        self.cost = Some(std::sync::Arc::new(crate::cost::CostModel::resolve_parts(
            None, 0, &groups,
        )));
        self.groups_registry = groups;
        self
    }
    /// Add a name to the `global_hooks:` list (globally-wired hooks).
    pub(crate) fn global_hook(mut self, name: &str) -> Self {
        self.global_hooks.push(name.into());
        self
    }
    pub(crate) fn lane(mut self, spec: LaneSpec) -> Self {
        self.lanes.push(spec);
        self
    }
    /// Define a pool over lane indices: `members` is `(lane_index, weight)` pairs.
    pub(crate) fn pool(mut self, name: &str, members: &[(usize, u32)]) -> Self {
        self.pools.insert(name.into(), weighted(members));
        self
    }
    /// Set the ALL-POOLS upstream-credential mode (1.5.3: the reserved `pools.upstream_credentials:`
    /// key — it used to be `auth.upstream_credentials`) — driving the egress credential-selection
    /// path. `Own` = the old `mode: none`; `Passthrough` = the old `mode: passthrough`. Per-pool
    /// overrides go on the pool's own `PoolRuntime` (see `.pool_runtime(...)`).
    pub(crate) fn upstream_creds(mut self, uc: crate::auth::UpstreamCreds) -> Self {
        self.upstream_credentials = uc;
        self
    }
    /// Override the ADMIN auth chain. `vec![]` is the explicit OPEN admin posture — the only way
    /// to reach the admin surface on a fixture that has no governance to hold an operator token.
    pub(crate) fn admin_chain(mut self, modules: Vec<String>) -> Self {
        self.admin_chain = Some(modules);
        self
    }

    /// Inject a resolved external admin auth module under `name` (the config module name that both
    /// `admin_chain` and `role_bindings.<name>` key off), marking the chain as plugin-backed so the
    /// admin auth middleware OFFLOADS it off the reactor — the seam the 1.5.2 admin-plane OIDC
    /// offload test drives. `has_plugin` is forced true.
    pub(crate) fn admin_module(
        mut self,
        name: &str,
        module: Box<dyn crate::auth::AuthModule>,
    ) -> Self {
        let chain = self
            .admin_modules
            .get_or_insert_with(|| crate::auth::AdminAuthChain {
                modules: std::collections::HashMap::new(),
                has_plugin: true,
            });
        chain.has_plugin = true;
        chain.modules.insert(name.to_string(), module);
        self
    }

    /// Set the built App's `public_url:` (the hosted-login base origin).
    pub(crate) fn public_url(mut self, url: &str) -> Self {
        self.public_url = Some(url.to_string());
        self
    }

    /// Make the built App an MCP server, from the same `mcp:` config shape an operator writes.
    ///
    /// Takes the CONFIG and runs the real validation rather than accepting a pre-built
    /// `crate::mcp::McpResource`: a test that hand-assembled the resource could mount a
    /// combination the validator refuses, and would then be asserting against a deployment that
    /// cannot exist.
    pub(crate) fn mcp(mut self, cfg: &crate::mcp::McpCfg) -> Self {
        self.mcp =
            Some(crate::mcp::McpResource::from_cfg(cfg).expect("test mcp config must be valid"));
        self
    }

    /// Make the built App an OAuth 2.1 AUTHORIZATION SERVER, from the same `oauth_as:` config shape
    /// an operator writes.
    ///
    /// Takes the CONFIG and runs the real `AsIdentity::from_cfg` validation and the real
    /// `AsPlane::build`, for the same reason [`TestApp::mcp`] does: a test that hand-assembled the
    /// plane could mount a combination boot refuses, and would then be asserting against a
    /// deployment that cannot exist. The signing key is left unset, so the plane generates the
    /// ephemeral one — the tests that use this builder assert about the MOUNTED SURFACE, and the
    /// surface does not depend on which key signs.
    pub(crate) fn oauth_as(mut self, cfg: &crate::oauth_as::config::OauthAsCfg) -> Self {
        let identity = crate::oauth_as::config::AsIdentity::from_cfg(cfg)
            .expect("test oauth_as config must be valid");
        let plane = crate::oauth_as::plane::AsPlane::build(identity, None, Vec::new())
            .expect("test oauth_as plane must build");
        self.oauth_as = Some(std::sync::Arc::new(plane));
        self
    }

    /// Register one `tools:` entry — one MCP server — through the SAME value validation the file
    /// path and the admin write path run.
    ///
    /// It validates rather than accepting the struct: a test that hand-assembled a registration
    /// could declare a combination boot refuses (an `unpinned` server carrying key material, a
    /// `stdio` transport nothing implements) and would then be asserting against a deployment that
    /// cannot exist.
    pub(crate) fn mcp_server(
        mut self,
        name: &str,
        def: crate::mcp::config::McpServerDefCfg,
    ) -> Self {
        crate::mcp::config::validate_server(name, &def)
            .expect("test tools: entry must be valid config");
        self.tool_defs.servers.insert(name.to_string(), def);
        self
    }

    /// The reserved SECTION-level `tools.hooks:` attach — the all-MCP hook list, which combines
    /// ADDITIVELY with each server's own `hooks:`. The twin of [`TestApp::agents_hooks`].
    pub(crate) fn tools_hooks(mut self, names: &[&str]) -> Self {
        self.tool_defs.all_server_hooks = names.iter().map(|n| (*n).to_string()).collect();
        self
    }

    /// The reserved SECTION-level `agents.hooks:` attach — the all-A2A hook list. Same combine rule,
    /// same spelling, on the sibling plane, because it is one operator concept.
    pub(crate) fn agents_hooks(mut self, names: &[&str]) -> Self {
        self.agent_defs.all_agent_hooks = names.iter().map(|n| (*n).to_string()).collect();
        self
    }

    /// Dispatch against these LIVE sightings — the cache a `connect`/refresh has published into.
    pub(crate) fn with_mcp_sightings(
        mut self,
        cache: std::sync::Arc<crate::mcp::client::catalogue::CatalogueCache>,
    ) -> Self {
        self.mcp_sightings = Some(cache);
        self
    }

    /// Give the built App the DURABLE HOME the MCP trust state writes through to, exactly as boot
    /// attaches the configured governance store: the demotion record's sink, the shared
    /// spent-approval ledger, and the boot replay of any demotion the store already holds.
    ///
    /// It takes a `dyn Store` rather than a whole governance runtime because these two properties
    /// need one thing from the store seam and nothing from governance, and because the only honest
    /// way to test them is against a store that really persists — which for this tree means the real
    /// `busbar-store-example-plugin` cdylib in its durable mode, loaded over the plugin C ABI (see
    /// [`super::plugin_store`]). A deployment that configures no store simply never calls this, and
    /// gets the process-local behaviour both properties had before.
    pub(crate) fn mcp_durable_store(
        mut self,
        store: std::sync::Arc<dyn busbar_api::Store>,
    ) -> Self {
        self.mcp_durable_store = Some(store);
        self
    }

    /// Inject a hosted-login method (1.5.2) keyed by `name`. `module` is a login-capable auth
    /// plugin (test stand-in); `client_secret`/`issuer` are the CORE-held confidential-client secret
    /// + issuer hint; `has_button` gates whether it renders on the chooser / accepts begin.
    pub(crate) fn login_method(
        mut self,
        name: &str,
        module: Box<dyn busbar_api::AuthPlugin>,
        client_secret: Option<String>,
        issuer: Option<String>,
        has_button: bool,
    ) -> Self {
        let lm = self
            .login_methods
            .get_or_insert_with(|| crate::auth::token::LoginMethods {
                methods: indexmap::IndexMap::new(),
            });
        let login_kind = module.login_kind();
        // Derive the hop host-allowlist from the issuer hint (same core-side rule as production), so a
        // test whose mock IdP host appears in `issuer` is reachable by the hop executor.
        let allowed_hosts =
            crate::auth::token::collect_allowed_hosts(&serde_json::Map::new(), issuer.as_deref());
        lm.methods.insert(
            name.to_string(),
            crate::auth::token::LoginMethod {
                module,
                client_secret: client_secret.map(busbar_api::Redacted::new),
                has_button,
                issuer,
                login_kind,
                allowed_hosts,
            },
        );
        self
    }

    pub(crate) fn auth(mut self, a: std::sync::Arc<crate::auth::AuthMiddleware>) -> Self {
        self.auth = Some(a);
        self
    }
    /// Install an `AuthMiddleware` whose data-plane chain is `[keys]` (the built-in signed-key
    /// verifier). This is what makes a data-plane request REQUIRE and resolve a virtual key: since
    /// 1.5.2 vkey enforcement is driven by the chain shape, not the admin token. Pair with
    /// `.governance(gov)` for the enforcing-vkey e2e posture.
    pub(crate) fn keys_chain(mut self) -> Self {
        let cfg = crate::config::AuthCfg {
            chain: vec![crate::config::AuthChainEntry::bare(
                crate::config::KEYS_MODULE,
            )],
            ..crate::config::AuthCfg::default_none()
        };
        self.auth = Some(std::sync::Arc::new(
            crate::auth::AuthMiddleware::new_builtin(&cfg),
        ));
        self
    }
    /// Install the TEST-ONLY OIDC stand-in as the whole data-plane chain: it identifies any
    /// non-empty credential and is audience-blind, which is what a real `kind: auth` plugin is
    /// forced to be by the module ABI. Use it wherever the thing under test is whether CORE refuses
    /// something a chain module would have admitted.
    pub(crate) fn idp_chain(mut self) -> Self {
        let cfg = crate::config::AuthCfg {
            chain: vec![crate::config::AuthChainEntry::bare("test-idp-module")],
            ..crate::config::AuthCfg::default_none()
        };
        self.auth = Some(std::sync::Arc::new(
            crate::auth::AuthMiddleware::new_builtin(&cfg),
        ));
        self
    }

    /// Set the `role_bindings:` table used by the built `App` (default: empty). Needed by tests that
    /// exercise the group re-key (an IdP/test principal whose role binds a group grant).
    /// Set the resolved token-mint policy (`auth.policy:`) on the built `App` (default: empty, no
    /// caps). Used by tests exercising `MintPolicy::check_mint` enforcement at `POST /keys`.
    pub(crate) fn mint_policy(mut self, policy: crate::admin::MintPolicy) -> Self {
        self.mint_policy = Some(policy);
        self
    }

    pub(crate) fn role_bindings(mut self, rb: crate::config::RoleBindings) -> Self {
        self.role_bindings = Some(rb);
        self
    }
    /// Install a resolved cost model (rate card / budget groups / flat fee) for tests exercising
    /// the derived-spend enforcement. Default: `CostModel::flat(1)` - no rate card, no groups,
    /// the production default 1-cent flat fee.
    pub(crate) fn cost(mut self, c: crate::cost::CostModel) -> Self {
        self.cost = Some(std::sync::Arc::new(c));
        self
    }

    pub(crate) fn governance(mut self, g: std::sync::Arc<crate::governance::GovState>) -> Self {
        self.governance = Some(g);
        self
    }
    pub(crate) fn failover(mut self, f: crate::config::FailoverCfg) -> Self {
        self.failover_cfg = Some(f);
        self
    }
    pub(crate) fn pool_runtime(mut self, name: &str, rt: crate::state::PoolRuntime) -> Self {
        self.pool_runtime.insert(name.into(), rt);
        self
    }
    pub(crate) fn fallback_pool(mut self, name: &str, members: &[(usize, u32)]) -> Self {
        self.fallback_pools.insert(name.into(), weighted(members));
        self
    }
    pub(crate) fn on_exhausted(mut self, name: &str, oe: crate::config::OnExhausted) -> Self {
        self.on_exhausted_cfgs.insert(name.into(), oe);
        self
    }
    pub(crate) fn build(self) -> std::sync::Arc<crate::state::App> {
        self.build_with_store().0
    }

    // (helper defined at module scope below — see `test_plugin_route_table`)

    /// As [`build`], but also hands back the concrete `Arc<HealthState>` — `App::store` is a
    /// `dyn LaneRuntime` trait object with no downcast support, so a test that needs to reach
    /// test-only breaker-cell manipulation (`HealthState::cell`/`cell_open`, real Open/HalfOpen
    /// state, not achievable through the trait's own methods) needs the typed handle to the SAME
    /// store instance the built `App` uses, not a second independent one.
    pub(crate) fn build_with_store(
        mut self,
    ) -> (
        std::sync::Arc<crate::state::App>,
        std::sync::Arc<crate::store::HealthState>,
    ) {
        // Captured before the `App` literal moves `self` apart. Attaching it AFTER the app exists is
        // not a convenience either: the boot replay reads the operator's live registrations off the
        // built catalogue, exactly as `run()` does, so there is nothing to replay into until then.
        let mcp_durable_store = self.mcp_durable_store.clone();
        let mut by_model = std::collections::HashMap::new();
        let mut lanes = Vec::with_capacity(self.lanes.len());
        let mut lane_data = Vec::with_capacity(self.lanes.len());
        for (i, spec) in self.lanes.iter().enumerate() {
            by_model.insert(spec.model.clone(), i);
            lanes.push(spec.to_lane());
            lane_data.push(spec.to_lane_data());
        }
        // B1.7 SEAM: the plane runtimes are built by the plane BUILDER methods (which still name
        // `crate::mcp`/`crate::a2a`) and handed here as type-erased objects, so `build()`'s own body
        // names no plane type. Built BEFORE `self` is partially moved apart below so the seam's
        // `&mut self` install call is still legal. Lowered ONCE and read twice, exactly as production
        // does it: the registry a test configures and the dispatch table that mounts it come from one
        // reading.
        let a2a_plane = self.build_a2a_plane_runtime();
        // Lowered ONCE for the same reason: `mcp:`'s typed field and the type-erased slot map below
        // must read the identical `Arc`, never two `Arc::new(self.mcp.clone())` calls.
        let mcp_arc = self.mcp.clone().map(std::sync::Arc::new);
        // Built here, ahead of the `App` literal, so the dispatch table reads the SAME `a2a_plane`
        // /`mcp` the slot map installs. The BUILDER method names the plane types; `build()` holds only
        // the type-inferred locals and the neutral dispatch object.
        let plane_dispatch = self.build_plane_dispatch(self.mcp.as_ref(), a2a_plane.as_ref());
        let mcp_runtime_slot = self.build_mcp_runtime();
        // Install the type-erased plane slots through the B1.7 seam, then MOVE the accumulated map into
        // the App slot below — `build()` never names the slot keys or the plane runtime types itself.
        self.install_plane_runtimes(mcp_arc, a2a_plane);
        let mut plane_slots = std::mem::take(&mut self.installed_plane_runtimes);
        // The MCP plane's always-present per-generation runtime rides `plane_slots` under its companion
        // key (`crate::state::MCP_RUNTIME_SLOT`), the same home production `appbuild` gives it — read
        // back through `crate::mcp::runtime`, no flat `App::mcp_runtime`/`mcp_verify` field.
        plane_slots.insert(crate::state::MCP_RUNTIME_SLOT, mcp_runtime_slot);
        let auth = self.auth.unwrap_or_else(|| {
            std::sync::Arc::new(crate::auth::AuthMiddleware::new_builtin(
                &crate::config::AuthCfg::default_none(),
            ))
        });
        let tslots = std::sync::Arc::new(crate::telemetry::AppSlots::build(
            &lanes,
            &self.pools,
            &by_model,
            crate::plane::RESIDUAL_KEY,
        ));
        let store = std::sync::Arc::new(crate::store::HealthState::new(lane_data));
        let requested_signals = crate::hooks::requested_signals(&self.hook_registry);
        let any_content_hook = crate::hooks::any_content_hook(&self.hook_registry);
        let plugin_routes = std::sync::Arc::new(if self.no_plugin_routes {
            crate::plugin_routes::PluginRouteTable::empty()
        } else {
            test_plugin_route_table()
        });
        // A test App is a BOOT App (production seeds this only when `prior` is `None`), so the rule is
        // production's verbatim: whatever this table declares is what the router mounted.
        let boot_route_paths = std::sync::Arc::new(plugin_routes.paths());
        // THE HOOK ENVIRONMENT, bound BEFORE the snapshot because two things read it: the App's own
        // control-plane surface, and the per-container gate resolution below.
        let hook_env = self.hook_env.clone().unwrap_or_else(|| {
            crate::hooks::HookEnv::new(
                std::sync::Arc::new(busbar_plugin_loader::PluginRegistry::empty()),
                std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
            )
        });
        // THE MCP AND A2A GATES, RESOLVED THE WAY PRODUCTION RESOLVES THEM, from the registry and
        // env this fixture was given. A test that hand-assembled a gate chain could attach a hook
        // the real resolver would have skipped (wrong kind, a rewrite gate, an absent plugin) and
        // would then be asserting against a deployment that cannot exist.
        let mcp_server_gates = crate::hooks::resolve_container_gates(
            self.tool_defs
                .servers
                .iter()
                .map(|(n, d)| (n.as_str(), d.hooks.as_slice())),
            &self.tool_defs.all_server_hooks,
            &self.hook_registry,
            &hook_env,
            0,
        );
        let a2a_agent_gates = crate::hooks::resolve_container_gates(
            self.agent_defs
                .agents
                .iter()
                .map(|(n, d)| (n.as_str(), d.hooks.as_slice())),
            &self.agent_defs.all_agent_hooks,
            &self.hook_registry,
            &hook_env,
            0,
        );
        let app = std::sync::Arc::new(crate::state::App {
            // No authorization server unless a test asked for one with `TestApp::oauth_as`, which is
            // the production default and is what keeps every existing test's route table unchanged
            // by this plane's arrival.
            oauth_as: self.oauth_as.clone(),
            agent_defs: std::sync::Arc::new(self.agent_defs),
            tslots,
            probe_schedule: std::sync::Arc::new(crate::health::ProbeSchedule::new(lanes.len())),
            lanes,
            store: store.clone(),
            plane_breakers: std::sync::Arc::new(crate::store::PlaneBreakers::new()),
            session_store: std::sync::Arc::new(crate::session::SessionStore::new(1024, None)),
            incremental_scan: false,
            tool_pools: self.tool_pools,
            agent_pools: self.agent_pools,
            by_model,
            pools: self.pools,
            upstream_credentials: self.upstream_credentials,
            // Mirror production (`appbuild`): the accessor's fast path is enabled only when no pool
            // installs an override, so a test that sets one via `.pool_runtime(...)` still exercises
            // the full lookup.
            any_pool_upstream_creds_override: self
                .pool_runtime
                .values()
                .any(|rt| rt.upstream_credentials.is_some()),
            client: crate::state::UpstreamClients::build(1, || {
                reqwest::Client::builder().build().unwrap()
            }),
            client_settings: crate::state::UpstreamClientSettings::from_limits(
                &crate::config::LimitsResolved::default(),
            ),
            auth,
            rewrite_hooks: Vec::new(),
            tap_hooks: Vec::new(),
            tap_hooks_candidate: Vec::new(),
            tap_hooks_routing: Vec::new(),
            tap_hooks_response: Vec::new(),
            global_gates: Vec::new(),
            mcp_server_gates,
            a2a_agent_gates,
            hook_env,
            hook_registry: self.hook_registry,
            requested_signals,
            any_content_hook,
            export_projections: Default::default(),
            global_hooks: self.global_hooks,
            groups_registry: self.groups_registry,
            base_group_names: self.base_group_names,
            identity_providers: self.identity_providers,
            export_defs: self.export_defs,
            versions: std::sync::Arc::new(crate::admin::versions::VersionLog::new()),
            mutation_limiter: std::sync::Arc::new(crate::admin::rate::MutationLimiter::new()),
            idempotency_cache: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            base_hook_names: self.base_hook_names,
            admin_chain: self
                .admin_chain
                .clone()
                .unwrap_or_else(|| vec!["admin-tokens".to_string()]),
            admin_modules: std::sync::Arc::new(
                self.admin_modules
                    .unwrap_or_else(crate::auth::AdminAuthChain::empty),
            ),
            login_methods: std::sync::Arc::new(
                self.login_methods
                    .unwrap_or_else(crate::auth::token::LoginMethods::empty),
            ),
            public_url: self.public_url,
            // The MCP plane and its dispatch table are built together from ONE validated resource,
            // exactly as `build_app_from_config` does it, so a test can never construct an App whose
            // ingress is mounted at one path while the audience check watches another.
            // BOTH PLANES, mounted the way production mounts them, so a router-walking test sees
            // the surface a deployment would have rather than one this fixture invented.
            // THE DISPATCH TABLE, built above through the plane BUILDER seam ([`build_plane_dispatch`])
            // from the SAME `mcp`/`a2a_plane` the slot map installs — so `build()` names no plane type.
            planes: std::sync::Arc::new(plane_dispatch),
            // THE TYPE-ERASED SLOT MAP (Step 2.3), installed through the B1.7 seam
            // ([`install_plane_runtimes`]) from the SAME two `Arc`s the dispatch reads — not a second
            // construction — so a test built through this fixture sees the identical "one object, two
            // readers" property `build_app_from_config` gives production. `build()` MOVES the seam map
            // in without naming a slot key or a plane runtime type.
            plane_slots,
            a2a_verify: Default::default(),
            a2a_cards: Default::default(),
            spent_token_ledger: Default::default(),
            demotion_record: Default::default(),
            credential_cache: std::sync::Arc::new(crate::auth_cache::CredentialCache::new()),
            auth_scope_caps: std::collections::HashMap::new(),
            role_bindings: self.role_bindings.unwrap_or_default(),
            config_path: self.disk_paths.as_ref().map(|(c, _)| c.clone()),
            providers_path: self.disk_paths.as_ref().map(|(_, p)| p.clone()),
            // 1.5.3 durable-by-default: unless a test explicitly asked for a LOCKED app
            // (`.no_overlay()`), give it a writable temp overlay so config mutations persist — the same
            // guarantee production boot enforces via the `locked` XOR overlay invariant. An explicit
            // `.overlay_path(...)` still wins.
            overlay_path: self.overlay_path.or_else(|| {
                if self.explicit_no_overlay {
                    None
                } else {
                    use std::sync::atomic::{AtomicU64, Ordering};
                    static SEQ: AtomicU64 = AtomicU64::new(0);
                    let n = SEQ.fetch_add(1, Ordering::Relaxed);
                    Some(std::env::temp_dir().join(format!(
                        "busbar-test-overlay-{}-{n}.json",
                        std::process::id()
                    )))
                }
            }),
            config_version: 0,
            max_keys_per_principal: 0,
            max_auto_provisioned_groups: 0,
            failover_cfg: self.failover_cfg,
            pool_runtime: self.pool_runtime,
            fallback_pools: self.fallback_pools,
            on_exhausted_cfgs: self.on_exhausted_cfgs,
            queued_depth: std::sync::Arc::new(crate::state::QueuedDepth::default()),
            governance: self.governance,
            secret_resolver: std::sync::Arc::new(
                crate::config::secret::SecretResolver::builtins_only(),
            ),
            cost: self
                .cost
                .unwrap_or_else(|| std::sync::Arc::new(crate::cost::CostModel::flat(1))),
            plugins_dir: self
                .plugins_dir
                .unwrap_or_else(|| std::path::PathBuf::from("plugins")),
            plugins_cfg: self.plugins_cfg.unwrap_or_default(),
            default_max_tokens: crate::config::DEFAULT_DEFAULT_MAX_TOKENS,
            reasoning_effort_budgets: [1024, 4096, 8192, 16384],
            self_key_ttl_secs: crate::admin::DEFAULT_KEY_TTL_SECS,
            mint_policy: std::sync::Arc::new(self.mint_policy.unwrap_or_default()),
            request_id_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                crate::state::seed_request_id_counter(),
            )),
            // Mirror production: `/metrics` is served via the built-in `prometheus` exporter's plugin
            // route. The test harness has no `export:` config, so synthesize the
            // prometheus route whenever the recorder is installed (`metrics::init()`/`init_with` — the
            // test's "metrics on" signal), preserving the auth-gated `/metrics` behavior these tests
            // exercise. Recorder not installed ⇒ empty table (no `/metrics`), as when metrics are off.
            plugin_routes,
            boot_route_paths,
        });
        // Mirror main's boot-version floor so rollback tests have a v0 to restore.
        app.versions
            .record(0, "system", "boot", &app.hook_registry, &app.global_hooks);
        // Mirror main's durable-MCP-trust boot block, in the same order: attach the sinks, then
        // replay the recorded demotions into the sightings cache BEFORE the app is handed to a
        // caller, which is where boot does it relative to binding a listener.
        if let Some(durable) = mcp_durable_store {
            // Narrowed to the plane surface exactly as boot does — these are plane sinks.
            let plane_store = crate::plane::store::PlaneStoreView::narrow(durable);
            app.spent_token_ledger.set_sink(plane_store.clone());
            app.demotion_record.set_sink(plane_store);
            Self::hydrate_mcp_demotion(&app);
        }
        // Register the process-wide admin `audit` seam stream ONCE (no-sink), the way the call/task
        // streams' front-door harnesses do. Production boots this through `register_and_migrate`; the
        // test HTTP harness never does, so the seam read model `AUDIT_LOG` (which `GET /audit` reads
        // once cut over) would stay empty. This funnel guarantees every live-server audit test's
        // `record_by` feeds the seam. Idempotent + re-entrancy-guarded (this is itself on the shared
        // global app's build path).
        crate::plane::auditlog::ensure_global_audit_stream_registered();
        (app, store)
    }
}

/// SEED every registered MCP server's verification clock as JUST CHECKED, WITHOUT a sighting, so
/// verify-on-call reuses the snapshot rather than re-fetching on the next `tools/call`.
///
/// The dispatch-LEG batteries (credentials, metering, breaker, reroute, roots, sampling, the wire
/// itself) assert what leaves busbar once a tool is servable; they use synthetic approved hashes and
/// mock upstreams that answer `tools/call` but not a verifiable `tools/list`. Verify-on-call would
/// otherwise re-fetch and fail-close them for a reason those batteries are not about. Stamping a
/// still-`Unsighted` ledger entry as fresh makes `crate::trust::reverify::due` answer "fresh", so the
/// gate reuses the snapshot and the declarative `Unsighted` → configured-hash comparison runs exactly
/// as it did before verify-on-call — which is the precondition these batteries were always written
/// against. The drift/quarantine batteries drive their OWN `call` helper and deliberately do NOT call
/// this, so they still fetch and detect drift.
pub(crate) fn prefresh_mcp_sightings(app: &crate::state::App) {
    use crate::mcp::client::catalogue::ServerCatalogue;
    use crate::mcp::client::identity::ServerId;
    let now = crate::store::now_ms();
    let servers: Vec<_> = crate::mcp::runtime(app)
        .catalogue
        .servers()
        .filter_map(|e| {
            ServerId::new(&e.id)
                .ok()
                .map(|sid| (sid, e.approval.clone()))
        })
        .collect();
    crate::mcp::runtime(app).sightings.apply(|map| {
        for (sid, approval) in servers {
            let entry = map
                .entry(sid.as_str().to_string())
                .or_insert_with(|| ServerCatalogue::seeded(sid.clone(), approval));
            entry.ledger.last_checked_ms = Some(now);
        }
    });
}

/// Build a [`crate::hooks::HookEnv`] whose registry loads the hermetic `busbar-hook-test-plugin`
/// cdylib under the given alias(es) (all pointing at the SAME cdylib) with the given declared manifest
/// `needs`. `None` when the cdylib is not built (the caller skips). Uses the unsigned +
/// `allow_unsigned` path (tests can't sign with the embedded first-party key) — still the full
/// scan/trust/load pipeline. Shared by the admin + resolution tests that need a hook to actually load.
pub(crate) fn test_hook_env(
    aliases: &[&str],
    needs: busbar_plugin_sign::HookNeeds,
) -> Option<crate::hooks::HookEnv> {
    test_hook_env_with_schema(aliases, needs, None)
}

/// As [`test_hook_env`], but lets a test stamp the loaded plugin's manifest with a
/// `settings_schema` — needed to exercise `GET /plugins/{name}/schema`'s describe→manifest
/// fallback (a real loaded hook whose live `describe` answers `schema: null` still has a real
/// manifest baseline to fall back to).
pub(crate) fn test_hook_env_with_schema(
    aliases: &[&str],
    needs: busbar_plugin_sign::HookNeeds,
    settings_schema: Option<&str>,
) -> Option<crate::hooks::HookEnv> {
    let cdylib = {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_hook_test_plugin");
        // Check BOTH the "uplifted" `<profile_dir>/<name>` copy (only refreshed when `[lib]` is a
        // ROOT build target, e.g. `cargo build --all-targets`) and the raw
        // `<profile_dir>/deps/<name>` compiler output (refreshed on every build that recompiles the
        // lib). A bare `cargo test` (a developer running `cargo test -p busbar` locally, or any
        // other scoped build step) does NOT uplift the cdylib to the top-level profile dir, only to
        // `target/deps` — checking only `profile_dir` silently found nothing even though the cdylib
        // really was built, making EVERY test that calls
        // `test_hook_env`/`test_hook_env_with_schema` (the admin hook-registration/resolution suite
        // among others) silently no-op instead of exercising real coverage. Same fix already
        // applied to store-postgres-plugin's, auth-oidc-plugin's, and webrequest-hook's equivalent
        // helpers.
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        let candidate = [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p);
        let Some(candidate) = candidate else {
            if std::env::var_os("CI").is_some() {
                panic!(
                    "the hook-test plugin cdylib is not built under CI (checked both the uplifted \
                     target dir and target/deps); refusing to silently skip the hook-plugin \
                     admin/resolution coverage"
                );
            }
            return None;
        };
        candidate
    };
    let lib = std::fs::read(&cdylib).expect("read hook cdylib");
    // A monotonic counter, NOT a clock read: two threads can read the same nanosecond, and a
    // colliding fixture path means one test scans a tarball another is still writing.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-test-hook-env-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (i, alias) in aliases.iter().enumerate() {
        let mut m = busbar_plugin_sign::Manifest {
            name: format!("busbar-hook-test-plugin-{i}"),
            alias: alias.to_string(),
            kind: "hook".into(),
            version: "1.5.0".into(),
            publisher: "acme".into(),
            abi_version: *busbar_plugin_loader::supported_abi("hook")
                .iter()
                .max()
                .unwrap(),
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: needs.clone(),
            settings_schema: settings_schema.map(str::to_string),
            schema_derived: false,
            host: None,
        };
        m.sha256 = busbar_plugin_sign::sha256_hex(&lib);
        let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", &lib).unwrap();
        std::fs::write(dir.join(format!("hook{i}.tar.gz")), tarball).unwrap();
    }
    let policy = busbar_plugin_sign::TrustPolicy {
        binary_version: "1.5.0".into(),
        allow_unsigned: true,
        ..Default::default()
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("scan");
    let _ = std::fs::remove_dir_all(&dir);
    Some(crate::hooks::HookEnv::new(
        std::sync::Arc::new(registry),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    ))
}

/// As [`test_hook_env`], but ALSO packs a second tarball under `wrong_kind_alias` whose manifest
/// claims `kind: "secret"` (reusing the SAME hook-test-plugin cdylib bytes — harmless, since a
/// resolves-to-wrong-kind check only ever reads `manifest.kind`, never `dlopen`s the wrong-kind
/// entry). Lets a test reach `probe_transport`'s "resolves, but to a non-hook kind" arm, which
/// `test_hook_env` alone cannot produce (every plugin it packs is `kind: "hook"`).
pub(crate) fn test_hook_env_with_wrong_kind_plugin(
    hook_alias: &str,
    wrong_kind_alias: &str,
) -> Option<crate::hooks::HookEnv> {
    let cdylib = {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_hook_test_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    };
    let Some(cdylib) = cdylib else {
        if std::env::var_os("CI").is_some() {
            panic!(
                "the hook-test plugin cdylib is not built under CI (checked both the uplifted \
                 target dir and target/deps); refusing to silently skip the wrong-kind-resolution \
                 coverage"
            );
        }
        return None;
    };
    let lib = std::fs::read(&cdylib).expect("read hook cdylib");
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-test-hook-env-wrongkind-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let manifest_for = |name: &str, alias: &str, kind: &str| busbar_plugin_sign::Manifest {
        name: name.to_string(),
        alias: alias.to_string(),
        kind: kind.to_string(),
        version: "1.5.0".into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi(kind)
            .iter()
            .max()
            .unwrap(),
        sha256: busbar_plugin_sign::sha256_hex(&lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    };
    let hook_tarball = busbar_plugin_loader::tarball::package(
        &manifest_for("busbar-hook-test-plugin-real", hook_alias, "hook"),
        "lib.so",
        &lib,
    )
    .unwrap();
    std::fs::write(dir.join("real-hook.tar.gz"), hook_tarball).unwrap();
    // `kind: "secret"` is arbitrary — any non-"hook" kind proves the resolves-to-wrong-kind arm;
    // "secret" is a real ABI kind this cdylib's manifest can validate under without needing a
    // matching implementation, since `probe_transport` never dlopens this entry.
    let wrong_kind_tarball = busbar_plugin_loader::tarball::package(
        &manifest_for(
            "busbar-hook-test-plugin-wrongkind",
            wrong_kind_alias,
            "secret",
        ),
        "lib.so",
        &lib,
    )
    .unwrap();
    std::fs::write(dir.join("wrong-kind.tar.gz"), wrong_kind_tarball).unwrap();
    let policy = busbar_plugin_sign::TrustPolicy {
        binary_version: "1.5.0".into(),
        allow_unsigned: true,
        ..Default::default()
    };
    let registry = busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("scan");
    let _ = std::fs::remove_dir_all(&dir);
    Some(crate::hooks::HookEnv::new(
        std::sync::Arc::new(registry),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    ))
}

/// THE METRICS RECORDER HARNESS: sum every exposition sample of `name` whose label set contains
/// ALL the given `key="value"` pairs, read from a fresh scrape of the process-global recorder
/// (`metrics::init` + `render` internally — callers never touch the recorder directly).
///
/// The global recorder is shared by every test in the process, so absolute values are meaningless;
/// assert STRICT DELTAS across the action under test (`before`/`after`), and give the test its own
/// pool/lane label values so parallel tests can't contribute to the matched sample. Matching is by
/// exact metric name (the char after the name must open the label set / value, so a name never
/// matches a longer neighbor it happens to prefix).
pub(crate) fn metric_sum(name: &str, labels: &[(&str, &str)]) -> f64 {
    crate::metrics::init();
    let frags: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
    crate::metrics::render()
        .lines()
        .filter(|l| {
            l.strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('{') || rest.starts_with(' '))
        })
        .filter(|l| frags.iter().all(|f| l.contains(f.as_str())))
        .filter_map(|l| l.rsplit(' ').next())
        .filter_map(|v| v.trim().parse::<f64>().ok())
        .sum()
}

fn weighted(members: &[(usize, u32)]) -> Vec<crate::state::WeightedLane> {
    members
        .iter()
        .map(|&(idx, weight)| crate::state::WeightedLane {
            reasoning: None,
            idx,
            weight,
            attempt_timeout_ms: None,
        })
        .collect()
}

/// Create (and return) a PRIVATE scratch directory for one test, under the process temp dir.
///
/// It lives in THIS file rather than beside the fixture that wants it because directory creation is
/// one of the hazards `structure-lint`'s choke-point registry keeps to a single owner: a
/// persist-then-swap is atomic only if every writer does the identical fsync/rename/cleanup dance,
/// so the greppable primitives get one home each — `crate::durable` for production, this file for
/// test scaffolding, which already creates the hook-plugin fixture trees the same way. A caller gets
/// a path back and never reaches for `create_dir_all` itself.
///
/// `name` must already be unique per test AND per thread; this does not make it so.
pub(crate) fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).expect("create the test scratch directory");
    dir
}

pub mod warn_capture;

/// The REAL `kind: store` plugin, loaded over the REAL C ABI: how a durability claim is judged.
pub(crate) mod plugin_store;

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

/// Panic-safe process-env restore for a test that must temporarily override a `std::env` var (e.g.
/// `BUSBAR_CONFIG`). A bare "set, assert, manually restore" sequence leaks the override to every
/// later test in the same binary the instant an `assert!`/`assert_eq!` in between fails: the panic
/// unwinds straight past the manual restore. `Drop` runs during unwind too, so holding the prior
/// value in a guard and restoring it there is safe regardless of whether the body between
/// construction and drop panics.
pub struct EnvVarGuard {
    key: &'static str,
    prior: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    /// Snapshot `key`'s current value (restored on drop). Does not itself set anything — callers
    /// `std::env::set_var` afterward.
    pub fn capture(key: &'static str) -> Self {
        Self {
            key,
            prior: std::env::var_os(key),
        }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.prior.take() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

/// The builtin-only `SecretResolver` (env/file sugar, no plugin modules) for a dependent crate's
/// tests — `SecretResolver::builtins_only` itself stays crate-private; this is the one doorway.
pub fn builtins_only_secret_resolver() -> crate::config::secret::SecretResolver {
    crate::config::secret::SecretResolver::builtins_only()
}
