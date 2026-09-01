// Compiled three ways: under this crate's own cfg(test) (users: the in-crate test trees), under
// the `test-support` FEATURE (users: a dependent crate's tests — the bin's), and never in a
// production build. In the feature-only build the in-crate users are absent, so the fixture set
// reads as dead to rustc; that is the compilation mode, not rot.
#![cfg_attr(not(test), allow(dead_code))]
// This is the crate's TEST-FIXTURE surface (compiled only under `cfg(test)` or the `test-support`
// feature, never in production). Its public builders legitimately name crate-internal config/state
// types in their signatures — that is the whole point of a fixture: it hands a test the engine's real
// inner types. Allowing `private_interfaces` here keeps those builders `pub` (reachable from a
// dependent crate's tests — the plane suites) WITHOUT widening the engine's production config/state
// types to `pub`. The types a dependent test must NAME to call a builder are widened individually.
#![allow(private_interfaces)]
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! In-crate mock-upstream test harness.

/// A data-plane `AuthMiddleware` whose chain is `[keys]` — the built-in signed-key verifier. Since
/// 1.5.2 virtual-key ENFORCEMENT is driven by the chain shape, not the admin token, so any e2e
/// fixture that mints a vkey and expects it to authenticate must run `keys` in the chain. Used by
/// the `minimal_app()`-style governed fixtures (which set `inner.auth = keys_chain_auth()`) and,
/// via `TestApp::keys_chain()`, by the builder fixtures.
pub fn keys_chain_auth() -> std::sync::Arc<crate::auth::AuthMiddleware> {
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
pub enum MockResponse {
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
pub struct MockServerState {
    queued_replies: Mutex<Vec<MockResponse>>,
    last_auth_header: std::sync::Mutex<Option<String>>,
    last_request_body: std::sync::Mutex<Option<Vec<u8>>>,
    last_request_headers: std::sync::Mutex<Option<axum::http::HeaderMap>>,
    last_request_path: std::sync::Mutex<Option<String>>,
}

impl MockServerState {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push(&self, response: MockResponse) {
        self.queued_replies.lock().unwrap().push(response);
    }
    fn next_response(&self) -> Option<MockResponse> {
        self.queued_replies.lock().unwrap().pop()
    }

    /// Record the last seen Authorization header for testing passthrough token forwarding
    pub fn record_auth_header(&self, header: &str) {
        *self.last_auth_header.lock().unwrap() = Some(header.to_string());
    }

    /// Get the recorded Authorization header (for assertions in tests)
    pub fn get_last_auth_header(&self) -> Option<String> {
        self.last_auth_header.lock().unwrap().clone()
    }

    /// Clear the recorded Authorization header
    pub fn clear_auth_header(&self) {
        *self.last_auth_header.lock().unwrap() = None;
    }

    /// Record the received request path (for translation / on-the-wire assertions).
    pub fn record_request_path(&self, path: &str) {
        *self.last_request_path.lock().unwrap() = Some(path.to_string());
    }

    /// Get the last received request path.
    pub fn get_last_request_path(&self) -> Option<String> {
        self.last_request_path.lock().unwrap().clone()
    }

    /// Record the last received request body (for translation / on-the-wire assertions).
    pub fn record_request_body(&self, body: &[u8]) {
        *self.last_request_body.lock().unwrap() = Some(body.to_vec());
    }

    /// Get the last received request body bytes (for assertions in tests).
    pub fn get_last_request_body(&self) -> Option<Vec<u8>> {
        self.last_request_body.lock().unwrap().clone()
    }

    /// Record the full set of request headers the upstream received (for indistinguishability
    /// assertions — e.g. that a health probe sends the same User-Agent/Accept as organic traffic).
    pub fn record_request_headers(&self, headers: &axum::http::HeaderMap) {
        *self.last_request_headers.lock().unwrap() = Some(headers.clone());
    }

    /// Get a single request header value the upstream received, by name (case-insensitive).
    pub fn get_last_request_header(&self, name: &str) -> Option<String> {
        self.last_request_headers
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|h| h.get(name))
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }
}

pub struct MockServer {
    addr: SocketAddr,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    pub async fn new(state: std::sync::Arc<MockServerState>) -> Self {
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
pub struct LaneSpec {
    model: String,
    provider: String,
    base_url: String,
    // NEUTRAL FIXTURE: a lane needs only its protocol's registry
    // NAME — the codec itself is resolved by-name from the installed registry at dispatch, never held
    // here. Storing the interned `&'static str` (a neutral `PROTO_*` const) instead of an
    // `Arc<crate::proto::Protocol>` lets the routing/dispatch suites build lanes without naming the
    // witnessed busbar-llm codec, so the witness can be deleted at the final flip.
    protocol: &'static str,
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
    pub fn new(model: &str, protocol: &'static str, base_url: &str) -> Self {
        Self {
            model: model.into(),
            provider: "test-provider".into(),
            base_url: base_url.into(),
            protocol,
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
    pub fn provider(mut self, p: &str) -> Self {
        self.provider = p.into();
        self
    }
    pub fn max(mut self, n: usize) -> Self {
        self.max = n;
        self
    }
    pub fn api_key(mut self, k: &str) -> Self {
        self.api_key = k.into();
        self
    }
    pub fn error_map(mut self, m: std::collections::HashMap<String, String>) -> Self {
        self.error_map = m;
        self
    }
    pub fn context_max(mut self, n: usize) -> Self {
        self.context_max = Some(n);
        self
    }
    pub fn path(mut self, p: &str) -> Self {
        self.path = Some(p.into());
        self
    }
    pub fn path_base(mut self, p: &str) -> Self {
        self.path_base = Some(p.into());
        self
    }
    pub fn auth(mut self, a: &str) -> Self {
        self.auth = Some(a.into());
        self
    }
    pub fn health(mut self, h: crate::config::HealthCfg) -> Self {
        self.health = Some(h);
        self
    }
    pub fn default_max_tokens(mut self, n: u32) -> Self {
        self.default_max_tokens = Some(n);
        self
    }
    pub fn upstream_model(mut self, n: &str) -> Self {
        self.upstream_model = Some(n.into());
        self
    }
    /// Mark the lane as budget-limited with `n` remaining requests (sets `limited = true`).
    pub fn budget(mut self, n: i64) -> Self {
        self.limited = true;
        self.budget = n;
        self
    }
    pub fn cooldown_until(mut self, t: u64) -> Self {
        self.cooldown_until = t;
        self
    }
    pub fn streak(mut self, n: u32) -> Self {
        self.streak = n;
        self
    }
    pub fn dead(mut self, reason: &str) -> Self {
        self.dead = true;
        self.dead_reason = reason.into();
        self
    }
    pub fn ok(mut self, n: u64) -> Self {
        self.ok = n;
        self
    }
    pub fn err(mut self, n: u64) -> Self {
        self.err = n;
        self
    }
    /// Override the lane's permit semaphore with a shared handle the test retains, so it can
    /// observe permit acquisition/release across the request lifetime.
    pub fn sem(mut self, sem: std::sync::Arc<tokio::sync::Semaphore>) -> Self {
        self.sem = Some(sem);
        self
    }

    fn to_lane(&self) -> crate::state::Lane {
        let auth = self.auth.as_deref().map(|a| match a {
            "api-key" => crate::config::ProviderAuth::ApiKey,
            "bearer" => crate::config::ProviderAuth::Bearer,
            other => panic!("unexpected test auth style in LaneSpec: {other}"),
        });
        let credential = crate::egress_auth::resolve(self.protocol, auth);
        crate::state::Lane {
            // The REAL boot prebuild (same as production appbuild), so the engine's prebuilt-vs-live
            // header paths are both exercised by the fixture protocols' real credentials.
            prebuilt_auth: crate::egress_auth::prebuild_auth(
                &credential,
                &self.api_key,
                &crate::proxy::host_from_base(&self.base_url),
            ),
            // The REAL boot precompute, so tests exercise the same egress-target table production
            // reads (and the probe/forward byte-identity proofs cover it). Test base URLs always
            // parse; a fixture that breaks that should fail loudly here.
            egress_targets: crate::proxy::build_egress_targets(
                self.protocol,
                self.path.as_deref(),
                self.path_base.as_deref(),
                self.upstream_model.as_deref().unwrap_or(&self.model),
                &self.base_url,
            )
            .expect("test lane egress URLs parse"),
            reasoning: false,
            prompt_caching: false,
            credential,
            model: self.model.clone(),
            provider: self.provider.clone(),
            signing_host: crate::proxy::host_from_base(&self.base_url),
            base_url: self.base_url.clone(),
            api_key: busbar_api::Redacted::new(self.api_key.clone()),
            // G6 A4b Lane inversion: `Lane.protocol` is the interned protocol NAME now, not an
            // `Arc<Protocol>`. The builder holds that interned name directly (Phase 1.5 neutral fixture).
            protocol: self.protocol,
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

/// Per-plane container-gate hook SPECS, keyed by plane decl key: each value is the plane's
/// `(container_name, own_hook_names)` pairs plus its section-level hook list.
type PlaneContainerHooks =
    std::collections::BTreeMap<&'static str, (Vec<(String, Vec<String>)>, Vec<String>)>;

#[allow(dead_code)]
pub struct TestApp {
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
    /// The built authorization server (`oauth_as:`). `None` (the default) = this deployment is not
    /// one, which is what every pre-existing test expects and what the gating proof in
    /// `oauth_as::tests::mount_tests` asserts costs nothing.
    oauth_as: Option<std::sync::Arc<crate::oauth_as::plane::AsPlane>>,
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
    /// THE PLANE INSTALL SEAM: the pre-built, type-erased plane runtimes `build()` moves into the
    /// App's [`crate::state::App::plane_slots`], keyed by each plane's decl key (and the MCP
    /// per-generation runtime under [`crate::state::runtime_slot_key`]). Filled from OUTSIDE core by
    /// each plane's test-kit through [`TestApp::install_plane_runtime`], so `build()` names no plane
    /// runtime type — the whole point of the B2/B3 relocation: core's fixture is plane-AGNOSTIC and
    /// the `busbar-mcp` / `busbar-a2a` test-kits own their own construction.
    installed_plane_runtimes:
        std::collections::BTreeMap<&'static str, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    /// THE NEUTRAL DISPATCH TABLE the built App mounts. A plane's test-kit describes its mounts and
    /// admissions through [`TestApp::mount_plane`] / [`TestApp::admit_plane`] (neutral `&str` paths,
    /// substrate `PlaneAdmission`), so `build()` names no plane type to assemble the router surface.
    plane_dispatch: crate::plane::PlaneDispatch,
    /// The type-erased section-defs config handles the built App carries, KEYED by the owning plane's
    /// decl key (mirroring `plane_gates`/`plane_pools`). The agents-section plane's entry becomes
    /// [`crate::state::App::agent_defs`]; an absent key ⇒ the neutral empty placeholder (`Arc::new(())`),
    /// which no test-path consumer downcasts — the A2A plane reads its `AgentsCfg` off its own runtime
    /// object, not off this handle. Each plane's test-kit sets its real erased defs here for fidelity.
    plane_defs_any:
        std::collections::BTreeMap<&'static str, std::sync::Arc<dyn std::any::Any + Send + Sync>>,
    /// NEUTRAL per-container hook SPECS, KEYED by the owning plane's decl key (the `tools:` plane's
    /// server hooks, the `agents:` plane's agent hooks) — each value is `(container_name, own_hook_names)`
    /// pairs plus the section-level hook list, handed here by that plane's test-kit as plain strings off
    /// its typed config, so `build()` resolves the gates against its OWN `hook_registry`/`hook_env`
    /// through the public `hooks::resolve_container_gates` (exactly as production does) without ever
    /// naming a plane-typed config section. Resolving at build time (not in the test-kit) keeps the
    /// resolution reading the same registry/env the fixture was given, regardless of builder order.
    container_hooks: PlaneContainerHooks,
    /// POST-BUILD hooks a plane's test-kit registers to run against the finished `App` (e.g. the MCP
    /// plane's durable-demotion replay, which names `mcp::demotion` and so cannot live in core).
    #[allow(clippy::type_complexity)]
    post_build: Vec<Box<dyn FnOnce(&std::sync::Arc<crate::state::App>)>>,
    /// TYPE-ERASED per-plane accumulator scratch. A plane's test-kit stashes its own builder state here
    /// (keyed by plane key) across the fluent chain — `.mcp(cfg)`, `.mcp_server(def)`, … each mutate
    /// ONE `McpScratch` — so core never names the plane's config types. Downcast back by the test-kit
    /// through [`TestApp::plane_scratch`] / [`TestApp::take_plane_scratch`].
    plane_scratch: std::collections::HashMap<&'static str, Box<dyn std::any::Any>>,
    /// PER-PLANE FINALIZERS run at the TOP of `build()`. Each is registered ONCE by a plane's test-kit
    /// (via [`TestApp::register_plane_finalizer`]); it reads its accumulated [`plane_scratch`] and
    /// drives the neutral install seams (`install_plane_runtime`, `mount_plane`/`admit_plane`,
    /// `set_container_hooks`, `set_plane_defs_any`, `on_built`). This is the doorway that keeps the
    /// fluent `.mcp(...).mcp_server(...).build()` call shape working while the runtime/resource
    /// construction that NAMES plane types lives entirely in the plane crate's test-kit.
    #[allow(clippy::type_complexity)]
    plane_finalizers: Vec<Box<dyn FnOnce(&mut dyn busbar_substrate::testkit::TestAppSeam)>>,
}

impl Default for TestApp {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(dead_code)]
impl TestApp {
    pub fn new() -> Self {
        Self {
            mcp_durable_store: None,
            upstream_credentials: crate::auth::UpstreamCreds::Own,
            lanes: Vec::new(),
            pools: std::collections::HashMap::new(),
            auth: None,
            admin_chain: None,
            admin_modules: None,
            login_methods: None,
            public_url: None,
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
            plane_dispatch: crate::plane::PlaneDispatch::default(),
            plane_defs_any: std::collections::BTreeMap::new(),
            container_hooks: std::collections::BTreeMap::new(),
            post_build: Vec::new(),
            plane_scratch: std::collections::HashMap::new(),
            plane_finalizers: Vec::new(),
        }
    }

    /// TEST-KIT SEAM — the fixture's configured `public_url:`, which a plane's finalizer needs to lower
    /// its runtime (the A2A plane derives its card/discovery origins from it). Named distinctly from
    /// the `public_url(url)` builder SETTER above.
    pub fn configured_public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    /// TEST-KIT SEAM — busbar's PUBLIC A2A card-issuer key off the fixture's governance, computed EXACTLY
    /// as production's `a2a_start` hook / `boot::start_planes` computes it, returned as the neutral
    /// substrate `CardIssuer`. The A2A test-kit stamps it onto its plane so a fixture that configures
    /// both an a2a plane and a card-signing governance key serves signed cards without running the boot
    /// fold. `None` when no governance / no card key — core exposes only the neutral value, never its
    /// `pub` governance accessor.
    pub fn card_issuer(&self) -> Option<busbar_substrate::plane::registry::CardIssuer> {
        self.governance.as_ref().and_then(|g| g.a2a_card_issuer())
    }

    /// THE PLANE INSTALL SEAM. Install a pre-built, type-erased plane runtime under its plane decl
    /// `key` (or the MCP per-generation runtime under [`crate::state::runtime_slot_key`]). `build()`
    /// moves the accumulated map into [`crate::state::App::plane_slots`], so this is the one doorway a
    /// plane runtime enters the built App's type-erased slot — the seam each plane's test-kit drives so
    /// core's fixture names no plane runtime type.
    pub fn install_plane_runtime(
        &mut self,
        key: &'static str,
        rt: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) -> &mut Self {
        self.installed_plane_runtimes.insert(key, rt);
        self
    }

    /// NEUTRAL DISPATCH SEAM — record that plane `key` is mounted at `path` speaking `wire`. A plane's
    /// test-kit calls this with the plane's own mount path (`&str`) and a substrate wire const, so
    /// `build()` mounts the plane surface without naming a plane type. Mirrors production's
    /// `PlaneDispatch::mount`.
    pub fn mount_plane(&mut self, key: &'static str, path: &str, wire: &'static str) -> &mut Self {
        let d = std::mem::take(&mut self.plane_dispatch);
        self.plane_dispatch = d.mount(key, path, wire);
        self
    }

    /// NEUTRAL DISPATCH SEAM — record plane `key`'s RFC 8707 admission. The admission is the substrate
    /// `PlaneAdmission` the plane's own accessor already returns, so `build()` names no plane type to
    /// wire the audience check. Mirrors production's `PlaneDispatch::admit`.
    pub fn admit_plane(
        &mut self,
        key: &'static str,
        admission: busbar_substrate::plane::PlaneAdmission,
    ) -> &mut Self {
        let d = std::mem::take(&mut self.plane_dispatch);
        self.plane_dispatch = d.admit(key, admission);
        self
    }

    /// NEUTRAL GATE SEAM — hand `build()` plane `plane_key`'s per-container hook SPECS as plain strings
    /// (`(container_name, own_hook_names)` pairs + the section hook list, e.g. `tools.hooks:`/`agents.hooks:`).
    /// `build()` resolves them against its own `hook_registry`/`hook_env` through the public
    /// `crate::hooks::resolve_container_gates`, exactly as production does, and files the gate map under
    /// `plane_key` — so no plane-typed config section enters core and one method serves every plane.
    pub fn set_container_hooks(
        &mut self,
        plane_key: &'static str,
        containers: Vec<(String, Vec<String>)>,
        section: Vec<String>,
    ) -> &mut Self {
        self.container_hooks
            .insert(plane_key, (containers, section));
        self
    }

    /// NEUTRAL SECTION-DEFS SEAM — set plane `plane_key`'s type-erased named-definition config the built
    /// App carries (the A2A plane's `agents:` defs become [`crate::state::App::agent_defs`]). The plane's
    /// test-kit erases its own config and hands it here KEYED, so core names no plane config type. No
    /// test-path consumer downcasts the handle (the plane reads its config off its runtime object); it
    /// exists for production fidelity.
    pub fn set_plane_defs_any(
        &mut self,
        plane_key: &'static str,
        defs: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) -> &mut Self {
        self.plane_defs_any.insert(plane_key, defs);
        self
    }

    /// NEUTRAL POST-BUILD SEAM — register a closure to run against the finished `App`. A plane's
    /// test-kit uses this for steps that name plane types (e.g. the MCP plane's durable-demotion
    /// replay), keeping them out of core's `build()`.
    #[allow(clippy::type_complexity)]
    pub fn on_built(
        &mut self,
        f: Box<dyn FnOnce(&std::sync::Arc<crate::state::App>)>,
    ) -> &mut Self {
        self.post_build.push(f);
        self
    }

    /// Build an App that BOOTED WITH NO PLUGIN ROUTES: empty live table, empty `boot_route_paths`.
    /// The fixture for the restart-to-apply signal — a config apply that ADDS a
    /// path the router never registered at boot.
    pub fn no_plugin_routes(mut self) -> Self {
        self.no_plugin_routes = true;
        self
    }

    /// Install a hook plugin-resolution env (for hook-transport resolution tests). Defaults to an
    /// empty registry (a hook's `plugin:` ref resolves to `None`, i.e. gate-absent).
    pub fn hook_env(mut self, env: crate::hooks::HookEnv) -> Self {
        self.hook_env = Some(env);
        self
    }

    /// Point the plugin surface at a specific directory (for the Admin API plugin catalog / install /
    /// remove / reload tests). Defaults to `plugins` when unset.
    pub fn plugins_dir(mut self, path: std::path::PathBuf) -> Self {
        self.plugins_dir = Some(path);
        self
    }
    /// Set the whole `plugins.*` posture (for install re-verification tests). Defaults to the
    /// strict disabled default.
    pub fn plugins_cfg(mut self, cfg: crate::config::PluginsCfg) -> Self {
        self.plugins_cfg = Some(cfg);
        self
    }

    /// Give the snapshot DISK TRUTH — the `config.yaml` / `providers.yaml` paths a rebuild reads.
    /// Without these the app is EPHEMERAL and every rebuild-from-disk path takes its no-disk branch,
    /// so the failure modes of the rebuild itself are unreachable from a test.
    pub fn disk_paths(mut self, config: std::path::PathBuf, providers: std::path::PathBuf) -> Self {
        self.disk_paths = Some((config, providers));
        self
    }

    /// Enable config-overlay persistence at `path` (for testing runtime-change durability).
    pub fn overlay_path(mut self, path: std::path::PathBuf) -> Self {
        self.overlay_path = Some(path);
        self.explicit_no_overlay = false;
        self
    }

    /// 1.5.3: build a LOCKED app (`config.locked: true` at runtime) — no overlay backend, so every
    /// config mutation is refused. Overrides the durable-by-default overlay `build()` otherwise
    /// provides. The only supported way for a test to reach `overlay_path: None`.
    pub fn no_overlay(mut self) -> Self {
        self.overlay_path = None;
        self.explicit_no_overlay = true;
        self
    }
    /// Register a hook definition in the `hooks:` registry (for the Admin API v1 hooks read surface).
    pub fn hook(mut self, name: &str, cfg: crate::config::HookCfg) -> Self {
        self.hook_registry.insert(name.into(), cfg);
        self
    }
    /// Register a BASE-config-defined hook (registry AND `base_hook_names`) so the API's base-hook
    /// read-only guards (register/put/patch/delete return 409) can be exercised.
    pub fn base_hook(mut self, name: &str, cfg: crate::config::HookCfg) -> Self {
        self.hook_registry.insert(name.into(), cfg);
        self.base_hook_names.insert(name.into());
        self
    }
    /// Register a `groups:` entry into the App's group registry (the Admin-API groups read/mutation
    /// surface). Marks it a BASE (config-file) group, so the base-shadow 409 guard sees it.
    pub fn group(mut self, name: &str, cfg: crate::config::GroupCfg) -> Self {
        self.groups_registry.insert(name.into(), cfg);
        self.base_group_names.insert(name.into());
        self
    }
    /// Seed an `identity-providers:` DEFINITION into the App's effective named map (the read side of
    /// the generic named-map admin CRUD). Mirror whatever the fixture's on-disk config.yaml declares.
    pub fn identity_provider(
        mut self,
        name: &str,
        cfg: crate::config::IdentityProviderCfg,
    ) -> Self {
        self.identity_providers.insert(name.into(), cfg);
        self
    }
    /// Seed an `export:` DEFINITION into the App's effective named map — the exporter twin of
    /// [`TestApp::identity_provider`].
    pub fn export_def(mut self, name: &str, cfg: crate::config::ExportDefCfg) -> Self {
        self.export_defs.insert(name.into(), cfg);
        self
    }
    /// Declare a `tool_pools:` failover pool over already-seeded `mcp_server` registrations —
    /// exactly the operator's grammar: ordered members, optional `repeatable:` operations.
    pub fn tool_pool(mut self, name: &str, members: &[&str], repeatable: &[&str]) -> Self {
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
    pub fn agent_pool(mut self, name: &str, members: &[&str]) -> Self {
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
    pub fn groups_tree(
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
    pub fn global_hook(mut self, name: &str) -> Self {
        self.global_hooks.push(name.into());
        self
    }
    pub fn lane(mut self, spec: LaneSpec) -> Self {
        self.lanes.push(spec);
        self
    }
    /// Define a pool over lane indices: `members` is `(lane_index, weight)` pairs.
    pub fn pool(mut self, name: &str, members: &[(usize, u32)]) -> Self {
        self.pools.insert(name.into(), weighted(members));
        self
    }
    /// Set the ALL-POOLS upstream-credential mode (1.5.3: the reserved `pools.upstream_credentials:`
    /// key — it used to be `auth.upstream_credentials`) — driving the egress credential-selection
    /// path. `Own` = the old `mode: none`; `Passthrough` = the old `mode: passthrough`. Per-pool
    /// overrides go on the pool's own `PoolRuntime` (see `.pool_runtime(...)`).
    pub fn upstream_creds(mut self, uc: crate::auth::UpstreamCreds) -> Self {
        self.upstream_credentials = uc;
        self
    }
    /// Override the ADMIN auth chain. `vec![]` is the explicit OPEN admin posture — the only way
    /// to reach the admin surface on a fixture that has no governance to hold an operator token.
    pub fn admin_chain(mut self, modules: Vec<String>) -> Self {
        self.admin_chain = Some(modules);
        self
    }

    /// Inject a resolved external admin auth module under `name` (the config module name that both
    /// `admin_chain` and `role_bindings.<name>` key off), marking the chain as plugin-backed so the
    /// admin auth middleware OFFLOADS it off the reactor — the seam the 1.5.2 admin-plane OIDC
    /// offload test drives. `has_plugin` is forced true.
    pub fn admin_module(mut self, name: &str, module: Box<dyn crate::auth::AuthModule>) -> Self {
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
    pub fn public_url(mut self, url: &str) -> Self {
        self.public_url = Some(url.to_string());
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
    pub fn oauth_as(mut self, cfg: &crate::oauth_as::config::OauthAsCfg) -> Self {
        let identity = crate::oauth_as::config::AsIdentity::from_cfg(cfg)
            .expect("test oauth_as config must be valid");
        let plane = crate::oauth_as::plane::AsPlane::build(identity, None, Vec::new())
            .expect("test oauth_as plane must build");
        self.oauth_as = Some(std::sync::Arc::new(plane));
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
    pub fn mcp_durable_store(mut self, store: std::sync::Arc<dyn busbar_api::Store>) -> Self {
        self.mcp_durable_store = Some(store);
        self
    }

    /// Inject a hosted-login method (1.5.2) keyed by `name`. `module` is a login-capable auth
    /// plugin (test stand-in); `client_secret`/`issuer` are the CORE-held confidential-client secret
    /// + issuer hint; `has_button` gates whether it renders on the chooser / accepts begin.
    pub fn login_method(
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

    pub fn auth(mut self, a: std::sync::Arc<crate::auth::AuthMiddleware>) -> Self {
        self.auth = Some(a);
        self
    }
    /// Install an `AuthMiddleware` whose data-plane chain is `[keys]` (the built-in signed-key
    /// verifier). This is what makes a data-plane request REQUIRE and resolve a virtual key: since
    /// 1.5.2 vkey enforcement is driven by the chain shape, not the admin token. Pair with
    /// `.governance(gov)` for the enforcing-vkey e2e posture.
    pub fn keys_chain(mut self) -> Self {
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
    pub fn idp_chain(mut self) -> Self {
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
    pub fn mint_policy(mut self, policy: crate::admin::MintPolicy) -> Self {
        self.mint_policy = Some(policy);
        self
    }

    pub fn role_bindings(mut self, rb: crate::config::RoleBindings) -> Self {
        self.role_bindings = Some(rb);
        self
    }
    /// Install a resolved cost model (rate card / budget groups / flat fee) for tests exercising
    /// the derived-spend enforcement. Default: `CostModel::flat(1)` - no rate card, no groups,
    /// the production default 1-cent flat fee.
    pub fn cost(mut self, c: crate::cost::CostModel) -> Self {
        self.cost = Some(std::sync::Arc::new(c));
        self
    }

    pub fn governance(mut self, g: std::sync::Arc<crate::governance::GovState>) -> Self {
        self.governance = Some(g);
        self
    }
    pub fn failover(mut self, f: crate::config::FailoverCfg) -> Self {
        self.failover_cfg = Some(f);
        self
    }
    pub fn pool_runtime(mut self, name: &str, rt: crate::state::PoolRuntime) -> Self {
        self.pool_runtime.insert(name.into(), rt);
        self
    }
    pub fn fallback_pool(mut self, name: &str, members: &[(usize, u32)]) -> Self {
        self.fallback_pools.insert(name.into(), weighted(members));
        self
    }
    pub fn on_exhausted(mut self, name: &str, oe: crate::config::OnExhausted) -> Self {
        self.on_exhausted_cfgs.insert(name.into(), oe);
        self
    }
    pub fn build(self) -> std::sync::Arc<crate::state::App> {
        self.build_with_store().0
    }

    // (helper defined at module scope below — see `test_plugin_route_table`)

    /// As [`build`], but also hands back the concrete `Arc<HealthState>` — `App::store` is a
    /// `dyn LaneRuntime` trait object with no downcast support, so a test that needs to reach
    /// test-only breaker-cell manipulation (`HealthState::cell`/`cell_open`, real Open/HalfOpen
    /// state, not achievable through the trait's own methods) needs the typed handle to the SAME
    /// store instance the built `App` uses, not a second independent one.
    pub fn build_with_store(
        mut self,
    ) -> (
        std::sync::Arc<crate::state::App>,
        std::sync::Arc<crate::store::HealthState>,
    ) {
        // PLANE FINALIZERS FIRST: each plane's test-kit registered one; it consumes its accumulated
        // scratch and drives the neutral install seams (runtimes, dispatch mounts/admissions, gate
        // specs, agents handle, post-build hooks). Run here — before anything below reads those fields
        // — so the fluent `.mcp(...)/.agent_def(...)` chain lowers to a real, externally-linked plane.
        let finalizers = std::mem::take(&mut self.plane_finalizers);
        for f in finalizers {
            f(&mut self);
        }
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
        // THE PLANE SLOTS, filled from OUTSIDE core: each plane's test-kit already built its runtime
        // objects (the `"mcp"`/`"a2a"` dispatch resources AND the MCP per-generation runtime under
        // `runtime_slot_key(<mcp decl key>)`) and installed them through [`TestApp::install_plane_runtime`], so
        // `build()` MOVES the accumulated type-erased map into the App slot without naming a plane
        // runtime type or a slot key of its own.
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut plane_slots = std::mem::take(&mut self.installed_plane_runtimes);
        // THE MCP PLANE'S ALWAYS-PRESENT per-generation runtime slot. In THIS crate's own test binary
        // (`#[cfg(test)]`) the MCP plane is a built-in of the process list (see `registry`), so — like
        // production `appbuild` — every generation must carry its runtime under `runtime_slot_key(<mcp decl key>)`, or
        // the plane's `reresolve_gates`/`on_swap` seams (run on every admin mutation) fault. A fixture
        // that opted the plane in through its test-kit already installed one; this fills the DEFAULT for
        // every other `TestApp`, sourced from the plane's own test-kit so `build()` names no MCP type.
        // Absent under an external `test-support` build (no `cfg(test)`), where the process list has no
        // MCP plane unless a test registers it — and such a test installs its own runtime.
        // The plane that owns the `tools:` section is the MCP plane; its stable decl key comes from the
        // registry (a built-in under `cfg(test)`), never spelled as a literal, and its default runtime
        // factory is reached through the `tests/`-file helper (which alone names `busbar_mcp`), so this
        // neutral source names no MCP token nor a plane symbol.
        #[cfg(test)]
        if let Some(decl) = crate::plane::registry::plane_decl_for_config_section(
            crate::config::named_map::NamedMapSection::Tools.key(),
        ) {
            plane_slots
                .entry(crate::state::runtime_slot_key(decl.key))
                .or_insert_with(crate::plane::registry::default_mcp_test_runtime);
        }
        // THE NEUTRAL DISPATCH TABLE, described by each plane's test-kit through the `mount_plane` /
        // `admit_plane` seams (neutral `&str` paths + substrate `PlaneAdmission`), so a router-walking
        // test sees the surface a deployment would have without `build()` naming a plane type.
        let plane_dispatch = std::mem::take(&mut self.plane_dispatch);
        let auth = self.auth.unwrap_or_else(|| {
            std::sync::Arc::new(crate::auth::AuthMiddleware::new_builtin(
                &crate::config::AuthCfg::default_none(),
            ))
        });
        // NEUTRAL label projections (money-path Phase 3-4 B) — pool→member-idx list, the direct-model
        // index, and a lane-idx→model resolver — so `AppSlots::build` banks the label space without
        // naming `Lane`/`WeightedLane`. Borrows `self.pools`/`by_model`/`lanes` before they move into
        // the runtime bundle below (NLL releases the borrows at the build call).
        let ts_pools: Vec<(&str, Vec<usize>)> = self
            .pools
            .iter()
            .map(|(name, members)| (name.as_str(), members.iter().map(|wl| wl.idx).collect()))
            .collect();
        let ts_by_model: Vec<(&str, usize)> = by_model
            .iter()
            .map(|(model, &idx)| (model.as_str(), idx))
            .collect();
        let tslots = std::sync::Arc::new(crate::telemetry::AppSlots::build(
            &ts_pools,
            &ts_by_model,
            |idx| lanes.get(idx).map(|lane| lane.model.as_str()),
            crate::plane::fallback_key(),
        ));
        let store = std::sync::Arc::new(crate::store::HealthState::new(lane_data));
        // THE LLM DATA-PLANE RUNTIME slot (R3/R4 sub-phase B) — the successor to the flat `llm_runtime`
        // field every fixture used to set. Built here (AFTER `tslots`' `&lanes`/`&self.pools`/
        // `&by_model` borrows above, and preserving the field order whose earlier fields BORROW
        // `lanes`/`self.pool_runtime` before the later fields MOVE them) and inserted into `plane_slots`
        // UNCONDITIONALLY under the interned `runtime_slot_key(<llm plane key>)`: a fixture always
        // configures its lanes/pools and expects them readable through `engine_tables`, exactly as the
        // always-present flat field guaranteed, so `build()` seeds the slot for every `TestApp` whose
        // process actually has an LLM (fallback) plane. GATED on `is_fallback` because `fallback_key()`
        // degrades to the FIRST registered plane's key when no plane flags itself fallback (the plane
        // suites' dependency-copy of core, which registers only MCP/A2A) — inserting there would key the
        // LLM runtime under a sibling's `runtime_slot_key` and clobber that sibling's own runtime slot.
        let llm_runtime_key = crate::state::runtime_slot_key(crate::plane::fallback_key());
        // Built and inserted ONLY when a real fallback (LLM) plane owns the key — otherwise `lanes`/
        // `by_model`/the `self.*` tables simply drop unused, and `App::llm_runtime` reads the empty
        // default (a surface with no LLM plane never routes through `engine_tables` anyway).
        if crate::plane::is_fallback(crate::plane::fallback_key()) {
            let llm_runtime = crate::state::NativeRuntime {
                probe_schedule: std::sync::Arc::new(crate::health::ProbeSchedule::new(lanes.len())),
                // Mirror production (`appbuild`): the accessor's fast path is enabled only when no pool
                // installs an override, so a test that sets one via `.pool_runtime(...)` still exercises
                // the full lookup.
                any_pool_upstream_creds_override: self
                    .pool_runtime
                    .values()
                    .any(|rt| rt.upstream_credentials.is_some()),
                lanes,
                by_model,
                pools: self.pools,
                pool_runtime: self.pool_runtime,
                fallback_pools: self.fallback_pools,
                on_exhausted_cfgs: self.on_exhausted_cfgs,
                failover_cfg: self.failover_cfg,
                queued_depth: std::sync::Arc::new(crate::state::QueuedDepth::default()),
                upstream_credentials: self.upstream_credentials,
                client: crate::state::UpstreamClients::build(1, || {
                    // The REAL owned egress client at default spec — tests drive the same hyper stack
                    // production runs (the in-process MockServer is plain http, which the connector's
                    // `https_or_http` posture serves).
                    crate::proxy::build_egress_client(&crate::proxy::EgressClientSpec::llm_lane(
                        4, 300, false, false,
                    ))
                }),
            };
            plane_slots.insert(
                llm_runtime_key,
                std::sync::Arc::new(llm_runtime) as std::sync::Arc<dyn std::any::Any + Send + Sync>,
            );
        }
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
        // THE PER-PLANE CONTAINER GATES, RESOLVED THE WAY PRODUCTION RESOLVES THEM, from the registry
        // and env this fixture was given. The per-container hook SPECS arrive KEYED by plane decl key
        // from each plane's test-kit (`set_container_hooks`); `build()` runs the SAME
        // `resolve_container_gates` production uses over them, so a test that hand-assembled a gate
        // chain could not attach a hook the real resolver would have skipped. Keyed here by each owning
        // plane's DECL KEY (resolved from the registry, never a literal) — the `tools:` section's plane
        // and the `agents:` section's plane — so an absent/compiled-out plane simply gets no entry,
        // which the gate read treats identically to the former empty-value entry. Computed BEFORE the
        // `App` literal so it holds no borrow of `self` across the moves the literal performs.
        let plane_gates_map: crate::state::PlaneGateMap = {
            let mut m = std::collections::BTreeMap::new();
            for section in [
                crate::config::named_map::NamedMapSection::Tools,
                crate::config::named_map::NamedMapSection::Agents,
            ] {
                if let Some(decl) =
                    crate::plane::registry::plane_decl_for_config_section(section.key())
                {
                    let (containers, section_hooks) = self
                        .container_hooks
                        .get(decl.key)
                        .cloned()
                        .unwrap_or_default();
                    let gates = crate::hooks::resolve_container_gates(
                        containers.iter().map(|(n, h)| (n.as_str(), h.as_slice())),
                        &section_hooks,
                        &self.hook_registry,
                        &hook_env,
                        0,
                    );
                    m.insert(decl.key, gates);
                }
            }
            m
        };
        let app = std::sync::Arc::new(crate::state::App {
            // No authorization server unless a test asked for one with `TestApp::oauth_as`, which is
            // the production default and is what keeps every existing test's route table unchanged
            // by this plane's arrival.
            oauth_as: self.oauth_as.clone(),
            // The type-erased `agents:` handle: the A2A test-kit erases its own `AgentsCfg` and hands
            // it via `set_plane_defs_any` KEYED by its plane; `build()` reads it under the decl key of
            // the plane that owns the `agents:` section (resolved from the registry, never a literal),
            // exactly as `plane_pools`/`plane_gates` below. Absent that, a neutral empty placeholder no
            // test-path consumer downcasts (the A2A plane reads its `AgentsCfg` off its runtime object).
            agent_defs: crate::plane::registry::plane_decl_for_config_section(
                crate::config::named_map::NamedMapSection::Agents.key(),
            )
            .and_then(|decl| self.plane_defs_any.remove(decl.key))
            .unwrap_or_else(|| std::sync::Arc::new(())),
            tslots,
            // THE LLM DATA-PLANE RUNTIME'S SLOT KEY (R3/R4 sub-phase B) — the bundle itself was composed
            // above into `plane_slots` under this interned key; the snapshot names only the key, and
            // `App::llm_runtime` downcasts the slot on the money path.
            llm_runtime_key,
            store: store.clone(),
            plane_breakers: std::sync::Arc::new(crate::store::PlaneBreakers::new()),
            session_store: std::sync::Arc::new(crate::session::SessionStore::new(1024, None)),
            incremental_scan: false,
            tool_pools: self.tool_pools,
            plane_pools: {
                // Keyed by the DECL KEY of the plane that owns the `agents:` section — resolved from
                // the registry, never spelled as a literal — exactly as production `appbuild` keys it.
                // A compiled-out plane has no decl for its section, so nothing is inserted (the pool
                // read treats an absent key identically to the former empty-value entry).
                let mut m = std::collections::BTreeMap::new();
                if let Some(decl) = crate::plane::registry::plane_decl_for_config_section(
                    crate::config::named_map::NamedMapSection::Agents.key(),
                ) {
                    m.insert(decl.key, self.agent_pools);
                }
                m
            },
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
            plane_gates: plane_gates_map,
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
            // THE NEUTRAL DISPATCH TABLE, described by each plane's test-kit through `mount_plane` /
            // `admit_plane` — so a router-walking test sees the surface a deployment would have while
            // `build()` names no plane type to assemble it.
            planes: std::sync::Arc::new(plane_dispatch),
            // THE TYPE-ERASED SLOT MAP, filled from outside core through [`TestApp::install_plane_runtime`]
            // by each plane's test-kit and MOVED in here — so a fixture-built App has the same "one
            // object, downcast by the plane's own accessor" property `build_app_from_config` gives
            // production, and `build()` names no slot key or plane runtime type.
            plane_slots,
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
        // Mirror main's durable-MCP-trust boot block: attach the plane sinks BEFORE the app is handed
        // to a caller. The MCP-specific demotion REPLAY that follows sink-attach in production is
        // registered by the MCP test-kit as a `post_build` hook (it names `mcp::demotion`), run below.
        if let Some(durable) = mcp_durable_store {
            // Narrowed to the plane surface exactly as boot does — these are plane sinks.
            let plane_store = crate::plane::store::PlaneStoreView::narrow(durable);
            app.spent_token_ledger.set_sink(plane_store.clone());
            app.demotion_record.set_sink(plane_store);
        }
        // Run each plane test-kit's POST-BUILD hooks against the finished App (e.g. the MCP plane's
        // durable-demotion replay), the doorway for steps that name plane types without core doing so.
        for f in self.post_build.drain(..) {
            f(&app);
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

// NOTE: `prefresh_mcp_sightings` (seed every registered MCP server's verification clock as just
// checked) named `mcp::runtime`/`mcp::client` types and so RELOCATED to `busbar_mcp::testkit`
// alongside the plane it serves — core's `test_support` stays plane-neutral.

/// Build a [`crate::hooks::HookEnv`] whose registry loads the hermetic `busbar-hook-test-plugin`
/// cdylib under the given alias(es) (all pointing at the SAME cdylib) with the given declared manifest
/// `needs`. `None` when the cdylib is not built (the caller skips). Uses the unsigned +
/// `allow_unsigned` path (tests can't sign with the embedded first-party key) — still the full
/// scan/trust/load pipeline. Shared by the admin + resolution tests that need a hook to actually load.
pub fn test_hook_env(
    aliases: &[&str],
    needs: busbar_plugin_sign::HookNeeds,
) -> Option<crate::hooks::HookEnv> {
    test_hook_env_with_schema(aliases, needs, None)
}

/// As [`test_hook_env`], but lets a test stamp the loaded plugin's manifest with a
/// `settings_schema` — needed to exercise `GET /plugins/{name}/schema`'s describe→manifest
/// fallback (a real loaded hook whose live `describe` answers `schema: null` still has a real
/// manifest baseline to fall back to).
pub fn test_hook_env_with_schema(
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
pub fn test_hook_env_with_wrong_kind_plugin(
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
pub fn metric_sum(name: &str, labels: &[(&str, &str)]) -> f64 {
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
pub fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).expect("create the test scratch directory");
    dir
}

pub mod warn_capture;

/// The REAL `kind: store` plugin, loaded over the REAL C ABI: how a durability claim is judged.
pub mod plugin_store;

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

// ── SHARED CONFIG-BUILD FIXTURES (relocated from src/tests/tests.rs) ─────────────────────────────
// `pub` so BOTH the in-crate unit tests and busbar-core's OWN integration-test target
// (`tests/plane_integration.rs`, where the plane crates link as ONE busbar_core) can build a RootCfg
// and drive it through the real `build_app_from_config`.
/// A minimal `RootCfg` whose SOLE provider's `api_key` is the given secret reference — the smallest
/// config that exercises `config_validate::secret_refs` (and thus `validate_secret_refs`).
pub fn cfg_with_provider_api_key(api_key: crate::config::SecretRef) -> crate::config::RootCfg {
    let mut error_map = std::collections::HashMap::new();
    error_map.insert("400".to_string(), "client_error".to_string());
    let provider = crate::config::ProviderCfg {
        // The registry-supplied residual-default dialect — the neutral test protocol — in place of the
        // hard-coded `"openai"` literal. Under every surface that drives this fixture the LLM protocols
        // are registered first (core's `cfg(test)` auto-publish, or each test's `install_test_seams`),
        // so this resolves to the same default dialect the literal named.
        protocol: crate::proto::residual_default_dialect()
            .expect("a residual-default protocol (the neutral test dialect) must be registered")
            .into(),
        base_url: "https://api.example.com".into(),
        api_key,
        health: None,
        error_map,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
    };
    let mut providers = std::collections::HashMap::new();
    providers.insert("acme".to_string(), provider);
    crate::config::RootCfg {
        tool_defs: crate::plane::config::ToolsSection::default().0,
        // No endpoint plane configured.
        endpoint_resources: Default::default(),
        oauth_as: None,
        agent_defs: crate::plane::config::AgentsSection::default().0,
        tool_pools: Default::default(),
        agent_pools: Default::default(),
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        listen: crate::config::DEFAULT_LISTEN_ADDR.into(),
        public_url: None,
        tls: None,
        admin_listen: crate::config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,
        providers,
        models: std::collections::HashMap::new(),
        pools: std::collections::HashMap::new(),
        hooks: std::collections::HashMap::new(),
        admin_auth: vec!["admin-tokens".to_string()],
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        store: None,
        secrets: std::collections::BTreeMap::new(),
        global_hooks: Vec::new(),
        blocked_metadata_hosts: Vec::new(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        limits: crate::config::LimitsResolved::default(),
        export: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
    }
}

pub fn build_once(
    cfg: crate::config::RootCfg,
    prior: Option<&crate::state::App>,
) -> Result<crate::state::App, String> {
    // Test-only direct call: there is no outer admin transaction / persist step here, so firing any
    // resolved governance-credential rotation immediately is correct
    // and keeps this helper's callers (which assert on rotation taking effect) unchanged.
    let (app, gov_rotate) = crate::build_app_from_config(
        cfg,
        crate::config::PluginsCfg::default(),
        None,
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
        (None, None),
        prior,
    )?;
    if let Some(rotate) = gov_rotate {
        rotate();
    }
    Ok(app)
}

/// A CLOSED single-module auth chain (the given module), for integration tests that must build an
/// mcp-server App (`mcp:` refuses an open data-plane chain). Built in-crate so the caller names no
/// `AuthChainEntry` field.
pub fn closed_auth_chain(module: &str) -> crate::config::AuthCfg {
    let mut auth = crate::config::AuthCfg::default_none();
    auth.chain = vec![crate::config::AuthChainEntry {
        name: module.to_string(),
        module: module.to_string(),
        max_admin_scope: None,
        token: None,
        settings: serde_json::Map::new(),
    }];
    auth
}

/// Drive a REAL oversized POST to `path` through the REAL layer stack and return the 413 body.
/// Asserts only the status and JSON-ness; the SHAPE is each caller's assertion.
pub async fn oversized_413_body(
    app: std::sync::Arc<crate::state::App>,
    path: &str,
) -> serde_json::Value {
    // A tiny body cap so an ordinary request trips `DefaultBodyLimit`.
    let (router, _handle) = crate::build_router_with_limits(app, 64, 1024, false);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    let oversized = "x".repeat(4096);
    let r = reqwest::Client::new()
        .post(format!("http://{addr}{path}"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "pad": oversized }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        413,
        "the body cap must reject the oversized POST to {path}"
    );
    let body = r.text().await.unwrap();
    server.abort();
    serde_json::from_str(&body)
        .unwrap_or_else(|e| panic!("the 413 body must be JSON ({e}): {body}"))
}

// ── THE NEUTRAL TEST-APP SEAM (busbar_substrate::testkit::TestAppSeam) ──────────────────────────────
// Core implements the neutral fixture seam for its concrete `TestApp`, so the extracted plane
// test-kits (`busbar-mcp`/`busbar-a2a`) build and drive the test App through the trait — naming no
// `busbar_core::state::App`/`test_support::TestApp` backwards. Each method delegates to the inherent
// fixture logic above (or to the type-erased scratch map); the object-safe scratch primitives back the
// generic `TestAppSeamExt::plane_scratch::<T>` sugar the plane test-kits call.
impl busbar_substrate::testkit::TestAppSeam for TestApp {
    fn plane_scratch_any(
        &mut self,
        key: &'static str,
        init: &dyn Fn() -> Box<dyn std::any::Any>,
    ) -> &mut dyn std::any::Any {
        self.plane_scratch.entry(key).or_insert_with(init).as_mut()
    }

    fn take_plane_scratch_any(&mut self, key: &'static str) -> Option<Box<dyn std::any::Any>> {
        self.plane_scratch.remove(key)
    }

    fn register_plane_finalizer(
        &mut self,
        f: Box<dyn FnOnce(&mut dyn busbar_substrate::testkit::TestAppSeam)>,
    ) {
        self.plane_finalizers.push(f);
    }

    fn configured_public_url(&self) -> Option<&str> {
        TestApp::configured_public_url(self)
    }

    fn card_issuer(
        &self,
        _plane_key: &'static str,
    ) -> Option<busbar_substrate::plane::registry::CardIssuer> {
        TestApp::card_issuer(self)
    }

    fn install_plane_runtime(
        &mut self,
        key: &'static str,
        rt: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) {
        TestApp::install_plane_runtime(self, key, rt);
    }

    fn mount_plane(&mut self, key: &'static str, path: &str, wire: &'static str) {
        TestApp::mount_plane(self, key, path, wire);
    }

    fn admit_plane(
        &mut self,
        key: &'static str,
        admission: busbar_substrate::plane::PlaneAdmission,
    ) {
        TestApp::admit_plane(self, key, admission);
    }

    fn set_container_hooks(
        &mut self,
        plane_key: &'static str,
        containers: Vec<(String, Vec<String>)>,
        section: Vec<String>,
    ) {
        TestApp::set_container_hooks(self, plane_key, containers, section);
    }

    fn set_plane_defs_any(
        &mut self,
        plane_key: &'static str,
        defs: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) {
        TestApp::set_plane_defs_any(self, plane_key, defs);
    }
}
