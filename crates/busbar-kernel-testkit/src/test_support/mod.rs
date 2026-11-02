#![cfg_attr(not(test), allow(dead_code))]
// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
mod overlay;
pub use overlay::{new_test_overlay, TestOverlayPause, TestOverlayStore};

pub fn hook_route_declarations(
    env: &mut crate::hooks::HookEnv,
    definitions: &std::collections::HashMap<String, crate::config::HookCfg>,
) -> Result<Vec<crate::plugin_routes::RouteDecl>, String> {
    env.route_decls(definitions)
}

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
    /// `eventstream_frame` so the bytes carry real prelude/message CRC32s an AWS SDK
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
    /// (each encoded via `eventstream_frame`), then PAUSES so the proxy reliably reads
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
    pub fn next_response(&self) -> Option<MockResponse> {
        self.queued_replies.lock().unwrap().pop()
    }

    pub fn record_request_path(&self, path: &str) {
        *self.last_request_path.lock().unwrap() = Some(path.to_string());
    }

    pub fn get_last_request_path(&self) -> Option<String> {
        self.last_request_path.lock().unwrap().clone()
    }

    pub fn record_request_body(&self, body: &[u8]) {
        *self.last_request_body.lock().unwrap() = Some(body.to_vec());
    }

    pub fn get_last_request_body(&self) -> Option<Vec<u8>> {
        self.last_request_body.lock().unwrap().clone()
    }

    pub fn record_request_headers(&self, headers: &axum::http::HeaderMap) {
        *self.last_request_headers.lock().unwrap() = Some(headers.clone());
    }

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
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MockServer {
    pub async fn new(state: std::sync::Arc<MockServerState>) -> Self {
        let app = Router::new()
            .route("/v1/messages", any(mock_handler))
            .route("/v1/chat/completions", any(mock_handler))
            .fallback(any(mock_handler))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stop_rx.await;
                })
                .await
                .unwrap();
        });
        Self {
            addr,
            handle: Some(handle),
            stop: Some(stop_tx),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.addr
    }
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

fn eventstream_frame(event_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut headers = Vec::new();
    let pairs = [
        (":event-type", event_type),
        (":content-type", "application/json"),
        (":message-type", "event"),
    ];
    for (name, value) in pairs {
        headers.push(name.len() as u8);
        headers.extend_from_slice(name.as_bytes());
        headers.push(7);
        headers.extend_from_slice(&(value.len() as u16).to_be_bytes());
        headers.extend_from_slice(value.as_bytes());
    }
    let total = (16 + headers.len() + payload.len()) as u32;
    let mut frame = [total, headers.len() as u32].map(u32::to_be_bytes).concat();
    frame.extend(crc32fast::hash(&frame).to_be_bytes());
    frame.extend(headers);
    frame.extend_from_slice(payload);
    frame.extend(crc32fast::hash(&frame).to_be_bytes());
    frame
}

fn frames_then_drop(frames: Vec<Bytes>) -> Body {
    let drop = stream::once(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        Err(std::io::Error::other("mid-stream connection drop"))
    });
    Body::from_stream(stream::iter(frames.into_iter().map(Ok::<Bytes, std::io::Error>)).chain(drop))
}

async fn mock_handler(
    State(state): State<std::sync::Arc<MockServerState>>,
    request: Request<Body>,
) -> Response<Body> {
    let (parts, body) = request.into_parts();

    state.record_request_path(parts.uri.path());

    state.record_request_headers(&parts.headers);

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
                let mut result: Vec<String> = events
                    .iter()
                    .take(idx)
                    .map(|d| format!("data: {d}\n\n"))
                    .collect();

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
                let mut result: Vec<String> = events
                    .into_iter()
                    .map(|d| format!("data: {d}\n\n"))
                    .collect();
                result.push("data: [DONE]\n\n".to_owned());
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
            let frames: Vec<Bytes> = ok_events
                .into_iter()
                .map(|d| Bytes::from(format!("data: {d}\n\n")))
                .collect();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(frames_then_drop(frames))
                .unwrap()
        }
        MockResponse::EventStream {
            frames,
            amzn_request_id,
        } => {
            let mut bytes: Vec<u8> = Vec::new();
            for (event_type, payload) in &frames {
                bytes.extend(eventstream_frame(event_type, payload));
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
            let frames: Vec<Bytes> = ok_frames
                .into_iter()
                .map(|(event_type, payload)| Bytes::from(eventstream_frame(event_type, &payload)))
                .collect();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/vnd.amazon.eventstream")
                .header("x-amzn-requestid", amzn_request_id)
                .body(frames_then_drop(frames))
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

#[allow(dead_code)]
pub struct LaneSpec {
    model: String,
    provider: String,
    base_url: String,

    protocol: &'static str,
    max: usize,
    api_key: busbar_contract::redacted::Secret<String>,
    error_map: std::collections::HashMap<String, String>,
    context_max: Option<usize>,
    path: Option<String>,
    path_base: Option<String>,
    auth: Option<String>,
    health: Option<crate::config::HealthCfg>,
    default_max_tokens: Option<u32>,
    upstream_model: Option<String>,

    limited: bool,
    budget: i64,
    cooldown_until: u64,
    streak: u32,
    dead: bool,
    dead_reason: String,
    ok: u64,
    err: u64,
    client_fault: u64,

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
            api_key: String::from("k").into(),
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
        self.api_key = k.to_string().into();
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

    pub fn sem(mut self, sem: std::sync::Arc<tokio::sync::Semaphore>) -> Self {
        self.sem = Some(sem);
        self
    }

    fn to_lane_input(&self) -> busbar_kernel::plane_driver::route_input::LaneInput {
        busbar_kernel::plane_driver::route_input::LaneInput {
            model: self.model.clone(),
            provider: self.provider.clone(),
            base_url: busbar_kernel_egress::trust::net::strip_userinfo(
                self.base_url.trim_end_matches('/'),
            )
            .into_owned(),
            max_concurrent: self.max,
        }
    }
    fn to_lane_data(&self) -> crate::store::LaneData {
        crate::store::LaneData::from_test_parts(
            self.model.clone(),
            self.provider.clone(),
            self.max,
            self.sem
                .clone()
                .unwrap_or_else(|| std::sync::Arc::new(tokio::sync::Semaphore::new(self.max))),
            self.limited,
            self.budget,
            self.cooldown_until,
            self.streak,
            self.dead,
            self.dead_reason.clone(),
            self.ok,
            self.err,
            self.client_fault,
        )
    }
}

fn test_plugin_route_table() -> crate::plugin_routes::PluginRouteTable {
    if crate::snapshot::recorder_installed() {
        crate::plugin_routes::build_route_table(export_axis::lines_scrape_routes())
            .unwrap_or_else(|_| crate::plugin_routes::PluginRouteTable::empty())
    } else {
        crate::plugin_routes::PluginRouteTable::empty()
    }
}

type PlaneContainerHooks =
    std::collections::BTreeMap<&'static str, (Vec<(String, Vec<String>)>, Vec<String>)>;

pub type BuiltApp = crate::state::App;

#[cfg(test)]
fn seeded_section_plane_runtime() -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    Some(std::sync::Arc::new(()))
}
#[cfg(not(test))]
fn seeded_section_plane_runtime() -> Option<std::sync::Arc<dyn std::any::Any + Send + Sync>> {
    None
}

#[allow(dead_code)]
pub struct TestApp {
    lanes: Vec<LaneSpec>,

    pools: std::collections::HashMap<String, Vec<(usize, u32)>>,
    auth: Option<std::sync::Arc<crate::auth::AuthMiddleware>>,

    admin_chain: Option<Vec<String>>,

    admin_modules: Option<crate::auth::AdminAuthChain>,

    login_methods: Vec<(
        String,
        std::sync::Arc<dyn busbar_contract::auth_calls::AuthCalls>,
        busbar_contract::auth::LoginKind,
        bool,
    )>,

    public_url: Option<String>,

    oauth_as: Option<std::sync::Arc<dyn std::any::Any + Send + Sync>>,

    plane_sections: Option<std::collections::BTreeSet<&'static str>>,
    plane_durable_store: Option<std::sync::Arc<dyn busbar_contract::records::RecordStore>>,
    role_bindings: Option<crate::config::RoleBindings>,

    mint_policy: Option<crate::governance::mint_policy::MintPolicy>,
    governance: Option<std::sync::Arc<crate::governance::GovState>>,
    cost: Option<std::sync::Arc<crate::cost::CostModel>>,

    pool_orderings: std::collections::HashMap<String, crate::hooks::ResolvedPolicy>,
    pool_decision_gates:
        std::collections::HashMap<String, Vec<(u16, crate::hooks::ResolvedPolicy)>>,
    #[allow(clippy::type_complexity)]
    pool_rewrite_chains: std::collections::HashMap<
        String,
        Vec<(
            std::time::Duration,
            std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
        )>,
    >,

    upstream_credentials: crate::auth::UpstreamCreds,
    fallback_pools: std::collections::HashMap<String, Vec<(usize, u32)>>,
    on_exhausted_cfgs: std::collections::HashMap<String, crate::config::OnExhausted>,
    hook_registry: std::collections::HashMap<String, crate::config::HookCfg>,
    global_hooks: Vec<String>,

    resolve_global_gates: bool,
    base_hook_names: std::collections::HashSet<String>,
    groups_registry: std::collections::BTreeMap<String, crate::config::GroupCfg>,
    base_group_names: std::collections::HashSet<String>,
    identity_providers: crate::config::IdentityProviders,
    export_defs: crate::config::ExportDefs,

    plane_pools_by_section: std::collections::BTreeMap<
        &'static str,
        std::collections::BTreeMap<String, crate::config::pools::CandidatePoolCfg>,
    >,
    overlay_path: Option<std::sync::Arc<crate::config::overlay::OverlayStore>>,

    explicit_no_overlay: bool,
    plugins_dir: Option<std::path::PathBuf>,
    plugins_cfg: Option<crate::config::PluginsCfg>,
    plugin_admission: Option<&'static dyn crate::admission::PluginAdmission>,
    hook_env: Option<crate::hooks::HookEnv>,
    disk_paths: Option<(std::path::PathBuf, std::path::PathBuf)>,

    no_plugin_routes: bool,

    installed_plane_runtimes:
        std::collections::BTreeMap<&'static str, std::sync::Arc<dyn std::any::Any + Send + Sync>>,

    plane_dispatch: crate::plane_driver::dispatch::PlaneDispatch,

    container_hooks: PlaneContainerHooks,

    plane_scratch: std::collections::HashMap<&'static str, Box<dyn std::any::Any>>,

    #[allow(clippy::type_complexity)]
    plane_finalizers: Vec<Box<dyn FnOnce(&mut dyn crate::test_support::TestAppSeam)>>,

    serve_tables: crate::plane_driver::serve::ServeTables,
}

impl Default for TestApp {
    fn default() -> Self {
        Self::new()
    }
}

impl TestApp {
    #[must_use]
    pub fn serve_tables(mut self, tables: crate::plane_driver::serve::ServeTables) -> Self {
        self.serve_tables = tables;
        self
    }

    pub fn plane_sections(mut self, sections: &[&'static str]) -> Self {
        self.plane_sections = Some(sections.iter().copied().collect());
        self
    }

    pub fn new() -> Self {
        root::ensure();
        Self {
            plane_durable_store: None,
            upstream_credentials: crate::auth::UpstreamCreds::Own,
            lanes: Vec::new(),
            pools: std::collections::HashMap::new(),
            auth: None,
            admin_chain: None,
            admin_modules: None,
            login_methods: Vec::new(),
            public_url: None,
            oauth_as: None,
            plane_sections: None,
            role_bindings: None,
            mint_policy: None,
            governance: None,
            cost: None,
            pool_orderings: std::collections::HashMap::new(),
            pool_decision_gates: std::collections::HashMap::new(),
            pool_rewrite_chains: std::collections::HashMap::new(),
            fallback_pools: std::collections::HashMap::new(),
            on_exhausted_cfgs: std::collections::HashMap::new(),
            hook_registry: std::collections::HashMap::new(),
            global_hooks: Vec::new(),
            resolve_global_gates: false,
            base_hook_names: std::collections::HashSet::new(),
            groups_registry: std::collections::BTreeMap::new(),
            base_group_names: std::collections::HashSet::new(),
            identity_providers: Default::default(),
            export_defs: Default::default(),
            plane_pools_by_section: Default::default(),
            overlay_path: None,
            explicit_no_overlay: false,
            plugins_dir: None,
            plugins_cfg: None,
            plugin_admission: None,
            hook_env: None,
            disk_paths: None,
            no_plugin_routes: false,
            installed_plane_runtimes: std::collections::BTreeMap::new(),
            plane_dispatch: crate::plane_driver::dispatch::PlaneDispatch::default(),
            container_hooks: std::collections::BTreeMap::new(),
            plane_scratch: std::collections::HashMap::new(),
            plane_finalizers: Vec::new(),
            serve_tables: crate::plane_driver::serve::ServeTables::default(),
        }
    }

    pub fn install_plane_runtime(
        &mut self,
        key: &'static str,
        rt: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) -> &mut Self {
        self.installed_plane_runtimes.insert(key, rt);
        self
    }

    pub fn mount_plane(&mut self, key: &'static str, path: &str, wire: &'static str) -> &mut Self {
        let d = std::mem::take(&mut self.plane_dispatch);
        self.plane_dispatch = d.mount(key, path, wire);
        self
    }

    pub fn admit_plane(
        &mut self,
        key: &'static str,
        admission: busbar_kernel::plane_driver::dispatch::PlaneAdmission,
    ) -> &mut Self {
        let d = std::mem::take(&mut self.plane_dispatch);
        self.plane_dispatch = d.admit(key, admission);
        self
    }

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

    pub fn set_plane_defs_any(
        &mut self,
        _plane_key: &'static str,
        _defs: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) -> &mut Self {
        self
    }

    pub fn no_plugin_routes(mut self) -> Self {
        self.no_plugin_routes = true;
        self
    }

    pub fn hook_env(mut self, env: crate::hooks::HookEnv) -> Self {
        self.hook_env = Some(env);
        self
    }

    pub fn plugins_dir(mut self, path: std::path::PathBuf) -> Self {
        self.plugins_dir = Some(path);
        self
    }

    pub fn plugins_cfg(mut self, cfg: crate::config::PluginsCfg) -> Self {
        self.plugins_cfg = Some(cfg);
        self
    }

    pub fn plugin_admission(mut self, a: &'static dyn crate::admission::PluginAdmission) -> Self {
        self.plugin_admission = Some(a);
        self
    }

    pub fn disk_paths(mut self, config: std::path::PathBuf, providers: std::path::PathBuf) -> Self {
        self.disk_paths = Some((config, providers));
        self
    }

    pub fn overlay_backend(
        mut self,
        backend: std::sync::Arc<crate::config::overlay::OverlayStore>,
    ) -> Self {
        self.overlay_path = Some(backend);
        self.explicit_no_overlay = false;
        self
    }

    pub fn no_overlay(mut self) -> Self {
        self.overlay_path = None;
        self.explicit_no_overlay = true;
        self
    }

    pub fn hook(mut self, name: &str, cfg: crate::config::HookCfg) -> Self {
        self.hook_registry.insert(name.into(), cfg);
        self
    }

    pub fn base_hook(mut self, name: &str, cfg: crate::config::HookCfg) -> Self {
        self.hook_registry.insert(name.into(), cfg);
        self.base_hook_names.insert(name.into());
        self
    }

    pub fn group(mut self, name: &str, cfg: crate::config::GroupCfg) -> Self {
        self.groups_registry.insert(name.into(), cfg);
        self.base_group_names.insert(name.into());
        self
    }

    pub fn identity_provider(
        mut self,
        name: &str,
        cfg: crate::config::IdentityProviderCfg,
    ) -> Self {
        self.identity_providers.insert(name.into(), cfg);
        self
    }

    pub fn export_def(mut self, name: &str, cfg: crate::config::ExportDefCfg) -> Self {
        self.export_defs.insert(name.into(), cfg);
        self
    }

    pub fn tool_pool(mut self, name: &str, members: &[&str], repeatable: &[&str]) -> Self {
        let section = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2];
        self.plane_pools_by_section
            .entry(section)
            .or_default()
            .insert(
                name.into(),
                crate::config::pools::CandidatePoolCfg {
                    members: members.iter().map(|m| (*m).to_string()).collect(),
                    repeatable: repeatable.iter().map(|o| (*o).to_string()).collect(),
                    breaker: None,
                },
            );
        self
    }

    pub fn agent_pool(mut self, name: &str, members: &[&str]) -> Self {
        let section = busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[3];
        self.plane_pools_by_section
            .entry(section)
            .or_default()
            .insert(
                name.into(),
                crate::config::pools::CandidatePoolCfg {
                    members: members.iter().map(|m| (*m).to_string()).collect(),
                    repeatable: Vec::new(),
                    breaker: None,
                },
            );
        self
    }

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

    pub fn global_hook(mut self, name: &str) -> Self {
        self.global_hooks.push(name.into());
        self
    }

    pub fn resolve_global_gates(mut self) -> Self {
        self.resolve_global_gates = true;
        self
    }
    pub fn lane(mut self, spec: LaneSpec) -> Self {
        self.lanes.push(spec);
        self
    }

    pub fn pool(mut self, name: &str, members: &[(usize, u32)]) -> Self {
        self.pools.insert(name.into(), members.to_vec());
        self
    }

    pub fn upstream_creds(mut self, uc: crate::auth::UpstreamCreds) -> Self {
        self.upstream_credentials = uc;
        self
    }

    pub fn admin_chain(mut self, modules: Vec<String>) -> Self {
        self.admin_chain = Some(modules);
        self
    }

    pub fn admin_module(mut self, name: &str, module: Box<dyn crate::auth::AuthModule>) -> Self {
        let chain = self
            .admin_modules
            .get_or_insert_with(crate::auth::AdminAuthChain::empty);
        chain.modules.insert(
            name.to_string(),
            crate::test_support::auth_helpers::in_process(module),
        );
        self
    }

    pub fn admin_door(
        mut self,
        name: &str,
        calls: std::sync::Arc<dyn busbar_contract::auth_calls::AuthCalls>,
    ) -> Self {
        let chain = self
            .admin_modules
            .get_or_insert_with(crate::auth::AdminAuthChain::empty);
        chain
            .modules
            .insert(name.to_string(), crate::auth::AdminModule { calls });
        self
    }

    pub fn public_url(mut self, url: &str) -> Self {
        self.public_url = Some(url.to_string());
        self
    }

    pub fn oauth_as_plane(
        mut self,
        plane: std::sync::Arc<dyn std::any::Any + Send + Sync>,
    ) -> Self {
        self.oauth_as = Some(plane);
        self
    }

    pub fn durable_store(
        mut self,
        store: std::sync::Arc<dyn busbar_contract::records::RecordStore>,
    ) -> Self {
        self.plane_durable_store = Some(store);
        self
    }

    pub fn login_method_door(
        mut self,
        name: &str,
        calls: std::sync::Arc<dyn busbar_contract::auth_calls::AuthCalls>,
        login_kind: busbar_contract::auth::LoginKind,
        has_button: bool,
    ) -> Self {
        let method = (name.to_owned(), calls, login_kind, has_button);
        if let Some(prior) = self.login_methods.iter_mut().find(|m| m.0 == name) {
            *prior = method;
        } else {
            self.login_methods.push(method);
        }
        self
    }

    pub fn auth(mut self, a: std::sync::Arc<crate::auth::AuthMiddleware>) -> Self {
        self.auth = Some(a);
        self
    }

    pub fn keys_chain(mut self) -> Self {
        let cfg = crate::config::AuthCfg {
            chain: vec![crate::config::AuthChainEntry::bare(
                crate::config::KEYS_MODULE,
            )],
            ..crate::config::AuthCfg::default_none()
        };
        self.auth = Some(std::sync::Arc::new(
            crate::test_support::auth_helpers::new_builtin(&cfg),
        ));
        self
    }

    pub fn idp_chain(mut self) -> Self {
        let cfg = crate::config::AuthCfg {
            chain: vec![crate::config::AuthChainEntry::bare("test-idp-module")],
            ..crate::config::AuthCfg::default_none()
        };
        self.auth = Some(std::sync::Arc::new(
            crate::test_support::auth_helpers::new_builtin(&cfg),
        ));
        self.role_bindings
            .get_or_insert_with(Default::default)
            .entry("test-idp-module".to_string())
            .or_default()
            .entry(auth_modules::TEST_IDP_ROLE.to_string())
            .or_default();
        self
    }

    pub fn mint_policy(mut self, policy: crate::governance::mint_policy::MintPolicy) -> Self {
        self.mint_policy = Some(policy);
        self
    }

    pub fn role_bindings(mut self, rb: crate::config::RoleBindings) -> Self {
        self.role_bindings = Some(rb);
        self
    }

    pub fn cost(mut self, c: crate::cost::CostModel) -> Self {
        self.cost = Some(std::sync::Arc::new(c));
        self
    }

    pub fn governance(mut self, g: std::sync::Arc<crate::governance::GovState>) -> Self {
        self.governance = Some(g);
        self
    }

    pub fn cost_kit(
        mut self,
        c: std::sync::Arc<dyn crate::test_support::engine_kit::CostKit>,
    ) -> Self {
        self.cost = Some(engine_kit::cost_model(c));
        self
    }

    pub fn governance_kit(
        self,
        g: std::sync::Arc<dyn crate::test_support::engine_kit::GovKit>,
    ) -> Self {
        self.governance(engine_kit::gov_state(g))
    }

    pub fn pool_policy_resolved(
        mut self,
        name: &str,
        policy: crate::hooks::ResolvedPolicy,
    ) -> Self {
        self.pool_orderings.insert(name.into(), policy);
        self
    }

    pub fn pool_gates_resolved(
        mut self,
        name: &str,
        gates: Vec<(u16, crate::hooks::ResolvedPolicy)>,
    ) -> Self {
        self.pool_decision_gates.insert(name.into(), gates);
        self
    }

    #[allow(clippy::type_complexity)]
    pub fn pool_rewrites_resolved(
        mut self,
        name: &str,
        rewrites: Vec<(
            std::time::Duration,
            std::sync::Arc<dyn crate::hooks::RoutingPolicy>,
        )>,
    ) -> Self {
        self.pool_rewrite_chains.insert(name.into(), rewrites);
        self
    }
    pub fn fallback_pool(mut self, name: &str, members: &[(usize, u32)]) -> Self {
        self.fallback_pools.insert(name.into(), members.to_vec());
        self
    }
    pub fn on_exhausted(mut self, name: &str, oe: crate::config::OnExhausted) -> Self {
        self.on_exhausted_cfgs.insert(name.into(), oe);
        self
    }
    pub fn build(self) -> std::sync::Arc<crate::state::App> {
        self.build_with_store().0
    }

    pub fn build_with_store(
        mut self,
    ) -> (
        std::sync::Arc<crate::state::App>,
        std::sync::Arc<crate::store::HealthState>,
    ) {
        let finalizers = std::mem::take(&mut self.plane_finalizers);
        for f in finalizers {
            f(&mut self);
        }

        let serve_tables = self.serve_tables.clone();

        let plane_durable_store = self.plane_durable_store.clone();
        let mut by_model = std::collections::HashMap::new();

        let mut lane_inputs = Vec::with_capacity(self.lanes.len());
        let mut lane_data = Vec::with_capacity(self.lanes.len());
        for (i, spec) in self.lanes.iter().enumerate() {
            by_model.insert(spec.model.clone(), i);
            lane_inputs.push(spec.to_lane_input());
            lane_data.push(spec.to_lane_data());
        }

        #[cfg_attr(not(test), allow(unused_mut))]
        let mut plane_slots = std::mem::take(&mut self.installed_plane_runtimes);

        if let Some(decl) = crate::plane_driver::registry::plane_decl_for_config_section(
            busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2],
        ) {
            if let Some(rt) = seeded_section_plane_runtime() {
                plane_slots
                    .entry(crate::state::runtime_slot_key(decl.key))
                    .or_insert(rt);
            }
        }

        let plane_dispatch = std::mem::take(&mut self.plane_dispatch);
        let auth = self.auth.unwrap_or_else(|| {
            std::sync::Arc::new(crate::test_support::auth_helpers::new_builtin(
                &crate::config::AuthCfg::default_none(),
            ))
        });

        let ts_pools_owned: Vec<(String, Vec<usize>)> = self
            .pools
            .iter()
            .map(|(name, members)| (name.clone(), members.iter().map(|(idx, _)| *idx).collect()))
            .collect();
        let ts_by_model_owned: Vec<(String, usize)> = by_model
            .iter()
            .map(|(model, &idx)| (model.clone(), idx))
            .collect();
        let ts_lane_models: Vec<String> =
            lane_inputs.iter().map(|lane| lane.model.clone()).collect();
        let store = std::sync::Arc::new(crate::store::HealthState::new(lane_data));

        let fallback = crate::plane_driver::registry::plane_decls()
            .iter()
            .copied()
            .find(|decl| decl.fallback);
        let fallback_runtime_key = crate::state::runtime_slot_key(fallback.map_or("", |d| d.key));

        let mut config_tables =
            std::sync::Arc::<busbar_kernel::plane_driver::route_tables::ConfigTables>::default();
        if fallback.is_some() {
            let mut pool_map: std::collections::BTreeMap<String, Vec<(usize, u32)>> =
                std::collections::BTreeMap::new();
            for (name, members) in self.fallback_pools.iter().chain(self.pools.iter()) {
                pool_map.insert(name.clone(), members.clone());
            }
            let pool_inputs: Vec<busbar_kernel::plane_driver::route_input::PoolInput> = pool_map
                .into_iter()
                .map(|(name, members)| busbar_kernel::plane_driver::route_input::PoolInput {
                    members: members
                        .iter()
                        .map(
                            |&(lane_idx, weight)| busbar_kernel::plane_driver::route_input::PoolMemberInput {
                                lane_idx,
                                weight,
                            },
                        )
                        .collect(),
                    on_exhausted: match self.on_exhausted_cfgs.get(&name) {
                        Some(crate::config::OnExhausted::FallbackPool(p)) => {
                            busbar_kernel::plane_driver::route_input::OnExhaustedInput::FallbackPool(p.clone())
                        }
                        Some(crate::config::OnExhausted::LeastBad) => {
                            busbar_kernel::plane_driver::route_input::OnExhaustedInput::LeastBad
                        }
                        Some(crate::config::OnExhausted::Queue { max_ms }) => {
                            busbar_kernel::plane_driver::route_input::OnExhaustedInput::Queue { max_ms: *max_ms }
                        }
                        _ => busbar_kernel::plane_driver::route_input::OnExhaustedInput::Status503,
                    },
                    name,
                })
                .collect();
            config_tables =
                std::sync::Arc::new(busbar_kernel::plane_driver::route_tables::ConfigTables::of(
                    &lane_inputs,
                    &pool_inputs,
                    &by_model,
                    self.upstream_credentials,
                ));
        }
        let requested_signals = crate::hooks::requested_signals(&self.hook_registry);
        let any_content_hook = crate::hooks::any_content_hook(&self.hook_registry);
        let plugin_routes = std::sync::Arc::new(if self.no_plugin_routes {
            crate::plugin_routes::PluginRouteTable::empty()
        } else {
            test_plugin_route_table()
        });

        let boot_route_paths = std::sync::Arc::new(plugin_routes.paths());

        let hook_env = self.hook_env.clone().unwrap_or_else(|| {
            crate::hooks::HookEnv::new(
                rows::empty(),
                std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
            )
            .expect("an empty registry's hook axis")
        });

        let plane_gates_map: crate::state::PlaneGateMap = {
            let mut m = std::collections::BTreeMap::new();
            for section in [
                busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2],
                busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[3],
            ] {
                if let Some(decl) =
                    crate::plane_driver::registry::plane_decl_for_config_section(section)
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

            for (&key, (containers, section_hooks)) in &self.container_hooks {
                if m.contains_key(key) {
                    continue;
                }
                let gates = crate::hooks::resolve_container_gates(
                    containers.iter().map(|(n, h)| (n.as_str(), h.as_slice())),
                    section_hooks,
                    &self.hook_registry,
                    &hook_env,
                    0,
                );
                m.insert(key, gates);
            }
            m
        };

        let plane_rewrites_map: crate::state::PlaneRewriteMap = {
            let mut m = std::collections::BTreeMap::new();
            for section in [
                busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[2],
                busbar_kernel::config::plane_sections::NAMED_MAP_SECTIONS[3],
            ] {
                if let Some(decl) =
                    crate::plane_driver::registry::plane_decl_for_config_section(section)
                {
                    let (containers, section_hooks) = self
                        .container_hooks
                        .get(decl.key)
                        .cloned()
                        .unwrap_or_default();
                    let rewrites = crate::hooks::resolve_container_rewrites(
                        containers.iter().map(|(n, h)| (n.as_str(), h.as_slice())),
                        &section_hooks,
                        &self.hook_registry,
                        &hook_env,
                        0,
                    );
                    m.insert(decl.key, rewrites);
                }
            }
            for (&key, (containers, section_hooks)) in &self.container_hooks {
                if m.contains_key(key) {
                    continue;
                }
                let rewrites = crate::hooks::resolve_container_rewrites(
                    containers.iter().map(|(n, h)| (n.as_str(), h.as_slice())),
                    section_hooks,
                    &self.hook_registry,
                    &hook_env,
                    0,
                );
                m.insert(key, rewrites);
            }
            m
        };
        let global_gates = if self.resolve_global_gates {
            crate::hooks::resolve_gate_hooks(&self.hook_registry, &self.global_hooks, &hook_env, 0)
        } else {
            Vec::new()
        };

        let parts = crate::state::AppParts {
            serve_tables,

            oauth_as: self.oauth_as.clone(),

            fallback_runtime_key,

            config_tables,
            root_rules: std::sync::Arc::new(crate::appbuild::AcceptAll),
            config_projection: None,
            store: store.clone(),

            limits: None,
            session_store: std::sync::Arc::new(crate::session::SessionStore::new(1024, None)),
            incremental_scan: false,

            plane_pools: self
                .plane_pools_by_section
                .into_iter()
                .filter_map(|(section, pools)| {
                    crate::plane_driver::registry::plane_decl_for_config_section(section)
                        .map(|decl| (decl.key, pools))
                })
                .collect(),
            auth,
            rewrite_hooks: Vec::new(),
            tap_hooks: Vec::new(),
            tap_hooks_candidate: Vec::new(),
            tap_hooks_routing: Vec::new(),
            tap_hooks_response: Vec::new(),
            global_gates,

            pool_orderings: self.pool_orderings,
            pool_decision_gates: self.pool_decision_gates,
            pool_rewrite_chains: self.pool_rewrite_chains,
            plane_gates: plane_gates_map,
            plane_rewrites: plane_rewrites_map,
            hook_env,
            hook_registry: self.hook_registry,
            requested_signals,
            any_content_hook,
            global_hooks: self.global_hooks,
            groups_registry: self.groups_registry,
            base_group_names: self.base_group_names,
            identity_providers: self.identity_providers.clone(),
            export_defs: self.export_defs,
            admin: std::sync::Arc::new(crate::admin::seam::AdminSlot::default()),
            base_hook_names: self.base_hook_names,
            admin_chain: self
                .admin_chain
                .clone()
                .unwrap_or_else(crate::config::default_admin_auth_names),
            admin_modules: {
                let mut chain = self
                    .admin_modules
                    .unwrap_or_else(crate::auth::AdminAuthChain::empty);

                if let Some(module) = auth_modules::open(auth_modules::TEST_SCOPE_MODULE) {
                    chain
                        .modules
                        .entry(auth_modules::TEST_SCOPE_MODULE.to_string())
                        .or_insert_with(|| crate::test_support::auth_helpers::in_process(module));
                }
                let digest = self.governance.as_ref().and_then(|g| g.admin_token_hash());
                let reg = crate::preflight::linked().expect("the linked registry");
                chain.operator = crate::auth::open_operator(&reg, digest, &self.identity_providers)
                    .expect("the linked operator credential opens");
                std::sync::Arc::new(chain)
            },
            public_url: self.public_url,

            planes: std::sync::Arc::new(plane_dispatch),

            plane_slots,
            plane_sections: self.plane_sections,
            demotion_record: Default::default(),

            amendments: self
                .governance
                .as_ref()
                .map_or_else(Default::default, |g| std::sync::Arc::clone(g.amendments())),
            auth_scope_caps: std::collections::HashMap::new(),
            role_bindings: self.role_bindings.unwrap_or_default(),
            config_path: self.disk_paths.as_ref().map(|(c, _)| c.clone()),
            providers_path: self.disk_paths.as_ref().map(|(_, p)| p.clone()),

            overlay_path: self.overlay_path.or_else(|| {
                if self.explicit_no_overlay {
                    None
                } else {
                    Some(new_test_overlay())
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
            plugin_admission: Some(self.plugin_admission.unwrap_or(&AdmissionStandIn)),
            self_key_ttl_secs: crate::governance::mint_policy::DEFAULT_KEY_TTL_SECS,
            mint_policy: std::sync::Arc::new(self.mint_policy.unwrap_or_default()),
            request_id_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                crate::state::seed_request_id_counter(),
            )),

            plugin_routes,
            boot_route_paths,
            planes_awaiting_restart: Vec::new(),
        };
        let mut app = crate::state::App::from_test_parts(parts);
        let ts_pools: Vec<(&str, Vec<usize>)> = ts_pools_owned
            .iter()
            .map(|(name, lanes)| (name.as_str(), lanes.clone()))
            .collect();
        let ts_by_model: Vec<(&str, usize)> = ts_by_model_owned
            .iter()
            .map(|(name, lane)| (name.as_str(), *lane))
            .collect();
        app.set_test_telemetry(
            &ts_pools,
            &ts_by_model,
            |idx| ts_lane_models.get(idx).map(String::as_str),
            crate::plane_driver::dispatch::fallback_key(),
        );
        for (name, calls, kind, button) in self.login_methods {
            crate::auth::login::install_method(&mut app, &name, calls, kind, button);
        }
        let app = std::sync::Arc::new(app);

        crate::admin::seam::record_boot(&app);

        if let Some(durable) = plane_durable_store {
            let plane_store = crate::store::plane_view::PlaneStoreView::narrow(durable);
            app.demotion_record.set_sink(plane_store);
        }

        audit::ensure_global_audit_stream_registered();
        (app, store)
    }
}

pub fn hook_axis_stand_in(
    registry: &std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
) -> Result<std::sync::Arc<dyn busbar_contract::hook_calls::HookAxis>, String> {
    let _ = registry;
    Ok(std::sync::Arc::new(ranking_double::RankingAxis))
}

pub mod accepted_audit;
pub mod audit;
pub mod auth_helpers;
pub mod governance;
pub mod hooks;
pub mod inbound;
pub mod metrics;
pub mod migration;
pub use governance::GovStateFixtures;

pub mod auth_stand_in;
pub mod hook_double;

pub mod operator_double;

pub mod ranking_double;

pub mod store_double;

pub fn install_linked_auth(
    rows: &'static [busbar_kernel_identity::operator::LinkedAuth],
    words: busbar_kernel_identity::operator::OperatorWords,
) {
    crate::preflight::install_linked_auth(rows, words);
}

/// What a dropped-in hook row's signed manifest DECLARES it needs (`needs.prompt`, `needs.user`), on
/// the `no ⊂ ro ⊂ rw` ladder the operator grant uses: the kernel's own reading of a hook plugin's
/// intent (the grant meet), which [`test_hook_env`] states on each row it registers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HookNeeds {
    /// The declared prompt need.
    pub prompt: busbar_contract::plugin_rows::NeedLevel,
    /// The declared caller-identity need.
    pub user: busbar_contract::plugin_rows::NeedLevel,
}

pub fn test_hook_env(aliases: &[&str], needs: HookNeeds) -> crate::hooks::HookEnv {
    test_hook_env_with_schema(aliases, needs, None)
}

pub fn test_hook_env_with_schema(
    aliases: &[&str],
    needs: HookNeeds,
    settings_schema: Option<&str>,
) -> crate::hooks::HookEnv {
    let registry = aliases
        .iter()
        .enumerate()
        .map(|(i, alias)| {
            let mut row = rows::row(
                &format!("hook-double-{i}"),
                alias,
                busbar_contract::abi::mechanism::kind::HOOK,
            );
            row.needs_prompt = needs.prompt;
            row.needs_user = needs.user;
            row.settings_schema = settings_schema.map(str::to_string);
            row
        })
        .fold(rows::linked_only(), rows::Rows::with_dropped);
    hook_double_env(registry, aliases)
}

pub fn test_hook_env_with_wrong_kind_plugin(
    hook_alias: &str,
    wrong_kind_alias: &str,
) -> crate::hooks::HookEnv {
    let registry = rows::linked_only()
        .with_dropped(rows::row(
            "hook-double-real",
            hook_alias,
            busbar_contract::abi::mechanism::kind::HOOK,
        ))
        .with_dropped(rows::row(
            "hook-double-wrongkind",
            wrong_kind_alias,
            "secret",
        ));
    hook_double_env(registry, &[hook_alias])
}

fn hook_double_env(registry: rows::Rows, doubled: &[&str]) -> crate::hooks::HookEnv {
    crate::hooks::HookEnv::with_axis(
        registry.into_rows(),
        hook_double::HookAxisDouble::new(doubled),
        std::sync::Arc::new(crate::config::secret::SecretResolver::builtins_only()),
    )
}

pub fn metric_sum(name: &str, labels: &[(&str, &str)]) -> f64 {
    crate::test_support::metrics::init();
    let frags: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{v}\"")).collect();
    crate::test_support::export_axis::render()
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

pub fn record_hook_read(
    amendments: &crate::audit::amend::NodeAmendments,
    name: &str,
    principal: Option<&str>,
    op: &str,
    identity: bool,
) {
    crate::audit::amend::record_test_hook_read(amendments, name, principal, op, identity);
}

pub fn scratch_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(name);
    std::fs::create_dir_all(&dir).expect("create the test scratch directory");
    dir
}

pub mod warn_capture;

pub mod tokens;

pub mod auth_modules;

pub mod export_axis;

pub mod outbound_auth;

pub mod rate_holders;

pub mod root;

pub mod issued {

    fn frozen_kind() -> String {
        const FROZEN: &str = include_str!("../../tests/fixtures/frozen_customer_text.yaml");
        FROZEN
            .lines()
            .find_map(|l| l.strip_prefix("signed_credential_kind:"))
            .map(|v| v.trim().to_string())
            .expect("the frozen fixture names the signed credential kind")
    }

    #[must_use]
    pub fn double() -> (String, busbar_contract::auth_calls::IssuedShape) {
        (
            frozen_kind(),
            busbar_contract::auth_calls::IssuedShape {
                id_prefix: "AKIA".to_string(),
                id_len: 20,
                id_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".to_string(),
                secret_len: 40,
                secret_alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    .to_string(),
            },
        )
    }
}

pub mod secrets;
pub use secrets::SecretsStandIn;

pub mod durable_store;

pub mod seam;

pub mod planes;
pub use seam::{
    build_router, engine_host, engine_host_value, BuiltAppSeam, TestAppSeam, TestAppSeamExt,
};

pub mod engine_kit;

pub struct EnvVarGuard {
    key: &'static str,
    prior: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
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

pub fn install_operator_auth_row(door: AuthDoor) {
    let words = OperatorWords {
        provider: crate::config::operator_provider(),
        principal_id: crate::config::operator_principal_id(),
    };
    install_operator_auth_row_as(words, door)
}

pub use busbar_kernel_identity::operator::{
    install_row as install_operator_auth_row_as, AuthDoor, OperatorWords,
};

pub fn install_test_root(rows: crate::preflight::RootInstall) {
    root::install_root(rows);
}

pub fn install_test_auth_axis(open: crate::preflight::AuthAxisOpener) {
    install_root_auth_axis(open);
}

pub fn install_root_hook_names(names: &'static [&'static str]) {
    root::install_hook_names(names);
}

pub fn install_root_auth_axis(open: crate::preflight::AuthAxisOpener) {
    let _ = ROOT_AUTH_AXIS.set(open);
    root::publish();
}

pub(crate) fn root_auth_axis() -> Option<crate::preflight::AuthAxisOpener> {
    ROOT_AUTH_AXIS
        .get()
        .map(|_| root_auth_axis_with_test_modules as crate::preflight::AuthAxisOpener)
}

static ROOT_AUTH_AXIS: std::sync::OnceLock<crate::preflight::AuthAxisOpener> =
    std::sync::OnceLock::new();

fn root_auth_axis_with_test_modules(
    registry: std::sync::Arc<dyn busbar_contract::plugin_rows::PluginRows>,
) -> std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    let open = ROOT_AUTH_AXIS
        .get()
        .expect("installed before the opener is reported");
    auth_modules::around(open(registry))
}

pub fn install_admin_verb_table_double() {
    use busbar_contract::authz::Scope;
    fn rung_of(name: &str) -> Option<Scope> {
        match name {
            "get_keys" => Some(Scope::ReadOnly),
            "post_keys" | "post_config_apply" => Some(Scope::Full),
            _ => None,
        }
    }
    fn verb_at(method: &str, path: &str) -> Option<&'static str> {
        let path = path.split('?').next().unwrap_or(path);
        match (method, path) {
            ("GET", "/api/v1/admin/keys") => Some("get_keys"),
            ("POST", "/api/v1/admin/keys") => Some("post_keys"),
            ("POST", "/api/v1/admin/config/apply") => Some("post_config_apply"),
            _ => None,
        }
    }
    crate::admin::seam::install_admin_verb_table(crate::admin::seam::AdminVerbTable {
        rung_of,
        verb_at,
    });
}

pub fn builtins_only_secret_resolver() -> crate::config::secret::SecretResolver {
    crate::config::secret::SecretResolver::builtins_only()
}

mod fixtures;
pub use fixtures::*;

#[path = "../limits.rs"]
pub(crate) mod fixture_limits;
pub use crate::app::{build_once, build_once_under, from_cfg};

#[cfg(test)]
#[path = "tests/eventstream_frame_tests.rs"]
mod eventstream_frame_tests;

pub fn fetch_stand_in(
    _dir: &std::path::Path,
    targets: &[crate::config::FetchTarget],
    _fatal_on_miss: bool,
    _blocked: &[String],
) -> Result<Vec<crate::preflight::Fetched>, Vec<String>> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    Err(targets
        .iter()
        .map(|t| {
            format!(
                "{}: a test build has no connector to download through",
                t.url
            )
        })
        .collect())
}

pub mod rows;

pub mod protocols;
pub use rows::registry_stand_in;

pub mod store_axis;
pub use store_axis::store_axis_stand_in;

/// THE STAND-IN PLUGIN ADMISSION: `preflight::RootInstall`'s `admission` in a test build, and what
/// a [`TestApp`] judges plugins through unless a test hands it the root's
/// ([`TestApp::plugin_admission`]). A test build has no loader (BUSBAR-1.6.0.md THE DESIGN l.322),
/// so it reads no tarball and judges no signature: it answers the questions the operator surface
/// asks of the posture alone, as the root's admission answers them — what names a tarball, the size
/// ceiling, the lifecycle default, a policy that resolves, an empty inventory — and refuses every
/// question about a tarball's bytes (upload, inspect, rollback). The root's admission, over the
/// loader's one trust builder, is proven by the composition root's tests (`crates/busbar/tests`).
#[derive(Debug, Clone, Copy, Default)]
pub struct AdmissionStandIn;

const NO_ADMISSION: &str =
    "a test build has no plugin admission: the composition root's tests prove it";

impl crate::admission::PluginAdmission for AdmissionStandIn {
    fn is_tarball(&self, file: &str) -> bool {
        file.ends_with(".tar.gz") || file.ends_with(".tgz")
    }

    fn max_tarball_bytes(&self) -> u64 {
        256 * 1024 * 1024 + 1024 * 1024
    }

    fn restart_default(&self, kind: &str) -> bool {
        kind != busbar_contract::abi::mechanism::kind::HOOK
            && kind != busbar_contract::abi::mechanism::kind::AUTH
    }

    fn policy_resolves(&self, _cfg: &crate::config::PluginsCfg) -> Result<(), String> {
        Ok(())
    }

    fn inventory(
        &self,
        _dir: &std::path::Path,
        _cfg: &crate::config::PluginsCfg,
    ) -> Result<Vec<crate::admission::Inventoried>, String> {
        Ok(Vec::new())
    }

    fn admit_upload(
        &self,
        _dir: &std::path::Path,
        _file: &str,
        _tarball: &[u8],
        _cfg: &crate::config::PluginsCfg,
    ) -> Result<crate::admission::Admitted, crate::admission::Refusal> {
        Err(crate::admission::Refusal::Validation(NO_ADMISSION.into()))
    }

    fn inspect(
        &self,
        _tarball: &[u8],
        _cfg: &crate::config::PluginsCfg,
    ) -> Result<(crate::admission::Stated, crate::admission::Judged), crate::admission::Refusal>
    {
        Err(crate::admission::Refusal::Validation(NO_ADMISSION.into()))
    }

    fn rollback_target(
        &self,
        _file: &str,
        _bytes: &[u8],
        _cfg: &crate::config::PluginsCfg,
    ) -> Result<crate::admission::Stated, crate::admission::Refusal> {
        Err(crate::admission::Refusal::Validation(NO_ADMISSION.into()))
    }
}

/// THE STAND-IN DURABLE WRITE: `preflight::RootInstall`'s `durable` in a test build (it has no
/// root). Plain filesystem calls — a write, an unlink, a directory tree — with the file mode a
/// caller asks for: a test's scratch files are not a durable publication, so there is no temp, no
/// rename and no fsync here. The one durable-write primitive (`temp → write → flush → fsync →
/// rename → fsync(parent)`) is the root's, proven by its fault matrix
/// (`crates/plugin-loader/src/tests/durable_tests.rs`). It lives in this file because the
/// `structure-lint` gate's `A-persistence` row ledgers this file for `create_dir_all`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DurableStandIn;

impl crate::durable::DurableFs for DurableStandIn {
    fn write_with(
        &self,
        path: &std::path::Path,
        bytes: &[u8],
        opts: crate::durable::DurableOpts,
    ) -> std::io::Result<()> {
        std::fs::write(path, bytes)?;
        #[cfg(unix)]
        if let Some(mode) = opts.mode {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = opts;
        Ok(())
    }

    fn remove(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::remove_file(path)
    }

    fn create_dir_all(&self, path: &std::path::Path) -> std::io::Result<()> {
        std::fs::create_dir_all(path)
    }
}

#[must_use]
pub fn auth_chain_module_stand_in(door: busbar_contract::abi::mechanism::door::DoorFn) -> bool {
    outbound_auth::declares_chain_module(door)
}
