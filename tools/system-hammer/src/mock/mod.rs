// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! In-process mock upstreams: one hyper server (HTTP/1.1 and h2c on the same port) on its own
//! tokio runtime, answering every far end a busbar scenario dials, routed by path:
//!
//! | path | far end |
//! |---|---|
//! | `/v1/chat/completions`, `/v1/responses`, `/v1/messages`, `/v2/chat`, `…:generateContent`, `…:streamGenerateContent`, `/model/…/converse[-stream]` | the six LLM dialects ([`llm`]), whole, streamed, tool call |
//! | `/mcp` | an MCP server (JSON-RPC: `initialize`, `tools/list`, `tools/call`) |
//! | `/.well-known/agent-card.json`, `POST /` | an A2A agent (JWS-signed card, `message/send`) |
//! | `/token`, `/jwks`, `/.well-known/openid-configuration` | an OAuth/OIDC IdP |
//! | `/v1/secret/…` | a Vault KV v2 server |
//! | `/v1/traces`, `/v1/metrics`, `/v1/logs`, `/webhook` | OTLP and webhook sinks |
//! | `/sidecar` | the webrequest hook's sidecar |
//! | `/v1/systemone`, `/api/evaluate` | a decisions provider (jev, nanojev) |
//! | `/v1/realtime/client_secrets` | the streams plane's session mint |
//! | `/__echo` | a trivial echo (the driver's self-test) |
//! | `/__hammer/stats` | per-far-end request counters |
//!
//! There is no artificial delay unless [`MockConfig::delay`] or [`MockConfig::chunk_interval`]
//! says so. Every body is prepared at start.

pub mod llm;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioExecutor, TokioIo};
use llm::{Bodies, Dialect};
use serde_json::{json, Value};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// What the mocks answer with.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MockConfig {
    /// Extra answer-text bytes in every LLM answer.
    pub reply_pad: usize,
    /// Content deltas per streamed LLM answer.
    pub stream_chunks: usize,
    /// Pause before every streamed frame after the first, microseconds.
    pub chunk_interval_us: u64,
    /// Pause before every answer, microseconds.
    pub delay_us: u64,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            reply_pad: 0,
            stream_chunks: 8,
            chunk_interval_us: 0,
            delay_us: 0,
        }
    }
}

/// The far ends the counters distinguish.
#[derive(Debug, Clone, Copy)]
#[repr(usize)]
pub enum Role {
    Llm,
    Mcp,
    A2a,
    Idp,
    Vault,
    Otlp,
    Webhook,
    Sidecar,
    Decisions,
    Streams,
    Echo,
    Other,
}

const ROLES: [&str; 12] = [
    "llm",
    "mcp",
    "a2a",
    "idp",
    "vault",
    "otlp",
    "webhook",
    "sidecar",
    "decisions",
    "streams",
    "echo",
    "other",
];

#[derive(Default)]
pub struct Stats {
    counts: [AtomicU64; 12],
    /// The last request no far end answered (method and path), for diagnosis.
    unknown: std::sync::Mutex<Option<String>>,
}

impl Stats {
    fn hit(&self, r: Role) {
        self.counts[r as usize].fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> Value {
        let mut m = serde_json::Map::new();
        for (i, r) in ROLES.iter().enumerate() {
            m.insert((*r).into(), json!(self.counts[i].load(Ordering::Relaxed)));
        }
        if let Some(u) = self.unknown.lock().unwrap().clone() {
            m.insert("unknown_last".into(), json!(u));
        }
        Value::Object(m)
    }
}

/// The A2A agent's card-signing key: a fixed ed25519 seed (the oracle capture mock's own), so the
/// card is the same bytes on every run.
pub const CARD_ISSUER_SEED: [u8; 32] = [0x42; 32];

/// The card issuer key as busbar's `jws_issuer_key` pin takes it: base64 SubjectPublicKeyInfo DER.
pub fn card_issuer_key() -> String {
    use base64::Engine as _;
    use ring::signature::KeyPair as _;
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&CARD_ISSUER_SEED)
        .expect("a 32-byte seed");
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(kp.public_key().as_ref());
    base64::engine::general_purpose::STANDARD.encode(der)
}

/// RFC 8785 canonical JSON for agent-card values.
fn jcs(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", Value::String((*k).clone()), jcs(&m[*k])))
                .collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::Array(a) => format!("[{}]", a.iter().map(jcs).collect::<Vec<_>>().join(",")),
        other => other.to_string(),
    }
}

fn signed_card(base: &str) -> Bytes {
    use base64::Engine as _;
    let e = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut card = json!({"name": "Hammer Agent", "description": "A load-test A2A agent.",
        "url": format!("{base}/"), "version": "1.0.0",
        "supportedInterfaces": [{"url": format!("{base}/"), "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0"}],
        "capabilities": {"streaming": false, "pushNotifications": false,
            "extendedAgentCard": false},
        "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
        "skills": [{"id": "echo", "name": "Echo", "description": "Returns the text it was given.",
            "tags": ["echo"]}]});
    let protected = e.encode(r#"{"alg":"EdDSA","kid":"hammer"}"#);
    let input = format!("{protected}.{}", e.encode(jcs(&card)));
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&CARD_ISSUER_SEED)
        .expect("a 32-byte seed");
    let sig = e.encode(kp.sign(input.as_bytes()).as_ref());
    card["signatures"] = json!([{"protected": protected, "signature": sig}]);
    Bytes::from(jcs(&card))
}

/// The MCP tool the scenarios pin: its description and schema hash.
pub const MCP_PING_DESCRIPTION: &str = "Returns the label it was given.";
pub const MCP_PING_SCHEMA_HASH: &str =
    "7939d1408e8fc1ac98025ed864c53703091d173e733b1d5c6156f14732da75b0";

struct State {
    cfg: MockConfig,
    bodies: Bodies,
    card: Bytes,
    stats: Arc<Stats>,
    mints: AtomicU64,
}

/// A running mock server.
pub struct Mock {
    pub addr: SocketAddr,
    /// The same far ends over TLS (a fresh self-signed cert for 127.0.0.1 and localhost).
    pub tls_addr: SocketAddr,
    /// `sha256/<base64>` of the TLS certificate's SubjectPublicKeyInfo (a `cert_spki` pin).
    pub spki_pin: String,
    /// The certificate, PEM (a `ca_cert_pem` trust root).
    pub cert_pem: String,
    pub stats: Arc<Stats>,
    _rt: tokio::runtime::Runtime,
}

impl Mock {
    /// Start on 127.0.0.1 (an ephemeral port) with `threads` runtime threads.
    pub fn start(cfg: MockConfig, threads: usize) -> std::io::Result<Mock> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads.max(1))
            .thread_name("hammer-mock")
            .enable_all()
            .build()?;
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let stats = Arc::new(Stats::default());
        let state = Arc::new(State {
            bodies: Bodies::build(cfg.reply_pad, cfg.stream_chunks),
            card: signed_card(&format!("http://{addr}")),
            cfg,
            stats: Arc::clone(&stats),
            mints: AtomicU64::new(0),
        });
        let tls_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        tls_listener.set_nonblocking(true)?;
        let tls_addr = tls_listener.local_addr()?;
        let (acceptor, spki_pin, cert_pem) = tls_acceptor()?;
        let st_tls = Arc::clone(&state);
        rt.spawn(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).expect("listener");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let _ = stream.set_nodelay(true);
                tokio::spawn(serve(Arc::clone(&state), stream));
            }
        });
        rt.spawn(async move {
            let listener = tokio::net::TcpListener::from_std(tls_listener).expect("listener");
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let _ = stream.set_nodelay(true);
                let (acceptor, st) = (acceptor.clone(), Arc::clone(&st_tls));
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        serve(st, tls).await;
                    }
                });
            }
        });
        Ok(Mock {
            addr,
            tls_addr,
            spki_pin,
            cert_pem,
            stats,
            _rt: rt,
        })
    }

    pub fn base(&self) -> String {
        format!("http://{}", self.addr)
    }
}

async fn serve<IO>(st: Arc<State>, io: IO)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let svc = hyper::service::service_fn(move |req| {
        let st = Arc::clone(&st);
        async move { Ok::<_, Infallible>(handle(&st, req).await) }
    });
    let mut b = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    b.http2()
        .initial_stream_window_size(4 << 20)
        .initial_connection_window_size(16 << 20)
        .max_concurrent_streams(4096);
    let _ = b.serve_connection(TokioIo::new(io), svc).await;
}

/// A self-signed LEAF certificate (`basicConstraints` critical `CA:FALSE`) for
/// 127.0.0.1/localhost, its SPKI pin and its PEM. A scenario pins it with `cert_spki` AND names
/// the PEM as the member's own root (`tls.ca_cert_pem`): the pin is checked on top of the chain,
/// never instead of it, and a `CA:TRUE` certificate served as the leaf is refused.
fn tls_acceptor() -> std::io::Result<(tokio_rustls::TlsAcceptor, String, String)> {
    use base64::Engine as _;
    use rcgen::PublicKeyData as _;
    let signing_key = rcgen::KeyPair::generate().map_err(std::io::Error::other)?;
    let mut params =
        rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".into()])
            .map_err(std::io::Error::other)?;
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    let cert = params
        .self_signed(&signing_key)
        .map_err(std::io::Error::other)?;
    let ck = rcgen::CertifiedKey { cert, signing_key };
    let spki = ck.signing_key.subject_public_key_info();
    let digest = ring::digest::digest(&ring::digest::SHA256, &spki);
    let pin = format!(
        "sha256/{}",
        base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
    );
    let pem = ck.cert.pem();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(ck.signing_key.serialize_der().into());
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(std::io::Error::other)?
    .with_no_client_auth()
    .with_single_cert(vec![ck.cert.der().clone()], key)
    .map_err(std::io::Error::other)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok((tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), pin, pem))
}

/// A mock response body: whole, or a sequence of frames with an optional pause between them.
pub enum MockBody {
    Whole(Option<Bytes>),
    Frames {
        frames: Vec<Bytes>,
        next: usize,
        interval: Duration,
        sleep: Option<Pin<Box<tokio::time::Sleep>>>,
    },
}

impl Body for MockBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            MockBody::Whole(b) => Poll::Ready(b.take().map(|b| Ok(Frame::data(b)))),
            MockBody::Frames {
                frames,
                next,
                interval,
                sleep,
            } => {
                if *next >= frames.len() {
                    return Poll::Ready(None);
                }
                if *next > 0 && !interval.is_zero() {
                    let s = sleep.get_or_insert_with(|| Box::pin(tokio::time::sleep(*interval)));
                    if s.as_mut().poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    *sleep = None;
                }
                let f = frames[*next].clone();
                *next += 1;
                Poll::Ready(Some(Ok(Frame::data(f))))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            MockBody::Whole(b) => b.is_none(),
            MockBody::Frames { frames, next, .. } => *next >= frames.len(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            MockBody::Whole(Some(b)) => SizeHint::with_exact(b.len() as u64),
            MockBody::Whole(None) => SizeHint::with_exact(0),
            MockBody::Frames { .. } => SizeHint::default(),
        }
    }
}

use std::future::Future as _;

fn reply(status: u16, ctype: &'static str, body: Bytes) -> Response<MockBody> {
    let mut r = Response::new(MockBody::Whole(Some(body)));
    *r.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    r.headers_mut()
        .insert(http::header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    r
}

fn json_reply(v: &Value) -> Response<MockBody> {
    reply(200, "application/json", Bytes::from(v.to_string()))
}

fn rpc_id(body: &[u8]) -> (String, Value) {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    let m = v
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    (m, v.get("id").cloned().unwrap_or(Value::Null))
}

async fn handle(st: &State, req: Request<Incoming>) -> Response<MockBody> {
    let method = req.method().clone();
    let mut path = req.uri().path().to_string();
    if path.contains('%') {
        // A gemini client may percent-encode the `:` of `:generateContent`.
        path = path.replace("%3A", ":").replace("%3a", ":");
    }
    let query = req.uri().query().unwrap_or("").to_string();
    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => Bytes::new(),
    };
    if st.cfg.delay_us > 0 && !path.starts_with("/__") {
        tokio::time::sleep(Duration::from_micros(st.cfg.delay_us)).await;
    }

    if path == "/__echo" {
        st.stats.hit(Role::Echo);
        return reply(200, "text/plain", Bytes::from_static(b"ok"));
    }
    if path == "/__hammer/stats" {
        return json_reply(&st.stats.snapshot());
    }

    if let Some((d, path_stream)) = Dialect::of_path(&path) {
        st.stats.hit(Role::Llm);
        let b = st.bodies.of(d);
        let stream = path_stream || (query.contains("alt=sse")) || llm::wants_stream(&body);
        if stream {
            let mut r = Response::new(MockBody::Frames {
                frames: b.stream.clone(),
                next: 0,
                interval: Duration::from_micros(st.cfg.chunk_interval_us),
                sleep: None,
            });
            r.headers_mut().insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static(b.stream_ctype),
            );
            r.headers_mut().insert(
                http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-cache"),
            );
            return r;
        }
        let whole = if llm::wants_tools(&body) {
            b.tool.clone()
        } else {
            b.whole.clone()
        };
        return reply(200, "application/json", whole);
    }

    match (method.clone(), path.as_str()) {
        (Method::POST, "/mcp") => {
            st.stats.hit(Role::Mcp);
            let (m, id) = rpc_id(&body);
            let result = match m.as_str() {
                "initialize" => json!({"protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "hammer-mcp", "version": "1.0.0"}}),
                "tools/list" => json!({"tools": [{"name": "ping",
                    "description": MCP_PING_DESCRIPTION,
                    "inputSchema": {"type": "object",
                        "properties": {"label": {"type": "string"}},
                        "additionalProperties": false}}]}),
                "tools/call" => json!({"content": [{"type": "text", "text": "ping: hammer"}],
                    "isError": false}),
                "ping" => json!({}),
                _ if id.is_null() => {
                    return reply(202, "application/json", Bytes::new());
                }
                _ => json!({}),
            };
            json_reply(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
        }
        (Method::GET, "/.well-known/agent-card.json")
        | (Method::GET, "/.well-known/agent.json") => {
            st.stats.hit(Role::A2a);
            reply(200, "application/json", st.card.clone())
        }
        (Method::POST, "/") | (Method::POST, "/a2a") => {
            st.stats.hit(Role::A2a);
            let (_, id) = rpc_id(&body);
            json_reply(&json!({"jsonrpc": "2.0", "id": id, "result": {"task": {
                "id": "task-0001", "contextId": "ctx-0001",
                "status": {"state": "TASK_STATE_COMPLETED", "timestamp": "2026-01-01T00:00:00Z"},
                "artifacts": [{"artifactId": "art-0001", "parts": [{"text": "ping"}]}]}}}))
        }
        (Method::POST, "/token") => {
            st.stats.hit(Role::Idp);
            let n = st.mints.fetch_add(1, Ordering::Relaxed) + 1;
            json_reply(&json!({"access_token": format!("hammer-minted-{n}"),
                "token_type": "Bearer", "expires_in": 3600}))
        }
        (Method::GET, "/jwks") => {
            st.stats.hit(Role::Idp);
            json_reply(&json!({"keys": []}))
        }
        (Method::GET, "/.well-known/openid-configuration") => {
            st.stats.hit(Role::Idp);
            let base = "http://127.0.0.1";
            json_reply(&json!({"issuer": base, "jwks_uri": format!("{base}/jwks"),
                "token_endpoint": format!("{base}/token")}))
        }
        (Method::GET, p) if p.starts_with("/v1/secret/") || p.starts_with("/v1/kv/") => {
            st.stats.hit(Role::Vault);
            json_reply(&json!({"data": {"data": {"api_key": "hammer-vault-key",
                "value": "hammer-vault-key"}, "metadata": {"version": 1}}}))
        }
        (Method::GET, "/v1/sys/health") => {
            st.stats.hit(Role::Vault);
            json_reply(&json!({"initialized": true, "sealed": false, "standby": false}))
        }
        (Method::POST, "/v1/traces")
        | (Method::POST, "/v1/metrics")
        | (Method::POST, "/v1/logs") => {
            st.stats.hit(Role::Otlp);
            reply(200, "application/x-protobuf", Bytes::new())
        }
        (Method::POST, "/webhook") => {
            st.stats.hit(Role::Webhook);
            json_reply(&json!({}))
        }
        (Method::POST, "/sidecar") => {
            st.stats.hit(Role::Sidecar);
            json_reply(&json!({}))
        }
        (Method::POST, "/v1/systemone") => {
            st.stats.hit(Role::Decisions);
            json_reply(
                &json!({"decision": "allow", "model": "mock", "usage": {"units": 1,
                "input_tokens": IN_TOK_DEC, "output_tokens": 1}}),
            )
        }
        (Method::POST, "/api/evaluate") => {
            st.stats.hit(Role::Decisions);
            json_reply(&json!({"result": "allow", "execution": {"states": 1}}))
        }
        (Method::POST, "/v1/realtime/client_secrets") => {
            st.stats.hit(Role::Streams);
            json_reply(&json!({"value": "ek_hammer_0001", "expires_at": 4_102_444_800u64}))
        }
        _ => {
            st.stats.hit(Role::Other);
            *st.stats.unknown.lock().unwrap() = Some(format!("{method} {path}?{query}"));
            reply(
                404,
                "application/json",
                Bytes::from(format!(
                    "{{\"error\":\"hammer mock: no far end at {method} {path}\"}}"
                )),
            )
        }
    }
}

const IN_TOK_DEC: i64 = 4;
