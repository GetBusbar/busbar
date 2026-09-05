// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `http` transport: request in, response frames out.
//!
//! `http` carries no session (`SESSION = false`) and its per-frame `StatusClass` rides the first
//! response frame (`STATUS_CLASS = Some(FirstFrame)`) — the kernel-derived leg of the fee decision
//! the design's settlement table reads. It composes over `tcp`/`tls` for its byte stream.
//!
//! ## What moved here, byte-identical
//!
//! [`HttpTransport::dial`] builds ONE pooled `hyper_util` client per transport instance, with the
//! exact posture 1.5.5's egress client used (`busbar_substrate::egress::engine`, read before this
//! was written): redirects never followed (hyper's client is structurally incapable of following
//! one — no policy to set), `connect_timeout` 10s, TCP keepalive 60s + nodelay, HTTP/2 keep-alive
//! interval 30s / timeout 10s with the adaptive window on, `pool_max_idle_per_host` /
//! `pool_idle_timeout` from [`ClientSettings`], and `upstream_http1_only` /
//! `upstream_h2_prior_knowledge` selecting the connector's ALPN offer exactly as the engine did.
//!
//! ## The seam this delivery leaves named rather than guessed
//!
//! [`Transport::dial`]/`listen`/`accept` return an opaque `Conn`; the actual HTTP exchange happens
//! at `write`/`frames`, because the trait carries no request payload at dial time. This crate's
//! `write` therefore expects ONE call carrying a complete raw HTTP/1.1 message (request line or
//! status line, headers, the blank line, and the body) — exactly the shape
//! `busbar_contract::EgressBody`/`TransportEnvelope` already produce — and reconstructs an
//! `http::Request`/response from it. True multi-call body streaming (bytes arriving across several
//! `write` calls before the message is complete) is not implemented in this delivery; see the
//! crate's delivery notes for why and what a follow-up would need.

#![deny(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::{
    ArenaBytes, ArrivalRecord, CloseReason, Conn, ConnHandle, Direction, Fut, Frame, FrameMeta,
    Kind, Listener, ListenerHandle, Plugin, Refusal, SlabBytes, StatusClass, StreamId, Transport,
    TransportConfigView, TransportError, TransportKeyHandle, TransportMeta,
};
use bytes::Bytes;
use futures::Stream;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::sync::Mutex as AsyncMutex;

mod raw;

pub use raw::{RawMessage, RawStartLine};

/// Bytes read per syscall on the ingress side, and the cap this crate scans a header prefix
/// against — the same "scanned prefix, at most the cursor cap" shape `MAX_CURSOR_BYTES` names.
pub const READ_CHUNK_BYTES: usize = busbar_contract::MAX_CURSOR_BYTES;

/// The client-affecting settings this transport's egress client is built from — the same fields
/// `busbar-core`'s `UpstreamClientSettings` carries, named here so this crate never has to depend
/// on `busbar-core` to read them.
#[derive(Clone, Copy, Debug)]
pub struct ClientSettings {
    /// Per-host idle keep-alive socket budget.
    pub pool_max_idle_per_host: usize,
    /// Idle keep-alive lifetime, in seconds.
    pub pool_idle_timeout_secs: u64,
    /// Pin the egress client to HTTP/1.1.
    pub upstream_http1_only: bool,
    /// Force cleartext HTTP/2 prior-knowledge.
    pub upstream_h2_prior_knowledge: bool,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            pool_max_idle_per_host: 32,
            pool_idle_timeout_secs: 4,
            upstream_http1_only: false,
            upstream_h2_prior_knowledge: false,
        }
    }
}

type EgressClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// One frame, or the transport error that ended the stream in its place.
type FrameResult = Result<(StreamId, Frame), TransportError>;

/// The sending half of the response-frame channel an egress `write` populates.
type RespSender = mpsc::UnboundedSender<FrameResult>;
/// The receiving half `frames` drains.
type RespReceiver = mpsc::UnboundedReceiver<FrameResult>;

enum Inner {
    /// An accepted connection: the raw framing lives here, one request per connection in this
    /// delivery (no HTTP/1.1 keep-alive pipelining — see the crate doc).
    Ingress {
        read: AsyncMutex<OwnedReadHalf>,
        write: AsyncMutex<OwnedWriteHalf>,
        leftover: AsyncMutex<Vec<u8>>,
    },
    /// A dialled destination: the exchange happens inside `write`, which pushes the response's
    /// frames into this channel for `frames` to drain.
    Egress {
        uri: http::Uri,
        client: Arc<EgressClient>,
        resp_tx: Mutex<Option<RespSender>>,
        resp_rx: AsyncMutex<RespReceiver>,
    },
}

struct HttpConnHandle {
    id: u64,
    peer: String,
}
impl ConnHandle for HttpConnHandle {
    fn id(&self) -> u64 {
        self.id
    }
    fn peer(&self) -> String {
        self.peer.clone()
    }
}

struct HttpListenerHandle {
    addr: String,
}
impl ListenerHandle for HttpListenerHandle {
    fn local_addr(&self) -> String {
        self.addr.clone()
    }
}

/// The `http` transport.
pub struct HttpTransport {
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, Arc<Inner>>>,
    listeners: Mutex<HashMap<String, Arc<TcpListener>>>,
    egress_client: Arc<EgressClient>,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport").finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// Build the transport, and with it the ONE pooled egress client this instance dials through
    /// — see the crate doc for the byte-identical posture this reproduces.
    #[must_use]
    pub fn new(settings: ClientSettings) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            conns: Mutex::new(HashMap::new()),
            listeners: Mutex::new(HashMap::new()),
            egress_client: Arc::new(build_egress_client(&settings)),
        }
    }

    fn inner(&self, id: u64) -> Option<Arc<Inner>> {
        self.conns.lock().expect("poisoned").get(&id).cloned()
    }

    fn map_io_err(e: &io::Error) -> TransportError {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => TransportError::Refused,
            io::ErrorKind::TimedOut => TransportError::Timeout,
            io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted => {
                TransportError::Reset
            }
            io::ErrorKind::AddrNotAvailable | io::ErrorKind::InvalidInput => {
                TransportError::AddressRefused
            }
            _ => TransportError::Closed,
        }
    }
}

/// Build the pinned egress client. Free function (not a method) so a battery test can build one
/// without a whole transport, to assert the posture directly.
#[must_use]
pub fn build_egress_client(settings: &ClientSettings) -> EgressClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(Some(Duration::from_secs(10)));
    http.set_keepalive(Some(Duration::from_secs(60)));
    http.set_nodelay(true);

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(webpki_roots_store())
        .with_no_client_auth();
    let builder = hyper_rustls::HttpsConnectorBuilder::new().with_tls_config(tls);
    let https = if settings.upstream_http1_only {
        builder.https_or_http().enable_http1().wrap_connector(http)
    } else {
        builder
            .https_or_http()
            .enable_all_versions()
            .wrap_connector(http)
    };

    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_max_idle_per_host(settings.pool_max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(settings.pool_idle_timeout_secs))
        .http2_keep_alive_interval(Some(Duration::from_secs(30)))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .http2_adaptive_window(true);
    if settings.upstream_h2_prior_knowledge && !settings.upstream_http1_only {
        builder.http2_only(true);
    }
    builder.build(https)
}

fn webpki_roots_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

fn status_class(status: u16) -> StatusClass {
    match status {
        200..=299 => StatusClass::Success,
        400..=499 => StatusClass::ClientError,
        500..=599 => StatusClass::ServerError,
        _ => StatusClass::Other,
    }
}

impl Plugin for HttpTransport {
    fn key(&self) -> &'static str {
        Self::KEY
    }
    fn kind(&self) -> Kind {
        Kind::Transport
    }
    fn abi(&self) -> busbar_contract::AbiVersion {
        busbar_contract::AbiVersion(1)
    }
}

impl TransportMeta for HttpTransport {
    const KEY: &'static str = "http";
    const SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[
        busbar_contract::SelectorForm::ExactPath,
        busbar_contract::SelectorForm::PrefixOneLevel,
        busbar_contract::SelectorForm::PathPattern,
        busbar_contract::SelectorForm::HeaderExact,
        busbar_contract::SelectorForm::HeaderPresent,
        busbar_contract::SelectorForm::HeaderPrefix,
        busbar_contract::SelectorForm::PathSuffix,
        busbar_contract::SelectorForm::PathContains,
    ];
    const EGRESS_SELECTOR_FORMS: &'static [busbar_contract::SelectorForm] = &[];
    const COMPOSES_OVER: &'static [&'static str] = &["tcp", "tls"];
    const HANDOFF: Option<busbar_contract::Handoff> = None;
    const SESSION: bool = false;
    const SESSION_BOUND: bool = false;
    const UNIT0_TRIGGER: Option<busbar_contract::Unit0Trigger> = None;
    const UPGRADES_TO: &'static [&'static str] = &[];
    const HANDSHAKE_TRIGGER: Option<busbar_contract::HandshakeTrigger> = None;
    const TRANSPORT_FACTS: &'static [&'static str] = &[];
    const DECODES_PAYLOAD: bool = false;
    const STATUS_CLASS: Option<busbar_contract::StatusAt> =
        Some(busbar_contract::StatusAt::FirstFrame);
}

impl Transport for HttpTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        ArrivalRecord {
            source: conn.peer(),
            port: 0,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["tcp", "http"],
        }
    }

    fn listen<'a>(
        &'a self,
        cfg: &'a dyn TransportConfigView,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Listener> {
        Box::pin(async move {
            let bind = cfg.bind().unwrap_or("127.0.0.1:0");
            let listener = TcpListener::bind(bind)
                .await
                .map_err(|_| TransportError::AddressRefused)?;
            let addr = listener
                .local_addr()
                .map_err(|_| TransportError::AddressRefused)?
                .to_string();
            self.listeners
                .lock()
                .expect("poisoned")
                .insert(addr.clone(), Arc::new(listener));
            Ok(Listener::new(Arc::new(HttpListenerHandle { addr })))
        })
    }

    fn accept<'a>(&'a self, l: &'a Listener) -> Fut<'a, Conn> {
        Box::pin(async move {
            let addr = l.local_addr();
            let listener = self
                .listeners
                .lock()
                .expect("poisoned")
                .get(&addr)
                .cloned()
                .ok_or(TransportError::Closed)?;
            let (stream, peer) = listener.accept().await.map_err(|_| TransportError::Closed)?;
            stream.set_nodelay(true).ok();
            let (read, write) = stream.into_split();
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let inner = Arc::new(Inner::Ingress {
                read: AsyncMutex::new(read),
                write: AsyncMutex::new(write),
                leftover: AsyncMutex::new(Vec::new()),
            });
            self.conns.lock().expect("poisoned").insert(id, inner);
            Ok(Conn::new(Arc::new(HttpConnHandle {
                id,
                peer: peer.to_string(),
            })))
        })
    }

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let host = match dest.facts() {
                busbar_contract::DestinationFacts::Upstream { host, .. } => host,
                _ => return Err(TransportError::AddressRefused),
            };
            let uri: http::Uri = host.parse().map_err(|_| TransportError::AddressRefused)?;
            let (tx, rx) = mpsc::unbounded_channel();
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let inner = Arc::new(Inner::Egress {
                uri,
                client: self.egress_client.clone(),
                resp_tx: Mutex::new(Some(tx)),
                resp_rx: AsyncMutex::new(rx),
            });
            self.conns.lock().expect("poisoned").insert(id, inner);
            Ok(Conn::new(Arc::new(HttpConnHandle {
                id,
                peer: host.to_string(),
            })))
        })
    }

    fn frames(
        &self,
        conn: Conn,
    ) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>> {
        let inner = self.inner(conn.id());
        // State: the connection (once — `None` after the HEAD/body pair or the response has been
        // fully drained) and a small queue of already-computed frames not yet handed out. The
        // queue is what lets one read (ingress: HEAD + one body chunk; egress: nothing buffered,
        // the channel already serialises them) become more than one `Stream` item.
        let state = (inner, std::collections::VecDeque::new());
        Box::pin(futures::stream::unfold(state, move |(inner, mut queue)| async move {
            if let Some(item) = queue.pop_front() {
                return Some((item, (inner, queue)));
            }
            let inner = inner?;
            let is_egress = matches!(&*inner, Inner::Egress { .. });
            match is_egress {
                true => {
                    let item = {
                        let Inner::Egress { resp_rx, .. } = &*inner else {
                            unreachable!("checked above")
                        };
                        let mut rx = resp_rx.lock().await;
                        rx.recv().await
                    };
                    item.map(|item| (item, (Some(inner), queue)))
                }
                false => match read_ingress_message(&inner).await {
                    Ok(Some(mut frames)) => {
                        if frames.is_empty() {
                            return None;
                        }
                        let first = frames.remove(0);
                        queue.extend(frames.into_iter().map(Ok));
                        // One request per connection in this delivery: the connection is not
                        // reused for a second read.
                        Some((Ok(first), (None, queue)))
                    }
                    Ok(None) => None,
                    Err(e) => Some((Err(e), (None, queue))),
                },
            }
        }))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        _stream: StreamId,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, usize> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            match &*inner {
                Inner::Ingress { write, .. } => {
                    let mut w = write.lock().await;
                    w.write_all(bytes.as_slice())
                        .await
                        .map_err(|e| Self::map_io_err(&e))?;
                    w.flush().await.map_err(|e| Self::map_io_err(&e))?;
                    Ok(bytes.len())
                }
                Inner::Egress {
                    uri,
                    client,
                    resp_tx,
                    ..
                } => {
                    let raw = raw::parse_message(bytes.as_slice())
                        .ok_or(TransportError::Framing)?;
                    let mut builder = http::Request::builder()
                        .method(raw.start.method_or("GET"))
                        .uri(uri.clone());
                    for (k, v) in &raw.headers {
                        builder = builder.header(k, v);
                    }
                    let req = builder
                        .body(Full::new(Bytes::copy_from_slice(&raw.body)))
                        .map_err(|_| TransportError::Framing)?;
                    let resp = client
                        .request(req)
                        .await
                        .map_err(|_| TransportError::Refused)?;
                    let status = resp.status().as_u16();
                    let mut head = format!("HTTP/1.1 {} {}\r\n", status, resp.status().canonical_reason().unwrap_or(""));
                    for (name, value) in resp.headers() {
                        head.push_str(name.as_str());
                        head.push_str(": ");
                        head.push_str(value.to_str().unwrap_or(""));
                        head.push_str("\r\n");
                    }
                    head.push_str("\r\n");
                    let head_bytes = head.into_bytes();
                    let head_len = head_bytes.len() as u64;
                    let body = resp
                        .into_body()
                        .collect()
                        .await
                        .map_err(|_| TransportError::Reset)?
                        .to_bytes();

                    let tx = resp_tx.lock().expect("poisoned").take();
                    if let Some(tx) = tx {
                        let head_frame = Frame {
                            direction: Direction::Inbound,
                            stream: StreamId(0),
                            bytes: SlabBytes::new(Arc::from(head_bytes.into_boxed_slice())),
                            meta: FrameMeta {
                                bytes: head_len,
                                transport_units: None,
                                status: Some(status_class(status)),
                            },
                        };
                        let _ = tx.send(Ok((StreamId(0), head_frame)));
                        if !body.is_empty() {
                            let body_arc: Arc<[u8]> = Arc::from(body.to_vec().into_boxed_slice());
                            let body_frame = Frame {
                                direction: Direction::Inbound,
                                stream: StreamId(0),
                                bytes: SlabBytes::new(body_arc),
                                meta: FrameMeta {
                                    bytes: body.len() as u64,
                                    transport_units: None,
                                    // Only the HEAD frame carries the status leg: it is per-frame
                                    // meta on the FIRST response frame (`StatusAt::FirstFrame`),
                                    // never repeated, so a composed layer (`sse`) can tell a head
                                    // frame from a body frame by this field alone.
                                    status: None,
                                },
                            };
                            let _ = tx.send(Ok((StreamId(0), body_frame)));
                        }
                    }
                    Ok(bytes.len())
                }
            }
        })
    }

    fn upgrade<'a>(
        &'a self,
        conn: Conn,
        _to: &'a str,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        let _ = conn;
        Box::pin(async move { Err(TransportError::Framing) })
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        self.conns.lock().expect("poisoned").remove(&conn.id());
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        _refusal: &'a Refusal,
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            if let Inner::Ingress { write, .. } = &*inner {
                let mut w = write.lock().await;
                w.write_all(bytes.as_slice())
                    .await
                    .map_err(|e| Self::map_io_err(&e))?;
                let _ = w.flush().await;
            }
            self.conns.lock().expect("poisoned").remove(&conn.id());
            Ok(())
        })
    }
}

/// Read one HTTP/1.1 request off an ingress connection: the scanned header prefix (bounded by
/// [`READ_CHUNK_BYTES`], mirroring the design's cursor cap) becomes the HEAD frame, and a declared
/// `Content-Length` body becomes one further body-chunk frame. No chunked-transfer-encoding
/// support in this delivery (see the crate doc's named simplifications).
async fn read_ingress_message(inner: &Inner) -> Result<Option<Vec<(StreamId, Frame)>>, TransportError> {
    let Inner::Ingress { read, leftover, .. } = inner else {
        return Err(TransportError::Framing);
    };
    let mut buf = leftover.lock().await;
    let mut r = read.lock().await;
    let header_end = loop {
        if let Some(pos) = find_header_end(&buf) {
            break pos;
        }
        if buf.len() >= READ_CHUNK_BYTES {
            return Err(TransportError::Framing);
        }
        let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
        let n = r
            .read(&mut chunk)
            .await
            .map_err(|e| HttpTransport::map_io_err(&e))?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_bytes = buf[..header_end].to_vec();
    let content_len = raw::parse_message(&header_bytes)
        .and_then(|m| m.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse::<usize>().ok()))
        .unwrap_or(0);

    let mut body = buf[header_end..].to_vec();
    buf.clear();
    while body.len() < content_len {
        let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
        let n = r
            .read(&mut chunk)
            .await
            .map_err(|e| HttpTransport::map_io_err(&e))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);

    let head_arc: Arc<[u8]> = Arc::from(header_bytes.into_boxed_slice());
    let head_len = head_arc.len() as u64;
    let mut frames = vec![(
        StreamId(0),
        Frame {
            direction: Direction::Inbound,
            stream: StreamId(0),
            bytes: SlabBytes::new(head_arc),
            meta: FrameMeta {
                bytes: head_len,
                transport_units: None,
                status: None,
            },
        },
    )];
    if !body.is_empty() {
        let body_arc: Arc<[u8]> = Arc::from(body.clone().into_boxed_slice());
        frames.push((
            StreamId(0),
            Frame {
                direction: Direction::Inbound,
                stream: StreamId(0),
                bytes: SlabBytes::new(body_arc),
                meta: FrameMeta {
                    bytes: body.len() as u64,
                    transport_units: None,
                    status: None,
                },
            },
        ));
    }
    Ok(Some(frames))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

#[cfg(test)]
mod tests;
