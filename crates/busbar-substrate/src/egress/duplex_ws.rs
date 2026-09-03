// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL FULL-DUPLEX WEBSOCKET EGRESS DIALER — the outbound half of the WS transport, the
//! neutral home for any plane's outbound duplex socket.
//!
//! A plane that selects [`crate::transport::Transport::WebSocket`] resolves the axis to
//! [`crate::transport::UpstreamWireKind::Duplex`] and dials the upstream here. The dialer hands back a
//! message [`Stream`]`<Item = Vec<u8>>` + [`Sink`]`<Vec<u8>>` pair — EXACTLY the shape
//! [`crate::ingress::byte_duplex::serve_messages`] consumes — so the plane composes session/media
//! logic on top and never holds a socket, a resolver, or the WS framing.
//!
//! ## THE GUARD IS NOT OPTIONAL (the egress-audit finding this closes)
//!
//! A `wss://` upstream is an operator/runtime target, so it is resolved-then-pinned-then-guarded on
//! EXACTLY the discipline the HTTP egress seam applies — never a raw `connect_async` that resolves DNS
//! itself. The order is [`crate::net_guard::resolve_and_pin_async`] FIRST (structural refusals, one
//! resolution, every answered address judged, the survivor pinned), then a TCP connect to THAT pinned
//! address, then a TLS handshake presenting the URL host for SNI / certificate validation, then the
//! client WS handshake OVER that already-guarded stream. The socket is never opened to anything the
//! guard did not judge: the `tokio-tungstenite` `connect` feature (which would resolve the name a
//! second time) is deliberately left off, and this is the only door.

use std::sync::Arc;

use futures::{Sink, SinkExt, Stream, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

use crate::net_guard::{self, GuardPolicy, GuardRefusal};

/// Why an outbound duplex dial failed — the FACT, kept separate so a caller renders its own sentence
/// (mirroring how [`GuardRefusal`] callers convert into their own vocabulary).
#[derive(Debug)]
pub enum DialError {
    /// The URL was not a `ws(s)://` URL, or had no usable host/port.
    Url(String),
    /// The net-guard refused the target (SSRF, plaintext, unresolvable, internal, metadata, …). The
    /// dial NEVER opens a socket past this — the guard is the reason a socket exists at all.
    Guard(GuardRefusal),
    /// The TCP connect to the pinned address failed.
    Connect(String),
    /// The TLS handshake to the pinned address (SNI = the URL host) failed.
    Tls(String),
    /// The WebSocket upgrade handshake over the established stream failed.
    Handshake(String),
}

impl std::fmt::Display for DialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialError::Url(u) => write!(f, "`{u}` is not a usable ws(s):// URL"),
            DialError::Guard(r) => write!(f, "{r}"),
            DialError::Connect(e) => write!(f, "connecting to the pinned address failed: {e}"),
            DialError::Tls(e) => write!(f, "the TLS handshake failed: {e}"),
            DialError::Handshake(e) => write!(f, "the WebSocket handshake failed: {e}"),
        }
    }
}

impl std::error::Error for DialError {}

impl From<GuardRefusal> for DialError {
    fn from(r: GuardRefusal) -> Self {
        DialError::Guard(r)
    }
}

/// `wss://host[:port]/path` (or `ws://…`) split into `(secure, host, port, request-url)`. Hand-written
/// because what is wanted is a STRICT recogniser over an operator-supplied string, not a permissive
/// parser; the request-url handed to the handshake keeps the original `ws(s)` scheme so the `Host` /
/// `Sec-WebSocket-*` headers are exactly what the upstream expects.
fn split_ws_url(url: &str) -> Result<(bool, String, u16, String), DialError> {
    let (secure, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (false, r)
    } else {
        return Err(DialError::Url(url.to_string()));
    };
    let (authority, _path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // No userinfo in an egress target: an `@` is an unusable authority, exactly as the HTTP guard
    // treats it.
    if authority.is_empty() || authority.contains('@') {
        return Err(DialError::Url(url.to_string()));
    }
    let (host, port) = match authority.rsplit_once(':') {
        // An IPv6 literal carries colons; only a trailing `:port` after a `]` (or on a bare host) is a
        // port. A colon inside `[...]` is part of the address.
        Some((h, p)) if !h.ends_with(']') && !p.contains(']') => {
            let port: u16 = p.parse().map_err(|_| DialError::Url(url.to_string()))?;
            (h.to_string(), port)
        }
        _ => (authority.to_string(), if secure { 443 } else { 80 }),
    };
    // Unbracket an IPv6 literal so the host reads the same to the guard and to rustls' SNI.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .map(str::to_string)
        .unwrap_or(host);
    if host.is_empty() {
        return Err(DialError::Url(url.to_string()));
    }
    Ok((secure, host, port, url.to_string()))
}

/// The rustls client config for the dial: webpki roots + the explicitly-named `ring` provider, the
/// SAME posture the egress engine builds its HTTP clients with (an ambient `builder()` panics at first
/// use when the composed binary carries more than one provider — explicit therefore, never ambient).
/// Shared by refcount across every dial via a `OnceLock`.
fn tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

/// DIAL an upstream `wss://` (or `ws://`) THROUGH the net-guard and hand back the message duplex.
///
/// The returned pair is what [`crate::ingress::byte_duplex::serve_messages`] consumes: the [`Stream`]
/// yields one inbound WS data payload (text/binary) per item as `Vec<u8>`; a frame `send` onto the
/// [`Sink`] is written as ONE binary WS message. Control frames (ping/pong/close) are handled by the
/// WS layer and never surface as frames — the neutral pump names no protocol and sees only data
/// payloads.
///
/// The guard runs FIRST and the socket is connected to the PINNED address; a `ws://` (plaintext)
/// target is admitted only when `policy` opts into it, exactly as the HTTP guard admits plaintext.
pub async fn dial(
    url: &str,
    policy: GuardPolicy,
) -> Result<
    (
        impl Stream<Item = Vec<u8>> + Unpin,
        impl Sink<Vec<u8>> + Unpin + Send + 'static,
    ),
    DialError,
> {
    let (secure, host, port, request_url) = split_ws_url(url)?;

    // THE GUARD, FIRST — resolve then pin then judge. `https = secure`: a `ws://` target is judged as
    // plaintext (admitted only under the policy's plaintext stance), a `wss://` as TLS. No socket is
    // opened to anything this did not pin.
    let pinned = net_guard::resolve_and_pin_async(&host, port, secure, policy).await?;

    // TCP to the PINNED address — never re-resolving the name (the TOCTOU the pin closes).
    let tcp = TcpStream::connect(pinned.socket_addr())
        .await
        .map_err(|e| DialError::Connect(e.to_string()))?;

    // The client WS handshake over the guarded stream. `wss` wraps the TCP in rustls (SNI = the URL
    // host, so the certificate is validated against the operator-registered name while the connection
    // rides the pinned address); `ws` runs the handshake over bare TCP.
    if secure {
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| DialError::Tls(e.to_string()))?;
        let tls = tokio_rustls::TlsConnector::from(tls_config())
            .connect(server_name, tcp)
            .await
            .map_err(|e| DialError::Tls(e.to_string()))?;
        let (ws, _resp) = tokio_tungstenite::client_async(&request_url, tls)
            .await
            .map_err(|e| DialError::Handshake(e.to_string()))?;
        let (tx, rx) = split_messages(ws);
        Ok((BoxedStream(rx), BoxedSink(tx)))
    } else {
        let (ws, _resp) = tokio_tungstenite::client_async(&request_url, tcp)
            .await
            .map_err(|e| DialError::Handshake(e.to_string()))?;
        let (tx, rx) = split_messages(ws);
        Ok((BoxedStream(rx), BoxedSink(tx)))
    }
}

/// Map a `WebSocketStream<S>` into the neutral `(frame-sink, frame-stream)` the pump speaks: outbound
/// `Vec<u8>` → one binary WS message; inbound text/binary → one `Vec<u8>` frame; control frames
/// (ping/pong/close) and errors are dropped so only data payloads reach the pump. Boxed so the two
/// scheme arms return one concrete type.
fn split_messages<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
) -> (
    futures::channel::mpsc::UnboundedSender<Vec<u8>>,
    futures::channel::mpsc::UnboundedReceiver<Vec<u8>>,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (in_tx, in_rx) = futures::channel::mpsc::unbounded::<Vec<u8>>();
    let (out_tx, mut out_rx) = futures::channel::mpsc::unbounded::<Vec<u8>>();

    // Reader task: inbound WS messages → `Vec<u8>` frames onto `in_tx`. Ends on close/error; dropping
    // `in_tx` ends the pump's inbound stream (the message-duplex analogue of EOF).
    tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            match msg {
                Ok(Message::Binary(b)) => {
                    if in_tx.unbounded_send(b.to_vec()).is_err() {
                        break;
                    }
                }
                Ok(Message::Text(t)) => {
                    if in_tx.unbounded_send(t.as_bytes().to_vec()).is_err() {
                        break;
                    }
                }
                // Control frames carry no plane data; the WS layer answers pings itself.
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });

    // Writer task: `Vec<u8>` frames from the pump → one binary WS message each. Ends when the pump
    // drops the sink (session over); a close is sent best-effort so the peer sees a clean shutdown.
    tokio::spawn(async move {
        while let Some(frame) = out_rx.next().await {
            if ws_tx.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
        let _ = ws_tx.close().await;
    });

    (out_tx, in_rx)
}

/// The concrete frame-stream the dial returns — an mpsc receiver of inbound `Vec<u8>` frames.
struct BoxedStream(futures::channel::mpsc::UnboundedReceiver<Vec<u8>>);

impl Stream for BoxedStream {
    type Item = Vec<u8>;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Vec<u8>>> {
        std::pin::Pin::new(&mut self.0).poll_next(cx)
    }
}

/// The concrete frame-sink the dial returns — an mpsc sender of outbound `Vec<u8>` frames, whose
/// `Error` is [`std::convert::Infallible`]-free `SendError` (a closed channel means the session ended).
struct BoxedSink(futures::channel::mpsc::UnboundedSender<Vec<u8>>);

impl Sink<Vec<u8>> for BoxedSink {
    type Error = futures::channel::mpsc::SendError;
    fn poll_ready(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.0).poll_ready(cx)
    }
    fn start_send(mut self: std::pin::Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        std::pin::Pin::new(&mut self.0).start_send(item)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::pin::Pin::new(&mut self.0).poll_close(cx)
    }
}

#[cfg(all(test, feature = "runtime"))]
#[path = "tests/duplex_ws_tests.rs"]
mod tests;
