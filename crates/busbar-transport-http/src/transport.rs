// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_contract::transport::wire::ArrivalRecord;
use busbar_contract::transport::wire::CloseReason;
use busbar_contract::transport::wire::Conn;
use busbar_contract::transport::wire::Listener;
use busbar_contract::transport::wire::TransportError;
use busbar_contract::{
    Frame, Fut, Refusal, ScratchBytes, StreamId, Transport, TransportConfigView,
    TransportKeyHandle, TransportMeta,
};
use futures::Stream;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    deliver_refusal, finalise, read_ingress_message, HttpConnHandle, HttpListenerHandle,
    HttpTransport, Inner, ReadSide, READ_CHUNK_BYTES,
};

impl Transport for HttpTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        // The port this connection arrived on, so the `Port` selector form has something to claim
        // by. Zero for a connection this transport does not hold.
        let port = self.inner(conn.id()).map_or(0, |inner| inner.local_port);
        ArrivalRecord {
            source: conn.peer(),
            port,
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
            let (stream, peer) = listener
                .accept()
                .await
                .map_err(|_| TransportError::Closed)?;
            stream.set_nodelay(true).ok();
            // Before the split, which is the last moment the socket itself can be asked.
            let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
            let (read, write) = stream.into_split();
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            let inner = Arc::new(Inner {
                read: AsyncMutex::new(ReadSide {
                    half: read,
                    scratch: vec![0_u8; READ_CHUNK_BYTES],
                }),
                write: AsyncMutex::new(write),
                leftover: AsyncMutex::new(Vec::new()),
                closed: AtomicBool::new(false),
                closing: tokio::sync::Notify::new(),
                local_port,
            });
            self.conns.lock().expect("poisoned").insert(id, inner);
            Ok(Conn::new(Arc::new(HttpConnHandle {
                id,
                peer: peer.to_string(),
            })))
        })
    }

    /// Refused, for every destination: this transport never dials (TODO #145).
    ///
    /// A client of its own here resolved the destination's name itself, out of sight of the
    /// kernel's one destination judge, and resolved it again on every pooled reconnect: a name
    /// that answered a public address at the check could answer a metadata or internal one at the
    /// dial. An upstream request leaves through the connector, which dials only an IP literal the
    /// judge passed, with this crate's door framing it (`BUSBAR-1.6.0.md`, "Dialing only what the
    /// kernel judged"). So nothing is resolved and no socket is opened here, whatever the
    /// destination names.
    fn dial<'a>(
        &'a self,
        _dest: &'a busbar_contract::VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move { Err(TransportError::AddressRefused) })
    }

    fn frames(
        &self,
        conn: Conn,
    ) -> Pin<Box<dyn Stream<Item = Result<(StreamId, Frame), TransportError>> + Send>> {
        let inner = self.inner(conn.id());
        let max_body_bytes = self.max_body_bytes;
        // State: the connection (once — `None` after the HEAD/body pair) and a small queue of
        // already-computed frames not yet handed out. The queue is what lets one read (HEAD + one
        // body chunk) become more than one `Stream` item.
        let state = (inner, std::collections::VecDeque::new());
        Box::pin(futures::stream::unfold(
            state,
            move |(inner, mut queue)| async move {
                if let Some(item) = queue.pop_front() {
                    return Some((item, (inner, queue)));
                }
                let inner = inner?;
                match read_ingress_message(&inner, max_body_bytes).await {
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
                }
            },
        ))
    }

    fn write<'a>(
        &'a self,
        conn: &'a Conn,
        _stream: StreamId,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, usize> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            let mut w = inner.write.lock().await;
            w.write_all(bytes.as_slice())
                .await
                .map_err(|e| Self::map_io_err(&e))?;
            w.flush().await.map_err(|e| Self::map_io_err(&e))?;
            Ok(bytes.len())
        })
    }

    /// An HTTP/1.1 message: the start line the envelope names, its headers, the blank line, and
    /// the body. The `method` and `path` fields are the request line rather than headers, because
    /// on this wire that is what they are — an envelope that wrote them as `method: POST` would
    /// describe a request no server has ever answered.
    fn encode_envelope<'a>(
        &self,
        fields: &[(&str, &[u8])],
        body: &[u8],
        arena: &'a dyn busbar_contract::PlaneAlloc,
    ) -> Result<ScratchBytes<'a>, busbar_contract::transport::wire::Encode> {
        let out = render_envelope(fields, body)?;
        arena
            .alloc_bytes(&out)
            .map_err(|_| busbar_contract::transport::wire::Encode::ScratchExhausted)
    }

    fn adopt<'a>(
        &'a self,
        _from: &'a dyn Transport,
        conn: Conn,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        // `http` is adopted BY `ws`, never onto: it takes no lower layer's stream, it hands its own
        // up. The transports it composes over give it a socket at `listen`/`dial`, not a handoff.
        let _ = conn;
        Box::pin(async move { Err(TransportError::HandoffMismatch) })
    }

    /// Give up the accepted socket under a connection, for the layer upgrading over it.
    ///
    /// This is the `http` → `ws` seam: the upgrade REQUEST has not been read here, because the
    /// layer adopting the stream is the one that speaks the upgrade and answers it.
    fn detach(&self, conn: &Conn) -> Option<busbar_contract::transport::wire::RawStream> {
        // Checked BEFORE the removal, under the same lock: see the sibling `tcp` note. Removing
        // first and then failing to unwrap loses the connection — no stream up, no entry left.
        let mut registry = self.conns.lock().expect("poisoned");
        if Arc::strong_count(registry.get(&conn.id())?) != 1 {
            return None;
        }
        let inner = registry.remove(&conn.id())?;
        drop(registry);
        let peer = conn.peer();
        let inner = Arc::try_unwrap(inner).ok()?;
        let Inner { read, write, .. } = inner;
        let stream = read.into_inner().half.reunite(write.into_inner()).ok()?;
        Some(busbar_contract::transport::wire::RawStream::new(
            Self::KEY,
            peer,
            Box::new(TokioAsyncReadCompatExt::compat(stream)),
        ))
    }

    fn composed_over(&self) -> Option<&'static str> {
        // `http` opens its own raw TCP socket at `listen`/`accept`, and dials nothing; whether core
        // secures a given listener's stream is that listener's own configuration, not a property
        // of this transport object.
        None
    }

    fn close(&self, conn: Conn, _reason: CloseReason) {
        // A frame stream holds its own clone of the state, so removing the registry entry is not
        // enough to drop the socket halves: the flag is what ends that stream at its next read,
        // after which the last clone goes and the socket really does close.
        finalise(&self.conns, conn.id());
    }

    fn unit0_refusal<'a>(
        &'a self,
        conn: Conn,
        // One request per connection here, so a refusal is always the whole of it.
        _stream: Option<StreamId>,
        _refusal: &'a Refusal,
        bytes: ScratchBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            let delivered = {
                let mut w = inner.write.lock().await;
                deliver_refusal(&mut *w, bytes.as_slice()).await
            };
            // The entry goes on EVERY path, including the one where the refusal never left. A
            // refusal finalises the connection whether or not the peer was still there to read it,
            // and a registry entry left behind on the failure path is a connection nothing will
            // ever close.
            finalise(&self.conns, conn.id());
            delivered
        })
    }
}

/// Render an outbound envelope (`fields`, post-decoration) and `body` as one HTTP/1.1 request
/// message: the bytes the egress cross-check reads, whichever door rendered them.
///
/// # Errors
///
/// A CR, LF or NUL in the method, the path, a field name or a value: `Encode::Unrepresentable`.
pub(crate) fn render_envelope(
    fields: &[(&str, &[u8])],
    body: &[u8],
) -> Result<Vec<u8>, busbar_contract::transport::wire::Encode> {
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };
    let method = field("method").unwrap_or(b"POST");
    let path = field("path").unwrap_or(b"/");

    // A CR, an LF or a NUL anywhere in a name, a value, the method or the path is a byte that
    // ENDS a line on this wire. Writing one through means the caller chooses where this
    // transport's header block ends and what comes after it: a value of
    // `x\r\nauthorization: bearer ...` is not a header value, it is a second header, injected.
    // The check is before the first byte is written, so nothing half-built ever reaches the
    // arena.
    let clean = |v: &[u8]| !v.iter().any(|b| matches!(b, b'\r' | b'\n' | 0));
    if !clean(method) || !clean(path) {
        return Err(busbar_contract::transport::wire::Encode::Unrepresentable);
    }
    for (name, value) in fields {
        if !clean(name.as_bytes()) || !clean(value) {
            return Err(busbar_contract::transport::wire::Encode::Unrepresentable);
        }
    }

    let mut out = Vec::with_capacity(body.len() + 128);
    out.extend_from_slice(method);
    out.push(b' ');
    out.extend_from_slice(path);
    out.extend_from_slice(b" HTTP/1.1\r\n");
    for (name, value) in fields {
        if name.eq_ignore_ascii_case("method") || name.eq_ignore_ascii_case("path") {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    // The length is this transport's to state: it is a fact about the bytes below, not
    // something an envelope gets to disagree with.
    out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(out)
}
