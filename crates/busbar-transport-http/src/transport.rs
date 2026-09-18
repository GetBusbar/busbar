// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The [`busbar_contract::Transport`] implementation itself.
//!
//! The struct, its egress client and its inherent helpers live in the crate root; this module
//! carries only the trait surface the kernel drives, so a sibling reader finds the same
//! `transport.rs` in every wire.

use super::*;

impl Transport for HttpTransport {
    fn arrival(&self, conn: &Conn) -> ArrivalRecord {
        // The port this connection arrived on, so the `Port` selector form has something to claim
        // by. Zero on a DIALLED connection, which arrived nowhere.
        let port = match self.inner(conn.id()).as_deref() {
            Some(Inner::Ingress { local_port, .. }) => *local_port,
            _ => 0,
        };
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
            let inner = Arc::new(Inner::Ingress {
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

    fn dial<'a>(
        &'a self,
        dest: &'a busbar_contract::VerifiedDestination,
        _keys: &'a TransportKeyHandle,
    ) -> Fut<'a, Conn> {
        Box::pin(async move {
            let host = match dest.facts() {
                busbar_contract::DestinationFacts::Upstream { address, .. } => {
                    address.authority().ok_or(TransportError::AddressRefused)?
                }
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
                pending: AsyncMutex::new(Vec::new()),
                head: Box::new(AsyncMutex::new(EgressHead::default())),
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
        let max_body_bytes = self.max_body_bytes;
        // State: the connection (once — `None` after the HEAD/body pair or the response has been
        // fully drained) and a small queue of already-computed frames not yet handed out. The
        // queue is what lets one read (ingress: HEAD + one body chunk; egress: nothing buffered,
        // the channel already serialises them) become more than one `Stream` item.
        let state = (inner, std::collections::VecDeque::new());
        Box::pin(futures::stream::unfold(
            state,
            move |(inner, mut queue)| async move {
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
                    false => match read_ingress_message(&inner, max_body_bytes).await {
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
            },
        ))
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
                    pending,
                    head,
                    ..
                } => {
                    let queued = bytes.len();
                    let mut buffered = pending.lock().await;
                    let mut cached = head.lock().await;
                    buffered.extend_from_slice(bytes.as_slice());
                    if buffered.len() > self.max_body_bytes {
                        // The operator's cap, applied to the accumulator itself: an unsent message
                        // that outgrows what this gateway accepts is refused here rather than held.
                        buffered.clear();
                        *cached = EgressHead::default();
                        return Err(TransportError::Framing);
                    }
                    let Some(raw) = complete_message(&buffered, &mut cached, self.max_body_bytes)?
                    else {
                        // A prefix of a message. Nothing goes on the wire until the declared length
                        // or the terminal chunk says the message is whole.
                        return Ok(queued);
                    };
                    buffered.clear();
                    drop(cached);
                    drop(buffered);
                    // From here to the send, every await is a point the caller can drop us at.
                    let mut guard = ExchangeGuard {
                        resp_tx,
                        armed: true,
                    };

                    // The dial URI names WHERE this connection goes; the envelope names WHAT is
                    // being asked for there. A per-request path is not a decoration — an upstream
                    // whose whole API surface is its path (`/model/{id}/converse`) answers a
                    // different question, or none, when the path is dropped for the dial URI's.
                    let RawStartLine::Request { method, path } = &raw.start else {
                        // A status line is an ANSWER. There is no request in it to send, and
                        // sending some default in its place would put a request on the wire the
                        // caller never wrote.
                        return Err(TransportError::Framing);
                    };
                    let mut builder = http::Request::builder()
                        .method(method.as_str())
                        .uri(request_target(uri, path)?);
                    for (k, v) in &raw.headers {
                        // `Transfer-Encoding` and `Content-Length` describe a framing this
                        // transport has already undone: the body below is the decoded one, and
                        // the client sets the length it actually sends. Forwarding either would
                        // describe a wire that is not the one going out.
                        if k.eq_ignore_ascii_case("transfer-encoding")
                            || k.eq_ignore_ascii_case("content-length")
                        {
                            continue;
                        }
                        builder = builder.header(k, v);
                    }
                    let req = builder
                        .body(Full::new(Bytes::from(raw.body)))
                        .map_err(|_| TransportError::Framing)?;
                    let resp = client.request(req).await.map_err(|e| map_egress_err(&e))?;
                    let status = resp.status().as_u16();
                    // Read against the instant the answer arrived: an HTTP-date `Retry-After`
                    // means "until then", and only this layer still holds both the header and the
                    // now that makes it a duration.
                    let retry_after = retry_after_secs(resp.headers(), now_unix_secs());
                    // Built as BYTES, not as a string: a header value the wire allows is not
                    // required to be UTF-8, and rendering an un-decodable one as the empty string
                    // hands the layer above a head that says the header was present and empty.
                    // What arrived is what goes up.
                    let mut head = format!(
                        "HTTP/1.1 {} {}\r\n",
                        status,
                        resp.status().canonical_reason().unwrap_or("")
                    )
                    .into_bytes();
                    for (name, value) in resp.headers() {
                        // The same two headers the request side strips, and for the same reason:
                        // hyper de-chunked the body on the way in, and what leaves here leaves as
                        // frames rather than as one length-declared blob. A head carrying either
                        // would describe a framing that is not the one going up.
                        if name.as_str().eq_ignore_ascii_case("transfer-encoding")
                            || name.as_str().eq_ignore_ascii_case("content-length")
                        {
                            continue;
                        }
                        head.extend_from_slice(name.as_str().as_bytes());
                        head.extend_from_slice(b": ");
                        head.extend_from_slice(value.as_bytes());
                        head.extend_from_slice(b"\r\n");
                    }
                    head.extend_from_slice(b"\r\n");
                    let head_bytes = head;
                    let head_len = head_bytes.len() as u64;

                    // The head is in hand, and it is the frame the status leg rides. This take is
                    // the one the guard exists to stand in for, so disarm it first.
                    guard.armed = false;
                    let tx = resp_tx.lock().expect("poisoned").take();
                    // The request is already OUT — the upstream has been asked, and has answered.
                    // With no sender left there is nowhere to put that answer, and `Ok` here would
                    // tell the caller its exchange was carried when the only observable half of it
                    // has been dropped. The connection has no delivery left in it; that is what it
                    // says.
                    let Some(tx) = tx else {
                        return Err(TransportError::Closed);
                    };
                    let head_frame = Frame {
                        direction: Direction::Inbound,
                        stream: StreamId(0),
                        bytes: SlabBytes::new(Arc::from(head_bytes.into_boxed_slice())),
                        meta: FrameMeta {
                            bytes: head_len,
                            transport_units: None,
                            status: Some(status_class(status)),
                            // The exact number and the wait the upstream asked for, read off the
                            // SAME head the class is read off. The class alone cannot tell a
                            // withdrawn credential (401/403, which takes every sibling lane down
                            // with it) from a malformed request (any other 4xx, which is the
                            // caller's own fault), and the wait is the upstream's own floor on
                            // when it is worth asking again.
                            // Named as HTTP's number, because that is the numbering this transport
                            // reads: a reader downstream matches it against HTTP's bands only
                            // because the frame says so, never because it assumed.
                            // The namespace is the one this transport DECLARES, not one
                            // this line spells: a frame cannot report in a numbering the
                            // transport did not say it reports in.
                            status_code: <Self as TransportMeta>::STATUS_NAMESPACE
                                .map(|ns| WireStatus::new(ns, u32::from(status))),
                            retry_after_secs: retry_after,
                        },
                    };
                    if tx.send(Ok((StreamId(0), head_frame))).is_err() {
                        // The receiver has gone: the frame stream this answer belongs to is no
                        // longer being drained. Same reading as above — the exchange happened and
                        // its answer reached nobody, so it is not an `Ok`.
                        return Err(TransportError::Closed);
                    }
                    // The body streams. Collecting it first would mean nothing composes over this
                    // transport: `sse` re-segments the bytes `http` hands it, and a body that only
                    // arrives when the upstream closes is one it can never re-segment in time — an
                    // event stream would deliver zero frames until close, and a stream that never
                    // closes would deliver nothing ever. So the pump runs on its own task and
                    // `write` answers on the head, which is also what makes the caller's write
                    // deadline a deadline on the exchange starting rather than on it finishing.
                    let body = resp.into_body();
                    tokio::spawn(pump_response_body(body, tx, self.max_response_bytes));
                    Ok(queued)
                }
            }
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
        arena: &'a dyn busbar_contract::Arena,
    ) -> Result<ArenaBytes<'a>, busbar_contract_transport::wire::Encode> {
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
            return Err(busbar_contract_transport::wire::Encode::Unrepresentable);
        }
        for (name, value) in fields {
            if !clean(name.as_bytes()) || !clean(value) {
                return Err(busbar_contract_transport::wire::Encode::Unrepresentable);
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
        arena
            .alloc_bytes(&out)
            .map_err(|_| busbar_contract_transport::wire::Encode::ArenaExhausted)
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
    /// layer adopting the stream is the one that speaks the upgrade and answers it. An egress
    /// connection has no socket to give — it dials through a pooled client, and a pooled connection
    /// is not one caller's to take.
    fn detach(&self, conn: &Conn) -> Option<busbar_contract_transport::wire::RawStream> {
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
        let Inner::Ingress { read, write, .. } = inner else {
            return None;
        };
        let stream = read.into_inner().half.reunite(write.into_inner()).ok()?;
        Some(busbar_contract_transport::wire::RawStream::new(
            Self::KEY,
            peer,
            Box::new(TokioAsyncReadCompatExt::compat(stream)),
        ))
    }

    fn composed_over(&self) -> Option<&'static str> {
        // `http` opens its own raw TCP socket at `listen`/`accept`, and its egress dials through a
        // pooled client of its own; which of `tcp`/`tls` a given listener runs over is that
        // listener's own configuration, not a property of this transport object.
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
        bytes: ArenaBytes<'a>,
    ) -> Fut<'a, ()> {
        Box::pin(async move {
            let inner = self.inner(conn.id()).ok_or(TransportError::Closed)?;
            let delivered = if let Inner::Ingress { write, .. } = &*inner {
                let mut w = write.lock().await;
                deliver_refusal(&mut *w, bytes.as_slice()).await
            } else {
                Ok(())
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
