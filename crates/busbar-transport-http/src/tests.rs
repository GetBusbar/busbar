//! The transport battery, for `http`: request in as a HEAD-plus-body frame pair, a real egress
//! round trip through the pinned client, per-frame `StatusClass` at the first response frame, and
//! the frame-meta honesty check.

use super::*;
use busbar_contract::{ConfigView, KernelSeal};
use futures::StreamExt;
use std::sync::Arc as StdArc;

struct FixtureSeal;
impl KernelSeal for FixtureSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-transport-http test fixture"
    }
}
fn fixture_key() -> TransportKeyHandle {
    TransportKeyHandle::issue(&FixtureSeal, 0, "test")
}

struct TestCfg {
    bind: String,
}
impl ConfigView for TestCfg {
    fn get_str(&self, _k: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _k: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _k: &str) -> Option<bool> {
        None
    }
}
impl TransportConfigView for TestCfg {
    fn bind(&self) -> Option<&str> {
        Some(&self.bind)
    }
}

fn upstream_dest(uri: &str) -> busbar_contract::VerifiedDestination {
    let host: &'static str = Box::leak(uri.to_string().into_boxed_str());
    busbar_contract::VerifiedDestination::seal(
        &FixtureSeal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract_transport::dest::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test"),
        },
        "http",
        None,
    )
}

/// A minimal fixed-response TCP server, standing in for an upstream, for the egress-side tests.
async fn fixed_response_server(response: &'static [u8]) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 4096];
        // Drain the request (don't care about its shape for this fixture).
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        tokio::io::AsyncWriteExt::write_all(&mut stream, response)
            .await
            .unwrap();
    });
    format!("http://{addr}/")
}

#[tokio::test]
async fn egress_round_trip_reports_status_class_on_the_first_frame() {
    let uri = fixed_response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await;
    let transport = HttpTransport::new(ClientSettings::default());
    let conn = transport
        .dial(&upstream_dest(&uri), &fixture_key())
        .await
        .unwrap();
    let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    transport
        .write(&conn, StreamId(0), ArenaBytes::new(req))
        .await
        .unwrap();

    let mut frames = transport.frames(conn);
    let (_s, head) = frames.next().await.unwrap().unwrap();
    assert_eq!(head.meta.status, Some(StatusClass::Success));
    assert!(std::str::from_utf8(head.bytes.as_slice())
        .unwrap()
        .starts_with("HTTP/1.1 200"));

    let (_s, body) = frames.next().await.unwrap().unwrap();
    assert_eq!(body.bytes.as_slice(), b"hello");
    assert!(frames.next().await.is_none());
}

#[tokio::test]
async fn egress_maps_4xx_and_5xx_status_classes() {
    for (status, class) in [
        (404_u16, StatusClass::ClientError),
        (500, StatusClass::ServerError),
    ] {
        let resp: &'static [u8] = Box::leak(
            format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n")
                .into_bytes()
                .into_boxed_slice(),
        );
        let uri = fixed_response_server(resp).await;
        let transport = HttpTransport::new(ClientSettings::default());
        let conn = transport
            .dial(&upstream_dest(&uri), &fixture_key())
            .await
            .unwrap();
        transport
            .write(
                &conn,
                StreamId(0),
                ArenaBytes::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            )
            .await
            .unwrap();
        let mut frames = transport.frames(conn);
        let (_s, head) = frames.next().await.unwrap().unwrap();
        assert_eq!(head.meta.status, Some(class));
    }
}

#[tokio::test]
async fn ingress_reads_a_head_and_body_frame_from_a_real_client() {
    let transport = StdArc::new(HttpTransport::new(ClientSettings::default()));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = transport.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let transport = transport.clone();
        async move { transport.accept(&listener).await.unwrap() }
    });

    let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(
        &mut client,
        b"POST /units HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd",
    )
    .await
    .unwrap();

    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let (_s, head) = frames.next().await.unwrap().unwrap();
    let head_text = String::from_utf8(head.bytes.as_slice().to_vec()).unwrap();
    assert!(head_text.starts_with("POST /units HTTP/1.1"));
    assert_eq!(head.meta.bytes, head.bytes.len() as u64);

    let (_s, body) = frames.next().await.unwrap().unwrap();
    assert_eq!(body.bytes.as_slice(), b"abcd");
}

/// A declared-length body that stops short at EOF is a framing error, not a short request.
///
/// The chunked branch already answers this way — a peer that stops before the terminal chunk gets
/// `Framing`, because guessing where the body ended is the one thing a transport must not do. The
/// declared-length branch is the same question and must give the same answer: a `Content-Length`
/// that the bytes do not honour is a message that never arrived, not a smaller one that did.
#[tokio::test]
async fn a_declared_length_body_cut_short_at_eof_is_a_framing_error() {
    let transport = StdArc::new(HttpTransport::new(ClientSettings::default()));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = transport.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let transport = transport.clone();
        async move { transport.accept(&listener).await.unwrap() }
    });

    let writer = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let mut wire = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n".to_vec();
        wire.extend_from_slice(&[b'a'; 200]);
        tokio::io::AsyncWriteExt::write_all(&mut client, &wire)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::shutdown(&mut client)
            .await
            .unwrap();
        // Hold the read half so the connection is half-closed, not reset.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });

    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the reader answers rather than hanging")
        .expect("the stream yields the framing error, not end-of-stream");
    assert_eq!(
        first.unwrap_err(),
        TransportError::Framing,
        "a body 800 bytes short of its declared length is not a complete request"
    );
    writer.abort();
}

/// The body cap the crate doc names is real, on both sides, and it is the operator's own
/// `limits.request_body_max_bytes` rather than a constant invented here.
///
/// Ingress refuses a declared length past the cap without reading the body behind it; egress
/// refuses to keep accumulating a message past it. One knob, two accumulators, so the cap this
/// transport applies can never disagree with the one the served door applies.
#[tokio::test]
async fn a_body_past_the_configured_maximum_is_refused_on_both_sides() {
    let settings = ClientSettings {
        request_body_max_bytes: 64,
        ..ClientSettings::default()
    };

    // Ingress: a declared length past the cap, plus a trickle of the body behind it.
    let transport = StdArc::new(HttpTransport::new(settings));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = transport.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let transport = transport.clone();
        async move { transport.accept(&listener).await.unwrap() }
    });
    let writer = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\n\r\nabcd",
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });
    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the reader refuses rather than buffering a megabyte")
        .expect("the stream yields the framing error");
    assert_eq!(
        first.unwrap_err(),
        TransportError::Framing,
        "a declared length past the configured maximum is refused, not accumulated"
    );
    writer.abort();

    // Egress: the pending accumulator refuses to grow past the same cap.
    let transport = HttpTransport::new(settings);
    let conn = transport
        .dial(&upstream_dest("http://127.0.0.1:1/"), &fixture_key())
        .await
        .unwrap();
    // Chunked, so no declared total: only the accumulator itself can refuse this.
    let head = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
    transport
        .write(&conn, StreamId(0), ArenaBytes::new(head))
        .await
        .unwrap();
    let mut err = None;
    for _ in 0..64 {
        if let Err(e) = transport
            .write(
                &conn,
                StreamId(0),
                ArenaBytes::new(b"10\r\naaaaaaaaaaaaaaaa\r\n"),
            )
            .await
        {
            err = Some(e);
            break;
        }
    }
    assert_eq!(
        err,
        Some(TransportError::Framing),
        "the egress accumulator refuses past the configured maximum instead of growing unbounded"
    );
}

/// A header block this transport cannot parse fails closed, rather than decoding as no headers.
///
/// The old reading took an unparsable block to mean an empty header list — declared length zero,
/// no body read — while the raw bytes still went up as the HEAD frame. That is a framing divergence
/// invented out of a parse failure: the reader must say it could not read the message.
#[tokio::test]
async fn an_unparsable_header_block_is_a_framing_error_not_a_headerless_request() {
    let transport = StdArc::new(HttpTransport::new(ClientSettings::default()));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = transport.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let transport = transport.clone();
        async move { transport.accept(&listener).await.unwrap() }
    });
    let writer = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length : 5\r\n\r\nhello",
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });

    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the reader answers rather than hanging")
        .expect("the stream yields the framing error");
    assert_eq!(
        first.unwrap_err(),
        TransportError::Framing,
        "a header block that does not parse is refused, not read as a request with no headers"
    );
    writer.abort();
}

/// A `Transfer-Encoding` whose final coding is not `chunked` is refused, not read as chunked and
/// not quietly fallen back to `Content-Length`. Both halves of the ambiguity, closed.
#[tokio::test]
async fn a_transfer_encoding_that_is_not_chunked_last_is_refused() {
    let transport = StdArc::new(HttpTransport::new(ClientSettings::default()));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = transport.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let transport = transport.clone();
        async move { transport.accept(&listener).await.unwrap() }
    });
    let writer = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });

    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the reader answers rather than hanging")
        .expect("the stream yields the framing error");
    assert_eq!(
        first.unwrap_err(),
        TransportError::Framing,
        "a coding list whose last entry is not chunked leaves the body length undeterminable"
    );
    writer.abort();
}

/// A message carrying BOTH a `Transfer-Encoding` and a `Content-Length` is refused on ingress.
///
/// The two headers describe two different framings of the same bytes, which is the classic
/// request-smuggling shape: whoever forwards it hands the next hop a length the bytes do not have.
/// An intermediary that chooses to forward must strip the `Content-Length` first; this one chooses
/// the other arm and refuses, because the HEAD frame it would otherwise hand up is the verbatim
/// header prefix and any reader re-parsing it would see the length that was never true.
///
/// The egress direction already gets this right by stripping both headers when it rebuilds the
/// request, and the round-trip cell above pins that. The two directions now agree.
#[tokio::test]
async fn a_message_with_both_a_transfer_encoding_and_a_content_length_is_refused() {
    let transport = StdArc::new(HttpTransport::new(ClientSettings::default()));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = transport.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let transport = transport.clone();
        async move { transport.accept(&listener).await.unwrap() }
    });
    let writer = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(
            &mut client,
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });

    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the reader answers rather than hanging")
        .expect("the stream yields the framing error");
    assert_eq!(
        first.unwrap_err(),
        TransportError::Framing,
        "two disagreeing framings of one body is a message to refuse, not one to forward"
    );
    writer.abort();
}

/// A `write` dropped mid-exchange ends the connection observably instead of hanging `frames`.
///
/// The battery's cancel-mid-frame cell, on the egress side. The exchange runs inside `write`, and a
/// caller is free to drop that future — a timeout, a select, a cancelled task. When it does, the
/// response sender is still sitting in the connection's slot, so nothing ever closes the channel
/// and `frames` waits on a receive that can never complete. A half-sent exchange is not resumable
/// and this does not pretend otherwise; what it guarantees is that the stream ENDS.
#[tokio::test]
async fn a_cancelled_egress_write_ends_the_frame_stream_rather_than_hanging_it() {
    // An upstream that accepts the connection and then never answers.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });

    let transport = HttpTransport::new(ClientSettings::default());
    let uri: &'static str = Box::leak(format!("http://{addr}/").into_boxed_str());
    let conn = transport
        .dial(&upstream_dest(uri), &fixture_key())
        .await
        .unwrap();

    // A complete message, so the exchange starts — and then the write future is dropped in it.
    let write_fut = transport.write(
        &conn,
        StreamId(0),
        ArenaBytes::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    );
    let cancelled = tokio::time::timeout(std::time::Duration::from_millis(50), write_fut).await;
    assert!(
        cancelled.is_err(),
        "the write really was dropped mid-flight"
    );

    let mut frames = transport.frames(conn);
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next()).await;
    assert!(
        matches!(ended, Ok(None) | Ok(Some(Err(_)))),
        "a cancelled exchange ends the stream; it must not leave frames() waiting forever"
    );
    server.abort();
}

/// A chunked body of at least a mebibyte, written in chunks that straddle the read budget, arrives
/// byte-exact — and the trailers that follow it arrive as their own frame rather than as body.
///
/// The budget boundary is the point of the cell. The reader takes at most [`READ_CHUNK_BYTES`] per
/// syscall, so a body this size is read many times over, and every chunk boundary, size line and
/// CRLF is free to fall in the middle of one of those reads. A reader that only handled a declared
/// `Content-Length` saw no body here at all.
#[tokio::test]
async fn a_chunked_body_of_at_least_a_mebibyte_at_a_budget_boundary() {
    let transport = StdArc::new(HttpTransport::new(ClientSettings::default()));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = transport.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let transport = transport.clone();
        async move { transport.accept(&listener).await.unwrap() }
    });

    // Chunks deliberately not a divisor of the read budget, so boundaries land inside reads.
    const CHUNK: usize = READ_CHUNK_BYTES / 3 + 7;
    const TOTAL: usize = 1024 * 1024 + 12_345;
    let payload: Vec<u8> = (0..TOTAL).map(|i| (i % 251) as u8).collect();

    let mut wire = b"POST /units HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTrailer: X-Checksum\r\n\r\n".to_vec();
    let mut chunk_count = 0_usize;
    for piece in payload.chunks(CHUNK) {
        wire.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
        wire.extend_from_slice(piece);
        wire.extend_from_slice(b"\r\n");
        chunk_count += 1;
    }
    wire.extend_from_slice(b"0\r\nX-Checksum: 42\r\n\r\n");
    assert!(chunk_count > 1, "the body spans more than one chunk");

    let writer = tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut client, &wire)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::flush(&mut client).await.unwrap();
        // Hold the socket open: closing it here would race the reader.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });

    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let (_s, head) = frames.next().await.unwrap().unwrap();
    assert!(String::from_utf8_lossy(head.bytes.as_slice()).starts_with("POST /units HTTP/1.1"));

    // One frame per chunk the sender wrote — the sender's own framing, not the reads' framing.
    let mut body = Vec::new();
    for _ in 0..chunk_count {
        let (_s, frame) = frames.next().await.unwrap().unwrap();
        assert_eq!(
            frame.meta.bytes,
            frame.bytes.len() as u64,
            "honest frame meta on every body chunk"
        );
        body.extend_from_slice(frame.bytes.as_slice());
    }
    assert_eq!(body.len(), TOTAL);
    assert_eq!(body, payload, "byte-exact across the budget boundary");

    let (_s, trailers) = frames.next().await.unwrap().unwrap();
    assert_eq!(trailers.bytes.as_slice(), b"X-Checksum: 42\r\n");
    writer.abort();
}

/// A body written across several calls goes on the wire once, when the message is whole.
///
/// The design's large-body shape is a HEAD frame followed by body-chunk frames, so `write` is
/// handed a message in pieces. Before this accumulated, the first piece was parsed as a complete
/// message and sent on its own, and every piece after it was sent as another request.
#[tokio::test]
async fn an_egress_body_accumulates_across_calls_until_the_declared_length() {
    // A server that records how many requests arrived and what the last body was.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = StdArc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let server = tokio::spawn({
        let seen = seen.clone();
        async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = Vec::new();
                loop {
                    let mut chunk = vec![0_u8; 8192];
                    let n = tokio::io::AsyncReadExt::read(&mut sock, &mut chunk)
                        .await
                        .unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                        let declared: usize = head
                            .lines()
                            .find_map(|l| {
                                l.strip_prefix("content-length: ")
                                    .or_else(|| l.strip_prefix("Content-Length: "))
                            })
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        if buf.len() >= pos + 4 + declared {
                            seen.lock().unwrap().push(buf[pos + 4..].to_vec());
                            let _ = tokio::io::AsyncWriteExt::write_all(
                                &mut sock,
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                            )
                            .await;
                            break;
                        }
                    }
                }
            }
        }
    });

    let transport = HttpTransport::new(ClientSettings::default());
    let uri: &'static str = Box::leak(format!("http://{addr}/units").into_boxed_str());
    let conn = transport
        .dial(&upstream_dest(uri), &fixture_key())
        .await
        .unwrap();

    // The message, split the way a plane writing a large body would split it.
    let head = b"POST /units HTTP/1.1\r\nHost: x\r\nContent-Length: 11\r\n\r\n";
    let pieces: [&[u8]; 3] = [head, b"hello ", b"world"];
    for piece in pieces {
        transport
            .write(&conn, StreamId(0), ArenaBytes::new(piece))
            .await
            .unwrap();
    }

    let mut frames = transport.frames(conn);
    let (_s, response_head) =
        tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
            .await
            .expect("the exchange ran once the message was whole")
            .unwrap()
            .unwrap();
    assert_eq!(response_head.meta.status, Some(StatusClass::Success));

    let bodies = seen.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1, "one request, not one per write call");
    assert_eq!(bodies[0], b"hello world", "reassembled byte-exact");
    server.abort();
}

/// The envelope's bytes are an HTTP message, because that is what this wire is.
///
/// The egress unit used to write a neutral layout — every field as `name: value`, a blank line, the
/// body — and hand it to `write` as if it were a request. It ran the lane cross-check over the same
/// buffer, so the check was honest about there being ONE buffer and wrong about what was in it. The
/// layout is the transport's, and this is the transport.
#[test]
fn the_envelope_encodes_as_an_http_message() {
    let transport = HttpTransport::new(ClientSettings::default());
    let arena = TestArena;
    let bytes = transport
        .encode_envelope(
            &[
                ("method", b"POST".as_slice()),
                ("path", b"/v1/messages".as_slice()),
                ("authorization", b"Bearer substituted".as_slice()),
            ],
            b"{\"model\":\"m\"}",
            &arena,
        )
        .unwrap();
    let text = String::from_utf8(bytes.as_slice().to_vec()).unwrap();

    assert!(
        text.starts_with("POST /v1/messages HTTP/1.1\r\n"),
        "the method and the path are the request line, not headers: {text:?}"
    );
    assert!(text.contains("authorization: Bearer substituted\r\n"));
    assert!(
        text.contains("content-length: 13\r\n"),
        "the length is a fact about the bytes below, stated by the transport"
    );
    assert!(text.ends_with("\r\n\r\n{\"model\":\"m\"}"));

    // And the message this transport wrote is one this transport can read back.
    let parsed = raw::parse_message(bytes.as_slice()).expect("a message it can read");
    assert_eq!(
        parsed.start,
        raw::RawStartLine::Request {
            method: "POST".to_string(),
            path: "/v1/messages".to_string()
        }
    );
    assert_eq!(parsed.body, b"{\"model\":\"m\"}");
}

/// A test arena that hands back what it was given. The real one is the kernel's per-unit one;
/// what this stands in for is only "the bytes come back with the arena's lifetime".
struct TestArena;

impl busbar_contract::Arena for TestArena {
    fn alloc_bytes<'a>(
        &'a self,
        src: &[u8],
    ) -> Result<busbar_contract::ArenaBytes<'a>, busbar_contract::ArenaBudget> {
        Ok(busbar_contract::ArenaBytes::new(Box::leak(
            src.to_vec().into_boxed_slice(),
        )))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, busbar_contract::ArenaBudget> {
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, busbar_contract::Span)],
    ) -> Result<&'a [(&'a str, busbar_contract::Span)], busbar_contract::ArenaBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

#[tokio::test]
async fn every_transport_error_is_mapped_on_dial() {
    let transport = HttpTransport::new(ClientSettings::default());

    // The dial's own refusals: an address that is not one, and a destination that is not upstream.
    let bad = upstream_dest("not a uri at all");
    let err = transport.dial(&bad, &fixture_key()).await.unwrap_err();
    assert_eq!(err, TransportError::AddressRefused);

    // EVERY arm of the mapper this crate shares with its whole ingress and egress path, one
    // io::Error per arm. The name of this cell claims exhaustiveness; before this, swapping two
    // arms of map_io_err left it green, which is the definition of an unpinned mapping. `http`
    // dials through a pooled client rather than a socket of its own, so the connect-time kinds
    // cannot be provoked through `dial` the way `tcp`'s sibling cell provokes them — the mapper is
    // driven directly instead, which is the same claim with nothing left implicit.
    for (kind, expected) in [
        (io::ErrorKind::ConnectionRefused, TransportError::Refused),
        (io::ErrorKind::TimedOut, TransportError::Timeout),
        (io::ErrorKind::ConnectionReset, TransportError::Reset),
        (io::ErrorKind::ConnectionAborted, TransportError::Reset),
        (
            io::ErrorKind::AddrNotAvailable,
            TransportError::AddressRefused,
        ),
        (io::ErrorKind::InvalidInput, TransportError::AddressRefused),
        (io::ErrorKind::BrokenPipe, TransportError::Closed),
        (io::ErrorKind::NotFound, TransportError::Closed),
    ] {
        let mapped = HttpTransport::map_io_err(&io::Error::new(kind, "fixture"));
        assert_eq!(
            mapped, expected,
            "io::ErrorKind::{kind:?} maps to {expected:?}"
        );
    }

    // And a real refusal off a real closed port, so the mapper's Refused arm is not only pinned
    // against a fabricated error: the exchange runs inside `write`, so that is where it surfaces.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    let uri: &'static str = Box::leak(format!("http://{addr}/").into_boxed_str());
    let conn = transport
        .dial(&upstream_dest(uri), &fixture_key())
        .await
        .expect("dialling is address parsing here; the socket comes later");
    let err = transport
        .write(
            &conn,
            StreamId(0),
            ArenaBytes::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        )
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::Refused);
}

#[test]
fn frame_meta_honesty_catches_inflating_and_deflating_fixtures() {
    fn honest(frame: &Frame) -> bool {
        frame.meta.bytes == frame.bytes.len() as u64
    }
    let base = Frame {
        direction: Direction::Inbound,
        stream: StreamId(0),
        bytes: SlabBytes::new(StdArc::from(&b"abcd"[..])),
        meta: FrameMeta {
            bytes: 4,
            transport_units: None,
            status: None,
        },
    };
    assert!(honest(&base));
    let inflated = Frame {
        meta: FrameMeta {
            bytes: 40,
            ..base.meta
        },
        ..base.clone()
    };
    assert!(!honest(&inflated));
    let deflated = Frame {
        meta: FrameMeta {
            bytes: 1,
            ..base.meta
        },
        ..base
    };
    assert!(!honest(&deflated));
}
