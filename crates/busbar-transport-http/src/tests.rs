//! The transport battery, for `http`: request in as a HEAD-plus-body frame pair, a real egress
//! round trip through the pinned client, per-frame `StatusClass` at the first response frame, and
//! the frame-meta honesty check.

use super::*;
use busbar_contract::plugin::KernelSeal;
use busbar_contract::ConfigView;
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

/// An upstream that answers with the request line it actually received, so a test can assert what
/// went out on the wire rather than what the caller meant to put there.
async fn request_line_echo_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 4096];
                let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
                    .await
                    .unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                let line = text.lines().next().unwrap_or("").trim_end().to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                    line.len(),
                    line
                );
                let _ = tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes()).await;
            });
        }
    });
    format!("http://{addr}/")
}

#[tokio::test]
async fn the_envelopes_own_method_and_path_are_what_reach_the_upstream() {
    let uri = request_line_echo_server().await;
    let transport = HttpTransport::new(ClientSettings::default());
    let conn = transport
        .dial(&upstream_dest(&uri), &fixture_key())
        .await
        .unwrap();
    let req = b"POST /v1/messages HTTP/1.1\r\nHost: x\r\ncontent-length: 0\r\n\r\n";
    transport
        .write(&conn, StreamId(0), ArenaBytes::new(req))
        .await
        .unwrap();

    let mut frames = transport.frames(conn);
    let (_s, _head) = frames.next().await.unwrap().unwrap();
    let (_s, body) = frames.next().await.unwrap().unwrap();
    let echoed = String::from_utf8(body.bytes.as_slice().to_vec()).unwrap();
    assert!(
        echoed.starts_with("POST /v1/messages "),
        "the upstream saw {echoed:?}, not the request the envelope named"
    );
}

#[tokio::test]
async fn a_status_line_is_not_a_request_this_transport_can_send() {
    let uri = fixed_response_server(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    let transport = HttpTransport::new(ClientSettings::default());
    let conn = transport
        .dial(&upstream_dest(&uri), &fixture_key())
        .await
        .unwrap();
    let msg = b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";
    let err = transport
        .write(&conn, StreamId(0), ArenaBytes::new(msg))
        .await
        .unwrap_err();
    assert_eq!(err, TransportError::Framing);
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

/// Drive one raw request through a real ingress connection and hand back the first frame result.
/// The header questions this exercises are asked of a live socket, not of a header vector built by
/// hand, so a reading that only holds in a unit test cannot pass here.
async fn ingress_first(request: &'static [u8]) -> Result<(StreamId, Frame), TransportError> {
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
        tokio::io::AsyncWriteExt::write_all(&mut client, request)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });
    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the reader answers rather than hanging")
        .expect("the stream yields something");
    writer.abort();
    first
}

/// RFC 9110 5.3: a field sent on more than one line means the same thing as the one line those
/// values would have made, joined by commas. So `Transfer-Encoding: chunked` followed by
/// `Transfer-Encoding: gzip` is the coding list `chunked, gzip` — one whose final coding is not
/// `chunked`, which RFC 9112 6.1 requires, and whose body length is therefore undeterminable.
/// Reading only the first line answers `chunked` and frames a body the sender never described:
/// the smuggling shape, spelled across two lines instead of one.
#[tokio::test]
async fn a_transfer_encoding_split_across_lines_is_read_as_the_one_list_it_is() {
    let err = ingress_first(
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    )
    .await
    .unwrap_err();
    assert_eq!(
        err,
        TransportError::Framing,
        "the combined list ends in gzip, so the body length is undeterminable"
    );
}

/// `chunked` applied twice is `chunked, chunked`: the final coding is chunked, but the first one is
/// a coding this transport cannot undo underneath it, and RFC 9112 6.1 forbids applying chunked
/// more than once. Refused rather than decoded one layer deep and handed up as whole.
#[tokio::test]
async fn chunked_declared_twice_is_refused() {
    let err = ingress_first(
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
    )
    .await
    .unwrap_err();
    assert_eq!(err, TransportError::Framing);
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

/// RFC 9112 6.3: an unparsable `Content-Length` with no `Transfer-Encoding` is unrecoverable
/// framing, not a body-less message. A value that overflows `usize` must refuse, not silently
/// serve the request as empty.
#[tokio::test]
async fn an_overflowing_content_length_is_a_framing_error() {
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
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999\r\n\r\n",
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
        .expect("the stream yields the framing error, not a body-less message");
    assert_eq!(
        first.unwrap_err(),
        TransportError::Framing,
        "a Content-Length that cannot fit a usize is unrecoverable framing, not zero"
    );
    writer.abort();
}

/// A leading sign on `Content-Length` is not `1*DIGIT`: RFC 9112 6.3 says the field carries a
/// non-negative integer with no sign, so `+5` must refuse rather than be parsed as five.
#[tokio::test]
async fn a_content_length_with_a_leading_sign_is_a_framing_error() {
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
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello",
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
        .expect("the stream yields the framing error, not a 5-byte body");
    assert_eq!(
        first.unwrap_err(),
        TransportError::Framing,
        "a signed Content-Length is not 1*DIGIT and must not be parsed as five"
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

/// A CR or an LF in a field is not data on this wire: it ENDS the line. A caller that can put one
/// in a value chooses where this transport's header block ends and what stands after it — a second
/// header, a body boundary, a whole second request. NUL is refused with them: nothing on this wire
/// carries one, and a reader that stops at it reads a different message than the one written.
#[test]
fn a_field_cannot_smuggle_a_line_ending_into_the_header_block() {
    let transport = HttpTransport::new(ClientSettings::default());
    let arena = TestArena;
    let poisoned: &[(&str, &[u8])] = &[
        ("x-note", b"ok\r\nauthorization: bearer stolen".as_slice()),
        ("x-note", b"ok\nauthorization: bearer stolen".as_slice()),
        ("x-note", b"ok\rmore".as_slice()),
        ("x-note", b"ok\0more".as_slice()),
        ("bad\r\nname", b"ok".as_slice()),
        ("method", b"GET / HTTP/1.1\r\nHost: elsewhere".as_slice()),
        ("path", b"/a\r\nHost: elsewhere".as_slice()),
    ];
    for field in poisoned {
        let err = transport
            .encode_envelope(std::slice::from_ref(field), b"body", &arena)
            .expect_err("a field carrying a line ending is not encodable");
        assert_eq!(
            err,
            busbar_contract_transport::wire::Encode::Unrepresentable,
            "field {:?} was written through",
            field.0
        );
    }
    // And an ordinary envelope beside them still encodes, so the check refuses injection rather
    // than refusing headers.
    transport
        .encode_envelope(&[("x-note", b"ok".as_slice())], b"body", &arena)
        .expect("a clean field still encodes");
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

/// The header-end scan costs a pass over the header, not a pass per read.
///
/// The reader takes as many reads as the network chooses, and a header dribbled a byte at a time
/// is the shape that separates a linear scan from a quadratic one: rescanning the whole buffer on
/// every read means the prefix already proven terminator-free is proven again, once per byte. The
/// budget bounds the damage at 64 KiB but does not change its class, and a bounded quadratic is
/// still CPU an attacker gets to spend for free.
///
/// This drives the SAME [`HeaderScan`] the ingress reader runs on, so what it counts is production
/// work rather than a model of it.
#[test]
fn the_header_scan_costs_one_pass_over_the_header_not_one_per_read() {
    let mut header = b"POST / HTTP/1.1\r\nX-Filler: ".to_vec();
    header.extend_from_slice(&[b'a'; 8192]);
    header.extend_from_slice(b"\r\n\r\n");

    let mut buf = Vec::with_capacity(header.len());
    let mut scan = HeaderScan::default();
    let mut found = None;
    for byte in &header {
        buf.push(*byte);
        if let Some(pos) = scan.find(&buf) {
            found = Some(pos);
            break;
        }
    }
    assert_eq!(
        found,
        Some(header.len()),
        "the boundary is still found at exactly the same offset"
    );

    let scanned = scan.scanned;
    let n = header.len();
    assert!(
        scanned < 4 * n,
        "a {n}-byte header dribbled a byte at a time cost {scanned} bytes of scanning; \
         a cursor makes that O(n), restarting at zero makes it O(n^2)"
    );
}

/// The egress header block is parsed once per message, not once per `write` call.
///
/// `write` accumulates, and it asks "is this message whole yet?" on every chunk. Answering that
/// used to re-run the whole header parse over the same unchanged prefix each time — a fresh Vec and
/// two Strings per header, allocated and dropped, for every chunk of the body. Same standard the
/// crate holds its chunked decoding to, now applied here.
#[test]
fn the_egress_header_block_is_parsed_once_across_many_write_calls() {
    let mut buffered = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n".to_vec();
    let mut cache = EgressHead::default();

    for i in 0..100 {
        buffered.push(b'a');
        let done = complete_message(&buffered, &mut cache, usize::MAX).unwrap();
        assert_eq!(
            done.is_some(),
            i == 99,
            "the exchange runs at the declared length and not one call before it"
        );
    }
    assert_eq!(
        cache.parses, 1,
        "one header block, one parse, however many calls the body arrived in"
    );

    // And the cache is spent with the message: the next one parses its own headers.
    assert!(
        cache.head.is_none(),
        "a completed message leaves no stale head"
    );
}

/// An upstream that streams and never closes delivers frames while it is still open.
///
/// This is the whole of what "composes over" means for a streamed body: `sse` re-segments the bytes
/// `http` hands it, so a body that only arrives when the upstream closes is a body `sse` can never
/// re-segment in time. Collecting the response before emitting anything turned every event stream
/// into a zero-frame stream until close, and a stream that never closes into nothing at all. The
/// response HEAD leaves as soon as the head arrives, and each body chunk as hyper yields it.
#[tokio::test]
async fn a_streamed_upstream_yields_frames_before_it_closes() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
        tokio::io::AsyncWriteExt::write_all(
            &mut sock,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await
        .unwrap();
        // One event every 100ms, and no terminal chunk ever: the stream does not end.
        loop {
            let event = b"data: tick\n\n";
            let mut piece = format!("{:x}\r\n", event.len()).into_bytes();
            piece.extend_from_slice(event);
            piece.extend_from_slice(b"\r\n");
            if tokio::io::AsyncWriteExt::write_all(&mut sock, &piece)
                .await
                .is_err()
            {
                return;
            }
            let _ = tokio::io::AsyncWriteExt::flush(&mut sock).await;
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });

    let transport = HttpTransport::new(ClientSettings::default());
    let uri: &'static str = Box::leak(format!("http://{addr}/").into_boxed_str());
    let conn = transport
        .dial(&upstream_dest(uri), &fixture_key())
        .await
        .unwrap();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        transport.write(
            &conn,
            StreamId(0),
            ArenaBytes::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        ),
    )
    .await
    .expect("write answers on the response head, not on the upstream's close")
    .unwrap();

    let mut frames = transport.frames(conn);
    let (_s, head) = tokio::time::timeout(std::time::Duration::from_secs(2), frames.next())
        .await
        .expect("the HEAD frame is emitted as soon as the head arrives")
        .unwrap()
        .unwrap();
    assert_eq!(head.meta.status, Some(StatusClass::Success));

    for _ in 0..2 {
        let (_s, body) = tokio::time::timeout(std::time::Duration::from_secs(2), frames.next())
            .await
            .expect("a body frame arrives while the upstream is still streaming")
            .unwrap()
            .unwrap();
        assert_eq!(body.bytes.as_slice(), b"data: tick\n\n");
        assert_eq!(body.meta.status, None, "the status leg rides the HEAD only");
        assert_eq!(body.meta.bytes, body.bytes.len() as u64);
    }
    server.abort();
}

/// A response body past the configured maximum ends the stream instead of growing the node's heap.
///
/// The request cap has always been real on both accumulators. The RESPONSE had none: an upstream —
/// or anything wearing one's address — could answer with as many bytes as it liked and this node
/// would hold every one of them. The cap is held against the bytes that actually arrive, since a
/// streamed body declares no total, and nothing past it is emitted.
#[tokio::test]
async fn a_response_body_past_the_cap_ends_the_stream_rather_than_accumulating() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
        tokio::io::AsyncWriteExt::write_all(
            &mut sock,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .await
        .unwrap();
        for _ in 0..64 {
            let payload = [b'a'; 1024];
            let mut piece = format!("{:x}\r\n", payload.len()).into_bytes();
            piece.extend_from_slice(&payload);
            piece.extend_from_slice(b"\r\n");
            if tokio::io::AsyncWriteExt::write_all(&mut sock, &piece)
                .await
                .is_err()
            {
                return;
            }
            let _ = tokio::io::AsyncWriteExt::flush(&mut sock).await;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });

    const CAP: usize = 4096;
    let transport = HttpTransport::new(ClientSettings {
        response_body_max_bytes: CAP,
        ..ClientSettings::default()
    });
    let uri: &'static str = Box::leak(format!("http://{addr}/").into_boxed_str());
    let conn = transport
        .dial(&upstream_dest(uri), &fixture_key())
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
    let (_s, head) = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the head arrives")
        .unwrap()
        .unwrap();
    assert_eq!(head.meta.status, Some(StatusClass::Success));

    let mut body_bytes = 0_usize;
    let ended = loop {
        let item = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
            .await
            .expect("the stream ends rather than accumulating an unbounded body");
        match item {
            Some(Ok((_s, frame))) => body_bytes += frame.bytes.len(),
            Some(Err(e)) => break Some(e),
            None => break None,
        }
    };
    assert_eq!(
        ended,
        Some(TransportError::Framing),
        "a response past the cap ends the stream with an error, not with a clean close"
    );
    assert!(
        body_bytes <= CAP,
        "{body_bytes} bytes were emitted for a {CAP}-byte cap"
    );
    server.abort();
}

/// The synthesised response head describes the bytes that follow it, not the ones on the wire.
///
/// hyper de-chunks the body before this transport ever sees it, so a `Transfer-Encoding: chunked`
/// copied out of the upstream's head describes a framing that is no longer there — and a
/// `Content-Length` copied beside it describes a body this transport now hands over in pieces. The
/// request side already strips both for exactly this reason; the response side says the same.
#[tokio::test]
async fn a_chunked_upstream_response_head_carries_no_framing_headers() {
    let uri = fixed_response_server(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
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
    let head_text = String::from_utf8(head.bytes.as_slice().to_vec())
        .unwrap()
        .to_ascii_lowercase();
    assert!(head_text.starts_with("http/1.1 200"));
    assert!(
        head_text.contains("content-type: text/plain"),
        "the headers that describe the payload are still carried: {head_text:?}"
    );
    assert!(
        !head_text.contains("transfer-encoding"),
        "a de-chunked body must not be described as chunked: {head_text:?}"
    );
    assert!(
        !head_text.contains("content-length"),
        "the length of a body handed over in frames is not the head's to state: {head_text:?}"
    );
    assert_eq!(head.meta.bytes, head.bytes.len() as u64);

    let (_s, body) = frames.next().await.unwrap().unwrap();
    assert_eq!(body.bytes.as_slice(), b"hello");
}

/// The egress chunked body is decoded once, not once per `write` call.
///
/// The sibling of the header-parse cell above, and the same standard: `write` accumulates and asks
/// "is this message whole yet?" on every chunk, and answering that with a FRESH decoder re-decoded
/// every byte received so far — quadratic in the body, with a full re-allocation of the decoded
/// chunks each time. The ingress reader already keeps one decoder across reads. This drives the
/// production `complete_message` and counts the bytes it actually feeds a decoder.
#[test]
fn the_egress_chunked_body_is_decoded_once_across_many_write_calls() {
    let mut buffered = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
    let mut cache = EgressHead::default();
    assert!(complete_message(&buffered, &mut cache, usize::MAX)
        .unwrap()
        .is_none());

    const CALLS: usize = 200;
    const PIECE: &[u8] = b"10\r\naaaaaaaaaaaaaaaa\r\n";
    let mut wire_bytes = 0_usize;
    for _ in 0..CALLS {
        buffered.extend_from_slice(PIECE);
        wire_bytes += PIECE.len();
        assert!(
            complete_message(&buffered, &mut cache, usize::MAX)
                .unwrap()
                .is_none(),
            "no terminal chunk yet, so the message is not whole"
        );
    }
    buffered.extend_from_slice(b"0\r\n\r\n");
    wire_bytes += 5;
    let done = complete_message(&buffered, &mut cache, usize::MAX)
        .unwrap()
        .expect("the terminal chunk completes the message");
    assert_eq!(
        done.body.len(),
        CALLS * 16,
        "the body is decoded byte-exact"
    );

    let fed = cache.feeds;
    assert!(
        fed <= 2 * wire_bytes,
        "a {wire_bytes}-byte chunked body arriving in {CALLS} calls cost {fed} bytes of decoding; \
         one decoder across the calls makes that O(n), a fresh one per call makes it O(n^2)"
    );

    // And the decoder is spent with the message: the next one decodes its own body.
    assert!(
        cache.head.is_none() && cache.decoder.is_none(),
        "a completed message leaves no stale decoder"
    );
}

/// One wrapping layer, standing in for the connector and pool layers a real client error arrives
/// wrapped in: the fact this transport reports must be read off the CHAIN, not off the top.
#[derive(Debug)]
struct Wrapped(io::Error);
impl std::fmt::Display for Wrapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "client error")
    }
}
impl std::error::Error for Wrapped {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// An error with nothing underneath it: the shape the fallback exists for.
#[derive(Debug)]
struct Opaque;
impl std::fmt::Display for Opaque {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "opaque")
    }
}
impl std::error::Error for Opaque {}

/// Every egress failure used to be reported as `Refused` — nothing was listening. A connect that
/// timed out, a keep-alive that went unanswered and a connection reset mid-response are three
/// different facts about an upstream, and collapsing them tells an operator the upstream is down
/// when it is slow, or wedged, or resetting mid-body.
#[test]
fn an_egress_failure_reports_the_fact_it_carries_not_a_refusal_for_everything() {
    let cases: Vec<(io::ErrorKind, TransportError)> = vec![
        (io::ErrorKind::TimedOut, TransportError::Timeout),
        (io::ErrorKind::ConnectionReset, TransportError::Reset),
        (io::ErrorKind::ConnectionAborted, TransportError::Reset),
        (io::ErrorKind::ConnectionRefused, TransportError::Refused),
        (
            io::ErrorKind::AddrNotAvailable,
            TransportError::AddressRefused,
        ),
        (io::ErrorKind::BrokenPipe, TransportError::Closed),
    ];
    for (kind, expected) in cases {
        let bare = io::Error::new(kind, "x");
        assert_eq!(map_egress_err(&bare), expected, "bare {kind:?}");
        let wrapped = Wrapped(io::Error::new(kind, "x"));
        assert_eq!(map_egress_err(&wrapped), expected, "wrapped {kind:?}");
    }
    assert_eq!(
        map_egress_err(&Opaque),
        TransportError::Refused,
        "an error carrying no io fact is the one case there is nothing more specific to say about"
    );
}

/// A writer that accepts every byte and then fails to flush: the exact shape a Unit 0 refusal must
/// not be able to report as delivered. `write_all` succeeds, so only the flush leg can catch it.
struct FlushFailsWriter {
    written: Vec<u8>,
}

impl tokio::io::AsyncWrite for FlushFailsWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        self.written.extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "the peer went away before the refusal reached it",
        )))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
}

/// A close ends a frame stream that is parked mid-request, and the socket really goes with it.
///
/// The registry entry is not the connection: a pump started before the close holds its own clone of
/// the state, parked on a read for the rest of a half-written request the peer may never finish.
/// Removing the registry's clone alone leaves that pump waiting forever — one leaked socket per
/// closed connection. The flag is what ends it, after which the last clone goes and the peer sees
/// the socket shut.
#[tokio::test]
async fn a_close_ends_a_parked_ingress_pump_and_releases_the_socket() {
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
    let conn = accept_fut.await.unwrap();

    // A pump that is live before the close, parked on the rest of a header block that never ends.
    let pump = tokio::spawn({
        let transport = transport.clone();
        let conn = conn.clone();
        async move { transport.frames(conn).next().await.is_none() }
    });
    tokio::io::AsyncWriteExt::write_all(&mut client, b"POST / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    transport.close(conn, CloseReason::Normal);

    // The peer keeps writing, as a peer that has not heard about the close will.
    tokio::io::AsyncWriteExt::write_all(&mut client, b"X-More: y\r\n")
        .await
        .unwrap();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("a closed connection's frame stream must end rather than park on the socket")
        .unwrap();
    assert!(ended, "a closed connection yields no further frames");

    // The pump was the last holder: with it finished the socket is really gone.
    let mut sink = [0_u8; 32];
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut client, &mut sink),
    )
    .await
    .expect("the closed socket must be released, which the peer reads as end-of-stream");
    assert_eq!(
        read.unwrap(),
        0,
        "the closed connection's socket must close"
    );
}

/// One read buffer per ingress connection, not a fresh `READ_CHUNK_BYTES` one per read syscall.
///
/// The ingress reader takes as many reads as the message arrives in — the header, then each piece of
/// the body — and a buffer allocated inside that loop is an allocation and a 64 KiB zero-fill on the
/// frame path for every one of them. The buffer belongs to the connection, behind the same lock as
/// the read half, which is what makes reusing it sound: one pump reads a connection at a time.
/// The refusal is the client-visible answer to an authentication failure, so "delivered" has to
/// mean the bytes left. `write_all` only proves they reached the writer's own buffer; the flush is
/// the evidence, and swallowing its failure reports a refusal nobody ever received. The sibling
/// `tcp` and `tls` crates already answer this way.
#[tokio::test]
async fn an_undelivered_unit0_refusal_is_an_error() {
    let mut w = FlushFailsWriter {
        written: Vec::new(),
    };
    let err = deliver_refusal(&mut w, b"refused")
        .await
        .expect_err("a refusal whose flush failed was never delivered and must not report Ok");
    assert_eq!(err, TransportError::Reset);
    assert_eq!(w.written.as_slice(), b"refused");
}

/// A peer that stops in the middle of a header block sent a message that never arrived. Reading
/// that as end-of-stream discards bytes already read and calls a truncated request no request at
/// all — the same guess the body branches already refuse to make.
#[tokio::test]
async fn a_header_block_cut_short_at_eof_is_a_framing_error() {
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
    tokio::spawn(async move {
        let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
        // Half a header block, then a close.
        tokio::io::AsyncWriteExt::write_all(&mut client, b"POST / HTTP/1.1\r\nHost: x")
            .await
            .unwrap();
        drop(client);
    });
    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the reader answers rather than hanging")
        .expect("a truncated header block is reported, not silently dropped");
    assert_eq!(first.unwrap_err(), TransportError::Framing);
}

/// A response header value the wire allows is not required to be UTF-8. Rendering an un-decodable
/// one as the empty string hands the layer above a head that says the header was present and empty
/// — a claim about the upstream's answer that the upstream did not make. What arrived goes up.
#[tokio::test]
async fn a_non_ascii_response_header_value_reaches_the_head_frame_as_its_own_bytes() {
    let uri = fixed_response_server(
        b"HTTP/1.1 200 OK\r\nx-note: caf\xc3\xa9\xff\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
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
    let joined = head.bytes.as_slice();
    let needle = b"x-note: caf\xc3\xa9\xff";
    assert!(
        joined.windows(needle.len()).any(|w| w == needle),
        "the head must carry the value the upstream sent, not an empty stand-in"
    );
}

/// The read buffer is per-connection and reused across reads, so a short read following a long one
/// must not carry the tail of its predecessor, and the buffer must be the same allocation each time
/// rather than a fresh `READ_CHUNK_BYTES` one per read syscall — of which this reader does several
/// per message: the header, each body chunk, the trailers.
#[tokio::test]
async fn one_read_buffer_per_connection_rather_than_one_per_read() {
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
        let body = vec![b'L'; 4096];
        let mut req = format!(
            "POST / HTTP/1.1\r\nHost: x\r\ncontent-length: {}\r\n\r\n",
            4101
        )
        .into_bytes();
        tokio::io::AsyncWriteExt::write_all(&mut client, &req)
            .await
            .unwrap();
        // A second read: the header is already consumed, so this one fills the buffer again.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        req = body;
        tokio::io::AsyncWriteExt::write_all(&mut client, &req)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        tokio::io::AsyncWriteExt::write_all(&mut client, b"short")
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });
    let conn = accept_fut.await.unwrap();
    let id = conn.id();
    let before = transport.scratch_addr(id).await.unwrap();
    let mut frames = transport.frames(conn);
    let (_s, head) = frames.next().await.unwrap().unwrap();
    assert!(head.bytes.as_slice().starts_with(b"POST / HTTP/1.1"));
    let (_s, body) = frames.next().await.unwrap().unwrap();
    assert_eq!(
        body.bytes.as_slice().len(),
        4101,
        "the declared body, whole and with no residue from the header read before it"
    );
    assert!(body.bytes.as_slice().ends_with(b"short"));
    assert_eq!(
        transport.scratch_addr(id).await.unwrap(),
        before,
        "one buffer per connection, not one per read"
    );
    writer.abort();
}

/// Every request line names its version. Without the check any two words followed by a space parse
/// as a request, so a blob that is not HTTP at all is read as one and its first two words become a
/// method and a path this transport goes on to act on.
#[test]
fn a_start_line_with_no_http_version_is_not_a_message() {
    assert!(
        raw::parse_message(b"GET /\r\nHost: x\r\n\r\n").is_none(),
        "a request line with no version token is not a request line"
    );
    assert!(
        raw::parse_message(b"NOT A REQUEST\r\nHost: x\r\n\r\n").is_none(),
        "an arbitrary first line is not a request line"
    );
    assert!(
        raw::parse_message(b"GET / HTTP/2\r\nHost: x\r\n\r\n").is_none(),
        "a version this reader does not frame is refused, not read with 1.x's rules"
    );
    assert!(
        raw::parse_message(b"HTTP/2 200 OK\r\n\r\n").is_none(),
        "and the same on the status side"
    );
    assert!(raw::parse_message(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_some());
    assert!(raw::parse_message(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n").is_some());
    assert!(raw::parse_message(b"HTTP/1.1 200 OK\r\n\r\n").is_some());
}

/// Frame meta is honest on the frames this transport REALLY emits, on both sides.
///
/// A predicate applied to hand-built `Frame` literals proves the predicate, not the transport: the
/// fixtures agree with themselves by construction and the transport is never asked. So the frames
/// here come out of a live ingress read and a live egress round trip, and the check is shown to
/// discriminate by perturbing a real one either way.
///
/// The egress HEAD frame is the one with somewhere to go wrong: its bytes are rebuilt from the
/// upstream's status line and headers with `Content-Length` and `Transfer-Encoding` stripped, so its
/// meta must count the bytes that survived the strip and not the head that arrived.
#[tokio::test]
async fn frame_meta_is_honest_on_the_frames_this_transport_emits() {
    fn honest(frame: &Frame) -> bool {
        frame.meta.bytes == frame.bytes.len() as u64
    }

    // Egress: a HEAD frame rebuilt past a stripped `Content-Length`, and the body frame after it.
    let uri =
        fixed_response_server(b"HTTP/1.1 200 OK\r\nX-Tag: t\r\nContent-Length: 5\r\n\r\nhello")
            .await;
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
    let head_text = String::from_utf8(head.bytes.as_slice().to_vec()).unwrap();
    assert!(
        !head_text.to_ascii_lowercase().contains("content-length"),
        "the head that goes up is the stripped one: {head_text:?}"
    );
    assert!(
        honest(&head),
        "the HEAD frame's meta counts the bytes that survived the strip, not the ones that arrived"
    );
    let (_s, body) = frames.next().await.unwrap().unwrap();
    assert_eq!(body.bytes.as_slice(), b"hello");
    assert!(honest(&body));

    // Ingress: the HEAD frame is the verbatim header prefix, the body frame is the decoded body.
    let served = StdArc::new(HttpTransport::new(ClientSettings::default()));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = served.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let accept_fut = tokio::spawn({
        let served = served.clone();
        async move { served.accept(&listener).await.unwrap() }
    });
    let mut client = tokio::net::TcpStream::connect(&addr).await.unwrap();
    tokio::io::AsyncWriteExt::write_all(
        &mut client,
        b"POST /units HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd",
    )
    .await
    .unwrap();
    let accepted = accept_fut.await.unwrap();
    let mut served_frames = served.frames(accepted);
    let (_s, in_head) = served_frames.next().await.unwrap().unwrap();
    let (_s, in_body) = served_frames.next().await.unwrap().unwrap();
    assert!(honest(&in_head) && honest(&in_body));
    assert_eq!(in_body.bytes.as_slice(), b"abcd");

    // And the check discriminates: a real frame perturbed either way fails it.
    for drift in [1_i64, -1] {
        for real in [&head, &body, &in_head, &in_body] {
            let perturbed = Frame {
                meta: FrameMeta {
                    bytes: real.meta.bytes.wrapping_add_signed(drift),
                    ..real.meta
                },
                ..real.clone()
            };
            assert!(
                !honest(&perturbed),
                "a frame claiming {drift:+} bytes against what it carries is not an honest one"
            );
        }
    }
}
