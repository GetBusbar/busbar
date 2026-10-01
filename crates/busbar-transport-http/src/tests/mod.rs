//! The transport battery, for `http`: request in as a HEAD-plus-body frame pair, the ingress
//! framing refusals, the frame-meta honesty check, and a dial that is refused before any socket.

use super::*;
// The `Transport` surface, its meta and its claim forms moved to the kind's own `transport.rs`,
// `meta.rs` and `claims.rs` (`BUSBAR-1.6.0.md` THE DESIGN, §2), so `use super::*` no longer carries them.
use busbar_contract::transport::wire::{CloseReason, FrameMeta, TransportError};
use busbar_contract::ConfigView;
use busbar_contract::{Transport, TransportConfigView, TransportKeyHandle};
use futures::StreamExt;
use std::sync::Arc as StdArc;
use std::time::Duration;

// The dial is refused before any socket (TODO #145): its own file, as the repo's tests live.
mod dial_refused;

use busbar_contract::plugin::TestKernelSeal as FixtureSeal;
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
            address: busbar_contract::transport::dest::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test"),
        },
        "http",
        None,
    )
}

/// Both RFC 9110 forms, and nothing else. A value nobody can read is a value nobody asked for.
#[test]
fn retry_after_parses_both_normative_forms() {
    // delay-seconds, which ignores `now` entirely.
    assert_eq!(super::parse_retry_after("7", 1_000), Some(7));
    assert_eq!(super::parse_retry_after("  120 ", 9_999), Some(120));
    assert_eq!(super::parse_retry_after("0", 0), Some(0));

    // IMF-fixdate. 06 Nov 1994 08:49:37 GMT is 784_111_777 in Unix seconds.
    assert_eq!(
        super::parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777 - 30),
        Some(30)
    );
    // Already past: floored at zero rather than wrapping into a lifetime of suppression.
    assert_eq!(
        super::parse_retry_after("Sun, 06 Nov 1994 08:49:37 GMT", 784_111_777 + 90),
        Some(0)
    );

    // Neither form.
    assert_eq!(super::parse_retry_after("", 0), None);
    assert_eq!(super::parse_retry_after("soon", 0), None);
    assert_eq!(super::parse_retry_after("-5", 0), None);
    assert_eq!(super::parse_retry_after("7.5", 0), None);
    // An obsolete HTTP-date form: parsed by nobody here, so it is absent rather than guessed.
    assert_eq!(
        super::parse_retry_after("Sunday, 06-Nov-94 08:49:37 GMT", 0),
        None
    );
    // Right length, wrong month.
    assert_eq!(
        super::parse_retry_after("Sun, 06 Xxx 1994 08:49:37 GMT", 0),
        None
    );
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

/// The body cap the crate doc names is real, and it is the operator's own
/// `limits.request_body_max_bytes` rather than a constant invented here: ingress refuses a declared
/// length past the cap without reading the body behind it, so the cap this transport applies can
/// never disagree with the one the served door applies.
#[tokio::test]
async fn a_body_past_the_configured_maximum_is_refused() {
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
}

/// Ingress refuses a CHUNKED body past the cap even when the whole message already sits in the read
/// buffer — the decode loop never has to iterate, so a cap check that lived only inside it would let
/// an oversized single-buffer body through. A chunked sender declares no total, so the refusal is on
/// the bytes that actually arrived, and it must fire whether they arrive in one read or many.
#[tokio::test]
async fn an_ingress_chunked_body_past_the_configured_maximum_is_refused() {
    let settings = ClientSettings {
        request_body_max_bytes: 64,
        ..ClientSettings::default()
    };
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
        // A single 0x50 (80-byte) chunk plus its terminal chunk, written in ONE go so the whole
        // chunked message lands in the read buffer at once: the decoder is done on the first feed
        // and the loop body never runs. 80 decoded bytes (and ~91 wire bytes) are both past the
        // 64-byte cap.
        let mut msg =
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n50\r\n".to_vec();
        msg.extend_from_slice(&[b'a'; 80]);
        msg.extend_from_slice(b"\r\n0\r\n\r\n");
        tokio::io::AsyncWriteExt::write_all(&mut client, &msg)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    });
    let conn = accept_fut.await.unwrap();
    let mut frames = transport.frames(conn);
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("the reader refuses rather than hanging")
        .expect("the stream yields the framing error");
    assert_eq!(
        first.unwrap_err(),
        TransportError::Framing,
        "a chunked body past the configured maximum is refused even when it arrives in one read"
    );
    writer.abort();
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

/// The envelope's bytes are an HTTP message, because that is what this wire is.
///
/// The egress unit used to write a neutral layout — every field as `name: value`, a blank line, the
/// body — and hand it to `write` as if it were a request. It ran the lane cross-check over the same
/// buffer, so the check was honest about there being ONE buffer and wrong about what was in it. The
/// layout is the transport's, and this is the transport.
#[test]
fn the_envelope_encodes_as_an_http_message() {
    let transport = HttpTransport::new(ClientSettings::default());
    let arena = TestPlaneAlloc;
    let bytes = transport
        .encode_envelope(
            &[
                ("method", b"POST".as_slice()),
                ("path", b"/v1/messages".as_slice()),
                ("authorization", b"Token substituted".as_slice()),
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
    assert!(text.contains("authorization: Token substituted\r\n"));
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
    let arena = TestPlaneAlloc;
    let poisoned: &[(&str, &[u8])] = &[
        ("x-note", b"ok\r\nauthorization: token stolen".as_slice()),
        ("x-note", b"ok\nauthorization: token stolen".as_slice()),
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
            busbar_contract::transport::wire::Encode::Unrepresentable,
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
struct TestPlaneAlloc;

impl busbar_contract::PlaneAlloc for TestPlaneAlloc {
    fn alloc_bytes<'a>(
        &'a self,
        src: &[u8],
    ) -> Result<busbar_contract::ScratchBytes<'a>, busbar_contract::PlaneAllocBudget> {
        Ok(busbar_contract::ScratchBytes::new(Box::leak(
            src.to_vec().into_boxed_slice(),
        )))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, busbar_contract::PlaneAllocBudget> {
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, busbar_contract::Span)],
    ) -> Result<&'a [(&'a str, busbar_contract::Span)], busbar_contract::PlaneAllocBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

#[test]
fn every_transport_error_is_mapped() {
    // EVERY arm of the mapper this crate's ingress path shares, one io::Error per arm. The name of
    // this cell claims exhaustiveness; before this, swapping two arms of map_io_err left it green,
    // which is the definition of an unpinned mapping. The mapper is driven directly, which is the
    // same claim with nothing left implicit.
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

/// The egress mirror of `a_message_with_both_a_transfer_encoding_and_a_content_length_is_refused`,
/// the ingress reader's own refusal.
///
/// Two headers naming two different lengths for one body is the canonical request-smuggling
/// primitive. Before this was wired, `complete_message` only refused a `Transfer-Encoding` it
/// could not read at all (anything but `chunked`); a body that was validly `chunked` AND carried a
/// `Content-Length` fell through to the chunked branch, was decoded, and was handed back as a
/// message with both framing headers stripped — a quiet disambiguation forwarded to the next hop,
/// which may resolve the same ambiguity the other way. This refuses the pair outright, mirroring
/// the ingress reader's identical check and identical error.
///
/// The second half proves this is not an over-refusal: a normal chunked body with no
/// `Content-Length` beside it — the exact shape every other egress chunked cell in this file
/// exercises — still completes.
#[test]
fn egress_refuses_a_chunked_body_declared_with_a_content_length() {
    let smuggled = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let mut cache = EgressHead::default();
    assert_eq!(
        complete_message(smuggled, &mut cache, usize::MAX).unwrap_err(),
        TransportError::Framing,
        "a chunked body naming a Content-Length beside it is the smuggling shape, refused rather \
         than silently disambiguated and forwarded"
    );

    let clean =
        b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n";
    let mut clean_cache = EgressHead::default();
    let done = complete_message(clean, &mut clean_cache, usize::MAX)
        .unwrap()
        .expect(
            "a normal chunked body with no Content-Length still completes — this refuses the \
                 smuggling PAIR, not chunked encoding on its own",
        );
    assert_eq!(
        done.body, b"abc",
        "the clean chunked body still decodes byte-exact"
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
    .expect("the closed socket must be released, which the peer reads as the end of the socket");
    // Either shape proves the release. The close now WAKES the parked read rather than waiting for
    // the peer's next bytes, so the socket may already be gone by the time those bytes land — which
    // the peer reads as a reset rather than as an orderly end. What is being pinned is that the
    // descriptor went, not which of the two ways the peer found out.
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "the closed connection's socket must close, not stay readable"
    );
}

/// The same close, against a peer that says NOTHING more after it.
///
/// The cell above only reaches the flag because the peer keeps writing: those bytes are what return
/// the read the pump is parked on, and the flag is not looked at until it returns. The peer this
/// close has to work against is the one that half-writes a request and then goes quiet — which is
/// the case the doc above actually names, and the only one where "parked on a read the peer may
/// never answer" is literally true. With nothing to return the read, a flag nothing wakes leaves the
/// pump parked for the life of the process, holding the last clone of the socket: one leaked
/// descriptor per closed connection, and a drain that never finishes. The close has to WAKE the
/// read, not merely mark it.
#[tokio::test]
async fn a_close_ends_a_parked_ingress_pump_whose_peer_never_writes_again() {
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

    let pump = tokio::spawn({
        let transport = transport.clone();
        let conn = conn.clone();
        async move { transport.frames(conn).next().await.is_none() }
    });
    // A header block that never ends, and a body that never starts.
    tokio::io::AsyncWriteExt::write_all(&mut client, b"POST / HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    transport.close(conn, CloseReason::Drain);

    // The peer holds the socket open and writes nothing further. Nothing but the close itself is
    // going to return that read.
    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("a close must wake the parked read, not wait for bytes that never come")
        .unwrap();
    assert!(ended, "a closed connection yields no further frames");

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

/// The same close again, with the pump parked on a BODY read rather than a header one.
///
/// A declared length the peer never finishes sending parks the reader in a different loop, and a
/// wake that only covers the header loop would leave this one holding the socket just as long.
#[tokio::test]
async fn a_close_ends_a_pump_parked_on_a_body_the_peer_never_finishes() {
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

    let pump = tokio::spawn({
        let transport = transport.clone();
        let conn = conn.clone();
        async move { transport.frames(conn).next().await.is_none() }
    });
    // A whole header block declaring ten bytes, and one byte of them.
    tokio::io::AsyncWriteExt::write_all(
        &mut client,
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\na",
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    transport.close(conn, CloseReason::Drain);

    let ended = tokio::time::timeout(std::time::Duration::from_secs(5), pump)
        .await
        .expect("a close must wake a read parked mid-body too")
        .unwrap();
    assert!(ended, "a closed connection yields no further frames");
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
/// `tcp` crate already answers this way.
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

/// Frame meta is honest on the frames this transport REALLY emits.
///
/// A predicate applied to hand-built `Frame` literals proves the predicate, not the transport: the
/// fixtures agree with themselves by construction and the transport is never asked. So the frames
/// here come out of a live ingress read, and the check is shown to discriminate by perturbing a
/// real one either way.
#[tokio::test]
async fn frame_meta_is_honest_on_the_frames_this_transport_emits() {
    fn honest(frame: &Frame) -> bool {
        frame.meta.bytes == frame.bytes.len() as u64
    }

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
        for real in [&in_head, &in_body] {
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

/// The arrival record names the port the connection actually arrived on.
///
/// `Port` is a selector form, and a claim by port reads this field: zero here made every arrival on
/// every listener look alike, so a node bound to two ports could not tell them apart. The port is
/// the ACCEPTED SOCKET's local port, which is what the sibling `tcp` and `ws` crates report
/// and the only place the fact exists on an ephemeral (`:0`) bind.
#[tokio::test]
async fn an_arrival_names_the_port_it_arrived_on() {
    let served = StdArc::new(HttpTransport::new(ClientSettings::default()));
    let cfg = TestCfg {
        bind: "127.0.0.1:0".to_string(),
    };
    let listener = served.listen(&cfg, &fixture_key()).await.unwrap();
    let addr = listener.local_addr();
    let bound_port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
    let accept_fut = tokio::spawn({
        let served = served.clone();
        async move { served.accept(&listener).await.unwrap() }
    });
    let _client = tokio::net::TcpStream::connect(&addr).await.unwrap();
    let conn = accept_fut.await.unwrap();

    assert_eq!(
        served.arrival(&conn).port,
        bound_port,
        "an arrival on a listener bound to {bound_port} must say so"
    );
}

/// A request carrying `Expect: 100-continue` is ANSWERED before its body is waited for.
///
/// This is what a client asks for when it would rather be refused than upload: `curl` sets the
/// header on its own for any body past about a kibibyte and then WAITS for the interim answer
/// before sending a byte. A reader that only parks on the body has both sides waiting on each
/// other until the client's own timeout fires — the request never arrives and the client sees a
/// hang, not a refusal. `hyper` served this surface in 1.5.5 and answered the header, so answering
/// it is the parity bar rather than an addition.
#[tokio::test]
async fn a_request_expecting_a_continue_is_answered_before_its_body_is_waited_for() {
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
    let conn = accept_fut.await.unwrap();

    // The head only — the body is deliberately withheld, exactly as a client that is waiting for
    // the go-ahead withholds it.
    tokio::io::AsyncWriteExt::write_all(
        &mut client,
        b"POST /x HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n",
    )
    .await
    .unwrap();

    let mut frames = served.frames(conn);
    let pump = tokio::spawn(async move { frames.next().await });

    let mut interim = [0_u8; 64];
    let n = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut client, &mut interim),
    )
    .await
    .expect("the interim answer must arrive before the body does")
    .unwrap();
    assert_eq!(
        &interim[..n],
        b"HTTP/1.1 100 Continue\r\n\r\n",
        "the answer is the one the client is waiting for, and nothing else"
    );

    // And the request completes normally once the client, so told, sends its body.
    tokio::io::AsyncWriteExt::write_all(&mut client, b"hello")
        .await
        .unwrap();
    let (_s, head) = tokio::time::timeout(Duration::from_secs(5), pump)
        .await
        .expect("the request arrives")
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(head.bytes.as_slice().starts_with(b"POST /x HTTP/1.1"));
}

