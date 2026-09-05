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
            address: busbar_contract::UpstreamAddress::socket(host),
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
        tokio::io::AsyncWriteExt::write_all(&mut stream, response).await.unwrap();
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
    assert!(std::str::from_utf8(head.bytes.as_slice()).unwrap().starts_with("HTTP/1.1 200"));

    let (_s, body) = frames.next().await.unwrap().unwrap();
    assert_eq!(body.bytes.as_slice(), b"hello");
    assert!(frames.next().await.is_none());
}

#[tokio::test]
async fn egress_maps_4xx_and_5xx_status_classes() {
    for (status, class) in [(404_u16, StatusClass::ClientError), (500, StatusClass::ServerError)] {
        let resp: &'static [u8] = Box::leak(
            format!("HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n").into_bytes().into_boxed_slice(),
        );
        let uri = fixed_response_server(resp).await;
        let transport = HttpTransport::new(ClientSettings::default());
        let conn = transport
            .dial(&upstream_dest(&uri), &fixture_key())
            .await
            .unwrap();
        transport
            .write(&conn, StreamId(0), ArenaBytes::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
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
    let (_s, response_head) = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
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

#[tokio::test]
async fn every_transport_error_is_mapped_on_dial() {
    let transport = HttpTransport::new(ClientSettings::default());
    let bad = upstream_dest("not a uri at all");
    let err = transport.dial(&bad, &fixture_key()).await.unwrap_err();
    assert_eq!(err, TransportError::AddressRefused);
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
        meta: FrameMeta { bytes: 40, ..base.meta },
        ..base.clone()
    };
    assert!(!honest(&inflated));
    let deflated = Frame {
        meta: FrameMeta { bytes: 1, ..base.meta },
        ..base
    };
    assert!(!honest(&deflated));
}
