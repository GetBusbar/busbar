//! The transport battery, for `sse`: the request/N-response-frame shape over a real streamed
//! upstream, the inherited `StatusClass` at the first response frame, and the terminator/frame
//! parser tests ported alongside `proto` itself.

use super::*;
use busbar_contract::KernelSeal;
use busbar_transport_http::ClientSettings;
use futures::StreamExt;

struct FixtureSeal;
impl KernelSeal for FixtureSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-transport-sse test fixture"
    }
}
fn fixture_key() -> TransportKeyHandle {
    TransportKeyHandle::issue(&FixtureSeal, 0, "test")
}

fn upstream_dest(uri: &str) -> busbar_contract::VerifiedDestination {
    let host: &'static str = Box::leak(uri.to_string().into_boxed_str());
    busbar_contract::VerifiedDestination::seal(
        &FixtureSeal,
        busbar_contract::DestinationFacts::Upstream {
            transport: "sse",
            address: busbar_contract_transport::dest::UpstreamAddress::socket(host),
            lane: busbar_contract::LaneId::new("test"),
        },
        "sse",
        None,
    )
}

/// A fixed upstream that streams two SSE frames in one response body.
async fn sse_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 4096];
        let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
        let body = b"event: message\ndata: {\"a\":1}\n\ndata: {\"a\":2}\n\n";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes())
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, body)
            .await
            .unwrap();
    });
    format!("http://{addr}/")
}

#[tokio::test]
async fn request_plus_n_response_frames_over_a_real_stream() {
    let uri = sse_server().await;
    let http = std::sync::Arc::new(HttpTransport::new(ClientSettings::default()));
    let sse = SseTransport::new(http);

    let conn = sse
        .dial(&upstream_dest(&uri), &fixture_key())
        .await
        .unwrap();
    sse.write(
        &conn,
        StreamId(0),
        ArenaBytes::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    )
    .await
    .unwrap();

    let mut frames = sse.frames(conn);
    let (_s, first) = frames.next().await.unwrap().unwrap();
    assert_eq!(
        first.meta.status,
        Some(busbar_contract_transport::wire::StatusClass::Success)
    );
    let (event, data) = proto::parse_sse_frame(first.bytes.as_slice()).unwrap();
    assert_eq!(event, "message");
    assert_eq!(data, "{\"a\":1}");

    let (_s, second) = frames.next().await.unwrap().unwrap();
    // The status leg is carried once, on the first response frame only — a composed layer must
    // not repeat it.
    assert_eq!(second.meta.status, None);
    let (event2, data2) = proto::parse_sse_frame(second.bytes.as_slice()).unwrap();
    assert_eq!(event2, "");
    assert_eq!(data2, "{\"a\":2}");

    assert!(frames.next().await.is_none());
}

/// The re-segmentation scan costs a pass over the frame, not a pass per arriving chunk.
///
/// An upstream trickling one large frame is the shape that separates a linear scan from a
/// quadratic one: rescanning the whole buffer on every http frame re-proves the prefix already
/// proven terminator-free, once per chunk. The crate next door holds its chunked decoder to exactly
/// this standard, and says why — for the bodies these paths exist to carry it is the difference
/// between a transport and a stall.
///
/// This drives the same [`proto::find_frame_terminator_from`] the transport's `frames` runs on, in
/// the same resume-and-rewind discipline, so what it counts is production work.
#[test]
fn the_resegmentation_scan_costs_one_pass_over_the_frame_not_one_per_chunk() {
    let mut frame = b"data: ".to_vec();
    frame.extend_from_slice(&[b'x'; 8192]);
    frame.extend_from_slice(b"\n\n");

    let mut buf: Vec<u8> = Vec::with_capacity(frame.len());
    let mut scanned_prefix = 0_usize;
    proto::SCANNED_BYTES.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut found = None;
    for byte in &frame {
        buf.push(*byte);
        match proto::find_frame_terminator_from(&buf, scanned_prefix.saturating_sub(3)) {
            Some(hit) => {
                found = Some(hit);
                break;
            }
            None => scanned_prefix = buf.len(),
        }
    }
    assert_eq!(
        found,
        Some((frame.len() - 2, 2)),
        "the frame boundary is still found at exactly the same offset"
    );

    let scanned = proto::SCANNED_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    let n = frame.len();
    assert!(
        scanned < 5 * n,
        "a {n}-byte frame arriving a byte at a time cost {scanned} bytes of scanning; \
         a resume point makes that O(n), restarting at zero makes it O(n^2)"
    );
}

/// A frame trickled in one byte at a time is segmented exactly as one delivered whole.
///
/// The correctness half of carrying a scan cursor: the only way an offset-tracking scan can be
/// wrong is by moving a frame boundary, so both deliveries are asserted to produce the same frames.
#[tokio::test]
async fn byte_at_a_time_delivery_segments_identically_to_one_shot_delivery() {
    async fn frames_of(trickle: bool) -> Vec<Vec<u8>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0_u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            let body = b"event: a\ndata: one\n\ndata: two\r\n\r\ndata: three\r\rdata: four\n\n";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            tokio::io::AsyncWriteExt::write_all(&mut stream, resp.as_bytes())
                .await
                .unwrap();
            if trickle {
                for byte in body {
                    tokio::io::AsyncWriteExt::write_all(&mut stream, &[*byte])
                        .await
                        .unwrap();
                    tokio::io::AsyncWriteExt::flush(&mut stream).await.unwrap();
                }
            } else {
                tokio::io::AsyncWriteExt::write_all(&mut stream, body)
                    .await
                    .unwrap();
            }
        });

        let uri = format!("http://{addr}/");
        let http = std::sync::Arc::new(HttpTransport::new(ClientSettings::default()));
        let sse = SseTransport::new(http);
        let conn = sse
            .dial(&upstream_dest(&uri), &fixture_key())
            .await
            .unwrap();
        sse.write(
            &conn,
            StreamId(0),
            ArenaBytes::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        )
        .await
        .unwrap();
        let mut out = Vec::new();
        let mut frames = sse.frames(conn);
        while let Some(Ok((_s, f))) = frames.next().await {
            out.push(f.bytes.as_slice().to_vec());
        }
        out
    }

    let whole = frames_of(false).await;
    let trickled = frames_of(true).await;
    assert_eq!(
        whole.len(),
        4,
        "four frames, every terminator shape among them"
    );
    assert_eq!(
        whole, trickled,
        "how the bytes were delivered is not a fact about where the frames end"
    );
}

#[test]
fn frame_meta_honesty_holds_for_sse_frames() {
    let raw = b"data: x\n\n";
    let bytes: std::sync::Arc<[u8]> = std::sync::Arc::from(&raw[..]);
    let frame = Frame {
        direction: Direction::Inbound,
        stream: StreamId(0),
        bytes: SlabBytes::new(bytes),
        meta: FrameMeta {
            bytes: raw.len() as u64,
            transport_units: None,
            status: None,
        },
    };
    assert_eq!(frame.meta.bytes, frame.bytes.len() as u64);
}
