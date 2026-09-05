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
            address: busbar_contract::UpstreamAddress::socket(host),
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
        tokio::io::AsyncWriteExt::write_all(&mut stream, body).await.unwrap();
    });
    format!("http://{addr}/")
}

#[tokio::test]
async fn request_plus_n_response_frames_over_a_real_stream() {
    let uri = sse_server().await;
    let http = std::sync::Arc::new(HttpTransport::new(ClientSettings::default()));
    let sse = SseTransport::new(http);

    let conn = sse.dial(&upstream_dest(&uri), &fixture_key()).await.unwrap();
    sse.write(
        &conn,
        StreamId(0),
        ArenaBytes::new(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
    )
    .await
    .unwrap();

    let mut frames = sse.frames(conn);
    let (_s, first) = frames.next().await.unwrap().unwrap();
    assert_eq!(first.meta.status, Some(busbar_contract::StatusClass::Success));
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
