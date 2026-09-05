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
    TransportKeyHandle::seal(&FixtureSeal, 0, "test")
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
            host,
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
