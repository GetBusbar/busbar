// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use axum::Router;
use busbar_core_connector::framer::FramerDoor;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{data_framer, DataFramer, DATA_SCHEME};

#[test]
fn operator_request_refuses_a_block_with_a_separatorless_line() {
    let head = busbar_core_connector::framer::Head {
        method: Some(b"GET".to_vec()),
        target: Some(b"/".to_vec()),
        ..Default::default()
    };
    let (_tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let body = super::InboundBody {
        pieces: rx,
        ended: false,
    };
    let block = b"x:y\r\nauthorization: Bearer t\r\n";
    let request =
        super::operator::request(&head, block, false, body, std::time::Duration::from_secs(1));
    assert!(request.is_none(), "later headers must not silently vanish");
}

#[test]
fn neutral_head_decoding_preserves_the_shared_abi_without_http_parsing() {
    let head = busbar_core_connector::framer::Head {
        method: Some(b"READ OBJECT".to_vec()),
        target: Some(b"opaque target with spaces?kept=%2f".to_vec()),
        authority: Some(b"opaque authority".to_vec()),
        ..Default::default()
    };
    let decoded = super::decoded_head(&head, b"opaque field: \0value\r\n").unwrap();
    assert_eq!(decoded.method, "READ OBJECT");
    assert_eq!(decoded.target, "opaque target with spaces");
    assert_eq!(decoded.query.as_deref(), Some("kept=%2f"));
    assert_eq!(decoded.authority, "opaque authority");
    assert_eq!(
        decoded.fields,
        vec![("opaque field".to_owned(), b"\0value".to_vec())]
    );
    assert!(super::decoded_head(&head, b"field: complete\r\nunparsed-tail").is_none());
    let mut invalid_text = head;
    invalid_text.method = Some(vec![0xff]);
    assert!(
        super::decoded_head(&invalid_text, &[]).is_none(),
        "the existing auth head ABI requires text"
    );
}

include!(concat!(env!("OUT_DIR"), "/context_test_sources.rs"));
owner_test_sources!(listener_framed);
owner_test_sources!(listener_session);
owner_test_sources!(listener_carrier);
#[test]
fn aggregate_body_charge_survives_reader_and_releases_at_request_end() {
    let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
    let charge = std::sync::Arc::new(super::BodyCharge::default());
    assert!(charge.take(&budget, 5));
    let reader = std::sync::Arc::clone(&charge);
    assert!(!reader.take(&budget, 4));
    assert_eq!(budget.available_permits(), 3);
    assert!(reader.take(&budget, 3));
    drop(reader);
    assert_eq!(budget.available_permits(), 0);
    drop(charge);
    assert_eq!(budget.available_permits(), 8);
}

#[tokio::test]
async fn framed_body_refuses_a_drip_below_the_shared_throughput_floor() {
    use std::future::Future as _;
    tokio::time::pause();
    let (send, pieces) = tokio::sync::mpsc::unbounded_channel();
    let mut gather = Box::pin(super::gather_body(
        super::InboundBody {
            pieces,
            ended: false,
        },
        0,
        Duration::from_secs(30),
    ));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    send.send(Ok(bytes::Bytes::from_static(b"a"))).unwrap();
    assert!(gather.as_mut().poll(&mut cx).is_pending());
    tokio::time::advance(Duration::from_secs(11)).await;
    send.send(Ok(bytes::Bytes::from_static(b"b"))).unwrap();
    assert!(
        matches!(
            gather.as_mut().poll(&mut cx),
            Poll::Ready(Err(busbar_contract::caps::ReasonCode::DeadlineExceeded))
        ),
        "periodic bytes must not retain an inbound permit forever"
    );
}

#[tokio::test]
async fn framed_body_preserves_prompt_pieces_and_per_request_size_limit() {
    for (limit, expected) in [
        (6, Ok(bytes::Bytes::from_static(b"abcdef"))),
        (5, Err(busbar_contract::caps::ReasonCode::BodyTooLarge)),
    ] {
        let (send, pieces) = tokio::sync::mpsc::unbounded_channel();
        send.send(Ok(bytes::Bytes::from_static(b"abc"))).unwrap();
        send.send(Ok(bytes::Bytes::from_static(b"def"))).unwrap();
        drop(send);
        assert_eq!(
            super::gather_body(
                super::InboundBody {
                    pieces,
                    ended: false
                },
                limit,
                Duration::from_secs(30)
            )
            .await,
            expected
        );
    }
}
