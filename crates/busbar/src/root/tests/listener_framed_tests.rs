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
