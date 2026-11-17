// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
use busbar_plugin_abi::records::{Records, U32Rec};

#[tokio::test]
async fn native_http_response_uses_funded_records_and_a_streaming_body_window() {
    let budget = ProcessAdmission::with_limits(2, 4 * 1024 * 1024, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let source = request.storage();
    let mut response = axum::response::Response::new(axum::body::Body::from(vec![9; PLAINTEXT_WINDOW + 7]));
    response.headers_mut().append("x-order", "one".parse().unwrap());
    response.headers_mut().append("x-order", "two".parse().unwrap());
    let mut pieces = ResponsePieces::new(response, source).unwrap();
    let head = pieces.next().await.unwrap().unwrap();
    assert_eq!(head.piece, busbar_plugin_abi::transport::E_HEAD);
    let mut records = Records::new(head.bytes.as_slice());
    assert_eq!(records.next().unwrap().unwrap().pod::<U32Rec>().unwrap().value, 200);
    assert_eq!(records.next().unwrap().unwrap().pair().unwrap(), ("x-order", &b"one"[..]));
    assert_eq!(records.next().unwrap().unwrap().pair().unwrap(), ("x-order", &b"two"[..]));
    drop(head);
    assert_eq!(budget.used(), (0, 0));
    let first = pieces.next().await.unwrap().unwrap();
    assert_eq!(first.bytes.len(), PLAINTEXT_WINDOW);
    assert_eq!(budget.used().0, PLAINTEXT_WINDOW);
    drop(first);
    let last = pieces.next().await.unwrap().unwrap();
    assert_eq!(last.bytes.as_slice(), &[9; 7]);
    drop(last);
    assert!(!pieces.eof());
    assert!(pieces.next().await.unwrap().is_none());
    assert!(pieces.eof());
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn native_http_record_encoding_refuses_before_allocating_uncharged_backing() {
    let budget = ProcessAdmission::with_limits(1, 15, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    let response = axum::response::Response::new(axum::body::Body::empty());
    assert!(ResponsePieces::new(response, request.storage()).is_err());
    assert_eq!(budget.used(), (0, 0));
    // Status alone needs one padded canonical 16-byte record.
    assert_eq!(quote_records(Some(200), &axum::http::HeaderMap::new()).unwrap(), 16);
}
