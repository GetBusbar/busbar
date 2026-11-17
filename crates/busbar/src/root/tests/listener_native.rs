// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::records::{Reply, Writer};

fn request_budget(bytes: u32) -> (Arc<ProcessAdmission>, RequestLease) {
    let budget = ProcessAdmission::with_limits(2, bytes, 0);
    let request = budget.try_enter(AdmissionClass::Data).unwrap();
    (budget, request)
}

#[test]
fn native_head_preserves_empty_query_duplicates_and_charges_before_copy() {
    let mut wire = Reply::new();
    wire.put_text(tag::H_METHOD, "POST").unwrap();
    wire.put_text(tag::H_PATH, "/one?").unwrap();
    wire.put_text(tag::H_AUTHORITY, "example.test").unwrap();
    wire.put_pair(tag::PAIR, "x-order", b"first").unwrap();
    wire.put_pair(tag::PAIR, "x-order", b"second").unwrap();
    let (budget, request) = request_budget(4096);
    let decoded = decode_head(wire.as_bytes(), &request).unwrap();
    assert_eq!(decoded.head.query.as_deref(), Some(""));
    assert_eq!(decoded.head.target, "/one");
    assert_eq!(decoded.head.fields.len(), 2);
    assert_eq!(decoded.head.fields[1].1, b"second");
    let held = decoded.credit.len();
    assert!(held >= 2 * std::mem::size_of::<(String, Vec<u8>)>());
    assert_eq!(budget.used(), (held, held));
    drop(decoded);
    assert_eq!(budget.used(), (0, 0));
    let (small, request) = request_budget(1);
    assert!(decode_head(wire.as_bytes(), &request).is_err());
    assert_eq!(small.used(), (0, 0));
}

#[test]
fn native_head_rejects_duplicate_identity_before_retaining_any_fields() {
    let mut wire = Reply::new();
    wire.put_text(tag::H_METHOD, "GET").unwrap();
    wire.put_text(tag::H_METHOD, "POST").unwrap();
    wire.put_text(tag::H_PATH, "/").unwrap();
    let (budget, request) = request_budget(4096);
    assert!(decode_head(wire.as_bytes(), &request).is_err());
    assert_eq!(budget.used(), (0, 0));
}

#[test]
fn native_input_window_is_not_a_total_body_limit_and_replacement_overlaps() {
    let (budget, request) = request_budget(2 * 1024 * 1024);
    let mut body = InputBody::new(&request).unwrap();
    let chunk = vec![7; PLAINTEXT_WINDOW];
    body.append(&request, &chunk, 1024 * 1024).unwrap();
    body.append(&request, &chunk, 1024 * 1024).unwrap();
    assert_eq!(body.bytes.len(), 2 * PLAINTEXT_WINDOW);
    assert_eq!(budget.used().0 as usize, 2 * PLAINTEXT_WINDOW);
    assert!(body.credit.request().same_request(&request));
    drop(body);
    assert_eq!(budget.used(), (0, 0));
    let (small, request) = request_budget(10);
    let mut body = InputBody::new(&request).unwrap();
    body.append(&request, b"123456", 64).unwrap();
    assert!(body.append(&request, b"7", 64).is_err());
    assert_eq!(body.bytes.as_slice(), b"123456");
    assert_eq!(small.used(), (6, 6));
}
